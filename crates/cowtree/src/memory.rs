//! Test-only in-memory [`HeadStore`] and [`PackStore`] with fault-injection hooks for crash,
//! quota, fencing, corruption, GC, and format-version refusal tests.
//!
//! Strictly gated behind `#[cfg(any(test, feature = "test-store"))]` — NEVER compiled into
//! production `os-client-kernel` or used as a `#56` fallback (contract §2.15).

use crate::pack::decode_pack_trailer;
use crate::store::{
    BlockLoc, CommitRequest, Digest, ForkRequest, GcLockGuard, GcRoot, HeadStore, PackId, PackMeta,
    PackStore, PackTrailer, ReceiveCommitRequest, RoPinGuard, SnapshotRecord, VolumeHead, VolumeId,
    WriterLease, WriterLockGuard, WriterMode,
};
use crate::{COWFS_FORMAT_VERSION, PACK_MAX_BYTES, digest_to_hex, sha256};
use abi::Errno;
use abi::fs::Timespec;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::future::poll_fn;
use std::rc::Rc;
use std::task::{Poll, Waker};
use vfs::BoxFuture;

fn ts_expired(created_at: Timespec, now: Timespec, grace_window_secs: u64) -> bool {
    let exp_sec = created_at.sec.saturating_add(grace_window_secs);
    exp_sec < now.sec || (exp_sec == now.sec && created_at.nsec <= now.nsec)
}

struct MemWriterGuard {
    state: Rc<RefCell<HeadState>>,
    volume: VolumeId,
    token: u64,
}

impl WriterLockGuard for MemWriterGuard {}

impl Drop for MemWriterGuard {
    fn drop(&mut self) {
        let mut st = self.state.borrow_mut();
        if st.active_locks.get(&self.volume) == Some(&self.token) {
            st.active_locks.remove(&self.volume);
        }
    }
}

struct MemGcGuard {
    state: Rc<RefCell<HeadState>>,
    exclusive: bool,
}

impl GcLockGuard for MemGcGuard {}

impl Drop for MemGcGuard {
    fn drop(&mut self) {
        let wakers = {
            let mut st = self.state.borrow_mut();
            if self.exclusive {
                st.gc_exclusive = false;
                std::mem::take(&mut st.gc_waiters)
            } else {
                st.gc_shared = st.gc_shared.saturating_sub(1);
                Vec::new()
            }
        };
        for w in wakers {
            w.wake();
        }
    }
}

struct MemRoPinGuard {
    state: Rc<RefCell<HeadState>>,
    pin_id: u64,
}

impl RoPinGuard for MemRoPinGuard {}

impl Drop for MemRoPinGuard {
    fn drop(&mut self) {
        self.state.borrow_mut().ro_pins.remove(&self.pin_id);
    }
}

struct NodeRecord {
    bytes: Vec<u8>,
    created_at: Timespec,
}

struct ReceiptRecord {
    volume: VolumeId,
    root: Digest,
    head: VolumeHead,
    created_at: Timespec,
}

struct HeadState {
    format_version: Option<u32>,
    heads: HashMap<VolumeId, VolumeHead>,
    nodes: HashMap<Digest, NodeRecord>,
    packs: HashMap<PackId, PackMeta>,
    blocks: HashMap<Digest, BlockLoc>,
    snapshots: HashMap<(VolumeId, String), SnapshotRecord>,
    receipts: HashMap<[u8; 16], ReceiptRecord>,
    grace_pins: Vec<GcRoot>,
    ro_pins: HashMap<u64, (VolumeId, Digest)>,
    next_ro_pin: u64,
    active_locks: HashMap<VolumeId, u64>,
    next_lock_token: u64,
    next_fork_seq: u64,
    gc_shared: usize,
    gc_exclusive: bool,
    gc_waiters: Vec<Waker>,
    fail_next_commit: Option<Errno>,
    fail_after_next_commit: Option<Errno>,
    grace_window_secs: u64,
}

impl Default for HeadState {
    fn default() -> Self {
        Self {
            format_version: None,
            heads: HashMap::new(),
            nodes: HashMap::new(),
            packs: HashMap::new(),
            blocks: HashMap::new(),
            snapshots: HashMap::new(),
            receipts: HashMap::new(),
            grace_pins: Vec::new(),
            ro_pins: HashMap::new(),
            next_ro_pin: 1,
            active_locks: HashMap::new(),
            next_lock_token: 1,
            next_fork_seq: 1,
            gc_shared: 0,
            gc_exclusive: false,
            gc_waiters: Vec::new(),
            fail_next_commit: None,
            fail_after_next_commit: None,
            grace_window_secs: 600,
        }
    }
}

/// Fast in-memory test [`HeadStore`] supporting fencing, O(1) snapshots/forks, GC locks, and
/// fault injection.
#[derive(Clone, Default)]
pub struct MemoryHeadStore {
    state: Rc<RefCell<HeadState>>,
}

impl MemoryHeadStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_format_version(&self, version: Option<u32>) {
        self.state.borrow_mut().format_version = version;
    }

    pub fn set_grace_window_secs(&self, secs: u64) {
        self.state.borrow_mut().grace_window_secs = secs;
    }

    /// Inject a one-shot error on the next `commit_head` call BEFORE applying (e.g. `ENOSPC` or `EIO`).
    pub fn fail_next_commit(&self, err: Errno) {
        self.state.borrow_mut().fail_next_commit = Some(err);
    }

    /// Inject a one-shot ambiguous error AFTER applying the next `commit_head` (simulating a lost
    /// commit acknowledgement where the head advanced and the receipt was recorded).
    pub fn fail_after_next_commit(&self, err: Errno) {
        self.state.borrow_mut().fail_after_next_commit = Some(err);
    }

    /// Bit-flip one byte in a stored B+tree node to test fail-closed SHA-256 verification.
    pub fn corrupt_node_byte(&self, digest: &Digest, offset: usize) -> bool {
        let mut st = self.state.borrow_mut();
        if let Some(rec) = st.nodes.get_mut(digest)
            && offset < rec.bytes.len()
        {
            rec.bytes[offset] ^= 0x01;
            return true;
        }
        false
    }

    /// Drop a single block index entry (for testing GC abort on unresolved live references).
    pub fn remove_block_index(&self, digest: &Digest) -> Option<BlockLoc> {
        self.state.borrow_mut().blocks.remove(digest)
    }

    pub fn node_count(&self) -> usize {
        self.state.borrow().nodes.len()
    }

    pub fn volume_exists(&self, volume: &VolumeId) -> bool {
        self.state.borrow().heads.contains_key(volume)
    }

    pub fn gc_lock_state(&self) -> (usize, bool) {
        let st = self.state.borrow();
        (st.gc_shared, st.gc_exclusive)
    }
}

impl HeadStore for MemoryHeadStore {
    fn format_version(&self) -> BoxFuture<'_, Option<u32>> {
        Box::pin(async move { Ok(self.state.borrow().format_version) })
    }

    fn grace_window_secs(&self) -> u64 {
        self.state.borrow().grace_window_secs
    }

    fn create_volume<'a>(
        &'a self,
        head: &'a VolumeHead,
        initial_nodes: &'a [(Digest, Vec<u8>)],
    ) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async move {
            let mut st = self.state.borrow_mut();
            if let Some(v) = st.format_version
                && v != COWFS_FORMAT_VERSION
            {
                return Err(Errno::EPROTONOSUPPORT);
            }
            if st.heads.contains_key(&head.volume) {
                return Err(Errno::EEXIST);
            }
            st.format_version = Some(COWFS_FORMAT_VERSION);
            for (digest, bytes) in initial_nodes {
                st.nodes.entry(*digest).or_insert_with(|| NodeRecord {
                    bytes: bytes.clone(),
                    created_at: head.updated_at,
                });
            }
            st.heads.insert(head.volume.clone(), head.clone());
            Ok(head.clone())
        })
    }

    fn read_head<'a>(&'a self, volume: &'a VolumeId) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async move {
            let st = self.state.borrow();
            if let Some(v) = st.format_version
                && v != COWFS_FORMAT_VERSION
            {
                return Err(Errno::EPROTONOSUPPORT);
            }
            st.heads.get(volume).cloned().ok_or(Errno::ENOENT)
        })
    }

    fn list_volumes(&self) -> BoxFuture<'_, Vec<VolumeHead>> {
        Box::pin(async move {
            let st = self.state.borrow();
            if let Some(v) = st.format_version
                && v != COWFS_FORMAT_VERSION
            {
                return Err(Errno::EPROTONOSUPPORT);
            }
            let mut out: Vec<VolumeHead> = st.heads.values().cloned().collect();
            out.sort_by(|a, b| a.volume.cmp(&b.volume));
            Ok(out)
        })
    }

    fn stage_objects<'a>(
        &'a self,
        nodes: &'a [(Digest, Vec<u8>)],
        packs: &'a [PackMeta],
        blocks: &'a [(Digest, BlockLoc)],
        now: Timespec,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let mut st = self.state.borrow_mut();
            for (digest, bytes) in nodes {
                st.nodes.insert(
                    *digest,
                    NodeRecord {
                        bytes: bytes.clone(),
                        created_at: now,
                    },
                );
            }
            for pm in packs {
                st.packs
                    .entry(pm.pack_id.clone())
                    .or_insert_with(|| pm.clone());
            }
            for (digest, loc) in blocks {
                st.blocks.entry(*digest).or_insert_with(|| loc.clone());
            }
            Ok(())
        })
    }

    fn check_no_readers<'a>(&'a self, volume: &'a VolumeId) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if self
                .state
                .borrow()
                .ro_pins
                .values()
                .any(|(v, _)| v == volume)
            {
                Err(Errno::EBUSY)
            } else {
                Ok(())
            }
        })
    }

    fn commit_received_root<'a>(
        &'a self,
        req: &'a ReceiveCommitRequest,
    ) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async move {
            if let Some(ref snap) = req.snapshot_name
                && (snap.is_empty() || snap.contains(['/', '\0']))
            {
                return Err(Errno::EINVAL);
            }
            let mut st = self.state.borrow_mut();
            if let Some(v) = st.format_version
                && v != COWFS_FORMAT_VERSION
            {
                return Err(Errno::EPROTONOSUPPORT);
            }
            if let Some(err) = st.fail_next_commit.take() {
                return Err(err);
            }
            if let Some(ref snap) = req.snapshot_name
                && st
                    .snapshots
                    .contains_key(&(req.volume.clone(), snap.clone()))
            {
                return Err(Errno::EEXIST);
            }
            let next_head = match req.expected_lease {
                Some((inc, fence, epoch)) => {
                    if let Some(rec) = st.receipts.get(&req.op_id) {
                        if rec.root != req.new_root {
                            return Err(Errno::EINVAL);
                        }
                        return Ok(rec.head.clone());
                    }
                    let cur = st.heads.get(&req.volume).cloned().ok_or(Errno::ENOENT)?;
                    if cur.incarnation != inc || cur.fence != fence || cur.epoch != epoch {
                        return Err(Errno::ESTALE);
                    }
                    let grace = st.grace_window_secs;
                    if grace > 0 {
                        st.grace_pins.push(GcRoot {
                            volume: req.volume.clone(),
                            root: cur.root,
                            pinned_until: Some(Timespec {
                                sec: req.committed_at.sec.saturating_add(grace),
                                nsec: req.committed_at.nsec,
                            }),
                        });
                    }
                    VolumeHead {
                        format_version: COWFS_FORMAT_VERSION,
                        volume: req.volume.clone(),
                        incarnation: cur.incarnation,
                        fence: cur.fence,
                        epoch: cur.epoch.saturating_add(1),
                        root: req.new_root,
                        parent_volume: cur.parent_volume,
                        ephemeral_if_unmodified: false,
                        modified: true,
                        updated_at: req.committed_at,
                    }
                }
                None => {
                    if st.heads.contains_key(&req.volume) {
                        return Err(Errno::EEXIST);
                    }
                    st.format_version = Some(COWFS_FORMAT_VERSION);
                    VolumeHead {
                        format_version: COWFS_FORMAT_VERSION,
                        volume: req.volume.clone(),
                        incarnation: 1,
                        fence: 1,
                        epoch: 0,
                        root: req.new_root,
                        parent_volume: None,
                        ephemeral_if_unmodified: false,
                        modified: true,
                        updated_at: req.committed_at,
                    }
                }
            };
            for (digest, bytes) in &req.put_nodes {
                st.nodes.insert(
                    *digest,
                    NodeRecord {
                        bytes: bytes.clone(),
                        created_at: req.committed_at,
                    },
                );
            }
            for pm in &req.put_packs {
                st.packs
                    .entry(pm.pack_id.clone())
                    .or_insert_with(|| pm.clone());
            }
            for (digest, loc) in &req.put_blocks {
                st.blocks.entry(*digest).or_insert_with(|| loc.clone());
            }
            st.heads.insert(req.volume.clone(), next_head.clone());
            st.receipts.insert(
                req.op_id,
                ReceiptRecord {
                    volume: req.volume.clone(),
                    root: req.new_root,
                    head: next_head.clone(),
                    created_at: req.committed_at,
                },
            );
            if let Some(ref snap) = req.snapshot_name {
                st.snapshots.insert(
                    (req.volume.clone(), snap.clone()),
                    SnapshotRecord {
                        volume: req.volume.clone(),
                        name: snap.clone(),
                        root: next_head.root,
                        epoch: next_head.epoch,
                        created_at: req.committed_at,
                    },
                );
            }
            Ok(next_head)
        })
    }

    fn pin_ro_root<'a>(
        &'a self,
        volume: &'a VolumeId,
        snapshot: Option<&'a str>,
    ) -> BoxFuture<'a, (VolumeHead, Box<dyn RoPinGuard>)> {
        Box::pin(async move {
            let _gc = self.acquire_gc_lock(false).await?;
            let mut st = self.state.borrow_mut();
            if let Some(v) = st.format_version
                && v != COWFS_FORMAT_VERSION
            {
                return Err(Errno::EPROTONOSUPPORT);
            }
            let mut head = st.heads.get(volume).cloned().ok_or(Errno::ENOENT)?;
            if head.format_version != COWFS_FORMAT_VERSION {
                return Err(Errno::EPROTONOSUPPORT);
            }
            if let Some(snap_name) = snapshot {
                let snap = st
                    .snapshots
                    .get(&(volume.clone(), snap_name.to_string()))
                    .cloned()
                    .ok_or(Errno::ENOENT)?;
                head.root = snap.root;
                head.epoch = snap.epoch;
                head.updated_at = snap.created_at;
            }
            if !st.nodes.contains_key(&head.root) {
                return Err(Errno::ENOENT);
            }
            let pin_id = st.next_ro_pin;
            st.next_ro_pin += 1;
            st.ro_pins.insert(pin_id, (volume.clone(), head.root));
            Ok((
                head,
                Box::new(MemRoPinGuard {
                    state: Rc::clone(&self.state),
                    pin_id,
                }) as Box<dyn RoPinGuard>,
            ))
        })
    }

    fn unpin_ro_root<'a>(&'a self, pin: Box<dyn RoPinGuard>) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            drop(pin);
            Ok(())
        })
    }

    fn acquire_writer<'a>(
        &'a self,
        volume: &'a VolumeId,
        mode: WriterMode,
    ) -> BoxFuture<'a, WriterLease> {
        Box::pin(async move {
            let needs_gc = matches!(mode, WriterMode::ForkOnBusy);
            let _gc = if needs_gc {
                Some(self.acquire_gc_lock(false).await?)
            } else {
                None
            };
            let mut st = self.state.borrow_mut();
            if let Some(v) = st.format_version
                && v != COWFS_FORMAT_VERSION
            {
                return Err(Errno::EPROTONOSUPPORT);
            }
            let existing = st.heads.get(volume).cloned().ok_or(Errno::ENOENT)?;
            if existing.format_version != COWFS_FORMAT_VERSION {
                return Err(Errno::EPROTONOSUPPORT);
            }
            let held = st.active_locks.contains_key(volume);
            match (held, mode) {
                (true, WriterMode::Exclusive) => Err(Errno::EBUSY),
                (true, WriterMode::ForkOnBusy) => {
                    if !st.nodes.contains_key(&existing.root) {
                        return Err(Errno::ENOENT);
                    }
                    let fork_vol = loop {
                        let seq = st.next_fork_seq;
                        st.next_fork_seq += 1;
                        let candidate = VolumeId(format!("{}-fork-{seq}", volume.0));
                        if !st.heads.contains_key(&candidate)
                            && !st.active_locks.contains_key(&candidate)
                        {
                            break candidate;
                        }
                    };
                    let fork_head = VolumeHead {
                        format_version: COWFS_FORMAT_VERSION,
                        volume: fork_vol.clone(),
                        incarnation: 1,
                        fence: 1,
                        epoch: 0,
                        root: existing.root,
                        parent_volume: Some(volume.clone()),
                        ephemeral_if_unmodified: true,
                        modified: false,
                        updated_at: existing.updated_at,
                    };
                    st.heads.insert(fork_vol.clone(), fork_head.clone());
                    let token = st.next_lock_token;
                    st.next_lock_token += 1;
                    st.active_locks.insert(fork_vol.clone(), token);
                    Ok(WriterLease {
                        volume: fork_vol.clone(),
                        incarnation: fork_head.incarnation,
                        fence: fork_head.fence,
                        epoch: fork_head.epoch,
                        head: fork_head,
                        forked_from: Some(volume.clone()),
                        expires_at: None,
                        guard: Box::new(MemWriterGuard {
                            state: Rc::clone(&self.state),
                            volume: fork_vol,
                            token,
                        }),
                    })
                }
                (_, WriterMode::ForceTakeover) => {
                    let head = st.heads.get_mut(volume).ok_or(Errno::ENOENT)?;
                    head.fence = head.fence.saturating_add(1);
                    let updated = head.clone();
                    let token = st.next_lock_token;
                    st.next_lock_token += 1;
                    st.active_locks.insert(volume.clone(), token);
                    Ok(WriterLease {
                        volume: volume.clone(),
                        incarnation: updated.incarnation,
                        fence: updated.fence,
                        epoch: updated.epoch,
                        head: updated,
                        forked_from: None,
                        expires_at: None,
                        guard: Box::new(MemWriterGuard {
                            state: Rc::clone(&self.state),
                            volume: volume.clone(),
                            token,
                        }),
                    })
                }
                (false, WriterMode::Exclusive | WriterMode::ForkOnBusy) => {
                    let token = st.next_lock_token;
                    st.next_lock_token += 1;
                    st.active_locks.insert(volume.clone(), token);
                    Ok(WriterLease {
                        volume: volume.clone(),
                        incarnation: existing.incarnation,
                        fence: existing.fence,
                        epoch: existing.epoch,
                        head: existing,
                        forked_from: None,
                        expires_at: None,
                        guard: Box::new(MemWriterGuard {
                            state: Rc::clone(&self.state),
                            volume: volume.clone(),
                            token,
                        }),
                    })
                }
            }
        })
    }

    fn renew_writer<'a>(&'a self, lease: &'a mut WriterLease) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let st = self.state.borrow();
            let head = st.heads.get(&lease.volume).ok_or(Errno::ENOENT)?;
            if head.incarnation != lease.incarnation || head.fence != lease.fence {
                return Err(Errno::ESTALE);
            }
            Ok(())
        })
    }

    fn release_writer<'a>(&'a self, lease: WriterLease) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            drop(lease);
            Ok(())
        })
    }

    fn get_node<'a>(&'a self, digest: &'a Digest) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(async move {
            self.state
                .borrow()
                .nodes
                .get(digest)
                .map(|r| r.bytes.clone())
                .ok_or(Errno::ENOENT)
        })
    }

    fn lookup_block<'a>(&'a self, digest: &'a Digest) -> BoxFuture<'a, Option<BlockLoc>> {
        Box::pin(async move { Ok(self.state.borrow().blocks.get(digest).cloned()) })
    }

    fn commit_head<'a>(&'a self, req: &'a CommitRequest) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async move {
            let mut st = self.state.borrow_mut();
            if let Some(err) = st.fail_next_commit.take() {
                return Err(err);
            }
            if let Some(rec) = st.receipts.get(&req.op_id) {
                if rec.root != req.new_root {
                    return Err(Errno::EINVAL);
                }
                return Ok(rec.head.clone());
            }
            let cur = st.heads.get(&req.volume).cloned().ok_or(Errno::ENOENT)?;
            if cur.incarnation != req.expected_incarnation
                || cur.fence != req.expected_fence
                || cur.epoch != req.expected_epoch
            {
                return Err(Errno::ESTALE);
            }
            for (digest, bytes) in &req.put_nodes {
                st.nodes.entry(*digest).or_insert_with(|| NodeRecord {
                    bytes: bytes.clone(),
                    created_at: req.committed_at,
                });
            }
            for pm in &req.put_packs {
                st.packs
                    .entry(pm.pack_id.clone())
                    .or_insert_with(|| pm.clone());
            }
            for (digest, loc) in &req.put_blocks {
                st.blocks.entry(*digest).or_insert_with(|| loc.clone());
            }
            // Pin superseded root for grace window.
            let grace = st.grace_window_secs;
            if grace > 0 {
                st.grace_pins.push(GcRoot {
                    volume: req.volume.clone(),
                    root: cur.root,
                    pinned_until: Some(Timespec {
                        sec: req.committed_at.sec.saturating_add(grace),
                        nsec: req.committed_at.nsec,
                    }),
                });
            }
            let next_head = VolumeHead {
                format_version: COWFS_FORMAT_VERSION,
                volume: req.volume.clone(),
                incarnation: cur.incarnation,
                fence: cur.fence,
                epoch: cur.epoch.saturating_add(1),
                root: req.new_root,
                parent_volume: cur.parent_volume,
                ephemeral_if_unmodified: cur.ephemeral_if_unmodified,
                modified: true,
                updated_at: req.committed_at,
            };
            st.heads.insert(req.volume.clone(), next_head.clone());
            st.receipts.insert(
                req.op_id,
                ReceiptRecord {
                    volume: req.volume.clone(),
                    root: req.new_root,
                    head: next_head.clone(),
                    created_at: req.committed_at,
                },
            );
            if let Some(err) = st.fail_after_next_commit.take() {
                return Err(err);
            }
            Ok(next_head)
        })
    }

    fn create_snapshot<'a>(
        &'a self,
        volume: &'a VolumeId,
        name: &'a str,
        head: &'a VolumeHead,
        now: Timespec,
    ) -> BoxFuture<'a, SnapshotRecord> {
        Box::pin(async move {
            if name.is_empty() || name.contains(['/', '\0']) {
                return Err(Errno::EINVAL);
            }
            let mut st = self.state.borrow_mut();
            if st.heads.get(volume) != Some(head) {
                return Err(Errno::ESTALE);
            }
            let key = (volume.clone(), name.to_string());
            if st.snapshots.contains_key(&key) {
                return Err(Errno::EEXIST);
            }
            let rec = SnapshotRecord {
                volume: volume.clone(),
                name: name.to_string(),
                root: head.root,
                epoch: head.epoch,
                created_at: now,
            };
            st.snapshots.insert(key, rec.clone());
            Ok(rec)
        })
    }

    fn get_snapshot<'a>(
        &'a self,
        volume: &'a VolumeId,
        name: &'a str,
    ) -> BoxFuture<'a, SnapshotRecord> {
        Box::pin(async move {
            self.state
                .borrow()
                .snapshots
                .get(&(volume.clone(), name.to_string()))
                .cloned()
                .ok_or(Errno::ENOENT)
        })
    }

    fn list_snapshots<'a>(&'a self, volume: &'a VolumeId) -> BoxFuture<'a, Vec<SnapshotRecord>> {
        Box::pin(async move {
            let mut out: Vec<SnapshotRecord> = self
                .state
                .borrow()
                .snapshots
                .iter()
                .filter(|((v, _), _)| v == volume)
                .map(|(_, s)| s.clone())
                .collect();
            out.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(out)
        })
    }

    fn delete_snapshot<'a>(&'a self, volume: &'a VolumeId, name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.state
                .borrow_mut()
                .snapshots
                .remove(&(volume.clone(), name.to_string()))
                .map(|_| ())
                .ok_or(Errno::ENOENT)
        })
    }

    fn delete_snapshot_checked<'a>(
        &'a self,
        head: &'a VolumeHead,
        name: &'a str,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let mut st = self.state.borrow_mut();
            let cur = st.heads.get(&head.volume).ok_or(Errno::ENOENT)?;
            if (cur.incarnation, cur.fence) != (head.incarnation, head.fence) {
                return Err(Errno::ESTALE);
            }
            st.snapshots
                .remove(&(head.volume.clone(), name.to_owned()))
                .ok_or(Errno::ENOENT)?;
            Ok(())
        })
    }

    fn fork_volume<'a>(&'a self, req: &'a ForkRequest) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async move {
            let mut st = self.state.borrow_mut();
            if st.heads.contains_key(&req.new_volume) {
                return Err(Errno::EEXIST);
            }
            if !st.nodes.contains_key(&req.source_root) {
                return Err(Errno::ENOENT);
            }
            let head = VolumeHead {
                format_version: COWFS_FORMAT_VERSION,
                volume: req.new_volume.clone(),
                incarnation: 1,
                fence: 1,
                epoch: 0,
                root: req.source_root,
                parent_volume: Some(req.source_volume.clone()),
                ephemeral_if_unmodified: req.ephemeral_if_unmodified,
                modified: false,
                updated_at: req.created_at,
            };
            st.heads.insert(req.new_volume.clone(), head.clone());
            Ok(head)
        })
    }

    fn delete_volume<'a>(&'a self, volume: &'a VolumeId) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let mut st = self.state.borrow_mut();
            if st.active_locks.contains_key(volume) {
                return Err(Errno::EBUSY);
            }
            st.heads.remove(volume).ok_or(Errno::ENOENT)?;
            st.snapshots.retain(|(v, _), _| v != volume);
            st.receipts.retain(|_, r| &r.volume != volume);
            Ok(())
        })
    }

    fn delete_volume_with_lease<'a>(
        &'a self,
        lease: WriterLease,
        only_if_unmodified_ephemeral: bool,
    ) -> BoxFuture<'a, bool> {
        Box::pin(async move {
            let res = {
                let mut st = self.state.borrow_mut();
                let cur = st.heads.get(&lease.volume).cloned().ok_or(Errno::ENOENT)?;
                if cur.incarnation != lease.incarnation
                    || cur.fence != lease.fence
                    || cur.epoch != lease.epoch
                {
                    Err(Errno::ESTALE)
                } else if only_if_unmodified_ephemeral
                    && (!cur.ephemeral_if_unmodified
                        || cur.modified
                        || st.snapshots.keys().any(|(v, _)| v == &lease.volume)
                        || st.ro_pins.values().any(|(v, _)| v == &lease.volume))
                {
                    Ok(false)
                } else {
                    st.heads.remove(&lease.volume);
                    st.snapshots.retain(|(v, _), _| v != &lease.volume);
                    st.receipts.retain(|_, r| r.volume != lease.volume);
                    Ok(true)
                }
            };
            drop(lease);
            res
        })
    }

    fn reformat_volume_with_lease<'a>(
        &'a self,
        lease: WriterLease,
        new_head: &'a VolumeHead,
        initial_nodes: &'a [(Digest, Vec<u8>)],
    ) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async move {
            let res = {
                let mut st = self.state.borrow_mut();
                if let Some(v) = st.format_version
                    && v != COWFS_FORMAT_VERSION
                {
                    Err(Errno::EPROTONOSUPPORT)
                } else {
                    let cur = st.heads.get(&lease.volume).cloned().ok_or(Errno::ENOENT)?;
                    if cur.incarnation != lease.incarnation
                        || cur.fence != lease.fence
                        || cur.epoch != lease.epoch
                    {
                        Err(Errno::ESTALE)
                    } else if st.ro_pins.values().any(|(v, _)| v == &lease.volume) {
                        Err(Errno::EBUSY)
                    } else {
                        st.snapshots.retain(|(v, _), _| v != &lease.volume);
                        st.receipts.retain(|_, r| r.volume != lease.volume);
                        for (digest, bytes) in initial_nodes {
                            st.nodes.entry(*digest).or_insert_with(|| NodeRecord {
                                bytes: bytes.clone(),
                                created_at: new_head.updated_at,
                            });
                        }
                        let mut replaced = new_head.clone();
                        replaced.volume = lease.volume.clone();
                        replaced.incarnation = cur.incarnation.saturating_add(1);
                        replaced.fence = 1;
                        replaced.epoch = 0;
                        replaced.modified = false;
                        replaced.ephemeral_if_unmodified = false;
                        replaced.parent_volume = None;
                        st.heads.insert(lease.volume.clone(), replaced.clone());
                        Ok(replaced)
                    }
                }
            };
            drop(lease);
            res
        })
    }

    fn acquire_gc_lock(&self, exclusive: bool) -> BoxFuture<'_, Box<dyn GcLockGuard>> {
        Box::pin(async move {
            if exclusive {
                let mut st = self.state.borrow_mut();
                if st.gc_exclusive || st.gc_shared > 0 {
                    return Err(Errno::EBUSY);
                }
                st.gc_exclusive = true;
                return Ok(Box::new(MemGcGuard {
                    state: Rc::clone(&self.state),
                    exclusive: true,
                }) as Box<dyn GcLockGuard>);
            }
            // Shared writer GC lock waits cleanly while exclusive GC sweep finishes.
            poll_fn(|cx| {
                let mut st = self.state.borrow_mut();
                if st.gc_exclusive {
                    st.gc_waiters.push(cx.waker().clone());
                    Poll::Pending
                } else {
                    st.gc_shared += 1;
                    Poll::Ready(Ok(Box::new(MemGcGuard {
                        state: Rc::clone(&self.state),
                        exclusive: false,
                    }) as Box<dyn GcLockGuard>))
                }
            })
            .await
        })
    }

    fn list_all_roots(&self) -> BoxFuture<'_, Vec<GcRoot>> {
        Box::pin(async move {
            let st = self.state.borrow();
            let mut out = Vec::new();
            for head in st.heads.values() {
                out.push(GcRoot {
                    volume: head.volume.clone(),
                    root: head.root,
                    pinned_until: None,
                });
            }
            for snap in st.snapshots.values() {
                out.push(GcRoot {
                    volume: snap.volume.clone(),
                    root: snap.root,
                    pinned_until: None,
                });
            }
            for (vol, root) in st.ro_pins.values() {
                out.push(GcRoot {
                    volume: vol.clone(),
                    root: *root,
                    pinned_until: None,
                });
            }
            out.extend(st.grace_pins.iter().cloned());
            Ok(out)
        })
    }

    fn list_indexed_packs(&self) -> BoxFuture<'_, HashSet<PackId>> {
        Box::pin(async move {
            let st = self.state.borrow();
            let mut out: HashSet<PackId> = st.packs.keys().cloned().collect();
            for loc in st.blocks.values() {
                out.insert(loc.pack_id.clone());
            }
            Ok(out)
        })
    }

    fn prune_abandoned_ephemeral_forks(
        &self,
        now: Timespec,
        grace_window_secs: u64,
    ) -> BoxFuture<'_, usize> {
        Box::pin(async move {
            let mut st = self.state.borrow_mut();
            let dead: Vec<VolumeId> = st
                .heads
                .iter()
                .filter(|(vol, head)| {
                    head.ephemeral_if_unmodified
                        && !head.modified
                        && !st.active_locks.contains_key(*vol)
                        && !st.snapshots.keys().any(|(v, _)| v == *vol)
                        && !st.ro_pins.values().any(|(v, _)| v == *vol)
                        && ts_expired(head.updated_at, now, grace_window_secs)
                })
                .map(|(vol, _)| vol.clone())
                .collect();
            for vol in &dead {
                st.heads.remove(vol);
                st.snapshots.retain(|(v, _), _| v != vol);
                st.receipts.retain(|_, r| &r.volume != vol);
            }
            Ok(dead.len())
        })
    }

    fn sweep_metadata<'a>(
        &'a self,
        keep_nodes: &'a HashSet<Digest>,
        keep_packs: &'a HashSet<PackId>,
        now: Timespec,
        grace_window_secs: u64,
    ) -> BoxFuture<'a, Vec<PackId>> {
        Box::pin(async move {
            let mut st = self.state.borrow_mut();
            // Expire grace pins when `pinned_until <= now`.
            st.grace_pins
                .retain(|pin| pin.pinned_until.is_none_or(|until| until > now));
            // Sweep unreachable nodes whose `created_at + grace_window_secs <= now`.
            st.nodes.retain(|d, rec| {
                keep_nodes.contains(d) || !ts_expired(rec.created_at, now, grace_window_secs)
            });
            let mut swept = Vec::new();
            let mut kept_pack_ids = HashSet::new();
            for (pid, meta) in &st.packs {
                if keep_packs.contains(pid) || !ts_expired(meta.created_at, now, grace_window_secs)
                {
                    kept_pack_ids.insert(pid.clone());
                } else {
                    swept.push(pid.clone());
                }
            }
            st.packs.retain(|pid, _| kept_pack_ids.contains(pid));
            st.blocks
                .retain(|_, loc| kept_pack_ids.contains(&loc.pack_id));
            let live_epochs: HashMap<VolumeId, u64> =
                st.heads.iter().map(|(v, h)| (v.clone(), h.epoch)).collect();
            st.receipts.retain(|_, rec| {
                live_epochs.get(&rec.volume) == Some(&rec.head.epoch)
                    || !ts_expired(rec.created_at, now, grace_window_secs)
            });
            Ok(swept)
        })
    }
}

#[derive(Default)]
struct PackState {
    packs: HashMap<PackId, Vec<u8>>,
    bytes_written: u64,
    pack_writes: u64,
    bytes_read: u64,
    quota_bytes: Option<u64>,
    fail_next_write: Option<Errno>,
}

/// Fast in-memory test [`PackStore`] with byte counters, quota cap, and bit-flip / fault injection.
#[derive(Clone, Default)]
pub struct MemoryPackStore {
    state: Rc<RefCell<PackState>>,
}

impl MemoryPackStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_quota_bytes(&self, quota: Option<u64>) {
        self.state.borrow_mut().quota_bytes = quota;
    }

    pub fn fail_next_write(&self, err: Errno) {
        self.state.borrow_mut().fail_next_write = Some(err);
    }

    pub fn reset_counters(&self) {
        let mut st = self.state.borrow_mut();
        st.bytes_written = 0;
        st.pack_writes = 0;
        st.bytes_read = 0;
    }

    pub fn bytes_written(&self) -> u64 {
        self.state.borrow().bytes_written
    }

    pub fn pack_writes(&self) -> u64 {
        self.state.borrow().pack_writes
    }

    pub fn bytes_read(&self) -> u64 {
        self.state.borrow().bytes_read
    }

    pub fn pack_count(&self) -> usize {
        self.state.borrow().packs.len()
    }

    /// Flip one bit inside a stored pack to verify SHA-256 fail-closed `EIO`.
    pub fn corrupt_pack_byte(&self, pack_id: &PackId, offset: usize) -> bool {
        let mut st = self.state.borrow_mut();
        if let Some(bytes) = st.packs.get_mut(pack_id)
            && offset < bytes.len()
        {
            bytes[offset] ^= 0x01;
            return true;
        }
        false
    }
}

impl PackStore for MemoryPackStore {
    fn write_pack<'a>(&'a self, pack_id: &'a PackId, bytes: &'a [u8]) -> BoxFuture<'a, PackMeta> {
        Box::pin(async move {
            if bytes.len() > PACK_MAX_BYTES {
                return Err(Errno::EFBIG);
            }
            let mut st = self.state.borrow_mut();
            if let Some(err) = st.fail_next_write.take() {
                return Err(err);
            }
            if digest_to_hex(&sha256(bytes)) != pack_id.0 {
                return Err(Errno::EINVAL);
            }
            let trailer = decode_pack_trailer(bytes)?;
            let meta = PackMeta {
                pack_id: pack_id.clone(),
                size: bytes.len() as u32,
                entry_count: trailer.entries.len() as u32,
                created_at: Timespec { sec: 0, nsec: 0 },
            };
            let existing_valid = st.packs.get(pack_id).is_some_and(|existing| {
                existing.len() == bytes.len() && digest_to_hex(&sha256(existing)) == pack_id.0
            });
            if !existing_valid {
                if let Some(quota) = st.quota_bytes {
                    let current: u64 = st
                        .packs
                        .iter()
                        .filter(|(k, _)| *k != pack_id)
                        .map(|(_, p)| p.len() as u64)
                        .sum();
                    if current + bytes.len() as u64 > quota {
                        return Err(Errno::ENOSPC);
                    }
                }
                st.packs.insert(pack_id.clone(), bytes.to_vec());
                st.bytes_written += bytes.len() as u64;
                st.pack_writes += 1;
            }
            Ok(meta)
        })
    }

    fn read_pack_range<'a>(
        &'a self,
        pack_id: &'a PackId,
        offset: u32,
        len: u32,
    ) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let mut st = self.state.borrow_mut();
            let bytes = st.packs.get(pack_id).ok_or(Errno::ENOENT)?;
            let start = offset as usize;
            let end = start.checked_add(len as usize).ok_or(Errno::EIO)?;
            if end > bytes.len() {
                return Err(Errno::EIO);
            }
            let out = bytes[start..end].to_vec();
            st.bytes_read += out.len() as u64;
            Ok(out)
        })
    }

    fn read_pack_trailer<'a>(&'a self, pack_id: &'a PackId) -> BoxFuture<'a, PackTrailer> {
        Box::pin(async move {
            let st = self.state.borrow();
            let bytes = st.packs.get(pack_id).ok_or(Errno::ENOENT)?;
            decode_pack_trailer(bytes)
        })
    }

    fn stat_pack<'a>(&'a self, pack_id: &'a PackId) -> BoxFuture<'a, Option<u64>> {
        Box::pin(async move {
            Ok(self
                .state
                .borrow()
                .packs
                .get(pack_id)
                .map(|b| b.len() as u64))
        })
    }

    fn list_packs(&self) -> BoxFuture<'_, Vec<PackId>> {
        Box::pin(async move { Ok(self.state.borrow().packs.keys().cloned().collect()) })
    }

    fn delete_pack<'a>(&'a self, pack_id: &'a PackId) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.state.borrow_mut().packs.remove(pack_id);
            Ok(())
        })
    }
}
