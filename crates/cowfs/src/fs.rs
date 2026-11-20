//! Complete POSIX [`vfs::Filesystem`] driver (`CowFs`) layered over `os-cowtree` single-map
//! Merkle CoW B+trees and pluggable [`HeadStore`] / [`PackStore`] backends (`contract.md` §2.5,
//! §2.15, §3, §5; #77).

use crate::inode::{DirIndexValue, DirItemValue, ExtentDataValue, InodeItem};
use crate::orphan;
use abi::Errno;
use abi::contract::FsCapabilities;
use abi::fs::{
    Access, Conflict, DirEntry, DirPage, Entry, FILE_MAX, FileType, FsId, Handle, LockFamily,
    LockKind, LockRange, Metadata, NodeId, OpenOptions, OpenRef, RenameFlags, SetAttr, StatFs,
    Stop, Timespec, Walked, WriteAt, Written, XattrFlags, check_component,
};
use abi::volume::CowfsInfoResp;
use cowtree::{
    Arena, ArenaConfig, ArenaStats, BLOCK_SIZE, COWFS_FORMAT_VERSION, CommitRequest, CowTree,
    Digest, ForkRequest, HeadStore, INLINE_MAX_BYTES, KIND_DIR_INDEX, KIND_DIR_ITEM,
    KIND_EXTENT_DATA, KIND_INODE_REF, KIND_XATTR_ITEM, Node, PackBuilder, PackMeta, PackStore,
    RootObject, SnapshotRecord, TreeKey, TreeOverlay, VolumeHead, VolumeId, WriterLease,
    WriterMode, digest_to_hex, sha256, verify_block_digest,
};
use os_core::acl::Entries;
use os_core::inode;
use os_core::permissions::{EXEC, Identity, Node as PermNode, READ, WRITE, created};
use os_core::xattr::{self, Space};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};
use vfs::{BoxFuture, Cred, DIR_PAGE_MAX, Filesystem, Result, profiles};

/// Root directory inode number inside every `os-cowfs` subvolume.
pub const ROOT_INO: u64 = 1;
/// Default primary subvolume name (`contract.md` §2.15).
pub const DEFAULT_SUBVOL: &str = "@";
/// Max single read/write byte count (Linux `MAX_RW_COUNT`).
const RW_MAX: usize = 0x7fff_f000;

/// Monotonic global open-ref counter so an `OpenRef` from an earlier mount can never collide with
/// a fresh mount (`EBADF`).
static NEXT_OPEN_ID: AtomicU64 = AtomicU64::new(1);

/// Clock returning `(sec, nsec)` since Unix epoch.
pub type CowFsClock = Rc<dyn Fn() -> Timespec>;

pub fn zero_clock() -> CowFsClock {
    Rc::new(|| Timespec { sec: 0, nsec: 0 })
}

/// Mount mode for opening an `os-cowfs` volume.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CowFsOpenMode {
    ReadWrite(WriterMode),
    ReadOnly,
    Snapshot(String),
}

/// Configuration for opening a [`CowFs`] instance.
#[derive(Clone)]
pub struct CowFsConfig {
    pub subvol: String,
    pub capabilities: FsCapabilities,
    pub arena: ArenaConfig,
    pub clock: CowFsClock,
    /// Optional logical capacity ceiling (bytes) reported in `statfs` and enforced on write.
    pub capacity_bytes: Option<u64>,
}

impl CowFsConfig {
    pub fn local_native(clock: CowFsClock) -> Self {
        Self {
            subvol: DEFAULT_SUBVOL.to_string(),
            capabilities: profiles::COWFS_LOCAL_NATIVE,
            arena: ArenaConfig::platform_default(),
            clock,
            capacity_bytes: None,
        }
    }

    pub fn local_browser(clock: CowFsClock) -> Self {
        Self {
            subvol: DEFAULT_SUBVOL.to_string(),
            capabilities: profiles::COWFS_LOCAL_BROWSER,
            arena: ArenaConfig::fixed_32mib(),
            clock,
            capacity_bytes: None,
        }
    }

    pub fn with_arena(mut self, arena: ArenaConfig) -> Self {
        self.arena = arena;
        self
    }

    pub fn with_subvol(mut self, subvol: impl Into<String>) -> Self {
        self.subvol = subvol.into();
        self
    }

    pub fn with_capacity(mut self, bytes: u64) -> Self {
        self.capacity_bytes = Some(bytes);
        self
    }
}

struct OpenRecord {
    ino: u64,
    generation: u64,
    access: Access,
    cred: Identity,
}

#[derive(Clone, Copy)]
struct Lock {
    owner: u64,
    family: LockFamily,
    kind: LockKind,
    range: LockRange,
}

impl Lock {
    fn conflicts(self, other: Lock) -> bool {
        self.owner != other.owner
            && self.family == other.family
            && self.range.overlaps(other.range)
            && (self.kind == LockKind::Exclusive || other.kind == LockKind::Exclusive)
    }
}

struct Waiter {
    ino: u64,
    lock: Lock,
    waker: Waker,
}

fn carve(locks: &mut Vec<Lock>, owner: u64, family: LockFamily, range: LockRange) {
    let mut pieces = Vec::new();
    locks.retain(|lock| {
        let cut = lock.owner == owner && lock.family == family && lock.range.overlaps(range);
        if cut {
            pieces.extend(
                lock.range
                    .minus(range)
                    .into_iter()
                    .flatten()
                    .map(|rest| Lock {
                        range: rest,
                        ..*lock
                    }),
            );
        }
        !cut
    });
    locks.extend(pieces);
}

#[derive(Default)]
struct AsyncMutex {
    held: Cell<bool>,
    next_id: Cell<u64>,
    waiters: RefCell<BTreeMap<u64, Waker>>,
}

struct AsyncMutexGuard<'a>(&'a AsyncMutex);
struct AsyncMutexWait<'a> {
    lock: &'a AsyncMutex,
    id: u64,
}

impl Drop for AsyncMutexWait<'_> {
    fn drop(&mut self) {
        self.lock.waiters.borrow_mut().remove(&self.id);
    }
}

impl Drop for AsyncMutexGuard<'_> {
    fn drop(&mut self) {
        self.0.held.set(false);
        for waker in self.0.waiters.take().into_values() {
            waker.wake();
        }
    }
}

impl AsyncMutex {
    async fn lock(&self) -> AsyncMutexGuard<'_> {
        let id = self.next_id.get();
        self.next_id.set(id.wrapping_add(1));
        let _wait = AsyncMutexWait { lock: self, id };
        poll_fn(|cx| {
            if self.held.replace(true) {
                self.waiters.borrow_mut().insert(id, cx.waker().clone());
                Poll::Pending
            } else {
                Poll::Ready(AsyncMutexGuard(self))
            }
        })
        .await
    }
}

struct CowFsState {
    head: VolumeHead,
    root_obj: RootObject,
    subvol_root: Digest,
    lease: Option<WriterLease>,
    forked_from: Option<VolumeId>,
    fenced: bool,
    /// True once an explicit user mutation (not an internal `relatime` update) has been staged.
    user_modified: bool,
    overlay: TreeOverlay,
    /// Uncommitted data blocks keyed by SHA-256 digest: `(bytes, refcount)`.
    dirty_blocks: HashMap<Digest, (Rc<Vec<u8>>, usize)>,
    dirty_block_bytes: usize,
    /// Open-file reference tracking (per-mount instance).
    opens: HashMap<u64, OpenRecord>,
    open_counts: HashMap<u64, u32>,
    locks: HashMap<u64, Vec<Lock>>,
    waiters: HashMap<u64, Waiter>,
    next_waiter: u64,
    /// Approximate allocated data blocks (for `statfs` & optional capacity checks).
    allocated_bytes: u64,
    inode_count_estimate: u64,
}

impl CowFsState {
    fn stage_dirty_block(&mut self, digest: Digest, bytes: Rc<Vec<u8>>) {
        if let Some((_, count)) = self.dirty_blocks.get_mut(&digest) {
            *count += 1;
        } else {
            let sz = bytes.len();
            self.dirty_blocks.insert(digest, (bytes, 1));
            self.dirty_block_bytes += sz;
        }
    }

    fn unstage_dirty_block(&mut self, digest: &Digest) {
        let remove = if let Some((_, count)) = self.dirty_blocks.get_mut(digest) {
            *count = count.saturating_sub(1);
            *count == 0
        } else {
            false
        };
        if remove && let Some((bytes, _)) = self.dirty_blocks.remove(digest) {
            self.dirty_block_bytes = self.dirty_block_bytes.saturating_sub(bytes.len());
        }
    }

    fn total_dirty_bytes(&self) -> usize {
        self.overlay.dirty_bytes() + self.dirty_block_bytes
    }

    fn is_dirty(&self) -> bool {
        !self.overlay.is_empty() || !self.dirty_blocks.is_empty()
    }

    fn deadlocks(&self, ino: u64, wanted: Lock) -> bool {
        let mut pending = vec![(ino, wanted)];
        let mut visited = HashSet::new();
        while let Some((ino, wanted_lock)) = pending.pop() {
            for held in self.locks.get(&ino).into_iter().flatten() {
                if !held.conflicts(wanted_lock) {
                    continue;
                }
                if held.owner == wanted.owner {
                    return true;
                }
                if visited.insert(held.owner) {
                    pending.extend(self.waiters.values().filter_map(|waiter| {
                        (waiter.lock.owner == held.owner && waiter.lock.family == wanted.family)
                            .then_some((waiter.ino, waiter.lock))
                    }));
                }
            }
        }
        false
    }
}

/// MIT pure-Rust POSIX Copy-on-Write filesystem driver (`FsType::Cowfs`).
pub struct CowFs<H: HeadStore + 'static, P: PackStore + 'static> {
    fs_id: FsId,
    volume_id: VolumeId,
    subvol: String,
    read_only: bool,
    /// Set when mounted via `CowFsOpenMode::Snapshot(name)`; pins the mount immutably to that snapshot.
    pinned_snapshot: Option<String>,
    capabilities: FsCapabilities,
    capacity_bytes: Option<u64>,
    root_generation: u64,
    clock: CowFsClock,
    head_store: Rc<H>,
    pack_store: Rc<P>,
    arena: RefCell<Arena>,
    state: RefCell<CowFsState>,
    commit_lock: AsyncMutex,
}

impl<H: HeadStore + 'static, P: PackStore + 'static> CowFs<H, P> {
    /// Initialize a brand-new `os-cowfs` volume (`mkfs.cowfs`) with root directory inode `1`.
    pub async fn format_volume(
        head_store: &H,
        _pack_store: &P,
        volume: VolumeId,
        root_uid: u32,
        root_gid: u32,
        root_mode: u16,
        now: Timespec,
    ) -> Result<VolumeHead> {
        if let Some(v) = head_store.format_version().await?
            && v != COWFS_FORMAT_VERSION
        {
            return Err(Errno::EPROTONOSUPPORT);
        }
        let root_inode = InodeItem {
            file_type: FileType::Dir,
            mode: root_mode & 0o7777,
            nlink: 2,
            uid: root_uid,
            gid: root_gid,
            size: 0,
            generation: 1,
            atime: now,
            mtime: now,
            ctime: now,
            rdev: None,
            symlink_target: None,
            next_dir_index: 1,
            acl_present: false,
            default_acl_present: false,
        };
        let leaf = Node::Leaf {
            entries: vec![cowtree::LeafEntry {
                key: TreeKey::inode_item(ROOT_INO),
                value: root_inode.encode(),
            }],
        };
        let (leaf_digest, leaf_bytes) = leaf.encode()?;

        let mut subvols = BTreeMap::new();
        subvols.insert(DEFAULT_SUBVOL.to_string(), leaf_digest);
        let root_obj = RootObject {
            format_version: COWFS_FORMAT_VERSION,
            features: 0,
            volume_uuid: volume.0.clone(),
            subvols,
            next_ino: ROOT_INO + 1,
            generation: 1,
            parent_root: None,
        };
        let (root_digest, root_bytes) = root_obj.encode()?;

        let head = VolumeHead {
            format_version: COWFS_FORMAT_VERSION,
            volume: volume.clone(),
            incarnation: 1,
            fence: 1,
            epoch: 0,
            root: root_digest,
            parent_volume: None,
            ephemeral_if_unmodified: false,
            modified: false,
            updated_at: now,
        };
        head_store
            .create_volume(
                &head,
                &[(leaf_digest, leaf_bytes), (root_digest, root_bytes)],
            )
            .await
    }

    /// Open a `cowfs` volume in read-write, read-only, or pinned-snapshot mode.
    pub async fn open(
        head_store: Rc<H>,
        pack_store: Rc<P>,
        volume: VolumeId,
        mode: CowFsOpenMode,
        config: CowFsConfig,
    ) -> Result<Self> {
        if let Some(v) = head_store.format_version().await?
            && v != COWFS_FORMAT_VERSION
        {
            return Err(Errno::EPROTONOSUPPORT);
        }

        let (
            head,
            root_digest,
            lease,
            forked_from,
            read_only,
            pinned_snapshot,
            capabilities,
            fs_id,
        ) = match mode {
            CowFsOpenMode::ReadWrite(writer_mode) => {
                let lease = head_store.acquire_writer(&volume, writer_mode).await?;
                if lease.head.format_version != COWFS_FORMAT_VERSION {
                    let _ = head_store.release_writer(lease).await;
                    return Err(Errno::EPROTONOSUPPORT);
                }
                let head = lease.head.clone();
                let root_digest = head.root;
                let forked_from = lease.forked_from.clone();
                let fs_id = FsId(format!("cowfs:{}", head.volume.0));
                (
                    head,
                    root_digest,
                    Some(lease),
                    forked_from,
                    false,
                    None,
                    config.capabilities,
                    fs_id,
                )
            }
            CowFsOpenMode::ReadOnly => {
                let head = head_store.read_head(&volume).await?;
                if head.format_version != COWFS_FORMAT_VERSION {
                    return Err(Errno::EPROTONOSUPPORT);
                }
                let root_digest = head.root;
                let fs_id = FsId(format!(
                    "cowfs:{}@{}",
                    head.volume.0,
                    digest_to_hex(&root_digest)
                ));
                let mut caps = profiles::COWFS_SNAPSHOT;
                caps.durability = config.capabilities.durability;
                (head, root_digest, None, None, true, None, caps, fs_id)
            }
            CowFsOpenMode::Snapshot(snap_name) => {
                let mut head = head_store.read_head(&volume).await?;
                if head.format_version != COWFS_FORMAT_VERSION {
                    return Err(Errno::EPROTONOSUPPORT);
                }
                let snap = head_store.get_snapshot(&volume, &snap_name).await?;
                let root_digest = snap.root;
                head.root = snap.root;
                head.epoch = snap.epoch;
                head.updated_at = snap.created_at;
                let fs_id = FsId(format!(
                    "cowfs:{}@{}",
                    volume.0,
                    digest_to_hex(&root_digest)
                ));
                let mut caps = profiles::COWFS_SNAPSHOT;
                caps.durability = config.capabilities.durability;
                (
                    head,
                    root_digest,
                    None,
                    None,
                    true,
                    Some(snap_name),
                    caps,
                    fs_id,
                )
            }
        };

        let raw_root = match head_store.get_node(&root_digest).await {
            Ok(bytes) => bytes,
            Err(e) => {
                if let Some(l) = lease {
                    let _ = head_store.release_writer(l).await;
                }
                return Err(e);
            }
        };
        let root_obj = match RootObject::decode_verified(&root_digest, &raw_root) {
            Ok(r) => r,
            Err(e) => {
                if let Some(l) = lease {
                    let _ = head_store.release_writer(l).await;
                }
                return Err(e);
            }
        };
        let Some(&subvol_root) = root_obj.subvols.get(&config.subvol) else {
            if let Some(l) = lease {
                let _ = head_store.release_writer(l).await;
            }
            return Err(Errno::ENOENT);
        };

        let arena = RefCell::new(Arena::new(config.arena));
        let tree = CowTree::new(&*head_store, &arena);
        let root_raw = match tree.get(&subvol_root, &TreeKey::inode_item(ROOT_INO)).await {
            Ok(Some(b)) => b,
            Ok(None) => {
                if let Some(l) = lease {
                    let _ = head_store.release_writer(l).await;
                }
                return Err(Errno::EIO);
            }
            Err(e) => {
                if let Some(l) = lease {
                    let _ = head_store.release_writer(l).await;
                }
                return Err(e);
            }
        };
        let root_inode = match InodeItem::decode(&root_raw) {
            Ok(i) => i,
            Err(e) => {
                if let Some(l) = lease {
                    let _ = head_store.release_writer(l).await;
                }
                return Err(e);
            }
        };

        let actual_volume = head.volume.clone();
        let initial_modified = head.modified;
        let fs = Self {
            fs_id,
            volume_id: actual_volume,
            subvol: config.subvol,
            read_only,
            pinned_snapshot,
            capabilities,
            capacity_bytes: config.capacity_bytes,
            root_generation: root_inode.generation,
            clock: config.clock,
            head_store,
            pack_store,
            arena,
            state: RefCell::new(CowFsState {
                head,
                root_obj,
                subvol_root,
                lease,
                forked_from,
                fenced: false,
                user_modified: initial_modified,
                overlay: TreeOverlay::new(),
                dirty_blocks: HashMap::new(),
                dirty_block_bytes: 0,
                opens: HashMap::new(),
                open_counts: HashMap::new(),
                locks: HashMap::new(),
                waiters: HashMap::new(),
                next_waiter: 1,
                allocated_bytes: 0,
                inode_count_estimate: 1,
            }),
            commit_lock: AsyncMutex::default(),
        };

        // On RW mount, reap any persisted `ORPHAN_ITEM`s left behind by an earlier crash while
        // unlinked files were still open (contract §2.15, §3).
        if !read_only {
            let reaped = fs.reap_orphans_on_mount().await?;
            if reaped > 0 {
                fs.commit_tx_group().await?;
            }
        }
        Ok(fs)
    }

    pub fn volume_id(&self) -> &VolumeId {
        &self.volume_id
    }

    pub fn forked_from(&self) -> Option<VolumeId> {
        self.state.borrow().forked_from.clone()
    }

    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    pub fn head_store_rc(&self) -> Rc<H> {
        Rc::clone(&self.head_store)
    }

    pub fn pack_store_rc(&self) -> Rc<P> {
        Rc::clone(&self.pack_store)
    }

    pub fn clock_rc(&self) -> CowFsClock {
        Rc::clone(&self.clock)
    }

    pub fn current_head(&self) -> VolumeHead {
        self.state.borrow().head.clone()
    }

    pub fn arena_stats(&self) -> ArenaStats {
        self.arena.borrow().stats()
    }

    /// Clear clean caches (tree LRU + clean data cache) — useful for cold-read benchmarks/tests.
    pub fn drop_clean_caches(&self) {
        self.arena.borrow_mut().clear_clean_caches();
    }

    pub fn volume_info(&self) -> CowfsInfoResp {
        let st = self.state.borrow();
        CowfsInfoResp {
            format_version: st.head.format_version,
            volume: st.head.volume.0.clone(),
            root: digest_to_hex(&st.head.root),
            incarnation: st.head.incarnation,
            fence: st.head.fence,
            epoch: st.head.epoch,
            writer_model: self.capabilities.writer_model,
            durability: self.capabilities.durability,
            read_only: self.read_only,
            parent_volume: st.head.parent_volume.as_ref().map(|v| v.0.clone()),
        }
    }

    /// Refresh an RO view to the volume's latest committed head (`-o remount,refresh`).
    /// Named snapshot mounts are pinned immutably and reject refresh (`EINVAL`).
    pub async fn refresh_ro(&self) -> Result<VolumeHead> {
        if !self.read_only || self.pinned_snapshot.is_some() {
            return Err(Errno::EINVAL);
        }
        let latest = self.head_store.read_head(&self.volume_id).await?;
        let raw_root = self.head_store.get_node(&latest.root).await?;
        let root_obj = RootObject::decode_verified(&latest.root, &raw_root)?;
        let &subvol_root = root_obj.subvols.get(&self.subvol).ok_or(Errno::ENOENT)?;
        let mut st = self.state.borrow_mut();
        st.head = latest.clone();
        st.root_obj = root_obj;
        st.subvol_root = subvol_root;
        Ok(latest)
    }

    /// Create an O(1) named snapshot (`name -> root_digest`), committing any dirty state first.
    pub async fn create_snapshot(&self, name: &str) -> Result<SnapshotRecord> {
        if self.read_only {
            return Err(Errno::EROFS);
        }
        self.commit_tx_group().await?;
        let head = self.state.borrow().head.clone();
        let now = (self.clock)();
        self.head_store
            .create_snapshot(&self.volume_id, name, &head, now)
            .await
    }

    /// Create an O(1) persistent fork volume seeded from `snapshot` (or current committed head).
    /// Zero data bytes are copied.
    pub async fn fork_volume(
        &self,
        snapshot: Option<&str>,
        new_volume: VolumeId,
        ephemeral_if_unmodified: bool,
    ) -> Result<VolumeHead> {
        if !self.read_only && snapshot.is_none() {
            self.commit_tx_group().await?;
        }
        let source_root = match snapshot {
            Some(snap_name) => {
                self.head_store
                    .get_snapshot(&self.volume_id, snap_name)
                    .await?
                    .root
            }
            None => self.state.borrow().head.root,
        };
        let req = ForkRequest {
            source_volume: self.volume_id.clone(),
            source_snapshot: snapshot
                .map(str::to_owned)
                .or_else(|| self.pinned_snapshot.clone()),
            source_root,
            new_volume,
            ephemeral_if_unmodified,
            created_at: (self.clock)(),
        };
        self.head_store.fork_volume(&req).await
    }

    /// Commit any dirty transaction group, release the writer lease, and auto-prune an unmodified
    /// ephemeral tab fork (`ephemeral_if_unmodified && !modified`, contract §2.1, Blueprint §3.2).
    pub async fn close_clean(&self) -> Result<()> {
        let (should_commit, should_prune) = {
            let st = self.state.borrow();
            let prune = st.head.ephemeral_if_unmodified && !st.head.modified && !st.user_modified;
            let commit = !self.read_only && !st.fenced && !prune && st.is_dirty();
            (commit, prune)
        };
        if should_commit {
            self.commit_tx_group().await?;
        }
        let (lease, vol) = {
            let mut st = self.state.borrow_mut();
            let lease = st.lease.take();
            (lease, st.head.volume.clone())
        };
        if let Some(l) = lease {
            self.head_store.release_writer(l).await?;
        }
        if should_prune {
            let _ = self.head_store.delete_volume(&vol).await;
        }
        Ok(())
    }

    /// Commit the current dirty transaction group atomically (`PackStore::write_pack` ->
    /// CoW B+tree node generation -> `HeadStore::commit_head` CAS).
    pub async fn commit_tx_group(&self) -> Result<VolumeHead> {
        if self.read_only {
            return Ok(self.state.borrow().head.clone());
        }
        let _guard = self.commit_lock.lock().await;
        self.commit_tx_group_locked().await
    }

    async fn commit_tx_group_locked(&self) -> Result<VolumeHead> {
        let (fenced, skip_commit, head_snap, subvol_root, root_obj_snap) = {
            let st = self.state.borrow();
            let ephemeral_atime_only =
                st.head.ephemeral_if_unmodified && !st.head.modified && !st.user_modified;
            (
                st.fenced,
                !st.is_dirty() || ephemeral_atime_only,
                st.head.clone(),
                st.subvol_root,
                st.root_obj.clone(),
            )
        };
        if fenced {
            return Err(Errno::ESTALE);
        }
        if skip_commit {
            // Even when clean, verify our writer fence hasn't been stolen (`ESTALE`).
            let latest = self.head_store.read_head(&self.volume_id).await?;
            if latest.incarnation != head_snap.incarnation || latest.fence != head_snap.fence {
                self.state.borrow_mut().fenced = true;
                return Err(Errno::ESTALE);
            }
            return Ok(head_snap);
        }

        // Acquire shared GC lock across pack write + head CAS so GC never sweeps in-flight packs.
        let _gc_guard = self.head_store.acquire_gc_lock(false).await?;

        // Snapshot dirty blocks & sorted overlay ops without clearing until CAS succeeds.
        let (dirty_blocks_snap, sorted_ops) = {
            let st = self.state.borrow();
            let blocks: Vec<(Digest, Rc<Vec<u8>>)> = st
                .dirty_blocks
                .iter()
                .map(|(d, (b, _))| (*d, Rc::clone(b)))
                .collect();
            let ops = st.overlay.clone_sorted_ops();
            (blocks, ops)
        };

        // 1. Pack & flush any new dirty data blocks (skipping intra-store dedupe hits).
        let mut builder = PackBuilder::new();
        for (digest, bytes) in &dirty_blocks_snap {
            if self.head_store.lookup_block(digest).await?.is_none() {
                builder.push(*digest, bytes)?;
            }
        }
        let built_packs = builder.finish()?;
        let now = (self.clock)();
        let mut put_packs: Vec<PackMeta> = Vec::with_capacity(built_packs.len());
        let mut put_blocks = Vec::new();
        for built in &built_packs {
            let mut meta = self
                .pack_store
                .write_pack(&built.pack_id, &built.bytes)
                .await?;
            meta.created_at = now;
            put_packs.push(meta);
            put_blocks.extend(built.locations.iter().cloned());
        }

        // 2. Apply sorted mutations to CoW B+tree (leaves -> parents -> new subvol root).
        let tree = CowTree::new(&*self.head_store, &self.arena);
        let (new_subvol_root, mut put_nodes) = tree.apply_batch(&subvol_root, &sorted_ops).await?;

        let mut next_root_obj = root_obj_snap;
        next_root_obj
            .subvols
            .insert(self.subvol.clone(), new_subvol_root);
        next_root_obj.parent_root = Some(head_snap.root);
        let (new_root_digest, root_bytes) = next_root_obj.encode()?;
        put_nodes.push((new_root_digest, root_bytes));

        // 3. Atomic strict HeadStore CAS checked against `(incarnation, fence, epoch)`.
        // Derive a globally collision-free idempotency key across tabs/processes/restarts from
        // `(volume, incarnation, fence, epoch, new_root_digest)`.
        let mut op_seed = Vec::with_capacity(16 + self.volume_id.0.len() + 64);
        op_seed.extend_from_slice(b"os-cowfs-op-v1\0");
        op_seed.extend_from_slice(&(self.volume_id.0.len() as u32).to_be_bytes());
        op_seed.extend_from_slice(self.volume_id.0.as_bytes());
        op_seed.extend_from_slice(&head_snap.incarnation.to_be_bytes());
        op_seed.extend_from_slice(&head_snap.fence.to_be_bytes());
        op_seed.extend_from_slice(&head_snap.epoch.to_be_bytes());
        op_seed.extend_from_slice(&new_root_digest);
        let op_hash = sha256(&op_seed);
        let mut op_id = [0u8; 16];
        op_id.copy_from_slice(&op_hash[..16]);

        let commit_req = CommitRequest {
            op_id,
            volume: self.volume_id.clone(),
            expected_incarnation: head_snap.incarnation,
            expected_fence: head_snap.fence,
            expected_epoch: head_snap.epoch,
            new_root: new_root_digest,
            put_nodes,
            put_packs,
            put_blocks,
            committed_at: now,
        };
        let committed_head = match self.head_store.commit_head(&commit_req).await {
            Ok(h) => h,
            Err(Errno::ESTALE) => {
                self.state.borrow_mut().fenced = true;
                return Err(Errno::ESTALE);
            }
            Err(e) => return Err(e),
        };

        // 4. Advance in-memory committed state and move flushed blocks to clean LRU cache.
        {
            let mut st = self.state.borrow_mut();
            st.head = committed_head.clone();
            st.root_obj = next_root_obj;
            st.subvol_root = new_subvol_root;
            if let Some(lease) = st.lease.as_mut() {
                lease.epoch = committed_head.epoch;
                lease.head = committed_head.clone();
            }
            st.overlay.clear();
            let old_dirty = std::mem::take(&mut st.dirty_blocks);
            st.dirty_block_bytes = 0;
            let mut arena = self.arena.borrow_mut();
            arena.set_dirty_bytes(0);
            for (d, (bytes, _)) in old_dirty {
                arena.put_data(d, bytes);
            }
        }
        Ok(committed_head)
    }

    fn sync_arena_dirty(&self) {
        let bytes = self.state.borrow().total_dirty_bytes();
        self.arena.borrow_mut().set_dirty_bytes(bytes);
    }

    async fn maybe_backpressure_flush(&self, incoming_bytes: usize) -> Result<()> {
        if self.read_only {
            return Ok(());
        }
        if self.arena.borrow().needs_backpressure_flush(incoming_bytes) {
            self.commit_tx_group().await?;
            self.arena.borrow_mut().record_backpressure_flush();
        }
        Ok(())
    }

    async fn reap_orphans_on_mount(&self) -> Result<usize> {
        let subvol_root = self.state.borrow().subvol_root;
        let tree = CowTree::new(&*self.head_store, &self.arena);
        let mut overlay = TreeOverlay::new();
        let reaped = orphan::reap_all_orphans(&tree, &subvol_root, &mut overlay).await?;
        if reaped > 0 {
            let mut st = self.state.borrow_mut();
            for (k, v) in overlay.take_sorted_ops() {
                match v {
                    Some(val) => st.overlay.put(k, val),
                    None => st.overlay.delete(k),
                }
            }
            let dirty = st.total_dirty_bytes();
            self.arena.borrow_mut().set_dirty_bytes(dirty);
        }
        Ok(reaped)
    }

    // -------------------------------------------------------------------------
    // Tree & inode helpers (never hold RefCell borrows across `.await`)
    // -------------------------------------------------------------------------

    async fn tree_get(&self, key: &TreeKey) -> Result<Option<Vec<u8>>> {
        let (staged, base_root) = {
            let st = self.state.borrow();
            if let Some(opt) = st.overlay.get(key) {
                return Ok(opt.map(|v| v.to_vec()));
            }
            (None::<()>, st.subvol_root)
        };
        let _ = staged;
        let tree = CowTree::new(&*self.head_store, &self.arena);
        tree.get(&base_root, key).await
    }

    async fn tree_scan(
        &self,
        start: &TreeKey,
        end: &TreeKey,
        limit: usize,
    ) -> Result<Vec<(TreeKey, Vec<u8>)>> {
        let (base_root, overlay_clone) = {
            let st = self.state.borrow();
            (st.subvol_root, st.overlay.clone())
        };
        let tree = CowTree::new(&*self.head_store, &self.arena);
        tree.scan_range_with_overlay(&base_root, &overlay_clone, start, end, limit)
            .await
    }

    async fn tree_find_le(
        &self,
        min_key: &TreeKey,
        max_key: &TreeKey,
    ) -> Result<Option<(TreeKey, Vec<u8>)>> {
        let (base_root, overlay_clone) = {
            let st = self.state.borrow();
            (st.subvol_root, st.overlay.clone())
        };
        let tree = CowTree::new(&*self.head_store, &self.arena);
        tree.find_le_with_overlay(&base_root, &overlay_clone, min_key, max_key)
            .await
    }

    async fn load_inode(&self, ino: u64) -> Result<Option<InodeItem>> {
        let Some(raw) = self.tree_get(&TreeKey::inode_item(ino)).await? else {
            return Ok(None);
        };
        InodeItem::decode(&raw).map(Some)
    }

    async fn load_perm_node(&self, ino: u64, item: &InodeItem) -> Result<PermNode> {
        let acl_entries = if item.acl_present {
            match self
                .tree_get(&TreeKey::xattr_item(ino, abi::ACL_ACCESS))
                .await?
            {
                Some(raw) => Some(serde_json::from_slice::<Entries>(&raw).map_err(|_| Errno::EIO)?),
                None => None,
            }
        } else {
            None
        };
        let default_acl = if item.default_acl_present {
            match self
                .tree_get(&TreeKey::xattr_item(ino, abi::ACL_DEFAULT))
                .await?
            {
                Some(raw) => Some(serde_json::from_slice::<Entries>(&raw).map_err(|_| Errno::EIO)?),
                None => None,
            }
        } else {
            None
        };
        Ok(item.to_perm_node(ino, acl_entries, default_acl))
    }

    fn stage_perm_acls(&self, ino: u64, node: &PermNode) -> Result<()> {
        let mut st = self.state.borrow_mut();
        st.user_modified = true;
        if node.acl.is_some() {
            let entries = node.entries();
            let raw = serde_json::to_vec(&entries).map_err(|_| Errno::EIO)?;
            st.overlay
                .put(TreeKey::xattr_item(ino, abi::ACL_ACCESS), raw);
        } else {
            st.overlay.delete(TreeKey::xattr_item(ino, abi::ACL_ACCESS));
        }
        if let Some(ref def) = node.default_acl {
            let raw = serde_json::to_vec(def).map_err(|_| Errno::EIO)?;
            st.overlay
                .put(TreeKey::xattr_item(ino, abi::ACL_DEFAULT), raw);
        } else {
            st.overlay
                .delete(TreeKey::xattr_item(ino, abi::ACL_DEFAULT));
        }
        drop(st);
        self.sync_arena_dirty();
        Ok(())
    }

    fn stage_inode(&self, ino: u64, item: &InodeItem) {
        {
            let mut st = self.state.borrow_mut();
            st.user_modified = true;
            st.overlay.put(TreeKey::inode_item(ino), item.encode());
        }
        self.sync_arena_dirty();
    }

    fn stage_inode_atime(&self, ino: u64, item: &InodeItem) {
        self.state
            .borrow_mut()
            .overlay
            .put(TreeKey::inode_item(ino), item.encode());
        self.sync_arena_dirty();
    }

    fn handle_for(&self, ino: u64, generation: u64) -> Handle {
        Handle {
            fs: self.fs_id.clone(),
            node: NodeId { ino, generation },
            proof: String::new(),
        }
    }

    fn entry_for(&self, ino: u64, item: &InodeItem) -> Entry {
        Entry {
            handle: self.handle_for(ino, item.generation),
            metadata: item.to_metadata(),
        }
    }

    async fn check_handle(&self, handle: &Handle) -> Result<(u64, InodeItem)> {
        if handle.fs != self.fs_id || !handle.proof.is_empty() {
            return Err(Errno::EACCES);
        }
        let Some(item) = self.load_inode(handle.node.ino).await? else {
            return Err(Errno::ESTALE);
        };
        if item.generation != handle.node.generation {
            return Err(Errno::ESTALE);
        }
        Ok((handle.node.ino, item))
    }

    fn open_record_clone(&self, open: &OpenRef) -> Result<(u64, u64, Access, Identity)> {
        if open.fs != self.fs_id {
            return Err(Errno::EBADF);
        }
        let st = self.state.borrow();
        let rec = st.opens.get(&open.id).ok_or(Errno::EBADF)?;
        if rec.ino != open.node.ino || rec.generation != open.node.generation {
            return Err(Errno::EBADF);
        }
        Ok((rec.ino, rec.generation, rec.access, rec.cred.clone()))
    }

    fn new_open(&self, cred: &Cred, ino: u64, generation: u64, access: Access) -> OpenRef {
        let id = NEXT_OPEN_ID.fetch_add(1, Ordering::Relaxed);
        let mut st = self.state.borrow_mut();
        st.opens.insert(
            id,
            OpenRecord {
                ino,
                generation,
                access,
                cred: cred.identity.clone(),
            },
        );
        *st.open_counts.entry(ino).or_insert(0) += 1;
        OpenRef {
            fs: self.fs_id.clone(),
            id,
            node: NodeId { ino, generation },
            access,
        }
    }

    fn check_rw(&self) -> Result<()> {
        if self.read_only {
            return Err(Errno::EROFS);
        }
        if self.state.borrow().fenced {
            return Err(Errno::ESTALE);
        }
        Ok(())
    }

    fn update_atime_if_needed(&self, ino: u64, item: &mut InodeItem, is_dir: bool) {
        if self.read_only {
            return;
        }
        let now = (self.clock)();
        let atime = (item.atime.sec, item.atime.nsec);
        let mtime = (item.mtime.sec, item.mtime.nsec);
        let ctime = (item.ctime.sec, item.ctime.nsec);
        let now_t = (now.sec, now.nsec);
        let update = match vfs::mount::active_mount_flags() {
            Some(flags) => flags.should_update_atime(is_dir, atime, mtime, ctime, now_t),
            None => {
                atime <= mtime
                    || atime <= ctime
                    || now.sec.saturating_sub(item.atime.sec) >= 24 * 60 * 60
            }
        };
        if update {
            item.atime = now;
            self.stage_inode_atime(ino, item);
        }
    }

    async fn searchable(
        &self,
        cred: &Cred,
        dir_ino: u64,
        dir_item: &InodeItem,
    ) -> Result<PermNode> {
        if dir_item.file_type != FileType::Dir {
            return Err(Errno::ENOTDIR);
        }
        let perm = self.load_perm_node(dir_ino, dir_item).await?;
        inode::require(&cred.identity, &perm, EXEC)?;
        Ok(perm)
    }

    async fn lookup_dir_item(&self, dir_ino: u64, name: &str) -> Result<Option<DirItemValue>> {
        let Some(raw) = self.tree_get(&TreeKey::dir_item(dir_ino, name)).await? else {
            return Ok(None);
        };
        DirItemValue::decode(&raw).map(Some)
    }

    async fn dir_is_empty(&self, dir_ino: u64) -> Result<bool> {
        let items = self
            .tree_scan(
                &TreeKey::kind_start(dir_ino, KIND_DIR_ITEM),
                &TreeKey::kind_end(dir_ino, KIND_DIR_ITEM),
                1,
            )
            .await?;
        Ok(items.is_empty())
    }

    async fn is_ancestor(&self, ancestor: u64, mut ino: u64) -> Result<bool> {
        loop {
            if ino == ancestor {
                return Ok(true);
            }
            if ino == ROOT_INO {
                return Ok(false);
            }
            let refs = self
                .tree_scan(
                    &TreeKey::kind_start(ino, KIND_INODE_REF),
                    &TreeKey::kind_end(ino, KIND_INODE_REF),
                    1,
                )
                .await?;
            let Some((key, _)) = refs.first() else {
                return Ok(false);
            };
            let Some((parent, _)) = key.tail_inode_ref() else {
                return Ok(false);
            };
            if parent == ino {
                return Ok(false);
            }
            ino = parent;
        }
    }

    fn alloc_ino(&self) -> (u64, u64) {
        let mut st = self.state.borrow_mut();
        let ino = st.root_obj.next_ino;
        st.root_obj.next_ino += 1;
        let generation = st.root_obj.generation;
        st.inode_count_estimate = st.inode_count_estimate.saturating_add(1);
        (ino, generation)
    }

    async fn reclaim_if_dead(&self, ino: u64, item: &InodeItem) -> Result<()> {
        let opens = self
            .state
            .borrow()
            .open_counts
            .get(&ino)
            .copied()
            .unwrap_or(0);
        if item.nlink == 0 {
            if opens == 0 {
                let (base_root, mut overlay) = {
                    let mut st = self.state.borrow_mut();
                    (st.subvol_root, std::mem::take(&mut st.overlay))
                };
                // Collect digests of dirty blocks we are about to drop.
                let mut dropped_digests = Vec::new();
                {
                    let tree = CowTree::new(&*self.head_store, &self.arena);
                    let mut start = TreeKey::kind_start(ino, KIND_EXTENT_DATA);
                    let end = TreeKey::kind_end(ino, KIND_EXTENT_DATA);
                    loop {
                        let batch = tree
                            .scan_range_with_overlay(&base_root, &overlay, &start, &end, 256)
                            .await?;
                        if batch.is_empty() {
                            break;
                        }
                        let last = batch.last().unwrap().0.clone();
                        let full = batch.len() == 256;
                        for (_, val) in batch {
                            if let Ok(ExtentDataValue::Extent { digest, .. }) =
                                ExtentDataValue::decode(&val)
                            {
                                dropped_digests.push(digest);
                            }
                        }
                        if !full {
                            break;
                        }
                        let mut tail = last.tail;
                        tail.push(0);
                        start = TreeKey::new(last.ino, last.kind, tail);
                    }
                    let res =
                        orphan::reclaim_inode_items(&tree, &base_root, &mut overlay, ino).await;
                    let mut st = self.state.borrow_mut();
                    st.overlay = overlay;
                    res?;
                }
                {
                    let mut st = self.state.borrow_mut();
                    for d in &dropped_digests {
                        st.unstage_dirty_block(d);
                    }
                    st.locks.remove(&ino);
                    st.inode_count_estimate = st.inode_count_estimate.saturating_sub(1);
                }
                self.sync_arena_dirty();
            } else {
                // Still open after last link gone -> persist ORPHAN_ITEM for crash recovery!
                {
                    let mut st = self.state.borrow_mut();
                    orphan::stage_orphan(&mut st.overlay, ino);
                }
                self.sync_arena_dirty();
            }
        }
        Ok(())
    }

    async fn read_verified_block(&self, digest: &Digest) -> Result<Rc<Vec<u8>>> {
        // 1. Check dirty uncommitted blocks.
        if let Some((bytes, _)) = self.state.borrow().dirty_blocks.get(digest) {
            return Ok(Rc::clone(bytes));
        }
        // 2. Check clean data LRU cache in Arena.
        if let Some(hit) = self.arena.borrow_mut().get_data(digest) {
            return Ok(hit);
        }
        // 3. Fetch from PackStore and SHA-256 verify BEFORE caching or returning bytes!
        let loc = self
            .head_store
            .lookup_block(digest)
            .await?
            .ok_or(Errno::EIO)?;
        let bytes = self
            .pack_store
            .read_pack_range(&loc.pack_id, loc.offset, loc.len)
            .await?;
        verify_block_digest(digest, &bytes)?;
        let rc = Rc::new(bytes);
        self.arena.borrow_mut().put_data(*digest, Rc::clone(&rc));
        Ok(rc)
    }

    /// Read up to `buf.len()` bytes of `ino` starting at `offset` (clamped by `inode.size`).
    async fn read_file_bytes(
        &self,
        ino: u64,
        file_size: u64,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize> {
        if offset >= file_size || buf.is_empty() {
            return Ok(0);
        }
        let target_len =
            usize::try_from(file_size - offset).map_or(buf.len(), |left| left.min(buf.len()));
        let mut done = 0usize;
        let min_k = TreeKey::kind_start(ino, KIND_EXTENT_DATA);

        while done < target_len {
            let at = offset + done as u64;
            let max_k = TreeKey::extent_data(ino, at);
            if let Some((ext_key, ext_raw)) = self.tree_find_le(&min_k, &max_k).await?
                && let Some(ext_start) = ext_key.tail_u64()
            {
                match ExtentDataValue::decode(&ext_raw)? {
                    ExtentDataValue::Inline(data) => {
                        let ext_end = ext_start.saturating_add(data.len() as u64);
                        if at < ext_end {
                            let within = (at - ext_start) as usize;
                            let avail = data.len() - within;
                            let take = avail.min(target_len - done);
                            buf[done..done + take].copy_from_slice(&data[within..within + take]);
                            done += take;
                            continue;
                        }
                    }
                    ExtentDataValue::Extent {
                        len: ext_len,
                        digest,
                        block_offset,
                    } => {
                        let ext_end = ext_start.saturating_add(u64::from(ext_len));
                        if at < ext_end {
                            let block = self.read_verified_block(&digest).await?;
                            let rel = (at - ext_start) as usize;
                            let start_in_blk =
                                (block_offset as usize).checked_add(rel).ok_or(Errno::EIO)?;
                            let avail_in_ext = (ext_len as usize) - rel;
                            let take = avail_in_ext.min(target_len - done);
                            let end_in_blk = start_in_blk.checked_add(take).ok_or(Errno::EIO)?;
                            if end_in_blk > block.len() {
                                return Err(Errno::EIO);
                            }
                            buf[done..done + take]
                                .copy_from_slice(&block[start_in_blk..end_in_blk]);
                            done += take;
                            continue;
                        }
                    }
                }
            }

            // `at` lies in a sparse hole. Find the next extent strictly after `at` (if any) to
            // know how many zeros to emit in one step.
            let next_start = TreeKey::extent_data(ino, at.saturating_add(1));
            let next_end = TreeKey::kind_end(ino, KIND_EXTENT_DATA);
            let next_ext = self.tree_scan(&next_start, &next_end, 1).await?;
            let hole_end = next_ext
                .first()
                .and_then(|(k, _)| k.tail_u64())
                .unwrap_or(file_size)
                .min(file_size);
            let hole_len = usize::try_from(hole_end.saturating_sub(at))
                .unwrap_or(usize::MAX)
                .min(target_len - done)
                .max(1);
            buf[done..done + hole_len].fill(0);
            done += hole_len;
        }
        Ok(target_len)
    }

    /// Resize regular file `ino` to `new_size`, freeing extents past `new_size` and zeroing any
    /// partial tail block.
    async fn resize_file(
        &self,
        ino: u64,
        inode_item: &mut InodeItem,
        new_size: u64,
        by: &Identity,
        now: Timespec,
    ) -> Result<()> {
        let old_size = inode_item.size;
        if new_size < old_size {
            // 1. Delete all extents starting at >= new_size.
            let mut start = TreeKey::extent_data(ino, new_size);
            let end = TreeKey::kind_end(ino, KIND_EXTENT_DATA);
            loop {
                let batch = self.tree_scan(&start, &end, 256).await?;
                if batch.is_empty() {
                    break;
                }
                let last = batch.last().unwrap().0.clone();
                let full = batch.len() == 256;
                {
                    let mut st = self.state.borrow_mut();
                    for (k, raw) in batch {
                        if let Ok(ExtentDataValue::Extent { digest, .. }) =
                            ExtentDataValue::decode(&raw)
                        {
                            st.unstage_dirty_block(&digest);
                        }
                        st.overlay.delete(k);
                    }
                }
                if !full {
                    break;
                }
                let mut tail = last.tail;
                tail.push(0);
                start = TreeKey::new(last.ino, last.kind, tail);
            }

            // 2. Trim any extent starting strictly before `new_size` that straddles `new_size`.
            if new_size > 0 {
                let min_k = TreeKey::kind_start(ino, KIND_EXTENT_DATA);
                let max_k = TreeKey::extent_data(ino, new_size - 1);
                if let Some((ext_key, ext_raw)) = self.tree_find_le(&min_k, &max_k).await?
                    && let Some(ext_start) = ext_key.tail_u64()
                {
                    match ExtentDataValue::decode(&ext_raw)? {
                        ExtentDataValue::Inline(mut data) => {
                            let keep = (new_size - ext_start) as usize;
                            if keep < data.len() {
                                data.truncate(keep);
                                let enc = ExtentDataValue::Inline(data).encode()?;
                                self.state.borrow_mut().overlay.put(ext_key, enc);
                            }
                        }
                        ExtentDataValue::Extent {
                            len: ext_len,
                            digest,
                            block_offset,
                        } => {
                            let ext_end = ext_start.saturating_add(u64::from(ext_len));
                            if new_size < ext_end {
                                // Split: keep untouched full 64 KiB blocks before the tail block,
                                // and rewrite the single straddling 64 KiB block zero-padded past
                                // `new_size`.
                                let blk_size = u64::from(BLOCK_SIZE);
                                let tail_blk_start = (new_size / blk_size) * blk_size;
                                let block_bytes = self.read_verified_block(&digest).await?;

                                // Remove old extent, preserving whether its backing block was
                                // staged uncommitted so a refcount-1 multi-block split stays staged.
                                let was_dirty = {
                                    let mut st = self.state.borrow_mut();
                                    let dirty = st.dirty_blocks.contains_key(&digest);
                                    st.unstage_dirty_block(&digest);
                                    st.overlay.delete(ext_key);
                                    dirty
                                };

                                // Re-emit prefix if `tail_blk_start > ext_start`.
                                if tail_blk_start > ext_start {
                                    let prefix_len = (tail_blk_start - ext_start) as u32;
                                    let prefix_val = ExtentDataValue::Extent {
                                        len: prefix_len,
                                        digest,
                                        block_offset,
                                    }
                                    .encode()?;
                                    let mut st = self.state.borrow_mut();
                                    if was_dirty {
                                        st.stage_dirty_block(digest, Rc::clone(&block_bytes));
                                    }
                                    st.overlay
                                        .put(TreeKey::extent_data(ino, ext_start), prefix_val);
                                }

                                // Rewrite straddling 64 KiB block zeroed past `new_size`.
                                let keep_in_blk = (new_size - tail_blk_start) as usize;
                                if keep_in_blk > 0 {
                                    let mut new_blk = vec![0u8; BLOCK_SIZE as usize];
                                    let src_off = (block_offset as usize)
                                        + (tail_blk_start - ext_start) as usize;
                                    let avail = block_bytes.len().saturating_sub(src_off);
                                    let copy_len = keep_in_blk.min(avail);
                                    new_blk[..copy_len]
                                        .copy_from_slice(&block_bytes[src_off..src_off + copy_len]);
                                    let new_dig = sha256(&new_blk);
                                    let val = ExtentDataValue::Extent {
                                        len: BLOCK_SIZE,
                                        digest: new_dig,
                                        block_offset: 0,
                                    }
                                    .encode()?;
                                    let mut st = self.state.borrow_mut();
                                    st.stage_dirty_block(new_dig, Rc::new(new_blk));
                                    st.overlay
                                        .put(TreeKey::extent_data(ino, tail_blk_start), val);
                                }
                            }
                        }
                    }
                }
            }
            self.sync_arena_dirty();
        }

        let mut perm = self.load_perm_node(ino, inode_item).await?;
        inode::remove_privs(by, &mut perm);
        inode_item.apply_perm_node(&perm);
        inode_item.size = new_size;
        inode_item.mtime = now;
        inode_item.ctime = now;
        self.stage_inode(ino, inode_item);
        Ok(())
    }

    /// Promote an inline extent at offset 0 (if present) into a 64 KiB block so larger/offset
    /// writes operate uniformly on 64 KiB aligned blocks.
    async fn promote_inline_if_present(&self, ino: u64) -> Result<()> {
        let key0 = TreeKey::extent_data(ino, 0);
        let Some(raw) = self.tree_get(&key0).await? else {
            return Ok(());
        };
        let ExtentDataValue::Inline(inline_bytes) = ExtentDataValue::decode(&raw)? else {
            return Ok(());
        };
        self.maybe_backpressure_flush(BLOCK_SIZE as usize).await?;
        let mut blk = vec![0u8; BLOCK_SIZE as usize];
        blk[..inline_bytes.len()].copy_from_slice(&inline_bytes);
        let digest = sha256(&blk);
        let enc = ExtentDataValue::Extent {
            len: BLOCK_SIZE,
            digest,
            block_offset: 0,
        }
        .encode()?;
        {
            let mut st = self.state.borrow_mut();
            st.stage_dirty_block(digest, Rc::new(blk));
            st.overlay.put(key0, enc);
        }
        self.sync_arena_dirty();
        Ok(())
    }

    /// Write `data` to regular file `ino` starting at `offset`, using `<= 2 KiB` inline storage
    /// for tiny files and `64 KiB` CoW aligned blocks with `Arena` dirty backpressure for larger
    /// or sparse files.
    async fn write_file_bytes(
        &self,
        ino: u64,
        inode_item: &mut InodeItem,
        offset: u64,
        data: &[u8],
    ) -> Result<usize> {
        let end = offset.saturating_add(data.len() as u64);

        // Fast path: keep tiny files (`<= 2 KiB`) inline inside the B+tree leaf!
        if inode_item.size <= INLINE_MAX_BYTES as u64 && end <= INLINE_MAX_BYTES as u64 {
            let key0 = TreeKey::extent_data(ino, 0);
            let existing = self.tree_get(&key0).await?;
            let can_inline = match existing.as_deref() {
                None => true,
                Some(raw) => matches!(ExtentDataValue::decode(raw)?, ExtentDataValue::Inline(_)),
            };
            if can_inline {
                let mut buf = match existing.as_deref() {
                    Some(raw) => match ExtentDataValue::decode(raw)? {
                        ExtentDataValue::Inline(v) => v,
                        _ => unreachable!(),
                    },
                    None => Vec::new(),
                };
                if buf.len() < end as usize {
                    buf.resize(end as usize, 0);
                }
                buf[offset as usize..end as usize].copy_from_slice(data);
                let enc = ExtentDataValue::Inline(buf).encode()?;
                self.maybe_backpressure_flush(enc.len() + 64).await?;
                self.state.borrow_mut().overlay.put(key0, enc);
                inode_item.size = inode_item.size.max(end);
                self.sync_arena_dirty();
                return Ok(data.len());
            }
        }

        // Promote any existing inline data into block 0 before 64 KiB block writes.
        self.promote_inline_if_present(ino).await?;

        let blk_size = u64::from(BLOCK_SIZE);
        let mut done = 0usize;

        while done < data.len() {
            let at = offset + done as u64;
            let blk_start = (at / blk_size) * blk_size;
            let within = (at % blk_size) as usize;
            let chunk = (BLOCK_SIZE as usize - within).min(data.len() - done);

            // Check optional logical capacity ceiling before allocating a brand-new block.
            let existing_cover = self
                .tree_find_le(
                    &TreeKey::kind_start(ino, KIND_EXTENT_DATA),
                    &TreeKey::extent_data(ino, blk_start),
                )
                .await?;
            let covering = match existing_cover {
                Some((k, raw)) => {
                    let ext_start = k.tail_u64().ok_or(Errno::EIO)?;
                    match ExtentDataValue::decode(&raw)? {
                        ExtentDataValue::Extent {
                            len,
                            digest,
                            block_offset,
                        } if blk_start < ext_start.saturating_add(u64::from(len)) => {
                            Some((k, ext_start, len, digest, block_offset))
                        }
                        _ => None,
                    }
                }
                None => None,
            };

            if covering.is_none()
                && let Some(cap) = self.capacity_bytes
            {
                let cur = self.state.borrow().allocated_bytes;
                if cur.saturating_add(blk_size) > cap {
                    if done > 0 {
                        return Ok(done);
                    }
                    return Err(Errno::ENOSPC);
                }
            }

            // Enforce Arena 8 MiB dirty slab backpressure BEFORE allocating another dirty block.
            if self
                .arena
                .borrow()
                .needs_backpressure_flush(BLOCK_SIZE as usize + 256)
            {
                // Persist current inode size so the intermediate flush is consistent.
                self.stage_inode(ino, inode_item);
                if let Err(e) = self.commit_tx_group().await {
                    if done > 0 && matches!(e, Errno::ENOSPC | Errno::EDQUOT) {
                        return Ok(done);
                    }
                    return Err(e);
                }
                self.arena.borrow_mut().record_backpressure_flush();
            }

            // Build the new 64 KiB block content (copy-on-write).
            let mut blk = vec![0u8; BLOCK_SIZE as usize];
            if let Some((old_key, ext_start, ext_len, old_digest, old_blk_off)) = covering {
                let need_read = chunk < BLOCK_SIZE as usize || ext_len > BLOCK_SIZE;
                let old_bytes = if need_read {
                    Some(self.read_verified_block(&old_digest).await?)
                } else {
                    None
                };
                if chunk < BLOCK_SIZE as usize
                    && let Some(ref bytes) = old_bytes
                {
                    let src_off = (old_blk_off as usize) + (blk_start - ext_start) as usize;
                    let avail = bytes.len().saturating_sub(src_off);
                    let copy_len = (BLOCK_SIZE as usize).min(avail);
                    blk[..copy_len].copy_from_slice(&bytes[src_off..src_off + copy_len]);
                }

                // Remove old extent and split untouched prefix/suffix if it spanned > 64 KiB.
                let ext_end = ext_start.saturating_add(u64::from(ext_len));
                let blk_end = blk_start.saturating_add(blk_size);
                {
                    let mut st = self.state.borrow_mut();
                    let was_dirty = st.dirty_blocks.contains_key(&old_digest);
                    st.unstage_dirty_block(&old_digest);
                    st.overlay.delete(old_key);

                    if blk_start > ext_start {
                        let pre_len = (blk_start - ext_start) as u32;
                        let pre_enc = ExtentDataValue::Extent {
                            len: pre_len,
                            digest: old_digest,
                            block_offset: old_blk_off,
                        }
                        .encode()?;
                        if was_dirty && let Some(ref bytes) = old_bytes {
                            st.stage_dirty_block(old_digest, Rc::clone(bytes));
                        }
                        st.overlay
                            .put(TreeKey::extent_data(ino, ext_start), pre_enc);
                    }
                    if ext_end > blk_end {
                        let suf_len = (ext_end - blk_end) as u32;
                        let suf_off = old_blk_off + (blk_end - ext_start) as u32;
                        let suf_enc = ExtentDataValue::Extent {
                            len: suf_len,
                            digest: old_digest,
                            block_offset: suf_off,
                        }
                        .encode()?;
                        if was_dirty && let Some(ref bytes) = old_bytes {
                            st.stage_dirty_block(old_digest, Rc::clone(bytes));
                        }
                        st.overlay.put(TreeKey::extent_data(ino, blk_end), suf_enc);
                    }
                }
            } else {
                self.state.borrow_mut().allocated_bytes += blk_size;
            }

            blk[within..within + chunk].copy_from_slice(&data[done..done + chunk]);
            let new_digest = sha256(&blk);
            let enc = ExtentDataValue::Extent {
                len: BLOCK_SIZE,
                digest: new_digest,
                block_offset: 0,
            }
            .encode()?;
            {
                let mut st = self.state.borrow_mut();
                st.stage_dirty_block(new_digest, Rc::new(blk));
                st.overlay.put(TreeKey::extent_data(ino, blk_start), enc);
            }
            done += chunk;
            inode_item.size = inode_item.size.max(offset + done as u64);
            self.sync_arena_dirty();
        }
        Ok(done)
    }

    // -------------------------------------------------------------------------
    // Lock helpers (identical semantics to MemFs, plus RO ENOLCK for exclusive locks)
    // -------------------------------------------------------------------------

    fn lockable(
        &self,
        open: &OpenRef,
        family: LockFamily,
        kind: Option<LockKind>,
        range: LockRange,
    ) -> Result<u64> {
        let (ino, _gen, access, _) = self.open_record_clone(open)?;
        let allowed = match (family, kind) {
            _ if access == Access::Path => false,
            (LockFamily::Flock, _) | (LockFamily::Posix, None) => true,
            (LockFamily::Posix, Some(LockKind::Shared)) => access.reads(),
            (LockFamily::Posix, Some(LockKind::Exclusive)) => access.writes(),
        };
        if !allowed {
            return Err(Errno::EBADF);
        }
        if family == LockFamily::Flock && range != LockRange::WHOLE {
            return Err(Errno::EINVAL);
        }
        // Contract §3: on RO / snapshot mounts, shared locks are instance-local; exclusive locks
        // return `ENOLCK` (no cross-instance lock keeper).
        if self.read_only && kind == Some(LockKind::Exclusive) {
            return Err(Errno::ENOLCK);
        }
        Ok(ino)
    }

    fn conflict(
        st: &CowFsState,
        ino: u64,
        owner: u64,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> Option<Conflict> {
        st.locks.get(&ino)?.iter().find_map(|lock| {
            (lock.owner != owner
                && lock.family == family
                && lock.range.overlaps(range)
                && (kind == LockKind::Exclusive || lock.kind == LockKind::Exclusive))
                .then_some(Conflict {
                    kind: lock.kind,
                    range: lock.range,
                    owner: lock.owner,
                })
        })
    }

    fn wake_lock_waiters(&self, ino: u64) {
        let wakers: Vec<Waker> = self
            .state
            .borrow()
            .waiters
            .values()
            .filter(|w| w.ino == ino)
            .map(|w| w.waker.clone())
            .collect();
        for w in wakers {
            w.wake();
        }
    }

    fn acquire_lock(
        &self,
        open: &OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
        waker: Option<&Waker>,
    ) -> Result<Option<u64>> {
        let ino = self.lockable(open, family, Some(kind), range)?;
        let owner = open.id;

        // flock conversion drops the old lock before waiting, matching Linux.
        let need_wake = {
            let mut st = self.state.borrow_mut();
            if family == LockFamily::Flock
                && let Some(locks) = st.locks.get_mut(&ino)
                && locks
                    .iter()
                    .any(|l| l.owner == owner && l.family == family && l.kind != kind)
            {
                carve(locks, owner, family, range);
                true
            } else {
                false
            }
        };
        if need_wake {
            self.wake_lock_waiters(ino);
            self.lockable(open, family, Some(kind), range)?;
        }

        let wanted = Lock {
            owner,
            family,
            kind,
            range,
        };
        let mut st = self.state.borrow_mut();
        if Self::conflict(&st, ino, owner, family, kind, range).is_some() {
            let Some(waker) = waker else {
                return Err(Errno::EAGAIN);
            };
            if family == LockFamily::Posix && st.deadlocks(ino, wanted) {
                return Err(Errno::EDEADLK);
            }
            let id = st.next_waiter;
            st.next_waiter += 1;
            st.waiters.insert(
                id,
                Waiter {
                    ino,
                    lock: wanted,
                    waker: waker.clone(),
                },
            );
            return Ok(Some(id));
        }

        let locks = st.locks.entry(ino).or_default();
        carve(locks, owner, family, range);
        let mut merged = range;
        locks.retain(|l| {
            let joins =
                l.owner == owner && l.family == family && l.kind == kind && l.range.touches(merged);
            if joins {
                merged = merged.union(l.range);
            }
            !joins
        });
        locks.push(Lock {
            owner,
            family,
            kind,
            range: merged,
        });
        drop(st);
        self.wake_lock_waiters(ino);
        Ok(None)
    }

    async fn add_node_in_dir(
        &self,
        dir_ino: u64,
        dir_item: &mut InodeItem,
        name: &str,
        node: PermNode,
    ) -> Result<(u64, InodeItem)> {
        self.maybe_backpressure_flush(1024).await?;
        let (ino, generation) = self.alloc_ino();
        let now = (self.clock)();
        let file_type = if node.directory {
            FileType::Dir
        } else if node.link.is_some() {
            FileType::Symlink
        } else if node.rdev.is_some() {
            FileType::CharDevice
        } else {
            FileType::File
        };
        let nlink = if file_type == FileType::Dir { 2 } else { 1 };
        let item = InodeItem {
            file_type,
            mode: node.mode & 0o7777,
            nlink,
            uid: node.owner,
            gid: node.group,
            size: 0,
            generation,
            atime: now,
            mtime: now,
            ctime: now,
            rdev: node.rdev.clone(),
            symlink_target: node.link.clone(),
            next_dir_index: 1,
            acl_present: node.acl.is_some(),
            default_acl_present: node.default_acl.is_some(),
        };

        let dir_index = dir_item.next_dir_index;
        dir_item.next_dir_index = dir_item.next_dir_index.saturating_add(1);
        if file_type == FileType::Dir {
            dir_item.nlink = dir_item.nlink.saturating_add(1);
        }
        dir_item.mtime = now;
        dir_item.ctime = now;

        let di = DirItemValue {
            child_ino: ino,
            child_gen: generation,
            file_type,
            dir_index,
        };
        let didx = DirIndexValue {
            child_ino: ino,
            child_gen: generation,
            file_type,
            name: name.to_string(),
        };

        {
            let mut st = self.state.borrow_mut();
            st.user_modified = true;
            st.overlay.put(TreeKey::inode_item(ino), item.encode());
            st.overlay
                .put(TreeKey::inode_ref(ino, dir_ino, name), Vec::new());
            st.overlay
                .put(TreeKey::dir_item(dir_ino, name), di.encode());
            st.overlay
                .put(TreeKey::dir_index(dir_ino, dir_index), didx.encode());
            st.overlay
                .put(TreeKey::inode_item(dir_ino), dir_item.encode());
        }
        if node.acl.is_some() || node.default_acl.is_some() {
            self.stage_perm_acls(ino, &node)?;
        } else {
            self.sync_arena_dirty();
        }
        Ok((ino, item))
    }

    async fn load_user_trusted_xattrs(&self, ino: u64) -> Result<BTreeMap<String, Vec<u8>>> {
        let mut out = BTreeMap::new();
        let mut start = TreeKey::kind_start(ino, KIND_XATTR_ITEM);
        let end = TreeKey::kind_end(ino, KIND_XATTR_ITEM);
        loop {
            let batch = self.tree_scan(&start, &end, 128).await?;
            if batch.is_empty() {
                break;
            }
            let last = batch.last().unwrap().0.clone();
            let full = batch.len() == 128;
            for (k, v) in batch {
                let name = String::from_utf8(k.tail).map_err(|_| Errno::EIO)?;
                if name != abi::ACL_ACCESS && name != abi::ACL_DEFAULT {
                    out.insert(name, v);
                }
            }
            if !full {
                break;
            }
            let mut tail = last.tail;
            tail.push(0);
            start = TreeKey::new(last.ino, last.kind, tail);
        }
        Ok(out)
    }

    async fn openable(
        &self,
        cred: &Cred,
        ino: u64,
        item: &InodeItem,
        options: &OpenOptions,
    ) -> Result<Access> {
        let access = options.access()?;
        if access == Access::Path {
            return Ok(access);
        }
        if access.writes() || options.is_truncate() {
            self.check_rw()?;
        }
        let mut mask = access.mask();
        if options.is_truncate() {
            mask |= WRITE;
        }
        let perm = self.load_perm_node(ino, item).await?;
        inode::may_open(&cred.identity, &perm, mask)?;
        Ok(access)
    }
}

struct CowLockWait<'a, H: HeadStore + 'static, P: PackStore + 'static> {
    fs: &'a CowFs<H, P>,
    open: &'a OpenRef,
    family: LockFamily,
    kind: LockKind,
    range: LockRange,
    waiting: Option<u64>,
}

impl<H: HeadStore + 'static, P: PackStore + 'static> Future for CowLockWait<'_, H, P> {
    type Output = Result<()>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        if let Some(id) = self.waiting.take() {
            self.fs.state.borrow_mut().waiters.remove(&id);
        }
        let (family, kind, range) = (self.family, self.kind, self.range);
        match self
            .fs
            .acquire_lock(self.open, family, kind, range, Some(cx.waker()))
        {
            Ok(Some(id)) => {
                self.waiting = Some(id);
                Poll::Pending
            }
            Ok(None) => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

impl<H: HeadStore + 'static, P: PackStore + 'static> Drop for CowLockWait<'_, H, P> {
    fn drop(&mut self) {
        if let Some(id) = self.waiting {
            self.fs.state.borrow_mut().waiters.remove(&id);
        }
    }
}

impl<H: HeadStore + 'static, P: PackStore + 'static> Filesystem for CowFs<H, P> {
    fn id(&self) -> &FsId {
        &self.fs_id
    }

    fn capabilities(&self) -> FsCapabilities {
        self.capabilities
    }

    fn root(&self) -> Handle {
        self.handle_for(ROOT_INO, self.root_generation)
    }

    fn lookup<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(async move {
            let (dir_ino, dir_item) = self.check_handle(dir).await?;
            check_component(name)?;
            self.searchable(cred, dir_ino, &dir_item).await?;
            let di = self
                .lookup_dir_item(dir_ino, name)
                .await?
                .ok_or(Errno::ENOENT)?;
            let child = self.load_inode(di.child_ino).await?.ok_or(Errno::ESTALE)?;
            Ok(self.entry_for(di.child_ino, &child))
        })
    }

    fn walk<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        names: &'a [String],
    ) -> BoxFuture<'a, Walked> {
        Box::pin(async move {
            let (mut cur_ino, mut cur_item) = self.check_handle(dir).await?;
            for name in names {
                check_component(name)?;
            }
            let mut entries = Vec::new();
            for (index, name) in names.iter().enumerate() {
                if index > 0 {
                    let stop = match cur_item.file_type {
                        FileType::Dir => None,
                        FileType::Symlink => Some(Stop::Symlink(index - 1)),
                        _ => Some(Stop::NotDirectory(index - 1)),
                    };
                    if stop.is_some() {
                        return Ok(Walked { entries, stop });
                    }
                }
                self.searchable(cred, cur_ino, &cur_item).await?;
                match self.lookup_dir_item(cur_ino, name).await? {
                    Some(di) => {
                        let child = self.load_inode(di.child_ino).await?.ok_or(Errno::ESTALE)?;
                        entries.push(self.entry_for(di.child_ino, &child));
                        cur_ino = di.child_ino;
                        cur_item = child;
                    }
                    None => {
                        return Ok(Walked {
                            entries,
                            stop: Some(Stop::Missing(index)),
                        });
                    }
                }
            }
            Ok(Walked {
                entries,
                stop: None,
            })
        })
    }

    fn parent<'a>(
        &'a self,
        _cred: &'a Cred,
        dir: &'a Handle,
    ) -> BoxFuture<'a, Option<(Entry, String)>> {
        Box::pin(async move {
            let (dir_ino, dir_item) = self.check_handle(dir).await?;
            if dir_item.file_type != FileType::Dir {
                return Err(Errno::ENOTDIR);
            }
            if dir_ino == ROOT_INO {
                return Ok(None);
            }
            if dir_item.nlink == 0 {
                return Err(Errno::ENOENT);
            }
            let refs = self
                .tree_scan(
                    &TreeKey::kind_start(dir_ino, KIND_INODE_REF),
                    &TreeKey::kind_end(dir_ino, KIND_INODE_REF),
                    1,
                )
                .await?;
            let Some((key, _)) = refs.first() else {
                return Err(Errno::ENOENT);
            };
            let Some((parent_ino, name)) = key.tail_inode_ref() else {
                return Err(Errno::EIO);
            };
            let Some(parent_item) = self.load_inode(parent_ino).await? else {
                return Err(Errno::ENOENT);
            };
            Ok(Some((
                self.entry_for(parent_ino, &parent_item),
                name.to_string(),
            )))
        })
    }

    fn metadata<'a>(&'a self, _cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Metadata> {
        Box::pin(async move {
            let (_, item) = self.check_handle(handle).await?;
            Ok(item.to_metadata())
        })
    }

    fn setattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        attr: &'a SetAttr,
    ) -> BoxFuture<'a, Metadata> {
        Box::pin(async move {
            self.check_rw()?;
            let (ino, mut item) = self.check_handle(handle).await?;
            if *attr == SetAttr::default() {
                return Ok(item.to_metadata());
            }
            let who = &cred.identity;
            let orig_perm = self.load_perm_node(ino, &item).await?;
            let mut perm = orig_perm.clone();
            if let Some(mode) = attr.mode {
                inode::chmod(who, &mut perm, mode)?;
            }
            inode::chown(who, &mut perm, attr.uid, attr.gid)?;
            inode::may_set_times(who, &orig_perm, attr.atime, attr.mtime)?;
            if let Some(size) = attr.size {
                match item.file_type {
                    FileType::Dir => return Err(Errno::EISDIR),
                    FileType::File => {}
                    _ => return Err(Errno::EINVAL),
                }
                inode::require(who, &orig_perm, WRITE)?;
                if size > FILE_MAX {
                    return Err(Errno::EFBIG);
                }
            }
            let now = (self.clock)();
            item.apply_perm_node(&perm);
            self.stage_perm_acls(ino, &perm)?;
            if let Some(size) = attr.size {
                self.resize_file(ino, &mut item, size, who, now).await?;
            }
            if let Some((sec, nsec)) = inode::time(attr.atime, (now.sec, now.nsec)) {
                item.atime = Timespec { sec, nsec };
            }
            if let Some((sec, nsec)) = inode::time(attr.mtime, (now.sec, now.nsec)) {
                item.mtime = Timespec { sec, nsec };
            }
            item.ctime = now;
            self.stage_inode(ino, &item);
            Ok(item.to_metadata())
        })
    }

    fn read_dir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle) -> BoxFuture<'a, Vec<DirEntry>> {
        Box::pin(async move {
            let (dir_ino, mut dir_item) = self.check_handle(dir).await?;
            if dir_item.file_type != FileType::Dir {
                return Err(Errno::ENOTDIR);
            }
            let perm = self.load_perm_node(dir_ino, &dir_item).await?;
            inode::require(&cred.identity, &perm, READ)?;
            if dir_item.nlink == 0 {
                return Err(Errno::ENOENT);
            }
            let mut out = Vec::new();
            let mut start = TreeKey::kind_start(dir_ino, KIND_DIR_ITEM);
            let end = TreeKey::kind_end(dir_ino, KIND_DIR_ITEM);
            loop {
                let batch = self.tree_scan(&start, &end, 512).await?;
                if batch.is_empty() {
                    break;
                }
                let last = batch.last().unwrap().0.clone();
                let full = batch.len() == 512;
                for (k, v) in batch {
                    let di = DirItemValue::decode(&v)?;
                    let name = String::from_utf8(k.tail).map_err(|_| Errno::EIO)?;
                    out.push(DirEntry {
                        name,
                        node: NodeId {
                            ino: di.child_ino,
                            generation: di.child_gen,
                        },
                        file_type: di.file_type,
                    });
                }
                if !full {
                    break;
                }
                let mut tail = last.tail;
                tail.push(0);
                start = TreeKey::new(last.ino, last.kind, tail);
            }
            self.update_atime_if_needed(dir_ino, &mut dir_item, true);
            Ok(out)
        })
    }

    /// Native O(log N + page) paged enumeration directly over `0x21` `DIR_INDEX` keys!
    /// Never loads the full directory into memory — enumerates 100k+ entries cleanly inside the
    /// `32 MiB` wasm32 slab arena.
    fn read_dir_page<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        cookie: u64,
        max_entries: usize,
    ) -> BoxFuture<'a, DirPage> {
        Box::pin(async move {
            let (dir_ino, mut dir_item) = self.check_handle(dir).await?;
            if dir_item.file_type != FileType::Dir {
                return Err(Errno::ENOTDIR);
            }
            let perm = self.load_perm_node(dir_ino, &dir_item).await?;
            inode::require(&cred.identity, &perm, READ)?;
            if dir_item.nlink == 0 {
                return Err(Errno::ENOENT);
            }

            let start = TreeKey::dir_index(dir_ino, cookie);
            let end = TreeKey::kind_end(dir_ino, KIND_DIR_INDEX);

            if max_entries == 0 {
                let peek = self.tree_scan(&start, &end, 1).await?;
                let next_cookie = peek.first().and_then(|(k, _)| k.tail_u64());
                self.update_atime_if_needed(dir_ino, &mut dir_item, true);
                return Ok(DirPage {
                    entries: Vec::new(),
                    next_cookie,
                });
            }

            let limit = max_entries.min(DIR_PAGE_MAX);
            let batch = self.tree_scan(&start, &end, limit + 1).await?;
            let has_more = batch.len() > limit;
            let next_cookie = if has_more {
                batch[limit].0.tail_u64()
            } else {
                None
            };
            let mut entries = Vec::with_capacity(batch.len().min(limit));
            for (_, raw) in batch.into_iter().take(limit) {
                let dv = DirIndexValue::decode(&raw)?;
                entries.push(DirEntry {
                    name: dv.name,
                    node: NodeId {
                        ino: dv.child_ino,
                        generation: dv.child_gen,
                    },
                    file_type: dv.file_type,
                });
            }
            self.update_atime_if_needed(dir_ino, &mut dir_item, true);
            Ok(DirPage {
                entries,
                next_cookie,
            })
        })
    }

    fn read_link<'a>(&'a self, _cred: &'a Cred, link: &'a Handle) -> BoxFuture<'a, String> {
        Box::pin(async move {
            let (ino, mut item) = self.check_handle(link).await?;
            let target = item.symlink_target.clone().ok_or(Errno::EINVAL)?;
            self.update_atime_if_needed(ino, &mut item, false);
            Ok(target)
        })
    }

    fn create<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
        options: &'a OpenOptions,
    ) -> BoxFuture<'a, (Entry, OpenRef)> {
        Box::pin(async move {
            self.check_rw()?;
            let access = options.access()?;
            if matches!(access, Access::Exec | Access::Path) {
                return Err(Errno::EINVAL);
            }
            let (dir_ino, mut dir_item) = self.check_handle(dir).await?;
            check_component(name)?;
            let parent_perm = self.searchable(cred, dir_ino, &dir_item).await?;
            if let Some(di) = self.lookup_dir_item(dir_ino, name).await? {
                if options.is_create_new() {
                    return Err(Errno::EEXIST);
                }
                let mut existing = self.load_inode(di.child_ino).await?.ok_or(Errno::ESTALE)?;
                if existing.file_type == FileType::Dir {
                    return Err(Errno::EISDIR);
                }
                self.openable(cred, di.child_ino, &existing, options)
                    .await?;
                if options.is_truncate() && existing.file_type == FileType::File {
                    let now = (self.clock)();
                    self.resize_file(di.child_ino, &mut existing, 0, &cred.identity, now)
                        .await?;
                }
                let open = self.new_open(cred, di.child_ino, existing.generation, access);
                return Ok((self.entry_for(di.child_ino, &existing), open));
            }

            inode::may_create(&cred.identity, &parent_perm, dir_item.nlink == 0)?;
            let node = created(&cred.identity, &parent_perm, mode, false, cred.umask);
            let (ino, item) = self
                .add_node_in_dir(dir_ino, &mut dir_item, name, node)
                .await?;
            let open = self.new_open(cred, ino, item.generation, access);
            Ok((self.entry_for(ino, &item), open))
        })
    }

    fn mkdir<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(async move {
            self.check_rw()?;
            let (dir_ino, mut dir_item) = self.check_handle(dir).await?;
            check_component(name)?;
            let parent_perm = self.searchable(cred, dir_ino, &dir_item).await?;
            if self.lookup_dir_item(dir_ino, name).await?.is_some() {
                return Err(Errno::EEXIST);
            }
            inode::may_create(&cred.identity, &parent_perm, dir_item.nlink == 0)?;
            let node = created(&cred.identity, &parent_perm, mode, true, cred.umask);
            let (ino, item) = self
                .add_node_in_dir(dir_ino, &mut dir_item, name, node)
                .await?;
            Ok(self.entry_for(ino, &item))
        })
    }

    fn mknod<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
        rdev: &'a str,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(async move {
            self.check_rw()?;
            if cred.identity.id != 0 {
                return Err(Errno::EPERM);
            }
            let (dir_ino, mut dir_item) = self.check_handle(dir).await?;
            check_component(name)?;
            let parent_perm = self.searchable(cred, dir_ino, &dir_item).await?;
            if self.lookup_dir_item(dir_ino, name).await?.is_some() {
                return Err(Errno::EEXIST);
            }
            inode::may_create(&cred.identity, &parent_perm, dir_item.nlink == 0)?;
            let mut node = created(&cred.identity, &parent_perm, mode, false, cred.umask);
            node.rdev = Some(rdev.to_string());
            let (ino, item) = self
                .add_node_in_dir(dir_ino, &mut dir_item, name, node)
                .await?;
            Ok(self.entry_for(ino, &item))
        })
    }

    fn symlink<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        target: &'a str,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(async move {
            self.check_rw()?;
            inode::check_link_target(target)?;
            let (dir_ino, mut dir_item) = self.check_handle(dir).await?;
            check_component(name)?;
            let parent_perm = self.searchable(cred, dir_ino, &dir_item).await?;
            if self.lookup_dir_item(dir_ino, name).await?.is_some() {
                return Err(Errno::EEXIST);
            }
            inode::may_create(&cred.identity, &parent_perm, dir_item.nlink == 0)?;
            let node = inode::new_symlink(&cred.identity, &parent_perm, target);
            let (ino, item) = self
                .add_node_in_dir(dir_ino, &mut dir_item, name, node)
                .await?;
            Ok(self.entry_for(ino, &item))
        })
    }

    fn link<'a>(
        &'a self,
        cred: &'a Cred,
        target: &'a Handle,
        dir: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(async move {
            self.check_rw()?;
            let (target_ino, mut target_item) = self.check_handle(target).await?;
            let (dir_ino, mut dir_item) = self.check_handle(dir).await?;
            check_component(name)?;
            let parent_perm = self.searchable(cred, dir_ino, &dir_item).await?;
            if self.lookup_dir_item(dir_ino, name).await?.is_some() {
                return Err(Errno::EEXIST);
            }
            let target_perm = self.load_perm_node(target_ino, &target_item).await?;
            inode::may_link(&cred.identity, &target_perm)?;
            inode::may_create(&cred.identity, &parent_perm, dir_item.nlink == 0)?;
            if target_item.nlink == 0 {
                return Err(Errno::ENOENT);
            }
            self.maybe_backpressure_flush(512).await?;
            let now = (self.clock)();
            let dir_index = dir_item.next_dir_index;
            dir_item.next_dir_index = dir_item.next_dir_index.saturating_add(1);
            dir_item.mtime = now;
            dir_item.ctime = now;
            target_item.nlink = target_item.nlink.saturating_add(1);
            target_item.ctime = now;

            let di = DirItemValue {
                child_ino: target_ino,
                child_gen: target_item.generation,
                file_type: target_item.file_type,
                dir_index,
            };
            let didx = DirIndexValue {
                child_ino: target_ino,
                child_gen: target_item.generation,
                file_type: target_item.file_type,
                name: name.to_string(),
            };
            {
                let mut st = self.state.borrow_mut();
                st.user_modified = true;
                st.overlay
                    .put(TreeKey::dir_item(dir_ino, name), di.encode());
                st.overlay
                    .put(TreeKey::dir_index(dir_ino, dir_index), didx.encode());
                st.overlay
                    .put(TreeKey::inode_ref(target_ino, dir_ino, name), Vec::new());
                st.overlay
                    .put(TreeKey::inode_item(dir_ino), dir_item.encode());
                st.overlay
                    .put(TreeKey::inode_item(target_ino), target_item.encode());
            }
            self.sync_arena_dirty();
            Ok(self.entry_for(target_ino, &target_item))
        })
    }

    fn unlink<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move { self.do_remove(cred, dir, name, false, None).await })
    }

    fn unlink_if<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        node: NodeId,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move { self.do_remove(cred, dir, name, false, Some(node)).await })
    }

    fn rmdir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move { self.do_remove(cred, dir, name, true, None).await })
    }

    fn rename<'a>(
        &'a self,
        cred: &'a Cred,
        from_dir: &'a Handle,
        from: &'a str,
        to_dir: &'a Handle,
        to: &'a str,
        flags: RenameFlags,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.check_rw()?;
            let who = &cred.identity;
            let (from_dir_ino, mut from_dir_item) = self.check_handle(from_dir).await?;
            let (to_dir_ino, mut to_dir_item) = self.check_handle(to_dir).await?;
            check_component(from)?;
            check_component(to)?;
            let from_perm = self.searchable(cred, from_dir_ino, &from_dir_item).await?;
            let to_perm = self.searchable(cred, to_dir_ino, &to_dir_item).await?;

            let src_di = self
                .lookup_dir_item(from_dir_ino, from)
                .await?
                .ok_or(Errno::ENOENT)?;
            let dst_di = self.lookup_dir_item(to_dir_ino, to).await?;
            if dst_di.is_some() && flags.contains(RenameFlags::NOREPLACE) {
                return Err(Errno::EEXIST);
            }
            if dst_di.is_some_and(|d| d.child_ino == src_di.child_ino) {
                return Ok(());
            }

            let mut src_item = self
                .load_inode(src_di.child_ino)
                .await?
                .ok_or(Errno::ESTALE)?;
            let moving_dir = src_item.file_type == FileType::Dir;
            if moving_dir && self.is_ancestor(src_di.child_ino, to_dir_ino).await? {
                return Err(Errno::EINVAL);
            }
            let src_perm = self.load_perm_node(src_di.child_ino, &src_item).await?;
            inode::may_delete(who, &from_perm, &src_perm)?;

            let mut target_opt = None;
            match dst_di {
                Some(tdi) => {
                    let target_item = self.load_inode(tdi.child_ino).await?.ok_or(Errno::ESTALE)?;
                    let target_perm = self.load_perm_node(tdi.child_ino, &target_item).await?;
                    inode::may_delete(who, &to_perm, &target_perm)?;
                    match (moving_dir, target_item.file_type == FileType::Dir) {
                        (true, false) => return Err(Errno::ENOTDIR),
                        (false, true) => return Err(Errno::EISDIR),
                        _ => {}
                    }
                    if target_item.file_type == FileType::Dir
                        && !self.dir_is_empty(tdi.child_ino).await?
                    {
                        return Err(Errno::ENOTEMPTY);
                    }
                    target_opt = Some((tdi, target_item));
                }
                None => {
                    inode::may_create(who, &to_perm, to_dir_item.nlink == 0)?;
                }
            }
            if moving_dir && from_dir_ino != to_dir_ino {
                inode::require(who, &src_perm, WRITE)?;
            }

            self.maybe_backpressure_flush(1024).await?;
            let now = (self.clock)();

            // Handle replaced target (if any).
            if let Some((tdi, mut target_item)) = target_opt {
                {
                    let mut st = self.state.borrow_mut();
                    st.overlay.delete(TreeKey::dir_item(to_dir_ino, to));
                    st.overlay
                        .delete(TreeKey::dir_index(to_dir_ino, tdi.dir_index));
                    st.overlay
                        .delete(TreeKey::inode_ref(tdi.child_ino, to_dir_ino, to));
                }
                if moving_dir {
                    to_dir_item.nlink = to_dir_item.nlink.saturating_sub(1);
                    target_item.nlink = 0;
                } else {
                    target_item.nlink = target_item.nlink.saturating_sub(1);
                }
                target_item.ctime = now;
                self.stage_inode(tdi.child_ino, &target_item);
                self.reclaim_if_dead(tdi.child_ino, &target_item).await?;
            }

            // Reload `from_dir_item` / `to_dir_item` cleanly if they are the same directory.
            let same_dir = from_dir_ino == to_dir_ino;
            if same_dir {
                from_dir_item.nlink = to_dir_item.nlink;
            }
            let new_dir_index = if same_dir {
                let idx = from_dir_item.next_dir_index;
                from_dir_item.next_dir_index = idx.saturating_add(1);
                idx
            } else {
                let idx = to_dir_item.next_dir_index;
                to_dir_item.next_dir_index = idx.saturating_add(1);
                idx
            };

            if moving_dir && !same_dir {
                from_dir_item.nlink = from_dir_item.nlink.saturating_sub(1);
                to_dir_item.nlink = to_dir_item.nlink.saturating_add(1);
            }
            from_dir_item.mtime = now;
            from_dir_item.ctime = now;
            to_dir_item.mtime = now;
            to_dir_item.ctime = now;
            src_item.ctime = now;

            let new_di = DirItemValue {
                child_ino: src_di.child_ino,
                child_gen: src_item.generation,
                file_type: src_item.file_type,
                dir_index: new_dir_index,
            };
            let new_didx = DirIndexValue {
                child_ino: src_di.child_ino,
                child_gen: src_item.generation,
                file_type: src_item.file_type,
                name: to.to_string(),
            };
            {
                let mut st = self.state.borrow_mut();
                st.user_modified = true;
                st.overlay.delete(TreeKey::dir_item(from_dir_ino, from));
                st.overlay
                    .delete(TreeKey::dir_index(from_dir_ino, src_di.dir_index));
                st.overlay
                    .delete(TreeKey::inode_ref(src_di.child_ino, from_dir_ino, from));

                st.overlay
                    .put(TreeKey::dir_item(to_dir_ino, to), new_di.encode());
                st.overlay.put(
                    TreeKey::dir_index(to_dir_ino, new_dir_index),
                    new_didx.encode(),
                );
                st.overlay.put(
                    TreeKey::inode_ref(src_di.child_ino, to_dir_ino, to),
                    Vec::new(),
                );

                st.overlay
                    .put(TreeKey::inode_item(from_dir_ino), from_dir_item.encode());
                if !same_dir {
                    st.overlay
                        .put(TreeKey::inode_item(to_dir_ino), to_dir_item.encode());
                }
                st.overlay
                    .put(TreeKey::inode_item(src_di.child_ino), src_item.encode());
            }
            self.sync_arena_dirty();
            Ok(())
        })
    }

    fn getxattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let space = xattr::space(name)?;
            let (ino, item) = self.check_handle(handle).await?;
            let perm = self.load_perm_node(ino, &item).await?;
            xattr::readable(&cred.identity, &perm, space)?;
            match space {
                Space::Access | Space::Default => {
                    let entries = xattr::acl(&perm, space)?;
                    Ok(serde_json::to_vec(&entries).unwrap_or_default())
                }
                Space::User | Space::Trusted => self
                    .tree_get(&TreeKey::xattr_item(ino, name))
                    .await?
                    .ok_or(Errno::ENODATA),
            }
        })
    }

    fn setxattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
        value: &'a [u8],
        flags: XattrFlags,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.check_rw()?;
            let space = xattr::space(name)?;
            let (ino, mut item) = self.check_handle(handle).await?;
            let mut perm = self.load_perm_node(ino, &item).await?;
            xattr::settable(&cred.identity, &perm, space)?;
            match space {
                Space::Access | Space::Default => {
                    xattr::check_flags(flags.bits(), xattr::has_acl(&perm, space))?;
                    let entries: Entries =
                        serde_json::from_slice(value).map_err(|_| Errno::EINVAL)?;
                    xattr::set_acl(&cred.identity, &mut perm, space, entries)?;
                    item.apply_perm_node(&perm);
                    self.stage_perm_acls(ino, &perm)?;
                }
                Space::User | Space::Trusted => {
                    let mut attrs = self.load_user_trusted_xattrs(ino).await?;
                    xattr::check_flags(flags.bits(), attrs.contains_key(name))?;
                    xattr::store(&mut attrs, name, value)?;
                    self.maybe_backpressure_flush(name.len() + value.len() + 64)
                        .await?;
                    self.state
                        .borrow_mut()
                        .overlay
                        .put(TreeKey::xattr_item(ino, name), value.to_vec());
                }
            }
            item.ctime = (self.clock)();
            self.stage_inode(ino, &item);
            Ok(())
        })
    }

    fn listxattr<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Vec<String>> {
        Box::pin(async move {
            let (ino, item) = self.check_handle(handle).await?;
            let perm = self.load_perm_node(ino, &item).await?;
            let attrs = self.load_user_trusted_xattrs(ino).await?;
            Ok(xattr::listed(&cred.identity, &perm, attrs.keys()))
        })
    }

    fn removexattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.check_rw()?;
            let space = xattr::space(name)?;
            let (ino, mut item) = self.check_handle(handle).await?;
            let mut perm = self.load_perm_node(ino, &item).await?;
            xattr::settable(&cred.identity, &perm, space)?;
            match space {
                Space::Access | Space::Default => {
                    xattr::remove_acl(&mut perm, space)?;
                    item.apply_perm_node(&perm);
                    self.stage_perm_acls(ino, &perm)?;
                }
                Space::User | Space::Trusted => {
                    if self
                        .tree_get(&TreeKey::xattr_item(ino, name))
                        .await?
                        .is_none()
                    {
                        return Err(Errno::ENODATA);
                    }
                    self.state
                        .borrow_mut()
                        .overlay
                        .delete(TreeKey::xattr_item(ino, name));
                }
            }
            item.ctime = (self.clock)();
            self.stage_inode(ino, &item);
            Ok(())
        })
    }

    fn statfs<'a>(&'a self, _cred: &'a Cred) -> BoxFuture<'a, StatFs> {
        Box::pin(async move {
            let st = self.state.borrow();
            let blk_size = u64::from(BLOCK_SIZE);
            let total_bytes = self.capacity_bytes.unwrap_or(1024 * 1024 * 1024);
            let blocks = total_bytes.div_ceil(blk_size);
            let used_blocks = st.allocated_bytes.div_ceil(blk_size);
            Ok(StatFs {
                block_size: blk_size,
                blocks,
                blocks_free: blocks.saturating_sub(used_blocks),
                files: st.inode_count_estimate,
                files_free: u64::MAX.saturating_sub(st.root_obj.next_ino),
                name_max: abi::NAME_MAX as u64,
            })
        })
    }

    fn open<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        options: &'a OpenOptions,
    ) -> BoxFuture<'a, OpenRef> {
        Box::pin(async move {
            let (ino, mut item) = self.check_handle(handle).await?;
            let access = self.openable(cred, ino, &item, options).await?;
            if access != Access::Path && options.is_truncate() && item.file_type == FileType::File {
                let now = (self.clock)();
                self.resize_file(ino, &mut item, 0, &cred.identity, now)
                    .await?;
            }
            Ok(self.new_open(cred, ino, item.generation, access))
        })
    }

    fn open_metadata<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, Metadata> {
        Box::pin(async move {
            let (ino, generation, _, _) = self.open_record_clone(open)?;
            let item = self.load_inode(ino).await?.ok_or(Errno::ESTALE)?;
            if item.generation != generation {
                return Err(Errno::ESTALE);
            }
            Ok(item.to_metadata())
        })
    }

    fn read_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a mut [u8],
        offset: u64,
    ) -> BoxFuture<'a, usize> {
        Box::pin(async move {
            let (ino, generation, access, _) = self.open_record_clone(open)?;
            if !access.reads() {
                return Err(Errno::EBADF);
            }
            let mut item = self.load_inode(ino).await?.ok_or(Errno::ESTALE)?;
            if item.generation != generation {
                return Err(Errno::ESTALE);
            }
            match item.file_type {
                FileType::File => {}
                FileType::Dir => return Err(Errno::EISDIR),
                _ => return Err(Errno::ENXIO),
            }
            if offset > FILE_MAX || buf.len() as u64 > FILE_MAX - offset {
                return Err(Errno::EINVAL);
            }
            let len = buf.len().min(RW_MAX);
            let n = self
                .read_file_bytes(ino, item.size, offset, &mut buf[..len])
                .await?;
            self.update_atime_if_needed(ino, &mut item, false);
            Ok(n)
        })
    }

    fn write_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a [u8],
        at: WriteAt,
    ) -> BoxFuture<'a, Written> {
        Box::pin(async move {
            self.check_rw()?;
            let (ino, generation, access, writer) = self.open_record_clone(open)?;
            if !access.writes() {
                return Err(Errno::EBADF);
            }
            let mut item = self.load_inode(ino).await?.ok_or(Errno::ESTALE)?;
            if item.generation != generation {
                return Err(Errno::ESTALE);
            }
            match item.file_type {
                FileType::File => {}
                FileType::Dir => return Err(Errno::EISDIR),
                _ => return Err(Errno::ENXIO),
            }
            let offset = match at {
                WriteAt::Offset(off) => off,
                WriteAt::End => item.size,
            };
            if buf.is_empty() {
                return Ok(Written { offset, len: 0 });
            }
            if offset >= FILE_MAX {
                return Err(Errno::EFBIG);
            }
            let room = usize::try_from(FILE_MAX - offset).unwrap_or(usize::MAX);
            let len = buf.len().min(room).min(RW_MAX);
            let written = self
                .write_file_bytes(ino, &mut item, offset, &buf[..len])
                .await?;
            if written > 0 {
                let mut perm = self.load_perm_node(ino, &item).await?;
                inode::remove_privs(&writer, &mut perm);
                item.apply_perm_node(&perm);
                let now = (self.clock)();
                item.mtime = now;
                item.ctime = now;
                self.stage_inode(ino, &item);
            }
            Ok(Written {
                offset,
                len: written,
            })
        })
    }

    fn set_len<'a>(&'a self, open: &'a OpenRef, size: u64) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let (ino, generation, access, writer) = self.open_record_clone(open)?;
            if access == Access::Path {
                return Err(Errno::EBADF);
            }
            self.check_rw()?;
            let mut item = self.load_inode(ino).await?.ok_or(Errno::ESTALE)?;
            if item.generation != generation {
                return Err(Errno::ESTALE);
            }
            if !access.writes() || item.file_type != FileType::File {
                return Err(Errno::EINVAL);
            }
            if size > FILE_MAX {
                return Err(Errno::EFBIG);
            }
            let now = (self.clock)();
            self.resize_file(ino, &mut item, size, &writer, now).await
        })
    }

    fn sync_all<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let (_, _, access, _) = self.open_record_clone(open)?;
            if access == Access::Path {
                return Err(Errno::EBADF);
            }
            if self.read_only {
                return Ok(());
            }
            self.commit_tx_group().await.map(|_| ())
        })
    }

    fn sync_fs<'a>(&'a self, _cred: &'a Cred) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if self.read_only {
                return Ok(());
            }
            self.commit_tx_group().await.map(|_| ())
        })
    }

    /// Intra-volume O(extents) extent clone (`FICLONE`, contract §5, Blueprint §3.2): copies
    /// `EXTENT_DATA` B+tree references with ZERO data bytes written to `PackStore`.
    fn reflink<'a>(
        &'a self,
        _cred: &'a Cred,
        src_open: &'a OpenRef,
        dst_open: &'a OpenRef,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if src_open.fs != self.fs_id || dst_open.fs != self.fs_id {
                return Err(Errno::EXDEV);
            }
            self.check_rw()?;
            let (src_ino, src_gen, src_acc, _) = self.open_record_clone(src_open)?;
            let (dst_ino, dst_gen, dst_acc, writer) = self.open_record_clone(dst_open)?;
            if !src_acc.reads() || !dst_acc.writes() {
                return Err(Errno::EBADF);
            }
            let src_item = self.load_inode(src_ino).await?.ok_or(Errno::ESTALE)?;
            let mut dst_item = self.load_inode(dst_ino).await?.ok_or(Errno::ESTALE)?;
            if src_item.generation != src_gen || dst_item.generation != dst_gen {
                return Err(Errno::ESTALE);
            }
            if src_item.file_type == FileType::Dir || dst_item.file_type == FileType::Dir {
                return Err(Errno::EISDIR);
            }
            if src_item.file_type != FileType::File || dst_item.file_type != FileType::File {
                return Err(Errno::EINVAL);
            }
            if src_ino == dst_ino {
                return Ok(());
            }

            // 1. Delete existing extents on dst_ino.
            let mut start = TreeKey::kind_start(dst_ino, KIND_EXTENT_DATA);
            let end = TreeKey::kind_end(dst_ino, KIND_EXTENT_DATA);
            loop {
                let batch = self.tree_scan(&start, &end, 256).await?;
                if batch.is_empty() {
                    break;
                }
                let last = batch.last().unwrap().0.clone();
                let full = batch.len() == 256;
                {
                    let mut st = self.state.borrow_mut();
                    for (k, raw) in batch {
                        if let Ok(ExtentDataValue::Extent { digest, .. }) =
                            ExtentDataValue::decode(&raw)
                        {
                            st.unstage_dirty_block(&digest);
                        }
                        st.overlay.delete(k);
                    }
                }
                if !full {
                    break;
                }
                let mut tail = last.tail;
                tail.push(0);
                start = TreeKey::new(last.ino, last.kind, tail);
            }

            // 2. Clone EXTENT_DATA B+tree items from src_ino to dst_ino (zero pack bytes copied).
            let mut s_start = TreeKey::kind_start(src_ino, KIND_EXTENT_DATA);
            let s_end = TreeKey::kind_end(src_ino, KIND_EXTENT_DATA);
            loop {
                let batch = self.tree_scan(&s_start, &s_end, 256).await?;
                if batch.is_empty() {
                    break;
                }
                let last = batch.last().unwrap().0.clone();
                let full = batch.len() == 256;
                {
                    let mut st = self.state.borrow_mut();
                    for (k, raw) in batch {
                        if let Ok(ExtentDataValue::Extent { digest, .. }) =
                            ExtentDataValue::decode(&raw)
                            && let Some((bytes, _)) = st.dirty_blocks.get(&digest).cloned()
                        {
                            st.stage_dirty_block(digest, bytes);
                        }
                        let dst_key = TreeKey::new(dst_ino, KIND_EXTENT_DATA, k.tail);
                        st.overlay.put(dst_key, raw);
                    }
                }
                if !full {
                    break;
                }
                let mut tail = last.tail;
                tail.push(0);
                s_start = TreeKey::new(last.ino, last.kind, tail);
            }

            let mut perm = self.load_perm_node(dst_ino, &dst_item).await?;
            inode::remove_privs(&writer, &mut perm);
            dst_item.apply_perm_node(&perm);
            dst_item.size = src_item.size;
            let now = (self.clock)();
            dst_item.mtime = now;
            dst_item.ctime = now;
            self.stage_inode(dst_ino, &dst_item);
            self.sync_arena_dirty();
            Ok(())
        })
    }

    fn lock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        Box::pin(CowLockWait {
            fs: self,
            open,
            family,
            kind,
            range,
            waiting: None,
        })
    }

    fn try_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.acquire_lock(open, family, kind, range, None)
                .map(|_| ())
        })
    }

    fn unlock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let ino = self.lockable(open, family, None, range)?;
            {
                let mut st = self.state.borrow_mut();
                if let Some(locks) = st.locks.get_mut(&ino) {
                    carve(locks, open.id, family, range);
                }
            }
            self.wake_lock_waiters(ino);
            Ok(())
        })
    }

    fn test_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, Option<Conflict>> {
        Box::pin(async move {
            let ino = self.lockable(open, LockFamily::Posix, None, range)?;
            let st = self.state.borrow();
            Ok(Self::conflict(
                &st,
                ino,
                open.id,
                LockFamily::Posix,
                kind,
                range,
            ))
        })
    }

    fn release<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let (ino, _, _, _) = self.open_record_clone(open)?;
            {
                let mut st = self.state.borrow_mut();
                st.opens.remove(&open.id);
                if let Some(locks) = st.locks.get_mut(&ino) {
                    locks.retain(|l| l.owner != open.id);
                }
                if let Some(cnt) = st.open_counts.get_mut(&ino) {
                    *cnt = cnt.saturating_sub(1);
                    if *cnt == 0 {
                        st.open_counts.remove(&ino);
                    }
                }
            }
            if !self.read_only
                && let Some(item) = self.load_inode(ino).await?
            {
                self.reclaim_if_dead(ino, &item).await?;
            }
            self.wake_lock_waiters(ino);
            Ok(())
        })
    }
}

impl<H: HeadStore + 'static, P: PackStore + 'static> CowFs<H, P> {
    async fn do_remove(
        &self,
        cred: &Cred,
        dir: &Handle,
        name: &str,
        directory: bool,
        expected: Option<NodeId>,
    ) -> Result<()> {
        self.check_rw()?;
        let (dir_ino, mut dir_item) = self.check_handle(dir).await?;
        check_component(name)?;
        let dir_perm = self.searchable(cred, dir_ino, &dir_item).await?;
        let di = self
            .lookup_dir_item(dir_ino, name)
            .await?
            .ok_or(Errno::ENOENT)?;
        if expected.is_some_and(|node| node.ino != di.child_ino || node.generation != di.child_gen)
        {
            return Err(Errno::ESTALE);
        }
        let mut victim = self.load_inode(di.child_ino).await?.ok_or(Errno::ESTALE)?;
        let victim_perm = self.load_perm_node(di.child_ino, &victim).await?;
        inode::may_delete(&cred.identity, &dir_perm, &victim_perm)?;

        match (directory, victim.file_type == FileType::Dir) {
            (false, true) => return Err(Errno::EISDIR),
            (true, false) => return Err(Errno::ENOTDIR),
            (true, true) if !self.dir_is_empty(di.child_ino).await? => {
                return Err(Errno::ENOTEMPTY);
            }
            _ => {}
        }

        self.maybe_backpressure_flush(512).await?;
        let now = (self.clock)();
        if directory {
            dir_item.nlink = dir_item.nlink.saturating_sub(1);
            victim.nlink = 0;
        } else {
            victim.nlink = victim.nlink.saturating_sub(1);
        }
        dir_item.mtime = now;
        dir_item.ctime = now;
        victim.ctime = now;

        {
            let mut st = self.state.borrow_mut();
            st.user_modified = true;
            st.overlay.delete(TreeKey::dir_item(dir_ino, name));
            st.overlay.delete(TreeKey::dir_index(dir_ino, di.dir_index));
            st.overlay
                .delete(TreeKey::inode_ref(di.child_ino, dir_ino, name));
            st.overlay
                .put(TreeKey::inode_item(dir_ino), dir_item.encode());
            st.overlay
                .put(TreeKey::inode_item(di.child_ino), victim.encode());
        }
        self.sync_arena_dirty();
        self.reclaim_if_dead(di.child_ino, &victim).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify_volume;
    use cowtree::memory::{MemoryHeadStore, MemoryPackStore};

    fn block_on<F: Future>(fut: F) -> F::Output {
        vfs::now_or_never(fut).expect("memory cowfs future ready")
    }

    #[test]
    fn uncommitted_multiblock_extent_split_preserves_dirty_block_on_write_and_truncate() {
        let hs = Rc::new(MemoryHeadStore::new());
        let ps = Rc::new(MemoryPackStore::new());
        let vol = VolumeId("vol-multiblk-split".into());
        let now = Timespec { sec: 1000, nsec: 0 };
        block_on(CowFs::format_volume(
            &*hs,
            &*ps,
            vol.clone(),
            0,
            0,
            0o755,
            now,
        ))
        .unwrap();
        let fs = block_on(CowFs::open(
            hs.clone(),
            ps.clone(),
            vol.clone(),
            CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
            CowFsConfig::local_browser(Rc::new(move || now)),
        ))
        .unwrap();
        let admin = Cred::root();
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true);

        // (a) Stage a single 192 KiB (3 * 64 KiB) uncommitted multi-block extent with refcount 1,
        // then overwrite its middle 64 KiB block -> splits into prefix [0, 64K), new [64K, 128K),
        // and suffix [128K, 192K). Both prefix and suffix must keep the dirty block staged!
        let (e_write, o_write) =
            block_on(fs.create(&admin, &fs.root(), "split_write.bin", 0o644, &opts)).unwrap();
        let ino_w = e_write.handle.node.ino;
        let mut multi_w = vec![0u8; 3 * BLOCK_SIZE as usize];
        multi_w[0..BLOCK_SIZE as usize].fill(0x11);
        multi_w[BLOCK_SIZE as usize..2 * BLOCK_SIZE as usize].fill(0x22);
        multi_w[2 * BLOCK_SIZE as usize..3 * BLOCK_SIZE as usize].fill(0x33);
        let dig_w = sha256(&multi_w);
        let ext_w = ExtentDataValue::Extent {
            len: 3 * BLOCK_SIZE,
            digest: dig_w,
            block_offset: 0,
        }
        .encode()
        .unwrap();
        {
            let mut item = block_on(fs.load_inode(ino_w)).unwrap().unwrap();
            item.size = (3 * BLOCK_SIZE) as u64;
            let mut st = fs.state.borrow_mut();
            st.stage_dirty_block(dig_w, Rc::new(multi_w));
            st.overlay.put(TreeKey::extent_data(ino_w, 0), ext_w);
            st.overlay.put(TreeKey::inode_item(ino_w), item.encode());
            st.user_modified = true;
        }
        // Overwrite 4 bytes inside the middle 64 KiB block [64K, 128K).
        block_on(fs.write_at(
            &o_write,
            b"MID!",
            WriteAt::Offset(u64::from(BLOCK_SIZE) + 8),
        ))
        .unwrap();

        // (b) Stage a single 192 KiB uncommitted multi-block extent with refcount 1, then truncate
        // to `128 KiB + 17` -> splits into untouched prefix [0, 128K) + zero-padded tail [128K, 192K).
        let (e_trunc, o_trunc) =
            block_on(fs.create(&admin, &fs.root(), "split_trunc.bin", 0o644, &opts)).unwrap();
        let ino_t = e_trunc.handle.node.ino;
        let mut multi_t = vec![0u8; 3 * BLOCK_SIZE as usize];
        multi_t[0..BLOCK_SIZE as usize].fill(0x44);
        multi_t[BLOCK_SIZE as usize..2 * BLOCK_SIZE as usize].fill(0x55);
        multi_t[2 * BLOCK_SIZE as usize..3 * BLOCK_SIZE as usize].fill(0x66);
        let dig_t = sha256(&multi_t);
        let ext_t = ExtentDataValue::Extent {
            len: 3 * BLOCK_SIZE,
            digest: dig_t,
            block_offset: 0,
        }
        .encode()
        .unwrap();
        {
            let mut item = block_on(fs.load_inode(ino_t)).unwrap().unwrap();
            item.size = (3 * BLOCK_SIZE) as u64;
            let mut st = fs.state.borrow_mut();
            st.stage_dirty_block(dig_t, Rc::new(multi_t));
            st.overlay.put(TreeKey::extent_data(ino_t, 0), ext_t);
            st.overlay.put(TreeKey::inode_item(ino_t), item.encode());
            st.user_modified = true;
        }
        let trunc_len = 2 * u64::from(BLOCK_SIZE) + 17;
        block_on(fs.set_len(&o_trunc, trunc_len)).unwrap();

        // Commit, drop caches, and verify BOTH split files read back intact from PackStore!
        block_on(fs.commit_tx_group()).unwrap();
        block_on(fs.release(&o_write)).unwrap();
        block_on(fs.release(&o_trunc)).unwrap();
        block_on(fs.close_clean()).unwrap();

        let report = block_on(verify_volume(&*hs, &*ps, &vol)).unwrap();
        assert!(report.ok, "fsck errors: {:?}", report.errors);

        let ro = block_on(CowFs::open(
            hs.clone(),
            ps.clone(),
            vol,
            CowFsOpenMode::ReadOnly,
            CowFsConfig::local_browser(Rc::new(move || now)),
        ))
        .unwrap();
        let mut ro_opt = OpenOptions::new();
        ro_opt.read(true);

        let w_ent = block_on(ro.lookup(&admin, &ro.root(), "split_write.bin")).unwrap();
        let w_fd = block_on(ro.open(&admin, &w_ent.handle, &ro_opt)).unwrap();
        let mut buf = vec![0u8; 3 * BLOCK_SIZE as usize];
        let mut off = 0;
        while off < buf.len() {
            let n = block_on(ro.read_at(&w_fd, &mut buf[off..], off as u64)).unwrap();
            assert!(n > 0);
            off += n;
        }
        assert!(buf[0..BLOCK_SIZE as usize].iter().all(|&b| b == 0x11));
        assert_eq!(
            &buf[BLOCK_SIZE as usize + 8..BLOCK_SIZE as usize + 12],
            b"MID!"
        );
        assert_eq!(buf[BLOCK_SIZE as usize], 0x22);
        assert!(buf[2 * BLOCK_SIZE as usize..].iter().all(|&b| b == 0x33));
        block_on(ro.release(&w_fd)).unwrap();

        let t_ent = block_on(ro.lookup(&admin, &ro.root(), "split_trunc.bin")).unwrap();
        assert_eq!(t_ent.metadata.size, trunc_len);
        let t_fd = block_on(ro.open(&admin, &t_ent.handle, &ro_opt)).unwrap();
        let mut tbuf = vec![0u8; trunc_len as usize];
        let mut toff = 0;
        while toff < tbuf.len() {
            let n = block_on(ro.read_at(&t_fd, &mut tbuf[toff..], toff as u64)).unwrap();
            assert!(n > 0);
            toff += n;
        }
        assert!(tbuf[0..BLOCK_SIZE as usize].iter().all(|&b| b == 0x44));
        assert!(
            tbuf[BLOCK_SIZE as usize..2 * BLOCK_SIZE as usize]
                .iter()
                .all(|&b| b == 0x55)
        );
        assert!(tbuf[2 * BLOCK_SIZE as usize..].iter().all(|&b| b == 0x66));
        block_on(ro.release(&t_fd)).unwrap();
    }
}
