//! Native Rust integration test suite for Issue `#56` (`L3c` — Two-Stage Standalone Offline Boot,
//! Blueprint §3.2 `B-01..08`, `docs/architecture/contract.md` §5).
//!
//! Exercises the real `TwoStageBoot` + `os_vfs::Vfs` + `os_cowfs::CowFs` + `os_cowtree` +
//! `LocalProcessTable` end-to-end with zero network and zero cloud drivers.

use abi::Errno;
use abi::contract::fs_magic;
use cowtree::pack::decode_pack_trailer;
use cowtree::{
    BlockLoc, COWFS_FORMAT_VERSION, CommitRequest, Digest, ForkRequest, GcLockGuard, GcRoot,
    HeadStore, PackId, PackMeta, PackStore, PackTrailer, RoPinGuard, SnapshotRecord, VolumeHead,
    VolumeId, WriterLease, WriterLockGuard, WriterMode,
};
use image::{CHUNK_SIZE_DEFAULT, Entry, Image, Kind, Node, chunk_digests, digest};
use os_client_kernel::boot_stage::{
    BOOT_PROFILE_PATH, BOOT_PROFILE_VERSION, BootProfile, BootStage, BootWriterMode,
    COWFSCK_REPORT_PATH, DEFAULT_STAGE2_INIT, MOUNTED_ROOT_INFO_PATH, MountedRootInfo,
    RecoveryReason, ReleaseImages, RootSpec, TwoStageBoot,
};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::rc::Rc;
use vfs::imagefs::MemoryBlobStore;
use vfs::{BoxFuture, Timespec};

const WASM_STUB: &[u8] = b"\0asm\x01\x00\x00\x00";

// -----------------------------------------------------------------------------
// Self-contained test-only in-memory `HeadStore` + `PackStore` with fault hooks
// -----------------------------------------------------------------------------

struct TestWriterGuard {
    state: Rc<RefCell<TestHeadState>>,
    volume: VolumeId,
    token: u64,
}
impl WriterLockGuard for TestWriterGuard {}
impl Drop for TestWriterGuard {
    fn drop(&mut self) {
        let mut st = self.state.borrow_mut();
        if st.active_locks.get(&self.volume) == Some(&self.token) {
            st.active_locks.remove(&self.volume);
        }
    }
}

struct TestGcGuard;
impl GcLockGuard for TestGcGuard {}

struct TestRoPinGuard;
impl RoPinGuard for TestRoPinGuard {}

#[derive(Default)]
struct TestHeadState {
    format_version: Option<u32>,
    heads: HashMap<VolumeId, VolumeHead>,
    nodes: HashMap<Digest, Vec<u8>>,
    packs: HashMap<PackId, PackMeta>,
    blocks: HashMap<Digest, BlockLoc>,
    snapshots: HashMap<(VolumeId, String), SnapshotRecord>,
    active_locks: HashMap<VolumeId, u64>,
    next_lock_token: u64,
    next_fork_seq: u64,
}

#[derive(Clone, Default)]
struct TestHeadStore {
    state: Rc<RefCell<TestHeadState>>,
}

impl TestHeadStore {
    fn new() -> Self {
        Self::default()
    }

    fn set_format_version(&self, version: Option<u32>) {
        self.state.borrow_mut().format_version = version;
    }

    fn corrupt_node_byte(&self, digest: &Digest, offset: usize) -> bool {
        let mut st = self.state.borrow_mut();
        if let Some(bytes) = st.nodes.get_mut(digest)
            && offset < bytes.len()
        {
            bytes[offset] ^= 0x01;
            return true;
        }
        false
    }
}

impl HeadStore for TestHeadStore {
    fn format_version(&self) -> BoxFuture<'_, Option<u32>> {
        Box::pin(async move { Ok(self.state.borrow().format_version) })
    }

    fn grace_window_secs(&self) -> u64 {
        600
    }

    fn create_volume<'a>(
        &'a self,
        head: &'a VolumeHead,
        initial_nodes: &'a [(Digest, Vec<u8>)],
    ) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async move {
            let mut st = self.state.borrow_mut();
            if let Some(ver) = st.format_version
                && ver != COWFS_FORMAT_VERSION
            {
                return Err(Errno::EPROTONOSUPPORT);
            }
            if st.heads.contains_key(&head.volume) {
                return Err(Errno::EEXIST);
            }
            st.format_version = Some(COWFS_FORMAT_VERSION);
            for (d, b) in initial_nodes {
                st.nodes.insert(*d, b.clone());
            }
            st.heads.insert(head.volume.clone(), head.clone());
            Ok(head.clone())
        })
    }

    fn read_head<'a>(&'a self, volume: &'a VolumeId) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async move {
            let st = self.state.borrow();
            st.heads.get(volume).cloned().ok_or(Errno::ENOENT)
        })
    }

    fn pin_ro_root<'a>(
        &'a self,
        volume: &'a VolumeId,
        snapshot: Option<&'a str>,
    ) -> BoxFuture<'a, (VolumeHead, Box<dyn RoPinGuard>)> {
        Box::pin(async move {
            let st = self.state.borrow();
            let mut head = st.heads.get(volume).cloned().ok_or(Errno::ENOENT)?;
            if let Some(snap_name) = snapshot {
                let snap = st
                    .snapshots
                    .get(&(volume.clone(), snap_name.to_string()))
                    .ok_or(Errno::ENOENT)?;
                head.root = snap.root;
                head.epoch = snap.epoch;
            }
            Ok((head, Box::new(TestRoPinGuard) as Box<dyn RoPinGuard>))
        })
    }

    fn unpin_ro_root<'a>(&'a self, _pin: Box<dyn RoPinGuard>) -> BoxFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn acquire_writer<'a>(
        &'a self,
        volume: &'a VolumeId,
        mode: WriterMode,
    ) -> BoxFuture<'a, WriterLease> {
        Box::pin(async move {
            let mut st = self.state.borrow_mut();
            if let Some(ver) = st.format_version
                && ver != COWFS_FORMAT_VERSION
            {
                return Err(Errno::EPROTONOSUPPORT);
            }
            let busy = st.active_locks.contains_key(volume);
            if busy {
                match mode {
                    WriterMode::Exclusive => return Err(Errno::EBUSY),
                    WriterMode::ForkOnBusy => {
                        let parent = st.heads.get(volume).cloned().ok_or(Errno::ENOENT)?;
                        st.next_fork_seq += 1;
                        let fork_id = VolumeId(format!("{}-fork-{}", volume.0, st.next_fork_seq));
                        let fork_head = VolumeHead {
                            format_version: COWFS_FORMAT_VERSION,
                            volume: fork_id.clone(),
                            incarnation: 1,
                            fence: 1,
                            epoch: parent.epoch,
                            root: parent.root,
                            parent_volume: Some(volume.clone()),
                            ephemeral_if_unmodified: true,
                            modified: false,
                            updated_at: parent.updated_at,
                        };
                        st.heads.insert(fork_id.clone(), fork_head.clone());
                        st.next_lock_token += 1;
                        let token = st.next_lock_token;
                        st.active_locks.insert(fork_id.clone(), token);
                        return Ok(WriterLease {
                            volume: fork_id.clone(),
                            incarnation: fork_head.incarnation,
                            fence: fork_head.fence,
                            epoch: fork_head.epoch,
                            head: fork_head,
                            forked_from: Some(volume.clone()),
                            expires_at: None,
                            guard: Box::new(TestWriterGuard {
                                state: Rc::clone(&self.state),
                                volume: fork_id,
                                token,
                            }),
                        });
                    }
                    WriterMode::ForceTakeover => {}
                }
            }
            let head = st.heads.get_mut(volume).ok_or(Errno::ENOENT)?;
            head.fence += 1;
            let updated = head.clone();
            st.next_lock_token += 1;
            let token = st.next_lock_token;
            st.active_locks.insert(volume.clone(), token);
            Ok(WriterLease {
                volume: volume.clone(),
                incarnation: updated.incarnation,
                fence: updated.fence,
                epoch: updated.epoch,
                head: updated,
                forked_from: None,
                expires_at: None,
                guard: Box::new(TestWriterGuard {
                    state: Rc::clone(&self.state),
                    volume: volume.clone(),
                    token,
                }),
            })
        })
    }

    fn renew_writer<'a>(&'a self, _lease: &'a mut WriterLease) -> BoxFuture<'a, ()> {
        Box::pin(async { Ok(()) })
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
                .cloned()
                .ok_or(Errno::ENOENT)
        })
    }

    fn lookup_block<'a>(&'a self, digest: &'a Digest) -> BoxFuture<'a, Option<BlockLoc>> {
        Box::pin(async move { Ok(self.state.borrow().blocks.get(digest).cloned()) })
    }

    fn commit_head<'a>(&'a self, req: &'a CommitRequest) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async move {
            let mut st = self.state.borrow_mut();
            let cur = st.heads.get(&req.volume).cloned().ok_or(Errno::ENOENT)?;
            if cur.incarnation != req.expected_incarnation
                || cur.fence != req.expected_fence
                || cur.epoch != req.expected_epoch
            {
                return Err(Errno::ESTALE);
            }
            for (d, b) in &req.put_nodes {
                st.nodes.insert(*d, b.clone());
            }
            for pm in &req.put_packs {
                st.packs.insert(pm.pack_id.clone(), pm.clone());
            }
            for (d, loc) in &req.put_blocks {
                st.blocks.insert(*d, loc.clone());
            }
            let next = VolumeHead {
                epoch: cur.epoch + 1,
                root: req.new_root,
                modified: true,
                ephemeral_if_unmodified: false,
                updated_at: req.committed_at,
                ..cur
            };
            st.heads.insert(req.volume.clone(), next.clone());
            Ok(next)
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
            let mut st = self.state.borrow_mut();
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
            let st = self.state.borrow();
            let mut out: Vec<_> = st
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

    fn fork_volume<'a>(&'a self, req: &'a ForkRequest) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async move {
            let mut st = self.state.borrow_mut();
            if st.heads.contains_key(&req.new_volume) {
                return Err(Errno::EEXIST);
            }
            let epoch = if let Some(snap_name) = &req.source_snapshot {
                st.snapshots
                    .get(&(req.source_volume.clone(), snap_name.clone()))
                    .map(|s| s.epoch)
                    .ok_or(Errno::ENOENT)?
            } else {
                st.heads
                    .get(&req.source_volume)
                    .map(|h| h.epoch)
                    .ok_or(Errno::ENOENT)?
            };
            let head = VolumeHead {
                format_version: COWFS_FORMAT_VERSION,
                volume: req.new_volume.clone(),
                incarnation: 1,
                fence: 0,
                epoch,
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
            Ok(())
        })
    }

    fn delete_volume_with_lease<'a>(
        &'a self,
        lease: WriterLease,
        only_if_unmodified_ephemeral: bool,
    ) -> BoxFuture<'a, bool> {
        Box::pin(async move {
            let deleted = {
                let mut st = self.state.borrow_mut();
                let cur = st.heads.get(&lease.volume).cloned().ok_or(Errno::ENOENT)?;
                if cur.incarnation != lease.incarnation
                    || cur.fence != lease.fence
                    || cur.epoch != lease.epoch
                {
                    return Err(Errno::ESTALE);
                }
                if only_if_unmodified_ephemeral && (!cur.ephemeral_if_unmodified || cur.modified) {
                    false
                } else {
                    st.heads.remove(&lease.volume);
                    st.snapshots.retain(|(v, _), _| v != &lease.volume);
                    true
                }
            };
            drop(lease);
            Ok(deleted)
        })
    }

    fn reformat_volume_with_lease<'a>(
        &'a self,
        lease: WriterLease,
        new_head: &'a VolumeHead,
        initial_nodes: &'a [(Digest, Vec<u8>)],
    ) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async move {
            let next = {
                let mut st = self.state.borrow_mut();
                let cur = st.heads.get(&lease.volume).cloned().ok_or(Errno::ENOENT)?;
                for (d, b) in initial_nodes {
                    st.nodes.insert(*d, b.clone());
                }
                let updated = VolumeHead {
                    incarnation: cur.incarnation + 1,
                    fence: 1,
                    epoch: 0,
                    ..new_head.clone()
                };
                st.heads.insert(lease.volume.clone(), updated.clone());
                st.snapshots.retain(|(v, _), _| v != &lease.volume);
                updated
            };
            drop(lease);
            Ok(next)
        })
    }

    fn acquire_gc_lock(&self, _exclusive: bool) -> BoxFuture<'_, Box<dyn GcLockGuard>> {
        Box::pin(async { Ok(Box::new(TestGcGuard) as Box<dyn GcLockGuard>) })
    }

    fn list_all_roots(&self) -> BoxFuture<'_, Vec<GcRoot>> {
        Box::pin(async move {
            let st = self.state.borrow();
            Ok(st
                .heads
                .values()
                .map(|h| GcRoot {
                    volume: h.volume.clone(),
                    root: h.root,
                    pinned_until: None,
                })
                .collect())
        })
    }

    fn list_indexed_packs(&self) -> BoxFuture<'_, HashSet<PackId>> {
        Box::pin(async move { Ok(self.state.borrow().packs.keys().cloned().collect()) })
    }

    fn prune_abandoned_ephemeral_forks(
        &self,
        _now: Timespec,
        _grace_window_secs: u64,
    ) -> BoxFuture<'_, usize> {
        Box::pin(async { Ok(0) })
    }

    fn sweep_metadata<'a>(
        &'a self,
        _keep_nodes: &'a HashSet<Digest>,
        _keep_packs: &'a HashSet<PackId>,
        _now: Timespec,
        _grace_window_secs: u64,
    ) -> BoxFuture<'a, Vec<PackId>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

#[derive(Clone, Default)]
struct TestPackStore {
    packs: Rc<RefCell<HashMap<PackId, Vec<u8>>>>,
}

impl TestPackStore {
    fn new() -> Self {
        Self::default()
    }
}

impl PackStore for TestPackStore {
    fn write_pack<'a>(&'a self, pack_id: &'a PackId, bytes: &'a [u8]) -> BoxFuture<'a, PackMeta> {
        Box::pin(async move {
            let trailer = decode_pack_trailer(bytes)?;
            self.packs
                .borrow_mut()
                .insert(pack_id.clone(), bytes.to_vec());
            Ok(PackMeta {
                pack_id: pack_id.clone(),
                size: bytes.len() as u32,
                entry_count: trailer.entries.len() as u32,
                created_at: Timespec { sec: 0, nsec: 0 },
            })
        })
    }

    fn read_pack_range<'a>(
        &'a self,
        pack_id: &'a PackId,
        offset: u32,
        len: u32,
    ) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let map = self.packs.borrow();
            let bytes = map.get(pack_id).ok_or(Errno::ENOENT)?;
            let start = offset as usize;
            let end = start.checked_add(len as usize).ok_or(Errno::EINVAL)?;
            if end > bytes.len() {
                return Err(Errno::EIO);
            }
            Ok(bytes[start..end].to_vec())
        })
    }

    fn read_pack_trailer<'a>(&'a self, pack_id: &'a PackId) -> BoxFuture<'a, PackTrailer> {
        Box::pin(async move {
            let map = self.packs.borrow();
            let bytes = map.get(pack_id).ok_or(Errno::ENOENT)?;
            decode_pack_trailer(bytes)
        })
    }

    fn stat_pack<'a>(&'a self, pack_id: &'a PackId) -> BoxFuture<'a, Option<u64>> {
        Box::pin(async move { Ok(self.packs.borrow().get(pack_id).map(|b| b.len() as u64)) })
    }

    fn list_packs(&self) -> BoxFuture<'_, Vec<PackId>> {
        Box::pin(async move { Ok(self.packs.borrow().keys().cloned().collect()) })
    }

    fn delete_pack<'a>(&'a self, pack_id: &'a PackId) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.packs.borrow_mut().remove(pack_id);
            Ok(())
        })
    }
}

// -----------------------------------------------------------------------------
// Synthetic Release v2 image builders
// -----------------------------------------------------------------------------

fn add_file(
    entries: &mut Vec<Entry>,
    blobs: &mut HashMap<String, Vec<u8>>,
    path: &str,
    uid: u32,
    gid: u32,
    mode: u16,
    bytes: &[u8],
) {
    let sha = digest(bytes);
    let chunks = chunk_digests(bytes, CHUNK_SIZE_DEFAULT).unwrap();
    blobs.insert(sha.clone(), bytes.to_vec());
    entries.push(Entry {
        path: path.to_string(),
        uid,
        gid,
        mode,
        node: Node::File {
            sha256: sha,
            size: bytes.len() as u64,
            chunk_size: CHUNK_SIZE_DEFAULT,
            chunks,
        },
    });
}

fn add_dir(entries: &mut Vec<Entry>, path: &str, uid: u32, gid: u32, mode: u16) {
    entries.push(Entry {
        path: path.to_string(),
        uid,
        gid,
        mode,
        node: Node::Directory,
    });
}

fn add_symlink(entries: &mut Vec<Entry>, path: &str, target: &str) {
    entries.push(Entry {
        path: path.to_string(),
        uid: 0,
        gid: 0,
        mode: 0o777,
        node: Node::Symlink {
            target: target.to_string(),
        },
    });
}

fn finalize_image(kind: Kind, name: &str, mut entries: Vec<Entry>) -> Image {
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    let img = Image {
        format: "os.image".to_string(),
        version: image::IMAGE_VERSION,
        abi: image::ABI,
        level: image::LEVEL,
        kind,
        name: name.to_string(),
        revision: "test-rev-1".to_string(),
        features: Vec::new(),
        provenance: BTreeMap::new(),
        entries,
    };
    img.validate().expect("synthetic release image valid");
    img
}

fn synthetic_release() -> (ReleaseImages, MemoryBlobStore) {
    let mut blob_map = HashMap::new();

    // 1. Stage 1 `Kind::Initramfs`
    let mut initramfs_entries = Vec::new();
    for d in [
        "/", "/dev", "/etc", "/proc", "/run", "/sysroot", "/tmp", "/usr", "/usr/bin", "/usr/lib",
    ] {
        add_dir(
            &mut initramfs_entries,
            d,
            0,
            0,
            if d == "/tmp" { 0o1777 } else { 0o755 },
        );
    }
    add_symlink(&mut initramfs_entries, "/bin", "usr/bin");
    add_symlink(&mut initramfs_entries, "/sbin", "usr/bin");
    add_symlink(&mut initramfs_entries, "/lib", "usr/lib");
    add_symlink(&mut initramfs_entries, "/lib64", "usr/lib");
    add_file(
        &mut initramfs_entries,
        &mut blob_map,
        "/init",
        0,
        0,
        0o755,
        WASM_STUB,
    );
    add_file(
        &mut initramfs_entries,
        &mut blob_map,
        "/usr/bin/utilities",
        0,
        0,
        0o755,
        WASM_STUB,
    );
    add_file(
        &mut initramfs_entries,
        &mut blob_map,
        "/usr/bin/dash",
        0,
        0,
        0o755,
        WASM_STUB,
    );
    add_symlink(&mut initramfs_entries, "/usr/bin/mount", "utilities");
    add_symlink(&mut initramfs_entries, "/usr/bin/switch_root", "utilities");
    add_symlink(&mut initramfs_entries, "/usr/bin/cowfsck", "utilities");
    add_symlink(&mut initramfs_entries, "/usr/bin/sh", "dash");
    let initramfs = finalize_image(Kind::Initramfs, "initramfs", initramfs_entries);

    // 2. `Kind::RootTemplate` (matching exact Contract §2.10 / §5 modes!)
    let mut tpl_entries = Vec::new();
    for (d, uid, gid, mode) in [
        ("/", 0, 0, 0o755),
        ("/dev", 0, 0, 0o755),
        ("/etc", 0, 0, 0o755),
        ("/home", 0, 0, 0o755),
        ("/home/user", 1000, 1000, 0o750),
        ("/mnt", 0, 0, 0o755),
        ("/mnt/local", 0, 0, 0o755),
        ("/mnt/shared", 0, 0, 0o755),
        ("/proc", 0, 0, 0o755),
        ("/root", 0, 0, 0o700),
        ("/run", 0, 0, 0o755),
        ("/tmp", 0, 0, 0o1777),
        ("/usr", 0, 0, 0o755),
        ("/var", 0, 0, 0o755),
        ("/var/log", 0, 0, 0o755),
        ("/var/tmp", 0, 0, 0o1777),
    ] {
        add_dir(&mut tpl_entries, d, uid, gid, mode);
    }
    add_file(
        &mut tpl_entries,
        &mut blob_map,
        "/etc/passwd",
        0,
        0,
        0o644,
        b"root:x:0:0:root:/root:/bin/sh\nuser:x:1000:1000:user:/home/user:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/sbin/nologin\n",
    );
    add_file(
        &mut tpl_entries,
        &mut blob_map,
        "/etc/group",
        0,
        0,
        0o644,
        b"root:x:0:\nwheel:x:10:user\nuser:x:1000:\nnobody:x:65534:\n",
    );
    add_file(
        &mut tpl_entries,
        &mut blob_map,
        "/etc/shadow",
        0,
        0,
        0o600,
        b"root:!:0:0:99999:7:::\nuser:!:0:0:99999:7:::\n",
    );
    add_file(
        &mut tpl_entries,
        &mut blob_map,
        "/etc/sudoers",
        0,
        0,
        0o440,
        b"root ALL=(ALL:ALL) ALL\n%wheel ALL=(ALL:ALL) NOPASSWD: ALL\n",
    );
    let root_template = finalize_image(Kind::RootTemplate, "root-template", tpl_entries);

    // 3. Stage 2 `Kind::Base`
    let mut base_entries = Vec::new();
    for d in ["/", "/usr", "/usr/bin", "/usr/lib", "/sys"] {
        add_dir(&mut base_entries, d, 0, 0, 0o755);
    }
    add_symlink(&mut base_entries, "/bin", "usr/bin");
    add_symlink(&mut base_entries, "/sbin", "usr/bin");
    add_symlink(&mut base_entries, "/lib", "usr/lib");
    add_symlink(&mut base_entries, "/lib64", "usr/lib");
    add_file(
        &mut base_entries,
        &mut blob_map,
        "/usr/bin/init",
        0,
        0,
        0o755,
        WASM_STUB,
    );
    add_file(
        &mut base_entries,
        &mut blob_map,
        "/usr/bin/supervise",
        0,
        0,
        0o755,
        WASM_STUB,
    );
    add_file(
        &mut base_entries,
        &mut blob_map,
        "/usr/bin/dash",
        0,
        0,
        0o755,
        WASM_STUB,
    );
    add_symlink(&mut base_entries, "/usr/bin/sh", "dash");
    let base = finalize_image(Kind::Base, "base", base_entries);

    let mut store = MemoryBlobStore::default();
    for (id, bytes) in blob_map {
        store.insert(id, bytes);
    }
    (
        ReleaseImages {
            initramfs,
            root_template,
            base,
            extensions: Vec::new(),
        },
        store,
    )
}

fn fixed_clock(sec: u64) -> (Rc<Cell<u64>>, Rc<dyn Fn() -> Timespec>) {
    let cell = Rc::new(Cell::new(sec));
    let c = Rc::clone(&cell);
    let clk: Rc<dyn Fn() -> Timespec> = Rc::new(move || Timespec {
        sec: c.get(),
        nsec: 0,
    });
    (cell, clk)
}

// -----------------------------------------------------------------------------
// B-02..08 Integration Tests
// -----------------------------------------------------------------------------

#[test]
fn b02_first_boot_seeds_root_template_and_persists_across_cold_reboot() {
    let (release, blobs) = synthetic_release();
    let head = Rc::new(TestHeadStore::new());
    let pack = Rc::new(TestPackStore::new());
    let (_tick, clk) = fixed_clock(1_735_000_000);

    // 1. First boot (`volume_uuid: None`): provisions volume + atomically seeds RootTemplate.
    let mut boot1 = vfs::now_or_never(TwoStageBoot::new_cowfs_root(
        "inst-1",
        BootProfile::default(),
        release.clone(),
        Rc::clone(&head),
        Rc::clone(&pack),
        blobs.clone(),
        Rc::clone(&clk),
        || "vol-primary-0001".to_string(),
    ))
    .unwrap()
    .unwrap();

    assert_eq!(boot1.stage(), BootStage::Stage2);
    let root_info = boot1.mounted_root().unwrap().clone();
    assert_eq!(root_info.volume_uuid, "vol-primary-0001");
    assert!(root_info.first_boot_seeded);
    assert_eq!(root_info.base_epoch, 1);

    // Exact account file modes (`shadow` 0600, `sudoers` 0440, `/home/user` 0750, `/root` 0700).
    let shadow_st = vfs::now_or_never(boot1.stat("/etc/shadow", false))
        .unwrap()
        .unwrap();
    assert_eq!(shadow_st.mode & 0o7777, 0o600);
    assert_eq!((shadow_st.uid, shadow_st.gid), (0, 0));

    // Codex Finding #2: Stage 2 console runs as a separate non-PID-1 login process (`uid 1000`)
    // on a local PTY (`/dev/pts/0`), NOT PID 1! Root-only reads/writes MUST fail `EACCES` without sudo.
    let console_proc = boot1
        .console_proc_snapshot()
        .expect("Stage 2 must spawn separate non-PID-1 console login process");
    assert_ne!(console_proc.pid, 1);
    assert_eq!(console_proc.ppid, 1);
    assert_eq!(console_proc.uid, 1000);
    assert_eq!(console_proc.gid, 1000);
    assert_eq!(console_proc.user, "user");
    assert_eq!(console_proc.tty.as_deref(), Some("/dev/pts/0"));
    assert_eq!(
        vfs::now_or_never(boot1.read_file("/etc/shadow")).unwrap(),
        Err(Errno::EACCES)
    );
    assert_eq!(
        vfs::now_or_never(boot1.read_file("/etc/sudoers")).unwrap(),
        Err(Errno::EACCES)
    );
    assert_eq!(
        vfs::now_or_never(boot1.write_file("/etc/motd", b"denied\n", 0o644)).unwrap(),
        Err(Errno::EACCES)
    );

    let sudoers_st = vfs::now_or_never(boot1.stat("/etc/sudoers", false))
        .unwrap()
        .unwrap();
    assert_eq!(sudoers_st.mode & 0o7777, 0o440);
    assert_eq!((sudoers_st.uid, sudoers_st.gid), (0, 0));
    let sudoers_body = String::from_utf8(
        vfs::now_or_never(boot1.read_file_sudo("/etc/sudoers"))
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert!(sudoers_body.contains("%wheel ALL=(ALL:ALL) NOPASSWD: ALL"));

    let home_st = vfs::now_or_never(boot1.stat("/home/user", false))
        .unwrap()
        .unwrap();
    assert_eq!(home_st.mode & 0o7777, 0o750);
    assert_eq!((home_st.uid, home_st.gid), (1000, 1000));

    let root_home_st = vfs::now_or_never(boot1.stat("/root", false))
        .unwrap()
        .unwrap();
    assert_eq!(root_home_st.mode & 0o7777, 0o700);

    // `statfs("/") == OS_COWFS_MAGIC`; `/proc/mounts` shows `/` = cowfs, `/usr` = image ro,nodev, `/tmp` = tmpfs.
    let sf_root = vfs::now_or_never(boot1.statfs("/")).unwrap().unwrap();
    assert_eq!(sf_root.f_type, fs_magic::OS_COWFS_MAGIC);

    let mounts = String::from_utf8(
        vfs::now_or_never(boot1.read_file("/proc/mounts"))
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert!(mounts.contains(" / cowfs "), "mounts: {mounts}");
    assert!(mounts.contains(" /usr image ro,nodev"), "mounts: {mounts}");
    assert!(mounts.contains(" /tmp tmpfs "), "mounts: {mounts}");
    assert!(mounts.contains(" /proc proc "), "mounts: {mounts}");
    assert!(mounts.contains(" /dev devtmpfs "), "mounts: {mounts}");
    assert!(mounts.contains(" /dev/pts devpts "), "mounts: {mounts}");
    assert!(mounts.contains(" /run tmpfs "), "mounts: {mounts}");

    // Zero remote devices seeded in `/dev`.
    let dev_entries = vfs::now_or_never(boot1.readdir("/dev")).unwrap().unwrap();
    for remote in ["archive", "media", "present", "snd"] {
        assert!(
            !dev_entries.iter().any(|e| e == remote),
            "/dev must not seed remote device {remote}"
        );
    }
    assert!(dev_entries.iter().any(|e| e == "vd0"));
    assert!(dev_entries.iter().any(|e| e == "null"));

    // Write user & config files (sudo for root-owned `/etc/motd`), sync, and cleanly shut down.
    vfs::now_or_never(boot1.write_file_sudo("/etc/motd", b"welcome offline\n", 0o644))
        .unwrap()
        .unwrap();
    vfs::now_or_never(boot1.write_file("/home/user/notes.txt", b"persisted note\n", 0o644))
        .unwrap()
        .unwrap();
    let synced_head = vfs::now_or_never(boot1.sync_fs()).unwrap().unwrap();
    assert!(synced_head.epoch > 1);
    let close_res = vfs::now_or_never(boot1.close_clean_with_prune())
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(close_res.retained);
    assert!(!close_res.pruned);
    drop(boot1);

    // 2. Cold reboot with persisted `BootProfile` pointing to `vol-primary-0001`.
    let reboot_profile = BootProfile {
        version: BOOT_PROFILE_VERSION,
        root: RootSpec::CowFs {
            volume_uuid: Some("vol-primary-0001".to_string()),
            writer_mode: BootWriterMode::ForkOnBusy,
        },
        default_user: "user".to_string(),
        generation: None,
        recovery: false,
    };
    let mut boot2 = vfs::now_or_never(TwoStageBoot::new_cowfs_root(
        "inst-2",
        reboot_profile,
        release,
        Rc::clone(&head),
        Rc::clone(&pack),
        blobs,
        clk,
        || panic!("reboot must not format a new volume"),
    ))
    .unwrap()
    .unwrap();

    assert_eq!(boot2.stage(), BootStage::Stage2);
    assert!(!boot2.mounted_root().unwrap().first_boot_seeded);
    assert_eq!(
        vfs::now_or_never(boot2.read_file("/etc/motd"))
            .unwrap()
            .unwrap(),
        b"welcome offline\n"
    );
    assert_eq!(
        vfs::now_or_never(boot2.read_file("/home/user/notes.txt"))
            .unwrap()
            .unwrap(),
        b"persisted note\n"
    );
    let _ = vfs::now_or_never(boot2.close_clean_with_prune())
        .unwrap()
        .unwrap();
}

#[test]
fn b03_switch_root_preserves_pid1_reclaims_stage1_tmpfs_and_detaches_stage1_usr() {
    let (release, blobs) = synthetic_release();
    let head = Rc::new(TestHeadStore::new());
    let pack = Rc::new(TestPackStore::new());
    let (clock_sec, clk) = fixed_clock(1_735_001_000);

    let mut boot = vfs::now_or_never(TwoStageBoot::boot_stage1(
        "inst-b03",
        BootProfile::default(),
        release,
        Rc::clone(&head),
        Rc::clone(&pack),
        blobs,
        Rc::clone(&clk),
    ))
    .unwrap()
    .unwrap();

    let pid1_before = boot.pid1_snapshot();
    assert_eq!(pid1_before.pid, 1);
    assert_eq!(pid1_before.path, "/init");
    assert_eq!(pid1_before.started, 1_735_001_000);

    vfs::now_or_never(boot.write_file("/initramfs_marker", b"ephemeral-stage1", 0o644))
        .unwrap()
        .unwrap();
    assert_eq!(
        vfs::now_or_never(boot.statfs("/")).unwrap().unwrap().f_type,
        fs_magic::TMPFS_MAGIC
    );

    // Advance wall clock by 5 seconds BEFORE switch_root to prove PID 1 `started` stays original boot_ns!
    clock_sec.set(1_735_001_005);

    let stage = vfs::now_or_never(boot.prepare_cowfs_root(|| "vol-b03".to_string()))
        .unwrap()
        .unwrap();
    assert_eq!(stage, BootStage::Stage1);

    let args = vec![DEFAULT_STAGE2_INIT.to_string()];
    vfs::now_or_never(boot.switch_root(1, "/sysroot", DEFAULT_STAGE2_INIT, &args))
        .unwrap()
        .unwrap();
    assert_eq!(boot.stage(), BootStage::Stage2);

    // 1. PID 1 preserved verbatim (`pid == 1`, exact original `started` and `started_ticks`).
    let pid1_after = boot.pid1_snapshot();
    assert_eq!(pid1_after.pid, 1);
    assert_eq!(pid1_after.path, DEFAULT_STAGE2_INIT);
    assert_eq!(pid1_after.started, pid1_before.started);
    assert_eq!(pid1_after.started_ticks, pid1_before.started_ticks);

    // 2. Stage 1 `/initramfs_marker` is completely unreachable & Stage 1 tmpfs was unlinked and dropped.
    assert_eq!(
        vfs::now_or_never(boot.stat("/initramfs_marker", false)).unwrap(),
        Err(Errno::ENOENT)
    );
    assert!(boot.stage1_reclaimed_entries() > 0);
    assert!(
        boot.stage1_tmpfs_dropped(),
        "Stage 1 tmpfs must have zero remaining refs"
    );

    // 3. `/run/os/boot-profile.json` and `/run/os/root` survived `MS_MOVE /run -> /sysroot/run`!
    let moved_profile = vfs::now_or_never(boot.read_file(BOOT_PROFILE_PATH))
        .unwrap()
        .unwrap();
    let parsed_profile: BootProfile = serde_json::from_slice(&moved_profile).unwrap();
    assert_eq!(
        parsed_profile.root,
        RootSpec::CowFs {
            volume_uuid: Some("vol-b03".to_string()),
            writer_mode: BootWriterMode::ForkOnBusy,
        }
    );
    let moved_root = vfs::now_or_never(boot.read_file(MOUNTED_ROOT_INFO_PATH))
        .unwrap()
        .unwrap();
    let parsed_root: MountedRootInfo = serde_json::from_slice(&moved_root).unwrap();
    assert_eq!(parsed_root.fstype, "cowfs");
    assert_eq!(parsed_root.volume_uuid, "vol-b03");

    // 4. `/proc/self/mountinfo` has no leftover Stage 1 `initramfs-usr` mount!
    let mountinfo = String::from_utf8(
        vfs::now_or_never(boot.read_file("/proc/self/mountinfo"))
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert!(
        !mountinfo.contains("initramfs-usr"),
        "Stage 1 /usr leaked: {mountinfo}"
    );
    assert!(mountinfo.contains(" / ") && mountinfo.contains(" - cowfs "));
    assert!(mountinfo.contains(" /usr ") && mountinfo.contains(" - image usr"));

    let _ = vfs::now_or_never(boot.close_clean_with_prune())
        .unwrap()
        .unwrap();
}

#[test]
fn b04_and_b05_fork_on_busy_prunes_unmodified_and_retains_modified_isolated_fork() {
    let (release, blobs) = synthetic_release();
    let head = Rc::new(TestHeadStore::new());
    let pack = Rc::new(TestPackStore::new());
    let (_tick, clk) = fixed_clock(1_735_002_000);

    // Tab 1 boots primary volume and writes `/home/user/tab1.txt`.
    let mut tab1 = vfs::now_or_never(TwoStageBoot::new_cowfs_root(
        "tab-1",
        BootProfile::default(),
        release.clone(),
        Rc::clone(&head),
        Rc::clone(&pack),
        blobs.clone(),
        Rc::clone(&clk),
        || "vol-shared-main".to_string(),
    ))
    .unwrap()
    .unwrap();
    vfs::now_or_never(tab1.write_file("/home/user/tab1.txt", b"from-tab-1\n", 0o644))
        .unwrap()
        .unwrap();
    vfs::now_or_never(tab1.sync_fs()).unwrap().unwrap();

    let tab2_profile = BootProfile {
        version: BOOT_PROFILE_VERSION,
        root: RootSpec::CowFs {
            volume_uuid: Some("vol-shared-main".to_string()),
            writer_mode: BootWriterMode::ForkOnBusy,
        },
        default_user: "user".to_string(),
        generation: None,
        recovery: false,
    };

    // B-04: Tab 2 opens while Tab 1 holds the writer lock -> O(1) persistent fork (`ephemeral_if_unmodified = true`).
    let mut tab2_ro_session = vfs::now_or_never(TwoStageBoot::new_cowfs_root(
        "tab-2-unmod",
        tab2_profile.clone(),
        release.clone(),
        Rc::clone(&head),
        Rc::clone(&pack),
        blobs.clone(),
        Rc::clone(&clk),
        || panic!("existing volume must fork rather than format"),
    ))
    .unwrap()
    .unwrap();
    assert_eq!(tab2_ro_session.stage(), BootStage::Stage2);
    let fork1_info = tab2_ro_session.mounted_root().unwrap().clone();
    assert_ne!(fork1_info.volume_uuid, "vol-shared-main");
    assert_eq!(fork1_info.forked_from.as_deref(), Some("vol-shared-main"));
    assert!(fork1_info.ephemeral_if_unmodified);
    assert!(!tab2_ro_session.banners().is_empty());
    assert_eq!(
        vfs::now_or_never(tab2_ro_session.read_file("/home/user/tab1.txt"))
            .unwrap()
            .unwrap(),
        b"from-tab-1\n"
    );

    // Clean exit WITHOUT any writes -> fork MUST be pruned automatically!
    let prune_outcome = vfs::now_or_never(tab2_ro_session.close_clean_with_prune())
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        prune_outcome.pruned,
        "unmodified fork must be pruned: {prune_outcome:?}"
    );
    assert!(!prune_outcome.retained);
    assert_eq!(
        vfs::now_or_never(head.read_head(&VolumeId(fork1_info.volume_uuid.clone()))).unwrap(),
        Err(Errno::ENOENT)
    );

    // B-05: Tab 2 opens again on fork, writes `/home/user/fork-only.txt`, syncs, and exits cleanly -> RETAINED!
    let mut tab2_rw_session = vfs::now_or_never(TwoStageBoot::new_cowfs_root(
        "tab-2-mod",
        tab2_profile,
        release.clone(),
        Rc::clone(&head),
        Rc::clone(&pack),
        blobs.clone(),
        Rc::clone(&clk),
        || panic!("existing volume must fork rather than format"),
    ))
    .unwrap()
    .unwrap();
    let fork2_uuid = tab2_rw_session.mounted_root().unwrap().volume_uuid.clone();
    vfs::now_or_never(tab2_rw_session.write_file(
        "/home/user/fork-only.txt",
        b"isolated-fork-write\n",
        0o644,
    ))
    .unwrap()
    .unwrap();
    vfs::now_or_never(tab2_rw_session.sync_fs())
        .unwrap()
        .unwrap();

    // Primary Tab 1 MUST NOT see Tab 2's fork write!
    assert_eq!(
        vfs::now_or_never(tab1.stat("/home/user/fork-only.txt", false)).unwrap(),
        Err(Errno::ENOENT)
    );

    let retain_outcome = vfs::now_or_never(tab2_rw_session.close_clean_with_prune())
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        retain_outcome.retained,
        "modified fork must be retained: {retain_outcome:?}"
    );
    assert!(!retain_outcome.pruned);

    // Rebooting directly into the retained fork sees `/home/user/fork-only.txt`!
    let mut tab3_reopen_fork = vfs::now_or_never(TwoStageBoot::new_cowfs_root(
        "tab-3-fork",
        BootProfile {
            version: BOOT_PROFILE_VERSION,
            root: RootSpec::CowFs {
                volume_uuid: Some(fork2_uuid),
                writer_mode: BootWriterMode::Exclusive,
            },
            default_user: "user".to_string(),
            generation: None,
            recovery: false,
        },
        release,
        Rc::clone(&head),
        Rc::clone(&pack),
        blobs,
        clk,
        || panic!("fork must exist"),
    ))
    .unwrap()
    .unwrap();
    assert_eq!(
        vfs::now_or_never(tab3_reopen_fork.read_file("/home/user/fork-only.txt"))
            .unwrap()
            .unwrap(),
        b"isolated-fork-write\n"
    );

    let _ = vfs::now_or_never(tab3_reopen_fork.close_clean_with_prune())
        .unwrap()
        .unwrap();
    let _ = vfs::now_or_never(tab1.close_clean_with_prune())
        .unwrap()
        .unwrap();
}

#[test]
fn b06_incompatible_format_version_fails_eprotonosupport_and_never_wipes_user_data() {
    let (release, blobs) = synthetic_release();
    let head = Rc::new(TestHeadStore::new());
    let pack = Rc::new(TestPackStore::new());
    let (_tick, clk) = fixed_clock(1_735_003_000);

    // 1. Seed a real volume with precious user data.
    let mut boot1 = vfs::now_or_never(TwoStageBoot::new_cowfs_root(
        "inst-b06-seed",
        BootProfile::default(),
        release.clone(),
        Rc::clone(&head),
        Rc::clone(&pack),
        blobs.clone(),
        Rc::clone(&clk),
        || "vol-precious".to_string(),
    ))
    .unwrap()
    .unwrap();
    vfs::now_or_never(boot1.write_file("/home/user/precious.txt", b"do-not-wipe\n", 0o644))
        .unwrap()
        .unwrap();
    let head_before = vfs::now_or_never(boot1.sync_fs()).unwrap().unwrap();
    let _ = vfs::now_or_never(boot1.close_clean_with_prune())
        .unwrap()
        .unwrap();
    drop(boot1);

    // 2. Bump store format version to incompatible `99`.
    head.set_format_version(Some(99));

    let profile = BootProfile {
        version: BOOT_PROFILE_VERSION,
        root: RootSpec::CowFs {
            volume_uuid: Some("vol-precious".to_string()),
            writer_mode: BootWriterMode::ForkOnBusy,
        },
        default_user: "user".to_string(),
        generation: None,
        recovery: false,
    };

    // 3. Boot -> MUST enter Stage1Recovery with `IncompatibleFormat { found_version: Some(99) }`
    //    and MUST NOT format, wipe, or modify the volume head!
    let boot_bad = vfs::now_or_never(TwoStageBoot::new_cowfs_root(
        "inst-b06-bad",
        profile.clone(),
        release.clone(),
        Rc::clone(&head),
        Rc::clone(&pack),
        blobs.clone(),
        Rc::clone(&clk),
        || panic!("must NEVER format on version mismatch"),
    ))
    .unwrap()
    .unwrap();

    assert_eq!(boot_bad.stage(), BootStage::Stage1Recovery);
    assert!(boot_bad.mounted_root().is_none());
    let rec = boot_bad.recovery().expect("recovery state must be set");
    assert_eq!(
        rec.reason,
        RecoveryReason::IncompatibleFormat {
            found_version: Some(99),
            expected_version: COWFS_FORMAT_VERSION,
        }
    );

    // Verify stored volume head is byte-for-byte untouched!
    let head_after_mismatch =
        vfs::now_or_never(head.read_head(&VolumeId("vol-precious".to_string())))
            .unwrap()
            .unwrap();
    assert_eq!(head_after_mismatch.root, head_before.root);
    assert_eq!(head_after_mismatch.epoch, head_before.epoch);

    // 4. Restore format version `1` -> user data still boots intact!
    head.set_format_version(Some(COWFS_FORMAT_VERSION));
    let mut boot_ok = vfs::now_or_never(TwoStageBoot::new_cowfs_root(
        "inst-b06-ok",
        profile,
        release,
        Rc::clone(&head),
        Rc::clone(&pack),
        blobs,
        clk,
        || panic!("existing volume must mount"),
    ))
    .unwrap()
    .unwrap();
    assert_eq!(boot_ok.stage(), BootStage::Stage2);
    assert_eq!(
        vfs::now_or_never(boot_ok.read_file("/home/user/precious.txt"))
            .unwrap()
            .unwrap(),
        b"do-not-wipe\n"
    );
    let _ = vfs::now_or_never(boot_ok.close_clean_with_prune())
        .unwrap()
        .unwrap();
}

#[test]
fn b07_corrupt_cowfsck_enters_recovery_with_rollback_and_exclusive_busy_fails_ebusy() {
    let (release, blobs) = synthetic_release();
    let head = Rc::new(TestHeadStore::new());
    let pack = Rc::new(TestPackStore::new());
    let (_tick, clk) = fixed_clock(1_735_004_000);

    // 1. Seed volume, write baseline file, snapshot `"good"`, then write another file into a new pack.
    let mut boot1 = vfs::now_or_never(TwoStageBoot::new_cowfs_root(
        "inst-b07-seed",
        BootProfile::default(),
        release.clone(),
        Rc::clone(&head),
        Rc::clone(&pack),
        blobs.clone(),
        Rc::clone(&clk),
        || "vol-b07".to_string(),
    ))
    .unwrap()
    .unwrap();
    vfs::now_or_never(boot1.write_file("/home/user/good.txt", b"safe-snapshot-data\n", 0o644))
        .unwrap()
        .unwrap();
    vfs::now_or_never(boot1.sync_fs()).unwrap().unwrap();
    vfs::now_or_never(boot1.create_snapshot("good"))
        .unwrap()
        .unwrap();

    // Test Exclusive `EBUSY` while `boot1` still holds the writer lock!
    let exclusive_profile = BootProfile {
        version: BOOT_PROFILE_VERSION,
        root: RootSpec::CowFs {
            volume_uuid: Some("vol-b07".to_string()),
            writer_mode: BootWriterMode::Exclusive,
        },
        default_user: "user".to_string(),
        generation: None,
        recovery: false,
    };
    let mut boot_busy = vfs::now_or_never(TwoStageBoot::new_cowfs_root(
        "inst-b07-busy",
        exclusive_profile,
        release.clone(),
        Rc::clone(&head),
        Rc::clone(&pack),
        blobs.clone(),
        Rc::clone(&clk),
        || panic!("must not format"),
    ))
    .unwrap()
    .unwrap();
    assert_eq!(boot_busy.stage(), BootStage::Stage1Recovery);
    assert_eq!(
        boot_busy.recovery().unwrap().reason,
        RecoveryReason::VolumeBusy {
            volume_uuid: "vol-b07".to_string()
        }
    );
    // Recovery action `fork_from_recovery` recovers into Stage 2 on a fork!
    let recovered_stage = vfs::now_or_never(boot_busy.fork_from_recovery())
        .unwrap()
        .unwrap();
    assert_eq!(recovered_stage, BootStage::Stage2);
    assert_eq!(
        boot_busy.mounted_root().unwrap().forked_from.as_deref(),
        Some("vol-b07")
    );
    let _ = vfs::now_or_never(boot_busy.close_clean_with_prune())
        .unwrap()
        .unwrap();

    // Now write post-snapshot data and corrupt the head's root node in `head_store`!
    vfs::now_or_never(boot1.write_file("/home/user/later.txt", b"after-snap\n", 0o644))
        .unwrap()
        .unwrap();
    let corrupted_head = vfs::now_or_never(boot1.sync_fs()).unwrap().unwrap();
    let _ = vfs::now_or_never(boot1.close_clean_with_prune())
        .unwrap()
        .unwrap();
    drop(boot1);

    // Corrupt a byte in the current root B+tree node (snapshot `"good"` points to its own intact root!).
    assert!(head.corrupt_node_byte(&corrupted_head.root, 0));

    let mut boot_corrupt = vfs::now_or_never(TwoStageBoot::new_cowfs_root(
        "inst-b07-corrupt",
        BootProfile {
            version: BOOT_PROFILE_VERSION,
            root: RootSpec::CowFs {
                volume_uuid: Some("vol-b07".to_string()),
                writer_mode: BootWriterMode::ForkOnBusy,
            },
            default_user: "user".to_string(),
            generation: None,
            recovery: false,
        },
        release,
        Rc::clone(&head),
        Rc::clone(&pack),
        blobs,
        clk,
        || panic!("must not format corrupt volume"),
    ))
    .unwrap()
    .unwrap();

    assert_eq!(boot_corrupt.stage(), BootStage::Stage1Recovery);
    assert!(boot_corrupt.mounted_root().is_none());
    let rec = boot_corrupt.recovery().unwrap();
    match &rec.reason {
        RecoveryReason::CorruptVolume { snapshots, .. } => {
            assert!(
                snapshots.contains(&"good".to_string()),
                "snapshots: {snapshots:?}"
            );
        }
        other => panic!("expected CorruptVolume recovery, got {other:?}"),
    }
    // `/run/os/cowfsck.json` was written in Stage 1 tmpfs `/run`!
    assert!(
        vfs::now_or_never(boot_corrupt.stat(COWFSCK_REPORT_PATH, false))
            .unwrap()
            .is_ok()
    );

    // Roll back to snapshot `"good"` -> mounts cleanly and reaches Stage 2!
    let rb_stage = vfs::now_or_never(
        boot_corrupt.rollback_to_snapshot("good", || "vol-b07-rolled".to_string()),
    )
    .unwrap()
    .unwrap();
    assert_eq!(rb_stage, BootStage::Stage2);
    assert_eq!(
        boot_corrupt.mounted_root().unwrap().volume_uuid,
        "vol-b07-rolled"
    );
    assert_eq!(
        vfs::now_or_never(boot_corrupt.read_file("/home/user/good.txt"))
            .unwrap()
            .unwrap(),
        b"safe-snapshot-data\n"
    );
    assert_eq!(
        vfs::now_or_never(boot_corrupt.stat("/home/user/later.txt", false)).unwrap(),
        Err(Errno::ENOENT)
    );
    let _ = vfs::now_or_never(boot_corrupt.close_clean_with_prune())
        .unwrap()
        .unwrap();
}

#[test]
fn b08_switch_root_refuses_misuse_before_moving_mounts_and_respects_st_dev() {
    let (release, blobs) = synthetic_release();
    let head = Rc::new(TestHeadStore::new());
    let pack = Rc::new(TestPackStore::new());
    let (_tick, clk) = fixed_clock(1_735_005_000);

    let mut boot = vfs::now_or_never(TwoStageBoot::boot_stage1(
        "inst-b08",
        BootProfile::default(),
        release,
        Rc::clone(&head),
        Rc::clone(&pack),
        blobs,
        clk,
    ))
    .unwrap()
    .unwrap();
    vfs::now_or_never(boot.prepare_cowfs_root(|| "vol-b08".to_string()))
        .unwrap()
        .unwrap();

    // 1. Non-PID-1 caller -> EPERM!
    assert_eq!(
        vfs::now_or_never(boot.switch_root(42, "/sysroot", DEFAULT_STAGE2_INIT, &[])).unwrap(),
        Err(Errno::EPERM)
    );

    // 2. Non-mountpoint target (same `st_dev` as `/`) -> EINVAL!
    vfs::now_or_never(boot.mkdir("/not_a_mount", 0o755))
        .unwrap()
        .unwrap();
    assert_eq!(
        vfs::now_or_never(boot.switch_root(1, "/not_a_mount", DEFAULT_STAGE2_INIT, &[])).unwrap(),
        Err(Errno::EINVAL)
    );

    // 3. Missing `<newroot><init>` -> ENOENT BEFORE moving `/proc`, `/dev`, `/run`!
    assert_eq!(
        vfs::now_or_never(boot.switch_root(1, "/sysroot", "/usr/bin/does-not-exist", &[])).unwrap(),
        Err(Errno::ENOENT)
    );
    // Verify `/proc`, `/dev`, `/run` are STILL mounted at Stage 1 locations!
    assert!(
        vfs::now_or_never(boot.read_file("/proc/mounts"))
            .unwrap()
            .is_ok()
    );
    assert!(
        vfs::now_or_never(boot.stat("/dev/null", false))
            .unwrap()
            .is_ok()
    );
    assert!(
        vfs::now_or_never(boot.stat(BOOT_PROFILE_PATH, false))
            .unwrap()
            .is_ok()
    );

    // 4. Non-executable `<newroot><init>` -> EACCES BEFORE moving any mounts!
    vfs::now_or_never(boot.write_file("/sysroot/nonexec_init", b"not-exec", 0o644))
        .unwrap()
        .unwrap();
    assert_eq!(
        vfs::now_or_never(boot.switch_root(1, "/sysroot", "/nonexec_init", &[])).unwrap(),
        Err(Errno::EACCES)
    );
    assert!(
        vfs::now_or_never(boot.read_file("/proc/mounts"))
            .unwrap()
            .is_ok()
    );
    assert!(
        vfs::now_or_never(boot.stat(BOOT_PROFILE_PATH, false))
            .unwrap()
            .is_ok()
    );

    // 5. Complete valid `switch_root` -> Stage 2 (`/` is now `os-cowfs`, NOT `tmpfs`).
    let args = vec![DEFAULT_STAGE2_INIT.to_string()];
    vfs::now_or_never(boot.switch_root(1, "/sysroot", DEFAULT_STAGE2_INIT, &args))
        .unwrap()
        .unwrap();
    assert_eq!(boot.stage(), BootStage::Stage2);
    // Verify `<newroot>` file `/nonexec_init` survived `st_dev`-bounded recursive unlink!
    assert_eq!(
        vfs::now_or_never(boot.read_file("/nonexec_init"))
            .unwrap()
            .unwrap(),
        b"not-exec"
    );

    // 6. Calling `switch_root` again when `/` is `os-cowfs` (not `tmpfs`) -> EINVAL!
    assert_eq!(
        vfs::now_or_never(boot.switch_root(1, "/sysroot", DEFAULT_STAGE2_INIT, &args)).unwrap(),
        Err(Errno::EINVAL)
    );

    let _ = vfs::now_or_never(boot.close_clean_with_prune())
        .unwrap()
        .unwrap();
}

#[test]
fn codex_24_and_32_ephemeral_snapshot_roots_and_missing_default_user_fail_closed() {
    let (release, blobs) = synthetic_release();
    let head = Rc::new(TestHeadStore::new());
    let pack = Rc::new(TestPackStore::new());
    let (_tick, clk) = fixed_clock(1_735_006_000);

    // 1. Codex #32: `RootSpec::Ephemeral` boots tmpfs root populated from `RootTemplate` with 0 CowFS volumes.
    let mut eph = vfs::now_or_never(TwoStageBoot::new_cowfs_root(
        "inst-eph",
        BootProfile {
            version: BOOT_PROFILE_VERSION,
            root: RootSpec::Ephemeral,
            default_user: "user".to_string(),
            generation: None,
            recovery: false,
        },
        release.clone(),
        Rc::clone(&head),
        Rc::clone(&pack),
        blobs.clone(),
        Rc::clone(&clk),
        || panic!("ephemeral root must not allocate a cowfs volume"),
    ))
    .unwrap()
    .unwrap();
    assert_eq!(eph.stage(), BootStage::Stage2);
    assert_eq!(eph.mounted_root().unwrap().fstype, "tmpfs");
    assert_eq!(
        vfs::now_or_never(eph.statfs("/")).unwrap().unwrap().f_type,
        fs_magic::TMPFS_MAGIC
    );
    assert_eq!(
        vfs::now_or_never(eph.read_file("/etc/shadow")).unwrap(),
        Err(Errno::EACCES)
    );
    let _ = vfs::now_or_never(eph.close_clean_with_prune())
        .unwrap()
        .unwrap();

    // 2. Codex #32 & #16: Seed a volume, flush_for_suspend keeps root open & writable,
    //    take snapshot `"ro-snap"`, then boot `RootSpec::Snapshot` read-only!
    let mut base_boot = vfs::now_or_never(TwoStageBoot::new_cowfs_root(
        "inst-snap-seed",
        BootProfile::default(),
        release.clone(),
        Rc::clone(&head),
        Rc::clone(&pack),
        blobs.clone(),
        Rc::clone(&clk),
        || "vol-snap-base".to_string(),
    ))
    .unwrap()
    .unwrap();
    vfs::now_or_never(base_boot.write_file("/home/user/from-snap.txt", b"snap-ok\n", 0o644))
        .unwrap()
        .unwrap();
    // Codex #16: `flush_for_suspend` commits dirty writes WITHOUT closing the root!
    let flushed = vfs::now_or_never(base_boot.flush_for_suspend())
        .unwrap()
        .unwrap()
        .expect("dirty root must flush on suspend");
    assert!(flushed.epoch > 1);
    // Subsequent write MUST still succeed (NOT EBADF)!
    vfs::now_or_never(base_boot.write_file("/home/user/after-suspend.txt", b"still-open\n", 0o644))
        .unwrap()
        .unwrap();
    vfs::now_or_never(base_boot.sync_fs()).unwrap().unwrap();
    vfs::now_or_never(base_boot.create_snapshot("ro-snap"))
        .unwrap()
        .unwrap();

    // Codex #24: Delete `user` from `/etc/passwd` on the volume, sync, and reboot ->
    // MUST enter `Stage1Recovery(AccountResolutionFailed)` instead of synthesizing UID 1000 `wheel`!
    vfs::now_or_never(base_boot.write_file_sudo(
        "/etc/passwd",
        b"root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/nonexistent:/sbin/nologin\n",
        0o644,
    ))
    .unwrap()
    .unwrap();
    vfs::now_or_never(base_boot.sync_fs()).unwrap().unwrap();
    let _ = vfs::now_or_never(base_boot.close_clean_with_prune())
        .unwrap()
        .unwrap();
    drop(base_boot);

    let missing_user_boot = vfs::now_or_never(TwoStageBoot::new_cowfs_root(
        "inst-missing-user",
        BootProfile {
            version: BOOT_PROFILE_VERSION,
            root: RootSpec::CowFs {
                volume_uuid: Some("vol-snap-base".to_string()),
                writer_mode: BootWriterMode::ForkOnBusy,
            },
            default_user: "user".to_string(),
            generation: None,
            recovery: false,
        },
        release.clone(),
        Rc::clone(&head),
        Rc::clone(&pack),
        blobs.clone(),
        Rc::clone(&clk),
        || panic!("must not format"),
    ))
    .unwrap()
    .unwrap();
    assert_eq!(missing_user_boot.stage(), BootStage::Stage1Recovery);
    match &missing_user_boot.recovery().unwrap().reason {
        RecoveryReason::AccountResolutionFailed { default_user, .. } => {
            assert_eq!(default_user, "user");
        }
        other => panic!("expected AccountResolutionFailed, got {other:?}"),
    }

    // Booting `"ro-snap"` (taken BEFORE `user` was deleted) via `RootSpec::Snapshot` succeeds RO!
    let mut snap_boot = vfs::now_or_never(TwoStageBoot::new_cowfs_root(
        "inst-ro-snap",
        BootProfile {
            version: BOOT_PROFILE_VERSION,
            root: RootSpec::Snapshot {
                volume_uuid: "vol-snap-base".to_string(),
                snapshot: "ro-snap".to_string(),
            },
            default_user: "user".to_string(),
            generation: None,
            recovery: false,
        },
        release,
        Rc::clone(&head),
        Rc::clone(&pack),
        blobs,
        clk,
        || panic!("snapshot root must not format"),
    ))
    .unwrap()
    .unwrap();
    assert_eq!(snap_boot.stage(), BootStage::Stage2);
    assert_eq!(
        vfs::now_or_never(snap_boot.read_file("/home/user/from-snap.txt"))
            .unwrap()
            .unwrap(),
        b"snap-ok\n"
    );
    assert_eq!(
        vfs::now_or_never(snap_boot.write_file("/home/user/denied.txt", b"x", 0o644)).unwrap(),
        Err(Errno::EROFS)
    );
    let _ = vfs::now_or_never(snap_boot.close_clean_with_prune())
        .unwrap()
        .unwrap();
}
