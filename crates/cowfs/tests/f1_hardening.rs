//! Comprehensive regression suite covering all Track F1 (`#77` `os-cowfs` & `os-cowtree`)
//! hardening items (`F1-01`..`F1-29`), including all CRITICAL and HIGH live repro cases.

use abi::Errno;
use abi::contract::{Durability, WriterModel, mount_flags};
use abi::fs::{FsId, OpenOptions, SetAttr, Timespec, WriteAt, XattrFlags};
use cowtree::memory::{MemoryHeadStore, MemoryPackStore};
use cowtree::{
    Arena, ArenaConfig, BLOCK_SIZE, BlockLoc, CommitRequest, CowTree, Digest, EXTENT_MAX_BYTES,
    ForkRequest, GcLockGuard, GcRoot, HeadStore, KEY_TAIL_MAX_BYTES, KIND_EXTENT_DATA, LeafEntry,
    Node, PackId, PackIndexEntry, PackStore, RoPinGuard, RootObject, SnapshotRecord, TreeKey,
    TreeOverlay, VolumeHead, VolumeId, WriterLease, WriterMode, decode_pack_trailer, encode_pack,
    sha256,
};
use os_core::acl::Entries;
use os_core::permissions::Identity;
use os_cowfs::inode::ExtentDataValue;
use os_cowfs::native_sqlite::{NativePackStore, NativeSqliteHeadStore};
use os_cowfs::{
    CowFs, CowFsClock, CowFsConfig, CowFsOpenMode, CowFsVolumeDevice, collect_garbage,
    verify_volume,
};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashSet};
use std::future::{Future, poll_fn};
use std::path::PathBuf;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use vfs::devfs::{DefaultDeviceBackend, DevTmpFs};
use vfs::vblk::{VblkDeviceBackend, VblkRegistry, VolumeDevice};
use vfs::{
    BoxFuture, Cred, DefaultFilesystemFactory, Filesystem, FsType, MountBacking, MountFlags,
    StartAnchor, Vfs, now_or_never,
};

fn noop_waker() -> Waker {
    fn clone(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    fn noop(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    // SAFETY: vtable pointers are static no-op functions that never dereference the null data pointer.
    unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
}

fn poll_once<F: Future + Unpin>(fut: &mut F) -> Poll<F::Output> {
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    Pin::new(fut).poll(&mut cx)
}

fn run<F: Future>(fut: F) -> F::Output {
    now_or_never(fut).expect("future must resolve")
}

/// Drive two pinned futures in strict alternating round-robin polls until both complete.
fn drive_interleaved<A, B, FA, FB>(fa: FA, fb: FB) -> (A, B)
where
    FA: Future<Output = A>,
    FB: Future<Output = B>,
{
    let mut fa = Box::pin(fa);
    let mut fb = Box::pin(fb);
    let mut out_a = None;
    let mut out_b = None;
    for _ in 0..10_000 {
        if out_a.is_none()
            && let Poll::Ready(v) = poll_once(&mut fa)
        {
            out_a = Some(v);
        }
        if out_b.is_none()
            && let Poll::Ready(v) = poll_once(&mut fb)
        {
            out_b = Some(v);
        }
        match (out_a.take(), out_b.take()) {
            (Some(a), Some(b)) => return (a, b),
            (a, b) => {
                out_a = a;
                out_b = b;
            }
        }
    }
    panic!("interleaved futures did not settle within 10_000 polls");
}

struct ManualClock(Rc<Cell<u64>>);
impl ManualClock {
    fn new(start: u64) -> Self {
        Self(Rc::new(Cell::new(start)))
    }
    fn advance(&self, secs: u64) {
        self.0.set(self.0.get() + secs);
    }
    fn now(&self) -> Timespec {
        Timespec {
            sec: self.0.get(),
            nsec: 0,
        }
    }
    fn clock(&self) -> CowFsClock {
        let cell = Rc::clone(&self.0);
        Rc::new(move || Timespec {
            sec: cell.get(),
            nsec: 0,
        })
    }
}

struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(1);
        let id = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("os-cowfs-f1-{tag}-{}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn rw_create() -> OpenOptions {
    let mut o = OpenOptions::new();
    o.read(true).write(true).create(true).truncate(true);
    o
}

fn ro_open() -> OpenOptions {
    let mut o = OpenOptions::new();
    o.read(true);
    o
}

fn rw_open() -> OpenOptions {
    let mut o = OpenOptions::new();
    o.read(true).write(true);
    o
}

type CommitHook = Box<dyn FnMut(&CommitRequest)>;

/// Controllable `HeadStore` wrapper over `MemoryHeadStore` for deterministic interleaving & fault
/// injection across `.await` boundaries.
struct ControllableHeadStore {
    inner: MemoryHeadStore,
    pause_commit: Cell<bool>,
    yield_get_node: Cell<bool>,
    fail_get_node_err: Cell<Option<Errno>>,
    fail_get_node_skip: Cell<usize>,
    commit_hook: RefCell<Option<CommitHook>>,
}

impl ControllableHeadStore {
    fn new() -> Self {
        Self {
            inner: MemoryHeadStore::new(),
            pause_commit: Cell::new(false),
            yield_get_node: Cell::new(false),
            fail_get_node_err: Cell::new(None),
            fail_get_node_skip: Cell::new(0),
            commit_hook: RefCell::new(None),
        }
    }
}

impl HeadStore for ControllableHeadStore {
    fn format_version(&self) -> BoxFuture<'_, Option<u32>> {
        self.inner.format_version()
    }
    fn grace_window_secs(&self) -> u64 {
        self.inner.grace_window_secs()
    }
    fn create_volume<'a>(
        &'a self,
        head: &'a VolumeHead,
        initial_nodes: &'a [(Digest, Vec<u8>)],
    ) -> BoxFuture<'a, VolumeHead> {
        self.inner.create_volume(head, initial_nodes)
    }
    fn read_head<'a>(&'a self, volume: &'a VolumeId) -> BoxFuture<'a, VolumeHead> {
        self.inner.read_head(volume)
    }
    fn delete_volume<'a>(&'a self, volume: &'a VolumeId) -> BoxFuture<'a, ()> {
        self.inner.delete_volume(volume)
    }
    fn delete_volume_with_lease<'a>(
        &'a self,
        lease: WriterLease,
        require_unmodified_ephemeral: bool,
    ) -> BoxFuture<'a, bool> {
        self.inner
            .delete_volume_with_lease(lease, require_unmodified_ephemeral)
    }
    fn reformat_volume_with_lease<'a>(
        &'a self,
        lease: WriterLease,
        new_head: &'a VolumeHead,
        initial_nodes: &'a [(Digest, Vec<u8>)],
    ) -> BoxFuture<'a, VolumeHead> {
        self.inner
            .reformat_volume_with_lease(lease, new_head, initial_nodes)
    }
    fn get_node<'a>(&'a self, digest: &'a Digest) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(async move {
            if self.yield_get_node.get() {
                let mut yielded = false;
                poll_fn(|_| {
                    if !yielded {
                        yielded = true;
                        Poll::Pending
                    } else {
                        Poll::Ready(())
                    }
                })
                .await;
            }
            if let Some(err) = self.fail_get_node_err.get() {
                let skip = self.fail_get_node_skip.get();
                if skip == 0 {
                    self.fail_get_node_err.set(None);
                    return Err(err);
                }
                self.fail_get_node_skip.set(skip - 1);
            }
            self.inner.get_node(digest).await
        })
    }
    fn lookup_block<'a>(&'a self, digest: &'a Digest) -> BoxFuture<'a, Option<BlockLoc>> {
        self.inner.lookup_block(digest)
    }
    fn acquire_writer<'a>(
        &'a self,
        volume: &'a VolumeId,
        mode: WriterMode,
    ) -> BoxFuture<'a, WriterLease> {
        self.inner.acquire_writer(volume, mode)
    }
    fn renew_writer<'a>(&'a self, lease: &'a mut WriterLease) -> BoxFuture<'a, ()> {
        self.inner.renew_writer(lease)
    }
    fn release_writer<'a>(&'a self, lease: WriterLease) -> BoxFuture<'a, ()> {
        self.inner.release_writer(lease)
    }
    fn pin_ro_root<'a>(
        &'a self,
        volume: &'a VolumeId,
        snapshot: Option<&'a str>,
    ) -> BoxFuture<'a, (VolumeHead, Box<dyn RoPinGuard>)> {
        self.inner.pin_ro_root(volume, snapshot)
    }
    fn unpin_ro_root<'a>(&'a self, guard: Box<dyn RoPinGuard>) -> BoxFuture<'a, ()> {
        self.inner.unpin_ro_root(guard)
    }
    fn commit_head<'a>(&'a self, req: &'a CommitRequest) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async move {
            poll_fn(|_| {
                if self.pause_commit.get() {
                    Poll::Pending
                } else {
                    Poll::Ready(())
                }
            })
            .await;
            if let Some(cb) = self.commit_hook.borrow_mut().as_mut() {
                cb(req);
            }
            self.inner.commit_head(req).await
        })
    }
    fn create_snapshot<'a>(
        &'a self,
        volume: &'a VolumeId,
        name: &'a str,
        head: &'a VolumeHead,
        now: Timespec,
    ) -> BoxFuture<'a, SnapshotRecord> {
        self.inner.create_snapshot(volume, name, head, now)
    }
    fn get_snapshot<'a>(
        &'a self,
        volume: &'a VolumeId,
        name: &'a str,
    ) -> BoxFuture<'a, SnapshotRecord> {
        self.inner.get_snapshot(volume, name)
    }
    fn list_snapshots<'a>(&'a self, volume: &'a VolumeId) -> BoxFuture<'a, Vec<SnapshotRecord>> {
        self.inner.list_snapshots(volume)
    }
    fn delete_snapshot<'a>(&'a self, volume: &'a VolumeId, name: &'a str) -> BoxFuture<'a, ()> {
        self.inner.delete_snapshot(volume, name)
    }
    fn fork_volume<'a>(&'a self, req: &'a ForkRequest) -> BoxFuture<'a, VolumeHead> {
        self.inner.fork_volume(req)
    }
    fn acquire_gc_lock(&self, exclusive: bool) -> BoxFuture<'_, Box<dyn GcLockGuard>> {
        self.inner.acquire_gc_lock(exclusive)
    }
    fn list_all_roots(&self) -> BoxFuture<'_, Vec<GcRoot>> {
        self.inner.list_all_roots()
    }
    fn list_indexed_packs(&self) -> BoxFuture<'_, HashSet<PackId>> {
        self.inner.list_indexed_packs()
    }
    fn prune_abandoned_ephemeral_forks(
        &self,
        now: Timespec,
        grace_window_secs: u64,
    ) -> BoxFuture<'_, usize> {
        self.inner
            .prune_abandoned_ephemeral_forks(now, grace_window_secs)
    }
    fn sweep_metadata<'a>(
        &'a self,
        keep_nodes: &'a HashSet<Digest>,
        keep_packs: &'a HashSet<PackId>,
        now: Timespec,
        grace_window_secs: u64,
    ) -> BoxFuture<'a, Vec<PackId>> {
        self.inner
            .sweep_metadata(keep_nodes, keep_packs, now, grace_window_secs)
    }
}

// =============================================================================
// F1-01 (CRITICAL): Concurrent mutations across `commit_tx_group` `.await`
// =============================================================================

#[test]
fn f1_01_concurrent_write_and_create_during_in_flight_commit_preserve_all_mutations_and_inodes() {
    let clock = ManualClock::new(1_000);
    let hs = Rc::new(ControllableHeadStore::new());
    let ps = Rc::new(MemoryPackStore::new());
    let vol = VolumeId("vol-f1-01".into());
    let admin = Cred::root();
    run(CowFs::format_volume(
        &*hs,
        &*ps,
        vol.clone(),
        0,
        0,
        0o755,
        clock.now(),
    ))
    .unwrap();
    let fs = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol.clone(),
        CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
        CowFsConfig::local_browser(clock.clock()),
    ))
    .unwrap();

    // Stage initial file and start `commit_tx_group()` paused inside `commit_head`.
    let (e_seed, o_seed) =
        run(fs.create(&admin, &fs.root(), "seed.txt", 0o644, &rw_create())).unwrap();
    run(fs.write_at(&o_seed, b"epoch-1", WriteAt::Offset(0))).unwrap();

    hs.pause_commit.set(true);
    let mut commit_fut = Box::pin(fs.commit_tx_group());
    assert!(matches!(poll_once(&mut commit_fut), Poll::Pending));

    // While commit 1 is suspended inside `commit_head`, concurrently create a new file AND
    // overwrite `seed.txt`!
    let (e_conc, o_conc) =
        run(fs.create(&admin, &fs.root(), "concurrent.txt", 0o644, &rw_create())).unwrap();
    assert_ne!(
        e_seed.handle.node.ino, e_conc.handle.node.ino,
        "concurrent create must allocate distinct inode"
    );
    run(fs.write_at(&o_conc, b"never-lost", WriteAt::Offset(0))).unwrap();
    run(fs.write_at(&o_seed, b"epoch-2", WriteAt::Offset(0))).unwrap();

    // Resume commit 1 -> finishes epoch 1 WITHOUT wiping live concurrent writes or resetting `next_ino`!
    hs.pause_commit.set(false);
    let head1 = match poll_once(&mut commit_fut) {
        Poll::Ready(Ok(h)) => h,
        other => panic!("expected commit 1 Ready(Ok), got {other:?}"),
    };
    assert_eq!(head1.epoch, 1);

    // Create a 3rd file after commit 1 -> must NOT reuse `e_conc`'s inode!
    let (e_third, o_third) =
        run(fs.create(&admin, &fs.root(), "third.txt", 0o644, &rw_create())).unwrap();
    assert_ne!(e_third.handle.node.ino, e_conc.handle.node.ino);
    run(fs.write_at(&o_third, b"third", WriteAt::Offset(0))).unwrap();

    // Now test rollback merge-under ordering: pause commit 2, stage a newer write on `seed.txt`,
    // then fail commit 2 with `ENOSPC` -> newer write MUST win over rolled-back older write!
    hs.pause_commit.set(true);
    hs.inner.fail_next_commit(Errno::ENOSPC);
    let mut commit2 = Box::pin(fs.commit_tx_group());
    assert!(matches!(poll_once(&mut commit2), Poll::Pending));
    run(fs.write_at(&o_seed, b"epoch-3-newest", WriteAt::Offset(0))).unwrap();
    hs.pause_commit.set(false);
    assert!(matches!(
        poll_once(&mut commit2),
        Poll::Ready(Err(Errno::ENOSPC))
    ));

    // Next commit persists everything cleanly: `seed.txt` has "epoch-3-newest", AND `concurrent.txt`
    // and `third.txt` are intact!
    run(fs.release(&o_seed)).unwrap();
    run(fs.release(&o_conc)).unwrap();
    run(fs.release(&o_third)).unwrap();
    run(fs.close_clean()).unwrap();

    let report = run(verify_volume(&*hs, &*ps, &vol)).unwrap();
    assert!(report.ok, "fsck errors: {:?}", report.errors);

    let ro = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol,
        CowFsOpenMode::ReadOnly,
        CowFsConfig::local_browser(clock.clock()),
    ))
    .unwrap();
    for (name, expected) in [
        ("seed.txt", b"epoch-3-newest".as_slice()),
        ("concurrent.txt", b"never-lost".as_slice()),
        ("third.txt", b"third".as_slice()),
    ] {
        let ent = run(ro.lookup(&admin, &ro.root(), name)).unwrap();
        let fd = run(ro.open(&admin, &ent.handle, &ro_open())).unwrap();
        let mut buf = vec![0u8; expected.len()];
        assert_eq!(run(ro.read_at(&fd, &mut buf, 0)).unwrap(), expected.len());
        assert_eq!(&buf, expected);
        run(ro.release(&fd)).unwrap();
    }
    run(ro.close_clean()).unwrap();
}

// =============================================================================
// F1-02 (CRITICAL): `reclaim_if_dead` error never loses unrelated overlay state
// =============================================================================

#[test]
fn f1_02_reclaim_if_dead_error_preserves_unrelated_overlay_mutations() {
    let clock = ManualClock::new(2_000);
    let hs = Rc::new(ControllableHeadStore::new());
    let ps = Rc::new(MemoryPackStore::new());
    let vol = VolumeId("vol-f1-02".into());
    let admin = Cred::root();
    run(CowFs::format_volume(
        &*hs,
        &*ps,
        vol.clone(),
        0,
        0,
        0o755,
        clock.now(),
    ))
    .unwrap();
    let fs = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol.clone(),
        CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
        CowFsConfig::local_browser(clock.clock()),
    ))
    .unwrap();

    // Commit a multi-block file so its B+tree leaves sit in `head_store`.
    let (_, o_vic) = run(fs.create(&admin, &fs.root(), "victim.bin", 0o644, &rw_create())).unwrap();
    run(fs.write_at(&o_vic, &vec![0xAB; 256 * 1024], WriteAt::Offset(0))).unwrap();
    run(fs.release(&o_vic)).unwrap();
    run(fs.commit_tx_group()).unwrap();

    // Stage an unrelated dirty file in the live overlay.
    let (_, o_keep) = run(fs.create(&admin, &fs.root(), "keep.txt", 0o644, &rw_create())).unwrap();
    run(fs.write_at(&o_keep, b"must-survive", WriteAt::Offset(0))).unwrap();
    run(fs.release(&o_keep)).unwrap();

    // Drop clean caches so `reclaim_if_dead_locked`'s scan hits `get_node`, and inject EIO!
    // Skip lookups inside `unlink` itself (root inode + victim dir_item + victim inode = 1 leaf hit,
    // wait: everything is cached on first leaf unless we inject EIO on the 2nd get_node!).
    // Ensure victim's extents are on a separate leaf by inserting 400 dummy files first.
    for i in 0..400 {
        let (_, fd) = run(fs.create(
            &admin,
            &fs.root(),
            &format!("pad_{i:04}.txt"),
            0o644,
            &rw_create(),
        ))
        .unwrap();
        run(fs.release(&fd)).unwrap();
    }
    run(fs.commit_tx_group()).unwrap();
    // Re-stage `keep2.txt` in overlay after commit.
    let (_, o_keep2) =
        run(fs.create(&admin, &fs.root(), "keep2.txt", 0o644, &rw_create())).unwrap();
    run(fs.write_at(&o_keep2, b"unrelated-dirty", WriteAt::Offset(0))).unwrap();
    run(fs.release(&o_keep2)).unwrap();

    fs.drop_clean_caches();
    // Inject EIO on `get_node` during `reclaim_if_dead_locked` (after root lookup, when scanning
    // victim's extent leaves across the multi-leaf tree) and verify `keep2.txt` survives!
    hs.fail_get_node_skip.set(1);
    hs.fail_get_node_err.set(Some(Errno::EIO));
    let res = run(fs.unlink(&admin, &fs.root(), "victim.bin"));
    assert_eq!(res.unwrap_err(), Errno::EIO);
    hs.fail_get_node_err.set(None);
    let ent = run(fs.lookup(&admin, &fs.root(), "keep2.txt")).unwrap();
    let fd = run(fs.open(&admin, &ent.handle, &ro_open())).unwrap();
    let mut got = [0u8; 15];
    assert_eq!(run(fs.read_at(&fd, &mut got, 0)).unwrap(), 15);
    assert_eq!(&got, b"unrelated-dirty");
    run(fs.release(&fd)).unwrap();
    run(fs.close_clean()).unwrap();
}

// =============================================================================
// F1-04 (CRITICAL): RO/fenced `close_clean` never prunes fork; closed mount refuses writes
// =============================================================================

#[test]
fn f1_04_ro_and_fenced_close_clean_never_prune_ephemeral_fork_and_closed_mount_refuses_writes() {
    let clock = ManualClock::new(3_000);
    let hs = Rc::new(MemoryHeadStore::new());
    let ps = Rc::new(MemoryPackStore::new());
    let vol = VolumeId("vol-f1-04".into());
    let admin = Cred::root();
    run(CowFs::format_volume(
        &*hs,
        &*ps,
        vol.clone(),
        0,
        0,
        0o755,
        clock.now(),
    ))
    .unwrap();

    let w1 = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol.clone(),
        CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
        CowFsConfig::local_browser(clock.clock()),
    ))
    .unwrap();

    // Open an unmodified ephemeral fork via ForkOnBusy.
    let fork1 = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol.clone(),
        CowFsOpenMode::ReadWrite(WriterMode::ForkOnBusy),
        CowFsConfig::local_browser(clock.clock()),
    ))
    .unwrap();
    let fork_id = fork1.volume_id().clone();

    // 1. Open RO on the unmodified ephemeral fork and call `ro.close_clean()` -> MUST NOT delete fork!
    let ro_fork = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        fork_id.clone(),
        CowFsOpenMode::ReadOnly,
        CowFsConfig::local_browser(clock.clock()),
    ))
    .unwrap();
    run(ro_fork.close_clean()).unwrap();
    assert!(
        run(hs.read_head(&fork_id)).is_ok(),
        "RO close_clean must NEVER delete an ephemeral fork"
    );

    // 2. Another writer takes over the ephemeral fork via ForceTakeover and writes data.
    let fork2 = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        fork_id.clone(),
        CowFsOpenMode::ReadWrite(WriterMode::ForceTakeover),
        CowFsConfig::local_browser(clock.clock()),
    ))
    .unwrap();
    let (_, f2o) =
        run(fork2.create(&admin, &fork2.root(), "saved.txt", 0o644, &rw_create())).unwrap();
    run(fork2.write_at(&f2o, b"from-fork2", WriteAt::Offset(0))).unwrap();
    run(fork2.release(&f2o)).unwrap();
    run(fork2.commit_tx_group()).unwrap();

    // 3. Fenced `fork1` discovers fence (or even before discovering it!) and calls `close_clean()`:
    //    `delete_volume_with_lease` MUST NOT delete `fork2`'s modified volume!
    run(fork1.close_clean()).unwrap();
    let head_after = run(hs.read_head(&fork_id)).expect("fenced close_clean must NOT delete fork");
    assert!(head_after.modified);

    // 4. Post-close mutations and commits on closed `fork1` / `fork2` MUST fail with `EBADF`!
    assert_eq!(
        run(fork1.create(&admin, &fork1.root(), "after.txt", 0o644, &rw_create())).unwrap_err(),
        Errno::EBADF
    );
    assert_eq!(run(fork1.commit_tx_group()).unwrap_err(), Errno::EBADF);

    run(fork2.close_clean()).unwrap();
    assert_eq!(
        run(fork2.mkdir(&admin, &fork2.root(), "nope", 0o755)).unwrap_err(),
        Errno::EBADF
    );
    assert_eq!(run(fork2.commit_tx_group()).unwrap_err(), Errno::EBADF);
    run(w1.close_clean()).unwrap();
}

// =============================================================================
// F1-05 (HIGH): `scan_range_with_overlay` must not truncate after tombstoned page
// =============================================================================

#[test]
fn f1_05_scan_range_with_overlay_does_not_truncate_after_tombstoned_page() {
    let clock = ManualClock::new(4_000);
    let hs = Rc::new(MemoryHeadStore::new());
    let ps = Rc::new(MemoryPackStore::new());
    let vol = VolumeId("vol-f1-05".into());
    let admin = Cred::root();
    run(CowFs::format_volume(
        &*hs,
        &*ps,
        vol.clone(),
        0,
        0,
        0o755,
        clock.now(),
    ))
    .unwrap();
    let fs = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol,
        CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
        CowFsConfig::local_browser(clock.clock()),
    ))
    .unwrap();

    // Exact Codex repro: commit 18 children in `d`, unlink first 17 in overlay, leaving 18th live!
    let d = run(fs.mkdir(&admin, &fs.root(), "d", 0o755)).unwrap();
    for i in 0..18 {
        let (_, fd) =
            run(fs.create(&admin, &d.handle, &format!("f{i:02}"), 0o644, &rw_create())).unwrap();
        run(fs.release(&fd)).unwrap();
    }
    run(fs.commit_tx_group()).unwrap();

    for i in 0..17 {
        run(fs.unlink(&admin, &d.handle, &format!("f{i:02}"))).unwrap();
    }

    // `rmdir` MUST refuse with ENOTEMPTY (previously saw 16 tombstoned base entries and returned empty)!
    assert_eq!(
        run(fs.rmdir(&admin, &fs.root(), "d")).unwrap_err(),
        Errno::ENOTEMPTY
    );
    let entries = run(fs.read_dir(&admin, &d.handle)).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "f17");

    let page = run(fs.read_dir_page(&admin, &d.handle, 0, 10)).unwrap();
    assert_eq!(page.entries.len(), 1);
    assert_eq!(page.entries[0].name, "f17");
    run(fs.close_clean()).unwrap();
}

// =============================================================================
// F1-06 (HIGH): Interleaved mkdir, O_APPEND, and paused read_at + truncate
// =============================================================================

#[test]
fn f1_06_concurrent_mkdir_append_and_paused_read_atime_are_serialized() {
    let clock = ManualClock::new(5_000);
    let hs = Rc::new(ControllableHeadStore::new());
    let ps = Rc::new(MemoryPackStore::new());
    let vol = VolumeId("vol-f1-06".into());
    let admin = Cred::root();
    run(CowFs::format_volume(
        &*hs,
        &*ps,
        vol.clone(),
        0,
        0,
        0o755,
        clock.now(),
    ))
    .unwrap();
    let fs = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol.clone(),
        CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
        CowFsConfig::local_browser(clock.clock()),
    ))
    .unwrap();

    // Seed parent dir + file and commit so cold reads yield inside `get_node`.
    let parent = run(fs.mkdir(&admin, &fs.root(), "par", 0o755)).unwrap();
    let (file_ent, f_fd) =
        run(fs.create(&admin, &parent.handle, "app.txt", 0o644, &rw_create())).unwrap();
    run(fs.write_at(&f_fd, b"HEAD", WriteAt::Offset(0))).unwrap();
    run(fs.commit_tx_group()).unwrap();

    // 1. Interleaved concurrent `mkdir` inside `par` -> unique dir_index cookies, fsck clean!
    fs.drop_clean_caches();
    hs.yield_get_node.set(true);
    let (r1, r2) = drive_interleaved(
        fs.mkdir(&admin, &parent.handle, "sub_a", 0o755),
        fs.mkdir(&admin, &parent.handle, "sub_b", 0o755),
    );
    r1.unwrap();
    r2.unwrap();

    // 2. Interleaved concurrent `O_APPEND` writes on `app.txt` -> neither clobbers the other!
    fs.drop_clean_caches();
    let (w1, w2) = drive_interleaved(
        fs.write_at(&f_fd, b"AAAA", WriteAt::End),
        fs.write_at(&f_fd, b"BBBB", WriteAt::End),
    );
    let w1 = w1.unwrap();
    let w2 = w2.unwrap();
    assert_ne!(w1.offset, w2.offset, "concurrent O_APPEND must serialize");
    let meta = run(fs.open_metadata(&f_fd)).unwrap();
    assert_eq!(meta.size, 12);

    // 3. Paused `read_at` after 24h (triggers relatime) raced with `set_len(0)` -> MUST NOT
    //    overwrite truncated size=0 with stale size=12!
    hs.yield_get_node.set(false);
    run(fs.commit_tx_group()).unwrap();
    clock.advance(90_000);
    fs.drop_clean_caches();
    hs.yield_get_node.set(true);
    let mut rbuf = [0u8; 12];
    let (r_res, t_res) = drive_interleaved(fs.read_at(&f_fd, &mut rbuf, 0), fs.set_len(&f_fd, 0));
    r_res.unwrap();
    t_res.unwrap();
    hs.yield_get_node.set(false);

    let after_meta = run(fs.metadata(&admin, &file_ent.handle)).unwrap();
    assert_eq!(
        after_meta.size, 0,
        "relatime update from concurrent read_at must never restore pre-truncate size"
    );

    run(fs.release(&f_fd)).unwrap();
    run(fs.close_clean()).unwrap();
    let report = run(verify_volume(&*hs, &*ps, &vol)).unwrap();
    assert!(report.ok, "fsck errors: {:?}", report.errors);
}

// =============================================================================
// F1-07 (HIGH): 4 GiB sparse truncate preserves inline prefix
// =============================================================================

#[test]
fn f1_07_resize_file_4gib_preserves_inline_prefix() {
    let clock = ManualClock::new(6_000);
    let hs = Rc::new(MemoryHeadStore::new());
    let ps = Rc::new(MemoryPackStore::new());
    let vol = VolumeId("vol-f1-07".into());
    let admin = Cred::root();
    run(CowFs::format_volume(
        &*hs,
        &*ps,
        vol.clone(),
        0,
        0,
        0o755,
        clock.now(),
    ))
    .unwrap();
    let fs = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol,
        CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
        CowFsConfig::local_browser(clock.clock()),
    ))
    .unwrap();

    let (_, fd) = run(fs.create(&admin, &fs.root(), "sparse.bin", 0o644, &rw_create())).unwrap();
    run(fs.write_at(&fd, b"INLINE-PREFIX", WriteAt::Offset(0))).unwrap();
    run(fs.set_len(&fd, 8 * 1024 * 1024 * 1024)).unwrap();
    run(fs.set_len(&fd, 4 * 1024 * 1024 * 1024)).unwrap();
    let mut got = [0u8; 13];
    assert_eq!(run(fs.read_at(&fd, &mut got, 0)).unwrap(), 13);
    assert_eq!(&got, b"INLINE-PREFIX");
    assert_eq!(
        run(fs.open_metadata(&fd)).unwrap().size,
        4 * 1024 * 1024 * 1024
    );
    run(fs.release(&fd)).unwrap();
    run(fs.close_clean()).unwrap();
}

// =============================================================================
// F1-08 (HIGH): Failed reflink preserves dst; large reflink respects arena budget
// =============================================================================

#[test]
fn f1_08_failed_reflink_preserves_dst_and_large_reflink_respects_arena_budget() {
    let clock = ManualClock::new(7_000);
    let hs = Rc::new(ControllableHeadStore::new());
    let ps = Rc::new(MemoryPackStore::new());
    let vol = VolumeId("vol-f1-08".into());
    let admin = Cred::root();
    run(CowFs::format_volume(
        &*hs,
        &*ps,
        vol.clone(),
        0,
        0,
        0o755,
        clock.now(),
    ))
    .unwrap();
    let tight_arena = ArenaConfig {
        tree_lru_bytes: 256 * 1024,
        clean_data_bytes: 512 * 1024,
        dirty_bytes: 128 * 1024,
    };
    let fs = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol.clone(),
        CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
        CowFsConfig::local_browser(clock.clock()).with_arena(tight_arena),
    ))
    .unwrap();

    // 1. Create `src` (400 extents spanning multiple B+tree leaves) and `dst` ("PRECIOUS-DST").
    let (_, o_src) = run(fs.create(&admin, &fs.root(), "src.bin", 0o644, &rw_create())).unwrap();
    let blk_src = vec![0x22u8; BLOCK_SIZE as usize];
    for i in 0..400u64 {
        run(fs.write_at(&o_src, &blk_src, WriteAt::Offset(i * u64::from(BLOCK_SIZE)))).unwrap();
    }
    let (_, o_dst) = run(fs.create(&admin, &fs.root(), "dst.bin", 0o644, &rw_create())).unwrap();
    run(fs.write_at(&o_dst, b"PRECIOUS-DST", WriteAt::Offset(0))).unwrap();
    run(fs.commit_tx_group()).unwrap();

    // 2. Drop clean caches and inject EIO on `get_node` midway through scanning `src`'s leaves ->
    //    `reflink` MUST fail with EIO while leaving `dst` ("PRECIOUS-DST") 100% intact!
    fs.drop_clean_caches();
    hs.fail_get_node_skip.set(2);
    hs.fail_get_node_err.set(Some(Errno::EIO));
    assert_eq!(
        run(fs.reflink(&admin, &o_src, &o_dst)).unwrap_err(),
        Errno::EIO
    );
    hs.fail_get_node_err.set(None);
    let mut check = [0u8; 12];
    assert_eq!(run(fs.read_at(&o_dst, &mut check, 0)).unwrap(), 12);
    assert_eq!(&check, b"PRECIOUS-DST");
    assert_eq!(run(fs.open_metadata(&o_dst)).unwrap().size, 12);

    // 3. Succeed on large reflink (1500 distinct extents -> triggers streaming path under 128 KiB
    //    dirty budget!) and verify peak dirty bytes stay within budget!
    let (_, o_huge_src) =
        run(fs.create(&admin, &fs.root(), "huge_src.bin", 0o644, &rw_create())).unwrap();
    let blk = vec![0x44u8; BLOCK_SIZE as usize];
    for i in 0..1500u64 {
        run(fs.write_at(
            &o_huge_src,
            &blk,
            WriteAt::Offset(i * u64::from(BLOCK_SIZE)),
        ))
        .unwrap();
    }
    let (_, o_huge_dst) =
        run(fs.create(&admin, &fs.root(), "huge_dst.bin", 0o644, &rw_create())).unwrap();
    run(fs.commit_tx_group()).unwrap();

    ps.reset_counters();
    run(fs.reflink(&admin, &o_huge_src, &o_huge_dst)).unwrap();
    run(fs.commit_tx_group()).unwrap();
    assert_eq!(ps.bytes_written(), 0, "reflink writes 0 pack bytes");
    assert_eq!(
        run(fs.open_metadata(&o_huge_dst)).unwrap().size,
        1500 * u64::from(BLOCK_SIZE)
    );
    assert!(
        fs.arena_stats().peak_dirty_bytes <= tight_arena.dirty_bytes,
        "peak dirty {} exceeded tight budget {}",
        fs.arena_stats().peak_dirty_bytes,
        tight_arena.dirty_bytes
    );

    run(fs.release(&o_src)).unwrap();
    run(fs.release(&o_dst)).unwrap();
    run(fs.release(&o_huge_src)).unwrap();
    run(fs.release(&o_huge_dst)).unwrap();
    run(fs.close_clean()).unwrap();
    assert!(run(verify_volume(&*hs, &*ps, &vol)).unwrap().ok);
}

// =============================================================================
// F1-09 (HIGH): Ambiguous EIO after commit applied reconciles via receipt
// =============================================================================

#[test]
fn f1_09_ambiguous_commit_eio_reconciles_receipt_on_retry_without_estale() {
    let clock = ManualClock::new(8_000);
    let hs = Rc::new(MemoryHeadStore::new());
    let ps = Rc::new(MemoryPackStore::new());
    let vol = VolumeId("vol-f1-09".into());
    let admin = Cred::root();
    run(CowFs::format_volume(
        &*hs,
        &*ps,
        vol.clone(),
        0,
        0,
        0o755,
        clock.now(),
    ))
    .unwrap();
    let fs = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol.clone(),
        CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
        CowFsConfig::local_browser(clock.clock()),
    ))
    .unwrap();

    let (_, fd) = run(fs.create(&admin, &fs.root(), "rec.txt", 0o644, &rw_create())).unwrap();
    run(fs.write_at(&fd, b"reconcile-me", WriteAt::Offset(0))).unwrap();

    // Simulate storage applying `commit_head` cleanly, then dropping the response (`EIO`).
    hs.fail_after_next_commit(Errno::EIO);
    assert_eq!(run(fs.commit_tx_group()).unwrap_err(), Errno::EIO);
    assert_eq!(run(hs.read_head(&vol)).unwrap().epoch, 1);

    // Stage an additional write while retry is pending!
    run(fs.write_at(&fd, b"-and-more", WriteAt::End)).unwrap();

    // Retry `commit_tx_group()` -> replays exact `op_id`, resolves receipt (no ESTALE!), AND
    // commits the newly staged write cleanly at epoch 2!
    let head = run(fs.commit_tx_group()).unwrap();
    assert_eq!(head.epoch, 2);
    run(fs.release(&fd)).unwrap();
    run(fs.close_clean()).unwrap();

    let ro = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol,
        CowFsOpenMode::ReadOnly,
        CowFsConfig::local_browser(clock.clock()),
    ))
    .unwrap();
    let ent = run(ro.lookup(&admin, &ro.root(), "rec.txt")).unwrap();
    let rfd = run(ro.open(&admin, &ent.handle, &ro_open())).unwrap();
    let mut got = vec![0u8; 21];
    assert_eq!(run(ro.read_at(&rfd, &mut got, 0)).unwrap(), 21);
    assert_eq!(&got, b"reconcile-me-and-more");
    run(ro.release(&rfd)).unwrap();
    run(ro.close_clean()).unwrap();
}

// =============================================================================
// F1-10 (HIGH): Open RO and Snapshot mounts pin roots across GC
// =============================================================================

#[test]
fn f1_10_ro_and_snapshot_mounts_pin_roots_across_gc() {
    let dir = TempDir::new("ro-snap-pin");
    let clock = ManualClock::new(9_000);
    let hs = Rc::new(NativeSqliteHeadStore::open(&dir.0).unwrap());
    let ps = Rc::new(NativePackStore::open(&dir.0).unwrap());
    hs.set_grace_window_secs(60);
    let vol = VolumeId("vol-f1-10".into());
    let admin = Cred::root();
    run(CowFs::format_volume(
        &*hs,
        &*ps,
        vol.clone(),
        0,
        0,
        0o755,
        clock.now(),
    ))
    .unwrap();

    let rw = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol.clone(),
        CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
        CowFsConfig::local_native(clock.clock()),
    ))
    .unwrap();
    let v1_bytes = vec![0x3Eu8; 64 * 1024];
    let (_, o) = run(rw.create(&admin, &rw.root(), "pinned.bin", 0o644, &rw_create())).unwrap();
    run(rw.write_at(&o, &v1_bytes, WriteAt::Offset(0))).unwrap();
    run(rw.release(&o)).unwrap();
    run(rw.create_snapshot("s1")).unwrap();

    let ro = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol.clone(),
        CowFsOpenMode::ReadOnly,
        CowFsConfig::local_native(clock.clock()),
    ))
    .unwrap();
    let snap = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol.clone(),
        CowFsOpenMode::Snapshot("s1".into()),
        CowFsConfig::local_native(clock.clock()),
    ))
    .unwrap();

    // Unlink file, delete snapshot record, advance clock far past grace window!
    run(rw.unlink(&admin, &rw.root(), "pinned.bin")).unwrap();
    run(rw.commit_tx_group()).unwrap();
    run(hs.delete_snapshot(&vol, "s1")).unwrap();
    clock.advance(3_600);

    // GC MUST keep pack while RO & Snapshot mounts are open!
    let gc1 = run(collect_garbage(&*hs, &*ps, clock.now())).unwrap();
    assert_eq!(gc1.swept_packs.len(), 0);
    for mnt in [&ro, &snap] {
        mnt.drop_clean_caches();
        let ent = run(mnt.lookup(&admin, &mnt.root(), "pinned.bin")).unwrap();
        let fd = run(mnt.open(&admin, &ent.handle, &ro_open())).unwrap();
        let mut got = vec![0u8; v1_bytes.len()];
        assert_eq!(run(mnt.read_at(&fd, &mut got, 0)).unwrap(), v1_bytes.len());
        assert_eq!(got, v1_bytes);
        run(mnt.release(&fd)).unwrap();
    }

    // Close RO -> Snapshot mount STILL keeps pack alive!
    run(ro.close_clean()).unwrap();
    let gc2 = run(collect_garbage(&*hs, &*ps, clock.now())).unwrap();
    assert_eq!(gc2.swept_packs.len(), 0);

    // Close Snapshot -> next GC sweeps pack cleanly!
    run(snap.close_clean()).unwrap();
    let gc3 = run(collect_garbage(&*hs, &*ps, clock.now())).unwrap();
    assert_eq!(gc3.swept_packs.len(), 1);
    run(rw.close_clean()).unwrap();
}

// =============================================================================
// F1-11 & F1-21 (HIGH/MED): Writer & fork wait for exclusive GC lock (no EBUSY)
// =============================================================================

#[test]
fn f1_11_f1_21_writer_and_fork_wait_for_exclusive_gc_lock() {
    let clock = ManualClock::new(10_000);
    let hs = Rc::new(MemoryHeadStore::new());
    let ps = Rc::new(MemoryPackStore::new());
    let vol = VolumeId("vol-f1-11".into());
    let admin = Cred::root();
    run(CowFs::format_volume(
        &*hs,
        &*ps,
        vol.clone(),
        0,
        0,
        0o755,
        clock.now(),
    ))
    .unwrap();
    let fs = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol.clone(),
        CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
        CowFsConfig::local_browser(clock.clock()),
    ))
    .unwrap();
    let (_, fd) = run(fs.create(&admin, &fs.root(), "a.txt", 0o644, &rw_create())).unwrap();
    run(fs.write_at(&fd, b"hello", WriteAt::Offset(0))).unwrap();
    run(fs.release(&fd)).unwrap();

    // Hold exclusive GC lock -> writer commit MUST wait (`Poll::Pending`), NOT fail with `EBUSY`!
    let excl = run(hs.acquire_gc_lock(true)).unwrap();
    let mut commit_fut = Box::pin(fs.commit_tx_group());
    assert!(matches!(poll_once(&mut commit_fut), Poll::Pending));
    drop(excl);
    let committed = match poll_once(&mut commit_fut) {
        Poll::Ready(Ok(h)) => h,
        other => panic!("expected commit Ready(Ok) after GC release, got {other:?}"),
    };
    assert_eq!(committed.epoch, 1);

    // Hold exclusive GC lock -> `fork_volume` MUST wait (`Poll::Pending`), NOT race or EBUSY!
    let excl2 = run(hs.acquire_gc_lock(true)).unwrap();
    let mut fork_fut = Box::pin(fs.fork_volume(None, VolumeId("vol-f1-11-fork".into()), false));
    assert!(matches!(poll_once(&mut fork_fut), Poll::Pending));
    drop(excl2);
    let forked = match poll_once(&mut fork_fut) {
        Poll::Ready(Ok(h)) => h,
        other => panic!("expected fork Ready(Ok) after GC release, got {other:?}"),
    };
    assert_eq!(forked.root, committed.root);
    run(fs.close_clean()).unwrap();
}

// =============================================================================
// F1-12 (HIGH): GC aborts on unindexed live block & preserves indexed pack on corrupt trailer
// =============================================================================

#[test]
fn f1_12_gc_aborts_on_missing_block_index_and_preserves_indexed_pack_on_corrupt_trailer() {
    // Part A: missing block index on live extent -> GC aborts with EIO and sweeps 0 packs!
    let clock = ManualClock::new(11_000);
    let hs = Rc::new(MemoryHeadStore::new());
    let ps = Rc::new(MemoryPackStore::new());
    let vol = VolumeId("vol-f1-12a".into());
    let admin = Cred::root();
    run(CowFs::format_volume(
        &*hs,
        &*ps,
        vol.clone(),
        0,
        0,
        0o755,
        clock.now(),
    ))
    .unwrap();
    let fs = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol.clone(),
        CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
        CowFsConfig::local_browser(clock.clock()),
    ))
    .unwrap();
    let data = vec![0x61u8; 64 * 1024];
    let (_, o) = run(fs.create(&admin, &fs.root(), "live.bin", 0o644, &rw_create())).unwrap();
    run(fs.write_at(&o, &data, WriteAt::Offset(0))).unwrap();
    run(fs.release(&o)).unwrap();
    run(fs.commit_tx_group()).unwrap();
    run(fs.close_clean()).unwrap();

    assert!(hs.remove_block_index(&sha256(&data)).is_some());
    clock.advance(3_600);
    assert_eq!(
        run(collect_garbage(&*hs, &*ps, clock.now())).unwrap_err(),
        Errno::EIO
    );
    assert_eq!(run(ps.list_packs()).unwrap().len(), 1);

    // Part B: on NativeSqlite + NativePackStore, corrupt trailer of an indexed pack -> GC must NOT
    // delete the indexed pack as an "unindexed orphan"!
    let dir = TempDir::new("gc-corrupt-trailer");
    let hs2 = Rc::new(NativeSqliteHeadStore::open(&dir.0).unwrap());
    let ps2 = Rc::new(NativePackStore::open(&dir.0).unwrap());
    hs2.set_grace_window_secs(60);
    let vol2 = VolumeId("vol-f1-12b".into());
    run(CowFs::format_volume(
        &*hs2,
        &*ps2,
        vol2.clone(),
        0,
        0,
        0o755,
        clock.now(),
    ))
    .unwrap();
    let fs2 = run(CowFs::open(
        hs2.clone(),
        ps2.clone(),
        vol2.clone(),
        CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
        CowFsConfig::local_native(clock.clock()),
    ))
    .unwrap();
    let (_, o2) = run(fs2.create(&admin, &fs2.root(), "keep.bin", 0o644, &rw_create())).unwrap();
    run(fs2.write_at(&o2, &vec![0x77u8; 64 * 1024], WriteAt::Offset(0))).unwrap();
    run(fs2.release(&o2)).unwrap();
    run(fs2.close_clean()).unwrap();

    let packs = run(ps2.list_packs()).unwrap();
    assert_eq!(packs.len(), 1);
    let pack_sz = run(ps2.stat_pack(&packs[0])).unwrap().unwrap();
    // Flip a byte in the pack footer so `read_pack_trailer` fails with EIO!
    ps2.corrupt_pack_byte(&packs[0], pack_sz - 2).unwrap();
    clock.advance(3_600);
    let gc = run(collect_garbage(&*hs2, &*ps2, clock.now())).unwrap();
    assert_eq!(gc.swept_packs.len(), 0);
    assert_eq!(
        run(ps2.list_packs()).unwrap().len(),
        1,
        "indexed pack with corrupt trailer must NOT be deleted as an unindexed orphan"
    );
}

// =============================================================================
// F1-13, F1-14, F1-15 (HIGH): Native ForceTakeover flock, write_pack SHA-256,
// multi-ForkOnBusy collision freedom & abandoned fork GC pruning
// =============================================================================

#[test]
fn f1_13_f1_14_f1_15_native_force_takeover_flock_write_pack_sha256_and_abandoned_fork_gc() {
    let dir = TempDir::new("native-hardening");
    let clock = ManualClock::new(12_000);
    let hs = Rc::new(NativeSqliteHeadStore::open(&dir.0).unwrap());
    let ps = Rc::new(NativePackStore::open(&dir.0).unwrap());
    hs.set_grace_window_secs(60);
    let vol = VolumeId("vol-f1-13".into());
    run(CowFs::format_volume(
        &*hs,
        &*ps,
        vol.clone(),
        0,
        0,
        0o755,
        clock.now(),
    ))
    .unwrap();

    // F1-13: ForceTakeover MUST hold a real exclusive flock even after prior holder closes!
    let w1 = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol.clone(),
        CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
        CowFsConfig::local_native(clock.clock()),
    ))
    .unwrap();
    let w2 = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol.clone(),
        CowFsOpenMode::ReadWrite(WriterMode::ForceTakeover),
        CowFsConfig::local_native(clock.clock()),
    ))
    .unwrap();
    assert_eq!(
        run(CowFs::open(
            hs.clone(),
            ps.clone(),
            vol.clone(),
            CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
            CowFsConfig::local_native(clock.clock()),
        ))
        .err(),
        Some(Errno::EBUSY)
    );
    // Close w1 -> w2 MUST STILL exclude w3!
    run(w1.close_clean()).unwrap();
    assert_eq!(
        run(CowFs::open(
            hs.clone(),
            ps.clone(),
            vol.clone(),
            CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
            CowFsConfig::local_native(clock.clock()),
        ))
        .err(),
        Some(Errno::EBUSY)
    );

    // F1-14: NativePackStore::write_pack verifies SHA-256 and replaces corrupt pre-existing file!
    let payload = vec![0x42u8; 4096];
    let built = encode_pack(&[(sha256(&payload), payload)]).unwrap();
    run(ps.write_pack(&built.pack_id, &built.bytes)).unwrap();
    ps.corrupt_pack_byte(&built.pack_id, 8).unwrap();
    assert_ne!(
        run(ps.read_pack_range(&built.pack_id, 0, built.bytes.len() as u32)).unwrap(),
        built.bytes
    );
    run(ps.write_pack(&built.pack_id, &built.bytes)).unwrap();
    assert_eq!(
        run(ps.read_pack_range(&built.pack_id, 0, built.bytes.len() as u32)).unwrap(),
        built.bytes
    );

    // F1-15: Multiple rapid ForkOnBusy opens generate unique CSPRNG IDs; crashed unmodified fork is
    // pruned by GC after grace window!
    let mut fork_ids = HashSet::new();
    let mut forks = Vec::new();
    for _ in 0..3 {
        let f = run(CowFs::open(
            hs.clone(),
            ps.clone(),
            vol.clone(),
            CowFsOpenMode::ReadWrite(WriterMode::ForkOnBusy),
            CowFsConfig::local_native(clock.clock()),
        ))
        .unwrap();
        assert!(fork_ids.insert(f.volume_id().clone()));
        forks.push(f);
    }
    // Drop first fork abruptly WITHOUT `close_clean()` (simulating crash), close others cleanly.
    let abandoned_id = forks[0].volume_id().clone();
    let active_id = forks[1].volume_id().clone();
    drop(forks.remove(0));
    run(forks.pop().unwrap().close_clean()).unwrap();
    // Advance past grace window and run GC: abandoned unlocked fork is pruned; still-open `active_id`
    // stays alive!
    clock.advance(120);
    run(collect_garbage(&*hs, &*ps, clock.now())).unwrap();
    assert_eq!(run(hs.read_head(&abandoned_id)).unwrap_err(), Errno::ENOENT);
    assert!(run(hs.read_head(&active_id)).is_ok());

    run(forks.pop().unwrap().close_clean()).unwrap();
    run(w2.close_clean()).unwrap();
}

// =============================================================================
// F1-17 (HIGH): `mkfs --force` bumps incarnation & wipes snapshots + receipts
// =============================================================================

#[test]
fn f1_17_mkfs_force_bumps_incarnation_and_wipes_snapshots_and_receipts() {
    let dir = TempDir::new("mkfs-force");
    let clock = ManualClock::new(13_000);
    let hs = Rc::new(NativeSqliteHeadStore::open(&dir.0).unwrap());
    let ps = Rc::new(NativePackStore::open(&dir.0).unwrap());
    let vol = VolumeId("vol-f1-17".into());
    let admin = Cred::root();
    run(CowFs::format_volume(
        &*hs,
        &*ps,
        vol.clone(),
        0,
        0,
        0o755,
        clock.now(),
    ))
    .unwrap();

    let fs = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol.clone(),
        CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
        CowFsConfig::local_native(clock.clock()),
    ))
    .unwrap();
    let (_, o) = run(fs.create(&admin, &fs.root(), "secret.txt", 0o644, &rw_create())).unwrap();
    run(fs.write_at(&o, b"old-data", WriteAt::Offset(0))).unwrap();
    run(fs.release(&o)).unwrap();
    run(fs.create_snapshot("old-snap")).unwrap();
    let old_inc = fs.current_head().incarnation;
    run(fs.close_clean()).unwrap();

    // Unmounted `mkfs(force = true)` bumps incarnation and wipes snapshots + receipts atomically!
    let dev = CowFsVolumeDevice::unmounted(
        vol.clone(),
        hs.clone(),
        ps.clone(),
        WriterModel::Local,
        Durability::TreeCommit,
        clock.clock(),
    );
    let info = run(dev.mkfs(true)).unwrap();
    assert!(info.incarnation > old_inc);
    assert_eq!(info.epoch, 0);
    assert_eq!(
        run(hs.get_snapshot(&vol, "old-snap")).unwrap_err(),
        Errno::ENOENT
    );
    assert!(run(hs.list_snapshots(&vol)).unwrap().is_empty());

    let fs2 = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol,
        CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
        CowFsConfig::local_native(clock.clock()),
    ))
    .unwrap();
    assert_eq!(
        run(fs2.lookup(&admin, &fs2.root(), "secret.txt")).unwrap_err(),
        Errno::ENOENT
    );
    run(fs2.close_clean()).unwrap();
}

// =============================================================================
// F1-18 (HIGH): `vblk::mkfs_cowfs` rejects symlinks & trailing slashes with ENOTBLK
// =============================================================================

#[test]
fn f1_18_vblk_mkfs_rejects_symlink_to_vd_with_enotblk() {
    let clock = ManualClock::new(14_000);
    let hs = Rc::new(MemoryHeadStore::new());
    let ps = Rc::new(MemoryPackStore::new());
    let vol_root = VolumeId("vol-vblk-root".into());
    let vol_unm = VolumeId("vol-vblk-unm".into());
    run(CowFs::format_volume(
        &*hs,
        &*ps,
        vol_root.clone(),
        0,
        0,
        0o755,
        clock.now(),
    ))
    .unwrap();
    let root_cow = Rc::new(
        run(CowFs::open(
            hs.clone(),
            ps.clone(),
            vol_root,
            CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
            CowFsConfig::local_native(clock.clock()),
        ))
        .unwrap(),
    );
    let factory = Rc::new(DefaultFilesystemFactory::new(Rc::new(|| (14_000, 0))));
    let vfs = run(Vfs::boot(
        "inst-f1-18",
        Rc::new(MountBacking::new(root_cow, FsType::Cowfs)),
        "volume:vol-vblk-root",
        factory,
    ))
    .unwrap();
    run(vfs.mkdirat(1, StartAnchor::Root, "/dev", 0o755)).unwrap();
    let dev_fs = Rc::new(DevTmpFs::new(
        FsId("devtmpfs:f1-18".into()),
        1,
        Box::new(|| (14_000, 0)),
        VblkDeviceBackend::new(DefaultDeviceBackend),
    ));
    dev_fs.register_vblk("vd1", 0o660).unwrap();
    let sys_ns = vfs.system_namespace();
    run(vfs.mount_on_namespace(
        &sys_ns,
        &Cred::root(),
        Rc::new(MountBacking::new(dev_fs, FsType::DevTmpFs)),
        None,
        "devtmpfs",
        "/dev",
        MountFlags::from_accepted(mount_flags::MS_NOSUID),
        0,
        None,
    ))
    .unwrap();

    let registry = VblkRegistry::new();
    registry
        .attach_named(
            "vd1",
            Rc::new(CowFsVolumeDevice::unmounted(
                vol_unm.clone(),
                hs.clone(),
                ps.clone(),
                WriterModel::Local,
                Durability::TreeCommit,
                clock.clock(),
            )),
        )
        .unwrap();

    // Create symlink `/sym_vd1 -> /dev/vd1`: mkfs MUST refuse symlink and trailing slash with ENOTBLK!
    run(vfs.symlinkat(1, "/dev/vd1", StartAnchor::Root, "/sym_vd1")).unwrap();
    assert_eq!(
        run(registry.mkfs_cowfs(&vfs, 1, "/sym_vd1", true)).unwrap_err(),
        Errno::ENOTBLK
    );
    assert_eq!(
        run(registry.mkfs_cowfs(&vfs, 1, "/dev/vd1/", true)).unwrap_err(),
        Errno::ENOTBLK
    );
    // Direct `/dev/vd1` succeeds cleanly!
    let info = run(registry.mkfs_cowfs(&vfs, 1, "/dev/vd1", false)).unwrap();
    assert_eq!(info.volume, vol_unm.0);
}

// =============================================================================
// F1-20 (HIGH): Oversized 18 KiB POSIX ACL rejected with E2BIG before dirtying
// =============================================================================

#[test]
fn f1_20_oversized_posix_acl_rejected_with_e2big_before_dirtying_overlay() {
    let clock = ManualClock::new(15_000);
    let hs = Rc::new(MemoryHeadStore::new());
    let ps = Rc::new(MemoryPackStore::new());
    let vol = VolumeId("vol-f1-20".into());
    let admin = Cred::root();
    run(CowFs::format_volume(
        &*hs,
        &*ps,
        vol.clone(),
        0,
        0,
        0o755,
        clock.now(),
    ))
    .unwrap();
    let fs = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol,
        CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
        CowFsConfig::local_browser(clock.clock()),
    ))
    .unwrap();

    let (ent, fd) = run(fs.create(&admin, &fs.root(), "acl.txt", 0o644, &rw_create())).unwrap();
    run(fs.release(&fd)).unwrap();
    run(fs.commit_tx_group()).unwrap();

    // Build an ~20 KiB POSIX ACL (> 16 KiB LEAF_MAX_BYTES, Codex's exact live repro).
    let mut users = BTreeMap::new();
    for uid in 1000..3200u32 {
        users.insert(uid, 6u16);
    }
    let huge = Entries {
        user: 6,
        group: 4,
        other: 4,
        mask: Some(6),
        users,
        groups: BTreeMap::new(),
    };
    let json = serde_json::to_vec(&huge).unwrap();
    assert!(json.len() > 16 * 1024);

    assert_eq!(
        run(fs.setxattr(
            &admin,
            &ent.handle,
            abi::ACL_ACCESS,
            &json,
            XattrFlags::empty()
        ))
        .unwrap_err(),
        Errno::E2BIG
    );

    // Subsequent writes and commits MUST succeed cleanly (overlay was NOT poisoned)!
    let (_, fd2) = run(fs.create(&admin, &fs.root(), "ok.txt", 0o644, &rw_create())).unwrap();
    run(fs.write_at(&fd2, b"healthy", WriteAt::Offset(0))).unwrap();
    run(fs.release(&fd2)).unwrap();
    run(fs.commit_tx_group()).unwrap();
    run(fs.close_clean()).unwrap();
}

// =============================================================================
// F1-22 (MEDIUM): Exact 1x GC grace window (not 2x)
// =============================================================================

#[test]
fn f1_22_gc_enforces_exact_1x_grace_window() {
    let dir = TempDir::new("gc-exact-1x");
    let clock = ManualClock::new(1_000);
    let hs = Rc::new(NativeSqliteHeadStore::open(&dir.0).unwrap());
    let ps = Rc::new(NativePackStore::open(&dir.0).unwrap());
    hs.set_grace_window_secs(600);
    let vol = VolumeId("vol-f1-22".into());
    let admin = Cred::root();
    run(CowFs::format_volume(
        &*hs,
        &*ps,
        vol.clone(),
        0,
        0,
        0o755,
        clock.now(),
    ))
    .unwrap();

    let fs = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol.clone(),
        CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
        CowFsConfig::local_native(clock.clock()),
    ))
    .unwrap();
    let (_, o) = run(fs.create(&admin, &fs.root(), "tmp.bin", 0o644, &rw_create())).unwrap();
    run(fs.write_at(&o, &vec![0x55u8; 64 * 1024], WriteAt::Offset(0))).unwrap();
    run(fs.release(&o)).unwrap();
    run(fs.commit_tx_group()).unwrap();
    run(fs.unlink(&admin, &fs.root(), "tmp.bin")).unwrap();
    run(fs.commit_tx_group()).unwrap();
    run(fs.close_clean()).unwrap();

    // At t = 1599 (599s < 600s grace): MUST keep pack.
    clock.advance(599);
    assert_eq!(
        run(collect_garbage(&*hs, &*ps, clock.now()))
            .unwrap()
            .swept_packs
            .len(),
        0
    );
    // At t = 1601 (601s > 600s grace, strictly < 2*600s): MUST sweep pack!
    clock.advance(2);
    assert_eq!(
        run(collect_garbage(&*hs, &*ps, clock.now()))
            .unwrap()
            .swept_packs
            .len(),
        1
    );
}

// =============================================================================
// F1-23 (MEDIUM): `write_at` strips S_ISUID/S_ISGID BEFORE backpressure commit
// =============================================================================

#[test]
fn f1_23_write_at_strips_setuid_before_backpressure_commit() {
    let clock = ManualClock::new(16_000);
    let hs = Rc::new(ControllableHeadStore::new());
    let ps = Rc::new(MemoryPackStore::new());
    let vol = VolumeId("vol-f1-23".into());
    let admin = Cred::root();
    let alice = Cred::new(Identity {
        id: 1000,
        group: 1000,
        groups: [1000].into_iter().collect(),
    });
    run(CowFs::format_volume(
        &*hs,
        &*ps,
        vol.clone(),
        0,
        0,
        0o755,
        clock.now(),
    ))
    .unwrap();
    let tight = ArenaConfig {
        tree_lru_bytes: 512 * 1024,
        clean_data_bytes: 512 * 1024,
        dirty_bytes: 256 * 1024,
    };
    let fs = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol,
        CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
        CowFsConfig::local_browser(clock.clock()).with_arena(tight),
    ))
    .unwrap();

    let (ent, root_fd) =
        run(fs.create(&admin, &fs.root(), "suid.bin", 0o777, &rw_create())).unwrap();
    run(fs.release(&root_fd)).unwrap();
    run(fs.setattr(
        &admin,
        &ent.handle,
        &SetAttr {
            mode: Some(0o6777),
            ..SetAttr::default()
        },
    ))
    .unwrap();
    run(fs.commit_tx_group()).unwrap();

    // Non-root opens and performs a single 512 KiB write that triggers a backpressure commit mid-write.
    // Hook inspects every committed `INODE_ITEM` for `ent.handle.node.ino` and verifies S_ISUID/S_ISGID
    // are ALREADY cleared at the intermediate commit!
    let target_ino = ent.handle.node.ino;
    let saw_intermediate_commit = Rc::new(Cell::new(false));
    let saw_clone = Rc::clone(&saw_intermediate_commit);
    *hs.commit_hook.borrow_mut() = Some(Box::new(move |req: &CommitRequest| {
        for (dig, raw) in &req.put_nodes {
            if let Ok(Node::Leaf { entries }) = Node::decode_verified(dig, raw) {
                for e in entries {
                    if e.key == TreeKey::inode_item(target_ino)
                        && let Ok(item) = os_cowfs::inode::InodeItem::decode(&e.value)
                    {
                        assert_eq!(
                            item.mode & 0o6000,
                            0,
                            "intermediate backpressure commit left S_ISUID/S_ISGID set: {:o}",
                            item.mode
                        );
                        saw_clone.set(true);
                    }
                }
            }
        }
    }));

    let alice_fd = run(fs.open(&alice, &ent.handle, &rw_open())).unwrap();
    let mut big = vec![0u8; 512 * 1024];
    for (i, chunk) in big.chunks_mut(64 * 1024).enumerate() {
        chunk.fill((i + 1) as u8);
    }
    run(fs.write_at(&alice_fd, &big, WriteAt::Offset(0))).unwrap();
    assert!(
        saw_intermediate_commit.get(),
        "512 KiB write under 256 KiB dirty limit must trigger intermediate backpressure commit"
    );
    run(fs.release(&alice_fd)).unwrap();
    run(fs.close_clean()).unwrap();
}

// =============================================================================
// F1-24 (MEDIUM): `allocated_bytes` persists across remount & decrements on shrink/unlink
// =============================================================================

#[test]
fn f1_24_allocated_bytes_persists_across_remount_and_decrements_on_truncate_unlink() {
    let clock = ManualClock::new(17_000);
    let hs = Rc::new(MemoryHeadStore::new());
    let ps = Rc::new(MemoryPackStore::new());
    let vol = VolumeId("vol-f1-24".into());
    let admin = Cred::root();
    let cap = 1024 * 1024u64; // 1 MiB = 16 blocks
    run(CowFs::format_volume(
        &*hs,
        &*ps,
        vol.clone(),
        0,
        0,
        0o755,
        clock.now(),
    ))
    .unwrap();

    let fs = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol.clone(),
        CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
        CowFsConfig::local_browser(clock.clock()).with_capacity(cap),
    ))
    .unwrap();
    assert_eq!(run(fs.statfs(&admin)).unwrap().blocks_free, 16);

    let (_, fd) = run(fs.create(&admin, &fs.root(), "a.bin", 0o644, &rw_create())).unwrap();
    run(fs.write_at(&fd, &vec![0x11u8; 256 * 1024], WriteAt::Offset(0))).unwrap();
    run(fs.release(&fd)).unwrap();
    assert_eq!(run(fs.statfs(&admin)).unwrap().blocks_free, 12);
    run(fs.close_clean()).unwrap();

    // Remount -> persisted `allocated_bytes` STILL shows 12 free blocks (not reset to 16)!
    let fs2 = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol,
        CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
        CowFsConfig::local_browser(clock.clock()).with_capacity(cap),
    ))
    .unwrap();
    assert_eq!(run(fs2.statfs(&admin)).unwrap().blocks_free, 12);
    let ent = run(fs2.lookup(&admin, &fs2.root(), "a.bin")).unwrap();
    let fd2 = run(fs2.open(&admin, &ent.handle, &rw_open())).unwrap();
    run(fs2.set_len(&fd2, 64 * 1024)).unwrap();
    assert_eq!(run(fs2.statfs(&admin)).unwrap().blocks_free, 15);
    run(fs2.release(&fd2)).unwrap();
    run(fs2.unlink(&admin, &fs2.root(), "a.bin")).unwrap();
    assert_eq!(run(fs2.statfs(&admin)).unwrap().blocks_free, 16);
    run(fs2.close_clean()).unwrap();
}

// =============================================================================
// F1-25 (MEDIUM): `setattr` failing `resize_file` does not dirty ACL or mode
// =============================================================================

#[test]
fn f1_25_setattr_failed_resize_does_not_dirty_acl_or_mode() {
    let dir = TempDir::new("setattr-atomic");
    let clock = ManualClock::new(18_000);
    let hs = Rc::new(NativeSqliteHeadStore::open(&dir.0).unwrap());
    let ps = Rc::new(NativePackStore::open(&dir.0).unwrap());
    let vol = VolumeId("vol-f1-25".into());
    let admin = Cred::root();
    run(CowFs::format_volume(
        &*hs,
        &*ps,
        vol.clone(),
        0,
        0,
        0o755,
        clock.now(),
    ))
    .unwrap();
    let fs = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol,
        CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
        CowFsConfig::local_native(clock.clock()),
    ))
    .unwrap();

    let (ent, fd) = run(fs.create(&admin, &fs.root(), "f.bin", 0o644, &rw_create())).unwrap();
    let blk = vec![0x99u8; 64 * 1024];
    run(fs.write_at(&fd, &blk, WriteAt::Offset(0))).unwrap();
    run(fs.release(&fd)).unwrap();
    run(fs.commit_tx_group()).unwrap();

    // Corrupt backing pack so `resize_file` to 100 bytes fails with `EIO` reading straddling block.
    let loc = run(hs.lookup_block(&sha256(&blk))).unwrap().unwrap();
    fs.drop_clean_caches();
    ps.corrupt_pack_byte(&loc.pack_id, 16).unwrap();

    assert_eq!(
        run(fs.setattr(
            &admin,
            &ent.handle,
            &SetAttr {
                mode: Some(0o600),
                size: Some(100),
                ..SetAttr::default()
            }
        ))
        .unwrap_err(),
        Errno::EIO
    );
    let meta = run(fs.metadata(&admin, &ent.handle)).unwrap();
    assert_eq!(
        meta.mode & 0o777,
        0o644,
        "mode must not change on failed setattr"
    );
    assert_eq!(
        meta.size,
        64 * 1024,
        "size must not change on failed setattr"
    );
    run(fs.close_clean()).unwrap();
}

// =============================================================================
// F1-26 & F1-27 (MEDIUM): `cowtree` invariants & `fsck` extent bounds
// =============================================================================

#[test]
fn f1_26_f1_27_cowtree_invariants_and_fsck_extent_bounds() {
    let hs = Rc::new(MemoryHeadStore::new());
    let ps = Rc::new(MemoryPackStore::new());
    let arena = RefCell::new(Arena::new(ArenaConfig::fixed_32mib()));
    let tree = CowTree::new(&*hs, &arena);

    // 1. `find_le_with_overlay` with `"aa"` and tombstoned `"b"` must return `"aa"` (no predecessor bug).
    let leaf = Node::Leaf {
        entries: vec![
            LeafEntry {
                key: TreeKey::dir_item(1, "aa"),
                value: b"val-aa".to_vec(),
            },
            LeafEntry {
                key: TreeKey::dir_item(1, "b"),
                value: b"val-b".to_vec(),
            },
        ],
    };
    let (leaf_dig, leaf_bytes) = leaf.encode().unwrap();
    let head = VolumeHead {
        format_version: cowtree::COWFS_FORMAT_VERSION,
        volume: VolumeId("vol-f1-26".into()),
        incarnation: 1,
        fence: 1,
        epoch: 0,
        root: leaf_dig,
        parent_volume: None,
        ephemeral_if_unmodified: false,
        modified: false,
        updated_at: Timespec { sec: 1, nsec: 0 },
    };
    run(hs.create_volume(&head, &[(leaf_dig, leaf_bytes)])).unwrap();

    let mut overlay = TreeOverlay::new();
    overlay.delete(TreeKey::dir_item(1, "b"));
    let found = run(tree.find_le_with_overlay(
        &leaf_dig,
        &overlay,
        &TreeKey::kind_start(1, cowtree::KIND_DIR_ITEM),
        &TreeKey::dir_item(1, "b"),
    ))
    .unwrap();
    assert_eq!(
        found.map(|(k, v)| (k.tail, v)),
        Some((b"aa".to_vec(), b"val-aa".to_vec()))
    );

    // 2. Oversized key tail (`> KEY_TAIL_MAX_BYTES`) rejected with `E2BIG` (never infinite loop).
    let huge_key = TreeKey::new(
        1,
        cowtree::KIND_XATTR_ITEM,
        vec![b'x'; KEY_TAIL_MAX_BYTES + 1],
    );
    assert_eq!(
        run(tree.apply_batch(&leaf_dig, &[(huge_key, Some(vec![1]))])).unwrap_err(),
        Errno::E2BIG
    );

    // 3. `encode_pack` rejects > 1 MiB block; `decode_pack_trailer` rejects flags != 0 & raw_len != len.
    let too_big = vec![0u8; EXTENT_MAX_BYTES as usize + 1];
    assert_eq!(
        encode_pack(&[(sha256(&too_big), too_big)]).unwrap_err(),
        Errno::EFBIG
    );
    let small = vec![0x12u8; 64];
    let mut bad_pack = encode_pack(&[(sha256(&small), small)]).unwrap().bytes;
    // Flip flags field inside trailer entry (last 2 bytes before the 40-byte footer) and recompute footer sha.
    let footer_start = bad_pack.len() - cowtree::pack::PACK_FOOTER_BYTES;
    let trailer_len =
        u32::from_be_bytes(bad_pack[footer_start..footer_start + 4].try_into().unwrap()) as usize;
    let trailer_start = footer_start - trailer_len;
    bad_pack[footer_start - 1] = 1; // flags = 1 != 0
    let new_sha = sha256(&bad_pack[trailer_start..footer_start]);
    bad_pack[footer_start + 4..footer_start + 36].copy_from_slice(&new_sha);
    assert_eq!(decode_pack_trailer(&bad_pack).unwrap_err(), Errno::EIO);

    // 4. `Arena::put_node` charges realistic heap bytes (>= encoded bytes).
    let stats_before = arena.borrow().stats();
    let sample = Node::Leaf {
        entries: (0..20u64)
            .map(|i| LeafEntry {
                key: TreeKey::inode_item(i),
                value: vec![0u8; 16],
            })
            .collect(),
    };
    let (sdig, sbytes) = sample.encode().unwrap();
    arena
        .borrow_mut()
        .put_node(sdig, sbytes.len(), Rc::new(sample));
    assert!(arena.borrow().stats().tree_lru_bytes > stats_before.tree_lru_bytes + sbytes.len());

    // 5. Multi-level B+tree heavy delete rebalancing preserves uniform leaf height & internal >= 2.
    let vol_rebal = VolumeId("vol-f1-26-rebal".into());
    let now = Timespec { sec: 100, nsec: 0 };
    run(CowFs::format_volume(
        &*hs,
        &*ps,
        vol_rebal.clone(),
        0,
        0,
        0o755,
        now,
    ))
    .unwrap();
    let fs = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol_rebal.clone(),
        CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
        CowFsConfig::local_browser(Rc::new(move || now)),
    ))
    .unwrap();
    let admin = Cred::root();
    for i in 0..800u32 {
        let (_, fd) = run(fs.create(
            &admin,
            &fs.root(),
            &format!("entry_{i:04}"),
            0o644,
            &rw_create(),
        ))
        .unwrap();
        run(fs.release(&fd)).unwrap();
    }
    run(fs.commit_tx_group()).unwrap();
    for i in 0..795u32 {
        run(fs.unlink(&admin, &fs.root(), &format!("entry_{i:04}"))).unwrap();
    }
    run(fs.commit_tx_group()).unwrap();
    run(fs.close_clean()).unwrap();
    let report = run(verify_volume(&*hs, &*ps, &vol_rebal)).unwrap();
    assert!(report.ok, "post-rebalance fsck errors: {:?}", report.errors);

    // 6. F1-27: `fsck` rejects out-of-bounds `block_offset + len > backing_block.len` extent!
    let vol_oob = VolumeId("vol-f1-27-oob".into());
    let payload = vec![0xAAu8; 64 * 1024];
    let dig = sha256(&payload);
    let built = encode_pack(&[(dig, payload)]).unwrap();
    let meta = run(ps.write_pack(&built.pack_id, &built.bytes)).unwrap();
    let bad_ext = ExtentDataValue::Extent {
        len: 128,
        digest: dig,
        block_offset: 64 * 1024 - 32, // 65504 + 128 > 65536!
    }
    .encode()
    .unwrap();
    let root_inode = os_cowfs::inode::InodeItem {
        file_type: abi::fs::FileType::Dir,
        mode: 0o755,
        nlink: 2,
        uid: 0,
        gid: 0,
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
    let bad_leaf = Node::Leaf {
        entries: vec![
            LeafEntry {
                key: TreeKey::inode_item(1),
                value: root_inode.encode(),
            },
            LeafEntry {
                key: TreeKey::new(2, KIND_EXTENT_DATA, 0u64.to_be_bytes().to_vec()),
                value: bad_ext,
            },
        ],
    };
    let (bl_dig, bl_bytes) = bad_leaf.encode().unwrap();
    let mut subvols = BTreeMap::new();
    subvols.insert("@".to_string(), bl_dig);
    let bad_root = RootObject {
        format_version: cowtree::COWFS_FORMAT_VERSION,
        features: 0,
        volume_uuid: vol_oob.0.clone(),
        subvols,
        next_ino: 3,
        generation: 1,
        parent_root: None,
        allocated_bytes: 0,
        inode_count: 1,
    };
    let (br_dig, br_bytes) = bad_root.encode().unwrap();
    let oob_head = VolumeHead {
        format_version: cowtree::COWFS_FORMAT_VERSION,
        volume: vol_oob.clone(),
        incarnation: 1,
        fence: 1,
        epoch: 0,
        root: br_dig,
        parent_volume: None,
        ephemeral_if_unmodified: false,
        modified: true,
        updated_at: now,
    };
    run(hs.create_volume(&oob_head, &[(bl_dig, bl_bytes), (br_dig, br_bytes)])).unwrap();
    // Register the backing pack & block index via a commit so `lookup_block` succeeds.
    let lease = run(hs.acquire_writer(&vol_oob, WriterMode::Exclusive)).unwrap();
    run(hs.commit_head(&CommitRequest {
        op_id: [9u8; 16],
        volume: vol_oob.clone(),
        expected_incarnation: lease.incarnation,
        expected_fence: lease.fence,
        expected_epoch: lease.epoch,
        new_root: br_dig,
        put_nodes: Vec::new(),
        put_packs: vec![meta],
        put_blocks: built.locations,
        committed_at: now,
    }))
    .unwrap();
    run(hs.release_writer(lease)).unwrap();

    let oob_report = run(verify_volume(&*hs, &*ps, &vol_oob)).unwrap();
    assert!(
        !oob_report.ok
            && oob_report
                .errors
                .iter()
                .any(|e| e.contains("exceeds backing block")),
        "fsck must reject out-of-bounds extent slice, got: {:?}",
        oob_report.errors
    );
    let _ = PackIndexEntry {
        digest: dig,
        offset: 0,
        len: 0,
        raw_len: 0,
        flags: 0,
    };
}

// =============================================================================
// F1-28 (MEDIUM): 5-second dirty commit deadline
// =============================================================================

#[test]
fn f1_28_five_second_dirty_commit_deadline() {
    let clock = ManualClock::new(20_000);
    let hs = Rc::new(MemoryHeadStore::new());
    let ps = Rc::new(MemoryPackStore::new());
    let vol = VolumeId("vol-f1-28".into());
    let admin = Cred::root();
    run(CowFs::format_volume(
        &*hs,
        &*ps,
        vol.clone(),
        0,
        0,
        0o755,
        clock.now(),
    ))
    .unwrap();
    let fs = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol.clone(),
        CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
        CowFsConfig::local_browser(clock.clock()),
    ))
    .unwrap();

    assert!(!fs.dirty_deadline_elapsed());
    assert_eq!(fs.ms_until_dirty_deadline(), None);

    let (_, fd) = run(fs.create(&admin, &fs.root(), "tiny.txt", 0o644, &rw_create())).unwrap();
    run(fs.write_at(&fd, b"hi", WriteAt::Offset(0))).unwrap();
    run(fs.release(&fd)).unwrap();

    // At +4s: deadline not yet elapsed; head still epoch 0.
    clock.advance(4);
    assert!(!fs.dirty_deadline_elapsed());
    assert_eq!(fs.ms_until_dirty_deadline(), Some(1_000));
    assert!(!run(fs.flush_if_dirty_deadline_elapsed()).unwrap());
    assert_eq!(run(hs.read_head(&vol)).unwrap().epoch, 0);

    // At +5s: deadline elapsed; `flush_if_dirty_deadline_elapsed()` commits automatically!
    clock.advance(1);
    assert!(fs.dirty_deadline_elapsed());
    assert_eq!(fs.ms_until_dirty_deadline(), Some(0));
    assert!(run(fs.flush_if_dirty_deadline_elapsed()).unwrap());
    assert_eq!(run(hs.read_head(&vol)).unwrap().epoch, 1);
    assert!(!fs.dirty_deadline_elapsed());
    assert_eq!(fs.ms_until_dirty_deadline(), None);

    run(fs.close_clean()).unwrap();
}

// =============================================================================
// Codex Audit #12: COWFS_IOC_FSCK exact-volume verification & rollback fork check
// =============================================================================

#[test]
fn codex_12_cowfs_ioc_fsck_verifies_exact_volume_and_rollback_fork() {
    use abi::contract::cowfs_ioctl;
    use abi::volume::{CowfsForkReq, CowfsForkResp, CowfsFsckReq, CowfsFsckResp};
    use os_cowfs::cowfs_ioctl_mounted;

    let clock = ManualClock::new(40_000);
    let hs = Rc::new(MemoryHeadStore::new());
    let ps = Rc::new(MemoryPackStore::new());
    let vol_a = VolumeId("vol-codex-12-a".into());
    let vol_b = VolumeId("vol-codex-12-b".into());
    let admin = Cred::root();
    let user = Cred::new(Identity::guest());

    run(CowFs::format_volume(
        &*hs,
        &*ps,
        vol_a.clone(),
        0,
        0,
        0o755,
        clock.now(),
    ))
    .unwrap();
    run(CowFs::format_volume(
        &*hs,
        &*ps,
        vol_b.clone(),
        0,
        0,
        0o755,
        clock.now(),
    ))
    .unwrap();

    // Populate `vol_a` with a clean snapshot `good`, then commit another file.
    let fs_a = Rc::new(
        run(CowFs::open(
            hs.clone(),
            ps.clone(),
            vol_a.clone(),
            CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
            CowFsConfig::local_browser(clock.clock()),
        ))
        .unwrap(),
    );
    let (_, fd_a) = run(fs_a.create(&admin, &fs_a.root(), "a.bin", 0o644, &rw_create())).unwrap();
    run(fs_a.write_at(&fd_a, &vec![0x11u8; 64 * 1024], WriteAt::Offset(0))).unwrap();
    run(fs_a.release(&fd_a)).unwrap();
    run(fs_a.commit_tx_group()).unwrap();
    let snap = run(fs_a.create_snapshot("good")).unwrap();
    assert_eq!(snap.name, "good");

    // Populate `vol_b` with its own distinct pack, then corrupt `vol_b`'s pack.
    let fs_b = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol_b.clone(),
        CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
        CowFsConfig::local_browser(clock.clock()),
    ))
    .unwrap();
    let (_, fd_b) = run(fs_b.create(&admin, &fs_b.root(), "b.bin", 0o644, &rw_create())).unwrap();
    run(fs_b.write_at(&fd_b, &vec![0x22u8; 64 * 1024], WriteAt::Offset(0))).unwrap();
    run(fs_b.release(&fd_b)).unwrap();
    run(fs_b.close_clean()).unwrap();

    let packs_before: std::collections::HashSet<_> =
        run(ps.list_packs()).unwrap().into_iter().collect();
    assert_eq!(packs_before.len(), 2);

    // Attach ONLY `vol_a` at `/dev/vd0`.
    let vblk = VblkRegistry::new();
    let dev_a = Rc::new(CowFsVolumeDevice::from_mounted(Rc::clone(&fs_a)));
    vblk.attach_named("vd0", dev_a).unwrap();

    // 1. Default `COWFS_IOC_FSCK` on `/dev/vd0` (permitted for non-root too) verifies `vol_a`!
    let raw_a = run(vblk.ioctl_rdev(&user, "vblk:vd0", cowfs_ioctl::COWFS_IOC_FSCK, b"")).unwrap();
    let resp_a: CowfsFsckResp = serde_json::from_slice(&raw_a).unwrap();
    assert!(resp_a.ok, "errors={:?}", resp_a.errors);
    assert_eq!(resp_a.volume, vol_a.0);
    assert!(resp_a.nodes_verified >= 2);
    assert!(resp_a.packs_verified >= 1);

    // 2. Requesting a missing `volume` UUID MUST return `ENOENT` (NEVER silently verify `vol_a`!).
    let missing_req = serde_json::to_vec(&CowfsFsckReq {
        volume: Some("vol-does-not-exist".into()),
    })
    .unwrap();
    assert_eq!(
        run(vblk.ioctl_rdev(
            &admin,
            "vblk:vd0",
            cowfs_ioctl::COWFS_IOC_FSCK,
            &missing_req
        )),
        Err(Errno::ENOENT)
    );
    assert_eq!(
        run(cowfs_ioctl_mounted(
            &fs_a,
            &admin,
            cowfs_ioctl::COWFS_IOC_FSCK,
            &missing_req
        )),
        Err(Errno::ENOENT)
    );

    // 3. Requesting `vol_b` explicitly via `/dev/vd0` verifies `vol_b` (not `vol_a`!).
    //    Corrupt `vol_b`'s pack and confirm `COWFS_IOC_FSCK { volume: Some(vol_b) }` reports
    //    `ok == false`, while `vol_a` remains `ok == true`!
    let b_block_dig = cowtree::sha256(&vec![0x22u8; 64 * 1024]);
    let b_pack = run(hs.lookup_block(&b_block_dig)).unwrap().unwrap().pack_id;
    ps.corrupt_pack_byte(&b_pack, 24);

    let req_b = serde_json::to_vec(&CowfsFsckReq {
        volume: Some(vol_b.0.clone()),
    })
    .unwrap();
    let raw_b =
        run(vblk.ioctl_rdev(&admin, "vblk:vd0", cowfs_ioctl::COWFS_IOC_FSCK, &req_b)).unwrap();
    let resp_b: CowfsFsckResp = serde_json::from_slice(&raw_b).unwrap();
    assert_eq!(resp_b.volume, vol_b.0);
    assert!(!resp_b.ok, "corrupt vol_b must report ok=false");
    assert!(
        resp_b
            .errors
            .iter()
            .any(|e| e.contains("digest mismatch") || e.contains("trailer")),
        "unexpected errors: {:?}",
        resp_b.errors
    );

    // Mounted dispatch `cowfs_ioctl_mounted` agrees identically.
    let raw_b_mounted = run(cowfs_ioctl_mounted(
        &fs_a,
        &admin,
        cowfs_ioctl::COWFS_IOC_FSCK,
        &req_b,
    ))
    .unwrap();
    let resp_b_mounted: CowfsFsckResp = serde_json::from_slice(&raw_b_mounted).unwrap();
    assert_eq!(resp_b_mounted, resp_b);

    // 4. Fork snapshot `good` via `COWFS_IOC_FORK` and verify the newly created rollback fork via
    //    `COWFS_IOC_FSCK { volume: Some(forked.volume) }`.
    let fork_req = serde_json::to_vec(&CowfsForkReq {
        snapshot: Some("good".into()),
        new_volume: "vol-codex-12-a-rollback-good".into(),
        ephemeral_if_unmodified: false,
    })
    .unwrap();
    let raw_fork =
        run(vblk.ioctl_rdev(&admin, "vblk:vd0", cowfs_ioctl::COWFS_IOC_FORK, &fork_req)).unwrap();
    let forked: CowfsForkResp = serde_json::from_slice(&raw_fork).unwrap();
    let rb_fsck_req = serde_json::to_vec(&CowfsFsckReq {
        volume: Some(forked.volume.clone()),
    })
    .unwrap();
    let raw_rb = run(vblk.ioctl_rdev(
        &admin,
        "vblk:vd0",
        cowfs_ioctl::COWFS_IOC_FSCK,
        &rb_fsck_req,
    ))
    .unwrap();
    let resp_rb: CowfsFsckResp = serde_json::from_slice(&raw_rb).unwrap();
    assert!(
        resp_rb.ok,
        "clean rollback fork must verify ok: {:?}",
        resp_rb.errors
    );
    assert_eq!(resp_rb.volume, forked.volume);

    // Corrupt `vol_a`'s pack (shared by snapshot `good` / rollback fork) -> rollback fork fsck
    // MUST fail with `ok == false`!
    let a_block_dig = cowtree::sha256(&vec![0x11u8; 64 * 1024]);
    let a_pack = run(hs.lookup_block(&a_block_dig)).unwrap().unwrap().pack_id;
    ps.corrupt_pack_byte(&a_pack, 24);
    let raw_rb_bad = run(vblk.ioctl_rdev(
        &admin,
        "vblk:vd0",
        cowfs_ioctl::COWFS_IOC_FSCK,
        &rb_fsck_req,
    ))
    .unwrap();
    let resp_rb_bad: CowfsFsckResp = serde_json::from_slice(&raw_rb_bad).unwrap();
    assert!(
        !resp_rb_bad.ok,
        "corrupt rollback fork must report ok=false"
    );
    assert!(!resp_rb_bad.errors.is_empty());

    // Invalid payload / unknown field -> EINVAL.
    assert_eq!(
        run(vblk.ioctl_rdev(
            &admin,
            "vblk:vd0",
            cowfs_ioctl::COWFS_IOC_FSCK,
            br#"{"unknown":true}"#
        )),
        Err(Errno::EINVAL)
    );

    run(fs_a.close_clean()).unwrap();
}

// =============================================================================
// Codex Audit #13: verify_head checks exact pinned head & open prunes corrupt fork
// =============================================================================

#[test]
fn codex_13_verify_head_checks_exact_head_and_corrupt_fork_open_does_not_leak() {
    let clock = ManualClock::new(45_000);
    let hs = Rc::new(MemoryHeadStore::new());
    let ps = Rc::new(MemoryPackStore::new());
    let vol = VolumeId("vol-codex-13".into());
    let admin = Cred::root();
    run(CowFs::format_volume(
        &*hs,
        &*ps,
        vol.clone(),
        0,
        0,
        0o755,
        clock.now(),
    ))
    .unwrap();

    let fs = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol.clone(),
        CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
        CowFsConfig::local_browser(clock.clock()),
    ))
    .unwrap();

    // Commit epoch 1 (clean).
    let (_, fd1) = run(fs.create(&admin, &fs.root(), "v1.bin", 0o644, &rw_create())).unwrap();
    run(fs.write_at(&fd1, &vec![0x31u8; 64 * 1024], WriteAt::Offset(0))).unwrap();
    run(fs.release(&fd1)).unwrap();
    let head_epoch1 = run(fs.commit_tx_group()).unwrap();
    assert_eq!(head_epoch1.epoch, 1);

    // Commit epoch 2 (different pack), then corrupt epoch 2's pack while epoch 1 stays intact.
    let (_, fd2) = run(fs.create(&admin, &fs.root(), "v2.bin", 0o644, &rw_create())).unwrap();
    run(fs.write_at(&fd2, &vec![0x32u8; 64 * 1024], WriteAt::Offset(0))).unwrap();
    run(fs.release(&fd2)).unwrap();
    let head_epoch2 = run(fs.commit_tx_group()).unwrap();
    assert_eq!(head_epoch2.epoch, 2);

    let v2_pack = run(hs.lookup_block(&cowtree::sha256(&vec![0x32u8; 64 * 1024])))
        .unwrap()
        .unwrap()
        .pack_id;
    ps.corrupt_pack_byte(&v2_pack, 12);

    // `verify_head` verifies the EXACT head passed in: epoch 1 is clean, epoch 2 is corrupt!
    let rep1 = run(os_cowfs::fsck::verify_head(&*hs, &*ps, &head_epoch1)).unwrap();
    assert!(rep1.ok, "epoch 1 head must verify clean: {:?}", rep1.errors);
    assert_eq!(rep1.epoch, 1);

    let rep2 = run(os_cowfs::fsck::verify_head(&*hs, &*ps, &head_epoch2)).unwrap();
    assert!(!rep2.ok, "epoch 2 head must detect corruption");
    assert_eq!(rep2.epoch, 2);

    // Corrupting the root object itself while `fs` holds the writer lease: a second opener using
    // `ForkOnBusy` MUST fail `CowFs::open` with `EIO` AND prune the unmodified ephemeral fork head!
    let roots_before = run(hs.list_all_roots()).unwrap().len();
    hs.corrupt_node_byte(&head_epoch2.root, 10);
    let fork_res = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol.clone(),
        CowFsOpenMode::ReadWrite(WriterMode::ForkOnBusy),
        CowFsConfig::local_browser(clock.clock()),
    ));
    assert_eq!(fork_res.err(), Some(Errno::EIO));
    let roots_after = run(hs.list_all_roots()).unwrap().len();
    assert_eq!(
        roots_after, roots_before,
        "failed ForkOnBusy open on corrupt root must prune the unmodified fork"
    );

    run(fs.close_clean()).unwrap();
}

// =============================================================================
// Codex Audit #16: CowFs::flush_for_suspend persists durably without closing
// =============================================================================

#[test]
fn codex_16_flush_for_suspend_persists_dirty_writes_and_keeps_mount_writable() {
    let clock = ManualClock::new(50_000);
    let hs = Rc::new(MemoryHeadStore::new());
    let ps = Rc::new(MemoryPackStore::new());
    let vol = VolumeId("vol-codex-16".into());
    let admin = Cred::root();
    run(CowFs::format_volume(
        &*hs,
        &*ps,
        vol.clone(),
        0,
        0,
        0o755,
        clock.now(),
    ))
    .unwrap();

    let fs = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol.clone(),
        CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
        CowFsConfig::local_browser(clock.clock()),
    ))
    .unwrap();

    // 1. Clean mount: `flush_for_suspend()` returns current head without advancing epoch.
    let h0 = run(fs.flush_for_suspend()).unwrap();
    assert_eq!(h0.epoch, 0);
    assert!(!fs.is_closed());

    // 2. Dirty write with an open handle held across suspend: `flush_for_suspend()` commits
    //    durably to epoch 1 WITHOUT closing `fs`, releasing the lease, or invalidating `fd`!
    let (_, fd) = run(fs.create(&admin, &fs.root(), "bfcache.txt", 0o644, &rw_create())).unwrap();
    run(fs.write_at(&fd, b"before-suspend-", WriteAt::Offset(0))).unwrap();
    assert_eq!(run(hs.read_head(&vol)).unwrap().epoch, 0);

    let h1 = run(fs.flush_for_suspend()).unwrap();
    assert_eq!(h1.epoch, 1);
    assert!(!fs.is_closed());
    assert_eq!(run(hs.read_head(&vol)).unwrap().epoch, 1);

    // An independent RO mount immediately sees the durably flushed data.
    let ro = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol.clone(),
        CowFsOpenMode::ReadOnly,
        CowFsConfig::local_browser(clock.clock()),
    ))
    .unwrap();
    let ent = run(ro.lookup(&admin, &ro.root(), "bfcache.txt")).unwrap();
    let mut ro_opts = OpenOptions::new();
    ro_opts.read(true);
    let rfd = run(ro.open(&admin, &ent.handle, &ro_opts)).unwrap();
    let mut buf = [0u8; 32];
    let n = run(ro.read_at(&rfd, &mut buf, 0)).unwrap();
    assert_eq!(&buf[..n], b"before-suspend-");
    run(ro.release(&rfd)).unwrap();
    run(ro.close_clean()).unwrap();

    // 3. After bfcache resume, subsequent writes on the SAME open `fd` and new files MUST succeed
    //    without `EBADF`!
    run(fs.write_at(&fd, b"after-resume", WriteAt::Offset(15))).unwrap();
    run(fs.release(&fd)).unwrap();
    let h2 = run(fs.flush_for_suspend()).unwrap();
    assert_eq!(h2.epoch, 2);

    // 4. Unmodified `ForkOnBusy` fork: `flush_for_suspend()` MUST NOT prune the fork and MUST NOT
    //    mark it modified, so bfcache restore continues seamlessly AND later clean close prunes it!
    let fork_fs = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol.clone(),
        CowFsOpenMode::ReadWrite(WriterMode::ForkOnBusy),
        CowFsConfig::local_browser(clock.clock()),
    ))
    .unwrap();
    let fork_vol = fork_fs.volume_id().clone();
    assert!(fork_fs.forked_from().is_some());
    let fh = run(fork_fs.flush_for_suspend()).unwrap();
    assert_eq!(fh.epoch, 0);
    assert!(!fork_fs.is_closed());
    assert!(
        run(hs.read_head(&fork_vol)).is_ok(),
        "flush_for_suspend must NOT prune unmodified ForkOnBusy fork"
    );
    assert!(
        !run(hs.read_head(&fork_vol)).unwrap().modified,
        "flush_for_suspend on clean fork must not flip modified=true"
    );
    // Subsequent clean close without modifications still prunes the unmodified fork!
    run(fork_fs.close_clean()).unwrap();
    assert_eq!(run(hs.read_head(&fork_vol)), Err(Errno::ENOENT));
    // And `flush_for_suspend()` on a closed mount returns `EBADF`.
    assert_eq!(run(fork_fs.flush_for_suspend()), Err(Errno::EBADF));

    run(fs.close_clean()).unwrap();
}

// =============================================================================
// Codex Audit #32 coordination: `@` + `@home` shared-lease RW subvolume views
// =============================================================================

#[test]
fn codex_32_multi_subvol_views_share_lease_dirty_hook_and_atomic_commit() {
    let clock = ManualClock::new(60_000);
    let hs = Rc::new(MemoryHeadStore::new());
    let ps = Rc::new(MemoryPackStore::new());
    let vol = VolumeId("vol-codex-32-home".into());
    let admin = Cred::root();
    run(CowFs::format_volume(
        &*hs,
        &*ps,
        vol.clone(),
        0,
        0,
        0o755,
        clock.now(),
    ))
    .unwrap();

    let dirty_fires = Rc::new(Cell::new(0u32));
    let dirty_cb = Rc::clone(&dirty_fires);
    let fs = Rc::new(
        run(CowFs::open(
            hs.clone(),
            ps.clone(),
            vol.clone(),
            CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
            CowFsConfig::local_browser(clock.clock())
                .with_on_dirty(Rc::new(move || dirty_cb.set(dirty_cb.get() + 1))),
        ))
        .unwrap(),
    );

    assert!(fs.has_subvol("@"));
    assert!(!fs.has_subvol("@home"));
    assert_eq!(fs.open_subvol_view("@home").err(), Some(Errno::ENOENT));
    assert_eq!(fs.open_subvol_view("").err(), Some(Errno::EINVAL));
    assert_eq!(fs.open_subvol_view("bad/name").err(), Some(Errno::EINVAL));

    // Create `@home` subvolume on the live RW mount (commits atomically).
    run(fs.create_subvol("@home", 0o755)).unwrap();
    assert!(fs.has_subvol("@home"));
    assert_eq!(run(fs.create_subvol("@home", 0o755)), Err(Errno::EEXIST));

    // Open `@home` subvolume view sharing the exact same writer lease (NO `EBUSY`!).
    let home_view = fs.open_subvol_view("@home").unwrap();
    assert_ne!(home_view.id(), fs.id());

    // Mount `@` at `/` and `@home` at `/home` inside one `Vfs` and write to BOTH concurrently!
    let factory = Rc::new(DefaultFilesystemFactory::new(Rc::new(|| (60_000, 0))));
    let root_backing = Rc::new(MountBacking::new(
        Rc::clone(&fs) as Rc<dyn Filesystem>,
        FsType::Cowfs,
    ));
    let vfs = run(Vfs::boot("subvol-test", root_backing, "cowfs", factory)).unwrap();
    run(vfs.mkdirat(1, StartAnchor::Root, "/home", 0o755)).unwrap();
    // Commit the `/home` mountpoint dir so dirty_fires starts clean before testing `@home` write.
    run(fs.commit_tx_group()).unwrap();
    let fires_before_home = dirty_fires.get();

    let sys_ns = vfs.system_namespace();
    let home_backing = Rc::new(MountBacking::new(home_view, FsType::Cowfs));
    run(vfs.mount_on_namespace(
        &sys_ns,
        &admin,
        home_backing,
        None,
        "cowfs:@home",
        "/home",
        MountFlags::default(),
        0,
        None,
    ))
    .unwrap();

    // Write into `/home/user.txt` (`@home` subvol) -> triggers `on_dirty` on shared `CowFs`!
    let fd_home = run(vfs.openat(
        1,
        StartAnchor::Root,
        "/home/user.txt",
        abi::O_CREAT | abi::O_WRONLY,
        0o644,
    ))
    .unwrap();
    run(vfs.write(1, fd_home, b"stored-in-at-home")).unwrap();
    run(vfs.close(1, fd_home)).unwrap();
    assert_eq!(
        dirty_fires.get(),
        fires_before_home + 1,
        "write on @home subvol view must trigger shared CowFs on_dirty hook"
    );

    // Also write into `/root-file.txt` (`@` subvol) in the same uncommitted transaction group.
    let fd_root = run(vfs.openat(
        1,
        StartAnchor::Root,
        "/root-file.txt",
        abi::O_CREAT | abi::O_WRONLY,
        0o644,
    ))
    .unwrap();
    run(vfs.write(1, fd_root, b"stored-in-at-root")).unwrap();
    run(vfs.close(1, fd_root)).unwrap();

    // Single `flush_for_suspend()` atomically commits BOTH `@` and `@home` in ONE epoch!
    let epoch_before = fs.current_head().epoch;
    let flushed = run(fs.flush_for_suspend()).unwrap();
    assert_eq!(flushed.epoch, epoch_before + 1);
    assert!(!fs.is_closed());

    // Confirm `@`'s underlying `/home` directory does NOT contain `user.txt` (it lives in `@home`).
    let root_home_ent = run(fs.lookup(&admin, &fs.root(), "home")).unwrap();
    assert_eq!(
        run(fs.lookup(&admin, &root_home_ent.handle, "user.txt")).err(),
        Some(Errno::ENOENT)
    );

    // Close cleanly, run `cowfsck` (must verify BOTH subvols cleanly!), and cold-reopen both!
    run(fs.close_clean()).unwrap();
    let report = run(verify_volume(&*hs, &*ps, &vol)).unwrap();
    assert!(report.ok, "multi-subvol fsck errors: {:?}", report.errors);
    assert_eq!(report.subvols_checked, 2);

    let reopened = Rc::new(
        run(CowFs::open(
            hs.clone(),
            ps.clone(),
            vol,
            CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
            CowFsConfig::local_browser(clock.clock()),
        ))
        .unwrap(),
    );
    assert!(reopened.has_subvol("@"));
    assert!(reopened.has_subvol("@home"));
    let home2 = reopened.open_subvol_view("@home").unwrap();
    let ent_u = run(home2.lookup(&admin, &home2.root(), "user.txt")).unwrap();
    let mut ro_opts = OpenOptions::new();
    ro_opts.read(true);
    let open_u = run(home2.open(&admin, &ent_u.handle, &ro_opts)).unwrap();
    let mut buf = [0u8; 32];
    let n = run(home2.read_at(&open_u, &mut buf, 0)).unwrap();
    assert_eq!(&buf[..n], b"stored-in-at-home");
    run(home2.release(&open_u)).unwrap();

    let ent_r = run(reopened.lookup(&admin, &reopened.root(), "root-file.txt")).unwrap();
    let open_r = run(reopened.open(&admin, &ent_r.handle, &ro_opts)).unwrap();
    let n2 = run(reopened.read_at(&open_r, &mut buf, 0)).unwrap();
    assert_eq!(&buf[..n2], b"stored-in-at-root");
    run(reopened.release(&open_r)).unwrap();
    run(reopened.close_clean()).unwrap();
}
