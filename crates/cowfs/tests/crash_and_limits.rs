//! Crash consistency, bounded `32 MiB` slab arena, writer fencing, O(1) snapshot/fork/`FICLONE`,
//! quota/corruption/version-mismatch refusals, and reachability GC gates (`#77`, Blueprint §3.2).

use abi::Errno;
use abi::fs::{OpenOptions, Timespec, WriteAt};
use cowtree::memory::{MemoryHeadStore, MemoryPackStore};
use cowtree::{
    ARENA_CLEAN_DATA_BYTES, ARENA_DIRTY_BYTES, ARENA_TREE_LRU_BYTES, ArenaConfig, BLOCK_SIZE,
    COWFS_FORMAT_VERSION, HeadStore, PackStore, VolumeId, WriterMode,
};
use os_cowfs::native_sqlite::{NativePackStore, NativeSqliteHeadStore};
use os_cowfs::{
    CowFs, CowFsClock, CowFsConfig, CowFsOpenMode, collect_garbage, verify_volume,
    verify_volume_strict,
};
use std::cell::Cell;
use std::collections::HashSet;
use std::future::Future;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use vfs::{Cred, Filesystem, now_or_never};

fn run<F: Future>(fut: F) -> F::Output {
    now_or_never(fut).expect("cowfs test future must resolve synchronously")
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
            std::env::temp_dir().join(format!("os-cowfs-limits-{tag}-{}-{id}", std::process::id()));
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

// -----------------------------------------------------------------------------
// 1. Crash between PackStore::write_pack and HeadStore::commit_head + GC orphan sweep
// -----------------------------------------------------------------------------

#[test]
fn crash_between_pack_write_and_head_commit_preserves_prior_epoch_and_gc_sweeps_orphan() {
    let dir = TempDir::new("crash-sqlite");
    let clock = ManualClock::new(1_000);
    let vol = VolumeId("vol-crash".into());

    let hs = Rc::new(NativeSqliteHeadStore::open(&dir.0).unwrap());
    let ps = Rc::new(NativePackStore::open(&dir.0).unwrap());
    hs.set_grace_window_secs(60);
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
    let admin = Cred::root();

    // Commit epoch 1 with committed file.
    let (_, o1) = run(fs.create(&admin, &fs.root(), "good.bin", 0o644, &rw_create())).unwrap();
    let good_data = vec![0x11u8; 128 * 1024];
    run(fs.write_at(&o1, &good_data, WriteAt::Offset(0))).unwrap();
    run(fs.release(&o1)).unwrap();
    let head1 = run(fs.commit_tx_group()).unwrap();
    assert_eq!(head1.epoch, 1);
    let packs_after_e1 = run(ps.list_packs()).unwrap();
    assert_eq!(packs_after_e1.len(), 1);

    // Stage epoch 2 data and inject a crash right AFTER PackStore::write_pack, BEFORE commit_head.
    let (_, o2) =
        run(fs.create(&admin, &fs.root(), "uncommitted.bin", 0o644, &rw_create())).unwrap();
    run(fs.write_at(&o2, &vec![0x99u8; 128 * 1024], WriteAt::Offset(0))).unwrap();
    run(fs.release(&o2)).unwrap();
    hs.fail_next_commit(Errno::EIO);
    assert_eq!(run(fs.commit_tx_group()).unwrap_err(), Errno::EIO);

    // Pack was flushed to disk, so an orphan pack exists on disk while head stayed at epoch 1!
    let packs_after_crash = run(ps.list_packs()).unwrap();
    assert_eq!(packs_after_crash.len(), 2);
    drop(fs); // simulate process death

    // Reopen RW -> lands cleanly at epoch 1, zero corruption, uncommitted file absent!
    let hs2 = Rc::new(NativeSqliteHeadStore::open(&dir.0).unwrap());
    let ps2 = Rc::new(NativePackStore::open(&dir.0).unwrap());
    let reopened = run(CowFs::open(
        hs2.clone(),
        ps2.clone(),
        vol.clone(),
        CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
        CowFsConfig::local_native(clock.clock()),
    ))
    .unwrap();
    assert_eq!(reopened.current_head().epoch, 1);
    assert_eq!(reopened.current_head().root, head1.root);
    assert_eq!(
        run(reopened.lookup(&admin, &reopened.root(), "uncommitted.bin")).unwrap_err(),
        Errno::ENOENT
    );
    let ge = run(reopened.lookup(&admin, &reopened.root(), "good.bin")).unwrap();
    let go = run(reopened.open(&admin, &ge.handle, &ro_open())).unwrap();
    let mut got = vec![0u8; good_data.len()];
    assert_eq!(
        run(reopened.read_at(&go, &mut got, 0)).unwrap(),
        good_data.len()
    );
    assert_eq!(got, good_data);
    run(reopened.release(&go)).unwrap();
    run(reopened.close_clean()).unwrap();

    // cowfsck reports 0 errors!
    let fsck1 = run(verify_volume(&*hs2, &*ps2, &vol)).unwrap();
    assert!(fsck1.ok, "fsck errors: {:?}", fsck1.errors);

    // Reachability GC sweeps the orphan pack cleanly!
    clock.advance(120);
    let gc = run(collect_garbage(&*hs2, &*ps2, clock.now())).unwrap();
    assert_eq!(gc.swept_packs.len(), 1);
    assert_eq!(run(ps2.list_packs()).unwrap().len(), 1);
    let fsck2 = run(verify_volume(&*hs2, &*ps2, &vol)).unwrap();
    assert!(fsck2.ok, "post-GC fsck errors: {:?}", fsck2.errors);
}

// -----------------------------------------------------------------------------
// 2. O(1) Snapshot, Fork, and FICLONE on 10 MiB file (0 pack bytes copied; 64 KiB CoW mutation)
// -----------------------------------------------------------------------------

#[test]
fn o1_snapshot_fork_and_ficlone_copy_zero_bytes_and_cow_only_64kib_on_mutation() {
    let dir = TempDir::new("o1-ficlone");
    let clock = ManualClock::new(2_000);
    let vol = VolumeId("vol-10m".into());
    let hs = Rc::new(NativeSqliteHeadStore::open(&dir.0).unwrap());
    let ps = Rc::new(NativePackStore::open(&dir.0).unwrap());
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
        CowFsConfig::local_native(clock.clock()).with_arena(ArenaConfig::fixed_32mib()),
    ))
    .unwrap();
    let admin = Cred::root();

    // Write a 10 MiB file with distinct per-block pattern and commit.
    const TEN_MIB: usize = 10 * 1024 * 1024;
    let (_, o_src) = run(fs.create(&admin, &fs.root(), "big.bin", 0o644, &rw_create())).unwrap();
    let mut pattern = vec![0u8; TEN_MIB];
    for (i, chunk) in pattern.chunks_mut(64 * 1024).enumerate() {
        chunk.fill((i % 251) as u8);
        chunk[0..4].copy_from_slice(&(i as u32).to_le_bytes());
    }
    run(fs.write_at(&o_src, &pattern, WriteAt::Offset(0))).unwrap();
    run(fs.commit_tx_group()).unwrap();

    // Reset PackStore write counters: snapshot + fork + FICLONE MUST copy 0 pack bytes!
    ps.reset_counters();
    let snap = run(fs.create_snapshot("v1")).unwrap();
    let fork_head =
        run(fs.fork_volume(Some(&snap.name), VolumeId("vol-10m-fork".into()), false)).unwrap();
    assert_eq!(fork_head.root, snap.root);

    let (_, o_clone) =
        run(fs.create(&admin, &fs.root(), "clone.bin", 0o644, &rw_create())).unwrap();
    run(fs.reflink(&admin, &o_src, &o_clone)).unwrap();
    run(fs.commit_tx_group()).unwrap();
    assert_eq!(
        ps.bytes_written(),
        0,
        "snapshot+fork+FICLONE must write 0 data pack bytes"
    );
    assert_eq!(ps.pack_writes(), 0);

    // Mutate 4 bytes inside `clone.bin` at offset 0 -> CoW only ONE 64 KiB block!
    run(fs.write_at(&o_clone, b"MUTE", WriteAt::Offset(0))).unwrap();
    run(fs.commit_tx_group()).unwrap();
    assert!(
        ps.bytes_written() > 0 && ps.bytes_written() <= 128 * 1024,
        "CoW mutation should write ~64 KiB, got {}",
        ps.bytes_written()
    );

    // Original file is completely unchanged; clone sees mutation at offset 0 and original elsewhere.
    let mut head_orig = [0u8; 4];
    let mut head_clone = [0u8; 4];
    let mut tail_clone = [0u8; 4];
    run(fs.read_at(&o_src, &mut head_orig, 0)).unwrap();
    run(fs.read_at(&o_clone, &mut head_clone, 0)).unwrap();
    run(fs.read_at(&o_clone, &mut tail_clone, (TEN_MIB - 64 * 1024) as u64)).unwrap();
    assert_eq!(head_orig, 0u32.to_le_bytes());
    assert_eq!(&head_clone, b"MUTE");
    assert_eq!(tail_clone, 159u32.to_le_bytes());
    run(fs.release(&o_src)).unwrap();
    run(fs.release(&o_clone)).unwrap();

    // Open forked volume, mutate offset 1 MiB, verify snapshot `v1` is unchanged!
    let fork_fs = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        VolumeId("vol-10m-fork".into()),
        CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
        CowFsConfig::local_native(clock.clock()),
    ))
    .unwrap();
    let fe = run(fork_fs.lookup(&admin, &fork_fs.root(), "big.bin")).unwrap();
    let fo = run(fork_fs.open(&admin, &fe.handle, &rw_open())).unwrap();
    ps.reset_counters();
    run(fork_fs.write_at(&fo, b"FORK", WriteAt::Offset(1024 * 1024))).unwrap();
    run(fork_fs.commit_tx_group()).unwrap();
    assert!(ps.bytes_written() <= 128 * 1024);

    // Cross-volume FICLONE between `fs` and `fork_fs` MUST fail with EXDEV!
    let (_, fs_dst) = run(fs.create(&admin, &fs.root(), "xdev.bin", 0o644, &rw_create())).unwrap();
    assert_eq!(run(fs.reflink(&admin, &fo, &fs_dst)), Err(Errno::EXDEV));
    run(fs.release(&fs_dst)).unwrap();
    run(fork_fs.release(&fo)).unwrap();

    // Snapshot view remains byte-for-byte identical to original!
    let snap_fs = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol.clone(),
        CowFsOpenMode::Snapshot("v1".into()),
        CowFsConfig::local_native(clock.clock()),
    ))
    .unwrap();
    let se = run(snap_fs.lookup(&admin, &snap_fs.root(), "big.bin")).unwrap();
    let so = run(snap_fs.open(&admin, &se.handle, &ro_open())).unwrap();
    let mut snap_check = [0u8; 4];
    run(snap_fs.read_at(&so, &mut snap_check, 1024 * 1024)).unwrap();
    assert_eq!(snap_check, 16u32.to_le_bytes());
    run(snap_fs.release(&so)).unwrap();

    run(fork_fs.close_clean()).unwrap();
    run(fs.close_clean()).unwrap();
}

// -----------------------------------------------------------------------------
// 3. Writer Exclusion, ForkOnBusy (unmodified prune vs modified keep), ForceTakeover, & RO reads
// -----------------------------------------------------------------------------

#[test]
fn writer_exclusion_fork_on_busy_force_takeover_and_concurrent_ro_reads() {
    let dir = TempDir::new("fencing-sqlite");
    let clock = ManualClock::new(3_000);
    let vol = VolumeId("vol-fence".into());
    let hs = Rc::new(NativeSqliteHeadStore::open(&dir.0).unwrap());
    let ps = Rc::new(NativePackStore::open(&dir.0).unwrap());
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
        CowFsConfig::local_native(clock.clock()),
    ))
    .unwrap();
    let admin = Cred::root();
    let (_, o) = run(w1.create(&admin, &w1.root(), "seed.txt", 0o644, &rw_create())).unwrap();
    run(w1.write_at(&o, b"v1", WriteAt::Offset(0))).unwrap();
    run(w1.release(&o)).unwrap();
    run(w1.commit_tx_group()).unwrap();

    // (a) Second writer with WriterMode::Exclusive -> EBUSY!
    let err = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol.clone(),
        CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
        CowFsConfig::local_native(clock.clock()),
    ))
    .err()
    .unwrap();
    assert_eq!(err, Errno::EBUSY);

    // (b1) Second writer with ForkOnBusy (unmodified) -> boots O(1) fork, auto-pruned on close!
    let fork_unmod = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol.clone(),
        CowFsOpenMode::ReadWrite(WriterMode::ForkOnBusy),
        CowFsConfig::local_native(clock.clock()),
    ))
    .unwrap();
    assert_eq!(fork_unmod.forked_from(), Some(vol.clone()));
    let unmod_id = fork_unmod.volume_id().clone();
    assert!(run(hs.read_head(&unmod_id)).is_ok());
    run(fork_unmod.close_clean()).unwrap();
    assert_eq!(run(hs.read_head(&unmod_id)), Err(Errno::ENOENT));

    // (b2) Second writer with ForkOnBusy (modified) -> preserved on clean shutdown!
    let fork_mod = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol.clone(),
        CowFsOpenMode::ReadWrite(WriterMode::ForkOnBusy),
        CowFsConfig::local_native(clock.clock()),
    ))
    .unwrap();
    let mod_id = fork_mod.volume_id().clone();
    let (_, fo) =
        run(fork_mod.create(&admin, &fork_mod.root(), "forked.txt", 0o644, &rw_create())).unwrap();
    run(fork_mod.write_at(&fo, b"kept", WriteAt::Offset(0))).unwrap();
    run(fork_mod.release(&fo)).unwrap();
    run(fork_mod.close_clean()).unwrap();
    assert!(run(hs.read_head(&mod_id)).unwrap().modified);

    // (d) Concurrent RO mount reads lock-free while RW writer commits new packs!
    let ro = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol.clone(),
        CowFsOpenMode::ReadOnly,
        CowFsConfig::local_native(clock.clock()),
    ))
    .unwrap();
    let (_, w_new) = run(w1.create(&admin, &w1.root(), "v2.bin", 0o644, &rw_create())).unwrap();
    run(w1.write_at(&w_new, &vec![0x42; 64 * 1024], WriteAt::Offset(0))).unwrap();
    run(w1.release(&w_new)).unwrap();
    run(w1.commit_tx_group()).unwrap();
    // Pinned RO still sees epoch 1 cleanly without contention!
    assert_eq!(
        run(ro.lookup(&admin, &ro.root(), "v2.bin")).unwrap_err(),
        Errno::ENOENT
    );
    let se = run(ro.lookup(&admin, &ro.root(), "seed.txt")).unwrap();
    let so = run(ro.open(&admin, &se.handle, &ro_open())).unwrap();
    let mut sb = [0u8; 2];
    run(ro.read_at(&so, &mut sb, 0)).unwrap();
    assert_eq!(&sb, b"v1");
    run(ro.release(&so)).unwrap();
    // `-o remount,refresh` advances RO to epoch 2!
    run(ro.refresh_ro()).unwrap();
    assert!(run(ro.lookup(&admin, &ro.root(), "v2.bin")).is_ok());

    // (c) ForceTakeover bumps fence -> w1's next commit fails with ESTALE, w2 head intact!
    let w2 = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol.clone(),
        CowFsOpenMode::ReadWrite(WriterMode::ForceTakeover),
        CowFsConfig::local_native(clock.clock()),
    ))
    .unwrap();
    assert!(w2.current_head().fence > w1.current_head().fence);

    let (_, stale_o) =
        run(w1.create(&admin, &w1.root(), "stale.txt", 0o644, &rw_create())).unwrap();
    run(w1.write_at(&stale_o, b"stale", WriteAt::Offset(0))).unwrap();
    run(w1.release(&stale_o)).unwrap();
    assert_eq!(run(w1.commit_tx_group()).unwrap_err(), Errno::ESTALE);

    // w2 commits cleanly and head stays intact!
    let (_, w2_o) = run(w2.create(&admin, &w2.root(), "winner.txt", 0o644, &rw_create())).unwrap();
    run(w2.write_at(&w2_o, b"winner", WriteAt::Offset(0))).unwrap();
    run(w2.release(&w2_o)).unwrap();
    run(w2.commit_tx_group()).unwrap();
    assert!(run(hs.read_head(&vol)).unwrap().epoch >= 3);
    run(w2.close_clean()).unwrap();
}

// -----------------------------------------------------------------------------
// 4. Quota (ENOSPC), Bit-Flip Corruption (EIO), and Format Version Mismatch (EPROTONOSUPPORT)
// -----------------------------------------------------------------------------

#[test]
fn quota_enospc_bitflip_eio_and_format_version_mismatch_never_wipes_volume() {
    let dir = TempDir::new("refusals-sqlite");
    let clock = ManualClock::new(4_000);
    let vol = VolumeId("vol-refuse".into());
    let hs = Rc::new(NativeSqliteHeadStore::open(&dir.0).unwrap());
    let ps = Rc::new(NativePackStore::open(&dir.0).unwrap());
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
    let admin = Cred::root();
    let (_, o1) = run(fs.create(&admin, &fs.root(), "precious.bin", 0o644, &rw_create())).unwrap();
    let precious = vec![0x77u8; 64 * 1024];
    run(fs.write_at(&o1, &precious, WriteAt::Offset(0))).unwrap();
    run(fs.release(&o1)).unwrap();
    let committed_head = run(fs.commit_tx_group()).unwrap();

    // (a1) Quota exhaustion during pack write -> ENOSPC; prior head intact!
    let (_, o2) = run(fs.create(&admin, &fs.root(), "too_big.bin", 0o644, &rw_create())).unwrap();
    run(fs.write_at(&o2, &vec![0x88u8; 128 * 1024], WriteAt::Offset(0))).unwrap();
    run(fs.release(&o2)).unwrap();
    ps.fail_next_write(Errno::ENOSPC);
    assert_eq!(run(fs.commit_tx_group()).unwrap_err(), Errno::ENOSPC);
    assert_eq!(run(hs.read_head(&vol)).unwrap(), committed_head);

    // (a2) Quota exhaustion during head commit -> ENOSPC; prior head intact!
    hs.fail_next_commit(Errno::ENOSPC);
    assert_eq!(run(fs.commit_tx_group()).unwrap_err(), Errno::ENOSPC);
    assert_eq!(run(hs.read_head(&vol)).unwrap(), committed_head);
    drop(fs);

    // (c) Format version mismatch (both > 1 and < 1) -> EPROTONOSUPPORT WITHOUT wiping volume!
    for bad_ver in [COWFS_FORMAT_VERSION + 1, 0] {
        hs.set_stored_format_version(bad_ver).unwrap();
        assert_eq!(
            run(CowFs::open(
                hs.clone(),
                ps.clone(),
                vol.clone(),
                CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
                CowFsConfig::local_native(clock.clock()),
            ))
            .err(),
            Some(Errno::EPROTONOSUPPORT)
        );
        assert_eq!(
            run(verify_volume(&*hs, &*ps, &vol)),
            Err(Errno::EPROTONOSUPPORT)
        );
    }
    // Restore version -> precious data is 100% intact (never silently reset!).
    hs.set_stored_format_version(COWFS_FORMAT_VERSION).unwrap();
    assert!(run(verify_volume(&*hs, &*ps, &vol)).unwrap().ok);

    // (b1) Bit-flip 1 byte inside `precious.bin`'s pack file -> read fails closed with EIO BEFORE exposing bytes!
    let precious_loc = run(hs.lookup_block(&cowtree::sha256(&precious)))
        .unwrap()
        .expect("precious.bin block indexed");
    ps.corrupt_pack_byte(&precious_loc.pack_id, 12).unwrap();
    let ro = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol.clone(),
        CowFsOpenMode::ReadOnly,
        CowFsConfig::local_native(clock.clock()),
    ))
    .unwrap();
    let pe = run(ro.lookup(&admin, &ro.root(), "precious.bin")).unwrap();
    let po = run(ro.open(&admin, &pe.handle, &ro_open())).unwrap();
    let mut read_buf = vec![0u8; 64];
    assert_eq!(run(ro.read_at(&po, &mut read_buf, 0)), Err(Errno::EIO));
    assert_eq!(
        read_buf,
        vec![0u8; 64],
        "corrupt bytes must NEVER be exposed"
    );
    run(ro.release(&po)).unwrap();
    assert_eq!(run(verify_volume_strict(&*hs, &*ps, &vol)), Err(Errno::EIO));

    // Un-flip pack byte, now flip 1 byte in the root B+tree node -> open fails closed with EIO!
    ps.corrupt_pack_byte(&precious_loc.pack_id, 12).unwrap();
    assert!(run(verify_volume(&*hs, &*ps, &vol)).unwrap().ok);
    assert!(hs.corrupt_node_byte(&committed_head.root, 20).unwrap());
    assert_eq!(
        run(CowFs::open(
            hs.clone(),
            ps.clone(),
            vol.clone(),
            CowFsOpenMode::ReadOnly,
            CowFsConfig::local_native(clock.clock()),
        ))
        .err(),
        Some(Errno::EIO)
    );
}

// -----------------------------------------------------------------------------
// 5. Bounded 32 MiB Arena: 8 GiB sparse cold read, 100k dir read_dir_page, >8 MiB sustained write
// -----------------------------------------------------------------------------

#[test]
fn bounded_32mib_arena_8gib_sparse_cold_read_100k_dir_paging_and_dirty_backpressure() {
    let clock = ManualClock::new(5_000);
    let hs = Rc::new(MemoryHeadStore::new());
    let ps = Rc::new(MemoryPackStore::new());
    let vol = VolumeId("vol-arena".into());
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
        CowFsConfig::local_browser(clock.clock()).with_arena(ArenaConfig::fixed_32mib()),
    ))
    .unwrap();
    let admin = Cred::root();

    // (a) 8 GiB sparse file cold random 4 KiB read near end!
    const EIGHT_GIB: u64 = 8 * 1024 * 1024 * 1024;
    let (sp_e, sp_o) =
        run(fs.create(&admin, &fs.root(), "8gib.sparse", 0o644, &rw_create())).unwrap();
    run(fs.set_len(&sp_o, EIGHT_GIB)).unwrap();
    let needle_off = EIGHT_GIB - 4096;
    let mut needle = vec![0u8; 4096];
    for (i, b) in needle.iter_mut().enumerate() {
        *b = ((i * 31 + 7) & 0xff) as u8;
    }
    run(fs.write_at(&sp_o, &needle, WriteAt::Offset(needle_off))).unwrap();
    run(fs.release(&sp_o)).unwrap();
    run(fs.commit_tx_group()).unwrap();

    // Cold read after dropping all clean caches.
    fs.drop_clean_caches();
    ps.reset_counters();
    let sp_ro = run(fs.open(&admin, &sp_e.handle, &ro_open())).unwrap();
    let mut got = vec![0u8; 4096];
    assert_eq!(run(fs.read_at(&sp_ro, &mut got, needle_off)).unwrap(), 4096);
    assert_eq!(got, needle);
    // Cold read of 4 KiB near 8 GiB touches ONLY one 64 KiB block!
    assert_eq!(ps.bytes_read(), u64::from(BLOCK_SIZE));
    // Sparse hole read at 4 GiB touches zero pack bytes!
    let mut hole = vec![0xFFu8; 4096];
    assert_eq!(
        run(fs.read_at(&sp_ro, &mut hole, 4 * 1024 * 1024 * 1024)).unwrap(),
        4096
    );
    assert!(hole.iter().all(|&b| b == 0));
    assert_eq!(ps.bytes_read(), u64::from(BLOCK_SIZE));
    run(fs.release(&sp_ro)).unwrap();

    // (c) Sustained writes exceeding 8 MiB dirty slab budget without manual sync -> backpressure!
    // Stamp every 64 KiB block with a unique index so intra-store dedupe cannot shrink it below 12 MiB.
    let (stream_e, stream_o) =
        run(fs.create(&admin, &fs.root(), "stream12m.bin", 0o644, &rw_create())).unwrap();
    let chunk_len = 256 * 1024usize;
    for i in 0..48u64 {
        let mut c = vec![0x3Cu8; chunk_len];
        for b in 0..4u64 {
            let off = (b as usize) * (BLOCK_SIZE as usize);
            c[off..off + 8].copy_from_slice(&i.to_le_bytes());
            c[off + 8..off + 16].copy_from_slice(&b.to_le_bytes());
        }
        run(fs.write_at(&stream_o, &c, WriteAt::Offset(i * chunk_len as u64))).unwrap();
    }
    run(fs.release(&stream_o)).unwrap();
    run(fs.commit_tx_group()).unwrap();

    let st_after_stream = fs.arena_stats();
    assert!(
        st_after_stream.backpressure_flushes > 0,
        "12 MiB write under 8 MiB dirty cap must trigger backpressure flushes"
    );
    assert!(st_after_stream.peak_dirty_bytes <= ARENA_DIRTY_BYTES);
    assert!(st_after_stream.peak_clean_data_bytes <= ARENA_CLEAN_DATA_BYTES);
    assert!(st_after_stream.peak_tree_lru_bytes <= ARENA_TREE_LRU_BYTES);
    assert!(st_after_stream.peak_total_bytes <= ArenaConfig::fixed_32mib().total_limit());

    // Spot-check streamed data after cold cache drop.
    fs.drop_clean_caches();
    let sr = run(fs.open(&admin, &stream_e.handle, &ro_open())).unwrap();
    for i in [0u64, 23, 47] {
        let mut hdr = [0u8; 8];
        run(fs.read_at(&sr, &mut hdr, i * chunk_len as u64)).unwrap();
        assert_eq!(hdr, i.to_le_bytes());
    }
    run(fs.release(&sr)).unwrap();

    // (b) 100,000-entry directory enumerated via `read_dir_page` within 32 MiB arena!
    let big_dir = run(fs.mkdir(&admin, &fs.root(), "dir100k", 0o755))
        .unwrap()
        .handle;
    const COUNT: usize = 100_000;
    let opts = {
        let mut o = OpenOptions::new();
        o.write(true).create_new(true);
        o
    };
    for i in 0..COUNT {
        let (_, open) =
            run(fs.create(&admin, &big_dir, &format!("f{i:06}"), 0o644, &opts)).unwrap();
        run(fs.release(&open)).unwrap();
    }
    run(fs.commit_tx_group()).unwrap();
    fs.drop_clean_caches();

    let mut seen = HashSet::with_capacity(COUNT);
    let mut cookie = 0u64;
    let mut pages = 0usize;
    loop {
        let page = run(fs.read_dir_page(&admin, &big_dir, cookie, 512)).unwrap();
        pages += 1;
        for entry in page.entries {
            assert!(seen.insert(entry.name), "duplicate entry in read_dir_page");
        }
        match page.next_cookie {
            Some(next) => {
                assert!(next > cookie, "dir_index cookie must advance monotonically");
                cookie = next;
            }
            None => break,
        }
    }
    assert_eq!(seen.len(), COUNT);
    assert!(pages >= COUNT / 512);

    let final_stats = fs.arena_stats();
    assert!(
        final_stats.peak_tree_lru_bytes <= ARENA_TREE_LRU_BYTES,
        "tree LRU {} > 8 MiB",
        final_stats.peak_tree_lru_bytes
    );
    assert!(
        final_stats.peak_clean_data_bytes <= ARENA_CLEAN_DATA_BYTES,
        "clean data {} > 16 MiB",
        final_stats.peak_clean_data_bytes
    );
    assert!(
        final_stats.peak_dirty_bytes <= ARENA_DIRTY_BYTES,
        "dirty {} > 8 MiB",
        final_stats.peak_dirty_bytes
    );
    assert!(
        final_stats.peak_total_bytes <= ArenaConfig::fixed_32mib().total_limit(),
        "total {} > 32 MiB",
        final_stats.peak_total_bytes
    );
    run(fs.close_clean()).unwrap();
}

// -----------------------------------------------------------------------------
// 6. Reachability GC: shared/exclusive lock, grace window, and snapshot pinning
// -----------------------------------------------------------------------------

#[test]
fn reachability_gc_honors_locks_grace_window_and_snapshot_pins() {
    let dir = TempDir::new("gc-sqlite");
    let clock = ManualClock::new(10_000);
    let vol = VolumeId("vol-gc".into());
    let hs = Rc::new(NativeSqliteHeadStore::open(&dir.0).unwrap());
    let ps = Rc::new(NativePackStore::open(&dir.0).unwrap());
    hs.set_grace_window_secs(600);
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
    let admin = Cred::root();

    // Epoch 1: write `pinned.bin` and snapshot `keep` (pins pack 1).
    let (_, o1) = run(fs.create(&admin, &fs.root(), "pinned.bin", 0o644, &rw_create())).unwrap();
    run(fs.write_at(&o1, &vec![0xAAu8; 64 * 1024], WriteAt::Offset(0))).unwrap();
    run(fs.release(&o1)).unwrap();
    run(fs.create_snapshot("keep")).unwrap();

    // Epoch 2: write `ephemeral.bin` (pack 2) without snapshot.
    clock.advance(10);
    let (_, o2) = run(fs.create(&admin, &fs.root(), "ephemeral.bin", 0o644, &rw_create())).unwrap();
    run(fs.write_at(&o2, &vec![0xBBu8; 64 * 1024], WriteAt::Offset(0))).unwrap();
    run(fs.release(&o2)).unwrap();
    run(fs.commit_tx_group()).unwrap();

    // Epoch 3: unlink BOTH files and commit -> pack 1 pinned by snapshot `keep`, pack 2 only in grace window!
    clock.advance(10);
    run(fs.unlink(&admin, &fs.root(), "pinned.bin")).unwrap();
    run(fs.unlink(&admin, &fs.root(), "ephemeral.bin")).unwrap();
    run(fs.commit_tx_group()).unwrap();
    assert_eq!(run(ps.list_packs()).unwrap().len(), 2);

    // While a shared commit GC lock is held, exclusive GC sweep MUST refuse with EBUSY!
    let shared_lock = run(hs.acquire_gc_lock(false)).unwrap();
    assert_eq!(
        run(collect_garbage(&*hs, &*ps, clock.now())),
        Err(Errno::EBUSY)
    );
    drop(shared_lock);

    // Within 600s grace window: GC keeps BOTH packs!
    clock.advance(100);
    let gc_early = run(collect_garbage(&*hs, &*ps, clock.now())).unwrap();
    assert_eq!(gc_early.swept_packs.len(), 0);
    assert_eq!(run(ps.list_packs()).unwrap().len(), 2);

    // Past 600s grace window: pack 2 is swept; pack 1 remains pinned by snapshot `keep`!
    clock.advance(700);
    let gc_mid = run(collect_garbage(&*hs, &*ps, clock.now())).unwrap();
    assert_eq!(gc_mid.swept_packs.len(), 1);
    assert_eq!(run(ps.list_packs()).unwrap().len(), 1);
    assert!(run(verify_volume(&*hs, &*ps, &vol)).unwrap().ok);

    // Delete snapshot `keep` -> next GC sweeps pack 1 too!
    run(hs.delete_snapshot(&vol, "keep")).unwrap();
    let gc_final = run(collect_garbage(&*hs, &*ps, clock.now())).unwrap();
    assert_eq!(gc_final.swept_packs.len(), 1);
    assert_eq!(run(ps.list_packs()).unwrap().len(), 0);
    assert!(run(verify_volume(&*hs, &*ps, &vol)).unwrap().ok);
    run(fs.close_clean()).unwrap();
}
