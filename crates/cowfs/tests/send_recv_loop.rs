//! Comprehensive Rust integration & conformance suite for Issue #79 (`L2.5c`):
//! - `C-01`: Merkle Delta Stream v1 (`OSCOWS1\0`) & `.cowpack` (`OSCOWA1\0`) wire/ABI contracts
//! - `C-02`: `mkfs.cowfs` (`COWFS_IOC_MKFS`) label, `-f`, `EBUSY`/`EEXIST`/`EPERM`/`ENOTBLK`
//! - `C-03`: `cowfs subvol` (`list`/`create`/`delete`, refusing `@`) on `/dev/vdN` AND mounted dirs
//! - `C-04`: `cowfs snapshot` (`list`/`create`/`delete`) & `cowfsck --snapshot`
//! - `C-05`: Full `send`/`receive` round-trip + truncation & bit-flip atomicity (`EIO`, 0 mutation)
//! - `C-06`: Incremental `send --parent A B` (`subtrees_skipped > 0`, compact delta) & missing
//!   parent refusal (`ENOENT` in both separate and shared stores) + native SQLite backend
//! - `C-07`/`C-08`: `/dev/loop-control` + `/dev/loop0..7` lifecycle, unlink-pinned `.cowpack`
//!   zero-copy RO mount, `EROFS`, `EBUSY` detach-while-mounted, `ENODEV` foreign fs
//! - `C-09`: `.cowpack` corruption detection (`verify_archive_file` `ok == false`, read `EIO`)

use abi::Errno;
use abi::contract::{Durability, WriterModel, cowfs_ioctl, loop_ioctl, mount_flags};
use abi::fs::Timespec;
use abi::volume::{
    CowfsFsckReq, CowfsFsckResp, CowfsInfoResp, CowfsMkfsReq, CowfsSendReq, CowfsSendResp,
    CowfsSnapDeleteReq, CowfsSnapListResp, CowfsSnapshotReq, CowfsSubvolReq, CowfsSubvolResp,
    LoopStatus64,
};
use cowtree::memory::{MemoryHeadStore, MemoryPackStore};
use cowtree::{ArenaConfig, HeadStore, VolumeId, WriterMode, digest_to_hex};
use os_cowfs::native_sqlite::{NativePackStore, NativeSqliteHeadStore};
use os_cowfs::{
    CowFs, CowFsClock, CowFsConfig, CowFsOpenMode, CowFsVolumeDevice, FileRefArchiveReader,
    ReceiveTarget, SliceArchiveReader, SliceSource, VecSink, open_archive_cowfs, receive_snapshot,
    send_snapshot, verify_archive_file, verify_volume,
};
use std::cell::Cell;
use std::collections::BTreeSet;
use std::future::Future;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use vfs::devfs::{DefaultDeviceBackend, DevTmpFs};
use vfs::loopdev::{LoopDeviceBackend, LoopRegistry, parse_loop_device_path};
use vfs::memfs::MemFs;
use vfs::vblk::{CowfsMountOptions, VblkDeviceBackend, VblkRegistry, is_non_block_tree_source};
use vfs::{
    Cred, DefaultFilesystemFactory, Filesystem, FsId, FsType, Identity, MountBacking, MountFlags,
    MountedFs, StartAnchor, Vfs, now_or_never,
};

fn run<F: Future>(fut: F) -> F::Output {
    now_or_never(fut).expect("local cowfs/vfs test future must resolve synchronously")
}

fn ticking_clock() -> CowFsClock {
    let tick = Cell::new(1_700_000_000u64);
    Rc::new(move || {
        let next = tick.get() + 1;
        tick.set(next);
        Timespec { sec: next, nsec: 0 }
    })
}

fn user_cred(uid: u32) -> Cred {
    Cred::new(Identity {
        id: uid,
        group: uid,
        groups: BTreeSet::from([uid]),
    })
}

struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(1);
        let id = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("os-cowfs-l25c-{tag}-{}-{id}", std::process::id()));
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

fn write_all_vfs(vfs: &Vfs, pid: u32, path: &str, data: &[u8]) {
    let fd = run(vfs.openat(
        pid,
        StartAnchor::Root,
        path,
        abi::O_WRONLY | abi::O_CREAT | abi::O_TRUNC,
        0o644,
    ))
    .unwrap();
    let mut off = 0u64;
    while (off as usize) < data.len() {
        let n = run(vfs.pwrite(pid, fd, &data[off as usize..], off)).unwrap();
        assert!(n > 0);
        off += n as u64;
    }
    run(vfs.close(pid, fd)).unwrap();
}

fn read_all_vfs(vfs: &Vfs, pid: u32, path: &str) -> vfs::Result<Vec<u8>> {
    let fd = run(vfs.openat(pid, StartAnchor::Root, path, abi::O_RDONLY, 0))?;
    let mut out = Vec::new();
    let mut off = 0u64;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match run(vfs.pread(pid, fd, &mut buf, off)) {
            Ok(0) => break,
            Ok(n) => {
                out.extend_from_slice(&buf[..n]);
                off += n as u64;
            }
            Err(e) => {
                let _ = run(vfs.close(pid, fd));
                return Err(e);
            }
        }
    }
    run(vfs.close(pid, fd))?;
    Ok(out)
}

fn boot_test_vfs(
    hs: Rc<MemoryHeadStore>,
    ps: Rc<MemoryPackStore>,
    root_fs: Rc<CowFs<MemoryHeadStore, MemoryPackStore>>,
) -> (Vfs, Rc<VblkRegistry>, Rc<LoopRegistry>) {
    let clock = ticking_clock();
    let vblk = Rc::new(VblkRegistry::new());
    let loop_reg = Rc::new(LoopRegistry::new());

    let factory = Rc::new(DefaultFilesystemFactory::new(Rc::new(|| {
        (1_700_000_000, 0)
    })));
    {
        let loop_m = Rc::clone(&loop_reg);
        let clock_m = Rc::clone(&clock);
        factory.register_async_system_mounter(FsType::Cowfs, move |_cred, source, flags, data| {
            let loop_m = Rc::clone(&loop_m);
            let clock_m = Rc::clone(&clock_m);
            Box::pin(async move {
                let opts = CowfsMountOptions::parse(data.as_deref())?;
                if is_non_block_tree_source(&source) {
                    return Err(Errno::ENOTBLK);
                }
                let ro = flags.rdonly || opts.ro;
                let idx = parse_loop_device_path(&source).ok_or(Errno::ENODEV)?;
                let (backing_file, _binding_ro, archive_format, loop_guard) =
                    loop_m.acquire_mount(idx, !ro)?;
                if archive_format != "cowpack-v1" {
                    drop(loop_guard);
                    return Err(Errno::EINVAL);
                }
                let reader = Rc::new(FileRefArchiveReader(backing_file));
                let cfg = CowFsConfig::local_native(clock_m)
                    .with_arena(ArenaConfig::fixed_32mib())
                    .with_subvol(&opts.subvol);
                let fs = match open_archive_cowfs(reader, format!("loop{idx}"), cfg).await {
                    Ok(f) => Rc::new(f),
                    Err(e) => {
                        drop(loop_guard);
                        return Err(e);
                    }
                };
                let root = fs.root();
                let dev = Rc::new(CowFsVolumeDevice::from_mounted(Rc::clone(&fs)));
                let backing = Rc::new(
                    MountBacking::new(fs as Rc<dyn Filesystem>, FsType::Cowfs)
                        .with_ceilings(true, false)
                        .with_volume_device(dev)
                        .with_on_release(move || drop(loop_guard)),
                );
                Ok(MountedFs {
                    backing,
                    root,
                    root_in_fs: "/".to_string(),
                })
            })
        });
    }

    let root_dev = Rc::new(CowFsVolumeDevice::from_mounted(Rc::clone(&root_fs)));
    let root_backing = Rc::new(
        MountBacking::new(Rc::clone(&root_fs) as Rc<dyn Filesystem>, FsType::Cowfs)
            .with_volume_device(Rc::clone(&root_dev) as Rc<dyn vfs::vblk::VolumeDevice>),
    );
    let vfs = run(Vfs::boot("l25c-test", root_backing, "cowfs:root", factory)).unwrap();

    run(vfs.mkdirat(1, StartAnchor::Root, "/dev", 0o755)).unwrap();
    run(vfs.mkdirat(1, StartAnchor::Root, "/tmp", 0o1777)).unwrap();
    run(vfs.mkdirat(1, StartAnchor::Root, "/mnt", 0o755)).unwrap();

    let dev_fs = Rc::new(DevTmpFs::new(
        FsId("devtmpfs".into()),
        1,
        Box::new(|| (1_700_000_000, 0)),
        LoopDeviceBackend::new(
            (*loop_reg).clone(),
            VblkDeviceBackend::new(DefaultDeviceBackend),
        ),
    ));
    vblk.attach_named("vd0", root_dev).unwrap();
    vblk.attach_named(
        "vd1",
        Rc::new(CowFsVolumeDevice::unmounted(
            VolumeId("vol-scratch".into()),
            hs,
            ps,
            WriterModel::Local,
            Durability::TreeCommit,
            clock,
        )),
    )
    .unwrap();
    dev_fs.register_vblk("vd0", 0o660).unwrap();
    dev_fs.register_vblk("vd1", 0o660).unwrap();
    dev_fs.register_loop_devices().unwrap();

    let sys_ns = vfs.system_namespace();
    run(vfs.mount_on_namespace(
        &sys_ns,
        &Cred::root(),
        Rc::new(MountBacking::new(dev_fs, FsType::DevTmpFs)),
        None,
        "devtmpfs",
        "/dev",
        MountFlags::default(),
        0,
        None,
    ))
    .unwrap();

    let tmp_fs = Rc::new(MemFs::new(
        FsId("tmpfs:tmp".into()),
        2,
        0,
        0,
        0o1777,
        Box::new(|| (1_700_000_000, 0)),
    ));
    run(vfs.mount_on_namespace(
        &sys_ns,
        &Cred::root(),
        Rc::new(MountBacking::new(tmp_fs, FsType::TmpFs)),
        None,
        "tmpfs",
        "/tmp",
        MountFlags::default(),
        0,
        None,
    ))
    .unwrap();

    // Spawn a non-root user process (pid 2, uid 1000).
    vfs.spawn_process(2, 1, user_cred(1000), None, None, None)
        .unwrap();

    (vfs, vblk, loop_reg)
}

#[test]
fn c02_c03_c04_mkfs_subvols_snapshots_and_mounted_dir_ioctls() {
    let hs = Rc::new(MemoryHeadStore::new());
    let ps = Rc::new(MemoryPackStore::new());
    let clock = ticking_clock();
    let root_vol = VolumeId("vol-root".into());
    run(CowFs::format_volume(
        &*hs,
        &*ps,
        root_vol.clone(),
        0,
        0,
        0o755,
        clock(),
    ))
    .unwrap();
    let root_fs = Rc::new(
        run(CowFs::open(
            Rc::clone(&hs),
            Rc::clone(&ps),
            root_vol,
            CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
            CowFsConfig::local_native(Rc::clone(&clock)),
        ))
        .unwrap(),
    );
    let (vfs, vblk, _loop_reg) = boot_test_vfs(Rc::clone(&hs), Rc::clone(&ps), Rc::clone(&root_fs));

    // C-02: mkfs via COWFS_IOC_MKFS on /dev/vd1 with label -> succeeds, second without -f -> EEXIST,
    // with -f -> bumps incarnation; mounted /dev/vd0 -> EBUSY; non-block dir -> ENOTBLK; non-root -> EPERM.
    let vd1_fd = run(vfs.openat(1, StartAnchor::Root, "/dev/vd1", abi::O_RDONLY, 0)).unwrap();
    let mk_req = serde_json::to_vec(&CowfsMkfsReq {
        force: false,
        label: Some("data-disk".into()),
        volume: None,
    })
    .unwrap();
    let mk_bytes =
        run(vblk.ioctl_fd(&vfs, 1, vd1_fd, cowfs_ioctl::COWFS_IOC_MKFS, &mk_req)).unwrap();
    let mk_info: CowfsInfoResp = serde_json::from_slice(&mk_bytes).unwrap();
    assert_eq!(mk_info.volume, "vol-scratch");
    assert_eq!(mk_info.incarnation, 1);

    // Label persisted as `trusted.cowfs.label` on the formatted volume's root inode!
    {
        let scratch_ro = run(CowFs::open(
            Rc::clone(&hs),
            Rc::clone(&ps),
            VolumeId("vol-scratch".into()),
            CowFsOpenMode::ReadOnly,
            CowFsConfig::local_native(Rc::clone(&clock)),
        ))
        .unwrap();
        let lbl =
            run(scratch_ro.getxattr(&Cred::root(), &scratch_ro.root(), "trusted.cowfs.label"))
                .unwrap();
        assert_eq!(lbl, b"data-disk");
        run(scratch_ro.close_clean()).unwrap();
    }

    assert_eq!(
        run(vblk.ioctl_fd(&vfs, 1, vd1_fd, cowfs_ioctl::COWFS_IOC_MKFS, &mk_req)).unwrap_err(),
        Errno::EEXIST
    );
    let force_req = serde_json::to_vec(&CowfsMkfsReq {
        force: true,
        label: Some("reformatted".into()),
        volume: None,
    })
    .unwrap();
    let mk2: CowfsInfoResp = serde_json::from_slice(
        &run(vblk.ioctl_fd(&vfs, 1, vd1_fd, cowfs_ioctl::COWFS_IOC_MKFS, &force_req)).unwrap(),
    )
    .unwrap();
    assert_eq!(mk2.incarnation, 2);
    run(vfs.close(1, vd1_fd)).unwrap();

    // Mounted /dev/vd0 -> EBUSY; mounted cowfs dir `/` -> ENOTBLK; non-root -> EPERM.
    let vd0_fd = run(vfs.openat(1, StartAnchor::Root, "/dev/vd0", abi::O_RDONLY, 0)).unwrap();
    assert_eq!(
        run(vblk.ioctl_fd(&vfs, 1, vd0_fd, cowfs_ioctl::COWFS_IOC_MKFS, &force_req)).unwrap_err(),
        Errno::EBUSY
    );
    run(vfs.close(1, vd0_fd)).unwrap();

    let root_dir_fd = run(vfs.openat(
        1,
        StartAnchor::Root,
        "/",
        abi::O_RDONLY | abi::O_DIRECTORY,
        0,
    ))
    .unwrap();
    assert_eq!(
        run(vblk.ioctl_fd(
            &vfs,
            1,
            root_dir_fd,
            cowfs_ioctl::COWFS_IOC_MKFS,
            &force_req
        ))
        .unwrap_err(),
        Errno::ENOTBLK
    );
    assert_eq!(
        run(vblk.mkfs_cowfs(&vfs, 2, "/dev/vd1", true)).unwrap_err(),
        Errno::EPERM
    );
    for non_blk in [
        "/",
        "/tmp",
        "hostfs:src",
        "opfs:proj",
        "helperfs:h",
        "sharefs:s",
    ] {
        assert_eq!(
            run(vblk.mkfs_cowfs(&vfs, 1, non_blk, true)).unwrap_err(),
            Errno::ENOTBLK,
            "target {non_blk} must fail ENOTBLK"
        );
    }

    // C-03: COWFS_IOC_SUBVOL directly on mounted cowfs directory fd `/`!
    let list_req = serde_json::to_vec(&CowfsSubvolReq::List {}).unwrap();
    let sv0: CowfsSubvolResp = serde_json::from_slice(
        &run(vblk.ioctl_fd(
            &vfs,
            1,
            root_dir_fd,
            cowfs_ioctl::COWFS_IOC_SUBVOL,
            &list_req,
        ))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(sv0.subvols.len(), 1);
    assert_eq!(sv0.subvols[0].name, "@");

    let create_req = serde_json::to_vec(&CowfsSubvolReq::Create {
        name: "data".into(),
    })
    .unwrap();
    let sv1: CowfsSubvolResp = serde_json::from_slice(
        &run(vblk.ioctl_fd(
            &vfs,
            1,
            root_dir_fd,
            cowfs_ioctl::COWFS_IOC_SUBVOL,
            &create_req,
        ))
        .unwrap(),
    )
    .unwrap();
    assert!(sv1.subvols.iter().any(|s| s.name == "data"));

    // Deleting `@` MUST fail with EBUSY!
    let del_at = serde_json::to_vec(&CowfsSubvolReq::Delete { name: "@".into() }).unwrap();
    assert_eq!(
        run(vblk.ioctl_fd(&vfs, 1, root_dir_fd, cowfs_ioctl::COWFS_IOC_SUBVOL, &del_at))
            .unwrap_err(),
        Errno::EBUSY
    );

    // Non-root can list subvols on `/` but cannot create/delete (`EPERM`); `O_PATH` fails `EBADF`.
    let u_dir_fd = run(vfs.openat(
        2,
        StartAnchor::Root,
        "/",
        abi::O_RDONLY | abi::O_DIRECTORY,
        0,
    ))
    .unwrap();
    assert!(
        run(vblk.ioctl_fd(&vfs, 2, u_dir_fd, cowfs_ioctl::COWFS_IOC_SUBVOL, &list_req)).is_ok()
    );
    assert_eq!(
        run(vblk.ioctl_fd(
            &vfs,
            2,
            u_dir_fd,
            cowfs_ioctl::COWFS_IOC_SUBVOL,
            &create_req
        ))
        .unwrap_err(),
        Errno::EPERM
    );
    run(vfs.close(2, u_dir_fd)).unwrap();

    let opath_fd = run(vfs.openat(1, StartAnchor::Root, "/", abi::O_PATH, 0)).unwrap();
    assert_eq!(
        run(vblk.ioctl_fd(&vfs, 1, opath_fd, cowfs_ioctl::COWFS_IOC_INFO, b"")).unwrap_err(),
        Errno::EBADF
    );
    run(vfs.close(1, opath_fd)).unwrap();

    // Mount subvol `data`, write a file in it, unmount, then delete `data`.
    let sub_view = root_fs.open_subvol_view("data").unwrap();
    run(vfs.mkdirat(1, StartAnchor::Root, "/mnt/data", 0o755)).unwrap();
    let sys_ns = vfs.system_namespace();
    run(vfs.mount_on_namespace(
        &sys_ns,
        &Cred::root(),
        Rc::new(
            MountBacking::new(sub_view, FsType::Cowfs).with_volume_device(Rc::new(
                CowFsVolumeDevice::from_mounted(Rc::clone(&root_fs)),
            )),
        ),
        None,
        "cowfs:vol-root:data",
        "/mnt/data",
        MountFlags::default(),
        0,
        None,
    ))
    .unwrap();
    write_all_vfs(&vfs, 1, "/mnt/data/isolated.txt", b"subvol-only");
    assert!(read_all_vfs(&vfs, 1, "/isolated.txt").is_err());
    assert_eq!(
        read_all_vfs(&vfs, 1, "/mnt/data/isolated.txt").unwrap(),
        b"subvol-only"
    );
    run(vfs.umount2(1, "/mnt/data", 0)).unwrap();

    let del_data = serde_json::to_vec(&CowfsSubvolReq::Delete {
        name: "data".into(),
    })
    .unwrap();
    let sv2: CowfsSubvolResp = serde_json::from_slice(
        &run(vblk.ioctl_fd(
            &vfs,
            1,
            root_dir_fd,
            cowfs_ioctl::COWFS_IOC_SUBVOL,
            &del_data,
        ))
        .unwrap(),
    )
    .unwrap();
    assert!(!sv2.subvols.iter().any(|s| s.name == "data"));

    // C-04: Snapshot create / list / fsck --snapshot / delete on mounted `/` fd.
    write_all_vfs(&vfs, 1, "/hello.txt", b"snap-v1");
    let snap1_req = serde_json::to_vec(&CowfsSnapshotReq {
        name: "s1".into(),
        ro: true,
    })
    .unwrap();
    assert!(
        run(vblk.ioctl_fd(
            &vfs,
            1,
            root_dir_fd,
            cowfs_ioctl::COWFS_IOC_SNAPSHOT,
            &snap1_req
        ))
        .is_ok()
    );
    let snap_list: CowfsSnapListResp = serde_json::from_slice(
        &run(vblk.ioctl_fd(&vfs, 1, root_dir_fd, cowfs_ioctl::COWFS_IOC_SNAP_LIST, b"")).unwrap(),
    )
    .unwrap();
    assert_eq!(snap_list.snapshots.len(), 1);
    assert_eq!(snap_list.snapshots[0].name, "s1");

    // Verify `COWFS_IOC_FSCK` targeting named snapshot `s1`.
    let fsck_snap_req = serde_json::to_vec(&CowfsFsckReq {
        volume: None,
        snapshot: Some("s1".into()),
        archive: false,
    })
    .unwrap();
    let fsck_resp: CowfsFsckResp = serde_json::from_slice(
        &run(vblk.ioctl_fd(
            &vfs,
            1,
            root_dir_fd,
            cowfs_ioctl::COWFS_IOC_FSCK,
            &fsck_snap_req,
        ))
        .unwrap(),
    )
    .unwrap();
    assert!(fsck_resp.ok);
    assert!(fsck_resp.nodes_verified >= 2);
    assert_eq!(fsck_resp.root, snap_list.snapshots[0].root);

    // Delete `s1` and verify it is removed.
    let del_snap = serde_json::to_vec(&CowfsSnapDeleteReq { name: "s1".into() }).unwrap();
    assert!(
        run(vblk.ioctl_fd(
            &vfs,
            1,
            root_dir_fd,
            cowfs_ioctl::COWFS_IOC_SNAP_DELETE,
            &del_snap
        ))
        .is_ok()
    );
    let snap_list2: CowfsSnapListResp = serde_json::from_slice(
        &run(vblk.ioctl_fd(&vfs, 1, root_dir_fd, cowfs_ioctl::COWFS_IOC_SNAP_LIST, b"")).unwrap(),
    )
    .unwrap();
    assert!(snap_list2.snapshots.is_empty());

    run(vfs.close(1, root_dir_fd)).unwrap();
    run(root_fs.close_clean()).unwrap();
}

#[test]
fn c05_c06_merkle_send_receive_incremental_skip_and_corruption_atomicity() {
    let src_hs = Rc::new(MemoryHeadStore::new());
    let src_ps = Rc::new(MemoryPackStore::new());
    let clock = ticking_clock();
    let src_vol = VolumeId("vol-src".into());
    run(CowFs::format_volume(
        &*src_hs,
        &*src_ps,
        src_vol.clone(),
        0,
        0,
        0o755,
        clock(),
    ))
    .unwrap();
    let src_fs = Rc::new(
        run(CowFs::open(
            Rc::clone(&src_hs),
            Rc::clone(&src_ps),
            src_vol.clone(),
            CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
            CowFsConfig::local_native(Rc::clone(&clock)),
        ))
        .unwrap(),
    );

    // Populate 100 distinct files (mixing inline and multi-block 70 KiB extents so the CoW B+tree
    // has multiple internal/leaf subtrees!) and take snapshot `A`.
    let root = src_fs.root();
    let dir_entry = run(src_fs.mkdir(&Cred::root(), &root, "files", 0o755)).unwrap();
    let mut expected_a: Vec<(String, Vec<u8>)> = Vec::new();
    for i in 0u32..100 {
        let name = format!("f{i:03}.dat");
        let payload = if i % 10 == 0 {
            // 70 KiB out-of-line extent payload
            let mut big = vec![(i as u8).wrapping_mul(7).wrapping_add(1); 70 * 1024];
            big[0..4].copy_from_slice(&i.to_le_bytes());
            big
        } else {
            format!("file-{i:03}-revision-A-payload-{}", "x".repeat(64)).into_bytes()
        };
        let opts = *abi::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true);
        let (_, open) =
            run(src_fs.create(&Cred::root(), &dir_entry.handle, &name, 0o644, &opts)).unwrap();
        run(src_fs.write_at(&open, &payload, abi::fs::WriteAt::Offset(0))).unwrap();
        run(src_fs.release(&open)).unwrap();
        expected_a.push((name, payload));
    }
    let snap_a = run(src_fs.create_snapshot("A")).unwrap();

    // Modify ONLY 2 files (one inline, one 70 KiB extent) and take snapshot `B`.
    let mut expected_b = expected_a.clone();
    for &idx in &[5usize, 50usize] {
        let (ref name, ref mut data) = expected_b[idx];
        *data = if idx == 50 {
            let mut big = vec![0xEE; 72 * 1024];
            big[0..8].copy_from_slice(b"MODIFIED");
            big
        } else {
            b"file-005-updated-in-B".to_vec()
        };
        let entry = run(src_fs.lookup(&Cred::root(), &dir_entry.handle, name)).unwrap();
        let opts = *abi::fs::OpenOptions::new().write(true).truncate(true);
        let open = run(src_fs.open(&Cred::root(), &entry.handle, &opts)).unwrap();
        run(src_fs.write_at(&open, data, abi::fs::WriteAt::Offset(0))).unwrap();
        run(src_fs.release(&open)).unwrap();
    }
    let snap_b = run(src_fs.create_snapshot("B")).unwrap();

    // Emit full A, full B, and incremental A -> B.
    let mut full_a_sink = VecSink::default();
    let full_a_resp = run(send_snapshot(
        &*src_hs,
        &*src_ps,
        &src_vol,
        None,
        "A",
        None,
        false,
        &mut full_a_sink,
    ))
    .unwrap();
    assert_eq!(full_a_resp.root, digest_to_hex(&snap_a.root));
    assert_eq!(full_a_resp.subtrees_skipped, 0);

    let mut full_b_sink = VecSink::default();
    let full_b_resp = run(send_snapshot(
        &*src_hs,
        &*src_ps,
        &src_vol,
        None,
        "B",
        None,
        false,
        &mut full_b_sink,
    ))
    .unwrap();

    let mut inc_sink = VecSink::default();
    let inc_resp = run(send_snapshot(
        &*src_hs,
        &*src_ps,
        &src_vol,
        None,
        "B",
        Some("A"),
        false,
        &mut inc_sink,
    ))
    .unwrap();
    assert_eq!(inc_resp.root, digest_to_hex(&snap_b.root));
    assert_eq!(inc_resp.parent_root, Some(digest_to_hex(&snap_a.root)));
    assert!(
        inc_resp.subtrees_skipped > 0,
        "incremental send must skip unchanged subtrees: {inc_resp:?}"
    );
    assert!(
        inc_sink.0.len() * 2 < full_b_sink.0.len(),
        "incremental stream ({} B) must be dramatically smaller than full stream ({} B)",
        inc_sink.0.len(),
        full_b_sink.0.len()
    );
    assert!(inc_resp.blocks_sent < full_b_resp.blocks_sent);

    // C-06 Missing parent refusal in BOTH a separate store AND the SAME shared store!
    let dst_hs = Rc::new(MemoryHeadStore::new());
    let dst_ps = Rc::new(MemoryPackStore::new());
    let dst_vol = VolumeId("vol-dst".into());
    assert_eq!(
        run(receive_snapshot(
            &*dst_hs,
            &*dst_ps,
            ReceiveTarget::UnmountedVolume(&dst_vol),
            Some("B"),
            clock(),
            &mut SliceSource::new(&inc_sink.0),
        ))
        .unwrap_err(),
        Errno::ENOENT
    );
    // In the SAME shared store (`src_hs` already has `snap_a` under `vol-src`), receiving
    // incremental `A -> B` into a fresh `vol-fresh-same-store` MUST still fail `ENOENT`!
    let same_store_vol = VolumeId("vol-fresh-same-store".into());
    run(CowFs::format_volume(
        &*src_hs,
        &*src_ps,
        same_store_vol.clone(),
        0,
        0,
        0o755,
        clock(),
    ))
    .unwrap();
    let before_same_head = run(src_hs.read_head(&same_store_vol)).unwrap();
    assert_eq!(
        run(receive_snapshot(
            &*src_hs,
            &*src_ps,
            ReceiveTarget::UnmountedVolume(&same_store_vol),
            Some("B"),
            clock(),
            &mut SliceSource::new(&inc_sink.0),
        ))
        .unwrap_err(),
        Errno::ENOENT
    );
    assert_eq!(
        run(src_hs.read_head(&same_store_vol)).unwrap(),
        before_same_head
    );

    // C-05 Corruption atomicity: truncated stream + bit-flip in NODE/BLOCK/END -> EIO & 0 mutation!
    let mut truncated = full_a_sink.0.clone();
    truncated.truncate(truncated.len() - 10);
    assert_eq!(
        run(receive_snapshot(
            &*dst_hs,
            &*dst_ps,
            ReceiveTarget::UnmountedVolume(&dst_vol),
            Some("A"),
            clock(),
            &mut SliceSource::new(&truncated),
        ))
        .unwrap_err(),
        Errno::EIO
    );
    assert_eq!(run(dst_hs.read_head(&dst_vol)).unwrap_err(), Errno::ENOENT);

    // Bit-flip inside stream body AND inside END trailer.
    for flip_pos in [120usize, full_a_sink.0.len() / 2, full_a_sink.0.len() - 5] {
        let mut flipped = full_a_sink.0.clone();
        flipped[flip_pos] ^= 0x01;
        assert_eq!(
            run(receive_snapshot(
                &*dst_hs,
                &*dst_ps,
                ReceiveTarget::UnmountedVolume(&dst_vol),
                Some("A"),
                clock(),
                &mut SliceSource::new(&flipped),
            ))
            .unwrap_err(),
            Errno::EIO,
            "bit-flip at offset {flip_pos} must fail EIO"
        );
        assert_eq!(run(dst_hs.read_head(&dst_vol)).unwrap_err(), Errno::ENOENT);
    }

    // Receive full A -> creates `vol-dst` + snapshot `A` atomically.
    let (head_a, recv_a) = run(receive_snapshot(
        &*dst_hs,
        &*dst_ps,
        ReceiveTarget::UnmountedVolume(&dst_vol),
        Some("A"),
        clock(),
        &mut SliceSource::new(&full_a_sink.0),
    ))
    .unwrap();
    assert_eq!(head_a.root, snap_a.root);
    assert_eq!(recv_a.snapshot.as_deref(), Some("A"));

    // Bit-flip on incremental B MUST leave `vol-dst` pinned cleanly at head A!
    let mut bad_inc = inc_sink.0.clone();
    let mid = bad_inc.len() / 2;
    bad_inc[mid] ^= 0x80;
    assert_eq!(
        run(receive_snapshot(
            &*dst_hs,
            &*dst_ps,
            ReceiveTarget::UnmountedVolume(&dst_vol),
            Some("B"),
            clock(),
            &mut SliceSource::new(&bad_inc),
        ))
        .unwrap_err(),
        Errno::EIO
    );
    assert_eq!(run(dst_hs.read_head(&dst_vol)).unwrap().root, snap_a.root);
    assert_eq!(
        run(dst_hs.get_snapshot(&dst_vol, "B")).unwrap_err(),
        Errno::ENOENT
    );

    // Receive valid incremental A -> B!
    let (head_b, recv_b) = run(receive_snapshot(
        &*dst_hs,
        &*dst_ps,
        ReceiveTarget::UnmountedVolume(&dst_vol),
        Some("B"),
        clock(),
        &mut SliceSource::new(&inc_sink.0),
    ))
    .unwrap();
    assert_eq!(head_b.root, snap_b.root);
    assert_eq!(recv_b.epoch, head_a.epoch + 1);
    assert!(run(verify_volume(&*dst_hs, &*dst_ps, &dst_vol)).unwrap().ok);

    // Verify EVERY single one of the 100 files in `vol-dst@B` matches byte-for-byte!
    let dst_ro = run(CowFs::open(
        Rc::clone(&dst_hs),
        Rc::clone(&dst_ps),
        dst_vol.clone(),
        CowFsOpenMode::ReadOnly,
        CowFsConfig::local_native(Rc::clone(&clock)),
    ))
    .unwrap();
    let dst_dir = run(dst_ro.lookup(&Cred::root(), &dst_ro.root(), "files")).unwrap();
    for (name, expected_bytes) in &expected_b {
        let ent = run(dst_ro.lookup(&Cred::root(), &dst_dir.handle, name)).unwrap();
        let open =
            run(dst_ro.open(&Cred::root(), &ent.handle, OpenOptions::new().read(true))).unwrap();
        let mut actual = vec![0u8; expected_bytes.len() + 64];
        let n = run(dst_ro.read_at(&open, &mut actual, 0)).unwrap();
        run(dst_ro.release(&open)).unwrap();
        assert_eq!(
            &actual[..n],
            expected_bytes.as_slice(),
            "mismatch on {name}"
        );
    }
    run(dst_ro.close_clean()).unwrap();

    // Native SQLite (`NativeSqliteHeadStore` + `NativePackStore`) atomic receive + list_volumes!
    let sql_dir = TempDir::new("sqlite-recv");
    let sql_hs = Rc::new(NativeSqliteHeadStore::open(&sql_dir.0).unwrap());
    let sql_ps = Rc::new(NativePackStore::open(&sql_dir.0).unwrap());
    let sql_vol = VolumeId("vol-sqlite-dst".into());
    let (sh_a, _) = run(receive_snapshot(
        &*sql_hs,
        &*sql_ps,
        ReceiveTarget::UnmountedVolume(&sql_vol),
        Some("A"),
        clock(),
        &mut SliceSource::new(&full_a_sink.0),
    ))
    .unwrap();
    assert_eq!(sh_a.root, snap_a.root);
    let (sh_b, _) = run(receive_snapshot(
        &*sql_hs,
        &*sql_ps,
        ReceiveTarget::UnmountedVolume(&sql_vol),
        Some("B"),
        clock(),
        &mut SliceSource::new(&inc_sink.0),
    ))
    .unwrap();
    assert_eq!(sh_b.root, snap_b.root);
    let vols = run(sql_hs.list_volumes()).unwrap();
    assert_eq!(vols.len(), 1);
    assert_eq!(vols[0].volume, sql_vol);
    assert!(run(verify_volume(&*sql_hs, &*sql_ps, &sql_vol)).unwrap().ok);

    run(src_fs.close_clean()).unwrap();
}

use abi::fs::OpenOptions;

#[test]
fn c07_c08_c09_cowpack_loop_device_mount_lifecycle_and_corruption_detection() {
    let hs = Rc::new(MemoryHeadStore::new());
    let ps = Rc::new(MemoryPackStore::new());
    let clock = ticking_clock();
    let root_vol = VolumeId("vol-root".into());
    run(CowFs::format_volume(
        &*hs,
        &*ps,
        root_vol.clone(),
        0,
        0,
        0o755,
        clock(),
    ))
    .unwrap();
    let root_fs = Rc::new(
        run(CowFs::open(
            Rc::clone(&hs),
            Rc::clone(&ps),
            root_vol,
            CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
            CowFsConfig::local_native(Rc::clone(&clock)),
        ))
        .unwrap(),
    );
    let (vfs, vblk, loop_reg) = boot_test_vfs(Rc::clone(&hs), Rc::clone(&ps), Rc::clone(&root_fs));

    // Populate files (inline + 128 KiB multi-block extent) on root cowfs and snapshot `pkg`.
    run(vfs.mkdirat(1, StartAnchor::Root, "/pkgdata", 0o755)).unwrap();
    write_all_vfs(&vfs, 1, "/pkgdata/manifest.txt", b"package-v1\n");
    let big_payload: Vec<u8> = (0u32..(128 * 1024))
        .map(|i| ((i.wrapping_mul(31) ^ (i >> 9) ^ (i >> 16)) & 0xff) as u8)
        .collect();
    write_all_vfs(&vfs, 1, "/pkgdata/blob.bin", &big_payload);

    let root_dir_fd = run(vfs.openat(
        1,
        StartAnchor::Root,
        "/",
        abi::O_RDONLY | abi::O_DIRECTORY,
        0,
    ))
    .unwrap();
    let snap_req = serde_json::to_vec(&CowfsSnapshotReq {
        name: "pkg".into(),
        ro: true,
    })
    .unwrap();
    run(vblk.ioctl_fd(
        &vfs,
        1,
        root_dir_fd,
        cowfs_ioctl::COWFS_IOC_SNAPSHOT,
        &snap_req,
    ))
    .unwrap();

    // Export `.cowpack` archive via `COWFS_IOC_SEND { archive: true }` directly to `/tmp/pkg.cowpack`!
    let out_fd = run(vfs.openat(
        1,
        StartAnchor::Root,
        "/tmp/pkg.cowpack",
        abi::O_WRONLY | abi::O_CREAT | abi::O_TRUNC,
        0o644,
    ))
    .unwrap();
    // Refuses `--archive` combined with `--parent` (`EINVAL`).
    let bad_arch_req = serde_json::to_vec(&CowfsSendReq {
        snapshot: "pkg".into(),
        parent: Some("pkg".into()),
        stream_fd: out_fd,
        archive: true,
    })
    .unwrap();
    assert_eq!(
        run(vblk.ioctl_fd(
            &vfs,
            1,
            root_dir_fd,
            cowfs_ioctl::COWFS_IOC_SEND,
            &bad_arch_req
        ))
        .unwrap_err(),
        Errno::EINVAL
    );

    let arch_req = serde_json::to_vec(&CowfsSendReq {
        snapshot: "pkg".into(),
        parent: None,
        stream_fd: out_fd,
        archive: true,
    })
    .unwrap();
    let send_resp: CowfsSendResp = serde_json::from_slice(
        &run(vblk.ioctl_fd(&vfs, 1, root_dir_fd, cowfs_ioctl::COWFS_IOC_SEND, &arch_req)).unwrap(),
    )
    .unwrap();
    run(vfs.close(1, out_fd)).unwrap();
    assert!(send_resp.bytes_written > 128 * 1024);
    assert!(send_resp.blocks_sent >= 1);

    // Save raw bytes for C-09 corruption testing.
    let archive_bytes = read_all_vfs(&vfs, 1, "/tmp/pkg.cowpack").unwrap();
    assert_eq!(&archive_bytes[..8], b"OSCOWA1\0");
    assert_eq!(
        &archive_bytes[archive_bytes.len() - 96..archive_bytes.len() - 88],
        b"OSCOWA1F"
    );

    // Verify intact archive via `verify_archive_file`.
    let clean_fsck = run(verify_archive_file(
        Rc::new(SliceArchiveReader(Rc::new(archive_bytes.clone()))),
        "/tmp/pkg.cowpack",
    ))
    .unwrap();
    assert!(clean_fsck.ok, "errors={:?}", clean_fsck.errors);
    assert!(clean_fsck.nodes_verified >= 2);
    assert!(clean_fsck.packs_verified >= 1);

    // C-07: `/dev/loop-control` `LOOP_CTL_GET_FREE` -> 0; non-root -> EPERM; dir/`O_PATH` -> EINVAL/EBADF.
    let ctl_fd =
        run(vfs.openat(1, StartAnchor::Root, "/dev/loop-control", abi::O_RDONLY, 0)).unwrap();
    let free_idx: u32 = serde_json::from_slice(
        &run(loop_reg.ioctl_fd(&vfs, 1, ctl_fd, loop_ioctl::LOOP_CTL_GET_FREE, b"")).unwrap(),
    )
    .unwrap();
    assert_eq!(free_idx, 0);
    run(vfs.close(1, ctl_fd)).unwrap();

    // Non-root cannot open 0660 `/dev/loop-control` or call `get_free` (`EPERM`).
    assert_eq!(
        loop_reg.get_free(&user_cred(1000)).unwrap_err(),
        Errno::EPERM
    );

    let loop0_fd = run(vfs.openat(1, StartAnchor::Root, "/dev/loop0", abi::O_RDONLY, 0)).unwrap();
    // Directory fd -> EINVAL; O_PATH fd -> EBADF!
    assert_eq!(
        run(loop_reg.ioctl_fd(
            &vfs,
            1,
            loop0_fd,
            loop_ioctl::LOOP_SET_FD,
            &serde_json::to_vec(&root_dir_fd).unwrap()
        ))
        .unwrap_err(),
        Errno::EINVAL
    );
    let opath_file =
        run(vfs.openat(1, StartAnchor::Root, "/tmp/pkg.cowpack", abi::O_PATH, 0)).unwrap();
    assert_eq!(
        run(loop_reg.ioctl_fd(
            &vfs,
            1,
            loop0_fd,
            loop_ioctl::LOOP_SET_FD,
            &serde_json::to_vec(&opath_file).unwrap()
        ))
        .unwrap_err(),
        Errno::EBADF
    );
    run(vfs.close(1, opath_file)).unwrap();

    // Bind `/tmp/pkg.cowpack` to `/dev/loop0` -> classifies `"cowpack-v1"` & `read_only: true`!
    let pkg_fd =
        run(vfs.openat(1, StartAnchor::Root, "/tmp/pkg.cowpack", abi::O_RDONLY, 0)).unwrap();
    let status: LoopStatus64 = serde_json::from_slice(
        &run(loop_reg.ioctl_fd(
            &vfs,
            1,
            loop0_fd,
            loop_ioctl::LOOP_SET_FD,
            &serde_json::to_vec(&pkg_fd).unwrap(),
        ))
        .unwrap(),
    )
    .unwrap();
    assert!(status.bound);
    assert!(status.read_only);
    assert_eq!(status.archive_format, "cowpack-v1");
    assert_eq!(status.root_digest.as_deref(), Some(send_resp.root.as_str()));

    // Binding already-bound `/dev/loop0` again -> EBUSY!
    assert_eq!(
        run(loop_reg.ioctl_fd(
            &vfs,
            1,
            loop0_fd,
            loop_ioctl::LOOP_SET_FD,
            &serde_json::to_vec(&pkg_fd).unwrap(),
        ))
        .unwrap_err(),
        Errno::EBUSY
    );
    run(vfs.close(1, pkg_fd)).unwrap();

    // Unlink `/tmp/pkg.cowpack` AFTER `LOOP_SET_FD` -> pinned FileRef MUST survive!
    run(vfs.unlinkat(1, StartAnchor::Root, "/tmp/pkg.cowpack", false)).unwrap();

    // C-08: Mount negative checks + zero-copy RO mount + detach-while-mounted EBUSY!
    run(vfs.mkdirat(1, StartAnchor::Root, "/mnt/pkg", 0o755)).unwrap();
    // Foreign fstype (`ext4`) -> ENODEV!
    assert_eq!(
        run(vfs.mount(
            1,
            "/dev/loop0",
            "/mnt/pkg",
            Some("ext4"),
            mount_flags::MS_RDONLY,
            None
        ))
        .unwrap_err(),
        Errno::ENODEV
    );
    // Writable mount without `-o ro` -> EROFS!
    assert_eq!(
        run(vfs.mount(1, "/dev/loop0", "/mnt/pkg", Some("cowfs"), 0, None)).unwrap_err(),
        Errno::EROFS
    );
    // Read-only mount succeeds zero-copy!
    run(vfs.mount(
        1,
        "/dev/loop0",
        "/mnt/pkg",
        Some("cowfs"),
        mount_flags::MS_RDONLY,
        None,
    ))
    .unwrap();

    // Read files directly from zero-copy mounted `.cowpack` archive!
    assert_eq!(
        read_all_vfs(&vfs, 1, "/mnt/pkg/pkgdata/manifest.txt").unwrap(),
        b"package-v1\n"
    );
    assert_eq!(
        read_all_vfs(&vfs, 1, "/mnt/pkg/pkgdata/blob.bin").unwrap(),
        big_payload
    );

    // Every mutation on mounted `.cowpack` fails `EROFS`!
    assert_eq!(
        run(vfs.openat(
            1,
            StartAnchor::Root,
            "/mnt/pkg/new.txt",
            abi::O_WRONLY | abi::O_CREAT,
            0o644
        ))
        .unwrap_err(),
        Errno::EROFS
    );
    assert_eq!(
        run(vfs.unlinkat(1, StartAnchor::Root, "/mnt/pkg/pkgdata/manifest.txt", false))
            .unwrap_err(),
        Errno::EROFS
    );

    // Detach while mounted -> `EBUSY`!
    assert_eq!(
        run(loop_reg.ioctl_fd(&vfs, 1, loop0_fd, loop_ioctl::LOOP_CLR_FD, b"")).unwrap_err(),
        Errno::EBUSY
    );

    // Unmount -> detach succeeds -> subsequent `LOOP_GET_STATUS64` returns `ENXIO`!
    run(vfs.umount2(1, "/mnt/pkg", 0)).unwrap();
    run(loop_reg.ioctl_fd(&vfs, 1, loop0_fd, loop_ioctl::LOOP_CLR_FD, b"")).unwrap();
    assert_eq!(
        run(loop_reg.ioctl_fd(&vfs, 1, loop0_fd, loop_ioctl::LOOP_GET_STATUS64, b"")).unwrap_err(),
        Errno::ENXIO
    );
    run(vfs.close(1, loop0_fd)).unwrap();

    // C-09: Corruption detection on `.cowpack` (header, pack data block, index, footer)!
    let header_flip_off = 0usize;
    let block_flip_off = 32usize; // inside first COWP pack payload
    let footer_flip_off = archive_bytes.len() - 4;
    let index_flip_off = archive_bytes.len() - 104;
    for (label, off) in [
        ("header", header_flip_off),
        ("data-block", block_flip_off),
        ("index", index_flip_off),
        ("footer", footer_flip_off),
    ] {
        let mut bad = archive_bytes.clone();
        bad[off] ^= 0x01;
        let rep = run(verify_archive_file(
            Rc::new(SliceArchiveReader(Rc::new(bad.clone()))),
            label,
        ))
        .unwrap();
        assert!(
            !rep.ok && !rep.errors.is_empty(),
            "bit-flip in {label} must fail verify_archive_file: {rep:?}"
        );

        // If header/index are intact (data-block bit-flip), mounting succeeds lazily and reading
        // the corrupted file MUST return `Errno::EIO` (never silently return corrupted bytes)!
        if label == "data-block" {
            let bad_fs = run(open_archive_cowfs(
                Rc::new(SliceArchiveReader(Rc::new(bad))),
                "bad-loop".into(),
                CowFsConfig::local_native(Rc::clone(&clock)),
            ))
            .unwrap();
            let dir_ent = run(bad_fs.lookup(&Cred::root(), &bad_fs.root(), "pkgdata")).unwrap();
            let blob_ent = run(bad_fs.lookup(&Cred::root(), &dir_ent.handle, "blob.bin")).unwrap();
            let open = run(bad_fs.open(
                &Cred::root(),
                &blob_ent.handle,
                OpenOptions::new().read(true),
            ))
            .unwrap();
            let mut buf = vec![0u8; 64 * 1024];
            assert_eq!(
                run(bad_fs.read_at(&open, &mut buf, 0)).unwrap_err(),
                Errno::EIO
            );
            run(bad_fs.release(&open)).unwrap();
            run(bad_fs.close_clean()).unwrap();
        }
    }

    run(vfs.close(1, root_dir_fd)).unwrap();
    run(root_fs.close_clean()).unwrap();
}
