//! Comprehensive L2 integration tests (#51, #52, #53 under #44):
//! mounts, provider lifecycles, mount namespaces, user-mount ceilings, `chroot`, `/proc`
//! inspection/magic links, `ImageFs`/`ShareFs`/`DevTmpFs`/`DevPtsFs`/`MemFs` drivers, and `#!`
//! shebang + `PATH` executable resolution.

use abi::Errno;
use abi::contract::{fs_magic, mount_flags, statfs_flags, umount_flags, unshare_flags};
use os_vfs::devfs::{DefaultDeviceBackend, DevPtsFs, DevTmpFs};
use os_vfs::imagefs::{BuildAssetSizes, ImageEntry, ImageFs, ImageNodeKind, MemoryBlobStore};
use os_vfs::memfs::{MemFs, TmpfsOptions};
use os_vfs::procfs::{ProcDynamicEntry, ProcFs, ProcProvider};
use os_vfs::sharefs::{LoopbackShareTransport, ShareError, ShareFs};
use os_vfs::{
    BoxFuture, Conflict, Cred, DefaultFilesystemFactory, DirEntry, Entry, FileRef, FileType,
    Filesystem, FsId, FsType, Handle, Identity, LockFamily, LockKind, LockRange, Metadata,
    MountBacking, MountFlags, MountedFs, OpenOptions, OpenRef, ProviderHealth, ProviderState,
    RenameFlags, SeekFrom, SetAttr, StartAnchor, StatFs, Timespec, Vfs, Walked, WriteAt, Written,
    XattrFlags, now_or_never, profiles,
};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

const WASM_BIN: &[u8] = b"\0asm\x01\x00\x00\x00";

fn run<F: Future>(fut: F) -> F::Output {
    now_or_never(fut).expect("test future must resolve synchronously")
}

fn user_cred(uid: u32, gid: u32) -> Cred {
    Cred::new(Identity {
        id: uid,
        group: gid,
        groups: BTreeSet::from([gid]),
    })
}

struct TestEnv {
    vfs: Vfs,
    factory: Rc<DefaultFilesystemFactory>,
    devpts: Rc<DevPtsFs>,
}

fn boot_env() -> TestEnv {
    let clock: Rc<dyn Fn() -> (u64, u32)> = Rc::new(|| (1_700_000_000, 0));
    let factory = Rc::new(DefaultFilesystemFactory::new(Rc::clone(&clock)));
    let root_fs = Rc::new(MemFs::new(
        FsId("cloud:root".into()),
        1,
        0,
        0,
        0o755,
        Box::new(|| (1_700_000_000, 0)),
    ));
    let root_backing = Rc::new(MountBacking::new(root_fs, FsType::Cloud));
    let vfs = run(Vfs::boot(
        "inst-l2-test",
        root_backing,
        "cloud",
        factory.clone(),
    ))
    .unwrap();

    // Seed standard directories on `/` (`proc`, `dev`, `usr`, `mnt`, `opt`, `tmp`, `etc`, `bin`).
    for dir in [
        "/proc",
        "/dev",
        "/usr",
        "/mnt",
        "/mnt/local",
        "/mnt/shared",
        "/opt",
        "/opt/private",
        "/tmp",
        "/etc",
    ] {
        let mode = if dir == "/tmp" { 0o1777 } else { 0o755 };
        run(vfs.mkdirat(1, StartAnchor::Root, dir, mode)).unwrap();
        if mode == 0o1777 {
            run(vfs.setattrat(
                1,
                StartAnchor::Root,
                dir,
                &SetAttr {
                    mode: Some(0o1777),
                    ..SetAttr::default()
                },
                true,
            ))
            .unwrap();
        }
    }
    run(vfs.symlinkat(1, "usr/bin", StartAnchor::Root, "/bin")).unwrap();

    // Mount `/proc`, `/dev`, `/dev/pts`, and `/mnt/local` tmpfs carrier.
    let proc_fs = Rc::new(ProcFs::local(
        FsId("proc:1".into()),
        Timespec {
            sec: 1_700_000_000,
            nsec: 0,
        },
    ));
    proc_fs.bind_bridge(vfs.proc_bridge());
    let proc_backing = Rc::new(MountBacking::new(proc_fs, FsType::Proc));
    let sys_ns = vfs.system_namespace();
    run(vfs.mount_on_namespace(
        &sys_ns,
        &Cred::root(),
        proc_backing,
        None,
        "proc",
        "/proc",
        MountFlags::from_accepted(
            mount_flags::MS_NOSUID | mount_flags::MS_NODEV | mount_flags::MS_NOEXEC,
        ),
        0,
        None,
    ))
    .unwrap();

    let dev_fs = Rc::new(DevTmpFs::new(
        FsId("devtmpfs:1".into()),
        1,
        Box::new(|| (1_700_000_000, 0)),
        DefaultDeviceBackend,
    ));
    let dev_backing = Rc::new(MountBacking::new(dev_fs, FsType::DevTmpFs));
    run(vfs.mount_on_namespace(
        &sys_ns,
        &Cred::root(),
        dev_backing,
        None,
        "devtmpfs",
        "/dev",
        MountFlags::from_accepted(mount_flags::MS_NOSUID),
        0,
        None,
    ))
    .unwrap();

    let devpts = Rc::new(DevPtsFs::with_default_backend(
        FsId("devpts:1".into()),
        1,
        Box::new(|| (1_700_000_000, 0)),
    ));
    let devpts_backing = Rc::new(MountBacking::new(devpts.clone(), FsType::DevPts));
    run(vfs.mount_on_namespace(
        &sys_ns,
        &Cred::root(),
        devpts_backing,
        None,
        "devpts",
        "/dev/pts",
        MountFlags::from_accepted(mount_flags::MS_NOSUID | mount_flags::MS_NOEXEC),
        0,
        None,
    ))
    .unwrap();

    TestEnv {
        vfs,
        factory,
        devpts,
    }
}

fn write_all(vfs: &Vfs, pid: u32, path: &str, mode: u16, bytes: &[u8]) {
    let fd = run(vfs.openat(
        pid,
        StartAnchor::AtFdCwd,
        path,
        abi::O_CREAT | abi::O_TRUNC | abi::O_WRONLY,
        mode,
    ))
    .unwrap();
    let n = run(vfs.write(pid, fd, bytes)).unwrap();
    assert_eq!(n, bytes.len());
    run(vfs.close(pid, fd)).unwrap();
}

fn read_all(vfs: &Vfs, pid: u32, path: &str) -> Result<Vec<u8>, Errno> {
    let fd = run(vfs.openat(pid, StartAnchor::AtFdCwd, path, abi::O_RDONLY, 0))?;
    let mut out = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        let res = run(vfs.read(pid, fd, &mut buf));
        match res {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) => {
                let _ = run(vfs.close(pid, fd));
                return Err(e);
            }
        }
    }
    run(vfs.close(pid, fd))?;
    Ok(out)
}

// -----------------------------------------------------------------------------
// 1. Contract §5 FsTypes, MountFlags, Propagation EINVAL, Tmpfs Options & StatFs
// -----------------------------------------------------------------------------

#[test]
fn fs_types_mount_flags_propagation_and_tmpfs_options() {
    for (name, expected, magic, user_ok) in [
        ("cloud", FsType::Cloud, fs_magic::OS_CLOUD_MAGIC, false),
        ("opfs", FsType::Opfs, fs_magic::FUSE_SUPER_MAGIC, true),
        ("hostfs", FsType::HostFs, fs_magic::FUSE_SUPER_MAGIC, true),
        (
            "helperfs",
            FsType::HelperFs,
            fs_magic::FUSE_SUPER_MAGIC,
            true,
        ),
        ("sharefs", FsType::ShareFs, fs_magic::FUSE_SUPER_MAGIC, true),
        ("image", FsType::Image, fs_magic::SQUASHFS_MAGIC, true),
        ("tmpfs", FsType::TmpFs, fs_magic::TMPFS_MAGIC, false),
        ("proc", FsType::Proc, fs_magic::PROC_SUPER_MAGIC, false),
        (
            "devtmpfs",
            FsType::DevTmpFs,
            fs_magic::DEVTMPFS_MAGIC,
            false,
        ),
        (
            "devpts",
            FsType::DevPts,
            fs_magic::DEVPTS_SUPER_MAGIC,
            false,
        ),
    ] {
        let parsed = FsType::parse(name).unwrap();
        assert_eq!(parsed, expected);
        assert_eq!(parsed.as_str(), name);
        assert_eq!(parsed.magic(), magic);
        assert_eq!(parsed.is_user_mountable(), user_ok);
    }

    for bad in ["sysfs", "", "ext4", "overlay", "TMPFS"] {
        assert_eq!(FsType::parse(bad), Err(Errno::ENODEV), "for {bad}");
    }

    let env = boot_env();
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/mnt/t", 0o755)).unwrap();

    // Unknown fstypes including "sysfs" -> ENODEV; missing fstype -> EINVAL.
    assert_eq!(
        run(env.vfs.mount(1, "sysfs", "/mnt/t", Some("sysfs"), 0, None)),
        Err(Errno::ENODEV)
    );
    assert_eq!(
        run(env.vfs.mount(1, "none", "/mnt/t", None, 0, None)),
        Err(Errno::EINVAL)
    );

    // Unsupported propagation modes -> EINVAL.
    for prop in [
        mount_flags::MS_SHARED,
        mount_flags::MS_SLAVE,
        mount_flags::MS_UNBINDABLE,
        0xDEAD_0000,
    ] {
        assert_eq!(
            run(env
                .vfs
                .mount(1, "tmpfs", "/mnt/t", Some("tmpfs"), prop, None)),
            Err(Errno::EINVAL)
        );
    }

    // Legacy MS_MGC_VAL + MS_SILENT + MS_PRIVATE + tmpfs options (mode, uid, gid, size).
    run(env.vfs.mount(
        1,
        "scratch",
        "/mnt/t",
        Some("tmpfs"),
        mount_flags::MS_MGC_VAL
            | mount_flags::MS_SILENT
            | mount_flags::MS_PRIVATE
            | mount_flags::MS_NOSUID
            | mount_flags::MS_NOATIME,
        Some("mode=0750,uid=1001,gid=1002,size=8k"),
    ))
    .unwrap();

    // Standalone `--make-private` succeeds on a mountpoint and fails with EINVAL on a non-mountpoint.
    run(env
        .vfs
        .mount(1, "", "/mnt/t", None, mount_flags::MS_PRIVATE, None))
    .unwrap();
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/mnt/t/sub", 0o755)).unwrap();
    assert_eq!(
        run(env
            .vfs
            .mount(1, "", "/mnt/t/sub", None, mount_flags::MS_PRIVATE, None)),
        Err(Errno::EINVAL)
    );

    let st = run(env.vfs.statat(1, StartAnchor::Root, "/mnt/t", true)).unwrap();
    assert_eq!(st.mode & 0o7777, 0o750);
    assert_eq!((st.uid, st.gid), (1001, 1002));

    let sfs = run(env.vfs.statfs(1, StartAnchor::Root, "/mnt/t")).unwrap();
    assert_eq!(sfs.f_type, fs_magic::TMPFS_MAGIC);
    assert_eq!(sfs.fstype, "tmpfs");
    assert_eq!(sfs.blocks, 2); // 8 KiB = 2 * 4096 pages
    assert_ne!(sfs.flags & statfs_flags::ST_NOSUID, 0);
    assert_ne!(sfs.flags & statfs_flags::ST_NOATIME, 0);

    // Writing past 8 KiB capacity fails with ENOSPC or short write then ENOSPC.
    let fd = run(env.vfs.openat(
        1,
        StartAnchor::Root,
        "/mnt/t/big",
        abi::O_CREAT | abi::O_WRONLY,
        0o644,
    ))
    .unwrap();
    let f_sfs = run(env.vfs.fstatfs(1, fd)).unwrap();
    assert_eq!(f_sfs.fsid, sfs.fsid);
    assert_eq!(run(env.vfs.write(1, fd, &[b'x'; 8192])).unwrap(), 8192);
    assert_eq!(run(env.vfs.write(1, fd, b"overflow")), Err(Errno::ENOSPC));
    run(env.vfs.close(1, fd)).unwrap();

    // Invalid tmpfs mount options -> EINVAL.
    for bad_opt in [
        "unknown=1",
        "mode=9999",
        "mode=17777",
        "uid=abc",
        "size=xyz",
        "bare",
    ] {
        assert_eq!(
            TmpfsOptions::parse(&Cred::root(), Some(bad_opt)),
            Err(Errno::EINVAL),
            "expected EINVAL for {bad_opt}"
        );
    }
}

// -----------------------------------------------------------------------------
// 2. Stacked Mounts & Mountpoint EBUSY Protection on Unlink/Rmdir/Rename
// -----------------------------------------------------------------------------

#[test]
fn stacked_mounts_and_mountpoint_mutation_ebusy() {
    let env = boot_env();
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/mnt/stack", 0o755)).unwrap();
    write_all(&env.vfs, 1, "/mnt/stack/under.txt", 0o644, b"under");

    // Mount layer A over /mnt/stack.
    run(env
        .vfs
        .mount(1, "layer-a", "/mnt/stack", Some("tmpfs"), 0, None))
    .unwrap();
    assert_eq!(
        read_all(&env.vfs, 1, "/mnt/stack/under.txt"),
        Err(Errno::ENOENT)
    );
    write_all(&env.vfs, 1, "/mnt/stack/a.txt", 0o644, b"from-a");

    // Mount layer B on top of layer A at /mnt/stack.
    run(env
        .vfs
        .mount(1, "layer-b", "/mnt/stack", Some("tmpfs"), 0, None))
    .unwrap();
    assert_eq!(
        read_all(&env.vfs, 1, "/mnt/stack/a.txt"),
        Err(Errno::ENOENT)
    );
    write_all(&env.vfs, 1, "/mnt/stack/b.txt", 0o644, b"from-b");
    assert_eq!(
        read_all(&env.vfs, 1, "/mnt/stack/b.txt").unwrap(),
        b"from-b"
    );

    // Mountpoint cannot be rmdir'd, unlinked, renamed away, or overwritten by rename -> EBUSY.
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/mnt/other", 0o755)).unwrap();
    assert_eq!(
        run(env.vfs.unlinkat(1, StartAnchor::Root, "/mnt/stack", true)),
        Err(Errno::EBUSY)
    );
    assert_eq!(
        run(env.vfs.renameat(
            1,
            StartAnchor::Root,
            "/mnt/stack",
            StartAnchor::Root,
            "/mnt/moved",
            RenameFlags::empty(),
        )),
        Err(Errno::EBUSY)
    );
    assert_eq!(
        run(env.vfs.renameat(
            1,
            StartAnchor::Root,
            "/mnt/other",
            StartAnchor::Root,
            "/mnt/stack",
            RenameFlags::empty(),
        )),
        Err(Errno::EBUSY)
    );

    // Unmount B -> A reappears; unmount A -> underlying `/` reappears!
    run(env.vfs.umount2(1, "/mnt/stack", 0)).unwrap();
    assert_eq!(
        read_all(&env.vfs, 1, "/mnt/stack/a.txt").unwrap(),
        b"from-a"
    );
    run(env.vfs.umount2(1, "/mnt/stack", 0)).unwrap();
    assert_eq!(
        read_all(&env.vfs, 1, "/mnt/stack/under.txt").unwrap(),
        b"under"
    );
}

// -----------------------------------------------------------------------------
// 3. Bind Mounts (Dir & File), Self-Descendant MS_REC, and Cross-MountId EXDEV
// -----------------------------------------------------------------------------

#[test]
fn bind_mounts_file_bind_self_descendant_rbind_and_exdev() {
    let env = boot_env();
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/dir", 0o755)).unwrap();
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/dir/sub", 0o755)).unwrap();
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/dir/child", 0o755)).unwrap();
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/bind", 0o755)).unwrap();
    write_all(&env.vfs, 1, "/dir/hello.txt", 0o644, b"shared-inode");

    // Mount a submount at /dir/child before rbind.
    run(env
        .vfs
        .mount(1, "child-tmp", "/dir/child", Some("tmpfs"), 0, None))
    .unwrap();
    write_all(
        &env.vfs,
        1,
        "/dir/child/in_child.txt",
        0o644,
        b"submount-data",
    );

    // Plain MS_BIND (without MS_REC) binds /dir -> /bind without copying /dir/child submount.
    run(env
        .vfs
        .mount(1, "/dir", "/bind", None, mount_flags::MS_BIND, None))
    .unwrap();
    assert_eq!(
        read_all(&env.vfs, 1, "/bind/hello.txt").unwrap(),
        b"shared-inode"
    );
    assert_eq!(
        read_all(&env.vfs, 1, "/bind/child/in_child.txt"),
        Err(Errno::ENOENT)
    );

    // Cross-MountId rename & link between /dir and /bind MUST fail with EXDEV even though both
    // point into the exact same underlying `Filesystem`!
    assert_eq!(
        run(env.vfs.renameat(
            1,
            StartAnchor::Root,
            "/dir/hello.txt",
            StartAnchor::Root,
            "/bind/moved.txt",
            RenameFlags::empty(),
        )),
        Err(Errno::EXDEV)
    );
    assert_eq!(
        run(env.vfs.linkat(
            1,
            StartAnchor::Root,
            "/dir/hello.txt",
            StartAnchor::Root,
            "/bind/hard.txt",
            false,
        )),
        Err(Errno::EXDEV)
    );

    // Self-descendant `mount --rbind /dir /dir/sub` MUST terminate cleanly and clone `/dir/child`!
    run(env.vfs.mount(
        1,
        "/dir",
        "/dir/sub",
        None,
        mount_flags::MS_BIND | mount_flags::MS_REC,
        None,
    ))
    .unwrap();
    assert_eq!(
        read_all(&env.vfs, 1, "/dir/sub/hello.txt").unwrap(),
        b"shared-inode"
    );
    assert_eq!(
        read_all(&env.vfs, 1, "/dir/sub/child/in_child.txt").unwrap(),
        b"submount-data"
    );

    // File-on-file bind mount works; dir-on-file and file-on-dir fail with ENOTDIR.
    write_all(&env.vfs, 1, "/etc/hosts", 0o644, b"127.0.0.1 localhost\n");
    write_all(&env.vfs, 1, "/tmp/hosts_target", 0o644, b"");
    assert_eq!(
        run(env.vfs.mount(
            1,
            "/dir",
            "/tmp/hosts_target",
            None,
            mount_flags::MS_BIND,
            None,
        )),
        Err(Errno::ENOTDIR)
    );
    assert_eq!(
        run(env
            .vfs
            .mount(1, "/etc/hosts", "/bind", None, mount_flags::MS_BIND, None)),
        Err(Errno::ENOTDIR)
    );
    run(env.vfs.mount(
        1,
        "/etc/hosts",
        "/tmp/hosts_target",
        None,
        mount_flags::MS_BIND,
        None,
    ))
    .unwrap();
    assert_eq!(
        read_all(&env.vfs, 1, "/tmp/hosts_target").unwrap(),
        b"127.0.0.1 localhost\n"
    );
    assert_eq!(
        run(env
            .vfs
            .unlinkat(1, StartAnchor::Root, "/tmp/hosts_target", false)),
        Err(Errno::EBUSY)
    );
    run(env.vfs.umount2(1, "/tmp/hosts_target", 0)).unwrap();
}

// -----------------------------------------------------------------------------
// 4. MS_MOVE & Contract §5 `switch_root` Sequence
// -----------------------------------------------------------------------------

#[test]
fn ms_move_and_switch_root_sequence() {
    let env = boot_env();
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/mnt/a", 0o755)).unwrap();
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/mnt/b", 0o755)).unwrap();
    run(env
        .vfs
        .mount(1, "movable", "/mnt/a", Some("tmpfs"), 0, None))
    .unwrap();
    run(env
        .vfs
        .mkdirat(1, StartAnchor::Root, "/mnt/a/inside", 0o755))
    .unwrap();
    write_all(&env.vfs, 1, "/mnt/a/keep.txt", 0o644, b"moved-ok");

    // Moving `/` or moving a mount into its own subtree fails with EINVAL.
    assert_eq!(
        run(env
            .vfs
            .mount(1, "/", "/mnt/b", None, mount_flags::MS_MOVE, None)),
        Err(Errno::EINVAL)
    );
    assert_eq!(
        run(env.vfs.mount(
            1,
            "/mnt/a",
            "/mnt/a/inside",
            None,
            mount_flags::MS_MOVE,
            None,
        )),
        Err(Errno::EINVAL)
    );

    // Move `/mnt/a` -> `/mnt/b`.
    run(env
        .vfs
        .mount(1, "/mnt/a", "/mnt/b", None, mount_flags::MS_MOVE, None))
    .unwrap();
    assert_eq!(read_all(&env.vfs, 1, "/mnt/a/keep.txt"), Err(Errno::ENOENT));
    assert_eq!(
        read_all(&env.vfs, 1, "/mnt/b/keep.txt").unwrap(),
        b"moved-ok"
    );
    run(env.vfs.umount2(1, "/mnt/b", 0)).unwrap();

    // Full `switch_root` sequence (`contract.md` §5):
    write_all(&env.vfs, 1, "/initramfs_marker", 0o644, b"ephemeral");
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/sysroot", 0o755)).unwrap();
    run(env
        .vfs
        .mount(1, "newroot", "/sysroot", Some("tmpfs"), 0, None))
    .unwrap();
    run(env
        .vfs
        .mkdirat(1, StartAnchor::Root, "/sysroot/proc", 0o555))
    .unwrap();
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/sysroot/dev", 0o755)).unwrap();
    write_all(&env.vfs, 1, "/sysroot/real_root", 0o644, b"switched");

    // 1. Open initial root as a descriptor.
    let old_root_fd = run(env.vfs.openat(
        1,
        StartAnchor::Root,
        "/",
        abi::O_RDONLY | abi::O_DIRECTORY,
        0,
    ))
    .unwrap();
    // 2. Move `/proc` and `/dev` (with its `/dev/pts` child!) onto `/sysroot`.
    run(env.vfs.mount(
        1,
        "/proc",
        "/sysroot/proc",
        None,
        mount_flags::MS_MOVE,
        None,
    ))
    .unwrap();
    run(env
        .vfs
        .mount(1, "/dev", "/sysroot/dev", None, mount_flags::MS_MOVE, None))
    .unwrap();
    // 3. `chdir("/sysroot")`, `mount(".", "/", MS_MOVE)`, `chroot(".")`.
    run(env.vfs.chdir(1, "/sysroot")).unwrap();
    run(env.vfs.mount(1, ".", "/", None, mount_flags::MS_MOVE, None)).unwrap();
    run(env.vfs.chroot(1, ".")).unwrap();

    assert_eq!(run(env.vfs.getcwd(1)).unwrap(), "/");
    assert_eq!(read_all(&env.vfs, 1, "/real_root").unwrap(), b"switched");
    assert_eq!(
        read_all(&env.vfs, 1, "/initramfs_marker"),
        Err(Errno::ENOENT)
    );
    // Moved `/proc` and `/dev` are live in the switched root!
    let mi = String::from_utf8(read_all(&env.vfs, 1, "/proc/self/mountinfo").unwrap()).unwrap();
    assert!(
        mi.contains(" / rw,relatime - tmpfs newroot ")
            && mi.contains(" /proc rw,nosuid,nodev,noexec,relatime - proc ")
            && mi.contains(" /dev/pts rw,nosuid,noexec,relatime - devpts "),
        "mountinfo after switch_root: {mi}"
    );
    let mtab = String::from_utf8(read_all(&env.vfs, 1, "/proc/mounts").unwrap()).unwrap();
    assert!(mtab.contains("newroot / tmpfs ") && mtab.contains("devpts /dev/pts devpts "));

    // 4. Clean up initial root's contents through `old_root_fd`, then close it.
    run(env.vfs.unlinkat(
        1,
        StartAnchor::DirFd(old_root_fd),
        "initramfs_marker",
        false,
    ))
    .unwrap();
    run(env.vfs.close(1, old_root_fd)).unwrap();
}

// -----------------------------------------------------------------------------
// 5. Remount, Writable-Open EBUSY, MS_RDONLY/NOEXEC/NOSUID/NODEV/NOSYMFOLLOW/SYNC,
//    Sticky-Dir Symlink Protection & MAXSYMLINKS
// -----------------------------------------------------------------------------

#[test]
fn remount_flags_enforcement_sticky_links_and_maxsymlinks() {
    let env = boot_env();
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/rw_src", 0o755)).unwrap();
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/ro_view", 0o755)).unwrap();
    write_all(&env.vfs, 1, "/rw_src/bin.wasm", 0o4755, WASM_BIN);
    run(env.vfs.setattrat(
        1,
        StartAnchor::Root,
        "/rw_src/bin.wasm",
        &SetAttr {
            mode: Some(0o4755),
            ..SetAttr::default()
        },
        true,
    ))
    .unwrap();
    run(env
        .vfs
        .mknodat(1, StartAnchor::Root, "/rw_src/zero_dev", 0o666, "zero"))
    .unwrap();
    run(env
        .vfs
        .symlinkat(1, "bin.wasm", StartAnchor::Root, "/rw_src/sym"))
    .unwrap();

    run(env
        .vfs
        .mount(1, "/rw_src", "/ro_view", None, mount_flags::MS_BIND, None))
    .unwrap();

    // Open writable fd on `/ro_view` -> remount `ro` MUST fail with EBUSY until closed!
    let wfd = run(env
        .vfs
        .openat(1, StartAnchor::Root, "/ro_view/bin.wasm", abi::O_RDWR, 0))
    .unwrap();
    let rfd = run(env
        .vfs
        .openat(1, StartAnchor::Root, "/ro_view/bin.wasm", abi::O_RDONLY, 0))
    .unwrap();
    assert_eq!(
        run(env.vfs.mount(
            1,
            "",
            "/ro_view",
            None,
            mount_flags::MS_REMOUNT | mount_flags::MS_BIND | mount_flags::MS_RDONLY,
            None,
        )),
        Err(Errno::EBUSY)
    );
    run(env.vfs.close(1, wfd)).unwrap();

    // Read-only fd does NOT block `remount,ro`! Add NOEXEC | NOSUID | NODEV | NOSYMFOLLOW.
    run(env.vfs.mount(
        1,
        "",
        "/ro_view",
        None,
        mount_flags::MS_REMOUNT
            | mount_flags::MS_BIND
            | mount_flags::MS_RDONLY
            | mount_flags::MS_NOEXEC
            | mount_flags::MS_NOSUID
            | mount_flags::MS_NODEV
            | mount_flags::MS_NOSYMFOLLOW,
        None,
    ))
    .unwrap();
    run(env.vfs.close(1, rfd)).unwrap();

    // EROFS across all mutations on `/ro_view`, while `/rw_src` remains writable!
    assert_eq!(
        run(env
            .vfs
            .openat(1, StartAnchor::Root, "/ro_view/bin.wasm", abi::O_WRONLY, 0)),
        Err(Errno::EROFS)
    );
    assert_eq!(
        run(env.vfs.openat(
            1,
            StartAnchor::Root,
            "/ro_view/new",
            abi::O_CREAT | abi::O_WRONLY,
            0o644,
        )),
        Err(Errno::EROFS)
    );
    assert_eq!(
        run(env.vfs.openat(
            1,
            StartAnchor::Root,
            "/ro_view/bin.wasm",
            abi::O_RDONLY | abi::O_TRUNC,
            0,
        )),
        Err(Errno::EROFS)
    );
    assert_eq!(
        run(env.vfs.mkdirat(1, StartAnchor::Root, "/ro_view/sub", 0o755)),
        Err(Errno::EROFS)
    );
    assert_eq!(
        run(env
            .vfs
            .unlinkat(1, StartAnchor::Root, "/ro_view/bin.wasm", false)),
        Err(Errno::EROFS)
    );
    assert_eq!(
        run(env.vfs.setattrat(
            1,
            StartAnchor::Root,
            "/ro_view/bin.wasm",
            &SetAttr {
                mode: Some(0o755),
                ..SetAttr::default()
            },
            true,
        )),
        Err(Errno::EROFS)
    );
    assert_eq!(
        run(env
            .vfs
            .accessat(1, StartAnchor::Root, "/ro_view/bin.wasm", abi::W_OK, true)),
        Err(Errno::EROFS)
    );
    // Underlying `/rw_src` is still rw!
    write_all(&env.vfs, 1, "/rw_src/still_rw", 0o644, b"ok");

    // MS_NOEXEC -> EACCES on exec and access(X_OK).
    assert_eq!(
        run(env
            .vfs
            .resolve_exec(1, "/ro_view/bin.wasm", vec![], None, false))
        .err(),
        Some(Errno::EACCES)
    );
    assert_eq!(
        run(env
            .vfs
            .accessat(1, StartAnchor::Root, "/ro_view/bin.wasm", abi::X_OK, true)),
        Err(Errno::EACCES)
    );

    // MS_NODEV -> EACCES on opening character device, while stat and O_PATH succeed.
    assert!(
        run(env
            .vfs
            .statat(1, StartAnchor::Root, "/ro_view/zero_dev", true))
        .is_ok()
    );
    assert_eq!(
        run(env
            .vfs
            .openat(1, StartAnchor::Root, "/ro_view/zero_dev", abi::O_RDONLY, 0)),
        Err(Errno::EACCES)
    );
    let path_fd = run(env
        .vfs
        .openat(1, StartAnchor::Root, "/ro_view/zero_dev", abi::O_PATH, 0))
    .unwrap();
    run(env.vfs.close(1, path_fd)).unwrap();

    // MS_NOSYMFOLLOW -> ELOOP when following symlink, while lstat and readlink succeed!
    assert_eq!(
        run(env.vfs.statat(1, StartAnchor::Root, "/ro_view/sym", true)),
        Err(Errno::ELOOP)
    );
    assert!(
        run(env.vfs.statat(1, StartAnchor::Root, "/ro_view/sym", false))
            .unwrap()
            .mode
            & abi::S_IFMT
            == abi::S_IFLNK
    );
    assert_eq!(
        run(env.vfs.readlinkat(1, StartAnchor::Root, "/ro_view/sym")).unwrap(),
        "bin.wasm"
    );

    // Remount removing NOEXEC (keeping NOSUID) -> `resolve_exec` succeeds with `nosuid: true`!
    run(env.vfs.mount(
        1,
        "",
        "/ro_view",
        None,
        mount_flags::MS_REMOUNT | mount_flags::MS_RDONLY | mount_flags::MS_NOSUID,
        None,
    ))
    .unwrap();
    let exec_res =
        run(env
            .vfs
            .resolve_exec(1, "/ro_view/bin.wasm", vec!["bin".into()], None, false))
        .unwrap();
    assert!(exec_res.nosuid);
    run(exec_res.file.close()).unwrap();

    // MS_SYNCHRONOUS & MS_DIRSYNC record durability syncs.
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/mnt/sync", 0o755)).unwrap();
    run(env.vfs.mount(
        1,
        "sync-tmp",
        "/mnt/sync",
        Some("tmpfs"),
        mount_flags::MS_SYNCHRONOUS | mount_flags::MS_DIRSYNC,
        None,
    ))
    .unwrap();
    write_all(&env.vfs, 1, "/mnt/sync/f", 0o644, b"durable");
    let sync_cnt = env
        .vfs
        .system_namespace()
        .borrow()
        .mounts()
        .values()
        .find(|m| m.source == "sync-tmp")
        .unwrap()
        .slot
        .backing
        .sync_count();
    assert!(sync_cnt >= 2);

    // Sticky-directory protected symlinks (`may_follow_link -> EACCES`) & `MAXSYMLINKS` (`40 -> ELOOP`).
    write_all(&env.vfs, 1, "/etc/secret", 0o644, b"public-readable");
    env.vfs
        .spawn_process(10, 1, user_cred(1001, 1001), None, None, None)
        .unwrap();
    env.vfs
        .spawn_process(11, 1, user_cred(1002, 1002), None, None, None)
        .unwrap();
    // Mallory (1002) places a symlink in sticky world-writable `/tmp` (owned by 0).
    run(env
        .vfs
        .symlinkat(11, "/etc/secret", StartAnchor::Root, "/tmp/mallory_link"))
    .unwrap();
    // Alice (1001) is blocked from following Mallory's symlink in `/tmp` -> EACCES!
    assert_eq!(
        read_all(&env.vfs, 10, "/tmp/mallory_link"),
        Err(Errno::EACCES)
    );
    // Mallory herself and root CAN follow it.
    assert_eq!(
        read_all(&env.vfs, 11, "/tmp/mallory_link").unwrap(),
        b"public-readable"
    );

    // 41-symlink chain -> ELOOP, whereas 40-symlink chain succeeds!
    write_all(&env.vfs, 1, "/tmp/chain_target", 0o644, b"end");
    let mut prev = "chain_target".to_string();
    for i in 1..=41 {
        let name = format!("/tmp/hop_{i}");
        run(env.vfs.symlinkat(1, &prev, StartAnchor::Root, &name)).unwrap();
        prev = format!("hop_{i}");
    }
    assert_eq!(read_all(&env.vfs, 1, "/tmp/hop_40").unwrap(), b"end");
    assert_eq!(read_all(&env.vfs, 1, "/tmp/hop_41"), Err(Errno::ELOOP));
}

// -----------------------------------------------------------------------------
// 6. All 4 Unmount / Provider Endings & Cross-Namespace Detach Independence
// -----------------------------------------------------------------------------

struct PendingFs {
    inner: Rc<MemFs>,
    block_reads: Cell<bool>,
    block_writes: Cell<bool>,
    wakers: RefCell<Vec<Waker>>,
}

impl PendingFs {
    fn new(id: &str) -> Self {
        Self {
            inner: Rc::new(MemFs::new(
                FsId(id.into()),
                1,
                0,
                0,
                0o777,
                Box::new(|| (1_700_000_000, 0)),
            )),
            block_reads: Cell::new(false),
            block_writes: Cell::new(false),
            wakers: RefCell::new(Vec::new()),
        }
    }
}

struct ParkFuture<'a> {
    flag: &'a Cell<bool>,
    wakers: &'a RefCell<Vec<Waker>>,
}

impl Future for ParkFuture<'_> {
    type Output = ();
    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.flag.get() {
            self.wakers.borrow_mut().push(cx.waker().clone());
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    }
}

impl Filesystem for PendingFs {
    fn id(&self) -> &FsId {
        self.inner.id()
    }
    fn capabilities(&self) -> abi::contract::FsCapabilities {
        profiles::HELPER
    }
    fn root(&self) -> Handle {
        self.inner.root()
    }
    fn lookup<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Entry> {
        self.inner.lookup(cred, dir, name)
    }
    fn walk<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        names: &'a [String],
    ) -> BoxFuture<'a, Walked> {
        self.inner.walk(cred, dir, names)
    }
    fn parent<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
    ) -> BoxFuture<'a, Option<(Entry, String)>> {
        self.inner.parent(cred, dir)
    }
    fn metadata<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Metadata> {
        self.inner.metadata(cred, handle)
    }
    fn setattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        attr: &'a SetAttr,
    ) -> BoxFuture<'a, Metadata> {
        self.inner.setattr(cred, handle, attr)
    }
    fn read_dir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle) -> BoxFuture<'a, Vec<DirEntry>> {
        self.inner.read_dir(cred, dir)
    }
    fn read_link<'a>(&'a self, cred: &'a Cred, link: &'a Handle) -> BoxFuture<'a, String> {
        self.inner.read_link(cred, link)
    }
    fn create<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
        options: &'a OpenOptions,
    ) -> BoxFuture<'a, (Entry, OpenRef)> {
        self.inner.create(cred, dir, name, mode, options)
    }
    fn mkdir<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
    ) -> BoxFuture<'a, Entry> {
        self.inner.mkdir(cred, dir, name, mode)
    }
    fn mknod<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
        rdev: &'a str,
    ) -> BoxFuture<'a, Entry> {
        self.inner.mknod(cred, dir, name, mode, rdev)
    }
    fn symlink<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        target: &'a str,
    ) -> BoxFuture<'a, Entry> {
        self.inner.symlink(cred, dir, name, target)
    }
    fn link<'a>(
        &'a self,
        cred: &'a Cred,
        target: &'a Handle,
        dir: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Entry> {
        self.inner.link(cred, target, dir, name)
    }
    fn unlink<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()> {
        self.inner.unlink(cred, dir, name)
    }
    fn rmdir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()> {
        self.inner.rmdir(cred, dir, name)
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
        self.inner.rename(cred, from_dir, from, to_dir, to, flags)
    }
    fn getxattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Vec<u8>> {
        self.inner.getxattr(cred, handle, name)
    }
    fn setxattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
        value: &'a [u8],
        flags: XattrFlags,
    ) -> BoxFuture<'a, ()> {
        self.inner.setxattr(cred, handle, name, value, flags)
    }
    fn listxattr<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Vec<String>> {
        self.inner.listxattr(cred, handle)
    }
    fn removexattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, ()> {
        self.inner.removexattr(cred, handle, name)
    }
    fn statfs<'a>(&'a self, cred: &'a Cred) -> BoxFuture<'a, StatFs> {
        self.inner.statfs(cred)
    }
    fn open<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        options: &'a OpenOptions,
    ) -> BoxFuture<'a, OpenRef> {
        self.inner.open(cred, handle, options)
    }
    fn open_metadata<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, Metadata> {
        self.inner.open_metadata(open)
    }
    fn read_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a mut [u8],
        offset: u64,
    ) -> BoxFuture<'a, usize> {
        Box::pin(async move {
            ParkFuture {
                flag: &self.block_reads,
                wakers: &self.wakers,
            }
            .await;
            self.inner.read_at(open, buf, offset).await
        })
    }
    fn write_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a [u8],
        at: WriteAt,
    ) -> BoxFuture<'a, Written> {
        Box::pin(async move {
            ParkFuture {
                flag: &self.block_writes,
                wakers: &self.wakers,
            }
            .await;
            self.inner.write_at(open, buf, at).await
        })
    }
    fn set_len<'a>(&'a self, open: &'a OpenRef, size: u64) -> BoxFuture<'a, ()> {
        self.inner.set_len(open, size)
    }
    fn sync_all<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        self.inner.sync_all(open)
    }
    fn lock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        self.inner.lock(open, family, kind, range)
    }
    fn try_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        self.inner.try_lock(open, family, kind, range)
    }
    fn unlock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        self.inner.unlock(open, family, range)
    }
    fn test_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, Option<Conflict>> {
        self.inner.test_lock(open, kind, range)
    }
    fn release<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        self.inner.release(open)
    }
}

#[test]
fn all_four_endings_and_cross_namespace_detach_independence() {
    let env = boot_env();

    // --- Ending 1 & 2: Busy EBUSY, UMOUNT_NOFOLLOW, Lazy MNT_DETACH, on_release & Cross-NS ---
    let released = Rc::new(Cell::new(false));
    let released_flag = Rc::clone(&released);
    let detach_fs = Rc::new(MemFs::new(
        FsId("tmpfs:detach".into()),
        1,
        0,
        0,
        0o755,
        Box::new(|| (1_700_000_000, 0)),
    ));
    let detach_backing = Rc::new(MountBacking::new(detach_fs, FsType::TmpFs).with_on_release(
        move || {
            released_flag.set(true);
        },
    ));
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/mnt/work", 0o755)).unwrap();
    run(env
        .vfs
        .symlinkat(1, "/mnt/work", StartAnchor::Root, "/mnt/work_link"))
    .unwrap();
    let sys_ns = env.vfs.system_namespace();
    run(env.vfs.mount_on_namespace(
        &sys_ns,
        &Cred::root(),
        detach_backing,
        None,
        "work",
        "/mnt/work",
        MountFlags::default(),
        0,
        None,
    ))
    .unwrap();
    write_all(&env.vfs, 1, "/mnt/work/doc.txt", 0o644, b"v1");

    // MNT_EXPIRE -> EINVAL; UMOUNT_NOFOLLOW on symlink -> EINVAL.
    assert_eq!(
        run(env.vfs.umount2(1, "/mnt/work", umount_flags::MNT_EXPIRE)),
        Err(Errno::EINVAL)
    );
    assert_eq!(
        run(env
            .vfs
            .umount2(1, "/mnt/work_link", umount_flags::UMOUNT_NOFOLLOW)),
        Err(Errno::EINVAL)
    );

    // Fork PID 2 in a cloned private MountNamespace (`CLONE_NEWNS`) BEFORE detaching in PID 1!
    env.vfs
        .fork_process(1, 2, unshare_flags::CLONE_NEWNS)
        .unwrap();
    run(env.vfs.chdir(2, "/mnt/work")).unwrap();
    assert_eq!(run(env.vfs.getcwd(2)).unwrap(), "/mnt/work");

    // In PID 1: open file + chdir into `/mnt/work` -> `umount2(..., 0)` fails with EBUSY!
    let held_fd = run(env
        .vfs
        .openat(1, StartAnchor::Root, "/mnt/work/doc.txt", abi::O_RDWR, 0))
    .unwrap();
    run(env.vfs.chdir(1, "/mnt/work")).unwrap();
    assert_eq!(run(env.vfs.umount2(1, "/mnt/work", 0)), Err(Errno::EBUSY));

    // Lazy detach (`MNT_DETACH`) in PID 1's namespace:
    run(env.vfs.umount2(1, "/mnt/work", umount_flags::MNT_DETACH)).unwrap();
    // Removed from PID 1's namespace immediately:
    assert_eq!(
        read_all(&env.vfs, 1, "/mnt/work/doc.txt"),
        Err(Errno::ENOENT)
    );
    // PID 1's `cwd` inside detached mount: `getcwd` -> ENOENT, `stat(".")` & relative open work,
    // and `..` clamps at detached root!
    assert_eq!(run(env.vfs.getcwd(1)), Err(Errno::ENOENT));
    assert!(run(env.vfs.statat(1, StartAnchor::AtFdCwd, ".", true)).is_ok());
    assert_eq!(read_all(&env.vfs, 1, "doc.txt").unwrap(), b"v1");
    assert_eq!(read_all(&env.vfs, 1, "../../doc.txt").unwrap(), b"v1");
    // Open `held_fd` keeps reading & writing!
    run(env.vfs.pwrite(1, held_fd, b"v2", 0)).unwrap();

    // Meanwhile in PID 2's sibling namespace: `/mnt/work` is STILL ATTACHED and `getcwd` STILL WORKS!
    assert_eq!(run(env.vfs.getcwd(2)).unwrap(), "/mnt/work");
    assert_eq!(read_all(&env.vfs, 2, "/mnt/work/doc.txt").unwrap(), b"v2");
    assert!(!released.get());

    // Release PID 1's `cwd` and `held_fd` -> backing STILL NOT released because PID 2's namespace holds it!
    run(env.vfs.chdir(1, "/")).unwrap();
    run(env.vfs.close(1, held_fd)).unwrap();
    assert!(!released.get());

    // Exit PID 2 and unmount `/mnt/work` in PID 2's namespace -> `on_release` fires!
    let ns2 = env.vfs.process_namespace(2).unwrap();
    run(env.vfs.chdir(2, "/")).unwrap();
    run(env.vfs.umount2(2, "/mnt/work", 0)).unwrap();
    run(env.vfs.exit_process(2)).unwrap();
    drop(ns2);
    assert!(released.get());

    // --- Ending 2b & 4: MNT_FORCE (`EIO`) and Provider Loss (`ENOTCONN` + `EIO` uncertain write) ---
    let pending_fs = Rc::new(PendingFs::new("helper:pending"));
    let provider = ProviderState::new();
    let pending_backing = Rc::new(
        MountBacking::new(pending_fs.clone(), FsType::HelperFs).with_provider(Rc::clone(&provider)),
    );
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/mnt/helper", 0o755)).unwrap();
    run(env.vfs.mount_on_namespace(
        &sys_ns,
        &Cred::root(),
        pending_backing,
        None,
        "helper",
        "/mnt/helper",
        MountFlags::default(),
        0,
        None,
    ))
    .unwrap();
    write_all(&env.vfs, 1, "/mnt/helper/data.bin", 0o644, b"hello");

    // Non-root `MNT_FORCE` -> EPERM.
    env.vfs
        .spawn_process(20, 1, user_cred(1001, 1001), None, None, None)
        .unwrap();
    assert_eq!(
        run(env.vfs.umount2(20, "/mnt/helper", umount_flags::MNT_FORCE)),
        Err(Errno::EPERM)
    );

    let (pfile, _) =
        run(env
            .vfs
            .open_file(1, StartAnchor::Root, "/mnt/helper/data.bin", abi::O_RDWR, 0))
        .unwrap();

    // Park an in-flight read -> `MNT_FORCE` aborts it with `EIO` (mount stays busy because `pfile` is open),
    // and once unblocked, subsequent reads succeed because `MNT_FORCE` did not disconnect the provider!
    pending_fs.block_reads.set(true);
    {
        let mut rbuf = [0u8; 5];
        let mut rfut = std::pin::pin!(pfile.read(&mut rbuf));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(rfut.as_mut().poll(&mut cx), Poll::Pending));
        assert_eq!(
            run(env.vfs.umount2(1, "/mnt/helper", umount_flags::MNT_FORCE)),
            Err(Errno::EBUSY)
        );
        assert_eq!(rfut.as_mut().poll(&mut cx), Poll::Ready(Err(Errno::EIO)));
    }
    pending_fs.block_reads.set(false);
    let mut ok_buf = [0u8; 5];
    assert_eq!(run(pfile.read_at(&mut ok_buf, 0)).unwrap(), 5);
    assert_eq!(&ok_buf, b"hello");
    assert_eq!(provider.uncertain_writes(), 0);

    // Now park BOTH an in-flight `read` AND an in-flight `write`, then trigger `provider.lose()`!
    pending_fs.block_reads.set(true);
    pending_fs.block_writes.set(true);
    {
        let mut rbuf = [0u8; 5];
        let mut rfut = std::pin::pin!(pfile.read_at(&mut rbuf, 0));
        let mut wfut = std::pin::pin!(pfile.write_at(b"world", 0));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(rfut.as_mut().poll(&mut cx), Poll::Pending));
        assert!(matches!(wfut.as_mut().poll(&mut cx), Poll::Pending));

        provider.lose();
        assert_eq!(provider.health(), ProviderHealth::Lost);

        // Read fails with `ENOTCONN` (not an uncertain write); write fails with `EIO` + uncertain write!
        assert_eq!(
            rfut.as_mut().poll(&mut cx),
            Poll::Ready(Err(Errno::ENOTCONN))
        );
        assert_eq!(provider.uncertain_writes(), 0);
        assert_eq!(wfut.as_mut().poll(&mut cx), Poll::Ready(Err(Errno::EIO)));
        assert_eq!(provider.uncertain_writes(), 1);
    }

    // Subsequent ops fail with `ENOTCONN` without incrementing `uncertain_writes`, while mount
    // stays inspectable in `/proc/self/mountinfo` and `close` + `umount2` succeed!
    assert_eq!(run(pfile.write(b"after")), Err(Errno::ENOTCONN));
    assert_eq!(provider.uncertain_writes(), 1);
    assert_eq!(
        run(env.vfs.statat(1, StartAnchor::Root, "/mnt/helper", true)),
        Err(Errno::ENOTCONN)
    );
    let mi = String::from_utf8(read_all(&env.vfs, 1, "/proc/self/mountinfo").unwrap()).unwrap();
    assert!(
        mi.contains(" /mnt/helper rw,relatime - helperfs helper "),
        "mountinfo: {mi}"
    );
    run(pfile.close()).unwrap();
    run(env.vfs.umount2(1, "/mnt/helper", 0)).unwrap();

    // --- Ending 3: Export Revocation (`ShareFs` -> `EACCES`) ---
    let pub_fs = Rc::new(MemFs::new(
        FsId("share:pub1".into()),
        1,
        1001,
        1001,
        0o755,
        Box::new(|| (1_700_000_000, 0)),
    ));
    let transport = LoopbackShareTransport::new(pub_fs);
    let fault = transport.fault_handle();
    let share_provider = ProviderState::new();
    let share_fs = ShareFs::new(transport, Rc::clone(&share_provider), false, false);
    let (share_backing, share_root) = share_fs.into_backing();
    run(env.vfs.mount_on_namespace(
        &sys_ns,
        &Cred::root(),
        share_backing,
        Some((share_root, "/".into())),
        "osfs:pub1",
        "/mnt/shared",
        MountFlags::default(),
        0,
        None,
    ))
    .unwrap();
    write_all(&env.vfs, 1, "/mnt/shared/note.txt", 0o644, b"shared");
    let sfd = run(env
        .vfs
        .openat(1, StartAnchor::Root, "/mnt/shared/note.txt", abi::O_RDWR, 0))
    .unwrap();
    run(env.vfs.chdir(1, "/mnt/shared")).unwrap();

    // Publisher revokes export -> transitions to `Revoked`, stays in `mountinfo`, all ops -> EACCES!
    fault.set(Some(ShareError::Revoked));
    assert_eq!(run(env.vfs.read(1, sfd, &mut [0u8; 4])), Err(Errno::EACCES));
    assert_eq!(share_provider.health(), ProviderHealth::Revoked);
    assert_eq!(run(env.vfs.write(1, sfd, b"x")), Err(Errno::EACCES));
    assert_eq!(run(env.vfs.fstat(1, sfd)), Err(Errno::EACCES));
    assert_eq!(run(env.vfs.fsync(1, sfd)), Err(Errno::EACCES));
    assert_eq!(
        run(env.vfs.statat(1, StartAnchor::Root, "/mnt/shared", true)),
        Err(Errno::EACCES)
    );
    // `chdir("/")` out of revoked cwd works, `mountinfo` still lists `/mnt/shared`, `close` & `umount2` work!
    run(env.vfs.chdir(1, "/")).unwrap();
    let mi_rev = String::from_utf8(read_all(&env.vfs, 1, "/proc/self/mountinfo").unwrap()).unwrap();
    assert!(
        mi_rev.contains(" /mnt/shared rw,relatime - sharefs osfs:pub1 "),
        "mountinfo: {mi_rev}"
    );
    run(env.vfs.close(1, sfd)).unwrap();
    run(env.vfs.umount2(1, "/mnt/shared", 0)).unwrap();
}

// -----------------------------------------------------------------------------
// 7. User-Mount Owner Ceiling (`uid 0` EACCES Denial) & Locked `nosuid,nodev`
// -----------------------------------------------------------------------------

#[test]
fn user_mount_owner_ceiling_denies_other_users_and_uid_0() {
    let env = boot_env();
    // Prepare `/mnt/local/alice` owned by Alice (1001) and `/mnt/local/bob` owned by Bob (1002).
    run(env
        .vfs
        .mkdirat(1, StartAnchor::Root, "/mnt/local/alice", 0o755))
    .unwrap();
    run(env.vfs.setattrat(
        1,
        StartAnchor::Root,
        "/mnt/local/alice",
        &SetAttr {
            uid: Some(1001),
            gid: Some(1001),
            ..SetAttr::default()
        },
        true,
    ))
    .unwrap();
    run(env
        .vfs
        .mkdirat(1, StartAnchor::Root, "/mnt/local/bob", 0o755))
    .unwrap();
    run(env.vfs.setattrat(
        1,
        StartAnchor::Root,
        "/mnt/local/bob",
        &SetAttr {
            uid: Some(1002),
            gid: Some(1002),
            ..SetAttr::default()
        },
        true,
    ))
    .unwrap();

    // Register a hostfs grant ONLY for Alice (`uid = 1001`, source `"dir:notes"`).
    env.factory
        .register_user_grant(1001, FsType::HostFs, "dir:notes", |_cred, _, _, _| {
            let fs = Rc::new(MemFs::new(
                FsId("hostfs:alice-notes".into()),
                1,
                1001,
                1001,
                0o755,
                Box::new(|| (1_700_000_000, 0)),
            ));
            let root = fs.root();
            Ok(MountedFs {
                backing: Rc::new(MountBacking::new(fs, FsType::HostFs)),
                root,
                root_in_fs: "/".into(),
            })
        });

    // Spawn Alice (PID 30, uid 1001) and Bob (PID 31, uid 1002).
    env.vfs
        .spawn_process(30, 1, user_cred(1001, 1001), None, None, None)
        .unwrap();
    env.vfs
        .spawn_process(31, 1, user_cred(1002, 1002), None, None, None)
        .unwrap();

    // Unprivileged user denials:
    // - Non-user-mountable fstype (`tmpfs`) -> EPERM
    assert_eq!(
        run(env
            .vfs
            .mount(30, "tmpfs", "/mnt/local/alice", Some("tmpfs"), 0, None)),
        Err(Errno::EPERM)
    );
    // - Target directory not owned by Alice -> EPERM
    assert_eq!(
        run(env
            .vfs
            .mount(30, "dir:notes", "/mnt/local/bob", Some("hostfs"), 0, None)),
        Err(Errno::EPERM)
    );
    // - Ungranted source -> EACCES
    assert_eq!(
        run(env.vfs.mount(
            30,
            "dir:stolen",
            "/mnt/local/alice",
            Some("hostfs"),
            0,
            None,
        )),
        Err(Errno::EACCES)
    );

    // Alice mounts her granted `hostfs` (even passing flags = 0, `nosuid` & `nodev` are forced!).
    run(env
        .vfs
        .mount(30, "dir:notes", "/mnt/local/alice", Some("hostfs"), 0, None))
    .unwrap();
    write_all(
        &env.vfs,
        30,
        "/mnt/local/alice/diary.txt",
        0o644,
        b"private",
    );
    run(env.vfs.chdir(30, "/mnt/local/alice")).unwrap();

    let mi = String::from_utf8(read_all(&env.vfs, 30, "/proc/self/mountinfo").unwrap()).unwrap();
    assert!(mi.contains("nosuid,nodev") && mi.contains("user_id=1001"));

    // CRITICAL INVARIANT (`contract.md` §2.7, §4):
    // BOTH Bob (`uid 1002`) AND instance root (`uid 0`, PID 1) get `EACCES` on Alice's user mount!
    for caller_pid in [1u32, 31u32] {
        assert_eq!(
            read_all(&env.vfs, caller_pid, "/mnt/local/alice/diary.txt"),
            Err(Errno::EACCES)
        );
        assert_eq!(
            run(env
                .vfs
                .statat(caller_pid, StartAnchor::Root, "/mnt/local/alice", true)),
            Err(Errno::EACCES)
        );
    }
    // Even root traversing `/proc/30/cwd` into Alice's user mount gets `EACCES`!
    assert_eq!(
        run(env.vfs.statat(1, StartAnchor::Root, "/proc/30/cwd", true)),
        Err(Errno::EACCES)
    );
    // Even if Alice forks a child (PID 32) that elevates/switches to `uid 0` holding an open fd,
    // `read` on that inherited fd fails with `EACCES`!
    let alice_fd = run(env.vfs.openat(
        30,
        StartAnchor::Root,
        "/mnt/local/alice/diary.txt",
        abi::O_RDONLY,
        0,
    ))
    .unwrap();
    env.vfs.fork_process(30, 32, 0).unwrap();
    env.vfs.set_cred(32, Cred::root()).unwrap();
    assert_eq!(
        run(env.vfs.read(32, alice_fd, &mut [0u8; 8])),
        Err(Errno::EACCES)
    );
    run(env.vfs.exit_process(32)).unwrap();
    run(env.vfs.close(30, alice_fd)).unwrap();
    run(env.vfs.chdir(30, "/")).unwrap();

    // Alice cannot clear `MS_NOSUID` or `MS_NODEV` via `MS_REMOUNT` (`EPERM`), but CAN remount `ro`
    // when preserving `MS_NOSUID | MS_NODEV`!
    assert_eq!(
        run(env.vfs.mount(
            30,
            "",
            "/mnt/local/alice",
            None,
            mount_flags::MS_REMOUNT | mount_flags::MS_RDONLY,
            None,
        )),
        Err(Errno::EPERM)
    );
    run(env.vfs.mount(
        30,
        "",
        "/mnt/local/alice",
        None,
        mount_flags::MS_REMOUNT
            | mount_flags::MS_RDONLY
            | mount_flags::MS_NOSUID
            | mount_flags::MS_NODEV,
        None,
    ))
    .unwrap();

    // Bob cannot unmount Alice's mount (`EPERM`), whereas instance root (`uid 0`) CAN unmount it!
    assert_eq!(
        run(env.vfs.umount2(31, "/mnt/local/alice", 0)),
        Err(Errno::EPERM)
    );
    run(env.vfs.umount2(1, "/mnt/local/alice", 0)).unwrap();
}

// -----------------------------------------------------------------------------
// 8. `chroot`: `ksys_chroot` Error Order, `..` Clamp, Outside `cwd`, Retained
//    `dirfd`, Absolute Symlinks, `cwd-rename`, and `cwd-remove`
// -----------------------------------------------------------------------------

#[test]
fn chroot_confinement_outside_cwd_retained_dirfd_and_cwd_lifecycle() {
    let env = boot_env();
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/jail", 0o755)).unwrap();
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/jail/etc", 0o755)).unwrap();
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/jail/sub", 0o755)).unwrap();
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/outside", 0o755)).unwrap();
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/no_search", 0o600)).unwrap();
    run(env.vfs.setattrat(
        1,
        StartAnchor::Root,
        "/no_search",
        &SetAttr {
            mode: Some(0o600),
            ..SetAttr::default()
        },
        true,
    ))
    .unwrap();

    write_all(&env.vfs, 1, "/etc/motd", 0o644, b"HOST-MOTD");
    write_all(&env.vfs, 1, "/jail/etc/motd", 0o644, b"JAIL-MOTD");
    write_all(&env.vfs, 1, "/outside/out.txt", 0o644, b"OUTSIDE-FILE");
    // Absolute symlink placed in `/outside`!
    run(env
        .vfs
        .symlinkat(1, "/etc/motd", StartAnchor::Root, "/outside/abs_motd"))
    .unwrap();
    // Escape-attempt symlink inside `/jail`!
    run(env.vfs.symlinkat(
        1,
        "../../../../etc/motd",
        StartAnchor::Root,
        "/jail/sub/escape",
    ))
    .unwrap();

    // Linux `ksys_chroot` check order for unprivileged user (uid 1001):
    // walk + X_OK FIRST (`ENOENT`, `ENOTDIR`, `EACCES`), THEN `uid == 0` (`EPERM`)!
    env.vfs
        .spawn_process(40, 1, user_cred(1001, 1001), None, None, None)
        .unwrap();
    assert_eq!(run(env.vfs.chroot(40, "/missing")), Err(Errno::ENOENT));
    assert_eq!(run(env.vfs.chroot(40, "/etc/motd")), Err(Errno::ENOTDIR));
    assert_eq!(run(env.vfs.chroot(40, "/no_search")), Err(Errno::EACCES));
    assert_eq!(run(env.vfs.chroot(40, "/jail")), Err(Errno::EPERM));

    // Fork privileged child PID 41, open retained `dirfd` on `/outside`, `chdir("/outside")`,
    // and call `chroot("/jail")` WITHOUT `chdir`!
    env.vfs.fork_process(1, 41, 0).unwrap();
    let retained_dirfd = run(env.vfs.openat(
        41,
        StartAnchor::Root,
        "/outside",
        abi::O_RDONLY | abi::O_DIRECTORY,
        0,
    ))
    .unwrap();
    run(env.vfs.chdir(41, "/outside")).unwrap();
    run(env.vfs.chroot(41, "/jail")).unwrap();

    // 1) `getcwd()` when `cwd` is outside `chroot` MUST return `ENOENT`!
    assert_eq!(run(env.vfs.getcwd(41)), Err(Errno::ENOENT));
    // 2) Relative path from outside `cwd` STILL resolves in `/outside`!
    assert_eq!(read_all(&env.vfs, 41, "out.txt").unwrap(), b"OUTSIDE-FILE");
    // 3) Absolute symlink followed from outside `cwd` STILL anchors at `/jail` (`ctx.root`)!
    assert_eq!(read_all(&env.vfs, 41, "abs_motd").unwrap(), b"JAIL-MOTD");
    // 4) Absolute path resolves inside `/jail`!
    assert_eq!(read_all(&env.vfs, 41, "/etc/motd").unwrap(), b"JAIL-MOTD");

    // Enter `/jail/sub`: `..` and relative symlinks clamp strictly at `/jail`!
    run(env.vfs.chdir(41, "/sub")).unwrap();
    assert_eq!(run(env.vfs.getcwd(41)).unwrap(), "/sub");
    assert_eq!(
        read_all(&env.vfs, 41, "../../../../etc/motd").unwrap(),
        b"JAIL-MOTD"
    );
    assert_eq!(read_all(&env.vfs, 41, "escape").unwrap(), b"JAIL-MOTD");

    // 5) Retained `dirfd` outside `chroot` works with `*at` AND `fchdir(retained_dirfd)`!
    let via_dirfd = run(env.vfs.openat(
        41,
        StartAnchor::DirFd(retained_dirfd),
        "out.txt",
        abi::O_RDONLY,
        0,
    ))
    .unwrap();
    let mut dbuf = [0u8; 12];
    assert_eq!(run(env.vfs.read(41, via_dirfd, &mut dbuf)).unwrap(), 12);
    assert_eq!(&dbuf, b"OUTSIDE-FILE");
    run(env.vfs.close(41, via_dirfd)).unwrap();

    run(env.vfs.fchdir(41, retained_dirfd)).unwrap();
    assert_eq!(run(env.vfs.getcwd(41)), Err(Errno::ENOENT));
    run(env.vfs.close(41, retained_dirfd)).unwrap();

    // 6) `cwd-rename` and `cwd-remove` inside `/jail`:
    run(env.vfs.chdir(41, "/sub")).unwrap();
    run(env.vfs.renameat(
        1,
        StartAnchor::Root,
        "/jail/sub",
        StartAnchor::Root,
        "/jail/renamed_sub",
        RenameFlags::empty(),
    ))
    .unwrap();
    assert_eq!(run(env.vfs.getcwd(41)).unwrap(), "/renamed_sub");

    // Remove `/jail/renamed_sub/escape` then `rmdir` `/jail/renamed_sub` while PID 41 is in it:
    run(env
        .vfs
        .unlinkat(1, StartAnchor::Root, "/jail/renamed_sub/escape", false))
    .unwrap();
    run(env
        .vfs
        .unlinkat(1, StartAnchor::Root, "/jail/renamed_sub", true))
    .unwrap();
    assert_eq!(run(env.vfs.getcwd(41)), Err(Errno::ENOENT));
    let dot_stat = run(env.vfs.statat(41, StartAnchor::AtFdCwd, ".", true)).unwrap();
    assert_eq!(dot_stat.nlink, 0);

    // 7) Mounted `chroot` root cannot be moved (`MS_MOVE -> EINVAL`) or detached (`umount2 -> EBUSY`),
    //    and unprivileged `unlinkat`/`renameat` on mountpoints check directory + sticky perms BEFORE `EBUSY`!
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/mnt/jail_mp", 0o755)).unwrap();
    run(env
        .vfs
        .mount(1, "jail_fs", "/mnt/jail_mp", Some("tmpfs"), 0, None))
    .unwrap();
    run(env
        .vfs
        .mkdirat(1, StartAnchor::Root, "/mnt/jail_mp/sub", 0o755))
    .unwrap();
    env.vfs.fork_process(1, 42, 0).unwrap();
    run(env.vfs.chroot(42, "/mnt/jail_mp")).unwrap();
    run(env.vfs.chdir(42, "/")).unwrap();
    assert_eq!(
        run(env
            .vfs
            .mount(42, "/", "/sub", None, mount_flags::MS_MOVE, None)),
        Err(Errno::EINVAL)
    );
    assert_eq!(
        run(env.vfs.umount2(42, "/", umount_flags::MNT_DETACH)),
        Err(Errno::EBUSY)
    );

    // Unprivileged PID 40 (`uid 1001`) on `/mnt/jail_mp` (parent `/mnt` is `0755` owned by 0) -> EACCES;
    // on `/tmp/sticky_mp` (parent `/tmp` is `1777` sticky, mountpoint owned by 0) -> EPERM!
    run(env
        .vfs
        .mkdirat(1, StartAnchor::Root, "/tmp/sticky_mp", 0o755))
    .unwrap();
    run(env
        .vfs
        .mount(1, "sticky_fs", "/tmp/sticky_mp", Some("tmpfs"), 0, None))
    .unwrap();
    assert_eq!(
        run(env
            .vfs
            .unlinkat(40, StartAnchor::Root, "/mnt/jail_mp", true)),
        Err(Errno::EACCES)
    );
    assert_eq!(
        run(env.vfs.renameat(
            40,
            StartAnchor::Root,
            "/mnt/jail_mp",
            StartAnchor::Root,
            "/mnt/jail_mp2",
            RenameFlags::empty(),
        )),
        Err(Errno::EACCES)
    );
    assert_eq!(
        run(env
            .vfs
            .unlinkat(40, StartAnchor::Root, "/tmp/sticky_mp", true)),
        Err(Errno::EPERM)
    );
    assert_eq!(
        run(env.vfs.renameat(
            40,
            StartAnchor::Root,
            "/tmp/sticky_mp",
            StartAnchor::Root,
            "/tmp/sticky_mp2",
            RenameFlags::empty(),
        )),
        Err(Errno::EPERM)
    );
}

// -----------------------------------------------------------------------------
// 9. Namespaces (`unshare`, `setns`, `CLONE_FS`, `CLONE_FILES`), `mountinfo`
//    Octal Escaping & `chroot` Filtering, `ProcFs`, `ImageFs`, `DevTmpFs` & `DevPtsFs`
// -----------------------------------------------------------------------------

struct MockProcProvider;
impl ProcProvider for MockProcProvider {
    fn top_entries<'a>(&'a self, _cred: &'a Cred) -> BoxFuture<'a, Vec<ProcDynamicEntry>> {
        Box::pin(async {
            Ok(vec![ProcDynamicEntry {
                name: "uptime".into(),
                file_type: FileType::File,
                mode: 0o444,
                uid: 0,
                gid: 0,
            }])
        })
    }
    fn read_top<'a>(&'a self, _cred: &'a Cred, name: &'a str) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(async move {
            if name == "uptime" {
                Ok(b"42.00 84.00\n".to_vec())
            } else {
                Err(Errno::ENOENT)
            }
        })
    }
    fn pid_entries<'a>(
        &'a self,
        _cred: &'a Cred,
        _pid: u32,
    ) -> BoxFuture<'a, Vec<ProcDynamicEntry>> {
        Box::pin(async {
            Ok(vec![ProcDynamicEntry {
                name: "cmdline".into(),
                file_type: FileType::File,
                mode: 0o444,
                uid: 0,
                gid: 0,
            }])
        })
    }
    fn read_pid<'a>(&'a self, _cred: &'a Cred, pid: u32, name: &'a str) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(async move {
            if name == "cmdline" {
                Ok(format!("proc-{pid}\0").into_bytes())
            } else {
                Err(Errno::ENOENT)
            }
        })
    }
}

#[test]
fn unshare_setns_clone_sharing_mountinfo_escaping_and_all_drivers() {
    let env = boot_env();

    // Replace `/proc` with `ProcFs<MockProcProvider>` to also test `ProcProvider` fallback!
    run(env.vfs.umount2(1, "/proc", 0)).unwrap();
    let proc_fs = Rc::new(ProcFs::new(
        FsId("proc:mock".into()),
        Timespec {
            sec: 1_700_000_000,
            nsec: 0,
        },
        MockProcProvider,
    ));
    proc_fs.bind_bridge(env.vfs.proc_bridge());
    let sys_ns = env.vfs.system_namespace();
    run(env.vfs.mount_on_namespace(
        &sys_ns,
        &Cred::root(),
        Rc::new(MountBacking::new(proc_fs.clone(), FsType::Proc)),
        None,
        "proc",
        "/proc",
        MountFlags::from_accepted(
            mount_flags::MS_NOSUID | mount_flags::MS_NODEV | mount_flags::MS_NOEXEC,
        ),
        0,
        None,
    ))
    .unwrap();

    assert_eq!(
        read_all(&env.vfs, 1, "/proc/uptime").unwrap(),
        b"42.00 84.00\n"
    );
    assert_eq!(
        read_all(&env.vfs, 1, "/proc/self/cmdline").unwrap(),
        b"proc-1\0"
    );
    assert_eq!(
        run(env.vfs.readlinkat(1, StartAnchor::Root, "/proc/mounts")).unwrap(),
        "self/mounts"
    );

    // `CLONE_FS` & `CLONE_FILES` sharing + `unshare` splitting:
    env.vfs
        .fork_process(1, 50, unshare_flags::CLONE_FS | unshare_flags::CLONE_FILES)
        .unwrap();
    run(env.vfs.chdir(50, "/tmp")).unwrap();
    assert_eq!(run(env.vfs.getcwd(1)).unwrap(), "/tmp"); // shared `FsContext`!
    let shared_fd = run(env
        .vfs
        .openat(50, StartAnchor::Root, "/proc/uptime", abi::O_RDONLY, 0))
    .unwrap();
    assert!(run(env.vfs.fstat(1, shared_fd)).is_ok()); // shared `FdTable`!

    // `setns` MUST fail with `EINVAL` when caller shares `CLONE_FS`!
    let self_ns_fd =
        run(env
            .vfs
            .openat(50, StartAnchor::Root, "/proc/self/ns/mnt", abi::O_RDONLY, 0))
        .unwrap();
    assert_eq!(
        env.vfs.setns(50, self_ns_fd, unshare_flags::CLONE_NEWNS),
        Err(Errno::EINVAL)
    );
    run(env.vfs.close(50, self_ns_fd)).unwrap();
    run(env.vfs.close(1, shared_fd)).unwrap();
    run(env.vfs.chdir(1, "/")).unwrap();

    // `unshare(CLONE_NEWNS)` on PID 50 implicitly unshares `CLONE_FS` and clones `MountNamespace`!
    env.vfs.unshare(50, unshare_flags::CLONE_FILES).unwrap();
    env.vfs.unshare(50, unshare_flags::CLONE_NEWNS).unwrap();
    assert_ne!(
        run(env
            .vfs
            .readlinkat(1, StartAnchor::Root, "/proc/self/ns/mnt"))
        .unwrap(),
        run(env
            .vfs
            .readlinkat(50, StartAnchor::Root, "/proc/self/ns/mnt"))
        .unwrap()
    );

    // Mount with special characters in PID 50's private namespace to test `mountinfo` escaping!
    let weird_dir = "/tmp/my dir\t1\n\\end";
    run(env.vfs.mkdirat(50, StartAnchor::Root, weird_dir, 0o755)).unwrap();
    run(env
        .vfs
        .mount(50, "src a\\b", weird_dir, Some("tmpfs"), 0, None))
    .unwrap();
    write_all(&env.vfs, 50, &format!("{weird_dir}/priv"), 0o644, b"ns50");

    // Invisible in PID 1's namespace; visible and octal-escaped in PID 50's `/proc/self/mountinfo`!
    assert_eq!(
        read_all(&env.vfs, 1, &format!("{weird_dir}/priv")),
        Err(Errno::ENOENT)
    );
    let mi50 = String::from_utf8(read_all(&env.vfs, 50, "/proc/self/mountinfo").unwrap()).unwrap();
    assert!(
        mi50.contains("/tmp/my\\040dir\\0111\\012\\134end"),
        "mountinfo: {mi50}"
    );
    assert!(
        mi50.contains(" tmpfs src\\040a\\134b rw"),
        "mountinfo: {mi50}"
    );

    // `setns` validation & denials:
    env.vfs
        .spawn_process(51, 1, user_cred(1001, 1001), None, None, None)
        .unwrap();
    assert_eq!(env.vfs.unshare(51, 0), Ok(()));
    assert_eq!(env.vfs.unshare(51, 0x1000_0000), Err(Errno::EINVAL));
    assert_eq!(
        env.vfs.unshare(51, unshare_flags::CLONE_NEWNS),
        Err(Errno::EPERM)
    );
    assert_eq!(env.vfs.setns(51, 999, 0), Err(Errno::EBADF));
    let reg_fd = run(env
        .vfs
        .openat(1, StartAnchor::Root, "/proc/uptime", abi::O_RDONLY, 0))
    .unwrap();
    assert_eq!(env.vfs.setns(1, reg_fd, 0), Err(Errno::EINVAL));
    run(env.vfs.close(1, reg_fd)).unwrap();

    // Foreign-instance `MountNs` `FileRef` MUST be rejected with `EINVAL`!
    let foreign_ns = env.vfs.system_namespace();
    let foreign_file = FileRef::new_mount_ns(
        proc_fs.clone(),
        None,
        "foreign-instance-id".into(),
        foreign_ns,
        os_vfs::Access::Read,
        Cred::root(),
        env.vfs.releases(),
    );
    let ffd = env
        .vfs
        .process_fds(1)
        .unwrap()
        .borrow_mut()
        .insert(foreign_file, false)
        .unwrap();
    assert_eq!(env.vfs.setns(1, ffd, 0), Err(Errno::EINVAL));
    run(env.vfs.close(1, ffd)).unwrap();

    // Non-root cannot open root's `/proc/50/ns/mnt` (`EACCES`), and even with a valid ns fd,
    // non-root `setns` fails with `EPERM`!
    assert_eq!(
        run(env
            .vfs
            .openat(51, StartAnchor::Root, "/proc/50/ns/mnt", abi::O_RDONLY, 0)),
        Err(Errno::EACCES)
    );
    let self_51_ns =
        run(env
            .vfs
            .openat(51, StartAnchor::Root, "/proc/self/ns/mnt", abi::O_RDONLY, 0))
        .unwrap();
    assert_eq!(env.vfs.setns(51, self_51_ns, 0), Err(Errno::EPERM));
    run(env.vfs.close(51, self_51_ns)).unwrap();

    // Privileged PID 52 opens `/proc/50/ns/mnt` and enters PID 50's namespace via `setns`!
    env.vfs.fork_process(1, 52, 0).unwrap();
    run(env.vfs.chdir(52, "/etc")).unwrap();
    let ns50_fd = run(env
        .vfs
        .openat(52, StartAnchor::Root, "/proc/50/ns/mnt", abi::O_RDONLY, 0))
    .unwrap();
    assert_eq!(
        env.vfs.setns(52, ns50_fd, unshare_flags::CLONE_FS),
        Err(Errno::EINVAL)
    );
    env.vfs
        .setns(52, ns50_fd, unshare_flags::CLONE_NEWNS)
        .unwrap();
    // `setns` resets `root` and `cwd` to target namespace's `"/"` and reveals PID 50's mount!
    assert_eq!(run(env.vfs.getcwd(52)).unwrap(), "/");
    assert_eq!(
        read_all(&env.vfs, 52, &format!("{weird_dir}/priv")).unwrap(),
        b"ns50"
    );
    run(env.vfs.close(52, ns50_fd)).unwrap();

    // Verify `mountinfo` `chroot` prefix stripping & filtering:
    run(env.vfs.mkdirat(50, StartAnchor::Root, "/tmp/proc", 0o555)).unwrap();
    run(env
        .vfs
        .mount(50, "/proc", "/tmp/proc", None, mount_flags::MS_BIND, None))
    .unwrap();
    run(env.vfs.chroot(50, "/tmp")).unwrap();
    run(env.vfs.chdir(50, "/")).unwrap();
    let mi_chroot =
        String::from_utf8(read_all(&env.vfs, 50, "/proc/self/mountinfo").unwrap()).unwrap();
    assert!(
        mi_chroot.contains(" /my\\040dir\\0111\\012\\134end rw,relatime - tmpfs "),
        "expected chroot prefix stripped in: {mi_chroot}"
    );
    assert!(mi_chroot.contains(" /proc rw,nosuid,nodev,noexec,relatime - proc "));
    assert!(
        !mi_chroot.contains(" /dev "),
        "outside-chroot /dev must be omitted: {mi_chroot}"
    );
    // And `readlink("/proc/52/root")` read by chrooted PID 50 shows `(unreachable)/`!
    assert_eq!(
        run(env.vfs.readlinkat(50, StartAnchor::Root, "/proc/52/root")).unwrap(),
        "(unreachable)/"
    );

    // `/proc/self/fd/<n>` & `/proc/self/fdinfo/<n>` + `DevTmpFs` + `DevPtsFs` + `ImageFs`:
    let null_fd = run(env
        .vfs
        .openat(1, StartAnchor::Root, "/dev/null", abi::O_RDWR, 0))
    .unwrap();
    assert_eq!(run(env.vfs.write(1, null_fd, b"discarded")).unwrap(), 9);
    assert_eq!(run(env.vfs.read(1, null_fd, &mut [1u8; 4])).unwrap(), 0);
    run(env.vfs.close(1, null_fd)).unwrap();

    let zero_fd = run(env
        .vfs
        .openat(1, StartAnchor::Root, "/dev/zero", abi::O_RDONLY, 0))
    .unwrap();
    let mut zbuf = [0xffu8; 8];
    assert_eq!(run(env.vfs.read(1, zero_fd, &mut zbuf)).unwrap(), 8);
    assert_eq!(zbuf, [0u8; 8]);
    run(env.vfs.close(1, zero_fd)).unwrap();

    let full_fd = run(env
        .vfs
        .openat(1, StartAnchor::Root, "/dev/full", abi::O_RDWR, 0))
    .unwrap();
    assert_eq!(run(env.vfs.write(1, full_fd, b"x")), Err(Errno::ENOSPC));
    assert_eq!(run(env.vfs.fsync(1, full_fd)), Err(Errno::EINVAL));
    run(env.vfs.close(1, full_fd)).unwrap();

    let urand_fd = run(env
        .vfs
        .openat(1, StartAnchor::Root, "/dev/urandom", abi::O_RDONLY, 0))
    .unwrap();
    let mut rbuf1 = [0u8; 16];
    let mut rbuf2 = [0u8; 16];
    assert_eq!(run(env.vfs.read(1, urand_fd, &mut rbuf1)).unwrap(), 16);
    assert_eq!(run(env.vfs.read(1, urand_fd, &mut rbuf2)).unwrap(), 16);
    assert_ne!(rbuf1, rbuf2);
    // `/dev/fd/<n>` follows `/proc/self/fd/<n>`!
    let fdinfo =
        String::from_utf8(read_all(&env.vfs, 1, &format!("/proc/self/fdinfo/{urand_fd}")).unwrap())
            .unwrap();
    assert!(
        fdinfo.contains("pos:\t32\n") && fdinfo.contains("mnt_id:\t"),
        "fdinfo: {fdinfo}"
    );
    assert!(
        run(env
            .vfs
            .statat(1, StartAnchor::Root, &format!("/dev/fd/{urand_fd}"), true))
        .is_ok()
    );
    run(env.vfs.close(1, urand_fd)).unwrap();

    // `DevPtsFs`: allocate PTY `0`, chmod/chown via `setattr`, list `/dev/pts`, close PTY `0`.
    let pty0 = env.devpts.allocate_pty(1001, 5, 0o620);
    assert_eq!(pty0, 0);
    let pts_entries: Vec<String> = run(env.vfs.readdir(1, StartAnchor::Root, "/dev/pts"))
        .unwrap()
        .into_iter()
        .map(|d| d.name)
        .collect();
    assert_eq!(pts_entries, vec!["ptmx", "0"]);
    let pty_st = run(env.vfs.statat(1, StartAnchor::Root, "/dev/pts/0", true)).unwrap();
    assert_eq!(
        (pty_st.uid, pty_st.gid, pty_st.mode & 0o777),
        (1001, 5, 0o620)
    );
    assert!(env.devpts.close_pty(0));
    assert_eq!(
        run(env.vfs.statat(1, StartAnchor::Root, "/dev/pts/0", true)),
        Err(Errno::ENOENT)
    );

    // `ImageFs` (both `from_build_assets` at `/usr` and `from_composition_json` at `/opt/private/ext`):
    let mut blobs = MemoryBlobStore::new();
    blobs.insert("/usr/bin/dash.wasm", WASM_BIN.to_vec());
    blobs.insert("/usr/bin/coreutils.wasm", WASM_BIN.to_vec());
    blobs.insert("/usr/bin/utilities.wasm", WASM_BIN.to_vec());
    blobs.insert("/usr/bin/init.wasm", WASM_BIN.to_vec());
    blobs.insert("/usr/bin/supervise.wasm", WASM_BIN.to_vec());
    let sys_img = Rc::new(ImageFs::from_build_assets(
        FsId("image:build".into()),
        BuildAssetSizes {
            coreutils: WASM_BIN.len() as u64,
            utilities: WASM_BIN.len() as u64,
            dash: WASM_BIN.len() as u64,
            supervise: WASM_BIN.len() as u64,
            init: WASM_BIN.len() as u64,
        },
        Timespec {
            sec: 1_700_000_000,
            nsec: 0,
        },
        blobs,
    ));
    let usr_handle = sys_img.handle_at("/usr").unwrap();
    run(env.vfs.mount_on_namespace(
        &sys_ns,
        &Cred::root(),
        Rc::new(MountBacking::new(sys_img, FsType::Image)),
        Some((usr_handle, "/usr".into())),
        "image:build",
        "/usr",
        MountFlags::from_accepted(mount_flags::MS_RDONLY | mount_flags::MS_NODEV),
        mount_flags::MS_RDONLY,
        None,
    ))
    .unwrap();

    // `/bin/sh` -> `usr/bin/sh` -> `dash` resolves across root `/` symlink into `/usr` `ImageFs`!
    assert_eq!(read_all(&env.vfs, 1, "/bin/sh").unwrap(), WASM_BIN);
    assert_eq!(
        run(env
            .vfs
            .unlinkat(1, StartAnchor::Root, "/usr/bin/dash", false)),
        Err(Errno::EROFS)
    );

    let mut ext_blobs = MemoryBlobStore::new();
    let sha = "a".repeat(64);
    ext_blobs.insert(&sha, b"ext-payload".to_vec());
    let comp_json = serde_json::json!({
        "entries": {
            "/": { "path": "/", "uid": 1001, "gid": 1001, "mode": 0o755, "node": { "type": "directory" } },
            "/tool.txt": { "path": "/tool.txt", "uid": 1001, "gid": 1001, "mode": 0o644, "node": { "type": "file", "sha256": sha, "size": 11 } }
        }
    })
    .to_string();
    let ext_img = Rc::new(
        ImageFs::from_composition_json(
            FsId("image:priv-ext".into()),
            false,
            Timespec {
                sec: 1_700_000_000,
                nsec: 0,
            },
            &comp_json,
            ext_blobs,
        )
        .unwrap(),
    );
    let ext_entry = ImageEntry {
        path: "/".into(),
        uid: 0,
        gid: 0,
        mode: 0o755,
        node: ImageNodeKind::Directory,
    };
    assert_eq!(ext_entry.path, "/");
    run(env
        .vfs
        .mkdirat(1, StartAnchor::Root, "/opt/private/ext1", 0o755))
    .unwrap();
    run(env.vfs.mount_on_namespace(
        &sys_ns,
        &Cred::root(),
        Rc::new(MountBacking::new(ext_img, FsType::Image)),
        None,
        "private:ext1",
        "/opt/private/ext1",
        MountFlags::from_accepted(mount_flags::MS_RDONLY),
        mount_flags::MS_RDONLY,
        Some(1001),
    ))
    .unwrap();
    assert_eq!(
        read_all(&env.vfs, 51, "/opt/private/ext1/tool.txt").unwrap(),
        b"ext-payload"
    );
    assert_eq!(
        read_all(&env.vfs, 1, "/opt/private/ext1/tool.txt"),
        Err(Errno::EACCES)
    );
    let _ = SeekFrom::Start(0);
    let _ = BTreeMap::<u32, u32>::new();
}

// -----------------------------------------------------------------------------
// 10. `resolve_exec`: `PATH` Search (`saw_eacces`), `#!` Shebang Loop (Depth 4,
//     5th -> `ELOOP`), Single Opt-Arg Rule, and Zero Outside-`chroot` Fallback
// -----------------------------------------------------------------------------

#[test]
fn resolve_exec_path_search_shebang_recursion_and_chroot_isolation() {
    let env = boot_env();
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/usr/bin", 0o755)).unwrap();
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/p1", 0o755)).unwrap();
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/p2", 0o755)).unwrap();
    write_all(&env.vfs, 1, "/usr/bin/dash", 0o755, WASM_BIN);

    // `/p1/cmd` is `0o644` (non-executable -> `EACCES`), `/p2/cmd` is `0o755` Wasm:
    write_all(&env.vfs, 1, "/p1/cmd", 0o644, WASM_BIN);
    write_all(&env.vfs, 1, "/p2/cmd", 0o755, WASM_BIN);

    // `PATH="/p1:/p2"` records `saw_eacces` on `/p1/cmd` and succeeds on `/p2/cmd`!
    let hit = run(env.vfs.resolve_exec(
        1,
        "cmd",
        vec!["cmd".into(), "--flag".into()],
        Some("/p1:/p2"),
        true,
    ))
    .unwrap();
    assert_eq!(hit.resolved_path, "/p2/cmd");
    assert_eq!(hit.argv, vec!["cmd", "--flag"]);
    run(hit.file.close()).unwrap();

    // `PATH="/p1:/missing"` finishes without match and returns `EACCES` (because `saw_eacces == true`),
    // whereas `PATH="/missing"` returns `ENOENT`!
    assert_eq!(
        run(env
            .vfs
            .resolve_exec(1, "cmd", vec![], Some("/p1:/missing"), true))
        .err(),
        Some(Errno::EACCES)
    );
    assert_eq!(
        run(env
            .vfs
            .resolve_exec(1, "cmd", vec![], Some("/missing"), true))
        .err(),
        Some(Errno::ENOENT)
    );

    // `#!` shebang single-optional-arg rule (`#! /bin/dash   -e -x  \n`):
    write_all(
        &env.vfs,
        1,
        "/tmp/run.sh",
        0o755,
        b"#! /bin/dash   -e -x  \necho hi\n",
    );
    let sh_exec = run(env.vfs.resolve_exec(
        1,
        "/tmp/run.sh",
        vec!["run.sh".into(), "arg1".into()],
        None,
        false,
    ))
    .unwrap();
    assert_eq!(sh_exec.resolved_path, "/bin/dash");
    assert_eq!(
        sh_exec.argv,
        vec!["/bin/dash", "-e -x", "/tmp/run.sh", "arg1"]
    );
    run(sh_exec.file.close()).unwrap();

    // 4-level `#!` chain (`s1 -> s2 -> s3 -> s4 -> /bin/dash`) succeeds;
    // 5-level `#!` chain (`s0 -> s1 -> s2 -> s3 -> s4 -> /bin/dash`) fails with `ELOOP`!
    write_all(&env.vfs, 1, "/tmp/s4", 0o755, b"#!/bin/dash -4\n");
    write_all(&env.vfs, 1, "/tmp/s3", 0o755, b"#!/tmp/s4 -3\n");
    write_all(&env.vfs, 1, "/tmp/s2", 0o755, b"#!/tmp/s3 -2\n");
    write_all(&env.vfs, 1, "/tmp/s1", 0o755, b"#!/tmp/s2 -1\n");
    write_all(&env.vfs, 1, "/tmp/s0", 0o755, b"#!/tmp/s1 -0\n");

    let deep4 =
        run(env
            .vfs
            .resolve_exec(1, "/tmp/s1", vec!["s1".into(), "tail".into()], None, false))
        .unwrap();
    assert_eq!(
        deep4.argv,
        vec![
            "/bin/dash",
            "-4",
            "/tmp/s4",
            "-3",
            "/tmp/s3",
            "-2",
            "/tmp/s2",
            "-1",
            "/tmp/s1",
            "tail"
        ]
    );
    run(deep4.file.close()).unwrap();

    assert_eq!(
        run(env
            .vfs
            .resolve_exec(1, "/tmp/s0", vec!["s0".into()], None, false))
        .err(),
        Some(Errno::ELOOP)
    );

    // Malformed shebangs & non-Wasm binaries -> ENOEXEC.
    write_all(&env.vfs, 1, "/tmp/empty_interp", 0o755, b"#!   \n");
    write_all(&env.vfs, 1, "/tmp/plain_text", 0o755, b"not wasm");
    assert_eq!(
        run(env
            .vfs
            .resolve_exec(1, "/tmp/empty_interp", vec![], None, false))
        .err(),
        Some(Errno::ENOEXEC)
    );
    assert_eq!(
        run(env
            .vfs
            .resolve_exec(1, "/tmp/plain_text", vec![], None, false))
        .err(),
        Some(Errno::ENOEXEC)
    );

    // Chroot executable confinement: inside `/empty_jail` (without `/usr` or `/bin`), BOTH
    // `/usr/bin/dash` AND a script with `#!/bin/dash` MUST fail with `ENOENT` (zero fallback)!
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/empty_jail", 0o755)).unwrap();
    write_all(
        &env.vfs,
        1,
        "/empty_jail/jail_script.sh",
        0o755,
        b"#!/bin/dash\n",
    );
    env.vfs.fork_process(1, 60, 0).unwrap();
    run(env.vfs.chroot(60, "/empty_jail")).unwrap();
    run(env.vfs.chdir(60, "/")).unwrap();

    assert_eq!(
        run(env
            .vfs
            .resolve_exec(60, "/usr/bin/dash", vec![], None, false))
        .err(),
        Some(Errno::ENOENT)
    );
    assert_eq!(
        run(env.vfs.resolve_exec(60, "dash", vec![], None, true)).err(),
        Some(Errno::ENOENT)
    );
    assert_eq!(
        run(env
            .vfs
            .resolve_exec(60, "/jail_script.sh", vec![], None, false))
        .err(),
        Some(Errno::ENOENT)
    );
}
