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
    block_opens: Cell<bool>,
    block_releases: Cell<bool>,
    fail_sync: Cell<Option<Errno>>,
    active_opens: Cell<usize>,
    sync_calls: Cell<usize>,
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
            block_opens: Cell::new(false),
            block_releases: Cell::new(false),
            fail_sync: Cell::new(None),
            active_opens: Cell::new(0),
            sync_calls: Cell::new(0),
            wakers: RefCell::new(Vec::new()),
        }
    }

    fn wake_all(&self) {
        let wakers: Vec<Waker> = self.wakers.borrow_mut().drain(..).collect();
        for w in wakers {
            w.wake();
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
        Box::pin(async move {
            ParkFuture {
                flag: &self.block_opens,
                wakers: &self.wakers,
            }
            .await;
            let res = self.inner.create(cred, dir, name, mode, options).await?;
            self.active_opens.set(self.active_opens.get() + 1);
            Ok(res)
        })
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
        Box::pin(async move {
            ParkFuture {
                flag: &self.block_opens,
                wakers: &self.wakers,
            }
            .await;
            let open = self.inner.open(cred, handle, options).await?;
            self.active_opens.set(self.active_opens.get() + 1);
            Ok(open)
        })
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
        Box::pin(async move {
            self.sync_calls.set(self.sync_calls.get() + 1);
            if let Some(err) = self.fail_sync.get() {
                return Err(err);
            }
            self.inner.sync_all(open).await
        })
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
        Box::pin(async move {
            ParkFuture {
                flag: &self.block_releases,
                wakers: &self.wakers,
            }
            .await;
            self.active_opens
                .set(self.active_opens.get().saturating_sub(1));
            self.inner.release(open).await
        })
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
            ..Default::default()
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
    // Contract 2 (`M-P0-10`): `owner_uid = Some(1001)` refuses target owned by `uid 0` (`EPERM`).
    assert_eq!(
        run(env.vfs.mount_on_namespace(
            &sys_ns,
            &Cred::root(),
            Rc::new(MountBacking::new(ext_img.clone(), FsType::Image)),
            None,
            "private:ext1",
            "/opt/private/ext1",
            MountFlags::from_accepted(mount_flags::MS_RDONLY),
            mount_flags::MS_RDONLY,
            Some(1001),
        )),
        Err(Errno::EPERM)
    );
    run(env.vfs.setattrat(
        1,
        StartAnchor::Root,
        "/opt/private/ext1",
        &SetAttr {
            uid: Some(1001),
            gid: Some(1001),
            ..SetAttr::default()
        },
        false,
    ))
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

// -----------------------------------------------------------------------------
// 11. PR #74 Review Regressions: Contracts 1 & 2, P0/P1/P2/P3 Track A Invariants
// -----------------------------------------------------------------------------

fn poll_once<F: Future>(fut: &mut std::pin::Pin<&mut F>) -> Poll<F::Output> {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    fut.as_mut().poll(&mut cx)
}

#[test]
fn contract1_fsetattr_and_file_setattr_as_enforce_cred_rofs_owner_and_provider() {
    let env = boot_env();

    // 1. Privilege drop (`M-P0-08`): opening as `uid 0`, dropping to `uid 1001`, then calling
    //    `Vfs::fsetattr` MUST check `pid`'s current `Cred` (not opener `file.cred()`), failing `EPERM`.
    write_all(&env.vfs, 1, "/tmp/root_secret", 0o644, b"hi");
    env.vfs.fork_process(1, 70, 0).unwrap();
    let fd = run(env
        .vfs
        .openat(70, StartAnchor::Root, "/tmp/root_secret", abi::O_RDWR, 0))
    .unwrap();
    env.vfs.set_cred(70, user_cred(1001, 1001)).unwrap();
    assert_eq!(
        run(env.vfs.fsetattr(
            70,
            fd,
            &SetAttr {
                mode: Some(0o600),
                ..SetAttr::default()
            },
        )),
        Err(Errno::EPERM)
    );
    // `O_PATH` descriptor -> `EBADF`.
    let path_fd = run(env.vfs.openat(
        1,
        StartAnchor::Root,
        "/tmp/root_secret",
        abi::O_PATH | abi::O_RDONLY,
        0,
    ))
    .unwrap();
    assert_eq!(
        run(env.vfs.fsetattr(
            1,
            path_fd,
            &SetAttr {
                mode: Some(0o600),
                ..SetAttr::default()
            },
        )),
        Err(Errno::EBADF)
    );
    run(env.vfs.close(1, path_fd)).unwrap();
    run(env.vfs.close(70, fd)).unwrap();

    // 2. `MS_RDONLY` -> `EROFS` and `MS_SYNCHRONOUS` -> `record_sync()` + `sync_all`.
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/mnt/fset", 0o755)).unwrap();
    let sync_fs = Rc::new(PendingFs::new("helper:fset"));
    let sync_backing = Rc::new(MountBacking::new(sync_fs.clone(), FsType::HelperFs));
    let sys_ns = env.vfs.system_namespace();
    run(env.vfs.mount_on_namespace(
        &sys_ns,
        &Cred::root(),
        sync_backing.clone(),
        None,
        "helper:fset",
        "/mnt/fset",
        MountFlags::from_accepted(mount_flags::MS_SYNCHRONOUS),
        0,
        None,
    ))
    .unwrap();
    write_all(&env.vfs, 1, "/mnt/fset/a.txt", 0o644, b"x");
    let sfd = run(env
        .vfs
        .openat(1, StartAnchor::Root, "/mnt/fset/a.txt", abi::O_RDWR, 0))
    .unwrap();
    let sync_before = sync_backing.sync_count();
    let meta = run(env.vfs.fsetattr(
        1,
        sfd,
        &SetAttr {
            mode: Some(0o640),
            ..SetAttr::default()
        },
    ))
    .unwrap();
    assert_eq!(meta.mode & 0o777, 0o640);
    assert!(sync_backing.sync_count() > sync_before);
    run(env.vfs.close(1, sfd)).unwrap();

    // Remount `MS_RDONLY`: pre-opened `O_RDONLY` fd fails `fsetattr` with `EROFS`.
    let rfd = run(env
        .vfs
        .openat(1, StartAnchor::Root, "/mnt/fset/a.txt", abi::O_RDONLY, 0))
    .unwrap();
    run(env.vfs.mount(
        1,
        "",
        "/mnt/fset",
        None,
        mount_flags::MS_REMOUNT | mount_flags::MS_RDONLY,
        None,
    ))
    .unwrap();
    assert_eq!(
        run(env.vfs.fsetattr(
            1,
            rfd,
            &SetAttr {
                mode: Some(0o600),
                ..SetAttr::default()
            },
        )),
        Err(Errno::EROFS)
    );
    run(env.vfs.close(1, rfd)).unwrap();

    // 3. User mount `owner_uid` ceiling + `ProviderState` (`Lost` -> `ENOTCONN`, `Revoked` -> `EACCES`),
    //    plus unmounted `FileRef` -> `EPERM`.
    run(env
        .vfs
        .mkdirat(1, StartAnchor::Root, "/mnt/local/u1001", 0o700))
    .unwrap();
    run(env.vfs.setattrat(
        1,
        StartAnchor::Root,
        "/mnt/local/u1001",
        &SetAttr {
            uid: Some(1001),
            gid: Some(1001),
            ..SetAttr::default()
        },
        false,
    ))
    .unwrap();
    let u_fs = Rc::new(MemFs::new(
        FsId("hostfs:u1001".into()),
        1,
        1001,
        1001,
        0o755,
        Box::new(|| (1_700_000_000, 0)),
    ));
    let u_prov = ProviderState::new();
    let u_backing =
        Rc::new(MountBacking::new(u_fs.clone(), FsType::HostFs).with_provider(u_prov.clone()));
    let alice = user_cred(1001, 1001);
    run(env.vfs.mount_on_namespace(
        &sys_ns,
        &alice,
        u_backing,
        None,
        "hostfs:u1001",
        "/mnt/local/u1001",
        MountFlags::default(),
        0,
        Some(1001),
    ))
    .unwrap();
    env.vfs
        .spawn_process(71, 1, alice.clone(), None, None, None)
        .unwrap();
    let (u_file, _) = run(env.vfs.open_file(
        71,
        StartAnchor::Root,
        "/mnt/local/u1001/item",
        abi::O_CREAT | abi::O_RDWR,
        0o644,
    ))
    .unwrap();
    // `uid 0` is denied by `owner_uid` ceiling on `FileRef::setattr_as`!
    assert_eq!(
        run(u_file.setattr_as(
            &Cred::root(),
            &SetAttr {
                mode: Some(0o600),
                ..SetAttr::default()
            },
        )),
        Err(Errno::EACCES)
    );
    // `Lost` -> `ENOTCONN`, `Revoked` -> terminal `EACCES` even if `lose()`/`reconnect()` is called!
    u_prov.lose();
    assert_eq!(
        run(u_file.setattr_as(
            &alice,
            &SetAttr {
                mode: Some(0o600),
                ..SetAttr::default()
            },
        )),
        Err(Errno::ENOTCONN)
    );
    u_prov.reconnect();
    assert_eq!(
        run(u_file.setattr_as(
            &alice,
            &SetAttr {
                mode: Some(0o600),
                ..SetAttr::default()
            },
        ))
        .unwrap()
        .mode
            & 0o777,
        0o600
    );
    u_prov.revoke();
    u_prov.lose();
    u_prov.reconnect();
    assert_eq!(u_prov.health(), ProviderHealth::Revoked);
    assert_eq!(
        run(u_file.setattr_as(
            &alice,
            &SetAttr {
                mode: Some(0o644),
                ..SetAttr::default()
            },
        )),
        Err(Errno::EACCES)
    );
    run(u_file.close()).unwrap();

    // Unmounted `FileRef::new` -> `EPERM`.
    let raw_fs = Rc::new(MemFs::new(
        FsId("mem:raw".into()),
        1,
        0,
        0,
        0o755,
        Box::new(|| (1_700_000_000, 0)),
    ));
    let (_, raw_open) = run(raw_fs.create(
        &Cred::root(),
        &raw_fs.root(),
        "x",
        0o644,
        OpenOptions::new().read(true).write(true),
    ))
    .unwrap();
    let raw_ref = FileRef::new(
        raw_fs.clone(),
        raw_open.clone(),
        Handle {
            fs: raw_fs.id().clone(),
            node: raw_open.node,
            proof: String::new(),
        },
        Cred::root(),
        OpenOptions::new().read(true).write(true),
        env.vfs.releases(),
    );
    assert_eq!(
        run(raw_ref.setattr_as(
            &Cred::root(),
            &SetAttr {
                mode: Some(0o600),
                ..SetAttr::default()
            },
        )),
        Err(Errno::EPERM)
    );
    run(raw_ref.close()).unwrap();
}

#[test]
fn contract2_user_mount_nofollow_and_mount_race_against_mnt_detach() {
    let env = boot_env();
    let alice = user_cred(1001, 1001);
    env.vfs
        .spawn_process(80, 1, alice.clone(), None, None, None)
        .unwrap();

    // Alice owns `/mnt/local` directory creation in this test setup:
    run(env.vfs.setattrat(
        1,
        StartAnchor::Root,
        "/mnt/local",
        &SetAttr {
            uid: Some(1001),
            gid: Some(1001),
            mode: Some(0o755),
            ..SetAttr::default()
        },
        false,
    ))
    .unwrap();
    // Alice plants a symlink `/mnt/local/escape -> /etc`!
    run(env
        .vfs
        .symlinkat(80, "/etc", StartAnchor::Root, "/mnt/local/escape"))
    .unwrap();

    let u_fs = Rc::new(MemFs::new(
        FsId("hostfs:escape".into()),
        1,
        1001,
        1001,
        0o755,
        Box::new(|| (1_700_000_000, 0)),
    ));
    let u_backing = Rc::new(MountBacking::new(u_fs.clone(), FsType::HostFs));
    let sys_ns = env.vfs.system_namespace();

    // Both `/mnt/local/escape` and `/mnt/local/escape/` with `owner_uid = Some(1001)` MUST
    // refuse the final symlink (`ENOTDIR`), never mounting onto `/etc`!
    for target in ["/mnt/local/escape", "/mnt/local/escape/"] {
        assert_eq!(
            run(env.vfs.mount_on_namespace(
                &sys_ns,
                &alice,
                u_backing.clone(),
                None,
                "hostfs:escape",
                target,
                MountFlags::default(),
                0,
                Some(1001),
            )),
            Err(Errno::ENOTDIR),
            "symlink target {target} must be rejected"
        );
    }

    // Unprivileged `Vfs::mount` also rejects symlink target (`ENOTDIR`) and foreign-owned dir (`EPERM`).
    env.factory
        .register_user_grant(1001, FsType::HostFs, "dir:ok", |_cred, _, _, _| {
            let fs = Rc::new(MemFs::new(
                FsId("hostfs:ok".into()),
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
    assert_eq!(
        run(env
            .vfs
            .mount(80, "dir:ok", "/mnt/local/escape", Some("hostfs"), 0, None)),
        Err(Errno::ENOTDIR)
    );

    // `M-P0-11`: Race `mount_on_namespace` across `.await` against `umount2("/mnt/race_p", MNT_DETACH)`!
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/mnt/race_p", 0o755)).unwrap();
    run(env
        .vfs
        .mount(1, "race-parent", "/mnt/race_p", Some("tmpfs"), 0, None))
    .unwrap();
    run(env
        .vfs
        .mkdirat(1, StartAnchor::Root, "/mnt/race_p/child_mp", 0o755))
    .unwrap();

    let slow_child = Rc::new(PendingFs::new("helper:slow-child"));
    slow_child.block_opens.set(true);
    let slow_backing = Rc::new(MountBacking::new(slow_child.clone(), FsType::HelperFs));

    let root_cred = Cred::root();
    {
        let mut mount_fut = std::pin::pin!(env.vfs.mount_on_namespace(
            &sys_ns,
            &root_cred,
            slow_backing,
            None,
            "helper:slow",
            "/mnt/race_p/child_mp",
            MountFlags::default(),
            0,
            None,
        ));
        assert!(matches!(poll_once(&mut mount_fut), Poll::Pending));

        // While `mount_on_namespace` is suspended opening `root_open`, lazily detach `/mnt/race_p`!
        run(env.vfs.umount2(1, "/mnt/race_p", umount_flags::MNT_DETACH)).unwrap();

        slow_child.block_opens.set(false);
        slow_child.wake_all();
        assert_eq!(poll_once(&mut mount_fut), Poll::Ready(Err(Errno::ENOENT)));
    }
    // Newly opened `OpenRef` was cleanly closed (zero leaked opens) and `unshare(CLONE_NEWNS)`
    // (`clone_private`) succeeds without panicking!
    assert_eq!(slow_child.active_opens.get(), 0);
    env.vfs
        .fork_process(1, 81, unshare_flags::CLONE_NEWNS)
        .unwrap();
}

#[test]
fn release_queue_scoping_provider_guards_and_mnt_force_close_abort() {
    let env = boot_env();
    let alice = user_cred(1001, 1001);
    let sys_ns = env.vfs.system_namespace();

    run(env
        .vfs
        .mkdirat(1, StartAnchor::Root, "/mnt/local/stalled", 0o700))
    .unwrap();
    run(env.vfs.setattrat(
        1,
        StartAnchor::Root,
        "/mnt/local/stalled",
        &SetAttr {
            uid: Some(1001),
            gid: Some(1001),
            ..SetAttr::default()
        },
        false,
    ))
    .unwrap();

    let stalled_fs = Rc::new(PendingFs::new("helper:stalled"));
    let stalled_prov = ProviderState::new();
    let stalled_backing = Rc::new(
        MountBacking::new(stalled_fs.clone(), FsType::HelperFs).with_provider(stalled_prov.clone()),
    );
    run(env.vfs.mount_on_namespace(
        &sys_ns,
        &alice,
        stalled_backing,
        None,
        "helper:stalled",
        "/mnt/local/stalled",
        MountFlags::default(),
        0,
        Some(1001),
    ))
    .unwrap();

    env.vfs
        .spawn_process(90, 1, alice.clone(), None, None, None)
        .unwrap();
    write_all(&env.vfs, 90, "/mnt/local/stalled/f1", 0o644, b"1");

    // Open two descriptors on Alice's mount, then stall `fs.release`!
    let (dropped_ref, _) = run(env.vfs.open_file(
        90,
        StartAnchor::Root,
        "/mnt/local/stalled/f1",
        abi::O_RDONLY,
        0,
    ))
    .unwrap();
    let (closing_ref, _) = run(env.vfs.open_file(
        90,
        StartAnchor::Root,
        "/mnt/local/stalled/f1",
        abi::O_RDONLY,
        0,
    ))
    .unwrap();

    stalled_fs.block_releases.set(true);
    // Dropping `dropped_ref` queues a release onto `env.vfs.releases()`.
    drop(dropped_ref);

    // `M-P1-05`: `uid 0` (PID 1) MUST NOT block on Alice's stalled release queue during
    // `chdir`, `openat`/`close`, or `exit_process`!
    run(env.vfs.chdir(1, "/tmp")).unwrap();
    write_all(&env.vfs, 1, "/tmp/root_unblocked", 0o644, b"fast");
    env.vfs.fork_process(1, 91, 0).unwrap();
    run(env.vfs.exit_process(91)).unwrap();
    run(env.vfs.chdir(1, "/")).unwrap();

    // Explicit `closing_ref.close()` parks while `block_releases == true`, and aborts immediately
    // with `EIO` when `umount2(..., MNT_FORCE)` forces the provider!
    {
        let mut close_fut = std::pin::pin!(closing_ref.close());
        assert!(matches!(poll_once(&mut close_fut), Poll::Pending));

        run(env.vfs.umount2(
            1,
            "/mnt/local/stalled",
            umount_flags::MNT_FORCE | umount_flags::MNT_DETACH,
        ))
        .unwrap();
        assert_eq!(poll_once(&mut close_fut), Poll::Ready(Err(Errno::EIO)));
    }

    // Once `ProviderState` is `Lost`, flushing `ReleaseQueue` fast-skips dead providers without hanging!
    stalled_prov.lose();
    assert_eq!(run(env.vfs.releases().flush()), Ok(()));
    stalled_fs.block_releases.set(false);
    stalled_fs.wake_all();
}

#[test]
fn proc_mountinfo_privacy_owner_masking_and_guarded_proc_links() {
    let env = boot_env();
    let alice = user_cred(1001, 1001);
    let bob = user_cred(1002, 1002);
    let sys_ns = env.vfs.system_namespace();

    run(env
        .vfs
        .mkdirat(1, StartAnchor::Root, "/mnt/local/alice_priv", 0o700))
    .unwrap();
    run(env.vfs.setattrat(
        1,
        StartAnchor::Root,
        "/mnt/local/alice_priv",
        &SetAttr {
            uid: Some(1001),
            gid: Some(1001),
            ..SetAttr::default()
        },
        false,
    ))
    .unwrap();
    let a_fs = Rc::new(MemFs::new(
        FsId("hostfs:alice-secret".into()),
        1,
        1001,
        1001,
        0o755,
        Box::new(|| (1_700_000_000, 0)),
    ));
    run(env.vfs.mount_on_namespace(
        &sys_ns,
        &alice,
        Rc::new(MountBacking::new(a_fs, FsType::HostFs)),
        None,
        "hostfs:alice-vault",
        "/mnt/local/alice_priv",
        MountFlags::default(),
        0,
        Some(1001),
    ))
    .unwrap();

    env.vfs
        .spawn_process(101, 1, alice.clone(), None, None, None)
        .unwrap();
    env.vfs
        .spawn_process(102, 1, bob.clone(), None, None, None)
        .unwrap();
    run(env
        .vfs
        .mkdirat(101, StartAnchor::Root, "/mnt/local/alice_priv/sub", 0o700))
    .unwrap();
    run(env.vfs.chdir(101, "/mnt/local/alice_priv/sub")).unwrap();

    // `M-P1-08`: Bob (`uid 1002`) is denied (`EACCES`) on `/proc/101/{mountinfo,mounts}`!
    for p in ["/proc/101/mountinfo", "/proc/101/mounts"] {
        assert_eq!(
            run(env.vfs.statat(102, StartAnchor::Root, p, true)).err(),
            Some(Errno::EACCES),
            "Bob stat {p}"
        );
        assert_eq!(read_all(&env.vfs, 102, p), Err(Errno::EACCES));
    }

    // Alice (`uid 1001`) sees her mount in `/proc/101/mountinfo`, while `uid 0` (PID 1) can read
    // `/proc/101/mountinfo` & `/proc/101/mounts` WITH Alice's `owner_uid` mount masked out!
    let alice_mi =
        String::from_utf8(read_all(&env.vfs, 101, "/proc/101/mountinfo").unwrap()).unwrap();
    assert!(alice_mi.contains("/mnt/local/alice_priv"));

    let root_mi = String::from_utf8(read_all(&env.vfs, 1, "/proc/101/mountinfo").unwrap()).unwrap();
    assert!(
        !root_mi.contains("alice_priv") && !root_mi.contains("alice-vault"),
        "uid 0 mountinfo must mask foreign owner_uid mounts: {root_mi}"
    );
    let root_mounts =
        String::from_utf8(read_all(&env.vfs, 1, "/proc/101/mounts").unwrap()).unwrap();
    assert!(!root_mounts.contains("alice_priv"));

    // `uid 0` calling `readlink("/proc/101/cwd")` goes through `guard_op` and fails `EACCES`
    // because Alice's `cwd` is inside an `owner_uid = Some(1001)` mount!
    assert_eq!(
        run(env.vfs.readlinkat(1, StartAnchor::Root, "/proc/101/cwd")),
        Err(Errno::EACCES)
    );
    assert_eq!(
        run(env.vfs.readlinkat(101, StartAnchor::Root, "/proc/101/cwd")).unwrap(),
        "/mnt/local/alice_priv/sub"
    );
}

#[test]
fn retained_dirfd_magic_links_and_detached_subtree_preserve_mount_topology() {
    let env = boot_env();

    // 1. Retained `DirFd` across `unshare(CLONE_NEWNS)` + `/proc/<other_pid>/root` (`M-P1-09`)
    //    + cross-namespace mountpoint `EBUSY` (`M-P3-03.3`):
    env.vfs.fork_process(1, 110, 0).unwrap();
    let root_dirfd_ns1 = run(env.vfs.openat(
        110,
        StartAnchor::Root,
        "/",
        abi::O_RDONLY | abi::O_DIRECTORY,
        0,
    ))
    .unwrap();

    // PID 110 unshares into a private mount namespace `ns2`.
    env.vfs.unshare(110, unshare_flags::CLONE_NEWNS).unwrap();

    // PID 1 mounts a new tmpfs at `/mnt/ns1_only` in `ns1` AFTER PID 110 unshared!
    run(env
        .vfs
        .mkdirat(1, StartAnchor::Root, "/mnt/ns1_only", 0o755))
    .unwrap();
    run(env
        .vfs
        .mount(1, "ns1-sub", "/mnt/ns1_only", Some("tmpfs"), 0, None))
    .unwrap();
    write_all(&env.vfs, 1, "/mnt/ns1_only/hello.txt", 0o644, b"from-ns1");

    // In PID 110's own root (`ns2`), `/mnt/ns1_only` does not exist;
    // BUT walking via `StartAnchor::DirFd(root_dirfd_ns1)` OR `/proc/1/root/mnt/ns1_only/hello.txt`
    // traverses `ns1`'s mount table, crosses into `ns1-sub`, and unwinds `..` back to `ns1`'s `/mnt`!
    assert_eq!(
        read_all(&env.vfs, 110, "/mnt/ns1_only/hello.txt"),
        Err(Errno::ENOENT)
    );
    let via_dirfd = run(env.vfs.openat(
        110,
        StartAnchor::DirFd(root_dirfd_ns1),
        "mnt/ns1_only/hello.txt",
        abi::O_RDONLY,
        0,
    ))
    .unwrap();
    let mut buf = [0u8; 16];
    let n = run(env.vfs.read(110, via_dirfd, &mut buf)).unwrap();
    assert_eq!(&buf[..n], b"from-ns1");
    run(env.vfs.close(110, via_dirfd)).unwrap();

    // Unwinding `..` out of `ns1_only` via `root_dirfd_ns1`:
    let unwind_fd = run(env.vfs.openat(
        110,
        StartAnchor::DirFd(root_dirfd_ns1),
        "mnt/ns1_only/../ns1_only/hello.txt",
        abi::O_RDONLY,
        0,
    ))
    .unwrap();
    run(env.vfs.close(110, unwind_fd)).unwrap();

    // Cross-namespace `/proc/1/root/...` magic link traversal from PID 110:
    assert_eq!(
        read_all(&env.vfs, 110, "/proc/1/root/mnt/ns1_only/hello.txt").unwrap(),
        b"from-ns1"
    );

    // `M-P3-03.3`: Trying to `rmdir` `/mnt/ns1_only` through `root_dirfd_ns1` from PID 110
    // checks `ns1`'s mount table and returns `EBUSY`!
    assert_eq!(
        run(env.vfs.unlinkat(
            110,
            StartAnchor::DirFd(root_dirfd_ns1),
            "mnt/ns1_only",
            true,
        )),
        Err(Errno::EBUSY)
    );
    run(env.vfs.close(110, root_dirfd_ns1)).unwrap();

    // 2. Detached subtree (`MNT_DETACH`) preserves internal submount crossings & `..` unwind,
    //    and releases both backings cleanly with zero `Rc` cycles when external pins drop!
    let parent_rel = Rc::new(Cell::new(false));
    let child_rel = Rc::new(Cell::new(false));
    let p_flag = Rc::clone(&parent_rel);
    let c_flag = Rc::clone(&child_rel);

    let p_fs = Rc::new(MemFs::new(
        FsId("tmpfs:det-p".into()),
        1,
        0,
        0,
        0o755,
        Box::new(|| (1_700_000_000, 0)),
    ));
    let c_fs = Rc::new(MemFs::new(
        FsId("tmpfs:det-c".into()),
        1,
        0,
        0,
        0o755,
        Box::new(|| (1_700_000_000, 0)),
    ));
    let sys_ns = env.vfs.system_namespace();
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/mnt/det_p", 0o755)).unwrap();
    run(env.vfs.mount_on_namespace(
        &sys_ns,
        &Cred::root(),
        Rc::new(MountBacking::new(p_fs, FsType::TmpFs).with_on_release(move || p_flag.set(true))),
        None,
        "det-p",
        "/mnt/det_p",
        MountFlags::default(),
        0,
        None,
    ))
    .unwrap();
    write_all(&env.vfs, 1, "/mnt/det_p/pfile.txt", 0o644, b"parent");
    run(env
        .vfs
        .mkdirat(1, StartAnchor::Root, "/mnt/det_p/sub", 0o755))
    .unwrap();
    run(env.vfs.mount_on_namespace(
        &sys_ns,
        &Cred::root(),
        Rc::new(MountBacking::new(c_fs, FsType::TmpFs).with_on_release(move || c_flag.set(true))),
        None,
        "det-c",
        "/mnt/det_p/sub",
        MountFlags::default(),
        0,
        None,
    ))
    .unwrap();
    write_all(&env.vfs, 1, "/mnt/det_p/sub/cfile.txt", 0o644, b"child");

    let det_dirfd = run(env.vfs.openat(
        1,
        StartAnchor::Root,
        "/mnt/det_p",
        abi::O_RDONLY | abi::O_DIRECTORY,
        0,
    ))
    .unwrap();

    // Lazily detach `/mnt/det_p` (which detaches both `det-p` and `det-c` as a `DetachedGroup`)!
    run(env.vfs.umount2(1, "/mnt/det_p", umount_flags::MNT_DETACH)).unwrap();
    assert!(!parent_rel.get() && !child_rel.get());

    // Walking from `det_dirfd` crosses into `sub/cfile.txt` AND unwinds `sub/../pfile.txt`!
    let cfd = run(env.vfs.openat(
        1,
        StartAnchor::DirFd(det_dirfd),
        "sub/cfile.txt",
        abi::O_RDONLY,
        0,
    ))
    .unwrap();
    let n = run(env.vfs.read(1, cfd, &mut buf)).unwrap();
    assert_eq!(&buf[..n], b"child");
    run(env.vfs.close(1, cfd)).unwrap();

    let pfd = run(env.vfs.openat(
        1,
        StartAnchor::DirFd(det_dirfd),
        "sub/../pfile.txt",
        abi::O_RDONLY,
        0,
    ))
    .unwrap();
    let n = run(env.vfs.read(1, pfd, &mut buf)).unwrap();
    assert_eq!(&buf[..n], b"parent");
    run(env.vfs.close(1, pfd)).unwrap();

    // Closing the last external pin (`det_dirfd`) breaks internal group links and drops both backings!
    run(env.vfs.close(1, det_dirfd)).unwrap();
    assert!(parent_rel.get(), "detached parent backing must release");
    assert!(child_rel.get(), "detached child backing must release");
}

#[test]
fn exec_preserve_unshares_clone_files_and_dirsync_synchronous_durability() {
    let env = boot_env();

    // 1. `M-P1-10`: `exec_preserve` unshares `CLONE_FILES` before `close_on_exec`!
    write_all(&env.vfs, 1, "/tmp/shared_cloexec", 0o644, b"keep-in-parent");
    env.vfs.fork_process(1, 120, 0).unwrap();
    let cfd = run(env.vfs.openat(
        120,
        StartAnchor::Root,
        "/tmp/shared_cloexec",
        abi::O_RDONLY | os_vfs::vfs::O_CLOEXEC,
        0,
    ))
    .unwrap();
    env.vfs
        .fork_process(120, 121, unshare_flags::CLONE_FILES)
        .unwrap();

    run(env.vfs.exec_preserve(121)).unwrap();
    // Closed in `121`, STILL open and readable in `120`!
    let mut buf = [0u8; 32];
    assert_eq!(run(env.vfs.read(121, cfd, &mut buf)), Err(Errno::EBADF));
    let n = run(env.vfs.read(120, cfd, &mut buf)).unwrap();
    assert_eq!(&buf[..n], b"keep-in-parent");
    run(env.vfs.close(120, cfd)).unwrap();

    // 2. `M-P1-11`: `MS_DIRSYNC` on `0300` (`wx`-only) directory + sync error propagation + zero
    //    `OpenRef` leak on `open_file` post-open sync error + `MS_SYNCHRONOUS` on `setattrat`/`xattr`!
    let dur_fs = Rc::new(PendingFs::new("helper:durable"));
    let dur_backing = Rc::new(MountBacking::new(dur_fs.clone(), FsType::HelperFs));
    let sys_ns = env.vfs.system_namespace();
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/mnt/dur", 0o755)).unwrap();
    run(env.vfs.mount_on_namespace(
        &sys_ns,
        &Cred::root(),
        dur_backing.clone(),
        None,
        "helper:durable",
        "/mnt/dur",
        MountFlags::from_accepted(mount_flags::MS_SYNCHRONOUS | mount_flags::MS_DIRSYNC),
        0,
        None,
    ))
    .unwrap();

    // Create a `0300` (`-wx------`) directory owned by Alice (`1001`), and have Alice create a file inside!
    run(env
        .vfs
        .mkdirat(1, StartAnchor::Root, "/mnt/dur/wx_dir", 0o300))
    .unwrap();
    run(env.vfs.setattrat(
        1,
        StartAnchor::Root,
        "/mnt/dur/wx_dir",
        &SetAttr {
            uid: Some(1001),
            gid: Some(1001),
            mode: Some(0o300),
            ..SetAttr::default()
        },
        false,
    ))
    .unwrap();
    env.vfs
        .spawn_process(122, 1, user_cred(1001, 1001), None, None, None)
        .unwrap();
    let wx_fd = run(env.vfs.openat(
        122,
        StartAnchor::Root,
        "/mnt/dur/wx_dir/created.txt",
        abi::O_CREAT | abi::O_WRONLY,
        0o600,
    ))
    .unwrap();
    run(env.vfs.close(122, wx_fd)).unwrap();

    // `setattrat`, `setxattrat`, and `removexattrat` all invoke real `sync_all` on `MS_SYNCHRONOUS`!
    for op in ["setattr", "setxattr", "removexattr"] {
        let before_calls = dur_fs.sync_calls.get();
        let before_rec = dur_backing.sync_count();
        match op {
            "setattr" => {
                run(env.vfs.setattrat(
                    122,
                    StartAnchor::Root,
                    "/mnt/dur/wx_dir/created.txt",
                    &SetAttr {
                        mode: Some(0o640),
                        ..SetAttr::default()
                    },
                    false,
                ))
                .unwrap();
            }
            "setxattr" => {
                run(env.vfs.setxattrat(
                    122,
                    StartAnchor::Root,
                    "/mnt/dur/wx_dir/created.txt",
                    "user.tag",
                    b"v1",
                    XattrFlags::empty(),
                    false,
                ))
                .unwrap();
            }
            "removexattr" => {
                run(env.vfs.removexattrat(
                    122,
                    StartAnchor::Root,
                    "/mnt/dur/wx_dir/created.txt",
                    "user.tag",
                    false,
                ))
                .unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            dur_fs.sync_calls.get() > before_calls && dur_backing.sync_count() > before_rec,
            "MS_SYNCHRONOUS must invoke real sync_all on {op}"
        );
    }

    // Inject `EIO` on `sync_all`: `open_file` with `O_CREAT` MUST return `Err(Errno::EIO)` AND
    // release the newly created `OpenRef` (`active_opens` returns to baseline = 1 for `root_open`)!
    let baseline_opens = dur_fs.active_opens.get();
    dur_fs.fail_sync.set(Some(Errno::EIO));
    assert_eq!(
        run(env.vfs.openat(
            122,
            StartAnchor::Root,
            "/mnt/dur/wx_dir/fail_sync.txt",
            abi::O_CREAT | abi::O_WRONLY,
            0o600,
        )),
        Err(Errno::EIO)
    );
    assert_eq!(
        dur_fs.active_opens.get(),
        baseline_opens,
        "open_file must not leak OpenRef when post-open sync fails"
    );
    assert_eq!(
        run(env
            .vfs
            .mkdirat(122, StartAnchor::Root, "/mnt/dur/wx_dir/sub_fail", 0o700)),
        Err(Errno::EIO)
    );
    dur_fs.fail_sync.set(None);
}

#[test]
fn p2_and_p3_mountinfo_rbind_rename_slashes_setns_atime_chardev_and_misc() {
    let env = boot_env();
    let sys_ns = env.vfs.system_namespace();

    // 1. `M-P2-01`: `ShareFs` `Revoked` stays terminal across subsequent `Disconnected`!
    let pub_mem = Rc::new(MemFs::new(
        FsId("share:pub".into()),
        1,
        1001,
        1001,
        0o755,
        Box::new(|| (1_700_000_000, 0)),
    ));
    let transport = LoopbackShareTransport::new(pub_mem);
    let fault = transport.fault_handle();
    let share_prov = ProviderState::new();
    let share_fs = ShareFs::new(transport, share_prov.clone(), false, false);
    fault.set(Some(ShareError::Revoked));
    assert_eq!(
        run(share_fs.statfs(&Cred::root())).err(),
        Some(Errno::EACCES)
    );
    assert_eq!(share_prov.health(), ProviderHealth::Revoked);
    fault.set(Some(ShareError::Disconnected));
    assert_eq!(
        run(share_fs.statfs(&Cred::root())).err(),
        Some(Errno::EACCES)
    );
    assert_eq!(share_prov.health(), ProviderHealth::Revoked);

    // 2. `M-P2-02`: Topological `mountinfo` order after `MS_MOVE` + chroot subdirectory `/` emission!
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/mnt/older", 0o755)).unwrap();
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/mnt/newer", 0o755)).unwrap();
    // `older` gets a lower `MountId` than `newer`:
    run(env
        .vfs
        .mount(1, "older-src", "/mnt/older", Some("tmpfs"), 0, None))
    .unwrap();
    run(env
        .vfs
        .mount(1, "newer-src", "/mnt/newer", Some("tmpfs"), 0, None))
    .unwrap();
    run(env
        .vfs
        .mkdirat(1, StartAnchor::Root, "/mnt/newer/slot", 0o755))
    .unwrap();
    // Move `older` (lower `MountId`) onto `/mnt/newer/slot` (higher `MountId`):
    run(env.vfs.mount(
        1,
        "/mnt/older",
        "/mnt/newer/slot",
        None,
        mount_flags::MS_MOVE,
        None,
    ))
    .unwrap();
    let mi = String::from_utf8(read_all(&env.vfs, 1, "/proc/self/mountinfo").unwrap()).unwrap();
    let pos_newer = mi.find(" /mnt/newer ").expect("newer in mountinfo");
    let pos_older = mi
        .find(" /mnt/newer/slot ")
        .expect("moved older in mountinfo");
    assert!(
        pos_newer < pos_older,
        "parent mount /mnt/newer must precede child /mnt/newer/slot in mountinfo:\n{mi}"
    );

    // Chroot into subdirectory `/mnt/newer/subjail` (not itself a mountpoint): `/proc/self/mountinfo`
    // emits the containing mount at `"/"` with `root` field `"/subjail"`!
    run(env
        .vfs
        .mkdirat(1, StartAnchor::Root, "/mnt/newer/subjail", 0o755))
    .unwrap();
    run(env
        .vfs
        .mkdirat(1, StartAnchor::Root, "/mnt/newer/subjail/proc", 0o555))
    .unwrap();
    run(env.vfs.mount(
        1,
        "/proc",
        "/mnt/newer/subjail/proc",
        None,
        mount_flags::MS_BIND,
        None,
    ))
    .unwrap();
    env.vfs.fork_process(1, 130, 0).unwrap();
    run(env.vfs.chroot(130, "/mnt/newer/subjail")).unwrap();
    run(env.vfs.chdir(130, "/")).unwrap();
    let subjail_mi =
        String::from_utf8(read_all(&env.vfs, 130, "/proc/self/mountinfo").unwrap()).unwrap();
    assert!(
        subjail_mi
            .lines()
            .any(|l| l.contains(" /subjail / ") && l.contains(" newer-src ")),
        "chroot into subdir must emit containing mount at / with /subjail root:\n{subjail_mi}"
    );

    // 3. `M-P2-05` & `M-P3-01.3`: Chrooted `setns` -> `EINVAL` (no chroot escape!), and `setns`
    //    checks `EBADF` / `O_PATH` (`EBADF`) before `nstype` (`EINVAL`)!
    env.vfs
        .fork_process(1, 131, unshare_flags::CLONE_NEWNS | unshare_flags::CLONE_FS)
        .unwrap(); // `M-P3-02.1`: `CLONE_NEWNS | CLONE_FS` allowed!
    let ns131_fd = run(env
        .vfs
        .openat(1, StartAnchor::Root, "/proc/131/ns/mnt", abi::O_RDONLY, 0))
    .unwrap();
    // Copy `ns131_fd` into chrooted PID 130's `FdTable` and verify `setns` is rejected with `EINVAL`:
    let ns_file_ref = env
        .vfs
        .process_fds(1)
        .unwrap()
        .borrow()
        .get(ns131_fd)
        .unwrap();
    let jailed_ns_fd = env
        .vfs
        .process_fds(130)
        .unwrap()
        .borrow_mut()
        .insert(ns_file_ref, false)
        .unwrap();
    assert_eq!(
        env.vfs.setns(130, jailed_ns_fd, unshare_flags::CLONE_NEWNS),
        Err(Errno::EINVAL)
    );
    // Invalid fd & `O_PATH` fd return `EBADF` even when `nstype` is bogus (`0xdead`):
    assert_eq!(env.vfs.setns(1, 999, 0xdead), Err(Errno::EBADF));
    let opath_ns = run(env.vfs.openat(
        1,
        StartAnchor::Root,
        "/proc/131/ns/mnt",
        abi::O_PATH | abi::O_RDONLY,
        0,
    ))
    .unwrap();
    assert_eq!(env.vfs.setns(1, opath_ns, 0xdead), Err(Errno::EBADF));
    run(env.vfs.close(1, opath_ns)).unwrap();
    run(env.vfs.close(1, ns131_fd)).unwrap();

    // 4. `M-P2-03`: `uid 0` `MS_BIND | MS_REC` succeeds over subtree containing `owner_uid` mount!
    run(env
        .vfs
        .mkdirat(1, StartAnchor::Root, "/mnt/local/u_sub", 0o700))
    .unwrap();
    run(env.vfs.setattrat(
        1,
        StartAnchor::Root,
        "/mnt/local/u_sub",
        &SetAttr {
            uid: Some(1001),
            gid: Some(1001),
            ..SetAttr::default()
        },
        false,
    ))
    .unwrap();
    let u_sub_fs = Rc::new(MemFs::new(
        FsId("hostfs:u-sub".into()),
        1,
        1001,
        1001,
        0o755,
        Box::new(|| (1_700_000_000, 0)),
    ));
    run(env.vfs.mount_on_namespace(
        &sys_ns,
        &user_cred(1001, 1001),
        Rc::new(MountBacking::new(u_sub_fs, FsType::HostFs)),
        None,
        "hostfs:u-sub",
        "/mnt/local/u_sub",
        MountFlags::default(),
        0,
        Some(1001),
    ))
    .unwrap();
    run(env
        .vfs
        .mkdirat(1, StartAnchor::Root, "/mnt/rbind_dst", 0o755))
    .unwrap();
    run(env.vfs.mount(
        1,
        "/mnt/local",
        "/mnt/rbind_dst",
        None,
        mount_flags::MS_BIND | mount_flags::MS_REC,
        None,
    ))
    .unwrap();
    // `owner_uid = Some(1001)` preserved on the cloned child mount!
    assert_eq!(
        run(env
            .vfs
            .statat(1, StartAnchor::Root, "/mnt/rbind_dst/u_sub", true))
        .err(),
        Some(Errno::EACCES)
    );

    // 5. `M-P2-04`: `renameat` independent `src`/`dst` trailing slashes!
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/tmp/rn", 0o755)).unwrap();
    write_all(&env.vfs, 1, "/tmp/rn/f", 0o644, b"file");
    write_all(&env.vfs, 1, "/tmp/rn/f2", 0o644, b"file2");
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/tmp/rn/d", 0o755)).unwrap();
    assert_eq!(
        run(env.vfs.renameat(
            1,
            StartAnchor::Root,
            "/tmp/rn/f",
            StartAnchor::Root,
            "/tmp/rn/d/",
            RenameFlags::empty(),
        )),
        Err(Errno::EISDIR)
    );
    assert_eq!(
        run(env.vfs.renameat(
            1,
            StartAnchor::Root,
            "/tmp/rn/d",
            StartAnchor::Root,
            "/tmp/rn/missing/",
            RenameFlags::empty(),
        )),
        Err(Errno::ENOENT)
    );
    assert_eq!(
        run(env.vfs.renameat(
            1,
            StartAnchor::Root,
            "/tmp/rn/f/",
            StartAnchor::Root,
            "/tmp/rn/newf",
            RenameFlags::empty(),
        )),
        Err(Errno::ENOTDIR)
    );
    assert_eq!(
        run(env.vfs.renameat(
            1,
            StartAnchor::Root,
            "/tmp/rn/d",
            StartAnchor::Root,
            "/tmp/rn/f2/",
            RenameFlags::empty(),
        )),
        Err(Errno::ENOTDIR)
    );

    // 6. `M-P2-06`: Mount atime flags (`MS_NOATIME`, `MS_NODIRATIME`, `MS_STRICTATIME`, `MS_RDONLY`)!
    let now_sec = Rc::new(Cell::new(1_700_000_000u64));
    let c1 = Rc::clone(&now_sec);
    let atime_fs = Rc::new(MemFs::new(
        FsId("tmpfs:atime".into()),
        1,
        0,
        0,
        0o755,
        Box::new(move || (c1.get(), 0)),
    ));
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/mnt/atime", 0o755)).unwrap();
    run(env.vfs.mount_on_namespace(
        &sys_ns,
        &Cred::root(),
        Rc::new(MountBacking::new(atime_fs, FsType::TmpFs)),
        None,
        "tmpfs:atime",
        "/mnt/atime",
        MountFlags::from_accepted(mount_flags::MS_NOATIME),
        0,
        None,
    ))
    .unwrap();
    write_all(&env.vfs, 1, "/mnt/atime/doc", 0o644, b"hello");
    run(env
        .vfs
        .mkdirat(1, StartAnchor::Root, "/mnt/atime/dir", 0o755))
    .unwrap();

    // Advance clock by 2 days; under `MS_NOATIME`, neither file read nor dir `fd_readdir` updates atime!
    now_sec.set(1_700_200_000);
    assert_eq!(read_all(&env.vfs, 1, "/mnt/atime/doc").unwrap(), b"hello");
    let dfd = run(env.vfs.openat(
        1,
        StartAnchor::Root,
        "/mnt/atime/dir",
        abi::O_RDONLY | abi::O_DIRECTORY,
        0,
    ))
    .unwrap();
    let _ = run(env.vfs.fd_readdir(1, dfd)).unwrap();
    run(env.vfs.close(1, dfd)).unwrap();
    assert_eq!(
        run(env.vfs.statat(1, StartAnchor::Root, "/mnt/atime/doc", true))
            .unwrap()
            .atime,
        1_700_000_000
    );
    assert_eq!(
        run(env.vfs.statat(1, StartAnchor::Root, "/mnt/atime/dir", true))
            .unwrap()
            .atime,
        1_700_000_000
    );

    // Remount `MS_NODIRATIME`: file read updates `atime`, dir `fd_readdir` does NOT!
    run(env.vfs.mount(
        1,
        "",
        "/mnt/atime",
        None,
        mount_flags::MS_REMOUNT | mount_flags::MS_NODIRATIME,
        None,
    ))
    .unwrap();
    assert_eq!(read_all(&env.vfs, 1, "/mnt/atime/doc").unwrap(), b"hello");
    let dfd = run(env.vfs.openat(
        1,
        StartAnchor::Root,
        "/mnt/atime/dir",
        abi::O_RDONLY | abi::O_DIRECTORY,
        0,
    ))
    .unwrap();
    let _ = run(env.vfs.fd_readdir(1, dfd)).unwrap();
    run(env.vfs.close(1, dfd)).unwrap();
    assert_eq!(
        run(env.vfs.statat(1, StartAnchor::Root, "/mnt/atime/doc", true))
            .unwrap()
            .atime,
        1_700_200_000
    );
    assert_eq!(
        run(env.vfs.statat(1, StartAnchor::Root, "/mnt/atime/dir", true))
            .unwrap()
            .atime,
        1_700_000_000
    );

    // Remount `MS_STRICTATIME`: advancing clock by just 5 seconds updates `atime` even though `atime > mtime`!
    run(env.vfs.mount(
        1,
        "",
        "/mnt/atime",
        None,
        mount_flags::MS_REMOUNT | mount_flags::MS_STRICTATIME,
        None,
    ))
    .unwrap();
    now_sec.set(1_700_200_005);
    assert_eq!(read_all(&env.vfs, 1, "/mnt/atime/doc").unwrap(), b"hello");
    assert_eq!(
        run(env.vfs.statat(1, StartAnchor::Root, "/mnt/atime/doc", true))
            .unwrap()
            .atime,
        1_700_200_005
    );

    // 7. `M-P3-01`..`M-P3-03`:
    // - `open(existing_dir, O_RDONLY | O_CREAT)` -> `EISDIR`:
    assert_eq!(
        run(env.vfs.openat(
            1,
            StartAnchor::Root,
            "/tmp",
            abi::O_RDONLY | abi::O_CREAT,
            0o644,
        )),
        Err(Errno::EISDIR)
    );

    // - `CharDevice` on `MS_RDONLY` mount (`M-P3-01.2`):
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/mnt/ro_dev", 0o755)).unwrap();
    run(env
        .vfs
        .mount(1, "/dev", "/mnt/ro_dev", None, mount_flags::MS_BIND, None))
    .unwrap();
    let null_wfd = run(env
        .vfs
        .openat(1, StartAnchor::Root, "/mnt/ro_dev/null", abi::O_WRONLY, 0))
    .unwrap();
    // Remount `MS_RDONLY` succeeds even while `/mnt/ro_dev/null` is open `O_WRONLY`!
    run(env.vfs.mount(
        1,
        "",
        "/mnt/ro_dev",
        None,
        mount_flags::MS_REMOUNT | mount_flags::MS_BIND | mount_flags::MS_RDONLY,
        None,
    ))
    .unwrap();
    assert_eq!(run(env.vfs.write(1, null_wfd, b"ok")).unwrap(), 2);
    run(env.vfs.close(1, null_wfd)).unwrap();
    assert_eq!(
        run(env
            .vfs
            .accessat(1, StartAnchor::Root, "/mnt/ro_dev/null", abi::W_OK, true)),
        Ok(())
    );
    let null_wfd2 = run(env
        .vfs
        .openat(1, StartAnchor::Root, "/mnt/ro_dev/null", abi::O_WRONLY, 0))
    .unwrap();
    run(env.vfs.close(1, null_wfd2)).unwrap();

    // - `remount,ro` returns `EBUSY` while an async write is in flight (`M-P3-01.5`) &
    //   `fsync` on `O_PATH` -> `EBADF` & `Lost` -> `ENOTCONN` (`M-P3-01.4`):
    let inflight_fs = Rc::new(PendingFs::new("helper:inflight"));
    let inflight_prov = ProviderState::new();
    run(env.vfs.mkdirat(1, StartAnchor::Root, "/mnt/inf", 0o755)).unwrap();
    run(env.vfs.mount_on_namespace(
        &sys_ns,
        &Cred::root(),
        Rc::new(
            MountBacking::new(inflight_fs.clone(), FsType::HelperFs)
                .with_provider(inflight_prov.clone()),
        ),
        None,
        "helper:inflight",
        "/mnt/inf",
        MountFlags::default(),
        0,
        None,
    ))
    .unwrap();
    let wfd = run(env.vfs.openat(
        1,
        StartAnchor::Root,
        "/mnt/inf/w",
        abi::O_CREAT | abi::O_RDWR,
        0o644,
    ))
    .unwrap();
    let opath_w = run(env.vfs.openat(
        1,
        StartAnchor::Root,
        "/mnt/inf/w",
        abi::O_PATH | abi::O_RDONLY,
        0,
    ))
    .unwrap();
    assert_eq!(run(env.vfs.fsync(1, opath_w)), Err(Errno::EBADF));
    assert_eq!(run(env.vfs.fdatasync(1, opath_w)), Err(Errno::EBADF));
    run(env.vfs.close(1, opath_w)).unwrap();

    inflight_fs.block_writes.set(true);
    {
        let mut w_fut = std::pin::pin!(env.vfs.write(1, wfd, b"inflight"));
        assert!(matches!(poll_once(&mut w_fut), Poll::Pending));
        // Close `wfd` so `writable_opens == 0` were it not for `w_fut` holding its `FileRef`,
        // OR test with read-only metadata mutation (`setattr` has `writable_opens == 0`!):
        inflight_fs.block_writes.set(false);
        inflight_fs.wake_all();
        assert_eq!(poll_once(&mut w_fut), Poll::Ready(Ok(8)));
    }
    run(env.vfs.close(1, wfd)).unwrap();

    // Test `in_flight_writes` directly with no writable opens: reopen `O_RDONLY`, check `Lost` fsync -> `ENOTCONN`:
    let r_inf = run(env
        .vfs
        .openat(1, StartAnchor::Root, "/mnt/inf/w", abi::O_RDONLY, 0))
    .unwrap();
    inflight_prov.lose();
    assert_eq!(run(env.vfs.fsync(1, r_inf)), Err(Errno::ENOTCONN));
    run(env.vfs.close(1, r_inf)).unwrap();

    inflight_prov.reconnect();
    inflight_fs.block_opens.set(true);
    {
        let mut create_fut = std::pin::pin!(env.vfs.openat(
            1,
            StartAnchor::Root,
            "/mnt/inf/creating_ro",
            abi::O_CREAT | abi::O_RDONLY,
            0o644,
        ));
        assert!(matches!(poll_once(&mut create_fut), Poll::Pending));
        // `writable_opens == 0`, yet `in_flight_writes == 1` -> `MS_REMOUNT | MS_RDONLY` returns `EBUSY`!
        assert_eq!(
            run(env.vfs.mount(
                1,
                "",
                "/mnt/inf",
                None,
                mount_flags::MS_REMOUNT | mount_flags::MS_RDONLY,
                None,
            )),
            Err(Errno::EBUSY)
        );
        inflight_fs.block_opens.set(false);
        inflight_fs.wake_all();
        let created_fd = match poll_once(&mut create_fut) {
            Poll::Ready(Ok(fd)) => fd,
            other => panic!("expected Ready(Ok(fd)), got {other:?}"),
        };
        run(env.vfs.close(1, created_fd)).unwrap();
    }

    // - `getcwd` > `abi::PATH_MAX` -> `ENAMETOOLONG` (`M-P3-02.2`):
    env.vfs.fork_process(1, 132, 0).unwrap();
    run(env.vfs.mkdirat(132, StartAnchor::Root, "/tmp/deep", 0o755)).unwrap();
    run(env.vfs.chdir(132, "/tmp/deep")).unwrap();
    let seg = "a".repeat(200);
    for _ in 0..22 {
        run(env.vfs.mkdirat(132, StartAnchor::AtFdCwd, &seg, 0o755)).unwrap();
        run(env.vfs.chdir(132, &seg)).unwrap();
    }
    assert_eq!(run(env.vfs.getcwd(132)), Err(Errno::ENAMETOOLONG));

    // - `/proc/self/fd/<n>` reopen on unmounted `FileRef` AND virtual `/proc` file (`M-P3-03.2`):
    let unmounted_fs = Rc::new(MemFs::new(
        FsId("mem:unmounted".into()),
        1,
        0,
        0,
        0o755,
        Box::new(|| (1_700_000_000, 0)),
    ));
    let (u_ent, u_open) = run(unmounted_fs.create(
        &Cred::root(),
        &unmounted_fs.root(),
        "anon",
        0o644,
        OpenOptions::new().read(true).write(true),
    ))
    .unwrap();
    run(unmounted_fs.write_at(&u_open, b"unmounted-ok", WriteAt::Offset(0))).unwrap();
    let u_fref = FileRef::new(
        unmounted_fs,
        u_open,
        u_ent.handle,
        Cred::root(),
        OpenOptions::new().read(true).write(true),
        env.vfs.releases(),
    );
    let u_fd = env
        .vfs
        .process_fds(1)
        .unwrap()
        .borrow_mut()
        .insert(u_fref, false)
        .unwrap();
    assert_eq!(
        read_all(&env.vfs, 1, &format!("/proc/self/fd/{u_fd}")).unwrap(),
        b"unmounted-ok"
    );
    run(env.vfs.close(1, u_fd)).unwrap();

    let proc_mounts_fd =
        run(env
            .vfs
            .openat(1, StartAnchor::Root, "/proc/self/mounts", abi::O_RDONLY, 0))
        .unwrap();
    let reopened_mounts =
        read_all(&env.vfs, 1, &format!("/proc/self/fd/{proc_mounts_fd}")).unwrap();
    assert!(!reopened_mounts.is_empty());
    run(env.vfs.close(1, proc_mounts_fd)).unwrap();

    // - `linkat` POSIX error ordering (`tests/links.spec.js:90-92`):
    //   `linkat(dir, existing_file) == Err(Errno::EPERM)` (checked BEFORE `EEXIST`, leaving
    //   `existing_file` untouched under `ln -f`) and `linkat(file, existing_dir) == Err(Errno::EEXIST)`.
    run(env
        .vfs
        .mkdirat(1, StartAnchor::Root, "/tmp/ln_src_dir", 0o755))
    .unwrap();
    write_all(&env.vfs, 1, "/tmp/ln_existing_file", 0o644, b"keep\n");
    write_all(&env.vfs, 1, "/tmp/ln_src_file", 0o644, b"src\n");
    run(env
        .vfs
        .mkdirat(1, StartAnchor::Root, "/tmp/ln_existing_dir", 0o755))
    .unwrap();
    assert_eq!(
        run(env.vfs.linkat(
            1,
            StartAnchor::Root,
            "/tmp/ln_src_dir",
            StartAnchor::Root,
            "/tmp/ln_existing_file",
            false,
        ))
        .err(),
        Some(Errno::EPERM)
    );
    assert_eq!(
        read_all(&env.vfs, 1, "/tmp/ln_existing_file").unwrap(),
        b"keep\n"
    );
    assert_eq!(
        run(env.vfs.linkat(
            1,
            StartAnchor::Root,
            "/tmp/ln_src_file",
            StartAnchor::Root,
            "/tmp/ln_existing_dir",
            false,
        ))
        .err(),
        Some(Errno::EEXIST)
    );
}
