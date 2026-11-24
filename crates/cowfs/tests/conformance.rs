//! Differential POSIX conformance suite for `os-cowfs` (`#77`, Blueprint §3.2):
//! - Runs the full `os-vfs` Linux semantics suite on BOTH `MemoryHeadStore+MemoryPackStore` AND
//!   real native SQLite (`WAL`+`synchronous=FULL`) + `NativePackStore` + `flock`.
//! - Covers `ORPHAN_ITEM` open-unlink persistence and automatic reaping on next RW mount.
//! - Covers `Vfs` mount/namespace/chroot integration (`FsType::Cowfs`, `read_dir_page`, `ficlone`,
//!   `syncfs`).
//! - Covers `/dev/vd0` (`DevTmpFs::register_vblk`, `VblkRegistry`, `BLK_INFO`, `BLK_LEASE`,
//!   `COWFS_IOC_{INFO,SNAPSHOT,FORK}`, root vs non-root `EPERM`, `ENOTTY`/`EBADF`, `EOPNOTSUPP`
//!   on raw read/write, and `mkfs.cowfs` `ENOTBLK`/`EBUSY`/`EEXIST`).

#[path = "support/remote_transport.rs"]
mod remote_transport;
use abi::contract::{Durability, WriterModel, cowfs_ioctl, fs_magic, mount_flags, unshare_flags};
use abi::volume::{BlkInfoResp, BlkLeaseResp, CowfsForkResp, CowfsInfoResp, CowfsSnapshotResp};
use abi::{ACL_ACCESS, ACL_DEFAULT, Errno};
use cowtree::memory::{MemoryHeadStore, MemoryPackStore};
use cowtree::{ArenaConfig, HeadStore, PackStore, VolumeId, WriterMode};
use os_cowfs::native_sqlite::{NativePackStore, NativeSqliteHeadStore};
use os_cowfs::{
    CowFs, CowFsClock, CowFsConfig, CowFsOpenMode, CowFsVolumeDevice, cowfs_ioctl_mounted,
};
use std::cell::Cell;
use std::collections::BTreeSet;
use std::future::Future;
use std::path::PathBuf;
use std::pin::pin;
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, atomic::AtomicUsize};
use std::task::{Context, Poll, Wake, Waker};
use vfs::devfs::{DefaultDeviceBackend, DevTmpFs};
use vfs::memfs::MemFs;
use vfs::vblk::{VblkDeviceBackend, VblkRegistry};
use vfs::{
    Cred, DefaultFilesystemFactory, FILE_MAX, FdTable, FileRef, Filesystem, FsId, FsType, Handle,
    Identity, LockFamily, LockKind, LockRange, MountBacking, MountFlags, OpenOptions, OpenRef,
    ReleaseQueue, RenameFlags, SetAttr, StartAnchor, Stop, Time, Timespec, Vfs, WriteAt, Written,
    XattrFlags, now_or_never,
};

#[derive(Default)]
struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn run<F: Future>(fut: F) -> F::Output {
    now_or_never(fut).expect("local cowfs future resolves synchronously")
}

fn ticking_clock() -> CowFsClock {
    let tick = Cell::new(100u64);
    Rc::new(move || {
        let next = tick.get() + 1;
        tick.set(next);
        Timespec { sec: next, nsec: 0 }
    })
}

fn user(id: u32) -> Cred {
    Cred::new(Identity {
        id,
        group: id,
        groups: BTreeSet::from([id]),
    })
}

fn names(path: &str) -> Vec<String> {
    path.split('/').map(String::from).collect()
}

fn read_opt() -> OpenOptions {
    *OpenOptions::new().read(true)
}
fn write_opt() -> OpenOptions {
    *OpenOptions::new().write(true)
}
fn rw_opt() -> OpenOptions {
    *OpenOptions::new().read(true).write(true)
}
fn path_opt() -> OpenOptions {
    *OpenOptions::new().path(true)
}
fn exec_opt() -> OpenOptions {
    *OpenOptions::new().exec(true)
}
fn create_new(mut opts: OpenOptions) -> OpenOptions {
    *opts.create_new(true)
}
fn range(start: u64, end: u64) -> LockRange {
    LockRange::try_from(start..end).unwrap()
}

struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        static SEQ: AtomicU64 = AtomicU64::new(1);
        let id = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("os-cowfs-conf-{tag}-{}-{id}", std::process::id()));
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

fn make_mem_cowfs(vol_name: &str) -> Rc<CowFs<MemoryHeadStore, MemoryPackStore>> {
    let hs = Rc::new(MemoryHeadStore::new());
    let ps = Rc::new(MemoryPackStore::new());
    let vol = VolumeId(vol_name.into());
    let clock = ticking_clock();
    run(CowFs::format_volume(
        &*hs,
        &*ps,
        vol.clone(),
        0,
        0,
        0o1777,
        clock(),
    ))
    .unwrap();
    let cfg = CowFsConfig::local_native(clock).with_arena(ArenaConfig::fixed_32mib());
    Rc::new(
        run(CowFs::open(
            hs,
            ps,
            vol,
            CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
            cfg,
        ))
        .unwrap(),
    )
}

fn make_sqlite_cowfs(
    dir: &TempDir,
    vol_name: &str,
) -> Rc<CowFs<NativeSqliteHeadStore, NativePackStore>> {
    let hs = Rc::new(NativeSqliteHeadStore::open(&dir.0).unwrap());
    let ps = Rc::new(NativePackStore::open(&dir.0).unwrap());
    let vol = VolumeId(vol_name.into());
    let clock = ticking_clock();
    run(CowFs::format_volume(
        &*hs,
        &*ps,
        vol.clone(),
        0,
        0,
        0o1777,
        clock(),
    ))
    .unwrap();
    let cfg = CowFsConfig::local_native(clock).with_arena(ArenaConfig::fixed_32mib());
    Rc::new(
        run(CowFs::open(
            hs,
            ps,
            vol,
            CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
            cfg,
        ))
        .unwrap(),
    )
}

fn new_file<H: HeadStore + 'static, P: PackStore + 'static>(
    fs: &CowFs<H, P>,
    cred: &Cred,
    dir: &Handle,
    name: &str,
    mode: u16,
    data: &[u8],
) -> Handle {
    let (entry, open) = run(fs.create(cred, dir, name, mode, &create_new(write_opt()))).unwrap();
    run(fs.write_at(&open, data, WriteAt::Offset(0))).unwrap();
    run(fs.release(&open)).unwrap();
    entry.handle
}

fn read_at<H: HeadStore + 'static, P: PackStore + 'static>(
    fs: &CowFs<H, P>,
    open: &OpenRef,
    offset: u64,
) -> Result<Vec<u8>, Errno> {
    let mut buf = vec![0u8; 64];
    let n = run(fs.read_at(open, &mut buf, offset))?;
    buf.truncate(n);
    Ok(buf)
}

fn chmod<H: HeadStore + 'static, P: PackStore + 'static>(
    fs: &CowFs<H, P>,
    cred: &Cred,
    handle: &Handle,
    mode: u16,
) -> Result<u16, Errno> {
    run(fs.setattr(
        cred,
        handle,
        &SetAttr {
            mode: Some(mode),
            ..SetAttr::default()
        },
    ))
    .map(|m| m.mode)
}

fn chown<H: HeadStore + 'static, P: PackStore + 'static>(
    fs: &CowFs<H, P>,
    cred: &Cred,
    handle: &Handle,
    uid: Option<u32>,
    gid: Option<u32>,
) -> Result<(), Errno> {
    run(fs.setattr(
        cred,
        handle,
        &SetAttr {
            uid,
            gid,
            ..SetAttr::default()
        },
    ))
    .map(|_| ())
}

fn poll_once<F: Future + ?Sized>(future: std::pin::Pin<&mut F>) -> Poll<F::Output> {
    let waker = Waker::from(Arc::new(WakeCount::default()));
    future.poll(&mut Context::from_waker(&waker))
}

/// Complete differential POSIX semantics suite run identically against any `CowFs<H, P>` backend.
fn run_full_posix_suite<H: HeadStore + 'static, P: PackStore + 'static>(
    fs: &Rc<CowFs<H, P>>,
    later: &Rc<CowFs<H, P>>,
    durability: Durability,
    writer_model: WriterModel,
) {
    let root = fs.root();
    let (alice, bob, carol) = (user(1000), user(1001), user(1002));
    let admin = Cred::root();

    // 1. Lookup, walk, parent, NAME_MAX, forged/foreign/stale handles & open refs.
    {
        let a = run(fs.mkdir(&alice, &root, "a", 0o755)).unwrap().handle;
        let b = run(fs.mkdir(&alice, &a, "b", 0o755)).unwrap().handle;
        let file = new_file(fs, &alice, &b, "f", 0o644, b"hello");
        run(fs.symlink(&alice, &a, "link", "b")).unwrap();

        let walked = run(fs.walk(&alice, &root, &names("a/b/f"))).unwrap();
        assert_eq!(walked.stop, None);
        assert_eq!(walked.entries.last().unwrap().handle, file);
        assert_eq!(
            run(fs.walk(&alice, &root, &names("a/nope/f")))
                .unwrap()
                .stop,
            Some(Stop::Missing(1))
        );
        assert_eq!(
            run(fs.walk(&alice, &root, &names("a/link/f")))
                .unwrap()
                .stop,
            Some(Stop::Symlink(1))
        );
        assert_eq!(
            run(fs.walk(&alice, &root, &names("a/b/f/x"))).unwrap().stop,
            Some(Stop::NotDirectory(2))
        );
        for bad in [".", "..", "x/y", ""] {
            assert_eq!(
                run(fs.lookup(&alice, &root, bad)).unwrap_err(),
                Errno::EINVAL
            );
            assert_eq!(
                run(fs.walk(&alice, &root, &[bad.to_string()])).unwrap_err(),
                Errno::EINVAL
            );
        }
        assert_eq!(
            run(fs.walk(&alice, &root, &names("missing/.."))).unwrap_err(),
            Errno::EINVAL
        );

        let (p, n) = run(fs.parent(&alice, &b)).unwrap().unwrap();
        assert_eq!((p.handle, n.as_str()), (a.clone(), "b"));
        assert!(run(fs.parent(&alice, &root)).unwrap().is_none());
        run(fs.rename(&alice, &a, "b", &root, "moved", RenameFlags::empty())).unwrap();
        let (p, n) = run(fs.parent(&alice, &b)).unwrap().unwrap();
        assert_eq!((p.handle, n.as_str()), (root.clone(), "moved"));
        chmod(fs, &alice, &b, 0).unwrap();
        assert_eq!(run(fs.parent(&alice, &b)).unwrap().unwrap().1, "moved");
        chmod(fs, &alice, &b, 0o755).unwrap();

        // NAME_MAX
        run(fs.mkdir(&alice, &root, &"n".repeat(255), 0o755)).unwrap();
        let long = "n".repeat(256);
        assert_eq!(
            run(fs.mkdir(&alice, &root, &long, 0o755)).unwrap_err(),
            Errno::ENAMETOOLONG
        );

        // Forged / foreign / stale handles and cross-instance open refs.
        let mut forged = file.clone();
        forged.proof = "forged".into();
        assert_eq!(
            run(fs.metadata(&alice, &forged)).unwrap_err(),
            Errno::EACCES
        );
        let mut foreign = file.clone();
        foreign.fs = FsId("other".into());
        assert_eq!(
            run(fs.metadata(&alice, &foreign)).unwrap_err(),
            Errno::EACCES
        );
        let mut stale = file.clone();
        stale.node.generation += 1;
        assert_eq!(run(fs.metadata(&alice, &stale)).unwrap_err(), Errno::ESTALE);

        let open_earlier = run(fs.open(&alice, &file, &read_opt())).unwrap();
        let later_f = new_file(later, &alice, &later.root(), "g", 0o644, b"secret");
        let _ = run(later.open(&alice, &later_f, &read_opt())).unwrap();
        assert_eq!(read_at(later, &open_earlier, 0).unwrap_err(), Errno::EBADF);
        assert_eq!(run(later.release(&open_earlier)).unwrap_err(), Errno::EBADF);
        run(fs.unlink(&alice, &b, "f")).unwrap();
        assert_eq!(read_at(fs, &open_earlier, 0).unwrap(), b"hello");
        run(fs.release(&open_earlier)).unwrap();
        assert_eq!(run(fs.metadata(&alice, &file)).unwrap_err(), Errno::ESTALE);
    }

    // 2. Permissions, sticky bit, exec access, modes, owners, times.
    {
        let priv_dir = run(fs.mkdir(&alice, &root, "priv", 0o700)).unwrap().handle;
        new_file(fs, &alice, &priv_dir, "secret", 0o600, b"s");
        assert_eq!(
            run(fs.lookup(&bob, &priv_dir, "secret")).unwrap_err(),
            Errno::EACCES
        );
        assert_eq!(
            run(fs.read_dir(&bob, &priv_dir)).unwrap_err(),
            Errno::EACCES
        );
        assert_eq!(
            run(fs.read_dir_page(&bob, &priv_dir, 0, 10)).unwrap_err(),
            Errno::EACCES
        );

        let shared = new_file(fs, &alice, &root, "shared", 0o666, b"x");
        chmod(fs, &alice, &shared, 0o666).unwrap();
        assert_eq!(
            run(fs.unlink(&bob, &root, "shared")).unwrap_err(),
            Errno::EPERM
        );
        assert_eq!(
            run(fs.rename(&bob, &root, "shared", &root, "stolen", RenameFlags::empty()))
                .unwrap_err(),
            Errno::EPERM
        );
        assert_eq!(
            run(fs.mknod(&alice, &root, "dev", 0o600, "null")).unwrap_err(),
            Errno::EPERM
        );

        // Exec-only binary (0o711): bob may exec, not read.
        let tool = new_file(fs, &alice, &root, "tool", 0o711, b"\0asm");
        let eopen = run(fs.open(&bob, &tool, &exec_opt())).unwrap();
        run(fs.release(&eopen)).unwrap();
        assert_eq!(
            run(fs.open(&bob, &tool, &read_opt())).unwrap_err(),
            Errno::EACCES
        );
        let data = new_file(fs, &alice, &root, "data", 0o644, b"x");
        assert_eq!(
            run(fs.open(&admin, &data, &exec_opt())).unwrap_err(),
            Errno::EACCES
        );

        // Setgid inheritance & clearing on chmod / write.
        let team = run(fs.mkdir(&admin, &root, "team", 0o2777)).unwrap().handle;
        chown(fs, &admin, &team, None, Some(50)).unwrap();
        chmod(fs, &admin, &team, 0o2777).unwrap();
        let (fe, fo) =
            run(fs.create(&alice, &team, "f", 0o2775, &create_new(write_opt()))).unwrap();
        assert_eq!((fe.metadata.mode, fe.metadata.gid), (0o755, 50));
        run(fs.release(&fo)).unwrap();

        let link = run(fs.symlink(&alice, &root, "sym_m", "team"))
            .unwrap()
            .handle;
        assert_eq!(
            chmod(fs, &alice, &link, 0o600).unwrap_err(),
            Errno::EOPNOTSUPP
        );
        assert_eq!(run(fs.read_link(&alice, &link)).unwrap(), "team");
        assert_eq!(run(fs.read_link(&alice, &data)).unwrap_err(), Errno::EINVAL);

        // Symlink target checks.
        assert_eq!(
            run(fs.symlink(&alice, &root, "s1", "")).unwrap_err(),
            Errno::ENOENT
        );
        assert_eq!(
            run(fs.symlink(&alice, &root, "s2", "a\0b")).unwrap_err(),
            Errno::EINVAL
        );

        // utimensat validation.
        assert_eq!(
            run(fs.setattr(
                &bob,
                &data,
                &SetAttr {
                    atime: Time::At { sec: 10, nsec: 0 },
                    mtime: Time::Omit,
                    ..SetAttr::default()
                }
            ))
            .unwrap_err(),
            Errno::EPERM
        );
        assert_eq!(
            run(fs.setattr(
                &alice,
                &data,
                &SetAttr {
                    atime: Time::At {
                        sec: 10,
                        nsec: 1_000_000_000
                    },
                    ..SetAttr::default()
                }
            ))
            .unwrap_err(),
            Errno::EINVAL
        );
    }

    // 3. Protected hard links, xattrs, and POSIX ACLs (access + default inheritance).
    {
        let orig = new_file(fs, &alice, &root, "hl_orig", 0o600, b"payload");
        assert_eq!(
            run(fs.link(&bob, &orig, &root, "hl_bob")).unwrap_err(),
            Errno::EPERM
        );
        let linked = run(fs.link(&alice, &orig, &root, "hl_two")).unwrap();
        assert_eq!(linked.handle.node, orig.node);
        assert_eq!(linked.metadata.nlink, 2);

        // Xattrs & ACLs.
        run(fs.setxattr(&alice, &orig, "user.tag", b"v1", XattrFlags::CREATE)).unwrap();
        assert_eq!(
            run(fs.setxattr(&alice, &orig, "user.tag", b"v2", XattrFlags::CREATE)).unwrap_err(),
            Errno::EEXIST
        );
        assert_eq!(run(fs.getxattr(&alice, &orig, "user.tag")).unwrap(), b"v1");
        run(fs.setxattr(&admin, &orig, "trusted.sec", b"ok", XattrFlags::empty())).unwrap();
        assert_eq!(
            run(fs.getxattr(&alice, &orig, "trusted.sec")).unwrap_err(),
            Errno::ENODATA
        );
        assert!(
            run(fs.listxattr(&admin, &orig))
                .unwrap()
                .contains(&"trusted.sec".to_string())
        );
        assert!(
            !run(fs.listxattr(&alice, &orig))
                .unwrap()
                .contains(&"trusted.sec".to_string())
        );

        // Grant bob read via POSIX ACL on `orig` (0o600 -> bob can read with ACL!).
        let acl_json = serde_json::json!({
            "user": 6,
            "group": 0,
            "other": 0,
            "mask": 4,
            "users": { "1001": 4 },
            "groups": {}
        });
        run(fs.setxattr(
            &alice,
            &orig,
            ACL_ACCESS,
            acl_json.to_string().as_bytes(),
            XattrFlags::empty(),
        ))
        .unwrap();
        assert!(run(fs.metadata(&alice, &orig)).unwrap().acl);
        let bo = run(fs.open(&bob, &orig, &read_opt())).unwrap();
        assert_eq!(read_at(fs, &bo, 0).unwrap(), b"payload");
        run(fs.release(&bo)).unwrap();
        assert_eq!(
            run(fs.open(&bob, &orig, &write_opt())).unwrap_err(),
            Errno::EACCES
        );

        // Default ACL on directory inherits onto child file.
        let acl_dir = run(fs.mkdir(&alice, &root, "acl_dir", 0o755))
            .unwrap()
            .handle;
        let def_acl = serde_json::json!({
            "user": 7,
            "group": 5,
            "other": 0,
            "mask": 6,
            "users": { "1002": 6 },
            "groups": {}
        });
        run(fs.setxattr(
            &alice,
            &acl_dir,
            ACL_DEFAULT,
            def_acl.to_string().as_bytes(),
            XattrFlags::empty(),
        ))
        .unwrap();
        let (child, co) =
            run(fs.create(&alice, &acl_dir, "child", 0o666, &create_new(rw_opt()))).unwrap();
        run(fs.release(&co)).unwrap();
        assert!(child.metadata.acl);
        let carol_open = run(fs.open(&carol, &child.handle, &rw_opt())).unwrap();
        run(fs.release(&carol_open)).unwrap();
    }

    // 4. O_PATH, removed directory, sparse 64-bit offsets, rename/NOREPLACE, device ENXIO.
    {
        let doomed = run(fs.mkdir(&alice, &root, "doomed", 0o755))
            .unwrap()
            .handle;
        let cwd = run(fs.open(&bob, &doomed, &path_opt())).unwrap();
        assert_eq!(read_at(fs, &cwd, 0).unwrap_err(), Errno::EBADF);
        assert_eq!(run(fs.sync_all(&cwd)).unwrap_err(), Errno::EBADF);
        assert_eq!(run(fs.set_len(&cwd, 0)).unwrap_err(), Errno::EBADF);
        run(fs.rmdir(&alice, &root, "doomed")).unwrap();
        assert_eq!(run(fs.parent(&bob, &doomed)).unwrap_err(), Errno::ENOENT);
        assert_eq!(run(fs.read_dir(&bob, &doomed)).unwrap_err(), Errno::ENOENT);
        assert_eq!(
            run(fs.read_dir_page(&bob, &doomed, 0, 16)).unwrap_err(),
            Errno::ENOENT
        );
        assert_eq!(
            run(fs.create(&alice, &doomed, "x", 0o644, &create_new(write_opt()))).unwrap_err(),
            Errno::ENOENT
        );
        run(fs.release(&cwd)).unwrap();
        assert_eq!(run(fs.metadata(&bob, &doomed)).unwrap_err(), Errno::ESTALE);

        // Sparse 64-bit offset & FILE_MAX boundaries.
        let (sp_e, sp_o) =
            run(fs.create(&alice, &root, "sparse", 0o644, &create_new(rw_opt()))).unwrap();
        let _ = sp_e;
        let big_off = FILE_MAX - 10;
        let w = run(fs.write_at(&sp_o, b"0123456789EXTRA", WriteAt::Offset(big_off))).unwrap();
        assert_eq!(
            w,
            Written {
                offset: big_off,
                len: 10
            }
        );
        let mut tail10 = [0u8; 10];
        assert_eq!(run(fs.read_at(&sp_o, &mut tail10, big_off)).unwrap(), 10);
        assert_eq!(&tail10, b"0123456789");
        assert_eq!(read_at(fs, &sp_o, big_off).unwrap_err(), Errno::EINVAL);
        assert_eq!(
            run(fs.write_at(&sp_o, b"x", WriteAt::Offset(FILE_MAX))).unwrap_err(),
            Errno::EFBIG
        );
        assert_eq!(
            run(fs.read_at(&sp_o, &mut [0; 1], FILE_MAX)).unwrap_err(),
            Errno::EINVAL
        );
        // Empty write changes nothing.
        let before = run(fs.open_metadata(&sp_o)).unwrap();
        let nw = run(fs.write_at(&sp_o, b"", WriteAt::Offset(0))).unwrap();
        assert_eq!(nw, Written { offset: 0, len: 0 });
        assert_eq!(run(fs.open_metadata(&sp_o)).unwrap().mtime, before.mtime);
        run(fs.release(&sp_o)).unwrap();

        // Rename & RENAME_NOREPLACE.
        let r1 = new_file(fs, &alice, &root, "r1", 0o644, b"one");
        let _r2 = new_file(fs, &alice, &root, "r2", 0o644, b"two");
        assert_eq!(
            run(fs.rename(&alice, &root, "r1", &root, "r2", RenameFlags::NOREPLACE)).unwrap_err(),
            Errno::EEXIST
        );
        let r1_open = run(fs.open(&alice, &r1, &read_opt())).unwrap();
        run(fs.rename(&alice, &root, "r1", &root, "r2", RenameFlags::empty())).unwrap();
        assert_eq!(read_at(fs, &r1_open, 0).unwrap(), b"one");
        run(fs.release(&r1_open)).unwrap();

        // CharDevice returns ENXIO on direct CowFs read/write.
        let dev = run(fs.mknod(&admin, &root, "cdev", 0o666, "null"))
            .unwrap()
            .handle;
        chmod(fs, &admin, &dev, 0o666).unwrap();
        let dopen = run(fs.open(&alice, &dev, &rw_opt())).unwrap();
        assert_eq!(read_at(fs, &dopen, 0).unwrap_err(), Errno::ENXIO);
        assert_eq!(run(fs.set_len(&dopen, 10)).unwrap_err(), Errno::EINVAL);
        run(fs.release(&dopen)).unwrap();
    }

    // 5. Advisory locks (flock + fcntl byte-range, split/merge, blocking LockWait, EDEADLK).
    {
        let lf = new_file(fs, &alice, &root, "lockfile", 0o666, b"0123456789");
        let o1 = run(fs.open(&alice, &lf, &rw_opt())).unwrap();
        let o2 = run(fs.open(&alice, &lf, &rw_opt())).unwrap();
        let ro = run(fs.open(&alice, &lf, &read_opt())).unwrap();

        // Posix exclusive needs write access.
        assert_eq!(
            run(fs.try_lock(&ro, LockFamily::Posix, LockKind::Exclusive, range(0, 5))).unwrap_err(),
            Errno::EBADF
        );
        // flock & fcntl never conflict with each other.
        run(fs.try_lock(
            &o1,
            LockFamily::Flock,
            LockKind::Exclusive,
            LockRange::WHOLE,
        ))
        .unwrap();
        run(fs.try_lock(&o2, LockFamily::Posix, LockKind::Exclusive, range(0, 10))).unwrap();
        assert_eq!(
            run(fs.try_lock(&o1, LockFamily::Posix, LockKind::Shared, range(2, 6))).unwrap_err(),
            Errno::EAGAIN
        );
        // F_GETLK works even on read-only fd.
        let conflict = run(fs.test_lock(&ro, LockKind::Exclusive, range(2, 4)))
            .unwrap()
            .unwrap();
        assert_eq!(conflict.owner, o2.id);

        // Blocking wait + deadlock detection across two files.
        let lf2 = new_file(fs, &alice, &root, "lockfile2", 0o666, b"abcdef");
        let f2_o1 = run(fs.open(&alice, &lf2, &rw_opt())).unwrap();
        let f2_o2 = run(fs.open(&alice, &lf2, &rw_opt())).unwrap();
        run(fs.try_lock(&f2_o1, LockFamily::Posix, LockKind::Exclusive, range(0, 4))).unwrap();
        {
            let mut wait1 =
                pin!(fs.lock(&f2_o2, LockFamily::Posix, LockKind::Exclusive, range(0, 4)));
            assert!(poll_once(wait1.as_mut()).is_pending());
        }
        run(fs.unlock(&o2, LockFamily::Posix, LockRange::WHOLE)).unwrap();
        run(fs.try_lock(&o1, LockFamily::Posix, LockKind::Exclusive, range(0, 5))).unwrap();
        run(fs.try_lock(&o2, LockFamily::Posix, LockKind::Exclusive, range(5, 10))).unwrap();
        {
            let mut w_o1 = pin!(fs.lock(&o1, LockFamily::Posix, LockKind::Exclusive, range(5, 10)));
            assert!(poll_once(w_o1.as_mut()).is_pending());
            // o2 waiting on o1's range [0, 5) completes the cycle -> EDEADLK!
            let mut w_o2 = pin!(fs.lock(&o2, LockFamily::Posix, LockKind::Exclusive, range(0, 5)));
            assert_eq!(poll_once(w_o2.as_mut()), Poll::Ready(Err(Errno::EDEADLK)));
        }
        run(fs.release(&f2_o1)).unwrap();
        run(fs.release(&f2_o2)).unwrap();
        run(fs.release(&ro)).unwrap();
        run(fs.release(&o2)).unwrap();
        run(fs.release(&o1)).unwrap();
    }

    // 6. FileRef + FdTable + ReleaseQueue + O_APPEND atomic writes.
    {
        let f = new_file(fs, &alice, &root, "append_log", 0o644, b"A");
        let releases = ReleaseQueue::new();
        let mut opts = OpenOptions::new();
        opts.write(true).append(true);
        let o1 = run(fs.open(&alice, &f, &opts)).unwrap();
        let o2 = run(fs.open(&alice, &f, &opts)).unwrap();
        let fr1 = FileRef::new(fs.clone(), o1, f.clone(), alice.clone(), &opts, &releases);
        let fr2 = FileRef::new(fs.clone(), o2, f.clone(), alice.clone(), &opts, &releases);
        let mut tbl = FdTable::new();
        let fd1 = tbl.insert(fr1.clone(), false).unwrap();
        let fd2 = tbl.insert(fr2.clone(), false).unwrap();
        assert_eq!(run(tbl.get(fd1).unwrap().write(b"BB")).unwrap(), 2);
        assert_eq!(run(tbl.get(fd2).unwrap().write(b"CCC")).unwrap(), 3);
        let ro = run(fs.open(&alice, &f, &read_opt())).unwrap();
        assert_eq!(read_at(fs, &ro, 0).unwrap(), b"ABBCCC");
        run(fs.release(&ro)).unwrap();
        drop(tbl);
        run(fr1.close()).unwrap();
        run(fr2.close()).unwrap();
        run(releases.flush()).unwrap();
    }

    // 7. Durability barrier & persistence commit (`sync_fs`).
    run(fs.sync_fs(&admin)).unwrap();
    assert!(fs.current_head().epoch >= 1);
    assert_eq!(fs.capabilities().durability, durability);
    assert_eq!(fs.capabilities().writer_model, writer_model);
}

#[test]
fn rv09_posix_conformance_fenced_remote_store() {
    let peer = Rc::new(remote_transport::Peer::default());
    let rw = CowFsOpenMode::ReadWrite(WriterMode::Exclusive);
    let fs = run(peer.mount("remote-posix", rw.clone(), true));
    let later = run(peer.mount("remote-other", rw, true));
    run_full_posix_suite(&fs, &later, Durability::FencedCommit, WriterModel::Fenced);
    run(peer.tick(20));
    run(fs.renew_lease()).unwrap();
    run(later.renew_lease()).unwrap();
    run(fs.close_clean()).unwrap();
    run(later.close_clean()).unwrap();
    assert_eq!(peer.pin_count(), 0);
}

#[test]
fn cowfs_posix_conformance_memory_store() {
    let fs = make_mem_cowfs("vol-conf-mem-1");
    let later = make_mem_cowfs("vol-conf-mem-2");
    run_full_posix_suite(&fs, &later, Durability::TreeCommit, WriterModel::Local);
    run(fs.close_clean()).unwrap();
    run(later.close_clean()).unwrap();
}

#[test]
fn cowfs_posix_conformance_native_sqlite_store() {
    let dir1 = TempDir::new("sqlite-1");
    let dir2 = TempDir::new("sqlite-2");
    let fs = make_sqlite_cowfs(&dir1, "vol-conf-sqlite-1");
    let later = make_sqlite_cowfs(&dir2, "vol-conf-sqlite-2");
    run_full_posix_suite(&fs, &later, Durability::TreeCommit, WriterModel::Local);

    // Verify persistence across reopen on native SQLite + packs.
    run(fs.close_clean()).unwrap();
    let hs = Rc::new(NativeSqliteHeadStore::open(&dir1.0).unwrap());
    let ps = Rc::new(NativePackStore::open(&dir1.0).unwrap());
    let report = run(os_cowfs::verify_volume(
        &*hs,
        &*ps,
        &VolumeId("vol-conf-sqlite-1".into()),
    ))
    .unwrap();
    assert!(report.ok, "cowfsck errors: {:?}", report.errors);

    let reopened = run(CowFs::open(
        hs,
        ps,
        VolumeId("vol-conf-sqlite-1".into()),
        CowFsOpenMode::ReadOnly,
        CowFsConfig::local_native(ticking_clock()),
    ))
    .unwrap();
    let alice = user(1000);
    let log_e = run(reopened.lookup(&alice, &reopened.root(), "append_log")).unwrap();
    let ro = run(reopened.open(&alice, &log_e.handle, &read_opt())).unwrap();
    assert_eq!(read_at(&reopened, &ro, 0).unwrap(), b"ABBCCC");
    // RO mount refuses exclusive lock with ENOLCK, allows shared lock.
    run(reopened.try_lock(&ro, LockFamily::Flock, LockKind::Shared, LockRange::WHOLE)).unwrap();
    assert_eq!(
        run(reopened.try_lock(
            &ro,
            LockFamily::Flock,
            LockKind::Exclusive,
            LockRange::WHOLE
        ))
        .unwrap_err(),
        Errno::ENOLCK
    );
    run(reopened.release(&ro)).unwrap();
    run(later.close_clean()).unwrap();
}

#[test]
fn orphan_item_survives_crash_and_is_reaped_on_next_rw_mount() {
    let dir = TempDir::new("orphan-reap");
    let vol = VolumeId("vol-orphan".into());
    {
        let hs = Rc::new(NativeSqliteHeadStore::open(&dir.0).unwrap());
        let ps = Rc::new(NativePackStore::open(&dir.0).unwrap());
        run(CowFs::format_volume(
            &*hs,
            &*ps,
            vol.clone(),
            0,
            0,
            0o755,
            Timespec { sec: 1, nsec: 0 },
        ))
        .unwrap();
        let fs = run(CowFs::open(
            hs.clone(),
            ps.clone(),
            vol.clone(),
            CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
            CowFsConfig::local_native(ticking_clock()),
        ))
        .unwrap();
        let admin = Cred::root();
        let (entry, open) =
            run(fs.create(&admin, &fs.root(), "temp.bin", 0o644, &create_new(rw_opt()))).unwrap();
        run(fs.write_at(&open, &vec![0xAB; 128 * 1024], WriteAt::Offset(0))).unwrap();
        run(fs.unlink(&admin, &fs.root(), "temp.bin")).unwrap();
        // Commit while the unlinked file is STILL open -> persists ORPHAN_ITEM!
        run(fs.sync_fs(&admin)).unwrap();
        let report = run(os_cowfs::verify_volume(&*hs, &*ps, &vol)).unwrap();
        assert!(report.ok, "errors: {:?}", report.errors);
        assert_eq!(report.orphan_inodes, 1);
        assert_eq!(run(fs.metadata(&admin, &entry.handle)).unwrap().nlink, 0);
        // Simulate abrupt crash (drop fs without releasing `open` or calling close_clean).
    }

    // Reopen RW -> orphan must be automatically reaped and committed!
    let hs = Rc::new(NativeSqliteHeadStore::open(&dir.0).unwrap());
    let ps = Rc::new(NativePackStore::open(&dir.0).unwrap());
    let fs = run(CowFs::open(
        hs.clone(),
        ps.clone(),
        vol.clone(),
        CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
        CowFsConfig::local_native(ticking_clock()),
    ))
    .unwrap();
    let report = run(os_cowfs::verify_volume(&*hs, &*ps, &vol)).unwrap();
    assert!(report.ok, "errors: {:?}", report.errors);
    assert_eq!(report.orphan_inodes, 0);
    run(fs.close_clean()).unwrap();
}

#[test]
fn vfs_mounts_namespaces_chroot_ficlone_syncfs_and_vblk_ioctls() {
    let dir = TempDir::new("vfs-vblk");
    let hs = Rc::new(NativeSqliteHeadStore::open(&dir.0).unwrap());
    let ps = Rc::new(NativePackStore::open(&dir.0).unwrap());
    let vol1 = VolumeId("vol-root".into());
    let vol2 = VolumeId("vol-data".into());
    let vol_unformatted = VolumeId("vol-raw".into());
    let clock = ticking_clock();
    run(CowFs::format_volume(
        &*hs,
        &*ps,
        vol1.clone(),
        0,
        0,
        0o755,
        clock(),
    ))
    .unwrap();
    run(CowFs::format_volume(
        &*hs,
        &*ps,
        vol2.clone(),
        0,
        0,
        0o755,
        clock(),
    ))
    .unwrap();

    let root_cow = Rc::new(
        run(CowFs::open(
            hs.clone(),
            ps.clone(),
            vol1.clone(),
            CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
            CowFsConfig::local_native(clock.clone()),
        ))
        .unwrap(),
    );
    let data_cow = Rc::new(
        run(CowFs::open(
            hs.clone(),
            ps.clone(),
            vol2.clone(),
            CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
            CowFsConfig::local_native(clock.clone()),
        ))
        .unwrap(),
    );

    let factory = Rc::new(DefaultFilesystemFactory::new(Rc::new(|| {
        (1_700_000_000, 0)
    })));
    let vfs = run(Vfs::boot(
        "inst-cowfs-l2",
        Rc::new(MountBacking::new(root_cow.clone(), FsType::Cowfs)),
        "volume:vol-root",
        factory,
    ))
    .unwrap();

    // Check statfs reports OS_COWFS_MAGIC and "cowfs".
    let sf = run(vfs.statfs(1, StartAnchor::Root, "/")).unwrap();
    assert_eq!(sf.f_type, fs_magic::OS_COWFS_MAGIC);
    assert_eq!(sf.fstype, "cowfs");

    // Mount `/dev` with `VblkDeviceBackend`, `/mnt/data` (second CowFs volume), and `/mnt/tmp`.
    run(vfs.mkdirat(1, StartAnchor::Root, "/dev", 0o755)).unwrap();
    run(vfs.mkdirat(1, StartAnchor::Root, "/mnt", 0o755)).unwrap();
    run(vfs.mkdirat(1, StartAnchor::Root, "/mnt/data", 0o755)).unwrap();
    run(vfs.mkdirat(1, StartAnchor::Root, "/jail", 0o755)).unwrap();
    run(vfs.mkdirat(1, StartAnchor::Root, "/jail/sub", 0o755)).unwrap();

    let dev_fs = Rc::new(DevTmpFs::new(
        FsId("devtmpfs:cow".into()),
        1,
        Box::new(|| (1_700_000_000, 0)),
        VblkDeviceBackend::new(DefaultDeviceBackend),
    ));
    dev_fs.register_vblk("vd0", 0o666).unwrap();
    dev_fs.register_vblk("vd1", 0o660).unwrap();

    let sys_ns = vfs.system_namespace();
    run(vfs.mount_on_namespace(
        &sys_ns,
        &Cred::root(),
        Rc::new(MountBacking::new(dev_fs.clone(), FsType::DevTmpFs)),
        None,
        "devtmpfs",
        "/dev",
        MountFlags::from_accepted(mount_flags::MS_NOSUID),
        0,
        None,
    ))
    .unwrap();
    run(vfs.mount_on_namespace(
        &sys_ns,
        &Cred::root(),
        Rc::new(MountBacking::new(data_cow.clone(), FsType::Cowfs)),
        None,
        "volume:vol-data",
        "/mnt/data",
        MountFlags::default(),
        0,
        None,
    ))
    .unwrap();

    // Test `Vfs::ficlone` intra-volume succeeds and cross-volume returns EXDEV!
    let src_fd = run(vfs.openat(
        1,
        StartAnchor::Root,
        "/src.bin",
        abi::O_CREAT | abi::O_RDWR,
        0o644,
    ))
    .unwrap();
    let payload = vec![0x5Au8; 128 * 1024];
    assert_eq!(run(vfs.write(1, src_fd, &payload)).unwrap(), payload.len());
    run(vfs.syncfs(1, src_fd)).unwrap();

    let dst_same = run(vfs.openat(
        1,
        StartAnchor::Root,
        "/dst.bin",
        abi::O_CREAT | abi::O_RDWR,
        0o644,
    ))
    .unwrap();
    let dst_other = run(vfs.openat(
        1,
        StartAnchor::Root,
        "/mnt/data/other.bin",
        abi::O_CREAT | abi::O_RDWR,
        0o644,
    ))
    .unwrap();

    run(vfs.ficlone(1, dst_same, src_fd)).unwrap();
    assert_eq!(run(vfs.ficlone(1, dst_other, src_fd)), Err(Errno::EXDEV));
    let mut check_buf = vec![0u8; payload.len()];
    assert_eq!(
        run(vfs.pread(1, dst_same, &mut check_buf, 0)).unwrap(),
        payload.len()
    );
    assert_eq!(check_buf, payload);
    run(vfs.close(1, src_fd)).unwrap();
    run(vfs.close(1, dst_same)).unwrap();
    run(vfs.close(1, dst_other)).unwrap();

    // Test `Vfs::read_dir_page` on CowFs root.
    let page1 = run(vfs.read_dir_page(1, StartAnchor::Root, "/", 0, 2)).unwrap();
    assert_eq!(page1.entries.len(), 2);
    assert!(page1.next_cookie.is_some());

    // Test mount namespace isolation (`unshare(CLONE_NEWNS)`) + chroot on CowFs.
    vfs.fork_process(1, 2, 0).unwrap();
    vfs.unshare(2, unshare_flags::CLONE_NEWNS).unwrap();
    run(vfs.chroot(2, "/jail")).unwrap();
    assert_eq!(
        run(vfs.statat(2, StartAnchor::Root, "/../src.bin", true)),
        Err(Errno::ENOENT)
    );
    assert!(run(vfs.statat(2, StartAnchor::Root, "/sub", true)).is_ok());

    // Test `/dev/vd0` (mounted root_cow) and `/dev/vd1` (unmounted vol_unformatted).
    let vblk = VblkRegistry::new();
    vblk.attach_named(
        "vd0",
        Rc::new(CowFsVolumeDevice::from_mounted(root_cow.clone())),
    )
    .unwrap();
    vblk.attach_named(
        "vd1",
        Rc::new(CowFsVolumeDevice::unmounted(
            vol_unformatted.clone(),
            hs.clone(),
            ps.clone(),
            WriterModel::Local,
            Durability::TreeCommit,
            clock.clone(),
        )),
    )
    .unwrap();

    // Raw read/write on `/dev/vd0` -> EOPNOTSUPP.
    let vd0_fd = run(vfs.openat(1, StartAnchor::Root, "/dev/vd0", abi::O_RDWR, 0)).unwrap();
    assert_eq!(
        run(vfs.read(1, vd0_fd, &mut [0u8; 8])),
        Err(Errno::EOPNOTSUPP)
    );
    assert_eq!(run(vfs.write(1, vd0_fd, b"raw")), Err(Errno::EOPNOTSUPP));

    // Root BLK_INFO, BLK_LEASE, COWFS_IOC_{INFO,SNAPSHOT,FORK} succeed.
    let blk_info: BlkInfoResp = serde_json::from_slice(
        &run(vblk.ioctl_fd(&vfs, 1, vd0_fd, cowfs_ioctl::BLK_INFO, b"")).unwrap(),
    )
    .unwrap();
    assert_eq!(blk_info.device, "/dev/vd0");
    assert_eq!(blk_info.volume, "vol-root");
    assert!(blk_info.formatted);

    let blk_lease: BlkLeaseResp = serde_json::from_slice(
        &run(vblk.ioctl_fd(&vfs, 1, vd0_fd, cowfs_ioctl::BLK_LEASE, b"")).unwrap(),
    )
    .unwrap();
    assert!(blk_lease.held);

    let info: CowfsInfoResp = serde_json::from_slice(
        &run(vblk.ioctl_fd(&vfs, 1, vd0_fd, cowfs_ioctl::COWFS_IOC_INFO, b"")).unwrap(),
    )
    .unwrap();
    assert_eq!(info.volume, "vol-root");

    let snap: CowfsSnapshotResp = serde_json::from_slice(
        &run(vblk.ioctl_fd(
            &vfs,
            1,
            vd0_fd,
            cowfs_ioctl::COWFS_IOC_SNAPSHOT,
            br#"{"name":"s1","ro":true}"#,
        ))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(snap.name, "s1");

    let fork: CowfsForkResp = serde_json::from_slice(
        &run(vblk.ioctl_fd(
            &vfs,
            1,
            vd0_fd,
            cowfs_ioctl::COWFS_IOC_FORK,
            br#"{"snapshot":"s1","new_volume":"vol-forked"}"#,
        ))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(fork.volume, "vol-forked");
    assert_eq!(fork.root, snap.root);

    // Invalid ioctl -> ENOTTY; invalid fd -> EBADF; non-vblk fd -> ENOTTY.
    assert_eq!(
        run(vblk.ioctl_fd(&vfs, 1, vd0_fd, 0xDEAD_BEEF, b"")),
        Err(Errno::ENOTTY)
    );
    assert_eq!(
        run(vblk.ioctl_fd(&vfs, 1, 999, cowfs_ioctl::BLK_INFO, b"")),
        Err(Errno::EBADF)
    );
    let reg_fd = run(vfs.openat(1, StartAnchor::Root, "/src.bin", abi::O_RDONLY, 0)).unwrap();
    assert_eq!(
        run(vblk.ioctl_fd(&vfs, 1, reg_fd, cowfs_ioctl::BLK_INFO, b"")),
        Err(Errno::ENOTTY)
    );
    run(vfs.close(1, reg_fd)).unwrap();

    // Non-root user: BLK_INFO/COWFS_IOC_INFO succeed, COWFS_IOC_{SNAPSHOT,FORK} -> EPERM!
    vfs.fork_process(1, 3, 0).unwrap();
    vfs.set_cred(3, user(1000)).unwrap();
    let u_vd0 = run(vfs.openat(3, StartAnchor::Root, "/dev/vd0", abi::O_RDONLY, 0)).unwrap();
    assert!(run(vblk.ioctl_fd(&vfs, 3, u_vd0, cowfs_ioctl::BLK_INFO, b"")).is_ok());
    assert!(run(vblk.ioctl_fd(&vfs, 3, u_vd0, cowfs_ioctl::COWFS_IOC_INFO, b"")).is_ok());
    assert_eq!(
        run(vblk.ioctl_fd(
            &vfs,
            3,
            u_vd0,
            cowfs_ioctl::COWFS_IOC_SNAPSHOT,
            br#"{"name":"s2"}"#,
        )),
        Err(Errno::EPERM)
    );
    assert_eq!(
        run(vblk.ioctl_fd(
            &vfs,
            3,
            u_vd0,
            cowfs_ioctl::COWFS_IOC_FORK,
            br#"{"new_volume":"bad"}"#,
        )),
        Err(Errno::EPERM)
    );
    assert_eq!(
        run(cowfs_ioctl_mounted(
            &root_cow,
            &user(1000),
            cowfs_ioctl::COWFS_IOC_SNAPSHOT,
            br#"{"name":"s3"}"#,
        )),
        Err(Errno::EPERM)
    );
    run(vfs.close(3, u_vd0)).unwrap();
    run(vfs.close(1, vd0_fd)).unwrap();

    // `mkfs.cowfs` target validation:
    // - directory / regular file / hostfs / opfs / sharefs -> ENOTBLK!
    for bad_target in [
        "/mnt/data",
        "/src.bin",
        "hostfs:proj",
        "opfs:workspace",
        "sharefs:exp",
    ] {
        assert_eq!(
            run(vblk.mkfs_cowfs(&vfs, 1, bad_target, false)),
            Err(Errno::ENOTBLK),
            "target {bad_target} must fail with ENOTBLK"
        );
    }
    // - mounted /dev/vd0 -> EBUSY!
    assert_eq!(
        run(vblk.mkfs_cowfs(&vfs, 1, "/dev/vd0", true)),
        Err(Errno::EBUSY)
    );
    // - unformatted /dev/vd1 -> succeeds; second mkfs without -f -> EEXIST; with -f -> succeeds!
    let mk = run(vblk.mkfs_cowfs(&vfs, 1, "/dev/vd1", false)).unwrap();
    assert_eq!(mk.volume, "vol-raw");
    assert_eq!(
        run(vblk.mkfs_cowfs(&vfs, 1, "/dev/vd1", false)),
        Err(Errno::EEXIST)
    );
    assert!(run(vblk.mkfs_cowfs(&vfs, 1, "/dev/vd1", true)).is_ok());

    // Keep an open description while the same device number is reassigned.
    let old = run(vfs.openat(1, StartAnchor::Root, "/dev/vd0", abi::O_RDONLY, 0)).unwrap();
    vblk.detach("vd0").unwrap();
    let replacement = vblk.get("vd1").unwrap();
    assert_eq!(vblk.attach(replacement), "vd0");
    vblk.register_node(&dev_fs, "vd0", 0o660).unwrap();
    assert_eq!(
        run(vblk.ioctl_fd(&vfs, 1, old, cowfs_ioctl::BLK_INFO, b"")),
        Err(Errno::ENODEV)
    );
    let new = run(vfs.openat(1, StartAnchor::Root, "/dev/vd0", abi::O_RDONLY, 0)).unwrap();
    let info: BlkInfoResp = serde_json::from_slice(
        &run(vblk.ioctl_fd(&vfs, 1, new, cowfs_ioctl::BLK_INFO, b"")).unwrap(),
    )
    .unwrap();
    assert_eq!(info.volume, "vol-raw");
    run(vfs.close(1, old)).unwrap();
    run(vfs.close(1, new)).unwrap();

    // DefaultFilesystemFactory rejects host-tree source on `mount -t cowfs` with ENOTBLK
    // and rejects invalid cowfs mount options with EINVAL.
    run(vfs.mkdirat(1, StartAnchor::Root, "/mnt/bad", 0o755)).unwrap();
    assert_eq!(
        run(vfs.mount(1, "/mnt/data", "/mnt/bad", Some("cowfs"), 0, None)),
        Err(Errno::ENOTBLK)
    );
    assert_eq!(
        run(vfs.mount(1, "volume:x", "/mnt/bad", Some("cowfs"), 0, Some("bogus=1"))),
        Err(Errno::EINVAL)
    );
    // Also check MemFs inherits default `read_dir_page` adapter seamlessly.
    let mem = MemFs::new(FsId("mem:page".into()), 1, 0, 0, 0o755, Box::new(|| (0, 0)));
    for i in 0..5 {
        run(mem.mkdir(&Cred::root(), &mem.root(), &format!("d{i}"), 0o755)).unwrap();
    }
    let mp = run(mem.read_dir_page(&Cred::root(), &mem.root(), 0, 2)).unwrap();
    assert_eq!(mp.entries.len(), 2);
    assert_eq!(mp.next_cookie, Some(2));
}
