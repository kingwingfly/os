//! Confined Linux filesystem, statx, durability, and host locking syscalls for `os-local-helper`.

use abi::Errno;
use abi::fs::{FILE_MAX, LockKind, LockRange, Timespec};
use serde::{Deserialize, Serialize};
use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};

const OPEN_HOW_SIZE: usize = std::mem::size_of::<OpenHow>();
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const RWF_APPEND: libc::c_int = 0x0000_0010;
const STATX_MNT_ID: u32 = 0x0000_1000;
const STATX_MNT_ID_UNIQUE: u32 = 0x0000_4000;
const STATX_SUBVOL: u32 = 0x0000_8000;
const FS_IOC_GETVERSION: libc::Ioctl = ((2u64 << 30)
    | ((std::mem::size_of::<libc::c_long>() as u64) << 16)
    | ((b'v' as u64) << 8)
    | 1) as libc::Ioctl;
const FS_IOC_GETFSUUID: libc::Ioctl = ((2u64 << 30)
    | ((std::mem::size_of::<FsUuid2>() as u64) << 16)
    | (0x15u64 << 8)) as libc::Ioctl;

#[repr(C)]
struct FsUuid2 {
    len: u8,
    uuid: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct LinuxStatxTimestamp {
    tv_sec: i64,
    tv_nsec: u32,
    __reserved: i32,
}

#[repr(C)]
struct LinuxStatx {
    stx_mask: u32,
    stx_blksize: u32,
    stx_attributes: u64,
    stx_nlink: u32,
    stx_uid: u32,
    stx_gid: u32,
    stx_mode: u16,
    __spare0: [u16; 1],
    stx_ino: u64,
    stx_size: u64,
    stx_blocks: u64,
    stx_attributes_mask: u64,
    stx_atime: LinuxStatxTimestamp,
    stx_btime: LinuxStatxTimestamp,
    stx_ctime: LinuxStatxTimestamp,
    stx_mtime: LinuxStatxTimestamp,
    stx_rdev_major: u32,
    stx_rdev_minor: u32,
    stx_dev_major: u32,
    stx_dev_minor: u32,
    stx_mnt_id: u64,
    stx_dio_mem_align: u32,
    stx_dio_offset_align: u32,
    stx_subvol: u64,
    stx_atomic_write_unit_min: u32,
    stx_atomic_write_unit_max: u32,
    stx_atomic_write_segments_max: u32,
    stx_dio_read_offset_align: u32,
    stx_atomic_write_unit_max_opt: u32,
    __spare2: [u32; 1],
    __spare3: [u64; 8],
}

const _: () = {
    assert!(std::mem::size_of::<LinuxStatx>() == 0x100);
    assert!(std::mem::offset_of!(LinuxStatx, stx_ino) == 0x20);
    assert!(std::mem::offset_of!(LinuxStatx, stx_btime) == 0x50);
    assert!(std::mem::offset_of!(LinuxStatx, stx_dev_major) == 0x88);
    assert!(std::mem::offset_of!(LinuxStatx, stx_mnt_id) == 0x90);
    assert!(std::mem::offset_of!(LinuxStatx, stx_subvol) == 0xa0);
};

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HostKind {
    Dir,
    File,
    Symlink,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum HostGen {
    Btime { sec: i64, nsec: u32 },
    IocVersion(u64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostStat {
    pub mnt_id: Option<u64>,
    pub subvol: Option<u64>,
    pub dev: (u32, u32),
    pub ino: u64,
    pub kind: HostKind,
    pub nlink: u32,
    pub size: u64,
    pub atime: (i64, u32),
    pub mtime: (i64, u32),
    pub ctime: (i64, u32),
    pub btime: Option<(i64, u32)>,
}

/// Distinguish mount points (including same-device bind mounts and single-file mounts) and btrfs
/// subvolumes/snapshots without misclassifying non-directory lower-layer overlayfs files.
pub fn boundary_crossed(parent: &HostStat, child: &HostStat) -> bool {
    let mount_changed = match (parent.mnt_id, child.mnt_id) {
        (Some(pm), Some(cm)) => pm != cm,
        _ => child.dev != parent.dev,
    };
    let subvol_changed =
        child.kind == HostKind::Dir && (child.dev != parent.dev || child.subvol != parent.subvol);
    mount_changed || subvol_changed
}

impl HostStat {
    pub fn times(&self) -> (Timespec, Timespec, Timespec) {
        (
            to_timespec(self.atime),
            to_timespec(self.mtime),
            to_timespec(self.ctime),
        )
    }
}

pub fn to_timespec(ts: (i64, u32)) -> Timespec {
    Timespec {
        sec: ts.0.max(0) as u64,
        nsec: ts.1,
    }
}

pub fn now_timespec() -> (i64, u32) {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    if rc == 0 {
        (ts.tv_sec, ts.tv_nsec.clamp(0, 999_999_999) as u32)
    } else {
        (0, 0)
    }
}

/// Convert a raw Linux errno integer into [`Errno`].
pub fn errno_from_raw(raw: i32) -> Errno {
    match raw {
        libc::EPERM => Errno::EPERM,
        libc::ENOENT => Errno::ENOENT,
        libc::ESRCH => Errno::ESRCH,
        libc::EIO => Errno::EIO,
        libc::ENXIO => Errno::ENXIO,
        libc::E2BIG => Errno::E2BIG,
        libc::EBADF => Errno::EBADF,
        libc::EAGAIN => Errno::EAGAIN, // Also covers EWOULDBLOCK on Linux.
        libc::EACCES => Errno::EACCES,
        libc::EBUSY => Errno::EBUSY,
        libc::EEXIST => Errno::EEXIST,
        libc::EXDEV => Errno::EXDEV,
        libc::ENODEV => Errno::ENODEV,
        libc::ENOTDIR => Errno::ENOTDIR,
        libc::EISDIR => Errno::EISDIR,
        libc::EINVAL => Errno::EINVAL,
        libc::EMFILE | libc::ENFILE => Errno::EMFILE,
        libc::ENOTTY => Errno::ENOTTY,
        libc::ETXTBSY => Errno::ETXTBSY,
        libc::EFBIG => Errno::EFBIG,
        libc::ENOSPC => Errno::ENOSPC,
        libc::EROFS => Errno::EROFS,
        libc::EMLINK => Errno::EMLINK,
        libc::EPIPE => Errno::EPIPE,
        libc::ERANGE => Errno::ERANGE,
        libc::EDEADLK => Errno::EDEADLK,
        libc::ENAMETOOLONG => Errno::ENAMETOOLONG,
        libc::ENOLCK => Errno::ENOLCK,
        libc::ENOSYS => Errno::ENOSYS,
        libc::ENOTEMPTY => Errno::ENOTEMPTY,
        libc::ELOOP => Errno::ELOOP,
        libc::ENODATA => Errno::ENODATA,
        libc::EOPNOTSUPP => Errno::EOPNOTSUPP,
        libc::EPROTONOSUPPORT => Errno::EPROTONOSUPPORT,
        libc::ENOTCONN => Errno::ENOTCONN,
        libc::ETIMEDOUT => Errno::ETIMEDOUT,
        libc::ESTALE => Errno::ESTALE,
        libc::EDQUOT => Errno::EDQUOT,
        libc::ECANCELED => Errno::ECANCELED,
        _ => Errno::EIO,
    }
}

pub fn last_errno() -> Errno {
    io::Error::last_os_error()
        .raw_os_error()
        .map(errno_from_raw)
        .unwrap_or(Errno::EIO)
}

pub fn io_to_errno(err: &io::Error) -> Errno {
    err.raw_os_error().map(errno_from_raw).unwrap_or(Errno::EIO)
}

fn c_str(s: &str) -> Result<CString, Errno> {
    CString::new(s).map_err(|_| Errno::EINVAL)
}

fn map_openat2_errno(raw: i32) -> Errno {
    match raw {
        // openat2 returns EXDEV when RESOLVE_BENEATH catches an escape attempt.
        libc::EXDEV => Errno::EACCES,
        other => errno_from_raw(other),
    }
}

/// Probe kernel `openat2(2)` availability on `root_fd`.
pub fn check_openat2(root_fd: BorrowedFd<'_>) -> Result<(), String> {
    let fd = open_beneath(
        root_fd,
        ".",
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0,
    )
    .map_err(|e| format!("openat2 probe failed: {}", e.text()))?;
    drop(fd);
    Ok(())
}

/// Open a path relative to `dir_fd` strictly confined beneath `dir_fd`, blocking magiclinks and
/// intermediate symlinks.
pub fn open_beneath(
    dir_fd: BorrowedFd<'_>,
    rel: &str,
    flags: libc::c_int,
    mode: u32,
) -> Result<OwnedFd, Errno> {
    let c_rel = c_str(rel)?;
    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC) as u64,
        mode: u64::from(mode),
        resolve: RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
    };
    loop {
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                dir_fd.as_raw_fd(),
                c_rel.as_ptr(),
                (&raw const how).cast::<libc::c_void>(),
                OPEN_HOW_SIZE,
            )
        };
        if fd >= 0 {
            return Ok(unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) });
        }
        let raw = io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        if raw == libc::EINTR {
            continue;
        }
        return Err(map_openat2_errno(raw));
    }
}

/// Upgrade an `O_PATH` directory descriptor to a readable directory descriptor via confined `"."`.
pub fn upgrade_dir_fd(dir_fd: BorrowedFd<'_>) -> Result<OwnedFd, Errno> {
    open_beneath(
        dir_fd,
        ".",
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        0,
    )
}

pub fn statx_fd(fd: BorrowedFd<'_>) -> Result<HostStat, Errno> {
    let mut stx: LinuxStatx = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::statx(
            fd.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
            libc::STATX_BASIC_STATS
                | libc::STATX_BTIME
                | STATX_MNT_ID_UNIQUE
                | STATX_MNT_ID
                | STATX_SUBVOL,
            (&raw mut stx).cast::<libc::statx>(),
        )
    };
    if rc != 0 {
        return Err(last_errno());
    }
    let kind = match u32::from(stx.stx_mode) & libc::S_IFMT {
        libc::S_IFDIR => HostKind::Dir,
        libc::S_IFREG => HostKind::File,
        libc::S_IFLNK => HostKind::Symlink,
        _ => HostKind::Other,
    };
    let btime = if (stx.stx_mask & libc::STATX_BTIME) != 0 {
        Some((
            stx.stx_btime.tv_sec,
            stx.stx_btime.tv_nsec.clamp(0, 999_999_999) as u32,
        ))
    } else {
        None
    };
    let mnt_id = if (stx.stx_mask & (STATX_MNT_ID_UNIQUE | STATX_MNT_ID)) != 0 {
        Some(stx.stx_mnt_id)
    } else {
        None
    };
    let subvol = if (stx.stx_mask & STATX_SUBVOL) != 0 {
        Some(stx.stx_subvol)
    } else {
        None
    };
    Ok(HostStat {
        mnt_id,
        subvol,
        dev: (stx.stx_dev_major, stx.stx_dev_minor),
        ino: stx.stx_ino,
        kind,
        nlink: stx.stx_nlink,
        size: stx.stx_size,
        atime: (stx.stx_atime.tv_sec, stx.stx_atime.tv_nsec),
        mtime: (stx.stx_mtime.tv_sec, stx.stx_mtime.tv_nsec),
        ctime: (stx.stx_ctime.tv_sec, stx.stx_ctime.tv_nsec),
        btime,
    })
}

/// Capture the kernel's persistent filesystem UUID (`FS_IOC_GETFSUUID`) from an open descriptor.
/// Returns `None` on filesystems/descriptors where `FS_IOC_GETFSUUID` is unsupported (e.g. Btrfs,
/// `O_PATH` descriptors, or kernels before 6.0).
pub fn capture_fsuuid_from_fd(fd: BorrowedFd<'_>) -> Option<[u8; 16]> {
    let mut out = FsUuid2 {
        len: 0,
        uuid: [0; 16],
    };
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), FS_IOC_GETFSUUID, &raw mut out) };
    if rc == 0 && (1..=16).contains(&out.len) {
        let mut uuid = [0u8; 16];
        let n = usize::from(out.len);
        uuid[..n].copy_from_slice(&out.uuid[..n]);
        Some(uuid)
    } else {
        None
    }
}

/// Capture the persistent filesystem UUID of a confined directory at `rel` beneath `dir_fd`.
pub fn capture_dir_fsuuid(dir_fd: BorrowedFd<'_>, rel: &str) -> Option<[u8; 16]> {
    let target = if rel.is_empty() { "." } else { rel };
    let rfd = open_beneath(
        dir_fd,
        target,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        0,
    )
    .ok()?;
    capture_fsuuid_from_fd(std::os::fd::AsFd::as_fd(&rfd))
}

/// Read `stx_btime` from `statx`, or fall back to `FS_IOC_GETVERSION` when the filesystem does not
/// populate `STATX_BTIME`. Refuses with `EOPNOTSUPP`/`EACCES` when neither incarnation is readable,
/// so reused host inode numbers never inherit stale grants silently.
pub fn capture_gen(
    dir_fd: BorrowedFd<'_>,
    rel: Option<&str>,
    stx: &HostStat,
) -> Result<HostGen, Errno> {
    if let Some((sec, nsec)) = stx.btime {
        return Ok(HostGen::Btime { sec, nsec });
    }
    if !matches!(stx.kind, HostKind::Dir | HostKind::File) {
        return Err(Errno::EOPNOTSUPP);
    }
    let rel = rel.filter(|r| !r.is_empty()).unwrap_or(".");
    let rfd = open_beneath(
        dir_fd,
        rel,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        0,
    )?;
    let mut ver: libc::c_long = 0;
    let rc = unsafe { libc::ioctl(rfd.as_raw_fd(), FS_IOC_GETVERSION, &raw mut ver) };
    if rc == 0 {
        Ok(HostGen::IocVersion(ver as u64))
    } else {
        let raw = io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::ENOTTY);
        Err(match raw {
            libc::ENOTTY | libc::ENOSYS | libc::EOPNOTSUPP | libc::EINVAL => Errno::EOPNOTSUPP,
            other => errno_from_raw(other),
        })
    }
}

pub fn capture_gen_from_fd(fd: BorrowedFd<'_>, stx: &HostStat) -> Result<HostGen, Errno> {
    if let Some((sec, nsec)) = stx.btime {
        return Ok(HostGen::Btime { sec, nsec });
    }
    if !matches!(stx.kind, HostKind::Dir | HostKind::File) {
        return Err(Errno::EOPNOTSUPP);
    }
    let mut ver: libc::c_long = 0;
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), FS_IOC_GETVERSION, &raw mut ver) };
    if rc == 0 {
        return Ok(HostGen::IocVersion(ver as u64));
    }
    let first_err = io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::ENOTTY);
    if first_err == libc::EBADF {
        let rfd = open_proc_fd(fd, libc::O_RDONLY | libc::O_NONBLOCK)?;
        let rc2 = unsafe { libc::ioctl(rfd.as_raw_fd(), FS_IOC_GETVERSION, &raw mut ver) };
        if rc2 == 0 {
            return Ok(HostGen::IocVersion(ver as u64));
        }
        let err2 = io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::ENOTTY);
        return Err(match err2 {
            libc::ENOTTY | libc::ENOSYS | libc::EOPNOTSUPP | libc::EINVAL => Errno::EOPNOTSUPP,
            other => errno_from_raw(other),
        });
    }
    Err(match first_err {
        libc::ENOTTY | libc::ENOSYS | libc::EOPNOTSUPP | libc::EINVAL => Errno::EOPNOTSUPP,
        other => errno_from_raw(other),
    })
}

/// Reopen an already-validated host descriptor via `/proc/self/fd` (e.g. for unlinked open inodes).
pub fn open_proc_fd(fd: BorrowedFd<'_>, flags: libc::c_int) -> Result<OwnedFd, Errno> {
    let path = format!("/proc/self/fd/{}", fd.as_raw_fd());
    let c_path = c_str(&path)?;
    loop {
        let raw = unsafe { libc::open(c_path.as_ptr(), flags | libc::O_CLOEXEC, 0) };
        if raw >= 0 {
            return Ok(unsafe { OwnedFd::from_raw_fd(raw) });
        }
        let code = io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        if code == libc::EINTR {
            continue;
        }
        return Err(errno_from_raw(code));
    }
}

/// Clear `O_NONBLOCK` on an open file descriptor after proving it is a regular file.
pub fn clear_nonblock(fd: BorrowedFd<'_>) -> Result<(), Errno> {
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(last_errno());
    }
    if (flags & libc::O_NONBLOCK) != 0 {
        let rc = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK) };
        if rc < 0 {
            return Err(last_errno());
        }
    }
    Ok(())
}

/// Resolve the live kernel path of an open descriptor via `/proc/self/fd`.
pub fn proc_fd_path(fd: BorrowedFd<'_>) -> Result<PathBuf, Errno> {
    std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd())).map_err(|e| io_to_errno(&e))
}

/// Resolve an already-open descriptor's live path relative to the live path of `root_fd` (`""` for
/// `root_fd` itself), dynamically tracking host renames of `--root` or ancestor directories and
/// handling literal `"* (deleted)"` names safely without relying on string suffixes.
pub fn fd_relpath_inside_root(
    root_fd: BorrowedFd<'_>,
    fd: BorrowedFd<'_>,
) -> Result<String, Errno> {
    let stx = statx_fd(fd)?;
    if stx.nlink == 0 {
        return Err(Errno::ENOENT);
    }
    let root_stx = statx_fd(root_fd)?;
    if root_stx.nlink == 0 {
        return Err(Errno::ENOENT);
    }

    let root_link = proc_fd_path(root_fd)?;
    let root_canon = std::fs::canonicalize(&root_link).map_err(|e| io_to_errno(&e))?;
    let link = proc_fd_path(fd)?;
    let canon = std::fs::canonicalize(&link).map_err(|e| io_to_errno(&e))?;
    let rel = canon.strip_prefix(&root_canon).map_err(|_| Errno::EACCES)?;
    let rel_str = if rel.as_os_str().is_empty() {
        String::new()
    } else {
        let mut parts = Vec::new();
        for comp in rel.components() {
            match comp {
                std::path::Component::Normal(p) => {
                    let s = p.to_str().ok_or(Errno::EIO)?;
                    parts.push(s);
                }
                _ => return Err(Errno::EACCES),
            }
        }
        parts.join("/")
    };

    // Guard against the rare case where an unlinked open dentry (`"... (deleted)"` with another
    // hard link so nlink > 0) collides with a real unrelated host entry literally named `"* (deleted)"`.
    let probe_target = if rel_str.is_empty() { "." } else { &rel_str };
    let probe = open_beneath(root_fd, probe_target, libc::O_PATH | libc::O_NOFOLLOW, 0)
        .map_err(|e| if e == Errno::EACCES { e } else { Errno::ENOENT })?;
    let probe_stx = statx_fd(std::os::fd::AsFd::as_fd(&probe))?;
    if probe_stx.ino != stx.ino
        || probe_stx.dev != stx.dev
        || probe_stx.mnt_id != stx.mnt_id
        || probe_stx.subvol != stx.subvol
        || probe_stx.kind != stx.kind
    {
        return Err(Errno::ENOENT);
    }
    Ok(rel_str)
}

/// Verify an already-open directory descriptor still resides inside `root_fd` and has not been
/// deleted or moved out of the mount tree externally.
pub fn verify_fd_inside_root(root_fd: BorrowedFd<'_>, fd: BorrowedFd<'_>) -> Result<(), Errno> {
    fd_relpath_inside_root(root_fd, fd).map(|_| ())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MountInfoEntry {
    pub mnt_id: u64,
    pub dev_maj_min: String,
    pub fs_root: PathBuf,
    pub mount_point: PathBuf,
}

fn unescape_mountinfo_bytes(raw: &str) -> PathBuf {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && (b'0'..=b'7').contains(&bytes[i + 1])
            && (b'0'..=b'7').contains(&bytes[i + 2])
            && (b'0'..=b'7').contains(&bytes[i + 3])
        {
            let val =
                ((bytes[i + 1] - b'0') << 6) | ((bytes[i + 2] - b'0') << 3) | (bytes[i + 3] - b'0');
            out.push(val);
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    PathBuf::from(OsString::from_vec(out))
}

fn normalize_abs_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::from("/");
    for comp in path.components() {
        match comp {
            std::path::Component::RootDir | std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::Normal(p) => out.push(p),
            std::path::Component::Prefix(_) => {}
        }
    }
    out
}

pub(crate) fn parse_mountinfo(contents: &str) -> Vec<MountInfoEntry> {
    let mut entries = Vec::new();
    for line in contents.lines() {
        let cols: Vec<&str> = line.split(' ').collect();
        if cols.len() < 5 {
            continue;
        }
        let Ok(mnt_id) = cols[0].parse::<u64>() else {
            continue;
        };
        entries.push(MountInfoEntry {
            mnt_id,
            dev_maj_min: cols[2].to_owned(),
            fs_root: normalize_abs_path(&unescape_mountinfo_bytes(cols[3])),
            mount_point: normalize_abs_path(&unescape_mountinfo_bytes(cols[4])),
        });
    }
    entries
}

fn fd_mountinfo_id(fd: BorrowedFd<'_>) -> Option<u64> {
    let text = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd())).ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("mnt_id:") {
            return rest.trim().parse::<u64>().ok();
        }
    }
    None
}

fn backing_for_path<'a>(
    mounts: &'a [MountInfoEntry],
    path: &Path,
    opt_mnt_id: Option<u64>,
) -> Option<(&'a str, PathBuf)> {
    let norm = normalize_abs_path(path);
    let entry = opt_mnt_id
        .and_then(|id| mounts.iter().find(|m| m.mnt_id == id))
        .or_else(|| {
            mounts
                .iter()
                .filter(|m| norm == m.mount_point || norm.starts_with(&m.mount_point))
                .max_by_key(|m| m.mount_point.as_os_str().len())
        })?;
    let rel = norm.strip_prefix(&entry.mount_point).ok()?;
    let mut backing = entry.fs_root.clone();
    backing.push(rel);
    Some((&entry.dev_maj_min, normalize_abs_path(&backing)))
}

fn path_same_or_descendant(candidate: &Path, ancestor: &Path) -> bool {
    let c = normalize_abs_path(candidate);
    let a = normalize_abs_path(ancestor);
    c == a || c.starts_with(&a)
}

pub(crate) fn check_mountinfo_overlap(
    mounts: &[MountInfoEntry],
    canonical_root: &Path,
    root_mnt_id: Option<u64>,
    state_dir: &Path,
    state_mnt_id: Option<u64>,
    folders_dir: &Path,
    folders_mnt_id: Option<u64>,
) -> Result<(), Errno> {
    let Some((root_dev, root_backing)) = backing_for_path(mounts, canonical_root, root_mnt_id)
    else {
        return Ok(());
    };
    let submounts: Vec<&MountInfoEntry> = mounts
        .iter()
        .filter(|m| path_same_or_descendant(&m.mount_point, canonical_root))
        .collect();

    for (target_path, target_mnt_id, check_submount_inside_target) in [
        (state_dir, state_mnt_id, false),
        (folders_dir, folders_mnt_id, true),
    ] {
        if path_same_or_descendant(target_path, canonical_root) {
            return Err(Errno::EINVAL);
        }
        if let Some((t_dev, t_backing)) = backing_for_path(mounts, target_path, target_mnt_id) {
            if t_dev == root_dev && path_same_or_descendant(&t_backing, &root_backing) {
                return Err(Errno::EINVAL);
            }
            for sub in &submounts {
                if t_dev == sub.dev_maj_min
                    && (path_same_or_descendant(&t_backing, &sub.fs_root)
                        || (check_submount_inside_target
                            && path_same_or_descendant(&sub.fs_root, &t_backing)))
                {
                    return Err(Errno::EINVAL);
                }
            }
        }
    }
    Ok(())
}

/// Reject state/folders paths that overlap `--root` directly or via Linux bind mounts / submounts.
pub fn verify_state_dirs_outside_root(
    canonical_root: &Path,
    root_fd: BorrowedFd<'_>,
    state_dir: &Path,
    state_fd: BorrowedFd<'_>,
    folders_dir: &Path,
    folders_fd: Option<BorrowedFd<'_>>,
) -> Result<(), Errno> {
    let canon_state = proc_fd_path(state_fd)
        .and_then(|p| std::fs::canonicalize(p).map_err(|e| io_to_errno(&e)))
        .unwrap_or_else(|_| state_dir.to_path_buf());
    if path_same_or_descendant(&canon_state, canonical_root) {
        return Err(Errno::EINVAL);
    }
    let canon_folders = if let Some(ffd) = folders_fd {
        proc_fd_path(ffd)
            .and_then(|p| std::fs::canonicalize(p).map_err(|e| io_to_errno(&e)))
            .unwrap_or_else(|_| folders_dir.to_path_buf())
    } else {
        folders_dir.to_path_buf()
    };
    if path_same_or_descendant(&canon_folders, canonical_root) {
        return Err(Errno::EINVAL);
    }
    if let Ok(raw) = std::fs::read_to_string("/proc/self/mountinfo") {
        let mounts = parse_mountinfo(&raw);
        let root_mnt = fd_mountinfo_id(root_fd);
        let state_mnt = fd_mountinfo_id(state_fd);
        let folders_mnt = folders_fd.and_then(fd_mountinfo_id).or(state_mnt);
        check_mountinfo_overlap(
            &mounts,
            canonical_root,
            root_mnt,
            &canon_state,
            state_mnt,
            &canon_folders,
            folders_mnt,
        )?;
    }
    Ok(())
}

pub fn openat_nofollow(
    dir_fd: BorrowedFd<'_>,
    name: &str,
    flags: libc::c_int,
    mode: u32,
) -> Result<OwnedFd, Errno> {
    let c_name = c_str(name)?;
    loop {
        let fd = unsafe {
            libc::openat(
                dir_fd.as_raw_fd(),
                c_name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                mode,
            )
        };
        if fd >= 0 {
            return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
        }
        let raw = io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        if raw == libc::EINTR {
            continue;
        }
        return Err(errno_from_raw(raw));
    }
}

pub fn mkdirat_dir(dir_fd: BorrowedFd<'_>, name: &str, mode: u32) -> Result<(), Errno> {
    let c_name = c_str(name)?;
    let rc = unsafe { libc::mkdirat(dir_fd.as_raw_fd(), c_name.as_ptr(), mode) };
    if rc == 0 { Ok(()) } else { Err(last_errno()) }
}

pub fn renameat_same_dir(dir_fd: BorrowedFd<'_>, from: &str, to: &str) -> Result<(), Errno> {
    let c_from = c_str(from)?;
    let c_to = c_str(to)?;
    let rc = unsafe {
        libc::renameat(
            dir_fd.as_raw_fd(),
            c_from.as_ptr(),
            dir_fd.as_raw_fd(),
            c_to.as_ptr(),
        )
    };
    if rc == 0 { Ok(()) } else { Err(last_errno()) }
}

pub fn fchmod_fd(fd: BorrowedFd<'_>, mode: u32) -> Result<(), Errno> {
    let rc = unsafe { libc::fchmod(fd.as_raw_fd(), mode) };
    if rc == 0 { Ok(()) } else { Err(last_errno()) }
}

pub fn readlink_fd(link_fd: BorrowedFd<'_>) -> Result<String, Errno> {
    let mut cap = 256usize;
    loop {
        let mut buf = vec![0u8; cap];
        let n = unsafe {
            libc::readlinkat(
                link_fd.as_raw_fd(),
                c"".as_ptr(),
                buf.as_mut_ptr().cast::<libc::c_char>(),
                buf.len(),
            )
        };
        if n < 0 {
            return Err(last_errno());
        }
        let n = n as usize;
        if n < cap {
            buf.truncate(n);
            return String::from_utf8(buf).map_err(|_| Errno::EIO);
        }
        if cap >= 4096 {
            return Err(Errno::ENAMETOOLONG);
        }
        cap = (cap * 2).min(4096);
    }
}

pub fn readdir_fd(dir_fd: BorrowedFd<'_>) -> Result<Vec<String>, Errno> {
    let rd = upgrade_dir_fd(dir_fd)?;
    let raw_fd = rd.as_raw_fd();
    // `fdopendir` takes ownership of the underlying fd on success.
    let dirp = unsafe { libc::fdopendir(raw_fd) };
    if dirp.is_null() {
        return Err(last_errno());
    }
    std::mem::forget(rd);

    struct DirGuard(*mut libc::DIR);
    impl Drop for DirGuard {
        fn drop(&mut self) {
            unsafe {
                libc::closedir(self.0);
            }
        }
    }
    let _guard = DirGuard(dirp);

    let mut names = Vec::new();
    loop {
        let errno_ptr = unsafe { libc::__errno_location() };
        unsafe { *errno_ptr = 0 };
        let entry = unsafe { libc::readdir(dirp) };
        if entry.is_null() {
            let err = unsafe { *errno_ptr };
            if err != 0 {
                return Err(errno_from_raw(err));
            }
            break;
        }
        let name_cstr = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        let Ok(name) = name_cstr.to_str() else {
            return Err(Errno::EIO);
        };
        if name == "." || name == ".." {
            continue;
        }
        names.push(name.to_owned());
    }
    names.sort();
    Ok(names)
}

pub fn mkdirat_fd(dir_fd: BorrowedFd<'_>, name: &str, mode: u32) -> Result<(), Errno> {
    let c_name = c_str(name)?;
    let rc = unsafe { libc::mkdirat(dir_fd.as_raw_fd(), c_name.as_ptr(), mode) };
    if rc == 0 { Ok(()) } else { Err(last_errno()) }
}

pub fn mkfifoat_fd(dir_fd: BorrowedFd<'_>, name: &str, mode: u32) -> Result<(), Errno> {
    let c_name = c_str(name)?;
    let rc = unsafe { libc::mkfifoat(dir_fd.as_raw_fd(), c_name.as_ptr(), mode) };
    if rc == 0 { Ok(()) } else { Err(last_errno()) }
}

pub fn symlinkat_fd(target: &str, dir_fd: BorrowedFd<'_>, name: &str) -> Result<(), Errno> {
    let c_target = c_str(target)?;
    let c_name = c_str(name)?;
    let rc = unsafe { libc::symlinkat(c_target.as_ptr(), dir_fd.as_raw_fd(), c_name.as_ptr()) };
    if rc == 0 { Ok(()) } else { Err(last_errno()) }
}

pub fn linkat_fd(
    old_dir: BorrowedFd<'_>,
    old_name: &str,
    new_dir: BorrowedFd<'_>,
    new_name: &str,
) -> Result<(), Errno> {
    let c_old = c_str(old_name)?;
    let c_new = c_str(new_name)?;
    let rc = unsafe {
        libc::linkat(
            old_dir.as_raw_fd(),
            c_old.as_ptr(),
            new_dir.as_raw_fd(),
            c_new.as_ptr(),
            0,
        )
    };
    if rc == 0 { Ok(()) } else { Err(last_errno()) }
}

pub fn unlinkat_fd(dir_fd: BorrowedFd<'_>, name: &str, dir: bool) -> Result<(), Errno> {
    let c_name = c_str(name)?;
    let flags = if dir { libc::AT_REMOVEDIR } else { 0 };
    let rc = unsafe { libc::unlinkat(dir_fd.as_raw_fd(), c_name.as_ptr(), flags) };
    if rc == 0 { Ok(()) } else { Err(last_errno()) }
}

pub fn renameat2_fd(
    from_dir: BorrowedFd<'_>,
    from: &str,
    to_dir: BorrowedFd<'_>,
    to: &str,
    noreplace: bool,
) -> Result<(), Errno> {
    let c_from = c_str(from)?;
    let c_to = c_str(to)?;
    let flags = if noreplace { libc::RENAME_NOREPLACE } else { 0 };
    let rc = unsafe {
        libc::renameat2(
            from_dir.as_raw_fd(),
            c_from.as_ptr(),
            to_dir.as_raw_fd(),
            c_to.as_ptr(),
            flags,
        )
    };
    if rc == 0 { Ok(()) } else { Err(last_errno()) }
}

fn to_utim_spec(t: abi::Time) -> libc::timespec {
    match t {
        abi::Time::Omit => libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        },
        abi::Time::Now => libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_NOW,
        },
        abi::Time::At { sec, nsec } => libc::timespec {
            tv_sec: sec as libc::time_t,
            tv_nsec: nsec as libc::c_long,
        },
    }
}

/// Apply timestamps directly to an already-validated file/directory/other descriptor (`O_PATH`
/// included) via `/proc/self/fd`, avoiding pathname lookup races. Not used for symlinks.
pub fn utimensat_exact_fd(
    fd: BorrowedFd<'_>,
    atime: abi::Time,
    mtime: abi::Time,
) -> Result<(), Errno> {
    let times = [to_utim_spec(atime), to_utim_spec(mtime)];
    let path = format!("/proc/self/fd/{}", fd.as_raw_fd());
    let c_path = c_str(&path)?;
    let rc = unsafe { libc::utimensat(libc::AT_FDCWD, c_path.as_ptr(), times.as_ptr(), 0) };
    if rc == 0 { Ok(()) } else { Err(last_errno()) }
}

/// Apply timestamps to `name` inside `dir_fd` without dereferencing symlinks (`AT_SYMLINK_NOFOLLOW`).
pub fn utimensat_nofollow_at(
    dir_fd: BorrowedFd<'_>,
    name: &str,
    atime: abi::Time,
    mtime: abi::Time,
) -> Result<(), Errno> {
    let times = [to_utim_spec(atime), to_utim_spec(mtime)];
    let c_name = c_str(name)?;
    let rc = unsafe {
        libc::utimensat(
            dir_fd.as_raw_fd(),
            c_name.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc == 0 { Ok(()) } else { Err(last_errno()) }
}

pub fn ftruncate_fd(fd: BorrowedFd<'_>, size: u64) -> Result<(), Errno> {
    if size > FILE_MAX {
        return Err(Errno::EFBIG);
    }
    loop {
        let rc = unsafe { libc::ftruncate(fd.as_raw_fd(), size as libc::off_t) };
        if rc == 0 {
            return Ok(());
        }
        let raw = io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        if raw == libc::EINTR {
            continue;
        }
        return Err(errno_from_raw(raw));
    }
}

pub fn pread_fd(fd: BorrowedFd<'_>, buf: &mut [u8], offset: u64) -> Result<usize, Errno> {
    if offset > i64::MAX as u64 {
        return Err(Errno::EINVAL);
    }
    loop {
        let n = unsafe {
            libc::pread(
                fd.as_raw_fd(),
                buf.as_mut_ptr().cast::<libc::c_void>(),
                buf.len(),
                offset as libc::off_t,
            )
        };
        if n >= 0 {
            return Ok(n as usize);
        }
        let raw = io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        if raw == libc::EINTR {
            continue;
        }
        return Err(errno_from_raw(raw));
    }
}

pub fn pwrite_fd(fd: BorrowedFd<'_>, data: &[u8], offset: u64) -> Result<usize, Errno> {
    if offset > i64::MAX as u64 {
        return Err(Errno::EINVAL);
    }
    if offset.saturating_add(data.len() as u64) > FILE_MAX {
        return Err(Errno::EFBIG);
    }
    let mut written = 0usize;
    while written < data.len() {
        let pos = offset + written as u64;
        let slice = &data[written..];
        let n = unsafe {
            libc::pwrite(
                fd.as_raw_fd(),
                slice.as_ptr().cast::<libc::c_void>(),
                slice.len(),
                pos as libc::off_t,
            )
        };
        if n < 0 {
            let raw = io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO);
            if raw == libc::EINTR {
                continue;
            }
            if written > 0 {
                return Ok(written);
            }
            return Err(errno_from_raw(raw));
        }
        if n == 0 {
            break;
        }
        written += n as usize;
    }
    Ok(written)
}

/// Atomic append at end of file using `pwritev2(..., -1, RWF_APPEND)`, returning `(start_offset,
/// len)` directly from the kernel-updated descriptor offset. Never falls back to non-atomic
/// `stat + pwrite`.
pub fn pwrite_append_fd(fd: BorrowedFd<'_>, data: &[u8]) -> Result<(u64, usize), Errno> {
    if data.is_empty() {
        let end = unsafe { libc::lseek(fd.as_raw_fd(), 0, libc::SEEK_END) };
        if end < 0 {
            return Err(last_errno());
        }
        return Ok((end as u64, 0));
    }
    let iov = libc::iovec {
        iov_base: data.as_ptr().cast::<libc::c_void>().cast_mut(),
        iov_len: data.len(),
    };
    loop {
        let n = unsafe { libc::pwritev2(fd.as_raw_fd(), &raw const iov, 1, -1, RWF_APPEND) };
        if n >= 0 {
            let n = n as usize;
            let end_pos = unsafe { libc::lseek(fd.as_raw_fd(), 0, libc::SEEK_CUR) };
            if end_pos < 0 {
                return Err(last_errno());
            }
            let start = (end_pos as u64).saturating_sub(n as u64);
            return Ok((start, n));
        }
        let raw = io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        if raw == libc::EINTR {
            continue;
        }
        if raw == libc::EOPNOTSUPP || raw == libc::ENOSYS {
            return Err(Errno::EOPNOTSUPP);
        }
        return Err(errno_from_raw(raw));
    }
}

pub fn sync_fd(fd: BorrowedFd<'_>, data_only: bool) -> Result<(), Errno> {
    loop {
        let rc = unsafe {
            if data_only {
                libc::fdatasync(fd.as_raw_fd())
            } else {
                libc::fsync(fd.as_raw_fd())
            }
        };
        if rc == 0 {
            return Ok(());
        }
        let raw = io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        if raw == libc::EINTR {
            continue;
        }
        return Err(errno_from_raw(raw));
    }
}

pub fn flock_fd(fd: BorrowedFd<'_>, op: libc::c_int) -> Result<(), Errno> {
    loop {
        let rc = unsafe { libc::flock(fd.as_raw_fd(), op) };
        if rc == 0 {
            return Ok(());
        }
        let raw = io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        if raw == libc::EINTR {
            continue;
        }
        return Err(errno_from_raw(raw));
    }
}

fn flock_struct(kind: Option<LockKind>, range: LockRange) -> Result<libc::flock, Errno> {
    let l_start = i64::try_from(range.start()).map_err(|_| Errno::EINVAL)?;
    let l_len = match range.end() {
        None => 0i64,
        Some(end) => {
            if end <= range.start() {
                return Err(Errno::EINVAL);
            }
            let len = end - range.start();
            // `end == i64::MAX + 1` or exceeding off_t cannot be represented as positive l_len cleanly.
            i64::try_from(len).map_err(|_| Errno::EINVAL)?
        }
    };
    let l_type = match kind {
        Some(LockKind::Shared) => libc::F_RDLCK,
        Some(LockKind::Exclusive) => libc::F_WRLCK,
        None => libc::F_UNLCK,
    } as libc::c_short;
    Ok(libc::flock {
        l_type,
        l_whence: libc::SEEK_SET as libc::c_short,
        l_start,
        l_len,
        l_pid: 0,
    })
}

pub fn ofd_setlk(
    fd: BorrowedFd<'_>,
    kind: Option<LockKind>,
    range: LockRange,
) -> Result<(), Errno> {
    let mut fl = flock_struct(kind, range)?;
    loop {
        let rc = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_OFD_SETLK, &raw mut fl) };
        if rc == 0 {
            return Ok(());
        }
        let raw = io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        if raw == libc::EINTR {
            continue;
        }
        return Err(errno_from_raw(raw));
    }
}

pub fn ofd_getlk(
    fd: BorrowedFd<'_>,
    kind: LockKind,
    range: LockRange,
) -> Result<Option<(LockKind, LockRange, i32)>, Errno> {
    let mut fl = flock_struct(Some(kind), range)?;
    loop {
        let rc = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_OFD_GETLK, &raw mut fl) };
        if rc == 0 {
            if fl.l_type == libc::F_UNLCK as libc::c_short {
                return Ok(None);
            }
            let conflict_kind = if fl.l_type == libc::F_RDLCK as libc::c_short {
                LockKind::Shared
            } else {
                LockKind::Exclusive
            };
            let start = u64::try_from(fl.l_start).map_err(|_| Errno::EIO)?;
            let end = if fl.l_len == 0 {
                None
            } else {
                Some(start.saturating_add(u64::try_from(fl.l_len).map_err(|_| Errno::EIO)?))
            };
            let conflict_range = LockRange::new(start, end).ok_or(Errno::EIO)?;
            return Ok(Some((conflict_kind, conflict_range, fl.l_pid)));
        }
        let raw = io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO);
        if raw == libc::EINTR {
            continue;
        }
        return Err(errno_from_raw(raw));
    }
}

pub fn fstatvfs_fd(fd: BorrowedFd<'_>) -> Result<abi::fs::StatFs, Errno> {
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::fstatvfs(fd.as_raw_fd(), &raw mut st) };
    if rc != 0 {
        return Err(last_errno());
    }
    Ok(abi::fs::StatFs {
        block_size: (st.f_frsize as u64).max(st.f_bsize as u64).max(1),
        blocks: st.f_blocks as u64,
        blocks_free: st.f_bavail as u64,
        files: st.f_files as u64,
        files_free: st.f_favail.min(st.f_ffree) as u64,
        name_max: (st.f_namemax as u64).min(abi::NAME_MAX as u64).max(1),
    })
}

pub fn random_bytes<const N: usize>() -> Result<[u8; N], Errno> {
    let mut out = [0u8; N];
    let mut done = 0usize;
    while done < N {
        let n = unsafe {
            libc::getrandom(out[done..].as_mut_ptr().cast::<libc::c_void>(), N - done, 0)
        };
        if n < 0 {
            let raw = io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO);
            if raw == libc::EINTR {
                continue;
            }
            return Err(errno_from_raw(raw));
        }
        done += n as usize;
    }
    Ok(out)
}

pub fn new_uuid_v4() -> Result<String, Errno> {
    let mut b = random_bytes::<16>()?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0],
        b[1],
        b[2],
        b[3],
        b[4],
        b[5],
        b[6],
        b[7],
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    ))
}

pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
