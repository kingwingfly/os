//! POSIX and Linux mount/namespace/root system calls for WASI and WASIX guests.
//!
//! This compatibility layer has no command names, UI callbacks or session credentials.
//! Relative paths are never pre-joined against guest `getcwd()` and `.` / `..` segments are
//! never collapsed in guest memory; all path resolution occurs inside the OS kernel against
//! the calling process's `(MountNamespace, FsContext.root, FsContext.cwd, FdTable)`.
//!
//! # `(module "os")` Wasm Host Import Contract (L2)
//!
//! All L2 host imports live under `(module "os")` and return `i32` (`>= 0` on success, or
//! `-wasi_errno` on error using standard `__WASI_ERRNO_*` numbers, matching `os.open`,
//! `os.waitpid2`, `os.setpgid`, and `os.getgroups` in `web/wasi/process.js`):
//!
//! | Import Name | Wasm Signature | Parameters & Semantics |
//! |---|---|---|
//! | `os.chdir` | `(i32, i32) -> i32` | `(path_ptr, path_len) -> 0 \| -errno`. Walks UTF-8 path from `(root, cwd)`, checks directory + `X_OK`, updates `FsContext.cwd`. |
//! | `os.fchdir` | `(i32) -> i32` | `(fd) -> 0 \| -errno`. Sets `FsContext.cwd` from open directory descriptor `fd` (even if outside `FsContext.root`). |
//! | `os.getcwd` | `(i32, i32) -> i32` | `(buf_ptr, buf_cap) -> (len_incl_nul) \| -errno`. Writes NUL-terminated path of `FsContext.cwd` relative to `FsContext.root`; returns `-EINVAL` (`-28`) if `buf_cap == 0`, `-ERANGE` (`-68`) if `len + 1 > buf_cap`, `-ENOENT` (`-44`) if `cwd` is unlinked, detached, or outside `FsContext.root`. **Must NOT be in `NEVER_SUSPENDS`**. |
//! | `os.chroot` | `(i32, i32) -> i32` | `(path_ptr, path_len) -> 0 \| -errno`. Walks path + checks dir & `X_OK`, requires `uid == 0` (`-EPERM` = `-63`), sets `FsContext.root` without altering `cwd` or `fds`. |
//! | `os.mount` | `(i32, i32, i32, i32, i32, i32, i64, i32, i32) -> i32` | `(src_ptr, src_len, tgt_ptr, tgt_len, fstype_ptr, fstype_len, flags_u64, data_ptr, data_len) -> 0 \| -errno`. Note `flags_u64` is Wasm `i64` (`BigInt` in JS). `ptr == 0 && len == 0` denotes `None` (`NULL`); `ptr != 0` denotes `Some(&str)` of `len` UTF-8 bytes. |
//! | `os.umount2` | `(i32, i32, i32) -> i32` | `(tgt_ptr, tgt_len, flags_u32) -> 0 \| -errno`. Unmounts or lazily detaches (`MNT_DETACH = 2`, `MNT_FORCE = 1`, `UMOUNT_NOFOLLOW = 8`). |
//! | `os.statfs` | `(i32, i32, i32) -> i32` | `(path_ptr, path_len, out_raw_statfs_ptr) -> 0 \| -errno`. Writes 80-byte `abi::RawStatFs` (`10 x u64` little-endian) to `out_raw_statfs_ptr`. |
//! | `os.fstatfs` | `(i32, i32) -> i32` | `(fd, out_raw_statfs_ptr) -> 0 \| -errno`. Writes 80-byte `abi::RawStatFs` for open descriptor `fd`. |
//! | `os.unshare` | `(i32) -> i32` | `(flags_u32) -> 0 \| -errno`. Supports `0`, `CLONE_FS` (`0x200`), `CLONE_FILES` (`0x400`), `CLONE_NEWNS` (`0x20000`). |
//! | `os.setns` | `(i32, i32) -> i32` | `(fd, nstype_u32) -> 0 \| -errno`. Joins `/proc/<pid>/ns/mnt` namespace descriptor (`nstype` `0` or `CLONE_NEWNS`). |
//! | `os.execve` | `(i32, i32) -> i32` | `(req_ptr, req_len) -> -errno` (never returns on success; unwinds image). `req` is UTF-8 JSON `{"file": str, "argv": [str], "env": [str], "search": bool}`. |
//!
//! # WASI Path Anchor Pseudo-Descriptors
//!
//! Strong overrides for `__wasilibc_find_abspath`, `__wasilibc_find_relpath`, and
//! `__wasilibc_find_relpath_alloc` pass uncollapsed paths to `wasi_snapshot_preview1::path_*`
//! anchored on:
//! - `abi::OS_FD_ROOT` (`0x7fff_fffd`): resolves relative to `FsContext.root`.
//! - `abi::OS_FD_CWD` (`0x7fff_fffe`): resolves relative to `FsContext.cwd`.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

pub mod pipe;
pub mod process;
pub(crate) mod wasi_libc;

pub use abi::contract::{fs_magic, mount_flags, statfs_flags, umount_flags, unshare_flags};
pub use abi::{Errno, OS_FD_CWD, OS_FD_ROOT, RawStatFs, Stat, StatFs, Time};
pub use process::execvp;

/// Structured OS ABI error payload stored inside `std::io::Error` so callers can recover the
/// exact `abi::Errno` (such as `ENOTCONN`, `ESTALE`, `EXDEV`, `EBUSY`, `EROFS`, `ELOOP`,
/// `ENODEV`, or `EPERM` vs `EACCES`) via [`errno_of`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OsCallError(pub abi::Error);

impl fmt::Display for OsCallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl std::error::Error for OsCallError {}

/// Extract the exact [`abi::Errno`] from an [`io::Error`], whether produced by an `os_posix`
/// ABI call / host import (`OsCallError`) or a raw OS error (`raw_os_error`).
pub fn errno_of(err: &io::Error) -> Option<abi::Errno> {
    if let Some(os) = err.get_ref().and_then(|e| e.downcast_ref::<OsCallError>()) {
        return Some(os.0.errno);
    }
    if let Some(code) = err.raw_os_error() {
        return raw_errno_to_abi(code);
    }
    None
}

#[cfg(target_os = "wasi")]
fn raw_errno_to_abi(code: i32) -> Option<abi::Errno> {
    wasi_libc::wasi_errno_to_abi(code)
}

#[cfg(all(unix, not(target_os = "wasi")))]
fn raw_errno_to_abi(code: i32) -> Option<abi::Errno> {
    use abi::Errno::*;
    Some(match code {
        1 => EPERM,
        2 => ENOENT,
        3 => ESRCH,
        4 => EINTR,
        5 => EIO,
        6 => ENXIO,
        7 => E2BIG,
        8 => ENOEXEC,
        9 => EBADF,
        10 => ECHILD,
        11 => EAGAIN,
        13 => EACCES,
        14 => EINVAL, // EFAULT
        16 => EBUSY,
        17 => EEXIST,
        18 => EXDEV,
        19 => ENODEV,
        20 => ENOTDIR,
        21 => EISDIR,
        22 => EINVAL,
        24 => EMFILE,
        25 => ENOTTY,
        26 => ETXTBSY,
        27 => EFBIG,
        28 => ENOSPC,
        30 => EROFS,
        31 => EMLINK,
        32 => EPIPE,
        34 => ERANGE,
        35 => EDEADLK,
        36 => ENAMETOOLONG,
        37 => ENOLCK,
        38 => ENOSYS,
        39 => ENOTEMPTY,
        40 => ELOOP,
        61 => ENODATA,
        93 => EPROTONOSUPPORT,
        95 => EOPNOTSUPP,
        107 => ENOTCONN,
        110 => ETIMEDOUT,
        116 => ESTALE,
        122 => EDQUOT,
        125 => ECANCELED,
        _ => return None,
    })
}

#[cfg(not(any(unix, target_os = "wasi")))]
fn raw_errno_to_abi(_code: i32) -> Option<abi::Errno> {
    None
}

/// Ensure the WASI libc path/cwd overrides in `os_posix` are linked before guest code runs.
pub fn init_preopens() -> io::Result<()> {
    wasi_libc::ensure_linked();
    Ok(())
}

/// Validate a guest path as UTF-8 without calling `getcwd()` or collapsing `.` / `..`.
pub fn raw_path(path: &Path) -> io::Result<String> {
    let text = path
        .to_str()
        .ok_or_else(|| os_error(abi::Error::because(Errno::EINVAL, "invalid UTF-8 path")))?;
    if text.contains('\0') {
        return Err(os_error(abi::Error::because(
            Errno::EINVAL,
            "path contains NUL byte",
        )));
    }
    Ok(text.to_owned())
}

fn raw_str(text: &str) -> io::Result<&str> {
    if text.contains('\0') {
        return Err(os_error(abi::Error::because(
            Errno::EINVAL,
            "string contains NUL byte",
        )));
    }
    Ok(text)
}

/// Read the full metadata of a path, following its last symlink only when requested.
pub fn stat(path: &Path, follow: bool) -> io::Result<Stat> {
    let path = raw_path(path)?;
    let call = if follow {
        abi::Call::Stat { path }
    } else {
        abi::Call::Lstat { path }
    };
    metadata(&request(&[call])?)
}

/// mkdir(2), retaining mode bits that WASI preview 1 cannot carry.
pub fn mkdir(path: &Path, mode: u32) -> io::Result<()> {
    unit_call(abi::Call::Mkdir {
        path: raw_path(path)?,
        mode: (mode & 0o7777) as u16,
    })
}

/// chmod(2), including permissions that WASI preview 1 cannot represent.
pub fn chmod(path: &Path, mode: u32) -> io::Result<()> {
    unit_call(abi::Call::Chmod {
        path: raw_path(path)?,
        mode: (mode & 0o7777) as u16,
    })
}

/// mount(2): attach, bind, move, or remount a filesystem in the caller's mount namespace.
pub fn mount(
    source: Option<&Path>,
    target: &Path,
    fstype: Option<&str>,
    flags: u64,
    data: Option<&str>,
) -> io::Result<()> {
    let source_str = match source {
        Some(p) => Some(raw_path(p)?),
        None => None,
    };
    let target_str = raw_path(target)?;
    let fstype_str = match fstype {
        Some(s) => Some(raw_str(s)?),
        None => None,
    };
    let data_str = match data {
        Some(s) => Some(raw_str(s)?),
        None => None,
    };
    #[cfg(target_arch = "wasm32")]
    {
        let (src_ptr, src_len) = opt_ptr_len(source_str.as_deref());
        let (type_ptr, type_len) = opt_ptr_len(fstype_str);
        let (data_ptr, data_len) = opt_ptr_len(data_str);
        // SAFETY: all slices live for the duration of this synchronous/suspending host import.
        let rc = unsafe {
            wasi_libc::host::host_mount(
                src_ptr,
                src_len,
                target_str.as_ptr(),
                target_str.len(),
                type_ptr,
                type_len,
                flags,
                data_ptr,
                data_len,
            )
        };
        host_unit_result(rc)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        unit_call(abi::Call::Mount {
            source: source_str.unwrap_or_default(),
            target: target_str,
            fstype: fstype_str.map(str::to_owned),
            flags,
            data: data_str.map(str::to_owned),
        })
    }
}

/// umount(2): unmount `target` (`umount2(target, 0)`).
pub fn umount(target: &Path) -> io::Result<()> {
    umount2(target, 0)
}

/// umount2(2): unmount or lazily detach `target` with `umount_flags::*`.
pub fn umount2(target: &Path, flags: u32) -> io::Result<()> {
    let target_str = raw_path(target)?;
    #[cfg(target_arch = "wasm32")]
    {
        // SAFETY: `target_str` lives across the host call.
        let rc =
            unsafe { wasi_libc::host::host_umount2(target_str.as_ptr(), target_str.len(), flags) };
        host_unit_result(rc)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        unit_call(abi::Call::Umount2 {
            target: target_str,
            flags,
        })
    }
}

/// chdir(2): set the calling process's working directory handle.
pub fn chdir(path: &Path) -> io::Result<()> {
    let path_str = raw_path(path)?;
    #[cfg(target_arch = "wasm32")]
    {
        // SAFETY: `path_str` lives across the host call.
        let rc = unsafe { wasi_libc::host::host_chdir(path_str.as_ptr(), path_str.len()) };
        host_unit_result(rc)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        unit_call(abi::Call::Chdir { path: path_str })
    }
}

/// fchdir(2): set the calling process's working directory from an open directory descriptor.
pub fn fchdir(fd: u32) -> io::Result<()> {
    #[cfg(target_arch = "wasm32")]
    {
        // SAFETY: scalar host import.
        let rc = unsafe { wasi_libc::host::host_fchdir(fd as i32) };
        host_unit_result(rc)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        unit_call(abi::Call::Fchdir { fd: fd.into() })
    }
}

/// getcwd(2): reconstruct the calling process's working directory path within its `chroot`.
pub fn getcwd() -> io::Result<PathBuf> {
    #[cfg(target_arch = "wasm32")]
    {
        let mut cap = 256usize;
        loop {
            let mut buf = vec![0u8; cap];
            // SAFETY: `buf` has `cap` writable bytes.
            let rc = unsafe { wasi_libc::host::host_getcwd(buf.as_mut_ptr(), cap) };
            if rc >= 0 {
                let len = (rc as usize).saturating_sub(1).min(buf.len());
                buf.truncate(len);
                let text = String::from_utf8(buf)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                return Ok(PathBuf::from(text));
            }
            if -rc == wasi_libc::WASI_ERANGE && cap < 65536 {
                cap *= 2;
                continue;
            }
            return Err(host_errno_error(-rc));
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let value = value_call(abi::Call::Getcwd)?;
        let path: String = serde_json::from_value(value)?;
        Ok(PathBuf::from(path))
    }
}

/// chroot(2): set the calling process's root directory handle without changing `cwd` or open fds.
pub fn chroot(path: &Path) -> io::Result<()> {
    let path_str = raw_path(path)?;
    #[cfg(target_arch = "wasm32")]
    {
        // SAFETY: `path_str` lives across the host call.
        let rc = unsafe { wasi_libc::host::host_chroot(path_str.as_ptr(), path_str.len()) };
        host_unit_result(rc)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        unit_call(abi::Call::Chroot { path: path_str })
    }
}

/// statfs(2): query filesystem statistics for `path`.
pub fn statfs(path: &Path) -> io::Result<abi::StatFs> {
    let path_str = raw_path(path)?;
    #[cfg(target_arch = "wasm32")]
    {
        let mut raw = abi::RawStatFs::default();
        // SAFETY: `path_str` is readable and `raw` is stack-owned (80 bytes).
        let rc =
            unsafe { wasi_libc::host::host_statfs(path_str.as_ptr(), path_str.len(), &mut raw) };
        host_unit_result(rc)?;
        Ok(abi::StatFs::from(raw))
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let value = value_call(abi::Call::Statfs { path: path_str })?;
        serde_json::from_value(value).map_err(Into::into)
    }
}

/// fstatfs(2): query filesystem statistics for open descriptor `fd`.
pub fn fstatfs(fd: u32) -> io::Result<abi::StatFs> {
    #[cfg(target_arch = "wasm32")]
    {
        let mut raw = abi::RawStatFs::default();
        // SAFETY: `raw` is stack-owned (80 bytes).
        let rc = unsafe { wasi_libc::host::host_fstatfs(fd as i32, &mut raw) };
        host_unit_result(rc)?;
        Ok(abi::StatFs::from(raw))
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let value = value_call(abi::Call::Fstatfs { fd: fd.into() })?;
        serde_json::from_value(value).map_err(Into::into)
    }
}

/// unshare(2): unshare mount namespace (`CLONE_NEWNS`), filesystem context (`CLONE_FS`),
/// or descriptor table (`CLONE_FILES`).
pub fn unshare(flags: u32) -> io::Result<()> {
    #[cfg(target_arch = "wasm32")]
    {
        // SAFETY: scalar host import.
        let rc = unsafe { wasi_libc::host::host_unshare(flags) };
        host_unit_result(rc)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        unit_call(abi::Call::Unshare { flags })
    }
}

/// setns(2): join the mount namespace referenced by `/proc/<pid>/ns/mnt` descriptor `fd`.
pub fn setns(fd: u32, nstype: u32) -> io::Result<()> {
    #[cfg(target_arch = "wasm32")]
    {
        // SAFETY: scalar host import.
        let rc = unsafe { wasi_libc::host::host_setns(fd as i32, nstype) };
        host_unit_result(rc)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        unit_call(abi::Call::Setns {
            fd: fd.into(),
            nstype,
        })
    }
}

/// fstatat(2): stat `path` relative to `dirfd` (`None` = `AT_FDCWD`).
pub fn statat(dirfd: Option<u32>, path: &Path, follow: bool) -> io::Result<Stat> {
    let path = raw_path(path)?;
    let call = match dirfd {
        Some(fd) => abi::Call::FstatAt {
            dirfd: fd.into(),
            path,
            nofollow: !follow,
        },
        None if follow => abi::Call::Stat { path },
        None => abi::Call::Lstat { path },
    };
    metadata(&request(&[call])?)
}

/// mkdirat(2): create directory `path` relative to `dirfd` (`None` = `AT_FDCWD`).
pub fn mkdirat(dirfd: Option<u32>, path: &Path, mode: u32) -> io::Result<()> {
    let path = raw_path(path)?;
    let mode = (mode & 0o7777) as u16;
    let call = match dirfd {
        Some(fd) => abi::Call::MkdirAt {
            dirfd: fd.into(),
            path,
            mode,
        },
        None => abi::Call::Mkdir { path, mode },
    };
    unit_call(call)
}

/// unlinkat(2): unlink or rmdir (`rmdir == true`) `path` relative to `dirfd` (`None` = `AT_FDCWD`).
pub fn unlinkat(dirfd: Option<u32>, path: &Path, rmdir: bool) -> io::Result<()> {
    let path = raw_path(path)?;
    let call = match dirfd {
        Some(fd) => abi::Call::UnlinkAt {
            dirfd: fd.into(),
            path,
            rmdir,
        },
        None if rmdir => abi::Call::Rmdir { path },
        None => abi::Call::Unlink { path },
    };
    unit_call(call)
}

/// renameat2(2): rename `(from_dirfd, from)` to `(to_dirfd, to)`.
pub fn renameat(
    from_dirfd: Option<u32>,
    from: &Path,
    to_dirfd: Option<u32>,
    to: &Path,
    noreplace: bool,
) -> io::Result<()> {
    let from = raw_path(from)?;
    let to = raw_path(to)?;
    let call = match (from_dirfd, to_dirfd) {
        (None, None) => abi::Call::Rename {
            from,
            to,
            noreplace,
        },
        (f, t) => abi::Call::RenameAt {
            from_dirfd: f.unwrap_or(abi::OS_FD_CWD as u32).into(),
            from,
            to_dirfd: t.unwrap_or(abi::OS_FD_CWD as u32).into(),
            to,
            noreplace,
        },
    };
    unit_call(call)
}

/// linkat(2): create hard link from `(from_dirfd, from)` to `(to_dirfd, to)`.
pub fn linkat(
    from_dirfd: Option<u32>,
    from: &Path,
    to_dirfd: Option<u32>,
    to: &Path,
    follow: bool,
) -> io::Result<()> {
    let from = raw_path(from)?;
    let to = raw_path(to)?;
    let call = match (from_dirfd, to_dirfd) {
        (None, None) => abi::Call::Link { from, to, follow },
        (f, t) => abi::Call::LinkAt {
            from_dirfd: f.unwrap_or(abi::OS_FD_CWD as u32).into(),
            from,
            to_dirfd: t.unwrap_or(abi::OS_FD_CWD as u32).into(),
            to,
            follow,
        },
    };
    unit_call(call)
}

/// symlinkat(2): create symbolic link `path` -> `target` relative to `dirfd` (`None` = `AT_FDCWD`).
pub fn symlinkat(target: &Path, dirfd: Option<u32>, path: &Path) -> io::Result<()> {
    let target = raw_path(target)?;
    let path = raw_path(path)?;
    let call = match dirfd {
        Some(fd) => abi::Call::SymlinkAt {
            target,
            dirfd: fd.into(),
            path,
        },
        None => abi::Call::Symlink { target, path },
    };
    unit_call(call)
}

/// readlinkat(2): read target of symbolic link `path` relative to `dirfd` (`None` = `AT_FDCWD`).
pub fn readlinkat(dirfd: Option<u32>, path: &Path) -> io::Result<PathBuf> {
    let path = raw_path(path)?;
    let call = match dirfd {
        Some(fd) => abi::Call::ReadlinkAt {
            dirfd: fd.into(),
            path,
        },
        None => abi::Call::Readlink { path },
    };
    let value = value_call(call)?;
    let link: String = serde_json::from_value(value)?;
    Ok(PathBuf::from(link))
}

/// utimensat(2): update access and modification timestamps relative to `dirfd` (`None` = `AT_FDCWD`).
pub fn utimensat(
    dirfd: Option<u32>,
    path: &Path,
    atime: abi::Time,
    mtime: abi::Time,
    follow: bool,
) -> io::Result<()> {
    let path = raw_path(path)?;
    let nofollow = !follow;
    let call = match dirfd {
        Some(fd) => abi::Call::UtimensAt {
            dirfd: fd.into(),
            path,
            atime,
            mtime,
            nofollow,
        },
        None => abi::Call::Utimens {
            path,
            atime,
            mtime,
            nofollow,
        },
    };
    unit_call(call)
}

/// Change this process's creation mask and return its previous value, as umask(2) does.
/// The mask is process-local; the authoritative filesystem still checks every operation.
#[cfg(target_os = "wasi")]
pub fn umask(mask: u32) -> u32 {
    #[link(wasm_import_module = "os")]
    unsafe extern "C" {
        #[link_name = "umask"]
        fn host_umask(mask: u32) -> u32;
    }
    // SAFETY: this scalar-only host call reads or writes no guest memory.
    unsafe { host_umask(mask & 0o777) }
}

#[cfg(target_arch = "wasm32")]
fn opt_ptr_len(value: Option<&str>) -> (*const u8, usize) {
    match value {
        Some(s) => (s.as_ptr(), s.len()),
        None => (core::ptr::null(), 0),
    }
}

#[cfg(target_arch = "wasm32")]
fn host_unit_result(rc: i32) -> io::Result<()> {
    if rc < 0 {
        Err(host_errno_error(-rc))
    } else {
        Ok(())
    }
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn host_errno_error(wasi_errno: i32) -> io::Error {
    if let Some(errno) = wasi_libc::wasi_errno_to_abi(wasi_errno) {
        os_error(abi::Error::new(errno))
    } else {
        io::Error::from_raw_os_error(wasi_errno)
    }
}

pub(crate) fn os_error(error: abi::Error) -> io::Error {
    let kind = match error.errno {
        abi::Errno::ENOENT => io::ErrorKind::NotFound,
        abi::Errno::EACCES | abi::Errno::EPERM => io::ErrorKind::PermissionDenied,
        abi::Errno::EEXIST => io::ErrorKind::AlreadyExists,
        abi::Errno::ENOTDIR => io::ErrorKind::NotADirectory,
        abi::Errno::EISDIR => io::ErrorKind::IsADirectory,
        abi::Errno::ENOTEMPTY => io::ErrorKind::DirectoryNotEmpty,
        abi::Errno::EINVAL => io::ErrorKind::InvalidInput,
        abi::Errno::EINTR => io::ErrorKind::Interrupted,
        abi::Errno::EDQUOT => io::ErrorKind::QuotaExceeded,
        abi::Errno::ENOTCONN => io::ErrorKind::NotConnected,
        abi::Errno::ESTALE => io::ErrorKind::StaleNetworkFileHandle,
        abi::Errno::EXDEV => io::ErrorKind::CrossesDevices,
        abi::Errno::EBUSY => io::ErrorKind::ResourceBusy,
        abi::Errno::EROFS => io::ErrorKind::ReadOnlyFilesystem,
        abi::Errno::ENOSPC => io::ErrorKind::StorageFull,
        abi::Errno::ENAMETOOLONG => io::ErrorKind::InvalidFilename,
        abi::Errno::EAGAIN => io::ErrorKind::WouldBlock,
        abi::Errno::EPIPE => io::ErrorKind::BrokenPipe,
        abi::Errno::ETIMEDOUT => io::ErrorKind::TimedOut,
        abi::Errno::EOPNOTSUPP | abi::Errno::ENOSYS => io::ErrorKind::Unsupported,
        abi::Errno::EDEADLK => io::ErrorKind::Deadlock,
        abi::Errno::EFBIG => io::ErrorKind::FileTooLarge,
        abi::Errno::ETXTBSY => io::ErrorKind::ExecutableFileBusy,
        abi::Errno::EMLINK => io::ErrorKind::TooManyLinks,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, OsCallError(error))
}

fn value_call(call: abi::Call) -> io::Result<serde_json::Value> {
    let mut reply = batch(&[call])?;
    reply.results.remove(0).into_result().map_err(os_error)
}

fn unit_call(call: abi::Call) -> io::Result<()> {
    value_call(call).map(|_| ())
}

/// Make an OS call batch with this process's credentials. No browser session is borrowed.
pub fn batch(calls: &[abi::Call]) -> io::Result<abi::Results> {
    let reply: abi::Results = serde_json::from_slice(&request(calls)?)?;
    if reply.results.len() != calls.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "incomplete OS reply",
        ));
    }
    Ok(reply)
}

#[cfg(target_os = "wasi")]
fn request(calls: &[abi::Call]) -> io::Result<Vec<u8>> {
    #[link(wasm_import_module = "os")]
    unsafe extern "C" {
        fn sys(calls: *const u8, len: usize) -> usize;
        fn reply(to: *mut u8);
    }
    let calls = serde_json::to_vec(calls)?;
    // SAFETY: the host reads only this buffer and reports the size of its pending reply.
    let len = unsafe { sys(calls.as_ptr(), calls.len()) };
    if len > 16 << 20 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "oversized OS reply",
        ));
    }
    let mut out = vec![0; len];
    // SAFETY: out has the length returned by sys; no intervening call replaces that reply.
    unsafe { reply(out.as_mut_ptr()) };
    Ok(out)
}

#[cfg(not(target_os = "wasi"))]
fn request(_: &[abi::Call]) -> io::Result<Vec<u8>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "requires the WASI OS adapter",
    ))
}

fn metadata(bytes: &[u8]) -> io::Result<Stat> {
    let mut results: abi::Results = serde_json::from_slice(bytes)?;
    if results.results.len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid stat reply",
        ));
    }
    let result = results
        .results
        .pop()
        .unwrap()
        .into_result()
        .map_err(os_error)?;
    serde_json::from_value(result).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_preserves_identity_modes_links_and_acl() {
        let stat = Stat {
            ino: 19,
            mode: 0o106750,
            nlink: 3,
            uid: 42,
            gid: 7,
            user: "ann".into(),
            group: "staff".into(),
            acl: true,
            ..Stat::default()
        };
        let reply = serde_json::json!({"results": [{"ok": stat}]}).to_string();
        assert_eq!(metadata(reply.as_bytes()).unwrap(), stat);
    }

    #[test]
    fn malformed_and_denied_metadata_never_become_placeholder_owners() {
        for bytes in [
            b"{}".as_slice(),
            b"{\"results\":[]}",
            b"{\"results\":[{\"ok\":{}}]}",
        ] {
            assert!(metadata(bytes).is_err());
        }
        let reply = serde_json::json!({"results": [{"err": {"errno": "EACCES"}}]}).to_string();
        let err = metadata(reply.as_bytes()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(errno_of(&err), Some(Errno::EACCES));
    }

    #[test]
    fn os_error_preserves_exact_errnos_and_kinds() {
        let cases = [
            (Errno::ENOTCONN, io::ErrorKind::NotConnected),
            (Errno::ESTALE, io::ErrorKind::StaleNetworkFileHandle),
            (Errno::EXDEV, io::ErrorKind::CrossesDevices),
            (Errno::EBUSY, io::ErrorKind::ResourceBusy),
            (Errno::EROFS, io::ErrorKind::ReadOnlyFilesystem),
            (Errno::ELOOP, io::ErrorKind::Other),
            (Errno::ENODEV, io::ErrorKind::Other),
            (Errno::EPERM, io::ErrorKind::PermissionDenied),
            (Errno::EACCES, io::ErrorKind::PermissionDenied),
            (Errno::EINVAL, io::ErrorKind::InvalidInput),
            (Errno::ENOTDIR, io::ErrorKind::NotADirectory),
            (Errno::ENOENT, io::ErrorKind::NotFound),
            (Errno::ERANGE, io::ErrorKind::Other),
            (Errno::EBADF, io::ErrorKind::Other),
            (Errno::ENOSPC, io::ErrorKind::StorageFull),
            (Errno::ENAMETOOLONG, io::ErrorKind::InvalidFilename),
            (Errno::EINTR, io::ErrorKind::Interrupted),
            (Errno::EDQUOT, io::ErrorKind::QuotaExceeded),
            (Errno::ENOLCK, io::ErrorKind::Other),
        ];
        for (errno, expected_kind) in cases {
            let err = os_error(abi::Error::because(errno, format!("custom {errno:?}")));
            assert_eq!(err.kind(), expected_kind, "{errno:?}");
            assert_eq!(errno_of(&err), Some(errno), "{errno:?}");
            assert_eq!(err.to_string(), format!("custom {errno:?}"));
        }
        // Distinguish EPERM from EACCES even though both map to PermissionDenied.
        let eperm = os_error(abi::Error::new(Errno::EPERM));
        let eacces = os_error(abi::Error::new(Errno::EACCES));
        assert_eq!(eperm.kind(), eacces.kind());
        assert_eq!(errno_of(&eperm), Some(Errno::EPERM));
        assert_eq!(errno_of(&eacces), Some(Errno::EACCES));
    }

    #[test]
    fn raw_path_preserves_relative_and_dotdot_without_getcwd() {
        assert_eq!(raw_path(Path::new(".")).unwrap(), ".");
        assert_eq!(raw_path(Path::new("..")).unwrap(), "..");
        assert_eq!(raw_path(Path::new("a/../b/./c/")).unwrap(), "a/../b/./c/");
        assert_eq!(raw_path(Path::new("/mnt/../etc")).unwrap(), "/mnt/../etc");
        let nul_err = raw_path(Path::new("bad\0path")).unwrap_err();
        assert_eq!(errno_of(&nul_err), Some(Errno::EINVAL));
    }

    #[test]
    fn split_guest_path_routes_root_and_cwd_without_collapsing() {
        assert_eq!(
            wasi_libc::split_guest_path(b""),
            Err(wasi_libc::WASI_ENOENT)
        );
        assert_eq!(
            wasi_libc::split_guest_path(b"/"),
            Ok((OS_FD_ROOT, b"/\0".as_slice(), b".".as_slice()))
        );
        assert_eq!(
            wasi_libc::split_guest_path(b"///"),
            Ok((OS_FD_ROOT, b"/\0".as_slice(), b".".as_slice()))
        );
        assert_eq!(
            wasi_libc::split_guest_path(b"/a/../b/"),
            Ok((OS_FD_ROOT, b"/\0".as_slice(), b"a/../b/".as_slice()))
        );
        assert_eq!(
            wasi_libc::split_guest_path(b"link/.."),
            Ok((OS_FD_CWD, b".\0".as_slice(), b"link/..".as_slice()))
        );
        assert_eq!(
            wasi_libc::split_guest_path(b".././sub/"),
            Ok((OS_FD_CWD, b".\0".as_slice(), b".././sub/".as_slice()))
        );
    }

    #[test]
    fn wasi_errno_table_roundtrips_contract_errnos() {
        for (wasi, expected) in [
            (wasi_libc::WASI_ENOTCONN, Errno::ENOTCONN),
            (wasi_libc::WASI_ESTALE, Errno::ESTALE),
            (wasi_libc::WASI_EXDEV, Errno::EXDEV),
            (wasi_libc::WASI_EBUSY, Errno::EBUSY),
            (wasi_libc::WASI_EROFS, Errno::EROFS),
            (wasi_libc::WASI_ELOOP, Errno::ELOOP),
            (wasi_libc::WASI_ENODEV, Errno::ENODEV),
            (wasi_libc::WASI_EPERM, Errno::EPERM),
            (wasi_libc::WASI_EACCES, Errno::EACCES),
            (wasi_libc::WASI_ERANGE, Errno::ERANGE),
        ] {
            assert_eq!(wasi_libc::wasi_errno_to_abi(wasi), Some(expected));
        }
    }
}
