//! WASI / WASIX guest libc overrides and `(module "os")` host import bindings.
//!
//! Defeats `wasi-libc` / `wasix-libc` guest-side `getcwd()` caching and lexical `.` / `..`
//! path collapsing by routing all absolute paths to `abi::OS_FD_ROOT` (`0x7fff_fffd`) and all
//! relative paths to `abi::OS_FD_CWD` (`0x7fff_fffe`) uncollapsed.

#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_E2BIG: i32 = 1;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_EACCES: i32 = 2;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_EAGAIN: i32 = 6;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_EBADF: i32 = 8;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_EBUSY: i32 = 10;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_ECANCELED: i32 = 11;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_ECHILD: i32 = 12;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_EDEADLK: i32 = 16;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_EDQUOT: i32 = 19;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_EEXIST: i32 = 20;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_EFAULT: i32 = 21;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_EFBIG: i32 = 22;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_EINTR: i32 = 27;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_EINVAL: i32 = 28;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_EIO: i32 = 29;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_EISDIR: i32 = 31;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_ELOOP: i32 = 32;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_EMFILE: i32 = 33;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_EMLINK: i32 = 34;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_ENAMETOOLONG: i32 = 37;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_ENODEV: i32 = 43;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_ENOENT: i32 = 44;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_ENOEXEC: i32 = 45;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_ENOLCK: i32 = 46;
#[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
pub(crate) const WASI_ENOMEM: i32 = 48;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_ENOSPC: i32 = 51;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_ENOSYS: i32 = 52;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_ENOTCONN: i32 = 53;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_ENOTDIR: i32 = 54;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_ENOTEMPTY: i32 = 55;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_EOPNOTSUPP: i32 = 58;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_ENOTTY: i32 = 59;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_ENXIO: i32 = 60;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_EPERM: i32 = 63;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_EPIPE: i32 = 64;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_EPROTONOSUPPORT: i32 = 66;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_ERANGE: i32 = 68;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_EROFS: i32 = 69;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_ESRCH: i32 = 71;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_ESTALE: i32 = 72;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_ETIMEDOUT: i32 = 73;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_ETXTBSY: i32 = 74;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_EXDEV: i32 = 75;

#[cfg(any(target_arch = "wasm32", test))]
pub(crate) fn wasi_errno_to_abi(code: i32) -> Option<abi::Errno> {
    use abi::Errno::*;
    Some(match code {
        WASI_E2BIG => E2BIG,
        WASI_EACCES => EACCES,
        WASI_EAGAIN => EAGAIN,
        WASI_EBADF => EBADF,
        WASI_EBUSY => EBUSY,
        WASI_ECANCELED => ECANCELED,
        WASI_ECHILD => ECHILD,
        WASI_EDEADLK => EDEADLK,
        WASI_EDQUOT => EDQUOT,
        WASI_EEXIST => EEXIST,
        WASI_EFBIG => EFBIG,
        WASI_EINTR => EINTR,
        WASI_EINVAL | WASI_EFAULT => EINVAL,
        WASI_EIO => EIO,
        WASI_EISDIR => EISDIR,
        WASI_ELOOP => ELOOP,
        WASI_EMFILE => EMFILE,
        WASI_EMLINK => EMLINK,
        WASI_ENAMETOOLONG => ENAMETOOLONG,
        WASI_ENODEV => ENODEV,
        WASI_ENOENT => ENOENT,
        WASI_ENOEXEC => ENOEXEC,
        WASI_ENOLCK => ENOLCK,
        WASI_ENOSPC => ENOSPC,
        WASI_ENOSYS => ENOSYS,
        WASI_ENOTCONN => ENOTCONN,
        WASI_ENOTDIR => ENOTDIR,
        WASI_ENOTEMPTY => ENOTEMPTY,
        WASI_EOPNOTSUPP => EOPNOTSUPP,
        WASI_ENOTTY => ENOTTY,
        WASI_ENXIO => ENXIO,
        WASI_EPERM => EPERM,
        WASI_EPIPE => EPIPE,
        WASI_EPROTONOSUPPORT => EPROTONOSUPPORT,
        WASI_ERANGE => ERANGE,
        WASI_EROFS => EROFS,
        WASI_ESRCH => ESRCH,
        WASI_ESTALE => ESTALE,
        WASI_ETIMEDOUT => ETIMEDOUT,
        WASI_ETXTBSY => ETXTBSY,
        WASI_EXDEV => EXDEV,
        217 => ENODATA,
        218 => ENOTBLK,
        _ => return None,
    })
}

#[cfg(any(target_arch = "wasm32", test))]
pub(crate) fn abi_errno_to_wasi(errno: abi::Errno) -> i32 {
    use abi::Errno::*;
    match errno {
        EPERM => WASI_EPERM,
        ENOENT => WASI_ENOENT,
        ESRCH => WASI_ESRCH,
        EIO => WASI_EIO,
        ENXIO => WASI_ENXIO,
        E2BIG => WASI_E2BIG,
        EBADF => WASI_EBADF,
        EAGAIN => WASI_EAGAIN,
        EACCES => WASI_EACCES,
        ENOTBLK => 218,
        EBUSY => WASI_EBUSY,
        EEXIST => WASI_EEXIST,
        EXDEV => WASI_EXDEV,
        ENODEV => WASI_ENODEV,
        ENOTDIR => WASI_ENOTDIR,
        EISDIR => WASI_EISDIR,
        EINVAL => WASI_EINVAL,
        EMFILE => WASI_EMFILE,
        ENOTTY => WASI_ENOTTY,
        ETXTBSY => WASI_ETXTBSY,
        EFBIG => WASI_EFBIG,
        ENOSPC => WASI_ENOSPC,
        EROFS => WASI_EROFS,
        EMLINK => WASI_EMLINK,
        EPIPE => WASI_EPIPE,
        ERANGE => WASI_ERANGE,
        ENAMETOOLONG => WASI_ENAMETOOLONG,
        ENOSYS => WASI_ENOSYS,
        ENOTEMPTY => WASI_ENOTEMPTY,
        ELOOP => WASI_ELOOP,
        ENODATA => 217,
        EOPNOTSUPP => WASI_EOPNOTSUPP,
        ESTALE => WASI_ESTALE,
        ETIMEDOUT => WASI_ETIMEDOUT,
        ECANCELED => WASI_ECANCELED,
        ENOEXEC => WASI_ENOEXEC,
        ECHILD => WASI_ECHILD,
        EDEADLK => WASI_EDEADLK,
        EPROTONOSUPPORT => WASI_EPROTONOSUPPORT,
        ENOTCONN => WASI_ENOTCONN,
        ENOLCK => WASI_ENOLCK,
        EDQUOT => WASI_EDQUOT,
        EINTR => WASI_EINTR,
    }
}

#[cfg(any(target_arch = "wasm32", test))]
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CTimespec {
    pub tv_sec: i64,
    pub tv_nsec: core::ffi::c_long,
}

#[cfg(any(target_arch = "wasm32", test))]
const _: () = {
    assert!(core::mem::size_of::<CTimespec>() == 16);
    assert!(core::mem::align_of::<CTimespec>() == 8);
    assert!(core::mem::offset_of!(CTimespec, tv_sec) == 0);
    assert!(core::mem::offset_of!(CTimespec, tv_nsec) == 8);
};

#[cfg(any(target_arch = "wasm32", test))]
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CTimeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

#[cfg(any(target_arch = "wasm32", test))]
const _: () = {
    assert!(core::mem::size_of::<CTimeval>() == 16);
    assert!(core::mem::align_of::<CTimeval>() == 8);
    assert!(core::mem::offset_of!(CTimeval, tv_sec) == 0);
    assert!(core::mem::offset_of!(CTimeval, tv_usec) == 8);
};

#[cfg(any(target_arch = "wasm32", test))]
pub(crate) fn convert_timevals(times: [CTimeval; 2]) -> Result<[CTimespec; 2], i32> {
    let [atime, mtime] = times;
    if !(0..1_000_000).contains(&atime.tv_usec) || !(0..1_000_000).contains(&mtime.tv_usec) {
        return Err(WASI_EINVAL);
    }
    Ok([
        CTimespec {
            tv_sec: atime.tv_sec,
            tv_nsec: (atime.tv_usec * 1000) as core::ffi::c_long,
        },
        CTimespec {
            tv_sec: mtime.tv_sec,
            tv_nsec: (mtime.tv_usec * 1000) as core::ffi::c_long,
        },
    ])
}

#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_AT_FDCWD: i32 = -2;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const LINUX_AT_FDCWD: i32 = -100;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const WASI_AT_SYMLINK_NOFOLLOW: i32 = 0x1;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) const LINUX_AT_SYMLINK_NOFOLLOW: i32 = 0x100;

#[cfg(any(target_arch = "wasm32", test))]
pub(crate) fn validate_fchmodat_flags(flags: i32) -> Result<(), i32> {
    let known = WASI_AT_SYMLINK_NOFOLLOW | LINUX_AT_SYMLINK_NOFOLLOW;
    if (flags & !known) != 0 {
        return Err(WASI_EINVAL);
    }
    if (flags & known) != 0 {
        return Err(WASI_EOPNOTSUPP);
    }
    Ok(())
}

#[cfg(any(target_arch = "wasm32", test))]
pub(crate) fn resolve_fchmodat_dirfd(fd: i32) -> Result<Option<u32>, i32> {
    if fd == WASI_AT_FDCWD || fd == LINUX_AT_FDCWD || fd == abi::OS_FD_CWD {
        Ok(None)
    } else if fd == abi::OS_FD_ROOT {
        Ok(Some(abi::OS_FD_ROOT as u32))
    } else if fd < 0 {
        Err(WASI_EBADF)
    } else {
        Ok(Some(fd as u32))
    }
}

/// Classify a raw NUL-free guest path slice into `(anchor_fd, abs_prefix_cstr, relative_slice)`
/// without calling `getcwd()` or lexically collapsing `.` or `..`.
/// All-slash paths (`"/"`, `"///"`) emit `(OS_FD_ROOT, "/")` while `"/."` emits `(OS_FD_ROOT, ".")`.
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) fn split_guest_path(raw: &[u8]) -> Result<(i32, &'static [u8], &[u8]), i32> {
    if raw.is_empty() {
        return Err(WASI_ENOENT);
    }
    if raw[0] == b'/' {
        let mut idx = 0;
        while idx < raw.len() && raw[idx] == b'/' {
            idx += 1;
        }
        let rel: &[u8] = if idx == raw.len() { b"/" } else { &raw[idx..] };
        Ok((abi::OS_FD_ROOT, b"/\0", rel))
    } else {
        Ok((abi::OS_FD_CWD, b".\0", raw))
    }
}

#[cfg(target_arch = "wasm32")]
pub(crate) mod host {
    #[link(wasm_import_module = "os")]
    unsafe extern "C" {
        #[link_name = "chdir"]
        pub fn host_chdir(path_ptr: *const u8, path_len: usize) -> i32;
        #[link_name = "fchdir"]
        pub fn host_fchdir(fd: i32) -> i32;
        #[link_name = "getcwd"]
        pub fn host_getcwd(buf_ptr: *mut u8, buf_cap: usize) -> i32;
        #[link_name = "chroot"]
        pub fn host_chroot(path_ptr: *const u8, path_len: usize) -> i32;
        #[link_name = "mount"]
        pub fn host_mount(
            source_ptr: *const u8,
            source_len: usize,
            target_ptr: *const u8,
            target_len: usize,
            fstype_ptr: *const u8,
            fstype_len: usize,
            flags: u64,
            data_ptr: *const u8,
            data_len: usize,
        ) -> i32;
        #[link_name = "umount2"]
        pub fn host_umount2(target_ptr: *const u8, target_len: usize, flags: u32) -> i32;
        #[link_name = "statfs"]
        pub fn host_statfs(
            path_ptr: *const u8,
            path_len: usize,
            out_ptr: *mut abi::RawStatFs,
        ) -> i32;
        #[link_name = "fstatfs"]
        pub fn host_fstatfs(fd: i32, out_ptr: *mut abi::RawStatFs) -> i32;
        #[link_name = "unshare"]
        pub fn host_unshare(flags: u32) -> i32;
        #[link_name = "setns"]
        pub fn host_setns(fd: i32, nstype: u32) -> i32;
        #[link_name = "execve"]
        pub fn host_execve(req_ptr: *const u8, req_len: usize) -> i32;
    }
}

#[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
mod c_abi {
    use super::host::*;
    use super::*;
    use core::ffi::c_void;

    /// Exact `wasm32-wasi` `<sys/statvfs.h>` binary layout (96 bytes, 8-byte aligned).
    #[repr(C)]
    pub struct CStatVfs {
        pub f_bsize: u32,
        pub f_frsize: u32,
        pub f_blocks: u64,
        pub f_bfree: u64,
        pub f_bavail: u64,
        pub f_files: u64,
        pub f_ffree: u64,
        pub f_favail: u64,
        pub f_fsid: u32,
        pub _pad: u32,
        pub f_flag: u32,
        pub f_namemax: u32,
        pub __reserved: [i32; 6],
    }

    const _: [(); 96] = [(); core::mem::size_of::<CStatVfs>()];

    unsafe extern "C" {
        fn __errno_location() -> *mut i32;
        fn malloc(size: usize) -> *mut c_void;
        fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void;
        fn free(ptr: *mut c_void);

        fn __wasilibc_nocwd_openat_nomode(dirfd: i32, path: *const u8, oflag: i32) -> i32;
        fn __wasilibc_nocwd_faccessat(dirfd: i32, path: *const u8, amode: i32, flags: i32) -> i32;
        fn __wasilibc_nocwd_readlinkat(
            dirfd: i32,
            path: *const u8,
            buf: *mut u8,
            bufsize: usize,
        ) -> isize;
        fn __wasilibc_nocwd_fstatat(
            dirfd: i32,
            path: *const u8,
            buf: *mut c_void,
            flags: i32,
        ) -> i32;
        fn __wasilibc_nocwd_utimensat(
            dirfd: i32,
            path: *const u8,
            times: *const CTimespec,
            flags: i32,
        ) -> i32;
        fn __wasilibc_nocwd___wasilibc_unlinkat(dirfd: i32, path: *const u8) -> i32;
        fn __wasilibc_nocwd___wasilibc_rmdirat(dirfd: i32, path: *const u8) -> i32;
        fn __wasilibc_nocwd_mkdirat_nomode(dirfd: i32, path: *const u8) -> i32;
        fn __wasilibc_nocwd_opendirat(dirfd: i32, path: *const u8) -> *mut c_void;
        fn __wasilibc_nocwd_scandirat(
            dirfd: i32,
            path: *const u8,
            namelist: *mut c_void,
            filter: *const c_void,
            compar: *const c_void,
        ) -> i32;
        fn __wasilibc_nocwd_symlinkat(target: *const u8, dirfd: i32, path: *const u8) -> i32;
        fn __wasilibc_nocwd_linkat(
            olddirfd: i32,
            oldpath: *const u8,
            newdirfd: i32,
            newpath: *const u8,
            flags: i32,
        ) -> i32;
        fn __wasilibc_nocwd_renameat(
            olddirfd: i32,
            oldpath: *const u8,
            newdirfd: i32,
            newpath: *const u8,
        ) -> i32;
    }

    #[inline]
    unsafe fn set_errno(err: i32) {
        // SAFETY: __errno_location returns the valid errno slot in WASI libc.
        unsafe { *__errno_location() = err };
    }

    #[inline]
    unsafe fn get_errno() -> i32 {
        // SAFETY: __errno_location returns the valid errno slot in WASI libc.
        unsafe { *__errno_location() }
    }

    #[inline]
    unsafe fn c_strlen(ptr: *const u8) -> usize {
        let mut len = 0usize;
        // SAFETY: caller guarantees ptr is a non-null NUL-terminated C string.
        while unsafe { *ptr.add(len) } != 0 {
            len += 1;
        }
        len
    }

    #[inline]
    unsafe fn c_result(rc: i32) -> i32 {
        if rc < 0 {
            // SAFETY: sets guest errno from negative WASI errno returned by host.
            unsafe { set_errno(-rc) };
            -1
        } else {
            rc
        }
    }

    /// Zero-allocation resolution of `path` to `(anchor_fd, nul_terminated_rel_ptr)`.
    #[inline]
    unsafe fn direct_relpath(path: *const u8) -> Option<(i32, *const u8)> {
        if path.is_null() {
            // SAFETY: valid guest errno location.
            unsafe { set_errno(WASI_EFAULT) };
            return None;
        }
        // SAFETY: path is non-null C string.
        let first = unsafe { *path };
        if first == 0 {
            unsafe { set_errno(WASI_ENOENT) };
            return None;
        }
        if first == b'/' {
            let mut idx = 0usize;
            // SAFETY: scanning until non-slash or NUL terminator.
            while unsafe { *path.add(idx) } == b'/' {
                idx += 1;
            }
            let rel = if unsafe { *path.add(idx) } == 0 {
                c"/".as_ptr().cast()
            } else {
                unsafe { path.add(idx) }
            };
            Some((abi::OS_FD_ROOT, rel))
        } else {
            Some((abi::OS_FD_CWD, path))
        }
    }

    fn fill_statvfs(raw: &abi::RawStatFs) -> CStatVfs {
        let frsize = if raw.f_frsize == 0 {
            raw.f_bsize
        } else {
            raw.f_frsize
        };
        CStatVfs {
            f_bsize: raw.f_bsize as u32,
            f_frsize: frsize as u32,
            f_blocks: raw.f_blocks,
            f_bfree: raw.f_bfree,
            f_bavail: raw.f_bavail,
            f_files: raw.f_files,
            f_ffree: raw.f_ffree,
            f_favail: raw.f_ffree,
            f_fsid: 0,
            _pad: 0,
            f_flag: raw.f_flags as u32,
            f_namemax: raw.f_namelen as u32,
            __reserved: [0; 6],
        }
    }

    /// Force the linker to pull this object unit out of `libos_posix.rlib` before `libstd`
    /// scans `libc.a`, ensuring strong symbol overrides take precedence over `libc.a`.
    pub(crate) fn ensure_linked() {
        std::hint::black_box(chdir as *const ());
        std::hint::black_box(getcwd as *const ());
        std::hint::black_box(chmod as *const ());
        std::hint::black_box(statvfs as *const ());
        std::hint::black_box(__wasilibc_find_relpath_alloc as *const ());
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn __wasilibc_register_preopened_fd(_fd: i32, _prefix: *const u8) -> i32 {
        0
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn __wasilibc_populate_preopens() {}

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn __wasilibc_reset_preopens() {}

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn __wasilibc_find_abspath(
        abspath: *const u8,
        abs_prefix: *mut *const u8,
        relative_path: *mut *const u8,
    ) -> i32 {
        if abspath.is_null() {
            // SAFETY: valid guest errno location.
            unsafe { set_errno(WASI_EFAULT) };
            return -1;
        }
        // SAFETY: abspath is a NUL-terminated C string from libc.
        let len = unsafe { c_strlen(abspath) };
        // SAFETY: abspath points to len valid bytes before NUL.
        let raw = unsafe { core::slice::from_raw_parts(abspath, len) };
        if raw.first().copied() != Some(b'/') {
            // SAFETY: valid guest errno location.
            unsafe { set_errno(WASI_ENOENT) };
            return -1;
        }
        let mut idx = 0usize;
        while idx < raw.len() && raw[idx] == b'/' {
            idx += 1;
        }
        if !abs_prefix.is_null() {
            // SAFETY: abs_prefix is writable when non-null.
            unsafe { *abs_prefix = c"/".as_ptr().cast() };
        }
        if !relative_path.is_null() {
            // SAFETY: relative_path is writable; returns static "/" or interior pointer in abspath.
            unsafe {
                *relative_path = if idx == raw.len() {
                    c"/".as_ptr().cast()
                } else {
                    abspath.add(idx)
                };
            }
        }
        abi::OS_FD_ROOT
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn __wasilibc_find_relpath_alloc(
        path: *const u8,
        abs_prefix: *mut *const u8,
        relative_path: *mut *mut u8,
        relative_path_len: *mut usize,
        can_realloc: i32,
    ) -> i32 {
        if path.is_null() || relative_path.is_null() || relative_path_len.is_null() {
            // SAFETY: valid guest errno location.
            unsafe { set_errno(WASI_EFAULT) };
            return -1;
        }
        // SAFETY: path is a NUL-terminated C string.
        let len = unsafe { c_strlen(path) };
        // SAFETY: path points to len valid bytes before NUL.
        let raw = unsafe { core::slice::from_raw_parts(path, len) };
        let (fd, prefix, rel) = match split_guest_path(raw) {
            Ok(parts) => parts,
            Err(err) => {
                // SAFETY: valid guest errno location.
                unsafe { set_errno(err) };
                return -1;
            }
        };
        let need = rel.len() + 1;
        // SAFETY: caller provided valid pointers for relative_path and relative_path_len.
        let mut buf = unsafe { *relative_path };
        let cap = unsafe { *relative_path_len };
        if cap < need || buf.is_null() {
            if can_realloc == 0 {
                // SAFETY: valid guest errno location.
                unsafe { set_errno(WASI_ERANGE) };
                return -1;
            }
            // SAFETY: *relative_path is NULL or a malloc-managed buffer per wasi-libc contract.
            let grown = unsafe { realloc(buf.cast(), need) }.cast::<u8>();
            if grown.is_null() {
                // SAFETY: valid guest errno location.
                unsafe { set_errno(WASI_ENOMEM) };
                return -1;
            }
            // SAFETY: updating caller's buffer pointer and capacity.
            unsafe {
                *relative_path = grown;
                *relative_path_len = need;
            }
            buf = grown;
        }
        // SAFETY: buf has at least `need` writable bytes (`rel.len() + 1`).
        unsafe {
            core::ptr::copy_nonoverlapping(rel.as_ptr(), buf, rel.len());
            *buf.add(rel.len()) = 0;
            if !abs_prefix.is_null() {
                *abs_prefix = prefix.as_ptr();
            }
        }
        fd
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn __wasilibc_find_relpath(
        path: *const u8,
        abs_prefix: *mut *const u8,
        relative_path: *mut *mut u8,
        relative_path_len: usize,
    ) -> i32 {
        let mut len = relative_path_len;
        // SAFETY: delegates with fixed capacity (`can_realloc = 0`).
        unsafe { __wasilibc_find_relpath_alloc(path, abs_prefix, relative_path, &mut len, 0) }
    }

    // Complete replacement of `posix.c.obj` path trampolines so `statvfs` and `fstatvfs`
    // override `libc.a` cleanly without duplicate-symbol conflicts.

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn __wasilibc_open_nomode(path: *const u8, oflag: i32) -> i32 {
        // SAFETY: resolves path without collapsing `.` / `..` and delegates to wasi-libc nocwd.
        let Some((fd, rel)) = (unsafe { direct_relpath(path) }) else {
            return -1;
        };
        unsafe { __wasilibc_nocwd_openat_nomode(fd, rel, oflag) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn open(path: *const core::ffi::c_char, oflag: i32, _args: ...) -> i32 {
        // SAFETY: WASI preview1 openat ignores mode just as upstream `posix.c` `open` does.
        unsafe { __wasilibc_open_nomode(path.cast(), oflag) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn __wasilibc_access(path: *const u8, amode: i32, flags: i32) -> i32 {
        let Some((fd, rel)) = (unsafe { direct_relpath(path) }) else {
            return -1;
        };
        unsafe { __wasilibc_nocwd_faccessat(fd, rel, amode, flags) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn access(path: *const u8, amode: i32) -> i32 {
        unsafe { __wasilibc_access(path, amode, 0) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn readlink(path: *const u8, buf: *mut u8, bufsize: usize) -> isize {
        let Some((fd, rel)) = (unsafe { direct_relpath(path) }) else {
            return -1;
        };
        unsafe { __wasilibc_nocwd_readlinkat(fd, rel, buf, bufsize) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn __wasilibc_stat(path: *const u8, buf: *mut c_void, flags: i32) -> i32 {
        let Some((fd, rel)) = (unsafe { direct_relpath(path) }) else {
            return -1;
        };
        unsafe { __wasilibc_nocwd_fstatat(fd, rel, buf, flags) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn stat(path: *const u8, buf: *mut c_void) -> i32 {
        unsafe { __wasilibc_stat(path, buf, 0) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn lstat(path: *const u8, buf: *mut c_void) -> i32 {
        // WASI `AT_SYMLINK_NOFOLLOW` = 1.
        unsafe { __wasilibc_stat(path, buf, 1) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn __wasilibc_utimens(
        path: *const u8,
        times: *const CTimespec,
        flags: i32,
    ) -> i32 {
        let Some((fd, rel)) = (unsafe { direct_relpath(path) }) else {
            return -1;
        };
        unsafe { __wasilibc_nocwd_utimensat(fd, rel, times, flags) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn utime(path: *const u8, times: *const [i64; 2]) -> i32 {
        let Some((fd, rel)) = (unsafe { direct_relpath(path) }) else {
            return -1;
        };
        if times.is_null() {
            return unsafe { __wasilibc_nocwd_utimensat(fd, rel, core::ptr::null(), 0) };
        }
        // SAFETY: non-null `utimbuf` holds `[actime, modtime]` as two `time_t` (`i64`).
        let [actime, modtime] = unsafe { *times };
        let ts = [
            CTimespec {
                tv_sec: actime,
                tv_nsec: 0,
            },
            CTimespec {
                tv_sec: modtime,
                tv_nsec: 0,
            },
        ];
        unsafe { __wasilibc_nocwd_utimensat(fd, rel, ts.as_ptr(), 0) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn utimes(path: *const u8, times: *const [CTimeval; 2]) -> i32 {
        let Some((fd, rel)) = (unsafe { direct_relpath(path) }) else {
            return -1;
        };
        if times.is_null() {
            return unsafe { __wasilibc_nocwd_utimensat(fd, rel, core::ptr::null(), 0) };
        }
        // SAFETY: non-null `timeval[2]` array.
        let raw_times = unsafe { *times };
        let ts = match convert_timevals(raw_times) {
            Ok(ts) => ts,
            Err(err) => {
                unsafe { set_errno(err) };
                return -1;
            }
        };
        unsafe { __wasilibc_nocwd_utimensat(fd, rel, ts.as_ptr(), 0) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn unlink(path: *const u8) -> i32 {
        let Some((fd, rel)) = (unsafe { direct_relpath(path) }) else {
            return -1;
        };
        unsafe { __wasilibc_nocwd___wasilibc_unlinkat(fd, rel) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn rmdir(path: *const u8) -> i32 {
        let Some((fd, rel)) = (unsafe { direct_relpath(path) }) else {
            return -1;
        };
        unsafe { __wasilibc_nocwd___wasilibc_rmdirat(fd, rel) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn remove(path: *const u8) -> i32 {
        let Some((fd, rel)) = (unsafe { direct_relpath(path) }) else {
            return -1;
        };
        // SAFETY: attempts file unlink first, falling back to rmdir on directory errors.
        let mut rc = unsafe { __wasilibc_nocwd___wasilibc_unlinkat(fd, rel) };
        if rc != 0 {
            let err = unsafe { get_errno() };
            if err == WASI_EISDIR || err == WASI_EPERM || err == WASI_EACCES {
                rc = unsafe { __wasilibc_nocwd___wasilibc_rmdirat(fd, rel) };
                if rc != 0 && unsafe { get_errno() } == WASI_ENOTDIR {
                    unsafe { set_errno(WASI_ENOENT) };
                }
            }
        }
        rc
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn mkdir(path: *const u8, _mode: u32) -> i32 {
        let Some((fd, rel)) = (unsafe { direct_relpath(path) }) else {
            return -1;
        };
        unsafe { __wasilibc_nocwd_mkdirat_nomode(fd, rel) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn opendir(path: *const u8) -> *mut c_void {
        let Some((fd, rel)) = (unsafe { direct_relpath(path) }) else {
            return core::ptr::null_mut();
        };
        unsafe { __wasilibc_nocwd_opendirat(fd, rel) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn scandir(
        path: *const u8,
        namelist: *mut c_void,
        filter: *const c_void,
        compar: *const c_void,
    ) -> i32 {
        let Some((fd, rel)) = (unsafe { direct_relpath(path) }) else {
            return -1;
        };
        unsafe { __wasilibc_nocwd_scandirat(fd, rel, namelist, filter, compar) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn symlink(target: *const u8, linkpath: *const u8) -> i32 {
        if target.is_null() {
            unsafe { set_errno(WASI_EFAULT) };
            return -1;
        }
        let Some((fd, rel)) = (unsafe { direct_relpath(linkpath) }) else {
            return -1;
        };
        unsafe { __wasilibc_nocwd_symlinkat(target, fd, rel) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn __wasilibc_link(
        oldpath: *const u8,
        newpath: *const u8,
        flags: i32,
    ) -> i32 {
        let Some((old_fd, old_rel)) = (unsafe { direct_relpath(oldpath) }) else {
            return -1;
        };
        let Some((new_fd, new_rel)) = (unsafe { direct_relpath(newpath) }) else {
            return -1;
        };
        unsafe { __wasilibc_nocwd_linkat(old_fd, old_rel, new_fd, new_rel, flags) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn link(oldpath: *const u8, newpath: *const u8) -> i32 {
        unsafe { __wasilibc_link(oldpath, newpath, 0) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn __wasilibc_link_oldat(
        olddirfd: i32,
        oldpath: *const u8,
        newpath: *const u8,
        flags: i32,
    ) -> i32 {
        if oldpath.is_null() {
            unsafe { set_errno(WASI_EFAULT) };
            return -1;
        }
        let Some((new_fd, new_rel)) = (unsafe { direct_relpath(newpath) }) else {
            return -1;
        };
        unsafe { __wasilibc_nocwd_linkat(olddirfd, oldpath, new_fd, new_rel, flags) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn __wasilibc_link_newat(
        oldpath: *const u8,
        newdirfd: i32,
        newpath: *const u8,
        flags: i32,
    ) -> i32 {
        if newpath.is_null() {
            unsafe { set_errno(WASI_EFAULT) };
            return -1;
        }
        let Some((old_fd, old_rel)) = (unsafe { direct_relpath(oldpath) }) else {
            return -1;
        };
        unsafe { __wasilibc_nocwd_linkat(old_fd, old_rel, newdirfd, newpath, flags) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn rename(oldpath: *const u8, newpath: *const u8) -> i32 {
        let Some((old_fd, old_rel)) = (unsafe { direct_relpath(oldpath) }) else {
            return -1;
        };
        let Some((new_fd, new_rel)) = (unsafe { direct_relpath(newpath) }) else {
            return -1;
        };
        unsafe { __wasilibc_nocwd_renameat(old_fd, old_rel, new_fd, new_rel) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn __wasilibc_rename_oldat(
        olddirfd: i32,
        oldpath: *const u8,
        newpath: *const u8,
    ) -> i32 {
        if oldpath.is_null() {
            unsafe { set_errno(WASI_EFAULT) };
            return -1;
        }
        let Some((new_fd, new_rel)) = (unsafe { direct_relpath(newpath) }) else {
            return -1;
        };
        unsafe { __wasilibc_nocwd_renameat(olddirfd, oldpath, new_fd, new_rel) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn __wasilibc_rename_newat(
        oldpath: *const u8,
        newdirfd: i32,
        newpath: *const u8,
    ) -> i32 {
        if newpath.is_null() {
            unsafe { set_errno(WASI_EFAULT) };
            return -1;
        }
        let Some((old_fd, old_rel)) = (unsafe { direct_relpath(oldpath) }) else {
            return -1;
        };
        unsafe { __wasilibc_nocwd_renameat(old_fd, old_rel, newdirfd, newpath) }
    }

    #[inline]
    unsafe fn io_result_to_c(res: std::io::Result<()>) -> i32 {
        match res {
            Ok(()) => 0,
            Err(err) => {
                let code = crate::errno_of(&err).map_or(WASI_EIO, abi_errno_to_wasi);
                // SAFETY: valid guest errno location.
                unsafe { set_errno(code) };
                -1
            }
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn chmod(path: *const u8, mode: u32) -> i32 {
        if path.is_null() {
            // SAFETY: valid guest errno location.
            unsafe { set_errno(WASI_EFAULT) };
            return -1;
        }
        // SAFETY: path is a NUL-terminated C string.
        let len = unsafe { c_strlen(path) };
        if len == 0 {
            unsafe { set_errno(WASI_ENOENT) };
            return -1;
        }
        let raw = unsafe { core::slice::from_raw_parts(path, len) };
        let Ok(text) = core::str::from_utf8(raw) else {
            unsafe { set_errno(WASI_EINVAL) };
            return -1;
        };
        unsafe { io_result_to_c(crate::chmod(std::path::Path::new(text), mode)) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn fchmod(fd: i32, mode: u32) -> i32 {
        if fd < 0 {
            // SAFETY: valid guest errno location.
            unsafe { set_errno(WASI_EBADF) };
            return -1;
        }
        unsafe { io_result_to_c(crate::fchmod(fd as u32, mode)) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn fchmodat(fd: i32, path: *const u8, mode: u32, flags: i32) -> i32 {
        if path.is_null() {
            // SAFETY: valid guest errno location.
            unsafe { set_errno(WASI_EFAULT) };
            return -1;
        }
        if let Err(err) = validate_fchmodat_flags(flags) {
            unsafe { set_errno(err) };
            return -1;
        }
        // SAFETY: path is a NUL-terminated C string.
        let len = unsafe { c_strlen(path) };
        if len == 0 {
            unsafe { set_errno(WASI_ENOENT) };
            return -1;
        }
        let raw = unsafe { core::slice::from_raw_parts(path, len) };
        let Ok(text) = core::str::from_utf8(raw) else {
            unsafe { set_errno(WASI_EINVAL) };
            return -1;
        };
        let dirfd = match resolve_fchmodat_dirfd(fd) {
            Ok(dirfd) => dirfd,
            Err(err) => {
                unsafe { set_errno(err) };
                return -1;
            }
        };
        unsafe { io_result_to_c(crate::fchmodat(dirfd, std::path::Path::new(text), mode)) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn chdir(path: *const u8) -> i32 {
        if path.is_null() {
            // SAFETY: valid guest errno location.
            unsafe { set_errno(WASI_EFAULT) };
            return -1;
        }
        // SAFETY: path is NUL-terminated.
        let len = unsafe { c_strlen(path) };
        // SAFETY: path is readable for len bytes.
        unsafe { c_result(host_chdir(path, len)) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn fchdir(fd: i32) -> i32 {
        // SAFETY: scalar host import.
        unsafe { c_result(host_fchdir(fd)) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn getcwd(buf: *mut u8, size: usize) -> *mut u8 {
        if !buf.is_null() {
            if size == 0 {
                // SAFETY: valid guest errno location.
                unsafe { set_errno(WASI_EINVAL) };
                return core::ptr::null_mut();
            }
            // SAFETY: caller provided writable buffer of `size` bytes.
            let rc = unsafe { host_getcwd(buf, size) };
            if rc < 0 {
                // SAFETY: valid guest errno location.
                unsafe { set_errno(-rc) };
                return core::ptr::null_mut();
            }
            return buf;
        }

        if size != 0 {
            // SAFETY: allocate requested fixed size via C malloc so caller may free().
            let alloc = unsafe { malloc(size) }.cast::<u8>();
            if alloc.is_null() {
                // SAFETY: valid guest errno location.
                unsafe { set_errno(WASI_ENOMEM) };
                return core::ptr::null_mut();
            }
            // SAFETY: alloc has `size` writable bytes.
            let rc = unsafe { host_getcwd(alloc, size) };
            if rc < 0 {
                // SAFETY: alloc came from malloc above.
                unsafe {
                    free(alloc.cast());
                    set_errno(-rc);
                }
                return core::ptr::null_mut();
            }
            return alloc;
        }

        let mut cap = 256usize;
        // SAFETY: initial allocation via C malloc.
        let mut alloc = unsafe { malloc(cap) }.cast::<u8>();
        if alloc.is_null() {
            // SAFETY: valid guest errno location.
            unsafe { set_errno(WASI_ENOMEM) };
            return core::ptr::null_mut();
        }
        loop {
            // SAFETY: alloc has `cap` writable bytes.
            let rc = unsafe { host_getcwd(alloc, cap) };
            if rc >= 0 {
                let used = (rc as usize).max(1);
                // SAFETY: shrink-to-fit with C realloc; retain `alloc` if shrink fails.
                let shrunk = unsafe { realloc(alloc.cast(), used) }.cast::<u8>();
                return if shrunk.is_null() { alloc } else { shrunk };
            }
            if rc != -WASI_ERANGE || cap >= 65536 {
                // SAFETY: alloc is owned and freed on error.
                unsafe {
                    free(alloc.cast());
                    set_errno(-rc);
                }
                return core::ptr::null_mut();
            }
            cap *= 2;
            // SAFETY: grow allocation via C realloc.
            let grown = unsafe { realloc(alloc.cast(), cap) }.cast::<u8>();
            if grown.is_null() {
                // SAFETY: original alloc remains valid when realloc returns NULL.
                unsafe {
                    free(alloc.cast());
                    set_errno(WASI_ENOMEM);
                }
                return core::ptr::null_mut();
            }
            alloc = grown;
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn chroot(path: *const u8) -> i32 {
        if path.is_null() {
            // SAFETY: valid guest errno location.
            unsafe { set_errno(WASI_EFAULT) };
            return -1;
        }
        // SAFETY: path is NUL-terminated.
        let len = unsafe { c_strlen(path) };
        // SAFETY: path is readable for len bytes.
        unsafe { c_result(host_chroot(path, len)) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn mount(
        source: *const u8,
        target: *const u8,
        filesystemtype: *const u8,
        mountflags: usize,
        data: *const c_void,
    ) -> i32 {
        if target.is_null() {
            // SAFETY: valid guest errno location.
            unsafe { set_errno(WASI_EFAULT) };
            return -1;
        }
        // SAFETY: non-null C string pointers are NUL-terminated.
        let src_len = if source.is_null() {
            0
        } else {
            unsafe { c_strlen(source) }
        };
        let tgt_len = unsafe { c_strlen(target) };
        let type_len = if filesystemtype.is_null() {
            0
        } else {
            unsafe { c_strlen(filesystemtype) }
        };
        let data_ptr = data.cast::<u8>();
        let data_len = if data_ptr.is_null() {
            0
        } else {
            unsafe { c_strlen(data_ptr) }
        };
        // SAFETY: buffers are valid for their respective lengths.
        unsafe {
            c_result(host_mount(
                source,
                src_len,
                target,
                tgt_len,
                filesystemtype,
                type_len,
                mountflags as u64,
                data_ptr,
                data_len,
            ))
        }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn umount2(target: *const u8, flags: u32) -> i32 {
        if target.is_null() {
            // SAFETY: valid guest errno location.
            unsafe { set_errno(WASI_EFAULT) };
            return -1;
        }
        // SAFETY: target is NUL-terminated.
        let len = unsafe { c_strlen(target) };
        // SAFETY: target is readable for len bytes.
        unsafe { c_result(host_umount2(target, len, flags)) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn umount(target: *const u8) -> i32 {
        // SAFETY: delegates to umount2 with flags = 0.
        unsafe { umount2(target, 0) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn statfs(path: *const u8, buf: *mut abi::RawStatFs) -> i32 {
        if path.is_null() || buf.is_null() {
            // SAFETY: valid guest errno location.
            unsafe { set_errno(WASI_EFAULT) };
            return -1;
        }
        // SAFETY: path is NUL-terminated and buf is writable.
        let len = unsafe { c_strlen(path) };
        unsafe { c_result(host_statfs(path, len, buf)) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn fstatfs(fd: i32, buf: *mut abi::RawStatFs) -> i32 {
        if buf.is_null() {
            // SAFETY: valid guest errno location.
            unsafe { set_errno(WASI_EFAULT) };
            return -1;
        }
        // SAFETY: buf is writable for 80 bytes.
        unsafe { c_result(host_fstatfs(fd, buf)) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn statvfs(path: *const u8, buf: *mut CStatVfs) -> i32 {
        if path.is_null() || buf.is_null() {
            // SAFETY: valid guest errno location.
            unsafe { set_errno(WASI_EFAULT) };
            return -1;
        }
        let mut raw = abi::RawStatFs::default();
        // SAFETY: path is NUL-terminated; raw is stack-owned.
        let len = unsafe { c_strlen(path) };
        let rc = unsafe { host_statfs(path, len, &mut raw) };
        if rc < 0 {
            // SAFETY: valid guest errno location.
            unsafe { set_errno(-rc) };
            return -1;
        }
        // SAFETY: buf is non-null and writable for CStatVfs (96 bytes).
        unsafe { *buf = fill_statvfs(&raw) };
        0
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn fstatvfs(fd: i32, buf: *mut CStatVfs) -> i32 {
        if buf.is_null() {
            // SAFETY: valid guest errno location.
            unsafe { set_errno(WASI_EFAULT) };
            return -1;
        }
        let mut raw = abi::RawStatFs::default();
        // SAFETY: raw is stack-owned.
        let rc = unsafe { host_fstatfs(fd, &mut raw) };
        if rc < 0 {
            // SAFETY: valid guest errno location.
            unsafe { set_errno(-rc) };
            return -1;
        }
        // SAFETY: buf is non-null and writable for CStatVfs (96 bytes).
        unsafe { *buf = fill_statvfs(&raw) };
        0
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn unshare(flags: i32) -> i32 {
        // SAFETY: scalar host import.
        unsafe { c_result(host_unshare(flags as u32)) }
    }

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn setns(fd: i32, nstype: i32) -> i32 {
        // SAFETY: scalar host import.
        unsafe { c_result(host_setns(fd, nstype as u32)) }
    }
}

#[cfg(all(target_arch = "wasm32", target_os = "wasi"))]
pub(crate) fn ensure_linked() {
    c_abi::ensure_linked();
}

#[cfg(not(all(target_arch = "wasm32", target_os = "wasi")))]
pub(crate) fn ensure_linked() {}
