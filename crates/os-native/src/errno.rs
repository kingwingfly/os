//! Bidirectional `abi::Errno` <-> WASI preview1 errno translation and POSIX/WASI constants.

use abi::Errno;

pub const WASI_ESUCCESS: u32 = 0;
pub const WASI_E2BIG: u32 = 1;
pub const WASI_EACCES: u32 = 2;
pub const WASI_EADDRINUSE: u32 = 3;
pub const WASI_EADDRNOTAVAIL: u32 = 4;
pub const WASI_EAFNOSUPPORT: u32 = 5;
pub const WASI_EAGAIN: u32 = 6;
pub const WASI_EBADF: u32 = 8;
pub const WASI_EBUSY: u32 = 10;
pub const WASI_ECANCELED: u32 = 11;
pub const WASI_ECHILD: u32 = 12;
pub const WASI_ECONNABORTED: u32 = 13;
pub const WASI_ECONNREFUSED: u32 = 14;
pub const WASI_ECONNRESET: u32 = 15;
pub const WASI_EDEADLK: u32 = 16;
pub const WASI_EDQUOT: u32 = 19;
pub const WASI_EEXIST: u32 = 20;
pub const WASI_EFAULT: u32 = 21;
pub const WASI_EFBIG: u32 = 22;
pub const WASI_EINTR: u32 = 27;
pub const WASI_EINVAL: u32 = 28;
pub const WASI_EIO: u32 = 29;
pub const WASI_EISCONN: u32 = 30;
pub const WASI_EISDIR: u32 = 31;
pub const WASI_ELOOP: u32 = 32;
pub const WASI_EMFILE: u32 = 33;
pub const WASI_EMLINK: u32 = 34;
pub const WASI_EMSGSIZE: u32 = 35;
pub const WASI_ENAMETOOLONG: u32 = 37;
pub const WASI_ENOBUFS: u32 = 42;
pub const WASI_ENODEV: u32 = 43;
pub const WASI_ENOENT: u32 = 44;
pub const WASI_ENOEXEC: u32 = 45;
pub const WASI_ENOLCK: u32 = 46;
pub const WASI_ENOMEM: u32 = 48;
pub const WASI_ENOSPC: u32 = 51;
pub const WASI_ENOSYS: u32 = 52;
pub const WASI_ENOTCONN: u32 = 53;
pub const WASI_ENOTDIR: u32 = 54;
pub const WASI_ENOTEMPTY: u32 = 55;
pub const WASI_ENOTSOCK: u32 = 57;
pub const WASI_EOPNOTSUPP: u32 = 58;
pub const WASI_ENOTTY: u32 = 59;
pub const WASI_ENXIO: u32 = 60;
pub const WASI_EPERM: u32 = 63;
pub const WASI_EPIPE: u32 = 64;
pub const WASI_EPROTONOSUPPORT: u32 = 66;
pub const WASI_EPROTOTYPE: u32 = 67;
pub const WASI_ERANGE: u32 = 68;
pub const WASI_EROFS: u32 = 69;
pub const WASI_ESPIPE: u32 = 70;
pub const WASI_ESRCH: u32 = 71;
pub const WASI_ESTALE: u32 = 72;
pub const WASI_ETIMEDOUT: u32 = 73;
pub const WASI_ETXTBSY: u32 = 74;
pub const WASI_EXDEV: u32 = 75;
pub const WASI_ETOOMANYREFS: u32 = 109;
pub const WASI_ENODATA: u32 = 217;
pub const WASI_ENOTBLK: u32 = 218;

// Linux open(2) flags.
pub const O_RDONLY: u32 = 0;
pub const O_WRONLY: u32 = 1;
pub const O_RDWR: u32 = 2;
pub const O_CREAT: u32 = 0o100;
pub const O_EXCL: u32 = 0o200;
pub const O_NOCTTY: u32 = 0o400;
pub const O_TRUNC: u32 = 0o1000;
pub const O_APPEND: u32 = 0o2000;
pub const O_NONBLOCK: u32 = 0o4000;
pub const O_DIRECTORY: u32 = 0o200_000;
pub const O_NOFOLLOW: u32 = 0o400_000;
pub const O_CLOEXEC: u32 = 0o2_000_000;
pub const O_PATH: u32 = 0o10_000_000;

// WASI preview1 constants.
pub const WASI_OFLAG_CREAT: u32 = 1;
pub const WASI_OFLAG_DIRECTORY: u32 = 2;
pub const WASI_OFLAG_EXCL: u32 = 4;
pub const WASI_OFLAG_TRUNC: u32 = 8;

pub const WASI_FDFLAG_APPEND: u16 = 1;
pub const WASI_FDFLAG_NONBLOCK: u16 = 4;

pub const WASI_LOOKUP_SYMLINK_FOLLOW: u32 = 1;

pub const WASI_RIGHT_READ: u64 = 1 << 1;
pub const WASI_RIGHT_SEEK: u64 = 1 << 2;
pub const WASI_RIGHT_TELL: u64 = 1 << 5;
pub const WASI_RIGHT_WRITE: u64 = 1 << 6;
pub const WASI_ALL_RIGHTS: u64 = (1 << 30) - 1;

pub const WASI_FILETYPE_UNKNOWN: u8 = 0;
pub const WASI_FILETYPE_CHARACTER_DEVICE: u8 = 2;
pub const WASI_FILETYPE_DIRECTORY: u8 = 3;
pub const WASI_FILETYPE_REGULAR_FILE: u8 = 4;
pub const WASI_FILETYPE_SOCKET_DGRAM: u8 = 5;
pub const WASI_FILETYPE_SOCKET_STREAM: u8 = 6;
pub const WASI_FILETYPE_SYMBOLIC_LINK: u8 = 7;

pub const FD_MAX: u32 = 1024;

pub fn abi_to_wasi(errno: Errno) -> u32 {
    use Errno::*;
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
        ENOTBLK => WASI_ENOTBLK,
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
        ENODATA => WASI_ENODATA,
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
        EADDRINUSE => WASI_EADDRINUSE,
        EADDRNOTAVAIL => WASI_EADDRNOTAVAIL,
        EAFNOSUPPORT => WASI_EAFNOSUPPORT,
        ECONNABORTED => WASI_ECONNABORTED,
        ECONNREFUSED => WASI_ECONNREFUSED,
        ECONNRESET => WASI_ECONNRESET,
        EISCONN => WASI_EISCONN,
        EMSGSIZE => WASI_EMSGSIZE,
        ENOBUFS => WASI_ENOBUFS,
        ENOTSOCK => WASI_ENOTSOCK,
        EPROTOTYPE => WASI_EPROTOTYPE,
        ETOOMANYREFS => WASI_ETOOMANYREFS,
    }
}

pub fn abi_to_neg_wasi(errno: Errno) -> i32 {
    -(abi_to_wasi(errno) as i32)
}

pub fn wasi_filetype_from_mode(mode: u32) -> u8 {
    match mode & abi::S_IFMT {
        abi::S_IFDIR => WASI_FILETYPE_DIRECTORY,
        abi::S_IFREG => WASI_FILETYPE_REGULAR_FILE,
        abi::S_IFLNK => WASI_FILETYPE_SYMBOLIC_LINK,
        abi::S_IFCHR => WASI_FILETYPE_CHARACTER_DEVICE,
        abi::S_IFSOCK => WASI_FILETYPE_SOCKET_STREAM,
        _ => WASI_FILETYPE_UNKNOWN,
    }
}

pub fn io_err_to_abi(err: &std::io::Error) -> Errno {
    if let Some(raw) = err.raw_os_error() {
        return match raw {
            libc::EPERM => Errno::EPERM,
            libc::ENOENT => Errno::ENOENT,
            libc::ESRCH => Errno::ESRCH,
            libc::EINTR => Errno::EINTR,
            libc::EIO => Errno::EIO,
            libc::ENXIO => Errno::ENXIO,
            libc::E2BIG => Errno::E2BIG,
            libc::ENOEXEC => Errno::ENOEXEC,
            libc::EBADF => Errno::EBADF,
            libc::ECHILD => Errno::ECHILD,
            libc::EAGAIN => Errno::EAGAIN,
            libc::EACCES => Errno::EACCES,
            libc::EBUSY => Errno::EBUSY,
            libc::EEXIST => Errno::EEXIST,
            libc::EXDEV => Errno::EXDEV,
            libc::ENODEV => Errno::ENODEV,
            libc::ENOTDIR => Errno::ENOTDIR,
            libc::EISDIR => Errno::EISDIR,
            libc::EINVAL => Errno::EINVAL,
            libc::EMFILE => Errno::EMFILE,
            libc::ENOTTY => Errno::ENOTTY,
            libc::ETXTBSY => Errno::ETXTBSY,
            libc::EFBIG => Errno::EFBIG,
            libc::ENOSPC => Errno::ENOSPC,
            libc::EROFS => Errno::EROFS,
            libc::EMLINK => Errno::EMLINK,
            libc::EPIPE => Errno::EPIPE,
            libc::ERANGE => Errno::ERANGE,
            libc::ENAMETOOLONG => Errno::ENAMETOOLONG,
            libc::ENOSYS => Errno::ENOSYS,
            libc::ENOTEMPTY => Errno::ENOTEMPTY,
            libc::ELOOP => Errno::ELOOP,
            libc::EOPNOTSUPP => Errno::EOPNOTSUPP,
            libc::ESTALE => Errno::ESTALE,
            libc::ETIMEDOUT => Errno::ETIMEDOUT,
            libc::EDQUOT => Errno::EDQUOT,
            libc::ENOTCONN => Errno::ENOTCONN,
            libc::ECONNREFUSED => Errno::ECONNREFUSED,
            libc::ECONNRESET => Errno::ECONNRESET,
            _ => Errno::EIO,
        };
    }
    use std::io::ErrorKind::*;
    match err.kind() {
        NotFound => Errno::ENOENT,
        PermissionDenied => Errno::EACCES,
        AlreadyExists => Errno::EEXIST,
        WouldBlock => Errno::EAGAIN,
        InvalidInput => Errno::EINVAL,
        BrokenPipe => Errno::EPIPE,
        Interrupted => Errno::EINTR,
        TimedOut => Errno::ETIMEDOUT,
        Unsupported => Errno::EOPNOTSUPP,
        _ => Errno::EIO,
    }
}
