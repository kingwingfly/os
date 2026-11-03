//! The system-call interface (owner's design, 2026-10-29): the page is user space, and what it
//! asks of the kernel (the Worker and its Durable Object) are system calls, as Linux's are. This
//! is what each call takes and gives back, and how it fails: an errno, as Linux names it, with
//! glibc's words for it, which user space prints as coreutils do.
//!
//! The calls go in batches (`Batch`), one request for many, as io_uring takes many: each runs
//! on its own, in order, and has its own result. A batch carries the process it runs for: its
//! umask, and whether it runs under sudo.
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Why a call failed, as Linux's errno says.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(clippy::upper_case_acronyms)]
pub enum Errno {
    EPERM,
    ENOENT,
    ESRCH,
    EIO,
    ENXIO,
    E2BIG,
    EBADF,
    EAGAIN,
    EACCES,
    EBUSY,
    EEXIST,
    EXDEV,
    ENODEV,
    ENOTDIR,
    EISDIR,
    EINVAL,
    EMFILE,
    ENOTTY,
    ETXTBSY,
    EFBIG,
    ENOSPC,
    EROFS,
    EMLINK,
    EPIPE,
    ERANGE,
    ENAMETOOLONG,
    ENOSYS,
    ENOTEMPTY,
    ELOOP,
    ENODATA,
    EOPNOTSUPP,
    ESTALE,
    ETIMEDOUT,
    ECANCELED,
}
impl Errno {
    /// What glibc's strerror says of it.
    pub fn text(self) -> &'static str {
        use Errno::*;
        match self {
            EPERM => "Operation not permitted",
            ENOENT => "No such file or directory",
            ESRCH => "No such process",
            EIO => "Input/output error",
            ENXIO => "No such device or address",
            E2BIG => "Argument list too long",
            EBADF => "Bad file descriptor",
            EAGAIN => "Resource temporarily unavailable",
            EACCES => "Permission denied",
            EBUSY => "Device or resource busy",
            EEXIST => "File exists",
            EXDEV => "Invalid cross-device link",
            ENODEV => "No such device",
            ENOTDIR => "Not a directory",
            EISDIR => "Is a directory",
            EINVAL => "Invalid argument",
            EMFILE => "Too many open files",
            ENOTTY => "Inappropriate ioctl for device",
            ETXTBSY => "Text file busy",
            EFBIG => "File too large",
            ENOSPC => "No space left on device",
            EROFS => "Read-only file system",
            EMLINK => "Too many links",
            EPIPE => "Broken pipe",
            ERANGE => "Numerical result out of range",
            ENAMETOOLONG => "File name too long",
            ENOSYS => "Function not implemented",
            ENOTEMPTY => "Directory not empty",
            ELOOP => "Too many levels of symbolic links",
            ENODATA => "No data available",
            EOPNOTSUPP => "Operation not supported",
            ESTALE => "Stale file handle",
            ETIMEDOUT => "Connection timed out",
            ECANCELED => "Operation canceled",
        }
    }
}

/// A call that failed: its errno, and, where the kernel's rule is its own (a home kept for its
/// account, a guest who may not present), what that rule says, which user space prints in place
/// of strerror's words.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Error {
    pub errno: Errno,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}
impl Error {
    pub fn new(errno: Errno) -> Self {
        Self {
            errno,
            detail: None,
        }
    }
    pub fn because(errno: Errno, detail: impl Into<String>) -> Self {
        Self {
            errno,
            detail: Some(detail.into()),
        }
    }
}
impl From<Errno> for Error {
    fn from(errno: Errno) -> Self {
        Self::new(errno)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.detail.as_deref().unwrap_or(self.errno.text()))
    }
}
impl std::error::Error for Error {}

/// The type of a node, in a mode's high bits, as Linux's `S_IFMT` says, ...
pub const S_IFMT: u32 = 0o170_000;
pub const S_IFREG: u32 = 0o100_000;
pub const S_IFDIR: u32 = 0o040_000;
pub const S_IFLNK: u32 = 0o120_000;
pub const S_IFCHR: u32 = 0o020_000;
/// ... and its special and permission bits.
pub const S_ISUID: u32 = 0o4000;
pub const S_ISGID: u32 = 0o2000;
pub const S_ISVTX: u32 = 0o1000;

/// access(2)'s modes.
pub const F_OK: u16 = 0;
pub const R_OK: u16 = 4;
pub const W_OK: u16 = 2;
pub const X_OK: u16 = 1;

/// The longest name of one part of a path, and of a whole path, in bytes.
pub const NAME_MAX: usize = 255;
pub const PATH_MAX: usize = 4096;
/// How many symbolic links one path's resolution follows before it fails with ELOOP.
pub const MAXSYMLINKS: usize = 40;

/// What stat(2) tells of a node.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Stat {
    pub ino: u64,
    /// Its type (`S_IF*`) and its special and permission bits.
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    /// Its owner's and group's names, as the account database says (what `getpwuid` would).
    pub user: String,
    pub group: String,
    pub size: u64,
    /// When its content, or a directory's entries, last changed, and when it last changed at
    /// all, in seconds since 1970, and the nanoseconds past them.
    pub mtime: u64,
    pub ctime: u64,
    #[serde(default, skip_serializing_if = "is_zero32")]
    pub mtime_nsec: u32,
    #[serde(default, skip_serializing_if = "is_zero32")]
    pub ctime_nsec: u32,
    /// When it was last read, as far as anything says: reading does not say so (the store is
    /// mounted `noatime`); making it, and utimensat, do.
    #[serde(default)]
    pub atime: u64,
    #[serde(default, skip_serializing_if = "is_zero32")]
    pub atime_nsec: u32,
    /// A symbolic link's target, as written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    /// A character device's driver.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdev: Option<String>,
    /// Whether it has an ACL beyond its mode, which ls -l marks with `+`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub acl: bool,
    /// A file still being written (an upload, a recording): what has arrived of it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writing: Option<Writing>,
}
impl Stat {
    pub fn kind(&self) -> u32 {
        self.mode & S_IFMT
    }
    pub fn is_dir(&self) -> bool {
        self.kind() == S_IFDIR
    }
    pub fn is_link(&self) -> bool {
        self.kind() == S_IFLNK
    }
    pub fn is_file(&self) -> bool {
        self.kind() == S_IFREG
    }
    pub fn is_device(&self) -> bool {
        self.kind() == S_IFCHR
    }
    /// Its permission and special bits.
    pub fn perm(&self) -> u16 {
        (self.mode & 0o7777) as u16
    }
}
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Writing {
    pub received: u64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub recording: bool,
}

/// An entry of a directory, as getdents(2) gives it, with what lstat(2) tells of it: none if
/// the directory may be read but not searched, as `ls -l` then shows `?`s.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Dirent {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stat: Option<Stat>,
}

/// Who the calling process is: its account and groups, and, signed in, whether it may sudo
/// and has lately (the timestamp sudo keeps).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Creds {
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
    pub user: String,
    pub group: String,
    pub group_names: Vec<String>,
    pub home: String,
    pub signed_in: bool,
    pub can_sudo: bool,
    pub sudo_active: bool,
}

/// setxattr(2)'s flags: fail if the attribute exists, or if it does not.
pub const XATTR_CREATE: u8 = 1;
pub const XATTR_REPLACE: u8 = 2;
/// The extended attributes that are a node's ACLs, as on Linux: their values are the ACL, as
/// JSON (`acl::Entries`).
pub const ACL_ACCESS: &str = "system.posix_acl_access";
pub const ACL_DEFAULT: &str = "system.posix_acl_default";

/// open(2)'s flags, with Linux's values. Content here is written whole, in chunks a writer may
/// send in any order (`pwrite` on the Worker, a chunk at an index), and shows once complete:
/// so an existing file is written only to be replaced (`O_TRUNC`), and appending (`O_APPEND`)
/// grows a new file from its end, a chunk at a time, readable as it grows (a recording).
pub const O_RDONLY: u32 = 0;
pub const O_WRONLY: u32 = 1;
pub const O_RDWR: u32 = 2;
pub const O_ACCMODE: u32 = 3;
pub const O_CREAT: u32 = 0o100;
pub const O_EXCL: u32 = 0o200;
pub const O_TRUNC: u32 = 0o1000;
pub const O_APPEND: u32 = 0o2000;
/// A directory, to read with getdents or name others from (`/proc/self/fd/N/NAME`, as openat
/// would): fails with ENOTDIR on anything else.
pub const O_DIRECTORY: u32 = 0o200000;
/// ioctl(2)'s FICLONE, as Linux numbers it: the file the descriptor writes takes the content of
/// the one `arg` reads, shared, nothing copied (what `cp` does).
pub const FICLONE: u32 = 0x4004_9409;

/// inotify(7)'s events, as Linux numbers them. The kernel tells a watch of a directory that
/// something in it changed (`IN_MODIFY`), not what: the watcher lists it again. `IN_IGNORED`:
/// the watch is gone (its directory removed, or the watcher may no longer list it).
pub const IN_MODIFY: u32 = 0x2;
pub const IN_IGNORED: u32 = 0x8000;
/// The most watches a session has, as fs.inotify.max_user_watches bounds a user's.
pub const WATCHES_MAX: usize = 128;

/// The requests of /dev/present's driver: show a file (`{path}`), on a descriptor that writes
/// it; ask to speak (`{withdraw}` to withdraw), on one that reads it; answer an ask (`{id,
/// allow}`), as its owner; speak (`{sdp, mid}`), on one that writes it, which an answer gave.
pub const PRESENT_SHOW: u32 = 0x5001;
pub const PRESENT_ASK: u32 = 0x5002;
pub const PRESENT_ANSWER: u32 = 0x5003;
pub const PRESENT_SPEAK: u32 = 0x5004;
/// The requests of /dev/snd's: send the sound (`{sdp, mid}`), on a descriptor that writes it;
/// hear it, on one that reads it; answer what Realtime offered (`{session, sdp}`).
pub const SND_PUBLISH: u32 = 0x5101;
pub const SND_LISTEN: u32 = 0x5102;
pub const SND_ANSWER: u32 = 0x5103;

/// What open(2) gave: the descriptor, and what a writer needs to write the file in chunks:
/// their size, those already there (an unfinished file it goes on with), and whether the
/// file is new.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Opened {
    pub fd: u32,
    pub size: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub chunk_size: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub committed: Vec<u64>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub created: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub resumed: bool,
    /// A descriptor reading a file whole: its token, to read it by (`GET /api/file?token=`),
    /// which the Worker serves without asking the kernel each time, as long as its session
    /// sends it. The kernel asks again, of the descriptor and the reader's permission, at most
    /// every `TOKEN_FRESH` seconds; closing it ends the token, at the latest then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}
/// How long the Worker trusts what the kernel last said of a read token.
pub const TOKEN_FRESH: u64 = 60;
fn is_zero(n: &u64) -> bool {
    *n == 0
}
fn is_zero32(n: &u32) -> bool {
    *n == 0
}
/// What close(2) of a descriptor that wrote gave: where the file is, its size and version.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Closed {
    pub path: String,
    pub size: u64,
    /// Its version, which an editor gives `open` to replace only what it read.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub created: bool,
}
/// Bytes, as a call takes or gives them: base64 in JSON, a third more than they are, where a
/// list of numbers would be four times.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Bytes(pub Vec<u8>);
impl Serialize for Bytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(&self.0))
    }
}
impl<'de> Deserialize<'de> for Bytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        STANDARD
            .decode(text)
            .map(Bytes)
            .map_err(serde::de::Error::custom)
    }
}
impl From<Vec<u8>> for Bytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}
impl std::ops::Deref for Bytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

/// The most bytes `pread` and `pwrite` carry in a batch; more stream on the Worker (`GET
/// /api/file`, `PUT /api/pwrite`).
pub const INLINE_MAX: u64 = 256 * 1024;

/// What `pread` read: its bytes, and the file's size.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Data {
    pub data: Bytes,
    pub size: u64,
}

/// A time utimensat(2) sets: now (`UTIME_NOW`), unchanged (`UTIME_OMIT`), or the time given.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Time {
    #[default]
    Now,
    Omit,
    #[serde(untagged)]
    At {
        sec: u64,
        nsec: u32,
    },
}

/// What statfs(2) tells of the file system a path is on.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct StatFs {
    /// Its block size, and how many blocks it has, has free, and has free to anyone.
    pub bsize: u64,
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    /// How many inodes it has, and has free.
    pub files: u64,
    pub ffree: u64,
    /// The longest name it takes.
    pub namelen: u64,
}

/// The descriptor a call works on: its number, or `{"ref": i}`, the one call `i` of the same
/// batch opened (its result's `fd`), as NFSv4's COMPOUND passes a filehandle on. A call naming a
/// call that failed fails as it did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum FdRef {
    Fd(u32),
    Ref {
        #[serde(rename = "ref")]
        call: usize,
    },
}
impl From<u32> for FdRef {
    fn from(fd: u32) -> Self {
        Self::Fd(fd)
    }
}
impl FdRef {
    /// Its number, once the batch has made it one.
    pub fn number(self) -> u32 {
        match self {
            Self::Fd(fd) => fd,
            Self::Ref { .. } => u32::MAX,
        }
    }
}

/// A system call. Paths are absolute, as user space makes them from its working directory;
/// the kernel resolves them, `..` and links included, as Linux does.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Call {
    /// Who the process is.
    Getcreds,
    Stat {
        path: String,
    },
    Lstat {
        path: String,
    },
    /// The entries of a directory, each with its lstat: from the `cookie`th, at most `count` of
    /// them (all, by default), as getdents(2) reads a directory a buffer at a time.
    Getdents {
        path: String,
        #[serde(default, skip_serializing_if = "is_zero")]
        cookie: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        count: Option<u64>,
    },
    Access {
        path: String,
        mode: u16,
    },
    Readlink {
        path: String,
    },
    Mkdir {
        path: String,
        mode: u16,
    },
    /// A regular file, empty, as mknod(2) makes one with `S_IFREG` (what touch makes); or,
    /// with `rdev`, a character device of that driver, in its directory (/dev/present,
    /// /dev/snd), as its driver lets: signed in, a name free or the caller's own.
    Mknod {
        path: String,
        mode: u16,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rdev: Option<String>,
    },
    Rmdir {
        path: String,
    },
    Unlink {
        path: String,
    },
    Rename {
        from: String,
        to: String,
        /// `RENAME_NOREPLACE`: fail with EEXIST rather than replace.
        #[serde(default)]
        noreplace: bool,
    },
    Link {
        from: String,
        to: String,
        /// linkat(2)'s `AT_SYMLINK_FOLLOW`: a link `from` names gives its target another name,
        /// not itself.
        #[serde(default)]
        follow: bool,
    },
    Symlink {
        target: String,
        path: String,
    },
    Chmod {
        path: String,
        mode: u16,
    },
    Chown {
        path: String,
        #[serde(default)]
        uid: Option<u32>,
        #[serde(default)]
        gid: Option<u32>,
        /// lchown(2): the link itself.
        #[serde(default)]
        nofollow: bool,
    },
    /// utimensat(2): set its access and modification times, each now, unchanged or as given
    /// (now, by default, as touch does). Now needs the owner, root, or write permission; a time
    /// given, the owner or root.
    Utimens {
        path: String,
        #[serde(default)]
        atime: Time,
        #[serde(default)]
        mtime: Time,
        #[serde(default)]
        nofollow: bool,
    },
    /// statfs(2): the file system `path` is on.
    Statfs {
        path: String,
    },
    Getxattr {
        path: String,
        name: String,
        #[serde(default)]
        nofollow: bool,
    },
    Setxattr {
        path: String,
        name: String,
        value: Bytes,
        #[serde(default)]
        flags: u8,
        #[serde(default)]
        nofollow: bool,
    },
    Listxattr {
        path: String,
        #[serde(default)]
        nofollow: bool,
    },
    Removexattr {
        path: String,
        name: String,
        #[serde(default)]
        nofollow: bool,
    },
    /// A descriptor of the file at `path`, for this session (each browser is one): to read, or
    /// to write. A writer that gives the file's `size` may send its chunks in any order, and
    /// what it replaces shows until it is whole (an upload); one that does not writes them in
    /// order, and the file is what it wrote, growing as it does, readable meanwhile, and whole
    /// when it closes (a program's output, or, with `O_APPEND`, a recording). A writer naming an
    /// unfinished file of its own account with the same `size` and `sha256` goes on with it,
    /// once no other session has made a call lately. `version`, given to replace a
    /// file, must be the one it has (ESTALE otherwise), as an editor's save needs.
    Open {
        path: String,
        flags: u32,
        #[serde(default = "creation_mode")]
        mode: u16,
        #[serde(default)]
        size: Option<u64>,
        #[serde(default)]
        sha256: Option<String>,
        #[serde(default)]
        version: Option<String>,
    },
    /// Let go of a descriptor. One that wrote completes its file, if every chunk is there; if
    /// not, the descriptor goes all the same, with EIO, and the file waits, unfinished, for a
    /// writer to go on with it. A recording is complete with what arrived.
    Close {
        fd: FdRef,
    },
    /// pread(2): at most `count` bytes (`INLINE_MAX`), from `offset`, of the file the
    /// descriptor `fd` reads, or that `path` names, which needs read permission as open does: a
    /// short read at its end, or at what has arrived of a file still being written.
    Pread {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fd: Option<FdRef>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<String>,
        #[serde(default)]
        offset: u64,
        count: u64,
    },
    /// pwrite(2) of chunk `index` of the file `fd` writes, with its bytes: at most
    /// `INLINE_MAX`, so a small file whole, or the short end of a large one.
    Pwrite {
        fd: FdRef,
        index: u64,
        data: Bytes,
    },
    /// Sign this session in as `username`, its password said (none needed by root, or under
    /// sudo): the session is a new one, its cookie the reply's. Rate-limited.
    Login {
        #[serde(default = "root")]
        username: String,
        #[serde(default)]
        password: String,
    },
    /// Sign this session out: it is a guest's from then on.
    Logout,
    /// sudo's timestamp: the account's own password said, the session may act as root for five
    /// minutes (a wheel member's); `revoke` ends it (sudo -k).
    Sudo {
        #[serde(default)]
        password: String,
        #[serde(default)]
        revoke: bool,
    },
    /// Set `username`'s password (the caller's by default): its own needs the current one, as
    /// passwd asks; root's sets any. Its other sessions end. `force` takes a short one.
    Passwd {
        #[serde(default)]
        username: Option<String>,
        password: String,
        #[serde(default)]
        current_password: Option<String>,
        #[serde(default)]
        force: bool,
    },
    /// Make an account, as useradd does: root's, of any name, home and groups, locked until
    /// passwd gives it a password; or, signed out, one's own, in group guest, home
    /// /guest/NAME, with `password`, which signs the session in as it.
    Useradd {
        name: String,
        #[serde(default)]
        create_home: bool,
        #[serde(default)]
        home: Option<String>,
        #[serde(default)]
        group: Option<String>,
        #[serde(default)]
        groups: Option<String>,
        #[serde(default)]
        password: Option<String>,
        #[serde(default)]
        short_password: bool,
    },
    /// Change an account, as usermod does: root's.
    Usermod {
        name: String,
        #[serde(default)]
        append: bool,
        #[serde(default)]
        groups: Option<String>,
        #[serde(default)]
        group: Option<String>,
        #[serde(default)]
        home: Option<String>,
        #[serde(default)]
        move_home: bool,
        #[serde(default)]
        rename: Option<String>,
        #[serde(default)]
        lock: bool,
        #[serde(default)]
        unlock: bool,
    },
    /// Delete an account, and with `remove` its home: root's; or an account of group guest's
    /// own, its `password` said, which signs the session out.
    Userdel {
        name: String,
        #[serde(default)]
        remove: bool,
        #[serde(default)]
        password: Option<String>,
    },
    Groupadd {
        name: String,
    },
    Groupmod {
        name: String,
        new_name: String,
    },
    Groupdel {
        name: String,
    },
    /// inotify_add_watch(2): watch the directory `path`, which the caller may list: what
    /// changes in it is told on this session's lines of the events socket, as `{"inotify":
    /// [{"wd": N, "mask": IN_MODIFY}]}`, while its account may list it. The watch's number;
    /// the same directory's again, watched twice. At most `WATCHES_MAX` (ENOSPC).
    InotifyAddWatch {
        path: String,
        #[serde(default = "modify")]
        mask: u32,
    },
    /// inotify_rm_watch(2).
    InotifyRmWatch {
        wd: u32,
    },
    /// A process of the session's account (zip, unzip, tar, faststart), run as the caller
    /// (root under sudo), from `cwd`: its pid, and a descriptor of this session that writes its
    /// standard input (`stdin`), as a pipe would: unzip's answers to its question, `{"decisions":
    /// {PATH: true|false}}`, go through pwrite. Its work is done apart (a container), reading
    /// and writing as it.
    Spawn {
        argv: Vec<String>,
        cwd: String,
    },
    /// Signal the process `pid`: it stops, between steps (SIGTERM).
    Kill {
        pid: String,
    },
    /// What the process `pid` is now, and what it wrote after line `since`, as waitid(2) with
    /// WNOHANG and a read of its output: its state (`running`, `question`, `done`, `failed`,
    /// `cancelled`), progress, question and new lines.
    Wait {
        pid: String,
        #[serde(default)]
        since: u64,
    },
    /// A request of the file or device `fd` reads or writes, about `arg`: FICLONE's the
    /// descriptor cloned from; a driver's, what its request takes.
    Ioctl {
        fd: FdRef,
        request: u32,
        #[serde(default)]
        arg: serde_json::Value,
    },
}
fn root() -> String {
    "root".into()
}
fn creation_mode() -> u16 {
    0o666
}
fn modify() -> u32 {
    IN_MODIFY
}

/// The process a batch of calls runs for, and the calls.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Batch {
    pub calls: Vec<Call>,
    /// Its umask, which what it makes takes off the mode asked for, as Linux's does.
    #[serde(default = "umask")]
    pub umask: u16,
    /// Whether it runs under sudo: as root, if its account may and has authenticated lately.
    #[serde(default)]
    pub sudo: bool,
}
fn umask() -> u16 {
    0o022
}
/// The most calls a batch takes.
pub const BATCH_MAX: usize = 256;

/// What a call gave back: its value, or its error.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Return {
    Ok(serde_json::Value),
    Err(Error),
}
impl Return {
    pub fn into_result(self) -> Result<serde_json::Value, Error> {
        match self {
            Self::Ok(value) => Ok(value),
            Self::Err(error) => Err(error),
        }
    }
}

/// A batch's results, one for each call, in order.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Results {
    pub results: Vec<Return>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calls_and_results_go_as_json_user_space_and_the_kernel_both_read() {
        let batch = Batch {
            calls: vec![
                Call::Stat { path: "/a".into() },
                Call::Rename {
                    from: "/a".into(),
                    to: "/b".into(),
                    noreplace: true,
                },
            ],
            ..Batch::default()
        };
        let text = serde_json::to_string(&batch).unwrap();
        assert!(text.contains(r#"{"stat":{"path":"/a"}}"#), "{text}");
        let read: Batch =
            serde_json::from_str(r#"{"calls":[{"getcreds":null},{"unlink":{"path":"/x"}}]}"#)
                .or_else(|_| {
                    serde_json::from_str(r#"{"calls":["getcreds",{"unlink":{"path":"/x"}}]}"#)
                })
                .unwrap();
        assert_eq!(read.umask, 0o022);
        assert_eq!(read.calls[1], Call::Unlink { path: "/x".into() });
        let failed = Return::Err(Error::new(Errno::ENOENT));
        assert_eq!(
            serde_json::to_string(&failed).unwrap(),
            r#"{"err":{"errno":"ENOENT"}}"#
        );
        assert_eq!(Errno::ENOTEMPTY.text(), "Directory not empty");
        let later: Vec<Call> = serde_json::from_str(
            r#"[{"close":{"fd":3}},{"pwrite":{"fd":{"ref":0},"index":0,"data":"aGk="}}]"#,
        )
        .unwrap();
        assert_eq!(later[0], Call::Close { fd: 3.into() });
        assert_eq!(
            later[1],
            Call::Pwrite {
                fd: FdRef::Ref { call: 0 },
                index: 0,
                data: b"hi".to_vec().into(),
            }
        );
        let touched: Call = serde_json::from_str(
            r#"{"utimens":{"path":"/a","atime":"omit","mtime":{"sec":5,"nsec":6}}}"#,
        )
        .unwrap();
        assert_eq!(
            touched,
            Call::Utimens {
                path: "/a".into(),
                atime: Time::Omit,
                mtime: Time::At { sec: 5, nsec: 6 },
                nofollow: false,
            }
        );
        assert_eq!(
            serde_json::from_str::<Call>(r#"{"utimens":{"path":"/a"}}"#).unwrap(),
            Call::Utimens {
                path: "/a".into(),
                atime: Time::Now,
                mtime: Time::Now,
                nofollow: false,
            }
        );
        assert_eq!(serde_json::to_string(&Time::Now).unwrap(), r#""now""#);
        assert_eq!(
            serde_json::to_string(&later[1]).unwrap(),
            r#"{"pwrite":{"fd":{"ref":0},"index":0,"data":"aGk="}}"#
        );
        assert_eq!(
            Error::because(Errno::EACCES, "/guest/ann is another account's home").to_string(),
            "/guest/ann is another account's home"
        );
    }
}
