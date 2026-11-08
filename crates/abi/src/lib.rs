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
    ENOEXEC,
    ECHILD,
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
            ENOEXEC => "Exec format error",
            ECHILD => "No child processes",
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

/// The most one argument, all of a process's arguments, and all of its environment take, and
/// the most its executable image may: Linux's limits, so that an uploaded module cannot ask the
/// host to hold more than a process should.
pub const ARG_MAX: usize = 128 * 1024;
pub const ENV_MAX: usize = 128 * 1024;
pub const EXEC_MAX: u64 = 128 * 1024 * 1024;
/// The most processes a namespace runs at once (a browser is one small machine).
pub const PROC_MAX: usize = 64;
/// How many processes an exec may replace, or a wait reap, in one call.
pub const PROC_POLL_MAX: usize = 256;

/// Signals, as Linux numbers them: what a process may be sent, and what ended it.
pub const SIGHUP: u8 = 1;
pub const SIGINT: u8 = 2;
pub const SIGQUIT: u8 = 3;
pub const SIGKILL: u8 = 9;
pub const SIGPIPE: u8 = 13;
pub const SIGTERM: u8 = 15;
pub const SIGCHLD: u8 = 17;
pub const SIGCONT: u8 = 18;
pub const SIGSTOP: u8 = 19;
pub const SIGTSTP: u8 = 20;
/// The signals by name, in number order, as `kill -l` lists them.
pub const SIGNALS: [(u8, &str); 10] = [
    (SIGHUP, "HUP"),
    (SIGINT, "INT"),
    (SIGQUIT, "QUIT"),
    (SIGKILL, "KILL"),
    (SIGPIPE, "PIPE"),
    (SIGTERM, "TERM"),
    (SIGCHLD, "CHLD"),
    (SIGCONT, "CONT"),
    (SIGSTOP, "STOP"),
    (SIGTSTP, "TSTP"),
];
/// The signal `name` names: by its name, with or without SIG, in any case, or its number.
pub fn signal_named(name: &str) -> Option<u8> {
    if let Ok(number) = name.parse::<u8>() {
        return SIGNALS.iter().find(|(n, _)| *n == number).map(|(n, _)| *n);
    }
    let upper = name.to_ascii_uppercase();
    let bare = upper.strip_prefix("SIG").unwrap_or(&upper);
    SIGNALS
        .iter()
        .find(|(_, signal)| *signal == bare)
        .map(|(n, _)| *n)
}
/// The name of the signal `number`, without SIG.
pub fn signal_name(number: u8) -> Option<&'static str> {
    SIGNALS
        .iter()
        .find(|(n, _)| *n == number)
        .map(|(_, name)| *name)
}

/// A process's state, as /proc/PID/status tells it: running, sleeping in a system call, stopped
/// by a signal, or a zombie whose parent has not waited for it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcState {
    #[default]
    Running,
    Sleeping,
    Stopped,
    Zombie,
}

/// Execution location; labels never grant access to an executor or cluster.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Placement {
    pub cluster: String,
    pub executor: String,
    pub cgroup: String,
}

/// Versioned capability discovery. Disabled features have no execution path yet.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Features {
    pub wasix: bool,
    pub cgroups: bool,
    pub cluster: bool,
    pub completion_queue: bool,
}

/// Reserved completion representation for future asynchronous batches/shared rings.
/// The current API continues returning ordered Results; this is not a new syscall.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Completion {
    pub request: u64,
    pub index: u32,
    pub result: Return,
}

/// What start_execve tells the loader: the process it made or replaced, the token that process
/// makes its calls with, how to read its image, and where it runs.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Exec {
    pub pid: u32,
    /// The process's token, which it sends as the batch's `proc`, with its `pid`.
    pub token: String,
    /// The image, as a descriptor of the process's own for a file, or an asset path for /usr.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fd: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_read: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub cgroup: String,
    #[serde(default)]
    pub placement: Placement,
}

/// What fork(2)'s registry half gives: the child, and the token its calls carry.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Forked {
    pub pid: u32,
    pub token: String,
}

/// Proof that a host still holds a process. It authorizes that process's lease and status
/// only, independently of the browser account currently signed in.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProcessProof {
    pub pid: u32,
    #[serde(rename = "proc")]
    pub token: String,
}

/// A process, as /proc and wait tell of it.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Proc {
    pub pid: u32,
    pub ppid: u32,
    pub state: ProcState,
    /// The wait status waitpid(2) gives: exit code << 8, or the signal that ended it.
    pub status: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<u8>,
    pub uid: u32,
    pub gid: u32,
    pub cgroup: String,
    pub path: String,
    pub argv: Vec<String>,
    pub started: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub ended: u64,
    /// The tab that runs it, if a client kernel said (`Execve`'s `seat`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seat: Option<String>,
    #[serde(default)]
    pub placement: Placement,
}

/// A process's wait status, as waitpid(2) encodes it: exit code in the high byte, or the signal
/// that ended it.
pub fn exit_status(code: i32) -> i32 {
    (code & 0xff) << 8
}
pub fn signal_status(signal: u8) -> i32 {
    signal as i32
}
pub fn exited(status: i32) -> Option<i32> {
    (status & 0x7f == 0).then_some((status >> 8) & 0xff)
}
pub fn signaled(status: i32) -> Option<u8> {
    (status & 0x7f != 0 && status & 0x7f != 0x7f).then_some((status & 0x7f) as u8)
}

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
    /// close(2) of a descriptor that writes, and the unfinished file it wrote with it: a new
    /// file disappears, an overwritten one keeps its old content, its chunks freed at once. An
    /// extension: what a cancelled upload, or a cancelled job, leaves is nobody's to finish.
    Discard {
        fd: FdRef,
    },
    /// fchmod(2): the mode of the file the descriptor `fd` has open, whatever name it has now
    /// (none followed), as its owner or root may change it.
    Fchmod {
        fd: FdRef,
        mode: u16,
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
    /// Begin a browser's process namespace, as init does. A new `boot` reaps only the calling
    /// account's old processes and lends. The browser's guest cookie names the namespace;
    /// a caller-supplied boot id grants no authority over another account.
    ProcInit {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        boot: Option<String>,
    },
    /// execve(2): run the executable at `path` as a new child of the namespace's init, or, with
    /// `pid` and that process's own token (`proc`), as that process, its image replaced. The
    /// kernel checks the path, regular and whole, and execute permission (X, not read: an
    /// x-only file runs), and gives the loader the image's descriptor or asset and the process's
    /// new token. A new process runs as the caller (root under sudo); a replaced one keeps its
    /// credentials and its open descriptors, as Linux's execve does.
    Execve {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pid: Option<u32>,
        /// The token of the process `pid`, which only that process holds: the proof that it
        /// replaces itself.
        #[serde(default, rename = "proc", skip_serializing_if = "Option::is_none")]
        token: Option<String>,
        path: String,
        #[serde(default)]
        argv: Vec<String>,
        #[serde(default)]
        env: Vec<String>,
        #[serde(default = "slash")]
        cwd: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cgroup: Option<String>,
        /// The tab that runs it (the client kernel's "seat"), which holds a Web Lock while it
        /// lives: a process whose seat's lock is free was left by a tab that is gone.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        seat: Option<String>,
    },
    /// fork(2)'s registry half: a child of `pid`, with its credentials, cgroup and descriptors
    /// copied. The client kernel clones the guest's wasm state (asyncify snapshot). The child
    /// is `child`, a pid the kernel was lent (`Pids`), when it forked at once and tells of it
    /// after; with none, the registry gives one.
    Fork {
        pid: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        child: Option<u32>,
        /// The parent's token, when its kernel tells of the fork in a batch of others' calls.
        #[serde(default, rename = "proc", skip_serializing_if = "Option::is_none")]
        token: Option<String>,
    },
    /// exit(2): the calling process (its token) ends with `status`, or by `signal`. It becomes a
    /// zombie until its parent waits for it; init reaps orphans. The kernel that hosts several
    /// tells of their ends in one batch, each naming its process by `pid` and token (`proc`).
    Exit {
        #[serde(default)]
        status: i32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signal: Option<u8>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pid: Option<u32>,
        #[serde(default, rename = "proc", skip_serializing_if = "Option::is_none")]
        token: Option<String>,
    },
    /// Lend the client kernel `kernel` (its own id, which it holds a Web Lock of while it runs)
    /// `count` pids of its namespace, which its forks take at once, without asking (`Fork`'s
    /// `child`). What a kernel was lent and did not take goes back once it is gone (`Gone`).
    /// Reservations belong to the caller's account and, for a process batch, its token.
    Pids {
        count: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        kernel: Option<String>,
    },
    /// What the client kernel checks is still there: the tabs (seats) whose processes still
    /// run, and the kernels holding lent pids (`{seats, kernels}`), for the account or all for root.
    Seats,
    /// The tab `seat`, or the kernel `kernel`, is gone (its Web Lock is free): what the tab ran
    /// ended with it, as by SIGKILL, and init reaps it; the pids the kernel was lent go back.
    /// Every affected row must belong to the caller's account, or the caller must be root.
    Gone {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        seat: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        kernel: Option<String>,
    },
    /// getpid(2), of the calling process.
    Getpid,
    /// What those processes are now, as waitid(2) with WNOHANG tells it, for the caller's
    /// namespace and account.
    ProcPoll {
        #[serde(default)]
        pids: Vec<u32>,
    },
    /// Renew hosted processes and recover their current state after a missed event.
    ProcKeep {
        processes: Vec<ProcessProof>,
    },
    /// A cgroup of the namespace's hierarchy, as cgroup v2 makes one.
    CgroupCreate {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        controllers: Option<String>,
    },
    CgroupRemove {
        path: String,
    },
    /// Write one of cgroup v2's control files: `cpu.max`, `cpu.weight`, `memory.max`,
    /// `pids.max`, `io.max`, `cgroup.freeze`, `devices.allow`, `devices.deny`.
    CgroupSet {
        path: String,
        key: String,
        value: String,
    },
    /// Move a process into a cgroup (`cgroup.procs`).
    CgroupAttach {
        pid: u32,
        path: String,
    },
    /// What a cgroup's control files say, and its processes.
    CgroupStat {
        path: String,
    },
    /// The cgroups below `path`, or the root's, as getdents lists a directory.
    CgroupList {
        #[serde(default = "slash")]
        path: String,
    },
    /// Signal the process `pid`: it stops, between steps (SIGTERM).
    Kill {
        pid: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signal: Option<u8>,
    },
    /// What the process `pid` is now, and what it wrote after line `since`, as waitid(2) with
    /// WNOHANG and a read of its output: its state (`running`, `question`, `done`, `failed`,
    /// `cancelled`), progress, question and new lines.
    Wait {
        pid: String,
        #[serde(default)]
        since: u64,
        /// A host may reap the zombie it ran by its token, even after the browser signs out.
        /// This grants no live-process or filesystem authority to a zombie's token.
        #[serde(default, rename = "proc", skip_serializing_if = "Option::is_none")]
        token: Option<String>,
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
/// What a `Kill` or a `Wait` names: a process of the browser's registry (a number), or an
/// archive job (its id, a word of hexadecimal digits that is never a number).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target<'a> {
    Pid(u32),
    Job(&'a str),
}
impl<'a> Target<'a> {
    pub fn of(pid: &'a str) -> Self {
        pid.parse().map_or(Target::Job(pid), Target::Pid)
    }
}

impl Call {
    /// Whether the call is the process registry's (each browser's own, not the filesystem's):
    /// the namespace, its processes and cgroups. A Kill or Wait of a number names a process; of
    /// a word, an archive job (`Target`).
    pub fn is_registry(&self) -> bool {
        match self {
            Call::ProcInit { .. }
            | Call::Execve { .. }
            | Call::Fork { .. }
            | Call::Exit { .. }
            | Call::Pids { .. }
            | Call::Seats
            | Call::Gone { .. }
            | Call::Getpid
            | Call::ProcPoll { .. }
            | Call::ProcKeep { .. }
            | Call::CgroupCreate { .. }
            | Call::CgroupRemove { .. }
            | Call::CgroupSet { .. }
            | Call::CgroupAttach { .. }
            | Call::CgroupStat { .. }
            | Call::CgroupList { .. } => true,
            Call::Kill { pid, .. } | Call::Wait { pid, .. } => {
                matches!(Target::of(pid), Target::Pid(_))
            }
            _ => false,
        }
    }
}

/// The most pids `Pids` lends at once.
pub const PIDS_MAX: u32 = 64;

fn root() -> String {
    "root".into()
}
/// The root directory, or the root cgroup: where a path not given starts.
fn slash() -> String {
    "/".into()
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
    /// The process the batch runs for, with the token its exec gave (`proc`): a process does
    /// not act as whoever holds the browser, but as whom it was executed. A page's batch names
    /// neither, and acts as the session's account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, rename = "proc", skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
}
fn umask() -> u16 {
    0o022
}
/// The most calls a batch takes.
pub const BATCH_MAX: usize = 256;
/// The most bytes a batch's request may be (it says its length): the authority's and each
/// machine's.
pub const BATCH_BYTES: u64 = 4 << 20;

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

    #[test]
    fn process_calls_carry_linuxs_values_and_old_batches_still_parse() {
        let call: Call = serde_json::from_str(
            r#"{"execve":{"path":"/usr/bin/coreutils","argv":["seq","3"],"env":["LANG=C"],"cwd":"/work"}}"#,
        )
        .unwrap();
        assert_eq!(
            call,
            Call::Execve {
                pid: None,
                token: None,
                path: "/usr/bin/coreutils".into(),
                argv: vec!["seq".into(), "3".into()],
                env: vec!["LANG=C".into()],
                cwd: "/work".into(),
                cgroup: None,
                seat: None,
            }
        );
        assert_eq!(signal_named("SIGTSTP"), Some(SIGTSTP));
        assert_eq!(signal_named("kill"), Some(SIGKILL));
        assert_eq!(signal_named("15"), Some(SIGTERM));
        assert_eq!(signal_named("BOGUS"), None);
        assert_eq!(signal_name(SIGCONT), Some("CONT"));
        let batch: Batch =
            serde_json::from_str(r#"{"calls":["getpid"],"proc":"ab","pid":7}"#).unwrap();
        assert_eq!(batch.process.as_deref(), Some("ab"));
        assert_eq!(batch.pid, Some(7));
        let old: Batch = serde_json::from_str(r#"{"calls":[]}"#).unwrap();
        assert_eq!((old.pid, old.process), (None, None));
        assert_eq!(exit_status(3), 3 << 8);
        assert_eq!(exited(3 << 8), Some(3));
        assert_eq!(signal_status(SIGKILL), 9);
        assert_eq!(signaled(9), Some(SIGKILL));
        assert_eq!(signaled(3 << 8), None);
        assert_eq!(Errno::ENOEXEC.text(), "Exec format error");
        // A kernel tells of several processes' ends in one batch, each by its pid and token.
        let exit: Call =
            serde_json::from_str(r#"{"exit":{"status":3,"pid":9,"proc":"cd"}}"#).unwrap();
        assert_eq!(
            exit,
            Call::Exit {
                status: 3,
                signal: None,
                pid: Some(9),
                token: Some("cd".into()),
            }
        );
        let old: Call = serde_json::from_str(r#"{"fork":{"pid":4}}"#).unwrap();
        assert_eq!(
            old,
            Call::Fork {
                pid: 4,
                child: None,
                token: None,
            }
        );
        // The registry's calls, and a Kill or Wait of a number, are the browser's own.
        assert!(Call::Seats.is_registry());
        assert!(
            Call::Kill {
                pid: "12".into(),
                signal: None
            }
            .is_registry()
        );
        assert!(
            !Call::Kill {
                pid: "a1b2".into(),
                signal: None
            }
            .is_registry()
        );
        assert!(!Call::Getcreds.is_registry());
        assert_eq!(Target::of("12"), Target::Pid(12));
        assert_eq!(Target::of("a1b2"), Target::Job("a1b2"));
        // A path not given is the root's, as a cgroup not given is.
        let exec: Call = serde_json::from_str(r#"{"execve":{"path":"x"}}"#).unwrap();
        assert!(matches!(exec, Call::Execve { ref cwd, .. } if cwd == "/"));
        let list: Call = serde_json::from_str(r#"{"cgroup_list":{}}"#).unwrap();
        assert_eq!(list, Call::CgroupList { path: "/".into() });
    }
}

/// Seconds without an authenticated host heartbeat before its processes are reaped.
pub const PROCESS_LEASE: u64 = 30 * 60;
/// Credential validity exceeds the host lease so a delayed revocation still expires.
pub const PROCESS_TOKEN_TTL: u64 = 2 * PROCESS_LEASE;
