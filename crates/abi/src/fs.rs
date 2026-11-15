//! Handle-based filesystem values shared by local drivers and the v2 wire protocol.
use crate::{Errno, Time};
use bitflags::bitflags;
use serde::{Deserialize, Serialize};
use std::ops::{Range, RangeFrom};
type Result<T> = std::result::Result<T, Errno>;

/// A filesystem's identity (contract §2.5): the authority's id, a UUID, a helper folder's id.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FsId(pub String);
impl FsId {
    /// `st_dev`: a stable number for this filesystem, the same wherever it is mounted (FNV-1a of
    /// its id, never 0).
    pub fn dev(&self) -> u64 {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in self.0.bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash.max(1)
    }
}

/// An object in a filesystem: what a handle names. The generation distinguishes an inode
/// number used again after its file is gone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId {
    pub ino: u64,
    pub generation: u64,
}

/// A handle (contract §2.3): names one object of one filesystem. `proof` is whatever the driver
/// or service needs to know the handle is its own (empty for local drivers; a server-issued tag
/// for remote ones). A handle grants nothing by itself: every call still checks its `Cred`.
/// A handle does not keep its object alive: an open reference does, including a path-only one
/// ([`OpenOptions::path`]).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Handle {
    pub fs: FsId,
    pub node: NodeId,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub proof: String,
}

/// What kind of object a node is, as `std::fs::FileType` says.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FileType {
    File,
    Dir,
    Symlink,
    CharDevice,
}
impl FileType {
    pub fn is_file(self) -> bool {
        self == FileType::File
    }
    pub fn is_dir(self) -> bool {
        self == FileType::Dir
    }
    pub fn is_symlink(self) -> bool {
        self == FileType::Symlink
    }
    pub fn is_char_device(self) -> bool {
        self == FileType::CharDevice
    }
    /// The `S_IFMT` bits of `st_mode`.
    pub fn mode(self) -> u32 {
        match self {
            FileType::File => crate::S_IFREG,
            FileType::Dir => crate::S_IFDIR,
            FileType::Symlink => crate::S_IFLNK,
            FileType::CharDevice => crate::S_IFCHR,
        }
    }
}

/// Seconds and nanoseconds since 1970, as Linux's `struct timespec64`.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct Timespec {
    pub sec: u64,
    pub nsec: u32,
}
impl From<(u64, u32)> for Timespec {
    fn from((sec, nsec): (u64, u32)) -> Self {
        Self { sec, nsec }
    }
}

/// What a filesystem tells of an object, as `std::fs::Metadata` and Linux's `struct kstat`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Metadata {
    pub file_type: FileType,
    /// Permission and special bits (`0o7777`).
    pub mode: u16,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub atime: Timespec,
    pub mtime: Timespec,
    pub ctime: Timespec,
    /// A device's driver.
    pub rdev: Option<String>,
    /// Whether it has an ACL beyond its mode.
    pub acl: bool,
}
impl Metadata {
    pub fn is_file(&self) -> bool {
        self.file_type.is_file()
    }
    pub fn is_dir(&self) -> bool {
        self.file_type.is_dir()
    }
    pub fn is_symlink(&self) -> bool {
        self.file_type.is_symlink()
    }
    /// `st_mode`: the type bits and the permission bits.
    pub fn st_mode(&self) -> u32 {
        self.file_type.mode() | u32::from(self.mode)
    }
}

/// An object found by name: its handle and metadata (Linux's dentry and inode, as a client
/// keeps them).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub handle: Handle,
    pub metadata: Metadata,
}

/// Why `Filesystem::walk` stopped before its last name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Stop {
    /// The name at this index does not exist.
    Missing(usize),
    /// The name at this index is a symbolic link: the client reads and follows it.
    Symlink(usize),
    /// The name at this index is not a directory, and more names follow it.
    NotDirectory(usize),
}

/// What `Filesystem::walk` resolved: one entry per name resolved, and why it stopped, if it did.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Walked {
    pub entries: Vec<Entry>,
    pub stop: Option<Stop>,
}

/// A directory entry, as `read_dir` gives it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DirEntry {
    pub name: String,
    pub node: NodeId,
    pub file_type: FileType,
}

/// The access an open reference grants (contract §2.3), as Linux's `FMODE_*`. Exec is checked
/// against execute permission, not read, and serves only the loader. Path (`O_PATH`) grants no
/// access at all: it keeps the object alive and anchors later calls, as a working directory, a
/// process root or a mount point needs, and asks no permission of the object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Access {
    Read,
    Write,
    ReadWrite,
    Exec,
    Path,
}
impl Access {
    pub fn reads(self) -> bool {
        matches!(self, Access::Read | Access::ReadWrite | Access::Exec)
    }
    pub fn writes(self) -> bool {
        matches!(self, Access::Write | Access::ReadWrite)
    }
    /// The permission bits it needs (`os_core::permissions` READ, WRITE, EXEC); none for Path.
    pub fn mask(self) -> u16 {
        match self {
            Access::Read => 4,
            Access::Write => 2,
            Access::ReadWrite => 4 | 2,
            Access::Exec => 1,
            Access::Path => 0,
        }
    }
}

/// How to open a file, as `std::fs::OpenOptions`, with what Linux adds: execute access for the
/// loader, and path-only opens (`O_PATH`). A driver reads the access, `truncate`, `create` and
/// `create_new`; `append` belongs to the description (`File`), which places each write.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OpenOptions {
    read: bool,
    write: bool,
    append: bool,
    // The Rust builder grants write access for append; raw O_APPEND is only a status flag.
    append_implies_write: bool,
    truncate: bool,
    create: bool,
    create_new: bool,
    exec: bool,
    path: bool,
}
impl OpenOptions {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn read(&mut self, read: bool) -> &mut Self {
        self.read = read;
        self
    }
    pub fn write(&mut self, write: bool) -> &mut Self {
        self.write = write;
        self
    }
    /// Every write goes at the end of the file; implies write.
    pub fn append(&mut self, append: bool) -> &mut Self {
        self.append = append;
        self.append_implies_write = append;
        self
    }
    pub fn truncate(&mut self, truncate: bool) -> &mut Self {
        self.truncate = truncate;
        self
    }
    pub fn create(&mut self, create: bool) -> &mut Self {
        self.create = create;
        self
    }
    /// Create the file, failing with EEXIST if the name is taken (`O_CREAT | O_EXCL`).
    pub fn create_new(&mut self, create_new: bool) -> &mut Self {
        self.create_new = create_new;
        self
    }
    /// Execute access, for the loader.
    pub fn exec(&mut self, exec: bool) -> &mut Self {
        self.exec = exec;
        self
    }
    /// A path-only open (`O_PATH`): no access, only a reference that keeps the object alive.
    pub fn path(&mut self, path: bool) -> &mut Self {
        self.path = path;
        self
    }
    /// From open(2)'s flags: the access mode, `O_APPEND`, `O_TRUNC`, `O_CREAT`, `O_EXCL` and
    /// `O_PATH`.
    pub fn from_flags(flags: u32) -> Result<Self> {
        let mut options = Self::new();
        if flags & crate::O_PATH != 0 {
            return Ok(*options.path(true));
        }
        match flags & crate::O_ACCMODE {
            crate::O_RDONLY => options.read(true),
            crate::O_WRONLY => options.write(true),
            crate::O_RDWR => options.read(true).write(true),
            _ => return Err(Errno::EINVAL),
        };
        options
            .append(flags & crate::O_APPEND != 0)
            .truncate(flags & crate::O_TRUNC != 0)
            .create(flags & crate::O_CREAT != 0)
            .create_new(flags & crate::O_CREAT != 0 && flags & crate::O_EXCL != 0);
        options.append_implies_write = false;
        Ok(options)
    }
    /// The access these options ask: EINVAL for none, or for exec or path with another.
    pub fn access(&self) -> Result<Access> {
        let write = self.write || (self.append && self.append_implies_write);
        match (self.path, self.exec, self.read, write) {
            (true, false, false, false) => Ok(Access::Path),
            (false, true, false, false) => Ok(Access::Exec),
            (false, false, true, false) => Ok(Access::Read),
            (false, false, false, true) => Ok(Access::Write),
            (false, false, true, true) => Ok(Access::ReadWrite),
            _ => Err(Errno::EINVAL),
        }
    }
    pub fn is_append(&self) -> bool {
        self.append
    }
    pub fn is_truncate(&self) -> bool {
        self.truncate
    }
    pub fn is_create(&self) -> bool {
        self.create || self.create_new
    }
    pub fn is_create_new(&self) -> bool {
        self.create_new
    }
}

/// An open reference (contract §2.3): the driver's record of one open, with the credential and
/// access granted then. Released by `Filesystem::release`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OpenRef {
    pub fs: FsId,
    pub id: u64,
    pub node: NodeId,
    pub access: Access,
}

/// Attribute changes, as Linux's `struct iattr`: chmod, chown, utimensat and truncate. `None`
/// and [`Time::Omit`] leave one alone. A driver checks them all before it changes any, as
/// `os_core::inode` decides.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SetAttr {
    pub mode: Option<u16>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub size: Option<u64>,
    pub atime: Time,
    pub mtime: Time,
}
impl Default for SetAttr {
    fn default() -> Self {
        Self {
            mode: None,
            uid: None,
            gid: None,
            size: None,
            atime: Time::Omit,
            mtime: Time::Omit,
        }
    }
}

/// Where a write goes (contract §2.3): at an offset, or at the end of the file as it is when
/// the write lands, which the driver decides atomically (`O_APPEND`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WriteAt {
    Offset(u64),
    End,
}

/// What a write did: the offset its data went to, and how many bytes went.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Written {
    pub offset: u64,
    pub len: usize,
}

/// The largest file size and offset, as Linux's `MAX_LFS_FILESIZE` (`off_t` is 64 bits on
/// every target): a write or truncate past it fails with `EFBIG`.
pub const FILE_MAX: u64 = i64::MAX as u64;

bitflags! {
    /// renameat2(2)'s flags; RENAME_NOREPLACE is the one the contract requires.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct RenameFlags: u32 {
        const NOREPLACE = 1;
    }
}

bitflags! {
    /// setxattr(2)'s flags.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
    pub struct XattrFlags: u8 {
        const CREATE = crate::XATTR_CREATE;
        const REPLACE = crate::XATTR_REPLACE;
    }
}

/// An advisory lock's kind, as `std::fs::File::lock_shared` and `lock` take them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LockKind {
    Shared,
    Exclusive,
}

/// Which locks a lock is among (contract §3). As on Linux, flock(2) locks and fcntl(2) byte-range
/// locks never conflict with each other. A flock lock covers the whole file and needs no
/// particular access; an fcntl lock needs read access to be shared and write access to be
/// exclusive (EBADF otherwise).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LockFamily {
    Flock,
    Posix,
}

/// The bytes a lock covers: from `start` up to `end`, not included, or to the end of the file,
/// however far it grows (fcntl(2)'s `l_len` of 0). Never empty.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LockRange {
    start: u64,
    end: Option<u64>,
}
impl LockRange {
    /// The whole file, as flock(2) locks it.
    pub const WHOLE: LockRange = LockRange {
        start: 0,
        end: None,
    };
    /// `start..end`, or `start..` without `end`; `None` if that would be empty.
    pub fn new(start: u64, end: Option<u64>) -> Option<Self> {
        match end {
            Some(end) if end <= start => None,
            _ => Some(Self { start, end }),
        }
    }
    pub fn start(self) -> u64 {
        self.start
    }
    /// Where it ends, not included; `None` for the end of the file.
    pub fn end(self) -> Option<u64> {
        self.end
    }
    fn end_or_max(self) -> u64 {
        self.end.unwrap_or(u64::MAX)
    }
    pub fn overlaps(self, other: LockRange) -> bool {
        self.start < other.end_or_max() && other.start < self.end_or_max()
    }
    /// Whether the two overlap or meet, so that one lock may take both.
    pub fn touches(self, other: LockRange) -> bool {
        self.start <= other.end_or_max() && other.start <= self.end_or_max()
    }
    /// The smallest range covering both.
    pub fn union(self, other: LockRange) -> LockRange {
        let end = match (self.end, other.end) {
            (Some(a), Some(b)) => Some(a.max(b)),
            _ => None,
        };
        LockRange {
            start: self.start.min(other.start),
            end,
        }
    }
    /// What is left of it outside `hole`: up to two pieces, before and after.
    pub fn minus(self, hole: LockRange) -> [Option<LockRange>; 2] {
        if !self.overlaps(hole) {
            return [Some(self), None];
        }
        let before = LockRange::new(self.start, Some(hole.start));
        let after = hole.end.and_then(|end| LockRange::new(end, self.end));
        [before, after]
    }
}
impl From<RangeFrom<u64>> for LockRange {
    fn from(range: RangeFrom<u64>) -> Self {
        LockRange {
            start: range.start,
            end: None,
        }
    }
}
impl TryFrom<Range<u64>> for LockRange {
    type Error = Errno;
    /// EINVAL for an empty range.
    fn try_from(range: Range<u64>) -> Result<Self> {
        LockRange::new(range.start, Some(range.end)).ok_or(Errno::EINVAL)
    }
}

/// A lock that conflicts with one asked for, as F_GETLK reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Conflict {
    pub kind: LockKind,
    pub range: LockRange,
    pub owner: u64,
}

/// statfs(2), as far as a driver knows it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatFs {
    pub block_size: u64,
    pub blocks: u64,
    pub blocks_free: u64,
    pub files: u64,
    pub files_free: u64,
    pub name_max: u64,
}

/// Whether `name` may be one component of a path: `ENAMETOOLONG` past `NAME_MAX` bytes, as
/// Linux says before anything else, and `EINVAL` for an empty name, `.`, `..`, or one with `/`
/// or NUL.
pub fn check_component(name: &str) -> Result<()> {
    if name.len() > crate::NAME_MAX {
        return Err(Errno::ENAMETOOLONG);
    }
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
        return Err(Errno::EINVAL);
    }
    Ok(())
}
