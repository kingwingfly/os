//! The VFS object model of the architecture contract (docs/architecture/contract.md §2.2,
//! §2.3), for #48 (L1a). Portable: no DOM, `web-sys` or `wasm-bindgen` types, so the browser
//! kernel, a native host and a headless test host run the same code.
//!
//! - A filesystem is a [`Filesystem`] driver, addressed by [`Handle`]s, never by paths. Path
//!   walking, `..`, symlinks and mount crossings belong to the client (§2.3); a driver resolves
//!   one name at a time ([`Filesystem::lookup`]) or several within itself ([`Filesystem::walk`]).
//! - Every call names the [`Cred`] acting, and the driver checks it, as Linux checks the
//!   calling process's credentials.
//! - [`Filesystem::open`] and [`Filesystem::create`] return an [`OpenRef`]: the driver's open
//!   reference, which records the credential and access granted at open. Reads and writes
//!   through it check only that access (§2.3).
//! - [`OpenFile`] is an open file description, shared by every descriptor that refers to it
//!   (offset and flags shared across `dup` and `fork`), and [`DescriptorTable`] is one process's
//!   descriptors, whatever the driver behind them.
//! - [`memfs`] is a complete in-memory driver: the reference the other drivers are tested
//!   against, and the instance's tmpfs.

pub mod descriptors;
pub mod memfs;
pub mod profiles;

pub use descriptors::{DescriptorTable, OpenFile};

use abi::Errno;
pub use abi::Time;
use abi::contract::FsCapabilities;
pub use os_core::permissions::Identity;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;

pub type Result<T> = std::result::Result<T, Errno>;
/// A driver call's result. Not `Send`: the browser kernel is single-threaded.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + 'a>>;

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
/// for remote ones). A handle grants nothing by itself: every call still checks its [`Cred`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Handle {
    pub fs: FsId,
    pub node: NodeId,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub proof: String,
}

/// The credential a call acts with (contract §2.4): who, and, for remote drivers, the credential
/// the identity service issued. Local drivers check `identity`.
#[derive(Clone, Debug)]
pub struct Cred {
    pub identity: Identity,
    pub umask: u16,
    /// The remote credential presented with this call, if the driver is remote.
    pub token: Option<String>,
}
impl Cred {
    pub fn new(identity: Identity) -> Self {
        Self {
            identity,
            umask: os_core::permissions::UMASK,
            token: None,
        }
    }
    pub fn root() -> Self {
        Self::new(Identity::root())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileKind {
    File,
    Directory,
    Symlink,
    Device,
}

/// What getattr tells of an object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Attr {
    pub kind: FileKind,
    /// Permission and special bits (`0o7777`).
    pub perm: u16,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    /// Seconds and nanoseconds since 1970.
    pub mtime: (u64, u32),
    pub ctime: (u64, u32),
    pub atime: (u64, u32),
    /// A device's driver.
    pub rdev: Option<String>,
    /// Whether it has an ACL beyond its mode.
    pub acl: bool,
}
impl Attr {
    /// `st_mode`: the type bits and the permission bits.
    pub fn mode(&self) -> u32 {
        let kind = match self.kind {
            FileKind::File => abi::S_IFREG,
            FileKind::Directory => abi::S_IFDIR,
            FileKind::Symlink => abi::S_IFLNK,
            FileKind::Device => abi::S_IFCHR,
        };
        kind | u32::from(self.perm)
    }
}

/// An object found by name: its handle and attributes.
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub handle: Handle,
    pub attr: Attr,
}

/// Why [`Filesystem::walk`] stopped before its last name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    /// The name at this index does not exist.
    Missing(usize),
    /// The name at this index is a symbolic link: the client reads and follows it.
    Symlink(usize),
    /// The name at this index is not a directory, and more names follow it.
    NotDirectory(usize),
}

/// What [`Filesystem::walk`] resolved: one entry per name resolved, and why it stopped, if it did.
#[derive(Clone, Debug, PartialEq)]
pub struct Walked {
    pub entries: Vec<Entry>,
    pub stop: Option<Stop>,
}

/// A directory entry, as readdir gives it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DirEntry {
    pub name: String,
    pub node: NodeId,
    pub kind: FileKind,
}

/// The access an open reference grants (contract §2.3). Exec is checked against execute
/// permission, not read, and serves only the loader.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Access {
    Read,
    Write,
    ReadWrite,
    Exec,
}
impl Access {
    /// From open(2)'s O_ACCMODE.
    pub fn from_flags(flags: u32) -> Result<Self> {
        match flags & abi::O_ACCMODE {
            abi::O_RDONLY => Ok(Access::Read),
            abi::O_WRONLY => Ok(Access::Write),
            abi::O_RDWR => Ok(Access::ReadWrite),
            _ => Err(Errno::EINVAL),
        }
    }
    pub fn reads(self) -> bool {
        matches!(self, Access::Read | Access::ReadWrite | Access::Exec)
    }
    pub fn writes(self) -> bool {
        matches!(self, Access::Write | Access::ReadWrite)
    }
    /// The permission bits it needs (`os_core::permissions` READ, WRITE, EXEC).
    pub fn bits(self) -> u16 {
        use os_core::permissions::{EXEC, READ, WRITE};
        match self {
            Access::Read => READ,
            Access::Write => WRITE,
            Access::ReadWrite => READ | WRITE,
            Access::Exec => EXEC,
        }
    }
}

/// An open reference (contract §2.3): the driver's record of one open, with the credential and
/// access granted then. Released by [`Filesystem::release`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OpenRef {
    pub fs: FsId,
    pub id: u64,
    pub node: NodeId,
    pub access: Access,
}

/// Attribute changes, as chmod, chown, utimensat and truncate make them; `None` and
/// [`Time::Omit`] leave one alone. A driver checks them all before it changes any, as
/// `os_core::inode` decides: times set to [`Time::Now`] need only write permission, a time
/// given needs the owner or root.
#[derive(Clone, Debug, PartialEq)]
pub struct SetAttr {
    pub perm: Option<u16>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub size: Option<u64>,
    pub atime: Time,
    pub mtime: Time,
}
impl Default for SetAttr {
    fn default() -> Self {
        Self {
            perm: None,
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

/// rename(2)'s flags: RENAME_NOREPLACE is the one the contract requires.
pub const RENAME_NOREPLACE: u32 = 1;

/// An advisory lock (contract §3): whole-file (`flock`) or a byte range (`fcntl`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LockKind {
    Shared,
    Exclusive,
}
/// A byte range; `len` 0 means to the end of the file, as fcntl(2) has it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockRange {
    pub start: u64,
    pub len: u64,
}
impl LockRange {
    pub const WHOLE: LockRange = LockRange { start: 0, len: 0 };
    /// The range from `start` up to `end`, not included; `u64::MAX` is the end of the file.
    pub fn between(start: u64, end: u64) -> Self {
        Self {
            start,
            len: if end == u64::MAX { 0 } else { end - start },
        }
    }
    /// Where it ends, not included: `u64::MAX` for one to the end of the file.
    pub fn end(self) -> u64 {
        if self.len == 0 {
            u64::MAX
        } else {
            self.start.saturating_add(self.len)
        }
    }
    pub fn overlaps(self, other: LockRange) -> bool {
        self.start < other.end() && other.start < self.end()
    }
    /// Whether the two overlap or meet, so that one lock may take both.
    pub fn touches(self, other: LockRange) -> bool {
        self.start <= other.end() && other.start <= self.end()
    }
}
/// A lock that conflicts with one asked for, as F_GETLK reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

/// A filesystem driver: the version 2 calls of the contract §2.3. Every call names the
/// credential acting; names are single components, never `.`, `..` or containing `/`
/// (`EINVAL`), and at most `NAME_MAX` bytes (`ENAMETOOLONG`), as [`check_component`] has it.
/// A handle whose object is gone, or whose generation changed, fails with `ESTALE`; a handle
/// the driver did not issue fails with `EACCES`. A directory that has been removed, though
/// still open, takes no new names (`ENOENT`).
pub trait Filesystem {
    fn id(&self) -> &FsId;
    /// What the driver provides (contract §3); every gate is read against it.
    fn capabilities(&self) -> FsCapabilities;
    fn root(&self) -> Handle;

    fn lookup<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str)
    -> BoxFuture<'a, Entry>;
    /// Resolve `names` one after another from `dir`, within this filesystem, stopping at the
    /// first missing name, symbolic link, or non-directory with names after it.
    fn walk<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        names: &'a [String],
    ) -> BoxFuture<'a, Walked>;
    /// The directory's parent and the directory's name in it; `None` at the filesystem's root.
    fn parent<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
    ) -> BoxFuture<'a, Option<(Entry, String)>>;
    fn getattr<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Attr>;
    fn setattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        set: &'a SetAttr,
    ) -> BoxFuture<'a, Attr>;
    fn readdir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle) -> BoxFuture<'a, Vec<DirEntry>>;
    fn readlink<'a>(&'a self, cred: &'a Cred, link: &'a Handle) -> BoxFuture<'a, String>;

    /// Create a regular file and open it in one call (contract §2.3): the open reference has
    /// `access` whatever the new file's mode, as Linux gives the creator. With `exclusive`, an
    /// existing name fails with `EEXIST`; without it, an existing file is opened as
    /// [`Filesystem::open`] would.
    #[allow(clippy::too_many_arguments)]
    fn create<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        perm: u16,
        exclusive: bool,
        access: Access,
    ) -> BoxFuture<'a, (Entry, OpenRef)>;
    fn mkdir<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        perm: u16,
    ) -> BoxFuture<'a, Entry>;
    fn mknod<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        perm: u16,
        rdev: &'a str,
    ) -> BoxFuture<'a, Entry>;
    fn symlink<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        target: &'a str,
    ) -> BoxFuture<'a, Entry>;
    fn link<'a>(
        &'a self,
        cred: &'a Cred,
        target: &'a Handle,
        dir: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Entry>;
    fn unlink<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()>;
    fn rmdir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()>;
    #[allow(clippy::too_many_arguments)]
    fn rename<'a>(
        &'a self,
        cred: &'a Cred,
        from_dir: &'a Handle,
        from: &'a str,
        to_dir: &'a Handle,
        to: &'a str,
        flags: u32,
    ) -> BoxFuture<'a, ()>;

    fn getxattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Vec<u8>>;
    /// Set an attribute; `flags` are setxattr(2)'s `XATTR_CREATE` and `XATTR_REPLACE`.
    fn setxattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
        value: &'a [u8],
        flags: u8,
    ) -> BoxFuture<'a, ()>;
    fn listxattr<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Vec<String>>;
    fn removexattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, ()>;
    fn statfs<'a>(&'a self, cred: &'a Cred) -> BoxFuture<'a, StatFs>;

    /// Open an existing object, checking `access` once (contract §2.3). A directory opens only
    /// for reading.
    fn open<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        access: Access,
        truncate: bool,
    ) -> BoxFuture<'a, OpenRef>;
    fn read<'a>(&'a self, open: &'a OpenRef, offset: u64, len: usize) -> BoxFuture<'a, Vec<u8>>;
    /// Write `data` at `at`, and say where it went and how much went. Nothing at all changes
    /// for empty `data`.
    fn write<'a>(
        &'a self,
        open: &'a OpenRef,
        at: WriteAt,
        data: &'a [u8],
    ) -> BoxFuture<'a, Written>;
    fn truncate<'a>(&'a self, open: &'a OpenRef, size: u64) -> BoxFuture<'a, ()>;
    /// Return after the driver's durability point (contract §3).
    fn fsync<'a>(&'a self, open: &'a OpenRef, datasync: bool) -> BoxFuture<'a, ()>;
    /// Take an advisory lock for `open`; a conflicting lock fails with `EAGAIN` (the caller
    /// waits and retries for a blocking request).
    fn lock<'a>(&'a self, open: &'a OpenRef, kind: LockKind, range: LockRange)
    -> BoxFuture<'a, ()>;
    fn unlock<'a>(&'a self, open: &'a OpenRef, range: LockRange) -> BoxFuture<'a, ()>;
    /// The first lock of another open reference that would conflict, as F_GETLK.
    fn getlk<'a>(
        &'a self,
        open: &'a OpenRef,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, Option<Conflict>>;
    /// End the open reference: its locks go, and an unlinked file's content goes with its last
    /// open reference.
    fn release<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()>;
}

/// Whether `name` may be one component of a path: `ENAMETOOLONG` past `NAME_MAX` bytes, as
/// Linux says before anything else, and `EINVAL` for an empty name, `.`, `..`, or one with `/`
/// or NUL.
pub fn check_component(name: &str) -> Result<()> {
    if name.len() > abi::NAME_MAX {
        return Err(Errno::ENAMETOOLONG);
    }
    if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
        return Err(Errno::EINVAL);
    }
    Ok(())
}

/// Whether `name` may be one component of a path ([`check_component`]).
pub fn valid_component(name: &str) -> bool {
    check_component(name).is_ok()
}

/// Run a future that never waits, as every [`memfs`] call is: for tests and synchronous callers.
pub fn ready<T>(future: impl Future<Output = T>) -> T {
    let mut future = std::pin::pin!(future);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(value) => value,
        std::task::Poll::Pending => panic!("os_vfs::ready: the future is not ready"),
    }
}
