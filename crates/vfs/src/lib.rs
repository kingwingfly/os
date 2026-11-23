//! The VFS of the architecture contract (docs/architecture/contract.md §2.2, §2.3), for #48
//! (L1a). Portable: no DOM, `web-sys` or `wasm-bindgen` types, so the browser kernel, a native
//! host and a headless test host run the same code.
//!
//! The names follow Rust's standard library where it has the operation ([`OpenOptions`],
//! [`Metadata`], [`FileType`], [`SeekFrom`], `read_at`, `set_len`, `sync_all`, `lock` and
//! `try_lock`), and the Linux kernel's where it does not (`lookup`, `setattr`, `statfs`,
//! `release`, [`FdTable`]).
//!
//! - A filesystem is a [`Filesystem`] driver, addressed by [`Handle`]s, never by paths. Path
//!   walking, `..`, symlinks and mount crossings belong to the client (§2.3); a driver resolves
//!   one name at a time ([`Filesystem::lookup`]) or several within itself ([`Filesystem::walk`]).
//! - Every call names the [`Cred`] acting, and the driver checks it, as Linux checks the
//!   calling process's credentials. The rules are `os_core::inode`'s, which the server's
//!   kernel shares.
//! - [`Filesystem::open`] and [`Filesystem::create`] return an [`OpenRef`]: the driver's open
//!   reference, which records the credential and access granted at open. Reads and writes
//!   through it check only that access (§2.3).
//! - [`FileRef`] is a counted reference to an open file description ([`File`], Linux's
//!   `struct file`), and [`FdTable`] is one process's descriptors, whatever the driver behind
//!   them.
//! - [`memfs`] is a complete in-memory driver: the reference the other drivers are tested
//!   against, and the instance's tmpfs.

pub mod cloud;
pub mod cloud_http;
pub mod context;
pub mod descriptions;
pub mod devfs;
pub mod fdtable;
pub mod file;
pub mod helperfs;
pub mod hostfs;
pub mod imagefs;
pub mod locks;
pub mod loopdev;
pub mod memfs;
pub mod mount;
pub mod namespace;
pub mod procfs;
pub mod profiles;
pub mod sharefs;
pub mod stat;
pub mod unix_sock;
pub mod vblk;
pub mod vfs;
pub mod walk;

pub use context::{FsContext, PathAnchor, SharedFdTable, SharedFsContext};
pub use fdtable::{FD_MAX, Fd, FdTable};
pub use file::{File, FileRef, MountNsFile, ReleaseQueue};
pub use mount::{
    AtimeMode, FsType, MountAttachment, MountBacking, MountEntry, MountFlags, MountId, MountPin,
    MountSlot, NamespaceId, ProviderHealth, ProviderState,
};
pub use namespace::{MountNamespace, escape_mountinfo, format_mountinfo, format_mounts};
pub use std::io::SeekFrom;
pub use vfs::{
    DefaultFilesystemFactory, FilesystemFactory, MAX_SHEBANG_DEPTH, MountedFs, ProcessCtx,
    ResolvedExec, Vfs,
};
pub use walk::{StartAnchor, WalkFlags, WalkResult};

use abi::Errno;
pub use abi::Time;
use abi::contract::FsCapabilities;
pub use os_core::permissions::Identity;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

pub type Result<T, E = Errno> = std::result::Result<T, E>;
/// A driver call's result. Not `Send`: the browser kernel is single-threaded.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + 'a>>;

pub use abi::fs::*;

/// The credential a call acts with (contract §2.4), as Linux's `struct cred`: who, and, for
/// remote drivers, the credential the identity service issued. Local drivers check `identity`.
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

/// Hard cap on entries per `read_dir_page` call so callers cannot blow the 32 MiB wasm32 arena.
pub const DIR_PAGE_MAX: usize = 1024;

/// A filesystem driver: the version 2 calls of the contract §2.3, as Linux's
/// `inode_operations` and `file_operations` together. Every call names the credential acting;
/// names are single components, never `.`, `..` or containing `/` (`EINVAL`), and at most
/// `NAME_MAX` bytes (`ENAMETOOLONG`), as [`check_component`] has it. A handle whose object is
/// gone, or whose generation changed, fails with `ESTALE`; a handle the driver did not issue
/// fails with `EACCES`. A directory that has been removed, though still open, takes no new
/// names and lists none (`ENOENT`).
pub trait Filesystem {
    fn id(&self) -> &FsId;
    /// What the driver provides (contract §3); every gate is read against it.
    fn capabilities(&self) -> FsCapabilities;
    fn root(&self) -> Handle;

    fn lookup<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str)
    -> BoxFuture<'a, Entry>;
    /// Resolve `names` one after another from `dir`, within this filesystem, stopping at the
    /// first missing name, symbolic link, or non-directory with names after it. Every name is
    /// checked before any is resolved.
    fn walk<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        names: &'a [String],
    ) -> BoxFuture<'a, Walked>;
    /// The directory's parent and the directory's name in it; `None` at the filesystem's root.
    /// It asks no permission, as getcwd(2) asks none; a removed directory has none (ENOENT).
    fn parent<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
    ) -> BoxFuture<'a, Option<(Entry, String)>>;
    /// getattr: the object's metadata.
    fn metadata<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Metadata>;
    fn setattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        attr: &'a SetAttr,
    ) -> BoxFuture<'a, Metadata>;
    /// Descriptor metadata changes may use a provider's open capability directly.
    fn setattr_open<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        _open: &'a OpenRef,
        attr: &'a SetAttr,
    ) -> BoxFuture<'a, Metadata> {
        self.setattr(cred, handle, attr)
    }
    fn read_dir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle) -> BoxFuture<'a, Vec<DirEntry>>;
    fn read_link<'a>(&'a self, cred: &'a Cred, link: &'a Handle) -> BoxFuture<'a, String>;

    /// Create a regular file and open it in one call, as open(2) with `O_CREAT` (contract
    /// §2.3): the open reference has the access `options` ask, whatever the new file's mode, as
    /// Linux gives the creator. With `create_new`, an existing name fails with `EEXIST`;
    /// without it, an existing file is opened as [`Filesystem::open`] would, truncated if
    /// `options` ask, in the same call, and a directory fails with `EISDIR`.
    fn create<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
        options: &'a OpenOptions,
    ) -> BoxFuture<'a, (Entry, OpenRef)>;
    fn mkdir<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
    ) -> BoxFuture<'a, Entry>;
    fn mknod<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
        rdev: &'a str,
    ) -> BoxFuture<'a, Entry>;
    /// Create a Unix-domain socket inode (`S_IFSOCK`, `FileType::Socket`).
    /// Unlike `mknod` for character devices, any caller with write+search permission on `dir`
    /// may create a socket inode.
    fn mksock<'a>(
        &'a self,
        _cred: &'a Cred,
        _dir: &'a Handle,
        _name: &'a str,
        _mode: u16,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(async { Err(Errno::EOPNOTSUPP) })
    }
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
    /// Remove a newly created upload only if the same inode still occupies this name.
    /// Drivers implement the comparison under their directory mutation lock.
    fn unlink_if<'a>(
        &'a self,
        _cred: &'a Cred,
        _dir: &'a Handle,
        _name: &'a str,
        _node: NodeId,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async { Err(Errno::EOPNOTSUPP) })
    }
    fn rmdir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()>;
    #[allow(clippy::too_many_arguments)]
    fn rename<'a>(
        &'a self,
        cred: &'a Cred,
        from_dir: &'a Handle,
        from: &'a str,
        to_dir: &'a Handle,
        to: &'a str,
        flags: RenameFlags,
    ) -> BoxFuture<'a, ()>;

    fn getxattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Vec<u8>>;
    fn setxattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
        value: &'a [u8],
        flags: XattrFlags,
    ) -> BoxFuture<'a, ()>;
    fn listxattr<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Vec<String>>;
    fn removexattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, ()>;
    fn statfs<'a>(&'a self, cred: &'a Cred) -> BoxFuture<'a, StatFs>;

    /// Open an existing object, checking the access `options` ask once (contract §2.3). A
    /// directory opens only for reading or as a path. `truncate` needs write permission, even
    /// with read-only access, as on Linux, and empties a regular file in the same call.
    fn open<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        options: &'a OpenOptions,
    ) -> BoxFuture<'a, OpenRef>;
    /// fstat: metadata of a retained open, including path-only references. Remote drivers
    /// authenticate the current caller and validate the retained grant, not a cached token.
    fn open_metadata<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, Metadata>;
    /// pread: read into `buf` from `offset`, and say how much was read (0 at the end).
    /// Offsets above [`FILE_MAX`] and ranges that overflow it are invalid (EINVAL), even at
    /// EOF. An empty buffer still requires a valid offset.
    fn read_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a mut [u8],
        offset: u64,
    ) -> BoxFuture<'a, usize>;
    /// pwrite: write `buf` at `at`, and say where it went and how much went, which may be
    /// less than all of it (a short write). Nothing at all changes for an empty `buf`.
    fn write_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a [u8],
        at: WriteAt,
    ) -> BoxFuture<'a, Written>;
    /// ftruncate: a regular file open for writing only (EINVAL otherwise).
    fn set_len<'a>(&'a self, open: &'a OpenRef, size: u64) -> BoxFuture<'a, ()>;
    /// fsync: return after the driver's durability point (contract §3).
    fn sync_all<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()>;
    /// fdatasync: the data and what is needed to read it back, at least.
    fn sync_data<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        self.sync_all(open)
    }
    /// Synchronize a file or directory addressed by `handle` (`MS_DIRSYNC` / `MS_SYNCHRONOUS` on
    /// handle-based operations where the caller holds no [`OpenRef`]).
    fn sync_handle<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if self.capabilities().durability == abi::contract::Durability::Volatile {
                return Ok(());
            }
            // The mutation was authorized with the acting credential. This internal
            // description only flushes the inode, including write/search-only directories.
            let mut options = OpenOptions::new();
            options.read(true);
            let open = match self.open(cred, handle, &options).await {
                Err(Errno::EACCES) => {
                    let service = Cred {
                        identity: Identity::root(),
                        ..cred.clone()
                    };
                    self.open(&service, handle, &options).await?
                }
                result => result?,
            };
            let sync_res = self.sync_all(&open).await;
            let rel_res = self.release(&open).await;
            sync_res?;
            rel_res
        })
    }
    /// Take an advisory lock for `open`, waiting until it is granted (F_SETLKW, flock without
    /// LOCK_NB). Dropping the future gives up the wait. An fcntl wait that would deadlock fails
    /// with EDEADLK; flock does not detect deadlock, as on Linux.
    fn lock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, ()>;
    /// Take an advisory lock for `open`, or fail at once with EAGAIN (F_SETLK, LOCK_NB).
    fn try_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, ()>;
    fn unlock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        range: LockRange,
    ) -> BoxFuture<'a, ()>;
    /// F_GETLK: the first fcntl lock of another open reference that would conflict.
    fn test_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, Option<Conflict>>;
    /// End the open reference: its locks go, and an unlinked file's content goes with its last
    /// open reference.
    fn release<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()>;

    /// Cursor-based paged directory enumeration (R7, #77).
    /// - `cookie == 0` begins at the first entry.
    /// - `max_entries` is clamped to `DIR_PAGE_MAX`; `max_entries == 0` returns an empty page.
    /// - Drivers with native indexed directories (e.g. `CowFs` `DIR_INDEX`) override this to
    ///   enumerate O(page) entries without loading the whole directory into memory.
    fn read_dir_page<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        cookie: u64,
        max_entries: usize,
    ) -> BoxFuture<'a, DirPage> {
        Box::pin(async move {
            let all = self.read_dir(cred, dir).await?;
            let start = usize::try_from(cookie).unwrap_or(all.len()).min(all.len());
            if max_entries == 0 {
                let next_cookie = (start < all.len()).then_some(start as u64);
                return Ok(DirPage {
                    entries: Vec::new(),
                    next_cookie,
                });
            }
            let limit = max_entries.min(DIR_PAGE_MAX);
            let end = start.saturating_add(limit).min(all.len());
            let next_cookie = (end < all.len()).then_some(end as u64);
            Ok(DirPage {
                entries: all[start..end].to_vec(),
                next_cookie,
            })
        })
    }

    /// Intra-filesystem O(1) extent reflink (`FICLONE`, contract §5).
    /// Cross-filesystem calls are rejected by `Vfs` with `Errno::EXDEV`.
    fn reflink<'a>(
        &'a self,
        _cred: &'a Cred,
        _src_open: &'a OpenRef,
        _dst_open: &'a OpenRef,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async { Err(Errno::EOPNOTSUPP) })
    }

    /// Whole-filesystem durability barrier (`syncfs(2)`, contract §5).
    fn sync_fs<'a>(&'a self, _cred: &'a Cred) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if self.capabilities().durability == abi::contract::Durability::Volatile {
                Ok(())
            } else {
                Err(Errno::EOPNOTSUPP)
            }
        })
    }
}

/// Poll a future once: its output if it is ready, as `futures::FutureExt::now_or_never`.
/// Tests and synchronous callers use this for calls that cannot wait. A contended lock can
/// return `None`, which cancels its wait when this helper drops the future.
pub fn now_or_never<F: Future>(future: F) -> Option<F::Output> {
    let mut future = std::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => Some(value),
        Poll::Pending => None,
    }
}
