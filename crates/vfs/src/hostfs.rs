//! Browser host-backed filesystem drivers (contract §2.2, §2.5, §2.12, §3, §5):
//! - [`HostFs::opfs`]: browser storage (`os-workspace` in OPFS, [`profiles::OPFS`]).
//! - [`HostFs::directory`]: host folder via a browser directory handle
//!   ([`profiles::DIRECTORY_HANDLE`]).
//!
//! Portable by construction: all POSIX permission, ACL, xattr, creation, open-unlink/rename,
//! fingerprint validation, store format versioning, and advisory lock rules live here in Rust
//! over [`HostTree`], [`MetaStore`], and [`ProfileLocks`]. No `wasm-bindgen`, `js-sys`, or DOM
//! types enter `os-vfs`.

mod locking;
pub mod mem;
mod ops;

use crate::locks::Locks;
use crate::{
    Access, BoxFuture, Conflict, Cred, DirEntry, Entry, FileType, Filesystem, FsId, Handle,
    Identity, LockFamily, LockKind, LockRange, Metadata, OpenOptions, OpenRef, RenameFlags, Result,
    SetAttr, StatFs, Timespec, Walked, WriteAt, Written, XattrFlags, profiles,
};
use abi::Errno;
use abi::contract::FsCapabilities;
use os_core::permissions::Node;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// Explicit durable metadata store format version (contract §2.12).
/// Older versions reset metadata once (never deleting user files); newer versions fail with
/// `Errno::EPROTONOSUPPORT` without modifying the store.
pub const STORE_FORMAT_VERSION: u32 = 3;

/// Fixed root directory inode number.
pub const ROOT_INO: u64 = 1;

/// Seconds and nanoseconds since 1970.
pub type Clock = Box<dyn Fn() -> (u64, u32)>;

/// Which browser host backend backs a [`HostFs`] instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostKind {
    Opfs,
    Directory,
}

/// Host capability ceiling granted at mount/attach time (contract §2.5, §2.12).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HostGrant {
    pub owner: Identity,
    pub read_only: bool,
    pub execute: bool,
}

/// Host file identity fingerprint recorded at the last OS observation or write.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fingerprint {
    pub size: u64,
    pub mtime_ns: u64,
}

/// Host entry attributes observed directly from the underlying OPFS or directory handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostEntry {
    pub file_type: FileType,
    pub size: u64,
    pub mtime: Timespec,
    pub fingerprint: Fingerprint,
    #[serde(default)]
    pub executable: bool,
}

/// Where an inode's backing content resides on the host.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Backing {
    /// Content resides at this mount-relative path inside `os-workspace` or the host folder.
    Path(String),
    /// Unlinked OPFS file still held open by at least one tab (`/os-orphans/<uuid>/<ino>`).
    Orphan(u64),
    /// Metadata-only object (emulated symlink, char device, or unlinked open directory).
    MetaOnly,
}

/// Crash-recovery journal record persisted in [`StoreHeader`] while staging an OPFS rename.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRename {
    pub from_path: String,
    pub to_path: String,
    pub is_dir: bool,
    pub source_has_path: bool,
    pub staged_target_ino: Option<u64>,
    pub staged_other_path: Option<String>,
    pub removed_empty_dir: bool,
}

/// Crash-recovery journal record persisted in [`StoreHeader`] while truncating an existing file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingTruncate {
    pub ino: u64,
    pub backing: Backing,
    pub target_mode: u16,
}

/// Persistent header stored in [`MetaStore`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreHeader {
    pub format_version: u32,
    pub uuid: String,
    pub next_ino: u64,
    pub next_open_id: u64,
    pub pending_rename: Option<PendingRename>,
    #[serde(default)]
    pub pending_truncate: Option<PendingTruncate>,
}

/// Persistent inode record stored in [`MetaStore`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InodeRecord {
    pub ino: u64,
    pub meta: Node,
    pub nlink: u32,
    pub size: u64,
    /// Directory child map (`name -> child_ino`), empty for non-directories.
    #[serde(default)]
    pub entries: BTreeMap<String, u64>,
    /// Directory's own parent inode (`ROOT_INO` for root).
    pub parent: u64,
    /// Directory's own entry name in `parent` (`""` for root).
    pub name: String,
    /// All live `(parent_dir_ino, entry_name)` links to a non-directory inode.
    #[serde(default)]
    pub parents: BTreeSet<(u64, String)>,
    #[serde(default)]
    pub xattrs: BTreeMap<String, Vec<u8>>,
    pub atime: (u64, u32),
    pub mtime: (u64, u32),
    pub ctime: (u64, u32),
    pub backing: Backing,
    #[serde(default)]
    pub fingerprint: Option<Fingerprint>,
    /// Set on directory-handle inodes once unlinked, overwritten, or changed outside the OS.
    #[serde(default)]
    pub stale: bool,
}

impl InodeRecord {
    pub fn file_type(&self) -> FileType {
        if self.meta.directory {
            FileType::Dir
        } else if self.meta.link.is_some() {
            FileType::Symlink
        } else if self.meta.rdev.is_some() {
            FileType::CharDevice
        } else {
            FileType::File
        }
    }

    pub fn removed(&self) -> bool {
        self.nlink == 0
    }
}

/// Atomic metadata write batch committed in a single IndexedDB transaction.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MetaBatch {
    pub header: Option<StoreHeader>,
    pub put_inodes: Vec<InodeRecord>,
    pub delete_inodes: Vec<u64>,
    pub put_locks: Vec<(u64, Locks)>,
    pub delete_locks: Vec<u64>,
}

/// RAII guard for a held profile-wide Web Lock; dropping releases the Web Lock.
pub trait LockGuard {}

/// Host I/O primitives over an OPFS `os-workspace` tree or a browser `FileSystemDirectoryHandle`.
pub trait HostTree {
    fn stat_path<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Option<HostEntry>>;
    fn list_dir<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Vec<(String, HostEntry)>>;
    fn create_file<'a>(
        &'a self,
        path: &'a str,
        create_new: bool,
        truncate: bool,
    ) -> BoxFuture<'a, HostEntry>;
    fn create_dir<'a>(&'a self, path: &'a str) -> BoxFuture<'a, HostEntry>;
    fn read_file<'a>(
        &'a self,
        backing: &'a Backing,
        offset: u64,
        len: usize,
        expected_fp: Option<Fingerprint>,
        expected_ino: Option<u64>,
    ) -> BoxFuture<'a, Vec<u8>>;
    fn write_file<'a>(
        &'a self,
        backing: &'a Backing,
        offset: u64,
        data: &'a [u8],
        append: bool,
        expected_fp: Option<Fingerprint>,
        expected_ino: Option<u64>,
    ) -> BoxFuture<'a, (Written, Fingerprint)>;
    fn set_file_len<'a>(
        &'a self,
        backing: &'a Backing,
        size: u64,
        expected_fp: Option<Fingerprint>,
        expected_ino: Option<u64>,
    ) -> BoxFuture<'a, Fingerprint>;
    fn flush_file<'a>(
        &'a self,
        backing: &'a Backing,
        data_only: bool,
        expected_fp: Option<Fingerprint>,
        expected_ino: Option<u64>,
    ) -> BoxFuture<'a, Fingerprint>;
    /// Retain the validated host directory/file entry handle for `ino` so subsequent lookups can
    /// verify object identity (`isSameEntry`) rather than accepting a path-matched replacement.
    fn retain_host_entry<'a>(&'a self, ino: u64, path: &'a str, is_dir: bool) -> BoxFuture<'a, ()>;
    /// Verify that the live host entry at `path` still matches the retained handle for `ino`.
    fn verify_host_entry<'a>(
        &'a self,
        ino: u64,
        path: &'a str,
        is_dir: bool,
    ) -> BoxFuture<'a, bool>;
    /// Drop any retained host handle associated with a stale or removed inode.
    fn forget_host_entry<'a>(&'a self, ino: u64) -> BoxFuture<'a, ()>;
    fn remove_file<'a>(&'a self, path: &'a str) -> BoxFuture<'a, ()>;
    fn remove_dir<'a>(&'a self, path: &'a str) -> BoxFuture<'a, ()>;
    /// Move a file or directory from `from` to `to`, returning any updated `(rel_path, fingerprint)`
    /// pairs for moved regular files.
    fn move_entry<'a>(
        &'a self,
        from: &'a str,
        to: &'a str,
        is_dir: bool,
    ) -> BoxFuture<'a, Vec<(String, Fingerprint)>>;
    /// Move `os-workspace/<path>` to `/os-orphans/<uuid>/<ino>` when unlinking an open OPFS file.
    fn move_to_orphan<'a>(&'a self, path: &'a str, ino: u64) -> BoxFuture<'a, ()>;
    /// Restore `/os-orphans/<uuid>/<ino>` back to `os-workspace/<to>` if a staged replacement fails.
    fn restore_orphan<'a>(&'a self, ino: u64, to: &'a str) -> BoxFuture<'a, ()>;
    /// Remove `/os-orphans/<uuid>/<ino>` after the last open reference closes or during crash sweep.
    fn remove_orphan(&self, ino: u64) -> BoxFuture<'_, ()>;
    /// List `<ino>` entries present under `/os-orphans/<uuid>/`.
    fn list_orphans(&self) -> BoxFuture<'_, Vec<u64>>;
}

/// Durable IndexedDB-backed metadata and byte-range lock store shared across tabs of the profile.
pub trait MetaStore {
    /// Return the stored format version BEFORE deserializing `StoreHeader`, so a newer release's
    /// schema changes still fail cleanly with `Errno::EPROTONOSUPPORT` instead of a parse error.
    fn read_version(&self) -> BoxFuture<'_, Option<u32>>;
    fn read_header(&self) -> BoxFuture<'_, Option<StoreHeader>>;
    /// Clear metadata/lock records only (never user files) and write `header` + `root` with strict
    /// durability.
    fn reset_to_current(&self, header: StoreHeader, root: InodeRecord) -> BoxFuture<'_, ()>;
    /// Mint a fresh profile-local UUID string when initializing an unversioned store.
    fn mint_uuid(&self) -> BoxFuture<'_, String>;
    fn get_inode(&self, ino: u64) -> BoxFuture<'_, Option<InodeRecord>>;
    fn find_by_backing<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Option<InodeRecord>>;
    fn list_all_inodes(&self) -> BoxFuture<'_, Vec<InodeRecord>>;
    fn get_locks(&self, ino: u64) -> BoxFuture<'_, Locks>;
    fn list_all_locks(&self) -> BoxFuture<'_, Vec<(u64, Locks)>>;
    fn commit(&self, batch: MetaBatch, strict: bool) -> BoxFuture<'_, ()>;
    fn sync_strict(&self) -> BoxFuture<'_, ()>;
}

/// Profile-wide named Web Locks coordinator (`navigator.locks` + cross-tab wake broadcast).
pub trait ProfileLocks {
    fn acquire<'a>(&'a self, name: &'a str, kind: LockKind) -> BoxFuture<'a, Box<dyn LockGuard>>;
    fn try_acquire<'a>(
        &'a self,
        name: &'a str,
        kind: LockKind,
    ) -> BoxFuture<'a, Option<Box<dyn LockGuard>>>;
    fn held_locks(&self) -> BoxFuture<'_, HashSet<String>>;
    fn notify_locks(&self);
    fn wait_for_change<'a>(&'a self, blocking_locks: &'a [String]) -> BoxFuture<'a, ()>;
    /// Unique ticket string for a pending blocking lock wait.
    fn new_ticket(&self) -> String;
}

struct OpenEntry {
    ino: u64,
    access: Access,
    cred: Identity,
    _open_guard: Box<dyn LockGuard>,
}

struct LocalState {
    opens: HashMap<u64, OpenEntry>,
}

/// Portable browser filesystem driver implementing [`Filesystem`] for OPFS and directory handles.
pub struct HostFs<T: HostTree, M: MetaStore, L: ProfileLocks> {
    kind: HostKind,
    id: FsId,
    uuid: String,
    generation: u64,
    grant: HostGrant,
    tree: T,
    meta: M,
    locks: L,
    clock: Clock,
    local: RefCell<LocalState>,
}

impl<T: HostTree, M: MetaStore, L: ProfileLocks> HostFs<T, M, L> {
    /// Mount browser storage (`os-workspace` in OPFS, `FsId("opfs:<uuid>")`), enforcing format
    /// version rules and sweeping any unlinked orphan files left by crashed tabs.
    pub async fn opfs(
        grant: HostGrant,
        generation: u64,
        tree: T,
        meta: M,
        locks: L,
        clock: Clock,
    ) -> Result<Self> {
        Self::init(HostKind::Opfs, grant, generation, tree, meta, locks, clock).await
    }

    /// Mount a host folder (`FileSystemDirectoryHandle`, `FsId("hostfs:<uuid>")`), enforcing
    /// format version rules without ever writing sidecar files into the user's folder.
    pub async fn directory(
        grant: HostGrant,
        generation: u64,
        tree: T,
        meta: M,
        locks: L,
        clock: Clock,
    ) -> Result<Self> {
        Self::init(
            HostKind::Directory,
            grant,
            generation,
            tree,
            meta,
            locks,
            clock,
        )
        .await
    }

    async fn init(
        kind: HostKind,
        grant: HostGrant,
        generation: u64,
        tree: T,
        meta: M,
        locks: L,
        clock: Clock,
    ) -> Result<Self> {
        let uuid = {
            let _mint_guard = locks.acquire("os-fs-mint", LockKind::Exclusive).await?;
            match meta.read_version().await? {
                Some(v) if v > STORE_FORMAT_VERSION => return Err(Errno::EPROTONOSUPPORT),
                Some(v) if v < STORE_FORMAT_VERSION => {
                    let uuid = match meta.read_header().await.ok().flatten() {
                        Some(h) if !h.uuid.is_empty() => h.uuid,
                        _ => meta.mint_uuid().await?,
                    };
                    let now = clock();
                    let root = Self::default_root(&grant, now);
                    let header = StoreHeader {
                        format_version: STORE_FORMAT_VERSION,
                        uuid: uuid.clone(),
                        next_ino: ROOT_INO + 1,
                        next_open_id: 1,
                        pending_rename: None,
                        pending_truncate: None,
                    };
                    meta.reset_to_current(header, root).await?;
                    uuid
                }
                Some(_) => {
                    let header = meta.read_header().await?.ok_or(Errno::EIO)?;
                    if meta.get_inode(ROOT_INO).await?.is_none() {
                        let now = clock();
                        let root = Self::default_root(&grant, now);
                        meta.commit(
                            MetaBatch {
                                put_inodes: vec![root],
                                ..MetaBatch::default()
                            },
                            true,
                        )
                        .await?;
                    }
                    header.uuid
                }
                None => {
                    let uuid = meta.mint_uuid().await?;
                    let now = clock();
                    let root = Self::default_root(&grant, now);
                    let header = StoreHeader {
                        format_version: STORE_FORMAT_VERSION,
                        uuid: uuid.clone(),
                        next_ino: ROOT_INO + 1,
                        next_open_id: 1,
                        pending_rename: None,
                        pending_truncate: None,
                    };
                    meta.reset_to_current(header, root).await?;
                    uuid
                }
            }
        };

        let prefix = match kind {
            HostKind::Opfs => "opfs",
            HostKind::Directory => "hostfs",
        };
        let fs = Self {
            kind,
            id: FsId(format!("{prefix}:{uuid}")),
            uuid,
            generation,
            grant,
            tree,
            meta,
            locks,
            clock,
            local: RefCell::new(LocalState {
                opens: HashMap::new(),
            }),
        };

        if kind == HostKind::Opfs {
            fs.sweep_orphans().await?;
        }
        Ok(fs)
    }

    fn default_root(grant: &HostGrant, now: (u64, u32)) -> InodeRecord {
        let mut node = Node::directory(grant.owner.id, grant.owner.group, 0o700);
        node.ino = ROOT_INO;
        InodeRecord {
            ino: ROOT_INO,
            meta: node,
            nlink: 2,
            size: 0,
            entries: BTreeMap::new(),
            parent: ROOT_INO,
            name: String::new(),
            parents: BTreeSet::new(),
            xattrs: BTreeMap::new(),
            atime: now,
            mtime: now,
            ctime: now,
            backing: Backing::Path(String::new()),
            fingerprint: None,
            stale: false,
        }
    }

    pub fn uuid(&self) -> &str {
        &self.uuid
    }

    pub fn grant(&self) -> &HostGrant {
        &self.grant
    }
}

impl<T: HostTree, M: MetaStore, L: ProfileLocks> Filesystem for HostFs<T, M, L> {
    fn id(&self) -> &FsId {
        &self.id
    }

    fn capabilities(&self) -> FsCapabilities {
        match self.kind {
            HostKind::Opfs => profiles::OPFS,
            HostKind::Directory => profiles::DIRECTORY_HANDLE,
        }
    }

    fn root(&self) -> Handle {
        self.make_handle(ROOT_INO)
    }

    fn lookup<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(self.do_lookup(cred, dir, name))
    }

    fn walk<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        names: &'a [String],
    ) -> BoxFuture<'a, Walked> {
        Box::pin(self.do_walk(cred, dir, names))
    }

    fn parent<'a>(
        &'a self,
        _cred: &'a Cred,
        dir: &'a Handle,
    ) -> BoxFuture<'a, Option<(Entry, String)>> {
        Box::pin(self.do_parent(dir))
    }

    fn metadata<'a>(&'a self, _cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Metadata> {
        Box::pin(self.do_metadata(handle))
    }

    fn open_metadata<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, Metadata> {
        Box::pin(self.do_open_metadata(open))
    }

    fn setattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        attr: &'a SetAttr,
    ) -> BoxFuture<'a, Metadata> {
        Box::pin(self.do_setattr(cred, handle, attr))
    }

    fn read_dir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle) -> BoxFuture<'a, Vec<DirEntry>> {
        Box::pin(self.do_read_dir(cred, dir))
    }

    fn read_link<'a>(&'a self, _cred: &'a Cred, link: &'a Handle) -> BoxFuture<'a, String> {
        Box::pin(self.do_read_link(link))
    }

    fn create<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
        options: &'a OpenOptions,
    ) -> BoxFuture<'a, (Entry, OpenRef)> {
        Box::pin(self.do_create(cred, dir, name, mode, options))
    }

    fn mkdir<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(self.do_mkdir(cred, dir, name, mode))
    }

    fn mknod<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
        rdev: &'a str,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(self.do_mknod(cred, dir, name, mode, rdev))
    }

    fn symlink<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        target: &'a str,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(self.do_symlink(cred, dir, name, target))
    }

    fn link<'a>(
        &'a self,
        cred: &'a Cred,
        target: &'a Handle,
        dir: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(self.do_link(cred, target, dir, name))
    }

    fn unlink<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(self.do_remove(cred, dir, name, false, None))
    }

    fn unlink_if<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        node: crate::NodeId,
    ) -> BoxFuture<'a, ()> {
        Box::pin(self.do_remove(cred, dir, name, false, Some(node)))
    }
    fn rmdir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(self.do_remove(cred, dir, name, true, None))
    }

    fn rename<'a>(
        &'a self,
        cred: &'a Cred,
        from_dir: &'a Handle,
        from: &'a str,
        to_dir: &'a Handle,
        to: &'a str,
        flags: RenameFlags,
    ) -> BoxFuture<'a, ()> {
        Box::pin(self.do_rename(cred, from_dir, from, to_dir, to, flags))
    }

    fn getxattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(self.do_getxattr(cred, handle, name))
    }

    fn setxattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
        value: &'a [u8],
        flags: XattrFlags,
    ) -> BoxFuture<'a, ()> {
        Box::pin(self.do_setxattr(cred, handle, name, value, flags))
    }

    fn listxattr<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Vec<String>> {
        Box::pin(self.do_listxattr(cred, handle))
    }

    fn removexattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, ()> {
        Box::pin(self.do_removexattr(cred, handle, name))
    }

    fn statfs<'a>(&'a self, _cred: &'a Cred) -> BoxFuture<'a, StatFs> {
        Box::pin(self.do_statfs())
    }

    fn open<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        options: &'a OpenOptions,
    ) -> BoxFuture<'a, OpenRef> {
        Box::pin(self.do_open(cred, handle, options))
    }

    fn read_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a mut [u8],
        offset: u64,
    ) -> BoxFuture<'a, usize> {
        Box::pin(self.do_read_at(open, buf, offset))
    }

    fn write_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a [u8],
        at: WriteAt,
    ) -> BoxFuture<'a, Written> {
        Box::pin(self.do_write_at(open, buf, at))
    }

    fn set_len<'a>(&'a self, open: &'a OpenRef, size: u64) -> BoxFuture<'a, ()> {
        Box::pin(self.do_set_len(open, size))
    }

    fn sync_all<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        Box::pin(self.do_sync(open, false))
    }

    fn sync_data<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        Box::pin(self.do_sync(open, true))
    }

    fn sync_handle<'a>(&'a self, _cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, ()> {
        Box::pin(self.do_sync_handle(handle))
    }

    fn lock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        Box::pin(self.do_lock(open, family, kind, range))
    }

    fn try_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        Box::pin(self.do_try_lock(open, family, kind, range))
    }

    fn unlock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        Box::pin(self.do_unlock(open, family, range))
    }

    fn test_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, Option<Conflict>> {
        Box::pin(self.do_test_lock(open, kind, range))
    }

    fn release<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        Box::pin(self.do_release(open))
    }
}
