//! Read-only content-addressed image filesystem driver (`image` fstype, contract §2.7, §3, §5).
//! Backs system `/usr` (`sysext`/`confext` bind mounts), unsigned local build-asset `/usr`, and
//! user private extensions at `/opt/private/<name>`.

use crate::{
    Access, BoxFuture, Conflict, Cred, DirEntry, Entry, FILE_MAX, FileType, Filesystem, FsId,
    Handle, LockFamily, LockKind, LockRange, Metadata, NodeId, OpenOptions, OpenRef, RenameFlags,
    Result, SetAttr, StatFs, Stop, Timespec, Walked, WriteAt, Written, XattrFlags, check_component,
    profiles,
};
use abi::Errno;
use abi::contract::FsCapabilities;
use os_core::inode;
use os_core::permissions::{EXEC, Node, READ};
use os_core::xattr::{self, Space};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

const ROOT_INO: u64 = 1;
const GENERATION: u64 = 1;
const BLOCK_SIZE: u64 = 4096;

/// Content-addressed or URL-addressed byte store backing [`ImageFs`] regular files.
pub trait BlobStore {
    fn read_at<'a>(
        &'a self,
        blob_id: &'a str,
        offset: u64,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, usize>;
}

/// In-memory [`BlobStore`] keyed by `blob_id` (`sha256` digest or asset path).
#[derive(Clone, Debug, Default)]
pub struct MemoryBlobStore {
    blobs: BTreeMap<String, Vec<u8>>,
}

impl MemoryBlobStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, blob_id: impl Into<String>, bytes: Vec<u8>) {
        self.blobs.insert(blob_id.into(), bytes);
    }
}

impl BlobStore for MemoryBlobStore {
    fn read_at<'a>(
        &'a self,
        blob_id: &'a str,
        offset: u64,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, usize> {
        Box::pin(async move {
            let Some(bytes) = self.blobs.get(blob_id) else {
                return Err(Errno::EIO);
            };
            if offset >= bytes.len() as u64 {
                return Ok(0);
            }
            let start = offset as usize;
            let len = (bytes.len() - start).min(buf.len());
            buf[..len].copy_from_slice(&bytes[start..start + len]);
            Ok(len)
        })
    }
}

/// Manifest entry consumed by [`ImageFs`] (compatible with `os_image::Entry` JSON).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageEntry {
    pub path: String,
    pub uid: u32,
    pub gid: u32,
    pub mode: u16,
    pub node: ImageNodeKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ImageNodeKind {
    Directory,
    File {
        #[serde(alias = "sha256")]
        blob_id: String,
        size: u64,
    },
    Symlink {
        target: String,
    },
}

/// Build-asset Wasm binary sizes for unsigned local development `/usr` mounts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildAssetSizes {
    pub coreutils: u64,
    pub utilities: u64,
    pub dash: u64,
    pub supervise: u64,
    pub init: u64,
}

struct ImageNode {
    ino: u64,
    meta: Node,
    nlink: u32,
    size: u64,
    blob_id: Option<String>,
    parent: u64,
    name: String,
    children: BTreeMap<String, u64>,
}

impl ImageNode {
    fn file_type(&self) -> FileType {
        if self.meta.directory {
            FileType::Dir
        } else if self.meta.link.is_some() {
            FileType::Symlink
        } else {
            FileType::File
        }
    }
}

struct OpenRecord {
    ino: u64,
    access: Access,
}

#[derive(Clone, Copy)]
struct Lock {
    owner: u64,
    family: LockFamily,
    kind: LockKind,
    range: LockRange,
}

impl Lock {
    fn conflicts(self, other: Lock) -> bool {
        self.owner != other.owner
            && self.family == other.family
            && self.range.overlaps(other.range)
            && (self.kind == LockKind::Exclusive || other.kind == LockKind::Exclusive)
    }
}

struct Waiter {
    ino: u64,
    lock: Lock,
    waker: Waker,
}

#[derive(Default)]
struct RuntimeState {
    next_open: u64,
    opens: HashMap<u64, OpenRecord>,
    locks: HashMap<u64, Vec<Lock>>,
    waiters: HashMap<u64, Waiter>,
    next_waiter: u64,
}

pub struct ImageFs<B> {
    fs_id: FsId,
    global_identity: bool,
    nodes: HashMap<u64, ImageNode>,
    path_index: BTreeMap<String, u64>,
    total_bytes: u64,
    mounted_at: Timespec,
    blobs: B,
    state: RefCell<RuntimeState>,
}

fn clean_image_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= abi::PATH_MAX
        && !path.contains('\0')
        && (path == "/"
            || (!path.ends_with('/')
                && path[1..]
                    .split('/')
                    .all(|p| !p.is_empty() && p != "." && p != ".." && p.len() <= abi::NAME_MAX)))
}

fn parent_and_name(path: &str) -> (&str, &str) {
    match path.rsplit_once('/') {
        Some(("", name)) => ("/", name),
        Some((parent, name)) => (parent, name),
        None => ("/", ""),
    }
}

fn carve(locks: &mut Vec<Lock>, owner: u64, family: LockFamily, range: LockRange) {
    let mut pieces = Vec::new();
    locks.retain(|lock| {
        let cut = lock.owner == owner && lock.family == family && lock.range.overlaps(range);
        if cut {
            pieces.extend(
                lock.range
                    .minus(range)
                    .into_iter()
                    .flatten()
                    .map(|rest| Lock {
                        range: rest,
                        ..*lock
                    }),
            );
        }
        !cut
    });
    locks.extend(pieces);
}

impl<B: BlobStore> ImageFs<B> {
    pub fn new(
        fs_id: FsId,
        global_identity: bool,
        mounted_at: Timespec,
        entries: impl IntoIterator<Item = ImageEntry>,
        blobs: B,
    ) -> Result<Self> {
        let mut by_path: BTreeMap<String, ImageEntry> = BTreeMap::new();
        for entry in entries {
            if !clean_image_path(&entry.path) || entry.mode > 0o7777 {
                return Err(Errno::EINVAL);
            }
            if let ImageNodeKind::Symlink { target } = &entry.node {
                inode::check_link_target(target)?;
            }
            if let ImageNodeKind::File { size, .. } = &entry.node
                && *size > FILE_MAX
            {
                return Err(Errno::EFBIG);
            }
            if by_path.insert(entry.path.clone(), entry).is_some() {
                return Err(Errno::EINVAL);
            }
        }

        // Synthesize missing ancestor directories (0o755 root:root) so partial compositions work
        // cleanly while rejecting non-directory ancestors.
        by_path.entry("/".to_string()).or_insert(ImageEntry {
            path: "/".to_string(),
            uid: 0,
            gid: 0,
            mode: 0o755,
            node: ImageNodeKind::Directory,
        });
        if !matches!(by_path["/"].node, ImageNodeKind::Directory) {
            return Err(Errno::EINVAL);
        }

        let all_paths: Vec<String> = by_path.keys().cloned().collect();
        for path in all_paths {
            let mut cur = path.as_str();
            while cur != "/" {
                let (par, _) = parent_and_name(cur);
                match by_path.get(par) {
                    Some(existing) => {
                        if !matches!(existing.node, ImageNodeKind::Directory) {
                            return Err(Errno::EINVAL);
                        }
                    }
                    None => {
                        by_path.insert(
                            par.to_string(),
                            ImageEntry {
                                path: par.to_string(),
                                uid: 0,
                                gid: 0,
                                mode: 0o755,
                                node: ImageNodeKind::Directory,
                            },
                        );
                    }
                }
                cur = par;
            }
        }

        let mut path_index: BTreeMap<String, u64> = BTreeMap::new();
        let mut nodes: HashMap<u64, ImageNode> = HashMap::new();
        let mut total_bytes = 0u64;

        for (ino, path) in (ROOT_INO..).zip(by_path.keys()) {
            path_index.insert(path.clone(), ino);
        }

        for (path, entry) in &by_path {
            let ino = path_index[path];
            let (parent_ino, name) = if path == "/" {
                (ROOT_INO, String::new())
            } else {
                let (par, nm) = parent_and_name(path);
                (path_index[par], nm.to_string())
            };
            let (mut meta, size, blob_id, nlink) = match &entry.node {
                ImageNodeKind::Directory => (
                    Node::directory(entry.uid, entry.gid, entry.mode),
                    BLOCK_SIZE,
                    None,
                    2u32,
                ),
                ImageNodeKind::File { blob_id, size } => {
                    total_bytes = total_bytes.saturating_add(*size);
                    (
                        Node::file(entry.uid, entry.gid, entry.mode, blob_id.clone(), *size),
                        *size,
                        Some(blob_id.clone()),
                        1u32,
                    )
                }
                ImageNodeKind::Symlink { target } => {
                    let mut n = Node::symlink(entry.uid, entry.gid, target);
                    n.mode = entry.mode;
                    (n, target.len() as u64, None, 1u32)
                }
            };
            meta.ino = ino;
            nodes.insert(
                ino,
                ImageNode {
                    ino,
                    meta,
                    nlink,
                    size,
                    blob_id,
                    parent: parent_ino,
                    name,
                    children: BTreeMap::new(),
                },
            );
        }

        // Wire directory `children` and subdirectory `nlink` counts.
        let child_links: Vec<(u64, String, u64, bool)> = nodes
            .values()
            .filter(|n| n.ino != ROOT_INO)
            .map(|n| (n.parent, n.name.clone(), n.ino, n.meta.directory))
            .collect();
        for (parent_ino, name, child_ino, is_dir) in child_links {
            let parent = nodes.get_mut(&parent_ino).expect("validated parent");
            parent.children.insert(name, child_ino);
            if is_dir {
                parent.nlink = parent.nlink.saturating_add(1);
            }
        }

        Ok(Self {
            fs_id,
            global_identity,
            nodes,
            path_index,
            total_bytes,
            mounted_at,
            blobs,
            state: RefCell::new(RuntimeState {
                next_open: 1,
                next_waiter: 1,
                ..RuntimeState::default()
            }),
        })
    }

    /// Construct [`ImageFs`] from `os_image::Composition` JSON (`{"entries": {...}}`, `{...}`, or `[...]`).
    pub fn from_composition_json(
        fs_id: FsId,
        global_identity: bool,
        mounted_at: Timespec,
        json_text: &str,
        blobs: B,
    ) -> Result<Self> {
        let value: Value = serde_json::from_str(json_text).map_err(|_| Errno::EINVAL)?;
        let entries_val = value.get("entries").unwrap_or(&value);
        let entries: Vec<ImageEntry> = if entries_val.is_object() {
            let map: BTreeMap<String, ImageEntry> =
                serde_json::from_value(entries_val.clone()).map_err(|_| Errno::EINVAL)?;
            map.into_values().collect()
        } else {
            serde_json::from_value(entries_val.clone()).map_err(|_| Errno::EINVAL)?
        };
        Self::new(fs_id, global_identity, mounted_at, entries, blobs)
    }

    /// Construct [`ImageFs`] from unsigned local build assets matching the merged-`/usr` tree.
    pub fn from_build_assets(
        fs_id: FsId,
        sizes: BuildAssetSizes,
        mounted_at: Timespec,
        blobs: B,
    ) -> Self {
        let mut entries = vec![
            ImageEntry {
                path: "/".into(),
                uid: 0,
                gid: 0,
                mode: 0o755,
                node: ImageNodeKind::Directory,
            },
            ImageEntry {
                path: "/bin".into(),
                uid: 0,
                gid: 0,
                mode: 0o777,
                node: ImageNodeKind::Symlink {
                    target: "usr/bin".into(),
                },
            },
            ImageEntry {
                path: "/lib".into(),
                uid: 0,
                gid: 0,
                mode: 0o777,
                node: ImageNodeKind::Symlink {
                    target: "usr/lib".into(),
                },
            },
            ImageEntry {
                path: "/lib64".into(),
                uid: 0,
                gid: 0,
                mode: 0o777,
                node: ImageNodeKind::Symlink {
                    target: "usr/lib".into(),
                },
            },
            ImageEntry {
                path: "/sbin".into(),
                uid: 0,
                gid: 0,
                mode: 0o777,
                node: ImageNodeKind::Symlink {
                    target: "usr/bin".into(),
                },
            },
            ImageEntry {
                path: "/sys".into(),
                uid: 0,
                gid: 0,
                mode: 0o555,
                node: ImageNodeKind::Directory,
            },
            ImageEntry {
                path: "/usr".into(),
                uid: 0,
                gid: 0,
                mode: 0o755,
                node: ImageNodeKind::Directory,
            },
            ImageEntry {
                path: "/usr/bin".into(),
                uid: 0,
                gid: 0,
                mode: 0o755,
                node: ImageNodeKind::Directory,
            },
            ImageEntry {
                path: "/usr/include".into(),
                uid: 0,
                gid: 0,
                mode: 0o755,
                node: ImageNodeKind::Directory,
            },
            ImageEntry {
                path: "/usr/lib".into(),
                uid: 0,
                gid: 0,
                mode: 0o755,
                node: ImageNodeKind::Directory,
            },
            ImageEntry {
                path: "/usr/lib64".into(),
                uid: 0,
                gid: 0,
                mode: 0o777,
                node: ImageNodeKind::Symlink {
                    target: "lib".into(),
                },
            },
            ImageEntry {
                path: "/usr/libexec".into(),
                uid: 0,
                gid: 0,
                mode: 0o755,
                node: ImageNodeKind::Directory,
            },
            ImageEntry {
                path: "/usr/local".into(),
                uid: 0,
                gid: 0,
                mode: 0o755,
                node: ImageNodeKind::Directory,
            },
            ImageEntry {
                path: "/usr/sbin".into(),
                uid: 0,
                gid: 0,
                mode: 0o777,
                node: ImageNodeKind::Symlink {
                    target: "bin".into(),
                },
            },
            ImageEntry {
                path: "/usr/share".into(),
                uid: 0,
                gid: 0,
                mode: 0o755,
                node: ImageNodeKind::Directory,
            },
            ImageEntry {
                path: "/usr/src".into(),
                uid: 0,
                gid: 0,
                mode: 0o755,
                node: ImageNodeKind::Directory,
            },
            ImageEntry {
                path: "/usr/bin/init".into(),
                uid: 0,
                gid: 0,
                mode: 0o755,
                node: ImageNodeKind::File {
                    blob_id: "/usr/bin/init.wasm".into(),
                    size: sizes.init,
                },
            },
            ImageEntry {
                path: "/usr/bin/supervise".into(),
                uid: 0,
                gid: 0,
                mode: 0o755,
                node: ImageNodeKind::File {
                    blob_id: "/usr/bin/supervise.wasm".into(),
                    size: sizes.supervise,
                },
            },
            ImageEntry {
                path: "/usr/bin/dash".into(),
                uid: 0,
                gid: 0,
                mode: 0o755,
                node: ImageNodeKind::File {
                    blob_id: "/usr/bin/dash.wasm".into(),
                    size: sizes.dash,
                },
            },
            ImageEntry {
                path: "/usr/bin/sh".into(),
                uid: 0,
                gid: 0,
                mode: 0o777,
                node: ImageNodeKind::Symlink {
                    target: "dash".into(),
                },
            },
            ImageEntry {
                path: "/usr/bin/coreutils".into(),
                uid: 0,
                gid: 0,
                mode: 0o755,
                node: ImageNodeKind::File {
                    blob_id: "/usr/bin/coreutils.wasm".into(),
                    size: sizes.coreutils,
                },
            },
            ImageEntry {
                path: "/usr/bin/utilities".into(),
                uid: 0,
                gid: 0,
                mode: 0o755,
                node: ImageNodeKind::File {
                    blob_id: "/usr/bin/utilities.wasm".into(),
                    size: sizes.utilities,
                },
            },
        ];

        for (names, target) in [
            (os_core::bin::PROGRAMS, "coreutils"),
            (os_core::bin::UTILITIES, "utilities"),
        ] {
            for &name in names {
                entries.push(ImageEntry {
                    path: format!("/usr/bin/{name}"),
                    uid: 0,
                    gid: 0,
                    mode: 0o777,
                    node: ImageNodeKind::Symlink {
                        target: target.into(),
                    },
                });
            }
        }

        Self::new(fs_id, true, mounted_at, entries, blobs)
            .expect("built-in system image tree is valid")
    }

    pub fn handle_at(&self, path: &str) -> Option<Handle> {
        self.path_index.get(path).map(|&ino| self.handle(ino))
    }

    pub fn entry_at(&self, path: &str) -> Option<Entry> {
        self.path_index.get(path).map(|&ino| self.entry(ino))
    }

    pub fn blobs(&self) -> &B {
        &self.blobs
    }

    fn handle(&self, ino: u64) -> Handle {
        Handle {
            fs: self.fs_id.clone(),
            node: NodeId {
                ino,
                generation: GENERATION,
            },
            proof: String::new(),
        }
    }

    fn check_handle(&self, handle: &Handle) -> Result<&ImageNode> {
        if handle.fs != self.fs_id || !handle.proof.is_empty() {
            return Err(Errno::EACCES);
        }
        if handle.node.generation != GENERATION {
            return Err(Errno::ESTALE);
        }
        self.nodes.get(&handle.node.ino).ok_or(Errno::ESTALE)
    }

    fn metadata_of(&self, node: &ImageNode) -> Metadata {
        Metadata {
            file_type: node.file_type(),
            mode: node.meta.mode & 0o7777,
            nlink: node.nlink,
            uid: node.meta.owner,
            gid: node.meta.group,
            size: node.size,
            atime: self.mounted_at,
            mtime: self.mounted_at,
            ctime: self.mounted_at,
            rdev: None,
            acl: false,
        }
    }

    fn entry(&self, ino: u64) -> Entry {
        let node = &self.nodes[&ino];
        Entry {
            handle: self.handle(ino),
            metadata: self.metadata_of(node),
        }
    }

    fn searchable(&self, cred: &Cred, dir: &ImageNode) -> Result<()> {
        if !dir.meta.directory {
            return Err(Errno::ENOTDIR);
        }
        inode::require(&cred.identity, &dir.meta, EXEC)
    }

    fn check_open<'s>(&self, state: &'s RuntimeState, open: &OpenRef) -> Result<&'s OpenRecord> {
        if open.fs != self.fs_id || open.node.generation != GENERATION {
            return Err(Errno::EBADF);
        }
        state
            .opens
            .get(&open.id)
            .filter(|rec| rec.ino == open.node.ino)
            .ok_or(Errno::EBADF)
    }

    fn deadlocks(state: &RuntimeState, ino: u64, wanted: Lock) -> bool {
        let mut pending = vec![(ino, wanted)];
        let mut visited = HashSet::new();
        while let Some((cur_ino, wanted_lock)) = pending.pop() {
            for held in state.locks.get(&cur_ino).into_iter().flatten() {
                if !held.conflicts(wanted_lock) {
                    continue;
                }
                if held.owner == wanted.owner {
                    return true;
                }
                if visited.insert(held.owner) {
                    pending.extend(state.waiters.values().filter_map(|w| {
                        (w.lock.owner == held.owner && w.lock.family == wanted.family)
                            .then_some((w.ino, w.lock))
                    }));
                }
            }
        }
        false
    }

    fn acquire_lock(
        &self,
        open: &OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
        wait: Option<(u64, Waker)>,
    ) -> Result<bool> {
        let mut state = self.state.borrow_mut();
        let rec = self.check_open(&state, open)?;
        let access = rec.access;
        let ino = rec.ino;
        match (family, kind) {
            (LockFamily::Flock, _) if access == Access::Path => return Err(Errno::EBADF),
            (LockFamily::Flock, _) => {}
            (LockFamily::Posix, LockKind::Shared) if access.reads() => {}
            (LockFamily::Posix, LockKind::Exclusive) if access.writes() => {}
            (LockFamily::Posix, _) => return Err(Errno::EBADF),
        }
        let wanted = Lock {
            owner: open.id,
            family,
            kind,
            range,
        };
        if family == LockFamily::Flock {
            let had_other = state
                .locks
                .get(&ino)
                .into_iter()
                .flatten()
                .any(|l| l.owner == open.id && l.family == LockFamily::Flock && l.kind != kind);
            if had_other {
                if let Some(list) = state.locks.get_mut(&ino) {
                    carve(list, open.id, LockFamily::Flock, LockRange::WHOLE);
                }
                Self::wake_waiters(&mut state, ino);
            }
        }
        let blocked = state
            .locks
            .get(&ino)
            .into_iter()
            .flatten()
            .any(|held| held.conflicts(wanted));
        if !blocked {
            if let Some((wid, _)) = &wait {
                state.waiters.remove(wid);
            }
            let list = state.locks.entry(ino).or_default();
            carve(list, open.id, family, range);
            list.push(wanted);
            return Ok(true);
        }
        let Some((wid, waker)) = wait else {
            return Err(Errno::EAGAIN);
        };
        if family == LockFamily::Posix && Self::deadlocks(&state, ino, wanted) {
            state.waiters.remove(&wid);
            return Err(Errno::EDEADLK);
        }
        state.waiters.insert(
            wid,
            Waiter {
                ino,
                lock: wanted,
                waker,
            },
        );
        Ok(false)
    }

    fn wake_waiters(state: &mut RuntimeState, ino: u64) {
        let wakers: Vec<Waker> = state
            .waiters
            .values()
            .filter(|w| w.ino == ino)
            .map(|w| w.waker.clone())
            .collect();
        for waker in wakers {
            waker.wake();
        }
    }
}

struct ImageLockFuture<'a, B: BlobStore> {
    fs: &'a ImageFs<B>,
    open: &'a OpenRef,
    family: LockFamily,
    kind: LockKind,
    range: LockRange,
    waiter_id: Option<u64>,
}

impl<B: BlobStore> Drop for ImageLockFuture<'_, B> {
    fn drop(&mut self) {
        if let Some(id) = self.waiter_id.take() {
            self.fs.state.borrow_mut().waiters.remove(&id);
        }
    }
}

impl<B: BlobStore> Future for ImageLockFuture<'_, B> {
    type Output = Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let fs = self.fs;
        let wid = *self.waiter_id.get_or_insert_with(|| {
            let mut s = fs.state.borrow_mut();
            let id = s.next_waiter;
            s.next_waiter += 1;
            id
        });
        match self.fs.acquire_lock(
            self.open,
            self.family,
            self.kind,
            self.range,
            Some((wid, cx.waker().clone())),
        ) {
            Ok(true) => {
                self.waiter_id = None;
                Poll::Ready(Ok(()))
            }
            Ok(false) => Poll::Pending,
            Err(e) => {
                self.waiter_id = None;
                Poll::Ready(Err(e))
            }
        }
    }
}

impl<B: BlobStore> Filesystem for ImageFs<B> {
    fn id(&self) -> &FsId {
        &self.fs_id
    }

    fn capabilities(&self) -> FsCapabilities {
        if self.global_identity {
            profiles::IMAGE_GLOBAL
        } else {
            profiles::IMAGE_PRIVATE
        }
    }

    fn root(&self) -> Handle {
        self.handle(ROOT_INO)
    }

    fn lookup<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(async move {
            let dir_node = self.check_handle(dir)?;
            check_component(name)?;
            self.searchable(cred, dir_node)?;
            let &child_ino = dir_node.children.get(name).ok_or(Errno::ENOENT)?;
            Ok(self.entry(child_ino))
        })
    }

    fn walk<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        names: &'a [String],
    ) -> BoxFuture<'a, Walked> {
        Box::pin(async move {
            let mut cur = self.check_handle(dir)?;
            for name in names {
                check_component(name)?;
            }
            let mut entries = Vec::new();
            for (idx, name) in names.iter().enumerate() {
                if idx > 0 {
                    let stop = match cur.file_type() {
                        FileType::Dir => None,
                        FileType::Symlink => Some(Stop::Symlink(idx - 1)),
                        _ => Some(Stop::NotDirectory(idx - 1)),
                    };
                    if stop.is_some() {
                        return Ok(Walked { entries, stop });
                    }
                }
                self.searchable(cred, cur)?;
                match cur.children.get(name) {
                    Some(&child_ino) => {
                        cur = &self.nodes[&child_ino];
                        entries.push(self.entry(child_ino));
                    }
                    None => {
                        return Ok(Walked {
                            entries,
                            stop: Some(Stop::Missing(idx)),
                        });
                    }
                }
            }
            Ok(Walked {
                entries,
                stop: None,
            })
        })
    }

    fn parent<'a>(
        &'a self,
        _cred: &'a Cred,
        dir: &'a Handle,
    ) -> BoxFuture<'a, Option<(Entry, String)>> {
        Box::pin(async move {
            let node = self.check_handle(dir)?;
            if !node.meta.directory {
                return Err(Errno::ENOTDIR);
            }
            if node.ino == ROOT_INO {
                return Ok(None);
            }
            Ok(Some((self.entry(node.parent), node.name.clone())))
        })
    }

    fn metadata<'a>(&'a self, _cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Metadata> {
        Box::pin(async move {
            let node = self.check_handle(handle)?;
            Ok(self.metadata_of(node))
        })
    }

    fn setattr<'a>(
        &'a self,
        _cred: &'a Cred,
        handle: &'a Handle,
        attr: &'a SetAttr,
    ) -> BoxFuture<'a, Metadata> {
        Box::pin(async move {
            let node = self.check_handle(handle)?;
            if *attr == SetAttr::default() {
                return Ok(self.metadata_of(node));
            }
            Err(Errno::EROFS)
        })
    }

    fn read_dir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle) -> BoxFuture<'a, Vec<DirEntry>> {
        Box::pin(async move {
            let node = self.check_handle(dir)?;
            if !node.meta.directory {
                return Err(Errno::ENOTDIR);
            }
            inode::require(&cred.identity, &node.meta, READ)?;
            let out = node
                .children
                .iter()
                .map(|(name, &child_ino)| {
                    let child = &self.nodes[&child_ino];
                    DirEntry {
                        name: name.clone(),
                        node: NodeId {
                            ino: child_ino,
                            generation: GENERATION,
                        },
                        file_type: child.file_type(),
                    }
                })
                .collect();
            Ok(out)
        })
    }

    fn read_link<'a>(&'a self, _cred: &'a Cred, link: &'a Handle) -> BoxFuture<'a, String> {
        Box::pin(async move {
            let node = self.check_handle(link)?;
            node.meta.link.clone().ok_or(Errno::EINVAL)
        })
    }

    fn create<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        _mode: u16,
        options: &'a OpenOptions,
    ) -> BoxFuture<'a, (Entry, OpenRef)> {
        Box::pin(async move {
            let dir_node = self.check_handle(dir)?;
            check_component(name)?;
            self.searchable(cred, dir_node)?;
            if let Some(&child_ino) = dir_node.children.get(name) {
                if options.is_create_new() {
                    return Err(Errno::EEXIST);
                }
                let child_entry = self.entry(child_ino);
                if child_entry.metadata.is_dir() {
                    return Err(Errno::EISDIR);
                }
                let open_ref = self.open(cred, &child_entry.handle, options).await?;
                return Ok((child_entry, open_ref));
            }
            Err(Errno::EROFS)
        })
    }

    fn mkdir<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        _mode: u16,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(async move {
            let dir_node = self.check_handle(dir)?;
            check_component(name)?;
            self.searchable(cred, dir_node)?;
            if dir_node.children.contains_key(name) {
                return Err(Errno::EEXIST);
            }
            Err(Errno::EROFS)
        })
    }

    fn mknod<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        _mode: u16,
        _rdev: &'a str,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(async move {
            let dir_node = self.check_handle(dir)?;
            check_component(name)?;
            self.searchable(cred, dir_node)?;
            if dir_node.children.contains_key(name) {
                return Err(Errno::EEXIST);
            }
            Err(Errno::EROFS)
        })
    }

    fn symlink<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        target: &'a str,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(async move {
            let dir_node = self.check_handle(dir)?;
            check_component(name)?;
            inode::check_link_target(target)?;
            self.searchable(cred, dir_node)?;
            if dir_node.children.contains_key(name) {
                return Err(Errno::EEXIST);
            }
            Err(Errno::EROFS)
        })
    }

    fn link<'a>(
        &'a self,
        cred: &'a Cred,
        target: &'a Handle,
        dir: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(async move {
            let _ = self.check_handle(target)?;
            let dir_node = self.check_handle(dir)?;
            check_component(name)?;
            self.searchable(cred, dir_node)?;
            Err(Errno::EROFS)
        })
    }

    fn unlink<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let dir_node = self.check_handle(dir)?;
            check_component(name)?;
            self.searchable(cred, dir_node)?;
            if !dir_node.children.contains_key(name) {
                return Err(Errno::ENOENT);
            }
            Err(Errno::EROFS)
        })
    }

    fn rmdir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let dir_node = self.check_handle(dir)?;
            check_component(name)?;
            self.searchable(cred, dir_node)?;
            if !dir_node.children.contains_key(name) {
                return Err(Errno::ENOENT);
            }
            Err(Errno::EROFS)
        })
    }

    fn rename<'a>(
        &'a self,
        cred: &'a Cred,
        from_dir: &'a Handle,
        from: &'a str,
        to_dir: &'a Handle,
        to: &'a str,
        _flags: RenameFlags,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let from_node = self.check_handle(from_dir)?;
            let to_node = self.check_handle(to_dir)?;
            check_component(from)?;
            check_component(to)?;
            self.searchable(cred, from_node)?;
            self.searchable(cred, to_node)?;
            if !from_node.children.contains_key(from) {
                return Err(Errno::ENOENT);
            }
            Err(Errno::EROFS)
        })
    }

    fn getxattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let _ = self.check_handle(handle)?;
            match xattr::space(name)? {
                Space::Trusted if cred.identity.id != 0 => Err(Errno::ENODATA),
                _ => Err(Errno::ENODATA),
            }
        })
    }

    fn setxattr<'a>(
        &'a self,
        _cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
        _value: &'a [u8],
        _flags: XattrFlags,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let _ = self.check_handle(handle)?;
            let _ = xattr::space(name)?;
            Err(Errno::EROFS)
        })
    }

    fn listxattr<'a>(&'a self, _cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Vec<String>> {
        Box::pin(async move {
            let _ = self.check_handle(handle)?;
            Ok(Vec::new())
        })
    }

    fn removexattr<'a>(
        &'a self,
        _cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let _ = self.check_handle(handle)?;
            let _ = xattr::space(name)?;
            Err(Errno::EROFS)
        })
    }

    fn statfs<'a>(&'a self, _cred: &'a Cred) -> BoxFuture<'a, StatFs> {
        Box::pin(async move {
            Ok(StatFs {
                block_size: BLOCK_SIZE,
                blocks: self.total_bytes.div_ceil(BLOCK_SIZE),
                blocks_free: 0,
                files: self.nodes.len() as u64,
                files_free: 0,
                name_max: abi::NAME_MAX as u64,
            })
        })
    }

    fn open<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        options: &'a OpenOptions,
    ) -> BoxFuture<'a, OpenRef> {
        Box::pin(async move {
            let node = self.check_handle(handle)?;
            let access = options.access()?;
            if access != Access::Path {
                if node.meta.is_link() {
                    return Err(Errno::ELOOP);
                }
                if node.meta.directory && (access.writes() || options.is_truncate()) {
                    return Err(Errno::EISDIR);
                }
                if access.writes() || options.is_truncate() {
                    return Err(Errno::EROFS);
                }
                inode::may_open(&cred.identity, &node.meta, access.mask())?;
            }
            let mut state = self.state.borrow_mut();
            let id = state.next_open;
            state.next_open += 1;
            state.opens.insert(
                id,
                OpenRecord {
                    ino: node.ino,
                    access,
                },
            );
            Ok(OpenRef {
                fs: self.fs_id.clone(),
                id,
                node: NodeId {
                    ino: node.ino,
                    generation: GENERATION,
                },
                access,
            })
        })
    }

    fn open_metadata<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, Metadata> {
        Box::pin(async move {
            let ino = {
                let state = self.state.borrow();
                self.check_open(&state, open)?.ino
            };
            Ok(self.metadata_of(&self.nodes[&ino]))
        })
    }

    fn read_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a mut [u8],
        offset: u64,
    ) -> BoxFuture<'a, usize> {
        Box::pin(async move {
            let (ino, access) = {
                let state = self.state.borrow();
                let rec = self.check_open(&state, open)?;
                (rec.ino, rec.access)
            };
            if !access.reads() {
                return Err(Errno::EBADF);
            }
            if offset > FILE_MAX || buf.len() as u64 > FILE_MAX - offset {
                return Err(Errno::EINVAL);
            }
            let node = &self.nodes[&ino];
            if node.meta.directory {
                return Err(Errno::EISDIR);
            }
            let Some(blob_id) = node.blob_id.as_deref() else {
                return Err(Errno::EINVAL);
            };
            if offset >= node.size || buf.is_empty() {
                return Ok(0);
            }
            let max_len =
                usize::try_from(node.size - offset).map_or(buf.len(), |r| r.min(buf.len()));
            self.blobs
                .read_at(blob_id, offset, &mut buf[..max_len])
                .await
        })
    }

    fn write_at<'a>(
        &'a self,
        open: &'a OpenRef,
        _buf: &'a [u8],
        _at: WriteAt,
    ) -> BoxFuture<'a, Written> {
        Box::pin(async move {
            let state = self.state.borrow();
            let _ = self.check_open(&state, open)?;
            Err(Errno::EBADF)
        })
    }

    fn set_len<'a>(&'a self, open: &'a OpenRef, _size: u64) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let state = self.state.borrow();
            let _ = self.check_open(&state, open)?;
            Err(Errno::EINVAL)
        })
    }

    fn sync_all<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let state = self.state.borrow();
            let rec = self.check_open(&state, open)?;
            if rec.access == Access::Path {
                return Err(Errno::EBADF);
            }
            Ok(())
        })
    }

    fn lock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        Box::pin(ImageLockFuture {
            fs: self,
            open,
            family,
            kind,
            range,
            waiter_id: None,
        })
    }

    fn try_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.acquire_lock(open, family, kind, range, None)
                .map(|_| ())
        })
    }

    fn unlock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let mut state = self.state.borrow_mut();
            let rec = self.check_open(&state, open)?;
            if rec.access == Access::Path {
                return Err(Errno::EBADF);
            }
            let ino = rec.ino;
            if let Some(list) = state.locks.get_mut(&ino) {
                carve(list, open.id, family, range);
                if list.is_empty() {
                    state.locks.remove(&ino);
                }
            }
            Self::wake_waiters(&mut state, ino);
            Ok(())
        })
    }

    fn test_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, Option<Conflict>> {
        Box::pin(async move {
            let state = self.state.borrow();
            let rec = self.check_open(&state, open)?;
            if rec.access == Access::Path {
                return Err(Errno::EBADF);
            }
            let wanted = Lock {
                owner: open.id,
                family: LockFamily::Posix,
                kind,
                range,
            };
            Ok(state
                .locks
                .get(&rec.ino)
                .into_iter()
                .flatten()
                .find(|held| held.conflicts(wanted))
                .map(|held| Conflict {
                    kind: held.kind,
                    range: held.range,
                    owner: held.owner,
                }))
        })
    }

    fn release<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let mut state = self.state.borrow_mut();
            let rec = self.check_open(&state, open)?;
            let ino = rec.ino;
            state.opens.remove(&open.id);
            state.waiters.retain(|_, w| w.lock.owner != open.id);
            if let Some(list) = state.locks.get_mut(&ino) {
                list.retain(|l| l.owner != open.id);
                if list.is_empty() {
                    state.locks.remove(&ino);
                }
            }
            Self::wake_waiters(&mut state, ino);
            Ok(())
        })
    }
}
