//! Device filesystems (`devtmpfs` at `/dev` and `devpts` at `/dev/pts`, contract §2.7, §5).

use crate::memfs::{Clock, MemFs};
use crate::{
    Access, BoxFuture, Conflict, Cred, DirEntry, Entry, FILE_MAX, FileType, Filesystem, FsId,
    Handle, LockFamily, LockKind, LockRange, Metadata, NodeId, OpenOptions, OpenRef, RenameFlags,
    Result, SetAttr, StatFs, Stop, Timespec, Walked, WriteAt, Written, XattrFlags, check_component,
    now_or_never, profiles,
};
use abi::Errno;
use abi::contract::FsCapabilities;
use os_core::inode;
use os_core::permissions::{EXEC, Node, READ};
use os_core::xattr;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap};

/// Host backend for character devices beyond the built-in byte devices (`null`, `zero`, `full`).
pub trait DeviceBackend {
    fn fill_random(&self, buf: &mut [u8]) -> Result<()> {
        // Portable deterministic splitmix64 fallback for pure-Rust tests; browser/native hosts
        // override with OS CSPRNG (`crypto.getRandomValues` / `getrandom`).
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15 ^ (buf.len() as u64);
        for chunk in buf.chunks_mut(8) {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^= z >> 31;
            let bytes = z.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }

    fn read_device<'a>(
        &'a self,
        _rdev: &'a str,
        _buf: &'a mut [u8],
        _offset: u64,
    ) -> BoxFuture<'a, usize> {
        Box::pin(async { Err(Errno::ENXIO) })
    }

    fn write_device<'a>(
        &'a self,
        _rdev: &'a str,
        _buf: &'a [u8],
        _at: WriteAt,
    ) -> BoxFuture<'a, Written> {
        Box::pin(async { Err(Errno::ENXIO) })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultDeviceBackend;
impl DeviceBackend for DefaultDeviceBackend {
    fn fill_random(&self, buf: &mut [u8]) -> Result<()> {
        thread_local! {
            static SEED: Cell<u64> = const { Cell::new(0x243f_6a88_85a3_08d3) };
        }
        SEED.with(|cell| {
            let mut state = cell.get();
            for chunk in buf.chunks_mut(8) {
                state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
                let mut z = state;
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                z ^= z >> 31;
                let bytes = z.to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
            cell.set(state);
        });
        Ok(())
    }
}

/// Remote character device drivers that require explicit credentialed attachment
/// (`docs/architecture/contract.md` §2.7). None of these are seeded at standalone boot.
pub const REMOTE_DEVICE_DRIVERS: [&str; 4] = ["archive", "media", "present", "snd"];

/// `/dev` filesystem (`devtmpfs` fstype).
pub struct DevTmpFs<D = DefaultDeviceBackend> {
    inner: MemFs,
    backend: D,
    attached_remotes: RefCell<HashMap<String, String>>,
}

impl<D: DeviceBackend> DevTmpFs<D> {
    pub fn new(id: FsId, generation: u64, clock: Clock, backend: D) -> Self {
        let mut root_cred = Cred::root();
        root_cred.umask = 0;
        let inner = MemFs::new(id, generation, 0, 0, 0o755, clock);
        let root = inner.root();

        // Seed ONLY instance-local devices at boot (Contract §2.7). Remote drivers
        // (`archive`, `media`, `present`, `snd`) are attached explicitly with a verified
        // remote credential via `attach_remote`.
        for (name, mode, rdev) in [
            ("null", 0o666, "null"),
            ("zero", 0o666, "zero"),
            ("full", 0o666, "full"),
            ("random", 0o666, "random"),
            ("urandom", 0o666, "urandom"),
            ("tty", 0o666, "tty"),
            ("console", 0o600, "console"),
            ("ptmx", 0o666, "ptmx"),
            ("system", 0o644, "system"),
        ] {
            now_or_never(inner.mknod(&root_cred, &root, name, mode, rdev))
                .expect("sync memfs mknod")
                .expect("seed dev node");
        }

        for (name, mode) in [("pts", 0o755), ("shm", 0o1777)] {
            let entry = now_or_never(inner.mkdir(&root_cred, &root, name, mode))
                .expect("sync memfs mkdir")
                .expect("seed dev dir");
            if mode == 0o1777 {
                now_or_never(inner.setattr(
                    &root_cred,
                    &entry.handle,
                    &SetAttr {
                        mode: Some(0o1777),
                        ..SetAttr::default()
                    },
                ))
                .expect("sync memfs setattr")
                .expect("seed shm sticky");
            }
        }

        for (name, target) in [
            ("fd", "/proc/self/fd"),
            ("stdin", "/proc/self/fd/0"),
            ("stdout", "/proc/self/fd/1"),
            ("stderr", "/proc/self/fd/2"),
        ] {
            now_or_never(inner.symlink(&root_cred, &root, name, target))
                .expect("sync memfs symlink")
                .expect("seed dev symlink");
        }

        Self {
            inner,
            backend,
            attached_remotes: RefCell::new(HashMap::new()),
        }
    }

    pub fn backend(&self) -> &D {
        &self.backend
    }

    /// Register a `/dev/vdN` managed volume device node (contract §2.16, #77).
    pub fn register_vblk(&self, name: &str, mode: u16) -> Result<Entry> {
        let mut root_cred = Cred::root();
        root_cred.umask = 0;
        let root = self.inner.root();
        let rdev = crate::vblk::vblk_rdev(name);
        now_or_never(self.inner.mknod(&root_cred, &root, name, mode, &rdev))
            .expect("sync memfs mknod")
    }

    /// Explicitly attach a remote device driver (`archive`, `media`, `present`, or `snd`)
    /// after verifying a non-empty remote credential/scope handle.
    pub fn attach_remote(&self, driver: &str, mode: u16, credential_scope: &str) -> Result<()> {
        if !REMOTE_DEVICE_DRIVERS.contains(&driver) {
            return Err(Errno::ENODEV);
        }
        if credential_scope.trim().is_empty() {
            return Err(Errno::EACCES);
        }
        let mut root_cred = Cred::root();
        root_cred.umask = 0;
        let root = self.inner.root();
        match driver {
            "archive" | "media" => {
                if now_or_never(self.inner.lookup(&root_cred, &root, driver))
                    .expect("sync memfs lookup")
                    .is_err()
                {
                    now_or_never(
                        self.inner
                            .mknod(&root_cred, &root, driver, mode & 0o777, driver),
                    )
                    .expect("sync memfs mknod")?;
                }
            }
            "present" | "snd" => {
                if now_or_never(self.inner.lookup(&root_cred, &root, driver))
                    .expect("sync memfs lookup")
                    .is_err()
                {
                    now_or_never(self.inner.mkdir(&root_cred, &root, driver, mode & 0o777))
                        .expect("sync memfs mkdir")?;
                }
            }
            _ => return Err(Errno::ENODEV),
        }
        self.attached_remotes
            .borrow_mut()
            .insert(driver.to_string(), credential_scope.to_string());
        Ok(())
    }

    /// Seed or update a named remote device node inside an attached `/dev/present` or `/dev/snd`
    /// directory. Refuses with `ENOTCONN` if the driver has not been explicitly attached.
    pub fn attach_remote_node(
        &self,
        driver: &str,
        name: &str,
        uid: u32,
        gid: u32,
        mode: u16,
    ) -> Result<()> {
        if !matches!(driver, "present" | "snd") {
            return Err(Errno::ENODEV);
        }
        if !self.is_remote_attached(driver) {
            return Err(Errno::ENOTCONN);
        }
        check_component(name)?;
        let mut root_cred = Cred::root();
        root_cred.umask = 0;
        let root = self.inner.root();
        let dir = now_or_never(self.inner.lookup(&root_cred, &root, driver))
            .expect("sync memfs lookup")?;
        if now_or_never(self.inner.lookup(&root_cred, &dir.handle, name))
            .expect("sync memfs lookup")
            .is_ok()
        {
            let _ = now_or_never(self.inner.unlink(&root_cred, &dir.handle, name))
                .expect("sync memfs unlink");
        }
        let entry =
            now_or_never(
                self.inner
                    .mknod(&root_cred, &dir.handle, name, mode & 0o777, driver),
            )
            .expect("sync memfs mknod")?;
        let _ = now_or_never(self.inner.setattr(
            &root_cred,
            &entry.handle,
            &SetAttr {
                uid: Some(uid),
                gid: Some(gid),
                mode: Some(mode & 0o777),
                ..SetAttr::default()
            },
        ))
        .expect("sync memfs setattr");
        Ok(())
    }

    /// Detach a remote device driver and remove its device node(s) from `/dev`.
    pub fn detach_remote(&self, driver: &str) -> Result<()> {
        if !REMOTE_DEVICE_DRIVERS.contains(&driver) {
            return Err(Errno::ENODEV);
        }
        self.attached_remotes.borrow_mut().remove(driver);
        let mut root_cred = Cred::root();
        root_cred.umask = 0;
        let root = self.inner.root();
        match driver {
            "archive" | "media" => {
                match now_or_never(self.inner.unlink(&root_cred, &root, driver))
                    .expect("sync memfs unlink")
                {
                    Ok(()) | Err(Errno::ENOENT) => Ok(()),
                    Err(e) => Err(e),
                }
            }
            "present" | "snd" => {
                if let Ok(dir) = now_or_never(self.inner.lookup(&root_cred, &root, driver))
                    .expect("sync memfs lookup")
                {
                    if let Ok(entries) = now_or_never(self.inner.read_dir(&root_cred, &dir.handle))
                        .expect("sync memfs readdir")
                    {
                        for child in entries {
                            let _ = now_or_never(self.inner.unlink(
                                &root_cred,
                                &dir.handle,
                                &child.name,
                            ))
                            .expect("sync memfs unlink");
                        }
                    }
                    let _ = now_or_never(self.inner.rmdir(&root_cred, &root, driver))
                        .expect("sync memfs rmdir");
                }
                Ok(())
            }
            _ => Err(Errno::ENODEV),
        }
    }

    pub fn is_remote_attached(&self, driver: &str) -> bool {
        self.attached_remotes.borrow().contains_key(driver)
    }

    pub fn remote_credential_scope(&self, driver: &str) -> Option<String> {
        self.attached_remotes.borrow().get(driver).cloned()
    }
}

impl<D: DeviceBackend> Filesystem for DevTmpFs<D> {
    fn id(&self) -> &FsId {
        self.inner.id()
    }
    fn capabilities(&self) -> FsCapabilities {
        profiles::DEVTMPFS
    }
    fn root(&self) -> Handle {
        self.inner.root()
    }
    fn lookup<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Entry> {
        self.inner.lookup(cred, dir, name)
    }
    fn walk<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        names: &'a [String],
    ) -> BoxFuture<'a, Walked> {
        self.inner.walk(cred, dir, names)
    }
    fn parent<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
    ) -> BoxFuture<'a, Option<(Entry, String)>> {
        self.inner.parent(cred, dir)
    }
    fn metadata<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Metadata> {
        self.inner.metadata(cred, handle)
    }
    fn setattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        attr: &'a SetAttr,
    ) -> BoxFuture<'a, Metadata> {
        self.inner.setattr(cred, handle, attr)
    }
    fn read_dir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle) -> BoxFuture<'a, Vec<DirEntry>> {
        self.inner.read_dir(cred, dir)
    }
    fn read_link<'a>(&'a self, cred: &'a Cred, link: &'a Handle) -> BoxFuture<'a, String> {
        self.inner.read_link(cred, link)
    }
    fn create<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
        options: &'a OpenOptions,
    ) -> BoxFuture<'a, (Entry, OpenRef)> {
        self.inner.create(cred, dir, name, mode, options)
    }
    fn mkdir<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
    ) -> BoxFuture<'a, Entry> {
        self.inner.mkdir(cred, dir, name, mode)
    }
    fn mknod<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
        rdev: &'a str,
    ) -> BoxFuture<'a, Entry> {
        self.inner.mknod(cred, dir, name, mode, rdev)
    }
    fn symlink<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        target: &'a str,
    ) -> BoxFuture<'a, Entry> {
        self.inner.symlink(cred, dir, name, target)
    }
    fn link<'a>(
        &'a self,
        cred: &'a Cred,
        target: &'a Handle,
        dir: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Entry> {
        self.inner.link(cred, target, dir, name)
    }
    fn unlink<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()> {
        self.inner.unlink(cred, dir, name)
    }
    fn rmdir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()> {
        self.inner.rmdir(cred, dir, name)
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
        self.inner.rename(cred, from_dir, from, to_dir, to, flags)
    }
    fn getxattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Vec<u8>> {
        self.inner.getxattr(cred, handle, name)
    }
    fn setxattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
        value: &'a [u8],
        flags: XattrFlags,
    ) -> BoxFuture<'a, ()> {
        self.inner.setxattr(cred, handle, name, value, flags)
    }
    fn listxattr<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Vec<String>> {
        self.inner.listxattr(cred, handle)
    }
    fn removexattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, ()> {
        self.inner.removexattr(cred, handle, name)
    }
    fn statfs<'a>(&'a self, cred: &'a Cred) -> BoxFuture<'a, StatFs> {
        self.inner.statfs(cred)
    }
    fn open<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        options: &'a OpenOptions,
    ) -> BoxFuture<'a, OpenRef> {
        self.inner.open(cred, handle, options)
    }
    fn open_metadata<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, Metadata> {
        self.inner.open_metadata(open)
    }
    fn read_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a mut [u8],
        offset: u64,
    ) -> BoxFuture<'a, usize> {
        Box::pin(async move {
            let meta = self.inner.open_metadata(open).await?;
            if meta.file_type == FileType::CharDevice {
                if !open.access.reads() {
                    return Err(Errno::EBADF);
                }
                if offset > FILE_MAX || buf.len() as u64 > FILE_MAX - offset {
                    return Err(Errno::EINVAL);
                }
                let rdev = meta.rdev.unwrap_or_default();
                return match rdev.as_str() {
                    "null" => Ok(0),
                    "zero" | "full" => {
                        buf.fill(0);
                        Ok(buf.len())
                    }
                    "random" | "urandom" => {
                        self.backend.fill_random(buf)?;
                        Ok(buf.len())
                    }
                    other => self.backend.read_device(other, buf, offset).await,
                };
            }
            self.inner.read_at(open, buf, offset).await
        })
    }
    fn write_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a [u8],
        at: WriteAt,
    ) -> BoxFuture<'a, Written> {
        Box::pin(async move {
            let meta = self.inner.open_metadata(open).await?;
            if meta.file_type == FileType::CharDevice {
                if !open.access.writes() {
                    return Err(Errno::EBADF);
                }
                if let WriteAt::Offset(off) = at
                    && (off > FILE_MAX || buf.len() as u64 > FILE_MAX - off)
                {
                    return Err(Errno::EINVAL);
                }
                let rdev = meta.rdev.unwrap_or_default();
                return match rdev.as_str() {
                    "null" | "zero" | "random" | "urandom" => Ok(Written {
                        offset: 0,
                        len: buf.len(),
                    }),
                    "full" => Err(Errno::ENOSPC),
                    other => self.backend.write_device(other, buf, at).await,
                };
            }
            self.inner.write_at(open, buf, at).await
        })
    }
    fn set_len<'a>(&'a self, open: &'a OpenRef, size: u64) -> BoxFuture<'a, ()> {
        self.inner.set_len(open, size)
    }
    fn sync_all<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let meta = self.inner.open_metadata(open).await?;
            if meta.file_type == FileType::CharDevice {
                if open.access == Access::Path {
                    return Err(Errno::EBADF);
                }
                return Err(Errno::EINVAL);
            }
            self.inner.sync_all(open).await
        })
    }
    fn lock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        self.inner.lock(open, family, kind, range)
    }
    fn try_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        self.inner.try_lock(open, family, kind, range)
    }
    fn unlock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        self.inner.unlock(open, family, range)
    }
    fn test_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, Option<Conflict>> {
        self.inner.test_lock(open, kind, range)
    }
    fn release<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        self.inner.release(open)
    }
}

const PTS_ROOT_INO: u64 = 1;
const PTS_PTMX_INO: u64 = 2;
const PTS_BASE_INO: u64 = 100;

struct PtyEntry {
    meta: Node,
    atime: (u64, u32),
    mtime: (u64, u32),
    ctime: (u64, u32),
}

struct PtsState {
    ptys: BTreeMap<u32, PtyEntry>,
    opens: HashMap<u64, (u64, Access)>,
    next_open: u64,
    ptmx: PtyEntry,
    root_meta: Node,
    created: (u64, u32),
}

/// `/dev/pts` slave PTY registry filesystem (`devpts` fstype).
pub struct DevPtsFs<D = DefaultDeviceBackend> {
    fs_id: FsId,
    generation: u64,
    clock: Clock,
    backend: D,
    state: RefCell<PtsState>,
}

impl DevPtsFs<DefaultDeviceBackend> {
    pub fn with_default_backend(id: FsId, generation: u64, clock: Clock) -> Self {
        Self::new(id, generation, clock, DefaultDeviceBackend)
    }
}

impl<D: DeviceBackend> DevPtsFs<D> {
    pub fn new(id: FsId, generation: u64, clock: Clock, backend: D) -> Self {
        let now = clock();
        let mut root_meta = Node::directory(0, 0, 0o755);
        root_meta.ino = PTS_ROOT_INO;
        let mut ptmx_meta = Node::device(0, 0, 0o666, "ptmx");
        ptmx_meta.ino = PTS_PTMX_INO;
        Self {
            fs_id: id,
            generation,
            clock,
            backend,
            state: RefCell::new(PtsState {
                ptys: BTreeMap::new(),
                opens: HashMap::new(),
                next_open: 1,
                ptmx: PtyEntry {
                    meta: ptmx_meta,
                    atime: now,
                    mtime: now,
                    ctime: now,
                },
                root_meta,
                created: now,
            }),
        }
    }

    pub fn allocate_pty(&self, uid: u32, gid: u32, mode: u16) -> u32 {
        let mut state = self.state.borrow_mut();
        let mut idx = 0u32;
        while state.ptys.contains_key(&idx) {
            idx = idx.saturating_add(1);
        }
        let now = (self.clock)();
        let rdev = format!("pts:{idx}");
        let mut meta = Node::device(uid, gid, mode & 0o7777, &rdev);
        meta.ino = PTS_BASE_INO + u64::from(idx);
        state.ptys.insert(
            idx,
            PtyEntry {
                meta,
                atime: now,
                mtime: now,
                ctime: now,
            },
        );
        idx
    }

    pub fn register_pty(&self, index: u32, uid: u32, gid: u32, mode: u16) {
        let mut state = self.state.borrow_mut();
        let now = (self.clock)();
        let rdev = format!("pts:{index}");
        let mut meta = Node::device(uid, gid, mode & 0o7777, &rdev);
        meta.ino = PTS_BASE_INO + u64::from(index);
        state.ptys.insert(
            index,
            PtyEntry {
                meta,
                atime: now,
                mtime: now,
                ctime: now,
            },
        );
    }

    pub fn close_pty(&self, index: u32) -> bool {
        self.state.borrow_mut().ptys.remove(&index).is_some()
    }

    pub fn active_ptys(&self) -> Vec<u32> {
        self.state.borrow().ptys.keys().copied().collect()
    }

    fn handle(&self, ino: u64) -> Handle {
        Handle {
            fs: self.fs_id.clone(),
            node: NodeId {
                ino,
                generation: self.generation,
            },
            proof: String::new(),
        }
    }

    fn check_handle(&self, state: &PtsState, handle: &Handle) -> Result<u64> {
        if handle.fs != self.fs_id || !handle.proof.is_empty() {
            return Err(Errno::EACCES);
        }
        if handle.node.generation != self.generation {
            return Err(Errno::ESTALE);
        }
        let ino = handle.node.ino;
        if ino == PTS_ROOT_INO || ino == PTS_PTMX_INO {
            return Ok(ino);
        }
        if ino >= PTS_BASE_INO
            && let Ok(idx) = u32::try_from(ino - PTS_BASE_INO)
            && state.ptys.contains_key(&idx)
        {
            return Ok(ino);
        }
        Err(Errno::ESTALE)
    }

    fn metadata_of(state: &PtsState, ino: u64) -> Option<Metadata> {
        if ino == PTS_ROOT_INO {
            return Some(Metadata {
                file_type: FileType::Dir,
                mode: state.root_meta.mode & 0o7777,
                nlink: 2,
                uid: state.root_meta.owner,
                gid: state.root_meta.group,
                size: 4096,
                atime: Timespec::from(state.created),
                mtime: Timespec::from(state.created),
                ctime: Timespec::from(state.created),
                rdev: None,
                acl: false,
            });
        }
        let pty = if ino == PTS_PTMX_INO {
            &state.ptmx
        } else {
            let idx = u32::try_from(ino.checked_sub(PTS_BASE_INO)?).ok()?;
            state.ptys.get(&idx)?
        };
        Some(Metadata {
            file_type: FileType::CharDevice,
            mode: pty.meta.mode & 0o7777,
            nlink: 1,
            uid: pty.meta.owner,
            gid: pty.meta.group,
            size: 0,
            atime: Timespec::from(pty.atime),
            mtime: Timespec::from(pty.mtime),
            ctime: Timespec::from(pty.ctime),
            rdev: pty.meta.rdev.clone(),
            acl: false,
        })
    }

    fn entry(&self, state: &PtsState, ino: u64) -> Result<Entry> {
        let metadata = Self::metadata_of(state, ino).ok_or(Errno::ESTALE)?;
        Ok(Entry {
            handle: self.handle(ino),
            metadata,
        })
    }

    fn lookup_child(state: &PtsState, name: &str) -> Option<u64> {
        if name == "ptmx" {
            return Some(PTS_PTMX_INO);
        }
        let idx: u32 = name.parse().ok()?;
        if idx.to_string() != name {
            return None;
        }
        state
            .ptys
            .contains_key(&idx)
            .then_some(PTS_BASE_INO + u64::from(idx))
    }
}

impl<D: DeviceBackend> Filesystem for DevPtsFs<D> {
    fn id(&self) -> &FsId {
        &self.fs_id
    }
    fn capabilities(&self) -> FsCapabilities {
        profiles::DEVPTS
    }
    fn root(&self) -> Handle {
        self.handle(PTS_ROOT_INO)
    }

    fn lookup<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(async move {
            let state = self.state.borrow();
            let dir_ino = self.check_handle(&state, dir)?;
            check_component(name)?;
            if dir_ino != PTS_ROOT_INO {
                return Err(Errno::ENOTDIR);
            }
            inode::require(&cred.identity, &state.root_meta, EXEC)?;
            let child_ino = Self::lookup_child(&state, name).ok_or(Errno::ENOENT)?;
            self.entry(&state, child_ino)
        })
    }

    fn walk<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        names: &'a [String],
    ) -> BoxFuture<'a, Walked> {
        Box::pin(async move {
            let state = self.state.borrow();
            let mut cur_ino = self.check_handle(&state, dir)?;
            for name in names {
                check_component(name)?;
            }
            let mut entries = Vec::new();
            for (idx, name) in names.iter().enumerate() {
                if idx > 0 && cur_ino != PTS_ROOT_INO {
                    return Ok(Walked {
                        entries,
                        stop: Some(Stop::NotDirectory(idx - 1)),
                    });
                }
                if cur_ino != PTS_ROOT_INO {
                    return Err(Errno::ENOTDIR);
                }
                inode::require(&cred.identity, &state.root_meta, EXEC)?;
                match Self::lookup_child(&state, name) {
                    Some(child_ino) => {
                        cur_ino = child_ino;
                        entries.push(self.entry(&state, child_ino)?);
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
            let state = self.state.borrow();
            let ino = self.check_handle(&state, dir)?;
            if ino != PTS_ROOT_INO {
                return Err(Errno::ENOTDIR);
            }
            Ok(None)
        })
    }

    fn metadata<'a>(&'a self, _cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Metadata> {
        Box::pin(async move {
            let state = self.state.borrow();
            let ino = self.check_handle(&state, handle)?;
            Self::metadata_of(&state, ino).ok_or(Errno::ESTALE)
        })
    }

    fn setattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        attr: &'a SetAttr,
    ) -> BoxFuture<'a, Metadata> {
        Box::pin(async move {
            let mut state = self.state.borrow_mut();
            let ino = self.check_handle(&state, handle)?;
            if *attr == SetAttr::default() {
                return Self::metadata_of(&state, ino).ok_or(Errno::ESTALE);
            }
            if attr.size.is_some() {
                return Err(if ino == PTS_ROOT_INO {
                    Errno::EISDIR
                } else {
                    Errno::EINVAL
                });
            }
            let who = &cred.identity;
            let now = (self.clock)();
            if ino == PTS_ROOT_INO {
                let mut meta = state.root_meta.clone();
                if let Some(mode) = attr.mode {
                    inode::chmod(who, &mut meta, mode)?;
                }
                inode::chown(who, &mut meta, attr.uid, attr.gid)?;
                inode::may_set_times(who, &state.root_meta, attr.atime, attr.mtime)?;
                state.root_meta = meta;
                return Self::metadata_of(&state, ino).ok_or(Errno::ESTALE);
            }
            let pty = if ino == PTS_PTMX_INO {
                &mut state.ptmx
            } else {
                let idx = u32::try_from(ino - PTS_BASE_INO).map_err(|_| Errno::ESTALE)?;
                state.ptys.get_mut(&idx).ok_or(Errno::ESTALE)?
            };
            let mut meta = pty.meta.clone();
            if let Some(mode) = attr.mode {
                inode::chmod(who, &mut meta, mode)?;
            }
            inode::chown(who, &mut meta, attr.uid, attr.gid)?;
            inode::may_set_times(who, &pty.meta, attr.atime, attr.mtime)?;
            pty.meta = meta;
            if let Some(at) = inode::time(attr.atime, now) {
                pty.atime = at;
            }
            if let Some(mt) = inode::time(attr.mtime, now) {
                pty.mtime = mt;
            }
            pty.ctime = now;
            Self::metadata_of(&state, ino).ok_or(Errno::ESTALE)
        })
    }

    fn read_dir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle) -> BoxFuture<'a, Vec<DirEntry>> {
        Box::pin(async move {
            let state = self.state.borrow();
            let ino = self.check_handle(&state, dir)?;
            if ino != PTS_ROOT_INO {
                return Err(Errno::ENOTDIR);
            }
            inode::require(&cred.identity, &state.root_meta, READ)?;
            let mut out = Vec::with_capacity(1 + state.ptys.len());
            out.push(DirEntry {
                name: "ptmx".into(),
                node: NodeId {
                    ino: PTS_PTMX_INO,
                    generation: self.generation,
                },
                file_type: FileType::CharDevice,
            });
            for &idx in state.ptys.keys() {
                out.push(DirEntry {
                    name: idx.to_string(),
                    node: NodeId {
                        ino: PTS_BASE_INO + u64::from(idx),
                        generation: self.generation,
                    },
                    file_type: FileType::CharDevice,
                });
            }
            Ok(out)
        })
    }

    fn read_link<'a>(&'a self, _cred: &'a Cred, link: &'a Handle) -> BoxFuture<'a, String> {
        Box::pin(async move {
            let state = self.state.borrow();
            let _ = self.check_handle(&state, link)?;
            Err(Errno::EINVAL)
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
            let child_entry = {
                let state = self.state.borrow();
                let dir_ino = self.check_handle(&state, dir)?;
                check_component(name)?;
                if dir_ino != PTS_ROOT_INO {
                    return Err(Errno::ENOTDIR);
                }
                inode::require(&cred.identity, &state.root_meta, EXEC)?;
                match Self::lookup_child(&state, name) {
                    Some(ino) => Some(self.entry(&state, ino)?),
                    None => None,
                }
            };
            if let Some(entry) = child_entry {
                if options.is_create_new() {
                    return Err(Errno::EEXIST);
                }
                let open = self.open(cred, &entry.handle, options).await?;
                return Ok((entry, open));
            }
            Err(Errno::EPERM)
        })
    }

    fn mkdir<'a>(
        &'a self,
        _cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        _mode: u16,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(async move {
            let state = self.state.borrow();
            let _ = self.check_handle(&state, dir)?;
            check_component(name)?;
            Err(Errno::EPERM)
        })
    }

    fn mknod<'a>(
        &'a self,
        _cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        _mode: u16,
        _rdev: &'a str,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(async move {
            let state = self.state.borrow();
            let _ = self.check_handle(&state, dir)?;
            check_component(name)?;
            Err(Errno::EPERM)
        })
    }

    fn symlink<'a>(
        &'a self,
        _cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        target: &'a str,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(async move {
            let state = self.state.borrow();
            let _ = self.check_handle(&state, dir)?;
            check_component(name)?;
            inode::check_link_target(target)?;
            Err(Errno::EPERM)
        })
    }

    fn link<'a>(
        &'a self,
        _cred: &'a Cred,
        target: &'a Handle,
        dir: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(async move {
            let state = self.state.borrow();
            let _ = self.check_handle(&state, target)?;
            let _ = self.check_handle(&state, dir)?;
            check_component(name)?;
            Err(Errno::EPERM)
        })
    }

    fn unlink<'a>(&'a self, _cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let state = self.state.borrow();
            let _ = self.check_handle(&state, dir)?;
            check_component(name)?;
            Err(Errno::EPERM)
        })
    }

    fn rmdir<'a>(&'a self, _cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let state = self.state.borrow();
            let _ = self.check_handle(&state, dir)?;
            check_component(name)?;
            Err(Errno::EPERM)
        })
    }

    fn rename<'a>(
        &'a self,
        _cred: &'a Cred,
        from_dir: &'a Handle,
        from: &'a str,
        to_dir: &'a Handle,
        to: &'a str,
        _flags: RenameFlags,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let state = self.state.borrow();
            let _ = self.check_handle(&state, from_dir)?;
            let _ = self.check_handle(&state, to_dir)?;
            check_component(from)?;
            check_component(to)?;
            Err(Errno::EPERM)
        })
    }

    fn getxattr<'a>(
        &'a self,
        _cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let state = self.state.borrow();
            let _ = self.check_handle(&state, handle)?;
            let _ = xattr::space(name)?;
            Err(Errno::ENODATA)
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
            let state = self.state.borrow();
            let _ = self.check_handle(&state, handle)?;
            let _ = xattr::space(name)?;
            Err(Errno::EOPNOTSUPP)
        })
    }

    fn listxattr<'a>(&'a self, _cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Vec<String>> {
        Box::pin(async move {
            let state = self.state.borrow();
            let _ = self.check_handle(&state, handle)?;
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
            let state = self.state.borrow();
            let _ = self.check_handle(&state, handle)?;
            let _ = xattr::space(name)?;
            Err(Errno::EOPNOTSUPP)
        })
    }

    fn statfs<'a>(&'a self, _cred: &'a Cred) -> BoxFuture<'a, StatFs> {
        Box::pin(async move {
            let state = self.state.borrow();
            Ok(StatFs {
                block_size: 4096,
                blocks: 0,
                blocks_free: 0,
                files: (2 + state.ptys.len()) as u64,
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
            let mut state = self.state.borrow_mut();
            let ino = self.check_handle(&state, handle)?;
            let access = options.access()?;
            if access != Access::Path {
                let meta = if ino == PTS_ROOT_INO {
                    &state.root_meta
                } else if ino == PTS_PTMX_INO {
                    &state.ptmx.meta
                } else {
                    let idx = u32::try_from(ino - PTS_BASE_INO).map_err(|_| Errno::ESTALE)?;
                    &state.ptys.get(&idx).ok_or(Errno::ESTALE)?.meta
                };
                let mut mask = access.mask();
                if options.is_truncate() {
                    mask |= os_core::permissions::WRITE;
                }
                inode::may_open(&cred.identity, meta, mask)?;
            }
            let id = state.next_open;
            state.next_open += 1;
            state.opens.insert(id, (ino, access));
            Ok(OpenRef {
                fs: self.fs_id.clone(),
                id,
                node: NodeId {
                    ino,
                    generation: self.generation,
                },
                access,
            })
        })
    }

    fn open_metadata<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, Metadata> {
        Box::pin(async move {
            let state = self.state.borrow();
            let &(ino, _) = state
                .opens
                .get(&open.id)
                .filter(|&&(i, _)| open.fs == self.fs_id && open.node.ino == i)
                .ok_or(Errno::EBADF)?;
            Self::metadata_of(&state, ino).ok_or(Errno::ESTALE)
        })
    }

    fn read_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a mut [u8],
        offset: u64,
    ) -> BoxFuture<'a, usize> {
        Box::pin(async move {
            let (ino, access, rdev) = {
                let state = self.state.borrow();
                let &(ino, access) = state
                    .opens
                    .get(&open.id)
                    .filter(|&&(i, _)| open.fs == self.fs_id && open.node.ino == i)
                    .ok_or(Errno::EBADF)?;
                let meta = Self::metadata_of(&state, ino).ok_or(Errno::ESTALE)?;
                (ino, access, meta.rdev)
            };
            if ino == PTS_ROOT_INO {
                return Err(Errno::EISDIR);
            }
            if !access.reads() {
                return Err(Errno::EBADF);
            }
            let rdev = rdev.unwrap_or_default();
            self.backend.read_device(&rdev, buf, offset).await
        })
    }

    fn write_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a [u8],
        at: WriteAt,
    ) -> BoxFuture<'a, Written> {
        Box::pin(async move {
            let (ino, access, rdev) = {
                let state = self.state.borrow();
                let &(ino, access) = state
                    .opens
                    .get(&open.id)
                    .filter(|&&(i, _)| open.fs == self.fs_id && open.node.ino == i)
                    .ok_or(Errno::EBADF)?;
                let meta = Self::metadata_of(&state, ino).ok_or(Errno::ESTALE)?;
                (ino, access, meta.rdev)
            };
            if ino == PTS_ROOT_INO {
                return Err(Errno::EBADF);
            }
            if !access.writes() {
                return Err(Errno::EBADF);
            }
            let rdev = rdev.unwrap_or_default();
            self.backend.write_device(&rdev, buf, at).await
        })
    }

    fn set_len<'a>(&'a self, open: &'a OpenRef, _size: u64) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let state = self.state.borrow();
            if !state
                .opens
                .get(&open.id)
                .is_some_and(|&(i, _)| open.fs == self.fs_id && open.node.ino == i)
            {
                return Err(Errno::EBADF);
            }
            Err(Errno::EINVAL)
        })
    }

    fn sync_all<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let state = self.state.borrow();
            let &(_, access) = state
                .opens
                .get(&open.id)
                .filter(|&&(i, _)| open.fs == self.fs_id && open.node.ino == i)
                .ok_or(Errno::EBADF)?;
            if access == Access::Path {
                return Err(Errno::EBADF);
            }
            Err(Errno::EINVAL)
        })
    }

    fn lock<'a>(
        &'a self,
        open: &'a OpenRef,
        _family: LockFamily,
        _kind: LockKind,
        _range: LockRange,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let state = self.state.borrow();
            let &(_, access) = state
                .opens
                .get(&open.id)
                .filter(|&&(i, _)| open.fs == self.fs_id && open.node.ino == i)
                .ok_or(Errno::EBADF)?;
            if access == Access::Path {
                return Err(Errno::EBADF);
            }
            Err(Errno::ENOLCK)
        })
    }

    fn try_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        self.lock(open, family, kind, range)
    }

    fn unlock<'a>(
        &'a self,
        open: &'a OpenRef,
        _family: LockFamily,
        _range: LockRange,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let state = self.state.borrow();
            let &(_, access) = state
                .opens
                .get(&open.id)
                .filter(|&&(i, _)| open.fs == self.fs_id && open.node.ino == i)
                .ok_or(Errno::EBADF)?;
            if access == Access::Path {
                return Err(Errno::EBADF);
            }
            Ok(())
        })
    }

    fn test_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        _kind: LockKind,
        _range: LockRange,
    ) -> BoxFuture<'a, Option<Conflict>> {
        Box::pin(async move {
            let state = self.state.borrow();
            let &(_, access) = state
                .opens
                .get(&open.id)
                .filter(|&&(i, _)| open.fs == self.fs_id && open.node.ino == i)
                .ok_or(Errno::EBADF)?;
            if access == Access::Path {
                return Err(Errno::EBADF);
            }
            Ok(None)
        })
    }

    fn release<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let mut state = self.state.borrow_mut();
            if state
                .opens
                .get(&open.id)
                .is_none_or(|&(i, _)| open.fs != self.fs_id || open.node.ino != i)
            {
                return Err(Errno::EBADF);
            }
            state.opens.remove(&open.id);
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_seeding_omits_remote_devices_and_attach_requires_credential() {
        let dev = DevTmpFs::new(
            FsId("devtmpfs:test".into()),
            1,
            Box::new(|| (1_700_000_000, 0)),
            DefaultDeviceBackend,
        );
        let root_cred = Cred::root();
        let root = dev.root();

        // Local boot devices exist.
        for local in [
            "null", "zero", "full", "random", "urandom", "tty", "console", "ptmx", "system", "pts",
            "shm", "fd",
        ] {
            assert!(
                now_or_never(dev.lookup(&root_cred, &root, local))
                    .unwrap()
                    .is_ok(),
                "expected boot device /dev/{local}"
            );
        }
        // Remote drivers are absent at standalone boot.
        for remote in REMOTE_DEVICE_DRIVERS {
            assert_eq!(
                now_or_never(dev.lookup(&root_cred, &root, remote))
                    .unwrap()
                    .unwrap_err(),
                Errno::ENOENT,
                "remote driver /dev/{remote} must not exist at boot"
            );
            assert!(!dev.is_remote_attached(remote));
        }

        // Empty credential scope is refused with EACCES; unknown driver -> ENODEV.
        assert_eq!(dev.attach_remote("archive", 0o666, ""), Err(Errno::EACCES));
        assert_eq!(
            dev.attach_remote("bogus", 0o666, "cred"),
            Err(Errno::ENODEV)
        );
        assert_eq!(
            dev.attach_remote_node("present", "deck", 1000, 1000, 0o644),
            Err(Errno::ENOTCONN)
        );

        // Explicit credentialed attach creates device nodes and detach removes them cleanly.
        dev.attach_remote("archive", 0o666, "scope:ann").unwrap();
        dev.attach_remote("present", 0o755, "scope:ann").unwrap();
        dev.attach_remote_node("present", "deck", 1000, 1000, 0o644)
            .unwrap();
        assert!(dev.is_remote_attached("archive"));
        assert!(dev.is_remote_attached("present"));
        assert!(
            now_or_never(dev.lookup(&root_cred, &root, "archive"))
                .unwrap()
                .is_ok()
        );
        let present_dir = now_or_never(dev.lookup(&root_cred, &root, "present"))
            .unwrap()
            .unwrap();
        assert!(
            now_or_never(dev.lookup(&root_cred, &present_dir.handle, "deck"))
                .unwrap()
                .is_ok()
        );

        dev.detach_remote("archive").unwrap();
        dev.detach_remote("present").unwrap();
        assert!(!dev.is_remote_attached("archive"));
        assert!(!dev.is_remote_attached("present"));
        assert_eq!(
            now_or_never(dev.lookup(&root_cred, &root, "archive"))
                .unwrap()
                .unwrap_err(),
            Errno::ENOENT
        );
        assert_eq!(
            now_or_never(dev.lookup(&root_cred, &root, "present"))
                .unwrap()
                .unwrap_err(),
            Errno::ENOENT
        );
    }
}
