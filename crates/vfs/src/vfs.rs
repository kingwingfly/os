//! Unified portable VFS coordinator (`Vfs`), process context management, mount/namespace/`chroot`
//! syscalls, and `#!` shebang + `PATH` executable resolver (`docs/architecture/contract.md` §2–§5).

use crate::context::{PathAnchor, SharedFdTable, SharedFsContext};
use crate::memfs::{Clock, MemFs};
use crate::mount::{
    FsType, MountAttachment, MountBacking, MountEntry, MountFlags, MountId, MountPin, MountSlot,
    NamespaceId,
};
use crate::namespace::MountNamespace;
use crate::procfs::{ProcBridge, ProcCallerInfo, ProcTargetInfo};
use crate::stat::stat as to_abi_stat;
use crate::walk::{
    MagicResolved, ParentResolution, StartAnchor, WalkFlags, WalkResult, ensure_searchable, walk,
    walk_parent,
};
use crate::{
    Access, BoxFuture, Cred, DirEntry, Entry, Fd, FileRef, FileType, Filesystem, Handle, Metadata,
    NodeId, OpenOptions, ReleaseQueue, RenameFlags, Result, SeekFrom, SetAttr, XattrFlags,
};
use abi::Errno;
use abi::contract::{mount_flags, statfs_flags, umount_flags, unshare_flags};
use os_core::inode;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::rc::{Rc, Weak};
use std::task::{Context, Poll};

/// Linux `O_CLOEXEC` open flag (`02000000`).
pub const O_CLOEXEC: u32 = 0o2_000_000;

/// Maximum `#!` shebang recursion depth (`MAX_BINPRM_RECURSION = 4` on Linux).
pub const MAX_SHEBANG_DEPTH: usize = 4;
const BINPRM_BUF_SIZE: usize = 256;

/// Result of instantiating a filesystem driver for `mount(2)`.
pub struct MountedFs {
    pub backing: Rc<MountBacking>,
    pub root: Handle,
    pub root_in_fs: String,
}

/// Factory creating new [`MountedFs`] instances for `mount(source, target, fstype, flags, data)`.
pub trait FilesystemFactory {
    fn mount_fs<'a>(
        &'a self,
        cred: &'a Cred,
        fstype: FsType,
        source: &'a str,
        flags: MountFlags,
        data: Option<&'a str>,
    ) -> BoxFuture<'a, MountedFs>;
}

type CustomMounter = Box<dyn Fn(&Cred, &str, MountFlags, Option<&str>) -> Result<MountedFs>>;

/// Ready-to-use [`FilesystemFactory`] supporting `tmpfs` (with `mode=`, `uid=`, `gid=`, `size=`)
/// out of the box plus pluggable system mounters and per-user grants (`opfs`, `hostfs`,
/// `helperfs`, `sharefs`, `image`).
pub struct DefaultFilesystemFactory {
    next_id: Cell<u64>,
    clock: Rc<dyn Fn() -> (u64, u32)>,
    system_mounters: RefCell<HashMap<FsType, CustomMounter>>,
    user_grants: RefCell<HashMap<(u32, FsType, String), CustomMounter>>,
}

impl Default for DefaultFilesystemFactory {
    fn default() -> Self {
        Self::new(Rc::new(|| (0, 0)))
    }
}

impl DefaultFilesystemFactory {
    pub fn new(clock: Rc<dyn Fn() -> (u64, u32)>) -> Self {
        Self {
            next_id: Cell::new(1),
            clock,
            system_mounters: RefCell::new(HashMap::new()),
            user_grants: RefCell::new(HashMap::new()),
        }
    }

    pub fn register_system_mounter(
        &self,
        fstype: FsType,
        mounter: impl Fn(&Cred, &str, MountFlags, Option<&str>) -> Result<MountedFs> + 'static,
    ) {
        self.system_mounters
            .borrow_mut()
            .insert(fstype, Box::new(mounter));
    }

    pub fn register_user_grant(
        &self,
        uid: u32,
        fstype: FsType,
        source: impl Into<String>,
        mounter: impl Fn(&Cred, &str, MountFlags, Option<&str>) -> Result<MountedFs> + 'static,
    ) {
        self.user_grants
            .borrow_mut()
            .insert((uid, fstype, source.into()), Box::new(mounter));
    }

    fn make_clock(&self) -> Clock {
        let c = Rc::clone(&self.clock);
        Box::new(move || c())
    }
}

impl FilesystemFactory for DefaultFilesystemFactory {
    fn mount_fs<'a>(
        &'a self,
        cred: &'a Cred,
        fstype: FsType,
        source: &'a str,
        flags: MountFlags,
        data: Option<&'a str>,
    ) -> BoxFuture<'a, MountedFs> {
        Box::pin(async move {
            if cred.identity.id != 0 {
                let grants = self.user_grants.borrow();
                let Some(mounter) = grants.get(&(cred.identity.id, fstype, source.to_string()))
                else {
                    return Err(Errno::EACCES);
                };
                return mounter(cred, source, flags, data);
            }

            if let Some(mounter) = self.system_mounters.borrow().get(&fstype) {
                return mounter(cred, source, flags, data);
            }

            match fstype {
                FsType::TmpFs => {
                    let seq = self.next_id.get();
                    self.next_id.set(seq + 1);
                    let fs = Rc::new(MemFs::from_mount_options(
                        crate::FsId(format!("tmpfs:{seq}")),
                        seq,
                        cred,
                        data,
                        self.make_clock(),
                    )?);
                    let root = fs.root();
                    let backing = Rc::new(MountBacking::new(fs, FsType::TmpFs));
                    Ok(MountedFs {
                        backing,
                        root,
                        root_in_fs: "/".to_string(),
                    })
                }
                FsType::Cowfs => {
                    crate::vblk::CowfsMountOptions::parse(data)?;
                    if crate::vblk::is_non_block_tree_source(source) {
                        return Err(Errno::ENOTBLK);
                    }
                    Err(Errno::ENODEV)
                }
                _ => Err(Errno::ENODEV),
            }
        })
    }
}

/// Resolved executable image and rewritten `argv` returned by [`Vfs::resolve_exec`].
pub struct ResolvedExec {
    pub file: FileRef,
    pub pin: MountPin,
    pub entry: Entry,
    pub argv: Vec<String>,
    pub resolved_path: String,
    pub nosuid: bool,
    pub header: Vec<u8>,
}

pub struct ProcessCtx {
    pub pid: u32,
    pub ppid: u32,
    pub cred: Cred,
    pub mnt_ns: Rc<RefCell<MountNamespace>>,
    pub fs_ctx: SharedFsContext,
    pub fds: SharedFdTable,
}

struct VfsInner {
    instance_id: String,
    next_mount_id: Cell<u64>,
    next_ns_id: Cell<u64>,
    active_pid: Cell<Option<u32>>,
    releases: ReleaseQueue,
    factory: Rc<dyn FilesystemFactory>,
    system_ns: Rc<RefCell<MountNamespace>>,
    namespaces: RefCell<HashMap<NamespaceId, Weak<RefCell<MountNamespace>>>>,
    processes: RefCell<BTreeMap<u32, ProcessCtx>>,
}

impl VfsInner {
    fn alloc_mount_id(&self) -> MountId {
        let id = self.next_mount_id.get();
        self.next_mount_id.set(id + 1);
        MountId(id)
    }

    fn alloc_ns_id(&self) -> NamespaceId {
        let id = self.next_ns_id.get();
        self.next_ns_id.set(id + 1);
        NamespaceId(id)
    }

    fn register_namespace(&self, ns: &Rc<RefCell<MountNamespace>>) {
        let id = ns.borrow().id();
        let mut map = self.namespaces.borrow_mut();
        map.retain(|_, w| w.strong_count() > 0);
        map.insert(id, Rc::downgrade(ns));
    }
}

impl ProcBridge for VfsInner {
    fn instance_id(&self) -> String {
        self.instance_id.clone()
    }

    fn current_caller(&self) -> Option<ProcCallerInfo> {
        let pid = self.active_pid.get()?;
        let procs = self.processes.borrow();
        let proc_ctx = procs.get(&pid)?;
        let root = proc_ctx.fs_ctx.borrow().root.clone();
        let ns_root = proc_ctx.mnt_ns.borrow().root_anchor();
        let is_at_ns_root = root.same_anchor(&ns_root);
        Some(ProcCallerInfo {
            pid,
            root,
            is_at_ns_root,
        })
    }

    fn local_pids(&self) -> Vec<u32> {
        self.processes.borrow().keys().copied().collect()
    }

    fn process_info(&self, pid: u32) -> Option<ProcTargetInfo> {
        let procs = self.processes.borrow();
        let p = procs.get(&pid)?;
        let ctx = p.fs_ctx.borrow();
        Some(ProcTargetInfo {
            pid: p.pid,
            uid: p.cred.identity.id,
            gid: p.cred.identity.group,
            mnt_ns: Rc::clone(&p.mnt_ns),
            root: ctx.root.clone(),
            cwd: ctx.cwd.clone(),
            fds: p.fds.clone(),
        })
    }

    fn namespace_by_id(&self, id: NamespaceId) -> Option<Rc<RefCell<MountNamespace>>> {
        if self.system_ns.borrow().id() == id {
            return Some(Rc::clone(&self.system_ns));
        }
        self.namespaces.borrow().get(&id).and_then(Weak::upgrade)
    }
}

struct WithCallerPid<'a, F> {
    active_pid: &'a Cell<Option<u32>>,
    pid: u32,
    fut: Pin<Box<F>>,
}

struct ActivePidGuard<'a> {
    cell: &'a Cell<Option<u32>>,
    prev: Option<u32>,
}

impl Drop for ActivePidGuard<'_> {
    fn drop(&mut self) {
        self.cell.set(self.prev);
    }
}

impl<F: Future> Future for WithCallerPid<'_, F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let prev = self.active_pid.replace(Some(self.pid));
        let _guard = ActivePidGuard {
            cell: self.active_pid,
            prev,
        };
        self.fut.as_mut().poll(cx)
    }
}

/// Instance-level VFS coordinator.
#[derive(Clone)]
pub struct Vfs {
    inner: Rc<VfsInner>,
}

#[derive(Clone)]
struct SubmountSpec {
    rel_segments: Vec<String>,
    backing: Rc<MountBacking>,
    root: Handle,
    root_open: FileRef,
    root_in_fs: String,
    source: String,
    flags: MountFlags,
    locked_flags: u64,
    owner_uid: Option<u32>,
}

impl Vfs {
    /// Boot a new [`Vfs`] instance with `root_backing` mounted at `"/"` in `system_ns` (`NamespaceId(1)`),
    /// and register PID 1 (`Cred::root()`).
    pub async fn boot(
        instance_id: impl Into<String>,
        root_backing: Rc<MountBacking>,
        root_source: impl Into<String>,
        factory: Rc<dyn FilesystemFactory>,
    ) -> Result<Self> {
        let releases = ReleaseQueue::new();
        let root_cred = Cred::root();
        let root_handle = root_backing.fs.root();
        let mut path_opts = OpenOptions::new();
        path_opts.path(true);
        let root_open_ref = root_backing
            .fs
            .open(&root_cred, &root_handle, &path_opts)
            .await?;
        let root_open = FileRef::new_with_provider(
            Rc::clone(&root_backing.fs),
            Rc::clone(&root_backing.provider),
            None,
            root_open_ref,
            root_handle.clone(),
            root_cred.clone(),
            &path_opts,
            &releases,
        );

        let ns_id = NamespaceId(1);
        let root_slot = MountSlot::new(
            MountId(1),
            ns_id,
            root_handle.node,
            root_backing,
            MountFlags::default(),
            0,
            None,
        );
        let root_entry = MountEntry {
            slot: root_slot,
            parent: None,
            root: root_handle,
            root_open,
            root_in_fs: "/".to_string(),
            source: root_source.into(),
        };
        let system_ns = Rc::new(RefCell::new(MountNamespace::new(ns_id, root_entry)));
        let init_anchor = system_ns.borrow().root_anchor();
        let init_ctx = SharedFsContext::new(
            init_anchor.clone(),
            init_anchor,
            os_core::permissions::UMASK,
        );
        let mut processes = BTreeMap::new();
        processes.insert(
            1,
            ProcessCtx {
                pid: 1,
                ppid: 0,
                cred: root_cred,
                mnt_ns: Rc::clone(&system_ns),
                fs_ctx: init_ctx,
                fds: SharedFdTable::new(),
            },
        );
        let mut namespaces = HashMap::new();
        namespaces.insert(ns_id, Rc::downgrade(&system_ns));

        Ok(Self {
            inner: Rc::new(VfsInner {
                instance_id: instance_id.into(),
                next_mount_id: Cell::new(2),
                next_ns_id: Cell::new(2),
                active_pid: Cell::new(None),
                releases,
                factory,
                system_ns,
                namespaces: RefCell::new(namespaces),
                processes: RefCell::new(processes),
            }),
        })
    }

    pub fn instance_id(&self) -> &str {
        &self.inner.instance_id
    }

    pub fn system_namespace(&self) -> Rc<RefCell<MountNamespace>> {
        Rc::clone(&self.inner.system_ns)
    }

    pub fn releases(&self) -> &ReleaseQueue {
        &self.inner.releases
    }

    pub fn proc_bridge(&self) -> Weak<dyn ProcBridge> {
        let rc: Rc<dyn ProcBridge> = self.inner.clone();
        Rc::downgrade(&rc)
    }

    /// Mint a private clone of `ns` (used by login session creation and `CLONE_NEWNS`).
    pub fn clone_namespace(
        &self,
        ns: &Rc<RefCell<MountNamespace>>,
    ) -> (Rc<RefCell<MountNamespace>>, HashMap<MountId, Rc<MountSlot>>) {
        let new_ns_id = self.inner.alloc_ns_id();
        let (cloned, map) = ns
            .borrow()
            .clone_private(new_ns_id, || self.inner.alloc_mount_id());
        let rc = Rc::new(RefCell::new(cloned));
        self.inner.register_namespace(&rc);
        (rc, map)
    }

    /// Spawn/register a new top-level process in `Vfs` (defaulting to `system_ns` and its `"/"`).
    pub fn spawn_process(
        &self,
        pid: u32,
        ppid: u32,
        cred: Cred,
        mnt_ns: Option<Rc<RefCell<MountNamespace>>>,
        root: Option<PathAnchor>,
        cwd: Option<PathAnchor>,
    ) -> Result<()> {
        let mut procs = self.inner.processes.borrow_mut();
        if procs.contains_key(&pid) {
            return Err(Errno::EEXIST);
        }
        let ns = mnt_ns.unwrap_or_else(|| Rc::clone(&self.inner.system_ns));
        self.inner.register_namespace(&ns);
        let default_anchor = ns.borrow().root_anchor();
        let root_anchor = root.unwrap_or_else(|| default_anchor.clone());
        let cwd_anchor = cwd.unwrap_or(default_anchor);
        let umask = cred.umask;
        procs.insert(
            pid,
            ProcessCtx {
                pid,
                ppid,
                cred,
                mnt_ns: ns,
                fs_ctx: SharedFsContext::new(root_anchor, cwd_anchor, umask),
                fds: SharedFdTable::new(),
            },
        );
        Ok(())
    }

    /// Fork `parent_pid` into `child_pid` honoring `CLONE_FS`, `CLONE_FILES`, and `CLONE_NEWNS`.
    pub fn fork_process(&self, parent_pid: u32, child_pid: u32, clone_flags: u32) -> Result<()> {
        let clean = unshare_flags::accepted_unshare(clone_flags)?;
        let mut procs = self.inner.processes.borrow_mut();
        if procs.contains_key(&child_pid) {
            return Err(Errno::EEXIST);
        }
        let parent = procs.get(&parent_pid).ok_or(Errno::ESRCH)?;
        if clean & unshare_flags::CLONE_NEWNS != 0 && parent.cred.identity.id != 0 {
            return Err(Errno::EPERM);
        }

        // When `CLONE_NEWNS` is set, the child gets an unshared `FsContext` so remapping its
        // `root`/`cwd` pins onto the new `MountNamespace` never mutates the parent's anchors.
        let share_fs =
            (clean & unshare_flags::CLONE_FS != 0) && (clean & unshare_flags::CLONE_NEWNS == 0);
        let share_files = clean & unshare_flags::CLONE_FILES != 0;
        let cred = parent.cred.clone();
        let fs_ctx = parent.fs_ctx.fork_clone(share_fs);
        let fds = parent.fds.fork_clone(share_files);
        let mnt_ns = if clean & unshare_flags::CLONE_NEWNS != 0 {
            let (new_ns, map) = self.clone_namespace(&parent.mnt_ns);
            let pin_map: HashMap<MountId, MountPin> =
                map.into_iter().map(|(k, slot)| (k, slot.pin())).collect();
            {
                let mut ctx = fs_ctx.borrow_mut();
                ctx.root.remap_pin(&pin_map);
                ctx.cwd.remap_pin(&pin_map);
            }
            new_ns
        } else {
            Rc::clone(&parent.mnt_ns)
        };

        procs.insert(
            child_pid,
            ProcessCtx {
                pid: child_pid,
                ppid: parent_pid,
                cred,
                mnt_ns,
                fs_ctx,
                fds,
            },
        );
        Ok(())
    }

    /// `execve` preservation: unshares `CLONE_FS` and `CLONE_FILES` if shared, keeps `mnt_ns`,
    /// `root`, `cwd`, and `umask` intact, and closes `FD_CLOEXEC` descriptors.
    pub async fn exec_preserve(&self, pid: u32) -> Result<()> {
        let (caller_uid, fds) = {
            let mut procs = self.inner.processes.borrow_mut();
            let proc_ctx = procs.get_mut(&pid).ok_or(Errno::ESRCH)?;
            proc_ctx.fs_ctx.unshare();
            proc_ctx.fds.unshare();
            (proc_ctx.cred.identity.id, proc_ctx.fds.clone())
        };
        fds.close_on_exec().await;
        let _ = self.inner.releases.flush_scoped(caller_uid, &[]).await;
        Ok(())
    }

    pub fn set_cred(&self, pid: u32, cred: Cred) -> Result<()> {
        let mut procs = self.inner.processes.borrow_mut();
        let proc_ctx = procs.get_mut(&pid).ok_or(Errno::ESRCH)?;
        proc_ctx.cred = cred;
        Ok(())
    }

    pub fn set_umask(&self, pid: u32, umask: u16) -> Result<u16> {
        let mut procs = self.inner.processes.borrow_mut();
        let proc_ctx = procs.get_mut(&pid).ok_or(Errno::ESRCH)?;
        let masked = umask & 0o777;
        proc_ctx.cred.umask = masked;
        let prev = {
            let mut ctx = proc_ctx.fs_ctx.borrow_mut();
            let old = ctx.umask;
            ctx.umask = masked;
            old
        };
        Ok(prev)
    }

    pub async fn exit_process(&self, pid: u32) -> Result<()> {
        let removed = self.inner.processes.borrow_mut().remove(&pid);
        let Some(proc_ctx) = removed else {
            return Err(Errno::ESRCH);
        };
        let caller_uid = proc_ctx.cred.identity.id;
        let mut providers = Vec::new();
        {
            let ctx = proc_ctx.fs_ctx.borrow();
            providers.push(Rc::as_ptr(ctx.root.pin.provider()));
            providers.push(Rc::as_ptr(ctx.cwd.pin.provider()));
        }
        if !proc_ctx.fds.is_shared() {
            proc_ctx.fds.close_all().await;
        }
        drop(proc_ctx);
        let _ = self
            .inner
            .releases
            .flush_scoped(caller_uid, &providers)
            .await;
        Ok(())
    }

    /// A host service grant applies only to a direct child with an unrestricted inherited root.
    pub fn check_service_child(&self, parent: u32, child: u32) -> Result<()> {
        let processes = self.inner.processes.borrow();
        let p = processes.get(&parent).ok_or(Errno::ESRCH)?;
        let c = processes.get(&child).ok_or(Errno::ESRCH)?;
        if parent == child
            || c.ppid != parent
            || [p, c].iter().any(|p| {
                !p.fs_ctx
                    .borrow()
                    .root
                    .same_anchor(&p.mnt_ns.borrow().root_anchor())
            })
        {
            return Err(Errno::EPERM);
        }
        Ok(())
    }

    pub fn install_service_namespace(
        &self,
        parent: u32,
        child: u32,
        ns: Rc<RefCell<MountNamespace>>,
    ) -> Result<()> {
        self.check_service_child(parent, child)?;
        let mut processes = self.inner.processes.borrow_mut();
        let child = processes.get_mut(&child).ok_or(Errno::ESRCH)?;
        let root = ns.borrow().root_anchor();
        child.fs_ctx.unshare();
        let mut ctx = child.fs_ctx.borrow_mut();
        ctx.root = root.clone();
        ctx.cwd = root;
        child.mnt_ns = ns;
        Ok(())
    }

    pub fn process_cred(&self, pid: u32) -> Result<Cred> {
        self.inner
            .processes
            .borrow()
            .get(&pid)
            .map(|p| p.cred.clone())
            .ok_or(Errno::ESRCH)
    }

    pub fn process_namespace(&self, pid: u32) -> Result<Rc<RefCell<MountNamespace>>> {
        let procs = self.inner.processes.borrow();
        let p = procs.get(&pid).ok_or(Errno::ESRCH)?;
        Ok(Rc::clone(&p.mnt_ns))
    }

    pub fn process_fs_context(&self, pid: u32) -> Result<SharedFsContext> {
        let procs = self.inner.processes.borrow();
        let p = procs.get(&pid).ok_or(Errno::ESRCH)?;
        Ok(p.fs_ctx.clone())
    }

    pub fn process_fds(&self, pid: u32) -> Result<SharedFdTable> {
        let procs = self.inner.processes.borrow();
        let p = procs.get(&pid).ok_or(Errno::ESRCH)?;
        Ok(p.fds.clone())
    }

    fn snapshot_proc(
        &self,
        pid: u32,
    ) -> Result<(
        Cred,
        Rc<RefCell<MountNamespace>>,
        SharedFsContext,
        SharedFdTable,
    )> {
        let procs = self.inner.processes.borrow();
        let p = procs.get(&pid).ok_or(Errno::ESRCH)?;
        let mut cred = p.cred.clone();
        cred.umask = p.fs_ctx.borrow().umask;
        Ok((cred, Rc::clone(&p.mnt_ns), p.fs_ctx.clone(), p.fds.clone()))
    }

    fn with_caller<'a, F>(&'a self, pid: u32, fut: F) -> WithCallerPid<'a, F>
    where
        F: Future,
    {
        WithCallerPid {
            active_pid: &self.inner.active_pid,
            pid,
            fut: Box::pin(fut),
        }
    }

    async fn open_path_ref(
        &self,
        cred: &Cred,
        backing: &Rc<MountBacking>,
        owner_uid: Option<u32>,
        handle: &Handle,
    ) -> Result<FileRef> {
        let mut opts = OpenOptions::new();
        opts.path(true);
        let open = backing
            .provider
            .guard_future(false, backing.fs.open(cred, handle, &opts))
            .await?;
        Ok(FileRef::new_with_provider(
            Rc::clone(&backing.fs),
            Rc::clone(&backing.provider),
            owner_uid,
            open,
            handle.clone(),
            cred.clone(),
            &opts,
            &self.inner.releases,
        ))
    }

    async fn make_anchor(&self, cred: &Cred, pin: MountPin, handle: Handle) -> Result<PathAnchor> {
        let open = self
            .open_path_ref(cred, pin.backing(), pin.owner_uid(), &handle)
            .await?;
        Ok(PathAnchor { pin, handle, open })
    }

    #[allow(clippy::too_many_arguments)]
    async fn resolve_fallback_last_step(
        &self,
        cred: &Cred,
        ns: &Rc<RefCell<MountNamespace>>,
        ctx: &crate::context::FsContext,
        fds: &impl crate::walk::FdLookup,
        anchor: &StartAnchor,
        target_path: &str,
        dst_pin: &MountPin,
        dst_entry: &Entry,
        last_step: Option<(MountPin, Handle, String)>,
    ) -> Option<(MountPin, Handle, String)> {
        if last_step.is_some() || dst_entry.handle.node == dst_pin.root_node() {
            return last_step;
        }
        let bridge: &dyn ProcBridge = &*self.inner;
        if let Ok(ParentResolution::Child(t)) =
            walk_parent(cred, ns, ctx, fds, Some(bridge), anchor, target_path).await
            && t.parent_pin.id() == dst_pin.id()
            && let Ok(looked) = t
                .parent_pin
                .guard_op(
                    cred,
                    false,
                    false,
                    t.parent_pin.fs().lookup(cred, &t.parent.handle, &t.name),
                )
                .await
            && looked.handle.node == dst_entry.handle.node
        {
            return Some((t.parent_pin, t.parent.handle, t.name));
        }
        None
    }

    async fn build_attachment(
        &self,
        cred: &Cred,
        dst_pin: MountPin,
        dst_entry: &Entry,
        last_step: Option<(MountPin, Handle, String)>,
    ) -> Result<MountAttachment> {
        let mountpoint_open = self
            .open_path_ref(
                cred,
                dst_pin.backing(),
                dst_pin.owner_uid(),
                &dst_entry.handle,
            )
            .await?;
        let (mp_parent_node, mp_name) = if dst_entry.handle.node == dst_pin.root_node() {
            (None, None)
        } else if let Some((step_pin, step_parent, step_name)) = last_step
            && step_pin.id() == dst_pin.id()
        {
            (Some(step_parent.node), Some(step_name))
        } else if dst_entry.metadata.is_dir()
            && let Some((parent_entry, name)) = dst_pin
                .guard_op(
                    cred,
                    false,
                    false,
                    dst_pin.fs().parent(cred, &dst_entry.handle),
                )
                .await?
        {
            (Some(parent_entry.handle.node), Some(name))
        } else {
            (None, None)
        };
        Ok(MountAttachment {
            parent_pin: dst_pin,
            mountpoint: dst_entry.handle.clone(),
            mountpoint_open,
            mp_parent_node,
            mp_name,
        })
    }

    async fn commit_mount_entry(
        &self,
        ns: &Rc<RefCell<MountNamespace>>,
        entry: MountEntry,
    ) -> Result<MountId> {
        let res = ns.borrow_mut().try_attach(entry);
        match res {
            Ok(id) => Ok(id),
            Err(boxed) => {
                let (
                    err,
                    MountEntry {
                        parent, root_open, ..
                    },
                ) = *boxed;
                if let Some(att) = parent {
                    let _ = att.mountpoint_open.close().await;
                }
                let _ = root_open.close().await;
                Err(err)
            }
        }
    }

    /// Programmatically attach `backing` inside `ns` at `target_path` (resolved from `ns` root).
    /// Used at kernel boot (`/usr`, `/proc`, `/dev`, `/dev/pts`, `/mnt/local`, `/mnt/shared`,
    /// `/opt/private`) and by the user mount service (`owner_uid = Some(uid)`).
    #[allow(clippy::too_many_arguments)]
    pub async fn mount_on_namespace(
        &self,
        ns: &Rc<RefCell<MountNamespace>>,
        cred: &Cred,
        backing: Rc<MountBacking>,
        subroot: Option<(Handle, String)>,
        source: &str,
        target_path: &str,
        flags: MountFlags,
        locked_flags: u64,
        owner_uid: Option<u32>,
    ) -> Result<MountId> {
        self.inner.register_namespace(ns);
        let ns_root = ns.borrow().root_anchor();
        let temp_ctx = crate::context::FsContext {
            root: ns_root.clone(),
            cwd: ns_root,
            umask: cred.umask,
        };
        let empty_fds = crate::FdTable::new();
        let bridge: &dyn ProcBridge = &*self.inner;
        let (walk_target, walk_flags) = if owner_uid.is_some() {
            let trimmed = if target_path.len() > 1 {
                let t = target_path.trim_end_matches('/');
                if t.is_empty() { "/" } else { t }
            } else {
                target_path
            };
            (trimmed, WalkFlags::MUST_BE_DIR)
        } else {
            (target_path, WalkFlags::FOLLOW_LAST)
        };
        let resolved = walk(
            cred,
            ns,
            &temp_ctx,
            &empty_fds,
            Some(bridge),
            &StartAnchor::Root,
            walk_target,
            walk_flags,
        )
        .await?;
        let WalkResult::Found {
            pin: dst_pin,
            entry: dst_entry,
            last_step,
            ..
        } = resolved
        else {
            return Err(Errno::ENOENT);
        };

        if let Some(uid) = owner_uid
            && (!dst_entry.metadata.is_dir() || dst_entry.metadata.uid != uid)
        {
            return Err(Errno::EPERM);
        }

        let (root_handle, root_in_fs) =
            subroot.unwrap_or_else(|| (backing.fs.root(), "/".to_string()));
        let root_meta = backing.fs.metadata(cred, &root_handle).await?;
        if root_meta.is_dir() != dst_entry.metadata.is_dir() {
            return Err(Errno::ENOTDIR);
        }

        let last_step = self
            .resolve_fallback_last_step(
                cred,
                ns,
                &temp_ctx,
                &empty_fds,
                &StartAnchor::Root,
                walk_target,
                &dst_pin,
                &dst_entry,
                last_step,
            )
            .await;

        let root_open = match self
            .open_path_ref(cred, &backing, owner_uid, &root_handle)
            .await
        {
            Ok(f) => f,
            Err(e) => return Err(e),
        };
        let att = match self
            .build_attachment(cred, dst_pin, &dst_entry, last_step)
            .await
        {
            Ok(a) => a,
            Err(e) => {
                let _ = root_open.close().await;
                return Err(e);
            }
        };
        let ns_id = ns.borrow().id();
        let mount_id = self.inner.alloc_mount_id();
        let slot = MountSlot::new(
            mount_id,
            ns_id,
            root_handle.node,
            backing,
            flags,
            locked_flags,
            owner_uid,
        );
        let entry = MountEntry {
            slot,
            parent: Some(att),
            root: root_handle,
            root_open,
            root_in_fs,
            source: source.to_string(),
        };
        self.commit_mount_entry(ns, entry).await
    }

    async fn sync_dir_if_needed(
        &self,
        cred: &Cred,
        pin: &MountPin,
        dir_handle: &Handle,
    ) -> Result<()> {
        let eff = pin.effective_flags();
        if !(eff.synchronous || eff.dirsync) {
            return Ok(());
        }
        pin.guard_op(cred, true, false, pin.fs().sync_handle(cred, dir_handle))
            .await?;
        pin.backing().record_sync();
        Ok(())
    }

    async fn sync_object_if_needed(
        &self,
        cred: &Cred,
        pin: &MountPin,
        handle: &Handle,
    ) -> Result<()> {
        if !pin.effective_flags().synchronous {
            return Ok(());
        }
        pin.guard_op(cred, true, false, pin.fs().sync_handle(cred, handle))
            .await?;
        pin.backing().record_sync();
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Working directory & root syscalls: getcwd, chdir, fchdir, chroot
    // -------------------------------------------------------------------------

    pub async fn getcwd(&self, pid: u32) -> Result<String> {
        self.with_caller(pid, async move {
            let (cred, ns, fs_ctx, _) = self.snapshot_proc(pid)?;
            let (root_anchor, cwd_anchor) = {
                let ctx = fs_ctx.borrow();
                (ctx.root.clone(), ctx.cwd.clone())
            };

            let mut cur_pin = cwd_anchor.pin;
            let mut cur_handle = cwd_anchor.handle;
            let mut cur_ns = if ns.borrow().id() == cur_pin.ns_id() {
                Rc::clone(&ns)
            } else {
                self.inner
                    .namespace_by_id(cur_pin.ns_id())
                    .unwrap_or_else(|| Rc::clone(&ns))
            };
            cur_pin.guard_enter(&cred)?;

            // Verify `cwd` has not been unlinked (`cwd-remove` -> ENOENT even if cwd == root).
            let cwd_meta = cur_pin
                .guard_op(
                    &cred,
                    false,
                    false,
                    cur_pin.fs().metadata(&cred, &cur_handle),
                )
                .await?;
            if cwd_meta.nlink == 0 {
                return Err(Errno::ENOENT);
            }

            let mut components: Vec<String> = Vec::new();
            loop {
                cur_pin.guard_enter(&cred)?;
                if root_anchor.same_location(&cur_pin, cur_handle.node) {
                    let path = if components.is_empty() {
                        "/".to_string()
                    } else {
                        components.reverse();
                        format!("/{}", components.join("/"))
                    };
                    if path.len() > abi::PATH_MAX {
                        return Err(Errno::ENAMETOOLONG);
                    }
                    return Ok(path);
                }

                while cur_handle.node == cur_pin.root_node() {
                    if root_anchor.same_location(&cur_pin, cur_handle.node) {
                        let path = if components.is_empty() {
                            "/".to_string()
                        } else {
                            components.reverse();
                            format!("/{}", components.join("/"))
                        };
                        if path.len() > abi::PATH_MAX {
                            return Err(Errno::ENAMETOOLONG);
                        }
                        return Ok(path);
                    }
                    if cur_pin.is_detached() {
                        if let Some((p_pin, mp_handle, _, _)) =
                            cur_pin.detached_mount_parent(cur_pin.id())
                        {
                            cur_pin = p_pin;
                            cur_handle = mp_handle;
                            continue;
                        }
                        // Detached mount root (`umount2(MNT_DETACH)`) -> ENOENT (`unmount-cwd`).
                        return Err(Errno::ENOENT);
                    }
                    if cur_ns.borrow().id() != cur_pin.ns_id()
                        && let Some(found) = self.inner.namespace_by_id(cur_pin.ns_id())
                    {
                        cur_ns = found;
                    }
                    let parent_step = cur_ns
                        .borrow()
                        .entry(cur_pin.id())
                        .and_then(|e| e.parent.as_ref())
                        .map(|att| (att.parent_pin.clone(), att.mountpoint.clone()));
                    match parent_step {
                        Some((p_pin, mp_handle)) => {
                            cur_pin = p_pin;
                            cur_handle = mp_handle;
                        }
                        // Reached namespace `/` without hitting `ctx.root` -> outside `chroot` (`ENOENT`).
                        None => return Err(Errno::ENOENT),
                    }
                }

                cur_pin.guard_enter(&cred)?;
                if root_anchor.same_location(&cur_pin, cur_handle.node) {
                    let path = if components.is_empty() {
                        "/".to_string()
                    } else {
                        components.reverse();
                        format!("/{}", components.join("/"))
                    };
                    if path.len() > abi::PATH_MAX {
                        return Err(Errno::ENAMETOOLONG);
                    }
                    return Ok(path);
                }

                match cur_pin
                    .guard_op(&cred, false, false, cur_pin.fs().parent(&cred, &cur_handle))
                    .await?
                {
                    Some((parent_entry, name)) => {
                        components.push(name);
                        cur_handle = parent_entry.handle;
                    }
                    None => return Err(Errno::ENOENT),
                }
            }
        })
        .await
    }

    pub async fn chdir(&self, pid: u32, path: &str) -> Result<()> {
        self.with_caller(pid, async move {
            let (cred, ns, fs_ctx, fds) = self.snapshot_proc(pid)?;
            let ctx_snap = fs_ctx.borrow().clone();
            let bridge: &dyn ProcBridge = &*self.inner;
            let resolved = walk(
                &cred,
                &ns,
                &ctx_snap,
                &fds,
                Some(bridge),
                &StartAnchor::AtFdCwd,
                path,
                WalkFlags::FOLLOW_LAST | WalkFlags::MUST_BE_DIR,
            )
            .await?;
            let WalkResult::Found { pin, entry, .. } = resolved else {
                return Err(Errno::ENOENT);
            };
            let mut searchable = false;
            ensure_searchable(&cred, &pin, &entry.handle, &mut searchable).await?;
            let new_cwd = self.make_anchor(&cred, pin, entry.handle).await?;
            let old_prov = {
                let mut ctx = fs_ctx.borrow_mut();
                let old = Rc::as_ptr(ctx.cwd.pin.provider());
                ctx.cwd = new_cwd;
                old
            };
            let _ = self
                .inner
                .releases
                .flush_scoped(cred.identity.id, &[old_prov])
                .await;
            Ok(())
        })
        .await
    }

    pub async fn fchdir(&self, pid: u32, fd: Fd) -> Result<()> {
        self.with_caller(pid, async move {
            let (cred, _, fs_ctx, fds) = self.snapshot_proc(pid)?;
            let file = fds.borrow().get(fd)?;
            if file.mount_ns().is_some() {
                return Err(Errno::ENOTDIR);
            }
            let pin = file.mount_pin().ok_or(Errno::EBADF)?.clone();
            let meta = file.metadata_as(&cred).await?;
            if !meta.is_dir() {
                return Err(Errno::ENOTDIR);
            }
            let mut searchable = false;
            ensure_searchable(&cred, &pin, file.handle(), &mut searchable).await?;
            let new_cwd = self.make_anchor(&cred, pin, file.handle().clone()).await?;
            let old_prov = {
                let mut ctx = fs_ctx.borrow_mut();
                let old = Rc::as_ptr(ctx.cwd.pin.provider());
                ctx.cwd = new_cwd;
                old
            };
            let _ = self
                .inner
                .releases
                .flush_scoped(cred.identity.id, &[old_prov])
                .await;
            Ok(())
        })
        .await
    }

    /// `chroot(2)`: walks `path` (`FOLLOW_LAST | MUST_BE_DIR`) and checks `X_OK` search permission
    /// FIRST, then enforces `cred.identity.id == 0` (`EPERM`), matching Linux `ksys_chroot`.
    /// Replaces ONLY `FsContext.root` — never alters `cwd`, `fds`, or `mnt_ns`.
    pub async fn chroot(&self, pid: u32, path: &str) -> Result<()> {
        self.with_caller(pid, async move {
            let (cred, ns, fs_ctx, fds) = self.snapshot_proc(pid)?;
            let ctx_snap = fs_ctx.borrow().clone();
            let bridge: &dyn ProcBridge = &*self.inner;
            let resolved = walk(
                &cred,
                &ns,
                &ctx_snap,
                &fds,
                Some(bridge),
                &StartAnchor::AtFdCwd,
                path,
                WalkFlags::FOLLOW_LAST | WalkFlags::MUST_BE_DIR,
            )
            .await?;
            let WalkResult::Found { pin, entry, .. } = resolved else {
                return Err(Errno::ENOENT);
            };
            let mut searchable = false;
            ensure_searchable(&cred, &pin, &entry.handle, &mut searchable).await?;
            if cred.identity.id != 0 {
                return Err(Errno::EPERM);
            }
            let new_root = self.make_anchor(&cred, pin, entry.handle).await?;
            let old_prov = {
                let mut ctx = fs_ctx.borrow_mut();
                let old = Rc::as_ptr(ctx.root.pin.provider());
                ctx.root = new_root;
                old
            };
            let _ = self
                .inner
                .releases
                .flush_scoped(cred.identity.id, &[old_prov])
                .await;
            Ok(())
        })
        .await
    }

    // -------------------------------------------------------------------------
    // Mount, umount2, unshare, setns, statfs, fstatfs
    // -------------------------------------------------------------------------

    async fn compute_root_in_fs(
        &self,
        cred: &Cred,
        ns: &Rc<RefCell<MountNamespace>>,
        src_pin: &MountPin,
        src_entry: &Entry,
        src_last_step: Option<(MountPin, Handle, String)>,
    ) -> Result<String> {
        let base_root_in_fs = ns
            .borrow()
            .entry(src_pin.id())
            .map(|e| e.root_in_fs.clone())
            .unwrap_or_else(|| "/".to_string());
        if src_entry.handle.node == src_pin.root_node() {
            return Ok(base_root_in_fs);
        }

        let mut segments: Vec<String> = Vec::new();
        let mut cur_handle = if src_entry.metadata.is_dir() {
            src_entry.handle.clone()
        } else if let Some((step_pin, parent_handle, file_name)) = src_last_step
            && step_pin.id() == src_pin.id()
        {
            segments.push(file_name);
            parent_handle
        } else {
            return Ok(base_root_in_fs);
        };

        while cur_handle.node != src_pin.root_node() {
            match src_pin
                .guard_op(cred, false, false, src_pin.fs().parent(cred, &cur_handle))
                .await?
            {
                Some((parent_entry, name)) => {
                    segments.push(name);
                    cur_handle = parent_entry.handle;
                }
                None => break,
            }
        }
        segments.reverse();
        let rel = segments.join("/");
        if base_root_in_fs == "/" {
            Ok(format!("/{rel}"))
        } else {
            Ok(format!("{}/{rel}", base_root_in_fs.trim_end_matches('/')))
        }
    }

    async fn snapshot_submounts_under(
        &self,
        cred: &Cred,
        ns: &Rc<RefCell<MountNamespace>>,
        src_pin: &MountPin,
        src_entry: &Entry,
    ) -> Result<Vec<SubmountSpec>> {
        if !src_entry.metadata.is_dir() {
            return Ok(Vec::new());
        }

        #[derive(Clone)]
        struct RawChild {
            id: MountId,
            mp_handle: Handle,
            slot: Rc<MountSlot>,
            root: Handle,
            root_open: FileRef,
            root_in_fs: String,
            source: String,
        }

        let by_parent: HashMap<MountId, Vec<RawChild>> = {
            let ns_ref = ns.borrow();
            let mut map: HashMap<MountId, Vec<RawChild>> = HashMap::new();
            let mut parent_ids: Vec<MountId> = ns_ref.mounts().keys().copied().collect();
            parent_ids.sort_by_key(|id| id.0);
            for p_id in parent_ids {
                for child_id in ns_ref.direct_children_of(p_id) {
                    if let Some(ce) = ns_ref.entry(child_id)
                        && let Some(att) = &ce.parent
                    {
                        map.entry(p_id).or_default().push(RawChild {
                            id: child_id,
                            mp_handle: att.mountpoint.clone(),
                            slot: Rc::clone(&ce.slot),
                            root: ce.root.clone(),
                            root_open: ce.root_open.clone(),
                            root_in_fs: ce.root_in_fs.clone(),
                            source: ce.source.clone(),
                        });
                    }
                }
            }
            map
        };

        struct SubmountQueueItem {
            cur_id: MountId,
            cur_slot: Rc<MountSlot>,
            boundary_node: NodeId,
            base_rel: Vec<String>,
            is_initial_src: bool,
        }

        let mut out = Vec::new();
        let mut queue: std::collections::VecDeque<SubmountQueueItem> =
            std::collections::VecDeque::new();
        queue.push_back(SubmountQueueItem {
            cur_id: src_pin.id(),
            cur_slot: Rc::clone(src_pin.slot()),
            boundary_node: src_entry.handle.node,
            base_rel: Vec::new(),
            is_initial_src: true,
        });

        while let Some(SubmountQueueItem {
            cur_id,
            cur_slot,
            boundary_node,
            base_rel,
            is_initial_src,
        }) = queue.pop_front()
        {
            let Some(children) = by_parent.get(&cur_id) else {
                continue;
            };
            for child in children {
                let mut rel_tail: Vec<String> = Vec::new();
                let mut inside = false;
                if child.mp_handle.node == boundary_node {
                    // On `src_pin` itself, `walk(FOLLOW_LAST)` already stepped to the topmost mount
                    // at `src_entry`, so only strict descendants inside `src_entry` lie beneath it.
                    if !is_initial_src {
                        inside = true;
                    }
                } else {
                    if cur_slot
                        .owner_uid
                        .is_some_and(|owner| owner != cred.identity.id)
                    {
                        continue;
                    }
                    let mut probe = child.mp_handle.clone();
                    loop {
                        if probe.node == boundary_node {
                            inside = true;
                            break;
                        }
                        if probe.node == cur_slot.root_node {
                            break;
                        }
                        match cur_slot
                            .guard_op(cred, false, false, cur_slot.backing.fs.parent(cred, &probe))
                            .await?
                        {
                            Some((p_entry, name)) => {
                                rel_tail.push(name);
                                probe = p_entry.handle;
                            }
                            None => break,
                        }
                    }
                }
                if !inside {
                    continue;
                }
                child.slot.backing.provider.check_health()?;
                rel_tail.reverse();
                let mut full_rel = base_rel.clone();
                full_rel.extend(rel_tail);
                out.push(SubmountSpec {
                    rel_segments: full_rel.clone(),
                    backing: Rc::clone(&child.slot.backing),
                    root: child.root.clone(),
                    root_open: child.root_open.clone(),
                    root_in_fs: child.root_in_fs.clone(),
                    source: child.source.clone(),
                    flags: child.slot.flags(),
                    locked_flags: child.slot.locked_flags(),
                    owner_uid: child.slot.owner_uid,
                });
                if child
                    .slot
                    .owner_uid
                    .is_none_or(|owner| owner == cred.identity.id)
                {
                    queue.push_back(SubmountQueueItem {
                        cur_id: child.id,
                        cur_slot: Rc::clone(&child.slot),
                        boundary_node: child.root.node,
                        base_rel: full_rel,
                        is_initial_src: false,
                    });
                }
            }
        }
        Ok(out)
    }

    pub async fn mount(
        &self,
        pid: u32,
        source: &str,
        target: &str,
        fstype: Option<&str>,
        flags: u64,
        data: Option<&str>,
    ) -> Result<()> {
        self.with_caller(pid, async move {
            let clean_with_priv = mount_flags::accepted(flags)?;
            let (cred, ns, fs_ctx, fds) = self.snapshot_proc(pid)?;
            let ctx_snap = fs_ctx.borrow().clone();
            let bridge: &dyn ProcBridge = &*self.inner;

            // Propagation-only `--make-private` (`MS_PRIVATE [| MS_REC]` with no other action):
            let non_priv = clean_with_priv & !mount_flags::MS_PRIVATE;
            if clean_with_priv & mount_flags::MS_PRIVATE != 0
                && (non_priv == 0 || non_priv == mount_flags::MS_REC)
                && fstype.is_none_or(str::is_empty)
            {
                let resolved = walk(
                    &cred,
                    &ns,
                    &ctx_snap,
                    &fds,
                    Some(bridge),
                    &StartAnchor::AtFdCwd,
                    target,
                    WalkFlags::FOLLOW_LAST,
                )
                .await?;
                let WalkResult::Found { pin, entry, .. } = resolved else {
                    return Err(Errno::ENOENT);
                };
                if entry.handle.node != pin.root_node() {
                    return Err(Errno::EINVAL);
                }
                if cred.identity.id != 0 {
                    return Err(Errno::EPERM);
                }
                return Ok(());
            }

            let clean = non_priv;

            // 1. `MS_REMOUNT` (including `MS_REMOUNT | MS_BIND`)
            if clean & mount_flags::MS_REMOUNT != 0 {
                if clean & mount_flags::MS_MOVE != 0 {
                    return Err(Errno::EINVAL);
                }
                let resolved = walk(
                    &cred,
                    &ns,
                    &ctx_snap,
                    &fds,
                    Some(bridge),
                    &StartAnchor::AtFdCwd,
                    target,
                    WalkFlags::FOLLOW_LAST,
                )
                .await?;
                let WalkResult::Found { pin, entry, .. } = resolved else {
                    return Err(Errno::ENOENT);
                };
                if entry.handle.node != pin.root_node() {
                    return Err(Errno::EINVAL);
                }
                if let Some(owner) = pin.owner_uid() {
                    if cred.identity.id != owner {
                        return Err(Errno::EACCES);
                    }
                    if owner != 0
                        && ((clean & mount_flags::MS_NOSUID == 0)
                            || (clean & mount_flags::MS_NODEV == 0))
                    {
                        return Err(Errno::EPERM);
                    }
                } else if cred.identity.id != 0 {
                    return Err(Errno::EPERM);
                }

                // Enforce locked ceiling flags (`MS_NOSUID`, `MS_NODEV`, `ceiling_rdonly`, `ceiling_noexec`).
                if (!clean) & pin.locked_flags() != 0 {
                    return Err(Errno::EPERM);
                }

                let new_flags = MountFlags::from_accepted(clean);
                if new_flags.rdonly
                    && !pin.effective_rdonly()
                    && (pin.writable_opens() > 0 || pin.in_flight_writes() > 0)
                {
                    return Err(Errno::EBUSY);
                }
                pin.slot().set_flags(new_flags);
                ns.borrow_mut().bump_generation();
                return Ok(());
            }

            // 2. `MS_BIND` (`| MS_REC`)
            if clean & mount_flags::MS_BIND != 0 {
                if clean & mount_flags::MS_MOVE != 0 {
                    return Err(Errno::EINVAL);
                }
                if cred.identity.id != 0 {
                    return Err(Errno::EPERM);
                }
                let src_res = walk(
                    &cred,
                    &ns,
                    &ctx_snap,
                    &fds,
                    Some(bridge),
                    &StartAnchor::AtFdCwd,
                    source,
                    WalkFlags::FOLLOW_LAST,
                )
                .await?;
                let WalkResult::Found {
                    pin: src_pin,
                    entry: src_entry,
                    last_step: src_last_step,
                    ..
                } = src_res
                else {
                    return Err(Errno::ENOENT);
                };

                let dst_res = walk(
                    &cred,
                    &ns,
                    &ctx_snap,
                    &fds,
                    Some(bridge),
                    &StartAnchor::AtFdCwd,
                    target,
                    WalkFlags::FOLLOW_LAST,
                )
                .await?;
                let WalkResult::Found {
                    pin: dst_pin,
                    entry: dst_entry,
                    last_step: dst_last_step,
                    ..
                } = dst_res
                else {
                    return Err(Errno::ENOENT);
                };

                if src_entry.metadata.is_dir() != dst_entry.metadata.is_dir() {
                    return Err(Errno::ENOTDIR);
                }

                // Pre-snapshot recursive submounts BEFORE attaching root bind mount so
                // `mount --rbind /dir /dir/sub` terminates cleanly!
                let rec_submounts = if clean & mount_flags::MS_REC != 0 {
                    self.snapshot_submounts_under(&cred, &ns, &src_pin, &src_entry)
                        .await?
                } else {
                    Vec::new()
                };

                let dst_last_step = self
                    .resolve_fallback_last_step(
                        &cred,
                        &ns,
                        &ctx_snap,
                        &fds,
                        &StartAnchor::AtFdCwd,
                        target,
                        &dst_pin,
                        &dst_entry,
                        dst_last_step,
                    )
                    .await;

                let root_in_fs = self
                    .compute_root_in_fs(&cred, &ns, &src_pin, &src_entry, src_last_step)
                    .await?;
                let src_source = ns
                    .borrow()
                    .entry(src_pin.id())
                    .map(|e| e.source.clone())
                    .unwrap_or_else(|| src_pin.fstype().as_str().to_string());

                let root_open = self
                    .open_path_ref(
                        &cred,
                        src_pin.backing(),
                        src_pin.owner_uid(),
                        &src_entry.handle,
                    )
                    .await?;
                let att = match self
                    .build_attachment(&cred, dst_pin, &dst_entry, dst_last_step)
                    .await
                {
                    Ok(a) => a,
                    Err(e) => {
                        let _ = root_open.close().await;
                        return Err(e);
                    }
                };

                let ns_id = ns.borrow().id();
                let bind_id = self.inner.alloc_mount_id();
                let bind_slot = MountSlot::new(
                    bind_id,
                    ns_id,
                    src_entry.handle.node,
                    Rc::clone(src_pin.backing()),
                    src_pin.flags(),
                    src_pin.locked_flags(),
                    src_pin.owner_uid(),
                );
                let bind_anchor_pin = bind_slot.pin();
                let bind_anchor_handle = src_entry.handle.clone();
                let bind_anchor_open = root_open.clone();

                self.commit_mount_entry(
                    &ns,
                    MountEntry {
                        slot: bind_slot,
                        parent: Some(att),
                        root: src_entry.handle.clone(),
                        root_open,
                        root_in_fs,
                        source: src_source,
                    },
                )
                .await?;

                if !rec_submounts.is_empty() {
                    let bind_anchor = PathAnchor {
                        pin: bind_anchor_pin,
                        handle: bind_anchor_handle,
                        open: bind_anchor_open,
                    };
                    for sub in rec_submounts {
                        let rel_path = if sub.rel_segments.is_empty() {
                            ".".to_string()
                        } else {
                            sub.rel_segments.join("/")
                        };
                        let sub_dst = walk(
                            &cred,
                            &ns,
                            &ctx_snap,
                            &fds,
                            Some(bridge),
                            &StartAnchor::Anchor(bind_anchor.clone()),
                            &rel_path,
                            WalkFlags::FOLLOW_LAST,
                        )
                        .await?;
                        let WalkResult::Found {
                            pin: sub_dst_pin,
                            entry: sub_dst_entry,
                            last_step: sub_last_step,
                            ..
                        } = sub_dst
                        else {
                            continue;
                        };
                        let sub_root_open = sub.root_open;
                        let sub_att = match self
                            .build_attachment(&cred, sub_dst_pin, &sub_dst_entry, sub_last_step)
                            .await
                        {
                            Ok(a) => a,
                            Err(e) => {
                                drop(sub_root_open);
                                return Err(e);
                            }
                        };
                        let sub_id = self.inner.alloc_mount_id();
                        let sub_slot = MountSlot::new(
                            sub_id,
                            ns_id,
                            sub.root.node,
                            sub.backing,
                            sub.flags,
                            sub.locked_flags,
                            sub.owner_uid,
                        );
                        let _ = self
                            .commit_mount_entry(
                                &ns,
                                MountEntry {
                                    slot: sub_slot,
                                    parent: Some(sub_att),
                                    root: sub.root,
                                    root_open: sub_root_open,
                                    root_in_fs: sub.root_in_fs,
                                    source: sub.source,
                                },
                            )
                            .await;
                    }
                }
                let _ = self
                    .inner
                    .releases
                    .flush_scoped(cred.identity.id, &[])
                    .await;
                return Ok(());
            }

            // 3. `MS_MOVE` (including `switch_root` move onto `"/"`)
            if clean & mount_flags::MS_MOVE != 0 {
                if cred.identity.id != 0 {
                    return Err(Errno::EPERM);
                }
                let src_res = walk(
                    &cred,
                    &ns,
                    &ctx_snap,
                    &fds,
                    Some(bridge),
                    &StartAnchor::AtFdCwd,
                    source,
                    WalkFlags::FOLLOW_LAST,
                )
                .await?;
                let WalkResult::Found {
                    pin: src_pin,
                    entry: src_entry,
                    ..
                } = src_res
                else {
                    return Err(Errno::ENOENT);
                };

                let ns_root_id = ns.borrow().root_mount_id();
                if src_entry.handle.node != src_pin.root_node()
                    || src_pin.id() == ns_root_id
                    || ctx_snap.root.same_location(&src_pin, src_entry.handle.node)
                    || !ns.borrow().contains_mount(src_pin.id())
                {
                    return Err(Errno::EINVAL);
                }

                let dst_res = walk(
                    &cred,
                    &ns,
                    &ctx_snap,
                    &fds,
                    Some(bridge),
                    &StartAnchor::AtFdCwd,
                    target,
                    WalkFlags::FOLLOW_LAST,
                )
                .await?;
                let WalkResult::Found {
                    pin: dst_pin,
                    entry: dst_entry,
                    last_step: dst_last_step,
                    ..
                } = dst_res
                else {
                    return Err(Errno::ENOENT);
                };

                if src_entry.metadata.is_dir() != dst_entry.metadata.is_dir() {
                    return Err(Errno::ENOTDIR);
                }
                if ns.borrow().is_mount_ancestor(src_pin.id(), dst_pin.id()) {
                    return Err(Errno::EINVAL);
                }

                let is_ns_root_target =
                    dst_pin.id() == ns_root_id && dst_entry.handle.node == dst_pin.root_node();
                if is_ns_root_target {
                    let detached = ns.borrow_mut().switch_root_move(src_pin.id())?;
                    drop(detached);
                } else {
                    let dst_last_step = self
                        .resolve_fallback_last_step(
                            &cred,
                            &ns,
                            &ctx_snap,
                            &fds,
                            &StartAnchor::AtFdCwd,
                            target,
                            &dst_pin,
                            &dst_entry,
                            dst_last_step,
                        )
                        .await;
                    let new_att = self
                        .build_attachment(&cred, dst_pin, &dst_entry, dst_last_step)
                        .await?;
                    let move_res = ns.borrow_mut().try_move_mount(src_pin.id(), new_att);
                    if let Err(boxed) = move_res {
                        let (err, failed_att) = *boxed;
                        let _ = failed_att.mountpoint_open.close().await;
                        return Err(err);
                    }
                }
                let _ = self
                    .inner
                    .releases
                    .flush_scoped(cred.identity.id, &[])
                    .await;
                return Ok(());
            }

            // 4. New filesystem mount (`fstype` required)
            let fstype_str = fstype.filter(|s| !s.is_empty()).ok_or(Errno::EINVAL)?;
            let kind = FsType::parse(fstype_str)?;
            let is_unpriv = cred.identity.id != 0;
            let (walk_target, dst_wflags) = if is_unpriv {
                let trimmed = if target.len() > 1 {
                    let t = target.trim_end_matches('/');
                    if t.is_empty() { "/" } else { t }
                } else {
                    target
                };
                (trimmed, WalkFlags::MUST_BE_DIR)
            } else {
                (target, WalkFlags::FOLLOW_LAST | WalkFlags::MUST_BE_DIR)
            };
            let dst_res = walk(
                &cred,
                &ns,
                &ctx_snap,
                &fds,
                Some(bridge),
                &StartAnchor::AtFdCwd,
                walk_target,
                dst_wflags,
            )
            .await?;
            let WalkResult::Found {
                pin: dst_pin,
                entry: dst_entry,
                last_step: dst_last_step,
                ..
            } = dst_res
            else {
                return Err(Errno::ENOENT);
            };

            let mut mnt_flags = MountFlags::from_accepted(clean);
            let mut locked_flags = 0u64;
            let owner_uid = if !is_unpriv {
                None
            } else {
                if !kind.is_user_mountable()
                    || !dst_entry.metadata.is_dir()
                    || dst_entry.metadata.uid != cred.identity.id
                {
                    return Err(Errno::EPERM);
                }
                mnt_flags.nosuid = true;
                mnt_flags.nodev = true;
                locked_flags |= mount_flags::MS_NOSUID | mount_flags::MS_NODEV;
                Some(cred.identity.id)
            };

            let mounted = self
                .inner
                .factory
                .mount_fs(&cred, kind, source, mnt_flags, data)
                .await?;
            let root_open = self
                .open_path_ref(&cred, &mounted.backing, owner_uid, &mounted.root)
                .await?;
            let att = match self
                .build_attachment(&cred, dst_pin, &dst_entry, dst_last_step)
                .await
            {
                Ok(a) => a,
                Err(e) => {
                    let _ = root_open.close().await;
                    return Err(e);
                }
            };

            let ns_id = ns.borrow().id();
            let mount_id = self.inner.alloc_mount_id();
            let mounted_prov = Rc::as_ptr(&mounted.backing.provider);
            let slot = MountSlot::new(
                mount_id,
                ns_id,
                mounted.root.node,
                mounted.backing,
                mnt_flags,
                locked_flags,
                owner_uid,
            );
            let src_label = if source.is_empty() {
                kind.as_str().to_string()
            } else {
                source.to_string()
            };
            self.commit_mount_entry(
                &ns,
                MountEntry {
                    slot,
                    parent: Some(att),
                    root: mounted.root,
                    root_open,
                    root_in_fs: mounted.root_in_fs,
                    source: src_label,
                },
            )
            .await?;
            let _ = self
                .inner
                .releases
                .flush_scoped(cred.identity.id, &[mounted_prov])
                .await;
            Ok(())
        })
        .await
    }

    pub async fn umount2(&self, pid: u32, target: &str, flags: u32) -> Result<()> {
        self.umount2_expected(pid, target, flags, None).await
    }

    pub async fn umount2_expected(
        &self,
        pid: u32,
        target: &str,
        flags: u32,
        expected: Option<MountId>,
    ) -> Result<()> {
        self.with_caller(pid, async move {
            let clean = umount_flags::accepted(flags)?;
            let (cred, ns, fs_ctx, fds) = self.snapshot_proc(pid)?;
            if clean & umount_flags::MNT_FORCE != 0 && cred.identity.id != 0 {
                return Err(Errno::EPERM);
            }

            let ctx_snap = fs_ctx.borrow().clone();
            let bridge: &dyn ProcBridge = &*self.inner;
            let mut walk_flags = WalkFlags::UMOUNT_FINAL;
            if clean & umount_flags::UMOUNT_NOFOLLOW == 0 {
                walk_flags |= WalkFlags::FOLLOW_LAST;
            }

            let resolved = walk(
                &cred,
                &ns,
                &ctx_snap,
                &fds,
                Some(bridge),
                &StartAnchor::AtFdCwd,
                target,
                walk_flags,
            )
            .await?;
            let WalkResult::Found { pin, entry, .. } = resolved else {
                return Err(Errno::ENOENT);
            };

            let target_id = pin.id();
            if expected.is_some_and(|id| id != target_id || !ns.borrow().contains_mount(id)) {
                return Ok(());
            }
            let root_node = pin.root_node();
            let owner_uid = pin.owner_uid();
            let provider = Rc::clone(pin.provider());
            let parent_prov = ns
                .borrow()
                .entry(target_id)
                .and_then(|e| e.parent.as_ref())
                .map(|att| Rc::as_ptr(att.parent_pin.provider()));
            // Drop `pin` BEFORE busy check so `umount2`'s own lookup pin does not count as busy!
            drop(pin);

            if entry.handle.node != root_node || !ns.borrow().contains_mount(target_id) {
                return Err(Errno::EINVAL);
            }
            if target_id == ns.borrow().root_mount_id()
                || (target_id == ctx_snap.root.pin.id()
                    && entry.handle.node == ctx_snap.root.handle.node)
            {
                return Err(Errno::EBUSY);
            }
            if cred.identity.id != 0 && owner_uid != Some(cred.identity.id) {
                return Err(Errno::EPERM);
            }

            if clean & umount_flags::MNT_FORCE != 0 {
                let subtree_providers: Vec<_> = {
                    let ns_ref = ns.borrow();
                    ns_ref
                        .collect_subtree_postorder(target_id)
                        .into_iter()
                        .filter_map(|id| {
                            ns_ref
                                .entry(id)
                                .map(|e| Rc::clone(&e.slot.backing.provider))
                        })
                        .collect()
                };
                if subtree_providers.is_empty() {
                    provider.force_abort();
                } else {
                    for p in subtree_providers {
                        p.force_abort();
                    }
                }
            }

            if clean & umount_flags::MNT_DETACH != 0 {
                let removed = ns.borrow_mut().detach_subtree(target_id)?;
                drop(removed);
                let mut flush_provs = Vec::new();
                if let Some(pp) = parent_prov {
                    flush_provs.push(pp);
                }
                let _ = self
                    .inner
                    .releases
                    .flush_scoped(cred.identity.id, &flush_provs)
                    .await;
            } else {
                let removed = ns.borrow_mut().unmount_ordinary(target_id)?;
                let target_prov = Rc::as_ptr(&provider);
                drop(removed);
                let mut flush_provs = vec![target_prov];
                if let Some(pp) = parent_prov {
                    flush_provs.push(pp);
                }
                let _ = self
                    .inner
                    .releases
                    .flush_scoped(cred.identity.id, &flush_provs)
                    .await;
            }
            Ok(())
        })
        .await
    }

    pub fn unshare(&self, pid: u32, flags: u32) -> Result<()> {
        let clean = unshare_flags::accepted_unshare(flags)?;
        if clean == 0 {
            return Ok(());
        }
        let mut procs = self.inner.processes.borrow_mut();
        let proc_ctx = procs.get_mut(&pid).ok_or(Errno::ESRCH)?;

        if clean & unshare_flags::CLONE_NEWNS != 0 {
            if proc_ctx.cred.identity.id != 0 {
                return Err(Errno::EPERM);
            }
            // Linux `sys_unshare`: `CLONE_NEWNS` implies `CLONE_FS`.
            proc_ctx.fs_ctx.unshare();
            let new_ns_id = self.inner.alloc_ns_id();
            let (cloned_ns, slot_map) = proc_ctx
                .mnt_ns
                .borrow()
                .clone_private(new_ns_id, || self.inner.alloc_mount_id());
            let pin_map: HashMap<MountId, MountPin> = slot_map
                .into_iter()
                .map(|(old_id, slot)| (old_id, slot.pin()))
                .collect();
            {
                let mut ctx = proc_ctx.fs_ctx.borrow_mut();
                ctx.root.remap_pin(&pin_map);
                ctx.cwd.remap_pin(&pin_map);
            }
            let new_ns_rc = Rc::new(RefCell::new(cloned_ns));
            self.inner.register_namespace(&new_ns_rc);
            proc_ctx.mnt_ns = new_ns_rc;
        }

        if clean & unshare_flags::CLONE_FS != 0 {
            proc_ctx.fs_ctx.unshare();
        }
        if clean & unshare_flags::CLONE_FILES != 0 {
            proc_ctx.fds.unshare();
        }
        Ok(())
    }

    pub fn setns(&self, pid: u32, fd: Fd, nstype: u32) -> Result<()> {
        let mut procs = self.inner.processes.borrow_mut();
        let proc_ctx = procs.get_mut(&pid).ok_or(Errno::ESRCH)?;

        let file = proc_ctx.fds.borrow().get(fd)?;
        if file.access() == Access::Path {
            return Err(Errno::EBADF);
        }
        unshare_flags::accepted_setns(nstype)?;
        let ns_file = file.mount_ns().ok_or(Errno::EINVAL)?;
        if ns_file.instance_id != self.inner.instance_id {
            return Err(Errno::EINVAL);
        }
        if proc_ctx.cred.identity.id != 0 {
            return Err(Errno::EPERM);
        }
        if proc_ctx.fs_ctx.is_shared() {
            return Err(Errno::EINVAL);
        }
        let old_ns_root = proc_ctx.mnt_ns.borrow().root_anchor();
        if !proc_ctx.fs_ctx.borrow().root.same_anchor(&old_ns_root) {
            return Err(Errno::EINVAL);
        }

        let target_ns = Rc::clone(&ns_file.ns);
        self.inner.register_namespace(&target_ns);
        let root_anchor = target_ns.borrow().root_anchor();
        proc_ctx.mnt_ns = target_ns;
        {
            let mut ctx = proc_ctx.fs_ctx.borrow_mut();
            ctx.root = root_anchor.clone();
            ctx.cwd = root_anchor;
        }
        Ok(())
    }

    async fn statfs_on_pin(&self, cred: &Cred, pin: &MountPin) -> Result<abi::StatFs> {
        let raw = pin
            .guard_op(cred, false, false, pin.fs().statfs(cred))
            .await?;
        let eff = pin.effective_flags();
        let mut st_flags = eff.to_statfs_flags();
        if pin.fs().capabilities().open_survives_unlink
            == abi::contract::Support::Refused(Errno::EROFS)
        {
            st_flags |= statfs_flags::ST_RDONLY;
        }
        Ok(abi::StatFs {
            f_type: pin.fstype().magic(),
            bsize: raw.block_size,
            frsize: raw.block_size,
            blocks: raw.blocks,
            bfree: raw.blocks_free,
            bavail: raw.blocks_free,
            files: raw.files,
            ffree: raw.files_free,
            fsid: pin.fs().id().dev(),
            namelen: raw.name_max,
            flags: st_flags,
            fstype: pin.fstype().as_str().to_string(),
        })
    }

    pub async fn statfs(&self, pid: u32, anchor: StartAnchor, path: &str) -> Result<abi::StatFs> {
        self.with_caller(pid, async move {
            let (cred, ns, fs_ctx, fds) = self.snapshot_proc(pid)?;
            let ctx_snap = fs_ctx.borrow().clone();
            let bridge: &dyn ProcBridge = &*self.inner;
            let resolved = walk(
                &cred,
                &ns,
                &ctx_snap,
                &fds,
                Some(bridge),
                &anchor,
                path,
                WalkFlags::FOLLOW_LAST,
            )
            .await?;
            let WalkResult::Found { pin, .. } = resolved else {
                return Err(Errno::ENOENT);
            };
            self.statfs_on_pin(&cred, &pin).await
        })
        .await
    }

    pub async fn fstatfs(&self, pid: u32, fd: Fd) -> Result<abi::StatFs> {
        self.with_caller(pid, async move {
            let (cred, _, _, fds) = self.snapshot_proc(pid)?;
            let file = fds.borrow().get(fd)?;
            if let Some(pin) = file.mount_pin() {
                return self.statfs_on_pin(&cred, pin).await;
            }
            if file.mount_ns().is_some() {
                return Ok(abi::StatFs {
                    f_type: FsType::Proc.magic(),
                    bsize: 4096,
                    frsize: 4096,
                    blocks: 0,
                    bfree: 0,
                    bavail: 0,
                    files: 0,
                    ffree: 0,
                    fsid: file.fs().id().dev(),
                    namelen: abi::NAME_MAX as u64,
                    flags: 0,
                    fstype: "proc".into(),
                });
            }
            let raw = file.fs().statfs(&cred).await?;
            Ok(abi::StatFs {
                f_type: 0,
                bsize: raw.block_size,
                frsize: raw.block_size,
                blocks: raw.blocks,
                bfree: raw.blocks_free,
                bavail: raw.blocks_free,
                files: raw.files,
                ffree: raw.files_free,
                fsid: file.fs().id().dev(),
                namelen: raw.name_max,
                flags: 0,
                fstype: String::new(),
            })
        })
        .await
    }

    // -------------------------------------------------------------------------
    // Path & *at filesystem operations + FD operations
    // -------------------------------------------------------------------------

    /// Open a path returning `(FileRef, Entry)` without inserting into `FdTable` (used by
    /// `openat` and `client-kernel` `proc_openat`).
    pub async fn open_file(
        &self,
        pid: u32,
        anchor: StartAnchor,
        path: &str,
        oflags: u32,
        mode: u16,
    ) -> Result<(FileRef, Entry)> {
        let target = self.resolve_open(pid, anchor, path, oflags).await?;
        self.open_resolved(pid, target, oflags, mode).await
    }

    /// Resolve the mount, inode or parent/name once, including the target of a dangling link.
    pub async fn resolve_open(
        &self,
        pid: u32,
        anchor: StartAnchor,
        path: &str,
        oflags: u32,
    ) -> Result<WalkResult> {
        self.with_caller(pid, async move {
            let options = OpenOptions::from_flags(oflags)?;
            let access = options.access()?;
            let (cred, ns, fs_ctx, fds) = self.snapshot_proc(pid)?;
            let ctx_snap = fs_ctx.borrow().clone();
            let bridge: &dyn ProcBridge = &*self.inner;

            let nofollow = oflags & abi::O_NOFOLLOW != 0;
            let must_dir = oflags & abi::O_DIRECTORY != 0;
            let is_creat = oflags & abi::O_CREAT != 0 && access != Access::Path;
            let is_excl = oflags & abi::O_EXCL != 0;

            let mut wflags = WalkFlags::empty();
            if !nofollow && !(is_creat && is_excl) {
                wflags |= WalkFlags::FOLLOW_LAST;
            }
            if must_dir
                && !is_creat
                && (wflags.contains(WalkFlags::FOLLOW_LAST) || access == Access::Path)
            {
                wflags |= WalkFlags::MUST_BE_DIR;
            }
            if is_creat {
                wflags |= WalkFlags::ALLOW_MISSING_LAST;
            }

            walk(
                &cred,
                &ns,
                &ctx_snap,
                &fds,
                Some(bridge),
                &anchor,
                path,
                wflags,
            )
            .await
        })
        .await
    }

    pub async fn open_resolved(
        &self,
        pid: u32,
        resolved: WalkResult,
        oflags: u32,
        mode: u16,
    ) -> Result<(FileRef, Entry)> {
        self.with_caller(pid, async move {
            let options = OpenOptions::from_flags(oflags)?;
            let access = options.access()?;
            let (cred, _, _, _) = self.snapshot_proc(pid)?;
            let must_dir = oflags & abi::O_DIRECTORY != 0;
            let is_creat = oflags & abi::O_CREAT != 0 && access != Access::Path;
            let is_excl = oflags & abi::O_EXCL != 0;
            match resolved {
                WalkResult::MissingLast {
                    parent_pin,
                    parent,
                    name,
                    trailing_slash,
                } => {
                    if trailing_slash || must_dir {
                        return Err(Errno::EISDIR);
                    }
                    if parent_pin.effective_rdonly() {
                        return Err(Errno::EROFS);
                    }
                    let (entry, open_ref) = parent_pin
                        .guard_op(
                            &cred,
                            true,
                            true,
                            parent_pin
                                .fs()
                                .create(&cred, &parent.handle, &name, mode, &options),
                        )
                        .await?;
                    let file_ref = FileRef::new_mounted_with_type(
                        parent_pin.clone(),
                        open_ref,
                        entry.handle.clone(),
                        Some(entry.metadata.file_type),
                        cred.clone(),
                        &options,
                        &self.inner.releases,
                    );
                    if let Err(err) = self
                        .sync_dir_if_needed(&cred, &parent_pin, &parent.handle)
                        .await
                    {
                        let _ = file_ref.close().await;
                        return Err(err);
                    }
                    Ok((file_ref, entry))
                }
                WalkResult::Found {
                    pin, entry, magic, ..
                } => {
                    if is_creat && is_excl {
                        return Err(Errno::EEXIST);
                    }
                    match magic {
                        Some(MagicResolved::MountNs { instance_id, ns }) => {
                            if must_dir {
                                return Err(Errno::ENOTDIR);
                            }
                            if access.writes() || options.is_truncate() || access == Access::Exec {
                                return Err(Errno::EACCES);
                            }
                            let ns_ino = ns.borrow().id().0;
                            let ns_entry = Entry {
                                handle: Handle {
                                    fs: pin.fs().id().clone(),
                                    node: NodeId {
                                        ino: ns_ino,
                                        generation: 1,
                                    },
                                    proof: String::new(),
                                },
                                metadata: Metadata {
                                    file_type: FileType::File,
                                    mode: 0o444,
                                    nlink: 1,
                                    uid: 0,
                                    gid: 0,
                                    size: 0,
                                    atime: Default::default(),
                                    mtime: Default::default(),
                                    ctime: Default::default(),
                                    rdev: None,
                                    acl: false,
                                },
                            };
                            let file_ref = FileRef::new_mount_ns(
                                Rc::clone(pin.fs()),
                                Some(pin),
                                instance_id,
                                ns,
                                access,
                                cred,
                                &self.inner.releases,
                            );
                            return Ok((file_ref, ns_entry));
                        }
                        Some(MagicResolved::OpenFile(orig))
                            if orig.is_virtual() || orig.mount_pin().is_none() =>
                        {
                            if entry.metadata.is_symlink() && access != Access::Path {
                                return Err(Errno::ELOOP);
                            }
                            if must_dir && !entry.metadata.is_dir() {
                                return Err(Errno::ENOTDIR);
                            }
                            if entry.metadata.is_dir()
                                && (access.writes() || options.is_truncate() || is_creat)
                            {
                                return Err(Errno::EISDIR);
                            }
                            if orig.is_virtual() {
                                if access.writes()
                                    || options.is_truncate()
                                    || access == Access::Exec
                                {
                                    return Err(Errno::EACCES);
                                }
                                let reopened = orig
                                    .reopen_virtual(access, cred, &self.inner.releases)
                                    .ok_or(Errno::EACCES)?;
                                return Ok((reopened, entry));
                            }
                            let open_ref = orig.fs().open(&cred, orig.handle(), &options).await?;
                            let is_trunc = options.is_truncate() && entry.metadata.is_file();
                            let refreshed_meta = if is_trunc {
                                orig.fs()
                                    .open_metadata(&open_ref)
                                    .await
                                    .unwrap_or(entry.metadata)
                            } else {
                                entry.metadata
                            };
                            let out_entry = Entry {
                                handle: orig.handle().clone(),
                                metadata: refreshed_meta,
                            };
                            let file_ref = FileRef::new(
                                Rc::clone(orig.fs()),
                                open_ref,
                                orig.handle().clone(),
                                cred,
                                &options,
                                &self.inner.releases,
                            );
                            return Ok((file_ref, out_entry));
                        }
                        _ => {}
                    }

                    if entry.metadata.is_symlink() && access != Access::Path {
                        return Err(Errno::ELOOP);
                    }
                    if must_dir && !entry.metadata.is_dir() {
                        return Err(Errno::ENOTDIR);
                    }
                    if entry.metadata.is_dir()
                        && (access.writes() || options.is_truncate() || is_creat)
                    {
                        return Err(Errno::EISDIR);
                    }
                    let is_char_dev = entry.metadata.file_type == FileType::CharDevice;
                    let wants_write =
                        access != Access::Path && (access.writes() || options.is_truncate());
                    if access != Access::Path {
                        if is_char_dev && pin.effective_flags().nodev {
                            return Err(Errno::EACCES);
                        }
                        if access == Access::Exec && pin.effective_noexec() {
                            return Err(Errno::EACCES);
                        }
                        if wants_write && !is_char_dev && pin.effective_rdonly() {
                            return Err(Errno::EROFS);
                        }
                    }

                    let is_trunc = options.is_truncate() && entry.metadata.is_file();
                    let write_guard = if wants_write && !is_char_dev {
                        Some(pin.begin_write()?)
                    } else {
                        None
                    };
                    let open_ref = pin
                        .guard_op(
                            &cred,
                            is_trunc,
                            false,
                            pin.fs().open(&cred, &entry.handle, &options),
                        )
                        .await?;
                    let file_type = entry.metadata.file_type;
                    let file_ref = FileRef::new_mounted_with_type(
                        pin.clone(),
                        open_ref,
                        entry.handle.clone(),
                        Some(file_type),
                        cred.clone(),
                        &options,
                        &self.inner.releases,
                    );
                    drop(write_guard);
                    if is_trunc && pin.effective_flags().synchronous {
                        if let Err(err) = pin
                            .guard_op(&cred, true, false, pin.fs().sync_all(file_ref.open_ref()))
                            .await
                        {
                            let _ = file_ref.close().await;
                            return Err(err);
                        }
                        pin.backing().record_sync();
                    }
                    let refreshed_meta = if is_trunc {
                        pin.guard_op(
                            &cred,
                            false,
                            false,
                            pin.fs().open_metadata(file_ref.open_ref()),
                        )
                        .await
                        .unwrap_or(entry.metadata)
                    } else {
                        entry.metadata
                    };
                    let out_entry = Entry {
                        handle: entry.handle,
                        metadata: refreshed_meta,
                    };
                    Ok((file_ref, out_entry))
                }
            }
        })
        .await
    }

    pub async fn openat(
        &self,
        pid: u32,
        anchor: StartAnchor,
        path: &str,
        oflags: u32,
        mode: u16,
    ) -> Result<Fd> {
        let (file_ref, _) = self.open_file(pid, anchor, path, oflags, mode).await?;
        let cloexec = oflags & O_CLOEXEC != 0;
        let (cred, _, _, fds) = self.snapshot_proc(pid)?;
        let prov = file_ref.mount_pin().map(|p| Rc::as_ptr(p.provider()));
        let res = fds.borrow_mut().insert(file_ref, cloexec);
        if res.is_err() {
            let provs: Vec<_> = prov.into_iter().collect();
            let _ = self
                .inner
                .releases
                .flush_scoped(cred.identity.id, &provs)
                .await;
        }
        res
    }

    pub async fn statat(
        &self,
        pid: u32,
        anchor: StartAnchor,
        path: &str,
        follow: bool,
    ) -> Result<abi::Stat> {
        self.with_caller(pid, async move {
            let (cred, ns, fs_ctx, fds) = self.snapshot_proc(pid)?;
            let ctx_snap = fs_ctx.borrow().clone();
            let bridge: &dyn ProcBridge = &*self.inner;
            let flags = if follow {
                WalkFlags::FOLLOW_LAST
            } else {
                WalkFlags::empty()
            };
            let resolved = walk(
                &cred,
                &ns,
                &ctx_snap,
                &fds,
                Some(bridge),
                &anchor,
                path,
                flags,
            )
            .await?;
            let WalkResult::Found {
                pin, entry, magic, ..
            } = resolved
            else {
                return Err(Errno::ENOENT);
            };
            if let Some(MagicResolved::MountNs { ns, .. }) = magic {
                let ns_ino = ns.borrow().id().0;
                let meta = Metadata {
                    file_type: FileType::File,
                    mode: 0o444,
                    nlink: 1,
                    uid: 0,
                    gid: 0,
                    size: 0,
                    atime: Default::default(),
                    mtime: Default::default(),
                    ctime: Default::default(),
                    rdev: None,
                    acl: false,
                };
                return Ok(to_abi_stat(
                    pin.fs().id(),
                    NodeId {
                        ino: ns_ino,
                        generation: 1,
                    },
                    &meta,
                ));
            }
            Ok(to_abi_stat(
                &entry.handle.fs,
                entry.handle.node,
                &entry.metadata,
            ))
        })
        .await
    }

    pub async fn fstat(&self, pid: u32, fd: Fd) -> Result<abi::Stat> {
        self.with_caller(pid, async move {
            let (cred, _, _, fds) = self.snapshot_proc(pid)?;
            let file = fds.borrow().get(fd)?;
            let meta = file.metadata_as(&cred).await?;
            Ok(to_abi_stat(file.fs().id(), file.handle().node, &meta))
        })
        .await
    }

    /// Descriptor attribute mutation (`fchmod`, `fchown`, `futimens`) acting with `pid`'s current
    /// credentials (contract §2.3).
    pub async fn fsetattr(&self, pid: u32, fd: Fd, attr: &SetAttr) -> Result<Metadata> {
        self.with_caller(pid, async move {
            let (cred, _, _, fds) = self.snapshot_proc(pid)?;
            let file = fds.borrow().get(fd)?;
            file.setattr_as(&cred, attr).await
        })
        .await
    }

    async fn release_temp_open(pin: &MountPin, open: &crate::OpenRef) {
        if pin.health() == crate::mount::ProviderHealth::Connected {
            let _ = pin
                .provider()
                .guard_future(false, pin.fs().release(open))
                .await;
        }
    }

    pub async fn accessat(
        &self,
        pid: u32,
        anchor: StartAnchor,
        path: &str,
        mode: u16,
        follow: bool,
    ) -> Result<()> {
        if mode & !(abi::R_OK | abi::W_OK | abi::X_OK) != 0 {
            return Err(Errno::EINVAL);
        }
        self.with_caller(pid, async move {
            let (cred, ns, fs_ctx, fds) = self.snapshot_proc(pid)?;
            let ctx_snap = fs_ctx.borrow().clone();
            let bridge: &dyn ProcBridge = &*self.inner;
            let flags = if follow {
                WalkFlags::FOLLOW_LAST
            } else {
                WalkFlags::empty()
            };
            let resolved = walk(
                &cred,
                &ns,
                &ctx_snap,
                &fds,
                Some(bridge),
                &anchor,
                path,
                flags,
            )
            .await?;
            let WalkResult::Found { pin, entry, .. } = resolved else {
                return Err(Errno::ENOENT);
            };
            if mode == abi::F_OK {
                return Ok(());
            }
            if mode & abi::W_OK != 0
                && entry.metadata.file_type != FileType::CharDevice
                && pin.effective_rdonly()
            {
                return Err(Errno::EROFS);
            }
            if mode & abi::X_OK != 0 && !entry.metadata.is_dir() && pin.effective_noexec() {
                return Err(Errno::EACCES);
            }
            if entry.metadata.is_dir() && mode == abi::X_OK {
                let mut searchable = false;
                return ensure_searchable(&cred, &pin, &entry.handle, &mut searchable).await;
            }
            let node = os_core::permissions::Node {
                ino: entry.handle.node.ino,
                directory: entry.metadata.is_dir(),
                owner: entry.metadata.uid,
                group: entry.metadata.gid,
                mode: entry.metadata.mode,
                links: entry.metadata.nlink,
                size: entry.metadata.size,
                file: None,
                rdev: entry.metadata.rdev.clone(),
                link: None,
                acl: None,
                default_acl: None,
            };
            if !entry.metadata.acl {
                inode::require(&cred.identity, &node, mode)
            } else {
                // Delegate ACL-bearing permission evaluation to the authoritative driver.
                if mode & abi::R_OK != 0 {
                    let mut opts = OpenOptions::new();
                    opts.read(true);
                    let open = pin
                        .guard_op(
                            &cred,
                            false,
                            false,
                            pin.fs().open(&cred, &entry.handle, &opts),
                        )
                        .await?;
                    Self::release_temp_open(&pin, &open).await;
                }
                if mode & abi::W_OK != 0 {
                    if entry.metadata.is_dir() {
                        let raw = pin
                            .guard_op(
                                &cred,
                                false,
                                false,
                                pin.fs().getxattr(&cred, &entry.handle, abi::ACL_ACCESS),
                            )
                            .await?;
                        let entries: os_core::acl::Entries =
                            serde_json::from_slice(&raw).map_err(|_| Errno::EIO)?;
                        let (acl_mode, acl_ext) = entries.split();
                        let mut acl_node = node.clone();
                        acl_node.mode = (acl_node.mode & !0o777) | acl_mode;
                        acl_node.acl = acl_ext;
                        inode::require(&cred.identity, &acl_node, abi::W_OK)?;
                    } else {
                        let mut opts = OpenOptions::new();
                        opts.write(true);
                        let open = pin
                            .guard_op(
                                &cred,
                                false,
                                false,
                                pin.fs().open(&cred, &entry.handle, &opts),
                            )
                            .await?;
                        Self::release_temp_open(&pin, &open).await;
                    }
                }
                if mode & abi::X_OK != 0 {
                    if entry.metadata.is_dir() {
                        let mut searchable = false;
                        ensure_searchable(&cred, &pin, &entry.handle, &mut searchable).await?;
                    } else {
                        let mut opts = OpenOptions::new();
                        opts.exec(true);
                        let open = pin
                            .guard_op(
                                &cred,
                                false,
                                false,
                                pin.fs().open(&cred, &entry.handle, &opts),
                            )
                            .await?;
                        Self::release_temp_open(&pin, &open).await;
                    }
                }
                Ok(())
            }
        })
        .await
    }

    pub async fn readlinkat(&self, pid: u32, anchor: StartAnchor, path: &str) -> Result<String> {
        if path.ends_with('/') {
            return Err(Errno::EINVAL);
        }
        self.with_caller(pid, async move {
            let (cred, ns, fs_ctx, fds) = self.snapshot_proc(pid)?;
            let ctx_snap = fs_ctx.borrow().clone();
            let bridge: &dyn ProcBridge = &*self.inner;
            let resolved = walk(
                &cred,
                &ns,
                &ctx_snap,
                &fds,
                Some(bridge),
                &anchor,
                path,
                WalkFlags::empty(),
            )
            .await?;
            let WalkResult::Found { pin, entry, .. } = resolved else {
                return Err(Errno::ENOENT);
            };
            if !entry.metadata.is_symlink() {
                return Err(Errno::EINVAL);
            }
            pin.guard_op(
                &cred,
                false,
                false,
                pin.fs().read_link(&cred, &entry.handle),
            )
            .await
        })
        .await
    }

    pub async fn readdir(
        &self,
        pid: u32,
        anchor: StartAnchor,
        path: &str,
    ) -> Result<Vec<DirEntry>> {
        self.with_caller(pid, async move {
            let (cred, ns, fs_ctx, fds) = self.snapshot_proc(pid)?;
            let ctx_snap = fs_ctx.borrow().clone();
            let bridge: &dyn ProcBridge = &*self.inner;
            let resolved = walk(
                &cred,
                &ns,
                &ctx_snap,
                &fds,
                Some(bridge),
                &anchor,
                path,
                WalkFlags::FOLLOW_LAST | WalkFlags::MUST_BE_DIR,
            )
            .await?;
            let WalkResult::Found { pin, entry, .. } = resolved else {
                return Err(Errno::ENOENT);
            };
            pin.guard_op(&cred, false, false, pin.fs().read_dir(&cred, &entry.handle))
                .await
        })
        .await
    }

    pub async fn fd_readdir(&self, pid: u32, fd: Fd) -> Result<Vec<DirEntry>> {
        self.with_caller(pid, async move {
            let (cred, _, _, fds) = self.snapshot_proc(pid)?;
            let file = fds.borrow().get(fd)?;
            if file.access() == Access::Path {
                return Err(Errno::EBADF);
            }
            if file.mount_ns().is_some() {
                return Err(Errno::ENOTDIR);
            }
            let meta = file.metadata_as(&cred).await?;
            if !meta.is_dir() {
                return Err(Errno::ENOTDIR);
            }
            if let Some(pin) = file.mount_pin() {
                pin.guard_op(&cred, false, false, pin.fs().read_dir(&cred, file.handle()))
                    .await
            } else {
                file.fs().read_dir(&cred, file.handle()).await
            }
        })
        .await
    }

    pub async fn mkdirat(
        &self,
        pid: u32,
        anchor: StartAnchor,
        path: &str,
        mode: u16,
    ) -> Result<Entry> {
        self.with_caller(pid, async move {
            let (cred, ns, fs_ctx, fds) = self.snapshot_proc(pid)?;
            let ctx_snap = fs_ctx.borrow().clone();
            let bridge: &dyn ProcBridge = &*self.inner;
            match walk_parent(&cred, &ns, &ctx_snap, &fds, Some(bridge), &anchor, path).await? {
                ParentResolution::Root { .. } | ParentResolution::DotOrDotDot { .. } => {
                    Err(Errno::EEXIST)
                }
                ParentResolution::Child(t) => {
                    if t.parent_pin.effective_rdonly() {
                        return Err(Errno::EROFS);
                    }
                    let entry = t
                        .parent_pin
                        .guard_op(
                            &cred,
                            true,
                            true,
                            t.parent_pin
                                .fs()
                                .mkdir(&cred, &t.parent.handle, &t.name, mode),
                        )
                        .await?;
                    self.sync_dir_if_needed(&cred, &t.parent_pin, &t.parent.handle)
                        .await?;
                    Ok(entry)
                }
            }
        })
        .await
    }

    pub async fn mknodat(
        &self,
        pid: u32,
        anchor: StartAnchor,
        path: &str,
        mode: u16,
        rdev: &str,
    ) -> Result<Entry> {
        self.with_caller(pid, async move {
            let (cred, ns, fs_ctx, fds) = self.snapshot_proc(pid)?;
            let ctx_snap = fs_ctx.borrow().clone();
            let bridge: &dyn ProcBridge = &*self.inner;
            match walk_parent(&cred, &ns, &ctx_snap, &fds, Some(bridge), &anchor, path).await? {
                ParentResolution::Root { .. } | ParentResolution::DotOrDotDot { .. } => {
                    Err(Errno::EEXIST)
                }
                ParentResolution::Child(t) => {
                    if t.trailing_slash {
                        return Err(Errno::ENOENT);
                    }
                    if t.parent_pin.effective_rdonly() {
                        return Err(Errno::EROFS);
                    }
                    let entry = t
                        .parent_pin
                        .guard_op(
                            &cred,
                            true,
                            true,
                            t.parent_pin
                                .fs()
                                .mknod(&cred, &t.parent.handle, &t.name, mode, rdev),
                        )
                        .await?;
                    self.sync_dir_if_needed(&cred, &t.parent_pin, &t.parent.handle)
                        .await?;
                    Ok(entry)
                }
            }
        })
        .await
    }

    pub async fn symlinkat(
        &self,
        pid: u32,
        target: &str,
        anchor: StartAnchor,
        path: &str,
    ) -> Result<Entry> {
        self.with_caller(pid, async move {
            let (cred, ns, fs_ctx, fds) = self.snapshot_proc(pid)?;
            let ctx_snap = fs_ctx.borrow().clone();
            let bridge: &dyn ProcBridge = &*self.inner;
            match walk_parent(&cred, &ns, &ctx_snap, &fds, Some(bridge), &anchor, path).await? {
                ParentResolution::Root { .. } | ParentResolution::DotOrDotDot { .. } => {
                    Err(Errno::EEXIST)
                }
                ParentResolution::Child(t) => {
                    if t.trailing_slash {
                        return Err(Errno::ENOENT);
                    }
                    if t.parent_pin.effective_rdonly() {
                        return Err(Errno::EROFS);
                    }
                    let entry = t
                        .parent_pin
                        .guard_op(
                            &cred,
                            true,
                            true,
                            t.parent_pin
                                .fs()
                                .symlink(&cred, &t.parent.handle, &t.name, target),
                        )
                        .await?;
                    self.sync_dir_if_needed(&cred, &t.parent_pin, &t.parent.handle)
                        .await?;
                    Ok(entry)
                }
            }
        })
        .await
    }

    async fn node_for_perm(
        cred: &Cred,
        pin: &MountPin,
        entry: &Entry,
    ) -> Result<os_core::permissions::Node> {
        let mut node = os_core::permissions::Node {
            ino: entry.handle.node.ino,
            directory: entry.metadata.is_dir(),
            owner: entry.metadata.uid,
            group: entry.metadata.gid,
            mode: entry.metadata.mode,
            links: entry.metadata.nlink,
            size: entry.metadata.size,
            file: None,
            rdev: entry.metadata.rdev.clone(),
            link: None,
            acl: None,
            default_acl: None,
        };
        if entry.metadata.acl {
            match pin
                .guard_op(
                    cred,
                    false,
                    false,
                    pin.fs().getxattr(cred, &entry.handle, abi::ACL_ACCESS),
                )
                .await
            {
                Ok(raw) => {
                    let entries: os_core::acl::Entries =
                        serde_json::from_slice(&raw).map_err(|_| Errno::EIO)?;
                    let (acl_mode, acl_ext) = entries.split();
                    node.mode = (node.mode & !0o777) | acl_mode;
                    node.acl = acl_ext;
                }
                Err(Errno::ENODATA | Errno::EOPNOTSUPP) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(node)
    }

    fn is_mountpoint_in_pin_ns(
        &self,
        default_ns: &Rc<RefCell<MountNamespace>>,
        pin: &MountPin,
        dir_node: NodeId,
        name: &str,
        item_node: Option<NodeId>,
    ) -> bool {
        if pin.is_detached() {
            return pin.detached_dir_has_mountpoint(pin.id(), dir_node, name)
                || item_node.is_some_and(|n| pin.detached_topmost_at(pin.id(), n).is_some());
        }
        let target_ns = if default_ns.borrow().id() == pin.ns_id() {
            Rc::clone(default_ns)
        } else {
            self.inner
                .namespace_by_id(pin.ns_id())
                .unwrap_or_else(|| Rc::clone(default_ns))
        };
        let ns_ref = target_ns.borrow();
        ns_ref.has_mountpoint_at_name(pin.id(), dir_node, name)
            || item_node.is_some_and(|n| ns_ref.is_mountpoint(pin.id(), n))
    }

    pub async fn unlinkat(
        &self,
        pid: u32,
        anchor: StartAnchor,
        path: &str,
        rmdir: bool,
    ) -> Result<()> {
        self.with_caller(pid, async move {
            let (cred, ns, fs_ctx, fds) = self.snapshot_proc(pid)?;
            let ctx_snap = fs_ctx.borrow().clone();
            let bridge: &dyn ProcBridge = &*self.inner;
            match walk_parent(&cred, &ns, &ctx_snap, &fds, Some(bridge), &anchor, path).await? {
                ParentResolution::Root { .. } => {
                    Err(if rmdir { Errno::EBUSY } else { Errno::EISDIR })
                }
                ParentResolution::DotOrDotDot { dot, .. } => {
                    if rmdir {
                        Err(if dot == "." {
                            Errno::EINVAL
                        } else {
                            Errno::ENOTEMPTY
                        })
                    } else {
                        Err(Errno::EISDIR)
                    }
                }
                ParentResolution::Child(t) => {
                    if t.parent_pin.effective_rdonly() {
                        return Err(Errno::EROFS);
                    }
                    let child = t
                        .parent_pin
                        .guard_op(
                            &cred,
                            false,
                            false,
                            t.parent_pin.fs().lookup(&cred, &t.parent.handle, &t.name),
                        )
                        .await?;
                    if !rmdir && t.trailing_slash {
                        return Err(if child.metadata.is_dir() {
                            Errno::EISDIR
                        } else {
                            Errno::ENOTDIR
                        });
                    }
                    let is_mp = self.is_mountpoint_in_pin_ns(
                        &ns,
                        &t.parent_pin,
                        t.parent.handle.node,
                        &t.name,
                        Some(child.handle.node),
                    );
                    if is_mp {
                        let dir_node = Self::node_for_perm(&cred, &t.parent_pin, &t.parent).await?;
                        let child_node = Self::node_for_perm(&cred, &t.parent_pin, &child).await?;
                        inode::may_delete(&cred.identity, &dir_node, &child_node)?;
                        if rmdir && !child.metadata.is_dir() {
                            return Err(Errno::ENOTDIR);
                        }
                        if !rmdir && child.metadata.is_dir() {
                            return Err(Errno::EISDIR);
                        }
                        return Err(Errno::EBUSY);
                    }
                    if rmdir {
                        t.parent_pin
                            .guard_op(
                                &cred,
                                true,
                                true,
                                t.parent_pin.fs().rmdir(&cred, &t.parent.handle, &t.name),
                            )
                            .await?;
                    } else {
                        t.parent_pin
                            .guard_op(
                                &cred,
                                true,
                                true,
                                t.parent_pin.fs().unlink(&cred, &t.parent.handle, &t.name),
                            )
                            .await?;
                    }
                    self.sync_dir_if_needed(&cred, &t.parent_pin, &t.parent.handle)
                        .await?;
                    Ok(())
                }
            }
        })
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn renameat(
        &self,
        pid: u32,
        from_anchor: StartAnchor,
        from: &str,
        to_anchor: StartAnchor,
        to: &str,
        flags: RenameFlags,
    ) -> Result<()> {
        self.with_caller(pid, async move {
            let (cred, ns, fs_ctx, fds) = self.snapshot_proc(pid)?;
            let ctx_snap = fs_ctx.borrow().clone();
            let bridge: &dyn ProcBridge = &*self.inner;

            let src = match walk_parent(
                &cred,
                &ns,
                &ctx_snap,
                &fds,
                Some(bridge),
                &from_anchor,
                from,
            )
            .await?
            {
                ParentResolution::Root { .. } | ParentResolution::DotOrDotDot { .. } => {
                    return Err(Errno::EBUSY);
                }
                ParentResolution::Child(t) => t,
            };

            let dst = match walk_parent(&cred, &ns, &ctx_snap, &fds, Some(bridge), &to_anchor, to)
                .await?
            {
                ParentResolution::Root { .. } | ParentResolution::DotOrDotDot { .. } => {
                    return Err(Errno::EBUSY);
                }
                ParentResolution::Child(t) => t,
            };

            // Cross-MountId check (`EXDEV` even between two bind mounts of the same `Filesystem`!).
            if src.parent_pin.id() != dst.parent_pin.id() {
                return Err(Errno::EXDEV);
            }
            if src.parent_pin.effective_rdonly() {
                return Err(Errno::EROFS);
            }

            let src_entry = src
                .parent_pin
                .guard_op(
                    &cred,
                    false,
                    false,
                    src.parent_pin
                        .fs()
                        .lookup(&cred, &src.parent.handle, &src.name),
                )
                .await?;
            if src.trailing_slash && !src_entry.metadata.is_dir() {
                return Err(Errno::ENOTDIR);
            }

            let dst_existing = dst
                .parent_pin
                .guard_op(
                    &cred,
                    false,
                    false,
                    dst.parent_pin
                        .fs()
                        .lookup(&cred, &dst.parent.handle, &dst.name),
                )
                .await;
            let dst_entry = match dst_existing {
                Ok(e) => Some(e),
                Err(Errno::ENOENT) => None,
                Err(e) => return Err(e),
            };
            match &dst_entry {
                Some(d) => {
                    if dst.trailing_slash && !d.metadata.is_dir() {
                        return Err(Errno::ENOTDIR);
                    }
                    if src_entry.metadata.is_dir() && !d.metadata.is_dir() {
                        return Err(Errno::ENOTDIR);
                    }
                    if !src_entry.metadata.is_dir() && d.metadata.is_dir() {
                        return Err(Errno::EISDIR);
                    }
                }
                None => {
                    if dst.trailing_slash {
                        return Err(Errno::ENOENT);
                    }
                }
            }
            let dst_node = dst_entry.as_ref().map(|e| e.handle.node);

            let is_mp = self.is_mountpoint_in_pin_ns(
                &ns,
                &src.parent_pin,
                src.parent.handle.node,
                &src.name,
                Some(src_entry.handle.node),
            ) || self.is_mountpoint_in_pin_ns(
                &ns,
                &dst.parent_pin,
                dst.parent.handle.node,
                &dst.name,
                dst_node,
            );
            if is_mp {
                let src_dir_node = Self::node_for_perm(&cred, &src.parent_pin, &src.parent).await?;
                let src_item_node = Self::node_for_perm(&cred, &src.parent_pin, &src_entry).await?;
                inode::may_delete(&cred.identity, &src_dir_node, &src_item_node)?;
                let dst_dir_node = Self::node_for_perm(&cred, &dst.parent_pin, &dst.parent).await?;
                if let Some(ref dst_e) = dst_entry {
                    let dst_item_node = Self::node_for_perm(&cred, &dst.parent_pin, dst_e).await?;
                    inode::may_delete(&cred.identity, &dst_dir_node, &dst_item_node)?;
                } else {
                    inode::may_create(
                        &cred.identity,
                        &dst_dir_node,
                        dst.parent.metadata.nlink == 0,
                    )?;
                }
                return Err(Errno::EBUSY);
            }

            src.parent_pin
                .guard_op(
                    &cred,
                    true,
                    true,
                    src.parent_pin.fs().rename(
                        &cred,
                        &src.parent.handle,
                        &src.name,
                        &dst.parent.handle,
                        &dst.name,
                        flags,
                    ),
                )
                .await?;
            self.sync_dir_if_needed(&cred, &src.parent_pin, &src.parent.handle)
                .await?;
            if dst.parent.handle.node != src.parent.handle.node {
                self.sync_dir_if_needed(&cred, &dst.parent_pin, &dst.parent.handle)
                    .await?;
            }
            Ok(())
        })
        .await
    }

    pub async fn linkat(
        &self,
        pid: u32,
        from_anchor: StartAnchor,
        from: &str,
        to_anchor: StartAnchor,
        to: &str,
        follow: bool,
    ) -> Result<Entry> {
        self.with_caller(pid, async move {
            let (cred, ns, fs_ctx, fds) = self.snapshot_proc(pid)?;
            let ctx_snap = fs_ctx.borrow().clone();
            let bridge: &dyn ProcBridge = &*self.inner;

            let wflags = if follow {
                WalkFlags::FOLLOW_LAST
            } else {
                WalkFlags::empty()
            };
            let old_res = walk(
                &cred,
                &ns,
                &ctx_snap,
                &fds,
                Some(bridge),
                &from_anchor,
                from,
                wflags,
            )
            .await?;
            let WalkResult::Found {
                pin: old_pin,
                entry: old_entry,
                magic,
                ..
            } = old_res
            else {
                return Err(Errno::ENOENT);
            };
            if matches!(magic, Some(MagicResolved::MountNs { .. })) || old_entry.metadata.is_dir() {
                return Err(Errno::EPERM);
            }

            let dst = match walk_parent(&cred, &ns, &ctx_snap, &fds, Some(bridge), &to_anchor, to)
                .await?
            {
                ParentResolution::Root { .. } | ParentResolution::DotOrDotDot { .. } => {
                    return Err(Errno::EEXIST);
                }
                ParentResolution::Child(t) => t,
            };

            if old_pin.id() != dst.parent_pin.id() {
                return Err(Errno::EXDEV);
            }
            if dst.trailing_slash {
                return Err(Errno::ENOENT);
            }
            if dst.parent_pin.effective_rdonly() {
                return Err(Errno::EROFS);
            }

            let entry = dst
                .parent_pin
                .guard_op(
                    &cred,
                    true,
                    true,
                    dst.parent_pin.fs().link(
                        &cred,
                        &old_entry.handle,
                        &dst.parent.handle,
                        &dst.name,
                    ),
                )
                .await?;
            self.sync_dir_if_needed(&cred, &dst.parent_pin, &dst.parent.handle)
                .await?;
            Ok(entry)
        })
        .await
    }

    pub async fn setattrat(
        &self,
        pid: u32,
        anchor: StartAnchor,
        path: &str,
        attr: &SetAttr,
        follow: bool,
    ) -> Result<Metadata> {
        self.with_caller(pid, async move {
            let (cred, ns, fs_ctx, fds) = self.snapshot_proc(pid)?;
            let ctx_snap = fs_ctx.borrow().clone();
            let bridge: &dyn ProcBridge = &*self.inner;
            let flags = if follow {
                WalkFlags::FOLLOW_LAST
            } else {
                WalkFlags::empty()
            };
            let resolved = walk(
                &cred,
                &ns,
                &ctx_snap,
                &fds,
                Some(bridge),
                &anchor,
                path,
                flags,
            )
            .await?;
            let WalkResult::Found { pin, entry, .. } = resolved else {
                return Err(Errno::ENOENT);
            };
            if pin.effective_rdonly() {
                return Err(Errno::EROFS);
            }
            let meta = pin
                .guard_op(
                    &cred,
                    true,
                    true,
                    pin.fs().setattr(&cred, &entry.handle, attr),
                )
                .await?;
            self.sync_object_if_needed(&cred, &pin, &entry.handle)
                .await?;
            Ok(meta)
        })
        .await
    }

    pub async fn getxattrat(
        &self,
        pid: u32,
        anchor: StartAnchor,
        path: &str,
        name: &str,
        follow: bool,
    ) -> Result<Vec<u8>> {
        self.with_caller(pid, async move {
            let (cred, ns, fs_ctx, fds) = self.snapshot_proc(pid)?;
            let ctx_snap = fs_ctx.borrow().clone();
            let bridge: &dyn ProcBridge = &*self.inner;
            let flags = if follow {
                WalkFlags::FOLLOW_LAST
            } else {
                WalkFlags::empty()
            };
            let resolved = walk(
                &cred,
                &ns,
                &ctx_snap,
                &fds,
                Some(bridge),
                &anchor,
                path,
                flags,
            )
            .await?;
            let WalkResult::Found { pin, entry, .. } = resolved else {
                return Err(Errno::ENOENT);
            };
            pin.guard_op(
                &cred,
                false,
                false,
                pin.fs().getxattr(&cred, &entry.handle, name),
            )
            .await
        })
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn setxattrat(
        &self,
        pid: u32,
        anchor: StartAnchor,
        path: &str,
        name: &str,
        value: &[u8],
        xflags: XattrFlags,
        follow: bool,
    ) -> Result<()> {
        self.with_caller(pid, async move {
            let (cred, ns, fs_ctx, fds) = self.snapshot_proc(pid)?;
            let ctx_snap = fs_ctx.borrow().clone();
            let bridge: &dyn ProcBridge = &*self.inner;
            let flags = if follow {
                WalkFlags::FOLLOW_LAST
            } else {
                WalkFlags::empty()
            };
            let resolved = walk(
                &cred,
                &ns,
                &ctx_snap,
                &fds,
                Some(bridge),
                &anchor,
                path,
                flags,
            )
            .await?;
            let WalkResult::Found { pin, entry, .. } = resolved else {
                return Err(Errno::ENOENT);
            };
            if pin.effective_rdonly() {
                return Err(Errno::EROFS);
            }
            pin.guard_op(
                &cred,
                true,
                true,
                pin.fs().setxattr(&cred, &entry.handle, name, value, xflags),
            )
            .await?;
            self.sync_object_if_needed(&cred, &pin, &entry.handle)
                .await?;
            Ok(())
        })
        .await
    }

    pub async fn listxattrat(
        &self,
        pid: u32,
        anchor: StartAnchor,
        path: &str,
        follow: bool,
    ) -> Result<Vec<String>> {
        self.with_caller(pid, async move {
            let (cred, ns, fs_ctx, fds) = self.snapshot_proc(pid)?;
            let ctx_snap = fs_ctx.borrow().clone();
            let bridge: &dyn ProcBridge = &*self.inner;
            let flags = if follow {
                WalkFlags::FOLLOW_LAST
            } else {
                WalkFlags::empty()
            };
            let resolved = walk(
                &cred,
                &ns,
                &ctx_snap,
                &fds,
                Some(bridge),
                &anchor,
                path,
                flags,
            )
            .await?;
            let WalkResult::Found { pin, entry, .. } = resolved else {
                return Err(Errno::ENOENT);
            };
            pin.guard_op(
                &cred,
                false,
                false,
                pin.fs().listxattr(&cred, &entry.handle),
            )
            .await
        })
        .await
    }

    pub async fn removexattrat(
        &self,
        pid: u32,
        anchor: StartAnchor,
        path: &str,
        name: &str,
        follow: bool,
    ) -> Result<()> {
        self.with_caller(pid, async move {
            let (cred, ns, fs_ctx, fds) = self.snapshot_proc(pid)?;
            let ctx_snap = fs_ctx.borrow().clone();
            let bridge: &dyn ProcBridge = &*self.inner;
            let flags = if follow {
                WalkFlags::FOLLOW_LAST
            } else {
                WalkFlags::empty()
            };
            let resolved = walk(
                &cred,
                &ns,
                &ctx_snap,
                &fds,
                Some(bridge),
                &anchor,
                path,
                flags,
            )
            .await?;
            let WalkResult::Found { pin, entry, .. } = resolved else {
                return Err(Errno::ENOENT);
            };
            if pin.effective_rdonly() {
                return Err(Errno::EROFS);
            }
            pin.guard_op(
                &cred,
                true,
                true,
                pin.fs().removexattr(&cred, &entry.handle, name),
            )
            .await?;
            self.sync_object_if_needed(&cred, &pin, &entry.handle)
                .await?;
            Ok(())
        })
        .await
    }

    pub async fn read(&self, pid: u32, fd: Fd, buf: &mut [u8]) -> Result<usize> {
        self.with_caller(pid, async move {
            let (cred, _, _, fds) = self.snapshot_proc(pid)?;
            let file = fds.borrow().get(fd)?;
            file.read_as(&cred, buf).await
        })
        .await
    }

    pub async fn write(&self, pid: u32, fd: Fd, buf: &[u8]) -> Result<usize> {
        self.with_caller(pid, async move {
            let (cred, _, _, fds) = self.snapshot_proc(pid)?;
            let file = fds.borrow().get(fd)?;
            file.write_as(&cred, buf).await
        })
        .await
    }

    pub async fn pread(&self, pid: u32, fd: Fd, buf: &mut [u8], offset: u64) -> Result<usize> {
        self.with_caller(pid, async move {
            let (cred, _, _, fds) = self.snapshot_proc(pid)?;
            let file = fds.borrow().get(fd)?;
            file.read_at_as(&cred, buf, offset).await
        })
        .await
    }

    pub async fn pwrite(&self, pid: u32, fd: Fd, buf: &[u8], offset: u64) -> Result<usize> {
        self.with_caller(pid, async move {
            let (cred, _, _, fds) = self.snapshot_proc(pid)?;
            let file = fds.borrow().get(fd)?;
            file.write_at_as(&cred, buf, offset).await
        })
        .await
    }

    pub async fn lseek(&self, pid: u32, fd: Fd, from: SeekFrom) -> Result<u64> {
        self.with_caller(pid, async move {
            let (cred, _, _, fds) = self.snapshot_proc(pid)?;
            let file = fds.borrow().get(fd)?;
            file.seek_as(&cred, from).await
        })
        .await
    }

    pub async fn ftruncate(&self, pid: u32, fd: Fd, size: u64) -> Result<()> {
        self.with_caller(pid, async move {
            let (cred, _, _, fds) = self.snapshot_proc(pid)?;
            let file = fds.borrow().get(fd)?;
            file.set_len_as(&cred, size).await
        })
        .await
    }

    pub async fn fsync(&self, pid: u32, fd: Fd) -> Result<()> {
        self.with_caller(pid, async move {
            let (cred, _, _, fds) = self.snapshot_proc(pid)?;
            let file = fds.borrow().get(fd)?;
            file.sync_all_as(&cred).await
        })
        .await
    }

    pub async fn fdatasync(&self, pid: u32, fd: Fd) -> Result<()> {
        self.with_caller(pid, async move {
            let (cred, _, _, fds) = self.snapshot_proc(pid)?;
            let file = fds.borrow().get(fd)?;
            file.sync_data_as(&cred).await
        })
        .await
    }

    pub fn dup(&self, pid: u32, fd: Fd, min: Fd, cloexec: bool) -> Result<Fd> {
        let fds = self.process_fds(pid)?;
        fds.borrow_mut().dup(fd, min, cloexec)
    }

    pub async fn dup2(&self, pid: u32, old: Fd, new: Fd) -> Result<Fd> {
        let (cred, _, _, fds) = self.snapshot_proc(pid)?;
        let old_prov = fds
            .borrow()
            .get(new)
            .ok()
            .and_then(|f| f.mount_pin().map(|p| Rc::as_ptr(p.provider())));
        let res = fds.dup2(old, new).await;
        let provs: Vec<_> = old_prov.into_iter().collect();
        let _ = self
            .inner
            .releases
            .flush_scoped(cred.identity.id, &provs)
            .await;
        res
    }

    pub async fn close(&self, pid: u32, fd: Fd) -> Result<()> {
        let (cred, _, _, fds) = self.snapshot_proc(pid)?;
        let old_prov = fds
            .borrow()
            .get(fd)
            .ok()
            .and_then(|f| f.mount_pin().map(|p| Rc::as_ptr(p.provider())));
        let res = fds.close(fd).await;
        let provs: Vec<_> = old_prov.into_iter().collect();
        let _ = self
            .inner
            .releases
            .flush_scoped(cred.identity.id, &provs)
            .await;
        res
    }

    // -------------------------------------------------------------------------
    // Chroot- & MountNamespace-faithful executable + `#!` shebang resolver
    // -------------------------------------------------------------------------

    async fn open_exec_candidate(
        &self,
        cred: &Cred,
        ns: &Rc<RefCell<MountNamespace>>,
        ctx: &crate::context::FsContext,
        fds: &impl crate::walk::FdLookup,
        candidate: &str,
    ) -> Result<(MountPin, Entry, FileRef)> {
        let bridge: &dyn ProcBridge = &*self.inner;
        let resolved = walk(
            cred,
            ns,
            ctx,
            fds,
            Some(bridge),
            &StartAnchor::AtFdCwd,
            candidate,
            WalkFlags::FOLLOW_LAST,
        )
        .await?;
        let WalkResult::Found {
            pin, entry, magic, ..
        } = resolved
        else {
            return Err(Errno::ENOENT);
        };
        if matches!(magic, Some(MagicResolved::MountNs { .. })) || !entry.metadata.is_file() {
            return Err(Errno::EACCES);
        }
        if pin.effective_noexec() {
            return Err(Errno::EACCES);
        }
        if entry.metadata.size > abi::EXEC_MAX {
            return Err(Errno::E2BIG);
        }

        let mut exec_opts = OpenOptions::new();
        exec_opts.exec(true);
        let open_ref = pin
            .guard_op(
                cred,
                false,
                false,
                pin.fs().open(cred, &entry.handle, &exec_opts),
            )
            .await?;
        let file_ref = FileRef::new_mounted_with_type(
            pin.clone(),
            open_ref,
            entry.handle.clone(),
            Some(entry.metadata.file_type),
            cred.clone(),
            &exec_opts,
            &self.inner.releases,
        );
        Ok((pin, entry, file_ref))
    }

    /// Resolve an executable (with optional `PATH` search and up to [`MAX_SHEBANG_DEPTH`] = 4
    /// levels of `#!` shebang expansion) strictly within `pid`'s `MountNamespace` and `FsContext`.
    pub async fn resolve_exec(
        &self,
        pid: u32,
        file: &str,
        argv: Vec<String>,
        path_env: Option<&str>,
        search_path: bool,
    ) -> Result<ResolvedExec> {
        self.with_caller(pid, async move {
            if file.is_empty() {
                return Err(Errno::ENOENT);
            }
            let (cred, ns, fs_ctx, fds) = self.snapshot_proc(pid)?;
            let ctx_snap = fs_ctx.borrow().clone();

            let mut cur_argv = if argv.is_empty() {
                vec![file.to_string()]
            } else {
                argv
            };

            // Step 1: Initial candidate resolution (`PATH` search when bare name & `search_path`).
            let (mut matched_path, mut pin, mut entry, mut file_ref) =
                if file.contains('/') || !search_path {
                    let (p, e, f) = self
                        .open_exec_candidate(&cred, &ns, &ctx_snap, &fds, file)
                        .await?;
                    (file.to_string(), p, e, f)
                } else {
                    let path_str = path_env.unwrap_or("/usr/bin");
                    let mut saw_eacces = false;
                    let mut found = None;
                    for dir in path_str.split(':') {
                        let candidate = if dir.is_empty() {
                            file.to_string()
                        } else if dir == "/" {
                            format!("/{file}")
                        } else {
                            format!("{}/{file}", dir.trim_end_matches('/'))
                        };
                        match self
                            .open_exec_candidate(&cred, &ns, &ctx_snap, &fds, &candidate)
                            .await
                        {
                            Ok((p, e, f)) => {
                                found = Some((candidate, p, e, f));
                                break;
                            }
                            Err(Errno::ENOENT | Errno::ENOTDIR) => continue,
                            Err(Errno::EACCES) => {
                                saw_eacces = true;
                                continue;
                            }
                            Err(err) => return Err(err),
                        }
                    }
                    match found {
                        Some(hit) => hit,
                        None => {
                            return Err(if saw_eacces {
                                Errno::EACCES
                            } else {
                                Errno::ENOENT
                            });
                        }
                    }
                };

            // Step 2: `#!` shebang loop (bounded by `MAX_SHEBANG_DEPTH = 4`).
            let mut depth = 0usize;
            loop {
                let mut buf = [0u8; BINPRM_BUF_SIZE];
                let read_res = file_ref.read_at_as(&cred, &mut buf, 0).await;
                let n = match read_res {
                    Ok(n) => n,
                    Err(e) => {
                        let _ = file_ref.close().await;
                        return Err(e);
                    }
                };
                let header = &buf[..n];

                if header.starts_with(b"#!") {
                    let _ = file_ref.close().await;
                    if depth >= MAX_SHEBANG_DEPTH {
                        return Err(Errno::ELOOP);
                    }
                    let (interp, opt_arg) = parse_shebang(header, n == BINPRM_BUF_SIZE)?;
                    let mut next_argv = Vec::with_capacity(2 + cur_argv.len());
                    next_argv.push(interp.clone());
                    if let Some(arg) = opt_arg {
                        next_argv.push(arg);
                    }
                    next_argv.push(matched_path);
                    if cur_argv.len() > 1 {
                        next_argv.extend_from_slice(&cur_argv[1..]);
                    }
                    cur_argv = next_argv;

                    // `#!` interpreters are NEVER searched in `PATH`; `/...` resolves from
                    // `FsContext.root` (`chroot`), relative from `FsContext.cwd`.
                    let (next_pin, next_entry, next_file) = self
                        .open_exec_candidate(&cred, &ns, &ctx_snap, &fds, &interp)
                        .await?;
                    matched_path = interp;
                    pin = next_pin;
                    entry = next_entry;
                    file_ref = next_file;
                    depth += 1;
                    continue;
                }

                if header.starts_with(b"\0asm") && header.len() >= 8 {
                    let nosuid = pin.effective_flags().nosuid;
                    return Ok(ResolvedExec {
                        file: file_ref,
                        pin,
                        entry,
                        argv: cur_argv,
                        resolved_path: matched_path,
                        nosuid,
                        header: header.to_vec(),
                    });
                }

                let _ = file_ref.close().await;
                return Err(Errno::ENOEXEC);
            }
        })
        .await
    }

    // -------------------------------------------------------------------------
    // Contract v2 additions (#77): read_dir_page, ficlone (FICLONE), syncfs
    // -------------------------------------------------------------------------

    /// Cursor-based paged directory enumeration by path (contract §3, R7, #77).
    pub async fn read_dir_page(
        &self,
        pid: u32,
        anchor: StartAnchor,
        path: &str,
        cookie: u64,
        max_entries: usize,
    ) -> Result<crate::DirPage> {
        self.with_caller(pid, async move {
            let (cred, ns, fs_ctx, fds) = self.snapshot_proc(pid)?;
            let ctx_snap = fs_ctx.borrow().clone();
            let bridge: &dyn ProcBridge = &*self.inner;
            let resolved = walk(
                &cred,
                &ns,
                &ctx_snap,
                &fds,
                Some(bridge),
                &anchor,
                path,
                WalkFlags::FOLLOW_LAST | WalkFlags::MUST_BE_DIR,
            )
            .await?;
            let WalkResult::Found { pin, entry, .. } = resolved else {
                return Err(Errno::ENOENT);
            };
            pin.guard_op(
                &cred,
                false,
                false,
                pin.fs()
                    .read_dir_page(&cred, &entry.handle, cookie, max_entries),
            )
            .await
        })
        .await
    }

    /// Cursor-based paged directory enumeration on an open directory descriptor (#77).
    pub async fn fd_read_dir_page(
        &self,
        pid: u32,
        fd: Fd,
        cookie: u64,
        max_entries: usize,
    ) -> Result<crate::DirPage> {
        self.with_caller(pid, async move {
            let (cred, _, _, fds) = self.snapshot_proc(pid)?;
            let file = fds.borrow().get(fd)?;
            if file.access() == Access::Path {
                return Err(Errno::EBADF);
            }
            if file.mount_ns().is_some() {
                return Err(Errno::ENOTDIR);
            }
            let meta = file.metadata_as(&cred).await?;
            if !meta.is_dir() {
                return Err(Errno::ENOTDIR);
            }
            if let Some(pin) = file.mount_pin() {
                pin.guard_op(
                    &cred,
                    false,
                    false,
                    pin.fs()
                        .read_dir_page(&cred, file.handle(), cookie, max_entries),
                )
                .await
            } else {
                file.fs()
                    .read_dir_page(&cred, file.handle(), cookie, max_entries)
                    .await
            }
        })
        .await
    }

    /// Intra-filesystem O(1) extent reflink (`ioctl(dst_fd, FICLONE, src_fd)`, contract §5, #77).
    /// Cross-filesystem or cross-volume calls fail with `Errno::EXDEV`; read-only destination
    /// mounts fail with `Errno::EROFS`.
    pub async fn ficlone(&self, pid: u32, dst_fd: Fd, src_fd: Fd) -> Result<()> {
        self.with_caller(pid, async move {
            let (cred, _, _, fds) = self.snapshot_proc(pid)?;
            let (dst_file, src_file) = {
                let table = fds.borrow();
                (table.get(dst_fd)?, table.get(src_fd)?)
            };
            if dst_file.access() == Access::Path || src_file.access() == Access::Path {
                return Err(Errno::EBADF);
            }
            if !src_file.access().reads() || !dst_file.access().writes() {
                return Err(Errno::EBADF);
            }
            if dst_file.is_virtual() || src_file.is_virtual() {
                return Err(Errno::EXDEV);
            }
            if src_file.fs().id() != dst_file.fs().id() {
                return Err(Errno::EXDEV);
            }
            let Some(dst_pin) = dst_file.mount_pin() else {
                return dst_file
                    .fs()
                    .reflink(&cred, src_file.open_ref(), dst_file.open_ref())
                    .await;
            };
            if let Some(src_pin) = src_file.mount_pin() {
                src_pin.guard_enter(&cred)?;
                if src_pin.fs().id() != dst_pin.fs().id() {
                    return Err(Errno::EXDEV);
                }
            }
            if dst_pin.effective_rdonly() {
                return Err(Errno::EROFS);
            }
            dst_pin
                .guard_op(
                    &cred,
                    true,
                    true,
                    dst_pin
                        .fs()
                        .reflink(&cred, src_file.open_ref(), dst_file.open_ref()),
                )
                .await?;
            if dst_pin.effective_flags().synchronous {
                dst_pin
                    .guard_op(
                        &cred,
                        true,
                        false,
                        dst_pin.fs().sync_all(dst_file.open_ref()),
                    )
                    .await?;
                dst_pin.backing().record_sync();
            }
            Ok(())
        })
        .await
    }

    /// Whole-filesystem durability barrier (`syncfs(2)`, contract §5, #77).
    pub async fn syncfs(&self, pid: u32, fd: Fd) -> Result<()> {
        self.with_caller(pid, async move {
            let (cred, _, _, fds) = self.snapshot_proc(pid)?;
            let file = fds.borrow().get(fd)?;
            if file.access() == Access::Path {
                return Err(Errno::EBADF);
            }
            if file.is_virtual() {
                return Err(Errno::EINVAL);
            }
            let meta = file.metadata_as(&cred).await?;
            if meta.file_type == FileType::CharDevice {
                return Err(Errno::EINVAL);
            }
            if let Some(pin) = file.mount_pin() {
                pin.guard_op(&cred, true, false, pin.fs().sync_fs(&cred))
                    .await?;
                pin.backing().record_sync();
                Ok(())
            } else {
                file.fs().sync_fs(&cred).await
            }
        })
        .await
    }
}

fn parse_shebang(header: &[u8], buffer_was_full: bool) -> Result<(String, Option<String>)> {
    let line = match header.iter().position(|&b| b == b'\n') {
        Some(nl) => &header[2..nl],
        None => {
            if buffer_was_full {
                return Err(Errno::ENOEXEC);
            }
            &header[2..]
        }
    };
    if line.contains(&0) {
        return Err(Errno::ENOEXEC);
    }
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let trimmed_start = trim_shebang_ws_start(line);
    let interp_len = trimmed_start
        .iter()
        .position(|&b| b == b' ' || b == b'\t')
        .unwrap_or(trimmed_start.len());
    let interp_bytes = &trimmed_start[..interp_len];
    if interp_bytes.is_empty() {
        return Err(Errno::ENOEXEC);
    }
    let interp = std::str::from_utf8(interp_bytes)
        .map_err(|_| Errno::ENOEXEC)?
        .to_string();

    let rest = trim_shebang_ws(trimmed_start.get(interp_len..).unwrap_or_default());
    let opt_arg = if rest.is_empty() {
        None
    } else {
        Some(
            std::str::from_utf8(rest)
                .map_err(|_| Errno::ENOEXEC)?
                .to_string(),
        )
    };
    Ok((interp, opt_arg))
}

fn trim_shebang_ws_start(mut s: &[u8]) -> &[u8] {
    while let Some((&first, rest)) = s.split_first() {
        if first == b' ' || first == b'\t' {
            s = rest;
        } else {
            break;
        }
    }
    s
}

fn trim_shebang_ws(s: &[u8]) -> &[u8] {
    let mut s = trim_shebang_ws_start(s);
    while let Some((&last, rest)) = s.split_last() {
        if last == b' ' || last == b'\t' {
            s = rest;
        } else {
            break;
        }
    }
    s
}
