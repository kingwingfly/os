//! `/proc` virtual filesystem (`proc` fstype, `docs/architecture/contract.md` §2.2, §4, §5).
//! Synthesizes `/proc/mounts -> self/mounts`, `/proc/self`, `/proc/<pid>/{mountinfo,mounts,ns/mnt,root,cwd,fd,fdinfo}`
//! locally from [`ProcBridge`] state, and delegates server/host entries via [`ProcProvider`].

use crate::context::{PathAnchor, SharedFdTable};
use crate::mount::MountPin;
use crate::namespace::{MountNamespace, format_mountinfo, format_mounts};
use crate::{
    Access, BoxFuture, Conflict, Cred, DirEntry, Entry, FILE_MAX, Fd, FileType, Filesystem, FsId,
    Handle, LockFamily, LockKind, LockRange, Metadata, NodeId, OpenOptions, OpenRef, RenameFlags,
    Result, SetAttr, StatFs, Stop, Timespec, Walked, WriteAt, Written, XattrFlags, check_component,
    profiles,
};
use abi::Errno;
use abi::contract::FsCapabilities;
use os_core::xattr;
use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};
use std::rc::{Rc, Weak};

const GENERATION: u64 = 1;
const ROOT_INO: u64 = 1;
const TOP_MOUNTS_INO: u64 = 2;
const TOP_SELF_INO: u64 = 3;

const TAG_TOP_DYN: u64 = 1;
const TAG_PID_FIXED: u64 = 2;
const TAG_PID_FD: u64 = 3;
const TAG_PID_FDINFO: u64 = 4;
const TAG_PID_DYN: u64 = 5;

const SUB_PID_DIR: u16 = 0;
const SUB_MOUNTINFO: u16 = 1;
const SUB_MOUNTS: u16 = 2;
const SUB_NS_DIR: u16 = 3;
const SUB_NS_MNT: u16 = 4;
const SUB_ROOT: u16 = 5;
const SUB_CWD: u16 = 6;
const SUB_FD_DIR: u16 = 7;
const SUB_FDINFO_DIR: u16 = 8;

/// Decoded 53-bit `/proc` inode kind (`<= abi::fs::JS_SAFE`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcNode {
    Root,
    TopMounts,
    TopSelf,
    TopDynamic(u16),
    PidDir(u32),
    PidMountinfo(u32),
    PidMounts(u32),
    PidNsDir(u32),
    PidNsMnt(u32),
    PidRoot(u32),
    PidCwd(u32),
    PidFdDir(u32),
    PidFdinfoDir(u32),
    PidFd(u32, u16),
    PidFdinfo(u32, u16),
    PidDynamic(u32, u16),
}

pub fn encode_proc_ino(node: ProcNode) -> u64 {
    let pack = |tag: u64, pid: u32, sub: u16| (tag << 48) | (u64::from(pid) << 16) | u64::from(sub);
    match node {
        ProcNode::Root => ROOT_INO,
        ProcNode::TopMounts => TOP_MOUNTS_INO,
        ProcNode::TopSelf => TOP_SELF_INO,
        ProcNode::TopDynamic(idx) => pack(TAG_TOP_DYN, 0, idx),
        ProcNode::PidDir(pid) => pack(TAG_PID_FIXED, pid, SUB_PID_DIR),
        ProcNode::PidMountinfo(pid) => pack(TAG_PID_FIXED, pid, SUB_MOUNTINFO),
        ProcNode::PidMounts(pid) => pack(TAG_PID_FIXED, pid, SUB_MOUNTS),
        ProcNode::PidNsDir(pid) => pack(TAG_PID_FIXED, pid, SUB_NS_DIR),
        ProcNode::PidNsMnt(pid) => pack(TAG_PID_FIXED, pid, SUB_NS_MNT),
        ProcNode::PidRoot(pid) => pack(TAG_PID_FIXED, pid, SUB_ROOT),
        ProcNode::PidCwd(pid) => pack(TAG_PID_FIXED, pid, SUB_CWD),
        ProcNode::PidFdDir(pid) => pack(TAG_PID_FIXED, pid, SUB_FD_DIR),
        ProcNode::PidFdinfoDir(pid) => pack(TAG_PID_FIXED, pid, SUB_FDINFO_DIR),
        ProcNode::PidFd(pid, fd) => pack(TAG_PID_FD, pid, fd),
        ProcNode::PidFdinfo(pid, fd) => pack(TAG_PID_FDINFO, pid, fd),
        ProcNode::PidDynamic(pid, idx) => pack(TAG_PID_DYN, pid, idx),
    }
}

pub fn decode_proc_ino(ino: u64) -> Option<ProcNode> {
    if ino == ROOT_INO {
        return Some(ProcNode::Root);
    }
    if ino == TOP_MOUNTS_INO {
        return Some(ProcNode::TopMounts);
    }
    if ino == TOP_SELF_INO {
        return Some(ProcNode::TopSelf);
    }
    if ino > abi::fs::JS_SAFE {
        return None;
    }
    let tag = ino >> 48;
    let pid = ((ino >> 16) & 0xffff_ffff) as u32;
    let sub = (ino & 0xffff) as u16;
    match tag {
        TAG_TOP_DYN if pid == 0 && sub > 0 => Some(ProcNode::TopDynamic(sub)),
        TAG_PID_FIXED => match sub {
            SUB_PID_DIR => Some(ProcNode::PidDir(pid)),
            SUB_MOUNTINFO => Some(ProcNode::PidMountinfo(pid)),
            SUB_MOUNTS => Some(ProcNode::PidMounts(pid)),
            SUB_NS_DIR => Some(ProcNode::PidNsDir(pid)),
            SUB_NS_MNT => Some(ProcNode::PidNsMnt(pid)),
            SUB_ROOT => Some(ProcNode::PidRoot(pid)),
            SUB_CWD => Some(ProcNode::PidCwd(pid)),
            SUB_FD_DIR => Some(ProcNode::PidFdDir(pid)),
            SUB_FDINFO_DIR => Some(ProcNode::PidFdinfoDir(pid)),
            _ => None,
        },
        TAG_PID_FD => Some(ProcNode::PidFd(pid, sub)),
        TAG_PID_FDINFO => Some(ProcNode::PidFdinfo(pid, sub)),
        TAG_PID_DYN if sub > 0 => Some(ProcNode::PidDynamic(pid, sub)),
        _ => None,
    }
}

#[derive(Clone)]
pub struct ProcCallerInfo {
    pub pid: u32,
    pub root: PathAnchor,
    pub is_at_ns_root: bool,
}

#[derive(Clone)]
pub struct ProcTargetInfo {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub mnt_ns: Rc<RefCell<MountNamespace>>,
    pub root: PathAnchor,
    pub cwd: PathAnchor,
    pub fds: SharedFdTable,
}

/// Bridge implemented by [`crate::Vfs`] supplying live local process/namespace/fd state to [`ProcFs`].
pub trait ProcBridge {
    fn instance_id(&self) -> String;
    fn current_caller(&self) -> Option<ProcCallerInfo>;
    fn local_pids(&self) -> Vec<u32>;
    fn process_info(&self, pid: u32) -> Option<ProcTargetInfo>;
}

pub fn may_inspect_proc(cred: &Cred, target_uid: u32) -> Result<()> {
    if cred.identity.id == 0 || cred.identity.id == target_uid {
        Ok(())
    } else {
        Err(Errno::EACCES)
    }
}

/// Dynamic `/proc` entry description returned by [`ProcProvider`].
#[derive(Clone, Debug)]
pub struct ProcDynamicEntry {
    pub name: String,
    pub file_type: FileType,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
}

/// Fallback provider for `/proc/<pid>/{status,cmdline,...}` and top-level `/proc/*` files until #54.
pub trait ProcProvider {
    fn list_pids<'a>(&'a self, _cred: &'a Cred) -> BoxFuture<'a, Vec<u32>> {
        Box::pin(async { Ok(Vec::new()) })
    }
    fn top_entries<'a>(&'a self, _cred: &'a Cred) -> BoxFuture<'a, Vec<ProcDynamicEntry>> {
        Box::pin(async { Ok(Vec::new()) })
    }
    fn read_top<'a>(&'a self, _cred: &'a Cred, _name: &'a str) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(async { Err(Errno::ENOENT) })
    }
    fn pid_entries<'a>(
        &'a self,
        _cred: &'a Cred,
        _pid: u32,
    ) -> BoxFuture<'a, Vec<ProcDynamicEntry>> {
        Box::pin(async { Ok(Vec::new()) })
    }
    fn read_pid<'a>(
        &'a self,
        _cred: &'a Cred,
        _pid: u32,
        _name: &'a str,
    ) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(async { Err(Errno::ENOENT) })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct EmptyProcProvider;
impl ProcProvider for EmptyProcProvider {}

struct ProcOpen {
    ino: u64,
    access: Access,
    bytes: Option<Vec<u8>>,
    metadata: Metadata,
}

#[derive(Default)]
struct InternTable {
    by_name: HashMap<String, u16>,
    by_id: HashMap<u16, String>,
    next_id: u16,
}

impl InternTable {
    fn intern(&mut self, name: &str) -> Result<u16> {
        if let Some(&id) = self.by_name.get(name) {
            return Ok(id);
        }
        let id = self.next_id.checked_add(1).ok_or(Errno::ENOSPC)?;
        self.next_id = id;
        self.by_name.insert(name.to_string(), id);
        self.by_id.insert(id, name.to_string());
        Ok(id)
    }

    fn get_name(&self, id: u16) -> Option<String> {
        self.by_id.get(&id).cloned()
    }
}

struct ProcRuntime {
    bridge: Option<Weak<dyn ProcBridge>>,
    top_names: InternTable,
    pid_names: InternTable,
    opens: HashMap<u64, ProcOpen>,
    next_open: u64,
}

pub struct ProcFs<P = EmptyProcProvider> {
    fs_id: FsId,
    mounted_at: Timespec,
    provider: P,
    state: RefCell<ProcRuntime>,
}

impl ProcFs<EmptyProcProvider> {
    pub fn local(fs_id: FsId, mounted_at: Timespec) -> Self {
        Self::new(fs_id, mounted_at, EmptyProcProvider)
    }
}

impl<P: ProcProvider> ProcFs<P> {
    pub fn new(fs_id: FsId, mounted_at: Timespec, provider: P) -> Self {
        Self {
            fs_id,
            mounted_at,
            provider,
            state: RefCell::new(ProcRuntime {
                bridge: None,
                top_names: InternTable::default(),
                pid_names: InternTable::default(),
                opens: HashMap::new(),
                next_open: 1,
            }),
        }
    }

    pub fn bind_bridge(&self, bridge: Weak<dyn ProcBridge>) {
        self.state.borrow_mut().bridge = Some(bridge);
    }

    fn bridge(&self) -> Option<Rc<dyn ProcBridge>> {
        self.state.borrow().bridge.as_ref()?.upgrade()
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

    fn check_handle(&self, handle: &Handle) -> Result<ProcNode> {
        if handle.fs != self.fs_id || !handle.proof.is_empty() {
            return Err(Errno::EACCES);
        }
        if handle.node.generation != GENERATION {
            return Err(Errno::ESTALE);
        }
        decode_proc_ino(handle.node.ino).ok_or(Errno::ESTALE)
    }

    fn make_meta(&self, file_type: FileType, mode: u16, uid: u32, gid: u32, size: u64) -> Metadata {
        Metadata {
            file_type,
            mode: mode & 0o7777,
            nlink: if file_type == FileType::Dir { 2 } else { 1 },
            uid,
            gid,
            size,
            atime: self.mounted_at,
            mtime: self.mounted_at,
            ctime: self.mounted_at,
            rdev: None,
            acl: false,
        }
    }

    async fn pid_owner(&self, cred: &Cred, pid: u32) -> Result<(u32, u32, bool)> {
        if let Some(bridge) = self.bridge()
            && let Some(info) = bridge.process_info(pid)
        {
            return Ok((info.uid, info.gid, true));
        }
        let remote = self.provider.list_pids(cred).await?;
        if remote.contains(&pid) {
            Ok((0, 0, false))
        } else {
            Err(Errno::ENOENT)
        }
    }

    async fn metadata_for(&self, cred: &Cred, node: ProcNode) -> Result<Metadata> {
        match node {
            ProcNode::Root => Ok(self.make_meta(FileType::Dir, 0o555, 0, 0, 4096)),
            ProcNode::TopMounts => {
                Ok(self.make_meta(FileType::Symlink, 0o777, 0, 0, "self/mounts".len() as u64))
            }
            ProcNode::TopSelf => {
                let caller_pid = self
                    .bridge()
                    .and_then(|b| b.current_caller().map(|c| c.pid))
                    .unwrap_or(1);
                Ok(self.make_meta(
                    FileType::Symlink,
                    0o777,
                    0,
                    0,
                    caller_pid.to_string().len() as u64,
                ))
            }
            ProcNode::TopDynamic(idx) => {
                let name = self
                    .state
                    .borrow()
                    .top_names
                    .get_name(idx)
                    .ok_or(Errno::ESTALE)?;
                let entries = self.provider.top_entries(cred).await?;
                let found = entries
                    .into_iter()
                    .find(|e| e.name == name)
                    .ok_or(Errno::ENOENT)?;
                Ok(self.make_meta(found.file_type, found.mode, found.uid, found.gid, 0))
            }
            ProcNode::PidDir(pid) => {
                let (uid, gid, _) = self.pid_owner(cred, pid).await?;
                Ok(self.make_meta(FileType::Dir, 0o555, uid, gid, 4096))
            }
            ProcNode::PidMountinfo(pid) | ProcNode::PidMounts(pid) => {
                let (uid, gid, is_local) = self.pid_owner(cred, pid).await?;
                if !is_local {
                    return Err(Errno::ENOENT);
                }
                Ok(self.make_meta(FileType::File, 0o444, uid, gid, 0))
            }
            ProcNode::PidNsDir(pid) => {
                let (uid, gid, is_local) = self.pid_owner(cred, pid).await?;
                if !is_local {
                    return Err(Errno::ENOENT);
                }
                Ok(self.make_meta(FileType::Dir, 0o511, uid, gid, 4096))
            }
            ProcNode::PidNsMnt(pid) | ProcNode::PidRoot(pid) | ProcNode::PidCwd(pid) => {
                let (uid, gid, is_local) = self.pid_owner(cred, pid).await?;
                if !is_local {
                    return Err(Errno::ENOENT);
                }
                Ok(self.make_meta(FileType::Symlink, 0o777, uid, gid, 0))
            }
            ProcNode::PidFdDir(pid) | ProcNode::PidFdinfoDir(pid) => {
                let (uid, gid, is_local) = self.pid_owner(cred, pid).await?;
                if !is_local {
                    return Err(Errno::ENOENT);
                }
                Ok(self.make_meta(FileType::Dir, 0o500, uid, gid, 4096))
            }
            ProcNode::PidFd(pid, fd) => {
                let bridge = self.bridge().ok_or(Errno::ENOENT)?;
                let info = bridge.process_info(pid).ok_or(Errno::ENOENT)?;
                if info.fds.borrow().get(Fd::from(fd)).is_err() {
                    return Err(Errno::ENOENT);
                }
                Ok(self.make_meta(FileType::Symlink, 0o700, info.uid, info.gid, 0))
            }
            ProcNode::PidFdinfo(pid, fd) => {
                let bridge = self.bridge().ok_or(Errno::ENOENT)?;
                let info = bridge.process_info(pid).ok_or(Errno::ENOENT)?;
                if info.fds.borrow().get(Fd::from(fd)).is_err() {
                    return Err(Errno::ENOENT);
                }
                Ok(self.make_meta(FileType::File, 0o400, info.uid, info.gid, 0))
            }
            ProcNode::PidDynamic(pid, idx) => {
                let _ = self.pid_owner(cred, pid).await?;
                let name = self
                    .state
                    .borrow()
                    .pid_names
                    .get_name(idx)
                    .ok_or(Errno::ESTALE)?;
                let entries = self.provider.pid_entries(cred, pid).await?;
                let found = entries
                    .into_iter()
                    .find(|e| e.name == name)
                    .ok_or(Errno::ENOENT)?;
                Ok(self.make_meta(found.file_type, found.mode, found.uid, found.gid, 0))
            }
        }
    }

    async fn lookup_node(&self, cred: &Cred, dir: ProcNode, name: &str) -> Result<Entry> {
        check_component(name)?;
        let child_node = match dir {
            ProcNode::Root => {
                if name == "mounts" {
                    ProcNode::TopMounts
                } else if name == "self" {
                    ProcNode::TopSelf
                } else if let Ok(pid) = name.parse::<u32>()
                    && pid.to_string() == name
                {
                    let _ = self.pid_owner(cred, pid).await?;
                    ProcNode::PidDir(pid)
                } else {
                    let entries = self.provider.top_entries(cred).await?;
                    let found = entries
                        .into_iter()
                        .find(|e| e.name == name)
                        .ok_or(Errno::ENOENT)?;
                    let idx = self.state.borrow_mut().top_names.intern(&found.name)?;
                    let ino = encode_proc_ino(ProcNode::TopDynamic(idx));
                    return Ok(Entry {
                        handle: self.handle(ino),
                        metadata: self.make_meta(
                            found.file_type,
                            found.mode,
                            found.uid,
                            found.gid,
                            0,
                        ),
                    });
                }
            }
            ProcNode::PidDir(pid) => {
                let (_, _, is_local) = self.pid_owner(cred, pid).await?;
                match name {
                    "mountinfo" if is_local => ProcNode::PidMountinfo(pid),
                    "mounts" if is_local => ProcNode::PidMounts(pid),
                    "ns" if is_local => ProcNode::PidNsDir(pid),
                    "root" if is_local => ProcNode::PidRoot(pid),
                    "cwd" if is_local => ProcNode::PidCwd(pid),
                    "fd" if is_local => ProcNode::PidFdDir(pid),
                    "fdinfo" if is_local => ProcNode::PidFdinfoDir(pid),
                    _ => {
                        let entries = self.provider.pid_entries(cred, pid).await?;
                        let found = entries
                            .into_iter()
                            .find(|e| e.name == name)
                            .ok_or(Errno::ENOENT)?;
                        let idx = self.state.borrow_mut().pid_names.intern(&found.name)?;
                        let ino = encode_proc_ino(ProcNode::PidDynamic(pid, idx));
                        return Ok(Entry {
                            handle: self.handle(ino),
                            metadata: self.make_meta(
                                found.file_type,
                                found.mode,
                                found.uid,
                                found.gid,
                                0,
                            ),
                        });
                    }
                }
            }
            ProcNode::PidNsDir(pid) => {
                let (_, _, is_local) = self.pid_owner(cred, pid).await?;
                if !is_local || name != "mnt" {
                    return Err(Errno::ENOENT);
                }
                ProcNode::PidNsMnt(pid)
            }
            ProcNode::PidFdDir(pid) => {
                let bridge = self.bridge().ok_or(Errno::ENOENT)?;
                let info = bridge.process_info(pid).ok_or(Errno::ENOENT)?;
                may_inspect_proc(cred, info.uid)?;
                let fd: u16 = name.parse().map_err(|_| Errno::ENOENT)?;
                if fd.to_string() != name || info.fds.borrow().get(Fd::from(fd)).is_err() {
                    return Err(Errno::ENOENT);
                }
                ProcNode::PidFd(pid, fd)
            }
            ProcNode::PidFdinfoDir(pid) => {
                let bridge = self.bridge().ok_or(Errno::ENOENT)?;
                let info = bridge.process_info(pid).ok_or(Errno::ENOENT)?;
                may_inspect_proc(cred, info.uid)?;
                let fd: u16 = name.parse().map_err(|_| Errno::ENOENT)?;
                if fd.to_string() != name || info.fds.borrow().get(Fd::from(fd)).is_err() {
                    return Err(Errno::ENOENT);
                }
                ProcNode::PidFdinfo(pid, fd)
            }
            _ => return Err(Errno::ENOTDIR),
        };
        let ino = encode_proc_ino(child_node);
        let metadata = self.metadata_for(cred, child_node).await?;
        Ok(Entry {
            handle: self.handle(ino),
            metadata,
        })
    }

    fn reader_root_for(&self, fallback_ns: &Rc<RefCell<MountNamespace>>) -> (PathAnchor, bool) {
        if let Some(bridge) = self.bridge()
            && let Some(caller) = bridge.current_caller()
        {
            return (caller.root, caller.is_at_ns_root);
        }
        (fallback_ns.borrow().root_anchor(), true)
    }

    async fn read_proc_bytes(&self, cred: &Cred, node: ProcNode) -> Result<Vec<u8>> {
        match node {
            ProcNode::PidMountinfo(pid) => {
                let bridge = self.bridge().ok_or(Errno::ENOENT)?;
                let info = bridge.process_info(pid).ok_or(Errno::ENOENT)?;
                let (reader_root, is_at_ns_root) = self.reader_root_for(&info.mnt_ns);
                Ok(
                    format_mountinfo(cred, &info.mnt_ns, &reader_root, is_at_ns_root)
                        .await
                        .into_bytes(),
                )
            }
            ProcNode::PidMounts(pid) => {
                let bridge = self.bridge().ok_or(Errno::ENOENT)?;
                let info = bridge.process_info(pid).ok_or(Errno::ENOENT)?;
                let (reader_root, is_at_ns_root) = self.reader_root_for(&info.mnt_ns);
                Ok(
                    format_mounts(cred, &info.mnt_ns, &reader_root, is_at_ns_root)
                        .await
                        .into_bytes(),
                )
            }
            ProcNode::PidFdinfo(pid, fd) => {
                let bridge = self.bridge().ok_or(Errno::ENOENT)?;
                let info = bridge.process_info(pid).ok_or(Errno::ENOENT)?;
                may_inspect_proc(cred, info.uid)?;
                let (file, cloexec) = {
                    let fds = info.fds.borrow();
                    let f = fds.get(Fd::from(fd))?;
                    let ce = fds.get_cloexec(Fd::from(fd)).unwrap_or(false);
                    (f, ce)
                };
                let mut flags = match file.access() {
                    Access::Read | Access::Exec => abi::O_RDONLY,
                    Access::Write => abi::O_WRONLY,
                    Access::ReadWrite => abi::O_RDWR,
                    Access::Path => abi::O_PATH,
                };
                if file.is_append() {
                    flags |= abi::O_APPEND;
                }
                if cloexec {
                    flags |= 0o2_000_000;
                }
                let mnt_id = file.mount_pin().map_or(0, |p| p.id().0);
                Ok(format!(
                    "pos:\t{}\nflags:\t0{:o}\nmnt_id:\t{}\n",
                    file.position(),
                    flags,
                    mnt_id
                )
                .into_bytes())
            }
            ProcNode::TopDynamic(idx) => {
                let name = self
                    .state
                    .borrow()
                    .top_names
                    .get_name(idx)
                    .ok_or(Errno::ESTALE)?;
                self.provider.read_top(cred, &name).await
            }
            ProcNode::PidDynamic(pid, idx) => {
                let name = self
                    .state
                    .borrow()
                    .pid_names
                    .get_name(idx)
                    .ok_or(Errno::ESTALE)?;
                self.provider.read_pid(cred, pid, &name).await
            }
            _ => Err(Errno::EINVAL),
        }
    }
}

/// Format the `readlink(2)` target of a `PathAnchor` relative to `reader_root`
/// (prepending `"(unreachable)"` when outside `reader_root` or on a detached mount, and
/// appending `" (deleted)"` when unlinked, matching Linux `proc_pid_readlink`).
pub async fn format_proc_link(
    cred: &Cred,
    target_ns: &Rc<RefCell<MountNamespace>>,
    target_pin: &MountPin,
    target_handle: &Handle,
    reader_root: &PathAnchor,
) -> String {
    let deleted = target_pin
        .fs()
        .metadata(cred, target_handle)
        .await
        .is_ok_and(|m| m.nlink == 0);
    let suffix = if deleted { " (deleted)" } else { "" };

    let mut cur_pin = target_pin.clone();
    let mut cur_handle = target_handle.clone();
    let mut segments: Vec<String> = Vec::new();
    let mut unreachable = false;

    loop {
        if cur_pin.id() == reader_root.pin.id() && cur_handle.node == reader_root.handle.node {
            break;
        }
        if cur_handle.node == cur_pin.root_node() {
            if cur_pin.is_detached() {
                unreachable = true;
                break;
            }
            let next_parent = target_ns
                .borrow()
                .entry(cur_pin.id())
                .and_then(|e| e.parent.as_ref())
                .map(|att| (att.parent_pin.clone(), att.mountpoint.clone()));
            match next_parent {
                Some((p_pin, mp_handle)) => {
                    cur_pin = p_pin;
                    cur_handle = mp_handle;
                    continue;
                }
                None => {
                    unreachable = true;
                    break;
                }
            }
        }
        let fs = Rc::clone(cur_pin.fs());
        match fs.parent(cred, &cur_handle).await {
            Ok(Some((parent_entry, name))) => {
                segments.push(name);
                cur_handle = parent_entry.handle;
            }
            Ok(None) => {
                unreachable = true;
                break;
            }
            Err(Errno::ENOENT) => {
                return format!(
                    "{}/(deleted)",
                    if unreachable { "(unreachable)" } else { "" }
                );
            }
            Err(_) => {
                unreachable = true;
                break;
            }
        }
    }

    segments.reverse();
    let base = if segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segments.join("/"))
    };
    let prefix = if unreachable { "(unreachable)" } else { "" };
    format!("{prefix}{base}{suffix}")
}

impl<P: ProcProvider> Filesystem for ProcFs<P> {
    fn id(&self) -> &FsId {
        &self.fs_id
    }

    fn capabilities(&self) -> FsCapabilities {
        profiles::PROC
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
            self.lookup_node(cred, dir_node, name).await
        })
    }

    fn walk<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        names: &'a [String],
    ) -> BoxFuture<'a, Walked> {
        Box::pin(async move {
            let mut cur_node = self.check_handle(dir)?;
            for name in names {
                check_component(name)?;
            }
            let cur_meta = self.metadata_for(cred, cur_node).await?;
            if !cur_meta.is_dir() {
                return Err(Errno::ENOTDIR);
            }
            // Enforce directory search permission on starting `/proc/<pid>/{fd,fdinfo}` dirs.
            match cur_node {
                ProcNode::PidFdDir(pid) | ProcNode::PidFdinfoDir(pid) => {
                    let (uid, _, _) = self.pid_owner(cred, pid).await?;
                    may_inspect_proc(cred, uid)?;
                }
                _ => {}
            }
            let mut entries = Vec::new();
            let mut cur_type = FileType::Dir;
            for (idx, name) in names.iter().enumerate() {
                if idx > 0 {
                    let stop = match cur_type {
                        FileType::Dir => None,
                        FileType::Symlink => Some(Stop::Symlink(idx - 1)),
                        _ => Some(Stop::NotDirectory(idx - 1)),
                    };
                    if stop.is_some() {
                        return Ok(Walked { entries, stop });
                    }
                }
                match self.lookup_node(cred, cur_node, name).await {
                    Ok(entry) => {
                        cur_node = decode_proc_ino(entry.handle.node.ino).ok_or(Errno::ESTALE)?;
                        cur_type = entry.metadata.file_type;
                        entries.push(entry);
                    }
                    Err(Errno::ENOENT) => {
                        return Ok(Walked {
                            entries,
                            stop: Some(Stop::Missing(idx)),
                        });
                    }
                    Err(e) => return Err(e),
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
        cred: &'a Cred,
        dir: &'a Handle,
    ) -> BoxFuture<'a, Option<(Entry, String)>> {
        Box::pin(async move {
            let node = self.check_handle(dir)?;
            let (parent_node, name) = match node {
                ProcNode::Root => return Ok(None),
                ProcNode::PidDir(pid) => (ProcNode::Root, pid.to_string()),
                ProcNode::PidNsDir(pid) => (ProcNode::PidDir(pid), "ns".to_string()),
                ProcNode::PidFdDir(pid) => (ProcNode::PidDir(pid), "fd".to_string()),
                ProcNode::PidFdinfoDir(pid) => (ProcNode::PidDir(pid), "fdinfo".to_string()),
                _ => return Err(Errno::ENOTDIR),
            };
            let ino = encode_proc_ino(parent_node);
            let metadata = self.metadata_for(cred, parent_node).await?;
            Ok(Some((
                Entry {
                    handle: self.handle(ino),
                    metadata,
                },
                name,
            )))
        })
    }

    fn metadata<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Metadata> {
        Box::pin(async move {
            let node = self.check_handle(handle)?;
            self.metadata_for(cred, node).await
        })
    }

    fn setattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        attr: &'a SetAttr,
    ) -> BoxFuture<'a, Metadata> {
        Box::pin(async move {
            let node = self.check_handle(handle)?;
            let meta = self.metadata_for(cred, node).await?;
            if *attr == SetAttr::default() {
                return Ok(meta);
            }
            Err(Errno::EPERM)
        })
    }

    fn read_dir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle) -> BoxFuture<'a, Vec<DirEntry>> {
        Box::pin(async move {
            let node = self.check_handle(dir)?;
            let mut out = Vec::new();
            match node {
                ProcNode::Root => {
                    out.push(DirEntry {
                        name: "mounts".into(),
                        node: NodeId {
                            ino: TOP_MOUNTS_INO,
                            generation: GENERATION,
                        },
                        file_type: FileType::Symlink,
                    });
                    out.push(DirEntry {
                        name: "self".into(),
                        node: NodeId {
                            ino: TOP_SELF_INO,
                            generation: GENERATION,
                        },
                        file_type: FileType::Symlink,
                    });
                    for dyn_entry in self.provider.top_entries(cred).await? {
                        let idx = self.state.borrow_mut().top_names.intern(&dyn_entry.name)?;
                        out.push(DirEntry {
                            name: dyn_entry.name,
                            node: NodeId {
                                ino: encode_proc_ino(ProcNode::TopDynamic(idx)),
                                generation: GENERATION,
                            },
                            file_type: dyn_entry.file_type,
                        });
                    }
                    let mut pids: BTreeSet<u32> = BTreeSet::new();
                    if let Some(bridge) = self.bridge() {
                        pids.extend(bridge.local_pids());
                    }
                    pids.extend(self.provider.list_pids(cred).await?);
                    for pid in pids {
                        out.push(DirEntry {
                            name: pid.to_string(),
                            node: NodeId {
                                ino: encode_proc_ino(ProcNode::PidDir(pid)),
                                generation: GENERATION,
                            },
                            file_type: FileType::Dir,
                        });
                    }
                }
                ProcNode::PidDir(pid) => {
                    let (_, _, is_local) = self.pid_owner(cred, pid).await?;
                    if is_local {
                        for (name, sub, ft) in [
                            ("cwd", ProcNode::PidCwd(pid), FileType::Symlink),
                            ("fd", ProcNode::PidFdDir(pid), FileType::Dir),
                            ("fdinfo", ProcNode::PidFdinfoDir(pid), FileType::Dir),
                            ("mountinfo", ProcNode::PidMountinfo(pid), FileType::File),
                            ("mounts", ProcNode::PidMounts(pid), FileType::File),
                            ("ns", ProcNode::PidNsDir(pid), FileType::Dir),
                            ("root", ProcNode::PidRoot(pid), FileType::Symlink),
                        ] {
                            out.push(DirEntry {
                                name: name.into(),
                                node: NodeId {
                                    ino: encode_proc_ino(sub),
                                    generation: GENERATION,
                                },
                                file_type: ft,
                            });
                        }
                    }
                    for dyn_entry in self.provider.pid_entries(cred, pid).await? {
                        let idx = self.state.borrow_mut().pid_names.intern(&dyn_entry.name)?;
                        out.push(DirEntry {
                            name: dyn_entry.name,
                            node: NodeId {
                                ino: encode_proc_ino(ProcNode::PidDynamic(pid, idx)),
                                generation: GENERATION,
                            },
                            file_type: dyn_entry.file_type,
                        });
                    }
                }
                ProcNode::PidNsDir(pid) => {
                    let (_, _, is_local) = self.pid_owner(cred, pid).await?;
                    if !is_local {
                        return Err(Errno::ENOENT);
                    }
                    out.push(DirEntry {
                        name: "mnt".into(),
                        node: NodeId {
                            ino: encode_proc_ino(ProcNode::PidNsMnt(pid)),
                            generation: GENERATION,
                        },
                        file_type: FileType::Symlink,
                    });
                }
                ProcNode::PidFdDir(pid) => {
                    let bridge = self.bridge().ok_or(Errno::ENOENT)?;
                    let info = bridge.process_info(pid).ok_or(Errno::ENOENT)?;
                    may_inspect_proc(cred, info.uid)?;
                    let fds: Vec<Fd> = info.fds.borrow().fds().collect();
                    for fd in fds {
                        if let Ok(fd16) = u16::try_from(fd) {
                            out.push(DirEntry {
                                name: fd.to_string(),
                                node: NodeId {
                                    ino: encode_proc_ino(ProcNode::PidFd(pid, fd16)),
                                    generation: GENERATION,
                                },
                                file_type: FileType::Symlink,
                            });
                        }
                    }
                }
                ProcNode::PidFdinfoDir(pid) => {
                    let bridge = self.bridge().ok_or(Errno::ENOENT)?;
                    let info = bridge.process_info(pid).ok_or(Errno::ENOENT)?;
                    may_inspect_proc(cred, info.uid)?;
                    let fds: Vec<Fd> = info.fds.borrow().fds().collect();
                    for fd in fds {
                        if let Ok(fd16) = u16::try_from(fd) {
                            out.push(DirEntry {
                                name: fd.to_string(),
                                node: NodeId {
                                    ino: encode_proc_ino(ProcNode::PidFdinfo(pid, fd16)),
                                    generation: GENERATION,
                                },
                                file_type: FileType::File,
                            });
                        }
                    }
                }
                _ => return Err(Errno::ENOTDIR),
            }
            Ok(out)
        })
    }

    fn read_link<'a>(&'a self, cred: &'a Cred, link: &'a Handle) -> BoxFuture<'a, String> {
        Box::pin(async move {
            let node = self.check_handle(link)?;
            match node {
                ProcNode::TopMounts => Ok("self/mounts".to_string()),
                ProcNode::TopSelf => {
                    let caller_pid = self
                        .bridge()
                        .and_then(|b| b.current_caller().map(|c| c.pid))
                        .unwrap_or(1);
                    Ok(caller_pid.to_string())
                }
                ProcNode::PidNsMnt(pid) => {
                    let bridge = self.bridge().ok_or(Errno::ENOENT)?;
                    let info = bridge.process_info(pid).ok_or(Errno::ENOENT)?;
                    may_inspect_proc(cred, info.uid)?;
                    let ns_id = info.mnt_ns.borrow().id().0;
                    Ok(format!("mnt:[{ns_id}]"))
                }
                ProcNode::PidRoot(pid) => {
                    let bridge = self.bridge().ok_or(Errno::ENOENT)?;
                    let info = bridge.process_info(pid).ok_or(Errno::ENOENT)?;
                    may_inspect_proc(cred, info.uid)?;
                    let (reader_root, _) = self.reader_root_for(&info.mnt_ns);
                    Ok(format_proc_link(
                        cred,
                        &info.mnt_ns,
                        &info.root.pin,
                        &info.root.handle,
                        &reader_root,
                    )
                    .await)
                }
                ProcNode::PidCwd(pid) => {
                    let bridge = self.bridge().ok_or(Errno::ENOENT)?;
                    let info = bridge.process_info(pid).ok_or(Errno::ENOENT)?;
                    may_inspect_proc(cred, info.uid)?;
                    let (reader_root, _) = self.reader_root_for(&info.mnt_ns);
                    Ok(format_proc_link(
                        cred,
                        &info.mnt_ns,
                        &info.cwd.pin,
                        &info.cwd.handle,
                        &reader_root,
                    )
                    .await)
                }
                ProcNode::PidFd(pid, fd) => {
                    let bridge = self.bridge().ok_or(Errno::ENOENT)?;
                    let info = bridge.process_info(pid).ok_or(Errno::ENOENT)?;
                    may_inspect_proc(cred, info.uid)?;
                    let file = info
                        .fds
                        .borrow()
                        .get(Fd::from(fd))
                        .map_err(|_| Errno::ENOENT)?;
                    if let Some(ns_file) = file.mount_ns() {
                        let ns_id = ns_file.ns.borrow().id().0;
                        return Ok(format!("mnt:[{ns_id}]"));
                    }
                    if let Some(pin) = file.mount_pin() {
                        let (reader_root, _) = self.reader_root_for(&info.mnt_ns);
                        return Ok(format_proc_link(
                            cred,
                            &info.mnt_ns,
                            pin,
                            file.handle(),
                            &reader_root,
                        )
                        .await);
                    }
                    Ok(format!("anon_inode:[fd:{fd}]"))
                }
                _ => Err(Errno::EINVAL),
            }
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
            match self.lookup_node(cred, dir_node, name).await {
                Ok(entry) => {
                    if options.is_create_new() {
                        return Err(Errno::EEXIST);
                    }
                    if entry.metadata.is_dir() {
                        return Err(Errno::EISDIR);
                    }
                    let open = self.open(cred, &entry.handle, options).await?;
                    Ok((entry, open))
                }
                Err(Errno::ENOENT) => Err(Errno::EACCES),
                Err(e) => Err(e),
            }
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
            let _ = self.check_handle(dir)?;
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
            let _ = self.check_handle(dir)?;
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
            let _ = self.check_handle(dir)?;
            check_component(name)?;
            os_core::inode::check_link_target(target)?;
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
            let _ = self.check_handle(target)?;
            let _ = self.check_handle(dir)?;
            check_component(name)?;
            Err(Errno::EPERM)
        })
    }

    fn unlink<'a>(&'a self, _cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let _ = self.check_handle(dir)?;
            check_component(name)?;
            Err(Errno::EPERM)
        })
    }

    fn rmdir<'a>(&'a self, _cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let _ = self.check_handle(dir)?;
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
            let _ = self.check_handle(from_dir)?;
            let _ = self.check_handle(to_dir)?;
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
            let _ = self.check_handle(handle)?;
            let _ = xattr::space(name)?;
            Err(Errno::EOPNOTSUPP)
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
            Err(Errno::EOPNOTSUPP)
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
            Err(Errno::EOPNOTSUPP)
        })
    }

    fn statfs<'a>(&'a self, _cred: &'a Cred) -> BoxFuture<'a, StatFs> {
        Box::pin(async move {
            Ok(StatFs {
                block_size: 4096,
                blocks: 0,
                blocks_free: 0,
                files: 0,
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
            let mut metadata = self.metadata_for(cred, node).await?;

            if access != Access::Path {
                if metadata.is_symlink() {
                    return Err(Errno::ELOOP);
                }
                if metadata.is_dir() {
                    if access.writes() || options.is_truncate() {
                        return Err(Errno::EISDIR);
                    }
                    if matches!(node, ProcNode::PidFdDir(_) | ProcNode::PidFdinfoDir(_)) {
                        may_inspect_proc(cred, metadata.uid)?;
                    }
                } else {
                    if access.writes() || options.is_truncate() {
                        return Err(Errno::EACCES);
                    }
                    if access == Access::Exec {
                        return Err(Errno::EACCES);
                    }
                }
            }

            let bytes = if metadata.is_file() && access != Access::Path {
                let data = self.read_proc_bytes(cred, node).await?;
                metadata.size = data.len() as u64;
                Some(data)
            } else {
                None
            };

            let mut state = self.state.borrow_mut();
            let id = state.next_open;
            state.next_open += 1;
            state.opens.insert(
                id,
                ProcOpen {
                    ino: handle.node.ino,
                    access,
                    bytes,
                    metadata,
                },
            );
            Ok(OpenRef {
                fs: self.fs_id.clone(),
                id,
                node: handle.node,
                access,
            })
        })
    }

    fn open_metadata<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, Metadata> {
        Box::pin(async move {
            let state = self.state.borrow();
            let rec = state
                .opens
                .get(&open.id)
                .filter(|r| open.fs == self.fs_id && r.ino == open.node.ino)
                .ok_or(Errno::EBADF)?;
            Ok(rec.metadata.clone())
        })
    }

    fn read_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a mut [u8],
        offset: u64,
    ) -> BoxFuture<'a, usize> {
        Box::pin(async move {
            let state = self.state.borrow();
            let rec = state
                .opens
                .get(&open.id)
                .filter(|r| open.fs == self.fs_id && r.ino == open.node.ino)
                .ok_or(Errno::EBADF)?;
            if !rec.access.reads() {
                return Err(Errno::EBADF);
            }
            if rec.metadata.is_dir() {
                return Err(Errno::EISDIR);
            }
            let Some(bytes) = rec.bytes.as_deref() else {
                return Err(Errno::EINVAL);
            };
            if offset > FILE_MAX || buf.len() as u64 > FILE_MAX - offset {
                return Err(Errno::EINVAL);
            }
            if offset >= bytes.len() as u64 || buf.is_empty() {
                return Ok(0);
            }
            let start = offset as usize;
            let len = (bytes.len() - start).min(buf.len());
            buf[..len].copy_from_slice(&bytes[start..start + len]);
            Ok(len)
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
            if !state
                .opens
                .get(&open.id)
                .is_some_and(|r| open.fs == self.fs_id && r.ino == open.node.ino)
            {
                return Err(Errno::EBADF);
            }
            Err(Errno::EBADF)
        })
    }

    fn set_len<'a>(&'a self, open: &'a OpenRef, _size: u64) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let state = self.state.borrow();
            if !state
                .opens
                .get(&open.id)
                .is_some_and(|r| open.fs == self.fs_id && r.ino == open.node.ino)
            {
                return Err(Errno::EBADF);
            }
            Err(Errno::EINVAL)
        })
    }

    fn sync_all<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let state = self.state.borrow();
            let rec = state
                .opens
                .get(&open.id)
                .filter(|r| open.fs == self.fs_id && r.ino == open.node.ino)
                .ok_or(Errno::EBADF)?;
            if rec.access == Access::Path {
                return Err(Errno::EBADF);
            }
            Ok(())
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
            let rec = state
                .opens
                .get(&open.id)
                .filter(|r| open.fs == self.fs_id && r.ino == open.node.ino)
                .ok_or(Errno::EBADF)?;
            if rec.access == Access::Path {
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
            let rec = state
                .opens
                .get(&open.id)
                .filter(|r| open.fs == self.fs_id && r.ino == open.node.ino)
                .ok_or(Errno::EBADF)?;
            if rec.access == Access::Path {
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
            let rec = state
                .opens
                .get(&open.id)
                .filter(|r| open.fs == self.fs_id && r.ino == open.node.ino)
                .ok_or(Errno::EBADF)?;
            if rec.access == Access::Path {
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
                .is_none_or(|r| open.fs != self.fs_id || r.ino != open.node.ino)
            {
                return Err(Errno::EBADF);
            }
            state.opens.remove(&open.id);
            Ok(())
        })
    }
}
