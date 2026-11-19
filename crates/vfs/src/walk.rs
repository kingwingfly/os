//! Component-wise VFS path resolution (`docs/architecture/contract.md` §2.3, §2.7, §4, §5).
//! Enforces `FsContext.root` (`chroot`) clamping on `..` and absolute symlinks, mount crossings,
//! `MAXSYMLINKS`, `MS_NOSYMFOLLOW`, sticky-directory `may_follow_link`, trailing-slash directory
//! rules, user-mount `owner_uid` ceilings, and `/proc` magic links.

use crate::context::{FsContext, PathAnchor, SharedFdTable};
use crate::descriptions::may_follow_link;
use crate::mount::{FsType, MountPin};
use crate::namespace::MountNamespace;
use crate::procfs::{self, ProcBridge, ProcNode};
use crate::{
    Cred, Entry, Fd, FdTable, FileRef, FileType, Handle, Metadata, Result, Stop, Timespec,
    check_component,
};
use abi::Errno;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::ops::{BitOr, BitOrAssign};
use std::rc::Rc;

/// Read-only descriptor lookup abstraction so [`walk`] and [`walk_parent`] borrow [`FdTable`] or
/// [`SharedFdTable`] without deep-cloning descriptor tables on every syscall.
pub trait FdLookup {
    fn get_fd(&self, fd: Fd) -> Result<FileRef>;
}

impl FdLookup for FdTable {
    fn get_fd(&self, fd: Fd) -> Result<FileRef> {
        self.get(fd)
    }
}

impl FdLookup for SharedFdTable {
    fn get_fd(&self, fd: Fd) -> Result<FileRef> {
        self.borrow().get(fd)
    }
}

impl<T: FdLookup + ?Sized> FdLookup for &T {
    fn get_fd(&self, fd: Fd) -> Result<FileRef> {
        (**self).get_fd(fd)
    }
}

/// Starting anchor for a path walk (`AT_FDCWD`, `OS_FD_ROOT`, `OS_FD_CWD`, or open `dirfd`).
#[derive(Clone, Debug)]
pub enum StartAnchor {
    /// Default (`AT_FDCWD` / `OS_FD_CWD`): `/...` -> `ctx.root`, relative -> `ctx.cwd`.
    AtFdCwd,
    /// Explicit root pseudo-fd (`OS_FD_ROOT`): resolves relative paths from `ctx.root`.
    Root,
    /// Open directory descriptor (`0..FD_MAX`): `/...` -> `ctx.root`, relative -> `fd`.
    DirFd(Fd),
    /// Direct internal [`PathAnchor`].
    Anchor(PathAnchor),
}

impl StartAnchor {
    /// Convert a WASI / client-kernel `anchor_kfd` (`OS_FD_ROOT`, `OS_FD_CWD`, `AT_FDCWD = -2`
    /// or `-100`, or `0..FD_MAX`) into a [`StartAnchor`].
    pub fn from_kfd(kfd: i32) -> Result<Self> {
        if kfd == abi::OS_FD_ROOT {
            Ok(Self::Root)
        } else if kfd == abi::OS_FD_CWD || kfd == -2 || kfd == -100 {
            Ok(Self::AtFdCwd)
        } else if kfd >= 0 {
            Ok(Self::DirFd(kfd as Fd))
        } else {
            Err(Errno::EBADF)
        }
    }
}

/// Bitmask flags controlling component-wise [`walk`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WalkFlags(u32);

impl WalkFlags {
    pub const EMPTY: Self = Self(0);
    /// Follow a symlink on the final path component (`stat`, `open` without `O_NOFOLLOW`, `chdir`, `chroot`).
    pub const FOLLOW_LAST: Self = Self(1 << 0);
    /// Require the resolved target to be a directory (`chdir`, `chroot`, `O_DIRECTORY`).
    pub const MUST_BE_DIR: Self = Self(1 << 1);
    /// Return [`WalkResult::MissingLast`] when the final component is absent (`open(O_CREAT)`).
    pub const ALLOW_MISSING_LAST: Self = Self(1 << 2);
    /// `umount2` target resolution: on the final component, descend to the topmost mount without
    /// running `guard_enter` on it (so root & owner can unmount `Revoked`, `Lost`, and user mounts),
    /// and if `!FOLLOW_LAST` (`UMOUNT_NOFOLLOW`), fail with `EINVAL` on a terminal symlink.
    pub const UMOUNT_FINAL: Self = Self(1 << 3);

    pub const fn empty() -> Self {
        Self::EMPTY
    }

    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl BitOr for WalkFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for WalkFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Special kernel object resolved by a magic `/proc` link.
pub enum MagicResolved {
    OpenFile(FileRef),
    MountNs {
        instance_id: String,
        ns: Rc<RefCell<MountNamespace>>,
    },
}

pub enum WalkResult {
    Found {
        pin: MountPin,
        entry: Entry,
        magic: Option<MagicResolved>,
        /// Parent `(pin, dir_handle, component_name)` of the final step when reached by a plain name.
        last_step: Option<(MountPin, Handle, String)>,
    },
    MissingLast {
        parent_pin: MountPin,
        parent: Entry,
        name: String,
        trailing_slash: bool,
    },
}

pub struct ParentTarget {
    pub parent_pin: MountPin,
    pub parent: Entry,
    pub name: String,
    pub trailing_slash: bool,
}

pub enum ParentResolution {
    Root {
        pin: MountPin,
        entry: Entry,
    },
    DotOrDotDot {
        parent_pin: MountPin,
        parent: Entry,
        dot: String,
        trailing_slash: bool,
    },
    Child(ParentTarget),
}

fn synthetic_mount_root_meta() -> Metadata {
    Metadata {
        file_type: FileType::Dir,
        mode: 0o755,
        nlink: 2,
        uid: 0,
        gid: 0,
        size: 4096,
        atime: Timespec::default(),
        mtime: Timespec::default(),
        ctime: Timespec::default(),
        rdev: None,
        acl: false,
    }
}

/// Verify `cred` has `X_OK` (`EXEC`) search permission on directory `(pin, dir_handle)`.
pub async fn ensure_searchable(
    cred: &Cred,
    pin: &MountPin,
    dir_handle: &Handle,
    cached: &mut bool,
) -> Result<()> {
    if !*cached {
        let probe = ["_".to_string()];
        pin.guard_op(cred, false, false, pin.fs().walk(cred, dir_handle, &probe))
            .await?;
        *cached = true;
    }
    Ok(())
}

async fn resolve_initial_anchor(
    cred: &Cred,
    ctx: &FsContext,
    fds: &impl FdLookup,
    anchor: &StartAnchor,
    force_root: bool,
) -> Result<(MountPin, Handle, Option<Metadata>)> {
    if force_root {
        return Ok((ctx.root.pin.clone(), ctx.root.handle.clone(), None));
    }
    match anchor {
        StartAnchor::Root => Ok((ctx.root.pin.clone(), ctx.root.handle.clone(), None)),
        StartAnchor::AtFdCwd => Ok((ctx.cwd.pin.clone(), ctx.cwd.handle.clone(), None)),
        StartAnchor::Anchor(a) => Ok((a.pin.clone(), a.handle.clone(), None)),
        StartAnchor::DirFd(fd) => {
            let file = fds.get_fd(*fd)?;
            if file.mount_ns().is_some() {
                return Err(Errno::ENOTDIR);
            }
            let pin = file.mount_pin().ok_or(Errno::EBADF)?.clone();
            let meta = file.metadata_as(cred).await?;
            if !meta.is_dir() {
                return Err(Errno::ENOTDIR);
            }
            Ok((pin, file.handle().clone(), Some(meta)))
        }
    }
}

fn ns_for_pin(
    default_ns: &Rc<RefCell<MountNamespace>>,
    proc_bridge: Option<&dyn ProcBridge>,
    pin: &MountPin,
) -> Rc<RefCell<MountNamespace>> {
    if default_ns.borrow().id() == pin.ns_id() {
        return Rc::clone(default_ns);
    }
    if let Some(b) = proc_bridge
        && let Some(found) = b.namespace_by_id(pin.ns_id())
    {
        return found;
    }
    Rc::clone(default_ns)
}

fn can_batch_on_pin(cur_ns: &MountNamespace, cur_pin: &MountPin) -> bool {
    if cur_pin.fstype() == FsType::Proc {
        return false;
    }
    if matches!(
        cur_pin.fstype(),
        FsType::HostFs | FsType::HelperFs | FsType::ShareFs
    ) {
        let has_children = if cur_pin.is_detached() {
            cur_pin.detached_has_children_on(cur_pin.id())
        } else {
            cur_ns.has_children_on(cur_pin.id())
        };
        if has_children {
            return false;
        }
    }
    true
}

fn seg_may_be_mountpoint(
    cur_ns: &MountNamespace,
    cur_pin: &MountPin,
    cur_dir_node: crate::NodeId,
    name: &str,
) -> bool {
    if cur_pin.is_detached() {
        cur_pin.detached_dir_has_mountpoint(cur_pin.id(), cur_dir_node, name)
            || cur_pin.detached_has_children_on(cur_pin.id())
    } else {
        cur_ns.may_be_mountpoint_name(cur_pin.id(), name)
    }
}

/// Component-wise path resolution against `(ns, ctx, fds)`.
#[allow(clippy::too_many_arguments)]
pub async fn walk(
    cred: &Cred,
    ns: &Rc<RefCell<MountNamespace>>,
    ctx: &FsContext,
    fds: &impl FdLookup,
    proc_bridge: Option<&dyn ProcBridge>,
    anchor: &StartAnchor,
    path: &str,
    flags: WalkFlags,
) -> Result<WalkResult> {
    if path.is_empty() {
        return Err(Errno::ENOENT);
    }
    if path.contains('\0') {
        return Err(Errno::EINVAL);
    }
    if path.len() > abi::PATH_MAX {
        return Err(Errno::ENAMETOOLONG);
    }

    let mut queue: VecDeque<String> = VecDeque::new();
    for seg in path.split('/').filter(|s| !s.is_empty()) {
        if seg.len() > abi::NAME_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        queue.push_back(seg.to_string());
    }

    let must_be_dir = flags.contains(WalkFlags::MUST_BE_DIR);
    let mut has_trailing_slash = path.ends_with('/') && !queue.is_empty();

    let (mut cur_pin, mut cur_handle, mut cur_meta) =
        resolve_initial_anchor(cred, ctx, fds, anchor, path.starts_with('/')).await?;
    let mut cur_ns = ns_for_pin(ns, proc_bridge, &cur_pin);
    let mut cur_searchable = false;
    let mut last_step: Option<(MountPin, Handle, String)> = None;
    let mut symlinks_followed: usize = 0;

    if !(queue.is_empty() && flags.contains(WalkFlags::UMOUNT_FINAL)) {
        cur_pin.guard_enter(cred)?;
    }

    'walk: loop {
        match queue.front().map(String::as_str) {
            None => {
                if flags.contains(WalkFlags::UMOUNT_FINAL) {
                    let meta = cur_meta.unwrap_or_else(synthetic_mount_root_meta);
                    return Ok(WalkResult::Found {
                        pin: cur_pin,
                        entry: Entry {
                            handle: cur_handle,
                            metadata: meta,
                        },
                        magic: None,
                        last_step,
                    });
                }
                cur_pin.guard_enter(cred)?;
                let meta = match cur_meta {
                    Some(m) => m,
                    None => {
                        cur_pin
                            .guard_op(cred, false, false, cur_pin.fs().metadata(cred, &cur_handle))
                            .await?
                    }
                };
                if (has_trailing_slash || must_be_dir) && !meta.is_dir() {
                    return Err(Errno::ENOTDIR);
                }
                return Ok(WalkResult::Found {
                    pin: cur_pin,
                    entry: Entry {
                        handle: cur_handle,
                        metadata: meta,
                    },
                    magic: None,
                    last_step,
                });
            }
            Some(".") => {
                ensure_searchable(cred, &cur_pin, &cur_handle, &mut cur_searchable).await?;
                queue.pop_front();
                last_step = None;
                if queue.is_empty() {
                    has_trailing_slash = true;
                }
                continue 'walk;
            }
            Some("..") => {
                ensure_searchable(cred, &cur_pin, &cur_handle, &mut cur_searchable).await?;
                queue.pop_front();
                last_step = None;

                // 1. Process `chroot` boundary check FIRST (before mount-root unwind!).
                if ctx.root.same_location(&cur_pin, cur_handle.node) {
                    if queue.is_empty() {
                        has_trailing_slash = true;
                    }
                    continue 'walk;
                }

                // 2. Mount-root unwind loop across stacked/parent mounts.
                let mut clamped = false;
                while cur_handle.node == cur_pin.root_node() {
                    if ctx.root.same_location(&cur_pin, cur_handle.node) {
                        clamped = true;
                        break;
                    }
                    if cur_pin.is_detached() {
                        match cur_pin.detached_mount_parent(cur_pin.id()) {
                            Some((p_pin, mp_handle, _, _)) => {
                                cur_pin = p_pin;
                                cur_handle = mp_handle;
                                cur_meta = None;
                                cur_searchable = false;
                                continue;
                            }
                            None => {
                                clamped = true;
                                break;
                            }
                        }
                    }
                    if cur_ns.borrow().id() != cur_pin.ns_id() {
                        cur_ns = ns_for_pin(ns, proc_bridge, &cur_pin);
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
                            cur_meta = None;
                            cur_searchable = false;
                        }
                        None => {
                            clamped = true;
                            break;
                        }
                    }
                }
                if !clamped && ctx.root.same_location(&cur_pin, cur_handle.node) {
                    clamped = true;
                }

                // 3. Intra-filesystem parent step.
                if !clamped {
                    cur_pin.guard_enter(cred)?;
                    if let Some((parent_entry, _)) = cur_pin
                        .guard_op(cred, false, false, cur_pin.fs().parent(cred, &cur_handle))
                        .await?
                    {
                        cur_handle = parent_entry.handle;
                        cur_meta = Some(parent_entry.metadata);
                        cur_searchable = false;
                    }
                }

                if queue.is_empty() {
                    has_trailing_slash = true;
                }
                continue 'walk;
            }
            Some(_) => {}
        }

        // Plain component(s): batch safely whenever names cannot hit a mountpoint or `/proc` link.
        let first = queue.pop_front().expect("checked non-empty");
        check_component(&first)?;
        let mut run = vec![first];
        {
            let ns_ref = cur_ns.borrow();
            if can_batch_on_pin(&ns_ref, &cur_pin)
                && !seg_may_be_mountpoint(&ns_ref, &cur_pin, cur_handle.node, &run[0])
            {
                while let Some(next) = queue.front() {
                    if next == "." || next == ".." {
                        break;
                    }
                    check_component(next)?;
                    if seg_may_be_mountpoint(&ns_ref, &cur_pin, cur_handle.node, next) {
                        break;
                    }
                    run.push(queue.pop_front().expect("checked front"));
                }
            }
        }

        let walked = cur_pin
            .guard_op(
                cred,
                false,
                false,
                cur_pin.fs().walk(cred, &cur_handle, &run),
            )
            .await?;
        cur_searchable = true;
        let walked_len = walked.entries.len();

        for (idx, entry) in walked.entries.into_iter().enumerate() {
            let seg_name = &run[idx];
            let is_last = idx + 1 == run.len() && queue.is_empty();

            // A. Check stacked child mounts on `(cur_pin.id(), entry.handle.node)`.
            let crossed = if cur_pin.is_detached() {
                cur_pin.detached_topmost_at(cur_pin.id(), entry.handle.node)
            } else {
                if cur_ns.borrow().id() != cur_pin.ns_id() {
                    cur_ns = ns_for_pin(ns, proc_bridge, &cur_pin);
                }
                cur_ns
                    .borrow()
                    .top_mount_at(cur_pin.id(), entry.handle.node)
                    .map(|(slot, root)| (slot.pin(), root))
            };
            if let Some((top_pin, top_root)) = crossed {
                let step_info = Some((cur_pin.clone(), cur_handle.clone(), seg_name.clone()));
                if is_last && flags.contains(WalkFlags::UMOUNT_FINAL) {
                    return Ok(WalkResult::Found {
                        pin: top_pin,
                        entry: Entry {
                            handle: top_root,
                            metadata: synthetic_mount_root_meta(),
                        },
                        magic: None,
                        last_step: step_info,
                    });
                }
                top_pin.guard_enter(cred)?;
                let top_meta = top_pin
                    .guard_op(cred, false, false, top_pin.fs().metadata(cred, &top_root))
                    .await?;
                for rest in run[idx + 1..].iter().rev() {
                    queue.push_front(rest.clone());
                }
                cur_pin = top_pin;
                cur_handle = top_root;
                cur_meta = Some(top_meta);
                cur_searchable = false;
                last_step = step_info;
                if queue.is_empty() {
                    let meta = cur_meta.expect("populated");
                    if (has_trailing_slash || must_be_dir) && !meta.is_dir() {
                        return Err(Errno::ENOTDIR);
                    }
                    return Ok(WalkResult::Found {
                        pin: cur_pin,
                        entry: Entry {
                            handle: cur_handle,
                            metadata: meta,
                        },
                        magic: None,
                        last_step,
                    });
                }
                continue 'walk;
            }

            // B. Magic `/proc` links (`root`, `cwd`, `ns/mnt`, `fd/<n>`).
            if cur_pin.fstype() == FsType::Proc
                && let Some(proc_node) = procfs::decode_proc_ino(entry.handle.node.ino)
                && matches!(
                    proc_node,
                    ProcNode::PidRoot(_)
                        | ProcNode::PidCwd(_)
                        | ProcNode::PidNsMnt(_)
                        | ProcNode::PidFd(_, _)
                )
            {
                if is_last
                    && flags.contains(WalkFlags::UMOUNT_FINAL)
                    && !flags.contains(WalkFlags::FOLLOW_LAST)
                {
                    return Err(Errno::EINVAL);
                }
                let should_follow =
                    !is_last || flags.contains(WalkFlags::FOLLOW_LAST) || has_trailing_slash;
                if should_follow {
                    if cur_pin.effective_flags().nosymfollow {
                        return Err(Errno::ELOOP);
                    }
                    symlinks_followed += 1;
                    if symlinks_followed > abi::MAXSYMLINKS {
                        return Err(Errno::ELOOP);
                    }
                    let bridge = proc_bridge.ok_or(Errno::ENOENT)?;
                    match proc_node {
                        ProcNode::PidRoot(pid) | ProcNode::PidCwd(pid) => {
                            let info = bridge.process_info(pid).ok_or(Errno::ENOENT)?;
                            procfs::may_inspect_proc(cred, info.uid)?;
                            let target_anchor = if matches!(proc_node, ProcNode::PidRoot(_)) {
                                info.root
                            } else {
                                info.cwd
                            };
                            if !(is_last
                                && queue.is_empty()
                                && flags.contains(WalkFlags::UMOUNT_FINAL))
                            {
                                target_anchor.pin.guard_enter(cred)?;
                            }
                            for rest in run[idx + 1..].iter().rev() {
                                queue.push_front(rest.clone());
                            }
                            cur_pin = target_anchor.pin;
                            cur_ns = ns_for_pin(&info.mnt_ns, proc_bridge, &cur_pin);
                            cur_handle = target_anchor.handle;
                            cur_meta = None;
                            cur_searchable = false;
                            last_step = None;
                            continue 'walk;
                        }
                        ProcNode::PidNsMnt(pid) => {
                            if !is_last || has_trailing_slash || must_be_dir {
                                return Err(Errno::ENOTDIR);
                            }
                            let info = bridge.process_info(pid).ok_or(Errno::ENOENT)?;
                            procfs::may_inspect_proc(cred, info.uid)?;
                            return Ok(WalkResult::Found {
                                pin: cur_pin,
                                entry,
                                magic: Some(MagicResolved::MountNs {
                                    instance_id: bridge.instance_id(),
                                    ns: info.mnt_ns,
                                }),
                                last_step: None,
                            });
                        }
                        ProcNode::PidFd(pid, fd) => {
                            let info = bridge.process_info(pid).ok_or(Errno::ENOENT)?;
                            procfs::may_inspect_proc(cred, info.uid)?;
                            let file = info
                                .fds
                                .borrow()
                                .get(Fd::from(fd))
                                .map_err(|_| Errno::ENOENT)?;
                            if !is_last || has_trailing_slash {
                                if file.mount_ns().is_some() {
                                    return Err(Errno::ENOTDIR);
                                }
                                let f_meta = file.metadata_as(cred).await?;
                                if !f_meta.is_dir() {
                                    return Err(Errno::ENOTDIR);
                                }
                                let f_pin = file.mount_pin().ok_or(Errno::ENOENT)?.clone();
                                f_pin.guard_enter(cred)?;
                                for rest in run[idx + 1..].iter().rev() {
                                    queue.push_front(rest.clone());
                                }
                                cur_pin = f_pin;
                                cur_ns = ns_for_pin(&info.mnt_ns, proc_bridge, &cur_pin);
                                cur_handle = file.handle().clone();
                                cur_meta = Some(f_meta);
                                cur_searchable = false;
                                last_step = None;
                                continue 'walk;
                            }
                            if let Some(ns_f) = file.mount_ns() {
                                if must_be_dir {
                                    return Err(Errno::ENOTDIR);
                                }
                                return Ok(WalkResult::Found {
                                    pin: cur_pin,
                                    entry,
                                    magic: Some(MagicResolved::MountNs {
                                        instance_id: ns_f.instance_id.clone(),
                                        ns: Rc::clone(&ns_f.ns),
                                    }),
                                    last_step: None,
                                });
                            }
                            let f_pin =
                                file.mount_pin().cloned().unwrap_or_else(|| cur_pin.clone());
                            f_pin.guard_enter(cred)?;
                            let f_meta = file.metadata_as(cred).await?;
                            if must_be_dir && !f_meta.is_dir() {
                                return Err(Errno::ENOTDIR);
                            }
                            return Ok(WalkResult::Found {
                                pin: f_pin,
                                entry: Entry {
                                    handle: file.handle().clone(),
                                    metadata: f_meta,
                                },
                                magic: Some(MagicResolved::OpenFile(file)),
                                last_step: None,
                            });
                        }
                        _ => unreachable!(),
                    }
                }
            }

            // C. Ordinary symlink resolution.
            if entry.metadata.is_symlink() {
                if is_last
                    && flags.contains(WalkFlags::UMOUNT_FINAL)
                    && !flags.contains(WalkFlags::FOLLOW_LAST)
                {
                    return Err(Errno::EINVAL);
                }
                if !is_last || flags.contains(WalkFlags::FOLLOW_LAST) || has_trailing_slash {
                    let parent_meta = match &cur_meta {
                        Some(m) => m.clone(),
                        None => {
                            let m = cur_pin
                                .guard_op(
                                    cred,
                                    false,
                                    false,
                                    cur_pin.fs().metadata(cred, &cur_handle),
                                )
                                .await?;
                            cur_meta = Some(m.clone());
                            m
                        }
                    };
                    if !may_follow_link(cred, &parent_meta, &entry.metadata) {
                        return Err(Errno::EACCES);
                    }
                    if cur_pin.effective_flags().nosymfollow {
                        return Err(Errno::ELOOP);
                    }
                    symlinks_followed += 1;
                    if symlinks_followed > abi::MAXSYMLINKS {
                        return Err(Errno::ELOOP);
                    }
                    let target = cur_pin
                        .guard_op(
                            cred,
                            false,
                            false,
                            cur_pin.fs().read_link(cred, &entry.handle),
                        )
                        .await?;
                    if target.is_empty() {
                        return Err(Errno::ENOENT);
                    }
                    if target.contains('\0') {
                        return Err(Errno::EINVAL);
                    }
                    if target.len() > abi::PATH_MAX {
                        return Err(Errno::ENAMETOOLONG);
                    }
                    for rest in run[idx + 1..].iter().rev() {
                        queue.push_front(rest.clone());
                    }
                    let mut target_segs = Vec::new();
                    for part in target.split('/').filter(|p| !p.is_empty()) {
                        if part.len() > abi::NAME_MAX {
                            return Err(Errno::ENAMETOOLONG);
                        }
                        target_segs.push(part.to_string());
                    }
                    for part in target_segs.into_iter().rev() {
                        queue.push_front(part);
                    }
                    if is_last
                        && (target.ends_with('/')
                            || target == "."
                            || target == ".."
                            || target.ends_with("/.")
                            || target.ends_with("/.."))
                    {
                        has_trailing_slash = true;
                    }
                    // Absolute symlinks ALWAYS anchor at `ctx.root`, even when `walk` started
                    // from an outside-`chroot` `cwd` or retained `dirfd`!
                    if target.starts_with('/') {
                        cur_pin = ctx.root.pin.clone();
                        cur_ns = ns_for_pin(ns, proc_bridge, &cur_pin);
                        cur_handle = ctx.root.handle.clone();
                        cur_meta = None;
                        cur_searchable = false;
                        last_step = None;
                        if !(queue.is_empty() && flags.contains(WalkFlags::UMOUNT_FINAL)) {
                            cur_pin.guard_enter(cred)?;
                        }
                    }
                    continue 'walk;
                }
            }

            // D. Terminal component.
            if is_last {
                if (has_trailing_slash || must_be_dir) && !entry.metadata.is_dir() {
                    return Err(Errno::ENOTDIR);
                }
                return Ok(WalkResult::Found {
                    pin: cur_pin.clone(),
                    entry,
                    magic: None,
                    last_step: Some((cur_pin, cur_handle, seg_name.clone())),
                });
            }

            // E. Intermediate directory advance.
            if !entry.metadata.is_dir() {
                return Err(Errno::ENOTDIR);
            }
            last_step = Some((cur_pin.clone(), cur_handle, seg_name.clone()));
            cur_handle = entry.handle;
            cur_meta = Some(entry.metadata);
            cur_searchable = idx + 1 < walked_len;
        }

        match walked.stop {
            Some(Stop::Missing(miss_idx)) => {
                if miss_idx + 1 == run.len()
                    && queue.is_empty()
                    && flags.contains(WalkFlags::ALLOW_MISSING_LAST)
                {
                    let parent_meta = match cur_meta {
                        Some(m) => m,
                        None => {
                            cur_pin
                                .guard_op(
                                    cred,
                                    false,
                                    false,
                                    cur_pin.fs().metadata(cred, &cur_handle),
                                )
                                .await?
                        }
                    };
                    if !parent_meta.is_dir() {
                        return Err(Errno::ENOTDIR);
                    }
                    return Ok(WalkResult::MissingLast {
                        parent_pin: cur_pin,
                        parent: Entry {
                            handle: cur_handle,
                            metadata: parent_meta,
                        },
                        name: run[miss_idx].clone(),
                        trailing_slash: has_trailing_slash,
                    });
                }
                return Err(Errno::ENOENT);
            }
            Some(Stop::NotDirectory(_)) => return Err(Errno::ENOTDIR),
            Some(Stop::Symlink(_)) | None => {}
        }
    }
}

/// Resolve the parent directory and final component name of `path` for directory-mutating
/// operations (`mkdir`, `mknod`, `symlink`, `unlink`, `rmdir`, `rename`, `link`).
pub async fn walk_parent(
    cred: &Cred,
    ns: &Rc<RefCell<MountNamespace>>,
    ctx: &FsContext,
    fds: &impl FdLookup,
    proc_bridge: Option<&dyn ProcBridge>,
    anchor: &StartAnchor,
    path: &str,
) -> Result<ParentResolution> {
    if path.is_empty() {
        return Err(Errno::ENOENT);
    }
    if path.contains('\0') {
        return Err(Errno::EINVAL);
    }
    if path.len() > abi::PATH_MAX {
        return Err(Errno::ENAMETOOLONG);
    }

    let trailing_slash = path.ends_with('/');
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        let pin = ctx.root.pin.clone();
        pin.guard_enter(cred)?;
        let meta = pin
            .guard_op(
                cred,
                false,
                false,
                pin.fs().metadata(cred, &ctx.root.handle),
            )
            .await?;
        return Ok(ParentResolution::Root {
            pin,
            entry: Entry {
                handle: ctx.root.handle.clone(),
                metadata: meta,
            },
        });
    }

    let (parent_pin, parent_entry, last_name) = match trimmed.rsplit_once('/') {
        Some((prefix, last)) => {
            if last.len() > abi::NAME_MAX {
                return Err(Errno::ENAMETOOLONG);
            }
            let dir_path = if prefix.is_empty() { "/" } else { prefix };
            let resolved = walk(
                cred,
                ns,
                ctx,
                fds,
                proc_bridge,
                anchor,
                dir_path,
                WalkFlags::FOLLOW_LAST | WalkFlags::MUST_BE_DIR,
            )
            .await?;
            match resolved {
                WalkResult::Found { pin, entry, .. } => (pin, entry, last.to_string()),
                WalkResult::MissingLast { .. } => return Err(Errno::ENOENT),
            }
        }
        None => {
            if trimmed.len() > abi::NAME_MAX {
                return Err(Errno::ENAMETOOLONG);
            }
            let (pin, handle, maybe_meta) =
                resolve_initial_anchor(cred, ctx, fds, anchor, false).await?;
            pin.guard_enter(cred)?;
            let meta = match maybe_meta {
                Some(m) => m,
                None => {
                    pin.guard_op(cred, false, false, pin.fs().metadata(cred, &handle))
                        .await?
                }
            };
            if !meta.is_dir() {
                return Err(Errno::ENOTDIR);
            }
            (
                pin,
                Entry {
                    handle,
                    metadata: meta,
                },
                trimmed.to_string(),
            )
        }
    };

    if last_name == "." || last_name == ".." {
        let mut searchable = false;
        ensure_searchable(cred, &parent_pin, &parent_entry.handle, &mut searchable).await?;
        return Ok(ParentResolution::DotOrDotDot {
            parent_pin,
            parent: parent_entry,
            dot: last_name,
            trailing_slash,
        });
    }

    check_component(&last_name)?;
    Ok(ParentResolution::Child(ParentTarget {
        parent_pin,
        parent: parent_entry,
        name: last_name,
        trailing_slash,
    }))
}
