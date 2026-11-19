//! Mount, provider lifecycle, and O(1) pin-counted mount-slot primitives
//! (`docs/architecture/contract.md` §2.5, §2.7, §4, §5).

use crate::{Cred, FileRef, Filesystem, FsId, Handle, NodeId, Result};
use abi::Errno;
use abi::contract::{fs_magic, mount_flags, statfs_flags};
use serde::{Deserialize, Serialize};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::{Future, poll_fn};
use std::rc::Rc;
use std::sync::{LazyLock, Mutex};
use std::task::{Poll, Waker};

thread_local! {
    static ACTIVE_MOUNT_FLAGS: Cell<Option<MountFlags>> = const { Cell::new(None) };
}

/// Returns the effective [`MountFlags`] of the mount currently being polled inside
/// [`MountSlot::guard_op`], or `None` for standalone unmounted driver calls.
pub fn active_mount_flags() -> Option<MountFlags> {
    ACTIVE_MOUNT_FLAGS.with(|c| c.get())
}

struct MountFlagsPollGuard {
    prev: Option<MountFlags>,
}

impl MountFlagsPollGuard {
    fn enter(flags: MountFlags) -> Self {
        let prev = ACTIVE_MOUNT_FLAGS.with(|c| c.replace(Some(flags)));
        Self { prev }
    }
}

impl Drop for MountFlagsPollGuard {
    fn drop(&mut self) {
        ACTIVE_MOUNT_FLAGS.with(|c| c.set(self.prev));
    }
}

/// Collision-free monotonic `0:minor` device number per distinct [`FsId`].
pub fn minor_for_fs_id(fs_id: &FsId) -> u64 {
    static MINORS: LazyLock<Mutex<(HashMap<String, u64>, u64)>> =
        LazyLock::new(|| Mutex::new((HashMap::new(), 1)));
    let mut guard = MINORS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(&m) = guard.0.get(&fs_id.0) {
        return m;
    }
    let m = guard.1;
    guard.1 = guard.1.saturating_add(1);
    guard.0.insert(fs_id.0.clone(), m);
    m
}

/// Kernel-monotonic mount identifier across the OS instance (never recycled, starts at 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct MountId(pub u64);

/// Kernel-monotonic mount namespace identifier across the OS instance (never recycled, starts at 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NamespaceId(pub u64);

/// Exact 10 filesystem types defined by `contract.md` §5.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FsType {
    Cloud,
    Opfs,
    HostFs,
    HelperFs,
    ShareFs,
    Image,
    TmpFs,
    Proc,
    DevTmpFs,
    DevPts,
}

impl FsType {
    /// Contract §5: unknown types (explicitly including `"sysfs"`) return `Err(Errno::ENODEV)`.
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "cloud" => Ok(Self::Cloud),
            "opfs" => Ok(Self::Opfs),
            "hostfs" => Ok(Self::HostFs),
            "helperfs" => Ok(Self::HelperFs),
            "sharefs" => Ok(Self::ShareFs),
            "image" => Ok(Self::Image),
            "tmpfs" => Ok(Self::TmpFs),
            "proc" => Ok(Self::Proc),
            "devtmpfs" => Ok(Self::DevTmpFs),
            "devpts" => Ok(Self::DevPts),
            _ => Err(Errno::ENODEV),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cloud => "cloud",
            Self::Opfs => "opfs",
            Self::HostFs => "hostfs",
            Self::HelperFs => "helperfs",
            Self::ShareFs => "sharefs",
            Self::Image => "image",
            Self::TmpFs => "tmpfs",
            Self::Proc => "proc",
            Self::DevTmpFs => "devtmpfs",
            Self::DevPts => "devpts",
        }
    }

    pub const fn magic(self) -> u64 {
        match self {
            Self::Cloud => fs_magic::OS_CLOUD_MAGIC,
            Self::Opfs | Self::HostFs | Self::HelperFs | Self::ShareFs => {
                fs_magic::FUSE_SUPER_MAGIC
            }
            Self::Image => fs_magic::SQUASHFS_MAGIC,
            Self::TmpFs => fs_magic::TMPFS_MAGIC,
            Self::Proc => fs_magic::PROC_SUPER_MAGIC,
            Self::DevTmpFs => fs_magic::DEVTMPFS_MAGIC,
            Self::DevPts => fs_magic::DEVPTS_SUPER_MAGIC,
        }
    }

    pub const fn is_user_mountable(self) -> bool {
        matches!(
            self,
            Self::Opfs | Self::HostFs | Self::HelperFs | Self::ShareFs | Self::Image
        )
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AtimeMode {
    #[default]
    Relatime,
    Noatime,
    Strictatime,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MountFlags {
    pub rdonly: bool,
    pub nosuid: bool,
    pub nodev: bool,
    pub noexec: bool,
    pub synchronous: bool,
    pub dirsync: bool,
    pub nosymfollow: bool,
    pub nodiratime: bool,
    pub lazytime: bool,
    pub atime: AtimeMode,
}

impl MountFlags {
    pub fn from_accepted(bits: u64) -> Self {
        use mount_flags::*;
        let atime = if bits & MS_NOATIME != 0 {
            AtimeMode::Noatime
        } else if bits & MS_STRICTATIME != 0 {
            AtimeMode::Strictatime
        } else {
            AtimeMode::Relatime
        };
        Self {
            rdonly: bits & MS_RDONLY != 0,
            nosuid: bits & MS_NOSUID != 0,
            nodev: bits & MS_NODEV != 0,
            noexec: bits & MS_NOEXEC != 0,
            synchronous: bits & MS_SYNCHRONOUS != 0,
            dirsync: bits & MS_DIRSYNC != 0,
            nosymfollow: bits & MS_NOSYMFOLLOW != 0,
            nodiratime: bits & MS_NODIRATIME != 0,
            lazytime: bits & MS_LAZYTIME != 0,
            atime,
        }
    }

    pub fn to_bits(self) -> u64 {
        use mount_flags::*;
        let mut out = 0;
        if self.rdonly {
            out |= MS_RDONLY;
        }
        if self.nosuid {
            out |= MS_NOSUID;
        }
        if self.nodev {
            out |= MS_NODEV;
        }
        if self.noexec {
            out |= MS_NOEXEC;
        }
        if self.synchronous {
            out |= MS_SYNCHRONOUS;
        }
        if self.dirsync {
            out |= MS_DIRSYNC;
        }
        if self.nosymfollow {
            out |= MS_NOSYMFOLLOW;
        }
        if self.nodiratime {
            out |= MS_NODIRATIME;
        }
        if self.lazytime {
            out |= MS_LAZYTIME;
        }
        match self.atime {
            AtimeMode::Noatime => out |= MS_NOATIME,
            AtimeMode::Relatime => out |= MS_RELATIME,
            AtimeMode::Strictatime => out |= MS_STRICTATIME,
        }
        out
    }

    pub fn to_statfs_flags(self) -> u64 {
        use statfs_flags::*;
        let mut out = 0;
        if self.rdonly {
            out |= ST_RDONLY;
        }
        if self.nosuid {
            out |= ST_NOSUID;
        }
        if self.nodev {
            out |= ST_NODEV;
        }
        if self.noexec {
            out |= ST_NOEXEC;
        }
        if self.synchronous {
            out |= ST_SYNCHRONOUS;
        }
        if self.nosymfollow {
            out |= ST_NOSYMFOLLOW;
        }
        if self.nodiratime {
            out |= ST_NODIRATIME;
        }
        match self.atime {
            AtimeMode::Noatime => out |= ST_NOATIME,
            AtimeMode::Relatime => out |= ST_RELATIME,
            AtimeMode::Strictatime => {}
        }
        out
    }

    pub fn format_mount_opts(self) -> String {
        let mut parts = Vec::with_capacity(8);
        parts.push(if self.rdonly { "ro" } else { "rw" });
        if self.nosuid {
            parts.push("nosuid");
        }
        if self.nodev {
            parts.push("nodev");
        }
        if self.noexec {
            parts.push("noexec");
        }
        match self.atime {
            AtimeMode::Noatime => parts.push("noatime"),
            AtimeMode::Relatime => parts.push("relatime"),
            AtimeMode::Strictatime => parts.push("strictatime"),
        }
        if self.nodiratime {
            parts.push("nodiratime");
        }
        if self.synchronous {
            parts.push("sync");
        }
        if self.dirsync {
            parts.push("dirsync");
        }
        if self.nosymfollow {
            parts.push("nosymfollow");
        }
        if self.lazytime {
            parts.push("lazytime");
        }
        parts.join(",")
    }

    /// Whether an access on a mounted inode should update `atime` under these mount flags.
    pub fn should_update_atime(
        self,
        is_dir: bool,
        atime: (u64, u32),
        mtime: (u64, u32),
        ctime: (u64, u32),
        now: (u64, u32),
    ) -> bool {
        if self.rdonly || self.atime == AtimeMode::Noatime {
            return false;
        }
        if is_dir && self.nodiratime {
            return false;
        }
        match self.atime {
            AtimeMode::Noatime => false,
            AtimeMode::Strictatime => true,
            AtimeMode::Relatime => {
                atime <= mtime || atime <= ctime || now.0.saturating_sub(atime.0) >= 24 * 60 * 60
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderHealth {
    Connected,
    /// Export withdrawn or receiver permission revoked: mount stays attached; all ops -> `EACCES`.
    Revoked,
    /// Helper died, host folder permission lost, or peer tab offline: mount stays attached;
    /// new ops -> `ENOTCONN`; in-flight mutating ops at transition -> `EIO` (uncertain write).
    Lost,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AbortCause {
    None,
    Force,
    Revoked,
    Lost,
}

pub struct ProviderState {
    health: Cell<ProviderHealth>,
    abort_epoch: Cell<u64>,
    last_abort: Cell<AbortCause>,
    in_flight: RefCell<BTreeMap<u64, Waker>>,
    next_call_id: Cell<u64>,
    uncertain_writes: Cell<u64>,
    in_guarded_poll: Cell<bool>,
}

impl Default for ProviderState {
    fn default() -> Self {
        Self {
            health: Cell::new(ProviderHealth::Connected),
            abort_epoch: Cell::new(0),
            last_abort: Cell::new(AbortCause::None),
            in_flight: RefCell::new(BTreeMap::new()),
            next_call_id: Cell::new(1),
            uncertain_writes: Cell::new(0),
            in_guarded_poll: Cell::new(false),
        }
    }
}

struct InFlightGuard<'a> {
    provider: &'a ProviderState,
    id: u64,
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.provider.in_flight.borrow_mut().remove(&self.id);
    }
}

struct PollScopeGuard<'a> {
    flag: &'a Cell<bool>,
    prev: bool,
}

impl Drop for PollScopeGuard<'_> {
    fn drop(&mut self) {
        self.flag.set(self.prev);
    }
}

impl ProviderState {
    pub fn new() -> Rc<Self> {
        Rc::new(Self::default())
    }

    pub fn health(&self) -> ProviderHealth {
        self.health.get()
    }

    pub fn abort_epoch(&self) -> u64 {
        self.abort_epoch.get()
    }

    pub fn uncertain_writes(&self) -> u64 {
        self.uncertain_writes.get()
    }

    pub fn record_uncertain_write(&self) {
        self.uncertain_writes
            .set(self.uncertain_writes.get().saturating_add(1));
    }

    pub fn is_in_guarded_poll(&self) -> bool {
        self.in_guarded_poll.get()
    }

    pub fn check_health(&self) -> Result<()> {
        match self.health.get() {
            ProviderHealth::Connected => Ok(()),
            ProviderHealth::Revoked => Err(Errno::EACCES),
            ProviderHealth::Lost => Err(Errno::ENOTCONN),
        }
    }

    fn wake_all(&self) {
        let wakers: Vec<Waker> = std::mem::take(&mut *self.in_flight.borrow_mut())
            .into_values()
            .collect();
        for waker in wakers {
            waker.wake();
        }
    }

    /// Publisher revoked export or receiver ACL withdrawn (`EACCES`).
    pub fn revoke(&self) {
        self.health.set(ProviderHealth::Revoked);
        self.last_abort.set(AbortCause::Revoked);
        self.abort_epoch.set(self.abort_epoch.get().wrapping_add(1));
        self.wake_all();
    }

    /// Provider lost (`ENOTCONN`, and `EIO` + uncertain write for in-flight mutations).
    pub fn lose(&self) {
        if self.health.get() == ProviderHealth::Revoked {
            return;
        }
        self.health.set(ProviderHealth::Lost);
        self.last_abort.set(AbortCause::Lost);
        self.abort_epoch.set(self.abort_epoch.get().wrapping_add(1));
        self.wake_all();
    }

    /// `umount2(..., MNT_FORCE)` by instance root: abort in-flight requests with `EIO` without
    /// permanently marking a still-connected provider dead.
    pub fn force_abort(&self) {
        self.last_abort.set(AbortCause::Force);
        self.abort_epoch.set(self.abort_epoch.get().wrapping_add(1));
        self.wake_all();
    }

    /// Restore `Connected` health when a provider reconnects.
    pub fn reconnect(&self) {
        if self.health.get() == ProviderHealth::Revoked {
            return;
        }
        self.health.set(ProviderHealth::Connected);
    }

    fn abort_error(&self, is_mutating: bool) -> Errno {
        match self.last_abort.get() {
            AbortCause::Force => Errno::EIO,
            AbortCause::Revoked => Errno::EACCES,
            AbortCause::Lost => {
                if is_mutating {
                    self.record_uncertain_write();
                    Errno::EIO
                } else {
                    Errno::ENOTCONN
                }
            }
            AbortCause::None => match self.health.get() {
                ProviderHealth::Revoked => Errno::EACCES,
                ProviderHealth::Lost => {
                    if is_mutating {
                        self.record_uncertain_write();
                        Errno::EIO
                    } else {
                        Errno::ENOTCONN
                    }
                }
                ProviderHealth::Connected => Errno::EIO,
            },
        }
    }

    pub async fn guard_future<T, F>(&self, is_mutating: bool, fut: F) -> Result<T>
    where
        F: Future<Output = Result<T>>,
    {
        self.check_health()?;
        let start_epoch = self.abort_epoch.get();
        let id = self.next_call_id.get();
        self.next_call_id.set(id.wrapping_add(1));
        let _guard = InFlightGuard { provider: self, id };
        let mut fut = std::pin::pin!(fut);
        poll_fn(|cx| {
            if self.abort_epoch.get() != start_epoch {
                return Poll::Ready(Err(self.abort_error(is_mutating)));
            }
            let prev = self.in_guarded_poll.replace(true);
            let scope = PollScopeGuard {
                flag: &self.in_guarded_poll,
                prev,
            };
            let polled = fut.as_mut().poll(cx);
            drop(scope);
            match polled {
                Poll::Ready(Ok(val)) => Poll::Ready(Ok(val)),
                Poll::Ready(Err(err)) => {
                    if self.abort_epoch.get() != start_epoch {
                        Poll::Ready(Err(self.abort_error(is_mutating)))
                    } else {
                        Poll::Ready(Err(err))
                    }
                }
                Poll::Pending => {
                    if self.abort_epoch.get() != start_epoch {
                        Poll::Ready(Err(self.abort_error(is_mutating)))
                    } else {
                        self.in_flight.borrow_mut().insert(id, cx.waker().clone());
                        Poll::Pending
                    }
                }
            }
        })
        .await
    }
}

/// Shared lifetime wrapper around a mounted [`Filesystem`]. Drops and runs `on_release` only when
/// EVERY [`MountEntry`] across ALL namespaces AND EVERY [`MountPin`] (`FileRef`, `cwd`, `root`) drops.
pub struct MountBacking {
    pub fs: Rc<dyn Filesystem>,
    pub fstype: FsType,
    pub provider: Rc<ProviderState>,
    pub ceiling_rdonly: bool,
    pub ceiling_noexec: bool,
    sync_count: Cell<u64>,
    on_release: RefCell<Option<Box<dyn FnOnce()>>>,
}

impl MountBacking {
    pub fn new(fs: Rc<dyn Filesystem>, fstype: FsType) -> Self {
        Self {
            fs,
            fstype,
            provider: ProviderState::new(),
            ceiling_rdonly: fstype == FsType::Image,
            ceiling_noexec: false,
            sync_count: Cell::new(0),
            on_release: RefCell::new(None),
        }
    }

    pub fn with_provider(mut self, provider: Rc<ProviderState>) -> Self {
        self.provider = provider;
        self
    }

    pub fn with_ceilings(mut self, rdonly: bool, noexec: bool) -> Self {
        self.ceiling_rdonly = rdonly || self.fstype == FsType::Image;
        self.ceiling_noexec = noexec;
        self
    }

    pub fn with_on_release(self, cb: impl FnOnce() + 'static) -> Self {
        *self.on_release.borrow_mut() = Some(Box::new(cb));
        self
    }

    pub fn record_sync(&self) {
        self.sync_count.set(self.sync_count.get().saturating_add(1));
    }

    pub fn sync_count(&self) -> u64 {
        self.sync_count.get()
    }
}

impl Drop for MountBacking {
    fn drop(&mut self) {
        if let Some(cb) = self.on_release.borrow_mut().take() {
            cb();
        }
    }
}

pub struct WriteOpGuard<'a>(&'a MountSlot);

impl<'a> WriteOpGuard<'a> {
    fn enter(slot: &'a MountSlot) -> Self {
        slot.in_flight_writes.set(slot.in_flight_writes.get() + 1);
        Self(slot)
    }
}

impl Drop for WriteOpGuard<'_> {
    fn drop(&mut self) {
        self.0
            .in_flight_writes
            .set(self.0.in_flight_writes.get() - 1);
    }
}

pub(crate) struct DetachedParent {
    pub parent_slot: Rc<MountSlot>,
    pub mountpoint: Handle,
    pub _mountpoint_open: FileRef,
    pub mp_parent_node: Option<NodeId>,
    pub mp_name: Option<String>,
}

pub(crate) struct DetachedNode {
    pub slot: Rc<MountSlot>,
    pub root: Handle,
    pub _root_open: FileRef,
    pub parent: Option<DetachedParent>,
}

/// Preserves internal parent/child mount topology for a lazily detached mount subtree as long as
/// at least one external [`MountPin`] (`FileRef`, `cwd`, `root`) references any mount in the
/// subtree. Clears all internal `Rc<MountSlot>` links immediately when `external_pins` reaches 0.
pub(crate) struct DetachedGroup {
    external_pins: Cell<usize>,
    nodes: RefCell<BTreeMap<MountId, DetachedNode>>,
    children: RefCell<HashMap<(MountId, NodeId), Vec<MountId>>>,
    parents_with_children: RefCell<HashSet<MountId>>,
    mp_names_by_parent: RefCell<HashMap<(MountId, NodeId), HashSet<String>>>,
}

impl DetachedGroup {
    pub(crate) fn install(
        entries: Vec<MountEntry>,
        children_order: HashMap<(MountId, NodeId), Vec<MountId>>,
    ) {
        if entries.is_empty() {
            return;
        }
        let detached_ids: HashSet<MountId> = entries.iter().map(|e| e.slot.id).collect();
        for entry in &entries {
            entry.slot.detached.set(true);
        }

        let mut nodes = BTreeMap::new();
        let mut mp_names_by_parent: HashMap<(MountId, NodeId), HashSet<String>> = HashMap::new();

        for entry in entries {
            let MountEntry {
                slot,
                parent,
                root,
                root_open,
                ..
            } = entry;
            let detached_parent = match parent {
                Some(att) => {
                    let parent_id = att.parent_pin.id();
                    if detached_ids.contains(&parent_id) {
                        let parent_slot = Rc::clone(att.parent_pin.slot());
                        drop(att.parent_pin);
                        if let (Some(dir_node), Some(name)) =
                            (att.mp_parent_node, att.mp_name.as_ref())
                        {
                            mp_names_by_parent
                                .entry((parent_id, dir_node))
                                .or_default()
                                .insert(name.clone());
                        }
                        Some(DetachedParent {
                            parent_slot,
                            mountpoint: att.mountpoint,
                            _mountpoint_open: att.mountpoint_open,
                            mp_parent_node: att.mp_parent_node,
                            mp_name: att.mp_name,
                        })
                    } else {
                        drop(att);
                        None
                    }
                }
                None => None,
            };
            nodes.insert(
                slot.id,
                DetachedNode {
                    slot,
                    root,
                    _root_open: root_open,
                    parent: detached_parent,
                },
            );
        }

        let external_pins: usize = nodes.values().map(|n| n.slot.active_pins()).sum();
        if external_pins == 0 {
            return;
        }

        let mut children: HashMap<(MountId, NodeId), Vec<MountId>> = HashMap::new();
        let mut parents_with_children: HashSet<MountId> = HashSet::new();
        for ((pm, pnode), stack) in children_order {
            if detached_ids.contains(&pm) {
                let filtered: Vec<MountId> = stack
                    .into_iter()
                    .filter(|cid| detached_ids.contains(cid))
                    .collect();
                if !filtered.is_empty() {
                    parents_with_children.insert(pm);
                    children.insert((pm, pnode), filtered);
                }
            }
        }

        let group = Rc::new(Self {
            external_pins: Cell::new(external_pins),
            nodes: RefCell::new(nodes),
            children: RefCell::new(children),
            parents_with_children: RefCell::new(parents_with_children),
            mp_names_by_parent: RefCell::new(mp_names_by_parent),
        });
        for node in group.nodes.borrow().values() {
            *node.slot.detached_group.borrow_mut() = Some(Rc::clone(&group));
        }
    }

    fn inc_external_pins(&self) {
        self.external_pins.set(self.external_pins.get() + 1);
    }

    fn dec_external_pins(&self) {
        let rem = self.external_pins.get() - 1;
        self.external_pins.set(rem);
        if rem == 0 {
            let nodes = std::mem::take(&mut *self.nodes.borrow_mut());
            self.children.borrow_mut().clear();
            self.parents_with_children.borrow_mut().clear();
            self.mp_names_by_parent.borrow_mut().clear();
            for node in nodes.into_values() {
                *node.slot.detached_group.borrow_mut() = None;
            }
        }
    }
}

/// Per-`MountId` state held by [`MountEntry`] and pinned by [`MountPin`].
pub struct MountSlot {
    pub id: MountId,
    pub ns_id: NamespaceId,
    pub root_node: NodeId,
    pub backing: Rc<MountBacking>,
    flags: Cell<MountFlags>,
    locked_flags: Cell<u64>,
    /// `None` for system mounts; `Some(uid)` for user mounts (owner-only ceiling, contract §2.7).
    pub owner_uid: Option<u32>,
    pub detached: Cell<bool>,
    active_pins: Cell<usize>,
    writable_opens: Cell<usize>,
    in_flight_writes: Cell<usize>,
    detached_group: RefCell<Option<Rc<DetachedGroup>>>,
}

impl MountSlot {
    pub fn new(
        id: MountId,
        ns_id: NamespaceId,
        root_node: NodeId,
        backing: Rc<MountBacking>,
        mut flags: MountFlags,
        mut locked_flags: u64,
        owner_uid: Option<u32>,
    ) -> Rc<Self> {
        if backing.ceiling_rdonly {
            flags.rdonly = true;
            locked_flags |= mount_flags::MS_RDONLY;
        }
        if backing.ceiling_noexec {
            flags.noexec = true;
            locked_flags |= mount_flags::MS_NOEXEC;
        }
        if owner_uid.is_some() {
            flags.nosuid = true;
            flags.nodev = true;
            locked_flags |= mount_flags::MS_NOSUID | mount_flags::MS_NODEV;
        }
        Rc::new(Self {
            id,
            ns_id,
            root_node,
            backing,
            flags: Cell::new(flags),
            locked_flags: Cell::new(locked_flags),
            owner_uid,
            detached: Cell::new(false),
            active_pins: Cell::new(0),
            writable_opens: Cell::new(0),
            in_flight_writes: Cell::new(0),
            detached_group: RefCell::new(None),
        })
    }

    pub fn pin(self: &Rc<Self>) -> MountPin {
        self.active_pins.set(self.active_pins.get() + 1);
        if let Some(group) = self.detached_group.borrow().as_ref() {
            group.inc_external_pins();
        }
        MountPin(Rc::clone(self))
    }

    pub fn flags(&self) -> MountFlags {
        self.flags.get()
    }

    pub fn set_flags(&self, mut flags: MountFlags) {
        if self.backing.ceiling_rdonly {
            flags.rdonly = true;
        }
        if self.backing.ceiling_noexec {
            flags.noexec = true;
        }
        self.flags.set(flags);
    }

    pub fn effective_flags(&self) -> MountFlags {
        let mut flags = self.flags.get();
        if self.backing.ceiling_rdonly {
            flags.rdonly = true;
        }
        if self.backing.ceiling_noexec {
            flags.noexec = true;
        }
        flags
    }

    pub fn effective_rdonly(&self) -> bool {
        self.flags.get().rdonly || self.backing.ceiling_rdonly
    }

    pub fn effective_noexec(&self) -> bool {
        self.flags.get().noexec || self.backing.ceiling_noexec
    }

    pub fn locked_flags(&self) -> u64 {
        self.locked_flags.get()
    }

    pub fn active_pins(&self) -> usize {
        self.active_pins.get()
    }

    pub fn is_busy(&self) -> bool {
        self.active_pins.get() > 0
    }

    pub fn writable_opens(&self) -> usize {
        self.writable_opens.get()
    }

    pub fn in_flight_writes(&self) -> usize {
        self.in_flight_writes.get()
    }

    pub fn begin_write(&self) -> Result<WriteOpGuard<'_>> {
        if self.effective_rdonly() {
            return Err(Errno::EROFS);
        }
        Ok(WriteOpGuard::enter(self))
    }

    pub(crate) fn inc_writable_opens(&self) {
        self.writable_opens.set(self.writable_opens.get() + 1);
    }

    pub(crate) fn dec_writable_opens(&self) {
        self.writable_opens.set(self.writable_opens.get() - 1);
    }

    pub fn check_owner(&self, cred: &Cred) -> Result<()> {
        if let Some(owner) = self.owner_uid
            && cred.identity.id != owner
        {
            return Err(Errno::EACCES);
        }
        Ok(())
    }

    pub fn guard_enter(&self, cred: &Cred) -> Result<()> {
        self.check_owner(cred)?;
        self.backing.provider.check_health()
    }

    pub async fn guard_op<T, F>(
        &self,
        cred: &Cred,
        is_mutating: bool,
        check_rofs: bool,
        fut: F,
    ) -> Result<T>
    where
        F: Future<Output = Result<T>>,
    {
        self.check_owner(cred)?;
        let _write_guard = if check_rofs {
            Some(self.begin_write()?)
        } else {
            None
        };
        let mut fut = std::pin::pin!(fut);
        let wrapped = poll_fn(|cx| {
            let _flags_guard = MountFlagsPollGuard::enter(self.effective_flags());
            fut.as_mut().poll(cx)
        });
        self.backing
            .provider
            .guard_future(is_mutating, wrapped)
            .await
    }
}

/// O(1) reference-counted pin on a [`MountSlot`], held by every [`crate::File`],
/// [`crate::context::PathAnchor`], and child [`MountAttachment`].
pub struct MountPin(Rc<MountSlot>);

/// A delegated writer keeps the mount busy just like a writable open description.
pub struct WritableMountPin(MountPin);

impl Drop for WritableMountPin {
    fn drop(&mut self) {
        self.0.slot().dec_writable_opens();
    }
}

impl Clone for MountPin {
    fn clone(&self) -> Self {
        self.0.active_pins.set(self.0.active_pins.get() + 1);
        if let Some(group) = self.0.detached_group.borrow().as_ref() {
            group.inc_external_pins();
        }
        Self(Rc::clone(&self.0))
    }
}

impl Drop for MountPin {
    fn drop(&mut self) {
        self.0.active_pins.set(self.0.active_pins.get() - 1);
        let group = self.0.detached_group.borrow().clone();
        if let Some(group) = group {
            group.dec_external_pins();
        }
    }
}

impl std::fmt::Debug for MountPin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MountPin")
            .field("id", &self.0.id)
            .field("ns_id", &self.0.ns_id)
            .field("fstype", &self.0.backing.fstype)
            .finish()
    }
}

impl MountPin {
    pub fn pin_writer(&self, cred: &Cred) -> Result<WritableMountPin> {
        self.guard_enter(cred)?;
        if self.effective_rdonly() {
            return Err(Errno::EROFS);
        }
        self.slot().inc_writable_opens();
        Ok(WritableMountPin(self.clone()))
    }

    pub fn slot(&self) -> &Rc<MountSlot> {
        &self.0
    }

    pub fn id(&self) -> MountId {
        self.0.id
    }

    pub fn ns_id(&self) -> NamespaceId {
        self.0.ns_id
    }

    pub fn root_node(&self) -> NodeId {
        self.0.root_node
    }

    pub fn backing(&self) -> &Rc<MountBacking> {
        &self.0.backing
    }

    pub fn fs(&self) -> &Rc<dyn Filesystem> {
        &self.0.backing.fs
    }

    pub fn fstype(&self) -> FsType {
        self.0.backing.fstype
    }

    pub fn provider(&self) -> &Rc<ProviderState> {
        &self.0.backing.provider
    }

    pub fn health(&self) -> ProviderHealth {
        self.0.backing.provider.health()
    }

    pub fn flags(&self) -> MountFlags {
        self.0.flags()
    }

    pub fn effective_flags(&self) -> MountFlags {
        self.0.effective_flags()
    }

    pub fn effective_rdonly(&self) -> bool {
        self.0.effective_rdonly()
    }

    pub fn effective_noexec(&self) -> bool {
        self.0.effective_noexec()
    }

    pub fn locked_flags(&self) -> u64 {
        self.0.locked_flags()
    }

    pub fn owner_uid(&self) -> Option<u32> {
        self.0.owner_uid
    }

    pub fn is_detached(&self) -> bool {
        self.0.detached.get()
    }

    pub fn is_busy(&self) -> bool {
        self.0.is_busy()
    }

    pub fn active_pins(&self) -> usize {
        self.0.active_pins()
    }

    pub fn writable_opens(&self) -> usize {
        self.0.writable_opens()
    }

    pub fn in_flight_writes(&self) -> usize {
        self.0.in_flight_writes()
    }

    pub fn begin_write(&self) -> Result<WriteOpGuard<'_>> {
        self.0.begin_write()
    }

    pub(crate) fn detached_topmost_at(
        &self,
        mp_mount: MountId,
        mp_node: NodeId,
    ) -> Option<(MountPin, Handle)> {
        let group = self.0.detached_group.borrow().clone()?;
        let children = group.children.borrow();
        let nodes = group.nodes.borrow();
        let mut cur_mount = mp_mount;
        let mut cur_node = mp_node;
        let mut found: Option<&DetachedNode> = None;
        while let Some(stack) = children.get(&(cur_mount, cur_node))
            && let Some(&top_id) = stack.last()
            && let Some(entry) = nodes.get(&top_id)
        {
            cur_mount = top_id;
            cur_node = entry.root.node;
            found = Some(entry);
        }
        let entry = found?;
        let pin = entry.slot.pin();
        let root = entry.root.clone();
        drop(nodes);
        drop(children);
        Some((pin, root))
    }

    pub(crate) fn detached_mount_parent(
        &self,
        mount_id: MountId,
    ) -> Option<(MountPin, Handle, Option<NodeId>, Option<String>)> {
        let group = self.0.detached_group.borrow().clone()?;
        let nodes = group.nodes.borrow();
        let p = nodes.get(&mount_id)?.parent.as_ref()?;
        let pin = p.parent_slot.pin();
        let mp = p.mountpoint.clone();
        let mp_parent = p.mp_parent_node;
        let mp_name = p.mp_name.clone();
        drop(nodes);
        Some((pin, mp, mp_parent, mp_name))
    }

    pub(crate) fn detached_dir_has_mountpoint(
        &self,
        parent_mount: MountId,
        parent_dir_node: NodeId,
        name: &str,
    ) -> bool {
        let Some(group) = self.0.detached_group.borrow().clone() else {
            return false;
        };
        let map = group.mp_names_by_parent.borrow();
        map.get(&(parent_mount, parent_dir_node))
            .is_some_and(|set| set.contains(name))
    }

    pub(crate) fn detached_has_children_on(&self, parent_mount: MountId) -> bool {
        let Some(group) = self.0.detached_group.borrow().clone() else {
            return false;
        };
        group.parents_with_children.borrow().contains(&parent_mount)
    }

    pub fn guard_enter(&self, cred: &Cred) -> Result<()> {
        self.0.guard_enter(cred)
    }

    pub async fn guard_op<T, F>(
        &self,
        cred: &Cred,
        is_mutating: bool,
        check_rofs: bool,
        fut: F,
    ) -> Result<T>
    where
        F: Future<Output = Result<T>>,
    {
        self.0.guard_op(cred, is_mutating, check_rofs, fut).await
    }
}

pub struct MountAttachment {
    pub parent_pin: MountPin,
    pub mountpoint: Handle,
    pub mountpoint_open: FileRef,
    /// Immediate parent directory `NodeId` of `mountpoint` on `parent_pin` (absent when stacked
    /// directly onto the root of `parent_pin`).
    pub mp_parent_node: Option<NodeId>,
    /// Component name of `mountpoint` inside `mp_parent_node`.
    pub mp_name: Option<String>,
}

pub struct MountEntry {
    pub slot: Rc<MountSlot>,
    pub parent: Option<MountAttachment>,
    pub root: Handle,
    pub root_open: FileRef,
    pub root_in_fs: String,
    pub source: String,
}
