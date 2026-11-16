//! Mount, provider lifecycle, and O(1) pin-counted mount-slot primitives
//! (`docs/architecture/contract.md` §2.5, §2.7, §4, §5).

use crate::{Cred, FileRef, Filesystem, Handle, NodeId, Result};
use abi::Errno;
use abi::contract::{fs_magic, mount_flags, statfs_flags};
use serde::{Deserialize, Serialize};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::rc::Rc;
use std::task::{Poll, Waker};

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
        })
    }

    pub fn pin(self: &Rc<Self>) -> MountPin {
        self.active_pins.set(self.active_pins.get() + 1);
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
        if check_rofs && self.effective_rdonly() {
            return Err(Errno::EROFS);
        }
        self.backing.provider.guard_future(is_mutating, fut).await
    }
}

/// O(1) reference-counted pin on a [`MountSlot`], held by every [`crate::File`],
/// [`crate::context::PathAnchor`], and child [`MountAttachment`].
pub struct MountPin(Rc<MountSlot>);

impl Clone for MountPin {
    fn clone(&self) -> Self {
        self.0.active_pins.set(self.0.active_pins.get() + 1);
        Self(Rc::clone(&self.0))
    }
}

impl Drop for MountPin {
    fn drop(&mut self) {
        self.0.active_pins.set(self.0.active_pins.get() - 1);
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
