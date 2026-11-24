//! `/dev/vdN` managed `cowfs` volume device registry, `BLK_INFO` / `BLK_LEASE` / `COWFS_IOC_*`
//! ioctl dispatch, and `mkfs.cowfs` target validation (`docs/architecture/contract.md` §2.7,
//! §2.16, §5; #77).

use crate::devfs::{DefaultDeviceBackend, DeviceBackend};
use crate::{
    Access, BoxFuture, Cred, Fd, FileRef, FileType, FsType, Result, StartAnchor, Vfs, WriteAt,
    Written,
};
use abi::Errno;
use abi::contract::cowfs_ioctl;
use abi::volume::{
    BlkInfoResp, BlkLeaseResp, CowfsForkReq, CowfsForkResp, CowfsFsckReq, CowfsFsckResp,
    CowfsGcReq, CowfsGcResp, CowfsInfoResp, CowfsMkfsReq, CowfsReceiveReq, CowfsReceiveResp,
    CowfsSendReq, CowfsSendResp, CowfsSnapDeleteReq, CowfsSnapListResp, CowfsSnapshotReq,
    CowfsSnapshotResp, CowfsSubvolReq, CowfsSubvolResp,
};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

/// Prefix carried in `Metadata::rdev` for `/dev/vdN` volume devices registered in `DevTmpFs`.
pub const VBLK_RDEV_PREFIX: &str = "vblk:";

/// Maximum JSON ioctl payload accepted by `/dev/vdN` (`64 KiB`, contract §2.16 bounded payloads).
pub const VBLK_IOCTL_PAYLOAD_MAX: usize = 64 * 1024;

/// Format the `rdev` tag for a `/dev/vdN` node (`"vblk:vd0"`).
pub fn vblk_rdev(name: &str) -> String {
    format!("{VBLK_RDEV_PREFIX}{name}")
}

/// Extract the device name (`"vd0"`) from a `vblk:` `rdev` string.
pub fn parse_vblk_rdev(rdev: &str) -> Option<&str> {
    let tag = rdev.strip_prefix(VBLK_RDEV_PREFIX)?;
    let name = tag.split('@').next()?;
    (!name.is_empty()).then_some(name)
}

/// Returns `true` if `request` is one of the `BLK_*` or `COWFS_IOC_*` ioctls handled by `VblkRegistry`.
pub const fn is_cowfs_or_blk_ioctl(request: u32) -> bool {
    matches!(
        request,
        cowfs_ioctl::BLK_INFO
            | cowfs_ioctl::BLK_LEASE
            | cowfs_ioctl::COWFS_IOC_INFO
            | cowfs_ioctl::COWFS_IOC_SNAPSHOT
            | cowfs_ioctl::COWFS_IOC_FORK
            | cowfs_ioctl::COWFS_IOC_FSCK
            | cowfs_ioctl::COWFS_IOC_MKFS
            | cowfs_ioctl::COWFS_IOC_SUBVOL
            | cowfs_ioctl::COWFS_IOC_SNAP_LIST
            | cowfs_ioctl::COWFS_IOC_SNAP_DELETE
            | cowfs_ioctl::COWFS_IOC_SEND
            | cowfs_ioctl::COWFS_IOC_RECEIVE
            | cowfs_ioctl::COWFS_IOC_GC
    )
}

/// Returns `true` if `source` names a non-block tree / host-folder / export target that
/// `mount -t cowfs` must refuse with `Errno::ENOTBLK` (contract §2.7, §4).
/// Allows `volume:`, `snapshot:`, `oci:`, `/dev/vdN`, and `/dev/loopN` (for read-only `.cowpack`
/// archive mounts; `mkfs.cowfs` separately refuses `/dev/loopN` with `EROFS`/`ENOTBLK`).
pub fn is_non_block_tree_source(source: &str) -> bool {
    let s = source.trim();
    if s.is_empty() {
        return true;
    }
    if s.starts_with("remote:volume:")
        || s.starts_with("remote:snapshot:")
        || s.starts_with("volume:")
        || s.starts_with("snapshot:")
        || s.starts_with("oci:")
        || s.starts_with("/dev/vd")
        || crate::loopdev::is_loop_device_path(s)
    {
        return false;
    }
    true
}

/// Validate `mount -t cowfs` options (`subvol=<name>`, `ro`, `excl`, `refresh`, contract §5).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CowfsMountOptions {
    pub subvol: String,
    pub ro: bool,
    pub excl: bool,
    pub refresh: bool,
    pub remote: bool,
    pub takeover: bool,
}

impl CowfsMountOptions {
    pub fn parse(data: Option<&str>) -> Result<Self> {
        let mut opts = Self {
            subvol: "@".to_string(),
            ro: false,
            excl: false,
            ..Self::default()
        };
        let Some(raw) = data else {
            return Ok(opts);
        };
        for item in raw.split(',').filter(|s| !s.is_empty()) {
            match item {
                "ro" => opts.ro = true,
                "rw" => opts.ro = false,
                "excl" => opts.excl = true,
                "remote" => opts.remote = true,
                "takeover" => opts.takeover = true,
                "refresh" => opts.refresh = true,
                other => {
                    let Some((key, val)) = other.split_once('=') else {
                        return Err(Errno::EINVAL);
                    };
                    if key != "subvol" || val.is_empty() || val.contains(['/', '\0']) {
                        return Err(Errno::EINVAL);
                    }
                    opts.subvol = val.to_string();
                }
            }
        }
        Ok(opts)
    }
}

pub trait StreamSink {
    fn write_chunk<'a>(&'a mut self, bytes: &'a [u8]) -> BoxFuture<'a, usize>;
}
pub trait StreamSource {
    fn read_chunk<'a>(&'a mut self, bytes: &'a mut [u8]) -> BoxFuture<'a, usize>;
}
impl StreamSink for FileRef {
    fn write_chunk<'a>(&'a mut self, bytes: &'a [u8]) -> BoxFuture<'a, usize> {
        Box::pin(self.write(bytes))
    }
}
impl StreamSource for FileRef {
    fn read_chunk<'a>(&'a mut self, bytes: &'a mut [u8]) -> BoxFuture<'a, usize> {
        Box::pin(self.read(bytes))
    }
}
pub enum IoctlStream<'a> {
    KernelFds(&'a Vfs, u32),
    Sink(&'a mut dyn StreamSink),
    Source(&'a mut dyn StreamSource),
}

/// Portable backend trait implemented by managed `os-cowfs` volume devices attached at `/dev/vdN`
/// or attached to a mounted `FsType::Cowfs` [`crate::MountBacking`].
pub trait VolumeDevice {
    fn volume_id(&self) -> &str;
    fn remote_source(&self) -> Option<String> {
        None
    }
    fn is_read_only(&self) -> bool {
        false
    }
    fn refresh_ro(&self) -> BoxFuture<'_, ()> {
        Box::pin(async { Err(Errno::EINVAL) })
    }
    fn blk_info<'a>(&'a self, dev_name: &'a str) -> BoxFuture<'a, BlkInfoResp>;
    fn blk_lease(&self) -> BoxFuture<'_, BlkLeaseResp>;
    fn cowfs_info(&self) -> BoxFuture<'_, CowfsInfoResp>;
    fn cowfs_fsck<'a>(&'a self, _req: &'a CowfsFsckReq) -> BoxFuture<'a, CowfsFsckResp> {
        Box::pin(async { Err(Errno::ENOTTY) })
    }
    fn cowfs_snapshot<'a>(&'a self, req: &'a CowfsSnapshotReq) -> BoxFuture<'a, CowfsSnapshotResp>;
    fn cowfs_fork<'a>(&'a self, req: &'a CowfsForkReq) -> BoxFuture<'a, CowfsForkResp>;
    fn mkfs(&self, force: bool) -> BoxFuture<'_, CowfsInfoResp>;
    fn cowfs_mkfs<'a>(&'a self, req: &'a CowfsMkfsReq) -> BoxFuture<'a, CowfsInfoResp> {
        self.mkfs(req.force)
    }
    fn cowfs_subvol<'a>(&'a self, _req: &'a CowfsSubvolReq) -> BoxFuture<'a, CowfsSubvolResp> {
        Box::pin(async { Err(Errno::ENOTTY) })
    }
    fn cowfs_snap_list(&self) -> BoxFuture<'_, CowfsSnapListResp> {
        Box::pin(async { Err(Errno::ENOTTY) })
    }
    fn cowfs_snap_delete<'a>(&'a self, _req: &'a CowfsSnapDeleteReq) -> BoxFuture<'a, ()> {
        Box::pin(async { Err(Errno::ENOTTY) })
    }
    fn cowfs_send<'a>(
        &'a self,
        _req: &'a CowfsSendReq,
        _sink: &'a mut dyn StreamSink,
    ) -> BoxFuture<'a, CowfsSendResp> {
        Box::pin(async { Err(Errno::ENOTTY) })
    }
    fn cowfs_receive<'a>(
        &'a self,
        _req: &'a CowfsReceiveReq,
        _source: &'a mut dyn StreamSource,
    ) -> BoxFuture<'a, CowfsReceiveResp> {
        Box::pin(async { Err(Errno::ENOTTY) })
    }
    fn cowfs_gc<'a>(&'a self, _req: &'a CowfsGcReq) -> BoxFuture<'a, CowfsGcResp> {
        Box::pin(async { Err(Errno::ENOTTY) })
    }
}

fn trim_json(payload: &[u8]) -> &[u8] {
    payload
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .map(|start| {
            let end = payload
                .iter()
                .rposition(|b| !b.is_ascii_whitespace())
                .map_or(start, |e| e + 1);
            &payload[start..end]
        })
        .unwrap_or(&[])
}

fn parse_fsck_req(payload: &[u8]) -> Result<CowfsFsckReq> {
    let trimmed = trim_json(payload);
    if trimmed.is_empty() || trimmed == b"null" {
        return Ok(CowfsFsckReq::default());
    }
    let req: CowfsFsckReq = serde_json::from_slice(trimmed).map_err(|_| Errno::EINVAL)?;
    if let Some(ref v) = req.volume
        && (v.is_empty() || v.contains(['/', '\0']))
    {
        return Err(Errno::EINVAL);
    }
    if let Some(ref s) = req.snapshot
        && (s.is_empty() || s.contains(['/', '\0']))
    {
        return Err(Errno::EINVAL);
    }
    Ok(req)
}

fn parse_mkfs_req(payload: &[u8]) -> Result<CowfsMkfsReq> {
    let trimmed = trim_json(payload);
    if trimmed.is_empty() || trimmed == b"null" {
        return Ok(CowfsMkfsReq::default());
    }
    let req: CowfsMkfsReq = serde_json::from_slice(trimmed).map_err(|_| Errno::EINVAL)?;
    if let Some(ref l) = req.label
        && (l.contains('\0') || l.len() > 64)
    {
        return Err(Errno::EINVAL);
    }
    if let Some(ref v) = req.volume
        && (v.is_empty() || v.contains(['/', '\0']))
    {
        return Err(Errno::EINVAL);
    }
    Ok(req)
}

fn parse_gc_req(payload: &[u8]) -> Result<CowfsGcReq> {
    let trimmed = trim_json(payload);
    if trimmed.is_empty() || trimmed == b"null" {
        return Ok(CowfsGcReq::default());
    }
    serde_json::from_slice(trimmed).map_err(|_| Errno::EINVAL)
}

/// `DeviceBackend` wrapper that refuses raw `read`/`write` on object-native `/dev/vdN` devices
/// with `Errno::EOPNOTSUPP` (contract §2.16) while delegating all other character devices to `D`.
#[derive(Clone, Debug, Default)]
pub struct VblkDeviceBackend<D = DefaultDeviceBackend> {
    inner: D,
}

impl<D> VblkDeviceBackend<D> {
    pub fn new(inner: D) -> Self {
        Self { inner }
    }
}

impl<D: DeviceBackend> DeviceBackend for VblkDeviceBackend<D> {
    fn fill_random(&self, buf: &mut [u8]) -> Result<()> {
        self.inner.fill_random(buf)
    }

    fn read_device<'a>(
        &'a self,
        rdev: &'a str,
        buf: &'a mut [u8],
        offset: u64,
    ) -> BoxFuture<'a, usize> {
        if parse_vblk_rdev(rdev).is_some() {
            return Box::pin(async { Err(Errno::EOPNOTSUPP) });
        }
        self.inner.read_device(rdev, buf, offset)
    }

    fn write_device<'a>(
        &'a self,
        rdev: &'a str,
        buf: &'a [u8],
        at: WriteAt,
    ) -> BoxFuture<'a, Written> {
        if parse_vblk_rdev(rdev).is_some() {
            return Box::pin(async { Err(Errno::EOPNOTSUPP) });
        }
        self.inner.write_device(rdev, buf, at)
    }
}

/// Registry mapping `/dev/vdN` device names to managed [`VolumeDevice`] instances.
#[derive(Default)]
struct Slot {
    instance_id: u64,
    device: Option<Rc<dyn VolumeDevice>>,
}
#[derive(Default)]
pub struct VblkRegistry {
    devices: RefCell<BTreeMap<String, Slot>>,
}

impl VblkRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach a volume device under the next free name (`vd0`, `vd1`, ...).
    pub fn attach(&self, device: Rc<dyn VolumeDevice>) -> String {
        let name = (0u64..)
            .map(|i| format!("vd{i}"))
            .find(|n| self.get(n).is_none())
            .expect("free vblk slot");
        self.attach_named(&name, device).expect("free vblk slot");
        name
    }

    pub fn attach_named(&self, name: &str, device: Rc<dyn VolumeDevice>) -> Result<()> {
        if !name
            .strip_prefix("vd")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit()))
        {
            return Err(Errno::EINVAL);
        }
        let mut slots = self.devices.borrow_mut();
        let slot = slots.entry(name.to_owned()).or_default();
        if slot.device.is_some() {
            return Err(Errno::EEXIST);
        }
        slot.instance_id = slot.instance_id.checked_add(1).ok_or(Errno::ENOSPC)?;
        slot.device = Some(device);
        Ok(())
    }

    /// A local volume keeps its device identity as it switches between mounted and unmounted.
    pub fn replace_named(&self, name: &str, device: Rc<dyn VolumeDevice>) -> Result<()> {
        if let Some(slot) = self.devices.borrow_mut().get_mut(name)
            && let Some(old) = &slot.device
        {
            if old.volume_id() != device.volume_id() {
                return Err(Errno::EBUSY);
            }
            slot.device = Some(device);
            return Ok(());
        }
        self.attach_named(name, device)
    }

    pub fn detach(&self, name: &str) -> Result<()> {
        self.devices
            .borrow_mut()
            .get_mut(name)
            .and_then(|s| s.device.take())
            .map(|_| ())
            .ok_or(Errno::ENODEV)
    }
    pub fn get(&self, name: &str) -> Option<Rc<dyn VolumeDevice>> {
        self.devices.borrow().get(name)?.device.clone()
    }

    pub fn registered_rdev(&self, name: &str) -> Result<String> {
        let slots = self.devices.borrow();
        let slot = slots
            .get(name)
            .filter(|s| s.device.is_some())
            .ok_or(Errno::ENODEV)?;
        // The original rdev spelling identifies the first instance of a slot.
        let mut tag = vblk_rdev(name);
        if slot.instance_id > 1 {
            tag.push_str(&format!("@{}", slot.instance_id));
        }
        Ok(tag)
    }

    pub fn device_for_rdev(&self, tag: &str) -> Result<Rc<dyn VolumeDevice>> {
        let name = parse_vblk_rdev(tag).ok_or(Errno::ENOTTY)?;
        if self.registered_rdev(name)? != tag {
            return Err(Errno::ENODEV);
        }
        self.get(name).ok_or(Errno::ENODEV)
    }

    pub fn register_node<D: DeviceBackend>(
        &self,
        fs: &crate::devfs::DevTmpFs<D>,
        name: &str,
        mode: u16,
    ) -> Result<()> {
        use crate::Filesystem;
        let tag = self.registered_rdev(name)?;
        let mut cred = Cred::root();
        cred.umask = 0;
        let root = fs.root();
        if let Ok(entry) =
            crate::now_or_never(fs.lookup(&cred, &root, name)).expect("sync devtmpfs")
        {
            if entry.metadata.rdev.as_ref() == Some(&tag) {
                return Ok(());
            }
            if entry.metadata.rdev.as_deref().and_then(parse_vblk_rdev) != Some(name) {
                return Err(Errno::EEXIST);
            }
            crate::now_or_never(fs.unlink(&cred, &root, name)).expect("sync devtmpfs")?;
        }
        crate::now_or_never(fs.mknod(&cred, &root, name, mode, &tag))
            .expect("sync devtmpfs")
            .map(|_| ())
    }

    pub fn find_by_volume(&self, volume_id: &str) -> Option<(String, Rc<dyn VolumeDevice>)> {
        self.devices.borrow().iter().find_map(|(name, slot)| {
            let dev = slot.device.as_ref()?;
            (dev.remote_source().is_none() && dev.volume_id() == volume_id)
                .then(|| (name.clone(), dev.clone()))
        })
    }

    /// Dispatch a `BLK_*` / `COWFS_IOC_*` ioctl directly against a [`VolumeDevice`].
    ///
    /// - `dev_name`: `Some("vd0")` for `/dev/vdN` char device targets, `None` for mounted `FsType::Cowfs`
    ///   directory targets (which refuse `BLK_*` with `ENOTTY` and `COWFS_IOC_MKFS` with `ENOTBLK`).
    /// - `vfs_ctx`: `Some((vfs, pid))` when caller fd resolution is available (required for
    ///   `COWFS_IOC_SEND` and `COWFS_IOC_RECEIVE`).
    /// - `mount_rdonly`: `true` if the target mount/device is read-only (mutating ops fail `EROFS`).
    #[allow(clippy::too_many_arguments)]
    pub async fn dispatch_volume_ioctl(
        dev: &dyn VolumeDevice,
        dev_name: Option<&str>,
        vfs_ctx: Option<(&Vfs, u32)>,
        cred: &Cred,
        fd_readable: bool,
        mount_rdonly: bool,
        request: u32,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        Self::dispatch_stream_ioctl(
            dev,
            dev_name,
            vfs_ctx.map(|(v, p)| IoctlStream::KernelFds(v, p)),
            cred,
            fd_readable,
            mount_rdonly,
            request,
            payload,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn dispatch_stream_ioctl(
        dev: &dyn VolumeDevice,
        dev_name: Option<&str>,
        stream: Option<IoctlStream<'_>>,
        cred: &Cred,
        fd_readable: bool,
        mount_rdonly: bool,
        request: u32,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        if payload.len() > VBLK_IOCTL_PAYLOAD_MAX {
            return Err(Errno::E2BIG);
        }
        let effective_rdonly = mount_rdonly || dev.is_read_only();
        match request {
            cowfs_ioctl::BLK_INFO => {
                let name = dev_name.ok_or(Errno::ENOTTY)?;
                if !fd_readable && cred.identity.id != 0 {
                    return Err(Errno::EBADF);
                }
                let resp = dev.blk_info(name).await?;
                serde_json::to_vec(&resp).map_err(|_| Errno::EIO)
            }
            cowfs_ioctl::BLK_LEASE => {
                if dev_name.is_none() {
                    return Err(Errno::ENOTTY);
                }
                if !fd_readable && cred.identity.id != 0 {
                    return Err(Errno::EBADF);
                }
                let resp = dev.blk_lease().await?;
                serde_json::to_vec(&resp).map_err(|_| Errno::EIO)
            }
            cowfs_ioctl::COWFS_IOC_INFO => {
                if !fd_readable && cred.identity.id != 0 {
                    return Err(Errno::EBADF);
                }
                let resp = dev.cowfs_info().await?;
                serde_json::to_vec(&resp).map_err(|_| Errno::EIO)
            }
            cowfs_ioctl::COWFS_IOC_FSCK => {
                if !fd_readable && cred.identity.id != 0 {
                    return Err(Errno::EBADF);
                }
                let req = parse_fsck_req(payload)?;
                let resp = dev.cowfs_fsck(&req).await?;
                serde_json::to_vec(&resp).map_err(|_| Errno::EIO)
            }
            cowfs_ioctl::COWFS_IOC_MKFS => {
                if cred.identity.id != 0 {
                    return Err(Errno::EPERM);
                }
                if dev_name.is_none() {
                    return Err(Errno::ENOTBLK);
                }
                let req = parse_mkfs_req(payload)?;
                if effective_rdonly && req.volume.is_none() {
                    return Err(Errno::EROFS);
                }
                let resp = dev.cowfs_mkfs(&req).await?;
                serde_json::to_vec(&resp).map_err(|_| Errno::EIO)
            }
            cowfs_ioctl::COWFS_IOC_SUBVOL => {
                let req: CowfsSubvolReq =
                    serde_json::from_slice(payload).map_err(|_| Errno::EINVAL)?;
                match &req {
                    CowfsSubvolReq::List {} => {
                        if !fd_readable && cred.identity.id != 0 {
                            return Err(Errno::EBADF);
                        }
                    }
                    CowfsSubvolReq::Create { .. } | CowfsSubvolReq::Delete { .. } => {
                        if cred.identity.id != 0 {
                            return Err(Errno::EPERM);
                        }
                        if effective_rdonly {
                            return Err(Errno::EROFS);
                        }
                    }
                }
                let resp = dev.cowfs_subvol(&req).await?;
                serde_json::to_vec(&resp).map_err(|_| Errno::EIO)
            }
            cowfs_ioctl::COWFS_IOC_SNAP_LIST => {
                if !fd_readable && cred.identity.id != 0 {
                    return Err(Errno::EBADF);
                }
                let resp = dev.cowfs_snap_list().await?;
                serde_json::to_vec(&resp).map_err(|_| Errno::EIO)
            }
            cowfs_ioctl::COWFS_IOC_SNAP_DELETE => {
                if cred.identity.id != 0 {
                    return Err(Errno::EPERM);
                }
                if effective_rdonly {
                    return Err(Errno::EROFS);
                }
                let req: CowfsSnapDeleteReq =
                    serde_json::from_slice(payload).map_err(|_| Errno::EINVAL)?;
                dev.cowfs_snap_delete(&req).await?;
                Ok(b"null".to_vec())
            }
            cowfs_ioctl::COWFS_IOC_SNAPSHOT => {
                if cred.identity.id != 0 {
                    return Err(Errno::EPERM);
                }
                if effective_rdonly {
                    return Err(Errno::EROFS);
                }
                let req: CowfsSnapshotReq =
                    serde_json::from_slice(payload).map_err(|_| Errno::EINVAL)?;
                let resp = dev.cowfs_snapshot(&req).await?;
                serde_json::to_vec(&resp).map_err(|_| Errno::EIO)
            }
            cowfs_ioctl::COWFS_IOC_FORK => {
                if cred.identity.id != 0 {
                    return Err(Errno::EPERM);
                }
                let req: CowfsForkReq =
                    serde_json::from_slice(payload).map_err(|_| Errno::EINVAL)?;
                let resp = dev.cowfs_fork(&req).await?;
                serde_json::to_vec(&resp).map_err(|_| Errno::EIO)
            }
            cowfs_ioctl::COWFS_IOC_SEND => {
                if dev_name.is_none() && cred.identity.id != 0 {
                    return Err(Errno::EPERM);
                }
                if !fd_readable && cred.identity.id != 0 {
                    return Err(Errno::EBADF);
                }
                let req: CowfsSendReq =
                    serde_json::from_slice(payload).map_err(|_| Errno::EINVAL)?;
                let mut file;
                let endpoint: &mut dyn StreamSink = match stream {
                    Some(IoctlStream::Sink(endpoint)) => endpoint,
                    Some(IoctlStream::KernelFds(vfs, pid)) => {
                        file = vfs.process_fds(pid)?.borrow().get(req.stream_fd)?;
                        if !file.access().writes() || file.is_virtual() {
                            return Err(Errno::EBADF);
                        }
                        &mut file
                    }
                    _ => return Err(Errno::EBADF),
                };
                let resp = dev.cowfs_send(&req, endpoint).await?;
                serde_json::to_vec(&resp).map_err(|_| Errno::EIO)
            }
            cowfs_ioctl::COWFS_IOC_RECEIVE => {
                if cred.identity.id != 0 {
                    return Err(Errno::EPERM);
                }
                let req: CowfsReceiveReq =
                    serde_json::from_slice(payload).map_err(|_| Errno::EINVAL)?;
                let targeting_same = req
                    .target_volume
                    .as_deref()
                    .is_none_or(|v| v == dev.volume_id());
                if effective_rdonly && targeting_same {
                    return Err(Errno::EROFS);
                }
                let mut file;
                let endpoint: &mut dyn StreamSource = match stream {
                    Some(IoctlStream::Source(endpoint)) => endpoint,
                    Some(IoctlStream::KernelFds(vfs, pid)) => {
                        file = vfs.process_fds(pid)?.borrow().get(req.stream_fd)?;
                        if !file.access().reads() || file.is_virtual() {
                            return Err(Errno::EBADF);
                        }
                        &mut file
                    }
                    _ => return Err(Errno::EBADF),
                };
                let resp = dev.cowfs_receive(&req, endpoint).await?;
                serde_json::to_vec(&resp).map_err(|_| Errno::EIO)
            }
            cowfs_ioctl::COWFS_IOC_GC => {
                if cred.identity.id != 0 {
                    return Err(Errno::EPERM);
                }
                if effective_rdonly {
                    return Err(Errno::EROFS);
                }
                let req = parse_gc_req(payload)?;
                let resp = dev.cowfs_gc(&req).await?;
                serde_json::to_vec(&resp).map_err(|_| Errno::EIO)
            }
            _ => Err(Errno::ENOTTY),
        }
    }

    /// Dispatch a `/dev/vdN` ioctl by `rdev` (`"vblk:vd0"`).
    pub async fn ioctl_rdev(
        &self,
        cred: &Cred,
        rdev: &str,
        request: u32,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        let Some(dev_name) = parse_vblk_rdev(rdev) else {
            return Err(Errno::ENOTTY);
        };
        let dev = self.device_for_rdev(rdev)?;
        Self::dispatch_volume_ioctl(
            &*dev,
            Some(dev_name),
            None,
            cred,
            true,
            false,
            request,
            payload,
        )
        .await
    }

    /// Dispatch a `BLK_*` or `COWFS_IOC_*` ioctl on an open file descriptor `fd` belonging to `pid`
    /// in `vfs`.
    ///
    /// Supports BOTH `/dev/vdN` char device fds AND open directory fds on a mounted `FsType::Cowfs`
    /// filesystem (`MountBacking::cowfs_volume_device()`). Rejects `O_PATH` (`EBADF`), non-readable
    /// fds on read ops (`EBADF`), non-root on mutating ops (`EPERM`), and read-only mounts (`EROFS`).
    pub async fn ioctl_fd(
        &self,
        vfs: &Vfs,
        pid: u32,
        fd: Fd,
        request: u32,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        self.ioctl_fd_stream(
            vfs,
            pid,
            fd,
            request,
            payload,
            IoctlStream::KernelFds(vfs, pid),
        )
        .await
    }

    pub async fn ioctl_fd_stream(
        &self,
        vfs: &Vfs,
        pid: u32,
        fd: Fd,
        request: u32,
        payload: &[u8],
        stream: IoctlStream<'_>,
    ) -> Result<Vec<u8>> {
        let cred = vfs.process_cred(pid)?;
        let fds = vfs.process_fds(pid)?;
        let file = fds.borrow().get(fd)?;
        if file.access() == Access::Path {
            return Err(Errno::EBADF);
        }
        if file.is_virtual() {
            return Err(Errno::ENOTTY);
        }
        let fd_readable = file.access().reads();
        let meta = file.metadata_as(&cred).await?;
        if meta.file_type == FileType::CharDevice {
            let Some(rdev) = meta.rdev.as_deref() else {
                return Err(Errno::ENOTTY);
            };
            let Some(dev_name) = parse_vblk_rdev(rdev) else {
                return Err(Errno::ENOTTY);
            };
            let dev = self.device_for_rdev(rdev)?;
            return Self::dispatch_stream_ioctl(
                &*dev,
                Some(dev_name),
                Some(stream),
                &cred,
                fd_readable,
                false,
                request,
                payload,
            )
            .await;
        }
        if meta.file_type == FileType::Dir
            && let Some(pin) = file.mount_pin()
            && pin.fstype() == FsType::Cowfs
            && let Some(dev) = pin.backing().cowfs_volume_device()
        {
            let mutation = match request {
                cowfs_ioctl::COWFS_IOC_RECEIVE => {
                    serde_json::from_slice::<CowfsReceiveReq>(payload).is_ok_and(|req| {
                        req.target_volume
                            .as_deref()
                            .is_none_or(|v| v == dev.volume_id())
                    })
                }
                cowfs_ioctl::COWFS_IOC_SUBVOL => matches!(
                    serde_json::from_slice::<CowfsSubvolReq>(payload),
                    Ok(CowfsSubvolReq::Create { .. } | CowfsSubvolReq::Delete { .. })
                ),
                cowfs_ioctl::COWFS_IOC_SNAPSHOT
                | cowfs_ioctl::COWFS_IOC_SNAP_DELETE
                | cowfs_ioctl::COWFS_IOC_GC => true,
                _ => false,
            };
            let _write = if mutation && cred.identity.id == 0 {
                Some(pin.begin_write()?)
            } else {
                None
            };
            return Self::dispatch_stream_ioctl(
                &**dev,
                None,
                Some(stream),
                &cred,
                fd_readable,
                pin.effective_rdonly(),
                request,
                payload,
            )
            .await;
        }
        if request == cowfs_ioctl::COWFS_IOC_MKFS {
            return Err(Errno::ENOTBLK);
        }
        Err(Errno::ENOTTY)
    }

    /// Execute `mkfs.cowfs` against `target` (`"/dev/vdN"` or `"volume:<uuid>"`).
    ///
    /// Contract §2.7 & §4:
    /// - Requires instance root (`EPERM` otherwise).
    /// - Any directory, regular file, symlink, host folder, browser-storage tree, or export
    ///   target MUST fail with `Errno::ENOTBLK` — mounting or targeting a tree never formats it.
    /// - Mounted or leased volume fails with `Errno::EBUSY`; already-formatted volume without
    ///   `force` fails with `Errno::EEXIST`.
    pub async fn mkfs_cowfs(
        &self,
        vfs: &Vfs,
        pid: u32,
        target: &str,
        force: bool,
    ) -> Result<CowfsInfoResp> {
        let cred = vfs.process_cred(pid)?;
        if cred.identity.id != 0 {
            return Err(Errno::EPERM);
        }
        if target.is_empty() {
            return Err(Errno::ENOTBLK);
        }
        if let Some(vol_id) = target.strip_prefix("volume:") {
            if vol_id.is_empty() {
                return Err(Errno::EINVAL);
            }
            let (_, dev) = self.find_by_volume(vol_id).ok_or(Errno::ENODEV)?;
            return dev.mkfs(force).await;
        }
        // Reject explicit non-block tree prefixes (hostfs:, opfs:, helperfs:, sharefs:, cloud:)
        // and trailing slashes (never valid for a block device target).
        if (target.contains(':') && !target.starts_with('/')) || target.ends_with('/') {
            return Err(Errno::ENOTBLK);
        }
        // Resolve path inside `pid`'s namespace & chroot WITHOUT following a final symlink:
        // contract §2.7 / §4 mandates `ENOTBLK` for symlink targets.
        let stat = match vfs.statat(pid, StartAnchor::AtFdCwd, target, false).await {
            Ok(s) => s,
            Err(Errno::ENOENT) => {
                // Non-existent path: if it doesn't name a /dev/vdN block device, refuse ENOTBLK.
                if target.starts_with("/dev/vd") {
                    return Err(Errno::ENOENT);
                }
                return Err(Errno::ENOTBLK);
            }
            Err(e) => return Err(e),
        };
        if (stat.mode & abi::S_IFMT) == abi::S_IFLNK || !stat.is_device() {
            return Err(Errno::ENOTBLK);
        }
        let Some(rdev) = stat.rdev.as_deref() else {
            return Err(Errno::ENOTBLK);
        };
        let dev = self.device_for_rdev(rdev).map_err(|e| {
            if e == Errno::ENOTTY {
                Errno::ENOTBLK
            } else {
                e
            }
        })?;
        dev.mkfs(force).await
    }
}
