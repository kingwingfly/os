//! `/dev/vdN` managed `cowfs` volume device registry, `BLK_INFO` / `BLK_LEASE` / `COWFS_IOC_*`
//! ioctl dispatch, and `mkfs.cowfs` target validation (`docs/architecture/contract.md` §2.7,
//! §2.16, §5; #77).

use crate::devfs::{DefaultDeviceBackend, DeviceBackend};
use crate::{Access, BoxFuture, Cred, Fd, FileType, Result, StartAnchor, Vfs, WriteAt, Written};
use abi::Errno;
use abi::contract::cowfs_ioctl;
use abi::volume::{
    BlkInfoResp, BlkLeaseResp, CowfsForkReq, CowfsForkResp, CowfsInfoResp, CowfsSnapshotReq,
    CowfsSnapshotResp,
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
    rdev.strip_prefix(VBLK_RDEV_PREFIX)
        .filter(|name| !name.is_empty())
}

/// Returns `true` if `source` names a non-block tree / host-folder / export target that
/// `mkfs.cowfs` or `mount -t cowfs` must refuse with `Errno::ENOTBLK` (contract §2.7, §4).
pub fn is_non_block_tree_source(source: &str) -> bool {
    let s = source.trim();
    if s.is_empty() {
        return true;
    }
    if s.starts_with("volume:")
        || s.starts_with("snapshot:")
        || s.starts_with("oci:")
        || s.starts_with("/dev/vd")
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
}

impl CowfsMountOptions {
    pub fn parse(data: Option<&str>) -> Result<Self> {
        let mut opts = Self {
            subvol: "@".to_string(),
            ro: false,
            excl: false,
            refresh: false,
        };
        let Some(raw) = data else {
            return Ok(opts);
        };
        for item in raw.split(',').filter(|s| !s.is_empty()) {
            match item {
                "ro" => opts.ro = true,
                "rw" => opts.ro = false,
                "excl" => opts.excl = true,
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

/// Portable backend trait implemented by managed `os-cowfs` volume devices attached at `/dev/vdN`.
pub trait VolumeDevice {
    fn volume_id(&self) -> &str;
    fn blk_info<'a>(&'a self, dev_name: &'a str) -> BoxFuture<'a, BlkInfoResp>;
    fn blk_lease(&self) -> BoxFuture<'_, BlkLeaseResp>;
    fn cowfs_info(&self) -> BoxFuture<'_, CowfsInfoResp>;
    fn cowfs_snapshot<'a>(&'a self, req: &'a CowfsSnapshotReq) -> BoxFuture<'a, CowfsSnapshotResp>;
    fn cowfs_fork<'a>(&'a self, req: &'a CowfsForkReq) -> BoxFuture<'a, CowfsForkResp>;
    fn mkfs(&self, force: bool) -> BoxFuture<'_, CowfsInfoResp>;
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
pub struct VblkRegistry {
    devices: RefCell<BTreeMap<String, Rc<dyn VolumeDevice>>>,
}

impl VblkRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach a volume device under the next free name (`vd0`, `vd1`, ...).
    pub fn attach(&self, device: Rc<dyn VolumeDevice>) -> String {
        let mut map = self.devices.borrow_mut();
        let mut idx = 0u32;
        loop {
            let name = format!("vd{idx}");
            if !map.contains_key(&name) {
                map.insert(name.clone(), device);
                return name;
            }
            idx = idx.saturating_add(1);
        }
    }

    /// Attach a volume device under an explicit `vdN` name (`EEXIST` if already taken).
    pub fn attach_named(&self, name: &str, device: Rc<dyn VolumeDevice>) -> Result<()> {
        if !name.starts_with("vd")
            || name.len() < 3
            || !name[2..].bytes().all(|b| b.is_ascii_digit())
        {
            return Err(Errno::EINVAL);
        }
        let mut map = self.devices.borrow_mut();
        if map.contains_key(name) {
            return Err(Errno::EEXIST);
        }
        map.insert(name.to_string(), device);
        Ok(())
    }

    pub fn detach(&self, name: &str) -> Result<()> {
        self.devices
            .borrow_mut()
            .remove(name)
            .map(|_| ())
            .ok_or(Errno::ENODEV)
    }

    pub fn get(&self, name: &str) -> Option<Rc<dyn VolumeDevice>> {
        self.devices.borrow().get(name).cloned()
    }

    pub fn find_by_volume(&self, volume_id: &str) -> Option<(String, Rc<dyn VolumeDevice>)> {
        self.devices
            .borrow()
            .iter()
            .find(|(_, dev)| dev.volume_id() == volume_id)
            .map(|(name, dev)| (name.clone(), Rc::clone(dev)))
    }

    /// Dispatch a `/dev/vdN` ioctl by `rdev` (`"vblk:vd0"`).
    ///
    /// Authorization (contract §2.16, §5, Blueprint §3.2):
    /// - `BLK_INFO`, `BLK_LEASE`, `COWFS_IOC_INFO`: permitted for any caller holding a readable
    ///   descriptor (or root).
    /// - `COWFS_IOC_SNAPSHOT`, `COWFS_IOC_FORK`: instance root (`uid == 0`) only (`EPERM`
    ///   otherwise).
    /// - Unknown ioctl request: `ENOTTY`.
    pub async fn ioctl_rdev(
        &self,
        cred: &Cred,
        rdev: &str,
        request: u32,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        if payload.len() > VBLK_IOCTL_PAYLOAD_MAX {
            return Err(Errno::E2BIG);
        }
        let Some(dev_name) = parse_vblk_rdev(rdev) else {
            return Err(Errno::ENOTTY);
        };
        let dev = self.get(dev_name).ok_or(Errno::ENODEV)?;
        match request {
            cowfs_ioctl::BLK_INFO => {
                let resp = dev.blk_info(dev_name).await?;
                serde_json::to_vec(&resp).map_err(|_| Errno::EIO)
            }
            cowfs_ioctl::BLK_LEASE => {
                let resp = dev.blk_lease().await?;
                serde_json::to_vec(&resp).map_err(|_| Errno::EIO)
            }
            cowfs_ioctl::COWFS_IOC_INFO => {
                let resp = dev.cowfs_info().await?;
                serde_json::to_vec(&resp).map_err(|_| Errno::EIO)
            }
            cowfs_ioctl::COWFS_IOC_SNAPSHOT => {
                if cred.identity.id != 0 {
                    return Err(Errno::EPERM);
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
            _ => Err(Errno::ENOTTY),
        }
    }

    /// Dispatch a `/dev/vdN` ioctl on an open file descriptor `fd` belonging to `pid` in `vfs`.
    /// Validates `fd` (`EBADF` if closed or `O_PATH`), confirms the target is a `/dev/vdN` node
    /// (`ENOTTY` for non-vblk files/dirs/devices), and enforces root/permission rules.
    pub async fn ioctl_fd(
        &self,
        vfs: &Vfs,
        pid: u32,
        fd: Fd,
        request: u32,
        payload: &[u8],
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
        let meta = file.metadata_as(&cred).await?;
        if meta.file_type != FileType::CharDevice {
            return Err(Errno::ENOTTY);
        }
        let Some(rdev) = meta.rdev.as_deref() else {
            return Err(Errno::ENOTTY);
        };
        self.ioctl_rdev(&cred, rdev, request, payload).await
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
        let Some(dev_name) = parse_vblk_rdev(rdev) else {
            return Err(Errno::ENOTBLK);
        };
        let dev = self.get(dev_name).ok_or(Errno::ENODEV)?;
        dev.mkfs(force).await
    }
}
