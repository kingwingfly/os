//! `/dev/loop-control` and `/dev/loop0..7` read-only pack archive & image loop devices
//! (`docs/architecture/contract.md` §2.16, §5; #79 `L2.5c`).
//!
//! - `/dev/loop-control` (`0660`, rdev `"loop:control"`): `LOOP_CTL_GET_FREE` (root only -> lowest
//!   unbound index `0..8`, or `ENODEV` if all 8 slots are bound).
//! - `/dev/loop0..7` (`0660`, rdev `"loop:loopN"`):
//!   - `LOOP_SET_FD` (root only): pins a regular readable `FileRef` (surviving unlink), probes the
//!     16-byte `OSCOWA1\0` header + 96-byte `OSCOWA1F` footer to classify `"cowpack-v1"` vs `"raw"`,
//!     and forces `read_only = true` for `"cowpack-v1"` archives or read-only fds.
//!   - `LOOP_CLR_FD` (root only): refuses `EBUSY` while `mount_count > 0`, otherwise drops the
//!     pinned `FileRef`.
//!   - `LOOP_GET_STATUS64`: returns [`LoopStatus64`] JSON (`ENXIO` if unbound).

use crate::devfs::{DefaultDeviceBackend, DeviceBackend};
use crate::{Access, BoxFuture, Cred, Fd, FileRef, FileType, Result, Vfs, WriteAt, Written};
use abi::Errno;
use abi::contract::loop_ioctl;
use abi::volume::LoopStatus64;
use std::cell::RefCell;
use std::rc::Rc;

/// `rdev` string for `/dev/loop-control`.
pub const LOOP_CONTROL_RDEV: &str = "loop:control";
/// `rdev` prefix for `/dev/loopN` (`"loop:loop0"`..`"loop:loop7"`).
pub const LOOP_RDEV_PREFIX: &str = "loop:";
/// Number of pre-created `/dev/loop0..7` device slots.
pub const LOOP_COUNT: usize = 8;

const ARCHIVE_HEADER_MAGIC: [u8; 8] = *b"OSCOWA1\0";
const ARCHIVE_FOOTER_MAGIC: [u8; 8] = *b"OSCOWA1F";
const ARCHIVE_VERSION: u16 = 1;
const ARCHIVE_HEADER_BYTES: usize = 16;
const ARCHIVE_FOOTER_BYTES: usize = 96;

/// Format the `rdev` tag for `/dev/loopN` (`"loop:loop0"`).
pub fn loop_rdev(name: &str) -> String {
    format!("{LOOP_RDEV_PREFIX}{name}")
}

/// Returns `true` iff `rdev` identifies `/dev/loop-control`.
pub fn is_loop_control_rdev(rdev: &str) -> bool {
    rdev == LOOP_CONTROL_RDEV
}

/// Extract slot index `0..LOOP_COUNT` from a `loop:loopN` `rdev` string.
pub fn parse_loop_rdev(rdev: &str) -> Option<usize> {
    let rest = rdev.strip_prefix("loop:loop")?;
    if rest.len() != 1 || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let idx: usize = rest.parse().ok()?;
    (idx < LOOP_COUNT).then_some(idx)
}

/// Extract slot index `0..LOOP_COUNT` from a `/dev/loopN` device path.
pub fn parse_loop_device_path(path: &str) -> Option<usize> {
    let rest = path.strip_prefix("/dev/loop")?;
    if rest.len() != 1 || !rest.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let idx: usize = rest.parse().ok()?;
    (idx < LOOP_COUNT).then_some(idx)
}

/// Returns `true` iff `path` names one of `/dev/loop0`..`/dev/loop7`.
pub fn is_loop_device_path(path: &str) -> bool {
    parse_loop_device_path(path).is_some()
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Active backing-file binding stored in a [`LoopSlot`].
pub struct LoopBinding {
    pub file: FileRef,
    pub read_only: bool,
    pub backing_dev: u64,
    pub backing_ino: u64,
    pub backing_size: u64,
    pub offset: u64,
    pub sizelimit: u64,
    pub archive_format: String,
    pub root_digest: Option<String>,
    pub file_name: String,
}

/// State of one `/dev/loopN` device slot.
pub struct LoopSlot {
    pub index: usize,
    pub backing: Option<LoopBinding>,
    pub mount_count: usize,
}

impl LoopSlot {
    fn new(index: usize) -> Self {
        Self {
            index,
            backing: None,
            mount_count: 0,
        }
    }

    fn status(&self) -> Option<LoopStatus64> {
        let b = self.backing.as_ref()?;
        Some(LoopStatus64 {
            device: format!("loop{}", self.index),
            bound: true,
            read_only: b.read_only,
            mounted: self.mount_count > 0,
            backing_dev: b.backing_dev,
            backing_ino: b.backing_ino,
            backing_size: b.backing_size,
            offset: b.offset,
            sizelimit: b.sizelimit,
            archive_format: b.archive_format.clone(),
            root_digest: b.root_digest.clone(),
            file_name: b.file_name.clone(),
        })
    }
}

/// RAII mount-reference guard keeping `LoopSlot::mount_count > 0` while a `/dev/loopN` mount is
/// active (so `LOOP_CLR_FD` strictly returns `Errno::EBUSY` until the mount and all its pins drop).
pub struct LoopMountGuard {
    slots: Rc<RefCell<Vec<LoopSlot>>>,
    index: usize,
}

impl Drop for LoopMountGuard {
    fn drop(&mut self) {
        if let Ok(mut slots) = self.slots.try_borrow_mut()
            && let Some(slot) = slots.get_mut(self.index)
        {
            slot.mount_count = slot.mount_count.saturating_sub(1);
        }
    }
}

/// Registry managing `/dev/loop0`..`/dev/loop7` bindings and mount-reference counts.
#[derive(Clone)]
pub struct LoopRegistry {
    slots: Rc<RefCell<Vec<LoopSlot>>>,
}

impl Default for LoopRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl LoopRegistry {
    pub fn new() -> Self {
        let slots = (0..LOOP_COUNT).map(LoopSlot::new).collect();
        Self {
            slots: Rc::new(RefCell::new(slots)),
        }
    }

    /// Return the lowest unbound slot index `0..LOOP_COUNT` (`LOOP_CTL_GET_FREE`, root only).
    pub fn get_free(&self, cred: &Cred) -> Result<u32> {
        if cred.identity.id != 0 {
            return Err(Errno::EPERM);
        }
        let slots = self.slots.borrow();
        for slot in slots.iter() {
            if slot.backing.is_none() {
                return Ok(slot.index as u32);
            }
        }
        Err(Errno::ENODEV)
    }

    /// Bind an open regular readable file descriptor `backing_fd` from `pid` onto `/dev/loop{index}`
    /// (`LOOP_SET_FD`, root only).
    pub async fn set_fd(
        &self,
        vfs: &Vfs,
        pid: u32,
        index: usize,
        backing_fd: Fd,
    ) -> Result<LoopStatus64> {
        let cred = vfs.process_cred(pid)?;
        if cred.identity.id != 0 {
            return Err(Errno::EPERM);
        }
        if index >= LOOP_COUNT {
            return Err(Errno::ENODEV);
        }
        if self.slots.borrow()[index].backing.is_some() {
            return Err(Errno::EBUSY);
        }

        let fds = vfs.process_fds(pid)?;
        let file = fds.borrow().get(backing_fd)?;
        if file.access() == Access::Path || !file.access().reads() {
            return Err(Errno::EBADF);
        }
        if file.is_virtual() {
            return Err(Errno::EINVAL);
        }

        let meta = file.metadata_as(&cred).await?;
        if meta.file_type != FileType::File {
            return Err(Errno::EINVAL);
        }
        let backing_size = meta.size;
        let backing_dev = file.handle().fs.dev();
        let backing_ino = file.handle().node.ino;

        // Probe 16-byte `OSCOWA1\0` header and 96-byte `OSCOWA1F` footer via zero-copy `read_at`.
        let (archive_format, root_digest, is_archive) =
            probe_cowpack_header_footer(&file, backing_size).await?;
        let read_only = is_archive || !file.access().writes();

        // Best-effort backing path for `losetup -a` display (via `/proc/self/fd/<backing_fd>`).
        let file_name = vfs
            .readlinkat(
                pid,
                crate::StartAnchor::Root,
                &format!("/proc/self/fd/{backing_fd}"),
            )
            .await
            .unwrap_or_else(|_| format!("ino:{backing_ino}"));

        let mut slots = self.slots.borrow_mut();
        let slot = slots.get_mut(index).ok_or(Errno::ENODEV)?;
        if slot.backing.is_some() {
            return Err(Errno::EBUSY);
        }
        slot.backing = Some(LoopBinding {
            file,
            read_only,
            backing_dev,
            backing_ino,
            backing_size,
            offset: 0,
            sizelimit: backing_size,
            archive_format,
            root_digest,
            file_name,
        });
        slot.status().ok_or(Errno::EIO)
    }

    /// Detach `/dev/loop{index}` (`LOOP_CLR_FD`, root only; refuses `EBUSY` while mounted).
    pub async fn clr_fd(&self, cred: &Cred, index: usize) -> Result<()> {
        if cred.identity.id != 0 {
            return Err(Errno::EPERM);
        }
        let detached = {
            let mut slots = self.slots.borrow_mut();
            let slot = slots.get_mut(index).ok_or(Errno::ENODEV)?;
            if slot.backing.is_none() {
                return Err(Errno::ENXIO);
            }
            if slot.mount_count > 0 {
                return Err(Errno::EBUSY);
            }
            slot.backing.take()
        };
        if let Some(binding) = detached {
            let _ = binding.file.close().await;
        }
        Ok(())
    }

    /// Query binding status of `/dev/loop{index}` (`LOOP_GET_STATUS64`; `ENXIO` if unbound).
    pub fn get_status64(&self, index: usize) -> Result<LoopStatus64> {
        let slots = self.slots.borrow();
        let slot = slots.get(index).ok_or(Errno::ENODEV)?;
        slot.status().ok_or(Errno::ENXIO)
    }

    /// Returns `true` if `/dev/loop{index}` is currently bound in read-only mode.
    pub fn is_bound_read_only(&self, index: usize) -> bool {
        self.slots
            .borrow()
            .get(index)
            .and_then(|s| s.backing.as_ref())
            .is_some_and(|b| b.read_only)
    }

    /// Clone the pinned backing `FileRef` + metadata for read-only inspection (`cowfsck /dev/loopN`
    /// or `LoopDeviceBackend::read_device`).
    fn io_binding(&self, index: usize) -> Result<(FileRef, bool, u64, u64)> {
        let slots = self.slots.borrow();
        let binding = slots
            .get(index)
            .ok_or(Errno::ENODEV)?
            .backing
            .as_ref()
            .ok_or(Errno::ENXIO)?;
        Ok((
            binding.file.clone(),
            binding.read_only,
            binding.offset,
            binding.sizelimit,
        ))
    }

    pub fn backing_file(&self, index: usize) -> Result<(FileRef, bool, String, String)> {
        let slots = self.slots.borrow();
        let slot = slots.get(index).ok_or(Errno::ENODEV)?;
        let b = slot.backing.as_ref().ok_or(Errno::ENXIO)?;
        Ok((
            b.file.clone(),
            b.read_only,
            b.archive_format.clone(),
            b.file_name.clone(),
        ))
    }

    /// Acquire a mount reference on `/dev/loop{index}` (incrementing `mount_count` until the
    /// returned [`LoopMountGuard`] drops). Fails with `ENXIO` if unbound and `EROFS` if
    /// `want_writable` is true while the loop device is read-only.
    pub fn acquire_mount(
        &self,
        index: usize,
        want_writable: bool,
    ) -> Result<(FileRef, bool, String, LoopMountGuard)> {
        let mut slots = self.slots.borrow_mut();
        let slot = slots.get_mut(index).ok_or(Errno::ENODEV)?;
        let b = slot.backing.as_ref().ok_or(Errno::ENXIO)?;
        if b.read_only && want_writable {
            return Err(Errno::EROFS);
        }
        slot.mount_count = slot.mount_count.saturating_add(1);
        let file = b.file.clone();
        let read_only = b.read_only;
        let archive_format = b.archive_format.clone();
        drop(slots);
        Ok((
            file,
            read_only,
            archive_format,
            LoopMountGuard {
                slots: Rc::clone(&self.slots),
                index,
            },
        ))
    }

    /// Dispatch `LOOP_CTL_GET_FREE`, `LOOP_SET_FD`, `LOOP_CLR_FD`, or `LOOP_GET_STATUS64` on an
    /// open descriptor `fd` belonging to `pid`.
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

        match request {
            loop_ioctl::LOOP_CTL_GET_FREE => {
                if !is_loop_control_rdev(rdev) {
                    return Err(Errno::ENOTTY);
                }
                let free = self.get_free(&cred)?;
                serde_json::to_vec(&free).map_err(|_| Errno::EIO)
            }
            loop_ioctl::LOOP_SET_FD => {
                let idx = parse_loop_rdev(rdev).ok_or(Errno::ENOTTY)?;
                if cred.identity.id != 0 {
                    return Err(Errno::EPERM);
                }
                let backing_fd: Fd = serde_json::from_slice(payload).map_err(|_| Errno::EINVAL)?;
                let status = self.set_fd(vfs, pid, idx, backing_fd).await?;
                serde_json::to_vec(&status).map_err(|_| Errno::EIO)
            }
            loop_ioctl::LOOP_CLR_FD => {
                let idx = parse_loop_rdev(rdev).ok_or(Errno::ENOTTY)?;
                self.clr_fd(&cred, idx).await?;
                Ok(b"null".to_vec())
            }
            loop_ioctl::LOOP_GET_STATUS64 => {
                let idx = parse_loop_rdev(rdev).ok_or(Errno::ENOTTY)?;
                if !file.access().reads() && cred.identity.id != 0 {
                    return Err(Errno::EBADF);
                }
                let status = self.get_status64(idx)?;
                serde_json::to_vec(&status).map_err(|_| Errno::EIO)
            }
            _ => Err(Errno::ENOTTY),
        }
    }
}

async fn read_exact_at(file: &FileRef, offset: u64, len: usize) -> Result<Vec<u8>> {
    let mut out = vec![0u8; len];
    let mut got = 0usize;
    while got < len {
        let n = file.read_at(&mut out[got..], offset + got as u64).await?;
        if n == 0 {
            return Err(Errno::EIO);
        }
        got += n;
    }
    Ok(out)
}

async fn probe_cowpack_header_footer(
    file: &FileRef,
    size: u64,
) -> Result<(String, Option<String>, bool)> {
    if size < 8 {
        return Ok(("raw".into(), None, false));
    }
    let header = read_exact_at(file, 0, size.min(ARCHIVE_HEADER_BYTES as u64) as usize).await?;
    if header[..8] != ARCHIVE_HEADER_MAGIC {
        return Ok(("raw".into(), None, false));
    }
    if size < (ARCHIVE_HEADER_BYTES + ARCHIVE_FOOTER_BYTES) as u64 {
        return Err(Errno::EIO);
    }
    let hdr_ver = u16::from_be_bytes([header[8], header[9]]);
    let footer = read_exact_at(
        file,
        size - ARCHIVE_FOOTER_BYTES as u64,
        ARCHIVE_FOOTER_BYTES,
    )
    .await?;
    if footer[..8] != ARCHIVE_FOOTER_MAGIC || header[10..16] != [0; 6] || footer[10..16] != [0; 6] {
        return Err(Errno::EIO);
    }
    let ftr_ver = u16::from_be_bytes([footer[8], footer[9]]);
    if hdr_ver != ARCHIVE_VERSION || ftr_ver != ARCHIVE_VERSION {
        return Err(Errno::EPROTONOSUPPORT);
    }
    let root_hex = hex_digest(&footer[32..64]);
    Ok(("cowpack-v1".to_string(), Some(root_hex), true))
}

/// `DeviceBackend` decorator handling `/dev/loop0..7` raw `read_at`/`write_at` proxied directly to
/// the slot's pinned `FileRef` (enforcing `EROFS` on read-only slots and `ENXIO` when unbound).
#[derive(Clone)]
pub struct LoopDeviceBackend<D = DefaultDeviceBackend> {
    registry: LoopRegistry,
    inner: D,
}

impl<D> LoopDeviceBackend<D> {
    pub fn new(registry: LoopRegistry, inner: D) -> Self {
        Self { registry, inner }
    }

    pub fn registry(&self) -> &LoopRegistry {
        &self.registry
    }
}

impl<D: DeviceBackend> DeviceBackend for LoopDeviceBackend<D> {
    fn open_device(&self, rdev: &str, cred: &Cred, open: &crate::OpenRef) -> Result<()> {
        if is_loop_control_rdev(rdev) || parse_loop_rdev(rdev).is_some() {
            return Ok(());
        }
        self.inner.open_device(rdev, cred, open)
    }

    fn release_device(&self, open: &crate::OpenRef) {
        self.inner.release_device(open);
    }

    fn poll_device(
        &self,
        rdev: &str,
        open: &crate::OpenRef,
        writing: bool,
    ) -> Result<Option<usize>> {
        if is_loop_control_rdev(rdev) || parse_loop_rdev(rdev).is_some() {
            return Ok(None);
        }
        self.inner.poll_device(rdev, open, writing)
    }

    fn fill_random(&self, buf: &mut [u8]) -> Result<()> {
        self.inner.fill_random(buf)
    }

    fn read_open_device<'a>(
        &'a self,
        rdev: &'a str,
        open: &'a crate::OpenRef,
        buf: &'a mut [u8],
        offset: u64,
    ) -> BoxFuture<'a, usize> {
        if is_loop_control_rdev(rdev) || parse_loop_rdev(rdev).is_some() {
            return self.read_device(rdev, buf, offset);
        }
        self.inner.read_open_device(rdev, open, buf, offset)
    }

    fn write_open_device<'a>(
        &'a self,
        rdev: &'a str,
        open: &'a crate::OpenRef,
        buf: &'a [u8],
        at: WriteAt,
    ) -> BoxFuture<'a, Written> {
        if is_loop_control_rdev(rdev) || parse_loop_rdev(rdev).is_some() {
            return self.write_device(rdev, buf, at);
        }
        self.inner.write_open_device(rdev, open, buf, at)
    }

    fn read_device<'a>(
        &'a self,
        rdev: &'a str,
        buf: &'a mut [u8],
        offset: u64,
    ) -> BoxFuture<'a, usize> {
        if is_loop_control_rdev(rdev) {
            return Box::pin(async { Err(Errno::EINVAL) });
        }
        if let Some(idx) = parse_loop_rdev(rdev) {
            return Box::pin(async move {
                let (file, _, start, capacity) = self.registry.io_binding(idx)?;
                let n = buf
                    .len()
                    .min(usize::try_from(capacity.saturating_sub(offset)).unwrap_or(usize::MAX));
                if n == 0 {
                    return Ok(0);
                }
                file.read_at(&mut buf[..n], start.checked_add(offset).ok_or(Errno::EIO)?)
                    .await
            });
        }
        self.inner.read_device(rdev, buf, offset)
    }

    fn write_device<'a>(
        &'a self,
        rdev: &'a str,
        buf: &'a [u8],
        at: WriteAt,
    ) -> BoxFuture<'a, Written> {
        if is_loop_control_rdev(rdev) {
            return Box::pin(async { Err(Errno::EINVAL) });
        }
        if let Some(idx) = parse_loop_rdev(rdev) {
            return Box::pin(async move {
                let (file, read_only, start, capacity) = self.registry.io_binding(idx)?;
                if read_only {
                    return Err(Errno::EROFS);
                }
                let off = match at {
                    WriteAt::Offset(o) => o,
                    WriteAt::End => capacity,
                };
                let n = buf
                    .len()
                    .min(usize::try_from(capacity.saturating_sub(off)).unwrap_or(usize::MAX));
                if n == 0 && !buf.is_empty() {
                    return Err(Errno::ENOSPC);
                }
                let len = file
                    .write_positioned(
                        file.cred(),
                        &buf[..n],
                        WriteAt::Offset(start.checked_add(off).ok_or(Errno::EIO)?),
                    )
                    .await?;
                Ok(Written { offset: off, len })
            });
        }
        self.inner.write_device(rdev, buf, at)
    }

    fn sync_device<'a>(&'a self, rdev: &'a str) -> BoxFuture<'a, ()> {
        if is_loop_control_rdev(rdev) || parse_loop_rdev(rdev).is_some() {
            return Box::pin(async { Err(Errno::EINVAL) });
        }
        self.inner.sync_device(rdev)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devfs::DevTmpFs;
    use crate::memfs::MemFs;
    use crate::{DefaultFilesystemFactory, FsId, FsType, MountBacking, MountFlags};
    use crate::{StartAnchor, now_or_never};
    use abi::contract::mount_flags;

    fn run<F: std::future::Future>(f: F) -> F::Output {
        now_or_never(f).expect("sync future")
    }

    #[test]
    fn loop_registry_enforces_root_regular_file_mount_busy_and_rofs() {
        let clock: Rc<dyn Fn() -> (u64, u32)> = Rc::new(|| (1_700_000_000, 0));
        let root_fs = Rc::new(MemFs::new(
            FsId("mem:root".into()),
            1,
            0,
            0,
            0o755,
            Box::new(|| (1_700_000_000, 0)),
        ));
        let factory = Rc::new(DefaultFilesystemFactory::new(clock));
        let vfs = run(Vfs::boot(
            "loop-test",
            Rc::new(MountBacking::new(root_fs, FsType::TmpFs)),
            "tmpfs",
            factory,
        ))
        .unwrap();
        let loops = LoopRegistry::new();
        let dev_fs = Rc::new(DevTmpFs::new(
            FsId("devtmpfs".into()),
            1,
            Box::new(|| (1_700_000_000, 0)),
            LoopDeviceBackend::new(loops.clone(), DefaultDeviceBackend),
        ));
        dev_fs.register_loop_devices().unwrap();
        run(vfs.mkdirat(1, StartAnchor::Root, "/dev", 0o755)).unwrap();
        run(vfs.mount_on_namespace(
            &vfs.system_namespace(),
            &Cred::root(),
            Rc::new(MountBacking::new(dev_fs, FsType::DevTmpFs)),
            None,
            "devtmpfs",
            "/dev",
            MountFlags::from_accepted(mount_flags::MS_NOSUID),
            0,
            None,
        ))
        .unwrap();

        // Spawn unprivileged uid 1000 process.
        let user = Cred::new(os_core::permissions::Identity {
            id: 1000,
            group: 1000,
            groups: std::collections::BTreeSet::from([1000]),
        });
        vfs.spawn_process(2, 1, user.clone(), None, None, None)
            .unwrap();

        // Create backing file and directory.
        let img_fd = run(vfs.openat(
            1,
            StartAnchor::Root,
            "/img.bin",
            abi::O_CREAT | abi::O_RDWR,
            0o644,
        ))
        .unwrap();
        run(vfs.write(1, img_fd, b"hello loop world")).unwrap();
        run(vfs.close(1, img_fd)).unwrap();
        run(vfs.mkdirat(1, StartAnchor::Root, "/adir", 0o755)).unwrap();

        // Non-root LOOP_CTL_GET_FREE -> EPERM.
        assert_eq!(loops.get_free(&user), Err(Errno::EPERM));
        assert_eq!(loops.get_free(&Cred::root()), Ok(0));

        // Directory fd -> EINVAL.
        let dir_fd = run(vfs.openat(
            1,
            StartAnchor::Root,
            "/adir",
            abi::O_RDONLY | abi::O_DIRECTORY,
            0,
        ))
        .unwrap();
        assert_eq!(run(loops.set_fd(&vfs, 1, 0, dir_fd)), Err(Errno::EINVAL));
        run(vfs.close(1, dir_fd)).unwrap();

        // O_PATH fd -> EBADF.
        let path_fd = run(vfs.openat(1, StartAnchor::Root, "/img.bin", abi::O_PATH, 0)).unwrap();
        assert_eq!(run(loops.set_fd(&vfs, 1, 0, path_fd)), Err(Errno::EBADF));
        run(vfs.close(1, path_fd)).unwrap();

        // Valid O_RDONLY regular file binds read-only; reads work via /dev/loop0, writes -> EROFS.
        let ro_fd = run(vfs.openat(1, StartAnchor::Root, "/img.bin", abi::O_RDONLY, 0)).unwrap();
        let status = run(loops.set_fd(&vfs, 1, 0, ro_fd)).unwrap();
        assert!(status.bound);
        assert!(status.read_only);
        assert_eq!(status.archive_format, "raw");
        run(vfs.close(1, ro_fd)).unwrap();

        // Unlinking /img.bin keeps pinned FileRef readable through /dev/loop0!
        run(vfs.unlinkat(1, StartAnchor::Root, "/img.bin", false)).unwrap();
        let lfd = run(vfs.openat(1, StartAnchor::Root, "/dev/loop0", abi::O_RDWR, 0)).unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(run(vfs.pread(1, lfd, &mut buf, 0)).unwrap(), 16);
        assert_eq!(&buf, b"hello loop world");
        assert_eq!(run(vfs.write(1, lfd, b"nope")), Err(Errno::EROFS));
        run(vfs.close(1, lfd)).unwrap();

        // Acquire mount -> LOOP_CLR_FD returns EBUSY until guard drops!
        let (_f, _ro, _fmt, guard) = loops.acquire_mount(0, false).unwrap();
        assert_eq!(run(loops.clr_fd(&Cred::root(), 0)), Err(Errno::EBUSY));
        drop(guard);
        run(loops.clr_fd(&Cred::root(), 0)).unwrap();
        assert_eq!(loops.get_status64(0), Err(Errno::ENXIO));
    }
}
