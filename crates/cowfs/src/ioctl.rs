//! `/dev/vdN` [`VolumeDevice`] implementation and mounted-directory `COWFS_IOC_*` dispatch
//! (`contract.md` §2.16, §5, Blueprint §3.2).

use crate::fs::{CowFs, CowFsClock};
use abi::Errno;
use abi::contract::{Durability, WriterModel, cowfs_ioctl};
use abi::volume::{
    BlkInfoResp, BlkLeaseResp, CowfsForkReq, CowfsForkResp, CowfsInfoResp, CowfsSnapshotReq,
    CowfsSnapshotResp,
};
use cowtree::{
    BLOCK_SIZE, COWFS_FORMAT_VERSION, HeadStore, PackStore, VolumeId, WriterMode, digest_to_hex,
};
use std::rc::Rc;
use vfs::vblk::VolumeDevice;
use vfs::{BoxFuture, Cred, Filesystem, Result};

/// Dispatch `COWFS_IOC_{INFO,SNAPSHOT,FORK}` directly against a mounted [`CowFs`] instance.
pub async fn cowfs_ioctl_mounted<H: HeadStore + 'static, P: PackStore + 'static>(
    fs: &CowFs<H, P>,
    cred: &Cred,
    request: u32,
    payload: &[u8],
) -> Result<Vec<u8>> {
    match request {
        cowfs_ioctl::COWFS_IOC_INFO => {
            let info = fs.volume_info();
            serde_json::to_vec(&info).map_err(|_| Errno::EIO)
        }
        cowfs_ioctl::COWFS_IOC_SNAPSHOT => {
            if cred.identity.id != 0 {
                return Err(Errno::EPERM);
            }
            let req: CowfsSnapshotReq =
                serde_json::from_slice(payload).map_err(|_| Errno::EINVAL)?;
            let snap = fs.create_snapshot(&req.name).await?;
            let resp = CowfsSnapshotResp {
                volume: snap.volume.0,
                name: snap.name,
                root: digest_to_hex(&snap.root),
                epoch: snap.epoch,
            };
            serde_json::to_vec(&resp).map_err(|_| Errno::EIO)
        }
        cowfs_ioctl::COWFS_IOC_FORK => {
            if cred.identity.id != 0 {
                return Err(Errno::EPERM);
            }
            let req: CowfsForkReq = serde_json::from_slice(payload).map_err(|_| Errno::EINVAL)?;
            let forked = fs
                .fork_volume(
                    req.snapshot.as_deref(),
                    VolumeId(req.new_volume.clone()),
                    req.ephemeral_if_unmodified,
                )
                .await?;
            let resp = CowfsForkResp {
                volume: forked.volume.0,
                parent_volume: forked
                    .parent_volume
                    .map(|v| v.0)
                    .unwrap_or_else(|| fs.volume_id().0.clone()),
                root: digest_to_hex(&forked.root),
                epoch: forked.epoch,
            };
            serde_json::to_vec(&resp).map_err(|_| Errno::EIO)
        }
        _ => Err(Errno::ENOTTY),
    }
}

/// Managed `os-cowfs` volume device attachable at `/dev/vdN` via `vfs::vblk::VblkRegistry`.
pub struct CowFsVolumeDevice<H: HeadStore + 'static, P: PackStore + 'static> {
    volume: VolumeId,
    head_store: Rc<H>,
    pack_store: Rc<P>,
    mounted: Option<Rc<CowFs<H, P>>>,
    writer_model: WriterModel,
    durability: Durability,
    read_only: bool,
    clock: CowFsClock,
}

impl<H: HeadStore + 'static, P: PackStore + 'static> CowFsVolumeDevice<H, P> {
    /// Wrap a currently mounted [`CowFs`] volume as a `/dev/vdN` device.
    pub fn from_mounted(fs: Rc<CowFs<H, P>>) -> Self {
        let caps = fs.capabilities();
        let volume = fs.volume_id().clone();
        let head_store = fs.head_store_rc();
        let pack_store = fs.pack_store_rc();
        let read_only = fs.is_read_only();
        let clock = fs.clock_rc();
        Self {
            volume,
            head_store,
            pack_store,
            mounted: Some(fs),
            writer_model: caps.writer_model,
            durability: caps.durability,
            read_only,
            clock,
        }
    }

    /// Wrap an unmounted volume slot backed by `head_store` / `pack_store` (supports `mkfs.cowfs`,
    /// `BLK_INFO`, `BLK_LEASE`, `COWFS_IOC_{INFO,FORK}`).
    pub fn unmounted(
        volume: VolumeId,
        head_store: Rc<H>,
        pack_store: Rc<P>,
        writer_model: WriterModel,
        durability: Durability,
        clock: CowFsClock,
    ) -> Self {
        Self {
            volume,
            head_store,
            pack_store,
            mounted: None,
            writer_model,
            durability,
            read_only: false,
            clock,
        }
    }
}

impl<H: HeadStore + 'static, P: PackStore + 'static> VolumeDevice for CowFsVolumeDevice<H, P> {
    fn volume_id(&self) -> &str {
        &self.volume.0
    }

    fn blk_info<'a>(&'a self, dev_name: &'a str) -> BoxFuture<'a, BlkInfoResp> {
        Box::pin(async move {
            let formatted = if self.mounted.is_some() {
                true
            } else {
                self.head_store.read_head(&self.volume).await.is_ok()
            };
            Ok(BlkInfoResp {
                device: format!("/dev/{dev_name}"),
                volume: self.volume.0.clone(),
                size: 0,
                sector: BLOCK_SIZE,
                writer_model: self.writer_model,
                durability: self.durability,
                read_only: self.read_only,
                formatted,
            })
        })
    }

    fn blk_lease(&self) -> BoxFuture<'_, BlkLeaseResp> {
        Box::pin(async move {
            if let Some(fs) = &self.mounted {
                let info = fs.volume_info();
                return Ok(BlkLeaseResp {
                    volume: info.volume,
                    held: !info.read_only,
                    incarnation: info.incarnation,
                    fence: info.fence,
                    epoch: info.epoch,
                    read_only: info.read_only,
                });
            }
            let head = self.head_store.read_head(&self.volume).await?;
            Ok(BlkLeaseResp {
                volume: head.volume.0,
                held: false,
                incarnation: head.incarnation,
                fence: head.fence,
                epoch: head.epoch,
                read_only: self.read_only,
            })
        })
    }

    fn cowfs_info(&self) -> BoxFuture<'_, CowfsInfoResp> {
        Box::pin(async move {
            if let Some(fs) = &self.mounted {
                return Ok(fs.volume_info());
            }
            let head = self.head_store.read_head(&self.volume).await?;
            Ok(CowfsInfoResp {
                format_version: head.format_version,
                volume: head.volume.0,
                root: digest_to_hex(&head.root),
                incarnation: head.incarnation,
                fence: head.fence,
                epoch: head.epoch,
                writer_model: self.writer_model,
                durability: self.durability,
                read_only: self.read_only,
                parent_volume: head.parent_volume.map(|v| v.0),
            })
        })
    }

    fn cowfs_snapshot<'a>(&'a self, req: &'a CowfsSnapshotReq) -> BoxFuture<'a, CowfsSnapshotResp> {
        Box::pin(async move {
            if let Some(fs) = &self.mounted {
                let snap = fs.create_snapshot(&req.name).await?;
                return Ok(CowfsSnapshotResp {
                    volume: snap.volume.0,
                    name: snap.name,
                    root: digest_to_hex(&snap.root),
                    epoch: snap.epoch,
                });
            }
            let head = self.head_store.read_head(&self.volume).await?;
            let now = (self.clock)();
            let snap = self
                .head_store
                .create_snapshot(&self.volume, &req.name, &head, now)
                .await?;
            Ok(CowfsSnapshotResp {
                volume: snap.volume.0,
                name: snap.name,
                root: digest_to_hex(&snap.root),
                epoch: snap.epoch,
            })
        })
    }

    fn cowfs_fork<'a>(&'a self, req: &'a CowfsForkReq) -> BoxFuture<'a, CowfsForkResp> {
        Box::pin(async move {
            if let Some(fs) = &self.mounted {
                let forked = fs
                    .fork_volume(
                        req.snapshot.as_deref(),
                        VolumeId(req.new_volume.clone()),
                        req.ephemeral_if_unmodified,
                    )
                    .await?;
                return Ok(CowfsForkResp {
                    volume: forked.volume.0,
                    parent_volume: forked
                        .parent_volume
                        .map(|v| v.0)
                        .unwrap_or_else(|| self.volume.0.clone()),
                    root: digest_to_hex(&forked.root),
                    epoch: forked.epoch,
                });
            }
            let source_root = match &req.snapshot {
                Some(snap_name) => {
                    self.head_store
                        .get_snapshot(&self.volume, snap_name)
                        .await?
                        .root
                }
                None => self.head_store.read_head(&self.volume).await?.root,
            };
            let fork_req = cowtree::ForkRequest {
                source_volume: self.volume.clone(),
                source_snapshot: req.snapshot.clone(),
                source_root,
                new_volume: VolumeId(req.new_volume.clone()),
                ephemeral_if_unmodified: req.ephemeral_if_unmodified,
                created_at: (self.clock)(),
            };
            let forked = self.head_store.fork_volume(&fork_req).await?;
            Ok(CowfsForkResp {
                volume: forked.volume.0,
                parent_volume: forked
                    .parent_volume
                    .map(|v| v.0)
                    .unwrap_or_else(|| self.volume.0.clone()),
                root: digest_to_hex(&forked.root),
                epoch: forked.epoch,
            })
        })
    }

    fn mkfs(&self, force: bool) -> BoxFuture<'_, CowfsInfoResp> {
        Box::pin(async move {
            if self.mounted.is_some() {
                return Err(Errno::EBUSY);
            }
            // Refuse if another writer currently holds the volume lease (`EBUSY`).
            match self.head_store.read_head(&self.volume).await {
                Ok(_) => {
                    // Check writer lock before deciding EBUSY vs EEXIST.
                    let lease = self
                        .head_store
                        .acquire_writer(&self.volume, WriterMode::Exclusive)
                        .await?;
                    self.head_store.release_writer(lease).await?;
                    if !force {
                        return Err(Errno::EEXIST);
                    }
                    self.head_store.delete_volume(&self.volume).await?;
                }
                Err(Errno::ENOENT) => {}
                Err(e) => return Err(e),
            }
            let head = CowFs::format_volume(
                &*self.head_store,
                &*self.pack_store,
                self.volume.clone(),
                0,
                0,
                0o755,
                (self.clock)(),
            )
            .await?;
            Ok(CowfsInfoResp {
                format_version: COWFS_FORMAT_VERSION,
                volume: head.volume.0,
                root: digest_to_hex(&head.root),
                incarnation: head.incarnation,
                fence: head.fence,
                epoch: head.epoch,
                writer_model: self.writer_model,
                durability: self.durability,
                read_only: false,
                parent_volume: None,
            })
        })
    }
}
