//! `/dev/vdN` [`VolumeDevice`] implementation and mounted-directory `COWFS_IOC_*` dispatch
//! (`contract.md` §2.16, §5, Blueprint §3.2).

use crate::fs::{CowFs, CowFsClock};
use abi::Errno;
use abi::contract::{Durability, WriterModel, cowfs_ioctl};
use abi::volume::{
    BlkInfoResp, BlkLeaseResp, CowfsForkReq, CowfsForkResp, CowfsFsckReq, CowfsFsckResp,
    CowfsInfoResp, CowfsSnapshotReq, CowfsSnapshotResp,
};
use cowtree::{
    BLOCK_SIZE, COWFS_FORMAT_VERSION, HeadStore, PackStore, VolumeId, WriterMode, digest_to_hex,
};
use std::rc::Rc;
use vfs::vblk::VolumeDevice;
use vfs::{BoxFuture, Cred, Filesystem, Result};

fn parse_fsck_req(payload: &[u8]) -> Result<CowfsFsckReq> {
    let trimmed = payload
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .map(|start| {
            let end = payload
                .iter()
                .rposition(|b| !b.is_ascii_whitespace())
                .map_or(start, |e| e + 1);
            &payload[start..end]
        })
        .unwrap_or(&[]);
    if trimmed.is_empty() || trimmed == b"null" {
        return Ok(CowfsFsckReq::default());
    }
    let req: CowfsFsckReq = serde_json::from_slice(trimmed).map_err(|_| Errno::EINVAL)?;
    if let Some(ref v) = req.volume
        && (v.is_empty() || v.contains(['/', '\0']))
    {
        return Err(Errno::EINVAL);
    }
    Ok(req)
}

async fn run_cowfs_fsck<H: HeadStore + 'static, P: PackStore + 'static>(
    head_store: &H,
    pack_store: &P,
    default_volume: &VolumeId,
    mounted: Option<&CowFs<H, P>>,
    req: &CowfsFsckReq,
) -> Result<CowfsFsckResp> {
    if let Some(ref v) = req.volume
        && (v.is_empty() || v.contains(['/', '\0']))
    {
        return Err(Errno::EINVAL);
    }
    if let Some(ver) = head_store.format_version().await?
        && ver != COWFS_FORMAT_VERSION
    {
        return Err(Errno::EPROTONOSUPPORT);
    }

    // Hold shared GC lock across head selection & verification so GC cannot sweep any
    // node or pack reachable from the exact head being checked.
    let _gc_guard = head_store.acquire_gc_lock(false).await?;

    let head = match &req.volume {
        Some(explicit) => {
            let target = VolumeId(explicit.clone());
            // Always look up the EXACT requested volume in `head_store` (returning `ENOENT` if
            // missing — NEVER silently verifying `default_volume`!).
            let h = head_store.read_head(&target).await?;
            if h.volume.0 != *explicit {
                return Err(Errno::ENOENT);
            }
            h
        }
        None => match mounted {
            Some(fs) if fs.is_read_only() => fs.current_head(),
            _ => head_store.read_head(default_volume).await?,
        },
    };

    if head.format_version != COWFS_FORMAT_VERSION {
        return Err(Errno::EPROTONOSUPPORT);
    }

    let report = crate::fsck::verify_head_pinned(head_store, pack_store, &head).await?;
    Ok(CowfsFsckResp {
        ok: report.ok,
        volume: head.volume.0,
        format_version: head.format_version,
        epoch: head.epoch,
        root: digest_to_hex(&head.root),
        subvols_checked: report.subvols_checked,
        nodes_verified: report.nodes_verified,
        extents_verified: report.extents_verified,
        packs_verified: report.packs_verified,
        orphan_inodes: report.orphan_inodes,
        errors: report.errors,
    })
}

/// Dispatch `COWFS_IOC_{INFO,FSCK,SNAPSHOT,FORK}` directly against a mounted [`CowFs`] instance.
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
        cowfs_ioctl::COWFS_IOC_FSCK => {
            let req = parse_fsck_req(payload)?;
            let head_store = fs.head_store_rc();
            let pack_store = fs.pack_store_rc();
            let resp =
                run_cowfs_fsck(&*head_store, &*pack_store, fs.volume_id(), Some(fs), &req).await?;
            serde_json::to_vec(&resp).map_err(|_| Errno::EIO)
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

    fn cowfs_fsck<'a>(&'a self, req: &'a CowfsFsckReq) -> BoxFuture<'a, CowfsFsckResp> {
        Box::pin(async move {
            run_cowfs_fsck(
                &*self.head_store,
                &*self.pack_store,
                &self.volume,
                self.mounted.as_deref(),
                req,
            )
            .await
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
            let _gc_guard = self.head_store.acquire_gc_lock(false).await?;
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
            // Hold shared GC lock from root selection through fork publication so GC cannot sweep
            // the selected root concurrently.
            let _gc_guard = self.head_store.acquire_gc_lock(false).await?;
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
            let _gc_guard = self.head_store.acquire_gc_lock(false).await?;
            let now = (self.clock)();
            // Refuse if another writer currently holds the volume lease (`EBUSY`).
            // On `--force`, replace the volume head, bump `incarnation`, and wipe prior snapshots
            // and receipts atomically WHILE holding the exclusive writer lease.
            let head = match self.head_store.read_head(&self.volume).await {
                Ok(_) => {
                    let lease = self
                        .head_store
                        .acquire_writer(&self.volume, WriterMode::Exclusive)
                        .await?;
                    if !force {
                        let _ = self.head_store.release_writer(lease).await;
                        return Err(Errno::EEXIST);
                    }
                    let (new_head, initial_nodes) = CowFs::<H, P>::build_initial_volume_nodes(
                        self.volume.clone(),
                        0,
                        0,
                        0o755,
                        now,
                    )?;
                    self.head_store
                        .reformat_volume_with_lease(lease, &new_head, &initial_nodes)
                        .await?
                }
                Err(Errno::ENOENT) => {
                    CowFs::format_volume(
                        &*self.head_store,
                        &*self.pack_store,
                        self.volume.clone(),
                        0,
                        0,
                        0o755,
                        now,
                    )
                    .await?
                }
                Err(e) => return Err(e),
            };
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
