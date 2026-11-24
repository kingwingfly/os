//! `/dev/vdN` [`VolumeDevice`] implementation and mounted-directory `COWFS_IOC_*` dispatch
//! (`contract.md` §2.16, §5, Blueprint §3.2, #79 `L2.5c`).

use crate::fs::{CowFs, CowFsClock, CowFsConfig, CowFsOpenMode};
use crate::send_recv::{ReceiveTarget, StreamSink, StreamSource, receive_snapshot, send_snapshot};
use abi::Errno;
use abi::contract::{Durability, WriterModel, cowfs_ioctl};
use abi::volume::{
    BlkInfoResp, BlkLeaseResp, CowfsForkReq, CowfsForkResp, CowfsFsckReq, CowfsFsckResp,
    CowfsGcReq, CowfsGcResp, CowfsInfoResp, CowfsMkfsReq, CowfsReceiveReq, CowfsReceiveResp,
    CowfsSendReq, CowfsSendResp, CowfsSnapDeleteReq, CowfsSnapEntry, CowfsSnapListResp,
    CowfsSnapshotReq, CowfsSnapshotResp, CowfsSubvolEntry, CowfsSubvolReq, CowfsSubvolResp,
};
use cowtree::{
    BLOCK_SIZE, COWFS_FORMAT_VERSION, HeadStore, PackStore, RootObject, VolumeId, WriterMode,
    digest_to_hex,
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
    if let Some(ref s) = req.snapshot
        && (s.is_empty() || s.contains(['/', '\0']))
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
    if let Some(ref s) = req.snapshot
        && (s.is_empty() || s.contains(['/', '\0']))
    {
        return Err(Errno::EINVAL);
    }
    let target = req
        .volume
        .as_ref()
        .map(|v| VolumeId(v.clone()))
        .unwrap_or_else(|| default_volume.clone());
    let exact = mounted
        .filter(|fs| fs.is_read_only() && req.volume.is_none() && req.snapshot.is_none())
        .map(|fs| fs.current_head());
    let (head, report) = if target != *default_volume
        && let Some((head, packs)) = head_store.scoped_stores(&target)
    {
        crate::fsck::verify_view(&*head, &packs, &target, req.snapshot.as_deref(), None).await?
    } else {
        crate::fsck::verify_view(
            head_store,
            pack_store,
            &target,
            req.snapshot.as_deref(),
            exact.as_ref(),
        )
        .await?
    };
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

/// Dispatch `COWFS_IOC_*` directly against a mounted [`CowFs`] instance (non-fd ioctls).
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
        cowfs_ioctl::COWFS_IOC_SUBVOL => {
            let req: CowfsSubvolReq = serde_json::from_slice(payload).map_err(|_| Errno::EINVAL)?;
            match req {
                CowfsSubvolReq::List {} => {}
                CowfsSubvolReq::Create { name } => {
                    if cred.identity.id != 0 {
                        return Err(Errno::EPERM);
                    }
                    fs.create_subvol(&name, 0o755).await?;
                }
                CowfsSubvolReq::Delete { name } => {
                    if cred.identity.id != 0 {
                        return Err(Errno::EPERM);
                    }
                    fs.delete_subvol(&name).await?;
                }
            }
            let subvols = fs
                .list_subvols()
                .into_iter()
                .map(|(name, root)| CowfsSubvolEntry {
                    name,
                    root: digest_to_hex(&root),
                })
                .collect();
            let resp = CowfsSubvolResp {
                volume: fs.volume_id().0.clone(),
                subvols,
            };
            serde_json::to_vec(&resp).map_err(|_| Errno::EIO)
        }
        cowfs_ioctl::COWFS_IOC_SNAP_LIST => {
            let snaps = fs.list_snapshots().await?;
            let resp = CowfsSnapListResp {
                volume: fs.volume_id().0.clone(),
                snapshots: snaps
                    .into_iter()
                    .map(|s| CowfsSnapEntry {
                        name: s.name,
                        root: digest_to_hex(&s.root),
                        epoch: s.epoch,
                        created_ms: s
                            .created_at
                            .sec
                            .saturating_mul(1000)
                            .saturating_add(u64::from(s.created_at.nsec) / 1_000_000),
                    })
                    .collect(),
            };
            serde_json::to_vec(&resp).map_err(|_| Errno::EIO)
        }
        cowfs_ioctl::COWFS_IOC_SNAP_DELETE => {
            if cred.identity.id != 0 {
                return Err(Errno::EPERM);
            }
            let req: CowfsSnapDeleteReq =
                serde_json::from_slice(payload).map_err(|_| Errno::EINVAL)?;
            fs.delete_snapshot(&req.name).await?;
            Ok(b"null".to_vec())
        }
        cowfs_ioctl::COWFS_IOC_GC => {
            if cred.identity.id != 0 {
                return Err(Errno::EPERM);
            }
            if fs.is_read_only() {
                return Err(Errno::EROFS);
            }
            let trimmed = payload
                .iter()
                .position(|b| !b.is_ascii_whitespace())
                .map(|s| &payload[s..])
                .unwrap_or(&[]);
            let req: CowfsGcReq = if trimmed.is_empty() || trimmed == b"null" {
                CowfsGcReq::default()
            } else {
                serde_json::from_slice(trimmed).map_err(|_| Errno::EINVAL)?
            };
            let hs = fs.head_store_rc();
            let ps = fs.pack_store_rc();
            let now = (fs.clock_rc())();
            let report = match req.grace_window_secs {
                Some(g) => crate::gc::collect_garbage_with_grace(&*hs, &*ps, now, g).await?,
                None => crate::gc::collect_garbage(&*hs, &*ps, now).await?,
            };
            let resp = CowfsGcResp {
                live_roots: report.live_roots,
                live_nodes: report.live_nodes,
                live_blocks: report.live_blocks,
                live_packs: report.live_packs,
                swept_packs: report.swept_packs.into_iter().map(|p| p.0).collect(),
            };
            serde_json::to_vec(&resp).map_err(|_| Errno::EIO)
        }
        cowfs_ioctl::COWFS_IOC_MKFS => Err(Errno::ENOTBLK),
        _ => Err(Errno::ENOTTY),
    }
}

/// Managed `os-cowfs` volume device attachable at `/dev/vdN` via `vfs::vblk::VblkRegistry`
/// or attached to a mounted `FsType::Cowfs` [`vfs::MountBacking`].
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
    /// Wrap a currently mounted [`CowFs`] volume as a `/dev/vdN` or mount-backed volume device.
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
    /// `BLK_INFO`, `BLK_LEASE`, and `COWFS_IOC_*`).
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

    async fn read_subvol_list(&self) -> Result<CowfsSubvolResp> {
        let entries = if let Some(fs) = &self.mounted {
            fs.list_subvols()
        } else {
            let _gc = self.head_store.acquire_gc_lock(false).await?;
            let head = self.head_store.read_head(&self.volume).await?;
            let raw = self.head_store.get_node(&head.root).await?;
            let root_obj = RootObject::decode_verified(&head.root, &raw)?;
            root_obj.subvols.into_iter().collect()
        };
        Ok(CowfsSubvolResp {
            volume: self.volume.0.clone(),
            subvols: entries
                .into_iter()
                .map(|(name, root)| CowfsSubvolEntry {
                    name,
                    root: digest_to_hex(&root),
                })
                .collect(),
        })
    }
}

impl<H: HeadStore + 'static, P: PackStore + 'static> VolumeDevice for CowFsVolumeDevice<H, P> {
    fn volume_id(&self) -> &str {
        &self.volume.0
    }

    fn remote_source(&self) -> Option<String> {
        (self.durability == Durability::FencedCommit).then(|| {
            if let Some(name) = self.mounted.as_ref().and_then(|fs| fs.pinned_snapshot()) {
                format!("remote:snapshot:{}@{name}", self.volume.0)
            } else {
                format!("remote:volume:{}", self.volume.0)
            }
        })
    }

    fn is_read_only(&self) -> bool {
        self.read_only
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
                return Ok(fs.lease_status());
            }
            let head = self.head_store.read_head(&self.volume).await?;
            Ok(BlkLeaseResp {
                volume: head.volume.0,
                held: false,
                fenced: false,
                expired: false,
                lease_expires_at: None,
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
                snapshot: None,
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
            let req = CowfsMkfsReq {
                force,
                label: None,
                volume: None,
            };
            self.cowfs_mkfs(&req).await
        })
    }

    fn cowfs_mkfs<'a>(&'a self, req: &'a CowfsMkfsReq) -> BoxFuture<'a, CowfsInfoResp> {
        Box::pin(async move {
            let target_vol = match &req.volume {
                Some(explicit) => VolumeId(explicit.clone()),
                None => self.volume.clone(),
            };
            if target_vol == self.volume && self.mounted.is_some() {
                return Err(Errno::EBUSY);
            }
            let _gc_guard = self.head_store.acquire_gc_lock(false).await?;
            let now = (self.clock)();
            // Refuse if another writer currently holds the volume lease (`EBUSY`).
            // On `--force`, replace the volume head, bump `incarnation`, and wipe prior snapshots
            // and receipts atomically WHILE holding the exclusive writer lease.
            let head = match self.head_store.read_head(&target_vol).await {
                Ok(_) => {
                    let lease = self
                        .head_store
                        .acquire_writer(&target_vol, WriterMode::Exclusive)
                        .await?;
                    if !req.force {
                        let readers = self.head_store.check_no_readers(&target_vol).await;
                        let _ = self.head_store.release_writer(lease).await;
                        readers?;
                        return Err(Errno::EEXIST);
                    }
                    let (new_head, initial_nodes) =
                        CowFs::<H, P>::build_initial_volume_nodes_with_label(
                            target_vol.clone(),
                            0,
                            0,
                            0o755,
                            now,
                            req.label.as_deref(),
                        )?;
                    self.head_store
                        .reformat_volume_with_lease(lease, &new_head, &initial_nodes)
                        .await?
                }
                Err(Errno::ENOENT) => {
                    CowFs::format_volume_with_label(
                        &*self.head_store,
                        &*self.pack_store,
                        target_vol.clone(),
                        0,
                        0,
                        0o755,
                        now,
                        req.label.as_deref(),
                    )
                    .await?
                }
                Err(e) => return Err(e),
            };
            Ok(CowfsInfoResp {
                snapshot: None,
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

    fn cowfs_subvol<'a>(&'a self, req: &'a CowfsSubvolReq) -> BoxFuture<'a, CowfsSubvolResp> {
        Box::pin(async move {
            match req {
                CowfsSubvolReq::List {} => self.read_subvol_list().await,
                CowfsSubvolReq::Create { name } => {
                    if let Some(fs) = &self.mounted {
                        fs.create_subvol(name, 0o755).await?;
                    } else {
                        let cfg = CowFsConfig::local_browser(Rc::clone(&self.clock));
                        let fs = CowFs::open(
                            Rc::clone(&self.head_store),
                            Rc::clone(&self.pack_store),
                            self.volume.clone(),
                            CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
                            cfg,
                        )
                        .await?;
                        let op_res = fs.create_subvol(name, 0o755).await;
                        let close_res = fs.close_clean().await;
                        op_res?;
                        close_res?;
                    }
                    self.read_subvol_list().await
                }
                CowfsSubvolReq::Delete { name } => {
                    if let Some(fs) = &self.mounted {
                        fs.delete_subvol(name).await?;
                    } else {
                        let cfg = CowFsConfig::local_browser(Rc::clone(&self.clock));
                        let fs = CowFs::open(
                            Rc::clone(&self.head_store),
                            Rc::clone(&self.pack_store),
                            self.volume.clone(),
                            CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
                            cfg,
                        )
                        .await?;
                        let op_res = fs.delete_subvol(name).await;
                        let close_res = fs.close_clean().await;
                        op_res?;
                        close_res?;
                    }
                    self.read_subvol_list().await
                }
            }
        })
    }

    fn cowfs_snap_list(&self) -> BoxFuture<'_, CowfsSnapListResp> {
        Box::pin(async move {
            let snaps = if let Some(fs) = &self.mounted {
                fs.list_snapshots().await?
            } else {
                self.head_store.list_snapshots(&self.volume).await?
            };
            Ok(CowfsSnapListResp {
                volume: self.volume.0.clone(),
                snapshots: snaps
                    .into_iter()
                    .map(|s| CowfsSnapEntry {
                        name: s.name,
                        root: digest_to_hex(&s.root),
                        epoch: s.epoch,
                        created_ms: s
                            .created_at
                            .sec
                            .saturating_mul(1000)
                            .saturating_add(u64::from(s.created_at.nsec) / 1_000_000),
                    })
                    .collect(),
            })
        })
    }

    fn cowfs_snap_delete<'a>(&'a self, req: &'a CowfsSnapDeleteReq) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if let Some(fs) = &self.mounted {
                return fs.delete_snapshot(&req.name).await;
            }
            if self.read_only {
                return Err(Errno::EROFS);
            }
            if req.name.is_empty() || req.name.contains(['/', '\0']) {
                return Err(Errno::EINVAL);
            }
            self.head_store
                .delete_snapshot(&self.volume, &req.name)
                .await
        })
    }

    fn refresh_ro(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.mounted
                .as_ref()
                .ok_or(Errno::EINVAL)?
                .refresh_ro()
                .await
                .map(|_| ())
        })
    }

    fn cowfs_send<'a>(
        &'a self,
        req: &'a CowfsSendReq,
        sink: &'a mut dyn StreamSink,
    ) -> BoxFuture<'a, CowfsSendResp> {
        Box::pin(async move {
            let mut pinned_head = None;
            if let Some(fs) = &self.mounted {
                if !fs.is_read_only() && (req.snapshot.is_empty() || req.snapshot == "@") {
                    fs.commit_tx_group().await?;
                }
                if fs.is_read_only() {
                    pinned_head = Some(fs.current_head());
                }
            }
            send_snapshot(
                &*self.head_store,
                &*self.pack_store,
                &self.volume,
                pinned_head.as_ref(),
                &req.snapshot,
                req.parent.as_deref(),
                req.archive,
                sink,
            )
            .await
        })
    }

    fn cowfs_receive<'a>(
        &'a self,
        req: &'a CowfsReceiveReq,
        source: &'a mut dyn StreamSource,
    ) -> BoxFuture<'a, CowfsReceiveResp> {
        Box::pin(async move {
            let target_vol = match &req.target_volume {
                Some(explicit) => {
                    if explicit.is_empty() || explicit.contains(['/', '\0']) {
                        return Err(Errno::EINVAL);
                    }
                    VolumeId(explicit.clone())
                }
                None => self.volume.clone(),
            };
            if target_vol == self.volume
                && let Some(fs) = &self.mounted
            {
                return fs
                    .receive_into_mounted(req.snapshot_name.as_deref(), source)
                    .await;
            }
            let now = (self.clock)();
            if let Some((head, packs)) = self.head_store.scoped_stores(&target_vol) {
                return receive_snapshot(
                    &*head,
                    &packs,
                    ReceiveTarget::UnmountedVolume(&target_vol),
                    req.snapshot_name.as_deref(),
                    now,
                    source,
                )
                .await
                .map(|(_, resp)| resp);
            }
            let (_, resp) = receive_snapshot(
                &*self.head_store,
                &*self.pack_store,
                ReceiveTarget::UnmountedVolume(&target_vol),
                req.snapshot_name.as_deref(),
                now,
                source,
            )
            .await?;
            Ok(resp)
        })
    }

    fn cowfs_gc<'a>(&'a self, req: &'a CowfsGcReq) -> BoxFuture<'a, CowfsGcResp> {
        Box::pin(async move {
            if self.read_only {
                return Err(Errno::EROFS);
            }
            let now = (self.clock)();
            let report = match req.grace_window_secs {
                Some(g) => {
                    crate::gc::collect_garbage_with_grace(
                        &*self.head_store,
                        &*self.pack_store,
                        now,
                        g,
                    )
                    .await?
                }
                None => {
                    crate::gc::collect_garbage(&*self.head_store, &*self.pack_store, now).await?
                }
            };
            Ok(CowfsGcResp {
                live_roots: report.live_roots,
                live_nodes: report.live_nodes,
                live_blocks: report.live_blocks,
                live_packs: report.live_packs,
                swept_packs: report.swept_packs.into_iter().map(|p| p.0).collect(),
            })
        })
    }
}
