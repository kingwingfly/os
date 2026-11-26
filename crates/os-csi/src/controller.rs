//! CSI v1.9 Identity + Controller plugin (`OsCsiController<C: ClusterStore>`).

use crate::fencing::{
    CsiSnapshotRecord, CsiVolumeKind, CsiVolumeRecord, VolumeAttachmentRecord,
    acquire_volume_publish_lease, csi_attachment_key, csi_fence_key, csi_ro_attachments_prefix,
    csi_snapshot_key, csi_snapshot_name_key, csi_snapshots_prefix, csi_volume_key,
    csi_volume_name_key, csi_volumes_prefix, get_exact_kv, list_prefix_kvs, map_cluster_err,
    release_volume_publish_lease, sha256_hex,
};
use crate::spec::*;
use crate::{CSI_DRIVER_NAME, CSI_DRIVER_VERSION};
use abi::Errno;
use abi::cluster_state::{
    ClusterCall, ClusterReply, Compare, CompareOp, CompareTarget, RangeEnd, TxnOp,
};
use abi::fs::Timespec;
use cowtree::{ForkRequest, HeadStore, VolumeId};
use os_cluster_state::fencing::{decode_record, encode_record};
use os_cluster_state::{ClusterGrant, ClusterStore};
use os_cowfs::native_sqlite::{NativePackStore, NativeSqliteHeadStore};
use os_cowfs::{CowFs, RawBlockVolume};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_VOLUME_CAPACITY_BYTES: u64 = 64 * 1024 * 1024;
pub const DEFAULT_BLOCK_SIZE: u32 = 4096;
pub const DEFAULT_PUBLISH_LEASE_TTL_SECS: u64 = 30;

pub type ClockFn = Arc<dyn Fn() -> u64 + Send + Sync>;

pub fn system_clock_secs() -> ClockFn {
    Arc::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(1_700_000_000)
    })
}

#[derive(Clone)]
pub struct CsiControllerConfig {
    pub tenant: String,
    pub grant: ClusterGrant,
    pub store_dir: PathBuf,
    pub lease_ttl_secs: u64,
    pub enable_controller_capability: bool,
    pub clock: ClockFn,
}

impl CsiControllerConfig {
    pub fn new(tenant: impl Into<String>, grant: ClusterGrant, store_dir: PathBuf) -> Self {
        Self {
            tenant: tenant.into(),
            grant,
            store_dir,
            lease_ttl_secs: DEFAULT_PUBLISH_LEASE_TTL_SECS,
            enable_controller_capability: true,
            clock: system_clock_secs(),
        }
    }
}

/// CSI v1.9 Identity + Controller plugin generic over `ClusterStore`.
pub struct OsCsiController<C: ClusterStore + Send + Sync + 'static> {
    store: Arc<C>,
    cfg: CsiControllerConfig,
}

impl<C: ClusterStore + Send + Sync + 'static> OsCsiController<C> {
    pub fn new(store: Arc<C>, cfg: CsiControllerConfig) -> Self {
        let _ = std::fs::create_dir_all(&cfg.store_dir);
        Self { store, cfg }
    }

    pub fn store_dir(&self) -> &Path {
        &self.cfg.store_dir
    }

    fn now_secs(&self) -> u64 {
        (self.cfg.clock)()
    }

    fn now_timespec(&self) -> Timespec {
        Timespec {
            sec: self.now_secs(),
            nsec: 0,
        }
    }

    fn record_to_volume(&self, rec: &CsiVolumeRecord) -> Volume {
        let mut ctx = BTreeMap::new();
        ctx.insert("os.csi/volume_kind".into(), rec.kind.as_str().into());
        ctx.insert("os.csi/block_size".into(), rec.block_size.to_string());
        ctx.insert(
            "os.csi/capacity_bytes".into(),
            rec.capacity_bytes.to_string(),
        );
        ctx.insert(
            "os.csi/store_dir".into(),
            self.cfg.store_dir.to_string_lossy().into_owned(),
        );
        let content_source = if let Some(ref sid) = rec.source_snapshot_id {
            Some(VolumeContentSource::Snapshot {
                snapshot_id: sid.clone(),
            })
        } else {
            rec.source_volume_id
                .as_ref()
                .map(|vid| VolumeContentSource::Volume {
                    volume_id: vid.clone(),
                })
        };
        Volume {
            capacity_bytes: rec.capacity_bytes as i64,
            volume_id: rec.volume_id.clone(),
            volume_context: ctx,
            content_source,
            accessible_topology: Vec::new(),
        }
    }

    fn record_to_snapshot(rec: &CsiSnapshotRecord) -> Snapshot {
        Snapshot {
            size_bytes: rec.size_bytes as i64,
            snapshot_id: rec.snapshot_id.clone(),
            source_volume_id: rec.source_volume_id.clone(),
            creation_time: Some(Timestamp {
                seconds: rec.created_at as i64,
                nanos: 0,
            }),
            ready_to_use: true,
        }
    }

    fn validate_capabilities_list(
        caps: &[VolumeCapability],
        expected_kind: Option<CsiVolumeKind>,
    ) -> CsiResult<CsiVolumeKind> {
        if caps.is_empty() {
            return Err(CsiError::invalid_argument(
                "volume_capabilities must not be empty",
            ));
        }
        let mut detected_kind = expected_kind;
        for cap in caps {
            if cap.access_mode.is_multi_node_multi_writer() {
                return Err(CsiError::invalid_argument(
                    "MULTI_NODE_MULTI_WRITER is not supported (single-writer fenced storage)",
                ));
            }
            if cap.access_mode == AccessMode::Unknown {
                return Err(CsiError::invalid_argument("access_mode must be specified"));
            }
            let cap_kind = match &cap.access_type {
                AccessType::Block => CsiVolumeKind::Block,
                AccessType::Mount { fs_type, .. } => {
                    if !fs_type.is_empty() && fs_type != "cowfs" {
                        return Err(CsiError::invalid_argument(format!(
                            "unsupported mount fs_type '{fs_type}' (expected 'cowfs')"
                        )));
                    }
                    CsiVolumeKind::Cowfs
                }
            };
            if let Some(prev) = detected_kind
                && prev != cap_kind
            {
                return Err(CsiError::invalid_argument(
                    "conflicting block and mount volume capabilities",
                ));
            }
            detected_kind = Some(cap_kind);
        }
        Ok(detected_kind.unwrap_or(CsiVolumeKind::Cowfs))
    }
}

async fn run_local_storage<T, F>(store_dir: PathBuf, f: F) -> CsiResult<T>
where
    T: Send + 'static,
    F: FnOnce(NativeSqliteHeadStore, NativePackStore) -> Result<T, Errno> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        std::fs::create_dir_all(&store_dir).map_err(|_| Errno::EIO)?;
        let hs = NativeSqliteHeadStore::open(&store_dir)?;
        let ps = NativePackStore::open(&store_dir)?;
        f(hs, ps)
    })
    .await
    .map_err(|e| CsiError::internal(format!("storage worker panicked: {e}")))?
    .map_err(map_errno_to_csi)
}

fn map_errno_to_csi(e: Errno) -> CsiError {
    match e {
        Errno::EINVAL => CsiError::invalid_argument("invalid argument"),
        Errno::ENOENT => CsiError::not_found("not found"),
        Errno::EEXIST => CsiError::already_exists("already exists"),
        Errno::EBUSY | Errno::ESTALE => CsiError::failed_precondition(format!("{e:?}")),
        Errno::ENOSPC | Errno::EFBIG | Errno::E2BIG => {
            CsiError::resource_exhausted(format!("{e:?}"))
        }
        Errno::EPERM | Errno::EACCES => CsiError::permission_denied(format!("{e:?}")),
        Errno::EOPNOTSUPP => CsiError::unimplemented("operation not supported"),
        other => CsiError::internal(format!("storage error: {other:?}")),
    }
}

fn block_on_local<F: std::future::Future>(fut: F) -> F::Output {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio current_thread runtime");
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, fut)
}

impl<C: ClusterStore + Send + Sync + 'static> CsiIdentity for OsCsiController<C> {
    fn get_plugin_info<'a>(
        &'a self,
        _req: GetPluginInfoRequest,
    ) -> BoxFuture<'a, CsiResult<GetPluginInfoResponse>> {
        Box::pin(async move {
            let mut manifest = BTreeMap::new();
            manifest.insert("storage".into(), "os-cowfs".into());
            manifest.insert("raw_block".into(), "os-nbd".into());
            Ok(GetPluginInfoResponse {
                name: CSI_DRIVER_NAME.to_string(),
                vendor_version: CSI_DRIVER_VERSION.to_string(),
                manifest,
            })
        })
    }

    fn get_plugin_capabilities<'a>(
        &'a self,
        _req: GetPluginCapabilitiesRequest,
    ) -> BoxFuture<'a, CsiResult<GetPluginCapabilitiesResponse>> {
        Box::pin(async move {
            let mut service_capabilities = Vec::new();
            if self.cfg.enable_controller_capability {
                service_capabilities.push(PluginServiceCapability::ControllerService);
            }
            Ok(GetPluginCapabilitiesResponse {
                service_capabilities,
            })
        })
    }

    fn probe<'a>(&'a self, _req: ProbeRequest) -> BoxFuture<'a, CsiResult<ProbeResponse>> {
        Box::pin(async move { Ok(ProbeResponse { ready: Some(true) }) })
    }
}

impl<C: ClusterStore + Send + Sync + 'static> CsiController for OsCsiController<C> {
    fn create_volume<'a>(
        &'a self,
        req: CreateVolumeRequest,
    ) -> BoxFuture<'a, CsiResult<CreateVolumeResponse>> {
        Box::pin(async move {
            if req.name.trim().is_empty() {
                return Err(CsiError::invalid_argument("volume name must not be empty"));
            }
            let param_kind = req
                .parameters
                .get("volume_kind")
                .map(|s| {
                    CsiVolumeKind::parse(s).ok_or_else(|| {
                        CsiError::invalid_argument(format!("invalid volume_kind '{s}'"))
                    })
                })
                .transpose()?;
            let kind = Self::validate_capabilities_list(&req.volume_capabilities, param_kind)?;
            let block_size = req
                .parameters
                .get("block_size")
                .map(|s| {
                    s.parse::<u32>()
                        .map_err(|_| CsiError::invalid_argument("invalid block_size"))
                })
                .transpose()?
                .unwrap_or(DEFAULT_BLOCK_SIZE);
            if !(cowtree::RAW_VOLUME_MIN_BLOCK_SIZE..=cowtree::RAW_VOLUME_MAX_BLOCK_SIZE)
                .contains(&block_size)
                || !block_size.is_power_of_two()
            {
                return Err(CsiError::invalid_argument(
                    "block_size must be a power of 2 in 512..=65536",
                ));
            }

            let req_bytes = req
                .capacity_range
                .as_ref()
                .map(|c| {
                    if c.required_bytes < 0 || c.limit_bytes < 0 {
                        return Err(CsiError::invalid_argument("negative capacity_range"));
                    }
                    if c.limit_bytes > 0 && c.required_bytes > c.limit_bytes {
                        return Err(CsiError::invalid_argument(
                            "required_bytes exceeds limit_bytes",
                        ));
                    }
                    let wanted = if c.required_bytes > 0 {
                        c.required_bytes as u64
                    } else if c.limit_bytes > 0 {
                        (c.limit_bytes as u64).min(DEFAULT_VOLUME_CAPACITY_BYTES)
                    } else {
                        DEFAULT_VOLUME_CAPACITY_BYTES
                    };
                    Ok(wanted)
                })
                .transpose()?
                .unwrap_or(DEFAULT_VOLUME_CAPACITY_BYTES);

            let bs64 = u64::from(block_size);
            let capacity_bytes = req_bytes.max(bs64).div_ceil(bs64).saturating_mul(bs64);

            let now = self.now_secs();
            let now_ts = self.now_timespec();
            let name_hash = sha256_hex(&req.name);
            let name_key = csi_volume_name_key(&self.cfg.tenant, &name_hash)?;

            // Idempotency check by volume name.
            if let Some(existing_name_kv) =
                get_exact_kv(&*self.store, &self.cfg.grant, name_key.clone(), now).await?
            {
                let existing_id: String =
                    decode_record(&existing_name_kv).map_err(map_cluster_err)?;
                let vol_key = csi_volume_key(&self.cfg.tenant, &existing_id)?;
                if let Some(vol_kv) =
                    get_exact_kv(&*self.store, &self.cfg.grant, vol_key, now).await?
                {
                    let existing: CsiVolumeRecord =
                        decode_record(&vol_kv).map_err(map_cluster_err)?;
                    if existing.kind != kind || existing.capacity_bytes < req_bytes {
                        return Err(CsiError::already_exists(
                            "volume name already exists with incompatible parameters",
                        ));
                    }
                    return Ok(CreateVolumeResponse {
                        volume: self.record_to_volume(&existing),
                    });
                }
            }

            let volume_id = format!("vol-{}", &name_hash[..24]);
            let mut source_snapshot_id = None;
            let mut source_volume_id = None;
            let mut effective_capacity = capacity_bytes;
            let mut effective_block_size = block_size;

            // Provision on local native storage (empty format OR O(1) snapshot/volume fork).
            match &req.volume_content_source {
                Some(VolumeContentSource::Snapshot { snapshot_id }) => {
                    let snap_key = csi_snapshot_key(&self.cfg.tenant, snapshot_id)?;
                    let snap_kv = get_exact_kv(&*self.store, &self.cfg.grant, snap_key, now)
                        .await?
                        .ok_or_else(|| {
                            CsiError::not_found(format!("snapshot {snapshot_id} not found"))
                        })?;
                    let snap_rec: CsiSnapshotRecord =
                        decode_record(&snap_kv).map_err(map_cluster_err)?;
                    if snap_rec.volume_kind != kind {
                        return Err(CsiError::invalid_argument(
                            "snapshot volume_kind does not match requested volume capability",
                        ));
                    }
                    source_snapshot_id = Some(snapshot_id.clone());
                    effective_capacity = effective_capacity.max(snap_rec.size_bytes);
                    let src_vol = VolumeId(snap_rec.source_volume_id.clone());
                    let src_snap = snap_rec.cowfs_snapshot_name.clone();
                    let new_vol = VolumeId(volume_id.clone());
                    let is_block = kind == CsiVolumeKind::Block;
                    let raw_meta = run_local_storage(self.cfg.store_dir.clone(), move |hs, ps| {
                        block_on_local(async move {
                            let _gc = hs.acquire_gc_lock(false).await?;
                            let snap = hs.get_snapshot(&src_vol, &src_snap).await?;
                            let fork_req = ForkRequest {
                                source_volume: src_vol,
                                source_snapshot: Some(src_snap),
                                source_root: snap.root,
                                new_volume: new_vol.clone(),
                                ephemeral_if_unmodified: false,
                                created_at: now_ts,
                            };
                            hs.fork_volume(&fork_req).await?;
                            if is_block {
                                let clk: os_cowfs::CowFsClock = Rc::new(move || now_ts);
                                let rv = RawBlockVolume::open(
                                    Rc::new(hs),
                                    Rc::new(ps),
                                    new_vol,
                                    os_cowfs::RawBlockOpenMode::ReadOnly,
                                    os_cowfs::RawBlockConfig::local_native(clk),
                                )
                                .await?;
                                let info = rv.info();
                                let _ = rv.close_clean().await;
                                Ok(Some((info.size_bytes, info.block_size)))
                            } else {
                                Ok(None)
                            }
                        })
                    })
                    .await?;
                    if let Some((sz, bs)) = raw_meta {
                        effective_capacity = sz;
                        effective_block_size = bs;
                    }
                }
                Some(VolumeContentSource::Volume { volume_id: src_vid }) => {
                    let src_key = csi_volume_key(&self.cfg.tenant, src_vid)?;
                    let src_kv = get_exact_kv(&*self.store, &self.cfg.grant, src_key, now)
                        .await?
                        .ok_or_else(|| {
                            CsiError::not_found(format!("source volume {src_vid} not found"))
                        })?;
                    let src_rec: CsiVolumeRecord =
                        decode_record(&src_kv).map_err(map_cluster_err)?;
                    if src_rec.kind != kind {
                        return Err(CsiError::invalid_argument(
                            "source volume kind does not match requested capability",
                        ));
                    }
                    source_volume_id = Some(src_vid.clone());
                    effective_capacity = effective_capacity.max(src_rec.capacity_bytes);
                    effective_block_size = src_rec.block_size;
                    let src_vol = VolumeId(src_vid.clone());
                    let new_vol = VolumeId(volume_id.clone());
                    let is_block = kind == CsiVolumeKind::Block;
                    let raw_meta = run_local_storage(self.cfg.store_dir.clone(), move |hs, ps| {
                        block_on_local(async move {
                            let _gc = hs.acquire_gc_lock(false).await?;
                            let head = hs.read_head(&src_vol).await?;
                            let fork_req = ForkRequest {
                                source_volume: src_vol,
                                source_snapshot: None,
                                source_root: head.root,
                                new_volume: new_vol.clone(),
                                ephemeral_if_unmodified: false,
                                created_at: now_ts,
                            };
                            hs.fork_volume(&fork_req).await?;
                            if is_block {
                                let clk: os_cowfs::CowFsClock = Rc::new(move || now_ts);
                                let rv = RawBlockVolume::open(
                                    Rc::new(hs),
                                    Rc::new(ps),
                                    new_vol,
                                    os_cowfs::RawBlockOpenMode::ReadOnly,
                                    os_cowfs::RawBlockConfig::local_native(clk),
                                )
                                .await?;
                                let info = rv.info();
                                let _ = rv.close_clean().await;
                                Ok(Some((info.size_bytes, info.block_size)))
                            } else {
                                Ok(None)
                            }
                        })
                    })
                    .await?;
                    if let Some((sz, bs)) = raw_meta {
                        effective_capacity = sz;
                        effective_block_size = bs;
                    }
                }
                None => {
                    let new_vol = VolumeId(volume_id.clone());
                    let cap = effective_capacity;
                    let bs = effective_block_size;
                    run_local_storage(self.cfg.store_dir.clone(), move |hs, ps| {
                        block_on_local(async move {
                            match kind {
                                CsiVolumeKind::Cowfs => {
                                    CowFs::format_volume(&hs, &ps, new_vol, 0, 0, 0o755, now_ts)
                                        .await?;
                                }
                                CsiVolumeKind::Block => {
                                    RawBlockVolume::format(&hs, &ps, new_vol, cap, bs, 0, now_ts)
                                        .await?;
                                }
                            }
                            Ok(())
                        })
                    })
                    .await?;
                }
            }

            let rec = CsiVolumeRecord {
                volume_id: volume_id.clone(),
                name: req.name.clone(),
                name_hash: name_hash.clone(),
                kind,
                capacity_bytes: effective_capacity,
                block_size: effective_block_size,
                source_snapshot_id,
                source_volume_id,
                created_at: now,
            };
            let vol_key = csi_volume_key(&self.cfg.tenant, &volume_id)?;
            let txn = self
                .store
                .rpc(
                    &self.cfg.grant,
                    ClusterCall::Txn {
                        compare: vec![
                            Compare {
                                key: name_key.clone(),
                                op: CompareOp::Equal,
                                target: CompareTarget::Version(0),
                            },
                            Compare {
                                key: vol_key.clone(),
                                op: CompareOp::Equal,
                                target: CompareTarget::Version(0),
                            },
                        ],
                        success: vec![
                            TxnOp::Put {
                                key: vol_key,
                                value_b64: encode_record(&rec).map_err(map_cluster_err)?,
                                lease_id: 0,
                                prev_kv: false,
                            },
                            TxnOp::Put {
                                key: name_key,
                                value_b64: encode_record(&volume_id).map_err(map_cluster_err)?,
                                lease_id: 0,
                                prev_kv: false,
                            },
                        ],
                        failure: vec![],
                    },
                    now,
                )
                .await
                .map_err(map_cluster_err)?;

            match txn {
                ClusterReply::Txn {
                    succeeded: true, ..
                } => Ok(CreateVolumeResponse {
                    volume: self.record_to_volume(&rec),
                }),
                _ => Err(CsiError::already_exists(
                    "concurrent CreateVolume collision",
                )),
            }
        })
    }

    fn delete_volume<'a>(
        &'a self,
        req: DeleteVolumeRequest,
    ) -> BoxFuture<'a, CsiResult<DeleteVolumeResponse>> {
        Box::pin(async move {
            if req.volume_id.is_empty() {
                return Err(CsiError::invalid_argument("volume_id must not be empty"));
            }
            let now = self.now_secs();
            let vol_key = csi_volume_key(&self.cfg.tenant, &req.volume_id)?;
            let Some(vol_kv) =
                get_exact_kv(&*self.store, &self.cfg.grant, vol_key.clone(), now).await?
            else {
                // CSI spec: DeleteVolume on non-existent volume succeeds idempotently.
                return Ok(DeleteVolumeResponse {});
            };
            let rec: CsiVolumeRecord = decode_record(&vol_kv).map_err(map_cluster_err)?;

            // Snapshot fence_key BEFORE checking RW & RO attachments so any concurrent RW or RO
            // publish (which bumps fence_epoch or ro_generation on fence_key) aborts the delete Txn.
            let fence_key = csi_fence_key(&self.cfg.tenant, &req.volume_id)?;
            let fence_kv =
                get_exact_kv(&*self.store, &self.cfg.grant, fence_key.clone(), now).await?;
            let fence_cmp = match fence_kv {
                Some(kv) => Compare {
                    key: fence_key,
                    op: CompareOp::Equal,
                    target: CompareTarget::ModRevision(kv.mod_revision),
                },
                None => Compare {
                    key: fence_key,
                    op: CompareOp::Equal,
                    target: CompareTarget::Version(0),
                },
            };

            // Refuse delete while published RW or RO.
            let rw_key = csi_attachment_key(&self.cfg.tenant, &req.volume_id)?;
            if get_exact_kv(&*self.store, &self.cfg.grant, rw_key.clone(), now)
                .await?
                .is_some()
            {
                return Err(CsiError::failed_precondition(format!(
                    "cannot delete volume {} while published RW",
                    req.volume_id
                )));
            }
            let ro_prefix = csi_ro_attachments_prefix(&self.cfg.tenant, &req.volume_id)?;
            let ro_list =
                list_prefix_kvs(&*self.store, &self.cfg.grant, ro_prefix, Some(1), now).await?;
            if !ro_list.is_empty() {
                return Err(CsiError::failed_precondition(format!(
                    "cannot delete volume {} while published RO",
                    req.volume_id
                )));
            }

            let name_key = csi_volume_name_key(&self.cfg.tenant, &rec.name_hash)?;
            // Never delete `fence_key` so `fence_epoch` stays strictly monotonic across recreations.
            let txn = self
                .store
                .rpc(
                    &self.cfg.grant,
                    ClusterCall::Txn {
                        compare: vec![
                            Compare {
                                key: rw_key,
                                op: CompareOp::Equal,
                                target: CompareTarget::Version(0),
                            },
                            fence_cmp,
                        ],
                        success: vec![
                            TxnOp::DeleteRange {
                                key: vol_key,
                                range_end: RangeEnd::Exact,
                                prev_kv: false,
                            },
                            TxnOp::DeleteRange {
                                key: name_key,
                                range_end: RangeEnd::Exact,
                                prev_kv: false,
                            },
                        ],
                        failure: vec![],
                    },
                    now,
                )
                .await
                .map_err(map_cluster_err)?;
            match txn {
                ClusterReply::Txn {
                    succeeded: true, ..
                } => {}
                _ => {
                    return Err(CsiError::failed_precondition(
                        "volume became published concurrently",
                    ));
                }
            }

            let vid = VolumeId(req.volume_id.clone());
            let _ = run_local_storage(self.cfg.store_dir.clone(), move |hs, _ps| {
                block_on_local(async move {
                    match hs.delete_volume(&vid).await {
                        Ok(()) | Err(Errno::ENOENT) => Ok(()),
                        Err(e) => Err(e),
                    }
                })
            })
            .await;

            Ok(DeleteVolumeResponse {})
        })
    }

    fn controller_publish_volume<'a>(
        &'a self,
        req: ControllerPublishVolumeRequest,
    ) -> BoxFuture<'a, CsiResult<ControllerPublishVolumeResponse>> {
        Box::pin(async move {
            if req.volume_id.is_empty() || req.node_id.is_empty() {
                return Err(CsiError::invalid_argument(
                    "volume_id and node_id are required",
                ));
            }
            let cap = req
                .volume_capability
                .as_ref()
                .ok_or_else(|| CsiError::invalid_argument("volume_capability is required"))?;
            let vol_kind = Self::validate_capabilities_list(std::slice::from_ref(cap), None)?;
            let readonly = req.readonly || cap.access_mode.is_read_only();

            let now = self.now_secs();
            let vol_key = csi_volume_key(&self.cfg.tenant, &req.volume_id)?;
            let vol_kv = get_exact_kv(&*self.store, &self.cfg.grant, vol_key, now)
                .await?
                .ok_or_else(|| {
                    CsiError::not_found(format!("volume {} not found", req.volume_id))
                })?;
            let rec: CsiVolumeRecord = decode_record(&vol_kv).map_err(map_cluster_err)?;
            if rec.kind != vol_kind {
                return Err(CsiError::invalid_argument(
                    "volume_capability access_type mismatches volume kind",
                ));
            }

            let att = acquire_volume_publish_lease(
                &*self.store,
                &self.cfg.grant,
                &self.cfg.tenant,
                &req.volume_id,
                &req.node_id,
                readonly,
                self.cfg.lease_ttl_secs,
                now,
            )
            .await?;

            let mut publish_context = BTreeMap::new();
            publish_context.insert("os.csi/volume_kind".into(), rec.kind.as_str().into());
            publish_context.insert("os.csi/fence_epoch".into(), att.fence_epoch.to_string());
            publish_context.insert("os.csi/lease_id".into(), att.lease_id.to_string());
            publish_context.insert(
                "os.csi/lease_ttl_secs".into(),
                att.lease_ttl_secs.to_string(),
            );
            publish_context.insert("os.csi/node_id".into(), att.node_id);
            publish_context.insert("os.csi/readonly".into(), att.readonly.to_string());
            publish_context.insert("os.csi/block_size".into(), rec.block_size.to_string());
            publish_context.insert(
                "os.csi/capacity_bytes".into(),
                rec.capacity_bytes.to_string(),
            );
            publish_context.insert(
                "os.csi/store_dir".into(),
                self.cfg.store_dir.to_string_lossy().into_owned(),
            );
            Ok(ControllerPublishVolumeResponse { publish_context })
        })
    }

    fn controller_unpublish_volume<'a>(
        &'a self,
        req: ControllerUnpublishVolumeRequest,
    ) -> BoxFuture<'a, CsiResult<ControllerUnpublishVolumeResponse>> {
        Box::pin(async move {
            if req.volume_id.is_empty() {
                return Err(CsiError::invalid_argument("volume_id is required"));
            }
            let now = self.now_secs();
            release_volume_publish_lease(
                &*self.store,
                &self.cfg.grant,
                &self.cfg.tenant,
                &req.volume_id,
                &req.node_id,
                now,
            )
            .await?;
            Ok(ControllerUnpublishVolumeResponse {})
        })
    }

    fn validate_volume_capabilities<'a>(
        &'a self,
        req: ValidateVolumeCapabilitiesRequest,
    ) -> BoxFuture<'a, CsiResult<ValidateVolumeCapabilitiesResponse>> {
        Box::pin(async move {
            if req.volume_id.is_empty() || req.volume_capabilities.is_empty() {
                return Err(CsiError::invalid_argument(
                    "volume_id and volume_capabilities are required",
                ));
            }
            let now = self.now_secs();
            let vol_key = csi_volume_key(&self.cfg.tenant, &req.volume_id)?;
            let vol_kv = get_exact_kv(&*self.store, &self.cfg.grant, vol_key, now)
                .await?
                .ok_or_else(|| {
                    CsiError::not_found(format!("volume {} not found", req.volume_id))
                })?;
            let rec: CsiVolumeRecord = decode_record(&vol_kv).map_err(map_cluster_err)?;

            match Self::validate_capabilities_list(&req.volume_capabilities, Some(rec.kind)) {
                Ok(_) => Ok(ValidateVolumeCapabilitiesResponse {
                    confirmed: Some(ValidateVolumeCapabilitiesConfirmed {
                        volume_context: req.volume_context,
                        volume_capabilities: req.volume_capabilities,
                        parameters: req.parameters,
                    }),
                    message: String::new(),
                }),
                Err(e) => Ok(ValidateVolumeCapabilitiesResponse {
                    confirmed: None,
                    message: e.message,
                }),
            }
        })
    }

    fn list_volumes<'a>(
        &'a self,
        req: ListVolumesRequest,
    ) -> BoxFuture<'a, CsiResult<ListVolumesResponse>> {
        Box::pin(async move {
            let now = self.now_secs();
            let prefix = csi_volumes_prefix(&self.cfg.tenant)?;
            let kvs =
                list_prefix_kvs(&*self.store, &self.cfg.grant, prefix, Some(512), now).await?;
            let start_idx: usize = if req.starting_token.is_empty() {
                0
            } else {
                req.starting_token
                    .parse::<usize>()
                    .map_err(|_| CsiError::new(CsiStatusCode::Aborted, "invalid starting_token"))?
            };
            let max_entries = if req.max_entries > 0 {
                req.max_entries as usize
            } else {
                kvs.len()
            };
            let mut entries = Vec::new();
            let mut next_token = String::new();
            for (idx, kv) in kvs.iter().enumerate().skip(start_idx) {
                if entries.len() >= max_entries {
                    next_token = idx.to_string();
                    break;
                }
                let rec: CsiVolumeRecord = decode_record(kv).map_err(map_cluster_err)?;
                let mut published_node_ids = Vec::new();
                if let Some(att_kv) = get_exact_kv(
                    &*self.store,
                    &self.cfg.grant,
                    csi_attachment_key(&self.cfg.tenant, &rec.volume_id)?,
                    now,
                )
                .await?
                {
                    let att: VolumeAttachmentRecord =
                        decode_record(&att_kv).map_err(map_cluster_err)?;
                    published_node_ids.push(att.node_id);
                }
                let ro_kvs = list_prefix_kvs(
                    &*self.store,
                    &self.cfg.grant,
                    csi_ro_attachments_prefix(&self.cfg.tenant, &rec.volume_id)?,
                    Some(64),
                    now,
                )
                .await?;
                for ro_kv in ro_kvs {
                    if let Ok(att) = decode_record::<VolumeAttachmentRecord>(&ro_kv)
                        && !published_node_ids.contains(&att.node_id)
                    {
                        published_node_ids.push(att.node_id);
                    }
                }
                entries.push(ListVolumesEntry {
                    volume: self.record_to_volume(&rec),
                    published_node_ids,
                });
            }
            Ok(ListVolumesResponse {
                entries,
                next_token,
            })
        })
    }

    fn controller_get_capabilities<'a>(
        &'a self,
        _req: ControllerGetCapabilitiesRequest,
    ) -> BoxFuture<'a, CsiResult<ControllerGetCapabilitiesResponse>> {
        Box::pin(async move {
            Ok(ControllerGetCapabilitiesResponse {
                capabilities: vec![
                    ControllerRpcCapability::CreateDeleteVolume,
                    ControllerRpcCapability::PublishUnpublishVolume,
                    ControllerRpcCapability::ListVolumes,
                    ControllerRpcCapability::CreateDeleteSnapshot,
                    ControllerRpcCapability::ListSnapshots,
                    ControllerRpcCapability::CloneVolume,
                    ControllerRpcCapability::PublishReadonly,
                ],
            })
        })
    }

    fn create_snapshot<'a>(
        &'a self,
        req: CreateSnapshotRequest,
    ) -> BoxFuture<'a, CsiResult<CreateSnapshotResponse>> {
        Box::pin(async move {
            if req.source_volume_id.is_empty() || req.name.trim().is_empty() {
                return Err(CsiError::invalid_argument(
                    "source_volume_id and snapshot name are required",
                ));
            }
            let now = self.now_secs();
            let now_ts = self.now_timespec();
            let name_hash = sha256_hex(&req.name);
            let sname_key = csi_snapshot_name_key(&self.cfg.tenant, &name_hash)?;

            if let Some(existing_name_kv) =
                get_exact_kv(&*self.store, &self.cfg.grant, sname_key.clone(), now).await?
            {
                let existing_id: String =
                    decode_record(&existing_name_kv).map_err(map_cluster_err)?;
                let skey = csi_snapshot_key(&self.cfg.tenant, &existing_id)?;
                if let Some(skv) = get_exact_kv(&*self.store, &self.cfg.grant, skey, now).await? {
                    let existing: CsiSnapshotRecord =
                        decode_record(&skv).map_err(map_cluster_err)?;
                    if existing.source_volume_id != req.source_volume_id {
                        return Err(CsiError::already_exists(
                            "snapshot name already exists for a different source volume",
                        ));
                    }
                    return Ok(CreateSnapshotResponse {
                        snapshot: Self::record_to_snapshot(&existing),
                    });
                }
            }

            let vol_key = csi_volume_key(&self.cfg.tenant, &req.source_volume_id)?;
            let vol_kv = get_exact_kv(&*self.store, &self.cfg.grant, vol_key, now)
                .await?
                .ok_or_else(|| {
                    CsiError::not_found(format!("source volume {} not found", req.source_volume_id))
                })?;
            let vol_rec: CsiVolumeRecord = decode_record(&vol_kv).map_err(map_cluster_err)?;

            let snapshot_id = format!("snap-{}", &name_hash[..24]);
            let cowfs_snap_name = snapshot_id.clone();
            let src_vol_id = VolumeId(req.source_volume_id.clone());
            let snap_name_for_store = cowfs_snap_name.clone();

            run_local_storage(self.cfg.store_dir.clone(), move |hs, _ps| {
                block_on_local(async move {
                    let _gc = hs.acquire_gc_lock(false).await?;
                    let head = hs.read_head(&src_vol_id).await?;
                    hs.create_snapshot(&src_vol_id, &snap_name_for_store, &head, now_ts)
                        .await?;
                    Ok(())
                })
            })
            .await?;

            let rec = CsiSnapshotRecord {
                snapshot_id: snapshot_id.clone(),
                name: req.name.clone(),
                name_hash,
                source_volume_id: req.source_volume_id.clone(),
                cowfs_snapshot_name: cowfs_snap_name,
                volume_kind: vol_rec.kind,
                size_bytes: vol_rec.capacity_bytes,
                created_at: now,
            };
            let skey = csi_snapshot_key(&self.cfg.tenant, &snapshot_id)?;
            let txn = self
                .store
                .rpc(
                    &self.cfg.grant,
                    ClusterCall::Txn {
                        compare: vec![
                            Compare {
                                key: sname_key.clone(),
                                op: CompareOp::Equal,
                                target: CompareTarget::Version(0),
                            },
                            Compare {
                                key: skey.clone(),
                                op: CompareOp::Equal,
                                target: CompareTarget::Version(0),
                            },
                        ],
                        success: vec![
                            TxnOp::Put {
                                key: skey,
                                value_b64: encode_record(&rec).map_err(map_cluster_err)?,
                                lease_id: 0,
                                prev_kv: false,
                            },
                            TxnOp::Put {
                                key: sname_key,
                                value_b64: encode_record(&snapshot_id).map_err(map_cluster_err)?,
                                lease_id: 0,
                                prev_kv: false,
                            },
                        ],
                        failure: vec![],
                    },
                    now,
                )
                .await
                .map_err(map_cluster_err)?;
            match txn {
                ClusterReply::Txn {
                    succeeded: true, ..
                } => Ok(CreateSnapshotResponse {
                    snapshot: Self::record_to_snapshot(&rec),
                }),
                _ => Err(CsiError::already_exists(
                    "concurrent CreateSnapshot collision",
                )),
            }
        })
    }

    fn delete_snapshot<'a>(
        &'a self,
        req: DeleteSnapshotRequest,
    ) -> BoxFuture<'a, CsiResult<DeleteSnapshotResponse>> {
        Box::pin(async move {
            if req.snapshot_id.is_empty() {
                return Err(CsiError::invalid_argument("snapshot_id is required"));
            }
            let now = self.now_secs();
            let skey = csi_snapshot_key(&self.cfg.tenant, &req.snapshot_id)?;
            let Some(skv) = get_exact_kv(&*self.store, &self.cfg.grant, skey.clone(), now).await?
            else {
                return Ok(DeleteSnapshotResponse {});
            };
            let rec: CsiSnapshotRecord = decode_record(&skv).map_err(map_cluster_err)?;
            let sname_key = csi_snapshot_name_key(&self.cfg.tenant, &rec.name_hash)?;

            let _ = self
                .store
                .rpc(
                    &self.cfg.grant,
                    ClusterCall::Txn {
                        compare: vec![],
                        success: vec![
                            TxnOp::DeleteRange {
                                key: skey,
                                range_end: RangeEnd::Exact,
                                prev_kv: false,
                            },
                            TxnOp::DeleteRange {
                                key: sname_key,
                                range_end: RangeEnd::Exact,
                                prev_kv: false,
                            },
                        ],
                        failure: vec![],
                    },
                    now,
                )
                .await
                .map_err(map_cluster_err)?;

            let src_vol = VolumeId(rec.source_volume_id);
            let snap_name = rec.cowfs_snapshot_name;
            let _ = run_local_storage(self.cfg.store_dir.clone(), move |hs, _ps| {
                block_on_local(async move {
                    match hs.delete_snapshot(&src_vol, &snap_name).await {
                        Ok(()) | Err(Errno::ENOENT) => Ok(()),
                        Err(e) => Err(e),
                    }
                })
            })
            .await;

            Ok(DeleteSnapshotResponse {})
        })
    }

    fn list_snapshots<'a>(
        &'a self,
        req: ListSnapshotsRequest,
    ) -> BoxFuture<'a, CsiResult<ListSnapshotsResponse>> {
        Box::pin(async move {
            let now = self.now_secs();
            if !req.snapshot_id.is_empty() {
                let skey = csi_snapshot_key(&self.cfg.tenant, &req.snapshot_id)?;
                if let Some(kv) = get_exact_kv(&*self.store, &self.cfg.grant, skey, now).await? {
                    let rec: CsiSnapshotRecord = decode_record(&kv).map_err(map_cluster_err)?;
                    if req.source_volume_id.is_empty()
                        || rec.source_volume_id == req.source_volume_id
                    {
                        return Ok(ListSnapshotsResponse {
                            entries: vec![Self::record_to_snapshot(&rec)],
                            next_token: String::new(),
                        });
                    }
                }
                return Ok(ListSnapshotsResponse::default());
            }

            let prefix = csi_snapshots_prefix(&self.cfg.tenant)?;
            let kvs =
                list_prefix_kvs(&*self.store, &self.cfg.grant, prefix, Some(512), now).await?;
            let mut filtered = Vec::new();
            for kv in kvs {
                let rec: CsiSnapshotRecord = decode_record(&kv).map_err(map_cluster_err)?;
                if req.source_volume_id.is_empty() || rec.source_volume_id == req.source_volume_id {
                    filtered.push(Self::record_to_snapshot(&rec));
                }
            }
            let start_idx: usize = if req.starting_token.is_empty() {
                0
            } else {
                req.starting_token
                    .parse::<usize>()
                    .map_err(|_| CsiError::new(CsiStatusCode::Aborted, "invalid starting_token"))?
            };
            let max_entries = if req.max_entries > 0 {
                req.max_entries as usize
            } else {
                filtered.len()
            };
            let mut entries = Vec::new();
            let mut next_token = String::new();
            for (idx, snap) in filtered.into_iter().enumerate().skip(start_idx) {
                if entries.len() >= max_entries {
                    next_token = idx.to_string();
                    break;
                }
                entries.push(snap);
            }
            Ok(ListSnapshotsResponse {
                entries,
                next_token,
            })
        })
    }
}
