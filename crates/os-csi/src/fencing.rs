//! `ClusterState` CSI key schema and atomic fenced publish-lease transactions (`Phase 9.5 #85`).
//!
//! Key layout (strictly under `/t/<tenant>/csi/...`, passing `abi::cluster_state::valid_cluster_key`):
//! - `/t/<tenant>/csi/volumes/<volume_id>` -> [`CsiVolumeRecord`]
//! - `/t/<tenant>/csi/volume-names/<sha256_hex>` -> `volume_id` (idempotent `CreateVolume`)
//! - `/t/<tenant>/csi/snapshots/<snapshot_id>` -> [`CsiSnapshotRecord`]
//! - `/t/<tenant>/csi/snapshot-names/<sha256_hex>` -> `snapshot_id` (idempotent `CreateSnapshot`)
//! - `/t/<tenant>/csi/fences/<volume_id>` -> [`VolumeFenceCounter`] (durable monotonic `fence_epoch`)
//! - `/t/<tenant>/csi/attachments/<volume_id>` -> [`VolumeAttachmentRecord`] (leased RW attachment)
//! - `/t/<tenant>/csi/ro-attachments/<volume_id>/<node_id>` -> [`VolumeAttachmentRecord`] (leased RO)

use crate::spec::{CsiError, CsiResult, CsiStatusCode};
use abi::Errno;
use abi::cluster_state::{
    ClusterCall, ClusterError, ClusterReply, Compare, CompareOp, CompareTarget, KeyValue, RangeEnd,
    TxnOp, TxnOpReply, valid_key_segment, valid_tenant_name,
};
use os_cluster_state::fencing::{decode_record, encode_record};
use os_cluster_state::{ClusterGrant, ClusterStore};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CsiVolumeKind {
    Cowfs,
    Block,
}

impl CsiVolumeKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cowfs => "cowfs",
            Self::Block => "block",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "cowfs" => Some(Self::Cowfs),
            "block" => Some(Self::Block),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsiVolumeRecord {
    pub volume_id: String,
    pub name: String,
    pub name_hash: String,
    pub kind: CsiVolumeKind,
    pub capacity_bytes: u64,
    pub block_size: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_snapshot_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_volume_id: Option<String>,
    pub created_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CsiSnapshotRecord {
    pub snapshot_id: String,
    pub name: String,
    pub name_hash: String,
    pub source_volume_id: String,
    pub cowfs_snapshot_name: String,
    pub volume_kind: CsiVolumeKind,
    pub size_bytes: u64,
    pub created_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeFenceCounter {
    pub volume_id: String,
    pub fence_epoch: u64,
    #[serde(default)]
    pub ro_generation: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeAttachmentRecord {
    pub volume_id: String,
    pub node_id: String,
    pub fence_epoch: u64,
    pub lease_id: u64,
    pub readonly: bool,
    pub published_at: u64,
    pub lease_ttl_secs: u64,
}

pub fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    let digest = h.finalize();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

pub fn map_cluster_err(e: ClusterError) -> CsiError {
    let code = match e.errno {
        Errno::EINVAL => CsiStatusCode::InvalidArgument,
        Errno::ENOENT => CsiStatusCode::NotFound,
        Errno::EEXIST => CsiStatusCode::AlreadyExists,
        Errno::EACCES | Errno::EPERM => CsiStatusCode::PermissionDenied,
        Errno::ESTALE | Errno::EBUSY => CsiStatusCode::FailedPrecondition,
        Errno::ENOSPC | Errno::EFBIG | Errno::E2BIG => CsiStatusCode::ResourceExhausted,
        _ => CsiStatusCode::Internal,
    };
    CsiError::new(code, e.to_string())
}

fn check_tenant_seg(tenant: &str, seg: &str) -> CsiResult<()> {
    if !valid_tenant_name(tenant) || !valid_key_segment(seg) {
        return Err(CsiError::invalid_argument(
            "invalid tenant or CSI record identifier",
        ));
    }
    Ok(())
}

pub fn csi_volume_key(tenant: &str, volume_id: &str) -> CsiResult<String> {
    check_tenant_seg(tenant, volume_id)?;
    Ok(format!("/t/{tenant}/csi/volumes/{volume_id}"))
}

pub fn csi_volumes_prefix(tenant: &str) -> CsiResult<String> {
    if !valid_tenant_name(tenant) {
        return Err(CsiError::invalid_argument("invalid tenant"));
    }
    Ok(format!("/t/{tenant}/csi/volumes/"))
}

pub fn csi_volume_name_key(tenant: &str, name_hash: &str) -> CsiResult<String> {
    check_tenant_seg(tenant, name_hash)?;
    Ok(format!("/t/{tenant}/csi/volume-names/{name_hash}"))
}

pub fn csi_snapshot_key(tenant: &str, snapshot_id: &str) -> CsiResult<String> {
    check_tenant_seg(tenant, snapshot_id)?;
    Ok(format!("/t/{tenant}/csi/snapshots/{snapshot_id}"))
}

pub fn csi_snapshots_prefix(tenant: &str) -> CsiResult<String> {
    if !valid_tenant_name(tenant) {
        return Err(CsiError::invalid_argument("invalid tenant"));
    }
    Ok(format!("/t/{tenant}/csi/snapshots/"))
}

pub fn csi_snapshot_name_key(tenant: &str, name_hash: &str) -> CsiResult<String> {
    check_tenant_seg(tenant, name_hash)?;
    Ok(format!("/t/{tenant}/csi/snapshot-names/{name_hash}"))
}

pub fn csi_fence_key(tenant: &str, volume_id: &str) -> CsiResult<String> {
    check_tenant_seg(tenant, volume_id)?;
    Ok(format!("/t/{tenant}/csi/fences/{volume_id}"))
}

pub fn csi_attachment_key(tenant: &str, volume_id: &str) -> CsiResult<String> {
    check_tenant_seg(tenant, volume_id)?;
    Ok(format!("/t/{tenant}/csi/attachments/{volume_id}"))
}

pub fn csi_ro_attachment_key(tenant: &str, volume_id: &str, node_id: &str) -> CsiResult<String> {
    check_tenant_seg(tenant, volume_id)?;
    check_tenant_seg(tenant, node_id)?;
    Ok(format!(
        "/t/{tenant}/csi/ro-attachments/{volume_id}/{node_id}"
    ))
}

pub fn csi_ro_attachments_prefix(tenant: &str, volume_id: &str) -> CsiResult<String> {
    check_tenant_seg(tenant, volume_id)?;
    Ok(format!("/t/{tenant}/csi/ro-attachments/{volume_id}/"))
}

fn exact_range_op(key: String) -> TxnOp {
    TxnOp::Range {
        key,
        range_end: RangeEnd::Exact,
        limit: Some(1),
        keys_only: false,
        count_only: false,
    }
}

pub async fn get_exact_kv<C: ClusterStore>(
    store: &C,
    grant: &ClusterGrant,
    key: String,
    now_secs: u64,
) -> CsiResult<Option<KeyValue>> {
    let reply = store
        .rpc(
            grant,
            ClusterCall::Range {
                key,
                range_end: RangeEnd::Exact,
                revision: 0,
                limit: Some(1),
                keys_only: false,
                count_only: false,
            },
            now_secs,
        )
        .await
        .map_err(map_cluster_err)?;
    match reply {
        ClusterReply::Range { mut kvs, .. } => Ok(kvs.pop()),
        _ => Err(CsiError::internal("unexpected ClusterState reply")),
    }
}

pub async fn list_prefix_kvs<C: ClusterStore>(
    store: &C,
    grant: &ClusterGrant,
    prefix: String,
    limit: Option<u32>,
    now_secs: u64,
) -> CsiResult<Vec<KeyValue>> {
    let reply = store
        .rpc(
            grant,
            ClusterCall::Range {
                key: prefix,
                range_end: RangeEnd::Prefix,
                revision: 0,
                limit,
                keys_only: false,
                count_only: false,
            },
            now_secs,
        )
        .await
        .map_err(map_cluster_err)?;
    match reply {
        ClusterReply::Range { kvs, .. } => Ok(kvs),
        _ => Err(CsiError::internal("unexpected ClusterState reply")),
    }
}

/// Atomically acquire a fenced publish lease for `(volume_id, node_id)` in `ClusterState`.
///
/// - For RW (`!readonly`): refuses if another node currently holds an active RW attachment lease;
///   atomically bumps `fence_epoch` on `/t/<tenant>/csi/fences/<volume_id>` and writes the
///   lease-bound `/t/<tenant>/csi/attachments/<volume_id>` record.
/// - For RO (`readonly`): permits concurrent RO readers on multiple nodes (writing lease-bound
///   `/t/<tenant>/csi/ro-attachments/<volume_id>/<node_id>`), refusing only if an active RW
///   attachment exists on a different node.
#[allow(clippy::too_many_arguments)]
pub async fn acquire_volume_publish_lease<C: ClusterStore>(
    store: &C,
    grant: &ClusterGrant,
    tenant: &str,
    volume_id: &str,
    node_id: &str,
    readonly: bool,
    lease_ttl_secs: u64,
    now_secs: u64,
) -> CsiResult<VolumeAttachmentRecord> {
    let vol_k = csi_volume_key(tenant, volume_id)?;
    let fence_k = csi_fence_key(tenant, volume_id)?;
    let rw_k = csi_attachment_key(tenant, volume_id)?;
    let ro_k = csi_ro_attachment_key(tenant, volume_id, node_id)?;

    // Ensure the volume exists.
    if get_exact_kv(store, grant, vol_k.clone(), now_secs)
        .await?
        .is_none()
    {
        return Err(CsiError::not_found(format!(
            "volume {volume_id} does not exist"
        )));
    }

    // Retry bounded CAS loop on concurrent fence counter updates.
    for _ in 0..8 {
        let rw_kv = get_exact_kv(store, grant, rw_k.clone(), now_secs).await?;
        let fence_kv = get_exact_kv(store, grant, fence_k.clone(), now_secs).await?;

        if !readonly {
            if let Some(ref existing_kv) = rw_kv {
                let existing: VolumeAttachmentRecord =
                    decode_record(existing_kv).map_err(map_cluster_err)?;
                if existing.node_id == node_id {
                    // Idempotent re-publish on same node if lease is still alive.
                    let ttl_ok = store
                        .rpc(
                            grant,
                            ClusterCall::LeaseKeepAlive {
                                lease_id: existing.lease_id,
                            },
                            now_secs,
                        )
                        .await
                        .is_ok();
                    if ttl_ok {
                        return Ok(existing);
                    }
                } else {
                    return Err(CsiError::failed_precondition(format!(
                        "volume {volume_id} is already published RW on node {}",
                        existing.node_id
                    )));
                }
            }
            // Refuse RW publish while RO readers are attached on other nodes.
            let ro_kvs = list_prefix_kvs(
                store,
                grant,
                csi_ro_attachments_prefix(tenant, volume_id)?,
                Some(16),
                now_secs,
            )
            .await?;
            if let Some(conflict) = ro_kvs.iter().find_map(|kv| {
                decode_record::<VolumeAttachmentRecord>(kv)
                    .ok()
                    .filter(|r| r.node_id != node_id)
            }) {
                return Err(CsiError::failed_precondition(format!(
                    "volume {volume_id} is published RO on node {}",
                    conflict.node_id
                )));
            }
        } else {
            // RO publish: refuse if another node holds an active RW attachment.
            if let Some(ref existing_kv) = rw_kv {
                let existing: VolumeAttachmentRecord =
                    decode_record(existing_kv).map_err(map_cluster_err)?;
                if existing.node_id != node_id {
                    return Err(CsiError::failed_precondition(format!(
                        "volume {volume_id} is currently published RW on node {}",
                        existing.node_id
                    )));
                }
            }
            if let Some(ref existing_ro_kv) =
                get_exact_kv(store, grant, ro_k.clone(), now_secs).await?
            {
                let existing: VolumeAttachmentRecord =
                    decode_record(existing_ro_kv).map_err(map_cluster_err)?;
                if store
                    .rpc(
                        grant,
                        ClusterCall::LeaseKeepAlive {
                            lease_id: existing.lease_id,
                        },
                        now_secs,
                    )
                    .await
                    .is_ok()
                {
                    return Ok(existing);
                }
            }
        }

        // Grant fresh ClusterState lease for this attachment.
        let granted = store
            .rpc(
                grant,
                ClusterCall::LeaseGrant {
                    ttl_secs: lease_ttl_secs,
                    node_id: None,
                },
                now_secs,
            )
            .await
            .map_err(map_cluster_err)?;
        let lease_id = match granted {
            ClusterReply::LeaseGranted { lease_id, .. } => lease_id,
            _ => return Err(CsiError::internal("expected LeaseGranted reply")),
        };

        let (prev_epoch, prev_ro_gen, fence_cmp) = match &fence_kv {
            Some(kv) => {
                let c: VolumeFenceCounter = decode_record(kv).map_err(map_cluster_err)?;
                (
                    c.fence_epoch,
                    c.ro_generation,
                    Compare {
                        key: fence_k.clone(),
                        op: CompareOp::Equal,
                        target: CompareTarget::ModRevision(kv.mod_revision),
                    },
                )
            }
            None => (
                0,
                0,
                Compare {
                    key: fence_k.clone(),
                    op: CompareOp::Equal,
                    target: CompareTarget::Version(0),
                },
            ),
        };

        let next_epoch = if readonly {
            prev_epoch
        } else {
            prev_epoch
                .checked_add(1)
                .ok_or_else(|| CsiError::resource_exhausted("CSI volume fence epoch overflow"))?
        };
        let next_ro_gen = if readonly {
            prev_ro_gen
                .checked_add(1)
                .ok_or_else(|| CsiError::resource_exhausted("CSI volume RO generation overflow"))?
        } else {
            prev_ro_gen
        };
        let attachment = VolumeAttachmentRecord {
            volume_id: volume_id.to_string(),
            node_id: node_id.to_string(),
            fence_epoch: next_epoch,
            lease_id,
            readonly,
            published_at: now_secs,
            lease_ttl_secs,
        };

        let counter = VolumeFenceCounter {
            volume_id: volume_id.to_string(),
            fence_epoch: next_epoch,
            ro_generation: next_ro_gen,
        };

        let mut compares = vec![
            Compare {
                key: vol_k.clone(),
                op: CompareOp::Greater,
                target: CompareTarget::Version(0),
            },
            fence_cmp,
        ];
        let mut success = vec![TxnOp::Put {
            key: fence_k.clone(),
            value_b64: encode_record(&counter).map_err(map_cluster_err)?,
            lease_id: 0,
            prev_kv: false,
        }];
        if !readonly {
            // Require RW attachment key absent (or previously expired).
            compares.push(Compare {
                key: rw_k.clone(),
                op: CompareOp::Equal,
                target: CompareTarget::Version(0),
            });
            success.push(TxnOp::Put {
                key: rw_k.clone(),
                value_b64: encode_record(&attachment).map_err(map_cluster_err)?,
                lease_id,
                prev_kv: false,
            });
        } else {
            // Require no conflicting RW attachment on another node.
            if let Some(ref existing_kv) = rw_kv {
                compares.push(Compare {
                    key: rw_k.clone(),
                    op: CompareOp::Equal,
                    target: CompareTarget::ModRevision(existing_kv.mod_revision),
                });
            } else {
                compares.push(Compare {
                    key: rw_k.clone(),
                    op: CompareOp::Equal,
                    target: CompareTarget::Version(0),
                });
            }
            success.push(TxnOp::Put {
                key: ro_k.clone(),
                value_b64: encode_record(&attachment).map_err(map_cluster_err)?,
                lease_id,
                prev_kv: false,
            });
        }

        let txn_reply = store
            .rpc(
                grant,
                ClusterCall::Txn {
                    compare: compares,
                    success,
                    failure: vec![exact_range_op(vol_k.clone()), exact_range_op(rw_k.clone())],
                },
                now_secs,
            )
            .await
            .map_err(map_cluster_err)?;

        match txn_reply {
            ClusterReply::Txn {
                succeeded: true, ..
            } => return Ok(attachment),
            ClusterReply::Txn {
                succeeded: false,
                responses,
                ..
            } => {
                // Revoke unused lease before retrying or returning error.
                let _ = store
                    .rpc(grant, ClusterCall::LeaseRevoke { lease_id }, now_secs)
                    .await;
                if let Some(TxnOpReply::Range { kvs, .. }) = responses.first()
                    && kvs.is_empty()
                {
                    return Err(CsiError::not_found(format!(
                        "volume {volume_id} was deleted concurrently"
                    )));
                }
                if !readonly
                    && let Some(TxnOpReply::Range { kvs, .. }) = responses.get(1)
                    && let Some(existing_kv) = kvs.first()
                {
                    let existing: VolumeAttachmentRecord =
                        decode_record(existing_kv).map_err(map_cluster_err)?;
                    if existing.node_id != node_id {
                        return Err(CsiError::failed_precondition(format!(
                            "volume {volume_id} is already published RW on node {}",
                            existing.node_id
                        )));
                    }
                }
            }
            _ => return Err(CsiError::internal("expected Txn reply")),
        }
    }

    Err(CsiError::new(
        CsiStatusCode::Aborted,
        "publish lease CAS contention exceeded retries",
    ))
}

/// Authoritatively verify a node's publish fencing token (`fence_epoch`, `lease_id`, `node_id`)
/// against `ClusterState`. Returns `FailedPrecondition` (`ESTALE`) on any mismatch or expired lease.
#[allow(clippy::too_many_arguments)]
pub async fn verify_volume_fence<C: ClusterStore>(
    store: &C,
    grant: &ClusterGrant,
    tenant: &str,
    volume_id: &str,
    node_id: &str,
    expected_fence_epoch: u64,
    expected_lease_id: u64,
    readonly: bool,
    now_secs: u64,
) -> CsiResult<VolumeAttachmentRecord> {
    let key = if readonly {
        csi_ro_attachment_key(tenant, volume_id, node_id)?
    } else {
        csi_attachment_key(tenant, volume_id)?
    };
    let kv = get_exact_kv(store, grant, key, now_secs)
        .await?
        .ok_or_else(|| {
            CsiError::failed_precondition(format!(
                "ESTALE: publish lease missing or expired for volume {volume_id}"
            ))
        })?;
    let att: VolumeAttachmentRecord = decode_record(&kv).map_err(map_cluster_err)?;
    if att.node_id != node_id
        || att.lease_id != expected_lease_id
        || kv.lease_id != expected_lease_id
    {
        return Err(CsiError::failed_precondition(format!(
            "ESTALE: publish attachment superseded for volume {volume_id}"
        )));
    }
    if !readonly {
        let fence_kv = get_exact_kv(store, grant, csi_fence_key(tenant, volume_id)?, now_secs)
            .await?
            .ok_or_else(|| CsiError::failed_precondition("ESTALE: missing volume fence counter"))?;
        let counter: VolumeFenceCounter = decode_record(&fence_kv).map_err(map_cluster_err)?;
        if counter.fence_epoch != expected_fence_epoch || att.fence_epoch != expected_fence_epoch {
            return Err(CsiError::failed_precondition(format!(
                "ESTALE: fence epoch mismatch (expected {expected_fence_epoch}, live {})",
                counter.fence_epoch
            )));
        }
    }
    // Confirm lease is live right now.
    let ttl = store
        .rpc(
            grant,
            ClusterCall::LeaseTimeToLive {
                lease_id: expected_lease_id,
                keys: false,
            },
            now_secs,
        )
        .await
        .map_err(|_| CsiError::failed_precondition("ESTALE: publish lease expired or revoked"))?;
    match ttl {
        ClusterReply::LeaseTtl {
            remaining_ttl_secs, ..
        } if remaining_ttl_secs > 0 => Ok(att),
        _ => Err(CsiError::failed_precondition(
            "ESTALE: publish lease expired",
        )),
    }
}

/// Release a node's publish attachment (RW or RO) and revoke its `ClusterState` lease.
/// Idempotent when already unpublished.
pub async fn release_volume_publish_lease<C: ClusterStore>(
    store: &C,
    grant: &ClusterGrant,
    tenant: &str,
    volume_id: &str,
    node_id: &str,
    now_secs: u64,
) -> CsiResult<()> {
    // Check RW attachment first.
    let rw_k = csi_attachment_key(tenant, volume_id)?;
    if let Some(kv) = get_exact_kv(store, grant, rw_k.clone(), now_secs).await? {
        let att: VolumeAttachmentRecord = decode_record(&kv).map_err(map_cluster_err)?;
        if node_id.is_empty() || att.node_id == node_id {
            let _ = store
                .rpc(
                    grant,
                    ClusterCall::Txn {
                        compare: vec![Compare {
                            key: rw_k.clone(),
                            op: CompareOp::Equal,
                            target: CompareTarget::ModRevision(kv.mod_revision),
                        }],
                        success: vec![TxnOp::DeleteRange {
                            key: rw_k,
                            range_end: RangeEnd::Exact,
                            prev_kv: false,
                        }],
                        failure: vec![],
                    },
                    now_secs,
                )
                .await;
            let _ = store
                .rpc(
                    grant,
                    ClusterCall::LeaseRevoke {
                        lease_id: att.lease_id,
                    },
                    now_secs,
                )
                .await;
        }
    }

    // Check RO attachment for this node (or all nodes if node_id empty).
    if !node_id.is_empty() {
        let ro_k = csi_ro_attachment_key(tenant, volume_id, node_id)?;
        if let Some(kv) = get_exact_kv(store, grant, ro_k.clone(), now_secs).await? {
            let att: VolumeAttachmentRecord = decode_record(&kv).map_err(map_cluster_err)?;
            let _ = store
                .rpc(
                    grant,
                    ClusterCall::Txn {
                        compare: vec![Compare {
                            key: ro_k.clone(),
                            op: CompareOp::Equal,
                            target: CompareTarget::ModRevision(kv.mod_revision),
                        }],
                        success: vec![TxnOp::DeleteRange {
                            key: ro_k,
                            range_end: RangeEnd::Exact,
                            prev_kv: false,
                        }],
                        failure: vec![],
                    },
                    now_secs,
                )
                .await;
            let _ = store
                .rpc(
                    grant,
                    ClusterCall::LeaseRevoke {
                        lease_id: att.lease_id,
                    },
                    now_secs,
                )
                .await;
        }
    } else {
        let ro_prefix = csi_ro_attachments_prefix(tenant, volume_id)?;
        let ro_kvs = list_prefix_kvs(store, grant, ro_prefix, Some(256), now_secs).await?;
        for kv in ro_kvs {
            let att: VolumeAttachmentRecord = match decode_record(&kv) {
                Ok(a) => a,
                Err(_) => continue,
            };
            let _ = store
                .rpc(
                    grant,
                    ClusterCall::Txn {
                        compare: vec![Compare {
                            key: kv.key.clone(),
                            op: CompareOp::Equal,
                            target: CompareTarget::ModRevision(kv.mod_revision),
                        }],
                        success: vec![TxnOp::DeleteRange {
                            key: kv.key,
                            range_end: RangeEnd::Exact,
                            prev_kv: false,
                        }],
                        failure: vec![],
                    },
                    now_secs,
                )
                .await;
            let _ = store
                .rpc(
                    grant,
                    ClusterCall::LeaseRevoke {
                        lease_id: att.lease_id,
                    },
                    now_secs,
                )
                .await;
        }
    }
    Ok(())
}
