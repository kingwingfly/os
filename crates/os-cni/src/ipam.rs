//! Atomic lease-backed IPAM over `ClusterState` with CAS-guarded idempotent `DEL`.

use crate::spec::{
    CNI_ERR_INTERNAL, CNI_ERR_INVALID_CONFIG, CNI_ERR_IO_FAILURE, CNI_ERR_TRY_AGAIN_LATER,
    CniAttachmentDescriptor, CniError,
};
use abi::Errno;
use abi::cluster_state::{
    ClusterCall, ClusterError, ClusterReply, Compare, CompareOp, CompareTarget, KeyValue, RangeEnd,
    TxnOp,
};
use abi::overlay::{
    IpamLeaseRecord, Ipv4Cidr, OVERLAY_V4_SUPERNET, OverlayEndpointRecord, TenantOverlayConfig,
    overlay_config_key, overlay_endpoint_key, overlay_ipam_v4_key, overlay_ipam_v4_prefix,
    overlay_node_endpoint_key,
};
use os_cluster_state::fencing::{decode_record, encode_record};
use os_cluster_state::{ClusterGrant, ClusterStore};
use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub type ClockFn = Arc<dyn Fn() -> u64 + Send + Sync>;

pub fn system_clock_secs() -> ClockFn {
    Arc::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(1_700_000_000)
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpamAllocRequest {
    pub tenant: String,
    pub network: String,
    pub endpoint_id: String,
    pub node_id: String,
    pub ifname: String,
    pub host_kind: String,
    pub mtu: u16,
    pub lease_ttl_secs: u64,
    pub static_ip: Option<Ipv4Addr>,
    pub requested_cidr: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocatedIpam {
    pub tenant: String,
    pub network: String,
    pub endpoint_id: String,
    pub node_id: String,
    pub ifname: String,
    pub ip: Ipv4Addr,
    pub prefix_len: u8,
    pub gateway: Ipv4Addr,
    pub cidr: Ipv4Cidr,
    pub ipv6: Option<String>,
    pub mtu: u16,
    pub lease_id: u64,
    pub fence_epoch: u64,
    pub allocated_at: u64,
}

fn map_cluster_err(err: ClusterError, ctx: &str) -> CniError {
    let code = match err.errno {
        Errno::ENOSPC | Errno::EBUSY | Errno::EAGAIN => CNI_ERR_TRY_AGAIN_LATER,
        Errno::EINVAL => CNI_ERR_INVALID_CONFIG,
        Errno::EACCES | Errno::EPERM | Errno::EIO | Errno::ETIMEDOUT => CNI_ERR_IO_FAILURE,
        _ => CNI_ERR_INTERNAL,
    };
    let detail = match err.detail {
        Some(ref msg) if !msg.is_empty() => format!("{ctx}: {:?}: {msg}", err.errno),
        _ => format!("{ctx}: {:?}", err.errno),
    };
    CniError::new(code, format!("ClusterState error during {ctx}"), detail)
}

async fn get_single_kv<C: ClusterStore>(
    store: &C,
    grant: &ClusterGrant,
    key: &str,
    now_secs: u64,
) -> Result<(u64, Option<KeyValue>), CniError> {
    let reply = store
        .rpc(
            grant,
            ClusterCall::Range {
                key: key.to_string(),
                range_end: RangeEnd::Exact,
                limit: Some(1),
                revision: 0,
                keys_only: false,
                count_only: false,
            },
            now_secs,
        )
        .await
        .map_err(|e| map_cluster_err(e, "range"))?;
    match reply {
        ClusterReply::Range { revision, kvs, .. } => Ok((revision, kvs.into_iter().next())),
        _ => Err(CniError::new(
            CNI_ERR_INTERNAL,
            "unexpected ClusterState reply",
            "expected Range reply",
        )),
    }
}

async fn list_prefix<C: ClusterStore>(
    store: &C,
    grant: &ClusterGrant,
    prefix: &str,
    now_secs: u64,
) -> Result<(u64, Vec<KeyValue>), CniError> {
    let reply = store
        .rpc(
            grant,
            ClusterCall::Range {
                key: prefix.to_string(),
                range_end: RangeEnd::Prefix,
                limit: Some(512),
                revision: 0,
                keys_only: false,
                count_only: false,
            },
            now_secs,
        )
        .await
        .map_err(|e| map_cluster_err(e, "range prefix"))?;
    match reply {
        ClusterReply::Range { revision, kvs, .. } => Ok((revision, kvs)),
        _ => Err(CniError::new(
            CNI_ERR_INTERNAL,
            "unexpected ClusterState reply",
            "expected Range prefix reply",
        )),
    }
}

async fn ensure_tenant_config<C: ClusterStore>(
    store: &C,
    grant: &ClusterGrant,
    tenant: &str,
    network: &str,
    requested_cidr: Option<&str>,
    mtu: u16,
    now_secs: u64,
) -> Result<TenantOverlayConfig, CniError> {
    let key = overlay_config_key(tenant);
    if let (_, Some(kv)) = get_single_kv(store, grant, &key, now_secs).await? {
        return decode_record::<TenantOverlayConfig>(&kv)
            .map_err(|e| map_cluster_err(e, "decode TenantOverlayConfig"));
    }

    let mut cfg = TenantOverlayConfig::default_for(tenant, network);
    cfg.mtu = mtu;
    if let Some(raw_cidr) = requested_cidr {
        let parsed = Ipv4Cidr::parse(raw_cidr).ok_or_else(|| {
            CniError::new(
                CNI_ERR_INVALID_CONFIG,
                "invalid overlay cidr",
                format!("'{raw_cidr}' is not a valid IPv4 CIDR"),
            )
        })?;
        if !OVERLAY_V4_SUPERNET.covers(parsed) || parsed.prefix_len > 29 {
            return Err(CniError::new(
                CNI_ERR_INVALID_CONFIG,
                "overlay cidr outside 10.64.0.0/10 supernet",
                format!("cidr '{raw_cidr}' must be inside {OVERLAY_V4_SUPERNET} with prefix <= 29"),
            ));
        }
        let gw = parsed.gateway_addr().ok_or_else(|| {
            CniError::new(
                CNI_ERR_INVALID_CONFIG,
                "overlay cidr too small for gateway",
                raw_cidr.to_string(),
            )
        })?;
        cfg.cidr_v4 = parsed.to_string();
        cfg.gateway_v4 = gw.to_string();
    }

    let val_b64 =
        encode_record(&cfg).map_err(|e| map_cluster_err(e, "encode TenantOverlayConfig"))?;
    let txn = store
        .rpc(
            grant,
            ClusterCall::Txn {
                compare: vec![Compare {
                    key: key.clone(),
                    op: CompareOp::Equal,
                    target: CompareTarget::Version(0),
                }],
                success: vec![TxnOp::Put {
                    key: key.clone(),
                    value_b64: val_b64,
                    lease_id: 0,
                    prev_kv: false,
                }],
                failure: vec![],
            },
            now_secs,
        )
        .await
        .map_err(|e| map_cluster_err(e, "init overlay config"))?;
    if let ClusterReply::Txn {
        succeeded: true, ..
    } = txn
    {
        return Ok(cfg);
    }
    if let (_, Some(kv)) = get_single_kv(store, grant, &key, now_secs).await? {
        return decode_record::<TenantOverlayConfig>(&kv)
            .map_err(|e| map_cluster_err(e, "decode TenantOverlayConfig"));
    }
    Ok(cfg)
}

async fn grant_lease<C: ClusterStore>(
    store: &C,
    grant: &ClusterGrant,
    ttl_secs: u64,
    node_id: &str,
    now_secs: u64,
) -> Result<u64, CniError> {
    let first = store
        .rpc(
            grant,
            ClusterCall::LeaseGrant {
                ttl_secs,
                node_id: Some(node_id.to_string()),
            },
            now_secs,
        )
        .await;
    let reply = match first {
        Ok(r) => r,
        Err(e) if e.errno == Errno::EACCES => store
            .rpc(
                grant,
                ClusterCall::LeaseGrant {
                    ttl_secs,
                    node_id: None,
                },
                now_secs,
            )
            .await
            .map_err(|e2| map_cluster_err(e2, "lease_grant"))?,
        Err(e) => return Err(map_cluster_err(e, "lease_grant")),
    };
    match reply {
        ClusterReply::LeaseGranted { lease_id, .. } => Ok(lease_id),
        _ => Err(CniError::new(
            CNI_ERR_INTERNAL,
            "unexpected LeaseGrant reply",
            "",
        )),
    }
}

async fn lease_is_alive<C: ClusterStore>(
    store: &C,
    grant: &ClusterGrant,
    lease_id: u64,
    now_secs: u64,
) -> Result<bool, CniError> {
    if lease_id == 0 {
        return Ok(false);
    }
    match store
        .rpc(
            grant,
            ClusterCall::LeaseTimeToLive {
                lease_id,
                keys: false,
            },
            now_secs,
        )
        .await
    {
        Ok(ClusterReply::LeaseTtl {
            remaining_ttl_secs, ..
        }) => Ok(remaining_ttl_secs > 0),
        Err(e) if e.errno == Errno::ENOENT => Ok(false),
        Err(e) => Err(map_cluster_err(e, "lease_ttl")),
        _ => Ok(false),
    }
}

/// Atomically allocate (or idempotently return existing live) lease-backed IP in `ClusterState`.
pub async fn allocate_ipam<C: ClusterStore>(
    store: &C,
    grant: &ClusterGrant,
    req: &IpamAllocRequest,
    now_secs: u64,
) -> Result<AllocatedIpam, CniError> {
    let cfg = ensure_tenant_config(
        store,
        grant,
        &req.tenant,
        &req.network,
        req.requested_cidr.as_deref(),
        req.mtu,
        now_secs,
    )
    .await?;
    let cidr = Ipv4Cidr::parse(&cfg.cidr_v4).ok_or_else(|| {
        CniError::new(
            CNI_ERR_INTERNAL,
            "invalid tenant CIDR in ClusterState",
            cfg.cidr_v4.clone(),
        )
    })?;
    let gateway: Ipv4Addr = cfg
        .gateway_v4
        .parse()
        .ok()
        .or_else(|| cidr.gateway_addr())
        .ok_or_else(|| {
            CniError::new(CNI_ERR_INTERNAL, "no gateway in CIDR", cfg.cidr_v4.clone())
        })?;
    let ep_key = overlay_endpoint_key(&req.tenant, &req.endpoint_id);
    let node_ep_key = overlay_node_endpoint_key(&req.tenant, &req.node_id, &req.endpoint_id);

    // Idempotent ADD retry: if endpoint already has a live lease, return it directly
    // (rejecting a conflicting explicit staticIp request).
    if let (_, Some(ep_kv)) = get_single_kv(store, grant, &ep_key, now_secs).await?
        && let Ok(existing) = decode_record::<OverlayEndpointRecord>(&ep_kv)
        && existing.endpoint_id == req.endpoint_id
        && lease_is_alive(store, grant, existing.lease_id, now_secs).await?
        && let Ok(ip) = existing.ip.parse::<Ipv4Addr>()
    {
        if let Some(want) = req.static_ip
            && want != ip
        {
            return Err(CniError::new(
                CNI_ERR_INVALID_CONFIG,
                "conflicting staticIp for existing endpoint",
                format!(
                    "endpoint '{}' already holds live IP {ip}, cannot reassign to {want}",
                    req.endpoint_id
                ),
            ));
        }
        return Ok(AllocatedIpam {
            tenant: existing.tenant,
            network: existing.network,
            endpoint_id: existing.endpoint_id,
            node_id: existing.node_id,
            ifname: existing.ifname,
            ip,
            prefix_len: cidr.prefix_len,
            gateway,
            cidr,
            ipv6: existing.ipv6,
            mtu: existing.mtu,
            lease_id: existing.lease_id,
            fence_epoch: existing.fence_epoch,
            allocated_at: now_secs,
        });
    }

    if let Some(static_ip) = req.static_ip
        && !cidr.is_valid_host_ip(static_ip)
    {
        return Err(CniError::new(
            CNI_ERR_INVALID_CONFIG,
            "staticIp outside tenant host range",
            format!("staticIp {static_ip} is not a usable host inside {cidr} (gateway {gateway})"),
        ));
    }

    let lease_id = grant_lease(store, grant, req.lease_ttl_secs, &req.node_id, now_secs).await?;
    let prefix = overlay_ipam_v4_prefix(&req.tenant);

    for _attempt in 0..16 {
        let (rev, kvs) = match list_prefix(store, grant, &prefix, now_secs).await {
            Ok(v) => v,
            Err(e) => {
                let _ = store
                    .rpc(grant, ClusterCall::LeaseRevoke { lease_id }, now_secs)
                    .await;
                return Err(e);
            }
        };

        let mut used = BTreeSet::new();
        for kv in &kvs {
            if let Some(seg) = kv.key.rsplit('/').next()
                && let Some(ip) = abi::overlay::parse_ipv4_key_segment(seg)
            {
                used.insert(ip);
            }
            if let Ok(rec) = decode_record::<IpamLeaseRecord>(kv)
                && let Ok(ip) = rec.ip.parse::<Ipv4Addr>()
            {
                used.insert(ip);
            }
        }

        let candidate = if let Some(static_ip) = req.static_ip {
            if used.contains(&static_ip) {
                let _ = store
                    .rpc(grant, ClusterCall::LeaseRevoke { lease_id }, now_secs)
                    .await;
                return Err(CniError::new(
                    CNI_ERR_TRY_AGAIN_LATER,
                    "requested staticIp already allocated",
                    format!("{static_ip} is currently leased"),
                ));
            }
            Some(static_ip)
        } else {
            let mut idx = 0u32;
            let mut found = None;
            while let Some(ip) = cidr.host_ip(idx) {
                if !used.contains(&ip) {
                    found = Some(ip);
                    break;
                }
                idx += 1;
            }
            found
        };

        let Some(chosen_ip) = candidate else {
            let _ = store
                .rpc(grant, ClusterCall::LeaseRevoke { lease_id }, now_secs)
                .await;
            return Err(CniError::new(
                CNI_ERR_TRY_AGAIN_LATER,
                "tenant IPv4 subnet exhausted",
                format!("no free host IPs remaining in {cidr}"),
            ));
        };

        let fence_epoch = rev.saturating_add(1);
        let ip_key = overlay_ipam_v4_key(&req.tenant, chosen_ip);
        let ip_rec = IpamLeaseRecord {
            tenant: req.tenant.clone(),
            network: req.network.clone(),
            ip: chosen_ip.to_string(),
            prefix_len: cidr.prefix_len,
            endpoint_id: req.endpoint_id.clone(),
            node_id: req.node_id.clone(),
            ifname: req.ifname.clone(),
            host_kind: req.host_kind.clone(),
            mtu: req.mtu,
            lease_id,
            fence_epoch,
            allocated_at: now_secs,
        };
        let ep_rec = OverlayEndpointRecord {
            tenant: req.tenant.clone(),
            network: req.network.clone(),
            endpoint_id: req.endpoint_id.clone(),
            ip: chosen_ip.to_string(),
            prefix_len: cidr.prefix_len,
            gateway: gateway.to_string(),
            cidr: cidr.to_string(),
            ipv6: None,
            node_id: req.node_id.clone(),
            ifname: req.ifname.clone(),
            mtu: req.mtu,
            lease_id,
            fence_epoch,
            host_kind: req.host_kind.clone(),
            allocated_at: now_secs,
        };
        let ip_b64 =
            encode_record(&ip_rec).map_err(|e| map_cluster_err(e, "encode IpamLeaseRecord"))?;
        let ep_b64 = encode_record(&ep_rec)
            .map_err(|e| map_cluster_err(e, "encode OverlayEndpointRecord"))?;

        let txn_res = store
            .rpc(
                grant,
                ClusterCall::Txn {
                    compare: vec![
                        Compare {
                            key: ip_key.clone(),
                            op: CompareOp::Equal,
                            target: CompareTarget::Version(0),
                        },
                        Compare {
                            key: ep_key.clone(),
                            op: CompareOp::Equal,
                            target: CompareTarget::Version(0),
                        },
                    ],
                    success: vec![
                        TxnOp::Put {
                            key: ip_key,
                            value_b64: ip_b64,
                            lease_id,
                            prev_kv: false,
                        },
                        TxnOp::Put {
                            key: ep_key.clone(),
                            value_b64: ep_b64.clone(),
                            lease_id,
                            prev_kv: false,
                        },
                        TxnOp::Put {
                            key: node_ep_key.clone(),
                            value_b64: ep_b64,
                            lease_id,
                            prev_kv: false,
                        },
                    ],
                    failure: vec![],
                },
                now_secs,
            )
            .await;

        match txn_res {
            Ok(ClusterReply::Txn {
                succeeded: true, ..
            }) => {
                return Ok(AllocatedIpam {
                    tenant: req.tenant.clone(),
                    network: req.network.clone(),
                    endpoint_id: req.endpoint_id.clone(),
                    node_id: req.node_id.clone(),
                    ifname: req.ifname.clone(),
                    ip: chosen_ip,
                    prefix_len: cidr.prefix_len,
                    gateway,
                    cidr,
                    ipv6: None,
                    mtu: req.mtu,
                    lease_id,
                    fence_epoch,
                    allocated_at: now_secs,
                });
            }
            Ok(ClusterReply::Txn {
                succeeded: false, ..
            }) => {
                if let (_, Some(ep_kv)) = get_single_kv(store, grant, &ep_key, now_secs).await?
                    && let Ok(existing) = decode_record::<OverlayEndpointRecord>(&ep_kv)
                    && existing.endpoint_id == req.endpoint_id
                    && lease_is_alive(store, grant, existing.lease_id, now_secs).await?
                    && let Ok(ip) = existing.ip.parse::<Ipv4Addr>()
                {
                    let _ = store
                        .rpc(grant, ClusterCall::LeaseRevoke { lease_id }, now_secs)
                        .await;
                    if let Some(want) = req.static_ip
                        && want != ip
                    {
                        return Err(CniError::new(
                            CNI_ERR_INVALID_CONFIG,
                            "conflicting staticIp for existing endpoint",
                            format!(
                                "endpoint '{}' already holds live IP {ip}, cannot reassign to {want}",
                                req.endpoint_id
                            ),
                        ));
                    }
                    return Ok(AllocatedIpam {
                        tenant: existing.tenant,
                        network: existing.network,
                        endpoint_id: existing.endpoint_id,
                        node_id: existing.node_id,
                        ifname: existing.ifname,
                        ip,
                        prefix_len: cidr.prefix_len,
                        gateway,
                        cidr,
                        ipv6: existing.ipv6,
                        mtu: existing.mtu,
                        lease_id: existing.lease_id,
                        fence_epoch: existing.fence_epoch,
                        allocated_at: now_secs,
                    });
                }
                continue;
            }
            Err(e) => {
                let _ = store
                    .rpc(grant, ClusterCall::LeaseRevoke { lease_id }, now_secs)
                    .await;
                return Err(map_cluster_err(e, "allocate ipam txn"));
            }
            _ => {
                let _ = store
                    .rpc(grant, ClusterCall::LeaseRevoke { lease_id }, now_secs)
                    .await;
                return Err(CniError::new(
                    CNI_ERR_INTERNAL,
                    "unexpected ClusterState Txn reply",
                    "",
                ));
            }
        }
    }

    let _ = store
        .rpc(grant, ClusterCall::LeaseRevoke { lease_id }, now_secs)
        .await;
    Err(CniError::new(
        CNI_ERR_TRY_AGAIN_LATER,
        "IPAM allocation contention",
        "exceeded CAS retry budget",
    ))
}

/// Verify that the local attachment matches live `ClusterState` IPAM, endpoint record, and lease TTL.
pub async fn check_ipam<C: ClusterStore>(
    store: &C,
    grant: &ClusterGrant,
    desc: &CniAttachmentDescriptor,
    now_secs: u64,
) -> Result<(), CniError> {
    if !lease_is_alive(store, grant, desc.lease_id, now_secs).await? {
        return Err(CniError::new(
            CNI_ERR_INTERNAL,
            "IPAM lease expired or missing",
            format!(
                "lease {} for container {} is not live",
                desc.lease_id, desc.container_id
            ),
        ));
    }

    let ep_key = overlay_endpoint_key(&desc.tenant, &desc.container_id);
    let (_, ep_kv) = get_single_kv(store, grant, &ep_key, now_secs).await?;
    let ep_kv = ep_kv.ok_or_else(|| {
        CniError::new(
            CNI_ERR_INTERNAL,
            "endpoint record missing in ClusterState",
            format!("key {ep_key} not found"),
        )
    })?;
    let ep_rec: OverlayEndpointRecord =
        decode_record(&ep_kv).map_err(|e| map_cluster_err(e, "decode endpoint record"))?;
    if ep_rec.ip != desc.ip
        || ep_rec.lease_id != desc.lease_id
        || ep_rec.fence_epoch != desc.fence_epoch
        || ep_rec.ifname != desc.ifname
    {
        return Err(CniError::new(
            CNI_ERR_INTERNAL,
            "endpoint drift detected in ClusterState",
            format!(
                "local=({}, lease {}, epoch {}) remote=({}, lease {}, epoch {})",
                desc.ip,
                desc.lease_id,
                desc.fence_epoch,
                ep_rec.ip,
                ep_rec.lease_id,
                ep_rec.fence_epoch
            ),
        ));
    }

    let ip: Ipv4Addr = desc.ip.parse().map_err(|_| {
        CniError::new(
            CNI_ERR_INVALID_CONFIG,
            "invalid IP in attachment descriptor",
            desc.ip.clone(),
        )
    })?;
    let ip_key = overlay_ipam_v4_key(&desc.tenant, ip);
    let (_, ip_kv) = get_single_kv(store, grant, &ip_key, now_secs).await?;
    let ip_kv = ip_kv.ok_or_else(|| {
        CniError::new(
            CNI_ERR_INTERNAL,
            "IPAM lease record missing in ClusterState",
            format!("key {ip_key} not found"),
        )
    })?;
    let ip_rec: IpamLeaseRecord =
        decode_record(&ip_kv).map_err(|e| map_cluster_err(e, "decode IPAM record"))?;
    if ip_rec.endpoint_id != desc.container_id
        || ip_rec.lease_id != desc.lease_id
        || ip_rec.fence_epoch != desc.fence_epoch
    {
        return Err(CniError::new(
            CNI_ERR_INTERNAL,
            "IPAM ownership mismatch",
            format!(
                "ip {} is owned by endpoint '{}' (lease {}, epoch {}), expected '{}'",
                desc.ip, ip_rec.endpoint_id, ip_rec.lease_id, ip_rec.fence_epoch, desc.container_id
            ),
        ));
    }

    Ok(())
}

/// Strictly idempotent, host-loss-resilient, CAS-guarded IPAM release (`CNI DEL`).
///
/// - Recovers `(ip, lease_id, node_id)` from `ClusterState` if local `$stateDir` was wiped.
/// - Ignores `ENOENT` on `LeaseRevoke` (already expired on host loss).
/// - Deletes `ip_key` ONLY IF stored `endpoint_id == container_id` via CAS `ModRevision` check,
///   so a delayed `DEL` never frees an IP that another pod legitimately reallocated after expiry!
pub async fn release_ipam<C: ClusterStore>(
    store: &C,
    grant: &ClusterGrant,
    tenant: &str,
    node_id_hint: &str,
    container_id: &str,
    local_hint: Option<&CniAttachmentDescriptor>,
    now_secs: u64,
) -> Result<(), CniError> {
    let ep_key = overlay_endpoint_key(tenant, container_id);
    let remote_ep_kv = get_single_kv(store, grant, &ep_key, now_secs).await?.1;
    let remote_ep: Option<OverlayEndpointRecord> =
        remote_ep_kv.as_ref().and_then(|kv| decode_record(kv).ok());

    let mut candidate_leases = BTreeSet::new();
    let mut candidate_ips = BTreeSet::new();
    let mut candidate_nodes = BTreeSet::new();

    if !node_id_hint.is_empty() {
        candidate_nodes.insert(node_id_hint.to_string());
    }
    if let Some(hint) = local_hint {
        if hint.lease_id != 0 {
            candidate_leases.insert(hint.lease_id);
        }
        if let Ok(ip) = hint.ip.parse::<Ipv4Addr>() {
            candidate_ips.insert(ip);
        }
        if !hint.node_id.is_empty() {
            candidate_nodes.insert(hint.node_id.clone());
        }
    }
    if let Some(ref ep) = remote_ep {
        if ep.lease_id != 0 {
            candidate_leases.insert(ep.lease_id);
        }
        if let Ok(ip) = ep.ip.parse::<Ipv4Addr>() {
            candidate_ips.insert(ip);
        }
        if !ep.node_id.is_empty() {
            candidate_nodes.insert(ep.node_id.clone());
        }
    }

    // 1. Revoke lease(s) (monotonically unique LeaseIds; ignore ENOENT if already expired).
    for lease_id in candidate_leases {
        match store
            .rpc(grant, ClusterCall::LeaseRevoke { lease_id }, now_secs)
            .await
        {
            Ok(_) => {}
            Err(e) if e.errno == Errno::ENOENT => {}
            Err(e) => return Err(map_cluster_err(e, "lease_revoke")),
        }
    }

    // 2. CAS-guarded conditional delete of IPAM record(s): ONLY delete if `endpoint_id == container_id`.
    for ip in candidate_ips {
        let ip_key = overlay_ipam_v4_key(tenant, ip);
        if let (_, Some(kv)) = get_single_kv(store, grant, &ip_key, now_secs).await?
            && let Ok(rec) = decode_record::<IpamLeaseRecord>(&kv)
            && rec.endpoint_id == container_id
        {
            let _ = store
                .rpc(
                    grant,
                    ClusterCall::Txn {
                        compare: vec![Compare {
                            key: ip_key.clone(),
                            op: CompareOp::Equal,
                            target: CompareTarget::ModRevision(kv.mod_revision),
                        }],
                        success: vec![TxnOp::DeleteRange {
                            key: ip_key,
                            range_end: RangeEnd::Exact,
                            prev_kv: false,
                        }],
                        failure: vec![],
                    },
                    now_secs,
                )
                .await
                .map_err(|e| map_cluster_err(e, "cas delete ip_key"))?;
        }
    }

    // 3. CAS-guarded conditional delete of endpoint reverse index.
    if let (_, Some(kv)) = get_single_kv(store, grant, &ep_key, now_secs).await?
        && let Ok(rec) = decode_record::<OverlayEndpointRecord>(&kv)
        && rec.endpoint_id == container_id
    {
        let _ = store
            .rpc(
                grant,
                ClusterCall::Txn {
                    compare: vec![Compare {
                        key: ep_key.clone(),
                        op: CompareOp::Equal,
                        target: CompareTarget::ModRevision(kv.mod_revision),
                    }],
                    success: vec![TxnOp::DeleteRange {
                        key: ep_key,
                        range_end: RangeEnd::Exact,
                        prev_kv: false,
                    }],
                    failure: vec![],
                },
                now_secs,
            )
            .await
            .map_err(|e| map_cluster_err(e, "cas delete ep_key"))?;
    }

    // 4. CAS-guarded conditional delete of node-endpoint index(es).
    for nid in candidate_nodes {
        let node_ep_key = overlay_node_endpoint_key(tenant, &nid, container_id);
        if let Ok((_, Some(kv))) = get_single_kv(store, grant, &node_ep_key, now_secs).await
            && let Ok(rec) = decode_record::<OverlayEndpointRecord>(&kv)
            && rec.endpoint_id == container_id
        {
            let _ = store
                .rpc(
                    grant,
                    ClusterCall::Txn {
                        compare: vec![Compare {
                            key: node_ep_key.clone(),
                            op: CompareOp::Equal,
                            target: CompareTarget::ModRevision(kv.mod_revision),
                        }],
                        success: vec![TxnOp::DeleteRange {
                            key: node_ep_key,
                            range_end: RangeEnd::Exact,
                            prev_kv: false,
                        }],
                        failure: vec![],
                    },
                    now_secs,
                )
                .await;
        }
    }

    Ok(())
}
