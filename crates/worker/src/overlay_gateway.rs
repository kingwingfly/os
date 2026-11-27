//! Edge HTTP + WebSocket gateway for Phase 10b (`#87` `/dev/net/tun` tenant L3 overlay).
//!
//! Mounted in `lib.rs` BEFORE `with_guest_cookie` so cookie-less `node.*` credentials work
//! cleanly while browser `session.*` credentials enforce matching `os_session` cookies and
//! same-origin CSRF checks:
//! - `POST /api/overlay/attach`  — verify `RemoteScope.overlay` + `Machine` liveness, allocate
//!   lease-backed IP in `ClusterState` DO (`/t/<tenant>/overlay/...`) via least-privilege
//!   `"overlay/*"` grant, register single-use 30s upgrade ticket in `OverlayRelay` DO.
//! - `POST /api/overlay/renew`   — extend `ClusterState` lease + refresh `OverlayRelay` expiry.
//! - `POST /api/overlay/detach`  — idempotently revoke lease, CAS-delete owned IPAM/endpoint
//!   records, and disconnect `OverlayRelay` socket.
//! - `GET  /api/overlay/connect` — consume single-use `?ticket=` (strict `session.*` vs `node.*`
//!   cookie separation) OR cookie-less `X-Process-Token` + `X-OS-Instance` + `?endpoint_id=` ->
//!   Hibernatable WebSocket inside `OverlayRelay` DO (`overlay:{cluster}:{tenant}:{network}`).

use crate::auth;
use crate::cluster_gateway::ClusterDoRpc;
use crate::resources::{self, IoRequest};
use abi::Errno;
use abi::auth_v2::{RemoteScope, valid_cluster_record_id};
use abi::cluster_state::{
    ClusterCall, ClusterReply, Compare, CompareOp, CompareTarget, RangeEnd, TxnOp,
    default_cluster_name, encode_value_b64, valid_cluster_name,
};
use abi::overlay::{
    IpamLeaseRecord, OVERLAY_DEFAULT_LEASE_TTL_SECS, OVERLAY_VERSION, OverlayAttachReply,
    OverlayAttachRequest, OverlayDetachRequest, OverlayEndpointRecord, OverlayRenewReply,
    OverlayRenewRequest, OverlayScope, TUN_MAX_MTU, TUN_MIN_MTU, TenantOverlayConfig,
    overlay_config_key, overlay_endpoint_key, overlay_ipam_v4_key, overlay_ipam_v4_prefix,
    overlay_ipam_v6_key, overlay_node_endpoint_key, valid_overlay_network_name, valid_tun_ifname,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use os_cluster_state::ClusterGrant;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeSet, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use worker::*;

const MAX_OVERLAY_BODY_BYTES: usize = 8192;

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct VerifiedOverlayCred {
    pub tenant: String,
    pub ns: String,
    pub cred_hash: String,
    pub instance_id: String,
    #[allow(dead_code)]
    pub uid: u32,
    pub node_id: Option<String>,
    pub overlay: OverlayScope,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct OverlaySessionCheck {
    pub endpoint_id: String,
    pub tenant: String,
    pub ns: String,
    pub cred_hash: String,
    pub instance_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct OverlayIssueTicket {
    pub cluster: String,
    pub tenant: String,
    pub network: String,
    pub endpoint_id: String,
    pub ip: String,
    pub prefix_len: u8,
    pub gateway: String,
    pub cidr: String,
    pub ipv6: Option<String>,
    pub mtu: u16,
    pub lease_id: u64,
    pub lease_expires_at: u64,
    pub host_kind: String,
    pub ns: String,
    pub cred_hash: String,
    pub instance_id: String,
    pub allowed_peer_cidrs: Vec<String>,
    pub max_bytes_per_sec: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct OverlayTicketCreated {
    pub secret: String,
    pub expires_at: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct OverlayErr {
    pub errno: Errno,
    pub message: String,
}

impl OverlayErr {
    pub fn new(errno: Errno, message: impl Into<String>) -> Self {
        Self {
            errno,
            message: message.into(),
        }
    }
}

fn io_err(e: worker::Error) -> OverlayErr {
    OverlayErr::new(Errno::EIO, e.to_string())
}

fn header(req: &Request, name: &str) -> std::result::Result<Option<String>, OverlayErr> {
    req.headers().get(name).map_err(io_err)
}

pub(crate) fn with_security_headers(mut resp: Response) -> Result<Response> {
    let headers = Headers::new();
    for (k, v) in resp.headers().entries() {
        headers.append(&k, &v)?;
    }
    headers.set("Cache-Control", "private, no-store")?;
    headers.set("Vary", "Cookie")?;
    headers.set("X-Content-Type-Options", "nosniff")?;
    resp = resp.with_headers(headers);
    Ok(resp)
}

pub(crate) fn error_response(err: &OverlayErr) -> Result<Response> {
    let status = match err.errno {
        Errno::EACCES | Errno::EPERM => 403,
        Errno::ENOENT => 404,
        Errno::EBUSY | Errno::EEXIST | Errno::EADDRINUSE => 409,
        Errno::ESTALE => 412,
        Errno::EAGAIN => 429,
        Errno::E2BIG | Errno::EFBIG | Errno::EMSGSIZE => 413,
        Errno::ENOSPC | Errno::EDQUOT => 507,
        Errno::EPROTONOSUPPORT | Errno::EOPNOTSUPP => 501,
        Errno::EIO => 500,
        _ => 400,
    };
    let mut resp = Response::from_json(&json!({
        "errno": err.errno,
        "error": err.message,
    }))?
    .with_status(status);
    resp.headers_mut()
        .set("X-OS-Errno", &format!("{:?}", err.errno))?;
    with_security_headers(resp)
}

fn check_origin(req: &Request, url: &Url) -> std::result::Result<(), OverlayErr> {
    let origin_hdr = header(req, "Origin")?;
    let has_cookie = header(req, "Cookie")?.is_some_and(|c| !c.trim().is_empty());
    if origin_hdr.is_some() || has_cookie {
        let expected = url.origin().ascii_serialization();
        if origin_hdr.as_deref() != Some(expected.as_str()) {
            return Err(OverlayErr::new(
                Errno::EACCES,
                "overlay requests with browser origin or cookie must originate from this site",
            ));
        }
    }
    Ok(())
}

async fn read_bounded_body(
    req: &mut Request,
    max_bytes: usize,
) -> std::result::Result<Vec<u8>, OverlayErr> {
    if header(req, "Content-Length")?
        .and_then(|s| s.parse::<usize>().ok())
        .is_some_and(|n| n > max_bytes)
    {
        return Err(OverlayErr::new(Errno::E2BIG, "request body too large"));
    }
    let bytes = req.bytes().await.map_err(io_err)?;
    if bytes.len() > max_bytes {
        return Err(OverlayErr::new(Errno::E2BIG, "request body too large"));
    }
    Ok(bytes)
}

async fn verify_overlay_cred(
    req: &Request,
    env: &Env,
) -> std::result::Result<VerifiedOverlayCred, OverlayErr> {
    let headers = Headers::new();
    for name in ["Cookie", "X-Process-Token", "X-OS-Instance"] {
        if let Some(v) = header(req, name)? {
            headers.set(name, &v).map_err(io_err)?;
        }
    }
    headers
        .set("Content-Type", "application/json")
        .map_err(io_err)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post).with_headers(headers);
    let sub = Request::new_with_init(
        "https://authority/internal/service-auth/verify-overlay",
        &init,
    )
    .map_err(io_err)?;
    let mut resp = env
        .durable_object("AUTHORITY")
        .map_err(io_err)?
        .get_by_name("filesystem")
        .map_err(io_err)?
        .fetch_with_request(sub)
        .await
        .map_err(io_err)?;
    if resp.status_code() == 403 {
        return Err(OverlayErr::new(
            Errno::EACCES,
            "overlay service credential with RemoteScope.overlay required",
        ));
    }
    if resp.status_code() != 200 {
        return Err(OverlayErr::new(
            Errno::EIO,
            format!(
                "authority verify-overlay failed (HTTP {})",
                resp.status_code()
            ),
        ));
    }
    let verified: VerifiedOverlayCred = resp.json().await.map_err(io_err)?;
    resources::checked_io(
        env,
        IoRequest {
            ns: verified.ns.clone(),
            token: verified.cred_hash.clone(),
            token_is_hash: true,
            pid: None,
            write: false,
            bytes: 0,
        },
    )
    .await
    .map_err(|e| {
        let errno = if e.errno == Errno::EPERM {
            Errno::EACCES
        } else {
            e.errno
        };
        OverlayErr::new(errno, e.to_string())
    })?;
    Ok(verified)
}

/// Batch live-revalidation of active `OverlayRelay` endpoints against `OsAuthority` and `Machine`.
pub(crate) async fn revalidate_overlay_sessions(
    env: &Env,
    sessions: &[OverlaySessionCheck],
) -> std::result::Result<BTreeSet<String>, OverlayErr> {
    if sessions.is_empty() {
        return Ok(BTreeSet::new());
    }
    #[derive(Deserialize)]
    struct BatchResp {
        revoked: Vec<String>,
    }
    let headers = Headers::new();
    headers
        .set("Content-Type", "application/json")
        .map_err(io_err)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(json!({ "items": sessions }).to_string().into()));
    let sub = Request::new_with_init(
        "https://authority/internal/service-auth/verify-overlay-batch",
        &init,
    )
    .map_err(io_err)?;
    let mut resp = env
        .durable_object("AUTHORITY")
        .map_err(io_err)?
        .get_by_name("filesystem")
        .map_err(io_err)?
        .fetch_with_request(sub)
        .await
        .map_err(io_err)?;
    if resp.status_code() != 200 {
        return Err(OverlayErr::new(
            Errno::EIO,
            "authority verify-overlay-batch failed",
        ));
    }
    let batch: BatchResp = resp.json().await.map_err(io_err)?;
    let mut revoked: BTreeSet<String> = batch.revoked.into_iter().collect();

    let mut by_cred: std::collections::BTreeMap<(String, String), Vec<String>> =
        std::collections::BTreeMap::new();
    for s in sessions {
        if !revoked.contains(&s.endpoint_id) {
            by_cred
                .entry((s.ns.clone(), s.cred_hash.clone()))
                .or_default()
                .push(s.endpoint_id.clone());
        }
    }
    for ((ns, cred_hash), ep_ids) in by_cred {
        let alive = resources::checked_io(
            env,
            IoRequest {
                ns,
                token: cred_hash,
                token_is_hash: true,
                pid: None,
                write: false,
                bytes: 0,
            },
        )
        .await
        .is_ok();
        if !alive {
            revoked.extend(ep_ids);
        }
    }
    Ok(revoked)
}

/// Synthesize a strictly least-privilege `ClusterGrant` restricted ONLY to `/t/<tenant>/overlay/*`.
pub(crate) fn overlay_ipam_grant(tenant: &str, owner: &str) -> ClusterGrant {
    ClusterGrant {
        tenant: tenant.to_string(),
        owner: owner.to_string(),
        admin: false,
        scope: RemoteScope {
            cluster_read: true,
            cluster_write: true,
            cluster_lease: true,
            cluster_prefixes: vec!["overlay/*".into()],
            ..RemoteScope::default()
        },
    }
}

/// Execute one internal `ClusterState` DO RPC using the least-privilege overlay grant.
pub(crate) async fn cluster_overlay_rpc(
    env: &Env,
    cluster: &str,
    tenant: &str,
    owner: &str,
    call: ClusterCall,
) -> std::result::Result<ClusterReply, OverlayErr> {
    let cmd = ClusterDoRpc {
        grant: overlay_ipam_grant(tenant, owner),
        cluster: cluster.to_string(),
        call,
    };
    let payload =
        serde_json::to_string(&cmd).map_err(|_| OverlayErr::new(Errno::EINVAL, "encode"))?;
    let headers = Headers::new();
    headers
        .set("Content-Type", "application/json")
        .map_err(io_err)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(payload.into()));
    let sub =
        Request::new_with_init("https://cluster-state/internal/rpc", &init).map_err(io_err)?;
    let mut resp = env
        .durable_object("CLUSTER_STATE")
        .map_err(io_err)?
        .get_by_name(&format!("cluster:{cluster}"))
        .map_err(io_err)?
        .fetch_with_request(sub)
        .await
        .map_err(io_err)?;
    if resp.status_code() >= 400 {
        let err_json: serde_json::Value = resp.json().await.unwrap_or_else(|_| json!({}));
        let errno: Errno = err_json
            .get("errno")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or(Errno::EIO);
        let msg = err_json
            .get("detail")
            .and_then(|v| v.as_str())
            .or_else(|| err_json.get("error").and_then(|v| v.as_str()))
            .unwrap_or("cluster IPAM RPC failed")
            .to_string();
        return Err(OverlayErr::new(errno, msg));
    }
    resp.json::<ClusterReply>().await.map_err(io_err)
}

pub(crate) fn overlay_do_name(cluster: &str, tenant: &str, network: &str) -> String {
    format!("overlay:{cluster}:{tenant}:{network}")
}

async fn call_overlay_do_post(
    env: &Env,
    cluster: &str,
    tenant: &str,
    network: &str,
    path: &str,
    body_json: String,
) -> std::result::Result<Response, OverlayErr> {
    let headers = Headers::new();
    headers
        .set("Content-Type", "application/json")
        .map_err(io_err)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(body_json.into()));
    let sub =
        Request::new_with_init(&format!("https://overlay-relay{path}"), &init).map_err(io_err)?;
    env.durable_object("OVERLAY_RELAY")
        .map_err(io_err)?
        .get_by_name(&overlay_do_name(cluster, tenant, network))
        .map_err(io_err)?
        .fetch_with_request(sub)
        .await
        .map_err(io_err)
}

fn encode_overlay_ticket(
    cluster: &str,
    tenant: &str,
    network: &str,
    ns: &str,
    secret: &str,
) -> String {
    format!(
        "{}.{}.{}.{}.{secret}",
        URL_SAFE_NO_PAD.encode(cluster.as_bytes()),
        URL_SAFE_NO_PAD.encode(tenant.as_bytes()),
        URL_SAFE_NO_PAD.encode(network.as_bytes()),
        URL_SAFE_NO_PAD.encode(ns.as_bytes()),
    )
}

struct DecodedTicket {
    cluster: String,
    tenant: String,
    network: String,
    ns: String,
    secret: String,
}

fn decode_overlay_ticket(raw: &str) -> std::result::Result<DecodedTicket, OverlayErr> {
    let parts: Vec<&str> = raw.split('.').collect();
    if parts.len() != 5 {
        return Err(OverlayErr::new(Errno::EACCES, "malformed overlay ticket"));
    }
    let decode_str = |s: &str| -> std::result::Result<String, OverlayErr> {
        let bytes = URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|_| OverlayErr::new(Errno::EACCES, "invalid overlay ticket encoding"))?;
        String::from_utf8(bytes)
            .map_err(|_| OverlayErr::new(Errno::EACCES, "invalid overlay ticket utf8"))
    };
    let cluster = decode_str(parts[0])?;
    let tenant = decode_str(parts[1])?;
    let network = decode_str(parts[2])?;
    let ns = decode_str(parts[3])?;
    let secret = parts[4].to_string();
    if !valid_cluster_name(&cluster)
        || !abi::cluster_state::valid_tenant_name(&tenant)
        || !valid_overlay_network_name(&network)
        || (!ns.starts_with("session.") && !ns.starts_with("node."))
        || secret.len() != 64
        || !secret.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(OverlayErr::new(
            Errno::EACCES,
            "invalid overlay ticket fields",
        ));
    }
    Ok(DecodedTicket {
        cluster,
        tenant,
        network,
        ns,
        secret,
    })
}

/// Entrypoint for `/api/overlay/*`.
pub async fn gateway(mut req: Request, env: &Env) -> Result<Response> {
    let url = req.url()?;
    let path = url.path().to_string();
    match (req.method(), path.as_str()) {
        (Method::Post, "/api/overlay/attach") => match handle_attach(&mut req, &url, env).await {
            Ok(resp) => with_security_headers(resp),
            Err(err) => error_response(&err),
        },
        (Method::Post, "/api/overlay/renew") => match handle_renew(&mut req, &url, env).await {
            Ok(resp) => with_security_headers(resp),
            Err(err) => error_response(&err),
        },
        (Method::Post, "/api/overlay/detach") => match handle_detach(&mut req, &url, env).await {
            Ok(resp) => with_security_headers(resp),
            Err(err) => error_response(&err),
        },
        (Method::Get, "/api/overlay/connect") => match handle_connect(&req, &url, env).await {
            Ok(resp) => {
                if resp.status_code() == 101 {
                    Ok(resp)
                } else {
                    with_security_headers(resp)
                }
            }
            Err(err) => error_response(&err),
        },
        (
            _,
            "/api/overlay/attach"
            | "/api/overlay/renew"
            | "/api/overlay/detach"
            | "/api/overlay/connect",
        ) => {
            let mut resp = Response::from_json(&json!({
                "errno": Errno::EINVAL,
                "error": "method not allowed",
            }))?
            .with_status(405);
            resp.headers_mut().set("X-OS-Errno", "EINVAL")?;
            with_security_headers(resp)
        }
        _ => error_response(&OverlayErr::new(Errno::ENOENT, "unknown overlay endpoint")),
    }
}

async fn ensure_tenant_config(
    env: &Env,
    cluster: &str,
    tenant: &str,
    owner: &str,
    network: &str,
) -> std::result::Result<TenantOverlayConfig, OverlayErr> {
    let cfg_key = overlay_config_key(tenant);
    for _ in 0..3 {
        let reply = cluster_overlay_rpc(
            env,
            cluster,
            tenant,
            owner,
            ClusterCall::Range {
                key: cfg_key.clone(),
                range_end: RangeEnd::Exact,
                limit: Some(1),
                revision: 0,
                keys_only: false,
                count_only: false,
            },
        )
        .await?;
        if let ClusterReply::Range { kvs, .. } = reply
            && let Some(kv) = kvs.first()
        {
            let raw = kv
                .decode_value()
                .map_err(|_| OverlayErr::new(Errno::EIO, "decode overlay config"))?;
            let cfg: TenantOverlayConfig = serde_json::from_slice(&raw)
                .map_err(|_| OverlayErr::new(Errno::EIO, "parse overlay config"))?;
            cfg.validate()
                .map_err(|e| OverlayErr::new(e.errno, e.to_string()))?;
            return Ok(cfg);
        }
        let default_cfg = TenantOverlayConfig::default_for(tenant, network);
        let bytes = serde_json::to_vec(&default_cfg)
            .map_err(|_| OverlayErr::new(Errno::EIO, "encode overlay config"))?;
        let txn = cluster_overlay_rpc(
            env,
            cluster,
            tenant,
            owner,
            ClusterCall::Txn {
                compare: vec![Compare {
                    key: cfg_key.clone(),
                    op: CompareOp::Equal,
                    target: CompareTarget::Version(0),
                }],
                success: vec![TxnOp::Put {
                    key: cfg_key.clone(),
                    value_b64: encode_value_b64(&bytes)
                        .map_err(|e| OverlayErr::new(e.errno, e.to_string()))?,
                    lease_id: 0,
                    prev_kv: false,
                }],
                failure: Vec::new(),
            },
        )
        .await?;
        if let ClusterReply::Txn {
            succeeded: true, ..
        } = txn
        {
            return Ok(default_cfg);
        }
    }
    Err(OverlayErr::new(
        Errno::EIO,
        "failed to initialize tenant overlay config",
    ))
}

fn caller_node_id(verified: &VerifiedOverlayCred) -> String {
    verified.node_id.clone().unwrap_or_else(|| {
        let h = auth::token_hash(&verified.instance_id);
        format!("inst-{}", &h[..h.len().min(32)])
    })
}

async fn handle_attach(
    req: &mut Request,
    url: &Url,
    env: &Env,
) -> std::result::Result<Response, OverlayErr> {
    check_origin(req, url)?;
    let verified = verify_overlay_cred(req, env).await?;
    let body = read_bounded_body(req, MAX_OVERLAY_BODY_BYTES).await?;
    let ask: OverlayAttachRequest = if body.is_empty() {
        OverlayAttachRequest {
            network: "default".into(),
            mtu: None,
            ifname: None,
            endpoint_id: None,
            static_ip: None,
            host_kind: None,
            cluster: None,
        }
    } else {
        serde_json::from_slice(&body)
            .map_err(|e| OverlayErr::new(Errno::EINVAL, format!("invalid attach request: {e}")))?
    };

    if !valid_overlay_network_name(&ask.network) {
        return Err(OverlayErr::new(
            Errno::EINVAL,
            "invalid overlay network name",
        ));
    }
    if !verified.overlay.allows_network(&ask.network) {
        return Err(OverlayErr::new(
            Errno::EACCES,
            format!(
                "overlay network '{}' not granted in RemoteScope.overlay",
                ask.network
            ),
        ));
    }
    let cluster = ask.cluster.unwrap_or_else(default_cluster_name);
    if !valid_cluster_name(&cluster) {
        return Err(OverlayErr::new(Errno::EINVAL, "invalid cluster name"));
    }
    let ifname = match ask.ifname {
        Some(n) if !n.is_empty() => {
            if !valid_tun_ifname(&n) {
                return Err(OverlayErr::new(Errno::EINVAL, "invalid tun interface name"));
            }
            n
        }
        _ => "tun0".to_string(),
    };
    let endpoint_id = match ask.endpoint_id {
        Some(id) if !id.is_empty() => {
            if !valid_cluster_record_id(&id) {
                return Err(OverlayErr::new(Errno::EINVAL, "invalid endpoint_id"));
            }
            id
        }
        _ => format!("ep_{}", &auth::random_token()[..24]),
    };
    let host_kind = ask.host_kind.unwrap_or_else(|| {
        if verified.ns.starts_with("node.") {
            "native".to_string()
        } else {
            "browser".to_string()
        }
    });
    if host_kind.len() > 32
        || !host_kind
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(OverlayErr::new(Errno::EINVAL, "invalid host_kind"));
    }
    let node_id = caller_node_id(&verified);

    let cfg = ensure_tenant_config(
        env,
        &cluster,
        &verified.tenant,
        &verified.cred_hash,
        &ask.network,
    )
    .await?;
    let (cidr_v4, cidr_v6) = cfg
        .validate()
        .map_err(|e| OverlayErr::new(e.errno, e.to_string()))?;

    let negotiated_mtu = ask
        .mtu
        .unwrap_or(cfg.mtu)
        .min(verified.overlay.max_mtu)
        .min(TUN_MAX_MTU);
    if negotiated_mtu < TUN_MIN_MTU {
        return Err(OverlayErr::new(Errno::EINVAL, "negotiated MTU below 1280"));
    }

    let static_ip = match ask.static_ip {
        Some(raw) if !raw.is_empty() => {
            let parsed: Ipv4Addr = raw
                .parse()
                .map_err(|_| OverlayErr::new(Errno::EINVAL, "invalid static_ip"))?;
            if !cidr_v4.is_valid_host_ip(parsed) {
                return Err(OverlayErr::new(
                    Errno::EINVAL,
                    "static_ip is outside tenant subnet host range",
                ));
            }
            Some(parsed)
        }
        _ => None,
    };

    // 1. Grant a 60s ClusterState lease for IPAM + endpoint records.
    let lease_reply = cluster_overlay_rpc(
        env,
        &cluster,
        &verified.tenant,
        &verified.cred_hash,
        ClusterCall::LeaseGrant {
            ttl_secs: OVERLAY_DEFAULT_LEASE_TTL_SECS,
            node_id: None,
        },
    )
    .await?;
    let (lease_id, lease_ttl_secs, lease_expires_at) = match lease_reply {
        ClusterReply::LeaseGranted {
            lease_id,
            ttl_secs,
            expires_at,
            ..
        } => (lease_id, ttl_secs, expires_at),
        _ => return Err(OverlayErr::new(Errno::EIO, "unexpected LeaseGrant reply")),
    };

    // 2. Atomically allocate IPv4 (+ optional IPv6) + endpoint records via CAS Txn.
    let ep_key = overlay_endpoint_key(&verified.tenant, &endpoint_id);
    let node_ep_key = overlay_node_endpoint_key(&verified.tenant, &node_id, &endpoint_id);
    let now = auth::now();
    let mut allocated: Option<(Ipv4Addr, Option<String>)> = None;

    for _attempt in 0..8 {
        let range_reply = cluster_overlay_rpc(
            env,
            &cluster,
            &verified.tenant,
            &verified.cred_hash,
            ClusterCall::Range {
                key: overlay_ipam_v4_prefix(&verified.tenant),
                range_end: RangeEnd::Prefix,
                limit: Some(512),
                revision: 0,
                keys_only: true,
                count_only: false,
            },
        )
        .await?;
        let mut used: HashSet<Ipv4Addr> = HashSet::new();
        if let ClusterReply::Range { kvs, .. } = range_reply {
            for kv in kvs {
                if let Some(seg) = kv.key.rsplit('/').next()
                    && let Some(ip) = abi::overlay::parse_ipv4_key_segment(seg)
                {
                    used.insert(ip);
                }
            }
        }
        // Enforce per-caller / per-node `max_interfaces` strictly against active node endpoints.
        let node_ep_prefix = format!("/t/{}/overlay/node-endpoints/{node_id}/", verified.tenant);
        let node_count_reply = cluster_overlay_rpc(
            env,
            &cluster,
            &verified.tenant,
            &verified.cred_hash,
            ClusterCall::Range {
                key: node_ep_prefix,
                range_end: RangeEnd::Prefix,
                limit: Some(256),
                revision: 0,
                keys_only: true,
                count_only: true,
            },
        )
        .await?;
        let active_node_eps = match node_count_reply {
            ClusterReply::Range { count, .. } => count,
            _ => 0,
        };
        if active_node_eps >= u64::from(verified.overlay.max_interfaces) {
            let _ = cluster_overlay_rpc(
                env,
                &cluster,
                &verified.tenant,
                &verified.cred_hash,
                ClusterCall::LeaseRevoke { lease_id },
            )
            .await;
            return Err(OverlayErr::new(
                Errno::ENOSPC,
                "overlay interface quota exceeded",
            ));
        }

        let (chosen_v4, host_idx) = if let Some(req_ip) = static_ip {
            if used.contains(&req_ip) {
                let _ = cluster_overlay_rpc(
                    env,
                    &cluster,
                    &verified.tenant,
                    &verified.cred_hash,
                    ClusterCall::LeaseRevoke { lease_id },
                )
                .await;
                return Err(OverlayErr::new(
                    Errno::EADDRINUSE,
                    "static_ip already leased",
                ));
            }
            let idx = req_ip.to_bits() - cidr_v4.network_addr().to_bits() - 2;
            (req_ip, idx)
        } else {
            let mut found = None;
            for idx in 0..253u32 {
                let Some(cand) = cidr_v4.host_ip(idx) else {
                    break;
                };
                if !used.contains(&cand) {
                    found = Some((cand, idx));
                    break;
                }
            }
            let Some(pair) = found else {
                let _ = cluster_overlay_rpc(
                    env,
                    &cluster,
                    &verified.tenant,
                    &verified.cred_hash,
                    ClusterCall::LeaseRevoke { lease_id },
                )
                .await;
                return Err(OverlayErr::new(
                    Errno::ENOSPC,
                    "tenant overlay subnet exhausted",
                ));
            };
            pair
        };

        let chosen_v6 =
            cidr_v6.and_then(|c6| u16::try_from(host_idx).ok().and_then(|i| c6.host_ip(i)));
        let ipv6_str = chosen_v6.map(|a| a.to_string());

        let ip_rec = IpamLeaseRecord {
            tenant: verified.tenant.clone(),
            network: ask.network.clone(),
            ip: chosen_v4.to_string(),
            prefix_len: cidr_v4.prefix_len,
            endpoint_id: endpoint_id.clone(),
            node_id: node_id.clone(),
            ifname: ifname.clone(),
            host_kind: host_kind.clone(),
            mtu: negotiated_mtu,
            lease_id,
            fence_epoch: 1,
            allocated_at: now,
        };
        let ep_rec = OverlayEndpointRecord {
            tenant: verified.tenant.clone(),
            network: ask.network.clone(),
            endpoint_id: endpoint_id.clone(),
            ip: chosen_v4.to_string(),
            prefix_len: cidr_v4.prefix_len,
            gateway: cfg.gateway_v4.clone(),
            cidr: cfg.cidr_v4.clone(),
            ipv6: ipv6_str.clone(),
            node_id: node_id.clone(),
            ifname: ifname.clone(),
            host_kind: host_kind.clone(),
            mtu: negotiated_mtu,
            lease_id,
            fence_epoch: 1,
            allocated_at: now,
        };
        let ip_key = overlay_ipam_v4_key(&verified.tenant, chosen_v4);
        let ip_bytes = serde_json::to_vec(&ip_rec)
            .map_err(|_| OverlayErr::new(Errno::EIO, "encode ip rec"))?;
        let ep_bytes = serde_json::to_vec(&ep_rec)
            .map_err(|_| OverlayErr::new(Errno::EIO, "encode ep rec"))?;
        let mut ops = vec![
            TxnOp::Put {
                key: ip_key.clone(),
                value_b64: encode_value_b64(&ip_bytes)
                    .map_err(|e| OverlayErr::new(e.errno, e.to_string()))?,
                lease_id,
                prev_kv: false,
            },
            TxnOp::Put {
                key: ep_key.clone(),
                value_b64: encode_value_b64(&ep_bytes)
                    .map_err(|e| OverlayErr::new(e.errno, e.to_string()))?,
                lease_id,
                prev_kv: false,
            },
            TxnOp::Put {
                key: node_ep_key.clone(),
                value_b64: encode_value_b64(&ep_bytes)
                    .map_err(|e| OverlayErr::new(e.errno, e.to_string()))?,
                lease_id,
                prev_kv: false,
            },
        ];
        if let Some(v6) = chosen_v6 {
            let v6_rec = IpamLeaseRecord {
                ip: v6.to_string(),
                prefix_len: cidr_v6.map_or(64, |c| c.prefix_len),
                ..ip_rec.clone()
            };
            let v6_bytes = serde_json::to_vec(&v6_rec)
                .map_err(|_| OverlayErr::new(Errno::EIO, "encode v6 rec"))?;
            ops.push(TxnOp::Put {
                key: overlay_ipam_v6_key(&verified.tenant, v6),
                value_b64: encode_value_b64(&v6_bytes)
                    .map_err(|e| OverlayErr::new(e.errno, e.to_string()))?,
                lease_id,
                prev_kv: false,
            });
        }
        let txn = cluster_overlay_rpc(
            env,
            &cluster,
            &verified.tenant,
            &verified.cred_hash,
            ClusterCall::Txn {
                compare: vec![
                    Compare {
                        key: ip_key,
                        op: CompareOp::Equal,
                        target: CompareTarget::Version(0),
                    },
                    Compare {
                        key: ep_key.clone(),
                        op: CompareOp::Equal,
                        target: CompareTarget::Version(0),
                    },
                ],
                success: ops,
                failure: Vec::new(),
            },
        )
        .await?;
        if let ClusterReply::Txn {
            succeeded: true, ..
        } = txn
        {
            allocated = Some((chosen_v4, ipv6_str));
            break;
        }
    }

    let Some((ip_v4, ipv6_str)) = allocated else {
        let _ = cluster_overlay_rpc(
            env,
            &cluster,
            &verified.tenant,
            &verified.cred_hash,
            ClusterCall::LeaseRevoke { lease_id },
        )
        .await;
        return Err(OverlayErr::new(
            Errno::EBUSY,
            "IPAM allocation conflict or duplicate endpoint_id",
        ));
    };

    // 3. Issue single-use 30s WebSocket upgrade ticket inside `OverlayRelay` DO.
    let issue_cmd = OverlayIssueTicket {
        cluster: cluster.clone(),
        tenant: verified.tenant.clone(),
        network: ask.network.clone(),
        endpoint_id: endpoint_id.clone(),
        ip: ip_v4.to_string(),
        prefix_len: cidr_v4.prefix_len,
        gateway: cfg.gateway_v4.clone(),
        cidr: cfg.cidr_v4.clone(),
        ipv6: ipv6_str.clone(),
        mtu: negotiated_mtu,
        lease_id,
        lease_expires_at,
        host_kind,
        ns: verified.ns.clone(),
        cred_hash: verified.cred_hash.clone(),
        instance_id: verified.instance_id.clone(),
        allowed_peer_cidrs: verified.overlay.allowed_peer_cidrs.clone(),
        max_bytes_per_sec: verified.overlay.max_bytes_per_sec,
    };
    let mut ticket_resp = match call_overlay_do_post(
        env,
        &cluster,
        &verified.tenant,
        &ask.network,
        "/internal/ticket",
        serde_json::to_string(&issue_cmd).map_err(|_| OverlayErr::new(Errno::EIO, "encode"))?,
    )
    .await
    {
        Ok(r) if r.status_code() == 200 => r,
        _ => {
            let _ = cluster_overlay_rpc(
                env,
                &cluster,
                &verified.tenant,
                &verified.cred_hash,
                ClusterCall::LeaseRevoke { lease_id },
            )
            .await;
            return Err(OverlayErr::new(
                Errno::EIO,
                "failed to register overlay upgrade ticket",
            ));
        }
    };
    let created: OverlayTicketCreated = ticket_resp.json().await.map_err(io_err)?;
    let full_ticket = encode_overlay_ticket(
        &cluster,
        &verified.tenant,
        &ask.network,
        &verified.ns,
        &created.secret,
    );

    Response::from_json(&OverlayAttachReply {
        version: OVERLAY_VERSION,
        ticket: full_ticket.clone(),
        tenant: verified.tenant,
        network: ask.network,
        endpoint_id,
        ip: ip_v4.to_string(),
        prefix_len: cidr_v4.prefix_len,
        gateway: cfg.gateway_v4,
        cidr: cfg.cidr_v4,
        ipv6: ipv6_str,
        mtu: negotiated_mtu,
        lease_id,
        lease_ttl_secs,
        expires_at: lease_expires_at,
        ws_url: format!("/api/overlay/connect?ticket={full_ticket}"),
        webtransport_url: None,
    })
    .map_err(io_err)
}

async fn handle_renew(
    req: &mut Request,
    url: &Url,
    env: &Env,
) -> std::result::Result<Response, OverlayErr> {
    check_origin(req, url)?;
    let verified = verify_overlay_cred(req, env).await?;
    let body = read_bounded_body(req, MAX_OVERLAY_BODY_BYTES).await?;
    let ask: OverlayRenewRequest = serde_json::from_slice(&body)
        .map_err(|e| OverlayErr::new(Errno::EINVAL, format!("invalid renew request: {e}")))?;
    if !valid_cluster_record_id(&ask.endpoint_id) || !valid_overlay_network_name(&ask.network) {
        return Err(OverlayErr::new(
            Errno::EINVAL,
            "invalid endpoint_id or network",
        ));
    }
    if !verified.overlay.allows_network(&ask.network) {
        return Err(OverlayErr::new(
            Errno::EACCES,
            "overlay network not granted",
        ));
    }
    let cluster = ask.cluster.unwrap_or_else(default_cluster_name);
    if !valid_cluster_name(&cluster) {
        return Err(OverlayErr::new(Errno::EINVAL, "invalid cluster name"));
    }

    // Confirm endpoint exists in this tenant and belongs to the caller's network + node/instance.
    let expected_node = caller_node_id(&verified);
    let ep_key = overlay_endpoint_key(&verified.tenant, &ask.endpoint_id);
    let range = cluster_overlay_rpc(
        env,
        &cluster,
        &verified.tenant,
        &verified.cred_hash,
        ClusterCall::Range {
            key: ep_key,
            range_end: RangeEnd::Exact,
            limit: Some(1),
            revision: 0,
            keys_only: false,
            count_only: false,
        },
    )
    .await?;
    let Some(ep_kv) = (match range {
        ClusterReply::Range { kvs, .. } => kvs.into_iter().next(),
        _ => None,
    }) else {
        return Err(OverlayErr::new(Errno::ENOENT, "overlay endpoint not found"));
    };
    let ep_raw = ep_kv
        .decode_value()
        .map_err(|_| OverlayErr::new(Errno::EIO, "decode overlay endpoint"))?;
    let ep_rec: OverlayEndpointRecord = serde_json::from_slice(&ep_raw)
        .map_err(|_| OverlayErr::new(Errno::EIO, "parse overlay endpoint"))?;
    if ep_rec.tenant != verified.tenant
        || ep_rec.network != ask.network
        || ep_rec.node_id != expected_node
    {
        return Err(OverlayErr::new(
            Errno::EACCES,
            "overlay endpoint does not belong to caller",
        ));
    }
    if ep_kv.lease_id != ask.lease_id || ep_rec.lease_id != ask.lease_id {
        return Err(OverlayErr::new(Errno::ESTALE, "endpoint lease_id mismatch"));
    }

    let kept = cluster_overlay_rpc(
        env,
        &cluster,
        &verified.tenant,
        &verified.cred_hash,
        ClusterCall::LeaseKeepAlive {
            lease_id: ask.lease_id,
        },
    )
    .await?;
    let (ttl_secs, expires_at) = match kept {
        ClusterReply::LeaseKeptAlive {
            ttl_secs,
            expires_at,
            ..
        } => (ttl_secs, expires_at),
        _ => {
            return Err(OverlayErr::new(
                Errno::EIO,
                "unexpected LeaseKeepAlive reply",
            ));
        }
    };

    let _ = call_overlay_do_post(
        env,
        &cluster,
        &verified.tenant,
        &ask.network,
        "/internal/renew",
        json!({
            "endpoint_id": ask.endpoint_id,
            "lease_id": ask.lease_id,
            "lease_expires_at": expires_at,
        })
        .to_string(),
    )
    .await;

    Response::from_json(&OverlayRenewReply {
        version: OVERLAY_VERSION,
        endpoint_id: ask.endpoint_id,
        lease_id: ask.lease_id,
        lease_ttl_secs: ttl_secs,
        expires_at,
    })
    .map_err(io_err)
}

async fn handle_detach(
    req: &mut Request,
    url: &Url,
    env: &Env,
) -> std::result::Result<Response, OverlayErr> {
    check_origin(req, url)?;
    let verified = verify_overlay_cred(req, env).await?;
    let body = read_bounded_body(req, MAX_OVERLAY_BODY_BYTES).await?;
    let ask: OverlayDetachRequest = serde_json::from_slice(&body)
        .map_err(|e| OverlayErr::new(Errno::EINVAL, format!("invalid detach request: {e}")))?;
    if !valid_cluster_record_id(&ask.endpoint_id) || !valid_overlay_network_name(&ask.network) {
        return Err(OverlayErr::new(
            Errno::EINVAL,
            "invalid endpoint_id or network",
        ));
    }
    if !verified.overlay.allows_network(&ask.network) {
        return Err(OverlayErr::new(
            Errno::EACCES,
            "overlay network not granted",
        ));
    }
    let cluster = ask.cluster.unwrap_or_else(default_cluster_name);
    if !valid_cluster_name(&cluster) {
        return Err(OverlayErr::new(Errno::EINVAL, "invalid cluster name"));
    }

    // 1. Look up endpoint record and strictly verify ownership before any mutation or lease revoke.
    let expected_node = caller_node_id(&verified);
    let ep_key = overlay_endpoint_key(&verified.tenant, &ask.endpoint_id);
    let ep_range = cluster_overlay_rpc(
        env,
        &cluster,
        &verified.tenant,
        &verified.cred_hash,
        ClusterCall::Range {
            key: ep_key.clone(),
            range_end: RangeEnd::Exact,
            limit: Some(1),
            revision: 0,
            keys_only: false,
            count_only: false,
        },
    )
    .await?;
    let Some(ep_kv) = (match ep_range {
        ClusterReply::Range { kvs, .. } => kvs.into_iter().next(),
        _ => None,
    }) else {
        // Already detached or expired: idempotent no-op without revoking arbitrary leases or sockets!
        return Response::from_json(&json!({ "ok": true })).map_err(io_err);
    };
    let ep_raw = ep_kv
        .decode_value()
        .map_err(|_| OverlayErr::new(Errno::EIO, "decode overlay endpoint"))?;
    let ep_rec: OverlayEndpointRecord = serde_json::from_slice(&ep_raw)
        .map_err(|_| OverlayErr::new(Errno::EIO, "parse overlay endpoint"))?;
    if ep_rec.tenant != verified.tenant
        || ep_rec.network != ask.network
        || ep_rec.node_id != expected_node
    {
        return Err(OverlayErr::new(
            Errno::EACCES,
            "overlay endpoint does not belong to caller",
        ));
    }
    if ask.lease_id != 0 && ask.lease_id != ep_rec.lease_id {
        return Err(OverlayErr::new(Errno::ESTALE, "endpoint lease_id mismatch"));
    }

    // CAS-delete IPv4 lease key ONLY if still owned by `endpoint_id`.
    if let Ok(ip_v4) = ep_rec.ip.parse::<Ipv4Addr>() {
        let ip_key = overlay_ipam_v4_key(&verified.tenant, ip_v4);
        if let Ok(ClusterReply::Range { kvs: ip_kvs, .. }) = cluster_overlay_rpc(
            env,
            &cluster,
            &verified.tenant,
            &verified.cred_hash,
            ClusterCall::Range {
                key: ip_key.clone(),
                range_end: RangeEnd::Exact,
                limit: Some(1),
                revision: 0,
                keys_only: false,
                count_only: false,
            },
        )
        .await
            && let Some(ip_kv) = ip_kvs.into_iter().next()
            && let Ok(ip_raw) = ip_kv.decode_value()
            && let Ok(ip_rec) = serde_json::from_slice::<IpamLeaseRecord>(&ip_raw)
            && ip_rec.endpoint_id == ask.endpoint_id
        {
            let _ = cluster_overlay_rpc(
                env,
                &cluster,
                &verified.tenant,
                &verified.cred_hash,
                ClusterCall::Txn {
                    compare: vec![Compare {
                        key: ip_key.clone(),
                        op: CompareOp::Equal,
                        target: CompareTarget::ModRevision(ip_kv.mod_revision),
                    }],
                    success: vec![TxnOp::DeleteRange {
                        key: ip_key,
                        range_end: RangeEnd::Exact,
                        prev_kv: false,
                    }],
                    failure: Vec::new(),
                },
            )
            .await;
        }
    }

    // CAS-delete IPv6 lease key (if present) ONLY if still owned by `endpoint_id`.
    if let Some(ip_v6) = ep_rec
        .ipv6
        .as_deref()
        .and_then(|s| s.parse::<Ipv6Addr>().ok())
    {
        let ip6_key = overlay_ipam_v6_key(&verified.tenant, ip_v6);
        if let Ok(ClusterReply::Range { kvs: ip6_kvs, .. }) = cluster_overlay_rpc(
            env,
            &cluster,
            &verified.tenant,
            &verified.cred_hash,
            ClusterCall::Range {
                key: ip6_key.clone(),
                range_end: RangeEnd::Exact,
                limit: Some(1),
                revision: 0,
                keys_only: false,
                count_only: false,
            },
        )
        .await
            && let Some(ip6_kv) = ip6_kvs.into_iter().next()
            && let Ok(ip6_raw) = ip6_kv.decode_value()
            && let Ok(ip6_rec) = serde_json::from_slice::<IpamLeaseRecord>(&ip6_raw)
            && ip6_rec.endpoint_id == ask.endpoint_id
        {
            let _ = cluster_overlay_rpc(
                env,
                &cluster,
                &verified.tenant,
                &verified.cred_hash,
                ClusterCall::Txn {
                    compare: vec![Compare {
                        key: ip6_key.clone(),
                        op: CompareOp::Equal,
                        target: CompareTarget::ModRevision(ip6_kv.mod_revision),
                    }],
                    success: vec![TxnOp::DeleteRange {
                        key: ip6_key,
                        range_end: RangeEnd::Exact,
                        prev_kv: false,
                    }],
                    failure: Vec::new(),
                },
            )
            .await;
        }
    }

    // CAS-delete endpoint & node-endpoint keys guarded by `CompareTarget::ModRevision`.
    let node_ep_key =
        overlay_node_endpoint_key(&verified.tenant, &ep_rec.node_id, &ask.endpoint_id);
    let node_ep_mod_rev = match cluster_overlay_rpc(
        env,
        &cluster,
        &verified.tenant,
        &verified.cred_hash,
        ClusterCall::Range {
            key: node_ep_key.clone(),
            range_end: RangeEnd::Exact,
            limit: Some(1),
            revision: 0,
            keys_only: true,
            count_only: false,
        },
    )
    .await
    {
        Ok(ClusterReply::Range { kvs, .. }) => kvs.into_iter().next().map(|kv| kv.mod_revision),
        _ => None,
    };
    let mut del_compares = vec![Compare {
        key: ep_key.clone(),
        op: CompareOp::Equal,
        target: CompareTarget::ModRevision(ep_kv.mod_revision),
    }];
    let mut del_ops = vec![TxnOp::DeleteRange {
        key: ep_key,
        range_end: RangeEnd::Exact,
        prev_kv: false,
    }];
    if let Some(nrev) = node_ep_mod_rev {
        del_compares.push(Compare {
            key: node_ep_key.clone(),
            op: CompareOp::Equal,
            target: CompareTarget::ModRevision(nrev),
        });
        del_ops.push(TxnOp::DeleteRange {
            key: node_ep_key,
            range_end: RangeEnd::Exact,
            prev_kv: false,
        });
    }
    let _ = cluster_overlay_rpc(
        env,
        &cluster,
        &verified.tenant,
        &verified.cred_hash,
        ClusterCall::Txn {
            compare: del_compares,
            success: del_ops,
            failure: Vec::new(),
        },
    )
    .await;

    // 2. Revoke ONLY the verified `ep_rec.lease_id` (`ENOENT` ignored).
    if ep_rec.lease_id != 0 {
        let _ = cluster_overlay_rpc(
            env,
            &cluster,
            &verified.tenant,
            &verified.cred_hash,
            ClusterCall::LeaseRevoke {
                lease_id: ep_rec.lease_id,
            },
        )
        .await;
    }

    // 3. Disconnect any live WebSocket inside `OverlayRelay` DO (ownership already verified).
    let _ = call_overlay_do_post(
        env,
        &cluster,
        &verified.tenant,
        &ask.network,
        "/internal/detach",
        json!({ "endpoint_id": ask.endpoint_id }).to_string(),
    )
    .await;

    Response::from_json(&json!({ "ok": true })).map_err(io_err)
}

async fn handle_connect(
    req: &Request,
    url: &Url,
    env: &Env,
) -> std::result::Result<Response, OverlayErr> {
    if !header(req, "Upgrade")?.is_some_and(|u| u.eq_ignore_ascii_case("websocket")) {
        let mut resp = Response::from_json(&json!({
            "errno": Errno::EINVAL,
            "error": "WebSocket upgrade required",
        }))
        .map_err(io_err)?
        .with_status(426);
        resp.headers_mut()
            .set("X-OS-Errno", "EINVAL")
            .map_err(io_err)?;
        return Ok(resp);
    }
    check_origin(req, url)?;

    let query_param = |k: &str| {
        url.query_pairs()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.into_owned())
            .filter(|s| !s.is_empty())
    };

    let (cluster, tenant, network, ticket_hash) = if let Some(raw_ticket) = query_param("ticket") {
        let decoded = decode_overlay_ticket(&raw_ticket)?;
        // Strict `session.*` vs `node.*` cookie checks!
        if decoded.ns.starts_with("session.") {
            if !auth::token_key(req)
                .is_some_and(|sess_key| decoded.ns == format!("session.{sess_key}"))
            {
                return Err(OverlayErr::new(
                    Errno::EACCES,
                    "session overlay ticket requires matching os_session cookie",
                ));
            }
        } else if decoded.ns.starts_with("node.")
            && (auth::token_key(req).is_some() || auth::guest_key(req).is_some())
        {
            return Err(OverlayErr::new(
                Errno::EACCES,
                "node overlay ticket cannot be used with browser cookies",
            ));
        }
        (
            decoded.cluster,
            decoded.tenant,
            decoded.network,
            auth::token_hash(&decoded.secret),
        )
    } else if header(req, "X-Process-Token")?.is_some_and(|t| !t.is_empty()) {
        let verified = verify_overlay_cred(req, env).await?;
        if !verified.ns.starts_with("node.") {
            return Err(OverlayErr::new(
                Errno::EACCES,
                "session overlay connect requires a single-use ticket",
            ));
        }
        let expected_node = caller_node_id(&verified);
        let endpoint_id = query_param("endpoint_id")
            .ok_or_else(|| OverlayErr::new(Errno::EINVAL, "missing endpoint_id query parameter"))?;
        if !valid_cluster_record_id(&endpoint_id) {
            return Err(OverlayErr::new(Errno::EINVAL, "invalid endpoint_id"));
        }
        let network = query_param("network").unwrap_or_else(|| "default".into());
        if !verified.overlay.allows_network(&network) {
            return Err(OverlayErr::new(
                Errno::EACCES,
                "overlay network not granted",
            ));
        }
        let cluster = query_param("cluster").unwrap_or_else(default_cluster_name);
        if !valid_cluster_name(&cluster) {
            return Err(OverlayErr::new(Errno::EINVAL, "invalid cluster name"));
        }
        // Look up the leased endpoint record in ClusterState.
        let ep_key = overlay_endpoint_key(&verified.tenant, &endpoint_id);
        let range = cluster_overlay_rpc(
            env,
            &cluster,
            &verified.tenant,
            &verified.cred_hash,
            ClusterCall::Range {
                key: ep_key,
                range_end: RangeEnd::Exact,
                limit: Some(1),
                revision: 0,
                keys_only: false,
                count_only: false,
            },
        )
        .await?;
        let Some(ep_kv) = (match range {
            ClusterReply::Range { kvs, .. } => kvs.into_iter().next(),
            _ => None,
        }) else {
            return Err(OverlayErr::new(
                Errno::ENOENT,
                "overlay endpoint not leased",
            ));
        };
        let ep_raw = ep_kv
            .decode_value()
            .map_err(|_| OverlayErr::new(Errno::EIO, "decode endpoint"))?;
        let ep_rec: OverlayEndpointRecord = serde_json::from_slice(&ep_raw)
            .map_err(|_| OverlayErr::new(Errno::EIO, "parse endpoint"))?;
        if ep_rec.tenant != verified.tenant
            || ep_rec.network != network
            || ep_rec.node_id != expected_node
        {
            return Err(OverlayErr::new(
                Errno::EACCES,
                "endpoint does not belong to authenticated node/tenant/network",
            ));
        }
        let ttl_reply = cluster_overlay_rpc(
            env,
            &cluster,
            &verified.tenant,
            &verified.cred_hash,
            ClusterCall::LeaseTimeToLive {
                lease_id: ep_rec.lease_id,
                keys: false,
            },
        )
        .await?;
        let lease_expires_at = match ttl_reply {
            ClusterReply::LeaseTtl {
                expires_at,
                remaining_ttl_secs,
                ..
            } if remaining_ttl_secs > 0 => expires_at,
            _ => return Err(OverlayErr::new(Errno::ESTALE, "endpoint lease expired")),
        };
        let issue_cmd = OverlayIssueTicket {
            cluster: cluster.clone(),
            tenant: verified.tenant.clone(),
            network: network.clone(),
            endpoint_id,
            ip: ep_rec.ip,
            prefix_len: ep_rec.prefix_len,
            gateway: ep_rec.gateway,
            cidr: ep_rec.cidr,
            ipv6: ep_rec.ipv6,
            mtu: ep_rec.mtu.min(verified.overlay.max_mtu),
            lease_id: ep_rec.lease_id,
            lease_expires_at,
            host_kind: ep_rec.host_kind,
            ns: verified.ns,
            cred_hash: verified.cred_hash,
            instance_id: verified.instance_id,
            allowed_peer_cidrs: verified.overlay.allowed_peer_cidrs,
            max_bytes_per_sec: verified.overlay.max_bytes_per_sec,
        };
        let mut ticket_resp = call_overlay_do_post(
            env,
            &cluster,
            &verified.tenant,
            &network,
            "/internal/ticket",
            serde_json::to_string(&issue_cmd).map_err(|_| OverlayErr::new(Errno::EIO, "encode"))?,
        )
        .await?;
        if ticket_resp.status_code() != 200 {
            return Err(OverlayErr::new(
                Errno::EIO,
                "failed to issue direct overlay ticket",
            ));
        }
        let created: OverlayTicketCreated = ticket_resp.json().await.map_err(io_err)?;
        (
            cluster,
            verified.tenant,
            network,
            auth::token_hash(&created.secret),
        )
    } else {
        return Err(OverlayErr::new(
            Errno::EACCES,
            "overlay ticket or ServiceAuth v2 credential required",
        ));
    };

    let headers = Headers::new();
    for name in [
        "Upgrade",
        "Connection",
        "Sec-WebSocket-Key",
        "Sec-WebSocket-Version",
        "Sec-WebSocket-Protocol",
        "Sec-WebSocket-Extensions",
    ] {
        if let Some(v) = header(req, name)? {
            headers.set(name, &v).map_err(io_err)?;
        }
    }
    let mut init = RequestInit::new();
    init.with_method(Method::Get).with_headers(headers);
    let sub = Request::new_with_init(
        &format!(
            "https://overlay-relay/internal/connect?ticket_hash={ticket_hash}&cluster={cluster}&tenant={tenant}&network={network}"
        ),
        &init,
    )
    .map_err(io_err)?;
    env.durable_object("OVERLAY_RELAY")
        .map_err(io_err)?
        .get_by_name(&overlay_do_name(&cluster, &tenant, &network))
        .map_err(io_err)?
        .fetch_with_request(sub)
        .await
        .map_err(io_err)
}
