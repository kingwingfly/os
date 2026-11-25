//! Edge HTTP + WebSocket gateway for `Boundary::ClusterState` v1 (`Phase 9.1a #83`).
//!
//! Routes:
//! - `POST /api/cluster/rpc`          — linearizable RPC (`Hello`, `Range`, `Txn`, `Lease*`, `Compact`)
//! - `POST /api/cluster/watch-ticket` — mint a short-lived single-use WebSocket upgrade ticket
//! - `GET  /api/cluster/watch`        — Hibernatable WebSocket watch stream (`?ticket=` or ServiceAuth headers)
use crate::resources::{self, IoRequest};
use abi::Errno;
use abi::cluster_state::{
    CLUSTER_RPC_BODY_MAX_BYTES, ClusterCall, ClusterError, ClusterRpcRequest, WatchTicketReply,
    WatchTicketRequest, default_cluster_name, valid_cluster_name,
};
use futures_util::StreamExt;
use os_cluster_state::ClusterGrant;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use worker::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct VerifiedClusterCred {
    pub grant: ClusterGrant,
    pub ns: String,
    pub cred_hash: String,
    pub instance_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ClusterDoRpc {
    pub grant: ClusterGrant,
    pub cluster: String,
    pub call: ClusterCall,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ClusterIssueTicket {
    pub cred: VerifiedClusterCred,
    pub cluster: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct SessionCheck {
    pub conn_id: String,
    pub tenant: String,
    pub ns: String,
    pub cred_hash: String,
    pub instance_id: String,
}

fn io_err(_: worker::Error) -> ClusterError {
    ClusterError::new(Errno::EIO)
}

fn header(req: &Request, name: &str) -> std::result::Result<Option<String>, ClusterError> {
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

pub(crate) fn error_response(err: &ClusterError, schema_mismatch: bool) -> Result<Response> {
    let status = if schema_mismatch {
        503
    } else {
        match err.errno {
            Errno::EACCES | Errno::EPERM => 403,
            Errno::ENOENT => 404,
            Errno::ESTALE => 412,
            Errno::EBUSY | Errno::EAGAIN | Errno::EEXIST | Errno::ECANCELED => 409,
            Errno::EFBIG | Errno::E2BIG | Errno::EMSGSIZE => 413,
            Errno::EDQUOT | Errno::ENOSPC => 507,
            Errno::EIO => 500,
            _ => 400,
        }
    };
    let mut resp = Response::from_json(err)?.with_status(status);
    resp.headers_mut()
        .set("X-OS-Errno", &format!("{:?}", err.errno))?;
    with_security_headers(resp)
}

fn check_origin(req: &Request, url: &Url) -> std::result::Result<(), ClusterError> {
    let origin_hdr = header(req, "Origin")?;
    let has_cookie = header(req, "Cookie")?.is_some_and(|c| !c.trim().is_empty());
    if origin_hdr.is_some() || has_cookie {
        let expected = url.origin().ascii_serialization();
        if origin_hdr.as_deref() != Some(expected.as_str()) {
            return Err(ClusterError::because(
                Errno::EACCES,
                "cluster requests with browser origin or cookie must originate from this site",
            ));
        }
    }
    Ok(())
}

pub(crate) async fn verify_cluster(
    req: &Request,
    env: &Env,
) -> std::result::Result<VerifiedClusterCred, ClusterError> {
    let headers = Headers::new();
    for name in ["Cookie", "X-Process-Token", "X-OS-Instance", "X-OS-Tenant"] {
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
        "https://authority/internal/service-auth/verify-cluster",
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
        return Err(ClusterError::because(
            Errno::EACCES,
            "cluster service credential required",
        ));
    }
    if resp.status_code() != 200 {
        return Err(ClusterError::new(Errno::EIO));
    }
    let verified: VerifiedClusterCred = resp.json().await.map_err(io_err)?;
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
        ClusterError::because(errno, e.to_string())
    })?;
    Ok(verified)
}

/// Batch live-revalidation of active WebSocket watch sessions against both `OsAuthority`
/// (one RPC) and `Machine` (deduplicated per `(ns, cred_hash)` with zero byte cost).
/// Returns the set of `conn_id`s that are revoked, locked, or expired.
pub(crate) async fn revalidate_sessions(
    env: &Env,
    sessions: &[SessionCheck],
) -> std::result::Result<BTreeSet<String>, ClusterError> {
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
        "https://authority/internal/service-auth/verify-cluster-batch",
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
        return Err(ClusterError::because(
            Errno::EIO,
            "authority batch verification failed",
        ));
    }
    let batch: BatchResp = resp.json().await.map_err(io_err)?;
    let mut revoked: BTreeSet<String> = batch.revoked.into_iter().collect();

    // Deduplicate remaining live sessions by `(ns, cred_hash)` and check owning `Machine` instance lease.
    let mut by_cred: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    for s in sessions {
        if !revoked.contains(&s.conn_id) {
            by_cred
                .entry((s.ns.clone(), s.cred_hash.clone()))
                .or_default()
                .push(s.conn_id.clone());
        }
    }
    for ((ns, cred_hash), conn_ids) in by_cred {
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
            revoked.extend(conn_ids);
        }
    }
    Ok(revoked)
}

async fn read_bounded_body(
    req: &mut Request,
    max_bytes: usize,
) -> std::result::Result<Vec<u8>, ClusterError> {
    if header(req, "Content-Length")?
        .and_then(|s| s.parse::<usize>().ok())
        .is_some_and(|n| n > max_bytes)
    {
        return Err(ClusterError::because(
            Errno::EFBIG,
            "request body exceeds maximum size",
        ));
    }
    let Ok(mut stream) = req.stream() else {
        return Ok(Vec::new());
    };
    let mut buf = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(io_err)?;
        if buf.len().saturating_add(chunk.len()) > max_bytes {
            return Err(ClusterError::because(
                Errno::EFBIG,
                "request body exceeds maximum size",
            ));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

async fn call_cluster_do_post(
    env: &Env,
    cluster: &str,
    path: &str,
    body_json: String,
) -> std::result::Result<Response, ClusterError> {
    let headers = Headers::new();
    headers
        .set("Content-Type", "application/json")
        .map_err(io_err)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(body_json.into()));
    let sub =
        Request::new_with_init(&format!("https://cluster-state{path}"), &init).map_err(io_err)?;
    env.durable_object("CLUSTER_STATE")
        .map_err(io_err)?
        .get_by_name(&format!("cluster:{cluster}"))
        .map_err(io_err)?
        .fetch_with_request(sub)
        .await
        .map_err(io_err)
}

pub async fn gateway(mut req: Request, env: &Env) -> Result<Response> {
    let url = req.url()?;
    let path = url.path().to_string();
    let method = req.method();
    match (method, path.as_str()) {
        (Method::Post, "/api/cluster/rpc") => match handle_rpc(&mut req, &url, env).await {
            Ok(resp) => with_security_headers(resp),
            Err(err) => error_response(&err, false),
        },
        (Method::Post, "/api/cluster/watch-ticket") => {
            match handle_watch_ticket(&mut req, &url, env).await {
                Ok(resp) => with_security_headers(resp),
                Err(err) => error_response(&err, false),
            }
        }
        (Method::Get, "/api/cluster/watch") => match handle_watch_ws(&req, &url, env).await {
            Ok(resp) => {
                if resp.status_code() == 101 {
                    Ok(resp)
                } else {
                    with_security_headers(resp)
                }
            }
            Err(err) => error_response(&err, false),
        },
        (_, "/api/cluster/rpc" | "/api/cluster/watch-ticket" | "/api/cluster/watch") => {
            let err = ClusterError::because(Errno::EINVAL, "method not allowed");
            let mut resp = Response::from_json(&err)?.with_status(405);
            resp.headers_mut().set("X-OS-Errno", "EINVAL")?;
            with_security_headers(resp)
        }
        _ => error_response(
            &ClusterError::because(Errno::ENOENT, "unknown cluster endpoint"),
            false,
        ),
    }
}

async fn handle_rpc(
    req: &mut Request,
    url: &Url,
    env: &Env,
) -> std::result::Result<Response, ClusterError> {
    check_origin(req, url)?;
    let verified = verify_cluster(req, env).await?;
    let body = read_bounded_body(req, CLUSTER_RPC_BODY_MAX_BYTES).await?;
    let rpc = ClusterRpcRequest::decode(&body)?;
    let cmd = ClusterDoRpc {
        grant: verified.grant,
        cluster: rpc.cluster.clone(),
        call: rpc.call,
    };
    let payload = serde_json::to_string(&cmd).map_err(|_| ClusterError::new(Errno::EINVAL))?;
    call_cluster_do_post(env, &rpc.cluster, "/internal/rpc", payload).await
}

async fn handle_watch_ticket(
    req: &mut Request,
    url: &Url,
    env: &Env,
) -> std::result::Result<Response, ClusterError> {
    check_origin(req, url)?;
    let verified = verify_cluster(req, env).await?;
    if !verified.grant.scope.cluster_watch {
        return Err(ClusterError::because(
            Errno::EACCES,
            "cluster_watch capability required",
        ));
    }
    let body = read_bounded_body(req, 4096).await?;
    let ticket_req = WatchTicketRequest::decode(&body)?;
    let cmd = ClusterIssueTicket {
        cred: verified,
        cluster: ticket_req.cluster.clone(),
    };
    let payload = serde_json::to_string(&cmd).map_err(|_| ClusterError::new(Errno::EINVAL))?;
    call_cluster_do_post(env, &ticket_req.cluster, "/internal/watch-ticket", payload).await
}

async fn handle_watch_ws(
    req: &Request,
    url: &Url,
    env: &Env,
) -> std::result::Result<Response, ClusterError> {
    if !header(req, "Upgrade")?.is_some_and(|u| u.eq_ignore_ascii_case("websocket")) {
        let mut resp = Response::from_json(&ClusterError::because(
            Errno::EINVAL,
            "WebSocket upgrade required",
        ))
        .map_err(io_err)?
        .with_status(426);
        resp.headers_mut()
            .set("X-OS-Errno", "EINVAL")
            .map_err(io_err)?;
        return Ok(resp);
    }
    check_origin(req, url)?;
    let cluster = url
        .query_pairs()
        .find(|(k, _)| k == "cluster")
        .map(|(_, v)| v.into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(default_cluster_name);
    if !valid_cluster_name(&cluster) {
        return Err(ClusterError::because(Errno::EINVAL, "invalid cluster name"));
    }
    let query_ticket = url
        .query_pairs()
        .find(|(k, _)| k == "ticket")
        .map(|(_, v)| v.into_owned())
        .filter(|s| !s.is_empty());

    let raw_ticket = if let Some(ticket) = query_ticket {
        if ticket.len() > 128 || !ticket.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ClusterError::because(Errno::EACCES, "invalid watch ticket"));
        }
        ticket
    } else if header(req, "X-Process-Token")?.is_some_and(|s| !s.is_empty()) {
        let verified = verify_cluster(req, env).await?;
        if !verified.grant.scope.cluster_watch {
            return Err(ClusterError::because(
                Errno::EACCES,
                "cluster_watch capability required",
            ));
        }
        let cmd = ClusterIssueTicket {
            cred: verified,
            cluster: cluster.clone(),
        };
        let payload = serde_json::to_string(&cmd).map_err(|_| ClusterError::new(Errno::EINVAL))?;
        let mut resp =
            call_cluster_do_post(env, &cluster, "/internal/watch-ticket", payload).await?;
        if resp.status_code() >= 400 {
            return Ok(resp);
        }
        let issued: WatchTicketReply = resp.json().await.map_err(io_err)?;
        issued.ticket
    } else {
        return Err(ClusterError::because(
            Errno::EACCES,
            "watch ticket or ServiceAuth v2 cluster credential required",
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
        &format!("https://cluster-state/internal/watch?cluster={cluster}&ticket={raw_ticket}"),
        &init,
    )
    .map_err(io_err)?;
    env.durable_object("CLUSTER_STATE")
        .map_err(io_err)?
        .get_by_name(&format!("cluster:{cluster}"))
        .map_err(io_err)?
        .fetch_with_request(sub)
        .await
        .map_err(io_err)
}
