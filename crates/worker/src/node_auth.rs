//! Edge router for `ServiceAuth v2` including worker-node bootstrap enrollment,
//! cookie-less `node.<enrollment_id>` routing, and live node revocation (`Phase 9.1b #84`).
use crate::{auth, db::Db, files::error_response};
use abi::auth_v2::{
    BOOTSTRAP_TTL_MAX_SECS, BOOTSTRAP_TTL_MIN_SECS, BootstrapTokenIssued, ExchangeBootstrapToken,
    INSTANCE_LEASE_SECONDS, MintBootstrapToken, NodeCredIssued, Request as AuthRequest,
    Response as AuthResponse, RevokeNode, VERSION, valid_cluster_record_id, valid_id,
};
use abi::cluster_state::valid_cluster_name;
use abi::{Errno, Error};
use serde::Deserialize;
use serde_json::{Value, json};
use worker::*;

fn auth_err(err: &Error) -> Result<Response> {
    let status = match err.errno {
        Errno::EACCES | Errno::EPERM => 403,
        Errno::ENOENT => 404,
        Errno::EBUSY | Errno::EEXIST => 409,
        Errno::ESTALE => 412,
        Errno::E2BIG => 413,
        Errno::EAGAIN => 429,
        Errno::ENOSYS => 501,
        _ => 400,
    };
    Ok(Response::from_json(&json!({
        "errno": err.errno,
        "error": err.to_string(),
    }))?
    .with_status(status))
}

fn with_security_headers(mut resp: Response) -> Result<Response> {
    let headers = Headers::new();
    for (name, value) in resp.headers().entries() {
        headers.append(&name, &value)?;
    }
    headers.set("Cache-Control", "private, no-store")?;
    headers.set("Vary", "Cookie")?;
    headers.set("X-Content-Type-Options", "nosniff")?;
    resp = resp.with_headers(headers);
    Ok(resp)
}

fn check_csrf(req: &Request) -> std::result::Result<(), Error> {
    let origin = req
        .headers()
        .get("Origin")
        .map_err(|_| Error::new(Errno::EIO))?;
    let has_cookie = req
        .headers()
        .get("Cookie")
        .map_err(|_| Error::new(Errno::EIO))?
        .is_some_and(|c| !c.trim().is_empty());
    if origin.is_some() || has_cookie {
        let expected = req
            .url()
            .map_err(|_| Error::new(Errno::EIO))?
            .origin()
            .ascii_serialization();
        if origin.as_deref() != Some(expected.as_str()) {
            return Err(Error::because(
                Errno::EACCES,
                "Write requests must originate from this site",
            ));
        }
    }
    Ok(())
}

async fn call_authority(
    env: &Env,
    endpoint: &str,
    cookie: Option<&str>,
    body: Value,
) -> std::result::Result<Value, Error> {
    let map = |e: worker::Error| Error::because(Errno::EIO, e.to_string());
    let headers = Headers::new();
    headers
        .set("Content-Type", "application/json")
        .map_err(map)?;
    if let Some(c) = cookie {
        headers.set("Cookie", c).map_err(map)?;
    }
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(body.to_string().into()));
    let sub =
        Request::new_with_init(&format!("https://authority{endpoint}"), &init).map_err(map)?;
    let mut resp = env
        .durable_object("AUTHORITY")
        .map_err(map)?
        .id_from_name("filesystem")
        .map_err(map)?
        .get_stub()
        .map_err(map)?
        .fetch_with_request(sub)
        .await
        .map_err(map)?;
    let status = resp.status_code();
    let val: Value = resp.json().await.map_err(map)?;
    if status >= 400 {
        let errno = val
            .get("errno")
            .and_then(|v| serde_json::from_value::<Errno>(v.clone()).ok())
            .unwrap_or(match status {
                401 | 403 => Errno::EACCES,
                404 => Errno::ENOENT,
                409 => Errno::EBUSY,
                412 => Errno::ESTALE,
                _ => Errno::EIO,
            });
        let detail = val["error"]
            .as_str()
            .unwrap_or_else(|| errno.text())
            .to_string();
        return Err(Error::because(errno, detail));
    }
    Ok(val)
}

async fn call_machine_json(
    env: &Env,
    ns: &str,
    endpoint: &str,
    body: Value,
) -> std::result::Result<Value, Error> {
    let map = |e: worker::Error| Error::because(Errno::EIO, e.to_string());
    let headers = Headers::new();
    headers
        .set("Content-Type", "application/json")
        .map_err(map)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(body.to_string().into()));
    let sub = Request::new_with_init(&format!("https://machine{endpoint}"), &init).map_err(map)?;
    let mut resp = env
        .durable_object("MACHINE")
        .map_err(map)?
        .id_from_name(ns)
        .map_err(map)?
        .get_stub()
        .map_err(map)?
        .fetch_with_request(sub)
        .await
        .map_err(map)?;
    let status = resp.status_code();
    let val: Value = resp.json().await.map_err(map)?;
    if status >= 400 {
        let errno = val
            .get("errno")
            .and_then(|v| serde_json::from_value::<Errno>(v.clone()).ok())
            .unwrap_or(match status {
                401 | 403 => Errno::EACCES,
                404 => Errno::ENOENT,
                409 => Errno::EBUSY,
                412 => Errno::ESTALE,
                _ => Errno::EIO,
            });
        let detail = val["error"]
            .as_str()
            .unwrap_or_else(|| errno.text())
            .to_string();
        return Err(Error::because(errno, detail));
    }
    Ok(val)
}

async fn verify_session_instance(
    env: &Env,
    session_ns: &str,
    instance_id: &str,
    host_proof: &str,
) -> std::result::Result<(), Error> {
    call_machine_json(
        env,
        session_ns,
        "/internal/verify-session-instance",
        json!({
            "ns": session_ns,
            "instance_id": instance_id,
            "host_proof": host_proof,
        }),
    )
    .await
    .map(|_| ())
}

async fn handle_mint_bootstrap(
    env: &Env,
    cookie: Option<&str>,
    session_key: Option<&str>,
    caller_ns: &str,
    mint: MintBootstrapToken,
) -> std::result::Result<Response, Error> {
    if session_key.is_none() {
        return Err(Error::because(
            Errno::EACCES,
            "authenticated cloud session required to mint a node bootstrap token",
        ));
    }
    if !valid_id(&mint.instance_id)
        || !valid_id(&mint.host_proof)
        || !valid_cluster_record_id(&mint.node_id)
        || !valid_cluster_name(&mint.cluster)
        || !(BOOTSTRAP_TTL_MIN_SECS..=BOOTSTRAP_TTL_MAX_SECS).contains(&mint.ttl_secs)
    {
        return Err(Error::because(
            Errno::EINVAL,
            "invalid bootstrap token request",
        ));
    }
    verify_session_instance(env, caller_ns, &mint.instance_id, &mint.host_proof).await?;

    let raw_bootstrap = format!("osbt_{}", auth::random_token());
    let token_hash = auth::token_hash(&raw_bootstrap);
    let issued = call_authority(
        env,
        "/internal/service-auth/mint-bootstrap",
        cookie,
        json!({
            "token_hash": token_hash,
            "node_id": mint.node_id,
            "cluster": mint.cluster,
            "ttl_secs": mint.ttl_secs,
            "scope": mint.scope,
            "sudo": mint.sudo,
        }),
    )
    .await?;

    let scope: abi::auth_v2::RemoteScope =
        serde_json::from_value(issued["scope"].clone()).unwrap_or_default();
    let reply = AuthResponse::BootstrapToken(BootstrapTokenIssued {
        version: VERSION,
        bootstrap_token: raw_bootstrap,
        node_id: issued["node_id"].as_str().unwrap_or_default().to_string(),
        cluster: issued["cluster"].as_str().unwrap_or_default().to_string(),
        tenant: issued["tenant"].as_str().unwrap_or_default().to_string(),
        expires: issued["expires"].as_u64().unwrap_or(0),
        scope,
    });
    Response::from_json(&reply).map_err(|e| Error::because(Errno::EIO, e.to_string()))
}

async fn handle_exchange_bootstrap(
    env: &Env,
    ex: ExchangeBootstrapToken,
) -> std::result::Result<Response, Error> {
    let valid_bt = ex
        .bootstrap_token
        .strip_prefix("osbt_")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()));
    if !valid_bt
        || !valid_id(&ex.instance.instance)
        || !valid_id(&ex.instance.host)
        || !valid_id(&ex.host_proof)
    {
        return Err(Error::because(
            Errno::EINVAL,
            "invalid bootstrap exchange request",
        ));
    }
    let bootstrap_hash = auth::token_hash(&ex.bootstrap_token);
    let raw_node_token = auth::random_token();
    let new_token_hash = auth::token_hash(&raw_node_token);
    let enrollment_id = auth::random_token()[..32].to_string();

    let exchanged = call_authority(
        env,
        "/internal/service-auth/exchange-bootstrap",
        None,
        json!({
            "bootstrap_hash": bootstrap_hash,
            "new_token_hash": new_token_hash,
            "enrollment_id": enrollment_id,
            "instance_id": ex.instance.instance,
        }),
    )
    .await?;

    let ns = exchanged["ns"].as_str().unwrap_or_default().to_string();
    let node_id = exchanged["node_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let cluster = exchanged["cluster"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let tenant = exchanged["tenant"].as_str().unwrap_or_default().to_string();
    let uid = exchanged["uid"].as_u64().unwrap_or(65534) as u32;
    let gid = exchanged["gid"].as_u64().unwrap_or(65534) as u32;
    let lineage = exchanged["lineage"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let expires = exchanged["expires"].as_u64().unwrap_or(0);
    let scope: abi::auth_v2::RemoteScope =
        serde_json::from_value(exchanged["scope"].clone()).unwrap_or_default();

    let enroll_res = call_machine_json(
        env,
        &ns,
        "/internal/node-enroll",
        json!({
            "ns": ns,
            "instance": ex.instance,
            "host_proof": ex.host_proof,
            "raw_token": raw_node_token,
            "uid": uid,
            "gid": gid,
            "lineage": lineage,
            "cgroup": "/services/kubelet",
            "scope": scope,
            "expires": expires,
        }),
    )
    .await;

    if let Err(err) = enroll_res {
        // Immediately revoke the freshly minted authority credential so zero orphans survive.
        let _ = call_authority(
            env,
            "/internal/revoke",
            None,
            json!({
                "ns": ns,
                "tokens": [new_token_hash],
                "renew": [],
            }),
        )
        .await;
        return Err(err);
    }

    let reply = AuthResponse::NodeEnrolled(NodeCredIssued {
        version: VERSION,
        token: raw_node_token,
        enrollment_id,
        ns,
        node_id,
        cluster,
        tenant,
        instance_id: ex.instance.instance,
        scope,
        lease_seconds: INSTANCE_LEASE_SECONDS,
        expires,
    });
    Response::from_json(&reply).map_err(|e| Error::because(Errno::EIO, e.to_string()))
}

async fn handle_revoke_node(
    env: &Env,
    cookie: Option<&str>,
    session_key: Option<&str>,
    caller_ns: &str,
    rev: RevokeNode,
) -> std::result::Result<Response, Error> {
    if session_key.is_none() {
        return Err(Error::because(
            Errno::EACCES,
            "authenticated cloud session required to revoke a node",
        ));
    }
    if !valid_id(&rev.instance_id)
        || !valid_id(&rev.host_proof)
        || !valid_cluster_record_id(&rev.node_id)
        || rev.enrollment_id.as_deref().is_some_and(|e| !valid_id(e))
    {
        return Err(Error::because(Errno::EINVAL, "invalid revoke_node request"));
    }
    verify_session_instance(env, caller_ns, &rev.instance_id, &rev.host_proof).await?;

    let revoked_val = call_authority(
        env,
        "/internal/service-auth/revoke-node",
        cookie,
        json!({
            "node_id": rev.node_id,
            "enrollment_id": rev.enrollment_id,
        }),
    )
    .await?;

    #[derive(Deserialize)]
    struct RevokeAuthorityReply {
        revoked: usize,
        #[serde(default)]
        namespaces: Vec<String>,
        #[serde(default)]
        clusters: Vec<String>,
    }
    let info: RevokeAuthorityReply =
        serde_json::from_value(revoked_val).map_err(|_| Error::new(Errno::EIO))?;

    // Fan out revocation to every affected node `Machine` DO so live checks fail closed immediately.
    for node_ns in &info.namespaces {
        let _ = call_machine_json(
            env,
            node_ns,
            "/internal/node-revoke",
            json!({ "ns": node_ns }),
        )
        .await;
    }

    // Trigger immediate watch revalidation on every affected `ClusterState` DO so live WS watches
    // disconnect immediately with close code 1008.
    for cluster in &info.clusters {
        if valid_cluster_name(cluster)
            && let Ok(cluster_ns) = env.durable_object("CLUSTER_STATE")
            && let Ok(stub) = cluster_ns.get_by_name(&format!("cluster:{cluster}"))
        {
            let headers = Headers::new();
            let _ = headers.set("Content-Type", "application/json");
            let mut init = RequestInit::new();
            init.with_method(Method::Post)
                .with_headers(headers)
                .with_body(Some(json!({ "cluster": cluster }).to_string().into()));
            if let Ok(sub) =
                Request::new_with_init("https://cluster-state/internal/revalidate-watches", &init)
            {
                let _ = stub.fetch_with_request(sub).await;
            }
        }
    }

    Response::from_json(&AuthResponse::NodeRevoked {
        revoked: info.revoked,
    })
    .map_err(|e| Error::because(Errno::EIO, e.to_string()))
}

/// Top-level `POST /api/service-auth` gateway handling both browser session/guest requests
/// and cookie-less enrolled worker-node requests (`X-OS-Node-Enrollment` / `ExchangeBootstrapToken`).
pub async fn gateway(mut req: Request, env: &Env) -> Result<Response> {
    if req.method() != Method::Post {
        return with_security_headers(error_response("Method not allowed", 405)?);
    }
    if let Err(err) = check_csrf(&req) {
        return with_security_headers(auth_err(&err)?);
    }
    if req
        .headers()
        .get("Content-Length")?
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|len| len > abi::BATCH_BYTES)
    {
        return with_security_headers(auth_err(&Errno::E2BIG.into())?);
    }
    let body = req.text().await?;
    if body.len() as u64 > abi::BATCH_BYTES {
        return with_security_headers(auth_err(&Errno::E2BIG.into())?);
    }
    let Ok(raw_val) = serde_json::from_str::<Value>(&body) else {
        return with_security_headers(auth_err(&Error::because(
            Errno::EINVAL,
            "invalid ServiceAuth JSON",
        ))?);
    };
    if let Some(ver) = raw_val.get("version").and_then(Value::as_u64)
        && ver != u64::from(VERSION)
    {
        return with_security_headers(auth_err(&Error::because(
            Errno::EPROTONOSUPPORT,
            format!("ServiceAuth v{VERSION} required"),
        ))?);
    }
    let Ok(parsed) = serde_json::from_value::<AuthRequest>(raw_val) else {
        return with_security_headers(auth_err(&Error::because(
            Errno::EINVAL,
            "invalid ServiceAuth v2 request",
        ))?);
    };

    let enrollment_hdr = req
        .headers()
        .get("X-OS-Node-Enrollment")?
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    // 1. Enrolled node routing via `X-OS-Node-Enrollment` (cookie-less; never injects `os_guest`).
    if let Some(enroll_id) = enrollment_hdr {
        if !valid_id(&enroll_id) {
            return with_security_headers(auth_err(&Error::because(
                Errno::EINVAL,
                "invalid X-OS-Node-Enrollment",
            ))?);
        }
        if matches!(
            parsed,
            AuthRequest::AttachInstance(_)
                | AuthRequest::MintServiceCred(_)
                | AuthRequest::MintBootstrapToken(_)
                | AuthRequest::ExchangeBootstrapToken(_)
                | AuthRequest::RevokeNode(_)
        ) {
            return with_security_headers(auth_err(&Error::because(
                Errno::EACCES,
                "operation not permitted on a node enrollment namespace",
            ))?);
        }
        let node_ns = format!("node.{enroll_id}");
        let headers = Headers::new();
        headers.set("Content-Type", "application/json")?;
        headers.set("Content-Length", &body.len().to_string())?;
        headers.set("X-OS-Internal-Node-Ns", &node_ns)?;
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_headers(headers)
            .with_body(Some(body.into()));
        let sub = Request::new_with_init("https://machine/api/service-auth", &init)?;
        let resp = env
            .durable_object("MACHINE")?
            .id_from_name(&node_ns)?
            .get_stub()?
            .fetch_with_request(sub)
            .await?;
        return with_security_headers(resp);
    }

    // 2. Cookie-less single-use bootstrap token exchange (never injects `os_guest`).
    if let AuthRequest::ExchangeBootstrapToken(ex) = parsed {
        let resp = match handle_exchange_bootstrap(env, ex).await {
            Ok(r) => r,
            Err(err) => auth_err(&err)?,
        };
        return with_security_headers(resp);
    }

    // 3. Session-authenticated node control (`MintBootstrapToken`, `RevokeNode`).
    let cookie = req.headers().get("Cookie")?;
    let session_key = auth::token_key(&req);
    let existing_guest_key = auth::guest_key(&req);
    let caller_ns = Db::namespace(session_key.as_deref(), existing_guest_key.as_deref());
    match parsed {
        AuthRequest::MintBootstrapToken(mint) => {
            let resp = match handle_mint_bootstrap(
                env,
                cookie.as_deref(),
                session_key.as_deref(),
                &caller_ns,
                mint,
            )
            .await
            {
                Ok(r) => r,
                Err(err) => auth_err(&err)?,
            };
            return with_security_headers(resp);
        }
        AuthRequest::RevokeNode(rev) => {
            let resp = match handle_revoke_node(
                env,
                cookie.as_deref(),
                session_key.as_deref(),
                &caller_ns,
                rev,
            )
            .await
            {
                Ok(r) => r,
                Err(err) => auth_err(&err)?,
            };
            return with_security_headers(resp);
        }
        _ => {}
    }

    // 4. Existing browser session/guest ServiceAuth v2 routing to `Machine` DO.
    let legacy_session = auth::legacy_cookie_token(&req, auth::COOKIE);
    let legacy_guest = auth::legacy_cookie_token(&req, auth::GUEST_COOKIE);
    let had_legacy_session = auth::cookie_token(&req, auth::LEGACY_COOKIE).is_some();
    let had_legacy_guest = auth::cookie_token(&req, auth::LEGACY_GUEST_COOKIE).is_some();
    let https = req.url()?.scheme() == "https";
    let (effective_cookie, minted_guest) = if auth::cookie_token(&req, auth::COOKIE).is_some()
        || auth::cookie_token(&req, auth::GUEST_COOKIE).is_some()
    {
        (cookie, None)
    } else {
        let tok = auth::random_token();
        let ours = format!("{}={tok}", auth::GUEST_COOKIE);
        let merged = match cookie {
            Some(c) if !c.trim().is_empty() => format!("{c}; {ours}"),
            _ => ours,
        };
        (Some(merged), Some(tok))
    };

    let guest_key = minted_guest
        .as_deref()
        .map(|t| format!("guest.{}", auth::token_hash(t)))
        .or_else(|| auth::guest_key(&req));
    let ns = Db::namespace(session_key.as_deref(), guest_key.as_deref());

    let headers = Headers::new();
    headers.set("Content-Type", "application/json")?;
    headers.set("Content-Length", &body.len().to_string())?;
    if let Some(ref c) = effective_cookie {
        headers.set("Cookie", c)?;
    }
    if let Some(rel) = req.headers().get("X-OS-Release")? {
        headers.set("X-OS-Release", &rel)?;
    }
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(body.into()));
    let sub = Request::new_with_init("https://machine/api/service-auth", &init)?;
    let mut resp = env
        .durable_object("MACHINE")?
        .id_from_name(&ns)?
        .get_stub()?
        .fetch_with_request(sub)
        .await?;
    resp = with_security_headers(resp)?;
    if let Some(token) = legacy_session
        && resp.headers().get("Set-Cookie")?.is_none()
    {
        resp.headers_mut()
            .append("Set-Cookie", &auth::cookie(https, &token, auth::TTL))?;
    }
    if let Some(token) = minted_guest.or(legacy_guest) {
        resp.headers_mut()
            .append("Set-Cookie", &auth::guest_cookie(https, &token))?;
    }
    for (present, name) in [
        (had_legacy_session, auth::LEGACY_COOKIE),
        (had_legacy_guest, auth::LEGACY_GUEST_COOKIE),
    ] {
        if present {
            resp.headers_mut()
                .append("Set-Cookie", &auth::expire_cookie(https, name))?;
        }
    }
    Ok(resp)
}
