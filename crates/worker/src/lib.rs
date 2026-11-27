mod api;
mod auth;
mod cloud_data;
mod cloudfs;
mod cluster_do;
mod cluster_gateway;
mod commands;
pub use cluster_do::ClusterState;
mod compiler;
mod creds;
mod db;
mod dev;
mod executor;
mod fds;
mod files;
mod guests;
mod jobs;
mod machine;
mod net_gateway;
mod node_auth;
mod overlay_do;
mod overlay_gateway;
pub use overlay_do::OverlayRelay;
mod pack_gateway;
mod registry;
mod registry_do;
mod storage_do;
pub use storage_do::StorageVolume;
mod placement;
mod procfs;
mod procs;
mod provider_policy;
mod resources;
mod runner;
mod store;
mod streams;
mod sys;
mod system;
mod usr;
pub use compiler::ModuleCompiler;
use files::error_response;
pub use machine::Machine;
pub use runner::JobRunner;
pub use store::OsAuthority;
use worker::*;

#[event(fetch)]
pub async fn main(req: Request, env: Env, ctx: Context) -> Result<Response> {
    let path = req.url()?.path().to_string();
    if path == "/v2" || path.starts_with("/v2/") {
        return registry::gateway(req, &env).await;
    }
    if path == "/api/cluster" || path.starts_with("/api/cluster/") {
        return cluster_gateway::gateway(req, &env).await;
    }
    if path == "/api/net" || path.starts_with("/api/net/") {
        return net_gateway::gateway(req, &env, &ctx).await;
    }
    if path == "/api/overlay" || path.starts_with("/api/overlay/") {
        return overlay_gateway::gateway(req, &env).await;
    }
    if path == "/api/service-auth" {
        return node_auth::gateway(req, &env).await;
    }
    // Cookie-less `X-Process-Token` requests on `/api/volumes/*` (e.g. headless `os-native`
    // kubelet worker nodes) bypass guest-cookie injection while still enforcing same-origin
    // CSRF whenever a browser `Origin` header is present.
    if path.starts_with("/api/volumes/")
        && req
            .headers()
            .get("X-Process-Token")?
            .is_some_and(|t| !t.is_empty())
        && auth::cookie_token(&req, auth::COOKIE).is_none()
        && auth::cookie_token(&req, auth::GUEST_COOKIE).is_none()
    {
        if let Some(origin) = req.headers().get("Origin")?
            && origin != req.url()?.origin().ascii_serialization()
        {
            return error_response("Write requests must originate from this site", 403);
        }
        let resp = pack_gateway::gateway(req, &env).await?;
        let headers = Headers::new();
        for (name, value) in resp.headers().entries() {
            headers.append(&name, &value)?;
        }
        headers.set("Cache-Control", "private, no-store")?;
        headers.set("Vary", "Cookie")?;
        headers.set("X-Content-Type-Options", "nosniff")?;
        return Ok(resp.with_headers(headers));
    }
    if !path.starts_with("/api/") {
        return system::route(req, &env).await;
    }
    // The page's line for changes: a WebSocket, which carries the session cookie, so only this
    // site may open one; its reply goes back as the authority made it.
    if path == "/api/events" {
        if req.headers().get("Origin")?.as_deref()
            != Some(req.url()?.origin().ascii_serialization().as_str())
        {
            return error_response("Change events must originate from this site", 403);
        }
        return env
            .durable_object("AUTHORITY")?
            .id_from_name("filesystem")?
            .get_stub()?
            .fetch_with_request(req)
            .await;
    }
    // A browser signed out is a session of its own, by a cookie it is given at once, so that
    // what it opens is its own (fds.rs).
    let (req, guest) = with_guest_cookie(req)?;
    let https = req.url()?.scheme() == "https";
    let result = async {
        if !matches!(req.method(), Method::Get | Method::Head)
            && req.headers().get("Origin")?.as_deref()
                != Some(req.url()?.origin().ascii_serialization().as_str())
        {
            return error_response("Write requests must originate from this site", 403);
        }
        // File bytes stream here, outside the authority, which only decides and records.
        match (req.method(), path.as_str()) {
            (_, path) if path.starts_with("/api/volumes/") => {
                pack_gateway::gateway(req, &env).await
            }
            (Method::Get | Method::Head, "/api/file") => files::read(req, &env).await,
            (Method::Post, "/api/fs/data") => cloud_data::gateway(req, &env).await,
            (Method::Put, "/api/pwrite") => files::pwrite(req, &env).await,
            // Retired `X-Registry` server process registry routing fails closed (Contract §2.12).
            (Method::Post, "/api/sys") if req.headers().get("X-Registry")?.is_some() => {
                Ok(Response::from_json(&serde_json::json!({
                    "errno": "EPERM",
                    "error": "server process registry route has been removed; use ServiceAuth v2",
                }))?
                .with_status(403))
            }
            _ => {
                env.durable_object("AUTHORITY")?
                    .id_from_name("filesystem")?
                    .get_stub()?
                    .fetch_with_request(req)
                    .await
            }
        }
    }
    .await;
    let mut response = match result {
        Ok(r) => r,
        Err(e) => {
            console_error!("request failed: {}", e);
            error_response("Service temporarily unavailable; please try again", 500)?
        }
    };
    if path == "/api/sys" {
        response = system::finish_preparation(&env, response).await?;
    }
    let headers = Headers::new();
    for (name, value) in response.headers().entries() {
        headers.append(&name, &value)?;
    }
    response = response.with_headers(headers);
    response
        .headers_mut()
        .set("Cache-Control", "private, no-store")?;
    response.headers_mut().set("Vary", "Cookie")?;
    response
        .headers_mut()
        .set("X-Content-Type-Options", "nosniff")?;
    let sets_session = response
        .headers()
        .get("Set-Cookie")?
        .is_some_and(|v| v.contains(&format!("{}=", auth::COOKIE)));
    if !sets_session && let Some(token) = guest {
        response
            .headers_mut()
            .append("Set-Cookie", &auth::guest_cookie(https, &token))?;
    }
    Ok(response)
}

/// `req`, with a new browser's own cookie if it has neither a session's nor its own; and that
/// cookie's token, for the reply to give it.
fn with_guest_cookie(req: Request) -> Result<(Request, Option<String>)> {
    if auth::cookie_token(&req, auth::COOKIE).is_some()
        || auth::cookie_token(&req, auth::GUEST_COOKIE).is_some()
    {
        return Ok((req, None));
    }
    let token = auth::random_token();
    let headers = Headers::new();
    for (name, value) in req.headers().entries() {
        if !name.eq_ignore_ascii_case("cookie") {
            headers.append(&name, &value)?;
        }
    }
    let ours = format!("{}={token}", auth::GUEST_COOKIE);
    let cookie = match req.headers().get("Cookie")? {
        Some(cookies) if !cookies.trim().is_empty() => format!("{cookies}; {ours}"),
        _ => ours,
    };
    headers.set("Cookie", &cookie)?;
    let init = web_sys::RequestInit::new();
    init.set_headers(&headers.0.into());
    let req = web_sys::Request::new_with_request_and_init(req.inner(), &init)
        .map_err(|e| Error::RustError(format!("{e:?}")))?;
    Ok((req.into(), Some(token)))
}
