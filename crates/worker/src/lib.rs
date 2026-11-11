mod api;
mod auth;
mod cgroup_lifetime;
mod commands;
mod compiler;
mod creds;
mod db;
mod dev;
mod executor;
mod fds;
mod files;
mod guests;
mod init;
mod jobs;
mod lifecycle;
mod login;
mod machine;
mod placement;
mod procfs;
mod procs;
mod provider_policy;
mod resources;
mod runner;
mod seat_policy;
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
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let path = req.url()?.path().to_string();
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
    let legacy_session = auth::legacy_cookie_token(&req, auth::COOKIE);
    let legacy_guest = auth::legacy_cookie_token(&req, auth::GUEST_COOKIE);
    let had_legacy_session = auth::cookie_token(&req, auth::LEGACY_COOKIE).is_some();
    let had_legacy_guest = auth::cookie_token(&req, auth::LEGACY_GUEST_COOKIE).is_some();
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
            (Method::Get | Method::Head, "/api/file") => files::read(req, &env).await,
            (Method::Put, "/api/pwrite") => files::pwrite(req, &env).await,
            // The client kernel's batches of process calls go to its browser's own machine
            // (machine.rs), not the filesystem's one authority. The header is routing only:
            // the machine authenticates the account or process and checks ownership.
            (Method::Post, "/api/sys") if req.headers().get("X-Registry")?.is_some() => {
                let ns = db::Db::namespace(
                    auth::token_key(&req).as_deref(),
                    auth::guest_key(&req).as_deref(),
                );
                env.durable_object("MACHINE")?
                    .id_from_name(&ns)?
                    .get_stub()?
                    .fetch_with_request(req)
                    .await
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
    if let Some(token) = legacy_session
        && response.headers().get("Set-Cookie")?.is_none()
    {
        response
            .headers_mut()
            .append("Set-Cookie", &auth::cookie(https, &token, auth::TTL))?;
    }
    if let Some(token) = guest.or(legacy_guest) {
        response
            .headers_mut()
            .append("Set-Cookie", &auth::guest_cookie(https, &token))?;
    }
    for (present, name) in [
        (had_legacy_session, auth::LEGACY_COOKIE),
        (had_legacy_guest, auth::LEGACY_GUEST_COOKIE),
    ] {
        if present {
            response
                .headers_mut()
                .append("Set-Cookie", &auth::expire_cookie(https, name))?;
        }
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
