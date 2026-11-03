mod api;
mod auth;
mod commands;
mod db;
mod dev;
mod fds;
mod files;
mod jobs;
mod procfs;
mod runner;
mod store;
mod streams;
mod sys;
mod usr;
use files::error_response;
pub use runner::JobRunner;
pub use store::TerminalAuthority;
use worker::*;

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let path = req.url()?.path().to_string();
    if !path.starts_with("/api/") {
        return env.assets("ASSETS")?.fetch_request(req).await;
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
            (Method::Get | Method::Head, "/api/file") => files::read(req, &env).await,
            (Method::Put, "/api/pwrite") => files::pwrite(req, &env).await,
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
    if let Some(token) = guest {
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
