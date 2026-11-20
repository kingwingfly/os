//! Server-side remote `io.max` accounting & pacing client (`Machine` DO `/internal/io`).
//!
//! Enforced per remote service credential & live instance attachment regardless of client claims.
//! Local memory (`memory.max`) and PID (`pids.max`) enforcement live in `os-kernel`'s
//! `LocalProcessTable` + `CgroupTable`.
use crate::db::Db;
use abi::{Errno, Error};
use serde::{Deserialize, Serialize};

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IoRequest {
    pub ns: String,
    pub token: String,
    #[serde(default)]
    pub pid: Option<u32>,
    pub write: bool,
    pub bytes: u64,
}

pub async fn io(
    env: &worker::Env,
    ns: String,
    token: Option<String>,
    pid: Option<u32>,
    write: bool,
    bytes: u64,
) -> Result<()> {
    let Some(token) = token else {
        return Ok(());
    };
    if bytes == 0 {
        return Ok(());
    }
    checked_io(
        env,
        IoRequest {
            ns,
            token,
            pid,
            write,
            bytes,
        },
    )
    .await
}

/// Validate the service credential + owning instance lease, then reserve its remote I/O budget.
pub async fn checked_io(env: &worker::Env, request: IoRequest) -> Result<()> {
    use worker::*;
    let map = |e: worker::Error| abi::Error::because(Errno::EIO, e.to_string());
    let mut init = RequestInit::new();
    init.with_method(Method::Post).with_body(Some(
        serde_json::to_string(&request)
            .map_err(|_| Errno::EIO)?
            .into(),
    ));
    let mut reply = env
        .durable_object("MACHINE")
        .map_err(map)?
        .id_from_name(&request.ns)
        .map_err(map)?
        .get_stub()
        .map_err(map)?
        .fetch_with_request(
            Request::new_with_init("https://machine/internal/io", &init).map_err(map)?,
        )
        .await
        .map_err(map)?;
    let result: abi::Return = reply.json().await.map_err(map)?;
    let value = result.into_result()?;
    let delay = value["delay_ms"].as_u64().ok_or(Errno::EIO)?;
    if delay != 0 {
        Delay::from(std::time::Duration::from_millis(delay)).await;
    }
    Ok(())
}

pub async fn request_io(
    env: &worker::Env,
    req: &worker::Request,
    write: bool,
    bytes: u64,
) -> Result<()> {
    let map = |e: worker::Error| Error::because(Errno::EIO, e.to_string());
    let ns = Db::namespace(
        crate::auth::token_key(req).as_deref(),
        crate::auth::guest_key(req).as_deref(),
    );
    let token = req.headers().get("X-Process-Token").map_err(map)?;
    let pid = req
        .headers()
        .get("X-Process-Pid")
        .map_err(map)?
        .map(|p| p.parse::<u32>().map_err(|_| Errno::EINVAL))
        .transpose()?;
    io(env, ns, token, pid, write, bytes).await
}

pub async fn session_io(
    env: &worker::Env,
    state: &worker::State,
    session: std::rc::Rc<crate::sys::Session>,
    write: bool,
    bytes: u64,
) -> Result<()> {
    if session.token.is_none() || bytes == 0 {
        return Ok(());
    }
    let asking = session.clone();
    let browser = crate::db::transact(state, move |db| {
        (
            asking
                .of(db)
                .map(|a| a.credential.is_some_and(|c| c.job().is_none())),
            false,
        )
    })
    .map_err(|e| Error::because(Errno::EIO, e.to_string()))??;
    if browser {
        io(
            env,
            session.namespace(),
            session.token.clone(),
            session.pid,
            write,
            bytes,
        )
        .await?;
    }
    Ok(())
}

pub fn refused(error: abi::Error) -> worker::Result<worker::Response> {
    worker::Response::from_json(&serde_json::json!({"errno":error.errno,"error":error.to_string()}))
        .map(|response| {
            response.with_status(match error.errno {
                Errno::EAGAIN => 429,
                Errno::EACCES | Errno::EPERM => 403,
                _ => 400,
            })
        })
}
