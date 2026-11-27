//! Edge HTTP + WebSocket outbound stream gateway for Phase 10a (`#86` `netd`).
//!
//! Routes (mounted in `lib.rs` BEFORE `with_guest_cookie` so cookie-less `ServiceAuth v2`
//! callers work cleanly while browser requests still enforce same-origin CSRF):
//! - `POST /api/net/ticket`  — authenticate `ServiceAuth v2`, evaluate `NetScope` + SSRF +
//!   optional two-key `NET_TEST_LOOPBACK_ADDRS`, reserve a concurrency slot in `Machine` DO,
//!   and issue a short-lived single-use upgrade ticket.
//! - `GET  /api/net/connect` — consume the single-use ticket (or authenticate direct headers),
//!   upgrade to WebSocket, dial outbound TCP/TLS via `cloudflare:sockets` (`worker_sys::connect`),
//!   re-verify resolved/connected `remoteAddress` against SSRF rules, and pump credit-windowed
//!   `[0x01..0x05]` data-plane frames with live byte/rate/revocation enforcement.

use crate::auth;
use crate::procs::NetTicketRow;
use crate::resources::{self, IoRequest};
use abi::Errno;
use abi::net_ctl::{
    DataFrame, LoopbackTestAllowlist, NET_DATA_CHUNK_MAX, NET_INITIAL_WINDOW_BYTES, NetErrorKind,
    NetFailure, NetQuota, NetScope, ParsedHost, StreamClosed, TlsMode, decode_ws_data_frame,
    encode_ws_data_frame, extract_ip_from_socket_addr_str,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::StreamExt;
use js_sys::{Object, Reflect, Uint8Array};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::VecDeque;
use std::pin::Pin;
use std::time::Duration;
use wasm_bindgen::{JsCast, JsValue};
use worker::wasm_bindgen_futures::JsFuture;
use worker::web_sys::{ReadableStreamDefaultReader, WritableStreamDefaultWriter};
use worker::*;

const MAX_TICKET_BODY_BYTES: usize = 4096;
const CHARGE_BATCH_BYTES: u64 = 32 * 1024;
const CHARGE_BATCH_INTERVAL_MS: f64 = 250.0;
const REVOCATION_POLL_INTERVAL_MS: f64 = 2_000.0;

#[derive(Clone, Debug, Deserialize)]
struct VerifiedNetCred {
    ns: String,
    cred_hash: String,
    instance_id: String,
    uid: u32,
    net: NetScope,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TicketRequest {
    host: String,
    port: u16,
    #[serde(default)]
    tls: TlsMode,
    #[serde(default)]
    timeout_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
struct TicketReply {
    ticket: String,
    stream_id: String,
    quota: NetQuota,
}

fn with_security_headers(mut resp: Response) -> Result<Response> {
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

fn failure_response(fail: &NetFailure) -> Result<Response> {
    let status = match fail.errno {
        Errno::EACCES | Errno::EPERM => 403,
        Errno::ENOENT => 404,
        Errno::EDQUOT | Errno::ENOSPC => 507,
        Errno::EAGAIN => 429,
        Errno::ETIMEDOUT => 504,
        Errno::E2BIG | Errno::EMSGSIZE => 413,
        Errno::EOPNOTSUPP | Errno::EPROTONOSUPPORT | Errno::EAFNOSUPPORT => 501,
        Errno::EIO => 500,
        _ => 400,
    };
    let mut resp = Response::from_json(&json!({
        "errno": fail.errno,
        "error": fail.kind,
        "message": fail.message,
    }))?
    .with_status(status);
    resp.headers_mut()
        .set("X-OS-Errno", &format!("{:?}", fail.errno))?;
    with_security_headers(resp)
}

fn io_fail(err: worker::Error) -> NetFailure {
    NetFailure::new(Errno::EIO, NetErrorKind::HostUnavailable, err.to_string())
}

fn header(req: &Request, name: &str) -> std::result::Result<Option<String>, NetFailure> {
    req.headers().get(name).map_err(io_fail)
}

fn check_origin(req: &Request, url: &Url) -> std::result::Result<(), NetFailure> {
    let origin_hdr = header(req, "Origin")?;
    let has_cookie = header(req, "Cookie")?.is_some_and(|c| !c.trim().is_empty());
    if origin_hdr.is_some() || has_cookie {
        let expected = url.origin().ascii_serialization();
        if origin_hdr.as_deref() != Some(expected.as_str()) {
            return Err(NetFailure::new(
                Errno::EACCES,
                NetErrorKind::PolicyDenied,
                "network gateway requests with browser origin or cookie must originate from this site",
            ));
        }
    }
    Ok(())
}

fn load_loopback_allowlist(env: &Env) -> std::result::Result<LoopbackTestAllowlist, NetFailure> {
    match env.var("NET_TEST_LOOPBACK_ADDRS") {
        Ok(val) => {
            let raw = val.to_string();
            LoopbackTestAllowlist::parse_csv(&raw).map_err(|e| {
                NetFailure::new(
                    Errno::EINVAL,
                    NetErrorKind::InvalidArgument,
                    format!("invalid NET_TEST_LOOPBACK_ADDRS: {e}"),
                )
            })
        }
        Err(_) => Ok(LoopbackTestAllowlist::new()),
    }
}

async fn verify_net_cred(
    req: &Request,
    env: &Env,
) -> std::result::Result<VerifiedNetCred, NetFailure> {
    let headers = Headers::new();
    for name in ["Cookie", "X-Process-Token", "X-OS-Instance"] {
        if let Some(v) = header(req, name)? {
            headers.set(name, &v).map_err(io_fail)?;
        }
    }
    headers
        .set("Content-Type", "application/json")
        .map_err(io_fail)?;
    let mut init = RequestInit::new();
    init.with_method(Method::Post).with_headers(headers);
    let sub = Request::new_with_init("https://authority/internal/service-auth/verify-net", &init)
        .map_err(io_fail)?;
    let mut resp = env
        .durable_object("AUTHORITY")
        .map_err(io_fail)?
        .get_by_name("filesystem")
        .map_err(io_fail)?
        .fetch_with_request(sub)
        .await
        .map_err(io_fail)?;
    if resp.status_code() == 403 {
        return Err(NetFailure::new(
            Errno::EACCES,
            NetErrorKind::PolicyDenied,
            "network egress service credential required",
        ));
    }
    if resp.status_code() != 200 {
        return Err(NetFailure::new(
            Errno::EIO,
            NetErrorKind::HostUnavailable,
            format!("authority verify-net failed (HTTP {})", resp.status_code()),
        ));
    }
    let verified: VerifiedNetCred = resp.json().await.map_err(io_fail)?;
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
        NetFailure::new(errno, NetFailure::from(errno).kind, e.to_string())
    })?;
    Ok(verified)
}

async fn read_bounded_body(
    req: &mut Request,
    max_bytes: usize,
) -> std::result::Result<Vec<u8>, NetFailure> {
    if header(req, "Content-Length")?
        .and_then(|s| s.parse::<usize>().ok())
        .is_some_and(|n| n > max_bytes)
    {
        return Err(NetFailure::new(
            Errno::E2BIG,
            NetErrorKind::InvalidArgument,
            "request body too large",
        ));
    }
    let bytes = req.bytes().await.map_err(io_fail)?;
    if bytes.len() > max_bytes {
        return Err(NetFailure::new(
            Errno::E2BIG,
            NetErrorKind::InvalidArgument,
            "request body too large",
        ));
    }
    Ok(bytes)
}

async fn machine_net_rpc(
    env: &Env,
    ns: &str,
    endpoint: &str,
    body: serde_json::Value,
) -> std::result::Result<serde_json::Value, NetFailure> {
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_body(Some(body.to_string().into()));
    let req =
        Request::new_with_init(&format!("https://machine{endpoint}"), &init).map_err(io_fail)?;
    let mut resp = env
        .durable_object("MACHINE")
        .map_err(io_fail)?
        .id_from_name(ns)
        .map_err(io_fail)?
        .get_stub()
        .map_err(io_fail)?
        .fetch_with_request(req)
        .await
        .map_err(io_fail)?;
    let ret: abi::Return = resp.json().await.map_err(io_fail)?;
    ret.into_result().map_err(|e| {
        let f = NetFailure::from(e.errno);
        NetFailure::new(e.errno, f.kind, e.to_string())
    })
}

fn tls_mode_str(tls: TlsMode) -> &'static str {
    match tls {
        TlsMode::Off => "off",
        TlsMode::On => "on",
        TlsMode::StartTls => "starttls",
    }
}

fn parse_tls_mode(raw: &str) -> std::result::Result<TlsMode, NetFailure> {
    match raw {
        "off" | "" => Ok(TlsMode::Off),
        "on" => Ok(TlsMode::On),
        "start_tls" | "starttls" => Ok(TlsMode::StartTls),
        _ => Err(NetFailure::new(
            Errno::EINVAL,
            NetErrorKind::InvalidArgument,
            format!("invalid tls mode '{raw}'"),
        )),
    }
}

fn encode_ticket(ns: &str, secret: &str) -> String {
    format!("{}.{secret}", URL_SAFE_NO_PAD.encode(ns.as_bytes()))
}

fn decode_ticket(raw: &str) -> std::result::Result<(String, String), NetFailure> {
    let Some((ns_b64, secret)) = raw.split_once('.') else {
        return Err(NetFailure::new(
            Errno::EACCES,
            NetErrorKind::PolicyDenied,
            "malformed stream ticket",
        ));
    };
    if secret.len() != 64 || !secret.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(NetFailure::new(
            Errno::EACCES,
            NetErrorKind::PolicyDenied,
            "invalid stream ticket secret",
        ));
    }
    let ns_bytes = URL_SAFE_NO_PAD.decode(ns_b64).map_err(|_| {
        NetFailure::new(
            Errno::EACCES,
            NetErrorKind::PolicyDenied,
            "invalid stream ticket namespace",
        )
    })?;
    let ns = String::from_utf8(ns_bytes).map_err(|_| {
        NetFailure::new(
            Errno::EACCES,
            NetErrorKind::PolicyDenied,
            "invalid stream ticket UTF-8",
        )
    })?;
    if !ns.starts_with("session.") && !ns.starts_with("node.") {
        return Err(NetFailure::new(
            Errno::EACCES,
            NetErrorKind::PolicyDenied,
            "invalid stream ticket namespace prefix",
        ));
    }
    Ok((ns, secret.to_string()))
}

/// Entrypoint for `/api/net/*`.
pub async fn gateway(mut req: Request, env: &Env, ctx: &Context) -> Result<Response> {
    let url = req.url()?;
    let path = url.path().to_string();
    match (req.method(), path.as_str()) {
        (Method::Post, "/api/net/ticket") => match handle_ticket(&mut req, &url, env).await {
            Ok(resp) => with_security_headers(resp),
            Err(fail) => failure_response(&fail),
        },
        (Method::Get, "/api/net/connect") => match handle_connect(&req, &url, env, ctx).await {
            Ok(resp) => {
                if resp.status_code() == 101 {
                    Ok(resp)
                } else {
                    with_security_headers(resp)
                }
            }
            Err(fail) => failure_response(&fail),
        },
        (_, "/api/net/ticket" | "/api/net/connect") => {
            let mut resp = Response::from_json(&json!({
                "errno": Errno::EINVAL,
                "error": NetErrorKind::InvalidArgument,
                "message": "method not allowed",
            }))?
            .with_status(405);
            resp.headers_mut().set("X-OS-Errno", "EINVAL")?;
            with_security_headers(resp)
        }
        _ => failure_response(&NetFailure::new(
            Errno::ENOENT,
            NetErrorKind::InvalidArgument,
            "unknown network gateway endpoint",
        )),
    }
}

async fn reserve_ticket_for_cred(
    env: &Env,
    verified: &VerifiedNetCred,
    host: &str,
    port: u16,
    tls: TlsMode,
    timeout_ms: Option<u64>,
    allowlist: &LoopbackTestAllowlist,
) -> std::result::Result<(String, String, String, NetQuota), NetFailure> {
    if tls == TlsMode::StartTls {
        return Err(NetFailure::new(
            Errno::EOPNOTSUPP,
            NetErrorKind::Unsupported,
            "TlsMode::StartTls upgrade is not supported (use TlsMode::Off or TlsMode::On)",
        ));
    }
    verified.net.check_egress(host, port, tls, allowlist)?;
    let mut quota = verified.net.quota.clamped().map_err(|e| {
        NetFailure::new(Errno::EINVAL, NetErrorKind::InvalidArgument, e.to_string())
    })?;
    if let Some(req_to) = timeout_ms
        && req_to > 0
    {
        quota.connect_timeout_ms = quota.connect_timeout_ms.min(req_to);
    }
    let scope_json = serde_json::to_string(&verified.net).map_err(|_| {
        NetFailure::new(
            Errno::EIO,
            NetErrorKind::HostUnavailable,
            "serialize net scope",
        )
    })?;
    let secret = auth::random_token();
    let ticket_hash = auth::token_hash(&secret);
    let stream_id = format!("net_{}", &auth::random_token()[..24]);
    machine_net_rpc(
        env,
        &verified.ns,
        "/internal/net/reserve",
        json!({
            "ns": verified.ns,
            "instance_id": verified.instance_id,
            "token_hash": verified.cred_hash,
            "uid": verified.uid,
            "ticket_hash": ticket_hash,
            "stream_id": stream_id,
            "host": host,
            "port": port,
            "tls": tls_mode_str(tls),
            "quota": quota,
            "scope_json": scope_json,
        }),
    )
    .await?;
    let ticket = encode_ticket(&verified.ns, &secret);
    Ok((ticket, ticket_hash, stream_id, quota))
}

async fn handle_ticket(
    req: &mut Request,
    url: &Url,
    env: &Env,
) -> std::result::Result<Response, NetFailure> {
    check_origin(req, url)?;
    let verified = verify_net_cred(req, env).await?;
    let body = read_bounded_body(req, MAX_TICKET_BODY_BYTES).await?;
    let ask: TicketRequest = serde_json::from_slice(&body).map_err(|e| {
        NetFailure::new(
            Errno::EINVAL,
            NetErrorKind::InvalidArgument,
            format!("invalid ticket request: {e}"),
        )
    })?;
    let allowlist = load_loopback_allowlist(env)?;
    let (ticket, _hash, stream_id, quota) = reserve_ticket_for_cred(
        env,
        &verified,
        &ask.host,
        ask.port,
        ask.tls,
        ask.timeout_ms,
        &allowlist,
    )
    .await?;
    Response::from_json(&TicketReply {
        ticket,
        stream_id,
        quota,
    })
    .map_err(io_fail)
}

async fn handle_connect(
    req: &Request,
    url: &Url,
    env: &Env,
    ctx: &Context,
) -> std::result::Result<Response, NetFailure> {
    if !header(req, "Upgrade")?.is_some_and(|u| u.eq_ignore_ascii_case("websocket")) {
        let mut resp = Response::from_json(&json!({
            "errno": Errno::EINVAL,
            "error": NetErrorKind::InvalidArgument,
            "message": "WebSocket upgrade required",
        }))
        .map_err(io_fail)?
        .with_status(426);
        resp.headers_mut()
            .set("X-OS-Errno", "EINVAL")
            .map_err(io_fail)?;
        return Ok(resp);
    }
    check_origin(req, url)?;
    let allowlist = load_loopback_allowlist(env)?;

    let query_param = |k: &str| {
        url.query_pairs()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.into_owned())
            .filter(|s| !s.is_empty())
    };

    let ticket_row: NetTicketRow = if let Some(raw_ticket) = query_param("ticket") {
        let (ns, secret) = decode_ticket(&raw_ticket)?;
        if ns.starts_with("session.") {
            // Browser `session.*` tickets MUST present the owning `os_session` cookie.
            if !auth::token_key(req).is_some_and(|sess_key| ns == format!("session.{sess_key}")) {
                return Err(NetFailure::new(
                    Errno::EACCES,
                    NetErrorKind::PolicyDenied,
                    "session stream ticket requires matching browser session cookie",
                ));
            }
        } else if ns.starts_with("node.") {
            // Non-browser `node.*` tickets must never be upgraded with browser cookies.
            if auth::token_key(req).is_some() || auth::guest_key(req).is_some() {
                return Err(NetFailure::new(
                    Errno::EACCES,
                    NetErrorKind::PolicyDenied,
                    "node stream ticket cannot be used with browser cookies",
                ));
            }
        }
        let ticket_hash = auth::token_hash(&secret);
        let val = machine_net_rpc(
            env,
            &ns,
            "/internal/net/consume-ticket",
            json!({ "ns": ns, "ticket_hash": ticket_hash }),
        )
        .await?;
        serde_json::from_value(val).map_err(|_| {
            NetFailure::new(
                Errno::EIO,
                NetErrorKind::HostUnavailable,
                "invalid consumed ticket row",
            )
        })?
    } else if header(req, "X-Process-Token")?.is_some_and(|t| !t.is_empty()) {
        let verified = verify_net_cred(req, env).await?;
        let host = query_param("host").ok_or_else(|| {
            NetFailure::new(
                Errno::EINVAL,
                NetErrorKind::InvalidArgument,
                "missing host query parameter",
            )
        })?;
        let port: u16 = query_param("port")
            .and_then(|p| p.parse::<u16>().ok())
            .filter(|&p| p > 0)
            .ok_or_else(|| {
                NetFailure::new(
                    Errno::EINVAL,
                    NetErrorKind::InvalidArgument,
                    "invalid port query parameter",
                )
            })?;
        let tls = parse_tls_mode(&query_param("tls").unwrap_or_default())?;
        let timeout_ms = query_param("timeout_ms").and_then(|t| t.parse::<u64>().ok());
        let (_ticket, ticket_hash, _stream_id, _quota) =
            reserve_ticket_for_cred(env, &verified, &host, port, tls, timeout_ms, &allowlist)
                .await?;
        let val = machine_net_rpc(
            env,
            &verified.ns,
            "/internal/net/consume-ticket",
            json!({ "ns": verified.ns, "ticket_hash": ticket_hash }),
        )
        .await?;
        serde_json::from_value(val).map_err(|_| {
            NetFailure::new(
                Errno::EIO,
                NetErrorKind::HostUnavailable,
                "invalid consumed ticket row",
            )
        })?
    } else {
        return Err(NetFailure::new(
            Errno::EACCES,
            NetErrorKind::PolicyDenied,
            "stream ticket or ServiceAuth v2 credential required",
        ));
    };

    let pair = match WebSocketPair::new() {
        Ok(p) => p,
        Err(e) => {
            let _ = machine_net_rpc(
                env,
                &ticket_row.ns,
                "/internal/net/release",
                json!({ "ns": ticket_row.ns, "stream_id": ticket_row.stream_id }),
            )
            .await;
            return Err(io_fail(e));
        }
    };
    let client = pair.client;
    let server = pair.server;
    // Cloudflare `workerd` defaults WebSocket `binaryType` to `"blob"` under modern
    // compatibility dates; force `"arraybuffer"` so `worker::MessageEvent::bytes()`
    // reads the binary frame payload instead of coercing a `Blob` to an empty `Uint8Array`.
    let _ = Reflect::set(
        server.as_ref(),
        &JsValue::from_str("binaryType"),
        &JsValue::from_str("arraybuffer"),
    );
    if let Err(e) = server.accept() {
        let _ = machine_net_rpc(
            env,
            &ticket_row.ns,
            "/internal/net/release",
            json!({ "ns": ticket_row.ns, "stream_id": ticket_row.stream_id }),
        )
        .await;
        return Err(io_fail(e));
    }
    let resp = match Response::from_websocket(client) {
        Ok(r) => r,
        Err(e) => {
            let _ = server.close(Some(1011), Some("upgrade failed"));
            let _ = machine_net_rpc(
                env,
                &ticket_row.ns,
                "/internal/net/release",
                json!({ "ns": ticket_row.ns, "stream_id": ticket_row.stream_id }),
            )
            .await;
            return Err(io_fail(e));
        }
    };

    let env_owned = env.clone();
    ctx.wait_until(async move {
        run_gateway_stream(env_owned, server, ticket_row, allowlist).await;
    });

    Ok(resp)
}

fn send_ws_error_json(ws: &WebSocket, errno: Errno, kind: NetErrorKind, message: &str) {
    let payload = json!({
        "kind": "error",
        "errno": errno,
        "error": kind,
        "message": message,
    });
    let _ = ws.send(&payload);
}

fn send_ws_data_frame(ws: &WebSocket, frame: &DataFrame) -> bool {
    let Ok(bytes) = encode_ws_data_frame(frame) else {
        return false;
    };
    ws.send_with_bytes(&bytes).is_ok()
}

fn dial_cloudflare_socket(
    host: &str,
    port: u16,
    tls: TlsMode,
) -> std::result::Result<worker::worker_sys::Socket, String> {
    let addr = Object::new();
    let _ = Reflect::set(
        &addr,
        &JsValue::from_str("hostname"),
        &JsValue::from_str(host),
    );
    let _ = Reflect::set(
        &addr,
        &JsValue::from_str("port"),
        &JsValue::from_f64(f64::from(port)),
    );
    let opts = Object::new();
    let _ = Reflect::set(
        &opts,
        &JsValue::from_str("allowHalfOpen"),
        &JsValue::from_bool(true),
    );
    let _ = Reflect::set(
        &opts,
        &JsValue::from_str("secureTransport"),
        &JsValue::from_str(tls_mode_str(tls)),
    );
    worker::worker_sys::connect(addr.into(), opts.into()).map_err(|e| format!("{e:?}"))
}

fn js_error_to_errno(msg: &str) -> (Errno, NetErrorKind) {
    let lower = msg.to_ascii_lowercase();
    if lower.contains("refused") {
        (Errno::ECONNREFUSED, NetErrorKind::ConnectFailed)
    } else if lower.contains("timeout") || lower.contains("timed out") {
        (Errno::ETIMEDOUT, NetErrorKind::Timeout)
    } else if lower.contains("reset") {
        (Errno::ECONNRESET, NetErrorKind::StreamReset)
    } else if lower.contains("private") || lower.contains("forbidden") || lower.contains("denied") {
        (Errno::EACCES, NetErrorKind::PrivateAddressDenied)
    } else {
        (Errno::ECONNREFUSED, NetErrorKind::ConnectFailed)
    }
}

async fn run_gateway_stream(
    env: Env,
    ws: WebSocket,
    ticket: NetTicketRow,
    allowlist: LoopbackTestAllowlist,
) {
    let ns = ticket.ns.clone();
    let stream_id = ticket.stream_id.clone();

    let result = run_gateway_stream_inner(&env, &ws, &ticket, &allowlist).await;
    if let Err((errno, kind, msg, sent_opened, bytes_sent, bytes_received)) = result {
        if sent_opened {
            let _ = send_ws_data_frame(
                &ws,
                &DataFrame::Closed(StreamClosed {
                    errno: Some(errno),
                    error: Some(kind),
                    message: Some(msg),
                    bytes_sent,
                    bytes_received,
                }),
            );
        } else {
            send_ws_error_json(&ws, errno, kind, &msg);
        }
    }
    let _ = ws.close(Some(1000), Some("stream ended"));
    let _ = machine_net_rpc(
        &env,
        &ns,
        "/internal/net/release",
        json!({ "ns": ns, "stream_id": stream_id }),
    )
    .await;
}

type StreamErr = (Errno, NetErrorKind, String, bool, u64, u64);

async fn run_gateway_stream_inner(
    env: &Env,
    ws: &WebSocket,
    ticket: &NetTicketRow,
    allowlist: &LoopbackTestAllowlist,
) -> std::result::Result<(), StreamErr> {
    let tls = parse_tls_mode(&ticket.tls).map_err(|f| (f.errno, f.kind, f.message, false, 0, 0))?;
    if tls == TlsMode::StartTls {
        return Err((
            Errno::EOPNOTSUPP,
            NetErrorKind::Unsupported,
            "TlsMode::StartTls upgrade is not supported".to_string(),
            false,
            0,
            0,
        ));
    }
    let scope: NetScope = serde_json::from_str(&ticket.scope_json).map_err(|_| {
        (
            Errno::EACCES,
            NetErrorKind::PolicyDenied,
            "corrupt net scope".to_string(),
            false,
            0,
            0,
        )
    })?;
    let quota: NetQuota = serde_json::from_str(&ticket.quota_json)
        .ok()
        .and_then(|q: NetQuota| q.clamped().ok())
        .ok_or_else(|| {
            (
                Errno::EINVAL,
                NetErrorKind::InvalidArgument,
                "corrupt net quota".to_string(),
                false,
                0,
                0,
            )
        })?;
    let parsed_host = scope
        .check_egress(&ticket.host, ticket.port, tls, allowlist)
        .map_err(|f| (f.errno, f.kind, f.message, false, 0, 0))?;

    let mut events = ws.events().map_err(|e| {
        (
            Errno::EIO,
            NetErrorKind::HostUnavailable,
            e.to_string(),
            false,
            0,
            0,
        )
    })?;

    // 1. Dial TCP/TLS via `cloudflare:sockets`.
    let socket = dial_cloudflare_socket(&ticket.host, ticket.port, tls).map_err(|msg| {
        let (errno, kind) = js_error_to_errno(&msg);
        (errno, kind, msg, false, 0, 0)
    })?;

    let opened_promise = socket.opened().map_err(|e| {
        let _ = socket.close();
        (
            Errno::ECONNREFUSED,
            NetErrorKind::ConnectFailed,
            format!("{e:?}"),
            false,
            0,
            0,
        )
    })?;

    // 2. Race `socket.opened()` against `connect_timeout_ms` AND client `CANCEL`/close!
    let mut opened_fut = Box::pin(JsFuture::from(opened_promise));
    let mut timeout_fut = Box::pin(Delay::from(Duration::from_millis(quota.connect_timeout_ms)));

    let socket_info: JsValue = loop {
        enum DialEv {
            Opened(std::result::Result<JsValue, JsValue>),
            Timeout,
            Ws(Option<Result<WebsocketEvent>>),
        }
        let ev = {
            let o = &mut opened_fut;
            let t = &mut timeout_fut;
            let w = events.next();
            futures_util::pin_mut!(w);
            futures_util::future::poll_fn(|cx| {
                use std::task::Poll;
                if let Poll::Ready(res) = o.as_mut().poll(cx) {
                    return Poll::Ready(DialEv::Opened(res));
                }
                if let Poll::Ready(()) = t.as_mut().poll(cx) {
                    return Poll::Ready(DialEv::Timeout);
                }
                if let Poll::Ready(ev) = w.as_mut().poll(cx) {
                    return Poll::Ready(DialEv::Ws(ev));
                }
                Poll::Pending
            })
            .await
        };
        match ev {
            DialEv::Opened(Ok(info)) => break info,
            DialEv::Opened(Err(e)) => {
                let _ = socket.close();
                let msg = format!("{e:?}");
                let (errno, kind) = js_error_to_errno(&msg);
                return Err((errno, kind, msg, false, 0, 0));
            }
            DialEv::Timeout => {
                let _ = socket.close();
                return Err((
                    Errno::ETIMEDOUT,
                    NetErrorKind::Timeout,
                    "connect timed out".to_string(),
                    false,
                    0,
                    0,
                ));
            }
            DialEv::Ws(Some(Ok(WebsocketEvent::Message(msg)))) => {
                if let Some(raw) = msg.bytes()
                    && matches!(decode_ws_data_frame(&raw), Ok(DataFrame::Cancel))
                {
                    let _ = socket.close();
                    return Err((
                        Errno::ECANCELED,
                        NetErrorKind::Canceled,
                        "connect canceled by client".to_string(),
                        false,
                        0,
                        0,
                    ));
                }
            }
            DialEv::Ws(Some(Ok(WebsocketEvent::Close(_))))
            | DialEv::Ws(Some(Err(_)))
            | DialEv::Ws(None) => {
                let _ = socket.close();
                return Err((
                    Errno::ECANCELED,
                    NetErrorKind::Canceled,
                    "client closed during connect".to_string(),
                    false,
                    0,
                    0,
                ));
            }
        }
    };

    // 3. Post-connect SSRF re-verification on `remoteAddress` (prevents DNS rebinding).
    // Note: when dialing a DNS hostname, Cloudflare `workerd` may echo the hostname in
    // `SocketInfo.remoteAddress` rather than the resolved IP; hostname DNS-rebinding defense
    // then relies on edge egress policy in addition to pre-dial SSRF hostname & scope checks.
    // Fail closed if `remoteAddress` contains a `%` zone ID or fails IP parsing when dialing an IP literal.
    let peer_addr = Reflect::get(&socket_info, &JsValue::from_str("remoteAddress"))
        .ok()
        .and_then(|v| v.as_string());
    if let Some(ref remote_str) = peer_addr {
        if remote_str.contains('%') {
            let _ = socket.close();
            return Err((
                Errno::EACCES,
                NetErrorKind::PrivateAddressDenied,
                "remoteAddress contains prohibited zone identifier".to_string(),
                false,
                0,
                0,
            ));
        }
        match extract_ip_from_socket_addr_str(remote_str) {
            Some(ip) => {
                if let Err(fail) =
                    scope.check_resolved_ip(&parsed_host, ip, ticket.port, tls, allowlist)
                {
                    let _ = socket.close();
                    return Err((fail.errno, fail.kind, fail.message, false, 0, 0));
                }
            }
            None if matches!(parsed_host, ParsedHost::Ip(_)) => {
                let _ = socket.close();
                return Err((
                    Errno::EACCES,
                    NetErrorKind::PrivateAddressDenied,
                    "unparseable remoteAddress for IP literal connection".to_string(),
                    false,
                    0,
                    0,
                ));
            }
            None => {}
        }
    }

    // 4. Emit `opened` text JSON handshake frame.
    let opened_msg = json!({
        "kind": "opened",
        "stream_id": ticket.stream_id,
        "peer_addr": peer_addr,
        "initial_window": NET_INITIAL_WINDOW_BYTES,
        "quota": quota,
    });
    if ws.send(&opened_msg).is_err() {
        let _ = socket.close();
        return Ok(());
    }

    // 5. Full-duplex credit-windowed pump between WebSocket and `cloudflare:sockets`.
    let readable = socket.readable().map_err(|e| {
        let _ = socket.close();
        (
            Errno::EIO,
            NetErrorKind::StreamReset,
            format!("socket readable: {e:?}"),
            true,
            0,
            0,
        )
    })?;
    let writable = socket.writable().map_err(|e| {
        let _ = socket.close();
        (
            Errno::EIO,
            NetErrorKind::StreamReset,
            format!("socket writable: {e:?}"),
            true,
            0,
            0,
        )
    })?;
    let reader: ReadableStreamDefaultReader = readable.get_reader().unchecked_into();
    let writer: WritableStreamDefaultWriter = writable.get_writer().map_err(|e| {
        let _ = reader.cancel();
        let _ = socket.close();
        (
            Errno::EIO,
            NetErrorKind::StreamReset,
            format!("socket writer: {e:?}"),
            true,
            0,
            0,
        )
    })?;

    let mut client_rx_credit = u64::from(NET_INITIAL_WINDOW_BYTES);
    let max_window = u64::from(NET_INITIAL_WINDOW_BYTES);
    let mut pending_rx: VecDeque<u8> = VecDeque::new();
    let mut pending_tx_chunks: VecDeque<Vec<u8>> = VecDeque::new();
    let mut pending_tx_bytes: usize = 0;
    let mut bytes_sent: u64 = 0;
    let mut bytes_received: u64 = 0;
    let mut unbilled_sent: u64 = 0;
    let mut unbilled_recv: u64 = 0;
    let mut remote_eof = false;
    let mut sent_remote_half_close = false;
    let mut client_half_closed = false;
    let mut client_write_closed = false;

    let started_ms = js_sys::Date::now();
    let mut last_activity_ms = started_ms;
    let mut last_charge_ms = started_ms;
    let mut pace_until_ms = started_ms;

    enum WriteOp {
        Data { len: u32, fut: Pin<Box<JsFuture>> },
        Close { fut: Pin<Box<JsFuture>> },
    }

    let mut in_flight_read: Option<Pin<Box<JsFuture>>> = None;
    let mut in_flight_write: Option<WriteOp> = None;

    let mut close_outcome: Option<StreamErr> = None;

    'pump: loop {
        // Flush any buffered RX bytes permitted by `client_rx_credit`.
        while !pending_rx.is_empty() && client_rx_credit > 0 {
            let take = pending_rx
                .len()
                .min(NET_DATA_CHUNK_MAX)
                .min(client_rx_credit as usize);
            let chunk: Vec<u8> = pending_rx.drain(..take).collect();
            client_rx_credit = client_rx_credit.saturating_sub(take as u64);
            if !send_ws_data_frame(ws, &DataFrame::Data(chunk)) {
                break 'pump;
            }
        }

        if remote_eof && pending_rx.is_empty() && !sent_remote_half_close {
            sent_remote_half_close = true;
            let _ = send_ws_data_frame(ws, &DataFrame::HalfClose);
        }
        if sent_remote_half_close && client_write_closed {
            let _ = send_ws_data_frame(
                ws,
                &DataFrame::Closed(StreamClosed {
                    errno: None,
                    error: None,
                    message: None,
                    bytes_sent,
                    bytes_received,
                }),
            );
            break;
        }

        let now_ms = js_sys::Date::now();
        if now_ms - started_ms >= quota.max_stream_lifetime_ms as f64 {
            close_outcome = Some((
                Errno::ETIMEDOUT,
                NetErrorKind::Timeout,
                "max stream lifetime exceeded".to_string(),
                true,
                bytes_sent,
                bytes_received,
            ));
            break;
        }
        if now_ms - last_activity_ms >= quota.idle_timeout_ms as f64 {
            close_outcome = Some((
                Errno::ETIMEDOUT,
                NetErrorKind::Timeout,
                "stream idle timeout".to_string(),
                true,
                bytes_sent,
                bytes_received,
            ));
            break;
        }

        // Batched server-side quota + revocation check against `Machine` DO.
        let unbilled_total = unbilled_sent.saturating_add(unbilled_recv);
        let due_for_charge = unbilled_total >= CHARGE_BATCH_BYTES
            || (unbilled_total > 0 && now_ms - last_charge_ms >= CHARGE_BATCH_INTERVAL_MS)
            || (now_ms - last_charge_ms >= REVOCATION_POLL_INTERVAL_MS);
        if due_for_charge {
            let s_delta = unbilled_sent;
            let r_delta = unbilled_recv;
            unbilled_sent = 0;
            unbilled_recv = 0;
            last_charge_ms = now_ms;
            match machine_net_rpc(
                env,
                &ticket.ns,
                "/internal/net/charge",
                json!({
                    "ns": ticket.ns,
                    "stream_id": ticket.stream_id,
                    "token_hash": ticket.token_hash,
                    "sent_delta": s_delta,
                    "recv_delta": r_delta,
                }),
            )
            .await
            {
                Ok(val) => {
                    let delay = val["delay_ms"].as_u64().unwrap_or(0);
                    if delay > 0 {
                        let now2 = js_sys::Date::now();
                        pace_until_ms = pace_until_ms.max(now2 + (delay.min(5_000) as f64));
                    }
                }
                Err(fail) => {
                    close_outcome = Some((
                        fail.errno,
                        fail.kind,
                        fail.message,
                        true,
                        bytes_sent,
                        bytes_received,
                    ));
                    break;
                }
            }
        }

        let now_ms = js_sys::Date::now();
        let throttled = pace_until_ms > now_ms + 2.0;

        // Kick off at most one concurrent upstream write or half-close (`writer.close()`).
        if in_flight_write.is_none() && !throttled {
            if let Some(chunk) = pending_tx_chunks.pop_front() {
                let len = chunk.len() as u32;
                pending_tx_bytes = pending_tx_bytes.saturating_sub(chunk.len());
                let js_arr = Uint8Array::from(chunk.as_slice());
                let fut = Box::pin(JsFuture::from(writer.write_with_chunk(&js_arr.into())));
                in_flight_write = Some(WriteOp::Data { len, fut });
            } else if client_half_closed && !client_write_closed {
                let fut = Box::pin(JsFuture::from(writer.close()));
                in_flight_write = Some(WriteOp::Close { fut });
            }
        }

        // Only pull from `ReadableStream` when buffer is empty, unthrottled, AND client has RX credit.
        if in_flight_read.is_none()
            && !throttled
            && !remote_eof
            && pending_rx.is_empty()
            && client_rx_credit > 0
        {
            in_flight_read = Some(Box::pin(JsFuture::from(reader.read())));
        }

        let idle_rem = (quota.idle_timeout_ms as f64 - (now_ms - last_activity_ms)).max(10.0);
        let life_rem = (quota.max_stream_lifetime_ms as f64 - (now_ms - started_ms)).max(10.0);
        let charge_rem = if unbilled_sent + unbilled_recv > 0 {
            (CHARGE_BATCH_INTERVAL_MS - (now_ms - last_charge_ms)).max(10.0)
        } else {
            (REVOCATION_POLL_INTERVAL_MS - (now_ms - last_charge_ms)).max(10.0)
        };
        let pace_rem = if throttled {
            (pace_until_ms - now_ms).clamp(10.0, 5_000.0)
        } else {
            2_000.0
        };
        let wake_ms = idle_rem
            .min(life_rem)
            .min(charge_rem)
            .min(pace_rem)
            .min(2_000.0) as u64;
        let mut timer_fut = Box::pin(Delay::from(Duration::from_millis(wake_ms.max(10))));

        enum LoopEv {
            SocketRead(std::result::Result<JsValue, JsValue>),
            WriteDataDone(u32, std::result::Result<JsValue, JsValue>),
            WriteCloseDone(std::result::Result<JsValue, JsValue>),
            Ws(Option<Result<WebsocketEvent>>),
            Tick,
        }

        let ev = {
            let r_opt = &mut in_flight_read;
            let w_opt = &mut in_flight_write;
            let t = &mut timer_fut;
            let ws_next = events.next();
            futures_util::pin_mut!(ws_next);
            futures_util::future::poll_fn(|cx| {
                use std::task::Poll;
                if let Poll::Ready(ev) = ws_next.as_mut().poll(cx) {
                    return Poll::Ready(LoopEv::Ws(ev));
                }
                if let Some(wop) = w_opt.as_mut() {
                    match wop {
                        WriteOp::Data { len, fut } => {
                            if let Poll::Ready(res) = fut.as_mut().poll(cx) {
                                return Poll::Ready(LoopEv::WriteDataDone(*len, res));
                            }
                        }
                        WriteOp::Close { fut } => {
                            if let Poll::Ready(res) = fut.as_mut().poll(cx) {
                                return Poll::Ready(LoopEv::WriteCloseDone(res));
                            }
                        }
                    }
                }
                if let Some(rf) = r_opt.as_mut()
                    && let Poll::Ready(res) = rf.as_mut().poll(cx)
                {
                    return Poll::Ready(LoopEv::SocketRead(res));
                }
                if let Poll::Ready(()) = t.as_mut().poll(cx) {
                    return Poll::Ready(LoopEv::Tick);
                }
                Poll::Pending
            })
            .await
        };

        match ev {
            LoopEv::Tick => continue,
            LoopEv::WriteDataDone(len, res) => {
                in_flight_write = None;
                match res {
                    Ok(_) => {
                        last_activity_ms = js_sys::Date::now();
                        let _ = send_ws_data_frame(ws, &DataFrame::Credit(len));
                    }
                    Err(e) => {
                        close_outcome = Some((
                            Errno::EPIPE,
                            NetErrorKind::StreamReset,
                            format!("remote write error: {e:?}"),
                            true,
                            bytes_sent,
                            bytes_received,
                        ));
                        break;
                    }
                }
            }
            LoopEv::WriteCloseDone(_res) => {
                in_flight_write = None;
                client_write_closed = true;
                last_activity_ms = js_sys::Date::now();
            }
            LoopEv::SocketRead(res) => {
                in_flight_read = None;
                match res {
                    Ok(chunk_obj) => {
                        let done = Reflect::get(&chunk_obj, &JsValue::from_str("done"))
                            .ok()
                            .and_then(|v| v.as_bool())
                            .unwrap_or(true);
                        if done {
                            remote_eof = true;
                        } else if let Ok(val) =
                            Reflect::get(&chunk_obj, &JsValue::from_str("value"))
                        {
                            let arr = Uint8Array::new(&val);
                            let mut buf = vec![0u8; arr.length() as usize];
                            arr.copy_to(&mut buf);
                            if !buf.is_empty() {
                                let len = buf.len() as u64;
                                bytes_received = bytes_received.saturating_add(len);
                                unbilled_recv = unbilled_recv.saturating_add(len);
                                last_activity_ms = js_sys::Date::now();
                                if bytes_sent.saturating_add(bytes_received)
                                    > quota.max_bytes_per_stream
                                {
                                    close_outcome = Some((
                                        Errno::EDQUOT,
                                        NetErrorKind::QuotaExceeded,
                                        "max_bytes_per_stream exceeded".to_string(),
                                        true,
                                        bytes_sent,
                                        bytes_received,
                                    ));
                                    break;
                                }
                                if let Some(bps) = quota.max_bytes_per_sec
                                    && bps > 0
                                {
                                    let dur_ms = (len as f64) * 1000.0 / (bps as f64);
                                    let now = js_sys::Date::now();
                                    pace_until_ms = pace_until_ms.max(now) + dur_ms;
                                }
                                pending_rx.extend(buf);
                            }
                        }
                    }
                    Err(e) => {
                        close_outcome = Some((
                            Errno::ECONNRESET,
                            NetErrorKind::StreamReset,
                            format!("remote read error: {e:?}"),
                            true,
                            bytes_sent,
                            bytes_received,
                        ));
                        break;
                    }
                }
            }
            LoopEv::Ws(Some(Ok(WebsocketEvent::Message(msg)))) => {
                let Some(raw) = msg.bytes() else {
                    continue;
                };
                match decode_ws_data_frame(&raw) {
                    Ok(DataFrame::Data(chunk)) => {
                        if client_half_closed {
                            close_outcome = Some((
                                Errno::EPIPE,
                                NetErrorKind::ProtocolError,
                                "DATA received after HALF_CLOSE".to_string(),
                                true,
                                bytes_sent,
                                bytes_received,
                            ));
                            break;
                        }
                        let len = chunk.len() as u64;
                        if len == 0 {
                            continue;
                        }
                        if pending_tx_bytes.saturating_add(chunk.len())
                            > (NET_INITIAL_WINDOW_BYTES as usize) * 2
                        {
                            close_outcome = Some((
                                Errno::EMSGSIZE,
                                NetErrorKind::ProtocolError,
                                "TX flow-control window exceeded".to_string(),
                                true,
                                bytes_sent,
                                bytes_received,
                            ));
                            break;
                        }
                        bytes_sent = bytes_sent.saturating_add(len);
                        unbilled_sent = unbilled_sent.saturating_add(len);
                        last_activity_ms = js_sys::Date::now();
                        if bytes_sent.saturating_add(bytes_received) > quota.max_bytes_per_stream {
                            close_outcome = Some((
                                Errno::EDQUOT,
                                NetErrorKind::QuotaExceeded,
                                "max_bytes_per_stream exceeded".to_string(),
                                true,
                                bytes_sent,
                                bytes_received,
                            ));
                            break;
                        }
                        if let Some(bps) = quota.max_bytes_per_sec
                            && bps > 0
                        {
                            let dur_ms = (len as f64) * 1000.0 / (bps as f64);
                            let now = js_sys::Date::now();
                            pace_until_ms = pace_until_ms.max(now) + dur_ms;
                        }
                        pending_tx_bytes += chunk.len();
                        pending_tx_chunks.push_back(chunk);
                    }
                    Ok(DataFrame::Credit(n)) => {
                        client_rx_credit = client_rx_credit
                            .saturating_add(u64::from(n))
                            .min(max_window);
                        last_activity_ms = js_sys::Date::now();
                    }
                    Ok(DataFrame::HalfClose) => {
                        if !client_half_closed {
                            client_half_closed = true;
                            last_activity_ms = js_sys::Date::now();
                        }
                    }
                    Ok(DataFrame::Cancel) => {
                        close_outcome = Some((
                            Errno::ECANCELED,
                            NetErrorKind::Canceled,
                            "canceled by client".to_string(),
                            true,
                            bytes_sent,
                            bytes_received,
                        ));
                        break;
                    }
                    Ok(DataFrame::Closed(_)) => break,
                    Err(e) => {
                        close_outcome = Some((
                            e.errno,
                            NetErrorKind::ProtocolError,
                            e.to_string(),
                            true,
                            bytes_sent,
                            bytes_received,
                        ));
                        break;
                    }
                }
            }
            LoopEv::Ws(Some(Ok(WebsocketEvent::Close(_))))
            | LoopEv::Ws(Some(Err(_)))
            | LoopEv::Ws(None) => {
                break;
            }
        }
    }

    // Flush any remaining unbilled TX/RX bytes to `Machine` DO before stream release so short
    // `< 32 KiB` streams cannot bypass server-side `io.max` accounting.
    if unbilled_sent > 0 || unbilled_recv > 0 {
        let _ = machine_net_rpc(
            env,
            &ticket.ns,
            "/internal/net/charge",
            json!({
                "ns": ticket.ns,
                "stream_id": ticket.stream_id,
                "token_hash": ticket.token_hash,
                "sent_delta": unbilled_sent,
                "recv_delta": unbilled_recv,
            }),
        )
        .await;
    }

    // Deterministic socket teardown regardless of exit path.
    let _ = reader.cancel();
    if !client_write_closed {
        let _ = writer.abort();
    }
    let _ = socket.close();

    if let Some(err) = close_outcome {
        Err(err)
    } else {
        Ok(())
    }
}
