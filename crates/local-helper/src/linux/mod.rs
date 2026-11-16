//! Linux local helper (`os-local-helper`): HTTP loopback server + confined host VFS engine.

pub mod fs;
pub mod locks;
pub mod store;
pub mod sys;
#[cfg(test)]
mod tests;

use abi::Errno;
use abi::local_helper::{CONTROL_MAX, Request};
use fs::HelperEngine;
use serde_json::{Value, json};
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

const MAX_INFLIGHT_HTTP: usize = 32;
const HEADER_MAX: usize = 64 * 1024;
const BODY_READ_DEADLINE: Duration = Duration::from_secs(10);
const ENGINE_SWEEP_INTERVAL: Duration = Duration::from_secs(1);

pub struct Config {
    pub root: PathBuf,
    pub origin: String,
    pub port: u16,
    pub write: bool,
    pub execute: bool,
    pub state_dir: PathBuf,
}

fn parse_args(args: &[String]) -> Result<Config, String> {
    let mut root: Option<PathBuf> = None;
    let mut origin: Option<String> = None;
    let mut port: u16 = 0;
    let mut write = false;
    let mut execute = false;
    let mut state_dir: Option<PathBuf> = None;

    let mut iter = args.iter().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--root" => {
                root = Some(PathBuf::from(
                    iter.next()
                        .ok_or_else(|| "missing --root path".to_owned())?,
                ));
            }
            "--origin" => {
                origin = Some(
                    iter.next()
                        .ok_or_else(|| "missing --origin value".to_owned())?
                        .clone(),
                );
            }
            "--port" => {
                let raw = iter
                    .next()
                    .ok_or_else(|| "missing --port value".to_owned())?;
                port = raw
                    .parse::<u16>()
                    .map_err(|_| format!("invalid --port value: {raw}"))?;
            }
            "--state-dir" => {
                state_dir = Some(PathBuf::from(
                    iter.next()
                        .ok_or_else(|| "missing --state-dir path".to_owned())?,
                ));
            }
            "--write" => write = true,
            "--execute" => execute = true,
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    let raw_root = root.ok_or_else(|| {
        "usage: os-local-helper --root DIR --origin ORIGIN [--port PORT] [--state-dir DIR] [--write] [--execute]".to_owned()
    })?;
    let origin = origin.ok_or_else(|| "missing --origin".to_owned())?;
    let canonical_root = std::fs::canonicalize(&raw_root).map_err(|e| {
        format!(
            "failed to canonicalize --root '{}': {e}",
            raw_root.display()
        )
    })?;
    let state_dir = match state_dir {
        Some(dir) => dir,
        None => store::default_state_dir()?,
    };
    let validated_state = store::validate_state_dir_outside_root(&canonical_root, &state_dir)?;

    Ok(Config {
        root: canonical_root,
        origin,
        port,
        write,
        execute,
        state_dir: validated_state,
    })
}

pub fn open_root_dir(path: &Path) -> Result<OwnedFd, String> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| format!("failed to open root '{}': {e}", path.display()))?;
    let fd: OwnedFd = file.into();
    sys::check_openat2(std::os::fd::AsFd::as_fd(&fd))?;
    Ok(fd)
}

pub fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    let cfg = parse_args(&args)?;
    let root_fd = open_root_dir(&cfg.root)?;
    let mut engine = HelperEngine::open(&cfg.root, &cfg.state_dir, root_fd, cfg.write, cfg.execute)
        .map_err(|e| format!("failed to initialize helper store: {} ({e:?})", e.text()))?;

    let token = Arc::new(sys::hex_encode(
        &sys::random_bytes::<32>()
            .map_err(|e| format!("failed to mint helper token: {}", e.text()))?,
    ));
    let allowed_origin = Arc::new(cfg.origin.clone());
    let addr = format!("127.0.0.1:{}", cfg.port);
    let listener = TcpListener::bind(&addr).map_err(|e| format!("failed to bind {addr}: {e}"))?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| format!("failed to inspect listener address: {e}"))?;

    println!(
        "{}",
        json!({
            "url": format!("http://{local_addr}"),
            "token": token.as_str(),
            "root": cfg.root,
            "write": cfg.write,
            "execute": cfg.execute,
            "fs": engine.fs_id().0,
        })
    );

    let (tx, rx) = mpsc::sync_channel::<(Request, mpsc::SyncSender<Result<Value, Errno>>)>(64);
    std::thread::Builder::new()
        .name("os-local-helper-engine".into())
        .spawn(move || {
            let mut last_sweep = Instant::now();
            loop {
                match rx.recv_timeout(ENGINE_SWEEP_INTERVAL) {
                    Ok((parsed, reply)) => {
                        let res = engine.handle_request(parsed);
                        let _ = reply.send(res);
                        if last_sweep.elapsed() >= ENGINE_SWEEP_INTERVAL {
                            engine.sweep_expired();
                            engine.flush_if_dirty();
                            last_sweep = Instant::now();
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        engine.sweep_expired();
                        engine.flush_if_dirty();
                        last_sweep = Instant::now();
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        })
        .map_err(|e| format!("failed to spawn helper engine thread: {e}"))?;

    let inflight = Arc::new(AtomicUsize::new(0));
    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                dispatch_http(stream, &allowed_origin, &token, &tx, &inflight);
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(format!("helper server receive error: {err}")),
        }
    }
    Ok(())
}

struct InflightGuard(Arc<AtomicUsize>);

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

fn try_acquire_worker(inflight: &Arc<AtomicUsize>) -> Option<InflightGuard> {
    let mut cur = inflight.load(Ordering::Relaxed);
    loop {
        if cur >= MAX_INFLIGHT_HTTP {
            return None;
        }
        match inflight.compare_exchange_weak(cur, cur + 1, Ordering::Acquire, Ordering::Relaxed) {
            Ok(_) => return Some(InflightGuard(Arc::clone(inflight))),
            Err(actual) => cur = actual,
        }
    }
}

fn dispatch_http(
    mut stream: TcpStream,
    allowed_origin: &Arc<String>,
    master_token: &Arc<String>,
    tx: &mpsc::SyncSender<(Request, mpsc::SyncSender<Result<Value, Errno>>)>,
    inflight: &Arc<AtomicUsize>,
) {
    let Some(guard) = try_acquire_worker(inflight) else {
        let _ = stream.set_write_timeout(Some(Duration::from_millis(20)));
        let _ = write_err_response(
            &mut stream,
            503,
            allowed_origin,
            Errno::EBUSY,
            "helper busy",
        );
        return;
    };

    let allowed_origin = Arc::clone(allowed_origin);
    let master_token = Arc::clone(master_token);
    let tx = tx.clone();
    let _ = std::thread::Builder::new()
        .name("os-local-helper-http".into())
        .spawn(move || {
            let _guard = guard;
            serve_http_connection(
                stream,
                &allowed_origin,
                &master_token,
                &tx,
                BODY_READ_DEADLINE,
            );
        });
}

enum ReadUntilError {
    Eof,
    TimedOut,
    TooBig,
    Io,
}

fn read_with_deadline(
    stream: &mut TcpStream,
    buf: &mut [u8],
    start: Instant,
    deadline: Duration,
) -> Result<usize, ReadUntilError> {
    loop {
        let Some(remaining) = deadline.checked_sub(start.elapsed()) else {
            return Err(ReadUntilError::TimedOut);
        };
        let _ = stream.set_read_timeout(Some(remaining.max(Duration::from_millis(1))));
        match stream.read(buf) {
            Ok(0) => return Err(ReadUntilError::Eof),
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                if start.elapsed() >= deadline {
                    return Err(ReadUntilError::TimedOut);
                }
            }
            Err(_) => return Err(ReadUntilError::Io),
        }
    }
}

struct ParsedHeaders {
    method: String,
    origin: Option<String>,
    authorization: Option<String>,
    content_length: Option<usize>,
    chunked: bool,
    expect_continue: bool,
}

fn parse_http_head(raw: &[u8]) -> Result<ParsedHeaders, (u16, Errno, &'static str)> {
    let text =
        std::str::from_utf8(raw).map_err(|_| (400, Errno::EINVAL, "invalid HTTP headers"))?;
    let mut lines = text.split("\r\n");
    let req_line = lines
        .next()
        .ok_or((400, Errno::EINVAL, "missing request line"))?;
    let mut parts = req_line.split_whitespace();
    let method = parts
        .next()
        .ok_or((400, Errno::EINVAL, "missing HTTP method"))?
        .to_owned();
    let _target = parts
        .next()
        .ok_or((400, Errno::EINVAL, "missing HTTP target"))?;
    let version = parts
        .next()
        .ok_or((400, Errno::EINVAL, "missing HTTP version"))?;
    if !version.starts_with("HTTP/1.") || parts.next().is_some() {
        return Err((400, Errno::EINVAL, "unsupported HTTP version"));
    }

    let mut origin = None;
    let mut authorization = None;
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    let mut expect_continue = false;

    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, val)) = line.split_once(':') else {
            return Err((400, Errno::EINVAL, "malformed HTTP header"));
        };
        let val = val.trim();
        if name.eq_ignore_ascii_case("origin") {
            origin = Some(val.to_owned());
        } else if name.eq_ignore_ascii_case("authorization") {
            authorization = Some(val.to_owned());
        } else if name.eq_ignore_ascii_case("content-length") {
            let len = val
                .parse::<usize>()
                .map_err(|_| (400, Errno::EINVAL, "invalid Content-Length"))?;
            if let Some(prev) = content_length
                && prev != len
            {
                return Err((400, Errno::EINVAL, "conflicting Content-Length"));
            }
            content_length = Some(len);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if val.eq_ignore_ascii_case("chunked") {
                chunked = true;
            } else {
                return Err((400, Errno::EINVAL, "unsupported Transfer-Encoding"));
            }
        } else if name.eq_ignore_ascii_case("expect") && val.eq_ignore_ascii_case("100-continue") {
            expect_continue = true;
        }
    }

    if chunked && content_length.is_some() {
        return Err((
            400,
            Errno::EINVAL,
            "conflicting Transfer-Encoding and Content-Length",
        ));
    }

    Ok(ParsedHeaders {
        method,
        origin,
        authorization,
        content_length,
        chunked,
        expect_continue,
    })
}

fn read_chunk_line(
    stream: &mut TcpStream,
    buf: &mut Vec<u8>,
    pos: &mut usize,
    start: Instant,
    deadline: Duration,
) -> Result<String, ReadUntilError> {
    let mut scratch = [0u8; 8192];
    loop {
        if let Some(rel) = buf[*pos..].windows(2).position(|w| w == b"\r\n") {
            let line = std::str::from_utf8(&buf[*pos..*pos + rel])
                .map_err(|_| ReadUntilError::Io)?
                .to_owned();
            *pos += rel + 2;
            return Ok(line);
        }
        if buf.len() - *pos > 4096 {
            return Err(ReadUntilError::Io);
        }
        let n = read_with_deadline(stream, &mut scratch, start, deadline)?;
        buf.extend_from_slice(&scratch[..n]);
    }
}

fn read_chunked_body(
    stream: &mut TcpStream,
    mut buf: Vec<u8>,
    start: Instant,
    deadline: Duration,
) -> Result<Vec<u8>, ReadUntilError> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    let mut scratch = [0u8; 8192];

    loop {
        let line = read_chunk_line(stream, &mut buf, &mut pos, start, deadline)?;
        let size_hex = line.split(';').next().unwrap_or("").trim();
        let chunk_len = usize::from_str_radix(size_hex, 16).map_err(|_| ReadUntilError::Io)?;
        if chunk_len == 0 {
            break;
        }
        if out.len().saturating_add(chunk_len) > CONTROL_MAX {
            return Err(ReadUntilError::TooBig);
        }
        let need = chunk_len + 2;
        while buf.len() - pos < need {
            let n = read_with_deadline(stream, &mut scratch, start, deadline)?;
            buf.extend_from_slice(&scratch[..n]);
            if buf.len() - pos > CONTROL_MAX + 8 {
                return Err(ReadUntilError::TooBig);
            }
        }
        out.extend_from_slice(&buf[pos..pos + chunk_len]);
        if &buf[pos + chunk_len..pos + chunk_len + 2] != b"\r\n" {
            return Err(ReadUntilError::Io);
        }
        pos += need;
        if pos > 65536 {
            buf.drain(..pos);
            pos = 0;
        }
    }
    Ok(out)
}

pub(crate) fn serve_http_connection(
    mut stream: TcpStream,
    allowed_origin: &str,
    master_token: &str,
    tx: &mpsc::SyncSender<(Request, mpsc::SyncSender<Result<Value, Errno>>)>,
    deadline: Duration,
) {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_write_timeout(Some(deadline));
    let start = Instant::now();

    let mut head_buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    let head_end = loop {
        if let Some(pos) = head_buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        if head_buf.len() >= HEADER_MAX {
            let _ = write_err_response(
                &mut stream,
                400,
                allowed_origin,
                Errno::EINVAL,
                "request headers exceed maximum",
            );
            return;
        }
        match read_with_deadline(&mut stream, &mut tmp, start, deadline) {
            Ok(n) => head_buf.extend_from_slice(&tmp[..n]),
            Err(ReadUntilError::Eof) => return,
            Err(ReadUntilError::TimedOut) => {
                let _ = write_err_response(
                    &mut stream,
                    408,
                    allowed_origin,
                    Errno::ETIMEDOUT,
                    "request header read timed out",
                );
                return;
            }
            Err(_) => {
                let _ = write_err_response(
                    &mut stream,
                    400,
                    allowed_origin,
                    Errno::EIO,
                    "failed reading request headers",
                );
                return;
            }
        }
    };

    let leftover = head_buf.split_off(head_end + 4);
    head_buf.truncate(head_end);

    let headers = match parse_http_head(&head_buf) {
        Ok(h) => h,
        Err((status, errno, msg)) => {
            let _ = write_err_response(&mut stream, status, allowed_origin, errno, msg);
            return;
        }
    };

    if headers.origin.as_deref() != Some(allowed_origin) {
        let _ = write_err_response(
            &mut stream,
            403,
            allowed_origin,
            Errno::EACCES,
            "origin mismatch",
        );
        return;
    }

    if headers.method == "OPTIONS" {
        let _ = write_http_response(&mut stream, 204, allowed_origin, None);
        return;
    }

    if headers.method != "POST" {
        let _ = write_err_response(
            &mut stream,
            405,
            allowed_origin,
            Errno::EINVAL,
            "POST required",
        );
        return;
    }

    let provided = headers
        .authorization
        .as_deref()
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    if !sys::constant_time_eq(provided.as_bytes(), master_token.as_bytes()) {
        let _ = write_err_response(
            &mut stream,
            401,
            allowed_origin,
            Errno::EACCES,
            "unauthorized",
        );
        return;
    }

    if let Some(len) = headers.content_length
        && len > CONTROL_MAX
    {
        let _ = write_err_response(
            &mut stream,
            413,
            allowed_origin,
            Errno::E2BIG,
            "request body exceeds maximum",
        );
        return;
    }

    if headers.expect_continue {
        let _ = stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
        let _ = stream.flush();
    }

    let raw = if headers.chunked {
        match read_chunked_body(&mut stream, leftover, start, deadline) {
            Ok(body) => body,
            Err(ReadUntilError::TimedOut) => {
                let _ = write_err_response(
                    &mut stream,
                    408,
                    allowed_origin,
                    Errno::ETIMEDOUT,
                    "request body read timed out",
                );
                return;
            }
            Err(ReadUntilError::TooBig) => {
                let _ = write_err_response(
                    &mut stream,
                    413,
                    allowed_origin,
                    Errno::E2BIG,
                    "request body exceeds maximum",
                );
                return;
            }
            Err(_) => {
                let _ = write_err_response(
                    &mut stream,
                    400,
                    allowed_origin,
                    Errno::EIO,
                    "failed reading body",
                );
                return;
            }
        }
    } else {
        let expected = headers.content_length.unwrap_or(0);
        let mut body = Vec::with_capacity(expected.min(65536));
        let take = expected.min(leftover.len());
        body.extend_from_slice(&leftover[..take]);
        let mut buf = [0u8; 8192];
        while body.len() < expected {
            let need = (expected - body.len()).min(buf.len());
            match read_with_deadline(&mut stream, &mut buf[..need], start, deadline) {
                Ok(n) => body.extend_from_slice(&buf[..n]),
                Err(ReadUntilError::TimedOut) => {
                    let _ = write_err_response(
                        &mut stream,
                        408,
                        allowed_origin,
                        Errno::ETIMEDOUT,
                        "request body read timed out",
                    );
                    return;
                }
                Err(_) => {
                    let _ = write_err_response(
                        &mut stream,
                        400,
                        allowed_origin,
                        Errno::EIO,
                        "failed reading body",
                    );
                    return;
                }
            }
        }
        body
    };

    let parsed: Request = match serde_json::from_slice(&raw) {
        Ok(r) => r,
        Err(_) => {
            // Distinguish legacy/unknown protocol frames (`{"op": ...}`, unknown versioned envelopes)
            // from syntactically invalid JSON so callers fail with EPROTONOSUPPORT cleanly.
            let status_errno = match serde_json::from_slice::<Value>(&raw) {
                Ok(val) if val.is_object() => {
                    (Errno::EPROTONOSUPPORT, "unsupported local-helper protocol")
                }
                _ => (Errno::EINVAL, "invalid JSON request"),
            };
            let _ = write_err_response(
                &mut stream,
                400,
                allowed_origin,
                status_errno.0,
                status_errno.1,
            );
            return;
        }
    };

    let (reply_tx, reply_rx) = mpsc::sync_channel(1);
    if tx.send((parsed, reply_tx)).is_err() {
        let _ = write_err_response(
            &mut stream,
            503,
            allowed_origin,
            Errno::ENODEV,
            "helper engine unavailable",
        );
        return;
    }
    match reply_rx.recv() {
        Ok(Ok(value)) => {
            let _ = write_json_response(&mut stream, 200, allowed_origin, value);
        }
        Ok(Err(errno)) => {
            let _ = write_err_response(&mut stream, 400, allowed_origin, errno, errno.text());
        }
        Err(_) => {
            let _ = write_err_response(
                &mut stream,
                503,
                allowed_origin,
                Errno::ENODEV,
                "helper engine disconnected",
            );
        }
    }
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Payload Too Large",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

fn write_http_response(
    stream: &mut TcpStream,
    status: u16,
    origin: &str,
    json_body: Option<&[u8]>,
) -> io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {status} {}\r\n\
         Access-Control-Allow-Origin: {origin}\r\n\
         Access-Control-Allow-Methods: POST, OPTIONS\r\n\
         Access-Control-Allow-Headers: Content-Type, Authorization\r\n\
         Access-Control-Allow-Private-Network: true\r\n\
         Vary: Origin\r\n\
         Connection: close\r\n",
        reason_phrase(status),
    );
    if let Some(body) = json_body {
        head.push_str(&format!(
            "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        ));
        stream.write_all(head.as_bytes())?;
        stream.write_all(body)?;
    } else {
        head.push_str("\r\n");
        stream.write_all(head.as_bytes())?;
    }
    stream.flush()
}

fn write_json_response(
    stream: &mut TcpStream,
    status: u16,
    origin: &str,
    body: Value,
) -> io::Result<()> {
    let bytes = body.to_string();
    write_http_response(stream, status, origin, Some(bytes.as_bytes()))
}

fn write_err_response(
    stream: &mut TcpStream,
    status: u16,
    origin: &str,
    errno: Errno,
    detail: &str,
) -> io::Result<()> {
    write_json_response(
        stream,
        status,
        origin,
        json!({
            "errno": errno,
            "error": detail,
        }),
    )
}

// Unused helper keepalive guard for non-server tests if needed.
#[allow(dead_code)]
fn _keep_file_ref(_f: &File) {}
