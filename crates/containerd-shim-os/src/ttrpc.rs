//! Spec-compliant containerd TTRPC v1 server and client over `0600` Unix domain sockets.
//!
//! Wire format:
//! - 10-byte big-endian frame header: `[length: u32][stream_id: u32][type: u8][flags: u8]`
//! - `type == 1`: `ttrpc.Request` protobuf payload (`service`, `method`, `payload`, `timeout_nano`, `metadata`)
//! - `type == 2`: `ttrpc.Response` protobuf payload (`status: google.rpc.Status`, `payload`)
//! - Bounded payload cap (`MAX_TTRPC_MESSAGE_BYTES = 4 MiB`), concurrent per-connection request
//!   dispatch (up to `MAX_TTRPC_CONCURRENT_REQUESTS = 64`), race-free `0600` socket creation via
//!   private `0700` staging directory, and clean unlink on drop.

use std::collections::HashMap;
use std::ffi::CString;
use std::future::Future;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::unix::OwnedWriteHalf;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex as AsyncMutex, Semaphore, oneshot, watch};

pub const TTRPC_HEADER_LEN: usize = 10;
pub const MESSAGE_TYPE_REQUEST: u8 = 1;
pub const MESSAGE_TYPE_RESPONSE: u8 = 2;
pub const MAX_TTRPC_MESSAGE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_TTRPC_CONCURRENT_REQUESTS: usize = 64;

/// Standard `google.rpc.Code` status codes used by TTRPC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum RpcCode {
    Ok = 0,
    Cancelled = 1,
    Unknown = 2,
    InvalidArgument = 3,
    DeadlineExceeded = 4,
    NotFound = 5,
    AlreadyExists = 6,
    PermissionDenied = 7,
    ResourceExhausted = 8,
    FailedPrecondition = 9,
    Unimplemented = 12,
    Internal = 13,
}

impl RpcCode {
    pub fn from_i32(v: i32) -> Self {
        match v {
            0 => Self::Ok,
            1 => Self::Cancelled,
            3 => Self::InvalidArgument,
            4 => Self::DeadlineExceeded,
            5 => Self::NotFound,
            6 => Self::AlreadyExists,
            7 => Self::PermissionDenied,
            8 => Self::ResourceExhausted,
            9 => Self::FailedPrecondition,
            12 => Self::Unimplemented,
            13 => Self::Internal,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RpcStatus {
    pub code: i32,
    pub message: String,
}

impl RpcStatus {
    pub fn ok() -> Self {
        Self {
            code: RpcCode::Ok as i32,
            message: String::new(),
        }
    }

    pub fn err(code: RpcCode, msg: impl Into<String>) -> Self {
        Self {
            code: code as i32,
            message: msg.into(),
        }
    }

    pub fn is_ok(&self) -> bool {
        self.code == 0
    }
}

impl std::fmt::Display for RpcStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ttrpc status({}): {}", self.code, self.message)
    }
}

impl std::error::Error for RpcStatus {}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TtrpcRequest {
    pub service: String,
    pub method: String,
    pub payload: Vec<u8>,
    pub timeout_nano: i64,
    pub metadata: Vec<(String, String)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TtrpcResponse {
    pub status: RpcStatus,
    pub payload: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Minimal Protobuf v3 wire helpers (shared with `task_proto`)
// ---------------------------------------------------------------------------

pub fn encode_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
}

pub fn decode_varint(data: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut res = 0u64;
    let mut shift = 0u32;
    loop {
        if *pos >= data.len() {
            return Err("truncated protobuf varint".into());
        }
        let b = data[*pos];
        *pos += 1;
        if shift >= 64 || (shift == 63 && (b & 0x7f) > 1) {
            return Err("protobuf varint overflow".into());
        }
        res |= u64::from(b & 0x7f) << shift;
        if (b & 0x80) == 0 {
            return Ok(res);
        }
        shift += 7;
    }
}

pub fn decode_tag(data: &[u8], pos: &mut usize) -> Result<(u32, u8), String> {
    let raw = decode_varint(data, pos)?;
    let field =
        u32::try_from(raw >> 3).map_err(|_| "protobuf field number overflow".to_string())?;
    if field == 0 {
        return Err("invalid protobuf field number 0".into());
    }
    Ok((field, (raw & 7) as u8))
}

pub fn encode_tag(out: &mut Vec<u8>, field: u32, wire_type: u8) {
    encode_varint(out, ((field as u64) << 3) | u64::from(wire_type));
}

pub fn encode_bytes_field(out: &mut Vec<u8>, field: u32, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    encode_tag(out, field, 2);
    encode_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

pub fn encode_string_field(out: &mut Vec<u8>, field: u32, s: &str) {
    encode_bytes_field(out, field, s.as_bytes());
}

pub fn encode_message_field(out: &mut Vec<u8>, field: u32, msg: &[u8]) {
    encode_tag(out, field, 2);
    encode_varint(out, msg.len() as u64);
    out.extend_from_slice(msg);
}

pub fn encode_u32_field(out: &mut Vec<u8>, field: u32, val: u32) {
    if val != 0 {
        encode_tag(out, field, 0);
        encode_varint(out, u64::from(val));
    }
}

pub fn encode_i32_field(out: &mut Vec<u8>, field: u32, val: i32) {
    if val != 0 {
        encode_tag(out, field, 0);
        encode_varint(out, val as i64 as u64);
    }
}

pub fn encode_i64_field(out: &mut Vec<u8>, field: u32, val: i64) {
    if val != 0 {
        encode_tag(out, field, 0);
        encode_varint(out, val as u64);
    }
}

pub fn encode_bool_field(out: &mut Vec<u8>, field: u32, val: bool) {
    if val {
        encode_tag(out, field, 0);
        out.push(1);
    }
}

pub fn read_len_delimited<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a [u8], String> {
    let raw_len = decode_varint(data, pos)?;
    let len = usize::try_from(raw_len).map_err(|_| "protobuf length overflow".to_string())?;
    let end = pos
        .checked_add(len)
        .ok_or_else(|| "protobuf length overflow".to_string())?;
    if end > data.len() {
        return Err("truncated protobuf length-delimited field".into());
    }
    let slice = &data[*pos..end];
    *pos = end;
    Ok(slice)
}

pub fn skip_field(data: &[u8], pos: &mut usize, wire_type: u8) -> Result<(), String> {
    match wire_type {
        0 => {
            let _ = decode_varint(data, pos)?;
            Ok(())
        }
        1 => {
            if *pos + 8 > data.len() {
                return Err("truncated 64-bit field".into());
            }
            *pos += 8;
            Ok(())
        }
        2 => {
            let _ = read_len_delimited(data, pos)?;
            Ok(())
        }
        5 => {
            if *pos + 4 > data.len() {
                return Err("truncated 32-bit field".into());
            }
            *pos += 4;
            Ok(())
        }
        other => Err(format!("unsupported protobuf wire type {other}")),
    }
}

pub fn encode_ttrpc_request(req: &TtrpcRequest) -> Vec<u8> {
    let mut out = Vec::new();
    encode_string_field(&mut out, 1, &req.service);
    encode_string_field(&mut out, 2, &req.method);
    encode_bytes_field(&mut out, 3, &req.payload);
    encode_i64_field(&mut out, 4, req.timeout_nano);
    for (k, v) in &req.metadata {
        let mut kv = Vec::new();
        encode_string_field(&mut kv, 1, k);
        encode_string_field(&mut kv, 2, v);
        encode_message_field(&mut out, 5, &kv);
    }
    out
}

pub fn decode_ttrpc_request(data: &[u8]) -> Result<TtrpcRequest, String> {
    let mut req = TtrpcRequest::default();
    let mut pos = 0usize;
    while pos < data.len() {
        let (field, wt) = decode_tag(data, &mut pos)?;
        match (field, wt) {
            (1, 2) => {
                let s = read_len_delimited(data, &mut pos)?;
                req.service = String::from_utf8(s.to_vec()).map_err(|_| "invalid utf8 service")?;
            }
            (2, 2) => {
                let s = read_len_delimited(data, &mut pos)?;
                req.method = String::from_utf8(s.to_vec()).map_err(|_| "invalid utf8 method")?;
            }
            (3, 2) => {
                req.payload = read_len_delimited(data, &mut pos)?.to_vec();
            }
            (4, 0) => {
                req.timeout_nano = decode_varint(data, &mut pos)? as i64;
            }
            (5, 2) => {
                let kv_bytes = read_len_delimited(data, &mut pos)?;
                let mut kp = 0usize;
                let mut k = String::new();
                let mut v = String::new();
                while kp < kv_bytes.len() {
                    match decode_tag(kv_bytes, &mut kp)? {
                        (1, 2) => {
                            k = String::from_utf8_lossy(read_len_delimited(kv_bytes, &mut kp)?)
                                .into_owned();
                        }
                        (2, 2) => {
                            v = String::from_utf8_lossy(read_len_delimited(kv_bytes, &mut kp)?)
                                .into_owned();
                        }
                        (_, w) => skip_field(kv_bytes, &mut kp, w)?,
                    }
                }
                req.metadata.push((k, v));
            }
            (_, w) => skip_field(data, &mut pos, w)?,
        }
    }
    Ok(req)
}

pub fn encode_ttrpc_response(resp: &TtrpcResponse) -> Vec<u8> {
    let mut out = Vec::new();
    let mut status_buf = Vec::new();
    encode_i32_field(&mut status_buf, 1, resp.status.code);
    encode_string_field(&mut status_buf, 2, &resp.status.message);
    if !status_buf.is_empty() {
        encode_message_field(&mut out, 1, &status_buf);
    }
    encode_bytes_field(&mut out, 2, &resp.payload);
    out
}

pub fn decode_ttrpc_response(data: &[u8]) -> Result<TtrpcResponse, String> {
    let mut status = RpcStatus::ok();
    let mut payload = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        let (field, wt) = decode_tag(data, &mut pos)?;
        match (field, wt) {
            (1, 2) => {
                let sb = read_len_delimited(data, &mut pos)?;
                let mut sp = 0usize;
                while sp < sb.len() {
                    match decode_tag(sb, &mut sp)? {
                        (1, 0) => status.code = decode_varint(sb, &mut sp)? as i32,
                        (2, 2) => {
                            status.message =
                                String::from_utf8_lossy(read_len_delimited(sb, &mut sp)?)
                                    .into_owned();
                        }
                        (_, w) => skip_field(sb, &mut sp, w)?,
                    }
                }
            }
            (2, 2) => {
                payload = read_len_delimited(data, &mut pos)?.to_vec();
            }
            (_, w) => skip_field(data, &mut pos, w)?,
        }
    }
    Ok(TtrpcResponse { status, payload })
}

// ---------------------------------------------------------------------------
// Frame I/O & Race-Free `0600` Unix Socket Binding
// ---------------------------------------------------------------------------

async fn read_frame<R: AsyncRead + Unpin>(
    stream: &mut R,
) -> io::Result<Option<(u32, u8, u8, Vec<u8>)>> {
    let mut hdr = [0u8; TTRPC_HEADER_LEN];
    match stream.read_exact(&mut hdr).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
    let stream_id = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
    let msg_type = hdr[8];
    let flags = hdr[9];
    if len > MAX_TTRPC_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("ttrpc frame exceeds {MAX_TTRPC_MESSAGE_BYTES} bytes: {len}"),
        ));
    }
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    Ok(Some((stream_id, msg_type, flags, body)))
}

async fn write_frame<W: AsyncWrite + Unpin>(
    stream: &mut W,
    stream_id: u32,
    msg_type: u8,
    flags: u8,
    body: &[u8],
) -> io::Result<()> {
    if body.len() > MAX_TTRPC_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ttrpc outgoing frame exceeds cap",
        ));
    }
    let mut hdr = [0u8; TTRPC_HEADER_LEN];
    hdr[0..4].copy_from_slice(&(body.len() as u32).to_be_bytes());
    hdr[4..8].copy_from_slice(&stream_id.to_be_bytes());
    hdr[8] = msg_type;
    hdr[9] = flags;
    stream.write_all(&hdr).await?;
    stream.write_all(body).await?;
    stream.flush().await
}

pub fn validate_safe_socket_path(path: &Path) -> io::Result<()> {
    if path.as_os_str().is_empty() || path.as_os_str().as_bytes().contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty or invalid TTRPC socket path",
        ));
    }
    for comp in path.components() {
        if matches!(comp, Component::ParentDir) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TTRPC socket path must not contain '..'",
            ));
        }
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        let mut cur = PathBuf::new();
        for comp in parent.components() {
            cur.push(comp);
            if matches!(comp, Component::RootDir) {
                continue;
            }
            let meta = std::fs::symlink_metadata(&cur)?;
            if meta.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("refusing symlink parent {}", cur.display()),
                ));
            }
            if !meta.file_type().is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::NotADirectory,
                    format!("parent is not a directory: {}", cur.display()),
                ));
            }
        }
    }
    if let Ok(meta) = std::fs::symlink_metadata(path)
        && (meta.file_type().is_symlink() || !meta.file_type().is_socket())
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "refusing to unlink non-socket or symlink path",
        ));
    }
    Ok(())
}

/// Ensure a private `0700` runtime directory `/tmp/os-shim-rt-<uid>` owned by `geteuid()` exists,
/// refusing symlinks or directories owned by another user / overly permissive modes.
pub fn ensure_private_shim_runtime_dir() -> io::Result<PathBuf> {
    let uid = unsafe { libc::geteuid() };
    let dir = PathBuf::from(format!("/tmp/os-shim-rt-{uid}"));
    let cpath = CString::new(dir.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in runtime dir path"))?;
    let rc = unsafe { libc::mkdir(cpath.as_ptr(), 0o700) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EEXIST) {
            return Err(err);
        }
    }
    let meta = std::fs::symlink_metadata(&dir)?;
    if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "private shim runtime path is not a directory: {}",
                dir.display()
            ),
        ));
    }
    if meta.uid() != uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "private shim runtime dir owned by unexpected uid {}",
                meta.uid()
            ),
        ));
    }
    if (meta.mode() & 0o777) != 0o700 {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(dir)
}

static BIND_STAGE_SEQ: AtomicU64 = AtomicU64::new(1);

/// Bind a Unix domain socket with race-free `0600` permissions:
/// creates a private `0700` staging directory, binds inside it, `chmod 0600`, re-validates the
/// target, atomically `rename()`s into place, and removes the staging directory. When the staged
/// path would exceed `SUN_LEN`, verifies the parent directory itself is `0700` owned by `geteuid()`.
pub fn bind_ttrpc_unix_0600(path: &Path) -> io::Result<UnixListener> {
    validate_safe_socket_path(path)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let uid = unsafe { libc::geteuid() };
    let seq = BIND_STAGE_SEQ.fetch_add(1, Ordering::Relaxed);
    let stage_dir = parent.join(format!(".ttrpc-{}-{seq}", std::process::id()));
    let stage_sock = stage_dir.join("s");

    if stage_sock.as_os_str().as_bytes().len() < 104 {
        let cdir = CString::new(stage_dir.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in staging dir"))?;
        if unsafe { libc::mkdir(cdir.as_ptr(), 0o700) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let bind_res = (|| -> io::Result<UnixListener> {
            let listener = UnixListener::bind(&stage_sock)?;
            std::fs::set_permissions(&stage_sock, std::fs::Permissions::from_mode(0o600))?;
            validate_safe_socket_path(path)?;
            if std::fs::symlink_metadata(path).is_ok() {
                std::fs::remove_file(path)?;
            }
            std::fs::rename(&stage_sock, path)?;
            Ok(listener)
        })();
        let _ = std::fs::remove_file(&stage_sock);
        let _ = std::fs::remove_dir(&stage_dir);
        return bind_res;
    }

    // Path too close to `SUN_LEN` for a staging subdir: require parent dir to already be private `0700`.
    let pmeta = std::fs::symlink_metadata(parent)?;
    if pmeta.file_type().is_symlink()
        || !pmeta.file_type().is_dir()
        || pmeta.uid() != uid
        || (pmeta.mode() & 0o077) != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing direct socket bind in non-private directory {}",
                parent.display()
            ),
        ));
    }
    if std::fs::symlink_metadata(path).is_ok() {
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Async TTRPC service dispatcher trait.
pub trait TtrpcHandler: Send + Sync + 'static {
    fn handle<'a>(
        &'a self,
        req: TtrpcRequest,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, RpcStatus>> + 'a>>;
}

/// RAII cleanup guard removing the bound Unix socket file on exit.
struct SocketUnlinkGuard(PathBuf);
impl Drop for SocketUnlinkGuard {
    fn drop(&mut self) {
        if let Ok(meta) = std::fs::symlink_metadata(&self.0)
            && meta.file_type().is_socket()
        {
            let _ = std::fs::remove_file(&self.0);
        }
    }
}

struct InFlightGuard(Arc<AtomicUsize>);
impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Serve TTRPC v1 over a `0600` Unix domain socket until `shutdown_rx` signals `true`.
///
/// Each accepted connection splits its Unix stream and dispatches requests concurrently via
/// `spawn_local` (bounded by `MAX_TTRPC_CONCURRENT_REQUESTS`), so a blocking `Wait` never
/// head-of-line blocks `Kill`, `State`, `Exec`, or `Shutdown` on the same persistent connection.
pub async fn serve_ttrpc_unix<H: TtrpcHandler>(
    socket_path: PathBuf,
    handler: Arc<H>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> io::Result<()> {
    let listener = bind_ttrpc_unix_0600(&socket_path)?;
    let _unlink_guard = SocketUnlinkGuard(socket_path);
    let in_flight = Arc::new(AtomicUsize::new(0));

    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(pair) => pair,
                    Err(e) => return Err(e),
                };
                let (mut read_half, write_half) = stream.into_split();
                let write_half = Arc::new(AsyncMutex::new(write_half));
                let sem = Arc::new(Semaphore::new(MAX_TTRPC_CONCURRENT_REQUESTS));
                let h = Arc::clone(&handler);
                let mut conn_shutdown = shutdown_rx.clone();
                let conn_in_flight = Arc::clone(&in_flight);

                tokio::task::spawn_local(async move {
                    loop {
                        let frame = tokio::select! {
                            changed = conn_shutdown.changed() => {
                                if changed.is_err() || *conn_shutdown.borrow() {
                                    break;
                                }
                                continue;
                            }
                            res = read_frame(&mut read_half) => {
                                match res {
                                    Ok(Some(f)) => f,
                                    Ok(None) | Err(_) => break,
                                }
                            }
                        };
                        let (stream_id, msg_type, _flags, body) = frame;
                        if msg_type != MESSAGE_TYPE_REQUEST {
                            let resp = TtrpcResponse {
                                status: RpcStatus::err(
                                    RpcCode::InvalidArgument,
                                    "expected TTRPC request frame",
                                ),
                                payload: Vec::new(),
                            };
                            let encoded = encode_ttrpc_response(&resp);
                            let mut w = write_half.lock().await;
                            let _ = write_frame(&mut *w, stream_id, MESSAGE_TYPE_RESPONSE, 0, &encoded).await;
                            continue;
                        }
                        let permit = match Arc::clone(&sem).try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => {
                                let resp = TtrpcResponse {
                                    status: RpcStatus::err(
                                        RpcCode::ResourceExhausted,
                                        "too many concurrent TTRPC requests on connection",
                                    ),
                                    payload: Vec::new(),
                                };
                                let encoded = encode_ttrpc_response(&resp);
                                let mut w = write_half.lock().await;
                                if write_frame(&mut *w, stream_id, MESSAGE_TYPE_RESPONSE, 0, &encoded).await.is_err() {
                                    break;
                                }
                                continue;
                            }
                        };

                        let h_req = Arc::clone(&h);
                        let w_req = Arc::clone(&write_half);
                        conn_in_flight.fetch_add(1, Ordering::AcqRel);
                        let req_guard = InFlightGuard(Arc::clone(&conn_in_flight));

                        tokio::task::spawn_local(async move {
                            let _permit = permit;
                            let _guard = req_guard;
                            let resp = match decode_ttrpc_request(&body) {
                                Ok(req) => match h_req.handle(req).await {
                                    Ok(payload) => TtrpcResponse {
                                        status: RpcStatus::ok(),
                                        payload,
                                    },
                                    Err(status) => TtrpcResponse {
                                        status,
                                        payload: Vec::new(),
                                    },
                                },
                                Err(e) => TtrpcResponse {
                                    status: RpcStatus::err(RpcCode::InvalidArgument, e),
                                    payload: Vec::new(),
                                },
                            };
                            let encoded = encode_ttrpc_response(&resp);
                            let mut w = w_req.lock().await;
                            let _ = write_frame(&mut *w, stream_id, MESSAGE_TYPE_RESPONSE, 0, &encoded).await;
                        });

                        if *conn_shutdown.borrow() {
                            break;
                        }
                    }
                });
            }
        }
    }

    // Give in-flight handlers (in particular `Shutdown`'s response write) a brief window to flush.
    for _ in 0..50 {
        if in_flight.load(Ordering::Acquire) == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }

    Ok(())
}

/// Async TTRPC v1 Unix domain socket client (sequential single-request API).
pub struct TtrpcClient {
    stream: UnixStream,
    next_stream_id: AtomicU32,
}

impl TtrpcClient {
    pub async fn connect(path: &Path) -> io::Result<Self> {
        let stream = UnixStream::connect(path).await?;
        Ok(Self {
            stream,
            next_stream_id: AtomicU32::new(1),
        })
    }

    pub async fn call(
        &mut self,
        service: &str,
        method: &str,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, RpcStatus> {
        let sid = self.next_stream_id.fetch_add(2, Ordering::SeqCst);
        let req = TtrpcRequest {
            service: service.to_string(),
            method: method.to_string(),
            payload,
            timeout_nano: 0,
            metadata: Vec::new(),
        };
        let encoded = encode_ttrpc_request(&req);
        write_frame(&mut self.stream, sid, MESSAGE_TYPE_REQUEST, 0, &encoded)
            .await
            .map_err(|e| RpcStatus::err(RpcCode::Internal, format!("ttrpc write: {e}")))?;

        let (resp_sid, resp_type, _flags, body) = read_frame(&mut self.stream)
            .await
            .map_err(|e| RpcStatus::err(RpcCode::Internal, format!("ttrpc read: {e}")))?
            .ok_or_else(|| RpcStatus::err(RpcCode::Internal, "ttrpc peer closed connection"))?;
        if resp_sid != sid || resp_type != MESSAGE_TYPE_RESPONSE {
            return Err(RpcStatus::err(
                RpcCode::Internal,
                format!("unexpected ttrpc frame sid={resp_sid} type={resp_type}"),
            ));
        }
        let resp = decode_ttrpc_response(&body)
            .map_err(|e| RpcStatus::err(RpcCode::Internal, format!("ttrpc decode: {e}")))?;
        if !resp.status.is_ok() {
            return Err(resp.status);
        }
        Ok(resp.payload)
    }

    /// Upgrade this connection into a multiplexed client supporting concurrent RPCs
    /// (e.g. concurrent `Wait` + `Kill`/`State`) over the same persistent Unix socket.
    pub fn into_multiplexed(self) -> MultiplexedTtrpcClient {
        MultiplexedTtrpcClient::from_stream(self.stream, self.next_stream_id.load(Ordering::SeqCst))
    }
}

type PendingMap = Arc<StdMutex<HashMap<u32, oneshot::Sender<Result<TtrpcResponse, RpcStatus>>>>>;

/// Multiplexed async TTRPC v1 client allowing concurrent in-flight RPCs on a single Unix connection.
pub struct MultiplexedTtrpcClient {
    writer: Arc<AsyncMutex<OwnedWriteHalf>>,
    pending: PendingMap,
    next_stream_id: AtomicU32,
    reader_task: tokio::task::JoinHandle<()>,
}

impl MultiplexedTtrpcClient {
    pub async fn connect(path: &Path) -> io::Result<Self> {
        let stream = UnixStream::connect(path).await?;
        Ok(Self::from_stream(stream, 1))
    }

    fn from_stream(stream: UnixStream, start_sid: u32) -> Self {
        let (mut read_half, write_half) = stream.into_split();
        let pending: PendingMap = Arc::new(StdMutex::new(HashMap::new()));
        let pending_reader = Arc::clone(&pending);
        let reader_task = tokio::spawn(async move {
            loop {
                match read_frame(&mut read_half).await {
                    Ok(Some((sid, msg_type, _flags, body))) => {
                        let tx = pending_reader.lock().unwrap().remove(&sid);
                        if let Some(tx) = tx {
                            let res = if msg_type != MESSAGE_TYPE_RESPONSE {
                                Err(RpcStatus::err(
                                    RpcCode::Internal,
                                    format!("unexpected ttrpc frame type={msg_type}"),
                                ))
                            } else {
                                decode_ttrpc_response(&body).map_err(|e| {
                                    RpcStatus::err(RpcCode::Internal, format!("ttrpc decode: {e}"))
                                })
                            };
                            let _ = tx.send(res);
                        }
                    }
                    Ok(None) | Err(_) => {
                        let drained: Vec<_> = pending_reader
                            .lock()
                            .unwrap()
                            .drain()
                            .map(|(_, tx)| tx)
                            .collect();
                        for tx in drained {
                            let _ = tx.send(Err(RpcStatus::err(
                                RpcCode::Internal,
                                "ttrpc peer closed connection",
                            )));
                        }
                        break;
                    }
                }
            }
        });
        Self {
            writer: Arc::new(AsyncMutex::new(write_half)),
            pending,
            next_stream_id: AtomicU32::new(start_sid),
            reader_task,
        }
    }

    pub async fn call(
        &self,
        service: &str,
        method: &str,
        payload: Vec<u8>,
    ) -> Result<Vec<u8>, RpcStatus> {
        let sid = self.next_stream_id.fetch_add(2, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(sid, tx);

        let req = TtrpcRequest {
            service: service.to_string(),
            method: method.to_string(),
            payload,
            timeout_nano: 0,
            metadata: Vec::new(),
        };
        let encoded = encode_ttrpc_request(&req);
        let write_res = {
            let mut w = self.writer.lock().await;
            write_frame(&mut *w, sid, MESSAGE_TYPE_REQUEST, 0, &encoded).await
        };
        if let Err(e) = write_res {
            self.pending.lock().unwrap().remove(&sid);
            return Err(RpcStatus::err(
                RpcCode::Internal,
                format!("ttrpc write: {e}"),
            ));
        }

        let resp = rx
            .await
            .map_err(|_| RpcStatus::err(RpcCode::Internal, "ttrpc reader task closed"))??;
        if !resp.status.is_ok() {
            return Err(resp.status);
        }
        Ok(resp.payload)
    }
}

impl Drop for MultiplexedTtrpcClient {
    fn drop(&mut self) {
        self.reader_task.abort();
    }
}
