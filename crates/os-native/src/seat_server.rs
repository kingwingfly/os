//! Dual-mode remote seat/PTY server (Unix `0600`, TCP JSON-lines, and RFC-6455 WebSocket)
//! plus `$STATE/host-ctl.sock` (`0600`) live token management and immediate client revocation.

use crate::boot::NativeOsHost;
use crate::pty::{PtyInstance, WinSize};
use crate::seat_proto::{
    ClientFrame, ControlReply, ControlRequest, ServerFrame, TokenRecord, TokenStore,
    negotiate_host_adapter,
};
use abi::Errno;
use abi::contract::{Boundary, Hello};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::net::{TcpListener, TcpStream, UnixListener};
use tokio::sync::{mpsc, watch};

pub(crate) const CTL_LINE_MAX: usize = 64 * 1024;
pub(crate) const WS_HDR_LINE_MAX: usize = 8 * 1024;
pub(crate) const FRAME_TEXT_MAX: usize = 16 * 1024 * 1024;

/// Read a single UTF-8 newline-delimited line with a strict upper bound to prevent OOM DoS.
pub(crate) async fn read_bounded_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max_len: usize,
) -> std::io::Result<Option<String>> {
    let mut buf = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if buf.is_empty() {
                return Ok(None);
            }
            break;
        }
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            let take = pos + 1;
            if buf.len().saturating_add(take) > max_len {
                reader.consume(take);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "line exceeds maximum length",
                ));
            }
            buf.extend_from_slice(&available[..take]);
            reader.consume(take);
            break;
        }
        let avail_len = available.len();
        if buf.len().saturating_add(avail_len) > max_len {
            reader.consume(avail_len);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "line exceeds maximum length",
            ));
        }
        buf.extend_from_slice(available);
        reader.consume(avail_len);
    }
    String::from_utf8(buf)
        .map(Some)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid utf-8 line"))
}

/// Configuration for `SeatServer`.
#[derive(Clone, Debug)]
pub struct SeatServerConfig {
    pub state_dir: PathBuf,
    pub unix_seat_path: Option<PathBuf>,
    pub tcp_listen: Option<SocketAddr>,
}

impl SeatServerConfig {
    pub fn default_for(state_dir: PathBuf) -> Self {
        let unix_seat_path = Some(state_dir.join("seat.sock"));
        Self {
            state_dir,
            unix_seat_path,
            tcp_listen: None,
        }
    }
}

/// Active client connection registry keyed by `token_id` for immediate live revocation.
#[derive(Default)]
struct LiveSessions {
    by_token: HashMap<String, Vec<(u64, mpsc::UnboundedSender<String>)>>,
    next_id: u64,
}

impl LiveSessions {
    fn register(&mut self, token_id: &str) -> (u64, mpsc::UnboundedReceiver<String>) {
        self.next_id += 1;
        let conn_id = self.next_id;
        let (tx, rx) = mpsc::unbounded_channel();
        self.by_token
            .entry(token_id.to_string())
            .or_default()
            .push((conn_id, tx));
        (conn_id, rx)
    }

    fn unregister(&mut self, token_id: &str, conn_id: u64) {
        if let Some(list) = self.by_token.get_mut(token_id) {
            list.retain(|(id, _)| *id != conn_id);
            if list.is_empty() {
                self.by_token.remove(token_id);
            }
        }
    }

    fn revoke(&mut self, token_id: &str, reason: &str) -> usize {
        let Some(list) = self.by_token.remove(token_id) else {
            return 0;
        };
        let mut count = 0;
        for (_, tx) in list {
            if tx.send(reason.to_string()).is_ok() {
                count += 1;
            }
        }
        count
    }
}

/// Shared state for all remote seat listeners and `$STATE/host-ctl.sock`.
pub struct SeatServerHandle {
    pub host: Arc<NativeOsHost>,
    pub tokens: Arc<TokenStore>,
    pub ctl_sock_path: PathBuf,
    pub unix_seat_path: Option<PathBuf>,
    pub tcp_addr: Option<SocketAddr>,
    sessions: Arc<Mutex<LiveSessions>>,
    shutdown_tx: watch::Sender<bool>,
}

impl SeatServerHandle {
    /// Start `$STATE/host-ctl.sock` (`0600`), optional `$STATE/seat.sock` (`0600`), and optional
    /// TCP/WebSocket listener on the current Tokio runtime.
    pub async fn start(
        host: Arc<NativeOsHost>,
        cfg: SeatServerConfig,
    ) -> Result<Arc<Self>, String> {
        std::fs::create_dir_all(&cfg.state_dir)
            .map_err(|e| format!("create state dir {}: {e}", cfg.state_dir.display()))?;

        let tokens = Arc::new(TokenStore::new(&cfg.state_dir));
        let sessions = Arc::new(Mutex::new(LiveSessions::default()));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let ctl_sock_path = cfg.state_dir.join("host-ctl.sock");
        let ctl_listener = bind_unix_0600(&ctl_sock_path)?;

        let unix_listener = match &cfg.unix_seat_path {
            Some(p) => Some((p.clone(), bind_unix_0600(p)?)),
            None => None,
        };

        let (tcp_addr, tcp_listener) = match cfg.tcp_listen {
            Some(addr) => {
                let listener = TcpListener::bind(addr)
                    .await
                    .map_err(|e| format!("bind TCP {addr}: {e}"))?;
                let bound = listener
                    .local_addr()
                    .map_err(|e| format!("local_addr: {e}"))?;
                (Some(bound), Some(listener))
            }
            None => (None, None),
        };

        let handle = Arc::new(Self {
            host,
            tokens,
            ctl_sock_path,
            unix_seat_path: cfg.unix_seat_path,
            tcp_addr,
            sessions,
            shutdown_tx,
        });

        // 1. Spawn `$STATE/host-ctl.sock` listener.
        {
            let h = Arc::clone(&handle);
            let mut stop = shutdown_rx.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = stop.changed() => break,
                        res = ctl_listener.accept() => {
                            let Ok((stream, _)) = res else { break };
                            let h2 = Arc::clone(&h);
                            tokio::spawn(async move {
                                handle_ctl_conn(h2, stream).await;
                            });
                        }
                    }
                }
            });
        }

        // 2. Spawn Unix seat listener (if configured).
        if let Some((_path, listener)) = unix_listener {
            let h = Arc::clone(&handle);
            let mut stop = shutdown_rx.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = stop.changed() => break,
                        res = listener.accept() => {
                            let Ok((stream, _)) = res else { break };
                            let h2 = Arc::clone(&h);
                            tokio::spawn(async move {
                                let (r, w) = tokio::io::split(stream);
                                let reader: BufReader<DynRead> = BufReader::new(Box::new(r));
                                let (rx, reader_task) = spawn_frame_reader(reader, false);
                                serve_seat_client(
                                    h2,
                                    rx,
                                    FrameWriter::JsonLines(Box::new(w)),
                                    reader_task,
                                )
                                .await;
                            });
                        }
                    }
                }
            });
        }

        // 3. Spawn dual-mode TCP / RFC-6455 WebSocket seat listener (if configured).
        if let Some(listener) = tcp_listener {
            let h = Arc::clone(&handle);
            let mut stop = shutdown_rx.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = stop.changed() => break,
                        res = listener.accept() => {
                            let Ok((stream, _)) = res else { break };
                            let h2 = Arc::clone(&h);
                            tokio::spawn(async move {
                                serve_tcp_or_ws(h2, stream).await;
                            });
                        }
                    }
                }
            });
        }

        Ok(handle)
    }

    /// Revoke token(s) persistently AND immediately sever every active connection using them.
    pub fn revoke_token_live(&self, id_or_prefix: &str) -> Result<(Vec<String>, usize), String> {
        let ids = self.tokens.revoke_token(id_or_prefix)?;
        let mut disconnected = 0usize;
        let mut guard = self.sessions.lock().unwrap();
        for id in &ids {
            disconnected += guard.revoke(id, "token revoked");
        }
        Ok((ids, disconnected))
    }

    /// Stop all listeners and remove Unix socket files.
    pub fn stop(&self) {
        let _ = self.shutdown_tx.send(true);
        let _ = std::fs::remove_file(&self.ctl_sock_path);
        if let Some(ref p) = self.unix_seat_path {
            let _ = std::fs::remove_file(p);
        }
    }
}

impl Drop for SeatServerHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

fn bind_unix_0600(path: &Path) -> Result<UnixListener, String> {
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
    let listener =
        UnixListener::bind(path).map_err(|e| format!("bind unix {}: {e}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("chmod 0600 {}: {e}", path.display()))?;
    Ok(listener)
}

async fn handle_ctl_conn(handle: Arc<SeatServerHandle>, stream: tokio::net::UnixStream) {
    let (r, mut w) = tokio::io::split(stream);
    let mut reader = BufReader::new(r);
    while let Ok(Some(line)) = read_bounded_line(&mut reader, CTL_LINE_MAX).await {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<ControlRequest>(trimmed) {
            Ok(ControlRequest::CreateToken {
                uid,
                label,
                allowed_seats,
                can_exec,
                ttl_secs,
            }) => match handle
                .tokens
                .create_token(uid, label, allowed_seats, can_exec, ttl_secs)
            {
                Ok((record, token)) => ControlReply::TokenCreated { record, token },
                Err(message) => ControlReply::Error { message },
            },
            Ok(ControlRequest::ListTokens) => match handle.tokens.list_tokens() {
                Ok(tokens) => ControlReply::Tokens { tokens },
                Err(message) => ControlReply::Error { message },
            },
            Ok(ControlRequest::RevokeToken { id_or_prefix }) => {
                match handle.revoke_token_live(&id_or_prefix) {
                    Ok((token_ids, disconnected_clients)) => ControlReply::Revoked {
                        token_ids,
                        disconnected_clients,
                    },
                    Err(message) => ControlReply::Error { message },
                }
            }
            Ok(ControlRequest::Inspect) => ControlReply::Inspect(handle.host.inspect().await),
            Err(e) => ControlReply::Error {
                message: format!("invalid control request: {e}"),
            },
        };
        let mut out = serde_json::to_string(&reply).unwrap_or_else(|_| {
            "{\"status\":\"error\",\"message\":\"serialize failed\"}".to_string()
        });
        out.push('\n');
        if w.write_all(out.as_bytes()).await.is_err() {
            break;
        }
        let _ = w.flush().await;
    }
}

// ---------------------------------------------------------------------------
// Dual-mode Transport: Cancel-Safe Reader Task + Writer (JSON-lines / WS)
// ---------------------------------------------------------------------------

type DynRead = Box<dyn AsyncRead + Unpin + Send>;
type DynWrite = Box<dyn AsyncWrite + Unpin + Send>;

enum ReaderEvent {
    Text(String),
    Ping(Vec<u8>),
    Closed,
    Err(String),
}

enum FrameWriter {
    JsonLines(DynWrite),
    WebSocket(DynWrite),
}

impl FrameWriter {
    async fn send_frame(&mut self, frame: &ServerFrame) -> Result<(), String> {
        let json = serde_json::to_string(frame).map_err(|e| format!("serialize frame: {e}"))?;
        match self {
            Self::JsonLines(writer) => {
                writer
                    .write_all(json.as_bytes())
                    .await
                    .map_err(|e| e.to_string())?;
                writer.write_all(b"\n").await.map_err(|e| e.to_string())?;
                writer.flush().await.map_err(|e| e.to_string())
            }
            Self::WebSocket(writer) => ws_write_frame(writer, 0x1, json.as_bytes(), false).await,
        }
    }

    async fn send_pong(&mut self, payload: &[u8]) -> Result<(), String> {
        if let Self::WebSocket(writer) = self {
            ws_write_frame(writer, 0xA, payload, false).await?;
        }
        Ok(())
    }

    async fn close_graceful(&mut self) {
        if let Self::WebSocket(writer) = self {
            let _ = ws_write_frame(writer, 0x8, &[], false).await;
        }
    }
}

fn spawn_frame_reader(
    mut reader: BufReader<DynRead>,
    is_ws: bool,
) -> (mpsc::Receiver<ReaderEvent>, tokio::task::JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(32);
    let task = tokio::spawn(async move {
        if !is_ws {
            loop {
                match read_bounded_line(&mut reader, FRAME_TEXT_MAX).await {
                    Ok(Some(line)) => {
                        let t = line.trim();
                        if t.is_empty() {
                            continue;
                        }
                        if tx.send(ReaderEvent::Text(t.to_string())).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => {
                        let _ = tx.send(ReaderEvent::Closed).await;
                        break;
                    }
                    Err(e) => {
                        let _ = tx.send(ReaderEvent::Err(format!("read error: {e}"))).await;
                        break;
                    }
                }
            }
        } else {
            let mut frag_buf: Option<Vec<u8>> = None;
            loop {
                match ws_read_event(&mut reader, true, &mut frag_buf).await {
                    Ok(Some(WsEvent::Text(t))) => {
                        if tx.send(ReaderEvent::Text(t)).await.is_err() {
                            break;
                        }
                    }
                    Ok(Some(WsEvent::Ping(p))) => {
                        if tx.send(ReaderEvent::Ping(p)).await.is_err() {
                            break;
                        }
                    }
                    Ok(Some(WsEvent::Close)) | Ok(None) => {
                        let _ = tx.send(ReaderEvent::Closed).await;
                        break;
                    }
                    Err(e) => {
                        let _ = tx.send(ReaderEvent::Err(e)).await;
                        break;
                    }
                }
            }
        }
    });
    (rx, task)
}

async fn recv_text_with_timeout(
    rx: &mut mpsc::Receiver<ReaderEvent>,
    writer: &mut FrameWriter,
    timeout: Duration,
) -> Result<Option<String>, String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
        if rem.is_zero() {
            return Err("timed out waiting for frame".into());
        }
        match tokio::time::timeout(rem, rx.recv()).await {
            Ok(Some(ReaderEvent::Text(t))) => return Ok(Some(t)),
            Ok(Some(ReaderEvent::Ping(p))) => {
                let _ = writer.send_pong(&p).await;
            }
            Ok(Some(ReaderEvent::Closed)) | Ok(None) => return Ok(None),
            Ok(Some(ReaderEvent::Err(e))) => return Err(e),
            Err(_) => return Err("timed out waiting for frame".into()),
        }
    }
}

async fn serve_tcp_or_ws(handle: Arc<SeatServerHandle>, stream: TcpStream) {
    let _ = stream.set_nodelay(true);
    let mut peek = [0u8; 4];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let is_http_ws = loop {
        let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
        if rem.is_zero() {
            return;
        }
        let n = match tokio::time::timeout(rem, stream.peek(&mut peek)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => return,
        };
        if n >= 4 {
            break &peek == b"GET ";
        }
        if peek[..n] != b"GET "[..n] {
            break false;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    };
    let (r, w) = tokio::io::split(stream);
    let mut reader: BufReader<DynRead> = BufReader::new(Box::new(r));
    let mut writer: DynWrite = Box::new(w);

    if is_http_ws {
        match tokio::time::timeout(
            Duration::from_secs(10),
            ws_server_handshake(&mut reader, &mut writer),
        )
        .await
        {
            Ok(Ok(())) => {}
            _ => return,
        }
        let (rx, reader_task) = spawn_frame_reader(reader, true);
        serve_seat_client(handle, rx, FrameWriter::WebSocket(writer), reader_task).await;
    } else {
        let (rx, reader_task) = spawn_frame_reader(reader, false);
        serve_seat_client(handle, rx, FrameWriter::JsonLines(writer), reader_task).await;
    }
}

async fn serve_seat_client(
    handle: Arc<SeatServerHandle>,
    mut rx: mpsc::Receiver<ReaderEvent>,
    mut io: FrameWriter,
    reader_task: tokio::task::JoinHandle<()>,
) {
    // 1. Mandatory `HostAdapter v2` Hello negotiation (`EPROTONOSUPPORT` on mismatch).
    let hello_text = match recv_text_with_timeout(&mut rx, &mut io, Duration::from_secs(10)).await {
        Ok(Some(t)) => t,
        _ => {
            reader_task.abort();
            return;
        }
    };
    let peer_hello = match serde_json::from_str::<ClientFrame>(&hello_text) {
        Ok(ClientFrame::Hello { boundary, versions }) => Hello { boundary, versions },
        _ => {
            // Also accept raw `abi::contract::Hello` JSON directly!
            match serde_json::from_str::<Hello>(&hello_text) {
                Ok(h) => h,
                Err(_) => {
                    let _ = io
                        .send_frame(&ServerFrame::err(
                            Errno::EPROTONOSUPPORT,
                            "expected HostAdapter v2 Hello frame",
                        ))
                        .await;
                    io.close_graceful().await;
                    reader_task.abort();
                    return;
                }
            }
        }
    };
    let version = match negotiate_host_adapter(&peer_hello) {
        Ok(v) => v,
        Err(errno) => {
            let _ = io
                .send_frame(&ServerFrame::err(
                    errno,
                    format!(
                        "HostAdapter negotiation failed: boundary={:?}, versions={:?}",
                        peer_hello.boundary, peer_hello.versions
                    ),
                ))
                .await;
            io.close_graceful().await;
            reader_task.abort();
            return;
        }
    };
    if io
        .send_frame(&ServerFrame::HelloOk {
            boundary: Boundary::HostAdapter,
            version,
            instance_id: handle.host.instance_id.clone(),
            release_id: handle.host.release_id.clone(),
        })
        .await
        .is_err()
    {
        reader_task.abort();
        return;
    }

    // 2. Mandatory token authentication (`EACCES` on missing/invalid/expired/revoked token).
    let auth_text = match recv_text_with_timeout(&mut rx, &mut io, Duration::from_secs(10)).await {
        Ok(Some(t)) => t,
        _ => {
            reader_task.abort();
            return;
        }
    };
    let token_str = match serde_json::from_str::<ClientFrame>(&auth_text) {
        Ok(ClientFrame::Auth { token }) => token,
        _ => {
            let _ = io
                .send_frame(&ServerFrame::err(
                    Errno::EACCES,
                    "authentication required before seat operations",
                ))
                .await;
            io.close_graceful().await;
            reader_task.abort();
            return;
        }
    };
    let tok: TokenRecord = match handle.tokens.authenticate(&token_str) {
        Ok(rec) => rec,
        Err(errno) => {
            let _ = io
                .send_frame(&ServerFrame::err(
                    errno,
                    "invalid, expired, or revoked seat token",
                ))
                .await;
            io.close_graceful().await;
            reader_task.abort();
            return;
        }
    };

    let (conn_id, mut revoke_rx) = handle.sessions.lock().unwrap().register(&tok.id);
    if io
        .send_frame(&ServerFrame::AuthOk {
            token_id: tok.id.clone(),
            uid: tok.uid,
            allowed_seats: tok.allowed_seats.clone(),
            can_exec: tok.can_exec,
        })
        .await
        .is_err()
    {
        handle.sessions.lock().unwrap().unregister(&tok.id, conn_id);
        reader_task.abort();
        return;
    }

    // Compute exact idle-expiry deadline from `tok.expires_at`.
    let expiry_deadline = tok.expires_at.map(|exp| {
        let target = std::time::UNIX_EPOCH + Duration::from_secs(exp);
        let rem = target
            .duration_since(std::time::SystemTime::now())
            .unwrap_or(Duration::ZERO);
        tokio::time::Instant::now() + rem
    });

    // 3. Authenticated session loop (supports attach/input/resize/detach, exec, list_seats, inspect,
    //    immediate live revocation interrupt, and proactive idle token expiry!).
    let mut attached: Option<(Arc<PtyInstance>, u64, mpsc::UnboundedReceiver<Vec<u8>>)> = None;

    loop {
        let expiry_fut = async {
            match expiry_deadline {
                Some(dl) => tokio::time::sleep_until(dl).await,
                None => std::future::pending::<()>().await,
            }
        };
        if let Some((ref pty, sub_id, ref mut out_rx)) = attached {
            let seat_num = pty.number;
            tokio::select! {
                reason = revoke_rx.recv() => {
                    let msg = reason.unwrap_or_else(|| "token revoked".to_string());
                    let _ = io.send_frame(&ServerFrame::err(Errno::EACCES, msg)).await;
                    io.close_graceful().await;
                    pty.unsubscribe(sub_id);
                    break;
                }
                _ = expiry_fut => {
                    let _ = io.send_frame(&ServerFrame::err(Errno::EACCES, "seat token expired")).await;
                    io.close_graceful().await;
                    pty.unsubscribe(sub_id);
                    break;
                }
                chunk = out_rx.recv() => {
                    if tok.is_expired(crate::kernel_actor::now_secs()) {
                        let _ = io.send_frame(&ServerFrame::err(Errno::EACCES, "seat token expired")).await;
                        io.close_graceful().await;
                        pty.unsubscribe(sub_id);
                        break;
                    }
                    match chunk {
                        Some(bytes) => {
                            if io.send_frame(&ServerFrame::Output {
                                seat: seat_num,
                                data_b64: B64.encode(&bytes),
                            }).await.is_err() {
                                pty.unsubscribe(sub_id);
                                break;
                            }
                        }
                        None => {
                            pty.unsubscribe(sub_id);
                            attached = None;
                        }
                    }
                }
                ev = rx.recv() => {
                    match ev {
                        Some(ReaderEvent::Ping(p)) => {
                            if io.send_pong(&p).await.is_err() {
                                pty.unsubscribe(sub_id);
                                break;
                            }
                        }
                        Some(ReaderEvent::Text(text)) => {
                            if !handle_authed_frame(&handle, &tok, &mut io, &mut attached, &text).await {
                                if let Some((p, sid, _)) = attached.take() {
                                    p.unsubscribe(sid);
                                }
                                break;
                            }
                        }
                        Some(ReaderEvent::Closed) | Some(ReaderEvent::Err(_)) | None => {
                            pty.unsubscribe(sub_id);
                            break;
                        }
                    }
                }
            }
        } else {
            tokio::select! {
                reason = revoke_rx.recv() => {
                    let msg = reason.unwrap_or_else(|| "token revoked".to_string());
                    let _ = io.send_frame(&ServerFrame::err(Errno::EACCES, msg)).await;
                    io.close_graceful().await;
                    break;
                }
                _ = expiry_fut => {
                    let _ = io.send_frame(&ServerFrame::err(Errno::EACCES, "seat token expired")).await;
                    io.close_graceful().await;
                    break;
                }
                ev = rx.recv() => {
                    match ev {
                        Some(ReaderEvent::Ping(p)) => {
                            if io.send_pong(&p).await.is_err() {
                                break;
                            }
                        }
                        Some(ReaderEvent::Text(text)) => {
                            if !handle_authed_frame(&handle, &tok, &mut io, &mut attached, &text).await {
                                break;
                            }
                        }
                        Some(ReaderEvent::Closed) | Some(ReaderEvent::Err(_)) | None => {
                            break;
                        }
                    }
                }
            }
        }
    }

    if let Some((p, sid, _)) = attached.take() {
        p.unsubscribe(sid);
    }
    handle.sessions.lock().unwrap().unregister(&tok.id, conn_id);
    reader_task.abort();
}

type AttachedPty = (Arc<PtyInstance>, u64, mpsc::UnboundedReceiver<Vec<u8>>);

async fn handle_authed_frame(
    handle: &Arc<SeatServerHandle>,
    tok: &TokenRecord,
    io: &mut FrameWriter,
    attached: &mut Option<AttachedPty>,
    text: &str,
) -> bool {
    // Re-check expiry on every frame.
    if tok.is_expired(crate::kernel_actor::now_secs()) {
        let _ = io
            .send_frame(&ServerFrame::err(Errno::EACCES, "seat token expired"))
            .await;
        io.close_graceful().await;
        return false;
    }

    let frame = match serde_json::from_str::<ClientFrame>(text) {
        Ok(f) => f,
        Err(e) => {
            let _ = io
                .send_frame(&ServerFrame::err(
                    Errno::EINVAL,
                    format!("invalid client frame: {e}"),
                ))
                .await;
            return true;
        }
    };

    match frame {
        ClientFrame::Hello { .. } | ClientFrame::Auth { .. } => {
            let _ = io
                .send_frame(&ServerFrame::err(Errno::EINVAL, "already authenticated"))
                .await;
            true
        }
        ClientFrame::ListSeats => {
            let seats: Vec<u32> = handle
                .host
                .kernel
                .ptys
                .list_numbers()
                .into_iter()
                .filter(|&n| tok.permits_seat(n))
                .collect();
            io.send_frame(&ServerFrame::Seats { seats }).await.is_ok()
        }
        ClientFrame::Inspect => {
            let info = handle.host.inspect().await;
            io.send_frame(&ServerFrame::Inspect(info)).await.is_ok()
        }
        ClientFrame::Attach {
            seat,
            spawn_if_missing,
            cols,
            rows,
        } => {
            let resolved_target: Result<u32, (Errno, String)> = match seat {
                Some(s) => {
                    if !tok.permits_seat(s) {
                        Err((
                            Errno::EACCES,
                            format!("token does not allow attaching to seat {s}"),
                        ))
                    } else {
                        Ok(s)
                    }
                }
                None => {
                    if tok.permits_seat(0) && handle.host.kernel.ptys.get(0).is_some() {
                        Ok(0)
                    } else if !tok.allowed_seats.is_empty() {
                        if let Some(&existing) = tok
                            .allowed_seats
                            .iter()
                            .find(|&&s| handle.host.kernel.ptys.get(s).is_some())
                        {
                            Ok(existing)
                        } else {
                            Ok(tok.allowed_seats[0])
                        }
                    } else {
                        Ok(0)
                    }
                }
            };
            let target_seat = match resolved_target {
                Ok(s) => s,
                Err((errno, msg)) => {
                    let _ = io.send_frame(&ServerFrame::err(errno, msg)).await;
                    return true;
                }
            };
            if let Some((old_pty, old_sub, _)) = attached.take() {
                old_pty.unsubscribe(old_sub);
            }
            let pty = match handle.host.kernel.ptys.get(target_seat) {
                Some(p) => p,
                None if spawn_if_missing => {
                    match handle
                        .host
                        .allocate_and_spawn_seat_shell(Some(target_seat), tok.uid)
                        .await
                    {
                        Ok(p) => p,
                        Err(Errno::EEXIST) => match handle.host.kernel.ptys.get(target_seat) {
                            Some(p) => p,
                            None => {
                                let _ = io
                                    .send_frame(&ServerFrame::err(
                                        Errno::ENOENT,
                                        format!("seat {target_seat} vanished during attach"),
                                    ))
                                    .await;
                                return true;
                            }
                        },
                        Err(e) => {
                            let _ = io
                                .send_frame(&ServerFrame::err(
                                    e,
                                    "failed to spawn shell on new seat",
                                ))
                                .await;
                            return true;
                        }
                    }
                }
                None => {
                    let _ = io
                        .send_frame(&ServerFrame::err(
                            Errno::ENOENT,
                            format!("seat {target_seat} does not exist"),
                        ))
                        .await;
                    return true;
                }
            };
            if let (Some(columns), Some(rows)) = (cols, rows) {
                let _ = pty.set_winsize(WinSize {
                    columns,
                    rows,
                    width: 0,
                    height: 0,
                });
            }
            let ws = pty.winsize();
            let (sub_id, snap, rx) = pty.subscribe();
            let seat_num = pty.number;
            *attached = Some((pty, sub_id, rx));
            io.send_frame(&ServerFrame::Attached {
                seat: seat_num,
                cols: ws.columns,
                rows: ws.rows,
                scrollback_b64: B64.encode(&snap),
            })
            .await
            .is_ok()
        }
        ClientFrame::Input { data_b64 } => {
            let Some((pty, _, _)) = attached.as_ref() else {
                let _ = io
                    .send_frame(&ServerFrame::err(Errno::ENOTCONN, "not attached to a seat"))
                    .await;
                return true;
            };
            let bytes = match B64.decode(&data_b64) {
                Ok(b) => b,
                Err(_) => {
                    let _ = io
                        .send_frame(&ServerFrame::err(Errno::EINVAL, "invalid base64 input"))
                        .await;
                    return true;
                }
            };
            if let Err(e) = pty.write_from_master(&bytes) {
                let _ = io
                    .send_frame(&ServerFrame::err(e, "pty write failed"))
                    .await;
            }
            true
        }
        ClientFrame::Resize { cols, rows } => {
            let Some((pty, _, _)) = attached.as_ref() else {
                let _ = io
                    .send_frame(&ServerFrame::err(Errno::ENOTCONN, "not attached to a seat"))
                    .await;
                return true;
            };
            if let Err(e) = pty.set_winsize(WinSize {
                columns: cols,
                rows,
                width: 0,
                height: 0,
            }) {
                let _ = io.send_frame(&ServerFrame::err(e, "invalid winsize")).await;
            }
            true
        }
        ClientFrame::Detach => {
            if let Some((pty, sub_id, _)) = attached.take() {
                let seat = pty.number;
                pty.unsubscribe(sub_id);
                return io.send_frame(&ServerFrame::Detached { seat }).await.is_ok();
            }
            true
        }
        ClientFrame::Exec {
            argv,
            env,
            cwd,
            stdin_b64,
            timeout_ms,
        } => {
            if !tok.can_exec {
                let _ = io
                    .send_frame(&ServerFrame::err(
                        Errno::EACCES,
                        "token does not have exec permission",
                    ))
                    .await;
                return true;
            }
            let stdin = match stdin_b64 {
                Some(b64) => match B64.decode(&b64) {
                    Ok(b) => b,
                    Err(_) => {
                        let _ = io
                            .send_frame(&ServerFrame::err(Errno::EINVAL, "invalid stdin_b64"))
                            .await;
                        return true;
                    }
                },
                None => Vec::new(),
            };
            let timeout = Duration::from_millis(timeout_ms.unwrap_or(30_000).clamp(100, 300_000));
            match handle
                .host
                .exec_command(tok.uid, argv, env, cwd, stdin, timeout)
                .await
            {
                Ok(out) => io
                    .send_frame(&ServerFrame::ExecResult {
                        exit_code: out.exit_code,
                        signal: out.signal,
                        stdout_b64: B64.encode(&out.stdout),
                        stderr_b64: B64.encode(&out.stderr),
                    })
                    .await
                    .is_ok(),
                Err(e) => io
                    .send_frame(&ServerFrame::err(e, "exec failed"))
                    .await
                    .is_ok(),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Minimal Zero-Dependency RFC-6455 WebSocket Framing + RFC-3174 SHA-1
// ---------------------------------------------------------------------------

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub(crate) fn ws_accept_key(sec_ws_key: &str) -> String {
    let mut input = Vec::with_capacity(sec_ws_key.len() + WS_GUID.len());
    input.extend_from_slice(sec_ws_key.trim().as_bytes());
    input.extend_from_slice(WS_GUID.as_bytes());
    B64.encode(sha1_rfc3174(&input))
}

async fn ws_server_handshake(
    reader: &mut BufReader<DynRead>,
    writer: &mut DynWrite,
) -> Result<(), String> {
    let mut key: Option<String> = None;
    let mut saw_end = false;
    for i in 0..64 {
        let Some(line) = read_bounded_line(reader, WS_HDR_LINE_MAX)
            .await
            .map_err(|e| format!("ws handshake read: {e}"))?
        else {
            return Err("eof during ws handshake".into());
        };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            saw_end = true;
            break;
        }
        if i > 0
            && let Some((k, v)) = trimmed.split_once(':')
            && k.eq_ignore_ascii_case("sec-websocket-key")
        {
            key = Some(v.trim().to_string());
        }
    }
    if !saw_end {
        let _ = writer
            .write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\n\r\n")
            .await;
        return Err("ws handshake header count exceeded".into());
    }
    let Some(key) = key else {
        let _ = writer
            .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
            .await;
        return Err("missing Sec-WebSocket-Key".into());
    };
    let accept = ws_accept_key(&key);
    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    writer
        .write_all(resp.as_bytes())
        .await
        .map_err(|e| format!("ws handshake write: {e}"))?;
    writer.flush().await.map_err(|e| e.to_string())
}

pub(crate) struct WsRawFrame {
    pub fin: bool,
    pub opcode: u8,
    pub payload: Vec<u8>,
}

pub(crate) enum WsEvent {
    Text(String),
    Ping(Vec<u8>),
    Close,
}

pub(crate) async fn ws_read_raw_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    require_masked: bool,
) -> Result<Option<WsRawFrame>, String> {
    let mut hdr = [0u8; 2];
    match reader.read_exact(&mut hdr).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(format!("ws read header: {e}")),
    }
    let fin = (hdr[0] & 0x80) != 0;
    if (hdr[0] & 0x70) != 0 {
        return Err("unsupported ws rsv bits".into());
    }
    let opcode = hdr[0] & 0x0f;
    let masked = (hdr[1] & 0x80) != 0;
    if require_masked && !masked {
        return Err("RFC 6455 violation: unmasked client ws frame".into());
    }
    if !require_masked && masked {
        return Err("RFC 6455 violation: masked server ws frame".into());
    }
    let len_code = hdr[1] & 0x7f;
    let payload_len: usize = match len_code {
        0..=125 => usize::from(len_code),
        126 => {
            let mut b = [0u8; 2];
            reader
                .read_exact(&mut b)
                .await
                .map_err(|e| format!("ws len16: {e}"))?;
            usize::from(u16::from_be_bytes(b))
        }
        127 => {
            let mut b = [0u8; 8];
            reader
                .read_exact(&mut b)
                .await
                .map_err(|e| format!("ws len64: {e}"))?;
            let n = u64::from_be_bytes(b);
            if n > FRAME_TEXT_MAX as u64 {
                return Err("ws frame exceeds 16 MiB".into());
            }
            n as usize
        }
        _ => unreachable!(),
    };
    if opcode >= 0x8 {
        if !fin {
            return Err("RFC 6455 violation: fragmented ws control frame".into());
        }
        if payload_len > 125 {
            return Err("RFC 6455 violation: ws control frame > 125 bytes".into());
        }
    }
    let mut mask = [0u8; 4];
    if masked {
        reader
            .read_exact(&mut mask)
            .await
            .map_err(|e| format!("ws mask: {e}"))?;
    }
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        reader
            .read_exact(&mut payload)
            .await
            .map_err(|e| format!("ws payload: {e}"))?;
        if masked {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i & 3];
            }
        }
    }
    Ok(Some(WsRawFrame {
        fin,
        opcode,
        payload,
    }))
}

pub(crate) async fn ws_read_event<R: AsyncRead + Unpin>(
    reader: &mut R,
    require_masked: bool,
    frag_buf: &mut Option<Vec<u8>>,
) -> Result<Option<WsEvent>, String> {
    loop {
        let Some(frame) = ws_read_raw_frame(reader, require_masked).await? else {
            return Ok(None);
        };
        match frame.opcode {
            0x8 => return Ok(Some(WsEvent::Close)),
            0x9 => return Ok(Some(WsEvent::Ping(frame.payload))),
            0xA => {}
            0x1 => {
                if frag_buf.is_some() {
                    return Err("unexpected ws text frame during fragmented message".into());
                }
                if frame.fin {
                    let text = String::from_utf8(frame.payload)
                        .map_err(|_| "invalid utf-8 in ws text frame".to_string())?;
                    return Ok(Some(WsEvent::Text(text)));
                }
                *frag_buf = Some(frame.payload);
            }
            0x0 => {
                let Some(buf) = frag_buf.as_mut() else {
                    return Err("unexpected ws continuation frame".into());
                };
                if buf.len().saturating_add(frame.payload.len()) > FRAME_TEXT_MAX {
                    return Err("fragmented ws message exceeds 16 MiB".into());
                }
                buf.extend_from_slice(&frame.payload);
                if frame.fin {
                    let assembled = frag_buf.take().unwrap_or_default();
                    let text = String::from_utf8(assembled)
                        .map_err(|_| "invalid utf-8 in fragmented ws text frame".to_string())?;
                    return Ok(Some(WsEvent::Text(text)));
                }
            }
            other => return Err(format!("unsupported ws opcode 0x{other:x}")),
        }
    }
}

pub(crate) async fn ws_write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    opcode: u8,
    payload: &[u8],
    mask_payload: bool,
) -> Result<(), String> {
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(0x80 | (opcode & 0x0f));
    let mask_bit = if mask_payload { 0x80u8 } else { 0u8 };
    if payload.len() <= 125 {
        out.push(mask_bit | (payload.len() as u8));
    } else if payload.len() <= 65535 {
        out.push(mask_bit | 126);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        out.push(mask_bit | 127);
        out.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    if mask_payload {
        let mut mask = [0u8; 4];
        let _ = crate::dev_backend::fill_os_random(&mut mask);
        out.extend_from_slice(&mask);
        for (i, &b) in payload.iter().enumerate() {
            out.push(b ^ mask[i & 3]);
        }
    } else {
        out.extend_from_slice(payload);
    }
    writer
        .write_all(&out)
        .await
        .map_err(|e| format!("ws write: {e}"))?;
    writer.flush().await.map_err(|e| e.to_string())
}

/// Pure-Rust RFC-3174 SHA-1 used strictly for the RFC-6455 `Sec-WebSocket-Accept` header.
fn sha1_rfc3174(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut w = [0u32; 80];
    for chunk in padded.as_chunks::<64>().0 {
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6455_accept_vector() {
        // RFC 6455 Section 1.3 canonical test vector
        assert_eq!(
            ws_accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn bounded_line_and_rfc6455_validation() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            // Oversized line without newline fails immediately with InvalidData.
            let huge = [b'x'; 200];
            let mut r = BufReader::new(&huge[..]);
            let err = read_bounded_line(&mut r, 64).await.unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

            // Unmasked client frame rejected when require_masked=true.
            let unmasked = [0x81u8, 0x02, b'h', b'i'];
            let mut cursor = &unmasked[..];
            assert!(ws_read_raw_frame(&mut cursor, true).await.is_err());

            // Control frame (Ping 0x9) > 125 bytes rejected.
            let mut big_ping = vec![0x89u8, 0x80 | 126, 0x00, 126, 0, 0, 0, 0];
            big_ping.resize(big_ping.len() + 126, b'a');
            let mut cursor = &big_ping[..];
            assert!(ws_read_raw_frame(&mut cursor, true).await.is_err());

            // Fragmented control frame (!fin on Ping) rejected.
            let frag_ping = [0x09u8, 0x80, 0, 0, 0, 0];
            let mut cursor = &frag_ping[..];
            assert!(ws_read_raw_frame(&mut cursor, true).await.is_err());

            // Fragmented text frame with interleaved Ping reassembles cleanly!
            let mut wire = Vec::new();
            // Fragment 1: fin=0, opcode=1, masked=1 (mask=0), payload="hel"
            wire.extend_from_slice(&[0x01, 0x83, 0, 0, 0, 0, b'h', b'e', b'l']);
            // Interleaved Ping: fin=1, opcode=9, masked=1 (mask=0), payload="p"
            wire.extend_from_slice(&[0x89, 0x81, 0, 0, 0, 0, b'p']);
            // Continuation final: fin=1, opcode=0, masked=1 (mask=0), payload="lo"
            wire.extend_from_slice(&[0x80, 0x82, 0, 0, 0, 0, b'l', b'o']);
            let mut cursor = &wire[..];
            let mut frag = None;
            assert!(matches!(
                ws_read_event(&mut cursor, true, &mut frag).await.unwrap(),
                Some(WsEvent::Ping(p)) if p == b"p"
            ));
            assert!(matches!(
                ws_read_event(&mut cursor, true, &mut frag).await.unwrap(),
                Some(WsEvent::Text(s)) if s == "hello"
            ));
        });
    }
}
