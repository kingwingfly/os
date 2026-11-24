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
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UnixListener};
use tokio::sync::{mpsc, watch};

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
                                let transport = FrameTransport::JsonLines {
                                    reader: BufReader::new(Box::new(r)),
                                    writer: Box::new(w),
                                };
                                serve_seat_client(h2, transport).await;
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
    let mut line = String::new();
    while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            line.clear();
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
        line.clear();
    }
}

// ---------------------------------------------------------------------------
// Dual-mode Transport: Newline-Delimited JSON OR RFC-6455 WebSocket
// ---------------------------------------------------------------------------

type DynRead = Box<dyn AsyncRead + Unpin + Send>;
type DynWrite = Box<dyn AsyncWrite + Unpin + Send>;

enum FrameTransport {
    JsonLines {
        reader: BufReader<DynRead>,
        writer: DynWrite,
    },
    WebSocket {
        reader: BufReader<DynRead>,
        writer: DynWrite,
    },
}

impl FrameTransport {
    async fn recv_text(&mut self) -> Result<Option<String>, String> {
        match self {
            Self::JsonLines { reader, .. } => {
                let mut line = String::new();
                loop {
                    line.clear();
                    let n = reader
                        .read_line(&mut line)
                        .await
                        .map_err(|e| format!("read error: {e}"))?;
                    if n == 0 {
                        return Ok(None);
                    }
                    let t = line.trim();
                    if !t.is_empty() {
                        return Ok(Some(t.to_string()));
                    }
                }
            }
            Self::WebSocket { reader, writer } => loop {
                let Some((opcode, payload)) = ws_read_frame(reader).await? else {
                    return Ok(None);
                };
                match opcode {
                    0x1 => {
                        let text = String::from_utf8(payload)
                            .map_err(|_| "invalid utf-8 in ws text frame".to_string())?;
                        return Ok(Some(text));
                    }
                    0x8 => {
                        let _ = ws_write_frame(writer, 0x8, &[], false).await;
                        return Ok(None);
                    }
                    0x9 => {
                        // Ping -> Pong
                        let _ = ws_write_frame(writer, 0xA, &payload, false).await;
                    }
                    0xA => {} // Pong
                    _ => return Err(format!("unsupported ws opcode 0x{opcode:x}")),
                }
            },
        }
    }

    async fn send_frame(&mut self, frame: &ServerFrame) -> Result<(), String> {
        let json = serde_json::to_string(frame).map_err(|e| format!("serialize frame: {e}"))?;
        match self {
            Self::JsonLines { writer, .. } => {
                writer
                    .write_all(json.as_bytes())
                    .await
                    .map_err(|e| e.to_string())?;
                writer.write_all(b"\n").await.map_err(|e| e.to_string())?;
                writer.flush().await.map_err(|e| e.to_string())
            }
            Self::WebSocket { writer, .. } => {
                ws_write_frame(writer, 0x1, json.as_bytes(), false).await
            }
        }
    }

    async fn close_graceful(&mut self) {
        if let Self::WebSocket { writer, .. } = self {
            let _ = ws_write_frame(writer, 0x8, &[], false).await;
        }
    }
}

async fn serve_tcp_or_ws(handle: Arc<SeatServerHandle>, stream: TcpStream) {
    let _ = stream.set_nodelay(true);
    let mut peek = [0u8; 4];
    let n = match tokio::time::timeout(Duration::from_secs(5), stream.peek(&mut peek)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return,
    };
    let is_http_ws = n >= 4 && &peek == b"GET ";
    let (r, w) = tokio::io::split(stream);
    let mut reader: BufReader<DynRead> = BufReader::new(Box::new(r));
    let mut writer: DynWrite = Box::new(w);

    let transport = if is_http_ws {
        match ws_server_handshake(&mut reader, &mut writer).await {
            Ok(()) => FrameTransport::WebSocket { reader, writer },
            Err(_) => return,
        }
    } else {
        FrameTransport::JsonLines { reader, writer }
    };

    serve_seat_client(handle, transport).await;
}

async fn serve_seat_client(handle: Arc<SeatServerHandle>, mut io: FrameTransport) {
    // 1. Mandatory `HostAdapter v2` Hello negotiation (`EPROTONOSUPPORT` on mismatch).
    let hello_text = match tokio::time::timeout(Duration::from_secs(10), io.recv_text()).await {
        Ok(Ok(Some(t))) => t,
        _ => return,
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
        return;
    }

    // 2. Mandatory token authentication (`EACCES` on missing/invalid/expired/revoked token).
    let auth_text = match tokio::time::timeout(Duration::from_secs(10), io.recv_text()).await {
        Ok(Ok(Some(t))) => t,
        _ => return,
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
        return;
    }

    // 3. Authenticated session loop (supports attach/input/resize/detach, exec, list_seats, inspect,
    //    plus immediate live revocation interrupt!).
    let mut attached: Option<(Arc<PtyInstance>, u64, mpsc::UnboundedReceiver<Vec<u8>>)> = None;

    loop {
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
                chunk = out_rx.recv() => {
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
                frame_res = io.recv_text() => {
                    let Ok(Some(text)) = frame_res else {
                        pty.unsubscribe(sub_id);
                        break;
                    };
                    if !handle_authed_frame(&handle, &tok, &mut io, &mut attached, &text).await {
                        if let Some((p, sid, _)) = attached.take() {
                            p.unsubscribe(sid);
                        }
                        break;
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
                frame_res = io.recv_text() => {
                    let Ok(Some(text)) = frame_res else {
                        break;
                    };
                    if !handle_authed_frame(&handle, &tok, &mut io, &mut attached, &text).await {
                        break;
                    }
                }
            }
        }
    }

    if let Some((p, sid, _)) = attached.take() {
        p.unsubscribe(sid);
    }
    handle.sessions.lock().unwrap().unregister(&tok.id, conn_id);
}

type AttachedPty = (Arc<PtyInstance>, u64, mpsc::UnboundedReceiver<Vec<u8>>);

async fn handle_authed_frame(
    handle: &Arc<SeatServerHandle>,
    tok: &TokenRecord,
    io: &mut FrameTransport,
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
            let target_seat = seat.unwrap_or(0);
            if !tok.permits_seat(target_seat) {
                let _ = io
                    .send_frame(&ServerFrame::err(
                        Errno::EACCES,
                        format!("token does not allow attaching to seat {target_seat}"),
                    ))
                    .await;
                return true;
            }
            if let Some((old_pty, old_sub, _)) = attached.take() {
                old_pty.unsubscribe(old_sub);
            }
            let pty = match handle.host.kernel.ptys.get(target_seat) {
                Some(p) => p,
                None if spawn_if_missing => {
                    let p = handle.host.kernel.ptys.allocate(false);
                    if let Err(e) = handle.host.spawn_shell_on_pty(&p, tok.uid, None) {
                        let _ = io
                            .send_frame(&ServerFrame::err(e, "failed to spawn shell on new seat"))
                            .await;
                        return true;
                    }
                    p
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
    let mut line = String::new();
    for i in 0..64 {
        line.clear();
        let n = reader
            .read_line(&mut line)
            .await
            .map_err(|e| format!("ws handshake read: {e}"))?;
        if n == 0 {
            return Err("eof during ws handshake".into());
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if i > 0
            && let Some((k, v)) = trimmed.split_once(':')
            && k.eq_ignore_ascii_case("sec-websocket-key")
        {
            key = Some(v.trim().to_string());
        }
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

pub(crate) async fn ws_read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<(u8, Vec<u8>)>, String> {
    let mut hdr = [0u8; 2];
    match reader.read_exact(&mut hdr).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(format!("ws read header: {e}")),
    }
    let opcode = hdr[0] & 0x0f;
    let masked = (hdr[1] & 0x80) != 0;
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
            if n > 16 * 1024 * 1024 {
                return Err("ws frame exceeds 16 MiB".into());
            }
            n as usize
        }
        _ => unreachable!(),
    };
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
    Ok(Some((opcode, payload)))
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
}
