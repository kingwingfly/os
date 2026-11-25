//! Remote seat/PTY client (`os-native attach`, `os-native exec`, and `$STATE/host-ctl.sock`
//! client for `os-native token create|list|revoke` & `os-native inspect`).

use crate::dev_backend::random_hex;
use crate::seat_proto::{
    ClientFrame, ControlReply, ControlRequest, ServerFrame, TokenStore, server_hello,
};
use crate::seat_server::{
    FRAME_TEXT_MAX, WS_HDR_LINE_MAX, WsEvent, read_bounded_line, ws_accept_key, ws_read_event,
    ws_write_frame,
};
use abi::contract::{Boundary, HOST_ADAPTER_VERSION};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use std::path::Path;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UnixStream};
use tokio::sync::mpsc;

type DynRead = Box<dyn AsyncRead + Unpin + Send>;
type DynWrite = Box<dyn AsyncWrite + Unpin + Send>;

enum ClientWriter {
    JsonLines(DynWrite),
    WebSocket(DynWrite),
}

enum ClientRecvEvent {
    Text(String),
    Ping(Vec<u8>),
    Closed,
    Err(String),
}

fn spawn_client_reader(
    mut reader: BufReader<DynRead>,
    is_ws: bool,
) -> (mpsc::Receiver<ClientRecvEvent>, tokio::task::JoinHandle<()>) {
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
                        if tx.send(ClientRecvEvent::Text(t.to_string())).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => {
                        let _ = tx.send(ClientRecvEvent::Closed).await;
                        break;
                    }
                    Err(e) => {
                        let _ = tx
                            .send(ClientRecvEvent::Err(format!("read error: {e}")))
                            .await;
                        break;
                    }
                }
            }
        } else {
            let mut frag_buf: Option<Vec<u8>> = None;
            loop {
                match ws_read_event(&mut reader, false, &mut frag_buf).await {
                    Ok(Some(WsEvent::Text(t))) => {
                        if tx.send(ClientRecvEvent::Text(t)).await.is_err() {
                            break;
                        }
                    }
                    Ok(Some(WsEvent::Ping(p))) => {
                        if tx.send(ClientRecvEvent::Ping(p)).await.is_err() {
                            break;
                        }
                    }
                    Ok(Some(WsEvent::Close)) | Ok(None) => {
                        let _ = tx.send(ClientRecvEvent::Closed).await;
                        break;
                    }
                    Err(e) => {
                        let _ = tx.send(ClientRecvEvent::Err(e)).await;
                        break;
                    }
                }
            }
        }
    });
    (rx, task)
}

/// Async client speaking `HostAdapter v2` over Unix socket, raw TCP, or RFC-6455 WebSocket.
pub struct SeatClient {
    rx: mpsc::Receiver<ClientRecvEvent>,
    writer: ClientWriter,
    reader_task: tokio::task::JoinHandle<()>,
}

impl Drop for SeatClient {
    fn drop(&mut self) {
        self.reader_task.abort();
    }
}

impl SeatClient {
    /// Connect to `unix:///path`, `tcp://host:port`, `ws://host:port[/path]`, or a bare socket path.
    pub async fn connect(target: &str) -> Result<Self, String> {
        if let Some(rest) = target.strip_prefix("ws://") {
            let (host_port, path) = match rest.split_once('/') {
                Some((hp, p)) => (hp, format!("/{p}")),
                None => (rest, "/".to_string()),
            };
            let stream = TcpStream::connect(host_port)
                .await
                .map_err(|e| format!("connect ws://{host_port}: {e}"))?;
            let _ = stream.set_nodelay(true);
            let (r, w) = tokio::io::split(stream);
            let mut reader: BufReader<DynRead> = BufReader::new(Box::new(r));
            let mut writer: DynWrite = Box::new(w);
            let key = B64.encode(random_hex(8).as_bytes());
            let req = format!(
                "GET {path} HTTP/1.1\r\n\
                 Host: {host_port}\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Key: {key}\r\n\
                 Sec-WebSocket-Version: 13\r\n\r\n"
            );
            writer
                .write_all(req.as_bytes())
                .await
                .map_err(|e| format!("ws req write: {e}"))?;
            writer.flush().await.map_err(|e| e.to_string())?;

            let mut status_ok = false;
            let mut accept_ok = false;
            let mut saw_end = false;
            let expected_accept = ws_accept_key(&key);
            for i in 0..64 {
                let Some(line) = read_bounded_line(&mut reader, WS_HDR_LINE_MAX)
                    .await
                    .map_err(|e| format!("ws resp read: {e}"))?
                else {
                    return Err("unexpected eof in ws response".into());
                };
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    saw_end = true;
                    break;
                }
                if i == 0 && trimmed.contains("101") {
                    status_ok = true;
                } else if let Some((k, v)) = trimmed.split_once(':')
                    && k.eq_ignore_ascii_case("sec-websocket-accept")
                    && v.trim() == expected_accept
                {
                    accept_ok = true;
                }
            }
            if !saw_end || !status_ok || !accept_ok {
                return Err("websocket upgrade rejected by server".into());
            }
            let (rx, reader_task) = spawn_client_reader(reader, true);
            Ok(Self {
                rx,
                writer: ClientWriter::WebSocket(writer),
                reader_task,
            })
        } else if let Some(addr) = target.strip_prefix("tcp://") {
            let stream = TcpStream::connect(addr)
                .await
                .map_err(|e| format!("connect tcp://{addr}: {e}"))?;
            let _ = stream.set_nodelay(true);
            let (r, w) = tokio::io::split(stream);
            let (rx, reader_task) = spawn_client_reader(BufReader::new(Box::new(r)), false);
            Ok(Self {
                rx,
                writer: ClientWriter::JsonLines(Box::new(w)),
                reader_task,
            })
        } else {
            let path = target.strip_prefix("unix://").unwrap_or(target);
            let stream = UnixStream::connect(path)
                .await
                .map_err(|e| format!("connect unix://{path}: {e}"))?;
            let (r, w) = tokio::io::split(stream);
            let (rx, reader_task) = spawn_client_reader(BufReader::new(Box::new(r)), false);
            Ok(Self {
                rx,
                writer: ClientWriter::JsonLines(Box::new(w)),
                reader_task,
            })
        }
    }

    pub async fn send(&mut self, frame: &ClientFrame) -> Result<(), String> {
        let json = serde_json::to_string(frame).map_err(|e| e.to_string())?;
        match &mut self.writer {
            ClientWriter::JsonLines(writer) => {
                writer
                    .write_all(json.as_bytes())
                    .await
                    .map_err(|e| e.to_string())?;
                writer.write_all(b"\n").await.map_err(|e| e.to_string())?;
                writer.flush().await.map_err(|e| e.to_string())
            }
            ClientWriter::WebSocket(writer) => {
                ws_write_frame(writer, 0x1, json.as_bytes(), true).await
            }
        }
    }

    /// Cancel-safe receive of the next `ServerFrame`.
    pub async fn recv(&mut self) -> Result<Option<ServerFrame>, String> {
        loop {
            match self.rx.recv().await {
                Some(ClientRecvEvent::Text(text)) => {
                    let frame: ServerFrame = serde_json::from_str(&text)
                        .map_err(|e| format!("parse server frame: {e}"))?;
                    return Ok(Some(frame));
                }
                Some(ClientRecvEvent::Ping(payload)) => {
                    if let ClientWriter::WebSocket(writer) = &mut self.writer {
                        let _ = ws_write_frame(writer, 0xA, &payload, true).await;
                    }
                }
                Some(ClientRecvEvent::Closed) | None => return Ok(None),
                Some(ClientRecvEvent::Err(e)) => return Err(e),
            }
        }
    }

    /// Perform standard `HostAdapter v2` handshake + bearer token authentication.
    pub async fn handshake_and_auth(&mut self, token: &str) -> Result<ServerFrame, String> {
        let hello = server_hello();
        self.send(&ClientFrame::Hello {
            boundary: hello.boundary,
            versions: hello.versions,
        })
        .await?;
        match self.recv().await? {
            Some(ServerFrame::HelloOk {
                boundary: Boundary::HostAdapter,
                version: HOST_ADAPTER_VERSION,
                ..
            }) => {}
            Some(ServerFrame::Error { errno, message, .. }) => {
                return Err(format!("{errno}: {message}"));
            }
            other => return Err(format!("unexpected hello reply: {other:?}")),
        }
        self.send(&ClientFrame::Auth {
            token: token.to_string(),
        })
        .await?;
        match self.recv().await? {
            Some(ok @ ServerFrame::AuthOk { .. }) => Ok(ok),
            Some(ServerFrame::Error { errno, message, .. }) => Err(format!("{errno}: {message}")),
            other => Err(format!("unexpected auth reply: {other:?}")),
        }
    }

    /// Send input bytes to the currently attached PTY seat.
    pub async fn send_input(&mut self, data: &[u8]) -> Result<(), String> {
        self.send(&ClientFrame::Input {
            data_b64: B64.encode(data),
        })
        .await
    }

    /// Resize the currently attached PTY seat.
    pub async fn send_resize(&mut self, cols: u16, rows: u16) -> Result<(), String> {
        self.send(&ClientFrame::Resize { cols, rows }).await
    }
}

/// Send a control request to a live `$STATE/host-ctl.sock` if present, or fall back to offline
/// `$STATE/seat-tokens.json` when the OS daemon is not currently running.
pub async fn send_control_request(
    state_dir: &Path,
    req: ControlRequest,
) -> Result<ControlReply, String> {
    let sock_path = state_dir.join("host-ctl.sock");
    if sock_path.exists()
        && let Ok(stream) = UnixStream::connect(&sock_path).await
    {
        let (r, mut w) = tokio::io::split(stream);
        let mut line = serde_json::to_string(&req).map_err(|e| e.to_string())?;
        line.push('\n');
        w.write_all(line.as_bytes())
            .await
            .map_err(|e| format!("write host-ctl.sock: {e}"))?;
        w.flush().await.map_err(|e| e.to_string())?;
        let mut reader = BufReader::new(r);
        let Some(resp) = read_bounded_line(&mut reader, 1024 * 1024)
            .await
            .map_err(|e| format!("read host-ctl.sock: {e}"))?
        else {
            return Err("host-ctl.sock closed without reply".into());
        };
        return serde_json::from_str::<ControlReply>(resp.trim())
            .map_err(|e| format!("parse control reply: {e}"));
    }

    // Offline fallback for token operations when daemon is not running.
    let store = TokenStore::new(state_dir);
    match req {
        ControlRequest::CreateToken {
            uid,
            label,
            allowed_seats,
            can_exec,
            ttl_secs,
        } => {
            let (record, token) =
                store.create_token(uid, label, allowed_seats, can_exec, ttl_secs)?;
            Ok(ControlReply::TokenCreated { record, token })
        }
        ControlRequest::ListTokens => Ok(ControlReply::Tokens {
            tokens: store.list_tokens()?,
        }),
        ControlRequest::RevokeToken { id_or_prefix } => {
            let token_ids = store.revoke_token(&id_or_prefix)?;
            Ok(ControlReply::Revoked {
                token_ids,
                disconnected_clients: 0,
            })
        }
        ControlRequest::Inspect => Err(format!(
            "no running os-native daemon found at {}",
            sock_path.display()
        )),
    }
}

/// Interactive CLI `os-native attach` loop forwarding stdin -> seat and seat output -> stdout.
pub async fn run_attach_cli(
    target: &str,
    token: &str,
    seat: Option<u32>,
    spawn_if_missing: bool,
) -> Result<i32, String> {
    let mut client = SeatClient::connect(target).await?;
    client.handshake_and_auth(token).await?;

    let (cols, rows) = terminal_size().unwrap_or((80, 24));
    client
        .send(&ClientFrame::Attach {
            seat,
            spawn_if_missing,
            cols: Some(cols),
            rows: Some(rows),
        })
        .await?;

    let attached_frame = client
        .recv()
        .await?
        .ok_or_else(|| "connection closed before attach reply".to_string())?;
    match attached_frame {
        ServerFrame::Attached { scrollback_b64, .. } => {
            if let Ok(bytes) = B64.decode(&scrollback_b64)
                && !bytes.is_empty()
            {
                use std::io::Write;
                let _ = std::io::stdout().write_all(&bytes);
                let _ = std::io::stdout().flush();
            }
        }
        ServerFrame::Error { errno, message, .. } => {
            return Err(format!("{errno}: {message}"));
        }
        other => return Err(format!("unexpected attach reply: {other:?}")),
    }

    let _raw_guard = RawTerminalGuard::enter_if_tty();

    let (in_tx, mut in_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    std::thread::spawn(move || {
        use std::io::Read;
        let mut stdin = std::io::stdin().lock();
        let mut buf = [0u8; 4096];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if in_tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });

    let mut exit_code = 0i32;
    loop {
        tokio::select! {
            maybe_in = in_rx.recv() => {
                match maybe_in {
                    Some(bytes) => {
                        // Ctrl-] (0x1d) detaches cleanly in interactive mode.
                        if bytes.len() == 1 && bytes[0] == 0x1d {
                            let _ = client.send(&ClientFrame::Detach).await;
                            break;
                        }
                        if client.send_input(&bytes).await.is_err() {
                            break;
                        }
                    }
                    None => {
                        let _ = client.send(&ClientFrame::Detach).await;
                        break;
                    }
                }
            }
            frame = client.recv() => {
                match frame {
                    Ok(Some(ServerFrame::Output { data_b64, .. })) => {
                        if let Ok(bytes) = B64.decode(&data_b64) {
                            use std::io::Write;
                            let _ = std::io::stdout().write_all(&bytes);
                            let _ = std::io::stdout().flush();
                        }
                    }
                    Ok(Some(ServerFrame::Detached { .. })) | Ok(None) => break,
                    Ok(Some(ServerFrame::Error { errno, message, .. })) => {
                        eprintln!("\r\nos-native attach: {errno}: {message}");
                        exit_code = 1;
                        break;
                    }
                    Ok(Some(_)) => {}
                    Err(e) => {
                        eprintln!("\r\nos-native attach: {e}");
                        exit_code = 1;
                        break;
                    }
                }
            }
        }
    }

    Ok(exit_code)
}

/// Non-interactive CLI `os-native exec` over `HostAdapter v2`.
pub async fn run_exec_cli(
    target: &str,
    token: &str,
    argv: Vec<String>,
    cwd: Option<String>,
    timeout_ms: Option<u64>,
) -> Result<i32, String> {
    let mut client = SeatClient::connect(target).await?;
    client.handshake_and_auth(token).await?;
    client
        .send(&ClientFrame::Exec {
            argv,
            env: Vec::new(),
            cwd,
            stdin_b64: None,
            timeout_ms,
        })
        .await?;
    match client.recv().await? {
        Some(ServerFrame::ExecResult {
            exit_code,
            stdout_b64,
            stderr_b64,
            ..
        }) => {
            use std::io::Write;
            if let Ok(out) = B64.decode(&stdout_b64) {
                let _ = std::io::stdout().write_all(&out);
                let _ = std::io::stdout().flush();
            }
            if let Ok(err) = B64.decode(&stderr_b64) {
                let _ = std::io::stderr().write_all(&err);
                let _ = std::io::stderr().flush();
            }
            Ok(exit_code)
        }
        Some(ServerFrame::Error { errno, message, .. }) => Err(format!("{errno}: {message}")),
        other => Err(format!("unexpected exec reply: {other:?}")),
    }
}

fn terminal_size() -> Option<(u16, u16)> {
    let mut ws = libc::winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let rc = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) };
    if rc == 0 && ws.ws_col > 0 && ws.ws_row > 0 {
        Some((ws.ws_col, ws.ws_row))
    } else {
        None
    }
}

struct RawTerminalGuard {
    orig: Option<libc::termios>,
}

impl RawTerminalGuard {
    fn enter_if_tty() -> Self {
        unsafe {
            if libc::isatty(libc::STDIN_FILENO) != 1 {
                return Self { orig: None };
            }
            let mut orig: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(libc::STDIN_FILENO, &mut orig) != 0 {
                return Self { orig: None };
            }
            let mut raw = orig;
            libc::cfmakeraw(&mut raw);
            let _ = libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw);
            Self { orig: Some(orig) }
        }
    }
}

impl Drop for RawTerminalGuard {
    fn drop(&mut self) {
        if let Some(orig) = self.orig.take() {
            unsafe {
                let _ = libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &orig);
            }
        }
    }
}
