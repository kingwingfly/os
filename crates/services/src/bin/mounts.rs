//! `/usr/bin/mounts`: ordinary unprivileged GUI Mounts Manager process (`#63` `L6b-2`).
//!
//! Connects to `/run/gui/seat0.sock` over `AF_UNIX`, renders inside a sealed Document surface
//! (`/usr/share/gui/mounts/mounts.json`), talks directly to `mountd` and `exportd` over
//! `AF_UNIX` with its own process `SO_PEERCRED` (including `SCM_RIGHTS` directory fd passing
//! for `ExportRequest::Publish`), inspects mount modes/manifests via POSIX syscalls, enforces
//! single-instance IPC over `/run/user/<uid>/mounts.sock`, and requests host-only browser
//! capability grants (`showDirectoryPicker`, OPFS, helper, share) through compositor-gated
//! `ClientReq::MountConsent`. Imports ZERO `gui_*` Wasm functions.

use std::collections::{BTreeMap, VecDeque};
use std::fs::File;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[cfg(not(target_os = "wasi"))]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(target_os = "wasi")]
use std::os::wasi::io::{AsRawFd, FromRawFd};

use abi::export_ctl::{
    CONTROL_MAX, ExportRequest, ExportResponse, SYSTEM_EXPORT_SOCK, TransportKind, decode_control,
    encode_control, user_export_sock,
};
use abi::gui::{
    ClientEvent, ClientReq, DocumentSource, MOUNTS_BUNDLE, MountConsentAction, Rect, SOCKET, Size,
    SurfaceId, SurfaceKind, SurfaceRole, SurfaceSpec, TransferItem, frame, sha256_hex, take_frame,
};
use abi::mount_ctl::{
    MountErrorKind, MountRequest, MountResponse, SYSTEM_MOUNT_SOCK, decode_frame, encode_frame,
    read_frame, user_mount_sock, write_frame,
};
use abi::socket::{MSG_DONTWAIT, MSG_NOSIGNAL, SHUT_WR, SOCK_CLOEXEC, SOCK_NONBLOCK};
use abi::{Call, Errno, Stat};
use os_posix::process::getuid;
use os_posix::socket::{UnixListener, UnixStream};
use os_services::gui_doc::{DocChunkAssembler, chunk_document_message};
use os_services::mounts::{
    ConsentFollowUp, MountsControlReply, MountsControlReq, MountsCore, MountsHostMsg, MountsTab,
    MountsUiMsg, PendingConsentAttach, export_error_message, export_source_path,
    format_busy_processes, mount_flags_for, mount_target_path, valid_mount_name,
};
use serde_json::{Value, json};

const MAX_CONTROL_LINE_BYTES: usize = 8192;
const MAX_CONTROL_PEERS_PER_TICK: usize = 16;

static STOP: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "wasi")]
#[unsafe(no_mangle)]
pub extern "C" fn __mounts_signal(sig: u32) {
    if matches!(sig, 1 | 2 | 15) {
        STOP.store(true, Ordering::SeqCst);
    }
}

fn install_signals() {
    #[cfg(target_os = "wasi")]
    {
        #[link(wasm_import_module = "wasix_32v1")]
        unsafe extern "C" {
            fn callback_signal(name: *const u8, len: usize);
        }
        #[link(wasm_import_module = "os")]
        unsafe extern "C" {
            fn sigaction(signal: u32, kind: u32, mask: u32, flags: u32) -> i32;
        }
        let name = b"__mounts_signal";
        // SAFETY: valid static callback name and scalar signal numbers.
        // Always set SA_RESTART (0x10000000) so `std::thread::sleep` on wasm32-wasip1
        // never panics on EINTR while STOP is checked in the main event loop.
        unsafe {
            callback_signal(name.as_ptr(), name.len());
            let _ = sigaction(13, 2, 0, 0x10000000); // SIGPIPE
            for sig in [1, 2, 15] {
                let _ = sigaction(sig, 2, 0, 0x10000000);
            }
        }
    }
}

fn poll_fds(read_fds: &[u32], write_fds: &[u32], timeout_ms: u64) {
    #[cfg(target_os = "wasi")]
    {
        #[link(wasm_import_module = "wasi_snapshot_preview1")]
        unsafe extern "C" {
            fn poll_oneoff(
                input: *const u8,
                output: *mut u8,
                count: usize,
                events: *mut usize,
            ) -> u32;
        }
        let total = read_fds.len() + write_fds.len() + 1;
        let mut input = vec![0u64; total * 6];
        let mut output = vec![0u64; total * 4];
        let in_bytes: &mut [u8] =
            unsafe { std::slice::from_raw_parts_mut(input.as_mut_ptr().cast::<u8>(), total * 48) };
        let mut idx = 0usize;
        for &fd in read_fds {
            let at = idx * 48;
            in_bytes[at..at + 8].copy_from_slice(&(idx as u64).to_le_bytes());
            in_bytes[at + 8] = 1; // fd_read
            in_bytes[at + 16..at + 20].copy_from_slice(&fd.to_le_bytes());
            idx += 1;
        }
        for &fd in write_fds {
            let at = idx * 48;
            in_bytes[at..at + 8].copy_from_slice(&(idx as u64).to_le_bytes());
            in_bytes[at + 8] = 2; // fd_write
            in_bytes[at + 16..at + 20].copy_from_slice(&fd.to_le_bytes());
            idx += 1;
        }
        let at = idx * 48;
        in_bytes[at..at + 8].copy_from_slice(&(idx as u64).to_le_bytes());
        in_bytes[at + 8] = 0; // clock
        in_bytes[at + 16..at + 20].copy_from_slice(&1u32.to_le_bytes());
        in_bytes[at + 24..at + 32].copy_from_slice(&(timeout_ms * 1_000_000).to_le_bytes());
        let mut events = 0usize;
        // SAFETY: aligned buffers sized for `total` subscriptions/events.
        let _ = unsafe {
            poll_oneoff(
                in_bytes.as_ptr(),
                output.as_mut_ptr().cast::<u8>(),
                total,
                &mut events,
            )
        };
    }
    #[cfg(not(target_os = "wasi"))]
    {
        let _ = (read_fds, write_fds);
        std::thread::sleep(Duration::from_millis(timeout_ms));
    }
}

struct SeatConn {
    socket: UnixStream,
    in_buf: Vec<u8>,
    out_queue: VecDeque<(Vec<u8>, usize)>,
}

impl SeatConn {
    fn connect() -> Result<Self, Errno> {
        let mut attempts = 0;
        let socket = loop {
            match UnixStream::connect(SOCKET) {
                Ok(s) => break s,
                Err(Errno::ENOENT | Errno::ECONNREFUSED) if attempts < 250 => {
                    attempts += 1;
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => return Err(e),
            }
        };
        Ok(Self {
            socket,
            in_buf: Vec::new(),
            out_queue: VecDeque::new(),
        })
    }

    fn send_blocking(&mut self, req: &ClientReq) -> Result<(), Errno> {
        let bytes = frame(req)?;
        let mut off = 0;
        while off < bytes.len() {
            match self.socket.send(&bytes[off..], MSG_NOSIGNAL) {
                Ok(0) => return Err(Errno::EPIPE),
                Ok(n) => off += n,
                Err(Errno::EAGAIN | Errno::EINTR) => std::thread::sleep(Duration::from_millis(5)),
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn recv_blocking(&mut self) -> Result<ClientEvent, Errno> {
        loop {
            if let Some(ev) = take_frame(&mut self.in_buf)? {
                return Ok(ev);
            }
            let mut chunk = [0u8; 4096];
            match self.socket.recv(&mut chunk, 0) {
                Ok(0) => return Err(Errno::EPIPE),
                Ok(n) => self.in_buf.extend_from_slice(&chunk[..n]),
                Err(Errno::EINTR | Errno::EAGAIN) => std::thread::sleep(Duration::from_millis(5)),
                Err(e) => return Err(e),
            }
        }
    }

    fn queue(&mut self, req: &ClientReq) -> Result<(), Errno> {
        let bytes = frame(req)?;
        self.out_queue.push_back((bytes, 0));
        self.flush()
    }

    fn has_pending_writes(&self) -> bool {
        !self.out_queue.is_empty()
    }

    fn flush(&mut self) -> Result<(), Errno> {
        while let Some((bytes, off)) = self.out_queue.front_mut() {
            match self
                .socket
                .send(&bytes[*off..], MSG_NOSIGNAL | MSG_DONTWAIT)
            {
                Ok(0) => return Err(Errno::EPIPE),
                Ok(n) => {
                    *off += n;
                    if *off >= bytes.len() {
                        self.out_queue.pop_front();
                    }
                }
                Err(Errno::EAGAIN | Errno::EINTR) => break,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn drain_events(&mut self) -> Result<Vec<ClientEvent>, Errno> {
        let mut chunk = [0u8; 8192];
        loop {
            match self.socket.recv(&mut chunk, MSG_DONTWAIT) {
                Ok(0) => return Err(Errno::EPIPE),
                Ok(n) => self.in_buf.extend_from_slice(&chunk[..n]),
                Err(Errno::EAGAIN | Errno::EINTR) => break,
                Err(e) => return Err(e),
            }
        }
        let mut events = Vec::new();
        while let Some(ev) = take_frame(&mut self.in_buf)? {
            events.push(ev);
        }
        Ok(events)
    }

    fn fd(&self) -> u32 {
        self.socket.as_raw_fd()
    }
}

fn lstat_path(path: &str) -> io::Result<Stat> {
    let reply = os_posix::batch(&[Call::Lstat {
        path: path.to_owned(),
    }])?;
    let val = reply
        .results
        .into_iter()
        .next()
        .ok_or_else(|| io::Error::other("empty lstat reply"))?
        .into_result()
        .map_err(|e| io::Error::other(e.to_string()))?;
    serde_json::from_value::<Stat>(val).map_err(|e| io::Error::other(e.to_string()))
}

fn send_all(stream: &UnixStream, bytes: &[u8]) -> Result<(), Errno> {
    let mut off = 0;
    while off < bytes.len() {
        match stream.send(&bytes[off..], MSG_NOSIGNAL) {
            Ok(0) => return Err(Errno::EPIPE),
            Ok(n) => off += n,
            Err(Errno::EAGAIN | Errno::EINTR) => std::thread::sleep(Duration::from_millis(5)),
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn read_json_line(stream: &UnixStream, timeout_ms: u64) -> Result<Value, String> {
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    while Instant::now() < deadline {
        if let Some(nl) = raw.iter().position(|&b| b == b'\n') {
            return serde_json::from_slice(&raw[..nl]).map_err(|e| e.to_string());
        }
        match stream.recv(&mut buf, MSG_DONTWAIT) {
            Ok(0) => break,
            Ok(n) => {
                if raw.len() + n > 65_536 {
                    return Err("reply too large".into());
                }
                raw.extend_from_slice(&buf[..n]);
            }
            Err(Errno::EAGAIN | Errno::EINTR) => std::thread::sleep(Duration::from_millis(5)),
            Err(e) => return Err(e.text().to_owned()),
        }
    }
    if !raw.is_empty() {
        serde_json::from_slice(&raw).map_err(|e| e.to_string())
    } else {
        Err("timed out waiting for reply".into())
    }
}

fn send_user_socket_rpc(
    uid: u32,
    sock_path: &str,
    payload: &Value,
    timeout_ms: u64,
) -> Result<Value, Errno> {
    let stream = UnixStream::connect(sock_path)?;
    let peer = stream.peer_cred()?;
    if peer.uid != uid {
        return Err(Errno::EACCES);
    }
    let mut bytes = serde_json::to_vec(payload).map_err(|_| Errno::EINVAL)?;
    bytes.push(b'\n');
    send_all(&stream, &bytes)?;
    read_json_line(&stream, timeout_ms).map_err(|_| Errno::EIO)
}

fn send_desktop_action(uid: u32, payload: &Value) -> Result<(), String> {
    let path = format!("/run/user/{uid}/desktop-actions.sock");
    let reply = send_user_socket_rpc(uid, &path, payload, 10_000).map_err(|e| match e {
        Errno::ENOENT | Errno::ECONNREFUSED => "desktop session unavailable".to_owned(),
        other => other.text().to_owned(),
    })?;
    let status = reply.get("status").and_then(Value::as_i64).unwrap_or(0);
    if status != 0 {
        let stderr = reply
            .get("stderr")
            .and_then(Value::as_str)
            .unwrap_or("Operation failed")
            .trim()
            .to_owned();
        return Err(if stderr.is_empty() {
            "Operation failed".to_owned()
        } else {
            stderr
        });
    }
    Ok(())
}

fn try_forward_to_existing(uid: u32, tab: Option<&str>) -> Result<bool, Errno> {
    let sock_path = format!("/run/user/{uid}/mounts.sock");
    let stream = match UnixStream::connect(&sock_path) {
        Ok(s) => s,
        Err(Errno::ENOENT | Errno::ECONNREFUSED) => return Ok(false),
        Err(e) => return Err(e),
    };
    let peer = stream.peer_cred()?;
    if peer.uid != uid {
        return Err(Errno::EACCES);
    }
    let req = MountsControlReq::Focus {
        tab: tab.map(str::to_owned),
    };
    let mut bytes = serde_json::to_vec(&req).map_err(|_| Errno::EINVAL)?;
    bytes.push(b'\n');
    send_all(&stream, &bytes)?;
    let _ = read_json_line(&stream, 2_000);
    let _ = send_desktop_action(uid, &json!({ "op": "focus_app", "app_id": "mounts" }));
    Ok(true)
}

fn bind_control_socket(uid: u32) -> (Option<UnixListener>, Option<String>, Option<u64>) {
    let dir = format!("/run/user/{uid}");
    if std::fs::create_dir_all(&dir).is_err() {
        return (None, None, None);
    }
    let Ok(dir_st) = lstat_path(&dir) else {
        return (None, None, None);
    };
    if (dir_st.mode & abi::S_IFMT) != abi::S_IFDIR || dir_st.uid != uid {
        return (None, None, None);
    }
    if (dir_st.mode & 0o7777) != 0o700 {
        if os_posix::chmod(Path::new(&dir), 0o700).is_err() {
            return (None, None, None);
        }
        let Ok(rechecked) = lstat_path(&dir) else {
            return (None, None, None);
        };
        if (rechecked.mode & abi::S_IFMT) != abi::S_IFDIR
            || rechecked.uid != uid
            || (rechecked.mode & 0o7777) != 0o700
        {
            return (None, None, None);
        }
    }
    let sock_path = format!("{dir}/mounts.sock");
    if let Ok(existing) = lstat_path(&sock_path) {
        if (existing.mode & abi::S_IFMT) != abi::S_IFSOCK || existing.uid != uid {
            return (None, None, None);
        }
        let _ = std::fs::remove_file(&sock_path);
    }
    match UnixListener::bind_with_mode(&sock_path, 0o600) {
        Ok(listener) => {
            let _ = listener.set_nonblocking(true);
            let sock_ino = lstat_path(&sock_path)
                .ok()
                .filter(|st| {
                    (st.mode & abi::S_IFMT) == abi::S_IFSOCK
                        && st.uid == uid
                        && (st.mode & 0o7777) == 0o600
                })
                .map(|st| st.ino);
            if sock_ino.is_none() {
                drop(listener);
                let _ = std::fs::remove_file(&sock_path);
                return (None, None, None);
            }
            (Some(listener), Some(sock_path), sock_ino)
        }
        Err(_) => (None, None, None),
    }
}

fn cleanup_control_socket(path: Option<&str>, expected_ino: Option<u64>) {
    let Some(path) = path else {
        return;
    };
    if let Some(ino) = expected_ino
        && let Ok(st) = lstat_path(path)
        && st.ino != ino
    {
        return;
    }
    let _ = std::fs::remove_file(path);
}

fn mountd_rpc(uid: u32, req: &MountRequest) -> Result<MountResponse, String> {
    let frame = encode_frame(req).map_err(|e| e.to_string())?;
    let start = Instant::now();
    let user_socket = user_mount_sock(uid);
    let (stream, server_uid) = loop {
        match UnixStream::connect(&user_socket) {
            Ok(s) => break (s, uid),
            Err(Errno::ENOENT | Errno::ECONNREFUSED) => (),
            Err(e) => return Err(e.text().to_owned()),
        }
        match UnixStream::connect(SYSTEM_MOUNT_SOCK) {
            Ok(s) => break (s, 0),
            Err(Errno::ENOENT | Errno::ECONNREFUSED)
                if start.elapsed() < Duration::from_secs(5) =>
            {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(e) => return Err(e.text().to_owned()),
        }
    };
    let peer = stream.peer_cred().map_err(|e| e.text().to_owned())?;
    if peer.uid != server_uid {
        return Err(Errno::EACCES.text().to_owned());
    }
    write_frame(&frame, |s| stream.send(s, MSG_NOSIGNAL)).map_err(|e| e.to_string())?;
    let _ = stream.shutdown(SHUT_WR);
    let raw = read_frame(|buf| stream.recv(buf, 0)).map_err(|e| e.to_string())?;
    let reply: MountResponse = decode_frame(&raw).map_err(|e| e.to_string())?;
    if let MountResponse::Error { error, message, .. } = reply {
        let details = match error {
            MountErrorKind::Busy { processes } => format_busy_processes(&processes),
            _ => String::new(),
        };
        let joined = [message, details]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" · ");
        return Err(joined);
    }
    Ok(reply)
}

fn export_exchange(stream: UnixStream, req: &ExportRequest) -> Result<ExportResponse, Errno> {
    let root = if let ExportRequest::Publish { source_path, .. } = req {
        let reply = os_posix::batch(&[Call::OpenAt {
            dirfd: (abi::OS_FD_CWD as u32).into(),
            path: source_path.clone(),
            flags: abi::O_RDONLY | abi::O_DIRECTORY | abi::O_NOFOLLOW,
            mode: 0,
        }])
        .map_err(|e| os_posix::errno_of(&e).unwrap_or(Errno::EIO))?;
        let val = reply
            .results
            .into_iter()
            .next()
            .ok_or(Errno::EIO)?
            .into_result()
            .map_err(|e| e.errno)?;
        let opened: abi::Opened = serde_json::from_value(val).map_err(|_| Errno::EIO)?;
        // SAFETY: OpenAt returned a freshly allocated owned fd.
        Some(unsafe { File::from_raw_fd(opened.fd as _) })
    } else {
        None
    };
    let frame = encode_control(req)?;
    let fds: Vec<u32> = root.iter().map(|f| f.as_raw_fd() as u32).collect();
    let mut sent = 0;
    while sent < frame.len() {
        match stream.send_with_fds(
            &frame[sent..],
            if sent == 0 { &fds } else { &[] },
            MSG_NOSIGNAL,
        ) {
            Ok(0) => return Err(Errno::EPIPE),
            Ok(n) => sent += n,
            Err(Errno::EINTR | Errno::EAGAIN) => std::thread::sleep(Duration::from_millis(5)),
            Err(e) => return Err(e),
        }
    }
    let mut received = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = match stream.recv(&mut buf, 0) {
            Err(Errno::EINTR | Errno::EAGAIN) => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            other => other?,
        };
        if n == 0 {
            return Err(Errno::ENOTCONN);
        }
        if received.len() + n > CONTROL_MAX {
            return Err(Errno::E2BIG);
        }
        received.extend_from_slice(&buf[..n]);
        if buf[..n].contains(&b'\n') {
            return decode_control(&received);
        }
    }
}

fn exportd_rpc(uid: u32, req: &ExportRequest) -> Result<ExportResponse, String> {
    let run_inner = || -> Result<ExportResponse, Errno> {
        let startup = Instant::now() + Duration::from_secs(1);
        let user = loop {
            if uid == 0 {
                break None;
            }
            match UnixStream::connect(&user_export_sock(uid)) {
                Ok(stream) if stream.peer_cred()?.uid == uid => break Some(stream),
                Ok(_) => return Err(Errno::EACCES),
                Err(Errno::ENOENT | Errno::ECONNREFUSED) => {
                    if !matches!(req, ExportRequest::Publish { .. }) || Instant::now() >= startup {
                        break None;
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(e) => return Err(e),
            }
        };
        let Some(stream) = user else {
            return export_exchange(UnixStream::connect(SYSTEM_EXPORT_SOCK)?, req);
        };
        let first = export_exchange(stream, req)?;
        let needs_fallback = matches!(req, ExportRequest::Revoke { .. })
            && matches!(
                first,
                ExportResponse::Error {
                    errno: Errno::EACCES
                }
            );
        if !needs_fallback {
            return Ok(first);
        }
        match UnixStream::connect(SYSTEM_EXPORT_SOCK) {
            Ok(sys_stream) => export_exchange(sys_stream, req),
            Err(Errno::ENOENT | Errno::ECONNREFUSED) => Ok(first),
            Err(e) => Err(e),
        }
    };
    match run_inner() {
        Ok(ExportResponse::Error { errno }) => Err(export_error_message(errno)),
        Ok(reply) => Ok(reply),
        Err(errno) => Err(export_error_message(errno)),
    }
}

fn probe_mount_modes_and_manifests(
    attachments: &[abi::mount_ctl::AttachmentInfo],
) -> (BTreeMap<String, u32>, BTreeMap<String, bool>) {
    enum Probe {
        Stat(String),
        Manifest(String),
    }
    let mut modes = BTreeMap::new();
    let mut manifests = BTreeMap::new();
    let mut probes = Vec::new();
    let mut calls = Vec::new();

    for a in attachments {
        if a.health == "connected" {
            probes.push(Probe::Stat(a.target.clone()));
            calls.push(Call::Stat {
                path: a.target.clone(),
            });
        }
        if a.source_id.is_some()
            && a.user_mount
            && !a.target.starts_with("/opt/private/")
            && (!a.noexec || a.source_label.starts_with("snapshot:"))
        {
            probes.push(Probe::Manifest(a.target.clone()));
            let base = a.target.trim_end_matches('/');
            calls.push(Call::Lstat {
                path: format!("{base}/manifest.json"),
            });
        }
    }
    if calls.is_empty() {
        return (modes, manifests);
    }
    let Ok(reply) = os_posix::batch(&calls) else {
        return (modes, manifests);
    };
    for (probe, ret) in probes.into_iter().zip(reply.results) {
        match probe {
            Probe::Stat(target) => {
                if let Ok(val) = ret.into_result()
                    && let Ok(st) = serde_json::from_value::<Stat>(val)
                {
                    modes.insert(target, st.mode);
                }
            }
            Probe::Manifest(target) => {
                let is_regular = ret
                    .into_result()
                    .ok()
                    .and_then(|v| serde_json::from_value::<Stat>(v).ok())
                    .is_some_and(|st| (st.mode & abi::S_IFMT) == abi::S_IFREG);
                manifests.insert(target, is_regular);
            }
        }
    }
    (modes, manifests)
}

fn open_dir_in_files(uid: u32, target: &str) -> Result<(), String> {
    let files_sock = format!("/run/user/{uid}/files.sock");
    match send_user_socket_rpc(
        uid,
        &files_sock,
        &json!({ "op": "open_dir", "path": target }),
        3_000,
    ) {
        Ok(_) => {
            let _ = send_desktop_action(uid, &json!({ "op": "focus_app", "app_id": "files" }));
            Ok(())
        }
        Err(Errno::ENOENT | Errno::ECONNREFUSED) => {
            // Files is not running yet; ask the desktop host to open/spawn it at `target`.
            send_desktop_action(uid, &json!({ "op": "open_dir", "path": target }))
        }
        Err(e) => Err(e.text().to_owned()),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingSeatReq {
    Other,
    Consent,
    Clipboard,
}

struct MountsApp {
    seat: SeatConn,
    surface_id: SurfaceId,
    uid: u32,
    core: MountsCore,
    doc_ready: bool,
    chunk_seq: u64,
    doc_asm: DocChunkAssembler,
    consent_in_flight: bool,
    pending_cap_probe: bool,
    queued_consent: Option<(MountConsentAction, PendingConsentAttach)>,
    pending_reqs: VecDeque<PendingSeatReq>,
    ctrl_listener: Option<UnixListener>,
    ctrl_path: Option<String>,
    ctrl_ino: Option<u64>,
    pending_events: VecDeque<ClientEvent>,
    closing: bool,
}

impl MountsApp {
    fn queue_seat(&mut self, kind: PendingSeatReq, req: &ClientReq) -> Result<(), Errno> {
        self.seat.queue(req)?;
        self.pending_reqs.push_back(kind);
        Ok(())
    }

    fn send_doc_msg(&mut self, msg: &MountsHostMsg) -> Result<(), Errno> {
        if !self.doc_ready {
            return Ok(());
        }
        let payload = serde_json::to_string(msg).map_err(|_| Errno::EINVAL)?;
        self.chunk_seq = self.chunk_seq.wrapping_add(1);
        for chunk in chunk_document_message(self.chunk_seq, &payload) {
            self.queue_seat(
                PendingSeatReq::Other,
                &ClientReq::DocumentReply {
                    surface_id: self.surface_id,
                    text: chunk,
                },
            )?;
        }
        Ok(())
    }

    fn push_snapshot(&mut self) -> Result<(), Errno> {
        let msg = self.core.snapshot_msg();
        self.send_doc_msg(&msg)
    }

    fn request_capabilities(&mut self) -> Result<(), Errno> {
        if self.consent_in_flight {
            self.pending_cap_probe = true;
            return Ok(());
        }
        self.pending_cap_probe = false;
        self.consent_in_flight = true;
        self.queue_seat(
            PendingSeatReq::Consent,
            &ClientReq::MountConsent {
                surface_id: self.surface_id,
                action: MountConsentAction::Capabilities {},
            },
        )
    }

    fn refresh_data(&mut self) {
        match mountd_rpc(self.uid, &MountRequest::ListAll { include_busy: true }) {
            Ok(MountResponse::All {
                sources,
                filesystems,
                attachments,
                exports,
            }) => {
                let (modes, manifests) = probe_mount_modes_and_manifests(&attachments);
                self.core.apply_list_all(
                    sources,
                    filesystems,
                    attachments,
                    exports,
                    &modes,
                    &manifests,
                );
            }
            Ok(_) => {
                self.core.notice = "Unexpected mountd reply.".into();
            }
            Err(err) => {
                self.core.notice = err;
            }
        }
    }

    fn attach_source(
        &mut self,
        source_id: String,
        fstype: String,
        target: String,
        flags: u64,
    ) -> Result<(), Errno> {
        let req = MountRequest::Attach {
            source_id: Some(source_id.clone()),
            source: source_id,
            target: target.clone(),
            fstype,
            flags,
            options: None,
            target_pid: None,
        };
        match mountd_rpc(self.uid, &req) {
            Ok(_) => {
                self.core.submitting = false;
                self.core.notice.clear();
                self.core.selected = Some(target);
                self.core.tab = MountsTab::Mounted;
                self.refresh_data();
            }
            Err(err) => {
                self.core.submitting = false;
                self.core.notice = err;
            }
        }
        self.push_snapshot()
    }

    fn start_mutating_consent(
        &mut self,
        action: MountConsentAction,
        attach: PendingConsentAttach,
    ) -> Result<(), Errno> {
        if self.consent_in_flight {
            if self.core.pending_attach.is_some() || self.queued_consent.is_some() {
                self.core.notice = "Another mount request is already in progress.".into();
                return self.push_snapshot();
            }
            // Only a non-mutating Capabilities probe is in flight; validate and queue this
            // user-initiated consent so it dispatches immediately when Capabilities finishes.
            if let Err(msg) = mount_target_path(&attach.fstype, &attach.name) {
                self.core.submitting = false;
                self.core.notice = msg.to_owned();
                return self.push_snapshot();
            }
            self.core.submitting = true;
            self.core.notice.clear();
            self.queued_consent = Some((action, attach));
            return self.push_snapshot();
        }
        match self.core.begin_consent(action, attach) {
            Ok(action) => {
                self.consent_in_flight = true;
                self.push_snapshot()?;
                self.queue_seat(
                    PendingSeatReq::Consent,
                    &ClientReq::MountConsent {
                        surface_id: self.surface_id,
                        action,
                    },
                )
            }
            Err(msg) => {
                self.core.submitting = false;
                self.core.notice = msg;
                self.push_snapshot()
            }
        }
    }

    fn handle_ui_msg(&mut self, msg: MountsUiMsg) -> Result<(), Errno> {
        match msg {
            MountsUiMsg::Ready {} => {
                self.doc_ready = true;
                self.refresh_data();
                self.push_snapshot()?;
                self.request_capabilities()?;
            }
            MountsUiMsg::Refresh {} => {
                self.core.notice.clear();
                self.refresh_data();
                self.push_snapshot()?;
                self.request_capabilities()?;
            }
            MountsUiMsg::SelectTab { tab } => {
                let next = MountsTab::parse(&tab);
                self.core.set_tab(next);
                if next != MountsTab::Connect {
                    self.refresh_data();
                }
                self.push_snapshot()?;
                if (!self.core.capabilities_loaded
                    && matches!(next, MountsTab::Add | MountsTab::Publish))
                    || (next == MountsTab::Publish && !self.core.relay_ready)
                {
                    self.request_capabilities()?;
                }
            }
            MountsUiMsg::SelectMount { target } => {
                self.core.select_mount(target);
                self.push_snapshot()?;
            }
            MountsUiMsg::OpenInFiles { target } => {
                self.core.notice.clear();
                if let Err(err) = open_dir_in_files(self.uid, &target) {
                    self.core.notice = err;
                    self.push_snapshot()?;
                }
            }
            MountsUiMsg::Unmount { target, lazy } => {
                self.core.notice.clear();
                let req = MountRequest::Detach {
                    target,
                    lazy,
                    force: false,
                    target_pid: None,
                };
                match mountd_rpc(self.uid, &req) {
                    Ok(_) => self.refresh_data(),
                    Err(err) => self.core.notice = err,
                }
                self.push_snapshot()?;
            }
            MountsUiMsg::ActivatePackage { source_id, name } => {
                self.core.notice.clear();
                if !valid_mount_name(&name) {
                    self.core.notice = "Invalid extension name.".into();
                    return self.push_snapshot();
                }
                let req = MountRequest::ActivatePrivate {
                    additional_sources: Vec::new(),
                    source_id,
                    name: name.clone(),
                    execute: true,
                };
                match mountd_rpc(self.uid, &req) {
                    Ok(_) => {
                        self.core.selected = Some(format!("/opt/private/{name}"));
                        self.refresh_data();
                    }
                    Err(err) => self.core.notice = err,
                }
                self.push_snapshot()?;
            }
            MountsUiMsg::ForgetSource { source_id } => {
                self.core.notice.clear();
                let req = MountRequest::ForgetSource { source_id };
                match mountd_rpc(self.uid, &req) {
                    Ok(_) => self.refresh_data(),
                    Err(err) => self.core.notice = err,
                }
                self.push_snapshot()?;
            }
            MountsUiMsg::MountExistingSource {
                source_id,
                kind,
                name,
                writable,
                execute,
            } => {
                self.core.notice.clear();
                match mount_target_path(&kind, &name) {
                    Ok(target) => {
                        let flags = mount_flags_for(writable, execute);
                        self.attach_source(source_id, kind, target, flags)?;
                    }
                    Err(msg) => {
                        self.core.notice = msg.to_owned();
                        self.push_snapshot()?;
                    }
                }
            }
            MountsUiMsg::RenewAndMount {
                source_id,
                kind,
                name,
                writable,
                execute,
            } => {
                self.start_mutating_consent(
                    MountConsentAction::RenewHostFolder {
                        source_id,
                        writable,
                    },
                    PendingConsentAttach {
                        fstype: kind,
                        name,
                        writable,
                        execute,
                        clear_field: None,
                    },
                )?;
            }
            MountsUiMsg::PickHostFolder {
                name,
                writable,
                execute,
                cloud,
                save,
            } => {
                self.start_mutating_consent(
                    MountConsentAction::PickHostFolder {
                        writable,
                        execute,
                        cloud,
                        save,
                    },
                    PendingConsentAttach {
                        fstype: "hostfs".into(),
                        name,
                        writable,
                        execute,
                        clear_field: None,
                    },
                )?;
            }
            MountsUiMsg::MountOpfs {
                name,
                writable,
                execute,
                cloud,
            } => {
                self.start_mutating_consent(
                    MountConsentAction::RegisterOpfs {
                        writable,
                        execute,
                        cloud,
                    },
                    PendingConsentAttach {
                        fstype: "opfs".into(),
                        name,
                        writable,
                        execute,
                        clear_field: None,
                    },
                )?;
            }
            MountsUiMsg::MountHelper {
                name,
                url,
                token,
                writable,
                execute,
                cloud,
            } => {
                self.start_mutating_consent(
                    MountConsentAction::RegisterHelper {
                        url,
                        token,
                        writable,
                        execute,
                        cloud,
                    },
                    PendingConsentAttach {
                        fstype: "helperfs".into(),
                        name,
                        writable,
                        execute,
                        clear_field: Some("token"),
                    },
                )?;
            }
            MountsUiMsg::ConnectShare {
                name,
                address,
                password,
                writable,
                execute,
            } => {
                self.start_mutating_consent(
                    MountConsentAction::RegisterShare {
                        address: address.trim().to_owned(),
                        password,
                        writable,
                        execute,
                    },
                    PendingConsentAttach {
                        fstype: "sharefs".into(),
                        name,
                        writable,
                        execute,
                        clear_field: Some("password"),
                    },
                )?;
            }
            MountsUiMsg::PublishExport {
                source,
                subpath,
                name,
                seconds,
                password,
            } => {
                self.core.notice.clear();
                let source_path = match export_source_path(&source, &subpath) {
                    Ok(p) => p,
                    Err(msg) => {
                        self.core.notice = msg.to_owned();
                        return self.push_snapshot();
                    }
                };
                let trimmed_name = name.trim();
                let final_name = if trimmed_name.is_empty() {
                    source_path
                        .rsplit('/')
                        .find(|s| !s.is_empty())
                        .unwrap_or("shared")
                        .to_owned()
                } else {
                    trimmed_name.to_owned()
                };
                let transports = if self.core.relay_ready {
                    Vec::new()
                } else {
                    vec![TransportKind::Ipc]
                };
                let req = ExportRequest::Publish {
                    name: final_name,
                    source_path,
                    writable: true,
                    execute: true,
                    seconds: seconds.clamp(60, 3_600),
                    password: (!password.is_empty()).then_some(password),
                    transports,
                };
                match exportd_rpc(self.uid, &req) {
                    Ok(_) => {
                        self.core
                            .pending_clear_fields
                            .push("export_password".to_owned());
                        self.refresh_data();
                    }
                    Err(err) => self.core.notice = err,
                }
                self.push_snapshot()?;
            }
            MountsUiMsg::RevokeExport { id } => {
                self.core.notice.clear();
                match exportd_rpc(self.uid, &ExportRequest::Revoke { id }) {
                    Ok(_) => self.refresh_data(),
                    Err(err) => self.core.notice = err,
                }
                self.push_snapshot()?;
            }
            MountsUiMsg::CopyAddress { address } => {
                self.queue_seat(
                    PendingSeatReq::Clipboard,
                    &ClientReq::ClipboardWrite {
                        surface_id: self.surface_id,
                        item: TransferItem {
                            mime: "text/plain".into(),
                            data: address.into_bytes().into(),
                        },
                    },
                )?;
            }
        }
        Ok(())
    }

    fn service_control_socket(&mut self) -> Result<(), Errno> {
        let Some(ref listener) = self.ctrl_listener else {
            return Ok(());
        };
        let mut accepted = Vec::new();
        for _ in 0..MAX_CONTROL_PEERS_PER_TICK {
            match listener.accept_flags(SOCK_NONBLOCK | SOCK_CLOEXEC) {
                Ok((stream, peer)) => accepted.push((stream, peer)),
                Err(Errno::EAGAIN | Errno::EINTR) => break,
                Err(_) => break,
            }
        }
        for (stream, peer) in accepted {
            if peer.uid != self.uid && peer.uid != 0 {
                continue;
            }
            let mut raw = Vec::new();
            let mut buf = [0u8; 1024];
            let deadline = Instant::now() + Duration::from_millis(50);
            while Instant::now() < deadline && raw.len() < MAX_CONTROL_LINE_BYTES {
                if raw.contains(&b'\n') {
                    break;
                }
                match stream.recv(&mut buf, MSG_DONTWAIT) {
                    Ok(0) => break,
                    Ok(n) => {
                        let take = n.min(MAX_CONTROL_LINE_BYTES - raw.len());
                        raw.extend_from_slice(&buf[..take]);
                    }
                    Err(Errno::EAGAIN | Errno::EINTR) => {
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
            let line = raw
                .iter()
                .position(|&b| b == b'\n')
                .map(|nl| &raw[..nl])
                .unwrap_or(&raw);
            let reply = match serde_json::from_slice::<MountsControlReq>(line) {
                Ok(MountsControlReq::Focus { tab }) => {
                    if let Some(t) = tab {
                        self.core.set_tab(MountsTab::parse(&t));
                    }
                    self.refresh_data();
                    let _ = self.push_snapshot();
                    let _ = self.send_doc_msg(&MountsHostMsg::Focus {});
                    let _ = self.request_capabilities();
                    MountsControlReply {
                        ok: true,
                        tab: Some(self.core.tab.as_str().to_owned()),
                        error: None,
                    }
                }
                Ok(MountsControlReq::Refresh { reset }) => {
                    self.refresh_data();
                    if reset {
                        self.core.reset_for_session_change();
                    }
                    let _ = self.push_snapshot();
                    let _ = self.request_capabilities();
                    MountsControlReply {
                        ok: true,
                        tab: Some(self.core.tab.as_str().to_owned()),
                        error: None,
                    }
                }
                Ok(MountsControlReq::Status {}) => MountsControlReply {
                    ok: true,
                    tab: Some(self.core.tab.as_str().to_owned()),
                    error: None,
                },
                Err(_) => MountsControlReply {
                    ok: false,
                    tab: None,
                    error: Some("invalid control request".into()),
                },
            };
            if let Ok(mut out) = serde_json::to_vec(&reply) {
                out.push(b'\n');
                let _ = send_all(&stream, &out);
            }
        }
        Ok(())
    }

    fn run(mut self) -> Result<(), Errno> {
        loop {
            if STOP.load(Ordering::SeqCst) {
                break;
            }
            match self.seat.drain_events() {
                Ok(events) => self.pending_events.extend(events),
                Err(Errno::EPIPE | Errno::ECONNRESET) => break,
                Err(e) => return Err(e),
            }

            while let Some(ev) = self.pending_events.pop_front() {
                match ev {
                    ClientEvent::CloseRequested { surface_id } if surface_id == self.surface_id => {
                        self.closing = true;
                        break;
                    }
                    ClientEvent::DocumentMessage { surface_id, text }
                        if surface_id == self.surface_id =>
                    {
                        if let Some(full) = self.doc_asm.feed(&text)
                            && let Ok(msg) = serde_json::from_str::<MountsUiMsg>(&full)
                        {
                            self.handle_ui_msg(msg)?;
                        }
                    }
                    ClientEvent::MountConsentResult {
                        surface_id,
                        outcome,
                    } if surface_id == self.surface_id => {
                        self.consent_in_flight = false;
                        match self.core.apply_consent_outcome(outcome) {
                            ConsentFollowUp::None => {
                                self.push_snapshot()?;
                            }
                            ConsentFollowUp::Attach {
                                source_id,
                                fstype,
                                target,
                                flags,
                            } => {
                                self.attach_source(source_id, fstype, target, flags)?;
                            }
                        }
                        if let Some((action, attach)) = self.queued_consent.take() {
                            self.start_mutating_consent(action, attach)?;
                        } else if self.pending_cap_probe && !self.consent_in_flight {
                            self.request_capabilities()?;
                        }
                    }
                    ClientEvent::Ok => {
                        if self.pending_reqs.pop_front() == Some(PendingSeatReq::Clipboard) {
                            self.core.notice = "Address copied.".into();
                            self.send_doc_msg(&MountsHostMsg::Notice {
                                text: self.core.notice.clone(),
                                submitting: self.core.submitting,
                            })?;
                        }
                    }
                    ClientEvent::Error { errno } => match self.pending_reqs.pop_front() {
                        Some(PendingSeatReq::Consent) if self.consent_in_flight => {
                            self.consent_in_flight = false;
                            let was_mutating = self.core.pending_attach.take().is_some();
                            self.core.submitting = false;
                            if was_mutating {
                                self.core.notice = errno.text().to_owned();
                            }
                            self.push_snapshot()?;
                            if let Some((action, attach)) = self.queued_consent.take() {
                                self.start_mutating_consent(action, attach)?;
                            } else if self.pending_cap_probe {
                                self.request_capabilities()?;
                            }
                        }
                        Some(PendingSeatReq::Clipboard) => {
                            self.core.notice = errno.text().to_owned();
                            self.send_doc_msg(&MountsHostMsg::Notice {
                                text: self.core.notice.clone(),
                                submitting: self.core.submitting,
                            })?;
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
            if self.closing || STOP.load(Ordering::SeqCst) {
                break;
            }

            self.service_control_socket()?;
            self.seat.flush()?;

            let mut read_fds = vec![self.seat.fd()];
            if let Some(ref listener) = self.ctrl_listener {
                read_fds.push(listener.as_raw_fd());
            }
            let mut write_fds = Vec::new();
            if self.seat.has_pending_writes() {
                write_fds.push(self.seat.fd());
            }
            poll_fds(&read_fds, &write_fds, 100);
        }

        // Closing the Mounts window NEVER detaches any mounted filesystems.
        let _ = self.seat.send_blocking(&ClientReq::Destroy {
            surface_id: self.surface_id,
        });
        cleanup_control_socket(self.ctrl_path.take().as_deref(), self.ctrl_ino.take());
        Ok(())
    }
}

fn run() -> Result<(), Errno> {
    os_posix::init_preopens().map_err(|_| Errno::EIO)?;
    install_signals();

    let args: Vec<String> = std::env::args().skip(1).collect();
    if matches!(args.first().map(String::as_str), Some("--help" | "-h")) {
        println!("Usage: mounts [--tab mounted|add|connect|publish]");
        return Ok(());
    }

    let mut cli_tab: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--tab" => {
                let Some(t) = args.get(i + 1) else {
                    return Err(Errno::EINVAL);
                };
                cli_tab = Some(t.clone());
                i += 2;
            }
            arg if !arg.starts_with('-') && cli_tab.is_none() => {
                cli_tab = Some(arg.to_owned());
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }

    let uid = getuid();
    if try_forward_to_existing(uid, cli_tab.as_deref())? {
        return Ok(());
    }

    let bundle_bytes = std::fs::read(MOUNTS_BUNDLE).map_err(|e| {
        eprintln!("mounts: failed to read {MOUNTS_BUNDLE}: {e}");
        os_posix::errno_of(&e).unwrap_or(Errno::ENOENT)
    })?;
    let expected_sha256 = sha256_hex(&bundle_bytes);

    let mut seat = SeatConn::connect()?;
    seat.send_blocking(&ClientReq::Hello {
        versions: vec![1],
        required: vec!["document".into(), "clipboard".into()],
    })?;
    match seat.recv_blocking()? {
        ClientEvent::Hello { version: 1 } => {}
        ClientEvent::Error { errno } => return Err(errno),
        _ => return Err(Errno::EPROTONOSUPPORT),
    }

    seat.send_blocking(&ClientReq::CreateSurface {
        spec: SurfaceSpec {
            role: SurfaceRole::Window,
            kind: SurfaceKind::Document(DocumentSource {
                bundle_path: MOUNTS_BUNDLE.into(),
                expected_sha256,
            }),
            title: "Mounts".into(),
            rect: Rect {
                x: 0,
                y: 0,
                width: 0,
                height: 0,
            },
            min_size: Size {
                width: 280,
                height: 180,
            },
            max_size: None,
            resizable: true,
            app_id: Some("mounts".into()),
        },
    })?;

    let surface_id = match seat.recv_blocking()? {
        ClientEvent::Created { surface_id } => surface_id,
        ClientEvent::Error { errno } => return Err(errno),
        _ => return Err(Errno::EIO),
    };

    let (ctrl_listener, ctrl_path, ctrl_ino) = bind_control_socket(uid);
    let initial_tab = cli_tab
        .as_deref()
        .map(MountsTab::parse)
        .unwrap_or(MountsTab::Mounted);

    let app = MountsApp {
        seat,
        surface_id,
        uid,
        core: MountsCore::new(uid, initial_tab),
        doc_ready: false,
        chunk_seq: 0,
        doc_asm: DocChunkAssembler::default(),
        consent_in_flight: false,
        pending_cap_probe: false,
        queued_consent: None,
        pending_reqs: VecDeque::new(),
        ctrl_listener,
        ctrl_path,
        ctrl_ino,
        pending_events: VecDeque::new(),
        closing: false,
    };

    app.run()
}

fn main() {
    if let Err(err) = run() {
        eprintln!("mounts: {err:?}");
        std::process::exit(1);
    }
}
