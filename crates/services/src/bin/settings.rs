//! `/usr/bin/settings`: GNOME/COSMIC-style System Settings GUI process.
//!
//! Connects to `/run/gui/seat0.sock` over `AF_UNIX`, renders inside a sealed Document surface
//! (`/usr/share/gui/settings/settings.json`), persists per-user appearance & dock settings to
//! `~/.config/os/settings.json`, enforces single-instance IPC over `/run/user/<uid>/settings.sock`,
//! and mediates privileged account/cloud & live desktop operations through the unified compositor-
//! and kernel-fenced `ClientReq::Portal` IPC. Imports ZERO `gui_*` Wasm functions.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use abi::gui::{
    AccountPortalAction, ClientEvent, ClientReq, DesktopPortalAction, DocumentSource, PortalRequest,
    PortalResponse, Rect, SETTINGS_BUNDLE, SOCKET, Size, SurfaceId, SurfaceKind, SurfaceRole,
    SurfaceSpec, frame, sha256_hex, take_frame,
};
use abi::socket::{MSG_DONTWAIT, MSG_NOSIGNAL};
use abi::{Call, Errno, Stat};
use os_posix::process::getuid;
use os_posix::socket::{UnixListener, UnixStream};
use os_services::gui_doc::{DocChunkAssembler, chunk_document_message};
use os_services::settings::{
    SETTINGS_REL_PATH, SettingsControlReply, SettingsControlReq, SettingsCore, SettingsHostMsg,
    SettingsSection, SettingsUiMsg, load_settings_file, normalize_theme, save_settings_file_atomic,
};
use serde_json::{Value, json};

static STOP: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "wasi")]
#[unsafe(no_mangle)]
pub extern "C" fn settings_signal_handler(sig: u32) {
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
            fn sigaction(sig: u32, kind: u32, mask: u32, flags: u32) -> i32;
        }
        let name = b"settings_signal_handler";
        // SAFETY: static exported signal callback; scalar WASI signal dispositions.
        unsafe {
            callback_signal(name.as_ptr(), name.len());
            for sig in [1, 2, 15] {
                let _ = sigaction(sig, 2, 0, 0);
            }
        }
    }
}

fn lstat_path(path: &str) -> Result<Stat, Errno> {
    let reply = os_posix::batch(&[Call::Lstat {
        path: path.to_owned(),
    }])
    .map_err(|e| os_posix::errno_of(&e).unwrap_or(Errno::EIO))?;
    let val = reply
        .results
        .into_iter()
        .next()
        .ok_or(Errno::EIO)?
        .into_result()
        .map_err(|e| e.errno)?;
    serde_json::from_value(val).map_err(|_| Errno::EIO)
}

fn send_all(stream: &UnixStream, bytes: &[u8]) -> Result<(), Errno> {
    let mut off = 0;
    while off < bytes.len() {
        match stream.send(&bytes[off..], MSG_NOSIGNAL) {
            Ok(0) => return Err(Errno::EPIPE),
            Ok(n) => off += n,
            Err(Errno::EINTR) => continue,
            Err(Errno::EAGAIN) => std::thread::sleep(Duration::from_millis(2)),
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn read_json_line(stream: &UnixStream, timeout_ms: u64) -> Result<Value, Errno> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let mut buf = Vec::new();
    let mut tmp = [0u8; 512];
    loop {
        if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
            return serde_json::from_slice(&buf[..pos]).map_err(|_| Errno::EINVAL);
        }
        if Instant::now() >= deadline {
            return Err(Errno::ETIMEDOUT);
        }
        match stream.recv(&mut tmp, MSG_DONTWAIT) {
            Ok(0) => {
                if !buf.is_empty() {
                    return serde_json::from_slice(&buf).map_err(|_| Errno::EINVAL);
                }
                return Err(Errno::EPIPE);
            }
            Ok(n) => {
                if buf.len() + n > 8192 {
                    return Err(Errno::E2BIG);
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            Err(Errno::EINTR) => continue,
            Err(Errno::EAGAIN) => std::thread::sleep(Duration::from_millis(5)),
            Err(e) => return Err(e),
        }
    }
}

fn send_desktop_action(uid: u32, payload: &Value) -> Result<(), Errno> {
    let sock_path = format!("/run/user/{uid}/desktop-actions.sock");
    let stream = UnixStream::connect(&sock_path)?;
    let peer = stream.peer_cred()?;
    if peer.uid != uid {
        return Err(Errno::EACCES);
    }
    let mut bytes = serde_json::to_vec(payload).map_err(|_| Errno::EINVAL)?;
    bytes.push(b'\n');
    send_all(&stream, &bytes)?;
    let _ = read_json_line(&stream, 2_000);
    Ok(())
}

fn try_forward_to_existing(uid: u32, section: Option<&str>) -> Result<bool, Errno> {
    let sock_path = format!("/run/user/{uid}/settings.sock");
    let stream = match UnixStream::connect(&sock_path) {
        Ok(s) => s,
        Err(Errno::ENOENT | Errno::ECONNREFUSED) => return Ok(false),
        Err(e) => return Err(e),
    };
    let peer = stream.peer_cred()?;
    if peer.uid != uid {
        return Err(Errno::EACCES);
    }
    let req = SettingsControlReq::Focus {
        section: section.map(str::to_owned),
    };
    let mut bytes = serde_json::to_vec(&req).map_err(|_| Errno::EINVAL)?;
    bytes.push(b'\n');
    send_all(&stream, &bytes)?;
    let _ = read_json_line(&stream, 2_000);
    let _ = send_desktop_action(uid, &json!({ "op": "focus_app", "app_id": "settings" }));
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
    let sock_path = format!("{dir}/settings.sock");
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

struct SeatConn {
    stream: UnixStream,
    rx_buf: Vec<u8>,
    tx_buf: Vec<u8>,
}

impl SeatConn {
    fn connect() -> Result<Self, Errno> {
        let mut attempts = 0;
        let stream = loop {
            if STOP.load(Ordering::SeqCst) {
                return Err(Errno::EINTR);
            }
            match UnixStream::connect(SOCKET) {
                Ok(s) => break s,
                Err(Errno::ENOENT | Errno::ECONNREFUSED) if attempts < 200 => {
                    attempts += 1;
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(e) => return Err(e),
            }
        };
        Ok(Self {
            stream,
            rx_buf: Vec::new(),
            tx_buf: Vec::new(),
        })
    }

    fn send_blocking(&mut self, req: &ClientReq) -> Result<(), Errno> {
        let bytes = frame(req)?;
        send_all(&self.stream, &bytes)
    }

    fn recv_blocking(&mut self) -> Result<ClientEvent, Errno> {
        let mut tmp = [0u8; 4096];
        loop {
            if let Some(ev) = take_frame(&mut self.rx_buf)? {
                return Ok(ev);
            }
            match self.stream.recv(&mut tmp, 0) {
                Ok(0) => return Err(Errno::EPIPE),
                Ok(n) => self.rx_buf.extend_from_slice(&tmp[..n]),
                Err(Errno::EINTR) => continue,
                Err(Errno::EAGAIN) => std::thread::sleep(Duration::from_millis(5)),
                Err(e) => return Err(e),
            }
        }
    }

    fn queue(&mut self, req: &ClientReq) -> Result<(), Errno> {
        let bytes = frame(req)?;
        self.tx_buf.extend_from_slice(&bytes);
        self.flush_nonblocking()
    }

    fn flush_nonblocking(&mut self) -> Result<(), Errno> {
        while !self.tx_buf.is_empty() {
            match self.stream.send(&self.tx_buf, MSG_NOSIGNAL | MSG_DONTWAIT) {
                Ok(0) => return Err(Errno::EPIPE),
                Ok(n) => {
                    self.tx_buf.drain(..n);
                }
                Err(Errno::EINTR) => continue,
                Err(Errno::EAGAIN) => break,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn drain_events(&mut self) -> Result<Vec<ClientEvent>, Errno> {
        let mut out = Vec::new();
        let mut tmp = [0u8; 4096];
        loop {
            match self.stream.recv(&mut tmp, MSG_DONTWAIT) {
                Ok(0) => {
                    while let Some(ev) = take_frame(&mut self.rx_buf)? {
                        out.push(ev);
                    }
                    if out.is_empty() {
                        return Err(Errno::EPIPE);
                    }
                    return Ok(out);
                }
                Ok(n) => self.rx_buf.extend_from_slice(&tmp[..n]),
                Err(Errno::EINTR) => continue,
                Err(Errno::EAGAIN) => break,
                Err(e) => return Err(e),
            }
        }
        while let Some(ev) = take_frame(&mut self.rx_buf)? {
            out.push(ev);
        }
        Ok(out)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PendingSeatReq {
    AccountProbe,
    DesktopProbe,
    MutatingPortal,
    Other,
}

struct SettingsApp {
    uid: u32,
    settings_path: PathBuf,
    seat: SeatConn,
    surface_id: SurfaceId,
    core: SettingsCore,
    doc_ready: bool,
    chunk_seq: u64,
    doc_asm: DocChunkAssembler,
    account_probe_in_flight: bool,
    desktop_probe_in_flight: bool,
    mutating_in_flight: bool,
    pending_refresh: bool,
    pending_reqs: VecDeque<PendingSeatReq>,
    ctrl_listener: Option<UnixListener>,
    ctrl_path: Option<String>,
    ctrl_ino: Option<u64>,
    pending_events: VecDeque<ClientEvent>,
    closing: bool,
}

impl SettingsApp {
    fn queue_seat(&mut self, kind: PendingSeatReq, req: &ClientReq) -> Result<(), Errno> {
        self.seat.queue(req)?;
        self.pending_reqs.push_back(kind);
        Ok(())
    }

    fn send_doc_msg(&mut self, msg: &SettingsHostMsg) -> Result<(), Errno> {
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

    fn request_account_status(&mut self) -> Result<(), Errno> {
        if self.account_probe_in_flight {
            self.pending_refresh = true;
            return Ok(());
        }
        self.pending_refresh = false;
        self.account_probe_in_flight = true;
        self.queue_seat(
            PendingSeatReq::AccountProbe,
            &ClientReq::Portal {
                surface_id: self.surface_id,
                request: PortalRequest::Account {
                    action: AccountPortalAction::Status {},
                },
            },
        )
    }

    fn request_desktop_prefs(&mut self) -> Result<(), Errno> {
        if self.desktop_probe_in_flight {
            return Ok(());
        }
        self.desktop_probe_in_flight = true;
        self.queue_seat(
            PendingSeatReq::DesktopProbe,
            &ClientReq::Portal {
                surface_id: self.surface_id,
                request: PortalRequest::Desktop {
                    action: DesktopPortalAction::GetPreferences {},
                },
            },
        )
    }

    fn send_mutating_portal(&mut self, request: PortalRequest) -> Result<(), Errno> {
        if self.mutating_in_flight {
            self.core.error = Some("Another settings action is already in progress.".into());
            return self.push_snapshot();
        }
        self.mutating_in_flight = true;
        self.core.busy = true;
        self.core.error = None;
        self.core.notice = None;
        self.push_snapshot()?;
        self.queue_seat(
            PendingSeatReq::MutatingPortal,
            &ClientReq::Portal {
                surface_id: self.surface_id,
                request,
            },
        )
    }

    fn handle_ui_msg(&mut self, msg: SettingsUiMsg) -> Result<(), Errno> {
        match msg {
            SettingsUiMsg::Ready {} => {
                self.doc_ready = true;
                self.push_snapshot()?;
                self.request_account_status()?;
                self.request_desktop_prefs()?;
            }
            SettingsUiMsg::Refresh {} => {
                self.core.error = None;
                self.request_account_status()?;
                self.request_desktop_prefs()?;
            }
            SettingsUiMsg::SelectSection { section } => {
                self.core.section = SettingsSection::parse(&section);
                self.core.error = None;
                self.push_snapshot()?;
            }
            SettingsUiMsg::CloudSignIn {
                username,
                password,
                scope,
            } => {
                let user = username.trim().to_owned();
                if user.is_empty() || password.is_empty() {
                    self.core.error = Some("Enter both cloud username and password.".into());
                    return self.push_snapshot();
                }
                self.send_mutating_portal(PortalRequest::Account {
                    action: AccountPortalAction::CloudSignIn {
                        username: user,
                        password,
                        scope,
                    },
                })?;
            }
            SettingsUiMsg::CloudSignOut {} => {
                self.send_mutating_portal(PortalRequest::Account {
                    action: AccountPortalAction::CloudSignOut {},
                })?;
            }
            SettingsUiMsg::SwitchLocalUser {} => {
                self.send_mutating_portal(PortalRequest::Account {
                    action: AccountPortalAction::SwitchLocalUser {},
                })?;
            }
            SettingsUiMsg::OpenMounts { tab } => {
                self.send_mutating_portal(PortalRequest::Account {
                    action: AccountPortalAction::OpenMounts { tab },
                })?;
            }
            SettingsUiMsg::SetPreferences {
                theme,
                dock_autohide,
            } => {
                let normalized = normalize_theme(&theme);
                self.core.theme = normalized.clone();
                self.core.dock_autohide = dock_autohide;
                self.core.has_disk_prefs = true;
                if let Err(err) =
                    save_settings_file_atomic(&self.settings_path, &self.core.disk_settings())
                {
                    self.core.error = Some(format!("Failed saving {}: {err}", self.core.settings_path));
                }
                self.send_mutating_portal(PortalRequest::Desktop {
                    action: DesktopPortalAction::ApplyPreferences {
                        theme: normalized,
                        dock_autohide,
                    },
                })?;
            }
            SettingsUiMsg::SetFullscreen { active } => {
                self.send_mutating_portal(PortalRequest::Desktop {
                    action: DesktopPortalAction::SetFullscreen { active },
                })?;
            }
        }
        Ok(())
    }

    fn poll_control_socket(&mut self) -> Result<(), Errno> {
        let mut accepted = Vec::new();
        if let Some(listener) = self.ctrl_listener.as_ref() {
            loop {
                match listener.accept() {
                    Ok((stream, peer)) => accepted.push((stream, peer)),
                    Err(Errno::EAGAIN | Errno::EINTR) => break,
                    Err(_) => break,
                }
            }
        }
        for (stream, peer) in accepted {
            if peer.uid != self.uid {
                continue;
            }
            let reply = match read_json_line(&stream, 500)
                .and_then(|val| serde_json::from_value::<SettingsControlReq>(val).map_err(|_| Errno::EINVAL))
            {
                Ok(SettingsControlReq::Focus { section }) => {
                    if let Some(sec) = section {
                        self.core.section = SettingsSection::parse(&sec);
                    }
                    self.push_snapshot()?;
                    self.request_account_status()?;
                    SettingsControlReply {
                        ok: true,
                        section: Some(self.core.section.as_str().into()),
                        error: None,
                    }
                }
                Ok(SettingsControlReq::Refresh {}) => {
                    self.request_account_status()?;
                    SettingsControlReply {
                        ok: true,
                        section: Some(self.core.section.as_str().into()),
                        error: None,
                    }
                }
                Ok(SettingsControlReq::SyncPreferences {
                    theme,
                    dock_autohide,
                    fullscreen,
                }) => {
                    self.core.theme = normalize_theme(&theme);
                    self.core.dock_autohide = dock_autohide;
                    self.core.fullscreen = fullscreen;
                    self.core.prefs_loaded = true;
                    self.push_snapshot()?;
                    SettingsControlReply {
                        ok: true,
                        section: Some(self.core.section.as_str().into()),
                        error: None,
                    }
                }
                Ok(SettingsControlReq::Status {}) => SettingsControlReply {
                    ok: true,
                    section: Some(self.core.section.as_str().into()),
                    error: None,
                },
                Err(e) => SettingsControlReply {
                    ok: false,
                    section: None,
                    error: Some(e.text().into()),
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
                            && let Ok(msg) = serde_json::from_str::<SettingsUiMsg>(&full)
                        {
                            self.handle_ui_msg(msg)?;
                        }
                    }
                    ClientEvent::PortalResult {
                        surface_id,
                        response,
                    } if surface_id == self.surface_id => match response {
                        PortalResponse::Account { outcome } => {
                            if self.mutating_in_flight && self.core.busy {
                                self.mutating_in_flight = false;
                            } else {
                                self.account_probe_in_flight = false;
                            }
                            self.core.apply_account_outcome(outcome);
                            self.push_snapshot()?;
                            if self.pending_refresh && !self.account_probe_in_flight {
                                self.request_account_status()?;
                            }
                        }
                        PortalResponse::Desktop { outcome } => {
                            let was_mutating = self.mutating_in_flight && self.core.busy;
                            if was_mutating {
                                self.mutating_in_flight = false;
                            } else {
                                self.desktop_probe_in_flight = false;
                            }
                            let prev_had_disk = self.core.has_disk_prefs;
                            let disk_theme = self.core.theme.clone();
                            let disk_dock = self.core.dock_autohide;
                            self.core.apply_desktop_outcome(outcome);
                            // If user had a persisted ~/.config/os/settings.json on startup,
                            // keep disk values authoritative when initial GetPreferences only
                            // reflects fullscreen state.
                            if !was_mutating && prev_had_disk {
                                self.core.theme = disk_theme;
                                self.core.dock_autohide = disk_dock;
                            }
                            self.push_snapshot()?;
                        }
                        PortalResponse::Mounts { .. } => {
                            self.mutating_in_flight = false;
                            self.core.busy = false;
                        }
                    },
                    ClientEvent::Ok => {
                        let _ = self.pending_reqs.pop_front();
                    }
                    ClientEvent::Error { errno } => {
                        let kind = self.pending_reqs.pop_front();
                        match kind {
                            Some(PendingSeatReq::AccountProbe) => {
                                self.account_probe_in_flight = false;
                            }
                            Some(PendingSeatReq::DesktopProbe) => {
                                self.desktop_probe_in_flight = false;
                            }
                            Some(PendingSeatReq::MutatingPortal) => {
                                self.mutating_in_flight = false;
                                self.core.busy = false;
                                self.core.error = Some(match errno {
                                    Errno::EACCES => "Permission denied. Click the button again to confirm.".into(),
                                    Errno::EBUSY => "Another system dialog is in progress.".into(),
                                    other => other.text().into(),
                                });
                                self.push_snapshot()?;
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }

            if self.closing {
                break;
            }
            self.poll_control_socket()?;
            self.seat.flush_nonblocking()?;
            std::thread::sleep(Duration::from_millis(12));
        }

        let _ = self.seat.send_blocking(&ClientReq::Destroy {
            surface_id: self.surface_id,
        });
        cleanup_control_socket(self.ctrl_path.as_deref(), self.ctrl_ino);
        Ok(())
    }
}

fn resolve_user_home(uid: u32) -> String {
    if let Ok(text) = std::fs::read_to_string("/etc/passwd") {
        for line in text.lines() {
            let fields: Vec<&str> = line.trim().split(':').collect();
            if fields.len() == 7
                && fields[2].parse::<u32>().ok() == Some(uid)
                && !fields[5].is_empty()
            {
                return fields[5].to_owned();
            }
        }
    }
    if let Ok(h) = std::env::var("HOME")
        && !h.is_empty()
        && (uid == 0 || h != "/")
    {
        return h;
    }
    if uid == 0 {
        "/root".into()
    } else {
        "/home/user".into()
    }
}

fn run() -> Result<(), Errno> {
    os_posix::init_preopens().map_err(|_| Errno::EIO)?;
    install_signals();

    let mut initial_section: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                println!("Usage: settings [--section accounts|system|appearance]");
                return Ok(());
            }
            "--section" => {
                if let Some(val) = args.next() {
                    initial_section = Some(val);
                }
            }
            other if !other.starts_with('-') && initial_section.is_none() => {
                initial_section = Some(other.to_owned());
            }
            _ => {}
        }
    }

    let uid = getuid();
    if let Ok(true) = try_forward_to_existing(uid, initial_section.as_deref()) {
        return Ok(());
    }

    let (ctrl_listener, ctrl_path, ctrl_ino) = bind_control_socket(uid);
    let home = resolve_user_home(uid);
    let settings_path = PathBuf::from(&home).join(SETTINGS_REL_PATH);
    let disk_prefs = load_settings_file(&settings_path);
    let core = SettingsCore::new(
        initial_section
            .as_deref()
            .map(SettingsSection::parse)
            .unwrap_or(SettingsSection::Accounts),
        settings_path.display().to_string(),
        disk_prefs,
    );

    let bundle_bytes = std::fs::read(SETTINGS_BUNDLE).map_err(|e| {
        eprintln!("settings: failed to read {SETTINGS_BUNDLE}: {e}");
        Errno::ENOENT
    })?;
    let expected_sha256 = sha256_hex(&bundle_bytes);

    let mut seat = SeatConn::connect()?;
    seat.send_blocking(&ClientReq::Hello {
        versions: vec![1],
        required: vec!["document".into(), "portal".into()],
    })?;
    match seat.recv_blocking()? {
        ClientEvent::Hello { .. } => {}
        ClientEvent::Error { errno } => {
            cleanup_control_socket(ctrl_path.as_deref(), ctrl_ino);
            return Err(errno);
        }
        _ => {
            cleanup_control_socket(ctrl_path.as_deref(), ctrl_ino);
            return Err(Errno::EIO);
        }
    }

    seat.send_blocking(&ClientReq::CreateSurface {
        spec: SurfaceSpec {
            role: SurfaceRole::Window,
            kind: SurfaceKind::Document(DocumentSource {
                bundle_path: SETTINGS_BUNDLE.into(),
                expected_sha256,
            }),
            title: "Settings".into(),
            rect: Rect {
                x: 120,
                y: 44,
                width: 820,
                height: 580,
            },
            min_size: Size {
                width: 320,
                height: 260,
            },
            max_size: None,
            resizable: true,
            app_id: Some("settings".into()),
        },
    })?;

    let mut pending_events = VecDeque::new();
    let surface_id = loop {
        match seat.recv_blocking()? {
            ClientEvent::Created { surface_id } => break surface_id,
            ClientEvent::Error { errno } => {
                cleanup_control_socket(ctrl_path.as_deref(), ctrl_ino);
                return Err(errno);
            }
            ev => pending_events.push_back(ev),
        }
    };

    let app = SettingsApp {
        uid,
        settings_path,
        seat,
        surface_id,
        core,
        doc_ready: false,
        chunk_seq: 0,
        doc_asm: DocChunkAssembler::default(),
        account_probe_in_flight: false,
        desktop_probe_in_flight: false,
        mutating_in_flight: false,
        pending_refresh: false,
        pending_reqs: VecDeque::new(),
        ctrl_listener,
        ctrl_path,
        ctrl_ino,
        pending_events,
        closing: false,
    };
    app.run()
}

fn main() {
    if let Err(err) = run() {
        eprintln!("settings: {}", err.text());
        std::process::exit(1);
    }
}
