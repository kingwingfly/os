//! `/usr/bin/terminal`: ordinary unprivileged GUI Terminal Emulator process (Contract v2 §2.12).
//!
//! Connects to `/run/gui/seat0.sock` over `AF_UNIX`, opens `/dev/ptmx` + `/dev/pts/<N>` pairs
//! for each tab, spawns `/usr/bin/osh` (with `setsid: true` and `ctty_fd: Some(0)`), runs the
//! ANSI VT grid (`os_core::ansi::screen::Screen`), and streams chunked `<= 4096`-byte
//! `DocumentReply` frames to its sealed Document surface. Imports ZERO `gui_*` Wasm functions.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[cfg(target_os = "wasi")]
use std::os::wasi::io::{AsRawFd, FromRawFd};

use abi::Errno;
use abi::gui::{
    ClientEvent, ClientReq, DocumentSource, Rect, SOCKET, Size, SurfaceId, SurfaceKind,
    SurfaceRole, SurfaceSpec, TERMINAL_BUNDLE, TransferItem, frame, sha256_hex, take_frame,
};
use abi::socket::{MSG_CMSG_CLOEXEC, MSG_DONTWAIT, MSG_NOSIGNAL, SOCK_CLOEXEC, SOCK_NONBLOCK};
#[cfg(target_os = "wasi")]
use os_posix::process::{SpawnOptions, Stdin, open_raw, spawn_configured};
use os_posix::process::{WNOHANG, getuid, ioctl, waitpid2};
use os_posix::socket::{UnixListener, UnixStream};
use os_services::terminal::{
    ControlReq, CopyAssembler, DocInMsg, TabModel, TabSummary, chunk_document_message,
    encode_tabs_message, format_paste_bytes,
};
use serde_json::json;

#[cfg(target_os = "wasi")]
const O_RDWR: u32 = 2;
#[cfg(target_os = "wasi")]
const O_NOCTTY: u32 = 0x100;
#[cfg(target_os = "wasi")]
const O_NONBLOCK: u32 = 0x800;
#[cfg(target_os = "wasi")]
const O_CLOEXEC: u32 = 0x80000;

const IOCTL_TIOCSWINSZ: u32 = 0x5414;
#[cfg(target_os = "wasi")]
const IOCTL_TIOCGPTN: u32 = 0x8004_5430;
#[cfg(target_os = "wasi")]
const IOCTL_TIOCSPTLCK: u32 = 0x4004_5431;

static STOP: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "wasi")]
#[unsafe(no_mangle)]
pub extern "C" fn __terminal_signal(sig: u32) {
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
        let name = b"__terminal_signal";
        // SAFETY: valid static callback name and scalar signal numbers.
        // Set SA_RESTART (0x10000000) so `std::thread::sleep` on wasm32-wasip1 never panics
        // on EINTR while STOP is checked in the main event loop.
        unsafe {
            callback_signal(name.as_ptr(), name.len());
            let _ = sigaction(13, 2, 0, 0x10000000); // SIGPIPE -> caught no-op (reset to SIG_DFL on exec)
            for sig in [1, 2, 15] {
                let _ = sigaction(sig, 2, 0, 0x10000000);
            }
        }
    }
}

/// Nonblocking compositor seat connection with bounded outbound write queue.
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
            let (n, _fds, _flags) = self.socket.recv_with_fds(&mut chunk, 0, MSG_CMSG_CLOEXEC)?;
            if n == 0 {
                return Err(Errno::EPIPE);
            }
            self.in_buf.extend_from_slice(&chunk[..n]);
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
            match self
                .socket
                .recv_with_fds(&mut chunk, 0, MSG_DONTWAIT | MSG_CMSG_CLOEXEC)
            {
                Ok((0, _, _)) => return Err(Errno::EPIPE),
                Ok((n, _, _)) => self.in_buf.extend_from_slice(&chunk[..n]),
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

struct LiveTab {
    model: TabModel,
    master: Option<File>,
    child_pid: Option<u32>,
    pending_write: VecDeque<u8>,
    #[cfg_attr(not(target_os = "wasi"), allow(dead_code))]
    shell_argv: Vec<String>,
    initial_cwd: String,
}

impl LiveTab {
    fn spawn(
        id: u32,
        cols: u16,
        rows: u16,
        shell_argv: Vec<String>,
        cwd: String,
        show_spawn_error: bool,
    ) -> io::Result<Self> {
        let mut tab = Self {
            model: TabModel::new(id, cols, rows, Some(cwd.clone())),
            master: None,
            child_pid: None,
            pending_write: VecDeque::new(),
            shell_argv,
            initial_cwd: cwd,
        };
        if let Err(err) = tab.start_shell() {
            if show_spawn_error {
                let prog = tab
                    .shell_argv
                    .first()
                    .map(String::as_str)
                    .unwrap_or("command");
                let msg = format!("{prog}: {err}\r\n[Process exited with status 126]\r\n");
                tab.model.feed_bytes(msg.as_bytes());
                tab.model.exited_status = Some(126);
                tab.model.dirty = true;
                return Ok(tab);
            }
            return Err(err);
        }
        Ok(tab)
    }

    #[cfg(not(target_os = "wasi"))]
    fn start_shell(&mut self) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "WASI required"))
    }

    #[cfg(target_os = "wasi")]
    fn start_shell(&mut self) -> io::Result<()> {
        let master_fd = open_raw("/dev/ptmx", O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC, 0)?;
        // SAFETY: `open_raw` returned a freshly allocated owned fd.
        let master = unsafe { File::from_raw_fd(master_fd as i32) };

        let ptn = ioctl(master_fd, IOCTL_TIOCGPTN, json!(null))?;
        let slave_path = ptn
            .get("name")
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .or_else(|| {
                ptn.get("number")
                    .and_then(|v| v.as_u64())
                    .map(|n| format!("/dev/pts/{n}"))
            })
            .ok_or_else(|| io::Error::other("TIOCGPTN returned no slave path"))?;
        let _ = ioctl(master_fd, IOCTL_TIOCSPTLCK, json!(0))?;
        let _ = ioctl(
            master_fd,
            IOCTL_TIOCSWINSZ,
            json!({
                "columns": self.model.cols,
                "rows": self.model.rows,
                "width": 0,
                "height": 0,
            }),
        );

        let slave_fd = open_raw(&slave_path, O_RDWR | O_NOCTTY | O_CLOEXEC, 0)?;
        // SAFETY: `open_raw` returned a freshly allocated owned slave fd.
        let slave = unsafe { File::from_raw_fd(slave_fd as i32) };

        let mut env_map: std::collections::BTreeMap<String, String> = std::env::vars().collect();
        if let Some((pw_user, pw_home)) = lookup_passwd_by_uid(getuid()) {
            let user_fallback = env_map
                .get("USER")
                .is_none_or(|u| u.is_empty() || (u == "guest" && pw_user != "guest"));
            if user_fallback {
                env_map.insert("USER".into(), pw_user.clone());
                env_map.insert("LOGNAME".into(), pw_user);
            }
            let home_fallback = env_map.get("HOME").is_none_or(|h| {
                h.is_empty() || (h == "/" && pw_home != "/" && !pw_home.is_empty())
            });
            if home_fallback && !pw_home.is_empty() {
                env_map.insert("HOME".into(), pw_home);
            }
        }
        env_map.insert("TERM".into(), "xterm-256color".into());
        env_map.insert("COLORTERM".into(), "truecolor".into());
        env_map.insert("SHELL".into(), "/usr/bin/osh".into());
        env_map
            .entry("PATH".into())
            .or_insert_with(|| "/usr/bin:/bin".into());
        env_map.insert("PWD".into(), self.initial_cwd.clone());
        let env: Vec<String> = env_map
            .into_iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();

        let dup2 = [(slave_fd, 0), (slave_fd, 1), (slave_fd, 2)];
        let opts = SpawnOptions {
            dup2: &dup2,
            setsid: true,
            ctty_fd: Some(0),
            ..SpawnOptions::default()
        };
        let child = spawn_configured(
            &self.shell_argv,
            Stdin::Inherit,
            &self.initial_cwd,
            &env,
            None,
            &opts,
        )?;
        // Immediately close the parent's copy of the slave fd so shell exit produces EIO/hangup.
        drop(slave);

        self.master = Some(master);
        self.child_pid = Some(child.id());
        self.pending_write.clear();
        Ok(())
    }

    fn master_fd(&self) -> Option<u32> {
        #[cfg(target_os = "wasi")]
        {
            self.master.as_ref().map(|f| f.as_raw_fd() as u32)
        }
        #[cfg(not(target_os = "wasi"))]
        {
            None
        }
    }

    fn set_winsz(&self, cols: u16, rows: u16) {
        if let Some(fd) = self.master_fd() {
            let _ = ioctl(
                fd,
                IOCTL_TIOCSWINSZ,
                json!({
                    "columns": cols,
                    "rows": rows,
                    "width": 0,
                    "height": 0,
                }),
            );
        }
    }

    fn queue_input(&mut self, bytes: &[u8]) {
        if self.master.is_none() {
            return;
        }
        self.pending_write.extend(bytes);
        self.flush_writes();
    }

    fn flush_writes(&mut self) {
        let Some(master) = self.master.as_mut() else {
            self.pending_write.clear();
            return;
        };
        while !self.pending_write.is_empty() {
            let (first, _) = self.pending_write.as_slices();
            if first.is_empty() {
                self.pending_write.make_contiguous();
                continue;
            }
            match master.write(first) {
                Ok(0) => break,
                Ok(n) => {
                    self.pending_write.drain(..n);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    self.pending_write.clear();
                    break;
                }
            }
        }
    }

    /// Drain up to `max_bytes` of available output from PTY master; returns
    /// `(meta_changed, hungup, hit_limit)` so unbounded producers (like `yes`) cannot starve
    /// `/dev/input` control events such as `Ctrl+C`.
    fn drain_master_bounded(&mut self, max_bytes: usize) -> (bool, bool, bool) {
        let mut meta_changed = false;
        let mut hungup = false;
        let mut drained = 0usize;
        let mut hit_limit = false;
        let mut buf = [0u8; 4096];
        let mut replies: Vec<u8> = Vec::new();
        while let Some(master) = self.master.as_mut() {
            if drained >= max_bytes {
                hit_limit = true;
                break;
            }
            match master.read(&mut buf) {
                Ok(0) => {
                    hungup = true;
                    break;
                }
                Ok(n) => {
                    drained += n;
                    let (reply, changed) = self.model.feed_bytes(&buf[..n]);
                    meta_changed |= changed;
                    if !reply.is_empty() {
                        replies.extend_from_slice(&reply);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    hungup = true;
                    break;
                }
            }
        }
        if !replies.is_empty() {
            self.queue_input(&replies);
        }
        if hungup {
            self.master = None;
            self.pending_write.clear();
        }
        (meta_changed, hungup, hit_limit)
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
        let mut input = vec![0u64; total * 6]; // 48 bytes per subscription, 8-byte aligned
        let mut output = vec![0u64; total * 4]; // 32 bytes per event, 8-byte aligned
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
        in_bytes[at + 16..at + 20].copy_from_slice(&1u32.to_le_bytes()); // monotonic
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

struct TerminalApp {
    seat: SeatConn,
    surface_id: SurfaceId,
    uid: u32,
    home: String,
    default_shell: String,
    default_cwd: String,
    cols: u16,
    rows: u16,
    next_tab_id: u32,
    tabs: Vec<LiveTab>,
    active_tab: u32,
    doc_ready: bool,
    surface_focused: bool,
    chunk_seq: u64,
    last_title: String,
    last_frame_sent: Instant,
    tabs_dirty: bool,
    force_full_frame: bool,
    copy_assembler: CopyAssembler,
    ctrl_listener: Option<UnixListener>,
    ctrl_path: Option<String>,
    ctrl_ino: Option<u64>,
    closing: bool,
}

impl TerminalApp {
    fn send_doc(&mut self, payload: &str) -> Result<(), Errno> {
        self.chunk_seq = self.chunk_seq.wrapping_add(1);
        for chunk in chunk_document_message(self.chunk_seq, payload) {
            self.seat.queue(&ClientReq::DocumentReply {
                surface_id: self.surface_id,
                text: chunk,
            })?;
        }
        Ok(())
    }

    fn active_tab_index(&self) -> Option<usize> {
        self.tabs.iter().position(|t| t.model.id == self.active_tab)
    }

    fn open_tab(
        &mut self,
        argv: Option<Vec<String>>,
        cwd: Option<String>,
        show_spawn_error: bool,
    ) -> io::Result<u32> {
        let id = self.next_tab_id;
        self.next_tab_id += 1;
        let shell_argv = argv
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| vec![self.default_shell.clone()]);
        let dir = cwd.unwrap_or_else(|| self.default_cwd.clone());
        let tab = LiveTab::spawn(id, self.cols, self.rows, shell_argv, dir, show_spawn_error)?;
        self.tabs.push(tab);
        self.active_tab = id;
        self.tabs_dirty = true;
        self.force_full_frame = true;
        Ok(id)
    }

    fn close_tab(&mut self, id: u32) {
        if let Some(pos) = self.tabs.iter().position(|t| t.model.id == id) {
            // Dropping `LiveTab` closes its PTY master fd, triggering kernel SIGHUP+SIGCONT.
            self.tabs.remove(pos);
            if self.tabs.is_empty() {
                self.closing = true;
                return;
            }
            if self.active_tab == id {
                let next_idx = pos.min(self.tabs.len() - 1);
                self.active_tab = self.tabs[next_idx].model.id;
                self.force_full_frame = true;
            }
            self.tabs_dirty = true;
        }
    }

    fn restart_tab(&mut self, id: u32) {
        let Some(tab) = self.tabs.iter_mut().find(|t| t.model.id == id) else {
            return;
        };
        tab.master = None;
        tab.child_pid = None;
        let cwd = tab.initial_cwd.clone();
        tab.model.reset_for_restart(Some(cwd));
        if let Err(err) = tab.start_shell() {
            let msg = format!("Failed to restart shell: {err}\r\n");
            tab.model.feed_bytes(msg.as_bytes());
            tab.model.exited_status = Some(127);
        }
        self.tabs_dirty = true;
        self.force_full_frame = true;
    }

    fn sync_window_title(&mut self) -> Result<(), Errno> {
        let title = self
            .active_tab_index()
            .map(|i| self.tabs[i].model.window_title(&self.home))
            .unwrap_or_else(|| "Terminal".into());
        if title != self.last_title {
            self.last_title = title.clone();
            self.seat.queue(&ClientReq::SetTitle {
                surface_id: self.surface_id,
                title,
            })?;
        }
        Ok(())
    }

    fn push_tabs_if_dirty(&mut self) -> Result<(), Errno> {
        if !self.doc_ready || !self.tabs_dirty {
            return Ok(());
        }
        let summaries: Vec<TabSummary> = self
            .tabs
            .iter()
            .map(|t| TabSummary {
                id: t.model.id,
                title: t.model.display_title(&self.home),
                exited: t.model.exited_status,
            })
            .collect();
        let msg = encode_tabs_message(self.active_tab, &summaries);
        self.tabs_dirty = false;
        self.send_doc(&msg)?;
        self.sync_window_title()
    }

    fn push_active_frame(&mut self) -> Result<(), Errno> {
        if !self.doc_ready {
            return Ok(());
        }
        let Some(idx) = self.active_tab_index() else {
            return Ok(());
        };
        let force = self.force_full_frame;
        if let Some(frame_json) = self.tabs[idx].model.build_frame_json(force) {
            self.force_full_frame = false;
            self.last_frame_sent = Instant::now();
            self.send_doc(&frame_json)?;
        } else {
            self.force_full_frame = false;
        }
        Ok(())
    }

    fn reap_children(&mut self) {
        while let Ok(Some((pid, status))) = waitpid2(-1, WNOHANG) {
            if let Some(tab) = self.tabs.iter_mut().find(|t| t.child_pid == Some(pid)) {
                // Drain any last bytes still sitting in the PTY master before marking exited.
                let _ = tab.drain_master_bounded(1024 * 1024);
                tab.child_pid = None;
                tab.master = None;
                let code = status.shell_status();
                tab.model.exited_status = Some(code);
                let banner = format!("\r\n[Process exited with status {code}]\r\n");
                tab.model.feed_bytes(banner.as_bytes());
                tab.model.dirty = true;
                self.tabs_dirty = true;
            }
        }
    }

    fn handle_doc_message(&mut self, text: &str) -> Result<(), Errno> {
        let Ok(msg) = serde_json::from_str::<DocInMsg>(text) else {
            return Ok(());
        };
        match msg {
            DocInMsg::Ready { cols, rows } => {
                self.doc_ready = true;
                self.resize_all(cols, rows);
                self.tabs_dirty = true;
                self.force_full_frame = true;
                self.push_tabs_if_dirty()?;
                self.push_active_frame()?;
                if self.surface_focused {
                    self.send_doc(r#"{"t":"focus"}"#)?;
                }
            }
            DocInMsg::Resize { cols, rows } => {
                self.resize_all(cols, rows);
            }
            DocInMsg::In { d } => {
                if let Some(idx) = self.active_tab_index() {
                    self.tabs[idx].queue_input(d.as_bytes());
                }
            }
            DocInMsg::NewTab => {
                let cwd = self
                    .active_tab_index()
                    .and_then(|i| self.tabs[i].model.osc.cwd.clone())
                    .or_else(|| Some(self.default_cwd.clone()));
                if let Err(err) = self.open_tab(None, cwd, false) {
                    eprintln!("terminal: new tab failed: {err}");
                }
            }
            DocInMsg::SelectTab { id } => {
                if self.tabs.iter().any(|t| t.model.id == id) && self.active_tab != id {
                    self.active_tab = id;
                    self.tabs_dirty = true;
                    self.force_full_frame = true;
                }
            }
            DocInMsg::CloseTab { id } => {
                self.close_tab(id);
            }
            DocInMsg::RestartTab { id } => {
                self.restart_tab(id);
            }
            DocInMsg::Copy { text } => {
                self.seat.queue(&ClientReq::ClipboardWrite {
                    surface_id: self.surface_id,
                    item: TransferItem {
                        mime: "text/plain".into(),
                        data: text.into_bytes().into(),
                    },
                })?;
            }
            DocInMsg::CopyChunk { id, i, n, d } => {
                if let Some(full) = self.copy_assembler.push(id, i, n, d) {
                    self.seat.queue(&ClientReq::ClipboardWrite {
                        surface_id: self.surface_id,
                        item: TransferItem {
                            mime: "text/plain".into(),
                            data: full.into_bytes().into(),
                        },
                    })?;
                }
            }
            DocInMsg::Paste => {
                self.seat.queue(&ClientReq::ClipboardRead {
                    surface_id: self.surface_id,
                })?;
            }
        }
        Ok(())
    }

    fn resize_all(&mut self, cols: u16, rows: u16) {
        let cols = cols.clamp(10, 500);
        let rows = rows.clamp(4, 200);
        if self.cols == cols && self.rows == rows {
            return;
        }
        self.cols = cols;
        self.rows = rows;
        for tab in &mut self.tabs {
            tab.model.resize(cols, rows);
            tab.set_winsz(cols, rows);
        }
        self.force_full_frame = true;
    }

    fn service_control_socket(&mut self) -> Result<(), Errno> {
        loop {
            let (client, cred) = {
                let Some(listener) = self.ctrl_listener.as_ref() else {
                    return Ok(());
                };
                match listener.accept_flags(SOCK_NONBLOCK | SOCK_CLOEXEC) {
                    Ok(c) => c,
                    Err(Errno::EAGAIN | Errno::EINTR) => break,
                    Err(_) => break,
                }
            };
            if cred.uid != self.uid {
                continue;
            }
            // Read one bounded control line (short wait up to 200ms).
            let mut raw = Vec::new();
            let mut buf = [0u8; 4096];
            let deadline = Instant::now() + Duration::from_millis(200);
            while Instant::now() < deadline && !raw.contains(&b'\n') && raw.len() < 8192 {
                match client.recv(&mut buf, MSG_DONTWAIT) {
                    Ok(0) => break,
                    Ok(n) => raw.extend_from_slice(&buf[..n]),
                    Err(Errno::EAGAIN | Errno::EINTR) => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
            let reply = match serde_json::from_slice::<ControlReq>(&raw) {
                Ok(ControlReq::OpenTab { argv, cwd }) => match self.open_tab(argv, cwd, true) {
                    Ok(tab) => {
                        if self.doc_ready {
                            let _ = self.send_doc(r#"{"t":"focus"}"#);
                        }
                        json!({ "ok": true, "tab": tab }).to_string() + "\n"
                    }
                    Err(e) => json!({ "ok": false, "error": e.to_string() }).to_string() + "\n",
                },
                Ok(ControlReq::Focus) => {
                    if self.doc_ready {
                        let _ = self.send_doc(r#"{"t":"focus"}"#);
                    }
                    json!({ "ok": true }).to_string() + "\n"
                }
                Err(_) => json!({ "ok": false, "error": "invalid request" }).to_string() + "\n",
            };
            let _ = client.send(reply.as_bytes(), MSG_NOSIGNAL);
        }
        Ok(())
    }

    fn run(mut self) -> Result<(), Errno> {
        while !self.closing && !STOP.load(Ordering::SeqCst) {
            self.seat.flush()?;

            // 1. Drain compositor events.
            for event in self.seat.drain_events()? {
                match event {
                    ClientEvent::CloseRequested { .. } => {
                        self.closing = true;
                        break;
                    }
                    ClientEvent::Focus { focused, .. } => {
                        self.surface_focused = focused;
                        if focused && self.doc_ready {
                            self.send_doc(r#"{"t":"focus"}"#)?;
                        }
                    }
                    ClientEvent::DocumentMessage { text, .. } => {
                        self.handle_doc_message(&text)?;
                    }
                    ClientEvent::PasteRequested { surface_id } => {
                        self.seat.queue(&ClientReq::ClipboardRead { surface_id })?;
                    }
                    ClientEvent::Clipboard { item } => {
                        if let Some(idx) = self.active_tab_index() {
                            let bp = self.tabs[idx].model.screen.bracketed_paste;
                            let bytes = format_paste_bytes(&item.data, bp);
                            self.tabs[idx].queue_input(&bytes);
                        }
                    }
                    _ => {}
                }
            }
            if self.closing || STOP.load(Ordering::SeqCst) {
                break;
            }

            // 2. Service optional per-user control socket.
            self.service_control_socket()?;

            // 3. Drain bounded PTY master output per tick and flush pending writes so
            //    unbounded producers (e.g. `yes`) never starve `/dev/input` (Ctrl+C).
            let mut any_hungup = false;
            let mut any_hit_limit = false;
            for tab in &mut self.tabs {
                tab.flush_writes();
                let (meta_changed, hungup, hit_limit) = tab.drain_master_bounded(64 * 1024);
                tab.flush_writes();
                if meta_changed {
                    self.tabs_dirty = true;
                }
                if hungup {
                    any_hungup = true;
                    if tab.model.exited_status.is_none() {
                        tab.model.dirty = true;
                    }
                }
                any_hit_limit |= hit_limit;
            }

            // 4. Reap exited shells (without closing emulator or sibling tabs).
            self.reap_children();
            if any_hungup {
                // If master hung up before child reaped, mark exited if still no master & no pid.
                for tab in &mut self.tabs {
                    if tab.master.is_none()
                        && tab.child_pid.is_none()
                        && tab.model.exited_status.is_none()
                    {
                        tab.model.exited_status = Some(0);
                        tab.model.dirty = true;
                        self.tabs_dirty = true;
                    }
                }
            }

            // 5. Push tab bar updates and coalesced active-tab frames (~16ms cadence).
            self.push_tabs_if_dirty()?;
            let active_dirty = self.force_full_frame
                || self
                    .active_tab_index()
                    .is_some_and(|i| self.tabs[i].model.dirty);
            let now = Instant::now();
            let elapsed = now.saturating_duration_since(self.last_frame_sent);
            if active_dirty && (self.force_full_frame || elapsed >= Duration::from_millis(16)) {
                self.push_active_frame()?;
            }
            self.seat.flush()?;

            // 6. Wait event-driven via poll_oneoff over seat socket, PTY masters, and control socket.
            let mut read_fds = vec![self.seat.fd()];
            if let Some(ref listener) = self.ctrl_listener {
                read_fds.push(listener.as_raw_fd());
            }
            if !any_hit_limit {
                for tab in &self.tabs {
                    if let Some(fd) = tab.master_fd() {
                        read_fds.push(fd);
                    }
                }
            }
            let mut write_fds = Vec::new();
            if self.seat.has_pending_writes() {
                write_fds.push(self.seat.fd());
            }
            for tab in &self.tabs {
                if !tab.pending_write.is_empty()
                    && let Some(fd) = tab.master_fd()
                {
                    write_fds.push(fd);
                }
            }
            let pending_frame = self
                .active_tab_index()
                .is_some_and(|i| self.tabs[i].model.dirty);
            let wait_ms = if any_hit_limit {
                1
            } else if pending_frame {
                16u64.saturating_sub(elapsed.as_millis() as u64).max(1)
            } else if any_hungup {
                10
            } else {
                100
            };
            poll_fds(&read_fds, &write_fds, wait_ms);
        }

        // Clean teardown: drop all tabs (closing PTY masters -> SIGHUP+SIGCONT), destroy surface,
        // and unlink our control socket only if it is still the inode we bound.
        self.tabs.clear();
        let _ = self.seat.send_blocking(&ClientReq::Destroy {
            surface_id: self.surface_id,
        });
        cleanup_control_socket(self.ctrl_path.take().as_deref(), self.ctrl_ino.take());
        Ok(())
    }
}

fn lstat_path(path: &str) -> io::Result<abi::Stat> {
    let reply = os_posix::batch(&[abi::Call::Lstat {
        path: path.to_owned(),
    }])?;
    let val = reply
        .results
        .into_iter()
        .next()
        .ok_or_else(|| io::Error::other("empty lstat reply"))?
        .into_result()
        .map_err(|e| io::Error::other(e.to_string()))?;
    serde_json::from_value::<abi::Stat>(val).map_err(|e| io::Error::other(e.to_string()))
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

fn lookup_passwd_by_uid(uid: u32) -> Option<(String, String)> {
    let text = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in text.lines() {
        let fields: Vec<&str> = line.trim().split(':').collect();
        if fields.len() == 7 && fields[2].parse::<u32>().ok() == Some(uid) {
            return Some((fields[0].to_owned(), fields[5].to_owned()));
        }
    }
    None
}

fn bind_control_socket(uid: u32) -> (Option<UnixListener>, Option<String>, Option<u64>) {
    let dir = format!("/run/user/{uid}");
    if std::fs::create_dir_all(&dir).is_err() {
        return (None, None, None);
    }
    if os_posix::chmod(Path::new(&dir), 0o700).is_err() {
        return (None, None, None);
    }
    let Ok(dir_st) = lstat_path(&dir) else {
        return (None, None, None);
    };
    if (dir_st.mode & 0o170000) != 0o040000 || dir_st.uid != uid || (dir_st.mode & 0o7777) != 0o700
    {
        return (None, None, None);
    }
    let sock_path = format!("{dir}/terminal.sock");
    let _ = std::fs::remove_file(&sock_path);
    match UnixListener::bind_with_mode(&sock_path, 0o600) {
        Ok(listener) => {
            let _ = listener.set_nonblocking(true);
            let sock_ino = lstat_path(&sock_path)
                .ok()
                .filter(|st| {
                    (st.mode & 0o170000) == 0o140000 && st.uid == uid && (st.mode & 0o7777) == 0o600
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

fn run() -> Result<(), Errno> {
    os_posix::init_preopens().map_err(|_| Errno::EIO)?;
    install_signals();

    let args: Vec<String> = std::env::args().skip(1).collect();
    if matches!(args.first().map(String::as_str), Some("--help" | "-h")) {
        println!("Usage: terminal [--shell PATH] [--cwd DIR] [-- ARGV...]");
        return Ok(());
    }

    let mut default_shell = "/usr/bin/osh".to_owned();
    let mut initial_cwd: Option<String> = None;
    let mut initial_argv: Option<Vec<String>> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--shell" => {
                if let Some(s) = args.get(i + 1) {
                    default_shell = s.clone();
                    i += 2;
                    continue;
                }
                return Err(Errno::EINVAL);
            }
            "--cwd" => {
                if let Some(c) = args.get(i + 1) {
                    initial_cwd = Some(c.clone());
                    i += 2;
                    continue;
                }
                return Err(Errno::EINVAL);
            }
            "--" => {
                let tail = args[i + 1..].to_vec();
                if !tail.is_empty() {
                    initial_argv = Some(tail);
                }
                break;
            }
            _ => {
                i += 1;
            }
        }
    }

    let uid = getuid();
    let pw_home = lookup_passwd_by_uid(uid)
        .map(|(_, h)| h)
        .filter(|h| !h.is_empty());
    let home = std::env::var("HOME")
        .ok()
        .filter(|h| !h.is_empty() && !(h == "/" && pw_home.as_deref().is_some_and(|p| p != "/")))
        .or(pw_home)
        .unwrap_or_else(|| "/".into());
    let default_cwd = initial_cwd.unwrap_or_else(|| {
        os_posix::getcwd()
            .ok()
            .and_then(|p| p.to_str().map(str::to_owned))
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| home.clone())
    });

    // Read the sealed Document bundle and compute its SHA-256 digest.
    let bundle_bytes = std::fs::read(TERMINAL_BUNDLE).map_err(|e| {
        eprintln!("terminal: failed to read {TERMINAL_BUNDLE}: {e}");
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
                bundle_path: TERMINAL_BUNDLE.into(),
                expected_sha256,
            }),
            title: "Terminal".into(),
            // Zero width/height asks the compositor to apply `default_app_rect("terminal")`
            // or the user's persisted `~/.config/os/desktop-layout.json` geometry.
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
            app_id: Some("terminal".into()),
        },
    })?;

    let surface_id = match seat.recv_blocking()? {
        ClientEvent::Created { surface_id } => surface_id,
        ClientEvent::Error { errno } => return Err(errno),
        _ => return Err(Errno::EIO),
    };

    let (ctrl_listener, ctrl_path, ctrl_ino) = bind_control_socket(uid);

    let mut app = TerminalApp {
        seat,
        surface_id,
        uid,
        home,
        default_shell,
        default_cwd: default_cwd.clone(),
        cols: 80,
        rows: 24,
        next_tab_id: 1,
        tabs: Vec::new(),
        active_tab: 0,
        doc_ready: false,
        surface_focused: false,
        chunk_seq: 0,
        last_title: "Terminal".into(),
        last_frame_sent: Instant::now() - Duration::from_secs(1),
        tabs_dirty: true,
        force_full_frame: true,
        copy_assembler: CopyAssembler::default(),
        ctrl_listener,
        ctrl_path,
        ctrl_ino,
        closing: false,
    };

    if let Err(err) = app.open_tab(initial_argv, Some(default_cwd), false) {
        eprintln!("terminal: failed to spawn initial shell: {err}");
        cleanup_control_socket(app.ctrl_path.take().as_deref(), app.ctrl_ino.take());
        return Err(Errno::EIO);
    }

    app.run()
}

fn main() {
    if let Err(err) = run() {
        eprintln!("terminal: {err:?}");
        std::process::exit(1);
    }
}
