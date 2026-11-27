//! `/usr/bin/editor`: ordinary unprivileged GUI text & source editor process (`#64` `L6c-1`).
//!
//! Connects to `/run/gui/seat0.sock` over `AF_UNIX`, renders CodeMirror 6 inside a sealed
//! Document surface (`/usr/share/gui/editor/editor.json`), opens/saves files strictly with its
//! own POSIX credentials and conditional `Call::Open { version }` revision checks, persists
//! atomic recovery drafts under `~/.local/state/os/editor/drafts/`, and exports unsaved drafts
//! via compositor-gated `ClientReq::ExportFile`. Imports ZERO `gui_*` Wasm functions.

use std::collections::VecDeque;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use abi::gui::{
    ClientEvent, ClientReq, DocumentSource, EDITOR_BUNDLE, MAX_EXPORT_INLINE, Rect, SOCKET, Size,
    SurfaceId, SurfaceKind, SurfaceRole, SurfaceSpec, frame, sha256_hex, take_frame,
};
use abi::socket::{MSG_CMSG_CLOEXEC, MSG_DONTWAIT, MSG_NOSIGNAL};
use abi::{Call, Errno, FdRef, Stat};
use os_posix::process::getuid;
use os_posix::socket::UnixStream;
use os_services::associations::is_editor_blocked_media_path;
use os_services::editor::{
    DRAFT_VERSION, DraftLoadOutcome, DraftRecord, EditorCore, EditorHostMsg, EditorUiMsg,
    MAX_EDIT_BYTES, MAX_EDITOR_ASSEMBLED_BYTES, MAX_EDITOR_CHUNKS, copy_path_for,
    decode_editable_text, export_filename, load_draft, remove_draft, save_draft_atomic,
    window_title,
};
use os_services::gui_doc::{DocChunkAssembler, chunk_document_message};
use serde_json::Value;

const READ_CHUNK_BYTES: u64 = 256 * 1024;
const MAX_OUTBOX_BYTES: usize = 8 * 1024 * 1024;

static STOP: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "wasi")]
#[unsafe(no_mangle)]
pub extern "C" fn __editor_signal(sig: u32) {
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
        let name = b"__editor_signal";
        // SAFETY: static callback name and scalar signal numbers with SA_RESTART so
        // `std::thread::sleep` on wasm32-wasip1 never panics on EINTR.
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
        std::thread::sleep(Duration::from_millis(timeout_ms.min(20)));
    }
}

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn lookup_passwd_home(uid: u32) -> Option<String> {
    let content = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in content.lines() {
        let mut parts = line.split(':');
        let _name = parts.next()?;
        let _pw = parts.next()?;
        let id = parts.next()?.parse::<u32>().ok()?;
        let _gid = parts.next()?;
        let _gecos = parts.next()?;
        let home = parts.next()?;
        if id == uid && !home.is_empty() {
            return Some(home.to_owned());
        }
    }
    None
}

fn resolve_abs_path(raw: &str, cwd: &str, home: &str) -> Result<String, Errno> {
    if raw.is_empty() || raw.contains('\0') {
        return Err(Errno::EINVAL);
    }
    let expanded = if raw == "~" {
        home.to_owned()
    } else if let Some(rest) = raw.strip_prefix("~/") {
        format!("{}/{rest}", home.trim_end_matches('/'))
    } else {
        raw.to_owned()
    };
    let joined = if expanded.starts_with('/') {
        expanded
    } else if cwd == "/" || cwd.is_empty() {
        format!("/{expanded}")
    } else {
        format!("{}/{expanded}", cwd.trim_end_matches('/'))
    };
    let mut parts: Vec<&str> = Vec::new();
    for seg in joined.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    let out = if parts.is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", parts.join("/"))
    };
    if out.len() > abi::PATH_MAX {
        return Err(Errno::ENAMETOOLONG);
    }
    Ok(out)
}

fn sys_call(call: Call) -> Result<Value, abi::Error> {
    let mut res = os_posix::batch(&[call]).map_err(|e| {
        abi::Error::because(os_posix::errno_of(&e).unwrap_or(Errno::EIO), e.to_string())
    })?;
    res.results
        .pop()
        .ok_or_else(|| abi::Error::from(Errno::EIO))?
        .into_result()
}

struct LoadedFile {
    content: String,
    base_rev: Option<String>,
    existing: bool,
    read_only: bool,
}

fn load_file_with_revision(path: &str) -> Result<LoadedFile, String> {
    if is_editor_blocked_media_path(path) {
        return Err("vim supports text, Markdown, and source files only".into());
    }
    let batch = os_posix::batch(&[
        Call::Stat {
            path: path.to_owned(),
        },
        Call::Access {
            path: path.to_owned(),
            mode: 2,
        },
    ])
    .map_err(|e| e.to_string())?;
    let mut iter = batch.results.into_iter();
    let stat_res = iter
        .next()
        .ok_or_else(|| "stat failed".to_owned())?
        .into_result();
    let access_res = iter
        .next()
        .ok_or_else(|| "access failed".to_owned())?
        .into_result();

    match stat_res {
        Err(err) if err.errno == Errno::ENOENT => Ok(LoadedFile {
            content: String::new(),
            base_rev: None,
            existing: false,
            read_only: false,
        }),
        Err(err) => Err(err.detail.filter(|d| !d.is_empty()).unwrap_or_else(|| {
            if err.errno == Errno::EACCES {
                "Permission denied".into()
            } else {
                err.errno.text().to_owned()
            }
        })),
        Ok(stat_val) => {
            let st: Stat =
                serde_json::from_value(stat_val).map_err(|_| "invalid stat".to_owned())?;
            if st.is_dir() {
                return Err("This is a directory".into());
            }
            if st.size > MAX_EDIT_BYTES as u64 {
                return Err("File exceeds 2 MB; download it to edit locally".into());
            }
            // Request revision tracking via `version: Some("")` on O_RDONLY so both local
            // mounts (`local:v1:...`) and `/mnt/cloud` (server ETag) return a version token.
            let opened_val = sys_call(Call::Open {
                path: path.to_owned(),
                flags: abi::O_RDONLY,
                mode: 0,
                size: None,
                sha256: None,
                version: Some(String::new()),
            })
            .map_err(|e| {
                e.detail
                    .filter(|d| !d.is_empty())
                    .unwrap_or_else(|| e.errno.text().to_owned())
            })?;
            let fd = opened_val
                .get("fd")
                .and_then(Value::as_u64)
                .ok_or_else(|| "open returned invalid fd".to_owned())? as u32;
            let mut open_rev = opened_val
                .get("version")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_owned);

            let mut bytes = Vec::with_capacity((st.size as usize).min(MAX_EDIT_BYTES));
            let mut offset: u64 = 0;
            let read_result: Result<(), String> = (|| {
                loop {
                    let pread_val = sys_call(Call::Pread {
                        fd: Some(FdRef::Fd(fd)),
                        path: None,
                        offset,
                        count: READ_CHUNK_BYTES,
                    })
                    .map_err(|e| {
                        e.detail
                            .filter(|d| !d.is_empty())
                            .unwrap_or_else(|| e.errno.text().to_owned())
                    })?;
                    let chunk: abi::Bytes = serde_json::from_value(
                        pread_val.get("data").cloned().unwrap_or(Value::Null),
                    )
                    .map_err(|_| "invalid read response".to_owned())?;
                    if chunk.is_empty() {
                        break;
                    }
                    if bytes.len().saturating_add(chunk.len()) > MAX_EDIT_BYTES {
                        return Err("File exceeds 2 MB".into());
                    }
                    bytes.extend_from_slice(&chunk);
                    offset = offset.saturating_add(chunk.len() as u64);
                    if (chunk.len() as u64) < READ_CHUNK_BYTES {
                        break;
                    }
                }
                Ok(())
            })();
            let close_val = sys_call(Call::Close { fd: FdRef::Fd(fd) }).ok();
            if open_rev.is_none() {
                open_rev = close_val
                    .as_ref()
                    .and_then(|v| v.get("version"))
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned);
            }
            read_result?;
            let content = decode_editable_text(&bytes)?;
            Ok(LoadedFile {
                content,
                base_rev: open_rev,
                existing: true,
                read_only: access_res.is_err(),
            })
        }
    }
}

fn save_file_conditional(
    path: &str,
    text: &str,
    existing: bool,
    base_rev: Option<&str>,
    force_overwrite: bool,
) -> Result<Option<String>, abi::Error> {
    let bytes = text.as_bytes();
    if bytes.len() > MAX_EDIT_BYTES {
        return Err(abi::Error::because(
            Errno::EFBIG,
            "The editor can save up to 2 MB of text. Download your draft first.",
        ));
    }
    let (flags, version) = if existing {
        if force_overwrite {
            (abi::O_WRONLY | abi::O_CREAT | abi::O_TRUNC, None)
        } else {
            (abi::O_WRONLY | abi::O_TRUNC, base_rev.map(str::to_owned))
        }
    } else if force_overwrite {
        (abi::O_WRONLY | abi::O_CREAT | abi::O_TRUNC, None)
    } else {
        (abi::O_WRONLY | abi::O_CREAT | abi::O_EXCL, None)
    };

    let opened_val = sys_call(Call::Open {
        path: path.to_owned(),
        flags,
        mode: 0o666,
        size: Some(bytes.len() as u64),
        sha256: Some(sha256_hex(bytes)),
        version,
    })?;
    let fd = opened_val
        .get("fd")
        .and_then(Value::as_u64)
        .ok_or_else(|| abi::Error::from(Errno::EIO))? as u32;
    let chunk_size = opened_val
        .get("chunk_size")
        .and_then(Value::as_u64)
        .filter(|&c| c > 0)
        .unwrap_or(abi::INLINE_MAX) as usize;

    let mut idx: u64 = 0;
    let mut off = 0usize;
    while off < bytes.len() {
        let end = (off + chunk_size).min(bytes.len());
        let chunk = bytes[off..end].to_vec();
        if let Err(err) = sys_call(Call::Pwrite {
            fd: FdRef::Fd(fd),
            index: idx,
            data: abi::Bytes(chunk),
        }) {
            let _ = sys_call(Call::Discard { fd: FdRef::Fd(fd) });
            return Err(err);
        }
        off = end;
        idx += 1;
    }

    let closed_val = sys_call(Call::Close { fd: FdRef::Fd(fd) })?;
    let new_rev = closed_val
        .get("version")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    Ok(new_rev)
}

struct SeatConn {
    socket: UnixStream,
    in_buf: Vec<u8>,
    out_queue: VecDeque<(Vec<u8>, usize)>,
    out_bytes: usize,
}

impl SeatConn {
    fn connect() -> Result<Self, Errno> {
        let mut attempts = 0u32;
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
            out_bytes: 0,
        })
    }

    #[allow(clippy::unnecessary_cast)]
    fn fd(&self) -> u32 {
        self.socket.as_raw_fd() as u32
    }

    fn has_pending_writes(&self) -> bool {
        !self.out_queue.is_empty()
    }

    fn queue(&mut self, req: &ClientReq) -> Result<(), Errno> {
        let bytes = frame(req)?;
        if self.out_bytes.saturating_add(bytes.len()) > MAX_OUTBOX_BYTES {
            return Err(Errno::ENOBUFS);
        }
        self.out_bytes += bytes.len();
        self.out_queue.push_back((bytes, 0));
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Errno> {
        while let Some((buf, off)) = self.out_queue.front_mut() {
            match self.socket.send(&buf[*off..], MSG_NOSIGNAL | MSG_DONTWAIT) {
                Ok(0) => return Err(Errno::EPIPE),
                Ok(n) => {
                    *off += n;
                    self.out_bytes = self.out_bytes.saturating_sub(n);
                    if *off >= buf.len() {
                        self.out_queue.pop_front();
                    }
                }
                Err(Errno::EAGAIN | Errno::EINTR) => break,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn send_blocking(&mut self, req: &ClientReq) -> Result<(), Errno> {
        self.queue(req)?;
        let deadline = Instant::now() + Duration::from_secs(15);
        while self.has_pending_writes() {
            self.flush()?;
            if self.has_pending_writes() {
                if Instant::now() >= deadline {
                    return Err(Errno::ETIMEDOUT);
                }
                poll_fds(&[], &[self.fd()], 20);
            }
        }
        Ok(())
    }

    fn recv_blocking(&mut self) -> Result<ClientEvent, Errno> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(ev) = take_frame(&mut self.in_buf)? {
                return Ok(ev);
            }
            let mut chunk = [0u8; 4096];
            match self
                .socket
                .recv_with_fds(&mut chunk, 1, MSG_DONTWAIT | MSG_CMSG_CLOEXEC)
            {
                Ok((0, _, _)) => return Err(Errno::EPIPE),
                Ok((n, _, _)) => {
                    self.in_buf.extend_from_slice(&chunk[..n]);
                }
                Err(Errno::EAGAIN | Errno::EINTR) => {
                    if Instant::now() >= deadline {
                        return Err(Errno::ETIMEDOUT);
                    }
                    poll_fds(&[self.fd()], &[], 20);
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn drain_events(&mut self) -> Result<Vec<ClientEvent>, Errno> {
        let mut events = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            match self
                .socket
                .recv_with_fds(&mut chunk, 1, MSG_DONTWAIT | MSG_CMSG_CLOEXEC)
            {
                Ok((0, _, _)) => return Err(Errno::EPIPE),
                Ok((n, _, _)) => {
                    self.in_buf.extend_from_slice(&chunk[..n]);
                }
                Err(Errno::EAGAIN | Errno::EINTR) => break,
                Err(e) => return Err(e),
            }
        }
        while let Some(ev) = take_frame(&mut self.in_buf)? {
            events.push(ev);
        }
        Ok(events)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingReq {
    DocumentReply,
    ExportFile,
}

struct EditorApp {
    seat: SeatConn,
    surface_id: SurfaceId,
    home: String,
    core: EditorCore,
    chunk_seq: u64,
    doc_asm: DocChunkAssembler,
    closing: bool,
    pending_reqs: VecDeque<PendingReq>,
}

impl EditorApp {
    fn send_doc_msg(&mut self, msg: &EditorHostMsg) -> Result<(), Errno> {
        let payload = serde_json::to_string(msg).map_err(|_| Errno::EINVAL)?;
        self.chunk_seq = self.chunk_seq.wrapping_add(1);
        for frame_text in chunk_document_message(self.chunk_seq, &payload) {
            self.seat.queue(&ClientReq::DocumentReply {
                surface_id: self.surface_id,
                text: frame_text,
            })?;
            self.pending_reqs.push_back(PendingReq::DocumentReply);
        }
        Ok(())
    }

    fn handle_save(
        &mut self,
        content: String,
        force_overwrite: bool,
        save_as_copy: bool,
    ) -> Result<(), Errno> {
        if self.core.saving || (self.core.read_only && !save_as_copy) {
            return Ok(());
        }
        if content.len() > MAX_EDIT_BYTES {
            self.core.status =
                "The editor can save up to 2 MB of text. Download your draft first.".to_owned();
            let msg = self.core.status_message(None);
            return self.send_doc_msg(&msg);
        }

        if save_as_copy {
            let mut saved_to = None;
            for n in 1..=99u32 {
                let candidate = copy_path_for(&self.core.path, n);
                match save_file_conditional(&candidate, &content, false, None, false) {
                    Ok(_) => {
                        saved_to = Some(candidate);
                        break;
                    }
                    Err(e) if e.errno == Errno::EEXIST => continue,
                    Err(e) => {
                        let msg = self.core.apply_save_err(e.errno, e.detail.as_deref());
                        return self.send_doc_msg(&msg);
                    }
                }
            }
            match saved_to {
                Some(copy_path) => {
                    self.core.status = format!("Saved copy to {copy_path}");
                    let msg = self.core.status_message(None);
                    return self.send_doc_msg(&msg);
                }
                None => {
                    self.core.status = "Could not find an unused copy filename".to_owned();
                    let msg = self.core.status_message(None);
                    return self.send_doc_msg(&msg);
                }
            }
        }

        self.core.saving = true;
        match save_file_conditional(
            &self.core.path,
            &content,
            self.core.existing,
            self.core.base_rev.as_deref(),
            force_overwrite,
        ) {
            Ok(new_rev) => {
                remove_draft(&self.home, &self.core.path);
                let msg = self.core.apply_save_ok(content, new_rev);
                self.send_doc_msg(&msg)
            }
            Err(err) => {
                // Keep recovery draft safely on disk whenever a save conflict occurs.
                if !self.core.draft_read_only {
                    let _ = save_draft_atomic(
                        &self.home,
                        &DraftRecord {
                            version: DRAFT_VERSION,
                            path: self.core.path.clone(),
                            base_rev: self.core.base_rev.clone(),
                            updated_at_ms: now_epoch_ms(),
                            content,
                        },
                    );
                }
                let msg = self.core.apply_save_err(err.errno, err.detail.as_deref());
                self.send_doc_msg(&msg)
            }
        }
    }

    fn handle_reload_from_disk(&mut self) -> Result<(), Errno> {
        match load_file_with_revision(&self.core.path) {
            Ok(loaded) => {
                remove_draft(&self.home, &self.core.path);
                self.core.content = loaded.content;
                self.core.base_rev = loaded.base_rev;
                self.core.existing = loaded.existing;
                self.core.read_only = loaded.read_only;
                self.core.dirty = !loaded.existing;
                self.core.show_discard = false;
                self.core.conflict = None;
                self.core.pending_draft = None;
                self.core.status = if loaded.read_only {
                    "Read-only: your account does not have write permission".to_owned()
                } else {
                    "Reloaded from disk".to_owned()
                };
                let msg = EditorHostMsg::ReplaceContent {
                    content: self.core.content.clone(),
                    dirty: self.core.dirty,
                    status: self.core.status.clone(),
                    read_only: self.core.read_only,
                    existing: self.core.existing,
                    show_discard: false,
                    has_draft: false,
                    conflict: None,
                };
                self.send_doc_msg(&msg)
            }
            Err(err) => {
                self.core.status = err;
                let msg = self.core.status_message(None);
                self.send_doc_msg(&msg)
            }
        }
    }

    fn handle_doc_message(&mut self, raw: &str) -> Result<(), Errno> {
        let Some(full) = self.doc_asm.feed(raw) else {
            return Ok(());
        };
        let Ok(msg) = serde_json::from_str::<EditorUiMsg>(&full) else {
            return Ok(());
        };
        match msg {
            EditorUiMsg::Ready {} => {
                let init = self.core.init_message();
                self.send_doc_msg(&init)?;
            }
            EditorUiMsg::Dirty { dirty } => {
                self.core.dirty = dirty;
                if !dirty {
                    self.core.show_discard = false;
                }
            }
            EditorUiMsg::DraftSync { content } => {
                if !self.core.read_only
                    && !self.core.draft_read_only
                    && self.core.load_error.is_none()
                    && content.len() <= MAX_EDIT_BYTES
                {
                    let _ = save_draft_atomic(
                        &self.home,
                        &DraftRecord {
                            version: DRAFT_VERSION,
                            path: self.core.path.clone(),
                            base_rev: self.core.base_rev.clone(),
                            updated_at_ms: now_epoch_ms(),
                            content,
                        },
                    );
                }
            }
            EditorUiMsg::Save {
                content,
                force_overwrite,
                save_as_copy,
            } => {
                self.handle_save(content, force_overwrite, save_as_copy)?;
            }
            EditorUiMsg::Close { force, dirty } => {
                if self.core.request_close(force, dirty) {
                    if force {
                        remove_draft(&self.home, &self.core.path);
                    }
                    self.closing = true;
                } else {
                    let st = self.core.status_message(None);
                    self.send_doc_msg(&st)?;
                }
            }
            EditorUiMsg::Download { content } => {
                let bytes = content.into_bytes();
                if bytes.len() > MAX_EXPORT_INLINE {
                    self.core.status = "Draft exceeds 2 MB download limit".to_owned();
                    let st = self.core.status_message(None);
                    self.send_doc_msg(&st)?;
                    return Ok(());
                }
                self.seat.queue(&ClientReq::ExportFile {
                    surface_id: self.surface_id,
                    filename: export_filename(&self.core.path),
                    mime: "text/plain;charset=utf-8".to_owned(),
                    data: Some(abi::Bytes(bytes)),
                })?;
                self.pending_reqs.push_back(PendingReq::ExportFile);
            }
            EditorUiMsg::RestoreDraft {} => {
                if let Some(msg) = self.core.restore_pending_draft() {
                    self.send_doc_msg(&msg)?;
                }
            }
            EditorUiMsg::DiscardDraft {} => {
                remove_draft(&self.home, &self.core.path);
                let msg = self.core.discard_pending_draft();
                self.send_doc_msg(&msg)?;
            }
            EditorUiMsg::ReloadFromDisk {} => {
                self.handle_reload_from_disk()?;
            }
        }
        Ok(())
    }

    fn run(mut self) -> Result<(), Errno> {
        while !self.closing && !STOP.load(Ordering::SeqCst) {
            self.seat.flush()?;
            for event in self.seat.drain_events()? {
                match event {
                    ClientEvent::CloseRequested { .. } => {
                        if self.core.request_close(false, self.core.dirty) {
                            self.closing = true;
                            break;
                        } else {
                            let st = self.core.status_message(None);
                            self.send_doc_msg(&st)?;
                        }
                    }
                    ClientEvent::Focus { focused: true, .. } => {
                        self.send_doc_msg(&EditorHostMsg::Focus {})?;
                    }
                    ClientEvent::DocumentMessage { text, .. } => {
                        self.handle_doc_message(&text)?;
                    }
                    ClientEvent::Error { errno } => {
                        if self.pending_reqs.pop_front() == Some(PendingReq::ExportFile) {
                            self.core.status = format!("Download failed: {}", errno.text());
                            let st = self.core.status_message(None);
                            self.send_doc_msg(&st)?;
                        }
                    }
                    ClientEvent::Ok => {
                        let _ = self.pending_reqs.pop_front();
                    }
                    _ => {}
                }
            }
            if self.closing || STOP.load(Ordering::SeqCst) {
                break;
            }
            self.seat.flush()?;
            let read_fds = [self.seat.fd()];
            let mut write_fds = Vec::new();
            if self.seat.has_pending_writes() {
                write_fds.push(self.seat.fd());
            }
            poll_fds(&read_fds, &write_fds, 50);
        }

        let _ = self.seat.send_blocking(&ClientReq::Destroy {
            surface_id: self.surface_id,
        });
        Ok(())
    }
}

fn run() -> Result<(), Errno> {
    os_posix::init_preopens().map_err(|_| Errno::EIO)?;
    install_signals();

    let args: Vec<String> = std::env::args().skip(1).collect();
    if matches!(args.first().map(String::as_str), Some("--help" | "-h")) {
        println!("Usage: editor [--wait] [--] FILE");
        return Ok(());
    }

    let mut target_arg: Option<String> = None;
    let mut after_dash = false;
    for arg in &args {
        if !after_dash && arg == "--" {
            after_dash = true;
            continue;
        }
        if !after_dash && arg == "--wait" {
            continue;
        }
        if target_arg.is_none() {
            target_arg = Some(arg.clone());
        }
    }
    let Some(raw_path) = target_arg else {
        eprintln!("editor: missing file operand");
        return Err(Errno::EINVAL);
    };

    let uid = getuid();
    let pw_home = lookup_passwd_home(uid);
    let home = std::env::var("HOME")
        .ok()
        .filter(|h| !h.is_empty() && !(h == "/" && pw_home.as_deref().is_some_and(|p| p != "/")))
        .or(pw_home)
        .unwrap_or_else(|| "/".into());
    let cwd = os_posix::getcwd()
        .ok()
        .and_then(|p| p.to_str().map(str::to_owned))
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| "/".into());
    let abs_path = resolve_abs_path(&raw_path, &cwd, &home)?;

    let core = match load_file_with_revision(&abs_path) {
        Ok(loaded) => {
            let draft = if loaded.read_only {
                DraftLoadOutcome::Missing
            } else {
                load_draft(&home, &abs_path)
            };
            EditorCore::from_loaded(
                abs_path.clone(),
                loaded.content,
                loaded.base_rev,
                loaded.existing,
                loaded.read_only,
                draft,
            )
        }
        Err(err) => EditorCore::from_load_error(abs_path.clone(), err),
    };

    let bundle_bytes = std::fs::read(Path::new(EDITOR_BUNDLE)).map_err(|e| {
        eprintln!("editor: failed to read {EDITOR_BUNDLE}: {e}");
        os_posix::errno_of(&e).unwrap_or(Errno::ENOENT)
    })?;
    let expected_sha256 = sha256_hex(&bundle_bytes);

    let mut seat = SeatConn::connect()?;
    seat.send_blocking(&ClientReq::Hello {
        versions: vec![1],
        required: vec!["document".into(), "export".into()],
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
                bundle_path: EDITOR_BUNDLE.into(),
                expected_sha256,
            }),
            title: window_title(&abs_path),
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
            app_id: Some("editor".into()),
        },
    })?;

    let surface_id = match seat.recv_blocking()? {
        ClientEvent::Created { surface_id } => surface_id,
        ClientEvent::Error { errno } => return Err(errno),
        _ => return Err(Errno::EIO),
    };

    let app = EditorApp {
        seat,
        surface_id,
        home,
        core,
        chunk_seq: 0,
        doc_asm: DocChunkAssembler::with_limits(MAX_EDITOR_ASSEMBLED_BYTES, MAX_EDITOR_CHUNKS),
        closing: false,
        pending_reqs: VecDeque::new(),
    };
    app.run()
}

fn main() {
    if let Err(err) = run() {
        eprintln!("editor: {err:?}");
        std::process::exit(1);
    }
}
