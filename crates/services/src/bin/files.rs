//! `/usr/bin/files`: ordinary unprivileged GUI File Manager process (`#63` `L6b-1`).
//!
//! Connects to `/run/gui/seat0.sock` over `AF_UNIX`, renders inside a sealed Document surface
//! (`/usr/share/gui/files/files.json`), lists directories strictly with its own POSIX process
//! credentials (`os_posix::batch`), persists last directory in `~/.config/os/files.json`,
//! enforces single-instance IPC over `/run/user/<uid>/files.sock`, launches executables in
//! `/usr/bin/terminal`, opens documents via `/run/user/<uid>/desktop-actions.sock`, and handles
//! local `SCM_RIGHTS` multi-file uploads + capability-verified `/mnt/cloud` resumable uploads.
//! Imports ZERO `gui_*` Wasm functions.

use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[cfg(not(target_os = "wasi"))]
use std::os::fd::FromRawFd;
#[cfg(target_os = "wasi")]
use std::os::wasi::io::FromRawFd;

use abi::contract::fs_magic;
use abi::gui::{
    ClientEvent, ClientReq, DocumentSource, FILES_BUNDLE, Rect, SOCKET, Size, SurfaceId,
    SurfaceKind, SurfaceRole, SurfaceSpec, frame, sha256_hex, take_frame,
};
use abi::socket::{MSG_CMSG_CLOEXEC, MSG_DONTWAIT, MSG_NOSIGNAL, SOCK_CLOEXEC, SOCK_NONBLOCK};
use abi::{Call, Dirent, Errno, IN_MODIFY, R_OK, Stat, X_OK};
use os_core::{Entry, kind, parent};
use os_posix::process::getuid;
use os_posix::socket::{UnixListener, UnixStream};
use os_services::files::{
    BUSY_NOTICE, CONFIG_REL_PATH, ConfigLoadOutcome, FilesControlReply, FilesControlReq, FilesCore,
    FilesHostMsg, FilesUiMsg, entry_view, faststart_warning_for_reader, is_mp4_family, join_child,
    load_config_file, resolve_location, sanitize_upload_name, save_config_file_atomic,
    upload_open_error_message, window_title,
};
use os_services::gui_doc::{DocChunkAssembler, chunk_document_message};
use serde_json::{Value, json};

const COPY_CHUNK_BYTES: usize = 64 * 1024;
const MAX_CONTROL_LINE_BYTES: usize = 8192;
const MAX_CONTROL_PEERS_PER_TICK: usize = 16;
const LIST_BATCH_ENTRIES: usize = 200;
const CLOUD_CACHE_TTL: Duration = Duration::from_secs(15);

static STOP: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "wasi")]
#[unsafe(no_mangle)]
pub extern "C" fn __files_signal(sig: u32) {
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
        let name = b"__files_signal";
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

/// Nonblocking compositor seat connection supporting `SCM_RIGHTS` file descriptor reception.
struct SeatConn {
    socket: UnixStream,
    in_buf: Vec<u8>,
    out_queue: VecDeque<(Vec<u8>, usize)>,
    received_fds: VecDeque<File>,
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
            received_fds: VecDeque::new(),
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
            let (n, fds, flags) = self.socket.recv_with_fds(&mut chunk, 4, MSG_CMSG_CLOEXEC)?;
            for fd in fds {
                // SAFETY: recvmsg installed a freshly allocated owned descriptor.
                self.received_fds
                    .push_back(unsafe { File::from_raw_fd(fd as _) });
            }
            if flags & abi::socket::MSG_CTRUNC != 0 {
                return Err(Errno::EINVAL);
            }
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
                .recv_with_fds(&mut chunk, 4, MSG_DONTWAIT | MSG_CMSG_CLOEXEC)
            {
                Ok((0, _, _)) => return Err(Errno::EPIPE),
                Ok((n, fds, flags)) => {
                    for fd in fds {
                        // SAFETY: recvmsg installed a freshly allocated owned descriptor.
                        self.received_fds
                            .push_back(unsafe { File::from_raw_fd(fd as _) });
                    }
                    if flags & abi::socket::MSG_CTRUNC != 0 {
                        return Err(Errno::EINVAL);
                    }
                    self.in_buf.extend_from_slice(&chunk[..n]);
                }
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

    fn pop_fd(&mut self) -> Option<File> {
        self.received_fds.pop_front()
    }

    #[cfg(target_os = "wasi")]
    fn fd(&self) -> u32 {
        self.socket.as_raw_fd()
    }
    #[cfg(not(target_os = "wasi"))]
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

fn load_uid_gid_tables() -> (HashMap<u32, String>, HashMap<u32, String>) {
    let mut users = HashMap::new();
    if let Ok(text) = std::fs::read_to_string("/etc/passwd") {
        for line in text.lines() {
            let fields: Vec<&str> = line.trim().split(':').collect();
            if fields.len() == 7
                && let Ok(uid) = fields[2].parse::<u32>()
            {
                users.insert(uid, fields[0].to_owned());
            }
        }
    }
    let mut groups = HashMap::new();
    if let Ok(text) = std::fs::read_to_string("/etc/group") {
        for line in text.lines() {
            let fields: Vec<&str> = line.trim().split(':').collect();
            if fields.len() >= 3
                && let Ok(gid) = fields[2].parse::<u32>()
            {
                groups.insert(gid, fields[0].to_owned());
            }
        }
    }
    (users, groups)
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

fn check_enterable(path: &str) -> Result<(), String> {
    let reply = os_posix::batch(&[
        Call::Stat {
            path: path.to_owned(),
        },
        Call::Access {
            path: path.to_owned(),
            mode: X_OK,
        },
    ])
    .map_err(|e| e.to_string())?;
    let mut iter = reply.results.into_iter();
    let st_val = iter
        .next()
        .ok_or_else(|| "stat failed".to_owned())?
        .into_result()
        .map_err(|e| e.to_string())?;
    let st: Stat = serde_json::from_value(st_val).map_err(|e| e.to_string())?;
    if !st.is_dir() {
        return Err(Errno::ENOTDIR.text().to_owned());
    }
    iter.next()
        .ok_or_else(|| "access failed".to_owned())?
        .into_result()
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn build_entry(
    name: &str,
    path: String,
    lstat: Option<&Stat>,
    opened: Option<&Stat>,
    denied: bool,
    users: &HashMap<u32, String>,
    groups: &HashMap<u32, String>,
) -> Entry {
    let Some(lstat) = lstat else {
        return Entry {
            name: name.to_owned(),
            path,
            kind: kind(name).into(),
            owner: "?".into(),
            group: "?".into(),
            denied: true,
            ..Entry::default()
        };
    };
    let directory = opened.unwrap_or(lstat).is_dir();
    let owner = if !lstat.user.is_empty() {
        lstat.user.clone()
    } else {
        users
            .get(&lstat.uid)
            .cloned()
            .unwrap_or_else(|| lstat.uid.to_string())
    };
    let group = if !lstat.group.is_empty() {
        lstat.group.clone()
    } else {
        groups
            .get(&lstat.gid)
            .cloned()
            .unwrap_or_else(|| lstat.gid.to_string())
    };
    Entry {
        name: name.to_owned(),
        path,
        directory,
        size: lstat.size,
        kind: if directory { "directory" } else { kind(name) }.into(),
        owner,
        group,
        mode: lstat.perm(),
        uploaded: lstat.writing.as_ref().map(|w| w.received),
        recording: lstat.writing.as_ref().is_some_and(|w| w.recording),
        link: lstat.link.clone(),
        device: lstat.rdev.clone(),
        links: lstat.nlink,
        mtime: lstat.mtime,
        acl: lstat.acl,
        denied,
    }
}

fn list_directory(dir: &str) -> Result<Vec<Entry>, String> {
    let reply = os_posix::batch(&[Call::Getdents {
        path: dir.to_owned(),
        cookie: 0,
        count: None,
    }])
    .map_err(|e| e.to_string())?;
    let val = reply
        .results
        .into_iter()
        .next()
        .ok_or_else(|| "empty getdents reply".to_owned())?
        .into_result()
        .map_err(|e| e.to_string())?;
    let dirents: Vec<Dirent> = serde_json::from_value(val).map_err(|e| e.to_string())?;
    if dirents.is_empty() {
        return Ok(Vec::new());
    }

    let (users, groups) = load_uid_gid_tables();
    let mut entries = Vec::with_capacity(dirents.len());
    for chunk in dirents.chunks(LIST_BATCH_ENTRIES) {
        let mut calls = Vec::with_capacity(chunk.len() * 3);
        for d in chunk {
            let path = join_child(dir, &d.name);
            calls.push(Call::Stat { path: path.clone() });
            calls.push(Call::Access {
                path: path.clone(),
                mode: R_OK,
            });
            calls.push(Call::Access {
                path,
                mode: R_OK | X_OK,
            });
        }
        let mut answers = os_posix::batch(&calls)
            .map_err(|e| e.to_string())?
            .results
            .into_iter();
        for d in chunk {
            let opened: Option<Stat> = answers
                .next()
                .and_then(|r| r.into_result().ok())
                .and_then(|v| serde_json::from_value(v).ok());
            let read_res = answers.next().map(abi::Return::into_result);
            let list_res = answers.next().map(abi::Return::into_result);
            let is_dir = opened.as_ref().is_some_and(Stat::is_dir);
            let check = if is_dir { list_res } else { read_res };
            let denied = check.is_some_and(|r| {
                r.as_ref()
                    .is_err_and(|e| matches!(e.errno, Errno::EACCES | Errno::EPERM))
            });
            let path = join_child(dir, &d.name);
            entries.push(build_entry(
                &d.name,
                path,
                d.stat.as_ref(),
                opened.as_ref(),
                denied,
                &users,
                &groups,
            ));
        }
    }
    Ok(entries)
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

fn try_forward_to_existing(uid: u32, dir: Option<&str>, upload: bool) -> Result<bool, Errno> {
    let sock_path = format!("/run/user/{uid}/files.sock");
    let stream = match UnixStream::connect(&sock_path) {
        Ok(s) => s,
        Err(Errno::ENOENT | Errno::ECONNREFUSED) => return Ok(false),
        Err(e) => return Err(e),
    };
    let peer = stream.peer_cred()?;
    if peer.uid != uid {
        return Err(Errno::EACCES);
    }
    let req = if let Some(path) = dir {
        FilesControlReq::OpenDir {
            path: path.to_owned(),
        }
    } else if upload {
        FilesControlReq::TriggerUpload {}
    } else {
        FilesControlReq::Focus {}
    };
    let mut bytes = serde_json::to_vec(&req).map_err(|_| Errno::EINVAL)?;
    bytes.push(b'\n');
    send_all(&stream, &bytes)?;
    let _ = read_json_line(&stream, 2_000);
    if dir.is_some() && upload {
        let _ = send_user_socket_rpc(uid, &sock_path, &json!({ "op": "trigger_upload" }), 2_000);
    }
    let _ = send_desktop_action(uid, &json!({ "op": "focus_app", "app_id": "files" }));
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
    let sock_path = format!("{dir}/files.sock");
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

#[cfg(target_os = "wasi")]
fn create_exclusive_file(path: &str) -> Result<File, Errno> {
    const O_WRONLY: u32 = 1;
    const O_CREAT: u32 = 0x40;
    const O_EXCL: u32 = 0x80;
    const O_CLOEXEC: u32 = 0x80000;
    let fd = os_posix::process::open_raw(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o666)
        .map_err(|e| os_posix::errno_of(&e).unwrap_or(Errno::EIO))?;
    // SAFETY: `open_raw` returned a freshly allocated owned fd.
    Ok(unsafe { File::from_raw_fd(fd as i32) })
}

#[cfg(not(target_os = "wasi"))]
fn create_exclusive_file(path: &str) -> Result<File, Errno> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| os_posix::errno_of(&e).unwrap_or(Errno::EIO))
}

struct LocalUploadBatch {
    dest_dir: String,
    results: Vec<String>,
    cancelled: bool,
    total: u32,
}

struct CloudDirCache {
    dir: String,
    wd: u32,
    at: Instant,
    entries: Option<Vec<Entry>>,
}

fn is_cloud_mount(dir: &str) -> bool {
    os_posix::statfs(Path::new(dir)).is_ok_and(|st| st.f_type == fs_magic::OS_CLOUD_MAGIC)
}

fn add_cloud_watch(dir: &str) -> Option<u32> {
    let reply = os_posix::batch(&[Call::InotifyAddWatch {
        path: dir.to_owned(),
        mask: IN_MODIFY,
        handle: None,
    }])
    .ok()?;
    let val = reply.results.into_iter().next()?.into_result().ok()?;
    val.as_u64().and_then(|v| u32::try_from(v).ok())
}

fn rm_cloud_watch(wd: u32) {
    let _ = os_posix::batch(&[Call::InotifyRmWatch { wd }]);
}

struct FilesApp {
    seat: SeatConn,
    surface_id: SurfaceId,
    uid: u32,
    core: FilesCore,
    config_path: PathBuf,
    doc_ready: bool,
    chunk_seq: u64,
    doc_asm: DocChunkAssembler,
    last_title: String,
    active_pick_id: Option<u64>,
    local_batch: Option<LocalUploadBatch>,
    pending_upload_on_ready: bool,
    cloud_cache: Option<CloudDirCache>,
    ctrl_listener: Option<UnixListener>,
    ctrl_path: Option<String>,
    ctrl_ino: Option<u64>,
    pending_events: VecDeque<ClientEvent>,
    closing: bool,
}

impl FilesApp {
    fn send_doc_msg(&mut self, msg: &FilesHostMsg) -> Result<(), Errno> {
        if !self.doc_ready {
            return Ok(());
        }
        let payload = serde_json::to_string(msg).map_err(|_| Errno::EINVAL)?;
        self.chunk_seq = self.chunk_seq.wrapping_add(1);
        for chunk in chunk_document_message(self.chunk_seq, &payload) {
            self.seat.queue(&ClientReq::DocumentReply {
                surface_id: self.surface_id,
                text: chunk,
            })?;
        }
        Ok(())
    }

    fn sync_window_title(&mut self) -> Result<(), Errno> {
        let title = window_title(&self.core.cwd);
        if title != self.last_title {
            self.last_title = title.clone();
            self.seat.queue(&ClientReq::SetTitle {
                surface_id: self.surface_id,
                title,
            })?;
        }
        Ok(())
    }

    fn persist_cwd(&self) {
        if !self.core.config_read_only {
            let _ = save_config_file_atomic(&self.config_path, &self.core.cwd);
        }
    }

    fn clear_cloud_watch(&mut self) {
        if let Some(prev) = self.cloud_cache.take() {
            rm_cloud_watch(prev.wd);
        }
    }

    fn fetch_listing_and_watch(
        &mut self,
        path: &str,
        force_rewatch: bool,
    ) -> Result<Vec<Entry>, String> {
        let cloud = is_cloud_mount(path);
        let wd = if cloud {
            let existing_wd = match self.cloud_cache.as_ref() {
                Some(prev) if prev.dir == path && !force_rewatch => Some(prev.wd),
                Some(_) => {
                    self.clear_cloud_watch();
                    None
                }
                None => None,
            };
            existing_wd.or_else(|| add_cloud_watch(path))
        } else {
            self.clear_cloud_watch();
            None
        };
        let listed = list_directory(path);
        match (&listed, wd) {
            (Ok(entries), Some(wd)) => {
                self.cloud_cache = Some(CloudDirCache {
                    dir: path.to_owned(),
                    wd,
                    at: Instant::now(),
                    entries: Some(entries.clone()),
                });
            }
            (Err(_), Some(wd)) => {
                self.cloud_cache = Some(CloudDirCache {
                    dir: path.to_owned(),
                    wd,
                    at: Instant::now(),
                    entries: None,
                });
            }
            _ => {}
        }
        listed
    }

    fn navigate_to(&mut self, path: String) -> Result<(), Errno> {
        if let Some(cache) = self.cloud_cache.as_ref()
            && cache.dir == path
            && cache.at.elapsed() < CLOUD_CACHE_TTL
            && let Some(entries) = cache.entries.clone()
        {
            self.core.notice.clear();
            let state = self.core.apply_listing(path, Ok(entries), false);
            self.persist_cwd();
            self.sync_window_title()?;
            return self.send_doc_msg(&state);
        }
        if let Err(err) = check_enterable(&path) {
            let msg = self.core.set_notice(format!("{path}: {err}"));
            self.send_doc_msg(&msg)?;
            return Ok(());
        }
        self.core.notice.clear();
        let listed = self.fetch_listing_and_watch(&path, false);
        let state = self.core.apply_listing(path, listed, false);
        self.persist_cwd();
        self.sync_window_title()?;
        self.send_doc_msg(&state)
    }

    fn refresh(&mut self, clear_notice: bool) -> Result<(), Errno> {
        if clear_notice {
            self.core.notice.clear();
        }
        if let Some(cache) = self.cloud_cache.as_mut() {
            cache.entries = None;
        }
        let path = self.core.cwd.clone();
        let listed = self.fetch_listing_and_watch(&path, clear_notice);
        let state = self.core.apply_listing(path, listed, true);
        self.send_doc_msg(&state)
    }

    fn open_entry(&mut self, name: &str) -> Result<(), Errno> {
        let Some(entry) = self.core.find_entry(name).cloned() else {
            return Ok(());
        };
        let view = entry_view(&entry);
        if let Some(refusal) = view.refusal {
            let msg = self.core.set_notice(refusal);
            return self.send_doc_msg(&msg);
        }
        if entry.directory {
            return self.navigate_to(entry.path);
        }
        let mut is_runnable = view.runnable;
        if entry.link.is_some() {
            match os_posix::stat(Path::new(&entry.path), true) {
                Err(err) => {
                    let text = os_posix::errno_of(&err)
                        .map(|e| e.text().to_owned())
                        .unwrap_or_else(|| err.to_string());
                    let msg = self.core.set_notice(format!("{}: {text}", entry.name));
                    return self.send_doc_msg(&msg);
                }
                Ok(st) if st.is_dir() => return self.navigate_to(entry.path),
                Ok(st) => {
                    is_runnable |= (st.mode & 0o111) != 0;
                }
            }
        }
        if is_runnable {
            let cwd = parent(&entry.path).to_owned();
            let term_sock = format!("/run/user/{}/terminal.sock", self.uid);
            let req = json!({
                "op": "open_tab",
                "argv": [entry.path],
                "cwd": cwd,
            });
            let launched = match send_user_socket_rpc(self.uid, &term_sock, &req, 2_000) {
                Ok(reply) if reply.get("ok").and_then(Value::as_bool) == Some(true) => Ok(()),
                Ok(reply) => Err(reply
                    .get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("Failed to launch program")
                    .to_owned()),
                Err(Errno::ENOENT | Errno::ECONNREFUSED) => send_desktop_action(
                    self.uid,
                    &json!({
                        "op": "open_terminal_tab",
                        "argv": [entry.path],
                        "cwd": cwd,
                    }),
                ),
                Err(e) => Err(e.text().to_owned()),
            };
            match launched {
                Ok(()) => {
                    let _ = send_desktop_action(
                        self.uid,
                        &json!({ "op": "focus_app", "app_id": "terminal" }),
                    );
                    let msg = self.core.set_notice(String::new());
                    self.send_doc_msg(&msg)?;
                }
                Err(err) => {
                    let msg = self.core.set_notice(err);
                    self.send_doc_msg(&msg)?;
                }
            }
            return Ok(());
        }

        match send_desktop_action(self.uid, &json!({ "op": "open", "path": entry.path })) {
            Ok(()) => {
                let msg = self.core.set_notice(String::new());
                self.send_doc_msg(&msg)
            }
            Err(err) => {
                let msg = self.core.set_notice(err);
                self.send_doc_msg(&msg)
            }
        }
    }

    fn start_upload(&mut self) -> Result<(), Errno> {
        if self.core.uploading {
            let msg = self.core.set_notice(BUSY_NOTICE);
            return self.send_doc_msg(&msg);
        }
        let cwd = self.core.cwd.clone();
        let is_cloud =
            os_posix::statfs(Path::new(&cwd)).is_ok_and(|st| st.f_type == fs_magic::OS_CLOUD_MAGIC);
        let cloud_dest = is_cloud.then_some(cwd);
        let prog = self.core.set_progress("↑ choosing files", true);
        self.send_doc_msg(&prog)?;
        self.active_pick_id = None;
        self.local_batch = None;
        self.seat.queue(&ClientReq::PickFile {
            surface_id: self.surface_id,
            multiple: true,
            cloud_dest,
        })
    }

    fn cancel_upload(&mut self) -> Result<(), Errno> {
        if !self.core.uploading {
            return Ok(());
        }
        if let Some(batch) = self.local_batch.as_mut() {
            batch.cancelled = true;
        }
        let req_id = self.active_pick_id.unwrap_or(0);
        let _ = self
            .seat
            .queue(&ClientReq::CancelPick { request_id: req_id });
        if self.core.progress == "↑ choosing files" && self.local_batch.is_none() {
            self.active_pick_id = None;
            let prog = self.core.set_progress(String::new(), false);
            self.send_doc_msg(&prog)?;
        }
        Ok(())
    }

    fn handle_picked(
        &mut self,
        name: Option<String>,
        size: u64,
        index: u32,
        total: u32,
    ) -> Result<(), Errno> {
        let Some(mut src) = self.seat.pop_fd() else {
            let prog = self
                .core
                .set_progress("✕ Upload failed: missing descriptor", false);
            self.local_batch = None;
            return self.send_doc_msg(&prog);
        };
        let total = total.max(1);
        if index > 0 && self.local_batch.is_none() {
            // Trailing item from an already-cancelled or aborted batch: drop fd and ignore.
            drop(src);
            return Ok(());
        }
        if index == 0 || self.local_batch.is_none() {
            self.core.notice.clear();
            self.local_batch = Some(LocalUploadBatch {
                dest_dir: self.core.cwd.clone(),
                results: Vec::new(),
                cancelled: false,
                total,
            });
        }
        let display_name = name.unwrap_or_else(|| format!("upload-{index}"));
        let already_cancelled = self.local_batch.as_ref().is_some_and(|b| b.cancelled);
        if !already_cancelled {
            let outcome = self.copy_one_picked_file(&display_name, size, &mut src);
            if let Some(batch) = self.local_batch.as_mut() {
                match outcome {
                    Ok((line, warning)) => {
                        batch.results.push(line);
                        if let Some(w) = warning {
                            batch.results.push(format!("  ⚠ {w}"));
                        }
                    }
                    Err(err_line) => {
                        batch.results.push(err_line);
                    }
                }
            }
        }
        drop(src);

        let done = self
            .local_batch
            .as_ref()
            .is_none_or(|b| b.cancelled || index.saturating_add(1) >= b.total);
        if done {
            let summary = self
                .local_batch
                .take()
                .map(|b| b.results.join("\n"))
                .unwrap_or_default();
            self.active_pick_id = None;
            let prog = self.core.set_progress(summary, false);
            self.send_doc_msg(&prog)?;
            self.refresh(false)?;
        }
        Ok(())
    }

    fn copy_one_picked_file(
        &mut self,
        display_name: &str,
        declared_size: u64,
        src: &mut File,
    ) -> Result<(String, Option<String>), String> {
        let clean_name = match sanitize_upload_name(display_name) {
            Ok(n) => n,
            Err(err) => return Err(format!("✕ {display_name}: {err}")),
        };
        let dest_dir = self
            .local_batch
            .as_ref()
            .map(|b| b.dest_dir.clone())
            .unwrap_or_else(|| self.core.cwd.clone());
        let file_size = src.metadata().map(|m| m.len()).unwrap_or(declared_size);

        // Inspect MP4 faststart before copying (matching web/app.js faststartWarning).
        let mut warning = None;
        if is_mp4_family(clean_name) {
            let prog = self
                .core
                .set_progress(format!("↑ {clean_name} · checking faststart"), true);
            let _ = self.send_doc_msg(&prog);
            let _ = self.seat.flush();
            warning = faststart_warning_for_reader(clean_name, file_size, src);
            let _ = src.seek(SeekFrom::Start(0));
        }
        let flagged = if warning.is_some() {
            " · ⚠ not faststart"
        } else {
            ""
        };

        let dest_path = join_child(&dest_dir, clean_name);
        let mut dst = match create_exclusive_file(&dest_path) {
            Ok(f) => f,
            Err(Errno::EEXIST) => {
                let is_dir =
                    os_posix::stat(Path::new(&dest_path), false).is_ok_and(|st| st.is_dir());
                let msg = if is_dir {
                    upload_open_error_message(Errno::EISDIR)
                } else {
                    upload_open_error_message(Errno::EEXIST)
                };
                return Err(format!("✕ {clean_name}: {msg}"));
            }
            Err(errno) => {
                return Err(format!(
                    "✕ {clean_name}: {}",
                    upload_open_error_message(errno)
                ));
            }
        };

        let mut buf = vec![0u8; COPY_CHUNK_BYTES];
        let mut copied: u64 = 0;
        let mut last_report = Instant::now() - Duration::from_secs(1);

        loop {
            // Poll compositor events between chunks so CancelUpload can abort mid-copy.
            if let Ok(events) = self.seat.drain_events() {
                for ev in events {
                    let _ = self.handle_mid_copy_event(ev);
                }
            }
            if STOP.load(Ordering::SeqCst)
                || self.closing
                || self.local_batch.as_ref().is_some_and(|b| b.cancelled)
            {
                drop(dst);
                let _ = std::fs::remove_file(&dest_path);
                let _ = self.seat.queue(&ClientReq::CancelPick { request_id: 0 });
                return Err(format!("✕ {clean_name}: Upload cancelled"));
            }

            let n = match src.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    drop(dst);
                    let _ = std::fs::remove_file(&dest_path);
                    return Err(format!("✕ {clean_name}: {e}"));
                }
            };
            if let Err(e) = dst.write_all(&buf[..n]) {
                drop(dst);
                let _ = std::fs::remove_file(&dest_path);
                let msg = os_posix::errno_of(&e)
                    .map(upload_open_error_message)
                    .unwrap_or_else(|| e.to_string());
                return Err(format!("✕ {clean_name}: {msg}"));
            }
            copied = copied.saturating_add(n as u64);
            if last_report.elapsed() >= Duration::from_millis(50) || copied >= file_size {
                last_report = Instant::now();
                let pct = (copied * 100)
                    .checked_div(file_size)
                    .map_or(100, |p| p.min(100));
                let prog = self
                    .core
                    .set_progress(format!("↑ {clean_name} · {pct}%{flagged}"), true);
                let _ = self.send_doc_msg(&prog);
                let _ = self.seat.flush();
            }
        }
        let _ = dst.flush();
        Ok((format!("✓ {clean_name}"), warning))
    }

    fn handle_mid_copy_event(&mut self, event: ClientEvent) -> Result<(), Errno> {
        match &event {
            ClientEvent::CloseRequested { .. } => {
                self.closing = true;
            }
            ClientEvent::DocumentMessage { text, .. } => {
                if let Ok(FilesUiMsg::CancelUpload {}) = serde_json::from_str::<FilesUiMsg>(text) {
                    if let Some(batch) = self.local_batch.as_mut() {
                        batch.cancelled = true;
                    }
                } else {
                    self.pending_events.push_back(event);
                }
            }
            ClientEvent::Error {
                errno: Errno::ECANCELED,
            } => {
                if let Some(batch) = self.local_batch.as_mut() {
                    batch.cancelled = true;
                }
            }
            _ => {
                // Preserve queued Picked (subsequent multi-file items) and other seat events
                // in strict FIFO order relative to `self.seat.received_fds`.
                self.pending_events.push_back(event);
            }
        }
        Ok(())
    }

    fn handle_doc_message(&mut self, raw: &str) -> Result<(), Errno> {
        let Some(full) = self.doc_asm.feed(raw) else {
            return Ok(());
        };
        let Ok(msg) = serde_json::from_str::<FilesUiMsg>(&full) else {
            return Ok(());
        };
        match msg {
            FilesUiMsg::Ready {} => {
                self.doc_ready = true;
                let state = self.core.state_message(true);
                self.send_doc_msg(&state)?;
                if !self.core.progress.is_empty() {
                    let prog = FilesHostMsg::Progress {
                        text: self.core.progress.clone(),
                        uploading: self.core.uploading,
                    };
                    self.send_doc_msg(&prog)?;
                }
                if self.pending_upload_on_ready {
                    self.pending_upload_on_ready = false;
                    let _ = self.start_upload();
                }
            }
            FilesUiMsg::Nav { path } => match self.core.resolve_typed(&path) {
                Ok(resolved) => self.navigate_to(resolved)?,
                Err(err) => {
                    let notice = self.core.set_notice(err);
                    self.send_doc_msg(&notice)?;
                }
            },
            FilesUiMsg::Up {} => {
                let up = self.core.parent_dir();
                self.navigate_to(up)?;
            }
            FilesUiMsg::Refresh {} => {
                self.refresh(true)?;
            }
            FilesUiMsg::Open { name } => {
                self.open_entry(&name)?;
            }
            FilesUiMsg::Upload {} => {
                self.start_upload()?;
            }
            FilesUiMsg::CancelUpload {} => {
                self.cancel_upload()?;
            }
            FilesUiMsg::DismissProgress {} => {
                if !self.core.uploading {
                    let prog = self.core.set_progress(String::new(), false);
                    self.send_doc_msg(&prog)?;
                }
            }
            FilesUiMsg::OpenMounts {} => {
                if let Err(err) =
                    send_desktop_action(self.uid, &json!({ "op": "focus_app", "app_id": "mounts" }))
                {
                    let notice = self.core.set_notice(err);
                    self.send_doc_msg(&notice)?;
                }
            }
        }
        Ok(())
    }

    fn service_control_socket(&mut self) -> Result<(), Errno> {
        for _ in 0..MAX_CONTROL_PEERS_PER_TICK {
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
            if cred.uid != self.uid && cred.uid != 0 {
                continue;
            }
            let mut raw = Vec::new();
            let mut buf = [0u8; 4096];
            let deadline = Instant::now() + Duration::from_millis(200);
            while Instant::now() < deadline
                && !raw.contains(&b'\n')
                && raw.len() < MAX_CONTROL_LINE_BYTES
            {
                match client.recv(&mut buf, MSG_DONTWAIT) {
                    Ok(0) => break,
                    Ok(n) => {
                        let room = MAX_CONTROL_LINE_BYTES.saturating_sub(raw.len());
                        raw.extend_from_slice(&buf[..n.min(room)]);
                    }
                    Err(Errno::EAGAIN | Errno::EINTR) => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
            let line = match raw.iter().position(|&b| b == b'\n') {
                Some(pos) => &raw[..pos],
                None => &raw[..],
            };
            let reply = match serde_json::from_slice::<FilesControlReq>(line) {
                Ok(FilesControlReq::OpenDir { path }) => match self.core.resolve_typed(&path) {
                    Ok(resolved) => match self.navigate_to(resolved) {
                        Ok(()) => FilesControlReply {
                            ok: true,
                            error: None,
                        },
                        Err(e) => FilesControlReply {
                            ok: false,
                            error: Some(e.text().to_owned()),
                        },
                    },
                    Err(err) => FilesControlReply {
                        ok: false,
                        error: Some(err),
                    },
                },
                Ok(FilesControlReq::Refresh {}) => match self.refresh(false) {
                    Ok(()) => FilesControlReply {
                        ok: true,
                        error: None,
                    },
                    Err(e) => FilesControlReply {
                        ok: false,
                        error: Some(e.text().to_owned()),
                    },
                },
                Ok(FilesControlReq::TriggerUpload {}) => {
                    let res = if self.doc_ready {
                        self.start_upload()
                    } else {
                        self.pending_upload_on_ready = true;
                        Ok(())
                    };
                    match res {
                        Ok(()) => FilesControlReply {
                            ok: true,
                            error: None,
                        },
                        Err(e) => FilesControlReply {
                            ok: false,
                            error: Some(e.text().to_owned()),
                        },
                    }
                }
                Ok(FilesControlReq::Focus {}) => {
                    let _ = self.send_doc_msg(&FilesHostMsg::Focus {});
                    FilesControlReply {
                        ok: true,
                        error: None,
                    }
                }
                Err(_) => FilesControlReply {
                    ok: false,
                    error: Some("invalid request".into()),
                },
            };
            if let Ok(mut out) = serde_json::to_vec(&reply) {
                out.push(b'\n');
                let _ = client.send(&out, MSG_NOSIGNAL);
            }
        }
        Ok(())
    }

    fn run(mut self) -> Result<(), Errno> {
        while !self.closing && !STOP.load(Ordering::SeqCst) {
            self.seat.flush()?;

            self.pending_events.extend(self.seat.drain_events()?);
            while let Some(event) = self.pending_events.pop_front() {
                match event {
                    ClientEvent::CloseRequested { .. } => {
                        self.closing = true;
                        break;
                    }
                    ClientEvent::DocumentMessage { text, .. } => {
                        self.handle_doc_message(&text)?;
                    }
                    ClientEvent::Picked {
                        name,
                        size,
                        index,
                        total,
                        ..
                    } => {
                        self.handle_picked(name, size, index, total)?;
                    }
                    ClientEvent::UploadProgress {
                        request_id,
                        text,
                        done,
                        error,
                        ..
                    } => {
                        if done {
                            self.active_pick_id = None;
                            let final_text = if text.is_empty() {
                                error.map(|e| format!("✕ {e}")).unwrap_or_default()
                            } else {
                                text
                            };
                            let prog = self.core.set_progress(final_text, false);
                            self.send_doc_msg(&prog)?;
                            self.refresh(false)?;
                        } else {
                            self.active_pick_id = Some(request_id);
                            let prog = self.core.set_progress(text, true);
                            self.send_doc_msg(&prog)?;
                        }
                    }
                    ClientEvent::Error {
                        errno: Errno::ECANCELED,
                    } => {
                        if self.core.uploading {
                            self.active_pick_id = None;
                            let summary = self
                                .local_batch
                                .take()
                                .map(|b| b.results.join("\n"))
                                .unwrap_or_default();
                            let prog = self.core.set_progress(summary, false);
                            self.send_doc_msg(&prog)?;
                        }
                    }
                    ClientEvent::Error { errno } if self.core.uploading => {
                        self.active_pick_id = None;
                        self.local_batch = None;
                        let prog = self.core.set_progress(format!("✕ {}", errno.text()), false);
                        self.send_doc_msg(&prog)?;
                    }
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

        self.clear_cloud_watch();
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
        println!("Usage: files [--dir PATH | PATH] [--upload]");
        return Ok(());
    }

    let mut cli_dir: Option<String> = None;
    let mut cli_upload = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--dir" => {
                let Some(d) = args.get(i + 1) else {
                    return Err(Errno::EINVAL);
                };
                cli_dir = Some(d.clone());
                i += 2;
            }
            "--upload" => {
                cli_upload = true;
                i += 1;
            }
            arg if !arg.starts_with('-') && cli_dir.is_none() => {
                cli_dir = Some(arg.to_owned());
                i += 1;
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

    let proc_cwd = os_posix::getcwd()
        .ok()
        .and_then(|p| p.to_str().map(str::to_owned))
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| "/".into());
    let resolved_cli_dir = cli_dir
        .as_deref()
        .and_then(|d| resolve_location(&proc_cwd, &home, d).ok());

    // Single-instance check: forward to already-running `/usr/bin/files` for this uid.
    if try_forward_to_existing(uid, resolved_cli_dir.as_deref(), cli_upload)? {
        return Ok(());
    }

    let config_path = PathBuf::from(&home).join(CONFIG_REL_PATH);
    let cfg_outcome = load_config_file(&config_path);
    let config_read_only = matches!(cfg_outcome, ConfigLoadOutcome::NewerVersion { .. });
    let saved_cwd = match cfg_outcome {
        ConfigLoadOutcome::Loaded(cwd) => Some(cwd),
        _ => None,
    };

    let candidate_cwd = resolved_cli_dir.or(saved_cwd).unwrap_or_else(|| "/".into());
    let initial_cwd = if check_enterable(&candidate_cwd).is_ok() {
        candidate_cwd
    } else {
        "/".into()
    };

    let bundle_bytes = std::fs::read(FILES_BUNDLE).map_err(|e| {
        eprintln!("files: failed to read {FILES_BUNDLE}: {e}");
        os_posix::errno_of(&e).unwrap_or(Errno::ENOENT)
    })?;
    let expected_sha256 = sha256_hex(&bundle_bytes);

    let mut seat = SeatConn::connect()?;
    seat.send_blocking(&ClientReq::Hello {
        versions: vec![1],
        required: vec!["document".into(), "picker".into()],
    })?;
    match seat.recv_blocking()? {
        ClientEvent::Hello { version: 1 } => {}
        ClientEvent::Error { errno } => return Err(errno),
        _ => return Err(Errno::EPROTONOSUPPORT),
    }

    let initial_title = window_title(&initial_cwd);
    seat.send_blocking(&ClientReq::CreateSurface {
        spec: SurfaceSpec {
            role: SurfaceRole::Window,
            kind: SurfaceKind::Document(DocumentSource {
                bundle_path: FILES_BUNDLE.into(),
                expected_sha256,
            }),
            title: initial_title.clone(),
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
            app_id: Some("files".into()),
        },
    })?;

    let surface_id = match seat.recv_blocking()? {
        ClientEvent::Created { surface_id } => surface_id,
        ClientEvent::Error { errno } => return Err(errno),
        _ => return Err(Errno::EIO),
    };

    let (ctrl_listener, ctrl_path, ctrl_ino) = bind_control_socket(uid);

    let mut core = FilesCore::new(initial_cwd.clone(), home, config_read_only);
    let initial_wd = is_cloud_mount(&initial_cwd)
        .then(|| add_cloud_watch(&initial_cwd))
        .flatten();
    let initial_list = list_directory(&initial_cwd);
    let initial_cloud_cache = initial_wd.map(|wd| CloudDirCache {
        dir: initial_cwd.clone(),
        wd,
        at: Instant::now(),
        entries: initial_list.as_ref().ok().cloned(),
    });
    let _ = core.apply_listing(initial_cwd, initial_list, true);

    let app = FilesApp {
        seat,
        surface_id,
        uid,
        core,
        config_path,
        doc_ready: false,
        chunk_seq: 0,
        doc_asm: DocChunkAssembler::default(),
        last_title: initial_title,
        active_pick_id: None,
        local_batch: None,
        pending_upload_on_ready: cli_upload,
        cloud_cache: initial_cloud_cache,
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
        eprintln!("files: {err:?}");
        std::process::exit(1);
    }
}
