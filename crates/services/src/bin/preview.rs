//! `/usr/bin/preview`: ordinary unprivileged GUI Document & Media Preview process (`#64` `L6c-2`).
//!
//! Connects to `/run/gui/seat0.sock` over `AF_UNIX`, renders inside a sealed Document surface
//! (`/usr/share/gui/preview/preview.json`), enforces POSIX permissions directly with its own
//! process credentials (`open`/`stat`/`mknod`/`unlink`/`getxattr`/`setxattr`/`ioctl`), passes
//! read-only open descriptors via `SCM_RIGHTS` (`StreamAsset`, `PreviewJob`, `ExportFile`),
//! persists reading places in `~/.local/state/os/preview/places.json` (Contract §2.12),
//! maintains single-instance reuse over `/run/user/<uid>/preview.sock` (unless `--speaker`),
//! and imports ZERO `gui_*` Wasm functions.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[cfg(not(target_os = "wasi"))]
use std::os::fd::AsRawFd;
#[cfg(target_os = "wasi")]
use std::os::wasi::io::AsRawFd;

use abi::gui::{
    AssetStreamMode, ClientEvent, ClientReq, DocumentSource, MAX_EXPORT_FD, MAX_STREAM_ASSET_BLOB,
    MAX_STREAM_ASSET_RANGE, MediaControlOp, MediaEventPayload, PREVIEW_BUNDLE, PreviewJobKind,
    PreviewJobOutput, Rect, SOCKET, SessionEventOp, Size, SurfaceId, SurfaceKind, SurfaceRole,
    SurfaceSpec, frame, sha256_hex, take_frame,
};
use abi::socket::{MSG_CMSG_CLOEXEC, MSG_DONTWAIT, MSG_NOSIGNAL, SOCK_CLOEXEC, SOCK_NONBLOCK};
use abi::{Call, Dirent, Errno, FdRef, Stat};
use os_posix::process::getuid;
use os_posix::socket::{UnixListener, UnixStream};
use os_preview::language;
use os_services::associations::load_effective_associations;
use os_services::editor::export_filename;
use os_services::gui_doc::{DocChunkAssembler, chunk_document_message};
use os_services::preview::{
    self, ARCHIVE_MAX, AudienceInfo, GAME_MANIFEST_MAX, Kind, LiveAsk, LiveAsking, LiveBarState,
    LiveSending, LiveVoice, MAX_PREVIEW_ASSEMBLED_BYTES, MAX_PREVIEW_CHUNKS, PDF_MAX,
    PLACES_REL_PATH, PlacesFile, PlacesLoadOutcome, PreviewControlReply, PreviewControlReq,
    PreviewHostMsg, PreviewUiMsg, PreviewViewPayload, SystemOsConfig, TEXT_MAX,
    default_present_name, group_name, load_places_file, load_system_os_config,
    media_mime_from_name, sanitize_highlight_html, sanitize_svg, save_places_file_atomic,
    to_cloud_path, validate_game_manifest,
};
use serde_json::{Value, json};

const MAX_CONTROL_LINE_BYTES: usize = 16_384;
const MAX_CONTROL_PEERS_PER_TICK: usize = 8;
const MAX_OUTBOX_BYTES: usize = 6 << 20;
const ACL_XATTR: &str = "system.posix_acl_access";
const PRESENT_PREFIX: &str = "/dev/present";
const RETRY_DELAYS_MS: [u64; 5] = [1_000, 2_000, 5_000, 10_000, 20_000];

static STOP: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "wasi")]
#[unsafe(no_mangle)]
pub extern "C" fn __preview_signal(sig: u32) {
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
        let name = b"__preview_signal";
        // SAFETY: static exported callback name and scalar signal numbers with SA_RESTART.
        unsafe {
            callback_signal(name.as_ptr(), name.len());
            let _ = sigaction(13, 2, 0, 0x10000000);
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
            in_bytes[at + 8] = 1;
            in_bytes[at + 16..at + 20].copy_from_slice(&fd.to_le_bytes());
            idx += 1;
        }
        for &fd in write_fds {
            let at = idx * 48;
            in_bytes[at..at + 8].copy_from_slice(&(idx as u64).to_le_bytes());
            in_bytes[at + 8] = 2;
            in_bytes[at + 16..at + 20].copy_from_slice(&fd.to_le_bytes());
            idx += 1;
        }
        let at = idx * 48;
        in_bytes[at..at + 8].copy_from_slice(&(idx as u64).to_le_bytes());
        in_bytes[at + 8] = 0;
        in_bytes[at + 16..at + 20].copy_from_slice(&1u32.to_le_bytes());
        in_bytes[at + 24..at + 32].copy_from_slice(&(timeout_ms * 1_000_000).to_le_bytes());
        let mut events = 0usize;
        // SAFETY: properly aligned poll_oneoff subscription/event arrays.
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

fn sys_call(call: Call) -> Result<Value, abi::Error> {
    let reply = os_posix::batch(&[call])
        .map_err(|e| abi::Error::from(os_posix::errno_of(&e).unwrap_or(Errno::EIO)))?;
    reply
        .results
        .into_iter()
        .next()
        .ok_or_else(|| abi::Error::from(Errno::EIO))?
        .into_result()
}

fn err_message(e: &abi::Error) -> String {
    e.detail
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| e.errno.text().to_owned())
}

fn lstat_path(path: &str) -> io::Result<Stat> {
    let val = sys_call(Call::Lstat {
        path: path.to_owned(),
    })
    .map_err(|e| io::Error::other(err_message(&e)))?;
    serde_json::from_value(val).map_err(|e| io::Error::other(e.to_string()))
}

fn stat_path(path: &str) -> Result<Stat, abi::Error> {
    let val = sys_call(Call::Stat {
        path: path.to_owned(),
    })?;
    serde_json::from_value(val).map_err(|_| abi::Error::from(Errno::EIO))
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

fn is_cloud_signed_in_and_user(uid: u32) -> Option<(String, u32)> {
    // Check that /mnt/cloud is mounted (`OS_CLOUD_MAGIC`) and read Cloud identity from
    // `/run/user/<local_uid>/cloud-creds.json` (written `0600` on explicit `cloud_sign_in`).
    let sfs = os_posix::statfs(Path::new("/mnt/cloud")).ok()?;
    if sfs.f_type != abi::contract::fs_magic::OS_CLOUD_MAGIC {
        return None;
    }
    let raw = std::fs::read_to_string(format!("/run/user/{uid}/cloud-creds.json")).ok()?;
    let creds: Value = serde_json::from_str(&raw).ok()?;
    if creds.get("signed_in").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    let user = creds.get("cloud_user").and_then(Value::as_str)?;
    let cloud_uid = creds.get("cloud_uid").and_then(Value::as_u64)?;
    Some((user.to_owned(), cloud_uid as u32))
}

/// Read a `/dev/present/*` device via POSIX `open(O_RDONLY)` + `pread` + `close`.
fn read_present_device(device: &str) -> Result<Value, String> {
    let opened_val = sys_call(Call::Open {
        path: device.to_owned(),
        flags: abi::O_RDONLY,
        mode: 0,
        size: None,
        sha256: None,
        version: None,
    })
    .map_err(|e| err_message(&e))?;
    let fd = opened_val
        .get("fd")
        .and_then(Value::as_u64)
        .ok_or_else(|| "invalid open reply".to_owned())? as u32;
    let mut bytes = Vec::new();
    let mut offset = 0u64;
    loop {
        match sys_call(Call::Pread {
            fd: Some(FdRef::Fd(fd)),
            path: None,
            offset,
            count: 65_536,
        }) {
            Ok(v) => {
                let data_val = v.get("data").cloned().unwrap_or(v);
                let chunk: abi::Bytes = serde_json::from_value(data_val).unwrap_or_default();
                if chunk.0.is_empty() {
                    break;
                }
                offset = offset.saturating_add(chunk.0.len() as u64);
                bytes.extend_from_slice(&chunk.0);
                if bytes.len() > 256 * 1024 {
                    break;
                }
            }
            Err(e) => {
                let _ = sys_call(Call::Close { fd: FdRef::Fd(fd) });
                return Err(err_message(&e));
            }
        }
    }
    let _ = sys_call(Call::Close { fd: FdRef::Fd(fd) });
    let parsed: Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("invalid device response: {e}"))?;
    Ok(parsed
        .get("device")
        .filter(|v| v.is_object())
        .cloned()
        .unwrap_or(parsed))
}

fn dev_ioctl_once(device: &str, flags: u32, request: u32, arg: Value) -> Result<Value, String> {
    let opened_val = sys_call(Call::Open {
        path: device.to_owned(),
        flags,
        mode: 0,
        size: None,
        sha256: None,
        version: None,
    })
    .map_err(|e| err_message(&e))?;
    let fd = opened_val
        .get("fd")
        .and_then(Value::as_u64)
        .ok_or_else(|| "invalid open reply".to_owned())? as u32;
    let res = sys_call(Call::Ioctl {
        fd: FdRef::Fd(fd),
        request,
        arg,
    })
    .map_err(|e| err_message(&e));
    let _ = sys_call(Call::Close { fd: FdRef::Fd(fd) });
    res
}

fn valid_device_segment(seg: &str) -> bool {
    !seg.is_empty()
        && seg.len() <= 128
        && seg != "."
        && seg != ".."
        && !seg.contains('/')
        && !seg.contains('\\')
        && !seg.contains('\0')
}

fn validate_device_path(device: &str, prefix: &str) -> Result<String, String> {
    let Some(seg) = device
        .strip_prefix(prefix)
        .and_then(|s| s.strip_prefix('/'))
    else {
        return Err(format!("invalid device path: {device}"));
    };
    if !valid_device_segment(seg) {
        return Err(format!("invalid device name: {seg}"));
    }
    Ok(format!("{prefix}/{seg}"))
}

fn dev_present_file(path: &str, name: Option<&str>) -> Result<Value, String> {
    let dev_name = name
        .map(str::to_owned)
        .unwrap_or_else(|| default_present_name(path));
    if !valid_device_segment(&dev_name) {
        return Err(format!("invalid presentation name: {dev_name}"));
    }
    let device = format!("{PRESENT_PREFIX}/{dev_name}");
    let st = stat_path(path).map_err(|e| err_message(&e))?;
    let acl = sys_call(Call::Getxattr {
        path: path.to_owned(),
        name: ACL_XATTR.to_owned(),
        nofollow: false,
    })
    .ok();
    sys_call(Call::Mknod {
        path: device.clone(),
        mode: (st.mode & 0o666) as u16,
        rdev: Some("present".to_owned()),
    })
    .map_err(|e| err_message(&e))?;
    if let Some(acl_val) = acl
        && let Ok(bytes) = serde_json::from_value::<abi::Bytes>(acl_val)
    {
        let _ = sys_call(Call::Setxattr {
            path: device.clone(),
            name: ACL_XATTR.to_owned(),
            value: bytes,
            flags: 0,
            nofollow: false,
        });
    }
    let mut info = dev_ioctl_once(
        &device,
        abi::O_WRONLY,
        abi::PRESENT_SHOW,
        json!({ "path": to_cloud_path(path) }),
    )?;
    if let Some(obj) = info.as_object_mut() {
        obj.insert("device".into(), Value::String(device));
    }
    Ok(info)
}

fn dev_stop(device: &str) -> Result<(), String> {
    let validated = validate_device_path(device, PRESENT_PREFIX)
        .or_else(|_| validate_device_path(device, "/dev/snd"))?;
    sys_call(Call::Unlink { path: validated })
        .map(|_| ())
        .map_err(|e| err_message(&e))
}

type PresentedBarInfo = (
    Option<String>,
    Vec<(String, String)>,
    Vec<LiveAsk>,
    Vec<LiveVoice>,
);

fn dev_list_presented_for_path(uid: u32, path: &str) -> PresentedBarInfo {
    let Some((user, cloud_uid)) = is_cloud_signed_in_and_user(uid) else {
        return (None, Vec::new(), Vec::new(), Vec::new());
    };
    let target = to_cloud_path(path);
    let Ok(val) = sys_call(Call::Getdents {
        path: PRESENT_PREFIX.to_owned(),
        cookie: 0,
        count: None,
    }) else {
        return (Some(user), Vec::new(), Vec::new(), Vec::new());
    };
    let Ok(entries) = serde_json::from_value::<Vec<Dirent>>(val) else {
        return (Some(user), Vec::new(), Vec::new(), Vec::new());
    };
    let mut presented = Vec::new();
    let mut asks = Vec::new();
    let mut voices = Vec::new();
    for entry in entries {
        if entry.stat.as_ref().is_some_and(|st| st.uid == cloud_uid) {
            let dev = format!("{PRESENT_PREFIX}/{}", entry.name);
            if let Ok(d) = read_present_device(&dev)
                && d.get("path").and_then(Value::as_str) == Some(target.as_str())
            {
                let ver = d
                    .get("version")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                presented.push((dev.clone(), ver));
                if let Some(arr) = d.get("asks").and_then(Value::as_array) {
                    for a in arr {
                        if let (Some(id), Some(name)) = (
                            a.get("id").and_then(Value::as_str),
                            a.get("name").and_then(Value::as_str),
                        ) {
                            asks.push(LiveAsk {
                                id: id.to_owned(),
                                name: name.to_owned(),
                                presentation: dev.clone(),
                            });
                        }
                    }
                }
                if let Some(arr) = d.get("voices").and_then(Value::as_array) {
                    for v in arr {
                        if let (Some(vdev), Some(speaker)) = (
                            v.get("device").and_then(Value::as_str),
                            v.get("speaker").and_then(Value::as_str),
                        ) {
                            voices.push(LiveVoice {
                                device: vdev.to_owned(),
                                speaker: speaker.to_owned(),
                                presentation: dev.clone(),
                                ask: v
                                    .get("ask")
                                    .and_then(Value::as_str)
                                    .unwrap_or("")
                                    .to_owned(),
                            });
                        }
                    }
                }
            }
        }
    }
    (Some(user), presented, asks, voices)
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
        Err("timed out waiting for preview reply".into())
    }
}

fn try_forward_to_existing(
    uid: u32,
    req: &PreviewControlReq,
) -> Result<Option<PreviewControlReply>, Errno> {
    let sock_path = format!("/run/user/{uid}/preview.sock");
    let stream = match UnixStream::connect(&sock_path) {
        Ok(s) => s,
        Err(Errno::ENOENT | Errno::ECONNREFUSED) => return Ok(None),
        Err(e) => return Err(e),
    };
    let peer = stream.peer_cred()?;
    if peer.uid != uid {
        return Err(Errno::EACCES);
    }
    let mut bytes = serde_json::to_vec(req).map_err(|_| Errno::EINVAL)?;
    bytes.push(b'\n');
    send_all(&stream, &bytes)?;
    let val = read_json_line(&stream, 10_000).map_err(|_| Errno::EIO)?;
    let reply: PreviewControlReply = serde_json::from_value(val).map_err(|_| Errno::EIO)?;
    Ok(Some(reply))
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
    let sock_path = format!("{dir}/preview.sock");
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

struct OutMsg {
    bytes: Vec<u8>,
    offset: usize,
    fd: Option<File>,
}

struct SeatConn {
    socket: UnixStream,
    in_buf: Vec<u8>,
    out_queue: VecDeque<OutMsg>,
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
        self.queue_with_fd(req, None)
    }

    fn queue_with_fd(&mut self, req: &ClientReq, fd: Option<File>) -> Result<(), Errno> {
        let bytes = frame(req)?;
        if self.out_bytes.saturating_add(bytes.len()) > MAX_OUTBOX_BYTES {
            return Err(Errno::ENOBUFS);
        }
        if fd.is_some() {
            // Ensure prior frames are flushed before sending an SCM_RIGHTS frame so the
            // compositor sees the fd on a clean frame boundary.
            self.flush_blocking()?;
        }
        self.out_bytes += bytes.len();
        self.out_queue.push_back(OutMsg {
            bytes,
            offset: 0,
            fd,
        });
        if self.out_queue.back().is_some_and(|m| m.fd.is_some()) {
            self.flush_blocking()?;
        } else {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Errno> {
        while let Some(m) = self.out_queue.front_mut() {
            let rights: Vec<u32> = m.fd.iter().map(|f| f.as_raw_fd() as u32).collect();
            let res = if rights.is_empty() {
                self.socket
                    .send(&m.bytes[m.offset..], MSG_NOSIGNAL | MSG_DONTWAIT)
            } else {
                self.socket.send_with_fds(
                    &m.bytes[m.offset..],
                    &rights,
                    MSG_NOSIGNAL | MSG_DONTWAIT,
                )
            };
            match res {
                Ok(0) => return Err(Errno::EPIPE),
                Ok(n) => {
                    m.fd.take();
                    m.offset += n;
                    self.out_bytes = self.out_bytes.saturating_sub(n);
                    if m.offset >= m.bytes.len() {
                        self.out_queue.pop_front();
                    }
                }
                Err(Errno::EAGAIN | Errno::EINTR) => break,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn flush_blocking(&mut self) -> Result<(), Errno> {
        let deadline = Instant::now() + Duration::from_secs(15);
        while self.has_pending_writes() {
            self.flush()?;
            if self.has_pending_writes() {
                if Instant::now() >= deadline {
                    return Err(Errno::ETIMEDOUT);
                }
                poll_fds(&[], &[self.fd()], 10);
            }
        }
        Ok(())
    }

    fn send_blocking(&mut self, req: &ClientReq) -> Result<(), Errno> {
        self.queue(req)?;
        self.flush_blocking()
    }

    fn recv_blocking(&mut self) -> Result<ClientEvent, Errno> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(ev) = take_frame(&mut self.in_buf)? {
                return Ok(ev);
            }
            let mut chunk = [0u8; 8192];
            match self
                .socket
                .recv_with_fds(&mut chunk, 1, MSG_DONTWAIT | MSG_CMSG_CLOEXEC)
            {
                Ok((0, _, _)) => return Err(Errno::EPIPE),
                Ok((n, _, _)) => self.in_buf.extend_from_slice(&chunk[..n]),
                Err(Errno::EAGAIN | Errno::EINTR) => {
                    if Instant::now() >= deadline {
                        return Err(Errno::ETIMEDOUT);
                    }
                    poll_fds(&[self.fd()], &[], 15);
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
                Ok((n, _, _)) => self.in_buf.extend_from_slice(&chunk[..n]),
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

#[derive(Clone, Debug)]
struct FollowingState {
    device: String,
    version: String,
    path: String,
    owner: String,
    controller: bool,
    ended: bool,
}

enum PendingJob {
    PdfOpen { version: u64 },
    PdfRender { version: u64, req_id: u64 },
    ListArchive { version: u64 },
    Highlight { version: u64, req_id: u64 },
    Diagram { version: u64, req_id: u64 },
}

struct ListeningStream {
    device: String,
    version: String,
    label: String,
    is_voice: bool,
    retry_attempt: usize,
    retry_at: Option<Instant>,
    pending_listen_fd: Option<(u32, String)>,
}

struct SpeakingState {
    presentation: String,
    ask_id: String,
    granted_fd: Option<u32>,
    write_fd: Option<u32>,
    device: Option<String>,
    stream_id: String,
}

#[derive(Clone)]
enum InitialAction {
    File(String),
    Manual(Option<String>),
}

struct PendingWhere {
    initial_pos: Option<[u32; 2]>,
    local_turned_at: Option<Instant>,
}

struct PreviewApp {
    seat: SeatConn,
    surface_id: SurfaceId,
    uid: u32,
    home: String,
    speaker_mode: bool,
    config: SystemOsConfig,
    places: PlacesFile,
    places_path: PathBuf,
    places_read_only: bool,
    doc_ready: bool,
    chunk_seq: u64,
    doc_asm: DocChunkAssembler,
    view_version: u64,
    next_asset_id: u64,
    next_job_id: u64,
    next_media_req: u64,
    current_path: Option<String>,
    current_manual: bool,
    current_title: String,
    active_pdf_doc: Option<u32>,
    game_mounted: bool,
    trail: Vec<String>,
    pending_jobs: HashMap<u64, PendingJob>,
    heard: HashMap<String, [u32; 2]>,
    pending_where: HashMap<String, PendingWhere>,
    following: Option<FollowingState>,
    attend_seq: u64,
    pending_attend_reqs: HashMap<u64, (String, u64)>,
    declined_presentation: Option<String>,
    bar: LiveBarState,
    bar_presented_versions: HashMap<String, String>,
    allowed_asks: BTreeSet<String>,
    asking_presentation: Option<String>,
    asking_id: Option<String>,
    speaking: Option<SpeakingState>,
    listening: BTreeMap<String, ListeningStream>,
    pending_media_reqs: HashMap<u64, String>,
    last_bar_note_at: Option<Instant>,
    ctrl_listener: Option<UnixListener>,
    ctrl_path: Option<String>,
    ctrl_ino: Option<u64>,
    pending_open: Option<InitialAction>,
    closing: bool,
}

impl PreviewApp {
    fn send_doc_msg(&mut self, msg: &PreviewHostMsg) -> Result<(), Errno> {
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

    fn set_title(&mut self, title: &str) -> Result<(), Errno> {
        let win_title = if self.speaker_mode {
            let base = title.rsplit('/').next().unwrap_or(title);
            format!("Speaker view · {base}")
        } else {
            title.to_owned()
        };
        if win_title != self.current_title {
            self.current_title = win_title.clone();
            self.seat.queue(&ClientReq::SetTitle {
                surface_id: self.surface_id,
                title: win_title,
            })?;
        }
        Ok(())
    }

    fn persist_places(&self) {
        if !self.places_read_only {
            let _ = save_places_file_atomic(&self.places_path, &self.places);
        }
    }

    fn send_session_json(&mut self, value: Value) {
        if let Ok(payload_json) = serde_json::to_string(&value) {
            let _ = self.seat.queue(&ClientReq::SessionEvents {
                surface_id: self.surface_id,
                control: SessionEventOp::Send { payload_json },
            });
        }
    }

    fn ask_where(&mut self, path: &str, initial_pos: Option<[u32; 2]>) {
        let cloud = to_cloud_path(path);
        self.pending_where.insert(
            cloud.clone(),
            PendingWhere {
                initial_pos,
                local_turned_at: None,
            },
        );
        self.send_session_json(json!({ "where": cloud }));
    }

    fn sync_followed_devices(&mut self) {
        let mut devices: Vec<String> = Vec::new();
        if let Some(ref f) = self.following {
            devices.push(f.device.clone());
        }
        for s in self.listening.values() {
            devices.push(s.device.clone());
        }
        if let Some(ref sp) = self.speaking
            && let Some(ref d) = sp.device
        {
            devices.push(d.clone());
        }
        self.send_session_json(json!({ "follow": devices }));
    }

    fn cleanup_current_view(&mut self) {
        self.view_version = self.view_version.wrapping_add(1);
        self.pending_jobs.clear();
        if let Some(doc_id) = self.active_pdf_doc.take() {
            let job_id = self.alloc_job_id();
            let _ = self.seat.queue(&ClientReq::PreviewJob {
                surface_id: self.surface_id,
                job_id,
                kind: PreviewJobKind::PdfClose { doc_id },
            });
        }
        if self.game_mounted {
            self.game_mounted = false;
            let _ = self.seat.queue(&ClientReq::MountGameEmbed {
                surface_id: self.surface_id,
                entry: None,
                title: String::new(),
            });
        }
        let _ = self.seat.queue(&ClientReq::ReleaseAsset {
            surface_id: self.surface_id,
            asset_id: None,
        });
    }

    fn alloc_asset_id(&mut self) -> u64 {
        self.next_asset_id = self.next_asset_id.saturating_add(1).max(1);
        self.next_asset_id
    }

    fn alloc_job_id(&mut self) -> u64 {
        self.next_job_id = self.next_job_id.saturating_add(1).max(1);
        self.next_job_id
    }

    fn alloc_media_req(&mut self) -> u64 {
        self.next_media_req = self.next_media_req.saturating_add(1).max(1);
        self.next_media_req
    }

    fn audience_info(&self, path: &str) -> Option<AudienceInfo> {
        let f = self.following.as_ref()?;
        if to_cloud_path(&f.path) == to_cloud_path(path) && !f.controller {
            Some(AudienceInfo {
                device: f.device.clone(),
                owner: f.owner.clone(),
                ended: f.ended,
            })
        } else {
            None
        }
    }

    fn unfollow(&mut self) {
        self.attend_seq = self.attend_seq.wrapping_add(1);
        self.pending_attend_reqs.clear();
        if let Some(pres) = self.asking_presentation.take() {
            if self
                .bar
                .asking
                .as_ref()
                .is_some_and(|a| a.state == "asking")
            {
                let _ = dev_ioctl_once(
                    &pres,
                    abi::O_RDONLY,
                    abi::PRESENT_ASK,
                    json!({ "withdraw": true }),
                );
            }
            self.stop_speaking();
        }
        self.asking_id = None;
        if self.following.take().is_some() {
            self.sync_followed_devices();
        }
    }

    fn stop_speaking(&mut self) {
        if let Some(sp) = self.speaking.take() {
            let req_id = self.alloc_media_req();
            let _ = self.seat.queue(&ClientReq::MediaControl {
                surface_id: self.surface_id,
                request_id: req_id,
                control: MediaControlOp::StopCapture {
                    stream_id: sp.stream_id,
                },
            });
            if let Some(fd) = sp.write_fd.or(sp.granted_fd) {
                let _ = sys_call(Call::Close { fd: FdRef::Fd(fd) });
            }
            self.sync_followed_devices();
        }
        self.bar.asking = None;
        self.asking_id = None;
        let _ = self.push_bar();
    }

    fn push_bar(&mut self) -> Result<(), Errno> {
        let bar = self.bar.clone();
        self.send_doc_msg(&PreviewHostMsg::LiveBar { bar })
    }

    fn set_bar_note(&mut self, note: String) {
        self.bar.note = note;
        self.last_bar_note_at = Some(Instant::now());
        let _ = self.push_bar();
    }

    fn refresh_bar_for_path(&mut self, path: &str) {
        let (user, presented, asks, voices) = dev_list_presented_for_path(self.uid, path);
        self.bar.path = Some(path.to_owned());
        self.bar.user = user;
        self.bar_presented_versions.clear();
        self.bar.presented.clear();
        for (dev, ver) in presented {
            self.bar_presented_versions.insert(dev.clone(), ver);
            self.bar.presented.push(dev);
        }
        self.bar.asks = asks;
        self.bar.voices = voices;
        let _ = self.push_bar();
    }

    fn start_listening_sound(&mut self, device: &str, label: &str, is_voice: bool, attempt: usize) {
        let stream_id = device.to_owned();
        let opened = sys_call(Call::Open {
            path: device.to_owned(),
            flags: abi::O_RDONLY,
            mode: 0,
            size: None,
            sha256: None,
            version: None,
        });
        let Ok(open_val) = opened else {
            return;
        };
        let Some(fd) = open_val.get("fd").and_then(Value::as_u64).map(|v| v as u32) else {
            return;
        };
        let offered = sys_call(Call::Ioctl {
            fd: FdRef::Fd(fd),
            request: abi::SND_LISTEN,
            arg: Value::Null,
        });
        let Ok(offer_val) = offered else {
            let _ = sys_call(Call::Close { fd: FdRef::Fd(fd) });
            return;
        };
        let Some(offer_sdp) = offer_val.get("sdp").and_then(Value::as_str) else {
            let _ = sys_call(Call::Close { fd: FdRef::Fd(fd) });
            return;
        };
        let session = offer_val
            .get("session")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let version = offer_val
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let req_id = self.alloc_media_req();
        self.listening.insert(
            stream_id.clone(),
            ListeningStream {
                device: device.to_owned(),
                version,
                label: label.to_owned(),
                is_voice,
                retry_attempt: attempt,
                retry_at: None,
                pending_listen_fd: Some((fd, session)),
            },
        );
        self.pending_media_reqs.insert(req_id, stream_id.clone());
        let _ = self.seat.queue(&ClientReq::MediaControl {
            surface_id: self.surface_id,
            request_id: req_id,
            control: MediaControlOp::ListenSdp {
                stream_id,
                label: label.to_owned(),
                offer_sdp: offer_sdp.to_owned(),
                is_voice,
            },
        });
        self.sync_followed_devices();
    }

    fn stop_listening_stream(&mut self, device: &str) {
        if let Some(old) = self.listening.remove(device) {
            if let Some((fd, _)) = old.pending_listen_fd {
                let _ = sys_call(Call::Close { fd: FdRef::Fd(fd) });
            }
            let req_id = self.alloc_media_req();
            let _ = self.seat.queue(&ClientReq::MediaControl {
                surface_id: self.surface_id,
                request_id: req_id,
                control: MediaControlOp::StopListen {
                    stream_id: Some(device.to_owned()),
                },
            });
            self.sync_followed_devices();
        }
    }

    fn attend_presentation(&mut self, device: &str) -> Result<(), String> {
        self.attend_seq = self.attend_seq.wrapping_add(1);
        self.pending_attend_reqs.clear();
        let info = read_present_device(device)?;
        self.apply_attended_info(device, &info)
    }

    fn request_reattend_async(&mut self, device: &str) {
        self.attend_seq = self.attend_seq.wrapping_add(1);
        let seq = self.attend_seq;
        let req_id = self.alloc_media_req();
        self.pending_attend_reqs
            .insert(req_id, (device.to_owned(), seq));
        let _ = self.seat.queue(&ClientReq::MediaControl {
            surface_id: self.surface_id,
            request_id: req_id,
            control: MediaControlOp::FetchPresentState {
                device: device.to_owned(),
            },
        });
    }

    fn apply_attended_info(&mut self, device: &str, info: &Value) -> Result<(), String> {
        let info = info.get("device").filter(|v| v.is_object()).unwrap_or(info);
        let dev_name = info
            .get("device")
            .and_then(Value::as_str)
            .unwrap_or(device)
            .to_owned();
        let version = info
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let path = info
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| "presentation missing path".to_owned())?
            .to_owned();
        let owner = info
            .get("owner")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let controller = info
            .get("controller")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let kind_str = info.get("kind").and_then(Value::as_str).unwrap_or("");
        let place = info
            .get("place")
            .and_then(Value::as_array)
            .and_then(|arr| Some([arr.first()?.as_u64()? as u32, arr.get(1)?.as_u64()? as u32]));
        if self.following.as_ref().map(|f| f.device.as_str()) != Some(dev_name.as_str()) {
            self.declined_presentation = None;
        }
        self.following = Some(FollowingState {
            device: dev_name.clone(),
            version,
            path: path.clone(),
            owner,
            controller,
            ended: false,
        });
        self.sync_followed_devices();

        if let Some(sound) = info.get("sound").and_then(Value::as_str)
            && !self.listening.contains_key(sound)
            && self.declined_presentation.as_deref() != Some(dev_name.as_str())
        {
            self.start_listening_sound(sound, sound, false, 0);
        }
        if let Some(voices) = info.get("voices").and_then(Value::as_array) {
            for v in voices {
                if let (Some(vdev), Some(speaker)) = (
                    v.get("device").and_then(Value::as_str),
                    v.get("speaker").and_then(Value::as_str),
                ) {
                    let ask = v.get("ask").and_then(Value::as_str);
                    if ask != self.asking_id.as_deref() && !self.listening.contains_key(vdev) {
                        self.start_listening_sound(vdev, &format!("{speaker} speaking"), true, 0);
                    }
                }
            }
        }

        let cloud_mounted = is_cloud_signed_in_and_user(self.uid).is_some();
        let view_path = if cloud_mounted && !path.starts_with("/mnt/cloud/") {
            format!("/mnt/cloud{path}")
        } else {
            path.clone()
        };
        if let Some(at) = place {
            self.heard.insert(view_path.clone(), at);
            self.heard.insert(path.clone(), at);
            let patch = if kind_str == "pdf" {
                json!({ "present": true, "page": at[0] })
            } else {
                json!({ "slides": true, "slide": at })
            };
            self.places.merge(&view_path, patch);
            self.persist_places();
        } else {
            let patch = if kind_str == "pdf" {
                json!({ "present": true })
            } else {
                json!({ "slides": true })
            };
            self.places.merge(&view_path, patch);
            self.persist_places();
        }
        self.open_path(&view_path, false, true)
            .map_err(|e| e.text().to_owned())
    }

    fn open_manual(&mut self, command: Option<&str>) -> Result<(), String> {
        let text = match command {
            Some(cmd) => match os_core::cli::page(cmd) {
                Some(p) => p,
                None if os_core::bin::program(cmd).is_some() => {
                    return Err(format!(
                        "{cmd} is /bin's (uutils): {cmd} --help says how to use it"
                    ));
                }
                None => {
                    return Err(format!(
                        "No manual entry for {cmd}. Enter man for the index."
                    ));
                }
            },
            None => os_core::cli::index(),
        };
        self.unfollow();
        self.trail.clear();
        self.cleanup_current_view();
        self.current_path = None;
        self.current_manual = true;
        let title = match command {
            Some(cmd) => format!("man · {cmd}"),
            None => "OS · Manual".to_owned(),
        };
        let _ = self.set_title(&title);
        let html = preview::markdown(&text, "/");
        let msg = PreviewHostMsg::Show {
            version: self.view_version,
            path: "/".into(),
            title,
            can_back: false,
            back_title: String::new(),
            can_download: false,
            speaker_mode: false,
            slide_theme: self.places.slide_theme.clone(),
            notes_size: self.places.notes_size,
            place: json!({}),
            last_presented: None,
            audience: None,
            payload: PreviewViewPayload::Markdown {
                html,
                slides: Vec::new(),
                as_slides: false,
                manual: true,
            },
        };
        self.send_doc_msg(&msg).map_err(|e| e.text().to_owned())
    }

    fn open_path(&mut self, path: &str, followed: bool, attending: bool) -> Result<(), Errno> {
        if path.starts_with("/dev/present/") {
            if let Err(err) = self.attend_presentation(path) {
                self.show_error(path, &err)?;
            }
            return Ok(());
        }
        if path.starts_with("/dev/snd/") {
            self.start_listening_sound(path, path, false, 0);
            return Ok(());
        }
        if !attending
            && self
                .following
                .as_ref()
                .is_some_and(|f| to_cloud_path(&f.path) != to_cloud_path(path))
        {
            self.unfollow();
        }
        if !followed {
            self.trail.clear();
        }
        self.cleanup_current_view();
        self.current_path = Some(path.to_owned());
        self.current_manual = false;
        self.set_title(path)?;

        let back_title = self
            .trail
            .last()
            .map(|p| format!("Back to {p}"))
            .unwrap_or_default();
        let can_back = !self.trail.is_empty();
        let place = self.places.get(path);
        let last_presented = self
            .heard
            .get(path)
            .or_else(|| self.heard.get(&to_cloud_path(path)))
            .copied();
        let audience = self.audience_info(path);

        let st = match stat_path(path) {
            Ok(s) => s,
            Err(e) => return self.show_error(path, &err_message(&e)),
        };
        if st.is_dir() {
            return self.show_error(path, "This is a directory; use cd");
        }
        let size = st.size;

        let (assoc, _) = load_effective_associations(Some(&self.home));
        let listed_kind = assoc.resolve(path).kind;

        if !attending
            && self.following.is_none()
            && matches!(listed_kind.as_str(), "slides" | "markdown" | "pdf")
        {
            let initial_pos = last_presented.or_else(|| {
                if listed_kind == "pdf" {
                    place
                        .get("page")
                        .and_then(Value::as_u64)
                        .map(|p| [p as u32, 0])
                } else {
                    place.get("slide").and_then(Value::as_array).and_then(|a| {
                        Some([a.first()?.as_u64()? as u32, a.get(1)?.as_u64()? as u32])
                    })
                }
            });
            self.ask_where(path, Some(initial_pos.unwrap_or([0, 0])));
            let _ = self.seat.flush();
        }

        // `.game` manifest: validated against read-only /usr/share/os/config.json.
        if listed_kind == "game" {
            if size > GAME_MANIFEST_MAX as u64 {
                return self.show_error(
                    path,
                    "Text exceeds 2 MB; use the download button in the top right.",
                );
            }
            let raw = match std::fs::read_to_string(path) {
                Ok(s) => s,
                Err(e) => return self.show_error(path, &e.to_string()),
            };
            match validate_game_manifest(&raw, &self.config) {
                Ok((entry, title)) => {
                    self.game_mounted = true;
                    self.seat.queue(&ClientReq::MountGameEmbed {
                        surface_id: self.surface_id,
                        entry: Some(entry),
                        title: title.clone(),
                    })?;
                    return self.send_doc_msg(&PreviewHostMsg::Show {
                        version: self.view_version,
                        path: path.to_owned(),
                        title: path.to_owned(),
                        can_back,
                        back_title,
                        can_download: true,
                        speaker_mode: false,
                        slide_theme: self.places.slide_theme.clone(),
                        notes_size: self.places.notes_size,
                        place,
                        last_presented: None,
                        audience: None,
                        payload: PreviewViewPayload::Game { title },
                    });
                }
                Err(msg) => return self.show_error(path, &msg),
            }
        }

        // Open the file with `/usr/bin/preview`'s own POSIX credentials and sniff header bytes.
        let mut file = match File::open(path) {
            Ok(f) => f,
            Err(e) => return self.show_error(path, &e.to_string()),
        };
        let mut head = vec![0u8; (size as usize).min(512)];
        let mut head_len = 0usize;
        while head_len < head.len() {
            match file.read(&mut head[head_len..]) {
                Ok(0) => break,
                Ok(n) => head_len += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return self.show_error(path, &e.to_string()),
            }
        }
        head.truncate(head_len);
        let lower_name = path.rsplit('/').next().unwrap_or(path).to_lowercase();
        let sniffed = preview::sniff(&lower_name, &head);

        // 1. PDF (`%PDF-` or `.pdf`)
        if matches!(sniffed, Some(Kind::Pdf)) || listed_kind == "pdf" {
            if size > PDF_MAX as u64 {
                return self.show_error(
                    path,
                    "The file is too large to preview; use the download button in the top right.",
                );
            }
            drop(file);
            let pdf_fd = match File::open(path) {
                Ok(f) => f,
                Err(e) => return self.show_error(path, &e.to_string()),
            };
            let job_id = self.alloc_job_id();
            self.pending_jobs.insert(
                job_id,
                PendingJob::PdfOpen {
                    version: self.view_version,
                },
            );
            self.seat.queue_with_fd(
                &ClientReq::PreviewJob {
                    surface_id: self.surface_id,
                    job_id,
                    kind: PreviewJobKind::PdfOpen {},
                },
                Some(pdf_fd),
            )?;
            self.send_doc_msg(&PreviewHostMsg::Show {
                version: self.view_version,
                path: path.to_owned(),
                title: path.to_owned(),
                can_back,
                back_title,
                can_download: true,
                speaker_mode: self.speaker_mode,
                slide_theme: self.places.slide_theme.clone(),
                notes_size: self.places.notes_size,
                place,
                last_presented,
                audience,
                payload: PreviewViewPayload::Pdf {
                    pages: Vec::new(),
                    doc_id: 0,
                    loading: true,
                    error: None,
                },
            })?;
            self.refresh_bar_for_path(path);
            return Ok(());
        }

        // 2. Archive (`.zip`, `.tar`, `.tar.gz`, `.tgz`, excluding Office docs)
        let ext = lower_name.rsplit_once('.').map_or("", |(_, e)| e);
        let is_office = matches!(
            ext,
            "doc"
                | "docx"
                | "xls"
                | "xlsx"
                | "ppt"
                | "pptx"
                | "odt"
                | "ods"
                | "odp"
                | "odg"
                | "pages"
                | "numbers"
                | "key"
        );
        if !is_office && (matches!(sniffed, Some(Kind::Archive)) || listed_kind == "archive") {
            if size > ARCHIVE_MAX as u64 {
                return self.show_error(
                    path,
                    "The file is too large to preview; use the download button in the top right.",
                );
            }
            drop(file);
            let arc_fd = match File::open(path) {
                Ok(f) => f,
                Err(e) => return self.show_error(path, &e.to_string()),
            };
            let job_id = self.alloc_job_id();
            self.pending_jobs.insert(
                job_id,
                PendingJob::ListArchive {
                    version: self.view_version,
                },
            );
            self.seat.queue_with_fd(
                &ClientReq::PreviewJob {
                    surface_id: self.surface_id,
                    job_id,
                    kind: PreviewJobKind::ListArchive {},
                },
                Some(arc_fd),
            )?;
            return self.send_doc_msg(&PreviewHostMsg::Show {
                version: self.view_version,
                path: path.to_owned(),
                title: path.to_owned(),
                can_back,
                back_title,
                can_download: true,
                speaker_mode: false,
                slide_theme: self.places.slide_theme.clone(),
                notes_size: self.places.notes_size,
                place,
                last_presented: None,
                audience: None,
                payload: PreviewViewPayload::Archive {
                    loading: true,
                    entries: Vec::new(),
                    more: false,
                    error: None,
                },
            });
        }

        // 3. Binary Media (Image / Video / Audio) -> zero-TOCTOU SCM_RIGHTS StreamAsset!
        let media_info: Option<(&str, &str)> = match sniffed {
            Some(Kind::Image(m)) => Some(("image", m)),
            Some(Kind::Video(m)) => Some(("video", m)),
            Some(Kind::Audio(m)) => Some(("audio", m)),
            _ if matches!(listed_kind.as_str(), "image" | "video" | "audio") => {
                media_mime_from_name(path)
            }
            _ => None,
        };
        if let Some((media_kind, mime)) = media_info {
            let mode = if size <= MAX_STREAM_ASSET_BLOB {
                AssetStreamMode::Blob
            } else if matches!(media_kind, "video" | "audio") && size <= MAX_STREAM_ASSET_RANGE {
                AssetStreamMode::RangePull
            } else {
                return self.show_error(
                    path,
                    "The file is too large to preview; use the download button in the top right.",
                );
            };
            drop(file);
            let media_fd = match File::open(path) {
                Ok(f) => f,
                Err(e) => return self.show_error(path, &e.to_string()),
            };
            let asset_id = self.alloc_asset_id();
            self.send_doc_msg(&PreviewHostMsg::Show {
                version: self.view_version,
                path: path.to_owned(),
                title: path.to_owned(),
                can_back,
                back_title,
                can_download: true,
                speaker_mode: false,
                slide_theme: self.places.slide_theme.clone(),
                notes_size: self.places.notes_size,
                place,
                last_presented: None,
                audience: None,
                payload: PreviewViewPayload::Media {
                    media_kind: media_kind.to_owned(),
                    asset_id,
                    mime: mime.to_owned(),
                    mode: match mode {
                        AssetStreamMode::Blob => "blob".into(),
                        AssetStreamMode::RangePull => "range_pull".into(),
                    },
                },
            })?;
            return self.seat.queue_with_fd(
                &ClientReq::StreamAsset {
                    surface_id: self.surface_id,
                    asset_id,
                    mime: mime.to_owned(),
                    mode,
                },
                Some(media_fd),
            );
        }

        // 4. Text / Slides / Markdown / Table / Cards / Diff / Code
        if size > TEXT_MAX as u64 {
            return self.show_error(
                path,
                "Text exceeds 2 MB; use the download button in the top right.",
            );
        }
        let mut data = head;
        if let Err(e) = file.read_to_end(&mut data) {
            return self.show_error(path, &e.to_string());
        }
        if listed_kind == "slides" {
            let source = String::from_utf8_lossy(&data).into_owned();
            let deck = preview::slides(&source, path);
            self.send_doc_msg(&PreviewHostMsg::Show {
                version: self.view_version,
                path: path.to_owned(),
                title: path.to_owned(),
                can_back,
                back_title,
                can_download: true,
                speaker_mode: self.speaker_mode,
                slide_theme: self.places.slide_theme.clone(),
                notes_size: self.places.notes_size,
                place,
                last_presented,
                audience,
                payload: PreviewViewPayload::Slides { slides: deck },
            })?;
            self.refresh_bar_for_path(path);
            return Ok(());
        }

        let classified = preview::kind(path, &data);
        let mut refresh_bar = false;
        let mut deferred_stream: Option<(u64, String, File)> = None;
        let payload = match classified {
            Kind::Markdown { html, source } => {
                refresh_bar = true;
                let as_slides =
                    place.get("slides").and_then(Value::as_bool) == Some(true) || self.speaker_mode;
                let deck = preview::slides(&source, path);
                PreviewViewPayload::Markdown {
                    html,
                    slides: deck,
                    as_slides,
                    manual: false,
                }
            }
            Kind::Code { text, language } => PreviewViewPayload::Code {
                text,
                language: language.map(str::to_owned),
            },
            Kind::Table(table) => PreviewViewPayload::Table {
                table,
                rows_max: preview::ROWS_MAX,
            },
            Kind::Cards(cards) => {
                if cards.is_empty() {
                    PreviewViewPayload::NoPreview {
                        message: "No preview for this kind of file. Download it to open it.".into(),
                    }
                } else {
                    PreviewViewPayload::Cards { cards }
                }
            }
            Kind::Diff(lines) => PreviewViewPayload::Diff { lines },
            Kind::Image(mime) => {
                // e.g. `.svg` detected after reading full UTF-8 text.
                let asset_id = self.alloc_asset_id();
                if let Ok(svg_fd) = File::open(path) {
                    deferred_stream = Some((asset_id, mime.to_owned(), svg_fd));
                }
                PreviewViewPayload::Media {
                    media_kind: "image".into(),
                    asset_id,
                    mime: mime.to_owned(),
                    mode: "blob".into(),
                }
            }
            Kind::None | Kind::Pdf | Kind::Archive | Kind::Video(_) | Kind::Audio(_) => {
                PreviewViewPayload::NoPreview {
                    message: "No preview for this kind of file. Download it to open it.".into(),
                }
            }
        };

        self.send_doc_msg(&PreviewHostMsg::Show {
            version: self.view_version,
            path: path.to_owned(),
            title: path.to_owned(),
            can_back,
            back_title,
            can_download: true,
            speaker_mode: self.speaker_mode,
            slide_theme: self.places.slide_theme.clone(),
            notes_size: self.places.notes_size,
            place,
            last_presented,
            audience,
            payload,
        })?;
        if let Some((asset_id, mime, svg_fd)) = deferred_stream {
            self.seat.queue_with_fd(
                &ClientReq::StreamAsset {
                    surface_id: self.surface_id,
                    asset_id,
                    mime,
                    mode: AssetStreamMode::Blob,
                },
                Some(svg_fd),
            )?;
        }
        if refresh_bar {
            self.refresh_bar_for_path(path);
        }
        Ok(())
    }

    fn show_error(&mut self, path: &str, message: &str) -> Result<(), Errno> {
        let back_title = self
            .trail
            .last()
            .map(|p| format!("Back to {p}"))
            .unwrap_or_default();
        self.send_doc_msg(&PreviewHostMsg::Show {
            version: self.view_version,
            path: path.to_owned(),
            title: path.to_owned(),
            can_back: !self.trail.is_empty(),
            back_title,
            can_download: !self.current_manual && self.current_path.is_some(),
            speaker_mode: false,
            slide_theme: self.places.slide_theme.clone(),
            notes_size: self.places.notes_size,
            place: json!({}),
            last_presented: None,
            audience: None,
            payload: PreviewViewPayload::Error {
                message: message.to_owned(),
            },
        })
    }

    fn handle_doc_message(&mut self, raw: &str) -> Result<(), Errno> {
        let Some(full) = self.doc_asm.feed(raw) else {
            return Ok(());
        };
        let Ok(msg) = serde_json::from_str::<PreviewUiMsg>(&full) else {
            return Ok(());
        };
        match msg {
            PreviewUiMsg::Ready {} => {
                self.doc_ready = true;
                if let Some(action) = self.pending_open.take() {
                    match action {
                        InitialAction::File(path) => self.open_path(&path, false, false)?,
                        InitialAction::Manual(cmd) => {
                            if let Err(err) = self.open_manual(cmd.as_deref()) {
                                self.show_error("/", &err)?;
                            }
                        }
                    }
                }
            }
            PreviewUiMsg::Close {} => {
                self.closing = true;
            }
            PreviewUiMsg::Back {} => {
                if let Some(prev) = self.trail.pop() {
                    self.open_path(&prev, true, false)?;
                }
            }
            PreviewUiMsg::Download {} => {
                let Some(path) = self.current_path.clone() else {
                    return Ok(());
                };
                let st = match stat_path(&path) {
                    Ok(s) => s,
                    Err(e) => {
                        return self.send_doc_msg(&PreviewHostMsg::Notice {
                            message: err_message(&e),
                        });
                    }
                };
                if st.size > MAX_EXPORT_FD {
                    return self.send_doc_msg(&PreviewHostMsg::Notice {
                        message: "Local browser downloads are limited to 128 MiB; copy larger files on their owner device.".into(),
                    });
                }
                match File::open(&path) {
                    Ok(fd) => {
                        let filename = export_filename(&path);
                        let mime = media_mime_from_name(&path)
                            .map(|(_, m)| m)
                            .unwrap_or("application/octet-stream");
                        self.seat.queue_with_fd(
                            &ClientReq::ExportFile {
                                surface_id: self.surface_id,
                                filename,
                                mime: mime.to_owned(),
                                data: None,
                            },
                            Some(fd),
                        )?;
                    }
                    Err(e) => {
                        self.send_doc_msg(&PreviewHostMsg::Notice {
                            message: e.to_string(),
                        })?;
                    }
                }
            }
            PreviewUiMsg::ToggleFullscreen { active } => {
                self.seat.queue(&ClientReq::RequestFullscreen {
                    surface_id: self.surface_id,
                    active,
                })?;
            }
            PreviewUiMsg::FollowLink { path } => {
                let target = preview::file_path(&path).unwrap_or(path);
                if let Some(cur) = self.current_path.clone() {
                    self.trail.push(cur);
                }
                self.open_path(&target, true, false)?;
            }
            PreviewUiMsg::RequestLocalImage { req_id, path } => {
                let Some(resolved) = preview::file_path(&path) else {
                    return self.send_doc_msg(&PreviewHostMsg::LocalImageError {
                        req_id,
                        message: "invalid image path".into(),
                    });
                };
                let st = match stat_path(&resolved) {
                    Ok(s) => s,
                    Err(e) => {
                        return self.send_doc_msg(&PreviewHostMsg::LocalImageError {
                            req_id,
                            message: err_message(&e),
                        });
                    }
                };
                if st.size > ARCHIVE_MAX as u64 {
                    return self.send_doc_msg(&PreviewHostMsg::LocalImageError {
                        req_id,
                        message: "local image exceeds preview limit".into(),
                    });
                }
                let mut f = match File::open(&resolved) {
                    Ok(f) => f,
                    Err(e) => {
                        return self.send_doc_msg(&PreviewHostMsg::LocalImageError {
                            req_id,
                            message: e.to_string(),
                        });
                    }
                };
                let mut head = vec![0u8; (st.size as usize).min(512)];
                let n = f.read(&mut head).unwrap_or(0);
                head.truncate(n);
                let Some(mime) = preview::image_mime(&resolved, &head) else {
                    return self.send_doc_msg(&PreviewHostMsg::LocalImageError {
                        req_id,
                        message: "unsupported local image".into(),
                    });
                };
                drop(f);
                let img_fd = match File::open(&resolved) {
                    Ok(f) => f,
                    Err(e) => {
                        return self.send_doc_msg(&PreviewHostMsg::LocalImageError {
                            req_id,
                            message: e.to_string(),
                        });
                    }
                };
                let asset_id = self.alloc_asset_id();
                self.seat.queue_with_fd(
                    &ClientReq::StreamAsset {
                        surface_id: self.surface_id,
                        asset_id,
                        mime: mime.to_owned(),
                        mode: AssetStreamMode::Blob,
                    },
                    Some(img_fd),
                )?;
                self.send_doc_msg(&PreviewHostMsg::LocalImageReady {
                    req_id,
                    asset_id,
                    mime: mime.to_owned(),
                })?;
            }
            PreviewUiMsg::RequestHighlight { req_id, info, text } => {
                let lang = language::of_block(&info).or_else(|| language::named(&info));
                let Some(lang) = lang else {
                    return self.send_doc_msg(&PreviewHostMsg::HighlightResult {
                        req_id,
                        html: None,
                        error: None,
                    });
                };
                let job_id = self.alloc_job_id();
                self.pending_jobs.insert(
                    job_id,
                    PendingJob::Highlight {
                        version: self.view_version,
                        req_id,
                    },
                );
                self.seat.queue(&ClientReq::PreviewJob {
                    surface_id: self.surface_id,
                    job_id,
                    kind: PreviewJobKind::Highlight {
                        language: lang.name.to_owned(),
                        group: group_name(lang.group).to_owned(),
                        text,
                    },
                })?;
            }
            PreviewUiMsg::RequestDiagram { req_id, source } => {
                let job_id = self.alloc_job_id();
                self.pending_jobs.insert(
                    job_id,
                    PendingJob::Diagram {
                        version: self.view_version,
                        req_id,
                    },
                );
                self.seat.queue(&ClientReq::PreviewJob {
                    surface_id: self.surface_id,
                    job_id,
                    kind: PreviewJobKind::Diagram { source },
                })?;
            }
            PreviewUiMsg::RequestPdfRender {
                req_id,
                doc_id,
                page,
                width,
            } => {
                let job_id = self.alloc_job_id();
                self.pending_jobs.insert(
                    job_id,
                    PendingJob::PdfRender {
                        version: self.view_version,
                        req_id,
                    },
                );
                self.seat.queue(&ClientReq::PreviewJob {
                    surface_id: self.surface_id,
                    job_id,
                    kind: PreviewJobKind::PdfRender {
                        doc_id,
                        page,
                        width: width.clamp(1, 3840),
                    },
                })?;
            }
            PreviewUiMsg::SavePlace { path, patch } => {
                self.places.merge(&path, patch);
                self.persist_places();
            }
            PreviewUiMsg::SetPref {
                slide_theme,
                notes_size,
            } => {
                if let Some(theme) = slide_theme
                    && matches!(theme.as_str(), "light" | "dark" | "sepia" | "night")
                {
                    self.places.slide_theme = theme;
                }
                if let Some(sz) = notes_size {
                    self.places.notes_size = sz.clamp(14, 56);
                }
                self.persist_places();
            }
            PreviewUiMsg::TellPresenting { path, column, row } => {
                let cloud = to_cloud_path(&path);
                if let Some(pw) = self.pending_where.get_mut(&cloud)
                    && pw.local_turned_at.is_none()
                {
                    pw.local_turned_at = Some(Instant::now());
                }
                self.heard.insert(path.clone(), [column, row]);
                self.heard.insert(cloud.clone(), [column, row]);
                let req_id = self.alloc_media_req();
                self.seat.queue(&ClientReq::MediaControl {
                    surface_id: self.surface_id,
                    request_id: req_id,
                    control: MediaControlOp::BroadcastPresent { path, column, row },
                })?;
                self.send_session_json(
                    json!({ "present": { "path": cloud, "at": [column, row] } }),
                );
            }
            PreviewUiMsg::AskWhere { path } => {
                self.ask_where(&path, None);
            }
            PreviewUiMsg::OpenSpeaker { .. } => {
                let Some(path) = self.current_path.clone() else {
                    return Ok(());
                };
                let req_id = self.alloc_media_req();
                self.seat.queue(&ClientReq::MediaControl {
                    surface_id: self.surface_id,
                    request_id: req_id,
                    control: MediaControlOp::OpenSpeaker { path },
                })?;
            }
            PreviewUiMsg::TogglePresenting { .. } => {
                if !self.bar.presented.is_empty() {
                    let devices = std::mem::take(&mut self.bar.presented);
                    for dev in devices {
                        if let Err(err) = dev_stop(&dev) {
                            self.set_bar_note(err);
                            return Ok(());
                        }
                    }
                    self.bar_presented_versions.clear();
                    self.push_bar()?;
                } else {
                    let Some(path) = self.current_path.clone() else {
                        return Ok(());
                    };
                    match dev_present_file(&path, None) {
                        Ok(made) => {
                            let dev = made
                                .get("device")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_owned();
                            let ver = made
                                .get("version")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_owned();
                            if !dev.is_empty() {
                                self.bar_presented_versions.insert(dev.clone(), ver);
                                self.bar.presented = vec![dev];
                            }
                            self.push_bar()?;
                        }
                        Err(err) => self.set_bar_note(err),
                    }
                }
            }
            PreviewUiMsg::GoLive { keep, .. } => {
                let Some(path) = self.current_path.clone() else {
                    return Ok(());
                };
                let req_id = self.alloc_media_req();
                self.seat.queue(&ClientReq::MediaControl {
                    surface_id: self.surface_id,
                    request_id: req_id,
                    control: MediaControlOp::GoLive { path, keep },
                })?;
            }
            PreviewUiMsg::AskToSpeak {} => {
                let Some(pres) = self.following.as_ref().map(|f| f.device.clone()) else {
                    return Ok(());
                };
                match self.bar.asking.as_ref().map(|a| a.state.as_str()) {
                    Some("asking") => {
                        let _ = dev_ioctl_once(
                            &pres,
                            abi::O_RDONLY,
                            abi::PRESENT_ASK,
                            json!({ "withdraw": true }),
                        );
                        self.bar.asking = None;
                        self.asking_presentation = None;
                        self.asking_id = None;
                        self.push_bar()?;
                    }
                    Some("connecting" | "speaking") => {
                        self.stop_speaking();
                    }
                    _ => {
                        self.asking_presentation = Some(pres.clone());
                        self.bar.asking = Some(LiveAsking {
                            state: "asking".into(),
                            error: None,
                        });
                        self.push_bar()?;
                        match dev_ioctl_once(&pres, abi::O_RDONLY, abi::PRESENT_ASK, Value::Null) {
                            Ok(val) => {
                                if let Some(id) = val.get("id").and_then(Value::as_str) {
                                    self.asking_id = Some(id.to_owned());
                                }
                                if let Some(err) = val.get("error").and_then(Value::as_str) {
                                    self.bar.asking = Some(LiveAsking {
                                        state: "error".into(),
                                        error: Some(err.to_owned()),
                                    });
                                    self.push_bar()?;
                                }
                            }
                            Err(err) => {
                                self.bar.asking = Some(LiveAsking {
                                    state: "error".into(),
                                    error: Some(err),
                                });
                                self.push_bar()?;
                            }
                        }
                    }
                }
            }
            PreviewUiMsg::AnswerAsk { id, allow } => {
                let found = self
                    .bar
                    .asks
                    .iter()
                    .find(|a| a.id == id)
                    .map(|a| a.presentation.clone());
                if let Some(pres) = found {
                    if allow {
                        self.allowed_asks.insert(id.clone());
                    }
                    if let Err(err) = dev_ioctl_once(
                        &pres,
                        abi::O_WRONLY,
                        abi::PRESENT_ANSWER,
                        json!({ "id": id, "allow": allow }),
                    ) {
                        self.set_bar_note(err);
                    }
                    self.bar.asks.retain(|a| a.id != id);
                    self.push_bar()?;
                }
            }
            PreviewUiMsg::EndVoice { device } => {
                if !self.bar.voices.iter().any(|v| v.device == device) {
                    return Ok(());
                }
                match validate_device_path(&device, "/dev/snd") {
                    Ok(valid) => {
                        if let Err(err) = dev_stop(&valid) {
                            self.set_bar_note(err);
                        }
                    }
                    Err(err) => self.set_bar_note(err),
                }
            }
        }
        Ok(())
    }

    fn handle_preview_job_result(
        &mut self,
        job_id: u64,
        output: PreviewJobOutput,
    ) -> Result<(), Errno> {
        let Some(pending) = self.pending_jobs.remove(&job_id) else {
            return Ok(());
        };
        match pending {
            PendingJob::PdfOpen { version } => {
                if version != self.view_version {
                    if let PreviewJobOutput::PdfOpened { doc_id, .. } = output {
                        let close_id = self.alloc_job_id();
                        let _ = self.seat.queue(&ClientReq::PreviewJob {
                            surface_id: self.surface_id,
                            job_id: close_id,
                            kind: PreviewJobKind::PdfClose { doc_id },
                        });
                    }
                    return Ok(());
                }
                match output {
                    PreviewJobOutput::PdfOpened { doc_id, pages } => {
                        self.active_pdf_doc = Some(doc_id);
                        self.send_doc_msg(&PreviewHostMsg::PdfReady {
                            version,
                            doc_id,
                            pages,
                        })?;
                    }
                    PreviewJobOutput::Error { detail } => {
                        self.send_doc_msg(&PreviewHostMsg::PdfError {
                            version,
                            message: format!("Could not open PDF: {detail}"),
                        })?;
                    }
                    _ => {}
                }
            }
            PendingJob::PdfRender { version, req_id } => {
                if version != self.view_version {
                    return Ok(());
                }
                match output {
                    PreviewJobOutput::PdfRendered {
                        doc_id,
                        page,
                        width,
                        height,
                    } => {
                        self.send_doc_msg(&PreviewHostMsg::PdfRendered {
                            req_id,
                            doc_id,
                            page,
                            width,
                            height,
                            error: None,
                        })?;
                    }
                    PreviewJobOutput::Error { detail } => {
                        self.send_doc_msg(&PreviewHostMsg::PdfRendered {
                            req_id,
                            doc_id: 0,
                            page: 0,
                            width: 0,
                            height: 0,
                            error: Some(detail),
                        })?;
                    }
                    _ => {}
                }
            }
            PendingJob::ListArchive { version } => {
                if version != self.view_version {
                    return Ok(());
                }
                match output {
                    PreviewJobOutput::ArchiveListed { entries, more } => {
                        self.send_doc_msg(&PreviewHostMsg::ArchiveReady {
                            version,
                            entries,
                            more,
                        })?;
                    }
                    PreviewJobOutput::Error { detail } => {
                        self.send_doc_msg(&PreviewHostMsg::ArchiveError {
                            version,
                            message: format!("Could not list the archive: {detail}"),
                        })?;
                    }
                    _ => {}
                }
            }
            PendingJob::Highlight { version, req_id } => {
                if version != self.view_version {
                    return Ok(());
                }
                match output {
                    PreviewJobOutput::Text { text } => {
                        let clean = sanitize_highlight_html(&text);
                        self.send_doc_msg(&PreviewHostMsg::HighlightResult {
                            req_id,
                            html: Some(clean),
                            error: None,
                        })?;
                    }
                    PreviewJobOutput::Error { detail } => {
                        self.send_doc_msg(&PreviewHostMsg::HighlightResult {
                            req_id,
                            html: None,
                            error: Some(detail),
                        })?;
                    }
                    _ => {}
                }
            }
            PendingJob::Diagram { version, req_id } => {
                if version != self.view_version {
                    return Ok(());
                }
                match output {
                    PreviewJobOutput::Text { text } => match sanitize_svg(&text) {
                        Ok(clean) => {
                            self.send_doc_msg(&PreviewHostMsg::DiagramResult {
                                req_id,
                                svg: Some(clean),
                                error: None,
                            })?;
                        }
                        Err(err) => {
                            self.send_doc_msg(&PreviewHostMsg::DiagramResult {
                                req_id,
                                svg: None,
                                error: Some(err),
                            })?;
                        }
                    },
                    PreviewJobOutput::Error { detail } => {
                        self.send_doc_msg(&PreviewHostMsg::DiagramResult {
                            req_id,
                            svg: None,
                            error: Some(detail),
                        })?;
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    fn handle_media_event(&mut self, payload: MediaEventPayload) -> Result<(), Errno> {
        match payload {
            MediaEventPayload::SpeakerOpened { ok, .. } => {
                if !ok {
                    self.send_doc_msg(&PreviewHostMsg::Notice {
                        message: "Allow pop-ups for the speaker view".into(),
                    })?;
                }
            }
            MediaEventPayload::PresentBroadcast { path, column, row } => {
                self.apply_present_update(&path, column, row, false)?;
            }
            MediaEventPayload::PresentState {
                request_id,
                device,
                body_json,
                error,
            } => {
                let Some((expected_dev, seq)) = self.pending_attend_reqs.remove(&request_id) else {
                    return Ok(());
                };
                if seq != self.attend_seq
                    || self.following.as_ref().map(|f| f.device.as_str())
                        != Some(expected_dev.as_str())
                {
                    return Ok(());
                }
                let ok = match (body_json, error) {
                    (Some(raw), None) => serde_json::from_str::<Value>(&raw)
                        .map_err(|e| e.to_string())
                        .and_then(|val| self.apply_attended_info(&device, &val)),
                    (_, Some(err)) => Err(err),
                    (None, None) => Err("empty presentation state".into()),
                };
                if ok.is_err() {
                    if let Some(f) = self.following.as_mut() {
                        f.ended = true;
                    }
                    let aud = self
                        .current_path
                        .as_deref()
                        .and_then(|p| self.audience_info(p));
                    self.send_doc_msg(&PreviewHostMsg::AudienceUpdate { audience: aud })?;
                }
            }
            MediaEventPayload::SdpAnswer {
                request_id,
                stream_id,
                sdp,
            } => {
                self.pending_media_reqs.remove(&request_id);
                if let Some(stream) = self.listening.get_mut(&stream_id)
                    && let Some((fd, session)) = stream.pending_listen_fd.take()
                {
                    let res = sys_call(Call::Ioctl {
                        fd: FdRef::Fd(fd),
                        request: abi::SND_ANSWER,
                        arg: json!({ "session": session, "sdp": sdp }),
                    });
                    let _ = sys_call(Call::Close { fd: FdRef::Fd(fd) });
                    if res.is_err() {
                        self.stop_listening_stream(&stream_id);
                    }
                }
            }
            MediaEventPayload::MicOffer {
                request_id,
                stream_id,
                sdp,
                mid,
            } => {
                self.pending_media_reqs.remove(&request_id);
                let Some(sp) = self.speaking.as_mut().filter(|s| s.stream_id == stream_id) else {
                    return Ok(());
                };
                let write_fd = match sp.granted_fd {
                    Some(fd) => fd,
                    None => match sys_call(Call::Open {
                        path: sp.presentation.clone(),
                        flags: abi::O_WRONLY,
                        mode: 0,
                        size: None,
                        sha256: None,
                        version: None,
                    }) {
                        Ok(v) => match v.get("fd").and_then(Value::as_u64) {
                            Some(fd) => fd as u32,
                            None => {
                                self.stop_speaking();
                                return Ok(());
                            }
                        },
                        Err(e) => {
                            let msg = err_message(&e);
                            self.stop_speaking();
                            self.bar.asking = Some(LiveAsking {
                                state: "error".into(),
                                error: Some(msg),
                            });
                            self.push_bar()?;
                            return Ok(());
                        }
                    },
                };
                sp.write_fd = Some(write_fd);
                let offer = json!({ "sdp": sdp, "mid": mid, "ask": sp.ask_id });
                match sys_call(Call::Ioctl {
                    fd: FdRef::Fd(write_fd),
                    request: abi::PRESENT_SPEAK,
                    arg: offer,
                }) {
                    Ok(ans) => {
                        let answer_sdp = ans
                            .get("sdp")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_owned();
                        sp.device = ans.get("device").and_then(Value::as_str).map(str::to_owned);
                        let req_id = self.alloc_media_req();
                        self.seat.queue(&ClientReq::MediaControl {
                            surface_id: self.surface_id,
                            request_id: req_id,
                            control: MediaControlOp::CaptureMicAnswer {
                                stream_id,
                                answer_sdp,
                            },
                        })?;
                    }
                    Err(e) => {
                        let msg = err_message(&e);
                        self.stop_speaking();
                        self.bar.asking = Some(LiveAsking {
                            state: "error".into(),
                            error: Some(msg),
                        });
                        self.push_bar()?;
                    }
                }
            }
            MediaEventPayload::MicConnected { stream_id, .. } => {
                if self
                    .speaking
                    .as_ref()
                    .is_some_and(|s| s.stream_id == stream_id)
                {
                    self.bar.asking = Some(LiveAsking {
                        state: "speaking".into(),
                        error: None,
                    });
                    self.sync_followed_devices();
                    self.push_bar()?;
                }
            }
            MediaEventPayload::StreamState { stream_id, state } => {
                if state == "stopped_by_user" {
                    if let Some(ref f) = self.following {
                        self.declined_presentation = Some(f.device.clone());
                    }
                    self.listening.remove(&stream_id);
                    self.sync_followed_devices();
                } else if state == "failed" {
                    if let Some(s) = self.listening.get_mut(&stream_id) {
                        if s.retry_attempt < RETRY_DELAYS_MS.len() {
                            let delay = RETRY_DELAYS_MS[s.retry_attempt];
                            s.retry_attempt += 1;
                            s.retry_at = Some(Instant::now() + Duration::from_millis(delay));
                        } else {
                            self.stop_listening_stream(&stream_id);
                        }
                    }
                } else if state == "mic_ended"
                    && self
                        .speaking
                        .as_ref()
                        .is_some_and(|s| s.stream_id == stream_id)
                {
                    self.stop_speaking();
                }
            }
            MediaEventPayload::LiveSoundState {
                device,
                version: _,
                recording,
                since_ms,
                progress,
                note,
                active,
            } => {
                if active {
                    self.bar.sound = Some(LiveSending {
                        device,
                        recording,
                        since: since_ms,
                        progress,
                    });
                } else {
                    self.bar.sound = None;
                }
                if let Some(n) = note {
                    self.set_bar_note(n);
                } else {
                    self.push_bar()?;
                }
            }
            MediaEventPayload::Error {
                request_id,
                stream_id,
                detail,
            } => {
                self.pending_media_reqs.remove(&request_id);
                if let Some(sid) = stream_id
                    && self.speaking.as_ref().is_some_and(|s| s.stream_id == sid)
                {
                    self.stop_speaking();
                    self.bar.asking = Some(LiveAsking {
                        state: "error".into(),
                        error: Some(detail),
                    });
                    self.push_bar()?;
                } else if !detail.is_empty() {
                    self.set_bar_note(detail);
                }
            }
        }
        Ok(())
    }

    fn apply_present_update(
        &mut self,
        path: &str,
        column: u32,
        row: u32,
        from_where: bool,
    ) -> Result<(), Errno> {
        let cloud = to_cloud_path(path);
        let mounted = if cloud.starts_with('/') {
            format!("/mnt/cloud{cloud}")
        } else {
            cloud.clone()
        };
        self.heard.insert(path.to_owned(), [column, row]);
        self.heard.insert(cloud.clone(), [column, row]);
        self.heard.insert(mounted.clone(), [column, row]);
        let mapped = match self.current_path.as_deref() {
            Some(cur) if to_cloud_path(cur) == cloud => cur.to_owned(),
            _ => path.to_owned(),
        };
        self.send_doc_msg(&PreviewHostMsg::PresentUpdate {
            path: mapped,
            column,
            row,
            from_where,
        })
    }

    fn handle_session_event(&mut self, event_json: &str) -> Result<(), Errno> {
        let Ok(msg) = serde_json::from_str::<Value>(event_json) else {
            return Ok(());
        };
        if msg.get("reconnected").and_then(Value::as_bool) == Some(true) {
            if self.following.is_some() || !self.listening.is_empty() || self.speaking.is_some() {
                self.sync_followed_devices();
            }
            if let Some(cur) = self.current_path.clone()
                && self.following.is_none()
            {
                self.ask_where(&cur, None);
            }
            return Ok(());
        }
        if let Some(present) = msg.get("present") {
            if let (Some(path), Some(at)) = (
                present.get("path").and_then(Value::as_str),
                present.get("at").and_then(Value::as_array),
            ) && let (Some(c), Some(r)) = (
                at.first().and_then(Value::as_u64),
                at.get(1).and_then(Value::as_u64),
            ) {
                let cloud = to_cloud_path(path);
                let pw = self.pending_where.remove(&cloud);
                if let Some(ref p) = pw
                    && let Some(turned_at) = p.local_turned_at
                    && turned_at.elapsed() < Duration::from_millis(500)
                    && p.initial_pos == Some([c as u32, r as u32])
                {
                    return Ok(());
                }
                let from_where = pw.is_some();
                self.apply_present_update(path, c as u32, r as u32, from_where)?;
            }
            return Ok(());
        }
        if let Some(sound) = msg.get("sound") {
            let pres = sound
                .get("presentation")
                .and_then(Value::as_str)
                .unwrap_or("");
            let dev = sound.get("device").and_then(Value::as_str).unwrap_or("");
            if let Some(speaker) = sound.get("speaker").and_then(Value::as_str) {
                let ask = sound.get("ask").and_then(Value::as_str).unwrap_or("");
                if self.bar.presented.iter().any(|p| p == pres) {
                    self.bar.voices.retain(|v| v.device != dev);
                    self.bar.voices.push(LiveVoice {
                        device: dev.to_owned(),
                        speaker: speaker.to_owned(),
                        presentation: pres.to_owned(),
                        ask: ask.to_owned(),
                    });
                    self.push_bar()?;
                    if self.allowed_asks.contains(ask) && !self.listening.contains_key(dev) {
                        self.start_listening_sound(dev, &format!("{speaker} speaking"), true, 0);
                    }
                } else if self.following.as_ref().is_some_and(|f| f.device == pres)
                    && Some(ask) != self.asking_id.as_deref()
                    && !self.listening.contains_key(dev)
                {
                    self.start_listening_sound(dev, &format!("{speaker} speaking"), true, 0);
                }
            } else if self.following.as_ref().is_some_and(|f| f.device == pres)
                && self.listening.values().all(|l| l.is_voice)
                && self.declined_presentation.as_deref() != Some(pres)
            {
                self.start_listening_sound(dev, dev, false, 0);
            }
            return Ok(());
        }
        if let Some(asking) = msg.get("asking") {
            let id = asking.get("id").and_then(Value::as_str).unwrap_or("");
            self.bar.asks.retain(|a| a.id != id);
            let gone = asking.get("gone").and_then(Value::as_bool).unwrap_or(false);
            let error = asking.get("error").and_then(Value::as_str);
            if !gone
                && error.is_none()
                && let (Some(name), Some(pres)) = (
                    asking.get("name").and_then(Value::as_str),
                    asking.get("presentation").and_then(Value::as_str),
                )
            {
                self.bar.asks.push(LiveAsk {
                    id: id.to_owned(),
                    name: name.to_owned(),
                    presentation: pres.to_owned(),
                });
            }
            if let Some(err) = error {
                self.set_bar_note(err.to_owned());
            } else {
                self.push_bar()?;
            }
            return Ok(());
        }
        if let Some(granted) = msg.get("granted") {
            let pres = granted
                .get("presentation")
                .and_then(Value::as_str)
                .unwrap_or("");
            if self.asking_presentation.as_deref() == Some(pres) {
                let ask_id = granted
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                let granted_fd = granted.get("fd").and_then(Value::as_u64).map(|v| v as u32);
                let stream_id = format!("voice-{ask_id}");
                self.speaking = Some(SpeakingState {
                    presentation: pres.to_owned(),
                    ask_id,
                    granted_fd,
                    write_fd: None,
                    device: None,
                    stream_id: stream_id.clone(),
                });
                self.bar.asking = Some(LiveAsking {
                    state: "connecting".into(),
                    error: None,
                });
                self.push_bar()?;
                let req_id = self.alloc_media_req();
                self.pending_media_reqs.insert(req_id, stream_id.clone());
                self.seat.queue(&ClientReq::MediaControl {
                    surface_id: self.surface_id,
                    request_id: req_id,
                    control: MediaControlOp::CaptureMicOffer { stream_id },
                })?;
            }
            return Ok(());
        }
        if let Some(denied) = msg.get("denied") {
            let pres = denied
                .get("presentation")
                .and_then(Value::as_str)
                .unwrap_or("");
            if self.asking_presentation.as_deref() == Some(pres) {
                self.bar.asking = Some(LiveAsking {
                    state: "denied".into(),
                    error: None,
                });
                self.push_bar()?;
            }
            return Ok(());
        }
        if let Some(followed) = msg.get("followed") {
            if let (Some(name), Some(version)) = (
                followed.get("name").and_then(Value::as_str),
                followed.get("version").and_then(Value::as_str),
            ) {
                let reattend = self
                    .following
                    .as_ref()
                    .is_some_and(|f| f.device == name && f.version != version);
                if reattend {
                    self.request_reattend_async(name);
                }
                let rehear = self
                    .listening
                    .get(name)
                    .is_some_and(|l| l.version != version);
                if rehear {
                    let (label, is_voice) = self
                        .listening
                        .get(name)
                        .map(|l| (l.label.clone(), l.is_voice))
                        .unwrap_or_else(|| (name.to_owned(), false));
                    self.stop_listening_stream(name);
                    self.start_listening_sound(name, &label, is_voice, 0);
                }
            }
            return Ok(());
        }
        if let Some(device) = msg.get("device") {
            let name = device.get("name").and_then(Value::as_str).unwrap_or("");
            if device.get("replaced").and_then(Value::as_bool) == Some(true) {
                if self.following.as_ref().is_some_and(|f| f.device == name) {
                    self.request_reattend_async(name);
                }
                if self.listening.contains_key(name) {
                    let (label, is_voice) = self
                        .listening
                        .get(name)
                        .map(|l| (l.label.clone(), l.is_voice))
                        .unwrap_or_else(|| (name.to_owned(), false));
                    self.stop_listening_stream(name);
                    self.start_listening_sound(name, &label, is_voice, 0);
                }
                return Ok(());
            }
            if let Some(f) = self.following.as_mut().filter(|f| f.device == name) {
                f.ended = true;
                let aud = self
                    .current_path
                    .as_deref()
                    .and_then(|p| self.audience_info(p));
                self.send_doc_msg(&PreviewHostMsg::AudienceUpdate { audience: aud })?;
            }
            if self.listening.contains_key(name) {
                self.stop_listening_stream(name);
            }
            if self.asking_presentation.as_deref() == Some(name)
                || self.speaking.as_ref().and_then(|s| s.device.as_deref()) == Some(name)
            {
                self.stop_speaking();
            }
            self.bar.presented.retain(|p| p != name);
            self.bar.voices.retain(|v| v.device != name);
            self.push_bar()?;
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
            let reply = match serde_json::from_slice::<PreviewControlReq>(line) {
                Ok(PreviewControlReq::Open { path }) => {
                    if path.starts_with("/dev/present/") {
                        match self.attend_presentation(&path) {
                            Ok(()) => PreviewControlReply {
                                ok: true,
                                stdout: None,
                                error: None,
                            },
                            Err(err) => PreviewControlReply {
                                ok: false,
                                stdout: None,
                                error: Some(err),
                            },
                        }
                    } else {
                        match self.open_path(&path, false, false) {
                            Ok(()) => PreviewControlReply {
                                ok: true,
                                stdout: None,
                                error: None,
                            },
                            Err(e) => PreviewControlReply {
                                ok: false,
                                stdout: None,
                                error: Some(e.text().to_owned()),
                            },
                        }
                    }
                }
                Ok(PreviewControlReq::Manual { command }) => {
                    match self.open_manual(command.as_deref()) {
                        Ok(()) => PreviewControlReply {
                            ok: true,
                            stdout: None,
                            error: None,
                        },
                        Err(err) => PreviewControlReply {
                            ok: false,
                            stdout: None,
                            error: Some(err),
                        },
                    }
                }
                Ok(PreviewControlReq::Present { path, name }) => {
                    match dev_present_file(&path, name.as_deref()) {
                        Ok(started) => {
                            let dev = started
                                .get("device")
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_owned();
                            let short = dev.rsplit('/').next().unwrap_or("");
                            let _ = self.open_path(&path, false, false);
                            PreviewControlReply {
                                ok: true,
                                stdout: Some(format!(
                                    "Presenting {path} as {dev}: whoever may read it follows it with open {dev}; present --stop {short} ends it\n"
                                )),
                                error: None,
                            }
                        }
                        Err(err) => PreviewControlReply {
                            ok: false,
                            stdout: None,
                            error: Some(err),
                        },
                    }
                }
                Ok(PreviewControlReq::StopPresent { name }) => {
                    if !valid_device_segment(&name) {
                        PreviewControlReply {
                            ok: false,
                            stdout: None,
                            error: Some(format!("invalid presentation name: {name}")),
                        }
                    } else {
                        let dev = format!("{PRESENT_PREFIX}/{name}");
                        match dev_stop(&dev) {
                            Ok(()) => PreviewControlReply {
                                ok: true,
                                stdout: Some(format!("Stopped {dev}\n")),
                                error: None,
                            },
                            Err(err) => PreviewControlReply {
                                ok: false,
                                stdout: None,
                                error: Some(err),
                            },
                        }
                    }
                }
                Ok(PreviewControlReq::Focus {}) => {
                    let _ = self.send_doc_msg(&PreviewHostMsg::Focus {});
                    PreviewControlReply {
                        ok: true,
                        stdout: None,
                        error: None,
                    }
                }
                Err(_) => PreviewControlReply {
                    ok: false,
                    stdout: None,
                    error: Some("invalid preview control request".into()),
                },
            };
            if let Ok(mut out) = serde_json::to_vec(&reply) {
                out.push(b'\n');
                let _ = client.send(&out, MSG_NOSIGNAL);
            }
        }
        Ok(())
    }

    fn tick_timers(&mut self) {
        if let Some(at) = self.last_bar_note_at
            && at.elapsed() >= Duration::from_secs(8)
        {
            self.last_bar_note_at = None;
            self.bar.note.clear();
            let _ = self.push_bar();
        }
        let now = Instant::now();
        let due: Vec<(String, String, bool, usize)> = self
            .listening
            .values()
            .filter_map(|s| {
                if s.retry_at.is_some_and(|t| now >= t) {
                    Some((
                        s.device.clone(),
                        s.label.clone(),
                        s.is_voice,
                        s.retry_attempt,
                    ))
                } else {
                    None
                }
            })
            .collect();
        for (dev, label, is_voice, attempt) in due {
            self.stop_listening_stream(&dev);
            self.start_listening_sound(&dev, &label, is_voice, attempt);
        }
    }

    fn run(mut self) -> Result<(), Errno> {
        while !self.closing && !STOP.load(Ordering::SeqCst) {
            self.seat.flush()?;
            for event in self.seat.drain_events()? {
                match event {
                    ClientEvent::CloseRequested { .. } => {
                        self.closing = true;
                        break;
                    }
                    ClientEvent::DocumentMessage { text, .. } => {
                        self.handle_doc_message(&text)?;
                    }
                    ClientEvent::FullscreenChanged { active, .. } => {
                        self.send_doc_msg(&PreviewHostMsg::Fullscreen {
                            active,
                            error: None,
                        })?;
                    }
                    ClientEvent::FullscreenError { detail, .. } => {
                        self.send_doc_msg(&PreviewHostMsg::Fullscreen {
                            active: false,
                            error: Some(detail),
                        })?;
                    }
                    ClientEvent::PreviewJobResult { job_id, output, .. } => {
                        self.handle_preview_job_result(job_id, output)?;
                    }
                    ClientEvent::MediaEvent { payload, .. } => {
                        self.handle_media_event(payload)?;
                    }
                    ClientEvent::SessionEvent { event_json, .. } => {
                        self.handle_session_event(&event_json)?;
                    }
                    ClientEvent::Focus { focused: true, .. } => {
                        let _ = self.send_doc_msg(&PreviewHostMsg::Focus {});
                    }
                    _ => {}
                }
            }
            if self.closing || STOP.load(Ordering::SeqCst) {
                break;
            }
            self.tick_timers();
            self.service_control_socket()?;
            self.seat.flush()?;

            let mut read_fds = vec![self.seat.fd()];
            if let Some(ref listener) = self.ctrl_listener {
                #[allow(clippy::unnecessary_cast)]
                read_fds.push(listener.as_raw_fd() as u32);
            }
            let mut write_fds = Vec::new();
            if self.seat.has_pending_writes() {
                write_fds.push(self.seat.fd());
            }
            poll_fds(&read_fds, &write_fds, 40);
        }

        self.unfollow();
        self.cleanup_current_view();
        let _ = self.seat.send_blocking(&ClientReq::SessionEvents {
            surface_id: self.surface_id,
            control: SessionEventOp::Unsubscribe {},
        });
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
        println!(
            "Usage: preview [--speaker] [--manual [CMD]] [--present [--name NAME]] [--stop-present NAME] [--] [PATH]"
        );
        return Ok(());
    }

    let mut speaker_mode = false;
    let mut manual_mode = false;
    let mut manual_cmd: Option<String> = None;
    let mut present_mode = false;
    let mut present_name: Option<String> = None;
    let mut stop_present: Option<String> = None;
    let mut target_path: Option<String> = None;

    let mut i = 0;
    let mut end_opts = false;
    while i < args.len() {
        let a = args[i].as_str();
        if !end_opts {
            match a {
                "--" => {
                    end_opts = true;
                    i += 1;
                    continue;
                }
                "--speaker" => {
                    speaker_mode = true;
                    i += 1;
                    continue;
                }
                "--manual" => {
                    manual_mode = true;
                    if let Some(next) = args.get(i + 1)
                        && !next.starts_with('-')
                    {
                        manual_cmd = Some(next.clone());
                        i += 2;
                    } else {
                        i += 1;
                    }
                    continue;
                }
                "--present" => {
                    present_mode = true;
                    i += 1;
                    continue;
                }
                "--name" => {
                    present_name = args.get(i + 1).cloned();
                    i += 2;
                    continue;
                }
                "--stop-present" => {
                    stop_present = args.get(i + 1).cloned();
                    i += 2;
                    continue;
                }
                _ => {}
            }
        }
        if target_path.is_none() {
            target_path = Some(a.to_owned());
        }
        i += 1;
    }

    if let Some(name) = stop_present {
        if !valid_device_segment(&name) {
            eprintln!("invalid presentation name: {name}");
            std::process::exit(1);
        }
        let dev = format!("{PRESENT_PREFIX}/{name}");
        match dev_stop(&dev) {
            Ok(()) => {
                println!("Stopped {dev}");
                return Ok(());
            }
            Err(err) => {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
    }

    // Pre-validate `/dev/present/*` permission BEFORE mapping any window or forwarding,
    // so denied access exits 1 with stderr and never pops up an empty Preview window.
    if let Some(ref p) = target_path
        && p.starts_with("/dev/present/")
        && !present_mode
        && let Err(err) = read_present_device(p)
    {
        eprintln!("{err}");
        std::process::exit(1);
    }

    // Pre-validate `man <cmd>` before mapping a window.
    if manual_mode
        && let Some(ref cmd) = manual_cmd
        && os_core::cli::page(cmd).is_none()
    {
        if os_core::bin::program(cmd).is_some() {
            eprintln!("{cmd} is /bin's (uutils): {cmd} --help says how to use it");
        } else {
            eprintln!("No manual entry for {cmd}. Enter man for the index.");
        }
        std::process::exit(1);
    }

    // Pre-validate `--present` permission / device creation BEFORE mapping a window.
    let mut initial_present_stdout: Option<String> = None;
    let mut initial_present_info: Option<Value> = None;
    if present_mode {
        let Some(ref path) = target_path else {
            eprintln!("Usage: present [-n NAME] FILE");
            std::process::exit(2);
        };
        match dev_present_file(path, present_name.as_deref()) {
            Ok(started) => {
                let dev = started
                    .get("device")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                let short = dev.rsplit('/').next().unwrap_or("");
                initial_present_stdout = Some(format!(
                    "Presenting {path} as {dev}: whoever may read it follows it with open {dev}; present --stop {short} ends it\n"
                ));
                initial_present_info = Some(started);
            }
            Err(err) => {
                eprintln!("{err}");
                std::process::exit(1);
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

    // Single-instance reuse (unless `--speaker` popup window).
    if !speaker_mode {
        let forward_req = if manual_mode {
            Some(PreviewControlReq::Manual {
                command: manual_cmd.clone(),
            })
        } else {
            target_path
                .clone()
                .map(|path| PreviewControlReq::Open { path })
        };
        if let Some(ref req) = forward_req
            && let Some(reply) = try_forward_to_existing(uid, req)?
        {
            if let Some(out) = initial_present_stdout.or(reply.stdout) {
                print!("{out}");
            }
            if !reply.ok {
                if let Some(err) = reply.error {
                    eprintln!("{err}");
                }
                std::process::exit(1);
            }
            return Ok(());
        }
    }

    if let Some(out) = initial_present_stdout {
        print!("{out}");
        let _ = io::Write::flush(&mut io::stdout());
    }

    let places_path = PathBuf::from(&home).join(PLACES_REL_PATH);
    let places_outcome = load_places_file(&places_path);
    let places_read_only = matches!(places_outcome, PlacesLoadOutcome::RefusedNewer(_));
    let mut places = match places_outcome {
        PlacesLoadOutcome::Loaded(p) => p,
        _ => PlacesFile::default(),
    };
    if let (Some(path), Some(started)) = (&target_path, &initial_present_info) {
        let kind = load_effective_associations(Some(&home))
            .0
            .resolve(path)
            .kind;
        let place = started.get("place").cloned();
        let patch = if kind == "pdf" {
            if let Some(p0) = place
                .as_ref()
                .and_then(|v| v.get(0))
                .and_then(Value::as_u64)
            {
                json!({ "present": true, "page": p0 })
            } else {
                json!({ "present": true })
            }
        } else if let Some(arr) = place.filter(|v| v.is_array()) {
            json!({ "slides": true, "slide": arr })
        } else {
            json!({ "slides": true })
        };
        places.merge(path, patch);
        if !places_read_only {
            let _ = save_places_file_atomic(&places_path, &places);
        }
    }

    let bundle_bytes = std::fs::read(PREVIEW_BUNDLE).map_err(|e| {
        eprintln!("preview: failed to read {PREVIEW_BUNDLE}: {e}");
        os_posix::errno_of(&e).unwrap_or(Errno::ENOENT)
    })?;
    let expected_sha256 = sha256_hex(&bundle_bytes);

    let mut seat = SeatConn::connect()?;
    seat.send_blocking(&ClientReq::Hello {
        versions: vec![1],
        required: vec![
            "document".into(),
            "export".into(),
            "fullscreen".into(),
            "media-stream".into(),
            "preview-compute".into(),
            "game-embed".into(),
            "live-media".into(),
        ],
    })?;
    match seat.recv_blocking()? {
        ClientEvent::Hello { version: 1 } => {}
        ClientEvent::Error { errno } => return Err(errno),
        _ => return Err(Errno::EPROTONOSUPPORT),
    }

    let initial_title = if manual_mode {
        match &manual_cmd {
            Some(c) => format!("man · {c}"),
            None => "OS · Manual".into(),
        }
    } else if let Some(ref p) = target_path {
        if speaker_mode {
            format!("Speaker view · {}", p.rsplit('/').next().unwrap_or(p))
        } else {
            p.clone()
        }
    } else {
        "Preview".into()
    };

    seat.send_blocking(&ClientReq::CreateSurface {
        spec: SurfaceSpec {
            role: SurfaceRole::Window,
            kind: SurfaceKind::Document(DocumentSource {
                bundle_path: PREVIEW_BUNDLE.into(),
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
                width: 320,
                height: 220,
            },
            max_size: None,
            resizable: true,
            app_id: Some("preview".into()),
        },
    })?;
    let surface_id = match seat.recv_blocking()? {
        ClientEvent::Created { surface_id } => surface_id,
        ClientEvent::Error { errno } => return Err(errno),
        _ => return Err(Errno::EIO),
    };

    seat.send_blocking(&ClientReq::SessionEvents {
        surface_id,
        control: SessionEventOp::Subscribe {},
    })?;

    let (ctrl_listener, ctrl_path, ctrl_ino) = if speaker_mode {
        (None, None, None)
    } else {
        bind_control_socket(uid)
    };

    let pending_open = if manual_mode {
        Some(InitialAction::Manual(manual_cmd))
    } else {
        target_path.map(InitialAction::File)
    };

    let app = PreviewApp {
        seat,
        surface_id,
        uid,
        home,
        speaker_mode,
        config: load_system_os_config(),
        places,
        places_path,
        places_read_only,
        doc_ready: false,
        chunk_seq: 0,
        doc_asm: DocChunkAssembler::with_limits(MAX_PREVIEW_ASSEMBLED_BYTES, MAX_PREVIEW_CHUNKS),
        view_version: 0,
        next_asset_id: 0,
        next_job_id: 0,
        next_media_req: 0,
        current_path: None,
        current_manual: false,
        current_title: initial_title,
        active_pdf_doc: None,
        game_mounted: false,
        trail: Vec::new(),
        pending_jobs: HashMap::new(),
        heard: HashMap::new(),
        pending_where: HashMap::new(),
        following: None,
        attend_seq: 0,
        pending_attend_reqs: HashMap::new(),
        declined_presentation: None,
        bar: LiveBarState::default(),
        bar_presented_versions: HashMap::new(),
        allowed_asks: BTreeSet::new(),
        asking_presentation: None,
        asking_id: None,
        speaking: None,
        listening: BTreeMap::new(),
        pending_media_reqs: HashMap::new(),
        last_bar_note_at: None,
        ctrl_listener,
        ctrl_path,
        ctrl_ino,
        pending_open,
        closing: false,
    };
    app.run()
}

fn main() {
    if let Err(e) = run() {
        eprintln!("preview: {}", e.text());
        std::process::exit(1);
    }
}
