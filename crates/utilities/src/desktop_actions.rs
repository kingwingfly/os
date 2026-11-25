//! Desktop-action CLI applets (`open`, `vim`, `man`, `present`, `stream`, `upload`).
//!
//! Each applet is a real `/usr/bin/*` executable (symlinked to `/usr/bin/utilities`) that speaks
//! newline-delimited JSON over `/run/user/<uid>/desktop-actions.sock` (`AF_UNIX`, verifying
//! `SO_PEERCRED.uid == getuid()`). `man` falls back to printing the manual text to stdout when
//! stdout is not a TTY or when no graphical desktop session is listening.

use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use abi::Errno;
use abi::socket::{MSG_DONTWAIT, MSG_NOSIGNAL};
use os_core::cli::{self, files, terminal};
use os_posix::process::{getuid, ioctl};
use os_posix::socket::UnixStream;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const IOCTL_TCGETS: u32 = 0x5401;
const MAX_LINE_BYTES: usize = 256 * 1024;

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "wasi")]
#[unsafe(no_mangle)]
pub extern "C" fn __desktop_action_signal(sig: u32) {
    if matches!(sig, 1 | 2 | 15) {
        INTERRUPTED.store(true, Ordering::SeqCst);
    }
}

fn install_cancel_handler() {
    INTERRUPTED.store(false, Ordering::SeqCst);
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
        let name = b"__desktop_action_signal";
        // SAFETY: valid static callback name and scalar signal numbers.
        // Set SA_RESTART (0x10000000) so `std::thread::sleep` is not interrupted with EINTR
        // (which panics in wasm32-wasip1 stdlib nanosleep) while `INTERRUPTED` wakes the loop.
        unsafe {
            callback_signal(name.as_ptr(), name.len());
            let _ = sigaction(2, 2, 0, 0x10000000); // SIGINT (SA_RESTART)
            let _ = sigaction(15, 2, 0, 0x10000000); // SIGTERM (SA_RESTART)
        }
    }
}

/// Wire request sent to `/run/user/<uid>/desktop-actions.sock`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum DesktopActionRequest {
    Open {
        path: String,
    },
    Vim {
        path: String,
    },
    Man {
        command: Option<String>,
    },
    Present {
        path: Option<String>,
        name: Option<String>,
        stop: Option<String>,
    },
    Stream {
        path: Option<String>,
        name: Option<String>,
        acl: Option<String>,
    },
    Upload {
        dir: String,
    },
    Cancel,
}

/// Wire response line received from `/run/user/<uid>/desktop-actions.sock`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DesktopActionReply {
    #[serde(default)]
    pub done: bool,
    #[serde(default)]
    pub status: i32,
    #[serde(default)]
    pub stdout: Option<String>,
    #[serde(default)]
    pub stderr: Option<String>,
    #[serde(default)]
    pub progress: Option<String>,
}

/// Socket path for the current user's desktop action bridge.
pub fn socket_path(uid: u32) -> String {
    format!("/run/user/{uid}/desktop-actions.sock")
}

/// Resolve a user-supplied path against `cwd` and `home` cleanly without collapsing `..` unsafely.
pub fn resolve_abs_path(raw: &str, cwd: &str, home: &str) -> String {
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
    if parts.is_empty() {
        "/".into()
    } else {
        format!("/{}", parts.join("/"))
    }
}

fn current_cwd() -> String {
    os_posix::getcwd()
        .ok()
        .and_then(|p| p.to_str().map(str::to_owned))
        .unwrap_or_else(|| "/".into())
}

fn current_home() -> String {
    std::env::var("HOME").unwrap_or_else(|_| "/".into())
}

fn stdout_is_tty() -> bool {
    ioctl(1, IOCTL_TCGETS, Value::Null).is_ok()
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

fn execute_desktop_action(
    req: &DesktopActionRequest,
    wait_cancellable: bool,
) -> Result<i32, String> {
    let uid = getuid();
    let path = socket_path(uid);
    let stream = UnixStream::connect(&path).map_err(|errno| match errno {
        Errno::ENOENT | Errno::ECONNREFUSED => {
            "desktop session unavailable (no graphical desktop-actions socket)".to_owned()
        }
        other => format!("cannot connect to {path}: {}", other.text()),
    })?;
    let peer = stream
        .peer_cred()
        .map_err(|e| format!("peercred failed: {}", e.text()))?;
    if peer.uid != uid {
        return Err(format!(
            "refusing desktop action socket owned by uid {} (expected {})",
            peer.uid, uid
        ));
    }

    let mut payload = serde_json::to_vec(req).map_err(|e| e.to_string())?;
    payload.push(b'\n');
    send_all(&stream, &payload).map_err(|e| format!("send failed: {}", e.text()))?;

    if wait_cancellable {
        install_cancel_handler();
    }

    let is_tty = stdout_is_tty();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut sent_cancel = false;
    let mut printed_progress = false;

    loop {
        if wait_cancellable && !sent_cancel && INTERRUPTED.load(Ordering::SeqCst) {
            sent_cancel = true;
            if let Ok(mut cancel) = serde_json::to_vec(&DesktopActionRequest::Cancel) {
                cancel.push(b'\n');
                let _ = send_all(&stream, &cancel);
            }
        }

        while let Some(nl) = buf.iter().position(|&b| b == b'\n') {
            let line = buf.drain(..=nl).collect::<Vec<u8>>();
            let reply: DesktopActionReply =
                serde_json::from_slice(&line).map_err(|e| format!("invalid desktop reply: {e}"))?;
            if let Some(progress) = reply.progress {
                if is_tty {
                    let _ = write!(io::stderr(), "\r\x1b[K{progress}");
                    let _ = io::stderr().flush();
                } else {
                    eprintln!("{progress}");
                }
                printed_progress = true;
            }
            if let Some(out) = reply.stdout {
                if printed_progress && is_tty {
                    let _ = write!(io::stderr(), "\r\x1b[K");
                    let _ = io::stderr().flush();
                    printed_progress = false;
                }
                let _ = io::stdout().write_all(out.as_bytes());
                let _ = io::stdout().flush();
            }
            if let Some(err) = reply.stderr {
                if printed_progress && is_tty {
                    let _ = write!(io::stderr(), "\r\x1b[K");
                    let _ = io::stderr().flush();
                    printed_progress = false;
                }
                let _ = io::stderr().write_all(err.as_bytes());
                let _ = io::stderr().flush();
            }
            if reply.done {
                if printed_progress && is_tty {
                    let _ = writeln!(io::stderr());
                }
                return Ok(if sent_cancel && reply.status == 0 {
                    130
                } else {
                    reply.status
                });
            }
        }

        let flags = if wait_cancellable { MSG_DONTWAIT } else { 0 };
        match stream.recv(&mut chunk, flags) {
            Ok(0) => {
                if printed_progress && is_tty {
                    let _ = writeln!(io::stderr());
                }
                if sent_cancel {
                    return Ok(130);
                }
                return Err("desktop action socket closed without completion reply".into());
            }
            Ok(n) => {
                if buf.len() + n > MAX_LINE_BYTES {
                    return Err("desktop action response exceeded frame limit".into());
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            Err(Errno::EAGAIN | Errno::EINTR) => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(format!("desktop action read error: {}", e.text())),
        }
    }
}

fn validate_device_name(raw: &str, prefix: &str) -> Result<String, String> {
    let trimmed = raw
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix('/'))
        .unwrap_or(raw);
    if trimmed.is_empty()
        || trimmed == "."
        || trimmed == ".."
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains('\0')
    {
        return Err(format!("invalid device name: {raw}"));
    }
    Ok(trimmed.to_owned())
}

/// Dispatch one of `open`, `vim`, `man`, `present`, `stream`, `upload`.
pub fn run(name: &str, args: &[String]) -> i32 {
    let mut full = Vec::with_capacity(args.len() + 1);
    full.push(name.to_owned());
    full.extend_from_slice(args);
    if cli::wants_help(&full)
        && let Some(help) = cli::help(name)
    {
        println!("{help}");
        return 0;
    }

    let cwd = current_cwd();
    let home = current_home();

    match name {
        "open" => {
            let parsed = match cli::parse::<files::Open>(args) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            };
            let path = resolve_abs_path(&parsed.file, &cwd, &home);
            let is_remote_device =
                path.starts_with("/dev/present/") || path.starts_with("/dev/snd/");
            if !is_remote_device {
                match std::fs::metadata(Path::new(&path)) {
                    Ok(meta) if meta.is_dir() => {
                        eprintln!("This is a directory; use cd");
                        return 1;
                    }
                    Ok(_) => {}
                    Err(err) => {
                        eprintln!("open: {}: {err}", parsed.file);
                        return 1;
                    }
                }
            }
            match execute_desktop_action(&DesktopActionRequest::Open { path }, false) {
                Ok(status) => status,
                Err(err) => {
                    eprintln!("open: {err}");
                    1
                }
            }
        }
        "vim" => {
            let parsed = match cli::parse::<files::Vim>(args) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            };
            let path = resolve_abs_path(&parsed.file, &cwd, &home);
            if let Ok(meta) = std::fs::metadata(Path::new(&path))
                && meta.is_dir()
            {
                eprintln!("vim: {}: Is a directory", parsed.file);
                return 1;
            }
            match execute_desktop_action(&DesktopActionRequest::Vim { path }, true) {
                Ok(status) => status,
                Err(err) => {
                    eprintln!("vim: {err}");
                    1
                }
            }
        }
        "man" => {
            let parsed = match cli::parse::<terminal::Man>(args) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            };
            let content = match &parsed.command {
                Some(cmd) => match cli::page(cmd) {
                    Some(page) => page,
                    None => {
                        eprintln!("man: no manual entry for {cmd}");
                        return 1;
                    }
                },
                None => cli::index(),
            };
            if !stdout_is_tty() {
                println!("{content}");
                return 0;
            }
            match execute_desktop_action(
                &DesktopActionRequest::Man {
                    command: parsed.command,
                },
                false,
            ) {
                Ok(status) => status,
                Err(_) => {
                    // Graceful fallback to terminal stdout when no GUI desktop bridge is listening.
                    println!("{content}");
                    0
                }
            }
        }
        "present" => {
            let parsed = match cli::parse::<files::Present>(args) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            };
            let stop = match parsed.stop.as_deref() {
                Some(s) => match validate_device_name(s, "/dev/present") {
                    Ok(clean) => Some(clean),
                    Err(err) => {
                        eprintln!("present: {err}");
                        return 2;
                    }
                },
                None => None,
            };
            let name = match parsed.name.as_deref() {
                Some(n) => match validate_device_name(n, "/dev/present") {
                    Ok(clean) => Some(clean),
                    Err(err) => {
                        eprintln!("present: {err}");
                        return 2;
                    }
                },
                None => None,
            };
            let path = parsed
                .file
                .as_deref()
                .map(|f| resolve_abs_path(f, &cwd, &home));
            match execute_desktop_action(&DesktopActionRequest::Present { path, name, stop }, false)
            {
                Ok(status) => status,
                Err(err) => {
                    eprintln!("present: {err}");
                    1
                }
            }
        }
        "stream" => {
            let parsed = match cli::parse::<files::Stream>(args) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            };
            let path = match parsed.file.as_deref() {
                Some(file) => {
                    let abs = resolve_abs_path(file, &cwd, &home);
                    let lower = abs.to_lowercase();
                    if !lower.ends_with(".weba") && !lower.ends_with(".webm") {
                        eprintln!(
                            "stream: {file}: browsers record Opus in WebM; name the recording NAME.weba"
                        );
                        return 1;
                    }
                    Some(abs)
                }
                None => None,
            };
            let name = match parsed.name.as_deref() {
                Some(n) => match validate_device_name(n, "/dev/snd") {
                    Ok(clean) => Some(clean),
                    Err(err) => {
                        eprintln!("stream: {err}");
                        return 2;
                    }
                },
                None => None,
            };
            let acl = (!parsed.modify.is_empty()).then(|| parsed.modify.join(","));
            match execute_desktop_action(&DesktopActionRequest::Stream { path, name, acl }, true) {
                Ok(status) => status,
                Err(err) => {
                    eprintln!("stream: {err}");
                    1
                }
            }
        }
        "upload" => {
            let parsed = match cli::parse::<files::Upload>(args) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{e}");
                    return 2;
                }
            };
            let dir = resolve_abs_path(parsed.dir.as_deref().unwrap_or("."), &cwd, &home);
            match execute_desktop_action(&DesktopActionRequest::Upload { dir }, true) {
                Ok(status) => status,
                Err(err) => {
                    eprintln!("upload: {err}");
                    1
                }
            }
        }
        _ => {
            eprintln!("utilities: {name}: unsupported desktop action");
            127
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_relative_and_tilde_paths() {
        assert_eq!(
            resolve_abs_path("notes.md", "/guest", "/guest"),
            "/guest/notes.md"
        );
        assert_eq!(
            resolve_abs_path("../shared/a.txt", "/guest/docs", "/guest"),
            "/guest/shared/a.txt"
        );
        assert_eq!(
            resolve_abs_path("~/photos", "/tmp", "/home/alice"),
            "/home/alice/photos"
        );
        assert_eq!(
            resolve_abs_path("/etc/passwd", "/guest", "/guest"),
            "/etc/passwd"
        );
        assert_eq!(socket_path(1000), "/run/user/1000/desktop-actions.sock");
    }

    #[test]
    fn desktop_action_protocol_round_trips() {
        let req = DesktopActionRequest::Vim {
            path: "/guest/notes.md".into(),
        };
        let encoded = serde_json::to_string(&req).unwrap();
        assert_eq!(encoded, r#"{"op":"vim","path":"/guest/notes.md"}"#);
        let decoded: DesktopActionRequest = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, req);

        let reply: DesktopActionReply =
            serde_json::from_str(r#"{"done":true,"status":0,"stdout":"ok\n"}"#).unwrap();
        assert!(reply.done);
        assert_eq!(reply.status, 0);
        assert_eq!(reply.stdout.as_deref(), Some("ok\n"));
    }

    #[test]
    fn device_name_validation_rejects_traversal() {
        assert_eq!(
            validate_device_name("demo", "/dev/present").unwrap(),
            "demo"
        );
        assert_eq!(
            validate_device_name("/dev/present/demo", "/dev/present").unwrap(),
            "demo"
        );
        assert!(validate_device_name("../../home/user/a", "/dev/present").is_err());
        assert!(validate_device_name("..", "/dev/present").is_err());
        assert!(validate_device_name("a/b", "/dev/snd").is_err());
        assert!(validate_device_name("", "/dev/snd").is_err());
    }
}
