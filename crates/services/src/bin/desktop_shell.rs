//! Supervised per-user desktop shell process (`/usr/bin/desktop-shell`, `#61` `L5b`).
//!
//! Speaks standard framed JSON over `/run/gui/seat0.sock` (`AF_UNIX`), zero `gui_*` Wasm
//! imports or exports. Exits cleanly (`0`) on `SIGTERM`/`SIGINT` or compositor socket EOF so
//! `init --user` does not spin-restart on graphical session teardown, while crashing/SIGKILL
//! triggers `RestartPolicy::OnFailure` recovery automatically.
use abi::{
    Errno,
    gui::*,
    socket::{MSG_DONTWAIT, MSG_NOSIGNAL},
};
use os_posix::socket::{UnixDatagram, UnixStream};
use os_services::desktop_shell::{
    DesktopShellCore, LAYOUT_REL_PATH, load_layout_file, save_layout_file_atomic,
};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

static STOP: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "wasi")]
#[unsafe(no_mangle)]
pub extern "C" fn desktop_shell_signal(sig: u32) {
    if matches!(sig, 1 | 2 | 15) {
        STOP.store(true, Ordering::Release);
    }
}

fn send_req(stream: &UnixStream, req: &ClientReq) -> Result<(), Errno> {
    let bytes = frame(req)?;
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

fn recv_blocking(stream: &UnixStream, buf: &mut Vec<u8>) -> Result<ClientEvent, Errno> {
    let mut tmp = [0u8; 4096];
    loop {
        if let Some(ev) = take_frame(buf)? {
            return Ok(ev);
        }
        match stream.recv(&mut tmp, 0) {
            Ok(0) => return Err(Errno::EPIPE),
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
            Err(Errno::EINTR) => continue,
            Err(Errno::EAGAIN) => std::thread::sleep(Duration::from_millis(5)),
            Err(e) => return Err(e),
        }
    }
}

fn notify_ready() {
    if let Ok(path) = std::env::var("NOTIFY_SOCKET")
        && !path.is_empty()
        && let Ok(sock) = UnixDatagram::unbound()
    {
        let _ = sock.send_to(b"READY=1\n", &path);
    }
}

fn flush_layout(
    stream: &UnixStream,
    layout_path: &std::path::Path,
    core: &mut DesktopShellCore,
) -> Result<bool, Errno> {
    let Some(layout) = core.take_dirty_layout() else {
        return Ok(false);
    };
    let pending_legacy = core.take_pending_legacy_migration();
    match save_layout_file_atomic(layout_path, &layout) {
        Ok(()) => {
            if let Some(seat_id) = pending_legacy {
                match send_req(stream, &ClientReq::LegacyLayoutMigrated { seat_id }) {
                    Ok(()) => {}
                    Err(Errno::EPIPE | Errno::ECONNRESET) => return Ok(true),
                    Err(e) => return Err(e),
                }
            }
        }
        Err(err) => {
            eprintln!("desktop-shell: failed saving layout: {err}");
            core.restore_pending_save(pending_legacy);
        }
    }
    Ok(false)
}

fn run() -> Result<(), Errno> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--help"] {
        println!("Usage: desktop-shell");
        return Ok(());
    }
    os_posix::init_preopens().map_err(|_| Errno::EIO)?;

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
        let name = b"desktop_shell_signal";
        // SAFETY: static exported callback, scalar WASIX signal dispositions.
        unsafe {
            callback_signal(name.as_ptr(), name.len());
            for sig in [1, 2, 15] {
                if sigaction(sig, 2, 0, 0) < 0 {
                    return Err(Errno::EIO);
                }
            }
        }
    }

    let home = std::env::var("HOME")
        .ok()
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "/home/user".into());
    let layout_path = PathBuf::from(home).join(LAYOUT_REL_PATH);
    let outcome = load_layout_file(&layout_path);
    let mut core = DesktopShellCore::new(outcome);

    let mut attempts = 0;
    let stream = loop {
        if STOP.load(Ordering::Acquire) {
            return Ok(());
        }
        match UnixStream::connect(SOCKET) {
            Ok(s) => break s,
            Err(Errno::ENOENT | Errno::ECONNREFUSED) if attempts < 250 => {
                attempts += 1;
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(e),
        }
    };

    let mut rx_buf = Vec::new();
    send_req(
        &stream,
        &ClientReq::Hello {
            versions: vec![1],
            required: vec![],
        },
    )?;
    if !matches!(
        recv_blocking(&stream, &mut rx_buf)?,
        ClientEvent::Hello { version: 1 }
    ) {
        return Err(Errno::EPROTONOSUPPORT);
    }

    let startup = core.startup_requests();
    for req in &startup {
        send_req(&stream, req)?;
        loop {
            match recv_blocking(&stream, &mut rx_buf)? {
                ClientEvent::Created { .. } | ClientEvent::Ok => break,
                ClientEvent::Error { errno } => return Err(errno),
                ev => {
                    for follow in core.handle_event(ev) {
                        send_req(&stream, &follow)?;
                    }
                    if flush_layout(&stream, &layout_path, &mut core)? {
                        return Ok(());
                    }
                }
            }
        }
    }

    notify_ready();
    let _ = stream.set_nonblocking(true);

    let mut tmp = [0u8; 8192];
    while !STOP.load(Ordering::Acquire) {
        let mut compositor_closed = false;
        loop {
            match stream.recv(&mut tmp, MSG_DONTWAIT) {
                Ok(0) => {
                    compositor_closed = true;
                    break;
                }
                Ok(n) => {
                    rx_buf.extend_from_slice(&tmp[..n]);
                }
                Err(Errno::EAGAIN | Errno::EINTR) => break,
                Err(Errno::EPIPE | Errno::ECONNRESET) => {
                    compositor_closed = true;
                    break;
                }
                Err(e) => return Err(e),
            }
        }

        while let Some(ev) = take_frame::<ClientEvent>(&mut rx_buf)? {
            for req in core.handle_event(ev) {
                match send_req(&stream, &req) {
                    Ok(()) => {}
                    Err(Errno::EPIPE | Errno::ECONNRESET) => {
                        compositor_closed = true;
                        break;
                    }
                    Err(e) => return Err(e),
                }
            }
            if compositor_closed {
                break;
            }
        }

        if flush_layout(&stream, &layout_path, &mut core)? {
            compositor_closed = true;
        }

        if compositor_closed {
            // Compositor ended the graphical session: exit cleanly (code 0) so `init --user`
            // does not spin-restart while the graphical target is down.
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(8));
    }

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("desktop-shell: {e:?} ({})", e.text());
        std::process::exit(1);
    }
}
