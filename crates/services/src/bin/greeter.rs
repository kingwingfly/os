//! Supervised root-owned greeter / lock-screen process (`/usr/bin/greeter`, `#61` `L5b`).
//!
//! Speaks standard framed JSON over `/run/gui/seat0.sock` (`AF_UNIX`), zero `gui_*` Wasm
//! imports or exports. Claims a modal `Greeter` or `Lock` surface and stays resident until
//! dismissed or `SIGTERM`.
use abi::{
    Errno,
    gui::*,
    socket::{MSG_DONTWAIT, MSG_NOSIGNAL},
};
use os_posix::socket::{UnixDatagram, UnixStream};
use os_services::greeter::{GreeterAction, GreeterConfig};
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

static STOP: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "wasi")]
#[unsafe(no_mangle)]
pub extern "C" fn greeter_signal(sig: u32) {
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

fn run() -> Result<(), Errno> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let cfg = match GreeterConfig::parse_args(&args)? {
        GreeterAction::Help(usage) => {
            println!("{usage}");
            return Ok(());
        }
        GreeterAction::Run(cfg) => cfg,
    };
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
        let name = b"greeter_signal";
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

    send_req(
        &stream,
        &ClientReq::CreateSurface {
            spec: cfg.surface_spec(),
        },
    )?;
    let surface_id = match recv_blocking(&stream, &mut rx_buf)? {
        ClientEvent::Created { surface_id } => surface_id,
        ClientEvent::Error { errno } => return Err(errno),
        _ => return Err(Errno::EIO),
    };

    notify_ready();
    let _ = stream.set_nonblocking(true);

    let mut tmp = [0u8; 4096];
    while !STOP.load(Ordering::Acquire) {
        match stream.recv(&mut tmp, MSG_DONTWAIT) {
            Ok(0) => return Ok(()),
            Ok(n) => {
                rx_buf.extend_from_slice(&tmp[..n]);
                while let Some(ev) = take_frame::<ClientEvent>(&mut rx_buf)? {
                    if matches!(ev, ClientEvent::CloseRequested { .. }) {
                        let _ = send_req(&stream, &ClientReq::Destroy { surface_id });
                        return Ok(());
                    }
                }
            }
            Err(Errno::EAGAIN | Errno::EINTR) => {}
            Err(Errno::EPIPE | Errno::ECONNRESET) => return Ok(()),
            Err(e) => return Err(e),
        }
        std::thread::sleep(Duration::from_millis(16));
    }

    let _ = send_req(&stream, &ClientReq::Destroy { surface_id });
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("greeter: {e:?} ({})", e.text());
        std::process::exit(1);
    }
}
