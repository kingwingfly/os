//! Two ordinary AF_UNIX clients. The renderer and the toolkit can be replaced
//! independently of the compositor. The pixel renderer lives in this process.
use abi::{Errno, gui::*};
use os_posix::socket::UnixStream;
#[cfg(not(target_os = "wasi"))]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(target_os = "wasi")]
use std::os::wasi::io::{AsRawFd, FromRawFd};
use std::{cell::RefCell, time::Duration};
type Result<T> = std::result::Result<T, Errno>;
struct Client {
    socket: UnixStream,
    id: SurfaceId,
    buf: Vec<u8>,
    pixel: bool,
    simulate_loss: bool,
    received: std::collections::VecDeque<std::fs::File>,
}
thread_local! {static CLIENT:RefCell<Option<Client>>=const{RefCell::new(None)};}
#[cfg(target_os = "wasi")]
#[link(wasm_import_module = "os")]
unsafe extern "C" {
    fn gui_dispatch() -> !;
    fn gui_paint(surface: u64, generation: u32, color: u32);
    fn gui_resize(surface: u64, width: u32, height: u32);
}
fn send(socket: &UnixStream, req: &ClientReq) -> Result<()> {
    send_with_file(socket, req, None)
}
fn send_with_file(
    socket: &UnixStream,
    req: &ClientReq,
    file: Option<&std::fs::File>,
) -> Result<()> {
    let bytes = frame(req)?;
    let mut off = 0;
    let fd = file.map(|f| f.as_raw_fd() as u32);
    while off < bytes.len() {
        let rights = if off == 0 { fd.as_slice() } else { &[] };
        let n = socket.send_with_fds(&bytes[off..], rights, abi::socket::MSG_NOSIGNAL)?;
        if n == 0 {
            return Err(Errno::EPIPE);
        }
        off += n;
    }
    Ok(())
}
fn recv(
    socket: &UnixStream,
    buf: &mut Vec<u8>,
    flags: u32,
    rights: &mut std::collections::VecDeque<std::fs::File>,
) -> Result<ClientEvent> {
    loop {
        if let Some(e) = take_frame(buf)? {
            return Ok(e);
        }
        let mut chunk = [0; 4096];
        let (n, fds, truncated) =
            socket.recv_with_fds(&mut chunk, 1, flags | abi::socket::MSG_CMSG_CLOEXEC)?;
        for fd in fds {
            // SAFETY: recvmsg installed a new owned descriptor.
            rights.push_back(unsafe { std::fs::File::from_raw_fd(fd as _) });
        }
        if truncated & abi::socket::MSG_CTRUNC != 0 {
            return Err(Errno::EINVAL);
        }
        if n == 0 {
            return Err(Errno::EPIPE);
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}
fn reply(c: &Client, text: String) -> Result<()> {
    send(
        &c.socket,
        &ClientReq::DocumentReply {
            surface_id: c.id,
            text,
        },
    )
}
#[derive(serde::Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum DocumentAction {
    Edit { text: String },
    Copy { text: String },
    Drag { text: String },
    Paste,
    Pick,
    Notify,
}
fn tick(c: &mut Client) -> Result<bool> {
    loop {
        match recv(
            &c.socket,
            &mut c.buf,
            abi::socket::MSG_DONTWAIT,
            &mut c.received,
        ) {
            Ok(ClientEvent::CloseRequested { .. }) => return Ok(false),
            Ok(ClientEvent::DocumentMessage { text, .. }) => {
                let Ok(action) = serde_json::from_str(&text) else {
                    continue;
                };
                let req = match action {
                    DocumentAction::Edit { text } => ClientReq::DocumentReply {
                        surface_id: c.id,
                        text: format!("{} characters", text.chars().count()),
                    },
                    DocumentAction::Copy { text } => ClientReq::ClipboardWrite {
                        surface_id: c.id,
                        item: TransferItem {
                            mime: "text/plain".into(),
                            data: text.into_bytes().into(),
                        },
                    },
                    DocumentAction::Paste => ClientReq::ClipboardRead { surface_id: c.id },
                    DocumentAction::Drag { text } => ClientReq::DndStart {
                        surface_id: c.id,
                        items: vec![TransferItem {
                            mime: "text/plain".into(),
                            data: text.into_bytes().into(),
                        }],
                    },
                    DocumentAction::Pick => ClientReq::PickFile { surface_id: c.id },
                    DocumentAction::Notify => ClientReq::Notify {
                        surface_id: c.id,
                        title: "Document".into(),
                        body: "Note is open".into(),
                    },
                };
                send(&c.socket, &req)?;
            }
            Ok(ClientEvent::Clipboard { item }) => {
                reply(c, String::from_utf8_lossy(&item.data).into_owned())?
            }
            Ok(ClientEvent::DndOffer { mimes, .. }) if !c.pixel => {
                reply(c, format!("Offered {}", mimes.join(", ")))?;
            }
            Ok(ClientEvent::DndDrop { items, .. }) if !c.pixel => {
                if let Some(item) = items.iter().find(|i| i.mime == "text/plain") {
                    reply(
                        c,
                        String::from_utf8_lossy(&item.data)
                            .chars()
                            .take(1024)
                            .collect(),
                    )?;
                }
            }
            Ok(ClientEvent::Picked { .. }) => {
                let file = c.received.pop_front().ok_or(Errno::EBADF)?;
                reply(
                    c,
                    format!(
                        "Selected {} bytes",
                        file.metadata().map_err(|_| Errno::EIO)?.len()
                    ),
                )?;
            }
            Ok(ClientEvent::Notification { .. }) => reply(c, "Notification sent".into())?,
            Ok(ClientEvent::Error { errno }) if !c.pixel => reply(c, format!("{errno:?}"))?,
            #[cfg(target_os = "wasi")]
            Ok(ClientEvent::Configure {
                surface_id,
                width,
                height,
                ..
            }) if c.pixel => {
                // SAFETY: the renderer resolves the surface inside this owner's Worker.
                unsafe { gui_resize(surface_id, width, height) };
            }
            Ok(ClientEvent::SurfaceReady { generation, .. }) if c.pixel => {
                #[cfg(target_os = "wasi")]
                // SAFETY: scalar inputs address only this process's current canvas.
                unsafe {
                    gui_paint(c.id, generation, 0x297268);
                }
                send(
                    &c.socket,
                    &ClientReq::SetA11y {
                        surface_id: c.id,
                        a11y: A11y {
                            label: "Geometric color study".into(),
                            role_description: "Pixel artwork".into(),
                            live_announcement: format!("Rendered generation {generation}"),
                        },
                    },
                )?;
                if std::mem::take(&mut c.simulate_loss) {
                    send(&c.socket, &ClientReq::SimulateLoss { surface_id: c.id })?;
                }
            }
            Ok(_) => {}
            Err(Errno::EAGAIN) => return Ok(true),
            Err(e) => return Err(e),
        }
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn gui_client_tick() -> i32 {
    CLIENT.with_borrow_mut(|c| c.as_mut().is_some_and(|c| tick(c).unwrap_or(false)) as i32)
}
fn run(pixel: bool) -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|s| s == "--help") {
        println!(
            "Usage: gui-sample-{} [--request JSON [--fd PATH] | --sha256 DIGEST | --simulate-loss | --role lock|greeter]",
            if pixel { "pixel" } else { "doc" }
        );
        return Ok(());
    }
    os_posix::init_preopens().map_err(|_| Errno::EIO)?;
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
    let mut buf = vec![];
    let mut received = std::collections::VecDeque::new();
    send(
        &socket,
        &ClientReq::Hello {
            versions: vec![1],
            required: vec![],
        },
    )?;
    if !matches!(
        recv(&socket, &mut buf, 0, &mut received)?,
        ClientEvent::Hello { version: 1 }
    ) {
        return Err(Errno::EPROTONOSUPPORT);
    }
    if args.first().is_some_and(|s| s == "--request") {
        let req =
            serde_json::from_str(args.get(1).ok_or(Errno::EINVAL)?).map_err(|_| Errno::EINVAL)?;
        let file = match &args[2..] {
            [] => None,
            [option, path] if option == "--fd" => {
                use std::io::{Seek, SeekFrom};
                let mut file = std::fs::File::open(path)
                    .map_err(|e| os_posix::errno_of(&e).unwrap_or(Errno::EIO))?;
                // The receiver verifies all bytes independently of this offset.
                file.seek(SeekFrom::End(0)).map_err(|_| Errno::EIO)?;
                Some(file)
            }
            _ => return Err(Errno::EINVAL),
        };
        send_with_file(&socket, &req, file.as_ref())?;
        println!(
            "{}",
            serde_json::to_string(&recv(&socket, &mut buf, 0, &mut received)?).unwrap()
        );
        return Ok(());
    }
    let kind = if pixel {
        SurfaceKind::Pixel
    } else {
        let bytes = serde_json::to_vec(&DocumentBundle {
            html: String::new(),
            css: include_str!("../../../web/gui/samples/doc-view.css").into(),
            js: include_str!("../../../web/gui/samples/doc-view.js").into(),
        })
        .unwrap();
        let digest = if args.first().is_some_and(|s| s == "--sha256") {
            args.get(1).ok_or(Errno::EINVAL)?.clone()
        } else {
            sha256_hex(&bytes)
        };
        SurfaceKind::Document(DocumentSource {
            bundle_path: SAMPLE_BUNDLE.into(),
            expected_sha256: digest,
        })
    };
    let rect = if pixel {
        Rect {
            x: 432,
            y: 112,
            width: 320,
            height: 250,
        }
    } else {
        Rect {
            x: 28,
            y: 38,
            width: 375,
            height: 300,
        }
    };
    send(
        &socket,
        &ClientReq::CreateSurface {
            spec: SurfaceSpec {
                role: match args.as_slice() {
                    [option, role] if option == "--role" => match role.as_str() {
                        "lock" => SurfaceRole::Lock,
                        "greeter" => SurfaceRole::Greeter,
                        _ => return Err(Errno::EINVAL),
                    },
                    _ => SurfaceRole::Window,
                },
                kind,
                title: if pixel { "Pixel study" } else { "Document" }.into(),
                rect,
                min_size: Size {
                    width: 160,
                    height: 100,
                },
                max_size: None,
                resizable: true,
            },
        },
    )?;
    let id = match recv(&socket, &mut buf, 0, &mut received)? {
        ClientEvent::Created { surface_id } => surface_id,
        ClientEvent::Error { errno } => return Err(errno),
        _ => return Err(Errno::EIO),
    };
    if pixel {
        send(
            &socket,
            &ClientReq::SetA11y {
                surface_id: id,
                a11y: A11y {
                    label: "Geometric color study".into(),
                    role_description: "Pixel artwork".into(),
                    live_announcement: "Pixel surface mapped".into(),
                },
            },
        )?;
    }
    CLIENT.replace(Some(Client {
        socket,
        id,
        buf,
        pixel,
        received,
        simulate_loss: args.iter().any(|s| s == "--simulate-loss"),
    }));
    #[cfg(target_os = "wasi")]
    // SAFETY: non-returning event-loop handoff after installing thread-local client state.
    unsafe {
        gui_dispatch()
    }
    #[cfg(not(target_os = "wasi"))]
    {
        while gui_client_tick() != 0 {
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }
}
pub fn sample(pixel: bool) {
    if let Err(e) = run(pixel) {
        eprintln!("GUI client: {e:?}");
        std::process::exit(1);
    }
}
