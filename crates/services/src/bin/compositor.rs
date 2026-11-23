//! Reference seat server. Every connection has a bounded stream decoder and a
//! kernel-authenticated peer. Slow or malformed clients cannot stall the seat.
use abi::{
    Call, Errno,
    gui::*,
    gui_ioctl as ioc,
    socket::{
        MSG_CMSG_CLOEXEC, MSG_CTRUNC, MSG_DONTWAIT, MSG_NOSIGNAL, PeerCred, SOCK_CLOEXEC,
        SOCK_NONBLOCK,
    },
};
use os_posix::socket::{UnixDatagram, UnixListener, UnixStream};
use os_services::{
    compositor::{CompositorCore, Output},
    exportd::now_ms,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
#[cfg(not(target_os = "wasi"))]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(target_os = "wasi")]
use std::os::wasi::io::{AsRawFd, FromRawFd};
use std::{
    collections::{BTreeMap, VecDeque},
    fs::File,
    io::Write,
    path::Path,
    time::Duration,
};
type Result<T> = std::result::Result<T, Errno>;
fn errno(e: std::io::Error) -> Errno {
    os_posix::errno_of(&e).unwrap_or(Errno::EIO)
}
fn syscall<T: DeserializeOwned>(call: Call) -> Result<T> {
    let v = os_posix::batch(&[call])
        .map_err(errno)?
        .results
        .pop()
        .ok_or(Errno::EIO)?
        .into_result()
        .map_err(|e| e.errno)?;
    serde_json::from_value(v).map_err(|_| Errno::EIO)
}
fn ioctl<T: DeserializeOwned>(file: &File, request: u32, arg: impl Serialize) -> Result<T> {
    syscall(Call::Ioctl {
        fd: (file.as_raw_fd() as u32).into(),
        request,
        arg: json!(arg),
    })
}
fn owned(fd: u32) -> File {
    // SAFETY: callers relinquish a newly opened or SCM_RIGHTS-installed fd.
    unsafe { File::from_raw_fd(fd as _) }
}
fn open(path: &str, flags: u32) -> Result<File> {
    let o: abi::Opened = syscall(Call::OpenAt {
        dirfd: (abi::OS_FD_CWD as u32).into(),
        path: path.into(),
        flags: flags | abi::O_NOFOLLOW | SOCK_CLOEXEC,
        mode: 0,
    })?;
    Ok(owned(o.fd))
}
fn bundle(display: &File, src: &DocumentSource, received: Option<File>) -> Result<Vec<u8>> {
    let file = if let Some(fd) = received {
        fd
    } else {
        // Dereference path sources only inside the immutable system GUI tree.
        // Other bundles must arrive as capabilities opened by the client.
        let tail = src
            .bundle_path
            .strip_prefix("/usr/share/gui/")
            .ok_or(Errno::EACCES)?;
        if tail.split('/').any(|s| matches!(s, "" | "." | "..")) {
            return Err(Errno::EACCES);
        }
        open(&src.bundle_path, abi::O_RDONLY)?
    };
    ioctl::<()>(display, ioc::CHECK_BUNDLE, file.as_raw_fd())?;
    let mut raw = vec![];
    // A passed open file description can already have a nonzero offset.
    // Positional reads hash the whole bundle and preserve the sender's cursor.
    loop {
        let chunk: abi::Data = syscall(Call::Pread {
            fd: Some((file.as_raw_fd() as u32).into()),
            path: None,
            offset: raw.len() as u64,
            count: 16384,
        })?;
        if chunk.data.is_empty() {
            break;
        }
        if chunk.size > MAX_BUNDLE as u64 || raw.len() + chunk.data.len() > MAX_BUNDLE {
            return Err(Errno::E2BIG);
        }
        raw.extend_from_slice(&chunk.data);
    }
    Ok(raw)
}
struct Message {
    bytes: Vec<u8>,
    offset: usize,
    fd: Option<File>,
}
struct Client {
    socket: UnixStream,
    peer: PeerCred,
    hello: bool,
    input: Vec<u8>,
    received: Option<File>,
    out: VecDeque<Message>,
    queued: usize,
}
impl Client {
    fn queue(&mut self, event: &ClientEvent, fd: Option<File>) -> Result<()> {
        let bytes = frame(event)?;
        if self.queued + bytes.len() > 2 * MAX_FRAME || self.out.len() >= 256 {
            return Err(Errno::ENOBUFS);
        }
        self.queued += bytes.len();
        self.out.push_back(Message {
            bytes,
            offset: 0,
            fd,
        });
        Ok(())
    }
    fn flush(&mut self) -> Result<()> {
        while let Some(m) = self.out.front_mut() {
            let rights: Vec<_> = m.fd.iter().map(|f| f.as_raw_fd() as u32).collect();
            match self.socket.send_with_fds(
                &m.bytes[m.offset..],
                &rights,
                MSG_NOSIGNAL | MSG_DONTWAIT,
            ) {
                Ok(0) => return Err(Errno::EPIPE),
                Ok(n) => {
                    m.fd.take();
                    m.offset += n;
                    self.queued -= n;
                    if m.offset == m.bytes.len() {
                        self.out.pop_front();
                    }
                }
                Err(Errno::EAGAIN) => break,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
    fn service(&mut self, core: &mut CompositorCore, display: &File) -> Result<()> {
        self.flush()?;
        let mut buf = [0; 8192];
        match self
            .socket
            .recv_with_fds(&mut buf, 1, MSG_CMSG_CLOEXEC | MSG_DONTWAIT)
        {
            Ok((n, fds, flags)) => {
                let mut fds = fds.into_iter().map(owned);
                let fd = fds.next();
                if n == 0 {
                    return Err(Errno::EPIPE);
                }
                if flags & MSG_CTRUNC != 0
                    || fd.is_some() && (!self.input.is_empty() || self.received.is_some())
                {
                    return Err(Errno::EINVAL);
                }
                if fd.is_some() {
                    self.received = fd;
                }
                self.input.extend_from_slice(&buf[..n]);
            }
            Err(Errno::EAGAIN) => return Ok(()),
            Err(e) => return Err(e),
        }
        while let Some(req) = take_frame::<ClientReq>(&mut self.input)? {
            let got = self.received.take();
            let simulate = if let ClientReq::SimulateLoss { surface_id } = req {
                Some(surface_id)
            } else {
                None
            };
            let result = if !self.hello && !matches!(req, ClientReq::Hello { .. }) {
                Err(Errno::EPROTONOSUPPORT)
            } else {
                core.request(self.peer, req, now_ms(), |src| bundle(display, src, got))
            };
            let response = match result {
                Ok(ClientEvent::Created { surface_id }) => {
                    ioctl::<()>(
                        display,
                        ioc::BIND_SURFACE,
                        BindSurface {
                            surface_id,
                            socket_fd: self.socket.as_raw_fd(),
                        },
                    )?;
                    ClientEvent::Created { surface_id }
                }
                Ok(ClientEvent::Hello { version }) => {
                    self.hello = true;
                    ClientEvent::Hello { version }
                }
                Ok(reply) => {
                    if let Some(id) = simulate {
                        ioctl::<()>(display, ioc::SIMULATE_LOSS, id)?;
                    }
                    reply
                }
                Err(errno) => ClientEvent::Error { errno },
            };
            self.queue(&response, None)?;
        }
        self.flush()
    }
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--help"] {
        println!("Usage: compositor [--shell-pid PID]");
        return Ok(());
    }
    os_posix::init_preopens().map_err(errno)?;
    let shell_pid = match args.as_slice() {
        [] => None,
        [flag, pid] if flag == "--shell-pid" => {
            Some(pid.parse::<u32>().map_err(|_| Errno::EINVAL)?)
        }
        _ => return Err(Errno::EINVAL),
    };
    let mut display = open("/dev/display", abi::O_WRONLY)?;
    let input = open("/dev/input", abi::O_RDONLY)?;
    let info: Value = ioctl(&display, ioc::INFO, json!({"versions":[1]}))?;
    let mut core = CompositorCore::new(info["epoch"].as_u64().ok_or(Errno::EIO)? * IDS_PER_SEAT);
    let dir = Path::new("/run/gui");
    std::fs::create_dir_all(dir).map_err(errno)?;
    let st = os_posix::stat(dir, false).map_err(errno)?;
    if st.mode & abi::S_IFMT != abi::S_IFDIR || st.uid != 0 || st.mode & 0o022 != 0 {
        return Err(Errno::EACCES);
    }
    os_posix::chmod(dir, 0o755).map_err(errno)?;
    // Only the exclusive seat owner can reach this point. Refuse unrelated nodes.
    if let Ok(st) = os_posix::stat(Path::new(SOCKET), false) {
        if st.uid != 0 || st.mode & abi::S_IFMT != abi::S_IFSOCK {
            return Err(Errno::EACCES);
        }
        std::fs::remove_file(SOCKET).map_err(errno)?;
    }
    let listener = UnixListener::bind_with_mode(SOCKET, 0o666)?;
    os_posix::chmod(Path::new(SOCKET), 0o666).map_err(errno)?;
    listener.set_nonblocking(true)?;
    if let Ok(path) = std::env::var("NOTIFY_SOCKET")
        && !path.is_empty()
    {
        UnixDatagram::unbound()?.send_to(b"READY=1\n", &path)?;
    }
    ioctl::<()>(
        &display,
        ioc::DISPLAY_CMD,
        DisplayCmd::SetDragMode {
            mode: DragMode::LocalLease,
        },
    )?;
    let mut clients: BTreeMap<u32, Client> = BTreeMap::new();
    let mut owners = BTreeMap::new();
    loop {
        while clients.len() < MAX_SURFACES {
            match listener.accept_flags(SOCK_NONBLOCK | SOCK_CLOEXEC) {
                Ok((socket, peer)) => {
                    if Some(peer.pid) == shell_pid && peer.uid == 0 {
                        core.designate_shell(peer)?;
                    }
                    clients.entry(peer.pid).or_insert(Client {
                        socket,
                        peer,
                        hello: false,
                        input: vec![],
                        received: None,
                        out: VecDeque::new(),
                        queued: 0,
                    });
                }
                Err(Errno::EAGAIN | Errno::EINTR) => break,
                Err(e) => return Err(e),
            }
        }
        clients.retain(|&pid, c| {
            if c.service(&mut core, &display).is_err() {
                core.client_gone(pid);
                false
            } else {
                true
            }
        });
        for _ in 0..64 {
            match ioctl::<SeatEvent>(&input, ioc::NEXT_EVENT, ()) {
                Ok(SeatEvent::Input(InputEvent::PickerResult {
                    surface_id,
                    request_id,
                    chosen: true,
                })) => {
                    let path = format!("/run/gui/pick-{request_id}");
                    let file = open(&path, abi::O_RDONLY);
                    let _ = std::fs::remove_file(path);
                    if core.finish_picker(surface_id, request_id)
                        && let Some(c) =
                            owners.get(&surface_id).and_then(|pid| clients.get_mut(pid))
                    {
                        match file {
                            Ok(f) => c.queue(&ClientEvent::Picked { surface_id }, Some(f))?,
                            Err(errno) => c.queue(&ClientEvent::Error { errno }, None)?,
                        };
                    }
                }
                Ok(SeatEvent::Input(e)) => {
                    let _ = core.input(e, now_ms());
                }
                Ok(SeatEvent::Display(e)) => {
                    let _ = core.device(e);
                }
                Ok(SeatEvent::ClientGone { pid }) => {
                    clients.remove(&pid);
                    core.client_gone(pid);
                }
                Err(Errno::EAGAIN) => break,
                Err(e) => return Err(e),
            }
        }
        core.expire(now_ms());
        for output in std::mem::take(&mut core.output) {
            match output {
                Output::Display(cmd) => {
                    match &cmd {
                        DisplayCmd::Map {
                            surface_id,
                            owner_pid,
                            ..
                        } => {
                            owners.insert(*surface_id, *owner_pid);
                        }
                        DisplayCmd::Unmap { surface_id } => {
                            owners.remove(surface_id);
                        }
                        _ => {}
                    }
                    let write = frame(&cmd)?
                        .chunks(32 * 1024)
                        .try_for_each(|chunk| display.write_all(chunk).map_err(errno));
                    if let Err(error) = write {
                        // A peer can exit between BIND_SURFACE and the last
                        // display write. Its dead binding cannot reset the seat.
                        let owner = match cmd {
                            DisplayCmd::Map { owner_pid, .. } => Some(owner_pid),
                            DisplayCmd::RecreatePixelCanvas { surface_id, .. } => {
                                owners.get(&surface_id).copied()
                            }
                            _ => None,
                        };
                        if let Some(pid) = owner
                            && matches!(error, Errno::ESTALE | Errno::EACCES)
                        {
                            clients.remove(&pid);
                            core.client_gone(pid);
                        } else {
                            return Err(error);
                        }
                    }
                }
                Output::Client(pid, event) => {
                    if let Some(c) = clients.get_mut(&pid)
                        && c.queue(&event, None).is_err()
                    {
                        clients.remove(&pid);
                        core.client_gone(pid);
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(4));
    }
}
fn main() {
    if let Err(e) = run() {
        eprintln!("compositor: {e:?}");
        std::process::exit(1);
    }
}
