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
    open_at(abi::OS_FD_CWD as u32, path, flags)
}
fn open_at(dir: u32, path: &str, flags: u32) -> Result<File> {
    let o: abi::Opened = syscall(Call::OpenAt {
        dirfd: dir.into(),
        path: path.into(),
        flags: flags | abi::O_NOFOLLOW | SOCK_CLOEXEC,
        mode: 0,
    })?;
    Ok(owned(o.fd))
}
struct BundleRead {
    file: File,
    spec: SurfaceSpec,
    deadline: u64,
    size: Option<usize>,
    bytes: Vec<u8>,
}
impl BundleRead {
    fn begin(spec: SurfaceSpec, received: Option<File>, directory: &File) -> Result<Self> {
        let file = if let Some(fd) = received {
            fd
        } else {
            let SurfaceKind::Document(src) = &spec.kind else {
                return Err(Errno::EINVAL);
            };
            let tail = src
                .bundle_path
                .strip_prefix("/usr/share/gui/")
                .ok_or(Errno::EACCES)?;
            if tail.len() > 4096 {
                return Err(Errno::E2BIG);
            }
            let mut components = tail.split('/').peekable();
            let mut dir = None;
            loop {
                let name = components.next().ok_or(Errno::EACCES)?;
                if matches!(name, "" | "." | "..") {
                    return Err(Errno::EACCES);
                }
                let parent = dir.as_ref().unwrap_or(directory).as_raw_fd() as u32;
                if components.peek().is_none() {
                    break open_at(parent, name, abi::O_RDONLY | SOCK_NONBLOCK)?;
                }
                dir = Some(open_at(parent, name, abi::O_RDONLY | abi::O_DIRECTORY)?);
            }
        };
        Ok(Self {
            file,
            spec,
            deadline: now_ms().saturating_add(5000),
            size: None,
            bytes: vec![],
        })
    }
    fn step(&mut self, display: &File) -> Result<bool> {
        if now_ms() >= self.deadline {
            return Err(Errno::ETIMEDOUT);
        }
        let fd = self.file.as_raw_fd() as u32;
        if self.size.is_none() {
            let size = ioctl::<usize>(display, ioc::CHECK_BUNDLE, fd)?;
            if size > MAX_BUNDLE {
                return Err(Errno::E2BIG);
            }
            self.size = Some(size);
        }
        let chunk: abi::Bytes = ioctl(display, ioc::READ_BUNDLE, (fd, self.bytes.len()))?;
        if self.bytes.len() + chunk.len() > self.size.unwrap() {
            return Err(Errno::E2BIG);
        }
        self.bytes.extend_from_slice(&chunk);
        if chunk.is_empty() && Some(self.bytes.len()) != self.size {
            return Err(Errno::EIO);
        }
        Ok(Some(self.bytes.len()) == self.size)
    }
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
    closing: bool,
    bundle: Option<BundleRead>,
    input: Vec<u8>,
    received: Option<File>,
    out: Outbox,
}
#[derive(Default)]
struct Outbox {
    messages: VecDeque<Message>,
    queued: usize,
}
impl Outbox {
    fn queue(&mut self, event: &ClientEvent, fd: Option<File>) -> Result<()> {
        let bytes = frame(event)?;
        if self.queued + bytes.len() > 2 * MAX_FRAME || self.messages.len() >= 256 {
            return Err(Errno::ENOBUFS);
        }
        self.queued += bytes.len();
        self.messages.push_back(Message {
            bytes,
            offset: 0,
            fd,
        });
        Ok(())
    }
}
impl Client {
    fn flush(&mut self) -> Result<()> {
        while let Some(m) = self.out.messages.front_mut() {
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
                    self.out.queued -= n;
                    if m.offset == m.bytes.len() {
                        self.out.messages.pop_front();
                    }
                }
                Err(Errno::ECANCELED) if m.fd.is_some() && m.offset == 0 => {
                    self.out.queued -= m.bytes.len();
                    m.fd.take();
                    m.bytes = frame(&ClientEvent::Error {
                        errno: Errno::ECANCELED,
                    })?;
                    self.out.queued += m.bytes.len();
                }
                Err(Errno::EAGAIN) => break,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
    fn reply(&mut self, result: Result<ClientEvent>, display: &File) -> Result<()> {
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
            Ok(event) => event,
            Err(errno) => ClientEvent::Error { errno },
        };
        self.out.queue(&response, None)
    }
    fn service(
        &mut self,
        core: &mut CompositorCore,
        display: &File,
        directory: &File,
    ) -> Result<()> {
        self.flush()?;
        if self.closing {
            return if self.out.messages.is_empty() {
                Err(Errno::EPIPE)
            } else {
                Ok(())
            };
        }
        if let Some(read) = self.bundle.as_mut() {
            let result = match read.step(display) {
                Ok(false) | Err(Errno::EAGAIN) => return Ok(()),
                Ok(true) => {
                    let load = self.bundle.take().unwrap();
                    core.request(
                        self.peer,
                        ClientReq::CreateSurface { spec: load.spec },
                        now_ms(),
                        |_| Ok(load.bytes),
                    )
                }
                Err(e) => {
                    self.bundle = None;
                    Err(e)
                }
            };
            self.reply(result, display)?;
        }
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
            Err(Errno::EAGAIN) => {}
            Err(e) => return Err(e),
        }
        while let Some(req) = take_frame::<ClientReq>(&mut self.input)? {
            let got = self.received.take();
            let hello = matches!(req, ClientReq::Hello { .. });
            if !self.hello || hello {
                let result =
                    core.request(self.peer, req, now_ms(), |_| Err(Errno::EPROTONOSUPPORT));
                self.hello = matches!(result, Ok(ClientEvent::Hello { .. }));
                self.closing = !self.hello;
                self.reply(result, display)?;
                if self.closing {
                    break;
                }
                continue;
            }
            if let ClientReq::CreateSurface {
                spec:
                    spec @ SurfaceSpec {
                        kind: SurfaceKind::Document(_),
                        ..
                    },
            } = req
            {
                match BundleRead::begin(spec, got, directory) {
                    Ok(read) => {
                        self.bundle = Some(read);
                        break;
                    }
                    Err(e) => self.reply(Err(e), display)?,
                }
            } else {
                let simulate = match &req {
                    ClientReq::SimulateLoss { surface_id } => Some(*surface_id),
                    _ => None,
                };
                let result = core.request(self.peer, req, now_ms(), |_| Err(Errno::EINVAL));
                if result.is_ok()
                    && let Some(id) = simulate
                {
                    ioctl::<()>(display, ioc::SIMULATE_LOSS, id)?;
                }
                self.reply(result, display)?;
            }
        }
        self.flush()
    }
}
fn deliver<C>(
    clients: &mut BTreeMap<u32, C>,
    core: &mut CompositorCore,
    pid: u32,
    send: impl FnOnce(&mut C) -> Result<()>,
) {
    if let Some(client) = clients.get_mut(&pid)
        && send(client).is_err()
    {
        clients.remove(&pid);
        core.client_gone(pid);
    }
}
fn run() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--help"] {
        println!("Usage: compositor [--shell-pid PID]");
        return Ok(());
    }
    os_posix::init_preopens().map_err(errno)?;
    let mut shell_pid = match args.as_slice() {
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
    let directory = open("/usr/share/gui", abi::O_RDONLY | abi::O_DIRECTORY)?;
    let dir = Path::new("/run/gui");
    std::fs::create_dir_all(dir).map_err(errno)?;
    let st = os_posix::stat(dir, false).map_err(errno)?;
    if st.mode & abi::S_IFMT != abi::S_IFDIR || st.uid != 0 || st.mode & 0o022 != 0 {
        return Err(Errno::EACCES);
    }
    os_posix::chmod(dir, 0o755).map_err(errno)?;
    // Recover named staging files if the previous seat died between open and unlink.
    for entry in std::fs::read_dir(dir).map_err(errno)? {
        let entry = entry.map_err(errno)?;
        if entry
            .file_name()
            .to_str()
            .and_then(|s| s.strip_prefix("pick-"))
            .is_some_and(|s| s.parse::<u64>().is_ok())
        {
            std::fs::remove_file(entry.path()).map_err(errno)?;
        }
    }
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
        for _ in 0..MAX_SURFACES {
            if clients.len() >= MAX_SURFACES {
                break;
            }
            match listener.accept_flags(SOCK_NONBLOCK | SOCK_CLOEXEC) {
                Ok((socket, peer)) => {
                    if clients.contains_key(&peer.pid) {
                        continue;
                    }
                    if Some(peer.pid) == shell_pid && peer.uid == 0 {
                        shell_pid.take();
                        core.designate_shell(peer)?;
                    }
                    clients.entry(peer.pid).or_insert(Client {
                        socket,
                        peer,
                        hello: false,
                        closing: false,
                        bundle: None,
                        input: vec![],
                        received: None,
                        out: Outbox::default(),
                    });
                }
                Err(Errno::EAGAIN | Errno::EINTR) => break,
                Err(e) => return Err(e),
            }
        }
        clients.retain(|&pid, c| {
            if c.service(&mut core, &display, &directory).is_err() {
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
                    let file = file.and_then(|f| {
                        std::fs::remove_file(path).map_err(errno)?;
                        ioctl::<()>(
                            &display,
                            ioc::ARM_PICK,
                            (surface_id, request_id, f.as_raw_fd()),
                        )?;
                        Ok(f)
                    });
                    if core.finish_picker(surface_id, request_id)
                        && let Some(&pid) = owners.get(&surface_id)
                    {
                        let (event, fd) = match file {
                            Ok(f) => (ClientEvent::Picked { surface_id }, Some(f)),
                            Err(_) => (
                                ClientEvent::Error {
                                    errno: Errno::ECANCELED,
                                },
                                None,
                            ),
                        };
                        deliver(&mut clients, &mut core, pid, |c| {
                            c.out.queue(&event, fd)?;
                            c.flush()?;
                            // Do not retain a selected descriptor behind a stalled receiver.
                            if !c.out.messages.is_empty() {
                                return Err(Errno::ENOBUFS);
                            }
                            Ok(())
                        });
                    }
                    core.output
                        .push(Output::Display(DisplayCmd::PickerDelivered { request_id }));
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
                    deliver(&mut clients, &mut core, pid, |c| c.out.queue(&event, None));
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn congested_picker_peer_does_not_take_down_the_seat() {
        let mut core = CompositorCore::default();
        let mut clients = BTreeMap::from([(21, Outbox::default()), (22, Outbox::default())]);
        let mut surfaces = vec![];
        for pid in clients.keys() {
            let peer = PeerCred {
                pid: *pid,
                uid: 1000,
                gid: 1000,
            };
            core.request(
                peer,
                ClientReq::Hello {
                    versions: vec![1],
                    required: vec!["pixel-input".into()],
                },
                0,
                |_| unreachable!(),
            )
            .unwrap();
            let reply = core
                .request(
                    peer,
                    ClientReq::CreateSurface {
                        spec: SurfaceSpec {
                            role: SurfaceRole::Window,
                            kind: SurfaceKind::Pixel,
                            title: "Window".into(),
                            rect: Rect {
                                x: 0,
                                y: 0,
                                width: 320,
                                height: 240,
                            },
                            min_size: Size {
                                width: 1,
                                height: 1,
                            },
                            max_size: None,
                            resizable: true,
                        },
                    },
                    0,
                    |_| unreachable!(),
                )
                .unwrap();
            let ClientEvent::Created { surface_id } = reply else {
                panic!("surface expected")
            };
            surfaces.push(surface_id);
        }
        for _ in 0..256 {
            clients
                .get_mut(&21)
                .unwrap()
                .queue(&ClientEvent::Ok, None)
                .unwrap();
        }
        deliver(&mut clients, &mut core, 21, |q| {
            q.queue(
                &ClientEvent::Picked {
                    surface_id: surfaces[0],
                },
                None,
            )
        });
        assert!(!clients.contains_key(&21));
        core.output.clear();
        core.input(
            InputEvent::Key {
                surface_id: surfaces[1],
                input: KeyInput {
                    key: "x".into(),
                    ..Default::default()
                },
                paste: false,
            },
            100,
        )
        .unwrap();
        assert!(matches!(
            &core.output[..],
            [Output::Client(22, ClientEvent::Key { .. })]
        ));
    }
}
