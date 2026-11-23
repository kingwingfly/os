//! Socket-activated host operations use the peer's kernel socket reference, including
//! when the system daemon serves a user in a different namespace. No UID from JSON is used.
use abi::mount_ctl::*;
use abi::socket::{MSG_DONTWAIT, MSG_NOSIGNAL, PeerCred, SOCK_CLOEXEC, SOCK_NONBLOCK};
use abi::{Call, Creds, Errno, Error};
use os_posix::socket::{UnixDatagram, UnixListener, UnixStream};
use os_services::mountd::{MountBackend, error_response, handle_request};
use serde_json::Value;
use std::path::Path;
use std::time::{Duration, Instant};

struct KernelBackend<'a> {
    client: &'a UnixStream,
}

impl MountBackend for KernelBackend<'_> {
    fn call(&mut self, request: MountBackendRequest) -> Result<Value, Errno> {
        let control = UnixStream::connect(MOUNT_HOST_SOCK)?;
        if control.peer_cred()?.uid != 0 {
            return Err(Errno::EACCES);
        }
        let frame = encode_frame(&request).map_err(|e| e.errno)?;
        let mut rights = Some(self.client.as_raw_fd());
        write_frame(&frame, |bytes| {
            let n = control.send_with_fds(bytes, rights.as_slice(), MSG_NOSIGNAL)?;
            if n != 0 {
                rights = None;
            }
            Ok(n)
        })
        .map_err(|e| e.errno)?;
        let reply = read_frame(|buf| control.recv(buf, 0)).map_err(|e| e.errno)?;
        decode_frame::<Result<Value, Errno>>(&reply).map_err(|e| e.errno)?
    }
}

struct Client {
    socket: UnixStream,
    peer: PeerCred,
    deadline: Instant,
    input: Vec<u8>,
    output: Option<Vec<u8>>,
    sent: usize,
}

impl Client {
    fn service(&mut self, scope: Option<u32>) -> bool {
        if Instant::now() >= self.deadline {
            return false;
        }
        if self.output.is_none() {
            let mut buf = [0; 4096];
            let reply = match self.socket.recv(&mut buf, MSG_DONTWAIT) {
                Err(Errno::EAGAIN | Errno::EINTR) => return true,
                Ok(0) | Err(_) => return false,
                Ok(n) if n > MAX_FRAME_BYTES - self.input.len() => {
                    error_response(Errno::E2BIG.into())
                }
                Ok(n) => {
                    self.input.extend_from_slice(&buf[..n]);
                    if !buf[..n].contains(&b'\n') {
                        if self.input.len() < MAX_FRAME_BYTES {
                            return true;
                        }
                        error_response(Errno::E2BIG.into())
                    } else {
                        match decode_frame(&self.input) {
                            Err(e) => error_response(e),
                            Ok(req) => handle_request(
                                &mut KernelBackend {
                                    client: &self.socket,
                                },
                                scope,
                                self.peer,
                                req,
                            ),
                        }
                    }
                }
            };
            self.output = encode_frame(&reply)
                .or_else(|e| encode_frame(&error_response(e)))
                .ok();
        }
        let Some(frame) = &self.output else {
            return false;
        };
        match self
            .socket
            .send(&frame[self.sent..], MSG_DONTWAIT | MSG_NOSIGNAL)
        {
            Ok(0) => false,
            Ok(n) => {
                self.sent += n;
                self.sent < frame.len()
            }
            Err(Errno::EAGAIN | Errno::EINTR) => true,
            Err(_) => false,
        }
    }
}

fn io_errno(e: std::io::Error) -> Error {
    Error::because(os_posix::errno_of(&e).unwrap_or(Errno::EIO), e.to_string())
}

fn run() -> Result<(), Error> {
    os_posix::init_preopens().map_err(io_errno)?;
    let creds: Creds = serde_json::from_value(
        os_posix::batch(&[Call::Getcreds])
            .map_err(io_errno)?
            .results
            .remove(0)
            .into_result()?,
    )
    .map_err(|_| Errno::EIO)?;
    let args: Vec<_> = std::env::args().skip(1).collect();
    let scope = match args.as_slice() {
        [] if creds.uid == 0 => None,
        [] => return Err(Errno::EPERM.into()),
        [arg] if arg == "--user" => Some(creds.uid),
        [arg, uid] if arg == "--user" && uid.parse::<u32>().ok() == Some(creds.uid) => {
            Some(creds.uid)
        }
        _ => {
            return Err(Error::because(
                Errno::EINVAL,
                "usage: mountd [--user [own-uid]]",
            ));
        }
    };
    let path = scope
        .map(user_mount_sock)
        .unwrap_or_else(|| SYSTEM_MOUNT_SOCK.into());
    let dir = Path::new(&path).parent().unwrap();
    let dir_mode = if scope.is_some() { 0o700 } else { 0o755 };
    match os_posix::mkdir(dir, dir_mode) {
        Ok(()) => (),
        Err(e) if os_posix::errno_of(&e) == Some(Errno::EEXIST) => (),
        Err(e) => return Err(io_errno(e)),
    }
    let stat = os_posix::stat(dir, false).map_err(io_errno)?;
    if stat.uid != creds.uid || stat.mode & abi::S_IFMT != abi::S_IFDIR {
        return Err(Errno::EACCES.into());
    }
    os_posix::chmod(dir, dir_mode).map_err(io_errno)?;
    if let Ok(stat) = os_posix::stat(Path::new(&path), false) {
        if stat.mode & abi::S_IFMT != abi::S_IFSOCK || stat.uid != creds.uid {
            return Err(Errno::EADDRINUSE.into());
        }
        match UnixStream::connect(&path) {
            Err(Errno::ECONNREFUSED) => std::fs::remove_file(&path).map_err(io_errno)?,
            _ => return Err(Errno::EADDRINUSE.into()),
        }
    }
    let listener = UnixListener::bind(&path)?;
    os_posix::chmod(
        Path::new(&path),
        if scope.is_some() { 0o600 } else { 0o666 },
    )
    .map_err(io_errno)?;
    listener.set_nonblocking(true)?;
    if let Ok(notify) = std::env::var("NOTIFY_SOCKET")
        && !notify.is_empty()
    {
        UnixDatagram::unbound()?.send_to(b"READY=1\n", &notify)?;
    }
    let mut clients = Vec::new();
    loop {
        while clients.len() < 32 {
            match listener.accept_flags(SOCK_NONBLOCK | SOCK_CLOEXEC) {
                Ok((socket, peer)) => clients.push(Client {
                    socket,
                    peer,
                    deadline: Instant::now() + Duration::from_secs(10),
                    input: vec![],
                    output: None,
                    sent: 0,
                }),
                Err(Errno::EAGAIN | Errno::EINTR) => break,
                Err(e) => return Err(e.into()),
            }
        }
        clients.retain_mut(|client| client.service(scope));
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("mountd: {e}");
        std::process::exit(1);
    }
}
