//! Nonblocking userspace export server. Only the control and admission
//! listeners differ. Every admitted stream is driven by the same ExportCore.
use crate::export_proto::{ExportCore, ExportFsOps};
use abi::export_ctl::*;
use abi::fs::{Handle, OpenRef};
use abi::socket::PeerCred;
use abi::{Call, Errno};
use os_posix::socket::{
    self, MSG_CMSG_CLOEXEC, MSG_CTRUNC, MSG_DONTWAIT, MSG_NOSIGNAL, SOCK_CLOEXEC, SOCK_NONBLOCK,
    UnixListener, UnixStream,
};
use serde::{Serialize, de::DeserializeOwned};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::fs::File;
#[cfg(not(target_os = "wasi"))]
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
#[cfg(target_os = "wasi")]
use std::os::wasi::io::{AsRawFd, FromRawFd, IntoRawFd};
use std::path::Path;
use std::rc::Rc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type Result<T> = std::result::Result<T, Errno>;
fn io_errno(e: std::io::Error) -> Errno {
    os_posix::errno_of(&e).unwrap_or(Errno::EIO)
}
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
fn sys<T: DeserializeOwned>(call: Call) -> Result<T> {
    let r = os_posix::batch(&[call])
        .map_err(io_errno)?
        .results
        .pop()
        .ok_or(Errno::EIO)?
        .into_result()
        .map_err(|e| e.errno)?;
    serde_json::from_value(r).map_err(|_| Errno::EIO)
}
fn dir_call<T: DeserializeOwned>(root: &File, call: ExportDirCall) -> Result<T> {
    sys(Call::Ioctl {
        fd: (root.as_raw_fd() as u32).into(),
        request: EXPORT_DIR_IOCTL,
        arg: serde_json::to_value(call).map_err(|_| Errno::EINVAL)?,
    })
}
pub fn current_uid() -> Result<u32> {
    Ok(sys::<abi::Creds>(Call::Getcreds)?.uid)
}

struct ScopedOps {
    root_fd: Rc<File>,
    root: Handle,
    cap: PeerIdentityCap,
}
impl ExportFsOps for ScopedOps {
    fn root(&self) -> Handle {
        self.root.clone()
    }
    fn at(&mut self, base: &Handle, call: AtOp) -> Result<OsfsResponse> {
        dir_call(
            &self.root_fd,
            ExportDirCall::At {
                cap: self.cap.clone(),
                base: base.clone(),
                call,
            },
        )
    }
    fn on_open(&mut self, open: &OpenRef, call: FdOp) -> Result<OsfsResponse> {
        dir_call(
            &self.root_fd,
            ExportDirCall::OnOpen {
                cap: self.cap.clone(),
                open: open.clone(),
                call,
            },
        )
    }
}
impl Drop for ScopedOps {
    fn drop(&mut self) {
        let _ = dir_call::<()>(
            &self.root_fd,
            ExportDirCall::End {
                cap: self.cap.clone(),
            },
        );
    }
}

struct Listener {
    socket: UnixListener,
    path: String,
    parent: File,
    tracked: bool,
    dev: u64,
    ino: u64,
}
impl Listener {
    fn bind(path: String, mode: u32) -> Result<Self> {
        let name = Path::new(&path);
        let parent = name.parent().and_then(Path::to_str).ok_or(Errno::EINVAL)?;
        let basename = name
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or(Errno::EINVAL)?
            .to_owned();
        let opened: abi::Opened = sys(Call::OpenAt {
            dirfd: (abi::OS_FD_CWD as u32).into(),
            path: parent.into(),
            flags: abi::O_RDONLY | abi::O_DIRECTORY | abi::O_NOFOLLOW,
            mode: 0,
        })?;
        // SAFETY: OpenAt installed a new owned directory descriptor.
        let parent = unsafe { File::from_raw_fd(opened.fd as _) };
        let socket = UnixListener::bind(&path)?;
        let st = os_posix::stat(Path::new(&path), false).map_err(io_errno)?;
        let mut bound = Self {
            socket,
            path,
            parent,
            tracked: false,
            dev: st.dev,
            ino: st.ino,
        };
        dir_call::<()>(
            &bound.parent,
            ExportDirCall::TrackListener {
                name: basename,
                dev: st.dev,
                ino: st.ino,
            },
        )?;
        bound.tracked = true;
        os_posix::chmod(Path::new(&bound.path), mode).map_err(io_errno)?;
        bound.socket.set_nonblocking(true)?;
        Ok(bound)
    }
    fn accept(&self) -> Result<(UnixStream, PeerCred)> {
        self.socket.accept_flags(SOCK_CLOEXEC | SOCK_NONBLOCK)
    }
}
impl Drop for Listener {
    fn drop(&mut self) {
        if self.tracked {
            let _ = dir_call::<()>(
                &self.parent,
                ExportDirCall::UnlinkListener {
                    dev: self.dev,
                    ino: self.ino,
                },
            );
            return;
        }
        let path = Path::new(&self.path);
        if os_posix::stat(path, false)
            .is_ok_and(|s| s.is_socket() && s.dev == self.dev && s.ino == self.ino)
        {
            let _ = os_posix::unlinkat(None, path, false);
        }
    }
}

struct Export {
    view: ExportEntry,
    end_reason: Errno,
    root_fd: Rc<File>,
    root: Handle,
    revoked: Rc<Cell<bool>>,
    ipc: Option<Listener>,
}
impl Drop for Export {
    fn drop(&mut self) {
        self.revoked.set(true);
        let _ = dir_call::<()>(
            &self.root_fd,
            ExportDirCall::Revoke {
                id: self.view.id.clone(),
                reason: self.end_reason,
            },
        );
    }
}
struct Client {
    export: String,
    view: ClientSessionView,
    stream: UnixStream,
    core: ExportCore<ScopedOps>,
    input: FrameReader,
    output: Vec<u8>,
    sent: usize,
    closing_since: Option<u64>,
}
impl Client {
    fn queue(&mut self, frames: Vec<OsfsFrame>) -> Result<()> {
        for frame in frames {
            let encoded = match encode_frame(&frame) {
                Err(Errno::E2BIG) if let OsfsFrame::Reply { request_id, .. } = frame => {
                    encode_frame(&OsfsFrame::Reply {
                        request_id,
                        result: Err(Errno::E2BIG),
                    })?
                }
                other => other?,
            };
            if self.output.len() + encoded.len()
                > (OSFS_MAX_INFLIGHT + 1) * (OSFS_MAX_FRAME_BYTES + 4)
            {
                return Err(Errno::ENOBUFS);
            }
            self.output.extend_from_slice(&encoded);
        }
        Ok(())
    }
    fn close(&mut self, errno: Errno, now: u64) -> Result<()> {
        if self.closing_since.is_none() {
            self.closing_since = Some(now);
            let frame = self.core.close(errno);
            self.queue(vec![frame])?;
        }
        Ok(())
    }
    fn poll(&mut self, now: u64) -> Result<bool> {
        if self.closing_since.is_none()
            && let Some(OsfsFrame::Closed { errno }) = self.core.tick(now)
        {
            self.close(errno, now)?;
        }
        if self.sent < self.output.len() {
            match self
                .stream
                .send(&self.output[self.sent..], MSG_NOSIGNAL | MSG_DONTWAIT)
            {
                Ok(0) => return Ok(false),
                Ok(n) => self.sent += n,
                Err(Errno::EAGAIN | Errno::EINTR) => {}
                Err(e) => return Err(e),
            }
            if self.sent < self.output.len() {
                return Ok(self.closing_since.is_none_or(|t| now < t + 1000));
            }
            self.output.clear();
            self.sent = 0;
        }
        if self.closing_since.is_some() {
            return Ok(false);
        }
        let mut bytes = [0; 16384];
        // Drain a bounded batch before dispatch so pipelined requests and
        // cancellation share the same four admission slots on every socket.
        for _ in 0..8 {
            match self.stream.recv(&mut bytes, MSG_DONTWAIT) {
                Ok(0) => return Ok(false),
                Ok(n) => {
                    let mut replies = Vec::new();
                    let r = self.input.feed(&bytes[..n], |frame| {
                        if !self.core.is_closed() {
                            replies.extend(self.core.receive(frame, now));
                        }
                        Ok(())
                    });
                    self.queue(replies)?;
                    if let Err(e) = r {
                        self.close(e, now)?;
                        break;
                    }
                    if self.core.is_closed() {
                        self.closing_since = Some(now);
                        break;
                    }
                }
                Err(Errno::EAGAIN | Errno::EINTR) => break,
                Err(e) => return Err(e),
            }
        }
        if self.closing_since.is_none() {
            let frames = self.core.dispatch(now);
            self.queue(frames)?;
        }
        Ok(true)
    }
}

struct Control {
    stream: UnixStream,
    peer: PeerCred,
    ingress: bool,
    deadline: u64,
    bytes: Vec<u8>,
    rights: Vec<File>,
    output: Vec<u8>,
    sent: usize,
}
impl Control {
    fn receive(&mut self) -> Result<bool> {
        let mut chunk = [0; 4096];
        let (n, fds, flags) = self.stream.recv_with_fds(
            &mut chunk,
            if self.ingress { 2 } else { 1 },
            MSG_DONTWAIT | MSG_CMSG_CLOEXEC,
        )?;
        let unexpected_rights = !self.bytes.is_empty() && !fds.is_empty();
        for fd in fds {
            // SAFETY: recvmsg installed a new, exclusively owned descriptor.
            self.rights.push(unsafe { File::from_raw_fd(fd as _) });
        }
        if n == 0 {
            return Err(Errno::ENOTCONN);
        }
        if flags & MSG_CTRUNC != 0
            || self.rights.len() > if self.ingress { 2 } else { 1 }
            || unexpected_rights
        {
            return Err(Errno::EINVAL);
        }
        if self.bytes.len() + n > CONTROL_MAX {
            return Err(Errno::E2BIG);
        }
        self.bytes.extend_from_slice(&chunk[..n]);
        Ok(self.bytes.contains(&b'\n'))
    }
    fn respond(&mut self, resp: &impl Serialize) -> Result<()> {
        self.output = encode_control(resp)?;
        Ok(())
    }
}

pub struct ExportDaemon {
    manager_uid: Option<u32>,
    control: Listener,
    ingress: Option<Listener>,
    exports: BTreeMap<String, Export>,
    clients: BTreeMap<u64, Client>,
    controls: Vec<Control>,
    next_session: u64,
}
impl ExportDaemon {
    pub fn bind(manager_uid: Option<u32>) -> Result<Self> {
        let uid = current_uid()?;
        if uid == 0 || manager_uid.is_some_and(|u| u != uid) {
            return Err(Errno::EPERM);
        }
        if manager_uid.is_none() {
            // PID 1 provisions /run/export for this service account. The
            // sticky share directory also hosts sockets owned by user daemons.
            let path = Path::new("/run/export/share");
            match os_posix::mkdir(path, 0o1777).map_err(io_errno) {
                Ok(()) => os_posix::chmod(path, 0o1777).map_err(io_errno)?,
                Err(Errno::EEXIST) => {
                    let st = os_posix::stat(path, false).map_err(io_errno)?;
                    if !st.is_dir() || st.mode & 0o1777 != 0o1777 || (st.uid != uid && st.uid != 0)
                    {
                        return Err(Errno::EACCES);
                    }
                }
                Err(e) => return Err(e),
            }
        }
        let path = manager_uid
            .map(user_export_sock)
            .unwrap_or_else(|| SYSTEM_EXPORT_SOCK.into());
        let control = Listener::bind(path, if manager_uid.is_some() { 0o600 } else { 0o666 })?;
        let ingress = if manager_uid.is_none() {
            Some(Listener::bind(EXPORT_TRANSPORT_SOCK.into(), 0o666)?)
        } else {
            None
        };
        Ok(Self {
            manager_uid,
            control,
            ingress,
            exports: BTreeMap::new(),
            clients: BTreeMap::new(),
            controls: vec![],
            next_session: 0,
        })
    }
    fn control(
        &mut self,
        peer: PeerCred,
        req: ExportRequest,
        root: Option<File>,
        now: u64,
    ) -> Result<ExportResponse> {
        if self.manager_uid.is_some_and(|uid| uid != peer.uid) {
            return Err(Errno::EACCES);
        }
        if !matches!(req, ExportRequest::Publish { .. }) && root.is_some() {
            return Err(Errno::EINVAL);
        }
        let owned = |id: &str| {
            self.exports
                .get(id)
                .filter(|e| e.view.owner_uid == peer.uid)
                .ok_or(Errno::EACCES)
        };
        match req {
            ExportRequest::Publish {
                name,
                source_path,
                writable,
                execute,
                seconds,
                password,
                transports,
            } => {
                let root = root.ok_or(Errno::EBADF)?;
                if peer.uid == 0 {
                    return Err(Errno::EACCES);
                }
                if name.is_empty()
                    || name.len() > 80
                    || source_path.len() >= abi::PATH_MAX
                    || !(1..=3600).contains(&seconds)
                    || password.as_ref().is_some_and(|p| p.len() > 256)
                {
                    return Err(Errno::EINVAL);
                }
                if self.exports.len() >= 128 {
                    return Err(Errno::ENOSPC);
                }
                let info: RootInfo = dir_call(&root, ExportDirCall::Inspect {})?;
                validate_root(&info)?;
                if info.publisher_uid != peer.uid {
                    return Err(Errno::EACCES);
                }
                let id = random_id()?;
                let rule = ExportRule { writable, execute }.intersect(info.ceiling);
                let expires_at = now + seconds * 1000;
                let protected = password.as_ref().is_some_and(|p| !p.is_empty());
                let ipc = transports.is_empty() || transports.contains(&TransportKind::Ipc);
                let listener = if ipc {
                    Some(Listener::bind(export_ipc_sock(&id), 0o666)?)
                } else {
                    None
                };
                let transports = dir_call(
                    &root,
                    ExportDirCall::Publish {
                        id: id.clone(),
                        name: name.clone(),
                        publisher_pid: peer.pid,
                        manager_uid: self.manager_uid,
                        expires_at,
                        rule,
                        password,
                        transports,
                    },
                )?;
                let view = ExportEntry {
                    id: id.clone(),
                    name,
                    source_path,
                    owner_uid: peer.uid,
                    rule,
                    password: protected,
                    transports,
                    expires_at,
                };
                self.exports.insert(
                    id,
                    Export {
                        view: view.clone(),
                        end_reason: Errno::ENOTCONN,
                        root_fd: Rc::new(root),
                        root: info.root.handle,
                        revoked: Rc::new(Cell::new(false)),
                        ipc: listener,
                    },
                );
                Ok(ExportResponse::Published { export: view })
            }
            ExportRequest::List {} => Ok(ExportResponse::Exports {
                exports: self
                    .exports
                    .values()
                    .filter(|e| e.view.owner_uid == peer.uid)
                    .map(|e| e.view.clone())
                    .collect(),
            }),
            ExportRequest::Status { id } => Ok(ExportResponse::Entry {
                export: owned(&id)?.view.clone(),
            }),
            ExportRequest::ListClients { id } => {
                owned(&id)?;
                Ok(ExportResponse::Clients {
                    clients: self
                        .clients
                        .values()
                        .filter(|c| c.export == id)
                        .map(|c| c.view.clone())
                        .collect(),
                })
            }
            ExportRequest::Transports {} => Ok(ExportResponse::Transports {
                exports: self
                    .exports
                    .values()
                    .filter(|e| e.view.owner_uid == peer.uid)
                    .map(|e| ExportTransportView {
                        id: e.view.id.clone(),
                        clients: self
                            .clients
                            .values()
                            .filter(|c| c.export == e.view.id && c.closing_since.is_none())
                            .map(|c| c.view.clone())
                            .collect(),
                    })
                    .collect(),
            }),
            ExportRequest::Revoke { id } => {
                owned(&id)?;
                self.retire(&id, Errno::EACCES, now);
                Ok(ExportResponse::Revoked {})
            }
        }
    }
    fn retire(&mut self, id: &str, errno: Errno, now: u64) {
        for client in self.clients.values_mut().filter(|c| c.export == id) {
            let _ = client.close(errno, now);
        }
        if let Some(mut export) = self.exports.remove(id) {
            export.end_reason = errno;
        }
    }
    fn admit(
        &mut self,
        id: &str,
        stream: UnixStream,
        header: Option<TransportSessionHeader>,
        now: u64,
    ) -> Result<()> {
        let e = self.exports.get(id).ok_or(Errno::ESTALE)?;
        if now >= e.view.expires_at {
            return Err(Errno::ESTALE);
        }
        if self.clients.values().filter(|c| c.export == id).count() >= 16 {
            return Err(Errno::EBUSY);
        }
        let transport = header
            .as_ref()
            .map(|h| h.transport)
            .unwrap_or(TransportKind::Ipc);
        if !e.view.transports.contains(&transport) {
            return Err(Errno::EACCES);
        }
        stream.set_nonblocking(true)?;
        let admission: Result<Admission> = dir_call(
            &e.root_fd,
            match header {
                Some(header) => ExportDirCall::AdmitRemote { header },
                None => ExportDirCall::AdmitLocal {
                    id: id.into(),
                    socket_fd: stream.as_raw_fd(),
                },
            },
        );
        let admission = match admission {
            Ok(a) => a,
            Err(errno) => {
                let frame = encode_frame(&OsfsFrame::Closed { errno })?;
                let _ = stream.send(&frame, MSG_DONTWAIT | MSG_NOSIGNAL);
                return Err(errno);
            }
        };
        let ops = ScopedOps {
            root_fd: e.root_fd.clone(),
            root: e.root.clone(),
            cap: admission.cap,
        };
        let expires_at = e.view.expires_at.min(admission.expires_at);
        self.next_session = self.next_session.checked_add(1).ok_or(Errno::ENOSPC)?;
        let view = ClientSessionView {
            id: self.next_session,
            peer_uid: admission.peer_uid,
            transport,
            expires_at,
        };
        self.clients.insert(
            view.id,
            Client {
                export: id.into(),
                view,
                stream,
                core: ExportCore::new(
                    ops,
                    e.view.rule.intersect(admission.rule),
                    expires_at,
                    e.revoked.clone(),
                ),
                input: FrameReader::default(),
                output: vec![],
                sent: 0,
                closing_since: None,
            },
        );
        Ok(())
    }
    fn ingress(
        &mut self,
        header: TransportSessionHeader,
        fd: File,
        forward: Option<File>,
        now: u64,
    ) -> Result<()> {
        if header.version != OSFS_VERSION || now >= header.expires_at {
            return Err(Errno::ESTALE);
        }
        if socket::getsockopt_fd(fd.as_raw_fd() as u32, socket::SOL_SOCKET, socket::SO_TYPE)?
            != socket::SOCK_STREAM as i32
        {
            return Err(Errno::EPROTOTYPE);
        }
        if self.manager_uid.is_none()
            && let Some(uid) = header.manager_uid
        {
            // Forward only to the owning daemon; it redeems and verifies the
            // sealed header against its own received directory description.
            let forward = forward.ok_or(Errno::EBADF)?;
            let relay_fd = forward.as_raw_fd() as u32;
            if socket::peercred_fd(relay_fd)?.uid != uid
                || socket::getpeername_fd(relay_fd)? != user_export_sock(uid)
            {
                return Err(Errno::EACCES);
            }
            let msg = encode_control(&header)?;
            let sent = socket::sendmsg_fd(
                relay_fd,
                &msg,
                &[fd.as_raw_fd() as u32],
                None,
                MSG_NOSIGNAL | MSG_DONTWAIT,
            )?;
            if sent != msg.len() {
                return Err(Errno::EIO);
            }
            return Ok(());
        }
        if forward.is_some() || self.manager_uid != header.manager_uid {
            return Err(Errno::EACCES);
        }
        let id = header.export_id.clone();
        // SAFETY: verified stream type above and transferred exclusive ownership.
        let stream = unsafe { UnixStream::from_raw_fd(fd.into_raw_fd() as u32) };
        self.admit(&id, stream, Some(header), now)
    }
    fn handle(&mut self, c: &mut Control, now: u64) -> Result<()> {
        let mut rights = std::mem::take(&mut c.rights).into_iter();
        let fd = rights.next();
        if c.ingress
            || (self.manager_uid.is_some()
                && serde_json::from_slice::<TransportSessionHeader>(&c.bytes).is_ok())
        {
            self.ingress(
                decode_control(&c.bytes)?,
                fd.ok_or(Errno::EBADF)?,
                rights.next(),
                now,
            )?;
            return c.respond(&ExportResponse::Accepted {});
        }
        let req = decode_control(&c.bytes)?;
        let reply = self.control(c.peer, req, fd, now)?;
        c.respond(&reply)
    }
    pub fn poll(&mut self, now: u64) {
        let expired: Vec<_> = self
            .exports
            .values()
            .filter(|e| now >= e.view.expires_at)
            .map(|e| e.view.id.clone())
            .collect();
        for id in expired {
            self.retire(&id, Errno::ESTALE, now);
        }
        for (listener, ingress) in
            std::iter::once((&self.control, false)).chain(self.ingress.iter().map(|l| (l, true)))
        {
            while self.controls.len() < 64 {
                let Ok((stream, peer)) = listener.accept() else {
                    break;
                };
                self.controls.push(Control {
                    stream,
                    peer,
                    ingress,
                    deadline: now + 5000,
                    bytes: vec![],
                    rights: vec![],
                    output: vec![],
                    sent: 0,
                });
            }
        }
        for mut c in std::mem::take(&mut self.controls) {
            if now >= c.deadline {
                continue;
            }
            if c.output.is_empty() {
                match c.receive() {
                    Ok(true) => {
                        if let Err(errno) = self.handle(&mut c, now) {
                            let _ = c.respond(&ExportResponse::Error { errno });
                        }
                    }
                    Ok(false) | Err(Errno::EAGAIN | Errno::EINTR) => {
                        self.controls.push(c);
                        continue;
                    }
                    Err(errno) => {
                        let _ = c.respond(&ExportResponse::Error { errno });
                    }
                }
            }
            match c
                .stream
                .send(&c.output[c.sent..], MSG_DONTWAIT | MSG_NOSIGNAL)
            {
                Ok(0) => {}
                Ok(n) => {
                    c.sent += n;
                    if c.sent < c.output.len() {
                        self.controls.push(c);
                    }
                }
                Err(Errno::EAGAIN | Errno::EINTR) => self.controls.push(c),
                Err(_) => {}
            }
        }
        let mut accepted = vec![];
        for (id, e) in &self.exports {
            if let Some(l) = &e.ipc
                && let Ok((s, _peer)) = l.accept()
            {
                accepted.push((id.clone(), s));
            }
        }
        for (id, stream) in accepted {
            let _ = self.admit(&id, stream, None, now);
        }
        self.clients.retain(|_, c| c.poll(now).unwrap_or(false));
    }
    pub fn run(&mut self, stopping: impl Fn() -> bool) -> Result<()> {
        if let Ok(path) = std::env::var("NOTIFY_SOCKET")
            && !path.is_empty()
        {
            socket::UnixDatagram::unbound()?.send_to(b"READY=1\n", &path)?;
        }
        while !stopping() {
            self.poll(now_ms());
            std::thread::sleep(Duration::from_millis(5));
        }
        let now = now_ms();
        for c in self.clients.values_mut() {
            let _ = c.close(Errno::ENOTCONN, now);
        }
        self.exports.clear();
        while !self.clients.is_empty() {
            self.clients
                .retain(|_, c| c.poll(now_ms()).unwrap_or(false));
            std::thread::sleep(Duration::from_millis(2));
        }
        Ok(())
    }
}
pub fn validate_root(info: &RootInfo) -> Result<()> {
    if !info.root.metadata.is_dir() {
        return Err(Errno::ENOTDIR);
    }
    if !info.stable_ino || info.root.handle.node.ino == 0 || info.root.handle.fs.0.is_empty() {
        return Err(Errno::EPROTONOSUPPORT);
    }
    Ok(())
}
fn random_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    #[cfg(target_os = "wasi")]
    {
        #[link(wasm_import_module = "wasi_snapshot_preview1")]
        unsafe extern "C" {
            fn random_get(buf: *mut u8, len: usize) -> u32;
        }
        // SAFETY: the import fills exactly the supplied writable slice.
        if unsafe { random_get(bytes.as_mut_ptr(), bytes.len()) } != 0 {
            return Err(Errno::EIO);
        }
    }
    #[cfg(not(target_os = "wasi"))]
    {
        use std::io::Read;
        File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut bytes))
            .map_err(io_errno)?;
    }
    bytes[6] = bytes[6] & 15 | 64;
    bytes[8] = bytes[8] & 63 | 128;
    let hex = format!("{:032x}", u128::from_be_bytes(bytes));
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refuses_non_directory_and_legacy_helper_without_inode_identity() {
        let time = serde_json::json!({ "sec": 0, "nsec": 0 });
        let mut info: RootInfo = serde_json::from_value(serde_json::json!({
            "root": {
                "handle": { "fs": "helper", "node": { "ino": 22, "generation": 3 } },
                "metadata": {
                    "mode": 511, "uid": 1000, "gid": 10, "nlink": 1, "size": 0,
                    "file_type": "dir", "acl": false, "rdev": null,
                    "atime": time, "mtime": time, "ctime": time,
                }
            },
            "publisher_uid": 1000, "stable_ino": true, "ceiling": { "writable": true, "execute": true }
        })).unwrap();
        assert!(validate_root(&info).is_ok());
        info.stable_ino = false;
        assert_eq!(validate_root(&info), Err(Errno::EPROTONOSUPPORT));
        info.root.metadata.file_type = abi::fs::FileType::File;
        assert_eq!(validate_root(&info), Err(Errno::ENOTDIR));
    }
}
