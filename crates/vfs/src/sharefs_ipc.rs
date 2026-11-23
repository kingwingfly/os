//! Framed osfs v2 client for a connected byte stream. Multiple VFS futures
//! can poll the same connection. Only the request that lost an unacknowledged
//! mutation reports an uncertain write.
use crate::mount::ProviderState;
use crate::sharefs::{ShareError, ShareFs, ShareFuture, ShareTransport};
use crate::*;
use abi::export_ctl::*;
use abi::{Bytes, Errno};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use std::future::poll_fn;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};

/// Implementations preserve byte order, support short transfers, and arrange
/// to wake the poller on readiness. Zero bytes means the peer closed.
pub trait ByteStream {
    fn poll_write(&self, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<Result<usize>>;
    fn poll_read(&self, cx: &mut Context<'_>, bytes: &mut [u8]) -> Poll<Result<usize>>;
    /// Event-loop streams schedule this notification after the current mount
    /// guard returns. The completed wire reply determines its precise errno.
    fn notify_loss(&self, provider: &Rc<ProviderState>) {
        provider.lose();
    }
}

/// Native adapter for a blocking AF_UNIX stream on a dedicated I/O thread.
#[cfg(unix)]
pub struct UnixByteStream(std::fs::File);
#[cfg(unix)]
impl From<std::os::unix::net::UnixStream> for UnixByteStream {
    fn from(socket: std::os::unix::net::UnixStream) -> Self {
        Self(std::fs::File::from(std::os::fd::OwnedFd::from(socket)))
    }
}
#[cfg(unix)]
impl UnixByteStream {
    pub fn connect_export(id: &str) -> Result<Self> {
        component(id)?;
        std::os::unix::net::UnixStream::connect(export_ipc_sock(id))
            .map(Into::into)
            .map_err(|_| Errno::ENOTCONN)
    }
}
#[cfg(unix)]
impl ByteStream for UnixByteStream {
    fn poll_write(&self, _: &mut Context<'_>, bytes: &[u8]) -> Poll<Result<usize>> {
        use std::io::Write;
        Poll::Ready((&self.0).write(bytes).map_err(|_| Errno::ENOTCONN))
    }
    fn poll_read(&self, _: &mut Context<'_>, bytes: &mut [u8]) -> Poll<Result<usize>> {
        use std::io::Read;
        Poll::Ready((&self.0).read(bytes).map_err(|_| Errno::ENOTCONN))
    }
}

struct Pending {
    mutation: bool,
    sent: bool,
    abandoned: bool,
    waker: Option<Waker>,
    answer: Option<std::result::Result<OsfsResponse, ShareError>>,
}
struct Outgoing {
    started: bool,
    id: u64,
    bytes: Vec<u8>,
    offset: usize,
}

#[derive(Default)]
struct StreamState {
    pending: BTreeMap<u64, Pending>,
    output: VecDeque<Outgoing>,
    reader: FrameReader,
    last: u64,
    closed: Option<Errno>,
    notified: bool,
}
struct Connection<S> {
    stream: S,
    state: RefCell<StreamState>,
    provider: Rc<ProviderState>,
}
impl<S: ByteStream> Connection<S> {
    fn enqueue(state: &mut StreamState, req: OsfsRequest, abandoned: bool) -> Result<u64> {
        let id = state.last.checked_add(1).ok_or(Errno::EIO)?;
        let mutation = req.is_mutation();
        let bytes = encode_frame(&OsfsFrame::Request {
            request_id: id,
            request: req,
        })?;
        state.last = id;
        state.output.push_back(Outgoing {
            started: false,
            id,
            bytes,
            offset: 0,
        });
        state.pending.insert(
            id,
            Pending {
                mutation,
                sent: false,
                abandoned,
                waker: None,
                answer: None,
            },
        );
        Ok(id)
    }

    fn finish(&self, state: &mut StreamState, errno: Errno) {
        if state.closed.is_some() {
            return;
        }
        let lost = matches!(
            errno,
            Errno::EPIPE | Errno::ENOTCONN | Errno::ETIMEDOUT | Errno::ECONNRESET | Errno::ENODEV
        );
        let errno = if lost { Errno::ENOTCONN } else { errno };
        state.closed = Some(errno);
        state.output.clear();
        if errno == Errno::EACCES {
            self.provider.revoke();
        }
        for p in state.pending.values_mut().filter(|p| p.answer.is_none()) {
            let err = if lost && p.sent && p.mutation {
                self.provider.record_uncertain_write();
                Errno::EIO
            } else {
                errno
            };
            p.answer = Some(Err(ShareError::Remote(err)));
            if let Some(w) = p.waker.take() {
                w.wake();
            }
        }
    }
    fn report_loss(&self, state: &mut StreamState) {
        if state.closed == Some(Errno::ENOTCONN)
            && !state.notified
            && state.pending.values().all(|p| p.abandoned)
        {
            state.notified = true;
            self.stream.notify_loss(&self.provider);
        }
    }
    fn flush(&self, state: &mut StreamState, cx: &mut Context<'_>) -> Result<()> {
        while let Some(out) = state.output.front_mut() {
            out.started = true;
            if let Some(p) = state.pending.get_mut(&out.id) {
                p.sent = true;
            }
            match self.stream.poll_write(cx, &out.bytes[out.offset..]) {
                Poll::Pending => break,
                Poll::Ready(Ok(0) | Err(_)) => return Err(Errno::ENOTCONN),
                Poll::Ready(Ok(n)) if n <= out.bytes.len() - out.offset => {
                    out.offset += n;
                    if out.offset == out.bytes.len() {
                        state.output.pop_front();
                    }
                }
                _ => return Err(Errno::EIO),
            }
        }
        Ok(())
    }
    fn pump(&self, state: &mut StreamState, cx: &mut Context<'_>, id: u64) -> Result<()> {
        self.flush(state, cx)?;
        let mut buf = [0; 8192];
        while state.pending.get(&id).is_some_and(|p| p.answer.is_none()) {
            match self.stream.poll_read(cx, &mut buf) {
                Poll::Pending => break,
                Poll::Ready(Ok(0) | Err(_)) => return Err(Errno::ENOTCONN),
                Poll::Ready(Ok(n)) => {
                    let mut releases = Vec::new();
                    state
                        .reader
                        .feed(buf.get(..n).ok_or(Errno::EIO)?, |frame| {
                            match frame {
                                OsfsFrame::Closed { errno } => return Err(errno),
                                OsfsFrame::Reply { request_id, result } => {
                                    let p = state.pending.get_mut(&request_id).ok_or(Errno::EIO)?;
                                    if !p.sent || p.answer.is_some() {
                                        return Err(Errno::EIO);
                                    }
                                    if p.abandoned {
                                        if let Ok(OsfsResponse::Opened { open, .. }) = result {
                                            releases.push(open.id);
                                        }
                                        state.pending.remove(&request_id);
                                    } else {
                                        p.answer = Some(result.map_err(ShareError::Remote));
                                        if let Some(w) = p.waker.take() {
                                            w.wake();
                                        }
                                    }
                                }
                                _ => return Err(Errno::EIO),
                            }
                            Ok(())
                        })?;
                    for handle in releases {
                        Self::enqueue(
                            state,
                            OsfsRequest::Fd {
                                handle,
                                call: FdOp::Release {},
                            },
                            true,
                        )?;
                    }
                    self.flush(state, cx)?;
                }
            }
        }
        Ok(())
    }
    async fn call(&self, req: OsfsRequest) -> std::result::Result<OsfsResponse, ShareError> {
        let id = {
            let mut state = self.state.borrow_mut();
            if let Some(e) = state.closed {
                return Err(ShareError::Remote(e));
            }
            if state
                .pending
                .values()
                .filter(|p| !p.abandoned && p.answer.is_none())
                .count()
                >= OSFS_MAX_INFLIGHT
                || state.pending.len() >= 3 * OSFS_MAX_INFLIGHT
            {
                return Err(ShareError::Remote(Errno::EAGAIN));
            }
            Self::enqueue(&mut state, req, false).map_err(ShareError::Remote)?
        };
        let guard = CancelOnDrop {
            connection: self,
            id,
            done: Cell::new(false),
        };
        let result = poll_fn(|cx| {
            let mut state = self.state.borrow_mut();
            if state.closed.is_none()
                && let Err(e) = self.pump(&mut state, cx, id)
            {
                self.finish(&mut state, e);
            }
            let p = state.pending.get_mut(&id).expect("live request");
            if let Some(answer) = p.answer.take() {
                state.pending.remove(&id);
                self.report_loss(&mut state);
                for other in state.pending.values_mut() {
                    if let Some(w) = other.waker.take() {
                        w.wake();
                    }
                }
                Poll::Ready(answer)
            } else {
                p.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        })
        .await;
        guard.done.set(true);
        result
    }
}

struct CancelOnDrop<'a, S: ByteStream> {
    connection: &'a Connection<S>,
    id: u64,
    done: Cell<bool>,
}
impl<S: ByteStream> Drop for CancelOnDrop<'_, S> {
    fn drop(&mut self) {
        if self.done.get() {
            return;
        }
        let mut s = self.connection.state.borrow_mut();
        if s.closed.is_some() {
            s.pending.remove(&self.id);
            self.connection.report_loss(&mut s);
            return;
        }
        if s.pending.get(&self.id).is_some_and(|p| p.answer.is_some()) {
            if let Some(Ok(OsfsResponse::Opened { open, .. })) =
                s.pending.remove(&self.id).and_then(|p| p.answer)
            {
                let _ = Connection::<S>::enqueue(
                    &mut s,
                    OsfsRequest::Fd {
                        handle: open.id,
                        call: FdOp::Release {},
                    },
                    true,
                );
            }
        } else if let Some(idx) = s.output.iter().position(|o| o.id == self.id && !o.started) {
            s.output.remove(idx);
            s.pending.remove(&self.id);
        } else if let Some(p) = s.pending.get_mut(&self.id) {
            p.abandoned = true;
            p.waker = None;
            let _ =
                Connection::<S>::enqueue(&mut s, OsfsRequest::Cancel { target_id: self.id }, true);
        }
        if let Err(e) = self
            .connection
            .flush(&mut s, &mut Context::from_waker(Waker::noop()))
        {
            self.connection.finish(&mut s, e);
        }
    }
}

pub struct IpcShareTransport<S> {
    connection: Connection<S>,
    root: Handle,
}

impl<S: ByteStream> IpcShareTransport<S> {
    /// The root and its filesystem identity come from the publisher, after
    /// the peer's root directory access check has succeeded.
    pub async fn connect(stream: S, rule: ExportRule) -> Result<ShareFs<Self>> {
        let provider = ProviderState::new();
        let connection = Connection {
            stream,
            state: RefCell::default(),
            provider: provider.clone(),
        };
        let answer = connection
            .call(OsfsRequest::Root {})
            .await
            .map_err(|e| match e {
                ShareError::Remote(e) => e,
                ShareError::Revoked => Errno::EACCES,
                ShareError::Disconnected => Errno::ENOTCONN,
            })?;
        let OsfsResponse::Root {
            entry,
            rule: admitted,
        } = answer
        else {
            return Err(Errno::EIO);
        };
        if !entry.metadata.is_dir() || !entry.handle.proof.is_empty() {
            return Err(Errno::EIO);
        }
        let rule = admitted.intersect(rule);
        Ok(ShareFs::new(
            Self {
                connection,
                root: entry.handle,
            },
            provider,
            !rule.writable,
            !rule.execute,
        ))
    }
    fn at<'a, T: 'a>(
        &'a self,
        base: &Handle,
        call: AtOp,
        decode: fn(OsfsResponse) -> Result<T>,
    ) -> ShareFuture<'a, T> {
        self.request(
            OsfsRequest::At {
                base: base.clone(),
                call,
            },
            decode,
        )
    }
    fn fd<'a, T: 'a>(
        &'a self,
        open: &OpenRef,
        call: FdOp,
        decode: fn(OsfsResponse) -> Result<T>,
    ) -> ShareFuture<'a, T> {
        self.request(
            OsfsRequest::Fd {
                handle: open.id,
                call,
            },
            decode,
        )
    }
    fn request<'a, T: 'a>(
        &'a self,
        req: OsfsRequest,
        decode: fn(OsfsResponse) -> Result<T>,
    ) -> ShareFuture<'a, T> {
        Box::pin(
            async move { decode(self.connection.call(req).await?).map_err(ShareError::Remote) },
        )
    }
}

fn unit(r: OsfsResponse) -> Result<()> {
    if let OsfsResponse::Unit = r {
        Ok(())
    } else {
        Err(Errno::EIO)
    }
}
fn entry(r: OsfsResponse) -> Result<Entry> {
    if let OsfsResponse::Entry(v) = r {
        Ok(v)
    } else {
        Err(Errno::EIO)
    }
}
fn metadata(r: OsfsResponse) -> Result<Metadata> {
    if let OsfsResponse::Metadata(v) = r {
        Ok(v)
    } else {
        Err(Errno::EIO)
    }
}
fn opened(r: OsfsResponse) -> Result<(Entry, OpenRef)> {
    if let OsfsResponse::Opened { entry, open } = r {
        Ok((entry, open))
    } else {
        Err(Errno::EIO)
    }
}

impl<S: ByteStream> ShareTransport for IpcShareTransport<S> {
    fn id(&self) -> &FsId {
        &self.root.fs
    }
    fn root(&self) -> Handle {
        self.root.clone()
    }
    fn lookup<'a>(
        &'a self,
        _cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
    ) -> ShareFuture<'a, Entry> {
        self.at(dir, AtOp::Lookup { name: name.into() }, entry)
    }
    fn walk<'a>(
        &'a self,
        _cred: &'a Cred,
        dir: &'a Handle,
        names: &'a [String],
    ) -> ShareFuture<'a, Walked> {
        self.at(
            dir,
            AtOp::Walk {
                names: names.to_vec(),
            },
            |r| match r {
                OsfsResponse::Walked(v) => Ok(v),
                _ => Err(Errno::EIO),
            },
        )
    }
    fn parent<'a>(
        &'a self,
        _cred: &'a Cred,
        dir: &'a Handle,
    ) -> ShareFuture<'a, Option<(Entry, String)>> {
        self.at(dir, AtOp::Parent {}, |r| match r {
            OsfsResponse::Parent(v) => Ok(v),
            _ => Err(Errno::EIO),
        })
    }
    fn metadata<'a>(&'a self, _cred: &'a Cred, handle: &'a Handle) -> ShareFuture<'a, Metadata> {
        self.at(handle, AtOp::Metadata {}, metadata)
    }
    fn open_metadata<'a>(&'a self, open: &'a OpenRef) -> ShareFuture<'a, Metadata> {
        self.fd(open, FdOp::Fstat {}, metadata)
    }
    fn setattr<'a>(
        &'a self,
        _cred: &'a Cred,
        handle: &'a Handle,
        attr: &'a SetAttr,
    ) -> ShareFuture<'a, Metadata> {
        self.at(handle, AtOp::Setattr { attr: attr.clone() }, metadata)
    }
    fn read_dir<'a>(&'a self, _cred: &'a Cred, dir: &'a Handle) -> ShareFuture<'a, Vec<DirEntry>> {
        self.at(dir, AtOp::ReadDir {}, |r| match r {
            OsfsResponse::Directory(v) => Ok(v),
            _ => Err(Errno::EIO),
        })
    }
    fn read_link<'a>(&'a self, _cred: &'a Cred, link: &'a Handle) -> ShareFuture<'a, String> {
        self.at(link, AtOp::ReadLink {}, |r| match r {
            OsfsResponse::Link(v) => Ok(v),
            _ => Err(Errno::EIO),
        })
    }
    fn create<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
        options: &'a OpenOptions,
    ) -> ShareFuture<'a, (Entry, OpenRef)> {
        self.at(
            dir,
            AtOp::Create {
                name: name.into(),
                mode,
                umask: cred.umask,
                options: *options,
            },
            opened,
        )
    }
    fn mkdir<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
    ) -> ShareFuture<'a, Entry> {
        self.at(
            dir,
            AtOp::Mkdir {
                name: name.into(),
                mode,
                umask: cred.umask,
            },
            entry,
        )
    }
    fn mknod<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
        rdev: &'a str,
    ) -> ShareFuture<'a, Entry> {
        self.at(
            dir,
            AtOp::Mknod {
                name: name.into(),
                mode,
                umask: cred.umask,
                rdev: rdev.into(),
            },
            entry,
        )
    }
    fn symlink<'a>(
        &'a self,
        _cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        target: &'a str,
    ) -> ShareFuture<'a, Entry> {
        self.at(
            dir,
            AtOp::Symlink {
                name: name.into(),
                target: target.into(),
            },
            entry,
        )
    }
    fn link<'a>(
        &'a self,
        _cred: &'a Cred,
        target: &'a Handle,
        dir: &'a Handle,
        name: &'a str,
    ) -> ShareFuture<'a, Entry> {
        self.at(
            dir,
            AtOp::Link {
                name: name.into(),
                target: target.clone(),
            },
            entry,
        )
    }
    fn unlink<'a>(
        &'a self,
        _cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
    ) -> ShareFuture<'a, ()> {
        self.at(dir, AtOp::Unlink { name: name.into() }, unit)
    }
    fn unlink_if<'a>(
        &'a self,
        _cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        node: crate::NodeId,
    ) -> ShareFuture<'a, ()> {
        self.at(
            dir,
            AtOp::UnlinkIf {
                name: name.into(),
                node,
            },
            unit,
        )
    }
    fn rmdir<'a>(&'a self, _cred: &'a Cred, dir: &'a Handle, name: &'a str) -> ShareFuture<'a, ()> {
        self.at(dir, AtOp::Rmdir { name: name.into() }, unit)
    }
    fn rename<'a>(
        &'a self,
        _cred: &'a Cred,
        from_dir: &'a Handle,
        from: &'a str,
        to_dir: &'a Handle,
        to: &'a str,
        flags: RenameFlags,
    ) -> ShareFuture<'a, ()> {
        self.at(
            from_dir,
            AtOp::Rename {
                name: from.into(),
                to_dir: to_dir.clone(),
                to: to.into(),
                flags,
            },
            unit,
        )
    }
    fn getxattr<'a>(
        &'a self,
        _cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> ShareFuture<'a, Vec<u8>> {
        self.at(handle, AtOp::Getxattr { name: name.into() }, bytes)
    }
    fn setxattr<'a>(
        &'a self,
        _cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
        value: &'a [u8],
        flags: XattrFlags,
    ) -> ShareFuture<'a, ()> {
        self.at(
            handle,
            AtOp::Setxattr {
                name: name.into(),
                value: Bytes(value.to_vec()),
                flags,
            },
            unit,
        )
    }
    fn listxattr<'a>(
        &'a self,
        _cred: &'a Cred,
        handle: &'a Handle,
    ) -> ShareFuture<'a, Vec<String>> {
        self.at(handle, AtOp::Listxattr {}, |r| match r {
            OsfsResponse::Names(v) => Ok(v),
            _ => Err(Errno::EIO),
        })
    }
    fn removexattr<'a>(
        &'a self,
        _cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> ShareFuture<'a, ()> {
        self.at(handle, AtOp::Removexattr { name: name.into() }, unit)
    }
    fn statfs<'a>(&'a self, _cred: &'a Cred) -> ShareFuture<'a, StatFs> {
        self.at(&self.root, AtOp::Statfs {}, |r| match r {
            OsfsResponse::Statfs(v) => Ok(v),
            _ => Err(Errno::EIO),
        })
    }
    fn open<'a>(
        &'a self,
        _cred: &'a Cred,
        handle: &'a Handle,
        options: &'a OpenOptions,
    ) -> ShareFuture<'a, OpenRef> {
        self.at(handle, AtOp::Open { options: *options }, |r| {
            opened(r).map(|(_, open)| open)
        })
    }
    fn read_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a mut [u8],
        offset: u64,
    ) -> ShareFuture<'a, usize> {
        Box::pin(async move {
            let count = buf.len().min(OSFS_CHUNK);
            let data = self.fd(open, FdOp::Read { offset, count }, bytes).await?;
            if data.len() > count {
                return Err(ShareError::Remote(Errno::EIO));
            }
            buf[..data.len()].copy_from_slice(&data);
            Ok(data.len())
        })
    }
    fn write_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a [u8],
        at: WriteAt,
    ) -> ShareFuture<'a, Written> {
        let count = buf.len().min(OSFS_CHUNK);
        Box::pin(async move {
            let result = self
                .fd(
                    open,
                    FdOp::Write {
                        at,
                        data: Bytes(buf[..count].to_vec()),
                    },
                    |r| match r {
                        OsfsResponse::Written(v) => Ok(v),
                        _ => Err(Errno::EIO),
                    },
                )
                .await?;
            if result.len > count {
                return Err(ShareError::Remote(Errno::EIO));
            }
            Ok(result)
        })
    }
    fn set_len<'a>(&'a self, open: &'a OpenRef, size: u64) -> ShareFuture<'a, ()> {
        self.fd(open, FdOp::Ftruncate { size }, unit)
    }
    fn sync_all<'a>(&'a self, open: &'a OpenRef) -> ShareFuture<'a, ()> {
        self.fd(open, FdOp::Sync { data_only: false }, unit)
    }
    fn sync_data<'a>(&'a self, open: &'a OpenRef) -> ShareFuture<'a, ()> {
        self.fd(open, FdOp::Sync { data_only: true }, unit)
    }
    fn lock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> ShareFuture<'a, ()> {
        self.fd(
            open,
            FdOp::Lock {
                family,
                kind,
                range,
                wait: true,
            },
            unit,
        )
    }
    fn try_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> ShareFuture<'a, ()> {
        self.fd(
            open,
            FdOp::Lock {
                family,
                kind,
                range,
                wait: false,
            },
            unit,
        )
    }
    fn unlock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        range: LockRange,
    ) -> ShareFuture<'a, ()> {
        self.fd(open, FdOp::Unlock { family, range }, unit)
    }
    fn test_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        kind: LockKind,
        range: LockRange,
    ) -> ShareFuture<'a, Option<Conflict>> {
        self.fd(open, FdOp::TestLock { kind, range }, |r| match r {
            OsfsResponse::Lock(v) => Ok(v),
            _ => Err(Errno::EIO),
        })
    }
    fn release<'a>(&'a self, open: &'a OpenRef) -> ShareFuture<'a, ()> {
        self.fd(open, FdOp::Release {}, unit)
    }
}
fn bytes(r: OsfsResponse) -> Result<Vec<u8>> {
    match r {
        OsfsResponse::Bytes(v) => Ok(v.0),
        _ => Err(Errno::EIO),
    }
}

/// VFS end of the directory-fd ioctl. A scoped directory retains the open
/// description transferred by SCM_RIGHTS, including the mount pin. Only
/// handles produced by a fresh component walk from that description reach a
/// driver. Wire proofs and numeric inode IDs never become driver handles.
pub struct ScopedDir {
    root: FileRef,
    cred: Cred,
    rule: ExportRule,
    live: Cell<bool>,
    opens: RefCell<BTreeMap<u64, (Handle, OpenRef)>>,
}
impl ScopedDir {
    pub fn new(root: FileRef, cred: Cred, rule: ExportRule) -> Result<Self> {
        if cred.identity.id == 0 {
            return Err(Errno::EACCES);
        }
        Ok(Self {
            root,
            cred,
            rule,
            live: Cell::new(true),
            opens: RefCell::default(),
        })
    }
    pub fn root(&self) -> Handle {
        Handle {
            proof: String::new(),
            ..self.root.handle().clone()
        }
    }
    fn fs(&self) -> &dyn Filesystem {
        self.root.fs().as_ref()
    }
    fn active(&self) -> Result<()> {
        if !self.live.get() {
            return Err(Errno::EACCES);
        }
        if let Some(pin) = self.root.mount_pin() {
            pin.provider().check_health()?;
        }
        Ok(())
    }
    fn ceiling(&self) -> ExportRule {
        let pin = self.root.mount_pin();
        self.rule.intersect(ExportRule {
            writable: !pin.is_some_and(|p| p.effective_rdonly()),
            execute: !pin.is_some_and(|p| p.effective_noexec()),
        })
    }
    async fn walk_from_pin(&self, path: &str) -> Result<Entry> {
        relative_path(path)?;
        self.active()?;
        let mut entry = Entry {
            handle: self.root.handle().clone(),
            metadata: self.fs().metadata(&self.cred, self.root.handle()).await?,
        };
        self.access(&entry, abi::R_OK | abi::X_OK).await?;
        if !path.is_empty() {
            for name in path.split('/') {
                if entry.metadata.is_symlink() {
                    return Err(Errno::ELOOP);
                }
                self.active()?;
                entry = self.fs().lookup(&self.cred, &entry.handle, name).await?;
            }
        }
        self.active()?;
        Ok(entry)
    }
    pub async fn resolve_beneath(&self, named: &Handle) -> Result<Entry> {
        if named.fs != self.root.handle().fs {
            return Err(Errno::EACCES);
        }
        let entry = self
            .walk_from_pin(&named.proof)
            .await
            .map_err(|e| if e == Errno::ENOENT { Errno::ESTALE } else { e })?;
        if entry.handle.node != named.node || entry.handle.fs != named.fs {
            return Err(Errno::ESTALE);
        }
        Ok(entry)
    }
    async fn access(&self, entry: &Entry, mask: u16) -> Result<()> {
        if mask & !7 != 0 {
            return Err(Errno::EINVAL);
        }
        let meta = &entry.metadata;
        let mut node = os_core::permissions::Node::directory(meta.uid, meta.gid, meta.mode);
        node.directory = meta.is_dir();
        if meta.acl {
            let data = self
                .fs()
                .getxattr(&self.cred, &entry.handle, abi::ACL_ACCESS)
                .await?;
            let acl: os_core::acl::Entries =
                serde_json::from_slice(&data).map_err(|_| Errno::EIO)?;
            node.set_entries(&acl);
        }
        os_core::inode::require(&self.cred.identity, &node, mask)
    }
    fn wire_entry(&self, mut entry: Entry, path: String) -> Entry {
        entry.handle.proof = path;
        self.ceiling().mask(&mut entry.metadata);
        entry
    }
    async fn keep(&self, entry: Entry, open: OpenRef, path: String) -> Result<OsfsResponse> {
        if !self.live.get() || self.opens.borrow().len() >= OSFS_MAX_HANDLES {
            self.fs().release(&open).await?;
            self.active()?;
            return Err(Errno::EMFILE);
        }
        let entry = self.wire_entry(entry, path);
        self.opens
            .borrow_mut()
            .insert(open.id, (entry.handle.clone(), open.clone()));
        Ok(OsfsResponse::Opened { entry, open })
    }
    /// Relative equivalents of the POSIX *at operations. Creation passes the
    /// original mode and umask separately to the driver for #49 inheritance.
    pub async fn at(&self, base: &Handle, call: AtOp) -> Result<OsfsResponse> {
        let entry = self.resolve_beneath(base).await?;
        let h = &entry.handle;
        let fs = self.fs();
        let cred = &self.cred;
        let path = &base.proof;
        let child = |name: &str| -> Result<String> {
            component(name)?;
            let joined = if path.is_empty() {
                name.to_owned()
            } else {
                format!("{path}/{name}")
            };
            relative_path(&joined)?;
            Ok(joined)
        };
        let rule = self.ceiling();
        if !rule.writable
            && (OsfsRequest::At {
                base: base.clone(),
                call: call.clone(),
            })
            .is_mutation()
        {
            return Err(Errno::EROFS);
        }
        let options = match &call {
            AtOp::Open { options } | AtOp::Create { options, .. } => Some(options),
            _ => None,
        };
        if let Some(options) = options {
            let access = options.access()?;
            if access == Access::Exec && !rule.execute {
                return Err(Errno::EACCES);
            }
            if access.writes() && !rule.writable {
                return Err(Errno::EROFS);
            }
            if self.opens.borrow().len() >= OSFS_MAX_HANDLES {
                return Err(Errno::EMFILE);
            }
        }
        match call {
            AtOp::Lookup { name } => {
                let path = child(&name)?;
                Ok(OsfsResponse::Entry(
                    self.wire_entry(fs.lookup(cred, h, &name).await?, path),
                ))
            }
            AtOp::Walk { names } => {
                let mut rel = path.clone();
                for name in &names {
                    component(name)?;
                }
                let mut result = fs.walk(cred, h, &names).await?;
                for (e, name) in result.entries.iter_mut().zip(names) {
                    if !rel.is_empty() {
                        rel.push('/');
                    }
                    rel.push_str(&name);
                    relative_path(&rel)?;
                    e.handle.proof = rel.clone();
                    rule.mask(&mut e.metadata);
                }
                Ok(OsfsResponse::Walked(result))
            }
            AtOp::Parent {} if path.is_empty() => Ok(OsfsResponse::Parent(None)),
            AtOp::Parent {} => {
                let (parent, name) = path.rsplit_once('/').unwrap_or(("", path));
                let entry = self.walk_from_pin(parent).await?;
                Ok(OsfsResponse::Parent(Some((
                    self.wire_entry(entry, parent.into()),
                    name.into(),
                ))))
            }
            AtOp::Metadata {} => Ok(OsfsResponse::Metadata(
                self.wire_entry(entry, path.clone()).metadata,
            )),
            AtOp::Access { mask } => {
                if mask & abi::W_OK != 0 && !rule.writable {
                    return Err(Errno::EROFS);
                }
                if mask & abi::X_OK != 0 && entry.metadata.is_file() && !rule.execute {
                    return Err(Errno::EACCES);
                }
                self.access(&entry, mask).await?;
                Ok(OsfsResponse::Unit)
            }
            AtOp::ReadDir {} => Ok(OsfsResponse::Directory(fs.read_dir(cred, h).await?)),
            AtOp::ReadLink {} => {
                self.allow_symlink()?;
                let target = fs.read_link(cred, h).await?;
                relative_path(&target).map_err(|_| Errno::ELOOP)?;
                Ok(OsfsResponse::Link(target))
            }
            AtOp::Statfs {} => Ok(OsfsResponse::Statfs(fs.statfs(cred).await?)),
            AtOp::Open { options } => {
                if entry.metadata.is_symlink() {
                    return Err(Errno::ELOOP);
                }
                if !entry.metadata.is_file() && !entry.metadata.is_dir() {
                    return Err(Errno::EACCES);
                }
                let open = fs.open(cred, h, &options).await?;
                self.keep(entry, open, path.clone()).await
            }
            AtOp::Create {
                name,
                mode,
                umask,
                options,
            } => {
                let path = child(&name)?;
                let (entry, open) = if options.access()? == Access::Path || !options.is_create() {
                    let entry = fs.lookup(cred, h, &name).await?;
                    if !entry.metadata.is_file() && !entry.metadata.is_dir() {
                        return Err(Errno::ELOOP);
                    }
                    let open = fs.open(cred, &entry.handle, &options).await?;
                    (entry, open)
                } else {
                    fs.create(
                        &Cred {
                            umask: umask & 0o777,
                            ..cred.clone()
                        },
                        h,
                        &name,
                        mode,
                        &options,
                    )
                    .await?
                };
                self.keep(entry, open, path).await
            }
            AtOp::Mkdir { name, mode, umask } => {
                let path = child(&name)?;
                Ok(OsfsResponse::Entry(
                    self.wire_entry(
                        fs.mkdir(
                            &Cred {
                                umask: umask & 0o777,
                                ..cred.clone()
                            },
                            h,
                            &name,
                            mode,
                        )
                        .await?,
                        path,
                    ),
                ))
            }
            AtOp::Mknod {
                name,
                mode,
                umask,
                rdev,
            } => {
                let path = child(&name)?;
                Ok(OsfsResponse::Entry(
                    self.wire_entry(
                        fs.mknod(
                            &Cred {
                                umask: umask & 0o777,
                                ..cred.clone()
                            },
                            h,
                            &name,
                            mode,
                            &rdev,
                        )
                        .await?,
                        path,
                    ),
                ))
            }
            AtOp::Symlink { name, target } => {
                let path = child(&name)?;
                self.allow_symlink()?;
                relative_path(&target)?;
                Ok(OsfsResponse::Entry(self.wire_entry(
                    fs.symlink(cred, h, &name, &target).await?,
                    path,
                )))
            }
            AtOp::Link { name, target } => {
                let path = child(&name)?;
                let src = self.resolve_beneath(&target).await?;
                Ok(OsfsResponse::Entry(self.wire_entry(
                    fs.link(cred, &src.handle, h, &name).await?,
                    path,
                )))
            }
            AtOp::Rename {
                name,
                to_dir,
                to,
                flags,
            } => {
                component(&name)?;
                component(&to)?;
                let dest = self.resolve_beneath(&to_dir).await?;
                fs.rename(cred, h, &name, &dest.handle, &to, flags).await?;
                Ok(OsfsResponse::Unit)
            }
            AtOp::Unlink { name } => {
                component(&name)?;
                fs.unlink(cred, h, &name).await?;
                Ok(OsfsResponse::Unit)
            }
            AtOp::UnlinkIf { name, node } => {
                component(&name)?;
                fs.unlink_if(cred, h, &name, node).await?;
                Ok(OsfsResponse::Unit)
            }
            AtOp::Rmdir { name } => {
                component(&name)?;
                fs.rmdir(cred, h, &name).await?;
                Ok(OsfsResponse::Unit)
            }
            AtOp::Setattr { attr } => {
                let mut meta = fs.setattr(cred, h, &attr).await?;
                self.ceiling().mask(&mut meta);
                Ok(OsfsResponse::Metadata(meta))
            }
            AtOp::Getxattr { name } => Ok(OsfsResponse::Bytes(Bytes(
                fs.getxattr(cred, h, &name).await?,
            ))),
            AtOp::Listxattr {} => Ok(OsfsResponse::Names(fs.listxattr(cred, h).await?)),
            AtOp::Setxattr { name, value, flags } => {
                fs.setxattr(cred, h, &name, &value.0, flags).await?;
                Ok(OsfsResponse::Unit)
            }
            AtOp::Removexattr { name } => {
                fs.removexattr(cred, h, &name).await?;
                Ok(OsfsResponse::Unit)
            }
        }
    }
    fn allow_symlink(&self) -> Result<()> {
        if self.root.mount_pin().is_some_and(|p| {
            p.fstype() == abi::contract::FsType::HelperFs || p.effective_flags().nosymfollow
        }) {
            Err(Errno::ELOOP)
        } else {
            Ok(())
        }
    }
    pub async fn on_open(&self, open: &OpenRef, call: FdOp) -> Result<OsfsResponse> {
        let (named, original) = self
            .opens
            .borrow()
            .get(&open.id)
            .cloned()
            .ok_or(Errno::EBADF)?;
        if open != &original {
            return Err(Errno::EBADF);
        }
        let fs = self.fs();
        if matches!(call, FdOp::Release {}) {
            self.opens.borrow_mut().remove(&open.id);
            fs.release(open).await?;
            return Ok(OsfsResponse::Unit);
        }
        let entry = self.resolve_beneath(&named).await?;
        let mask = match &call {
            FdOp::Write { .. } | FdOp::Ftruncate { .. } => {
                if !self.ceiling().writable {
                    return Err(Errno::EROFS);
                }
                abi::W_OK
            }
            FdOp::Read { .. } if open.access == Access::Exec => abi::X_OK,
            FdOp::Read { .. } | FdOp::ReadDir {} => abi::R_OK,
            _ if open.access == Access::Path => {
                if entry.metadata.is_dir() {
                    abi::X_OK
                } else {
                    abi::R_OK
                }
            }
            _ => open.access.mask(),
        };
        if mask & abi::X_OK != 0 && entry.metadata.is_file() && !self.ceiling().execute {
            return Err(Errno::EACCES);
        }
        self.access(&entry, mask).await?;
        self.active()?;
        let reads_inode = matches!(call, FdOp::Read { .. } | FdOp::ReadDir {} | FdOp::Fstat {});
        let result = match call {
            FdOp::Fstat {} => {
                let mut meta = fs.open_metadata(open).await?;
                self.ceiling().mask(&mut meta);
                Ok(OsfsResponse::Metadata(meta))
            }
            FdOp::ReadDir {} if open.access.reads() => Ok(OsfsResponse::Directory(
                fs.read_dir(&self.cred, &entry.handle).await?,
            )),
            FdOp::ReadDir {} => Err(Errno::EBADF),
            FdOp::Read { offset, count } => {
                if count > OSFS_CHUNK {
                    return Err(Errno::E2BIG);
                }
                let mut bytes = vec![0; count];
                let n = fs.read_at(open, &mut bytes, offset).await?;
                bytes.truncate(n);
                Ok(OsfsResponse::Bytes(Bytes(bytes)))
            }
            FdOp::Write { at, data } => {
                if data.0.len() > OSFS_CHUNK {
                    return Err(Errno::E2BIG);
                }
                Ok(OsfsResponse::Written(fs.write_at(open, &data.0, at).await?))
            }
            FdOp::Ftruncate { size } => {
                fs.set_len(open, size).await?;
                Ok(OsfsResponse::Unit)
            }
            FdOp::Sync { data_only } => {
                if data_only {
                    fs.sync_data(open).await?;
                } else {
                    fs.sync_all(open).await?;
                }
                Ok(OsfsResponse::Unit)
            }
            FdOp::Lock {
                family,
                kind,
                range,
                ..
            } => {
                fs.try_lock(open, family, kind, range).await?;
                Ok(OsfsResponse::Unit)
            }
            FdOp::Unlock { family, range } => {
                fs.unlock(open, family, range).await?;
                Ok(OsfsResponse::Unit)
            }
            FdOp::TestLock { kind, range } => {
                Ok(OsfsResponse::Lock(fs.test_lock(open, kind, range).await?))
            }
            FdOp::Release {} => unreachable!(),
        }?;
        self.active()?;
        if reads_inode {
            // A host driver may have yielded while reading. Do not return
            // those bytes if the inode moved or access changed in that time.
            let current = self.resolve_beneath(&named).await?;
            self.access(&current, mask).await?;
        }
        Ok(result)
    }
    pub async fn close(&self) {
        self.live.set(false);
        let opens = std::mem::take(&mut *self.opens.borrow_mut());
        for (_, open) in opens.into_values() {
            let _ = self.fs().release(&open).await;
        }
    }
}

// The production services crate intentionally has no dependency on a kernel or
// VFS implementation. Exercise its actual portable engine at this boundary
// without introducing a Cargo dependency in either direction.
#[cfg(test)]
#[path = "../../services/src/export_proto.rs"]
mod export_proto;

#[cfg(test)]
mod tests {
    use super::export_proto::{ExportCore, ExportFsOps};
    use super::*;
    use crate::memfs::MemFs;
    use std::future::Future;

    fn run<F: Future>(f: F) -> F::Output {
        now_or_never(f).expect("in-memory operation ready")
    }
    fn cred(uid: u32) -> Cred {
        Cred::new(Identity {
            id: uid,
            group: uid,
            groups: [uid, 42].into(),
        })
    }
    const RW: ExportRule = ExportRule {
        writable: true,
        execute: true,
    };
    struct Backend(ScopedDir);
    impl ExportFsOps for Backend {
        fn root(&self) -> Handle {
            self.0.root()
        }
        fn at(&mut self, h: &Handle, op: AtOp) -> Result<OsfsResponse> {
            run(self.0.at(h, op))
        }
        fn on_open(&mut self, o: &OpenRef, op: FdOp) -> Result<OsfsResponse> {
            run(self.0.on_open(o, op))
        }
    }
    struct Source {
        fs: Rc<dyn Filesystem>,
        root: FileRef,
        owner: Cred,
    }
    impl Source {
        fn new() -> Self {
            let owner = cred(1001);
            let fs: Rc<dyn Filesystem> = Rc::new(MemFs::new(
                FsId("volume".into()),
                7,
                1001,
                1001,
                0o755,
                Box::new(|| (1, 0)),
            ));
            let sub = run(fs.mkdir(&owner, &fs.root(), "share", 0o777))
                .unwrap()
                .handle;
            run(fs.setattr(
                &owner,
                &sub,
                &SetAttr {
                    mode: Some(0o2777),
                    ..Default::default()
                },
            ))
            .unwrap();
            let options = *OpenOptions::new().read(true);
            let open = run(fs.open(&owner, &sub, &options)).unwrap();
            let root = FileRef::new(
                fs.clone(),
                open,
                sub,
                owner.clone(),
                &options,
                &ReleaseQueue::new(),
            );
            Self { fs, root, owner }
        }
        fn backend(&self, rule: ExportRule) -> Backend {
            Backend(ScopedDir::new(self.root.clone(), cred(2002), rule).unwrap())
        }
        fn session(&self, rule: ExportRule) -> (ShareFs<Loop>, Rc<LinkState>) {
            let revoked = Rc::new(Cell::new(false));
            let link = Rc::new(LinkState {
                core: RefCell::new(ExportCore::new(
                    self.backend(rule),
                    rule,
                    100,
                    revoked.clone(),
                )),
                revoked,
                now: Cell::new(10),
                reader: RefCell::default(),
                replies: RefCell::default(),
                drop_reply: Cell::default(),
                hold_replies: Cell::default(),
            });
            let client = run(IpcShareTransport::connect(LoopStream(link.clone()), rule)).unwrap();
            (client, link)
        }
    }
    type Loop = IpcShareTransport<LoopStream>;
    struct LoopStream(Rc<LinkState>);
    struct LinkState {
        core: RefCell<ExportCore<Backend>>,
        revoked: Rc<Cell<bool>>,
        now: Cell<u64>,
        reader: RefCell<FrameReader>,
        replies: RefCell<VecDeque<u8>>,
        drop_reply: Cell<bool>,
        hold_replies: Cell<bool>,
    }
    impl ByteStream for LoopStream {
        fn poll_write(&self, _: &mut Context<'_>, bytes: &[u8]) -> Poll<Result<usize>> {
            let n = bytes.len().min(31);
            let mut core = self.0.core.borrow_mut();
            let now = self.0.now.get();
            let r = self.0.reader.borrow_mut().feed(&bytes[..n], |f| {
                let mut frames = core.receive(f, now);
                if !core.is_closed() {
                    frames.extend(core.dispatch(now));
                }
                for frame in frames {
                    self.0.replies.borrow_mut().extend(encode_frame(&frame)?);
                }
                Ok(())
            });
            Poll::Ready(r.map(|()| n))
        }
        fn poll_read(&self, _: &mut Context<'_>, b: &mut [u8]) -> Poll<Result<usize>> {
            if self.0.drop_reply.get() {
                return Poll::Ready(Ok(0));
            }
            if self.0.hold_replies.get() {
                return Poll::Pending;
            }
            let mut q = self.0.replies.borrow_mut();
            if q.is_empty() {
                return Poll::Pending;
            }
            let n = q.len().min(b.len()).min(23);
            for byte in &mut b[..n] {
                *byte = q.pop_front().unwrap();
            }
            Poll::Ready(Ok(n))
        }
    }
    fn create(fs: &ShareFs<Loop>, name: &str) -> (Entry, OpenRef) {
        let options = *OpenOptions::new().read(true).write(true).create_new(true);
        run(fs.create(&cred(2002), &fs.root(), name, 0o666, &options)).unwrap()
    }
    #[test]
    fn ipc_open_descriptions_recheck_inode_acl_and_export_revocation() {
        let s = Source::new();
        let (fs, link) = s.session(RW);
        let (entry, o) = create(&fs, "f");
        assert_eq!(entry.metadata.uid, 2002);
        assert_eq!(entry.metadata.gid, 1001);
        assert_eq!(entry.metadata.mode, 0o644);
        run(fs.write_at(&o, b"content", WriteAt::End)).unwrap();
        let mut out = [0; 7];
        assert_eq!(run(fs.read_at(&o, &mut out, 0)), Ok(7));
        assert_eq!(&out, b"content");
        let h = run(s.fs.lookup(&s.owner, s.root.handle(), "f"))
            .unwrap()
            .handle;
        run(s.fs.setattr(
            &cred(2002),
            &h,
            &SetAttr {
                mode: Some(0),
                ..Default::default()
            },
        ))
        .unwrap();
        assert_eq!(run(fs.open_metadata(&o)), Err(Errno::EACCES));
        assert_eq!(run(fs.read_at(&o, &mut out, 0)), Err(Errno::EBADF));
        let (_, open) = create(&fs, "other");
        link.revoked.set(true);
        assert_eq!(run(fs.set_len(&open, 1)), Err(Errno::EACCES));
        assert_eq!(
            run(fs.metadata(&cred(2002), &fs.root())),
            Err(Errno::EACCES)
        );
        assert_eq!(fs.provider().uncertain_writes(), 0);
    }
    #[test]
    fn existing_file_acl_changes_reach_open_and_default_acl_reaches_new_inode() {
        let s = Source::new();
        let mut acl = os_core::acl::Entries::access(0o700, None);
        acl.users.insert(2002, 7);
        acl.mask = Some(7);
        let acl = serde_json::to_vec(&acl).unwrap();
        let dir = s.root.handle();
        for name in [abi::ACL_ACCESS, abi::ACL_DEFAULT] {
            run(s
                .fs
                .setxattr(&s.owner, dir, name, &acl, XattrFlags::empty()))
            .unwrap();
        }
        let opts = *OpenOptions::new().read(true).write(true).create_new(true);
        let (entry, owner_fd) = run(s.fs.create(&s.owner, dir, "published", 0o666, &opts)).unwrap();
        let (fs, _) = s.session(RW);
        let remote = run(fs.lookup(&cred(2002), &fs.root(), "published")).unwrap();
        let open =
            run(fs.open(&cred(2002), &remote.handle, OpenOptions::new().read(true))).unwrap();
        assert!(run(fs.open_metadata(&open)).unwrap().acl);
        run(s.fs.removexattr(&s.owner, &entry.handle, abi::ACL_ACCESS)).unwrap();
        run(s.fs.setattr(
            &s.owner,
            &entry.handle,
            &SetAttr {
                mode: Some(0o600),
                ..Default::default()
            },
        ))
        .unwrap();
        assert_eq!(run(fs.read_at(&open, &mut [0; 1], 0)), Err(Errno::EACCES));
        let (fresh, _) = create(&fs, "new");
        assert!(fresh.metadata.acl);
        assert_eq!(
            (fresh.metadata.uid, fresh.metadata.gid, fresh.metadata.mode),
            (2002, 1001, 0o660)
        );
        run(s.fs.release(&owner_fd)).unwrap();
    }
    #[test]
    fn pinned_root_rename_replacement_symlink_and_moved_out_handle() {
        let s = Source::new();
        let (fs, _) = s.session(RW);
        let (f, open) = create(&fs, "kept");
        let base = &s.fs.root();
        run(s
            .fs
            .rename(&s.owner, base, "share", base, "moved", RenameFlags::empty()))
        .unwrap();
        run(s.fs.mkdir(&s.owner, base, "share", 0o755)).unwrap();
        assert_eq!(
            run(fs.lookup(&cred(2002), &fs.root(), "kept"))
                .unwrap()
                .handle
                .node,
            f.handle.node
        );
        run(s
            .fs
            .symlink(&s.owner, s.root.handle(), "escape", "../secret"))
        .unwrap();
        let link = run(fs.lookup(&cred(2002), &fs.root(), "escape"))
            .unwrap()
            .handle;
        assert_eq!(run(fs.read_link(&cred(2002), &link)), Err(Errno::ELOOP));
        assert_eq!(
            run(fs.open(&cred(2002), &link, OpenOptions::new().read(true))),
            Err(Errno::ELOOP)
        );
        run(s.fs.rename(
            &s.owner,
            s.root.handle(),
            "kept",
            base,
            "outside",
            RenameFlags::empty(),
        ))
        .unwrap();
        create(&fs, "kept");
        assert_eq!(
            run(fs.write_at(&open, b"changed", WriteAt::End)),
            Err(Errno::ESTALE)
        );
        assert_eq!(
            run(s.fs.lookup(&s.owner, base, "outside"))
                .unwrap()
                .metadata
                .size,
            0
        );
    }
    #[test]
    fn lease_releases_locks_and_all_128_retained_opens() {
        let s = Source::new();
        let (fs, link) = s.session(RW);
        let (_, open) = create(&fs, "f");
        run(fs.try_lock(
            &open,
            LockFamily::Flock,
            LockKind::Exclusive,
            LockRange::WHOLE,
        ))
        .unwrap();
        let (second, _) = s.session(RW);
        let h = run(second.lookup(&cred(2002), &second.root(), "f"))
            .unwrap()
            .handle;
        let opt = *OpenOptions::new().read(true);
        let competitor = run(second.open(&cred(2002), &h, &opt)).unwrap();
        assert_eq!(
            run(second.try_lock(
                &competitor,
                LockFamily::Flock,
                LockKind::Exclusive,
                LockRange::WHOLE
            )),
            Err(Errno::EAGAIN)
        );
        for _ in 1..128 {
            run(fs.open(&cred(2002), &h, &opt)).unwrap();
        }
        assert_eq!(run(fs.open(&cred(2002), &h, &opt)), Err(Errno::EMFILE));
        link.now.set(100);
        assert_eq!(run(fs.open_metadata(&open)), Err(Errno::ESTALE));
        assert_eq!(run(fs.open_metadata(&open)), Err(Errno::ESTALE));
        run(second.try_lock(
            &competitor,
            LockFamily::Flock,
            LockKind::Exclusive,
            LockRange::WHOLE,
        ))
        .unwrap();
    }
    #[test]
    fn read_only_and_noexec_mask_all_metadata_and_deny_mutation() {
        let s = Source::new();
        let (owner, _) = s.session(RW);
        let (file, _) = create(&owner, "executable");
        run(owner.setattr(
            &cred(2002),
            &file.handle,
            &SetAttr {
                mode: Some(0o777),
                ..Default::default()
            },
        ))
        .unwrap();
        let (ro, _) = s.session(ExportRule::default());
        let h = run(ro.lookup(&cred(2002), &ro.root(), "executable")).unwrap();
        assert_eq!(h.metadata.mode, 0o444);
        assert_eq!(
            run(ro.open(&cred(2002), &h.handle, OpenOptions::new().exec(true))),
            Err(Errno::EACCES)
        );
        assert_eq!(
            run(ro.unlink(&cred(2002), &ro.root(), "executable")),
            Err(Errno::EROFS)
        );
        let o = run(ro.open(&cred(2002), &h.handle, OpenOptions::new().read(true))).unwrap();
        assert_eq!(run(ro.open_metadata(&o)).unwrap().mode, 0o444);
    }
    #[test]
    fn dropped_replies_distinguish_inflight_mutations_from_confirmed_work() {
        for mutate in [false, true] {
            let s = Source::new();
            let (fs, link) = s.session(RW);
            let (_, o) = create(&fs, "f");
            run(fs.write_at(&o, b"confirmed", WriteAt::End)).unwrap();
            link.drop_reply.set(true);
            let error = if mutate {
                run(fs.write_at(&o, b"unconfirmed", WriteAt::End)).unwrap_err()
            } else {
                run(fs.read_at(&o, &mut [0; 2], 0)).unwrap_err()
            };
            assert_eq!(error, if mutate { Errno::EIO } else { Errno::ENOTCONN });
            assert_eq!(fs.provider().uncertain_writes(), u64::from(mutate));
        }
    }
    #[test]
    fn cancelling_after_the_server_opened_releases_the_unclaimed_description() {
        let s = Source::new();
        let (fs, link) = s.session(RW);
        let (entry, created) = create(&fs, "f");
        run(fs.release(&created)).unwrap();
        let opts = *OpenOptions::new().read(true);
        let cred = cred(2002);
        link.hold_replies.set(true);
        assert!(now_or_never(fs.open(&cred, &entry.handle, &opts)).is_none());
        link.hold_replies.set(false);
        for _ in 0..OSFS_MAX_HANDLES {
            run(fs.open(&cred, &entry.handle, &opts)).unwrap();
        }
        assert_eq!(
            run(fs.open(&cred, &entry.handle, &opts)),
            Err(Errno::EMFILE)
        );
    }
    #[cfg(unix)]
    #[test]
    fn real_unix_stream_round_trips_while_offline() {
        use std::io::{Read, Write};
        let (receiver, server_socket) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut publisher = std::fs::File::from(std::os::fd::OwnedFd::from(server_socket));
        let server = std::thread::spawn(move || {
            let source = Source::new();
            let mut core = ExportCore::new(source.backend(RW), RW, 100, Rc::new(Cell::new(false)));
            let mut framer = FrameReader::default();
            let mut buf = [0; 41];
            loop {
                let n = publisher.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                framer
                    .feed(&buf[..n], |frame| {
                        let replies = core.receive(frame, 1).into_iter().chain(core.dispatch(1));
                        for reply in replies {
                            publisher.write_all(&encode_frame(&reply)?).unwrap();
                        }
                        Ok(())
                    })
                    .unwrap();
            }
        });
        let fs = run(IpcShareTransport::connect(
            UnixByteStream::from(receiver),
            RW,
        ))
        .unwrap();
        let dir = run(fs.mkdir(&cred(2002), &fs.root(), "offline", 0o777)).unwrap();
        assert_eq!(dir.metadata.uid, 2002);
        assert_eq!(dir.handle.fs, fs.root().fs);
        drop(fs);
        server.join().unwrap();
    }
}
