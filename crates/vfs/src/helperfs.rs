//! Linux helper filesystem driver (contract §2.5, §3, §6): portable VFS client over
//! [`abi::local_helper`]. Negotiates `Boundary::LocalHelper` v1 via `Hello`, attaches with explicit
//! host grant ceilings, forwards OS credentials and open references, chunks large reads/writes at
//! [`DATA_MAX`], polls/cancels blocking host locks, and maps lost lock-keeper reachability to
//! `ENOLCK` (`ENOTCONN` when provider unreachable, `EIO` for uncertain mutations/writes, `ENODEV`
//! on confirmed detached sessions).

use crate::{
    BoxFuture, Conflict, Cred, DirEntry, Entry, FILE_MAX, Filesystem, FsCapabilities, FsId, Handle,
    LockFamily, LockKind, LockRange, Metadata, OpenOptions, OpenRef, RenameFlags, Result, SetAttr,
    StatFs, Walked, WriteAt, Written, XattrFlags, check_component,
};
use abi::Errno;
use abi::contract::{Boundary, Hello};
use abi::local_helper::{
    AttachReply, CONTROL_MAX, Call, DATA_MAX, HelloReply, HelperGrant, LockOutcome, ReadReply,
    RenewReply, Request, VERSION, WireCred,
};
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::{Poll, Waker};

/// Typed outcome failure from a [`HelperTransport`] request, separating unacknowledged transport
/// uncertainty and HTTP `503` worker-pool overload from confirmed `HelperEngine` `Errno` refusals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HelperError {
    /// Transport drop, timeout (`ENOTCONN`/`ETIMEDOUT`), or corrupted HTTP `200` body (`EIO`);
    /// request execution is uncertain so in-flight open/lock tickets must still be cancelled.
    Transport(Errno),
    /// Helper HTTP worker pool was saturated (`503`); request never reached the engine.
    Overload,
    /// Confirmed protocol/engine refusal returned in an HTTP response (including genuine Linux
    /// `EBUSY` on an active submount, `EAGAIN` on `TryLock`, or `ENODEV` on a dead session).
    Engine(Errno),
}

pub type HelperFuture<'a, T> =
    Pin<Box<dyn Future<Output = std::result::Result<T, HelperError>> + 'a>>;

/// Reply returned by a [`HelperHttpHost`] POST request.
#[derive(Clone, Debug)]
pub struct HttpReply {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Host HTTP + timer primitives used by [`HttpHelperTransport`].
pub trait HelperHttpHost {
    /// POST a JSON request envelope to the local helper endpoint.
    /// Returning `Err` indicates no HTTP reply arrived (helper unreachable / connection dropped);
    /// non-200 HTTP statuses must be returned inside `Ok(HttpReply)`.
    fn post<'a>(&'a self, body: Vec<u8>) -> BoxFuture<'a, HttpReply>;
    fn sleep(&self, millis: u32) -> BoxFuture<'_, ()>;
    fn ticket(&self) -> String;
}

/// Portable transport connecting [`HelperFs`] to an `os-local-helper` service.
pub trait HelperTransport {
    fn request(&self, request: Request) -> HelperFuture<'_, Value>;
    fn pause(&self) -> BoxFuture<'_, ()>;
    fn ticket(&self) -> String;
}

/// [`HelperTransport`] implemented over any [`HelperHttpHost`].
pub struct HttpHelperTransport<H>(pub H);

impl<H> HttpHelperTransport<H> {
    pub fn host(&self) -> &H {
        &self.0
    }
}

fn parse_http_refusal(reply: &HttpReply) -> HelperError {
    let parsed_errno = serde_json::from_slice::<Value>(&reply.body)
        .ok()
        .and_then(|body| serde_json::from_value::<Errno>(body["errno"].clone()).ok());
    if reply.status == 503 {
        return match parsed_errno {
            Some(Errno::ENODEV) => HelperError::Engine(Errno::ENODEV),
            _ => HelperError::Overload,
        };
    }
    if reply.status == 408 {
        let errno = match parsed_errno {
            Some(e @ (Errno::ETIMEDOUT | Errno::ENOTCONN)) => e,
            _ => Errno::ETIMEDOUT,
        };
        return HelperError::Transport(errno);
    }
    let errno = parsed_errno.unwrap_or(match reply.status {
        401 | 403 => Errno::EACCES,
        413 => Errno::E2BIG,
        _ => Errno::EIO,
    });
    HelperError::Engine(errno)
}

impl<H: HelperHttpHost> HelperTransport for HttpHelperTransport<H> {
    fn request(&self, request: Request) -> HelperFuture<'_, Value> {
        Box::pin(async move {
            let body = serde_json::to_vec(&request).map_err(|_| HelperError::Engine(Errno::EIO))?;
            if body.len() > CONTROL_MAX {
                return Err(HelperError::Engine(Errno::E2BIG));
            }
            let reply = self.0.post(body).await.map_err(|e| match e {
                Errno::ETIMEDOUT => HelperError::Transport(Errno::ETIMEDOUT),
                _ => HelperError::Transport(Errno::ENOTCONN),
            })?;
            if reply.status != 200 {
                return Err(parse_http_refusal(&reply));
            }
            serde_json::from_slice(&reply.body).map_err(|_| HelperError::Transport(Errno::EIO))
        })
    }

    fn pause(&self) -> BoxFuture<'_, ()> {
        self.0.sleep(abi::local_helper::LOCK_POLL_MILLIS)
    }

    fn ticket(&self) -> String {
        self.0.ticket()
    }
}

#[derive(Clone)]
struct Pending {
    cred: WireCred,
    call: Call,
}

struct OpenEntry {
    record: OpenRef,
    cred: WireCred,
    closing: bool,
    cancelled_release: bool,
    drained: bool,
}

#[derive(Default)]
struct DrainLock {
    held: Cell<bool>,
    next_waiter: Cell<u64>,
    waiters: RefCell<BTreeMap<u64, Waker>>,
}

struct DrainGuard<'a>(&'a DrainLock);

struct DrainWait<'a> {
    lock: &'a DrainLock,
    id: u64,
}

impl Drop for DrainWait<'_> {
    fn drop(&mut self) {
        self.lock.waiters.borrow_mut().remove(&self.id);
    }
}

impl DrainLock {
    async fn lock(&self) -> DrainGuard<'_> {
        let id = self.next_waiter.get();
        self.next_waiter.set(id + 1);
        let _wait = DrainWait { lock: self, id };
        poll_fn(|context| {
            if self.held.replace(true) {
                self.waiters
                    .borrow_mut()
                    .insert(id, context.waker().clone());
                Poll::Pending
            } else {
                Poll::Ready(DrainGuard(self))
            }
        })
        .await
    }
}

impl Drop for DrainGuard<'_> {
    fn drop(&mut self) {
        self.0.held.set(false);
        for waker in self.0.waiters.take().into_values() {
            waker.wake();
        }
    }
}

struct CancelGuard<'a, T: HelperTransport> {
    fs: &'a HelperFs<T>,
    pending: Option<Pending>,
}

impl<T: HelperTransport> Drop for CancelGuard<'_, T> {
    fn drop(&mut self) {
        if let Some(pending) = self.pending.take() {
            self.fs.pending.borrow_mut().push_back(pending);
        }
    }
}

struct ReleaseGuard<'a, T: HelperTransport> {
    fs: &'a HelperFs<T>,
    id: u64,
    enqueue: Option<Pending>,
    completed: bool,
}

impl<T: HelperTransport> Drop for ReleaseGuard<'_, T> {
    fn drop(&mut self) {
        if !self.completed {
            if let Some(entry) = self.fs.opens.borrow_mut().get_mut(&self.id) {
                entry.cancelled_release = true;
            }
            if let Some(pending) = self.enqueue.take() {
                self.fs.pending.borrow_mut().push_back(pending);
            }
        }
    }
}

/// Portable VFS driver communicating with a Linux `os-local-helper` instance.
pub struct HelperFs<T> {
    transport: T,
    attach: AttachReply,
    opens: RefCell<HashMap<u64, OpenEntry>>,
    pending: RefCell<VecDeque<Pending>>,
    draining: DrainLock,
}

fn to_wire_cred(cred: &Cred) -> WireCred {
    WireCred {
        id: cred.identity.id,
        group: cred.identity.group,
        groups: cred.identity.groups.iter().copied().collect(),
        umask: cred.umask,
    }
}

fn map_nonlock_err(err: HelperError) -> Errno {
    match err {
        HelperError::Transport(Errno::EIO) => Errno::EIO,
        HelperError::Transport(_) | HelperError::Overload => Errno::ENOTCONN,
        HelperError::Engine(errno) => errno,
    }
}

fn map_uncertain_mutation_err(err: HelperError) -> Errno {
    match err {
        HelperError::Transport(_) => Errno::EIO,
        HelperError::Overload => Errno::ENOTCONN,
        HelperError::Engine(errno) => errno,
    }
}

fn map_lock_err(err: HelperError) -> Errno {
    match err {
        HelperError::Transport(_) | HelperError::Overload | HelperError::Engine(Errno::ENODEV) => {
            Errno::ENOLCK
        }
        HelperError::Engine(errno) => errno,
    }
}

fn uncertain_err(err: HelperError) -> bool {
    matches!(err, HelperError::Transport(_))
}

fn rejected_lock_before_queue(err: HelperError) -> bool {
    matches!(
        err,
        HelperError::Overload
            | HelperError::Engine(
                Errno::EACCES
                    | Errno::EBADF
                    | Errno::EINVAL
                    | Errno::EDEADLK
                    | Errno::EPROTONOSUPPORT
                    | Errno::ENOSPC
                    | Errno::ECANCELED
                    | Errno::ENODEV
            )
    )
}

impl<T: HelperTransport> HelperFs<T> {
    /// Negotiate `Boundary::LocalHelper` v1 via [`Request::Hello`] and attach to the helper's
    /// folder root with `grant`.
    pub async fn connect(
        transport: T,
        client_id: impl Into<String>,
        cred: &Cred,
        grant: HelperGrant,
    ) -> Result<Self> {
        let hello_raw = transport
            .request(Request::Hello(Hello {
                boundary: Boundary::LocalHelper,
                versions: vec![VERSION],
            }))
            .await
            .map_err(map_nonlock_err)?;
        let hello: HelloReply =
            serde_json::from_value(hello_raw).map_err(|_| Errno::EPROTONOSUPPORT)?;
        if hello.boundary != Boundary::LocalHelper
            || hello.version != VERSION
            || hello.handshake.is_empty()
        {
            return Err(Errno::EPROTONOSUPPORT);
        }

        let attach_raw = transport
            .request(Request::Attach {
                version: VERSION,
                client_id: client_id.into(),
                cred: to_wire_cred(cred),
                grant,
                handshake: hello.handshake,
            })
            .await
            .map_err(map_nonlock_err)?;
        let attach: AttachReply =
            serde_json::from_value(attach_raw).map_err(|_| Errno::EPROTONOSUPPORT)?;
        if attach.version != VERSION || attach.root.fs != attach.fs {
            return Err(Errno::EPROTONOSUPPORT);
        }

        Ok(Self {
            transport,
            attach,
            opens: RefCell::new(HashMap::new()),
            pending: RefCell::new(VecDeque::new()),
            draining: DrainLock::default(),
        })
    }

    pub fn pending_cancellations(&self) -> usize {
        self.pending.borrow().len()
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn session(&self) -> &str {
        &self.attach.session
    }

    pub fn grant(&self) -> HelperGrant {
        self.attach.grant
    }

    pub fn lease_seconds(&self) -> u64 {
        self.attach.lease_seconds
    }

    /// Renew the active session lease so held descriptors and locks remain live, and best-effort
    /// drain any deferred cleanup obligations while otherwise idle.
    pub async fn renew(&self) -> Result<RenewReply> {
        let raw = self
            .transport
            .request(Request::Renew {
                version: VERSION,
                session: self.attach.session.clone(),
            })
            .await
            .map_err(map_nonlock_err)?;
        let reply: RenewReply = serde_json::from_value(raw).map_err(|_| Errno::EIO)?;
        let _ = self.drain().await;
        Ok(reply)
    }

    /// Drain queued cleanup operations and explicitly detach the helper session on unmount.
    pub async fn detach(&self) -> Result<()> {
        let _ = self.drain().await;
        self.transport
            .request(Request::Detach {
                version: VERSION,
                session: self.attach.session.clone(),
            })
            .await
            .map(|_| ())
            .map_err(map_nonlock_err)
    }

    /// Flush deferred `CancelLock`, `CancelOpen`, and `Release` requests from previously dropped
    /// or transiently failed futures.
    pub async fn drain_raw(&self) -> std::result::Result<(), HelperError> {
        let _guard = self.draining.lock().await;
        while let Some(item) = { self.pending.borrow().front().cloned() } {
            let reply = self.send_raw(&item.cred, item.call.clone()).await;
            let _ = self.pending.borrow_mut().pop_front();
            match (&item.call, reply) {
                (_, Ok(_)) => {
                    if let Call::Release { open } = &item.call
                        && let Some(entry) = self.opens.borrow_mut().get_mut(&open.id)
                    {
                        entry.drained = true;
                    }
                }
                // Confirmed closed (`EBADF`) or session already gone (`ENODEV`) means server state
                // is already clean; do not treat transport loss (`Transport`/`Overload`) as clean.
                (
                    Call::Release { open },
                    Err(HelperError::Engine(Errno::EBADF | Errno::ENODEV)),
                ) => {
                    if let Some(entry) = self.opens.borrow_mut().get_mut(&open.id) {
                        entry.drained = true;
                    }
                }
                (_, Err(HelperError::Engine(Errno::ENODEV))) => {
                    while let Some(rest) = self.pending.borrow_mut().pop_front() {
                        if let Call::Release { open } = rest.call
                            && let Some(entry) = self.opens.borrow_mut().get_mut(&open.id)
                        {
                            entry.drained = true;
                        }
                    }
                    return Err(HelperError::Engine(Errno::ENODEV));
                }
                (
                    _,
                    Err(HelperError::Engine(
                        Errno::EBADF
                        | Errno::EINVAL
                        | Errno::EACCES
                        | Errno::EPROTONOSUPPORT
                        | Errno::E2BIG,
                    )),
                ) => {
                    if let Call::Release { open } = &item.call
                        && let Some(entry) = self.opens.borrow_mut().get_mut(&open.id)
                    {
                        entry.drained = true;
                    }
                }
                (_, Err(e)) => {
                    self.pending.borrow_mut().push_front(item);
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    pub async fn drain(&self) -> Result<()> {
        self.drain_raw().await.map_err(map_nonlock_err)
    }

    async fn send_raw(
        &self,
        cred: &WireCred,
        call: Call,
    ) -> std::result::Result<Value, HelperError> {
        self.transport
            .request(Request::Call {
                version: VERSION,
                session: self.attach.session.clone(),
                cred: cred.clone(),
                call,
            })
            .await
    }

    async fn call<R: DeserializeOwned>(&self, cred: &Cred, call: Call) -> Result<R> {
        self.drain_raw().await.map_err(map_nonlock_err)?;
        let wire = to_wire_cred(cred);
        let value = self.send_raw(&wire, call).await.map_err(map_nonlock_err)?;
        serde_json::from_value(value).map_err(|_| Errno::EIO)
    }

    async fn call_mutation<R: DeserializeOwned>(&self, cred: &Cred, call: Call) -> Result<R> {
        self.drain_raw().await.map_err(map_nonlock_err)?;
        let wire = to_wire_cred(cred);
        let value = self
            .send_raw(&wire, call)
            .await
            .map_err(map_uncertain_mutation_err)?;
        serde_json::from_value(value).map_err(|_| Errno::EIO)
    }

    fn open_cred(&self, open: &OpenRef) -> Result<WireCred> {
        if open.fs != self.attach.fs {
            return Err(Errno::EACCES);
        }
        let opens = self.opens.borrow();
        let entry = opens.get(&open.id).ok_or(Errno::EBADF)?;
        if entry.record != *open {
            return Err(Errno::EACCES);
        }
        if entry.closing {
            return Err(Errno::EBADF);
        }
        Ok(entry.cred.clone())
    }

    fn remember_open(&self, open: OpenRef, cred: WireCred) {
        self.opens.borrow_mut().insert(
            open.id,
            OpenEntry {
                record: open,
                cred,
                closing: false,
                cancelled_release: false,
                drained: false,
            },
        );
    }

    async fn opened<R: DeserializeOwned>(&self, open: &OpenRef, call: Call) -> Result<R> {
        let cred = self.open_cred(open)?;
        self.drain_raw().await.map_err(map_nonlock_err)?;
        let value = self.send_raw(&cred, call).await.map_err(map_nonlock_err)?;
        serde_json::from_value(value).map_err(|_| Errno::EIO)
    }

    async fn opened_mutation<R: DeserializeOwned>(&self, open: &OpenRef, call: Call) -> Result<R> {
        let cred = self.open_cred(open)?;
        self.drain_raw().await.map_err(map_nonlock_err)?;
        let value = self
            .send_raw(&cred, call)
            .await
            .map_err(map_uncertain_mutation_err)?;
        serde_json::from_value(value).map_err(|_| Errno::EIO)
    }

    async fn opened_lock<R: DeserializeOwned>(&self, open: &OpenRef, call: Call) -> Result<R> {
        let cred = self.open_cred(open)?;
        self.drain_raw().await.map_err(map_lock_err)?;
        let value = self.send_raw(&cred, call).await.map_err(map_lock_err)?;
        serde_json::from_value(value).map_err(|_| Errno::EIO)
    }

    fn check_handle_fs(&self, handle: &Handle) -> Result<()> {
        if handle.fs != self.attach.fs {
            Err(Errno::EACCES)
        } else {
            Ok(())
        }
    }
}

impl<T: HelperTransport> Filesystem for HelperFs<T> {
    fn id(&self) -> &FsId {
        &self.attach.fs
    }

    fn capabilities(&self) -> FsCapabilities {
        self.attach.capabilities
    }

    fn root(&self) -> Handle {
        self.attach.root.clone()
    }

    fn lookup<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(async move {
            self.check_handle_fs(dir)?;
            check_component(name)?;
            self.call(
                cred,
                Call::Lookup {
                    dir: dir.clone(),
                    name: name.to_owned(),
                },
            )
            .await
        })
    }

    fn walk<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        names: &'a [String],
    ) -> BoxFuture<'a, Walked> {
        Box::pin(async move {
            self.check_handle_fs(dir)?;
            for name in names {
                check_component(name)?;
            }
            self.call(
                cred,
                Call::Walk {
                    dir: dir.clone(),
                    names: names.to_vec(),
                },
            )
            .await
        })
    }

    fn parent<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
    ) -> BoxFuture<'a, Option<(Entry, String)>> {
        Box::pin(async move {
            self.check_handle_fs(dir)?;
            self.call(cred, Call::Parent { dir: dir.clone() }).await
        })
    }

    fn metadata<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Metadata> {
        Box::pin(async move {
            self.check_handle_fs(handle)?;
            self.call(
                cred,
                Call::Metadata {
                    handle: handle.clone(),
                },
            )
            .await
        })
    }

    fn setattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        attr: &'a SetAttr,
    ) -> BoxFuture<'a, Metadata> {
        Box::pin(async move {
            self.check_handle_fs(handle)?;
            self.call_mutation(
                cred,
                Call::Setattr {
                    handle: handle.clone(),
                    attr: attr.clone(),
                },
            )
            .await
        })
    }

    fn read_dir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle) -> BoxFuture<'a, Vec<DirEntry>> {
        Box::pin(async move {
            self.check_handle_fs(dir)?;
            self.call(cred, Call::ReadDir { dir: dir.clone() }).await
        })
    }

    fn read_link<'a>(&'a self, cred: &'a Cred, link: &'a Handle) -> BoxFuture<'a, String> {
        Box::pin(async move {
            self.check_handle_fs(link)?;
            self.call(cred, Call::ReadLink { link: link.clone() }).await
        })
    }

    fn create<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
        options: &'a OpenOptions,
    ) -> BoxFuture<'a, (Entry, OpenRef)> {
        Box::pin(async move {
            self.check_handle_fs(dir)?;
            check_component(name)?;
            self.drain_raw().await.map_err(map_nonlock_err)?;
            let wire = to_wire_cred(cred);
            let ticket = self.transport.ticket();
            let mut guard = CancelGuard {
                fs: self,
                pending: Some(Pending {
                    cred: wire.clone(),
                    call: Call::CancelOpen {
                        ticket: ticket.clone(),
                    },
                }),
            };
            let reply = self
                .send_raw(
                    &wire,
                    Call::Create {
                        dir: dir.clone(),
                        name: name.to_owned(),
                        mode,
                        options: *options,
                        ticket,
                    },
                )
                .await;
            match reply {
                Ok(value) => {
                    let (entry, open): (Entry, OpenRef) =
                        serde_json::from_value(value).map_err(|_| Errno::EIO)?;
                    self.remember_open(open.clone(), wire);
                    guard.pending = None;
                    Ok((entry, open))
                }
                Err(raw_err) => {
                    if !uncertain_err(raw_err) {
                        guard.pending = None;
                    }
                    Err(map_nonlock_err(raw_err))
                }
            }
        })
    }

    fn mkdir<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(async move {
            self.check_handle_fs(dir)?;
            check_component(name)?;
            self.call_mutation(
                cred,
                Call::Mkdir {
                    dir: dir.clone(),
                    name: name.to_owned(),
                    mode,
                },
            )
            .await
        })
    }

    fn mknod<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
        rdev: &'a str,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(async move {
            self.check_handle_fs(dir)?;
            check_component(name)?;
            self.call_mutation(
                cred,
                Call::Mknod {
                    dir: dir.clone(),
                    name: name.to_owned(),
                    mode,
                    rdev: rdev.to_owned(),
                },
            )
            .await
        })
    }

    fn symlink<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        target: &'a str,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(async move {
            self.check_handle_fs(dir)?;
            check_component(name)?;
            self.call_mutation(
                cred,
                Call::Symlink {
                    dir: dir.clone(),
                    name: name.to_owned(),
                    target: target.to_owned(),
                },
            )
            .await
        })
    }

    fn link<'a>(
        &'a self,
        cred: &'a Cred,
        target: &'a Handle,
        dir: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(async move {
            self.check_handle_fs(target)?;
            self.check_handle_fs(dir)?;
            check_component(name)?;
            self.call_mutation(
                cred,
                Call::Link {
                    target: target.clone(),
                    dir: dir.clone(),
                    name: name.to_owned(),
                },
            )
            .await
        })
    }

    fn unlink<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.check_handle_fs(dir)?;
            check_component(name)?;
            let _: Value = self
                .call_mutation(
                    cred,
                    Call::Unlink {
                        dir: dir.clone(),
                        name: name.to_owned(),
                    },
                )
                .await?;
            Ok(())
        })
    }

    fn rmdir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.check_handle_fs(dir)?;
            check_component(name)?;
            let _: Value = self
                .call_mutation(
                    cred,
                    Call::Rmdir {
                        dir: dir.clone(),
                        name: name.to_owned(),
                    },
                )
                .await?;
            Ok(())
        })
    }

    fn rename<'a>(
        &'a self,
        cred: &'a Cred,
        from_dir: &'a Handle,
        from: &'a str,
        to_dir: &'a Handle,
        to: &'a str,
        flags: RenameFlags,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.check_handle_fs(from_dir)?;
            self.check_handle_fs(to_dir)?;
            check_component(from)?;
            check_component(to)?;
            let _: Value = self
                .call_mutation(
                    cred,
                    Call::Rename {
                        from_dir: from_dir.clone(),
                        from: from.to_owned(),
                        to_dir: to_dir.clone(),
                        to: to.to_owned(),
                        flags,
                    },
                )
                .await?;
            Ok(())
        })
    }

    fn getxattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(async move {
            self.check_handle_fs(handle)?;
            let bytes: abi::Bytes = self
                .call(
                    cred,
                    Call::Getxattr {
                        handle: handle.clone(),
                        name: name.to_owned(),
                    },
                )
                .await?;
            Ok(bytes.0)
        })
    }

    fn setxattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
        value: &'a [u8],
        flags: XattrFlags,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.check_handle_fs(handle)?;
            let _: Value = self
                .call_mutation(
                    cred,
                    Call::Setxattr {
                        handle: handle.clone(),
                        name: name.to_owned(),
                        value: abi::Bytes(value.to_vec()),
                        flags,
                    },
                )
                .await?;
            Ok(())
        })
    }

    fn listxattr<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Vec<String>> {
        Box::pin(async move {
            self.check_handle_fs(handle)?;
            self.call(
                cred,
                Call::Listxattr {
                    handle: handle.clone(),
                },
            )
            .await
        })
    }

    fn removexattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.check_handle_fs(handle)?;
            let _: Value = self
                .call_mutation(
                    cred,
                    Call::Removexattr {
                        handle: handle.clone(),
                        name: name.to_owned(),
                    },
                )
                .await?;
            Ok(())
        })
    }

    fn statfs<'a>(&'a self, cred: &'a Cred) -> BoxFuture<'a, StatFs> {
        Box::pin(async move { self.call(cred, Call::Statfs).await })
    }

    fn open<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        options: &'a OpenOptions,
    ) -> BoxFuture<'a, OpenRef> {
        Box::pin(async move {
            self.check_handle_fs(handle)?;
            self.drain_raw().await.map_err(map_nonlock_err)?;
            let wire = to_wire_cred(cred);
            let ticket = self.transport.ticket();
            let mut guard = CancelGuard {
                fs: self,
                pending: Some(Pending {
                    cred: wire.clone(),
                    call: Call::CancelOpen {
                        ticket: ticket.clone(),
                    },
                }),
            };
            let reply = self
                .send_raw(
                    &wire,
                    Call::Open {
                        handle: handle.clone(),
                        options: *options,
                        ticket,
                    },
                )
                .await;
            match reply {
                Ok(value) => {
                    let open: OpenRef = serde_json::from_value(value).map_err(|_| Errno::EIO)?;
                    self.remember_open(open.clone(), wire);
                    guard.pending = None;
                    Ok(open)
                }
                Err(raw_err) => {
                    if !uncertain_err(raw_err) {
                        guard.pending = None;
                    }
                    Err(map_nonlock_err(raw_err))
                }
            }
        })
    }

    fn open_metadata<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, Metadata> {
        Box::pin(async move {
            self.opened(open, Call::OpenMetadata { open: open.clone() })
                .await
        })
    }

    fn read_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a mut [u8],
        offset: u64,
    ) -> BoxFuture<'a, usize> {
        Box::pin(async move {
            if offset > FILE_MAX || (buf.len() as u64) > FILE_MAX - offset {
                return Err(Errno::EINVAL);
            }
            let count = (buf.len() as u64).min(DATA_MAX);
            let reply: ReadReply = self
                .opened(
                    open,
                    Call::ReadAt {
                        open: open.clone(),
                        offset,
                        count,
                    },
                )
                .await?;
            if reply.data.0.len() > count as usize {
                return Err(Errno::EIO);
            }
            let n = reply.data.0.len();
            buf[..n].copy_from_slice(&reply.data.0);
            Ok(n)
        })
    }

    fn write_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a [u8],
        at: WriteAt,
    ) -> BoxFuture<'a, Written> {
        Box::pin(async move {
            let room = match at {
                WriteAt::Offset(offset) if offset < FILE_MAX => FILE_MAX - offset,
                _ => u64::MAX,
            };
            let length = (buf.len() as u64).min(DATA_MAX).min(room);
            self.opened_mutation(
                open,
                Call::WriteAt {
                    open: open.clone(),
                    data: abi::Bytes(buf[..length as usize].to_vec()),
                    at,
                },
            )
            .await
        })
    }

    fn set_len<'a>(&'a self, open: &'a OpenRef, size: u64) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let _: Value = self
                .opened_mutation(
                    open,
                    Call::SetLen {
                        open: open.clone(),
                        size,
                    },
                )
                .await?;
            Ok(())
        })
    }

    fn sync_all<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let _: Value = self
                .opened_mutation(
                    open,
                    Call::Sync {
                        open: open.clone(),
                        data_only: false,
                    },
                )
                .await?;
            Ok(())
        })
    }

    fn sync_data<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let _: Value = self
                .opened_mutation(
                    open,
                    Call::Sync {
                        open: open.clone(),
                        data_only: true,
                    },
                )
                .await?;
            Ok(())
        })
    }

    fn lock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let cred = self.open_cred(open)?;
            self.drain_raw().await.map_err(map_lock_err)?;
            let ticket = self.transport.ticket();
            let mut guard = CancelGuard {
                fs: self,
                pending: Some(Pending {
                    cred: cred.clone(),
                    call: Call::CancelLock {
                        open: open.clone(),
                        ticket: ticket.clone(),
                    },
                }),
            };
            let mut first = true;
            loop {
                let raw_reply = self
                    .send_raw(
                        &cred,
                        Call::Lock {
                            open: open.clone(),
                            family,
                            kind,
                            range,
                            ticket: ticket.clone(),
                        },
                    )
                    .await;
                if first {
                    if let Err(raw_err) = &raw_reply
                        && rejected_lock_before_queue(*raw_err)
                    {
                        guard.pending = None;
                    }
                    first = false;
                }
                let value = raw_reply.map_err(map_lock_err)?;
                let outcome: LockOutcome = serde_json::from_value(value).map_err(|_| Errno::EIO)?;
                if outcome == LockOutcome::Acquired {
                    guard.pending = None;
                    return Ok(());
                }
                self.transport.pause().await.map_err(|_| Errno::ENOLCK)?;
            }
        })
    }

    fn try_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let _: Value = self
                .opened_lock(
                    open,
                    Call::TryLock {
                        open: open.clone(),
                        family,
                        kind,
                        range,
                    },
                )
                .await?;
            Ok(())
        })
    }

    fn unlock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let _: Value = self
                .opened_lock(
                    open,
                    Call::Unlock {
                        open: open.clone(),
                        family,
                        range,
                    },
                )
                .await?;
            Ok(())
        })
    }

    fn test_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, Option<Conflict>> {
        Box::pin(async move {
            self.opened_lock(
                open,
                Call::TestLock {
                    open: open.clone(),
                    kind,
                    range,
                },
            )
            .await
        })
    }

    fn release<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if open.fs != self.attach.fs {
                return Err(Errno::EACCES);
            }
            enum ReleaseAction {
                First(WireCred),
                WaitDrained,
                AlreadyDrained(bool),
            }
            let action = {
                let mut opens = self.opens.borrow_mut();
                let entry = opens.get_mut(&open.id).ok_or(Errno::EBADF)?;
                if entry.record != *open {
                    return Err(Errno::EACCES);
                }
                if entry.drained {
                    let was_cancelled = entry.cancelled_release;
                    opens.remove(&open.id);
                    ReleaseAction::AlreadyDrained(was_cancelled)
                } else {
                    let action = if entry.closing {
                        ReleaseAction::WaitDrained
                    } else {
                        entry.closing = true;
                        ReleaseAction::First(entry.cred.clone())
                    };
                    entry.cancelled_release = false;
                    action
                }
            };
            match action {
                ReleaseAction::AlreadyDrained(was_cancelled) => {
                    if was_cancelled {
                        self.drain_raw().await.map_err(map_nonlock_err)
                    } else {
                        Err(Errno::EBADF)
                    }
                }
                ReleaseAction::First(cred) => {
                    let mut guard = ReleaseGuard {
                        fs: self,
                        id: open.id,
                        enqueue: Some(Pending {
                            cred: cred.clone(),
                            call: Call::Release { open: open.clone() },
                        }),
                        completed: false,
                    };
                    self.drain_raw().await.map_err(map_nonlock_err)?;
                    let sent = {
                        let _lock = self.draining.lock().await;
                        self.send_raw(&cred, Call::Release { open: open.clone() })
                            .await
                    };
                    match sent {
                        Ok(_) => {
                            self.opens.borrow_mut().remove(&open.id);
                            guard.enqueue = None;
                            guard.completed = true;
                            Ok(())
                        }
                        Err(HelperError::Engine(e @ (Errno::ENODEV | Errno::EBADF))) => {
                            self.opens.borrow_mut().remove(&open.id);
                            guard.enqueue = None;
                            guard.completed = true;
                            Err(e)
                        }
                        Err(raw_err) => Err(map_nonlock_err(raw_err)),
                    }
                }
                ReleaseAction::WaitDrained => {
                    let mut guard = ReleaseGuard {
                        fs: self,
                        id: open.id,
                        enqueue: None,
                        completed: false,
                    };
                    let drained = self.drain_raw().await;
                    match drained {
                        Ok(()) => {
                            guard.completed = true;
                            self.opens.borrow_mut().remove(&open.id);
                            Ok(())
                        }
                        Err(HelperError::Engine(e @ (Errno::ENODEV | Errno::EBADF))) => {
                            guard.completed = true;
                            self.opens.borrow_mut().remove(&open.id);
                            Err(e)
                        }
                        Err(raw_err) => {
                            if self
                                .opens
                                .borrow()
                                .get(&open.id)
                                .is_some_and(|entry| entry.drained)
                            {
                                guard.completed = true;
                                self.opens.borrow_mut().remove(&open.id);
                                return Ok(());
                            }
                            Err(map_nonlock_err(raw_err))
                        }
                    }
                }
            }
        })
    }
}
