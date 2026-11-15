//! Client-kernel glue for the cloud driver (#48): the browser host of its HTTP transport, the
//! instance's one session with the cloud filesystem service, and the descriptions this kernel
//! keeps for its processes' cloud files (`os_vfs::descriptions`).
//!
//! - **Session.** One per kernel (instance), connected with the first opening process's
//!   credential and renewed by the page's timer (`cloud_renew`, at least every minute, also
//!   while calls are pending). The resume secret and request tickets stay in this kernel.
//! - **Caller.** Every call names the process acting. Its credential (its current token: a
//!   fork's is its parent's; an exec replaces it) and PID are read from this kernel's process
//!   table before the driver awaits anything (`Transport::caller`); the driver keeps the
//!   opener's credential for cleanup.
//! - **Descriptions.** A process host numbers its descriptors; this kernel keeps what they
//!   refer to, by id, with the processes that hold each: inherited by a fork's child before it
//!   runs, kept across exec, let go at close and at exit. A blocking lock wait can be given
//!   up (`cloud_cancel`), which cancels its durable wait at the service.
//! - **Paths.** Only regular files the cloud tree serves are opened here (`inside`). Anything
//!   else, a directory, a device, `/proc`, a local mount, answers `{"fallback": true}`, and
//!   its caller keeps using the path calls, which coexist with v2 until #51 (contract §2.10).
use crate::{Kernel, State, fail};
use abi::{Batch, Call, Creds, Errno, Error};
use serde_json::json;
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::future::{Future, poll_fn};
use std::pin::{Pin, pin};
use std::rc::Rc;
use std::task::{Context, Poll, Waker};
use vfs::cloud::CloudFs;
use vfs::cloud_http::{Host, HttpTransport, Reply};
use vfs::descriptions::{Descriptions, Id};
use vfs::{
    BoxFuture, Cred, FileRef, Filesystem, Identity, LockFamily, LockKind, LockRange, OpenOptions,
    SeekFrom,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

type JsResult<T> = std::result::Result<T, JsValue>;

/// Whether the cloud tree serves `path` (absolute, as resolved so far). The rest belongs to
/// other filesystems: the instance's `/proc` and `/dev`, and the local mounts.
pub(crate) fn inside(path: &str) -> bool {
    const OTHERS: [&str; 6] = [
        "/proc",
        "/dev",
        "/sys",
        "/mnt/local",
        "/mnt/shared",
        "/opt/private",
    ];
    !OTHERS.iter().any(|other| {
        path == *other
            || path
                .strip_prefix(other)
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

/// A function the kernel Worker's script installs (web/kernel/client.js).
fn installed(name: &str) -> vfs::Result<(JsValue, js_sys::Function)> {
    let global: JsValue = js_sys::global().into();
    let function = js_sys::Reflect::get(&global, &JsValue::from_str(name))
        .ok()
        .and_then(|f| f.dyn_into::<js_sys::Function>().ok())
        .ok_or(Errno::EIO)?;
    Ok((global, function))
}
async fn promised(value: JsValue) -> vfs::Result<JsValue> {
    let promise = value
        .dyn_into::<js_sys::Promise>()
        .map_err(|_| Errno::EIO)?;
    JsFuture::from(promise).await.map_err(|_| Errno::EIO)
}

/// Which kernel process is currently driving the cloud session across a poll.
#[derive(Clone, Default)]
pub(crate) enum Actor {
    #[default]
    None,
    Process(u32),
    Exiting(u32, Option<String>),
}

struct Acted<F> {
    current: Rc<RefCell<Actor>>,
    actor: Actor,
    future: F,
}
impl<F: Future> Future for Acted<F> {
    type Output = F::Output;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        struct Reset<'a>(&'a RefCell<Actor>, Actor);
        impl Drop for Reset<'_> {
            fn drop(&mut self) {
                *self.0.borrow_mut() = std::mem::take(&mut self.1);
            }
        }
        // SAFETY: `current` and `actor` are not pinned; `future` remains structurally pinned.
        let this = unsafe { self.get_unchecked_mut() };
        let previous = std::mem::replace(&mut *this.current.borrow_mut(), this.actor.clone());
        let _reset = Reset(&this.current, previous);
        unsafe { Pin::new_unchecked(&mut this.future) }.poll(cx)
    }
}

/// The browser's half of the transport: `self.cloudFsPost(path, headers, body)` (a same-origin
/// fetch, which carries the `Origin` header), `cloudFsSleep(ms)` and `cloudFsTicket()`.
pub(crate) struct BrowserHost {
    state: Rc<RefCell<State>>,
    current: Rc<RefCell<Actor>>,
}
impl Host for BrowserHost {
    fn post<'a>(
        &'a self,
        path: &'a str,
        headers: Vec<(&'static str, String)>,
        body: Vec<u8>,
    ) -> BoxFuture<'a, Reply> {
        Box::pin(async move {
            let (global, post) = installed("cloudFsPost")?;
            let fields = js_sys::Object::new();
            for (name, value) in headers {
                js_sys::Reflect::set(&fields, &name.into(), &value.into())
                    .map_err(|_| Errno::EIO)?;
            }
            let body = js_sys::Uint8Array::from(body.as_slice());
            let answer = post
                .call3(&global, &path.into(), &fields, &body)
                .map_err(|_| Errno::EIO)?;
            let reply = promised(answer).await?;
            let status = js_sys::Reflect::get(&reply, &"status".into())
                .ok()
                .and_then(|status| status.as_f64())
                .ok_or(Errno::EIO)? as u16;
            let body = js_sys::Reflect::get(&reply, &"body".into()).map_err(|_| Errno::EIO)?;
            Ok(Reply {
                status,
                body: js_sys::Uint8Array::new(&body).to_vec(),
            })
        })
    }
    fn sleep(&self, millis: u32) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let (global, sleep) = installed("cloudFsSleep")?;
            let answer = sleep
                .call1(&global, &JsValue::from(millis))
                .map_err(|_| Errno::EIO)?;
            promised(answer).await.map(|_| ())
        })
    }
    fn ticket(&self) -> String {
        // A host without its ticket source cannot make a unique ticket; an empty one names
        // nothing at the service, so the call fails instead of colliding with another.
        installed("cloudFsTicket")
            .ok()
            .and_then(|(global, ticket)| ticket.call0(&global).ok())
            .and_then(|ticket| ticket.as_string())
            .unwrap_or_default()
    }
    fn caller(&self) -> vfs::Result<(String, Option<u32>)> {
        let state = self.state.borrow();
        match &*self.current.borrow() {
            Actor::None => Err(Errno::EACCES),
            Actor::Process(pid) => {
                let local = state
                    .processes
                    .get(pid)
                    .filter(|local| local.ended.is_none())
                    .ok_or(Errno::EACCES)?;
                Ok((local.token.clone(), Some(*pid)))
            }
            Actor::Exiting(pid, token) => {
                if let Some(token) = token {
                    return Ok((token.clone(), Some(*pid)));
                }
                let local = state.processes.get(pid).ok_or(Errno::EACCES)?;
                Ok((local.token.clone(), Some(*pid)))
            }
        }
    }
}

type Fs = CloudFs<HttpTransport<BrowserHost>>;

/// A wait that can be given up from another call.
#[derive(Default)]
struct Cancel {
    cancelled: Cell<bool>,
    waker: RefCell<Option<Waker>>,
}
impl Cancel {
    fn cancel(&self) {
        self.cancelled.set(true);
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }
    /// `future`'s answer, or EINTR once cancelled, dropping `future` (whose own guard then
    /// queues the cancellation its driver owes).
    async fn run<T>(&self, future: impl Future<Output = vfs::Result<T>>) -> vfs::Result<T> {
        let mut future = pin!(future);
        poll_fn(|context| {
            if self.cancelled.get() {
                return Poll::Ready(Err(Errno::EINTR));
            }
            if let Poll::Ready(value) = future.as_mut().poll(context) {
                return Poll::Ready(value);
            }
            *self.waker.borrow_mut() = Some(context.waker().clone());
            Poll::Pending
        })
        .await
    }
}

/// The instance's session with the cloud filesystem service, and its descriptions.
pub(crate) struct Cloud {
    fs: Rc<Fs>,
    table: Descriptions,
    waits: RefCell<HashMap<(u32, Id), Rc<Cancel>>>,
}

/// Connects the session once, for every caller that needs it meanwhile.
pub(crate) struct Connector {
    cloud: RefCell<Option<Rc<Cloud>>>,
    busy: Cell<bool>,
    waiters: RefCell<Vec<Waker>>,
    /// Monotonic description IDs across reconnects so old Workers can never alias new opens.
    next_id: Rc<Cell<Id>>,
}
impl Default for Connector {
    fn default() -> Self {
        Self {
            cloud: RefCell::default(),
            busy: Cell::default(),
            waiters: RefCell::default(),
            next_id: Rc::new(Cell::new(1)),
        }
    }
}
struct Connecting<'a>(&'a Connector);
impl Drop for Connecting<'_> {
    fn drop(&mut self) {
        self.0.busy.set(false);
        for waker in self.0.waiters.take() {
            waker.wake();
        }
    }
}
impl Connector {
    pub(crate) fn current(&self) -> Option<Rc<Cloud>> {
        self.cloud.borrow().clone()
    }
    async fn get(
        &self,
        state: &Rc<RefCell<State>>,
        current: &Rc<RefCell<Actor>>,
        token: &str,
    ) -> vfs::Result<Rc<Cloud>> {
        poll_fn(|context| {
            if self.cloud.borrow().is_some() || !self.busy.get() {
                Poll::Ready(())
            } else {
                self.waiters.borrow_mut().push(context.waker().clone());
                Poll::Pending
            }
        })
        .await;
        if let Some(cloud) = self.current() {
            return Ok(cloud);
        }
        self.busy.set(true);
        let _connecting = Connecting(self);
        let host = BrowserHost {
            state: state.clone(),
            current: current.clone(),
        };
        let fs = Rc::new(CloudFs::connect(HttpTransport(host), token.to_string()).await?);
        let cloud = Rc::new(Cloud {
            table: Descriptions::with_id_source(
                fs.clone() as Rc<dyn Filesystem>,
                self.next_id.clone(),
            ),
            fs,
            waits: RefCell::default(),
        });
        *self.cloud.borrow_mut() = Some(cloud.clone());
        Ok(cloud)
    }
}

fn errno(error: Errno) -> JsValue {
    fail(Error::from(error))
}
fn family(name: &str) -> JsResult<LockFamily> {
    match name {
        "flock" => Ok(LockFamily::Flock),
        "posix" => Ok(LockFamily::Posix),
        _ => Err(errno(Errno::EINVAL)),
    }
}
fn kind(name: &str) -> JsResult<LockKind> {
    match name {
        "shared" => Ok(LockKind::Shared),
        "exclusive" => Ok(LockKind::Exclusive),
        _ => Err(errno(Errno::EINVAL)),
    }
}
fn range(start: u64, end: Option<u64>) -> JsResult<LockRange> {
    LockRange::new(start, end).ok_or_else(|| errno(Errno::EINVAL))
}

fn parse_id(id: f64) -> JsResult<Id> {
    if !id.is_finite() || id < 1.0 || id.fract() != 0.0 || id > 9_007_199_254_740_991.0 {
        return Err(errno(Errno::EBADF));
    }
    Ok(id as Id)
}

impl Kernel {
    fn acted<F: Future>(&self, actor: Actor, future: F) -> Acted<F> {
        Acted {
            current: self.current.clone(),
            actor,
            future,
        }
    }
    fn drop_if_disconnected(&self, cloud: &Rc<Cloud>, err: Errno) {
        if err == Errno::ENOTCONN {
            let mut slot = self.cloud.cloud.borrow_mut();
            if slot
                .as_ref()
                .is_some_and(|current| Rc::ptr_eq(current, cloud))
            {
                *slot = None;
            }
        }
    }
    fn map_cloud<T>(&self, cloud: &Rc<Cloud>, result: vfs::Result<T>) -> JsResult<T> {
        if let Err(err) = result {
            self.drop_if_disconnected(cloud, err);
            return Err(errno(err));
        }
        Ok(result.expect("checked ok"))
    }
    /// The session, connecting it with `token` if there is none.
    async fn cloud(&self, token: &str) -> JsResult<Rc<Cloud>> {
        self.cloud
            .get(&self.state, &self.current, token)
            .await
            .map_err(errno)
    }
    /// The description `id` that `pid` of `host` holds.
    fn described(&self, pid: u32, host: &str, id: f64) -> JsResult<(Rc<Cloud>, FileRef)> {
        self.token(pid, host)?;
        let id = parse_id(id)?;
        let cloud = self.cloud.current().ok_or_else(|| errno(Errno::EBADF))?;
        let file = cloud.table.get(pid, id).map_err(errno)?;
        Ok((cloud, file))
    }
    fn is_live(&self, pid: u32) -> bool {
        self.state
            .borrow()
            .processes
            .get(&pid)
            .is_some_and(|local| local.ended.is_none())
    }
    /// Fetch and cache the acting process's authenticated identity from `/api/sys` on the
    /// authority (never `X-Registry`) so client-side traversal rules (such as protected
    /// symlinks in sticky directories) match the service's authority.
    async fn cloud_identity(&self, pid: u32, token: &str) -> JsResult<Identity> {
        if let Some(identity) = self.state.borrow().identities.get(token).cloned() {
            return Ok(identity);
        }
        let body = serde_json::to_vec(&Batch {
            calls: vec![Call::Getcreds],
            umask: None,
            sudo: false,
            pid: Some(pid),
            process: Some(token.to_string()),
        })
        .map_err(|error| fail(Error::because(Errno::EIO, error.to_string())))?;
        let host = BrowserHost {
            state: self.state.clone(),
            current: self.current.clone(),
        };
        let reply = host
            .post(
                "/api/sys",
                vec![("Content-Type", "application/json".to_string())],
                body,
            )
            .await
            .map_err(errno)?;
        if reply.status != 200 {
            let detail = String::from_utf8_lossy(&reply.body).into_owned();
            return Err(fail(Error::because(Errno::EIO, detail)));
        }
        let results: abi::Results = serde_json::from_slice(&reply.body)
            .map_err(|error| fail(Error::because(Errno::EIO, error.to_string())))?;
        let value = results
            .results
            .into_iter()
            .next()
            .ok_or_else(|| fail(Errno::EIO.into()))?
            .into_result()
            .map_err(fail)?;
        let creds: Creds = crate::from_value(value, "creds")?;
        let identity = Identity {
            id: creds.uid,
            group: creds.gid,
            groups: creds.groups.into_iter().collect(),
        };
        let mut state = self.state.borrow_mut();
        if state
            .processes
            .get(&pid)
            .is_some_and(|local| local.ended.is_none() && local.token == token)
        {
            state.identities.insert(token.to_string(), identity.clone());
            state.retain_spare();
        }
        Ok(identity)
    }
    /// What `pid`'s exit lets go of: its cloud descriptions and lock waits.
    pub(crate) async fn cloud_exited(&self, pid: u32, token: Option<String>) {
        let Some(cloud) = self.cloud.current() else {
            return;
        };
        cloud.waits.borrow_mut().retain(|(holder, _), wait| {
            if *holder == pid {
                wait.cancel();
            }
            *holder != pid
        });
        self.acted(Actor::Exiting(pid, token), async {
            cloud.table.exit(pid).await;
            let _ = cloud.table.flush().await;
            let _ = cloud.fs.drain().await;
        })
        .await;
    }
}

#[wasm_bindgen]
impl Kernel {
    /// open(2) of `path` (absolute, `..` and links unresolved) by the process `pid`: `flags` are
    /// Linux's, `mode` and `umask` its creation mode and mask. `{"id", "stat"}`, or
    /// `{"fallback": true}` for a path this kernel leaves to the path calls.
    pub async fn cloud_open(
        &self,
        pid: u32,
        host: &str,
        path: &str,
        flags: u32,
        mode: u16,
        umask: u16,
    ) -> JsResult<String> {
        let token = self.token(pid, host)?;
        let options = OpenOptions::from_flags(flags).map_err(errno)?;
        let nofollow = flags & abi::O_NOFOLLOW != 0;
        let directory = flags & abi::O_DIRECTORY != 0;
        if !inside(path) {
            return Ok(json!({ "fallback": true }).to_string());
        }
        let identity = self.cloud_identity(pid, &token).await?;
        if !self.is_live(pid) {
            return Err(errno(Errno::ESRCH));
        }
        let cred = Cred {
            identity,
            umask,
            token: Some(token.clone()),
        };
        let mut cloud = self.acted(Actor::Process(pid), self.cloud(&token)).await?;
        if !self.is_live(pid) {
            self.acted(Actor::Exiting(pid, Some(token)), async {
                let _ = cloud.table.flush().await;
                let _ = cloud.fs.drain().await;
            })
            .await;
            return Err(errno(Errno::ESRCH));
        }
        let open_result = self
            .acted(Actor::Process(pid), async {
                match cloud
                    .table
                    .open_with(
                        pid, &cred, path, &options, mode, nofollow, directory, &inside,
                    )
                    .await
                {
                    Err(Errno::ENOTCONN)
                        if cloud.table.is_empty() && cloud.fs.pending_cancellations() == 0 =>
                    {
                        self.drop_if_disconnected(&cloud, Errno::ENOTCONN);
                        cloud = self.cloud(&token).await?;
                        self.map_cloud(
                            &cloud,
                            cloud
                                .table
                                .open_with(
                                    pid, &cred, path, &options, mode, nofollow, directory, &inside,
                                )
                                .await,
                        )
                    }
                    other => self.map_cloud(&cloud, other),
                }
            })
            .await;
        if !self.is_live(pid) {
            self.acted(Actor::Exiting(pid, Some(token)), async {
                if let Ok(Some(opened)) = open_result {
                    let _ = cloud.table.close(pid, opened.id).await;
                }
                let _ = cloud.table.flush().await;
                let _ = cloud.fs.drain().await;
            })
            .await;
            return Err(errno(Errno::ESRCH));
        }
        let Some(opened) = open_result? else {
            return Ok(json!({ "fallback": true }).to_string());
        };
        let handle = opened.file.handle();
        let mut metadata = opened.entry.metadata.clone();
        if options.is_truncate() {
            metadata.size = 0;
        }
        let stat = vfs::stat::stat(&handle.fs, handle.node, &metadata);
        Ok(json!({ "id": opened.id, "stat": stat }).to_string())
    }

    /// read(2) (at the shared position) or pread(2) (at `offset`): at most `count` bytes.
    pub async fn cloud_read(
        &self,
        pid: u32,
        host: &str,
        id: f64,
        count: u32,
        offset: Option<u64>,
    ) -> JsResult<Vec<u8>> {
        let (cloud, file) = self.described(pid, host, id)?;
        let mut buf = vec![0; count.min(abi::remote_fs::DATA_MAX as u32) as usize];
        let read = self
            .acted(Actor::Process(pid), async {
                let res = match offset {
                    Some(offset) => file.read_at(&mut buf, offset).await,
                    None => file.read(&mut buf).await,
                };
                self.map_cloud(&cloud, res)
            })
            .await?;
        buf.truncate(read);
        Ok(buf)
    }

    /// write(2) (at the shared position, or the end with O_APPEND) or pwrite(2): how much went.
    pub async fn cloud_write(
        &self,
        pid: u32,
        host: &str,
        id: f64,
        data: Vec<u8>,
        offset: Option<u64>,
    ) -> JsResult<f64> {
        let (cloud, file) = self.described(pid, host, id)?;
        let written = self
            .acted(Actor::Process(pid), async {
                let res = match offset {
                    Some(offset) => file.write_at(&data, offset).await,
                    None => file.write(&data).await,
                };
                self.map_cloud(&cloud, res)
            })
            .await?;
        Ok(written as f64)
    }

    /// lseek(2): `whence` 0 (SET), 1 (CUR) or 2 (END, the size as the service has it now).
    pub async fn cloud_seek(
        &self,
        pid: u32,
        host: &str,
        id: f64,
        offset: i64,
        whence: u8,
    ) -> JsResult<u64> {
        let (cloud, file) = self.described(pid, host, id)?;
        let from = match whence {
            0 => SeekFrom::Start(u64::try_from(offset).map_err(|_| errno(Errno::EINVAL))?),
            1 => SeekFrom::Current(offset),
            2 => SeekFrom::End(offset),
            _ => return Err(errno(Errno::EINVAL)),
        };
        self.acted(Actor::Process(pid), async {
            self.map_cloud(&cloud, file.seek(from).await)
        })
        .await
    }

    /// fstat(2): the description's object as the service has it now, with its filesystem's
    /// `dev`, its inode and its live link count (0 once unlinked).
    pub async fn cloud_fstat(&self, pid: u32, host: &str, id: f64) -> JsResult<String> {
        let (cloud, file) = self.described(pid, host, id)?;
        let metadata = self
            .acted(Actor::Process(pid), async {
                self.map_cloud(&cloud, file.metadata().await)
            })
            .await?;
        let handle = file.handle();
        Ok(serde_json::to_string(&vfs::stat::stat(&handle.fs, handle.node, &metadata)).unwrap())
    }

    /// ftruncate(2).
    pub async fn cloud_truncate(&self, pid: u32, host: &str, id: f64, size: u64) -> JsResult<()> {
        let (cloud, file) = self.described(pid, host, id)?;
        self.acted(Actor::Process(pid), async {
            self.map_cloud(&cloud, file.set_len(size).await)
        })
        .await
    }

    /// fsync(2) or fdatasync(2): returns once the service's commit point covers the file.
    pub async fn cloud_sync(&self, pid: u32, host: &str, id: f64, data_only: bool) -> JsResult<()> {
        let (cloud, file) = self.described(pid, host, id)?;
        self.acted(Actor::Process(pid), async {
            let res = if data_only {
                file.sync_data().await
            } else {
                file.sync_all().await
            };
            self.map_cloud(&cloud, res)
        })
        .await
    }

    /// fcntl(F_SETFL) of O_APPEND, for every descriptor of the description.
    pub fn cloud_set_append(&self, pid: u32, host: &str, id: f64, append: bool) -> JsResult<()> {
        let (_cloud, file) = self.described(pid, host, id)?;
        file.set_append(append);
        Ok(())
    }

    /// fcntl(F_GETFL) of O_APPEND, for the description.
    pub fn cloud_append(&self, pid: u32, host: &str, id: f64) -> JsResult<bool> {
        let (_cloud, file) = self.described(pid, host, id)?;
        Ok(file.is_append())
    }

    /// fork(2): the child `child` holds the descriptions `ids` (a JSON array) its parent `pid`
    /// holds, before the child runs.
    pub fn cloud_inherit(&self, pid: u32, child: u32, ids: &str, host: &str) -> JsResult<()> {
        self.token(pid, host)?;
        self.token(child, host)?;
        let ids: Vec<Id> = crate::parse(ids, "descriptions")?;
        if ids.is_empty() {
            return Ok(());
        }
        let cloud = self.cloud.current().ok_or_else(|| errno(Errno::EBADF))?;
        cloud.table.inherit(pid, child, &ids).map_err(errno)
    }

    /// close(2) of the last of `pid`'s descriptors of `id`. The last holder's close releases
    /// the open reference, and its answer is close's.
    pub async fn cloud_close(&self, pid: u32, host: &str, id: f64) -> JsResult<()> {
        self.token(pid, host)?;
        let id = parse_id(id)?;
        let cloud = self.cloud.current().ok_or_else(|| errno(Errno::EBADF))?;
        self.acted(Actor::Process(pid), async {
            self.map_cloud(&cloud, cloud.table.close(pid, id).await)
        })
        .await
    }

    /// flock(2) (`family` "flock", the whole file) or an fcntl byte-range lock ("posix",
    /// `start`..`end`, `end` absent for the end of file): `kind` "shared" or "exclusive".
    /// Without `wait`, EAGAIN on a conflict (LOCK_NB, F_SETLK); with it, the call waits until
    /// granted (F_SETLKW), EDEADLK for an fcntl wait that would deadlock, EINTR if given up.
    #[allow(clippy::too_many_arguments)]
    pub async fn cloud_lock(
        &self,
        pid: u32,
        host: &str,
        id: f64,
        family: &str,
        kind: &str,
        start: u64,
        end: Option<u64>,
        wait: bool,
    ) -> JsResult<()> {
        let (cloud, file) = self.described(pid, host, id)?;
        let id = parse_id(id)?;
        let (family, kind) = (self::family(family)?, self::kind(kind)?);
        let range = range(start, end)?;
        self.acted(Actor::Process(pid), async {
            if !wait {
                return self.map_cloud(&cloud, file.try_lock(family, kind, range).await);
            }
            let key = (pid, id);
            let cancel = Rc::new(Cancel::default());
            if let Some(previous) = cloud.waits.borrow_mut().insert(key, cancel.clone()) {
                previous.cancel();
            }
            let result = cancel.run(file.lock(family, kind, range)).await;
            let mut waits = cloud.waits.borrow_mut();
            if waits
                .get(&key)
                .is_some_and(|current| Rc::ptr_eq(current, &cancel))
            {
                waits.remove(&key);
            }
            drop(waits);
            if result.is_err() {
                // A wait given up owes its cancellation now, not at the next call.
                let _ = cloud.fs.drain().await;
            }
            self.map_cloud(&cloud, result)
        })
        .await
    }

    /// Give up `pid`'s lock wait on `id`, as a signal interrupts F_SETLKW: it fails with EINTR.
    pub fn cloud_cancel(&self, pid: u32, host: &str, id: f64) -> JsResult<()> {
        self.token(pid, host)?;
        let id = parse_id(id)?;
        if let Some(cloud) = self.cloud.current()
            && let Some(wait) = cloud.waits.borrow_mut().remove(&(pid, id))
        {
            wait.cancel();
        }
        Ok(())
    }

    /// Unlock `family`'s locks of the description over the range.
    pub async fn cloud_unlock(
        &self,
        pid: u32,
        host: &str,
        id: f64,
        family: &str,
        start: u64,
        end: Option<u64>,
    ) -> JsResult<()> {
        let (cloud, file) = self.described(pid, host, id)?;
        let (family, range) = (self::family(family)?, range(start, end)?);
        self.acted(Actor::Process(pid), async {
            self.map_cloud(&cloud, file.unlock(family, range).await)
        })
        .await
    }

    /// F_GETLK: the first fcntl lock of another description that would conflict, or null.
    pub async fn cloud_test_lock(
        &self,
        pid: u32,
        host: &str,
        id: f64,
        kind: &str,
        start: u64,
        end: Option<u64>,
    ) -> JsResult<String> {
        let (cloud, file) = self.described(pid, host, id)?;
        let (kind, range) = (self::kind(kind)?, range(start, end)?);
        let conflict = self
            .acted(Actor::Process(pid), async {
                self.map_cloud(&cloud, file.test_lock(kind, range).await)
            })
            .await?;
        Ok(serde_json::to_string(&conflict).unwrap())
    }

    /// Renew the session's lease with a live process's credential (the page's timer, at least
    /// every minute, whatever calls are pending), draining deferred cleanup first. A session
    /// no process can renew any more, and that holds nothing, is forgotten: its lease ends it.
    pub async fn cloud_renew(&self) -> JsResult<()> {
        let Some(cloud) = self.cloud.current() else {
            return Ok(());
        };
        let tokens: Vec<String> = {
            let state = self.state.borrow();
            let mut tokens: Vec<String> = state
                .processes
                .values()
                .filter(|local| local.ended.is_none())
                .map(|local| local.token.clone())
                .collect();
            tokens.dedup();
            tokens
        };
        self.acted(Actor::None, async {
            let mut result = Err(Errno::EACCES);
            for token in tokens {
                let cred = Cred {
                    identity: Identity::guest(),
                    umask: 0,
                    token: Some(token),
                };
                result = cloud.fs.renew(&cred).await;
                if result.is_ok() || matches!(result, Err(Errno::ENOTCONN)) {
                    break;
                }
            }
            let _ = cloud.table.flush().await;
            if let Err(err) = result {
                self.drop_if_disconnected(&cloud, err);
                if cloud.table.is_empty() && cloud.fs.pending_cancellations() == 0 {
                    let mut slot = self.cloud.cloud.borrow_mut();
                    if slot
                        .as_ref()
                        .is_some_and(|current| Rc::ptr_eq(current, &cloud))
                    {
                        *slot = None;
                    }
                    return Ok(());
                }
            }
            result.map_err(errno)
        })
        .await
    }
}
