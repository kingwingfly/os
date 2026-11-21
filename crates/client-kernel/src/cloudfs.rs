//! Client-kernel root `/` cloud filesystem driver (`CloudFs` v2 + cookie page session bridge +
//! seeded offline `MemFs` fallback for headless tests).
//!
//! Legacy `Descriptions::open_with`, `inside()`, and `{"fallback": true}` are retired completely
//! (#51, contract §2.3, §2.10, §2.12). Every `/` operation runs through [`os_vfs::Vfs`] as the
//! root [`Filesystem`] driver.

use crate::{Kernel, State, fail};
use abi::contract::FsCapabilities;
use abi::remote_fs as wire;
use abi::{
    BATCH_MAX, Batch, Bytes, Call, Errno, Error, FdRef, ProcState, Results, Return, Stat, Time,
};
use serde_json::Value;
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet, VecDeque};
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};
use vfs::cloud::{CloudFs, Transport};
use vfs::cloud_http::{Host, HttpTransport, PageTarget, Reply};
use vfs::memfs::MemFs;
use vfs::{
    Access, BoxFuture, Conflict, Cred, DirEntry, Entry, FILE_MAX, FileType, Filesystem, FsId,
    Handle, Identity, LockFamily, LockKind, LockRange, Metadata, NodeId, OpenOptions, OpenRef,
    RenameFlags, SetAttr, StatFs, Stop, Timespec, Walked, WriteAt, Written, XattrFlags,
    check_component, now_or_never, profiles,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

type JsResult<T> = std::result::Result<T, JsValue>;

pub(crate) const SEED_DIRS: &[(&str, u16)] = &[
    ("/", 0o755),
    ("/usr", 0o755),
    ("/sys", 0o555),
    ("/proc", 0o555),
    ("/dev", 0o755),
    ("/dev/pts", 0o755),
    ("/dev/present", 0o755),
    ("/dev/snd", 0o755),
    ("/etc", 0o755),
    ("/boot", 0o755),
    ("/home", 0o755),
    ("/mnt", 0o755),
    ("/mnt/local", 0o755),
    ("/mnt/shared", 0o755),
    ("/opt", 0o755),
    ("/opt/private", 0o755),
    ("/root", 0o700),
    ("/run", 0o755),
    ("/srv", 0o755),
    ("/tmp", 0o1777),
    ("/var", 0o755),
    ("/var/tmp", 0o1777),
    ("/var/log", 0o755),
    ("/var/lib", 0o755),
    ("/var/cache", 0o755),
];

pub(crate) const SEED_SYMLINKS: &[(&str, &str)] = &[
    ("/bin", "usr/bin"),
    ("/sbin", "usr/bin"),
    ("/lib", "usr/lib"),
    ("/lib64", "usr/lib"),
];

fn is_local_carrier_path(path: &str) -> bool {
    matches!(
        path,
        "/" | "/usr"
            | "/sys"
            | "/proc"
            | "/dev"
            | "/dev/pts"
            | "/run"
            | "/tmp"
            | "/mnt"
            | "/mnt/local"
            | "/mnt/shared"
            | "/opt"
            | "/opt/private"
            | "/bin"
            | "/sbin"
            | "/lib"
            | "/lib64"
    )
}

fn is_mounted_carrier_dir(path: &str) -> bool {
    matches!(
        path,
        "/usr" | "/proc" | "/dev" | "/run" | "/tmp" | "/mnt/local" | "/mnt/shared" | "/opt/private"
    )
}

fn cred_permits_exec(meta: &Metadata, cred: &Cred) -> bool {
    if cred.identity.id == 0 {
        return true;
    }
    if cred.identity.id == meta.uid {
        return (meta.mode & 0o100) != 0;
    }
    if cred.identity.group == meta.gid || cred.identity.groups.contains(&meta.gid) {
        return (meta.mode & 0o010) != 0;
    }
    (meta.mode & 0o001) != 0
}

#[derive(Default)]
struct PageLock {
    locked: Cell<bool>,
    waiters: RefCell<VecDeque<Waker>>,
}

struct PageLockGuard(Rc<PageLock>);

impl Drop for PageLockGuard {
    fn drop(&mut self) {
        self.0.locked.set(false);
        if let Some(w) = self.0.waiters.borrow_mut().pop_front() {
            w.wake();
        }
    }
}

async fn lock_page(lock: Rc<PageLock>) -> PageLockGuard {
    poll_fn(|cx| {
        if !lock.locked.get() {
            lock.locked.set(true);
            Poll::Ready(())
        } else {
            let mut waiters = lock.waiters.borrow_mut();
            if !waiters.iter().any(|w| w.will_wake(cx.waker())) {
                waiters.push_back(cx.waker().clone());
            }
            Poll::Pending
        }
    })
    .await;
    PageLockGuard(lock)
}

pub(crate) fn installed(name: &str) -> vfs::Result<(JsValue, js_sys::Function)> {
    let global: JsValue = js_sys::global().into();
    let function = js_sys::Reflect::get(&global, &JsValue::from_str(name))
        .ok()
        .and_then(|f| f.dyn_into::<js_sys::Function>().ok())
        .ok_or(Errno::EIO)?;
    Ok((global, function))
}

pub(crate) async fn promised(value: JsValue) -> vfs::Result<JsValue> {
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
    Ephemeral(String),
}

pub(crate) struct Acted<F> {
    pub(crate) current: Rc<RefCell<Actor>>,
    pub(crate) actor: Actor,
    pub(crate) future: F,
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

/// The browser's half of the transport: `self.cloudFsPost(path, headers, body)`,
/// `cloudFsSleep(ms)` and `cloudFsTicket()`.
pub(crate) struct BrowserHost {
    pub(crate) state: Rc<RefCell<State>>,
    pub(crate) current: Rc<RefCell<Actor>>,
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
            let mut has_instance = false;
            for (name, value) in headers {
                if name.eq_ignore_ascii_case("X-OS-Instance") {
                    has_instance = true;
                }
                js_sys::Reflect::set(&fields, &name.into(), &value.into())
                    .map_err(|_| Errno::EIO)?;
            }
            if !has_instance {
                let inst_id = self.state.borrow().instance_id.clone();
                if !inst_id.is_empty() {
                    js_sys::Reflect::set(&fields, &"X-OS-Instance".into(), &inst_id.into())
                        .map_err(|_| Errno::EIO)?;
                }
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
            let bytes = js_sys::Uint8Array::new(&body).to_vec();
            if status != 200
                && let Ok(val) = serde_json::from_slice::<Value>(&bytes)
                && let Some(code) = val["errno"].as_str()
                && let Ok(parsed) = serde_json::from_value::<Errno>(Value::String(code.to_string()))
            {
                let detail = val["detail"]
                    .as_str()
                    .or_else(|| val["error"].as_str())
                    .filter(|s| !s.is_empty());
                record_last_page_error(parsed, detail);
            }
            Ok(Reply {
                status,
                body: bytes,
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
                let proc = state
                    .table
                    .proc(*pid)
                    .filter(|p| p.state != ProcState::Zombie)
                    .ok_or(Errno::EACCES)?;
                let rem = proc.cred.remote.as_ref().ok_or(Errno::EACCES)?;
                if !proc.cred.cloud_access || !rem.cloud_access {
                    return Err(Errno::EACCES);
                }
                Ok((rem.token.clone(), Some(*pid)))
            }
            Actor::Exiting(pid, token) => {
                if let Some(token) = token {
                    return Ok((token.clone(), Some(*pid)));
                }
                let proc = state.table.proc(*pid).ok_or(Errno::EACCES)?;
                let rem = proc.cred.remote.as_ref().ok_or(Errno::EACCES)?;
                Ok((rem.token.clone(), Some(*pid)))
            }
            Actor::Ephemeral(token) => Ok((token.clone(), None)),
        }
    }
}

type Fs = CloudFs<HttpTransport<BrowserHost>>;

pub(crate) struct Cloud {
    pub(crate) fs: Rc<Fs>,
    pub(crate) live_opens: Cell<usize>,
    pub(crate) session_uid: u32,
}

/// Connects one `CloudFs` session per account/guest UID so cookie/account rotations (e.g.
/// guest->guest or guest->root) never mismatch `vfs_sessions.ns` while existing opens stay alive.
#[derive(Default)]
pub(crate) struct ConnectorInner {
    pub(crate) clouds: RefCell<HashMap<u32, Rc<Cloud>>>,
    latest_uid: Cell<Option<u32>>,
    busy: Cell<bool>,
    waiters: RefCell<Vec<Waker>>,
}

#[derive(Clone, Default)]
pub(crate) struct Connector(Rc<ConnectorInner>);

struct Connecting<'a>(&'a ConnectorInner);
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
        let clouds = self.0.clouds.borrow();
        if let Some(uid) = self.0.latest_uid.get()
            && let Some(c) = clouds.get(&uid)
        {
            return Some(Rc::clone(c));
        }
        clouds.values().next().cloned()
    }

    pub(crate) fn all(&self) -> Vec<Rc<Cloud>> {
        self.0.clouds.borrow().values().cloned().collect()
    }

    pub(crate) fn current_session(&self) -> Option<(String, String)> {
        self.current().map(|cloud| {
            let s = cloud.fs.session();
            (s.id.clone(), s.secret.clone())
        })
    }

    pub(crate) fn drop_if_same(&self, cloud: &Rc<Cloud>) {
        let mut clouds = self.0.clouds.borrow_mut();
        if clouds
            .get(&cloud.session_uid)
            .is_some_and(|cur| Rc::ptr_eq(cur, cloud))
        {
            clouds.remove(&cloud.session_uid);
        }
    }

    pub(crate) async fn get(
        &self,
        state: &Rc<RefCell<State>>,
        current: &Rc<RefCell<Actor>>,
        uid: u32,
        token: &str,
    ) -> vfs::Result<Rc<Cloud>> {
        poll_fn(|context| {
            if self.0.clouds.borrow().contains_key(&uid) || !self.0.busy.get() {
                Poll::Ready(())
            } else {
                self.0.waiters.borrow_mut().push(context.waker().clone());
                Poll::Pending
            }
        })
        .await;
        if let Some(cloud) = self.0.clouds.borrow().get(&uid).cloned() {
            self.0.latest_uid.set(Some(uid));
            return Ok(cloud);
        }
        self.0.busy.set(true);
        let _connecting = Connecting(&self.0);
        let host = BrowserHost {
            state: state.clone(),
            current: current.clone(),
        };
        let fs = Rc::new(CloudFs::connect(HttpTransport(host), token.to_string()).await?);
        let cloud = Rc::new(Cloud {
            fs,
            live_opens: Cell::new(0),
            session_uid: uid,
        });
        // Prune idle sessions belonging to superseded accounts/guests so we don't accumulate them.
        self.0
            .clouds
            .borrow_mut()
            .retain(|&k, c| k == uid || c.live_opens.get() > 0);
        self.0.clouds.borrow_mut().insert(uid, cloud.clone());
        self.0.latest_uid.set(Some(uid));
        Ok(cloud)
    }
}

fn errno(error: Errno) -> JsValue {
    fail(Error::from(error))
}

fn js_now_timespec() -> (u64, u32) {
    let ms = js_sys::Date::now();
    if !ms.is_finite() || ms <= 0.0 {
        return (0, 0);
    }
    let whole_ms = ms.trunc() as u64;
    let sub_ns = ((ms.fract() * 1_000_000.0).round() as u64).min(999_999);
    let total_ns = whole_ms.saturating_mul(1_000_000).saturating_add(sub_ns);
    (total_ns / 1_000_000_000, (total_ns % 1_000_000_000) as u32)
}

fn stat_to_metadata(st: &Stat) -> Metadata {
    let kind_bits = st.mode & 0o170000;
    let file_type = if kind_bits == abi::S_IFDIR {
        FileType::Dir
    } else if kind_bits == abi::S_IFLNK {
        FileType::Symlink
    } else if kind_bits == abi::S_IFCHR {
        FileType::CharDevice
    } else {
        FileType::File
    };
    Metadata {
        file_type,
        mode: (st.mode & 0o7777) as u16,
        nlink: st.nlink,
        uid: st.uid,
        gid: st.gid,
        size: st.size,
        atime: Timespec {
            sec: st.atime,
            nsec: st.atime_nsec,
        },
        mtime: Timespec {
            sec: st.mtime,
            nsec: st.mtime_nsec,
        },
        ctime: Timespec {
            sec: st.ctime,
            nsec: st.ctime_nsec,
        },
        rdev: st.rdev.clone(),
        acl: st.acl,
    }
}

fn join_cloud_path(parent: &str, name: &str) -> String {
    if parent == "/" || parent.is_empty() {
        format!("/{name}")
    } else {
        format!("{}/{name}", parent.trim_end_matches('/'))
    }
}

fn split_cloud_parent(path: &str) -> Option<(String, String)> {
    if path == "/" || path.is_empty() {
        return None;
    }
    let trimmed = path.trim_end_matches('/');
    match trimmed.rsplit_once('/') {
        Some(("", name)) if !name.is_empty() => Some(("/".to_string(), name.to_string())),
        Some((parent, name)) if !name.is_empty() => Some((parent.to_string(), name.to_string())),
        _ => None,
    }
}

thread_local! {
    static LAST_PAGE_ERROR_DETAIL: RefCell<Option<(Errno, String)>> = const { RefCell::new(None) };
}

pub(crate) fn clear_last_page_error() {
    LAST_PAGE_ERROR_DETAIL.with(|slot| *slot.borrow_mut() = None);
}

pub(crate) fn record_last_page_error(errno: Errno, detail: Option<&str>) {
    if let Some(d) = detail
        && !d.is_empty()
        && d != errno.text()
    {
        LAST_PAGE_ERROR_DETAIL.with(|slot| {
            *slot.borrow_mut() = Some((errno, d.to_string()));
        });
    }
}

pub(crate) fn take_last_page_error_detail(errno: Errno) -> Option<String> {
    LAST_PAGE_ERROR_DETAIL.with(|slot| {
        let matches = slot.borrow().as_ref().is_some_and(|(e, _)| *e == errno);
        if matches {
            slot.borrow_mut().take().map(|(_, d)| d)
        } else {
            None
        }
    })
}

fn parse_page_reply(reply_str: &str) -> vfs::Result<Value> {
    let reply: Value = serde_json::from_str(reply_str).map_err(|_| Errno::EIO)?;
    let status = reply["status"].as_u64().unwrap_or(0);
    let text = reply["text"].as_str().unwrap_or("");
    if status != 200 {
        if let Ok(err_val) = serde_json::from_str::<Value>(text) {
            let parsed = err_val["errno"]
                .as_str()
                .and_then(|code| {
                    serde_json::from_value::<Errno>(Value::String(code.to_string())).ok()
                })
                .unwrap_or(match status {
                    401 | 403 => Errno::EACCES,
                    404 => Errno::ENOENT,
                    409 => Errno::ESTALE,
                    413 => Errno::EFBIG,
                    _ => Errno::EIO,
                });
            let detail = err_val["detail"]
                .as_str()
                .or_else(|| err_val["error"].as_str());
            record_last_page_error(parsed, detail);
            return Err(parsed);
        }
        return Err(match status {
            401 | 403 => Errno::EACCES,
            404 => Errno::ENOENT,
            409 => Errno::ESTALE,
            413 => Errno::EFBIG,
            _ => Errno::EIO,
        });
    }
    serde_json::from_str(text).map_err(|_| Errno::EIO)
}

fn session_headers_js(fs_session: Option<(&str, &str)>) -> Option<JsValue> {
    let (sid, secret) = fs_session?;
    if sid.is_empty() || secret.is_empty() {
        return None;
    }
    let headers = js_sys::Object::new();
    let _ = js_sys::Reflect::set(&headers, &"X-Fs-Session".into(), &JsValue::from_str(sid));
    let _ = js_sys::Reflect::set(&headers, &"X-Fs-Secret".into(), &JsValue::from_str(secret));
    Some(headers.into())
}

/// Send an unprivileged or `sudo` cookie-authenticated batch to `/api/sys` on `OsAuthority`
/// (NEVER `X-Registry`), installed as `self.pageSysPost(bodyJson, extraHeaders)` by
/// `web/kernel/client.js`.
pub(crate) async fn page_sys_batch_with_session(
    batch: Batch,
    fs_session: Option<(&str, &str)>,
) -> vfs::Result<Vec<Return>> {
    page_batch_target(batch, fs_session, None, None).await
}

async fn page_batch_target(
    batch: Batch,
    fs_session: Option<(&str, &str)>,
    target: Option<PageTarget>,
    fd_epoch: Option<&str>,
) -> vfs::Result<Vec<Return>> {
    let (global, post) = installed("pageSysPost")?;
    let body = serde_json::to_string(&batch).map_err(|_| Errno::EIO)?;
    let headers = session_headers_js(fs_session).unwrap_or_else(|| js_sys::Object::new().into());
    if let Some(target) = target {
        let json = serde_json::to_string(&target).map_err(|_| Errno::EIO)?;
        js_sys::Reflect::set(&headers, &"X-Fs-Target".into(), &json.into())
            .map_err(|_| Errno::EIO)?;
    }
    if let Some(epoch) = fd_epoch {
        js_sys::Reflect::set(&headers, &"X-Fd-Epoch".into(), &epoch.into())
            .map_err(|_| Errno::EIO)?;
    }
    let answer = post
        .call2(&global, &body.into(), &headers)
        .map_err(|_| Errno::EIO)?;
    let raw = promised(answer).await?;
    let reply_str = raw.as_string().ok_or(Errno::EIO)?;
    let text_val = parse_page_reply(&reply_str)?;
    let results: Results = serde_json::from_value(text_val).map_err(|_| Errno::EIO)?;
    Ok(results.results)
}

pub(crate) async fn page_sys_batch(batch: Batch) -> vfs::Result<Vec<Return>> {
    page_sys_batch_with_session(batch, None).await
}

async fn page_sys_one_with_session(
    call: Call,
    umask: Option<u16>,
    sudo: bool,
    fs_session: Option<(&str, &str)>,
) -> vfs::Result<Value> {
    page_target_call(call, umask, sudo, fs_session, None).await
}

pub(crate) async fn page_target_call(
    call: Call,
    umask: Option<u16>,
    sudo: bool,
    fs_session: Option<(&str, &str)>,
    target: Option<PageTarget>,
) -> vfs::Result<Value> {
    let mut results = page_batch_target(
        Batch {
            calls: vec![call],
            umask,
            sudo,
            pid: None,
            process: None,
        },
        fs_session,
        target,
        None,
    )
    .await?;
    let ret = results.pop().ok_or(Errno::EIO)?;
    ret.into_result().map_err(|e| {
        record_last_page_error(e.errno, e.detail.as_deref());
        e.errno
    })
}

#[derive(Clone, serde::Deserialize)]
pub(crate) struct AuthorityPageFd {
    pub(crate) fd: u32,
    pub(crate) fd_epoch: String,
}

impl AuthorityPageFd {
    pub(crate) async fn call(&self, call: Call, sudo: bool) -> vfs::Result<Value> {
        page_batch_target(
            Batch {
                calls: vec![call],
                umask: None,
                sudo,
                pid: None,
                process: None,
            },
            None,
            None,
            Some(&self.fd_epoch),
        )
        .await?
        .pop()
        .ok_or(Errno::EIO)?
        .into_result()
        .map_err(|e| {
            record_last_page_error(e.errno, e.detail.as_deref());
            e.errno
        })
    }

    pub(crate) async fn close(&self, sudo: bool) -> vfs::Result<Value> {
        self.call(Call::Close { fd: self.fd.into() }, sudo).await
    }
}

async fn read_page_fd(
    fd: &AuthorityPageFd,
    offset: u64,
    buf: &mut [u8],
    sudo: bool,
) -> vfs::Result<usize> {
    let count = (buf.len() as u64).min(abi::INLINE_MAX);
    if count == 0 {
        return Ok(0);
    }
    let value = fd
        .call(
            Call::Pread {
                fd: Some(fd.fd.into()),
                path: None,
                offset,
                count,
            },
            sudo,
        )
        .await?;
    let data: Bytes = serde_json::from_value(value["data"].clone()).map_err(|_| Errno::EIO)?;
    if data.0.len() > count as usize {
        return Err(Errno::EIO);
    }
    buf[..data.0.len()].copy_from_slice(&data.0);
    Ok(data.0.len())
}

enum OpenRecord {
    Mem(OpenRef),
    PathOnly {
        node: NodeId,
    },
    Remote {
        cloud: Rc<Cloud>,
        real: OpenRef,
    },
    RemoteExec {
        cloud: Rc<Cloud>,
        real: OpenRef,
        token: String,
    },
    Page {
        read_fd: Option<AuthorityPageFd>,
        read_meta: Option<Metadata>,
        path: String,
        node: NodeId,
        access: Access,
        sudo: bool,
        stale: bool,
    },
}

#[derive(Default)]
struct PageReadCache {
    uid: u32,
    sudo: bool,
    mut_epoch: u64,
    entries: HashMap<String, Entry>,
    links: HashMap<String, Option<String>>,
    missing: HashSet<String>,
    complete_dirs: HashMap<String, Metadata>,
    transport_err: Option<Errno>,
}

impl PageReadCache {
    fn new(uid: u32, sudo: bool, mut_epoch: u64) -> Self {
        Self {
            uid,
            sudo,
            mut_epoch,
            ..Self::default()
        }
    }
}

pub(crate) struct PageReadScope {
    driver: Rc<RootCloudDriver>,
}

impl Drop for PageReadScope {
    fn drop(&mut self) {
        let next = self.driver.page_read_depth.get().saturating_sub(1);
        self.driver.page_read_depth.set(next);
        if next == 0 {
            *self.driver.page_read_cache.borrow_mut() = None;
        }
    }
}

type LazyMintHook = Rc<dyn Fn(u32)>;

/// Unified `/` cloud filesystem driver mounted at the root of `system_mnt_ns`.
pub(crate) struct RootCloudDriver {
    fs_id: FsId,
    mem: MemFs,
    state: Rc<RefCell<State>>,
    current: Rc<RefCell<Actor>>,
    connector: Connector,
    pub(crate) active_pid: Rc<Cell<Option<u32>>>,
    pub(crate) page_sudo: Rc<Cell<bool>>,
    pub(crate) sync_boot_mem: Cell<bool>,
    pub(crate) use_seed_cache: Cell<bool>,
    server_seeded: Cell<bool>,
    cloud_denied_pids: RefCell<HashSet<u32>>,
    canonical_nodes: RefCell<HashMap<String, NodeId>>,
    node_paths: RefCell<HashMap<NodeId, String>>,
    path_entries: RefCell<HashMap<String, Entry>>,
    page_mut_epoch: Cell<u64>,
    page_read_depth: Cell<u32>,
    page_read_cache: RefCell<Option<PageReadCache>>,
    cloud_handles: RefCell<HashMap<NodeId, Handle>>,
    next_open: Cell<u64>,
    opens: RefCell<HashMap<u64, OpenRecord>>,
    page_locks: RefCell<HashMap<u64, Rc<PageLock>>>,
    writing_by_ino: RefCell<HashMap<u64, abi::Writing>>,
    uid_names: RefCell<HashMap<u32, String>>,
    gid_names: RefCell<HashMap<u32, String>>,
    on_lazy_mint: RefCell<Option<LazyMintHook>>,
}

impl RootCloudDriver {
    pub(crate) fn new(
        state: Rc<RefCell<State>>,
        current: Rc<RefCell<Actor>>,
        connector: Connector,
    ) -> Self {
        let fs_id = FsId("cloud".to_string());
        let mem = MemFs::new(fs_id.clone(), 1, 0, 0, 0o755, Box::new(js_now_timespec));
        let mut root_cred = Cred::root();
        root_cred.umask = 0;

        let mut dir_handles: HashMap<String, Handle> = HashMap::new();
        dir_handles.insert("/".to_string(), mem.root());

        for &(path, mode) in SEED_DIRS {
            if path == "/" {
                continue;
            }
            let (parent_path, name) = split_cloud_parent(path).expect("seed parent");
            let parent = dir_handles
                .get(&parent_path)
                .expect("parent seeded")
                .clone();
            let entry = now_or_never(mem.mkdir(&root_cred, &parent, &name, mode & 0o777))
                .expect("sync memfs mkdir")
                .expect("seed dir");
            if mode & 0o7000 != 0 {
                let _ = now_or_never(mem.setattr(
                    &root_cred,
                    &entry.handle,
                    &SetAttr {
                        mode: Some(mode),
                        ..SetAttr::default()
                    },
                ));
            }
            dir_handles.insert(path.to_string(), entry.handle);
        }

        let mut canonical_nodes = HashMap::new();
        let mut node_paths = HashMap::new();
        for &(path, target) in SEED_SYMLINKS {
            let (parent_path, name) = split_cloud_parent(path).expect("symlink parent");
            let parent = dir_handles
                .get(&parent_path)
                .expect("parent seeded")
                .clone();
            let entry = now_or_never(mem.symlink(&root_cred, &parent, &name, target))
                .expect("sync memfs symlink")
                .expect("seed symlink");
            canonical_nodes.insert(path.to_string(), entry.handle.node);
            node_paths.insert(entry.handle.node, path.to_string());
        }

        let etc = dir_handles.get("/etc").expect("/etc seeded").clone();
        for name in ["passwd", "group"] {
            if let Some(Ok((_, oref))) = now_or_never(mem.create(
                &root_cred,
                &etc,
                name,
                0o644,
                OpenOptions::new().write(true).create_new(true),
            )) {
                let _ = now_or_never(mem.release(&oref));
            }
        }

        for (path, handle) in &dir_handles {
            if is_local_carrier_path(path) {
                canonical_nodes.insert(path.clone(), handle.node);
                node_paths.insert(handle.node, path.clone());
            }
        }

        Self {
            fs_id,
            mem,
            state,
            current,
            connector,
            active_pid: Rc::new(Cell::new(None)),
            page_sudo: Rc::new(Cell::new(false)),
            sync_boot_mem: Cell::new(false),
            use_seed_cache: Cell::new(false),
            server_seeded: Cell::new(false),
            cloud_denied_pids: RefCell::new(HashSet::new()),
            canonical_nodes: RefCell::new(canonical_nodes),
            node_paths: RefCell::new(node_paths),
            path_entries: RefCell::new(HashMap::new()),
            page_mut_epoch: Cell::new(0),
            page_read_depth: Cell::new(0),
            page_read_cache: RefCell::new(None),
            cloud_handles: RefCell::new(HashMap::new()),
            next_open: Cell::new(1),
            opens: RefCell::new(HashMap::new()),
            page_locks: RefCell::new(HashMap::new()),
            writing_by_ino: RefCell::new(HashMap::new()),
            uid_names: RefCell::new(HashMap::new()),
            gid_names: RefCell::new(HashMap::new()),
            on_lazy_mint: RefCell::new(None),
        }
    }

    pub(crate) fn set_on_lazy_mint(&self, hook: LazyMintHook) {
        *self.on_lazy_mint.borrow_mut() = Some(hook);
    }

    fn notify_lazy_mint(&self, pid: u32) {
        if let Some(hook) = self.on_lazy_mint.borrow().as_ref().cloned() {
            hook(pid);
        }
    }

    pub(crate) fn cached_uid_name(&self, uid: u32) -> Option<String> {
        self.uid_names.borrow().get(&uid).cloned()
    }

    pub(crate) fn cached_gid_name(&self, gid: u32) -> Option<String> {
        self.gid_names.borrow().get(&gid).cloned()
    }

    pub(crate) fn clear_cached_account_names(&self) {
        self.uid_names.borrow_mut().clear();
        self.gid_names.borrow_mut().clear();
    }

    /// Resolve a remote cloud directory (such as `/dev/present` or `/dev/snd`) directly via
    /// `Lstat` for bind-mounting into `/dev` on explicit `attach_remote_device`.
    pub(crate) async fn lookup_remote_dir_handle(&self, path: &str) -> vfs::Result<Entry> {
        if !self.is_remote_mode() || installed("pageSysPost").is_err() {
            return Err(Errno::ENOTCONN);
        }
        let val = self
            .page_sys_one(
                Call::Lstat {
                    path: path.to_string(),
                },
                None,
                false,
            )
            .await?;
        let st: Stat = serde_json::from_value(val).map_err(|_| Errno::EIO)?;
        let entry = self.record_path_stat(path, &st);
        if !entry.metadata.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        Ok(entry)
    }

    pub(crate) fn writing_of(&self, ino: u64) -> Option<abi::Writing> {
        self.writing_by_ino.borrow().get(&ino).cloned()
    }

    /// Clear cached upload/recording progress tags and invalidate the uploaded path after a
    /// delegated server upload closes or discards so subsequent listings show the final size.
    pub(crate) fn invalidate_uploaded_path(&self, path: Option<&str>) {
        self.writing_by_ino.borrow_mut().clear();
        if let Some(p) = path {
            self.invalidate_page_path(p, false);
        } else {
            self.bump_page_mutation();
            self.path_entries.borrow_mut().clear();
        }
    }

    /// Parse and clear the internal `os.writing:<received>:<0|1>` wire tag from `Metadata.rdev`
    /// on regular files before `os_vfs` sees it (so `Vfs::node_for_perm` never treats an uploading
    /// file as a device node), caching any active `abi::Writing` status by inode.
    fn strip_and_record_writing(&self, ino: u64, meta: &mut Metadata) {
        if meta.file_type == FileType::File
            && let Some(tag) = meta.rdev.as_deref()
            && tag.starts_with("os.writing:")
        {
            let parsed = tag.strip_prefix("os.writing:").and_then(|rest| {
                let (rec_s, flag_s) = rest.split_once(':')?;
                let received = rec_s.parse::<u64>().ok()?;
                let recording = match flag_s {
                    "0" => false,
                    "1" => true,
                    _ => return None,
                };
                Some(abi::Writing {
                    received,
                    recording,
                })
            });
            meta.rdev = None;
            if let Some(w) = parsed {
                self.writing_by_ino.borrow_mut().insert(ino, w);
                return;
            }
        }
        self.writing_by_ino.borrow_mut().remove(&ino);
    }

    pub(crate) fn is_remote_mode(&self) -> bool {
        if self.sync_boot_mem.get() {
            return false;
        }
        self.server_seeded.get()
            || installed("cloudFsPost").is_ok()
            || installed("pageSysPost").is_ok()
    }

    fn make_handle(&self, ino: u64) -> Handle {
        Handle {
            fs: self.fs_id.clone(),
            node: NodeId { ino, generation: 1 },
            proof: String::new(),
        }
    }

    pub(crate) fn fs_id(&self) -> &FsId {
        &self.fs_id
    }

    pub(crate) fn uncached_page_paths(
        &self,
        paths: &[String],
        uid: u32,
        sudo: bool,
    ) -> Vec<String> {
        let epoch = self.page_mut_epoch.get();
        let slot = self.page_read_cache.borrow();
        let Some(cache) = slot.as_ref() else {
            return Vec::new();
        };
        if cache.uid != uid || cache.sudo != sudo || cache.mut_epoch != epoch {
            return Vec::new();
        }
        paths
            .iter()
            .filter(|p| !cache.entries.contains_key(*p) && !cache.missing.contains(*p))
            .cloned()
            .collect()
    }

    fn bump_page_mutation(&self) {
        self.page_mut_epoch
            .set(self.page_mut_epoch.get().wrapping_add(1));
        *self.page_read_cache.borrow_mut() = None;
    }

    pub(crate) fn begin_page_read(self: &Rc<Self>, uid: u32, sudo: bool) -> PageReadScope {
        let prev = self.page_read_depth.get();
        self.page_read_depth.set(prev.saturating_add(1));
        let epoch = self.page_mut_epoch.get();
        let mut slot = self.page_read_cache.borrow_mut();
        if prev == 0 {
            *slot = Some(PageReadCache::new(uid, sudo, epoch));
        } else if slot
            .as_ref()
            .is_some_and(|c| c.uid != uid || c.sudo != sudo || c.mut_epoch != epoch)
        {
            *slot = None;
        }
        PageReadScope {
            driver: Rc::clone(self),
        }
    }

    pub(crate) fn ensure_page_read_cache(&self, uid: u32, sudo: bool) -> bool {
        if self.page_read_depth.get() == 0 {
            return false;
        }
        let epoch = self.page_mut_epoch.get();
        let mut slot = self.page_read_cache.borrow_mut();
        if slot.is_none() {
            *slot = Some(PageReadCache::new(uid, sudo, epoch));
            return true;
        }
        false
    }

    pub(crate) async fn prewarm_page_paths(
        &self,
        paths: &[String],
        umask: u16,
        uid: u32,
        sudo: bool,
    ) {
        if installed("pageSysPost").is_err() || paths.is_empty() {
            return;
        }
        let epoch = self.page_mut_epoch.get();
        let to_fetch: Vec<String> = {
            let slot = self.page_read_cache.borrow();
            let Some(cache) = slot.as_ref() else {
                return;
            };
            if cache.uid != uid || cache.sudo != sudo || cache.mut_epoch != epoch {
                return;
            }
            paths
                .iter()
                .filter(|p| !cache.entries.contains_key(*p) && !cache.missing.contains(*p))
                .cloned()
                .collect()
        };
        if to_fetch.is_empty() {
            return;
        }
        let fs_session = self.connector.current_session();
        let fs_sess_ref = fs_session.as_ref().map(|(s, k)| (s.as_str(), k.as_str()));
        for chunk in to_fetch.chunks(BATCH_MAX) {
            let calls = chunk
                .iter()
                .map(|p| Call::Lstat { path: p.clone() })
                .collect();
            let results = match page_sys_batch_with_session(
                Batch {
                    calls,
                    umask: Some(umask),
                    sudo,
                    pid: None,
                    process: None,
                },
                fs_sess_ref,
            )
            .await
            {
                Ok(results) => results,
                Err(err) => {
                    let mut slot = self.page_read_cache.borrow_mut();
                    if let Some(cache) = slot.as_mut()
                        && cache.uid == uid
                        && cache.sudo == sudo
                        && cache.mut_epoch == epoch
                    {
                        cache.transport_err = Some(err);
                    }
                    return;
                }
            };
            if self.page_mut_epoch.get() != epoch {
                return;
            }
            for (path, ret) in chunk.iter().zip(results) {
                match ret {
                    Return::Ok(val) => {
                        if let Ok(st) = serde_json::from_value::<Stat>(val) {
                            self.record_path_stat(path, &st);
                        }
                    }
                    Return::Err(err) if err.errno == Errno::ENOENT => {
                        let mut slot = self.page_read_cache.borrow_mut();
                        if let Some(cache) = slot.as_mut()
                            && cache.uid == uid
                            && cache.sudo == sudo
                            && cache.mut_epoch == epoch
                        {
                            cache.missing.insert(path.clone());
                        }
                    }
                    Return::Err(_) => {}
                }
            }
        }
    }

    fn record_path_stat(&self, path: &str, st: &Stat) -> Entry {
        let node = self
            .canonical_nodes
            .borrow()
            .get(path)
            .copied()
            .unwrap_or(NodeId {
                ino: st.ino.max(1),
                generation: if path == "/" && st.ino <= 1 { 1 } else { 2 },
            });
        let entry = Entry {
            handle: Handle {
                fs: self.fs_id.clone(),
                node,
                proof: String::new(),
            },
            metadata: stat_to_metadata(st),
        };
        if !st.user.is_empty() && st.user != st.uid.to_string() {
            self.uid_names.borrow_mut().insert(st.uid, st.user.clone());
        }
        if !st.group.is_empty() && st.group != st.gid.to_string() {
            self.gid_names.borrow_mut().insert(st.gid, st.group.clone());
        }
        if let Some(writing) = &st.writing {
            self.writing_by_ino
                .borrow_mut()
                .insert(node.ino, writing.clone());
        } else {
            self.writing_by_ino.borrow_mut().remove(&node.ino);
        }
        self.node_paths.borrow_mut().insert(node, path.to_string());
        self.path_entries
            .borrow_mut()
            .insert(path.to_string(), entry.clone());
        let epoch = self.page_mut_epoch.get();
        if let Some(cache) = self.page_read_cache.borrow_mut().as_mut()
            && cache.mut_epoch == epoch
        {
            cache.missing.remove(path);
            cache.entries.insert(path.to_string(), entry.clone());
            cache.links.insert(path.to_string(), st.link.clone());
        }
        entry
    }

    fn cached_page_entry(&self, cred: &Cred, path: &str) -> Option<Entry> {
        let sudo = self.page_sudo.get();
        let epoch = self.page_mut_epoch.get();
        let slot = self.page_read_cache.borrow();
        let cache = slot.as_ref()?;
        if cache.uid != cred.identity.id || cache.sudo != sudo || cache.mut_epoch != epoch {
            return None;
        }
        cache.entries.get(path).cloned()
    }

    fn cached_page_entry_for_open(
        &self,
        node: NodeId,
        path: &str,
        open_sudo: bool,
    ) -> Option<Metadata> {
        let sudo = self.page_sudo.get() || open_sudo;
        let epoch = self.page_mut_epoch.get();
        let slot = self.page_read_cache.borrow();
        let cache = slot.as_ref()?;
        if cache.sudo != sudo || cache.mut_epoch != epoch {
            return None;
        }
        let _ = node;
        cache.entries.get(path).map(|e| e.metadata.clone())
    }

    fn cached_page_transport_err(&self, cred: &Cred) -> Option<Errno> {
        let sudo = self.page_sudo.get();
        let epoch = self.page_mut_epoch.get();
        let slot = self.page_read_cache.borrow();
        let cache = slot.as_ref()?;
        if cache.uid != cred.identity.id || cache.sudo != sudo || cache.mut_epoch != epoch {
            return None;
        }
        cache.transport_err
    }

    fn lookup_page_cache(
        &self,
        cred: &Cred,
        dir_path: &str,
        child_path: &str,
        name: &str,
    ) -> Option<vfs::Result<Entry>> {
        let sudo = self.page_sudo.get();
        let epoch = self.page_mut_epoch.get();
        let slot = self.page_read_cache.borrow();
        let cache = slot.as_ref()?;
        if cache.uid != cred.identity.id || cache.sudo != sudo || cache.mut_epoch != epoch {
            return None;
        }
        if let Some(err) = cache.transport_err {
            return Some(Err(err));
        }
        if let Some(entry) = cache.entries.get(child_path) {
            return Some(Ok(entry.clone()));
        }
        if cache.missing.contains(child_path) {
            return Some(Err(Errno::ENOENT));
        }
        if let Some(dir_meta) = cache.complete_dirs.get(dir_path)
            && (name != "_" || (!dir_meta.acl && cred_permits_exec(dir_meta, cred)))
        {
            return Some(Err(Errno::ENOENT));
        }
        None
    }

    fn cached_page_link(&self, cred: &Cred, path: &str) -> Option<String> {
        let sudo = self.page_sudo.get();
        let epoch = self.page_mut_epoch.get();
        let slot = self.page_read_cache.borrow();
        let cache = slot.as_ref()?;
        if cache.uid != cred.identity.id || cache.sudo != sudo || cache.mut_epoch != epoch {
            return None;
        }
        cache.links.get(path).and_then(|v| v.clone())
    }

    fn wrap_remote_node(&self, raw: NodeId, known_path: Option<&str>) -> NodeId {
        if let Some(canon) = known_path.and_then(|p| self.canonical_nodes.borrow().get(p).copied())
        {
            return canon;
        }
        if raw.ino == 1 {
            NodeId {
                ino: 1,
                generation: 1,
            }
        } else {
            NodeId {
                ino: raw.ino,
                generation: raw.generation.saturating_add(1).max(2),
            }
        }
    }

    fn wrap_cloud_entry(&self, mut real: Entry, known_path: Option<String>) -> Entry {
        let node = self.wrap_remote_node(real.handle.node, known_path.as_deref());
        self.strip_and_record_writing(node.ino, &mut real.metadata);
        self.cloud_handles
            .borrow_mut()
            .insert(node, real.handle.clone());
        if let Some(p) = known_path {
            self.node_paths.borrow_mut().insert(node, p.clone());
            let wrapped = Entry {
                handle: Handle {
                    fs: self.fs_id.clone(),
                    node,
                    proof: String::new(),
                },
                metadata: real.metadata,
            };
            self.path_entries.borrow_mut().insert(p, wrapped.clone());
            wrapped
        } else {
            Entry {
                handle: Handle {
                    fs: self.fs_id.clone(),
                    node,
                    proof: String::new(),
                },
                metadata: real.metadata,
            }
        }
    }

    pub(crate) fn canonical_cloud_path(&self, node: NodeId) -> Option<String> {
        if !self.is_remote_mode() {
            // Reconstruct path in `mem` for headless tests if needed.
            let mut cur = Handle {
                fs: self.fs_id.clone(),
                node,
                proof: String::new(),
            };
            let root_cred = Cred::root();
            let mut parts = Vec::new();
            loop {
                if cur.node.ino == self.mem.root().node.ino {
                    parts.reverse();
                    return Some(if parts.is_empty() {
                        "/".to_string()
                    } else {
                        format!("/{}", parts.join("/"))
                    });
                }
                match now_or_never(self.mem.parent(&root_cred, &cur)) {
                    Some(Ok(Some((parent_entry, name)))) => {
                        parts.push(name);
                        cur = parent_entry.handle;
                    }
                    _ => return self.node_paths.borrow().get(&node).cloned(),
                }
            }
        }
        self.node_paths.borrow().get(&node).cloned()
    }

    fn actor_for_cred(&self, cred: &Cred) -> Actor {
        if let Some(pid) = self.active_pid.get() {
            return Actor::Process(pid);
        }
        if let Some(token) = &cred.token {
            let state = self.state.borrow();
            for pid in state.table.all_pids() {
                if let Some(proc) = state.table.proc(pid)
                    && proc.state != ProcState::Zombie
                    && proc.cred.remote.as_ref().map(|r| r.token.as_str()) == Some(token.as_str())
                {
                    return Actor::Process(pid);
                }
            }
        }
        Actor::None
    }

    fn acted<F: Future>(&self, actor: Actor, future: F) -> Acted<F> {
        Acted {
            current: self.current.clone(),
            actor,
            future,
        }
    }

    async fn connect_cloud(&self, cred: &Cred) -> vfs::Result<(Actor, Rc<Cloud>, Cred)> {
        let token = if let Some(tok) = cred.token.as_deref().filter(|t| !t.is_empty()) {
            tok.to_string()
        } else if let Some(pid) = self.active_pid.get() {
            let existing = self.state.borrow().table.proc(pid).and_then(|p| {
                (p.state != ProcState::Zombie && p.cred.cloud_access)
                    .then(|| {
                        p.cred
                            .remote
                            .as_ref()
                            .filter(|r| r.cloud_access)
                            .map(|r| r.token.clone())
                    })
                    .flatten()
            });
            if let Some(tok) = existing {
                tok
            } else {
                let rem = crate::lazy_mint_remote_cred(&self.state, pid)
                    .await
                    .map_err(|e| e.errno)?;
                self.notify_lazy_mint(pid);
                rem.token
            }
        } else {
            return Err(Errno::EACCES);
        };
        let mut rcred = cred.clone();
        rcred.token = Some(token.clone());
        if let Some(pid) = self.active_pid.get()
            && let Some(id) = self
                .state
                .borrow()
                .table
                .proc(pid)
                .map(|p| p.cred.identity.clone())
        {
            rcred.identity = id;
        }
        let actor = self.actor_for_cred(&rcred);
        let session_uid = if let Some(pid) = self.active_pid.get() {
            self.state
                .borrow()
                .table
                .proc(pid)
                .and_then(|p| p.cred.remote.as_ref().map(|r| r.uid))
                .unwrap_or(rcred.identity.id)
        } else {
            rcred.identity.id
        };
        let cloud = self
            .acted(
                actor.clone(),
                self.connector
                    .get(&self.state, &self.current, session_uid, &token),
            )
            .await?;
        self.cloud_handles
            .borrow_mut()
            .insert(cloud.fs.root().node, cloud.fs.root());
        Ok((actor, cloud, rcred))
    }

    async fn ensure_cloud_handle(
        &self,
        cloud: &Rc<Cloud>,
        cred: &Cred,
        handle: &Handle,
    ) -> vfs::Result<Handle> {
        if handle.fs != self.fs_id {
            return Err(Errno::EACCES);
        }
        if handle.node.ino == 1 {
            return Ok(cloud.fs.root());
        }
        if let Some(real) = self.cloud_handles.borrow().get(&handle.node).cloned()
            && real.fs == *cloud.fs.id()
        {
            return Ok(real);
        }
        let Some(path) = self.node_paths.borrow().get(&handle.node).cloned() else {
            return Err(Errno::ESTALE);
        };
        let is_canonical = self.canonical_nodes.borrow().get(&path) == Some(&handle.node);
        let names: Vec<String> = path
            .split('/')
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        if names.is_empty() {
            return Ok(cloud.fs.root());
        }
        let mut walked = cloud.fs.walk(cred, &cloud.fs.root(), &names).await?;
        let mut cur_path = String::new();
        for (seg, entry) in names.iter().zip(walked.entries.iter_mut()) {
            cur_path = format!("{cur_path}/{seg}");
            self.strip_and_record_writing(entry.handle.node.ino, &mut entry.metadata);
            let mapped_node = self.wrap_remote_node(entry.handle.node, Some(&cur_path));
            self.cloud_handles
                .borrow_mut()
                .insert(mapped_node, entry.handle.clone());
            self.node_paths
                .borrow_mut()
                .insert(mapped_node, cur_path.clone());
        }
        if walked.stop.is_some() {
            return Err(Errno::ESTALE);
        }
        if is_canonical {
            return walked
                .entries
                .last()
                .map(|e| e.handle.clone())
                .ok_or(Errno::ESTALE);
        }
        walked
            .entries
            .last()
            .filter(|e| e.handle.node.ino == self.page_ino(handle.node))
            .map(|e| e.handle.clone())
            .ok_or(Errno::ESTALE)
    }

    /// Resolve a wrapper `Handle` to the server's HMAC-authenticated `Handle` (`InotifyAddWatch`).
    pub(crate) async fn real_cloud_handle(
        &self,
        cred: &Cred,
        handle: &Handle,
    ) -> vfs::Result<Handle> {
        if self.is_cloud_denied(cred) {
            return Err(Errno::EACCES);
        }
        if !self.is_remote_mode()
            || !self.has_cloud_token(cred)
            || installed("cloudFsPost").is_err()
        {
            return Ok(handle.clone());
        }
        let (actor, cloud, rcred) = self.connect_cloud(cred).await?;
        self.acted(actor, self.ensure_cloud_handle(&cloud, &rcred, handle))
            .await
    }

    /// Resolve a wrapper `OpenRef` to the server's `OpenRef` (`/dev/{archive,media}` `PathAt.open`).
    pub(crate) fn real_cloud_open_ref(&self, open: &OpenRef) -> Option<OpenRef> {
        if open.fs != self.fs_id {
            return None;
        }
        match self.opens.borrow().get(&open.id)? {
            OpenRecord::Remote { real, .. } => Some(real.clone()),
            OpenRecord::Mem(m) => Some(m.clone()),
            _ => None,
        }
    }

    /// Server-side `FICLONE` (`wire::Call::Clone` on `/api/fs`, or in-memory copy in offline tests).
    pub(crate) async fn clone_file(
        &self,
        pid: u32,
        cred: &Cred,
        src_open: &OpenRef,
        dst_open: &OpenRef,
    ) -> vfs::Result<()> {
        if src_open.fs != self.fs_id || dst_open.fs != self.fs_id {
            return Err(Errno::EXDEV);
        }
        if self.cloud_denied_pids.borrow().contains(&pid) {
            return Err(Errno::EACCES);
        }
        if !self.is_remote_mode() {
            let (src_mem, dst_mem) = {
                let opens = self.opens.borrow();
                let s = match opens.get(&src_open.id) {
                    Some(OpenRecord::Mem(o)) => o.clone(),
                    _ => return Err(Errno::EBADF),
                };
                let d = match opens.get(&dst_open.id) {
                    Some(OpenRecord::Mem(o)) => o.clone(),
                    _ => return Err(Errno::EBADF),
                };
                (s, d)
            };
            if !src_mem.access.reads() || !dst_mem.access.writes() {
                return Err(Errno::EBADF);
            }
            let src_meta = self.mem.open_metadata(&src_mem).await?;
            self.mem.set_len(&dst_mem, 0).await?;
            let mut offset = 0u64;
            let mut buf = vec![0u8; 64 * 1024];
            while offset < src_meta.size {
                let n = self.mem.read_at(&src_mem, &mut buf, offset).await?;
                if n == 0 {
                    break;
                }
                self.mem
                    .write_at(&dst_mem, &buf[..n], WriteAt::Offset(offset))
                    .await?;
                offset += n as u64;
            }
            return Ok(());
        }

        let token = if let Some(tok) = cred.token.as_deref().filter(|t| !t.is_empty()) {
            tok.to_string()
        } else {
            let existing = self.state.borrow().table.proc(pid).and_then(|p| {
                (p.state != ProcState::Zombie && p.cred.cloud_access)
                    .then(|| {
                        p.cred
                            .remote
                            .as_ref()
                            .filter(|r| r.cloud_access)
                            .map(|r| r.token.clone())
                    })
                    .flatten()
            });
            if let Some(tok) = existing {
                tok
            } else {
                let tok = crate::lazy_mint_remote_cred(&self.state, pid)
                    .await
                    .map_err(|e| e.errno)?
                    .token;
                self.notify_lazy_mint(pid);
                tok
            }
        };
        let (cloud, src_real, dst_real) = {
            let opens = self.opens.borrow();
            let (c1, s) = match opens.get(&src_open.id) {
                Some(OpenRecord::Remote { cloud, real }) => (Rc::clone(cloud), real.clone()),
                _ => return Err(Errno::EBADF),
            };
            let (c2, d) = match opens.get(&dst_open.id) {
                Some(OpenRecord::Remote { cloud, real }) => (Rc::clone(cloud), real.clone()),
                _ => return Err(Errno::EBADF),
            };
            if !Rc::ptr_eq(&c1, &c2) {
                return Err(Errno::EBADF);
            }
            (c1, s, d)
        };
        let host = BrowserHost {
            state: self.state.clone(),
            current: self.current.clone(),
        };
        let transport = HttpTransport(host);
        let req = wire::Request {
            version: wire::VERSION,
            credential: token.to_string(),
            session: Some(cloud.fs.session().clone()),
            call: wire::Call::Clone {
                source: src_real,
                target: dst_real,
            },
        };
        let res = self
            .acted(Actor::Process(pid), transport.request(req))
            .await;
        if let Err(Errno::ENOTCONN) = res
            && cloud.live_opens.get() == 0
        {
            self.connector.drop_if_same(&cloud);
        }
        res.map(|_| ())
    }

    fn alloc_open(&self, node: NodeId, access: Access, record: OpenRecord) -> OpenRef {
        let id = self.next_open.get();
        self.next_open.set(id + 1);
        self.opens.borrow_mut().insert(id, record);
        OpenRef {
            fs: self.fs_id.clone(),
            id,
            node,
            access,
        }
    }

    fn path_for_handle(&self, handle: &Handle) -> vfs::Result<String> {
        if handle.fs != self.fs_id {
            return Err(Errno::EACCES);
        }
        if handle.node.ino == 1 {
            return Ok("/".to_string());
        }
        self.node_paths
            .borrow()
            .get(&handle.node)
            .cloned()
            .ok_or(Errno::ESTALE)
    }

    pub(crate) fn set_cloud_access(&self, pid: u32, allowed: bool) {
        if allowed {
            self.cloud_denied_pids.borrow_mut().remove(&pid);
        } else {
            self.cloud_denied_pids.borrow_mut().insert(pid);
        }
    }

    fn is_active_pid_cloud_denied(&self) -> bool {
        let Some(pid) = self.active_pid.get() else {
            return false;
        };
        self.cloud_denied_pids.borrow().contains(&pid)
    }

    fn is_cloud_denied(&self, cred: &Cred) -> bool {
        let denied = self.cloud_denied_pids.borrow();
        if let Some(pid) = self.active_pid.get() {
            if denied.contains(&pid) {
                return true;
            }
            if let Ok(state) = self.state.try_borrow()
                && let Some(proc) = state.table.proc(pid)
                && !proc.cred.cloud_access
            {
                return true;
            }
            return false;
        }
        if denied.is_empty() {
            return false;
        }
        if let Some(token) = &cred.token
            && let Ok(state) = self.state.try_borrow()
        {
            for pid in state.table.all_pids() {
                if let Some(proc) = state.table.proc(pid)
                    && proc.state != ProcState::Zombie
                    && proc.cred.remote.as_ref().map(|r| r.token.as_str()) == Some(token.as_str())
                {
                    return denied.contains(&pid) || !proc.cred.cloud_access;
                }
            }
        }
        false
    }

    fn cached_or_mem_carrier_entry(&self, path: &str) -> Option<Entry> {
        if !is_local_carrier_path(path) {
            return None;
        }
        if let Some(cached) = self.path_entries.borrow().get(path).cloned() {
            return Some(cached);
        }
        if path == "/" {
            let meta = now_or_never(self.mem.metadata(&Cred::root(), &self.mem.root()))?.ok()?;
            return Some(Entry {
                handle: self.root(),
                metadata: meta,
            });
        }
        let root_cred = Cred::root();
        let mut cur = self.mem.root();
        for seg in path.split('/').filter(|s| !s.is_empty()) {
            cur = now_or_never(self.mem.lookup(&root_cred, &cur, seg))?
                .ok()?
                .handle;
        }
        let meta = now_or_never(self.mem.metadata(&root_cred, &cur))?.ok()?;
        let node = self
            .canonical_nodes
            .borrow()
            .get(path)
            .copied()
            .unwrap_or(NodeId {
                ino: 0x8000_0000_0000_0000 | cur.node.ino,
                generation: cur.node.generation,
            });
        let entry = Entry {
            handle: Handle {
                fs: self.fs_id.clone(),
                node,
                proof: String::new(),
            },
            metadata: meta,
        };
        self.node_paths.borrow_mut().insert(node, path.to_string());
        self.path_entries
            .borrow_mut()
            .insert(path.to_string(), entry.clone());
        Some(entry)
    }

    fn has_cloud_token(&self, cred: &Cred) -> bool {
        if self.is_cloud_denied(cred) || installed("cloudFsPost").is_err() {
            return false;
        }
        cred.token.as_deref().is_some_and(|t| !t.is_empty()) || self.active_pid.get().is_some()
    }

    pub(crate) fn current_fs_session(&self) -> Option<(String, String)> {
        self.connector.current_session()
    }

    pub(crate) fn is_pid_cloud_denied(&self, pid: u32) -> bool {
        self.cloud_denied_pids.borrow().contains(&pid)
    }

    async fn page_sys_one(&self, call: Call, umask: Option<u16>, sudo: bool) -> vfs::Result<Value> {
        let fs_session = self.connector.current_session();
        page_sys_one_with_session(
            call,
            umask,
            sudo,
            fs_session.as_ref().map(|(s, k)| (s.as_str(), k.as_str())),
        )
        .await
    }

    pub(crate) async fn guarded_page_call(
        &self,
        call: Call,
        umask: Option<u16>,
        sudo: bool,
        target: PageTarget,
    ) -> vfs::Result<Value> {
        let session = self.current_fs_session();
        page_target_call(
            call,
            umask,
            sudo,
            session
                .as_ref()
                .map(|(id, key)| (id.as_str(), key.as_str())),
            Some(target),
        )
        .await
    }

    pub(crate) fn page_ino(&self, node: NodeId) -> u64 {
        if node == self.root().node {
            self.canonical_nodes
                .borrow()
                .get("/")
                .map_or(node.ino, |n| n.ino)
        } else {
            node.ino
        }
    }

    async fn page_read_open(
        &self,
        path: &str,
        node: NodeId,
        sudo: bool,
    ) -> vfs::Result<(AuthorityPageFd, Stat)> {
        let reply = self
            .guarded_page_call(
                Call::Open {
                    path: path.into(),
                    flags: abi::O_RDONLY,
                    mode: 0,
                    size: None,
                    sha256: None,
                    version: None,
                },
                None,
                sudo,
                PageTarget::Inode(self.page_ino(node)),
            )
            .await?;
        let fd: AuthorityPageFd = serde_json::from_value(reply.clone()).map_err(|_| Errno::EIO)?;
        match serde_json::from_value(reply["stat"].clone()) {
            Ok(stat) => Ok((fd, stat)),
            Err(_) => {
                let _ = fd.close(sudo).await;
                Err(Errno::EIO)
            }
        }
    }

    async fn read_page_prefix(
        &self,
        path: &str,
        node: NodeId,
        len: usize,
        sudo: bool,
    ) -> vfs::Result<Vec<u8>> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let (fd, _) = self.page_read_open(path, node, sudo).await?;
        let result = async {
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(len).map_err(|_| Errno::EFBIG)?;
            bytes.resize(len, 0);
            let mut pos = 0;
            while pos < len {
                let n = read_page_fd(&fd, pos as u64, &mut bytes[pos..], sudo).await?;
                if n == 0 {
                    return Err(Errno::ESTALE);
                }
                pos += n;
            }
            Ok(bytes)
        }
        .await;
        let close = fd.close(sudo).await;
        let bytes = result?;
        close?;
        Ok(bytes)
    }

    fn page_lock_for(&self, ino: u64) -> Rc<PageLock> {
        self.page_locks.borrow_mut().entry(ino).or_default().clone()
    }

    fn invalidate_page_path(&self, path: &str, subtree: bool) {
        self.bump_page_mutation();
        let slash_prefix = format!("{path}/");
        self.path_entries
            .borrow_mut()
            .retain(|k, _| k != path && !(subtree && k.starts_with(&slash_prefix)));
        self.node_paths
            .borrow_mut()
            .retain(|_, v| v != path && !(subtree && v.starts_with(&slash_prefix)));
        for record in self.opens.borrow_mut().values_mut() {
            if let OpenRecord::Page {
                path: open_path,
                stale,
                ..
            } = record
                && (open_path == path || (subtree && open_path.starts_with(&slash_prefix)))
            {
                *stale = true;
            }
        }
    }

    fn rename_page_paths(&self, old_prefix: &str, new_prefix: &str) {
        self.bump_page_mutation();
        let slash_prefix = format!("{old_prefix}/");
        let new_slash = format!("{new_prefix}/");
        self.path_entries.borrow_mut().retain(|k, _| {
            k != old_prefix
                && !k.starts_with(&slash_prefix)
                && k != new_prefix
                && !k.starts_with(&new_slash)
        });
        update_renamed_paths(&mut self.node_paths.borrow_mut(), old_prefix, new_prefix);
        for record in self.opens.borrow_mut().values_mut() {
            if let OpenRecord::Page { path, .. } = record {
                if path == old_prefix {
                    *path = new_prefix.to_string();
                } else if let Some(rest) = path.strip_prefix(&slash_prefix) {
                    *path = format!("{new_prefix}/{rest}");
                }
            }
        }
    }

    async fn page_rmw_mutate(
        &self,
        path: &str,
        expected_node: NodeId,
        umask: u16,
        sudo: bool,
        mutation: PageMutation<'_>,
        reader: Option<u64>,
    ) -> vfs::Result<Written> {
        self.bump_page_mutation();
        let _guard = lock_page(self.page_lock_for(expected_node.ino)).await;
        for attempt in 0..3 {
            let target = PageTarget::Inode(self.page_ino(expected_node));
            let st_val = self
                .guarded_page_call(Call::Lstat { path: path.into() }, None, sudo, target)
                .await?;
            let version = st_val["version"].as_str().ok_or(Errno::ESTALE)?.to_owned();
            let st: Stat = serde_json::from_value(st_val).map_err(|_| Errno::EIO)?;
            let mode = (st.mode & 0o7777) as u16;
            let fs_session = self.connector.current_session();
            let fs_sess_ref = fs_session.as_ref().map(|(s, k)| (s.as_str(), k.as_str()));

            let (next, written) = match mutation {
                PageMutation::WriteAt { buf, at } => {
                    let write_off = match at {
                        WriteAt::Offset(off) => off,
                        WriteAt::End => st.size,
                    };
                    if write_off > FILE_MAX || buf.len() as u64 > FILE_MAX - write_off {
                        return Err(Errno::EINVAL);
                    }
                    if write_off + buf.len() as u64 > os_core::MAX_FILE
                        || st.size > os_core::MAX_FILE
                    {
                        return Err(Errno::EFBIG);
                    }
                    if buf.is_empty() {
                        return Ok(Written {
                            offset: write_off,
                            len: 0,
                        });
                    }
                    let off = usize::try_from(write_off).map_err(|_| Errno::EFBIG)?;
                    let end = off.checked_add(buf.len()).ok_or(Errno::EFBIG)?;
                    let cur_len = usize::try_from(st.size).map_err(|_| Errno::EFBIG)?;
                    let mut next = self
                        .read_page_prefix(path, expected_node, cur_len, sudo)
                        .await?;
                    if next.len() < end {
                        next.try_reserve_exact(end - next.len())
                            .map_err(|_| Errno::EFBIG)?;
                        next.resize(end, 0);
                    }
                    next[off..end].copy_from_slice(buf);
                    (
                        next,
                        Written {
                            offset: write_off,
                            len: buf.len(),
                        },
                    )
                }
                PageMutation::SetLen(size) => {
                    if size > os_core::MAX_FILE {
                        return Err(Errno::EFBIG);
                    }
                    let target_len = usize::try_from(size).map_err(|_| Errno::EFBIG)?;
                    let read_len = usize::try_from(st.size.min(size)).map_err(|_| Errno::EFBIG)?;
                    let mut next = self
                        .read_page_prefix(path, expected_node, read_len, sudo)
                        .await?;
                    next.try_reserve_exact(target_len - next.len())
                        .map_err(|_| Errno::EFBIG)?;
                    next.resize(target_len, 0);
                    (next, Written { offset: 0, len: 0 })
                }
            };

            match write_whole_cloud_page(
                path,
                &next,
                mode,
                false,
                umask,
                sudo,
                Some(&version),
                fs_sess_ref,
                target,
            )
            .await
            {
                Ok(_) => {
                    if let Some(id) = reader {
                        // Read/write descriptions must see their own newly committed content.
                        let (fd, _) = self.page_read_open(path, expected_node, sudo).await?;
                        let release = match self.opens.borrow_mut().get_mut(&id) {
                            Some(OpenRecord::Page { read_fd, .. }) => read_fd.replace(fd),
                            _ => Some(fd),
                        };
                        if let Some(old) = release {
                            old.close(sudo).await?;
                        }
                    }
                    return Ok(written);
                }
                Err(Errno::ESTALE) if attempt < 2 => continue,
                Err(err) => return Err(err),
            }
        }
        Err(Errno::ESTALE)
    }
}

#[derive(Clone, Copy)]
enum PageMutation<'a> {
    SetLen(u64),
    WriteAt { buf: &'a [u8], at: WriteAt },
}

impl Filesystem for RootCloudDriver {
    fn id(&self) -> &FsId {
        &self.fs_id
    }

    fn capabilities(&self) -> FsCapabilities {
        profiles::CLOUD
    }

    fn root(&self) -> Handle {
        self.make_handle(1)
    }

    fn lookup<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(async move {
            if !self.is_remote_mode() {
                return self.mem.lookup(cred, dir, name).await;
            }
            check_component(name)?;
            if self.is_cloud_denied(cred) {
                let dir_path = self.path_for_handle(dir).map_err(|_| Errno::EACCES)?;
                if is_mounted_carrier_dir(&dir_path) {
                    return Err(Errno::ENOENT);
                }
                let child_path = join_cloud_path(&dir_path, name);
                if let Some(entry) = self.cached_or_mem_carrier_entry(&child_path) {
                    return Ok(entry);
                }
                if name == "_"
                    && let Some(dir_entry) = self.cached_or_mem_carrier_entry(&dir_path)
                    && dir_entry.metadata.file_type == FileType::Dir
                    && cred_permits_exec(&dir_entry.metadata, cred)
                {
                    return Err(Errno::ENOENT);
                }
                return Err(Errno::EACCES);
            }
            // Local mountpoint carriers (`/`, `/usr`, `/proc`, `/dev`, `/run`, `/tmp`, `/mnt/*`,
            // `/opt/private`, `/bin`, `/sbin`, `/lib`, `/lib64`) resolve locally with ZERO RPCs.
            let known_dir_path = self.node_paths.borrow().get(&dir.node).cloned();
            if let Some(dir_path) = known_dir_path {
                if is_mounted_carrier_dir(&dir_path) {
                    return Err(Errno::ENOENT);
                }
                let child_path = join_cloud_path(&dir_path, name);
                if is_local_carrier_path(&child_path)
                    && let Some(entry) = self.cached_or_mem_carrier_entry(&child_path)
                {
                    return Ok(entry);
                }
            }
            if self.has_cloud_token(cred) {
                let (actor, cloud, rcred) = self.connect_cloud(cred).await?;
                let dir_path = self.node_paths.borrow().get(&dir.node).cloned();
                let res = self
                    .acted(actor, async {
                        let real_dir = self.ensure_cloud_handle(&cloud, &rcred, dir).await?;
                        cloud.fs.lookup(&rcred, &real_dir, name).await
                    })
                    .await;
                if let Err(Errno::ENOTCONN) = res
                    && cloud.live_opens.get() == 0
                {
                    self.connector.drop_if_same(&cloud);
                }
                let entry = res?;
                let child_path = dir_path.map(|p| join_cloud_path(&p, name));
                return Ok(self.wrap_cloud_entry(entry, child_path));
            }

            let dir_path = self.path_for_handle(dir)?;
            let child_path = join_cloud_path(&dir_path, name);
            if (self.use_seed_cache.get() || matches!(child_path.as_str(), "/usr" | "/sys"))
                && let Some(cached) = self.path_entries.borrow().get(&child_path).cloned()
            {
                return Ok(cached);
            }
            if let Some(hit) = self.lookup_page_cache(cred, &dir_path, &child_path, name) {
                return hit;
            }
            let sudo = self.page_sudo.get();
            let val = self
                .page_sys_one(
                    Call::Lstat {
                        path: child_path.clone(),
                    },
                    Some(cred.umask),
                    sudo,
                )
                .await?;
            let st: Stat = serde_json::from_value(val).map_err(|_| Errno::EIO)?;
            Ok(self.record_path_stat(&child_path, &st))
        })
    }

    fn walk<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        names: &'a [String],
    ) -> BoxFuture<'a, Walked> {
        Box::pin(async move {
            if !self.is_remote_mode() {
                return self.mem.walk(cred, dir, names).await;
            }
            for name in names {
                check_component(name)?;
            }
            if names.is_empty() {
                return Ok(Walked {
                    entries: Vec::new(),
                    stop: None,
                });
            }
            let starts_local_carrier = self.node_paths.borrow().get(&dir.node).is_some_and(|dp| {
                is_mounted_carrier_dir(dp) || is_local_carrier_path(&join_cloud_path(dp, &names[0]))
            });
            if !starts_local_carrier && self.has_cloud_token(cred) {
                let (actor, cloud, rcred) = self.connect_cloud(cred).await?;
                let base_path = self.node_paths.borrow().get(&dir.node).cloned();
                let res = self
                    .acted(actor, async {
                        let real_dir = self.ensure_cloud_handle(&cloud, &rcred, dir).await?;
                        cloud.fs.walk(&rcred, &real_dir, names).await
                    })
                    .await;
                if let Err(Errno::ENOTCONN) = res
                    && cloud.live_opens.get() == 0
                {
                    self.connector.drop_if_same(&cloud);
                }
                let walked = res?;
                let mut cur_path = base_path;
                let entries = walked
                    .entries
                    .into_iter()
                    .enumerate()
                    .map(|(idx, e)| {
                        let next_path = cur_path.as_ref().map(|p| join_cloud_path(p, &names[idx]));
                        cur_path = next_path.clone();
                        self.wrap_cloud_entry(e, next_path)
                    })
                    .collect();
                return Ok(Walked {
                    entries,
                    stop: walked.stop,
                });
            }

            let mut cur = dir.clone();
            let mut cur_kind: Option<FileType> = None;
            let mut entries = Vec::new();
            for (idx, name) in names.iter().enumerate() {
                if let Some(ft) = cur_kind {
                    let stop = match ft {
                        FileType::Dir => None,
                        FileType::Symlink => Some(Stop::Symlink(idx - 1)),
                        _ => Some(Stop::NotDirectory(idx - 1)),
                    };
                    if stop.is_some() {
                        return Ok(Walked { entries, stop });
                    }
                }
                match self.lookup(cred, &cur, name).await {
                    Ok(entry) => {
                        cur = entry.handle.clone();
                        cur_kind = Some(entry.metadata.file_type);
                        entries.push(entry);
                    }
                    Err(Errno::ENOENT) => {
                        return Ok(Walked {
                            entries,
                            stop: Some(Stop::Missing(idx)),
                        });
                    }
                    Err(err) => return Err(err),
                }
            }
            Ok(Walked {
                entries,
                stop: None,
            })
        })
    }

    fn parent<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
    ) -> BoxFuture<'a, Option<(Entry, String)>> {
        Box::pin(async move {
            if !self.is_remote_mode() {
                return self.mem.parent(cred, dir).await;
            }
            if dir.fs != self.fs_id {
                return Err(Errno::EACCES);
            }
            if dir.node.ino == 1 {
                return Ok(None);
            }
            if self.is_cloud_denied(cred) {
                let path = self.path_for_handle(dir).map_err(|_| Errno::EACCES)?;
                if !is_local_carrier_path(&path) {
                    return Err(Errno::EACCES);
                }
                let Some((parent_path, name)) = split_cloud_parent(&path) else {
                    return Ok(None);
                };
                let parent_entry = self
                    .cached_or_mem_carrier_entry(&parent_path)
                    .ok_or(Errno::EACCES)?;
                return Ok(Some((parent_entry, name)));
            }
            let known_path = self.node_paths.borrow().get(&dir.node).cloned();
            if let Some(path) = known_path
                && is_local_carrier_path(&path)
                && let Some((parent_path, name)) = split_cloud_parent(&path)
                && let Some(parent_entry) = self.cached_or_mem_carrier_entry(&parent_path)
            {
                return Ok(Some((parent_entry, name)));
            }
            if self.has_cloud_token(cred) {
                let (actor, cloud, rcred) = self.connect_cloud(cred).await?;
                let child_path = self.node_paths.borrow().get(&dir.node).cloned();
                let res = self
                    .acted(actor, async {
                        let real_dir = self.ensure_cloud_handle(&cloud, &rcred, dir).await?;
                        cloud.fs.parent(&rcred, &real_dir).await
                    })
                    .await?;
                return Ok(res.map(|(entry, name)| {
                    let parent_path = child_path
                        .as_deref()
                        .and_then(split_cloud_parent)
                        .map(|(p, _)| p);
                    (self.wrap_cloud_entry(entry, parent_path), name)
                }));
            }
            let path = self.path_for_handle(dir)?;
            let Some((parent_path, name)) = split_cloud_parent(&path) else {
                return Ok(None);
            };
            if self.use_seed_cache.get()
                && let Some(cached) = self.path_entries.borrow().get(&parent_path).cloned()
            {
                return Ok(Some((cached, name)));
            }
            if let Some(cached) = self.cached_page_entry(cred, &parent_path) {
                return Ok(Some((cached, name)));
            }
            if let Some(err) = self.cached_page_transport_err(cred) {
                return Err(err);
            }
            let sudo = self.page_sudo.get();
            let val = self
                .page_sys_one(
                    Call::Lstat {
                        path: parent_path.clone(),
                    },
                    Some(cred.umask),
                    sudo,
                )
                .await?;
            let st: Stat = serde_json::from_value(val).map_err(|_| Errno::EIO)?;
            Ok(Some((self.record_path_stat(&parent_path, &st), name)))
        })
    }

    fn metadata<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Metadata> {
        Box::pin(async move {
            if !self.is_remote_mode() {
                return self.mem.metadata(cred, handle).await;
            }
            if handle.fs != self.fs_id {
                return Err(Errno::EACCES);
            }
            if self.is_cloud_denied(cred) {
                let path = self.path_for_handle(handle).map_err(|_| Errno::EACCES)?;
                return self
                    .cached_or_mem_carrier_entry(&path)
                    .map(|e| e.metadata)
                    .ok_or(Errno::EACCES);
            }
            let known_path = self.node_paths.borrow().get(&handle.node).cloned();
            if let Some(path) = known_path
                && is_local_carrier_path(&path)
                && (self.active_pid.get().is_some() || !self.server_seeded.get())
                && let Some(entry) = self.cached_or_mem_carrier_entry(&path)
            {
                return Ok(entry.metadata);
            }
            if self.has_cloud_token(cred) {
                let (actor, cloud, rcred) = self.connect_cloud(cred).await?;
                let mut meta = self
                    .acted(actor, async {
                        let real = self.ensure_cloud_handle(&cloud, &rcred, handle).await?;
                        cloud.fs.metadata(&rcred, &real).await
                    })
                    .await?;
                self.strip_and_record_writing(handle.node.ino, &mut meta);
                return Ok(meta);
            }
            if (self.use_seed_cache.get() || installed("pageSysPost").is_err())
                && let Some(path) = self.node_paths.borrow().get(&handle.node).cloned()
                && let Some(cached) = self.path_entries.borrow().get(&path).cloned()
            {
                return Ok(cached.metadata);
            }
            let path = self.path_for_handle(handle)?;
            if let Some(cached) = self.cached_page_entry(cred, &path) {
                return Ok(cached.metadata);
            }
            if let Some(err) = self.cached_page_transport_err(cred) {
                return Err(err);
            }
            let sudo = self.page_sudo.get();
            let val = self
                .page_sys_one(Call::Lstat { path: path.clone() }, Some(cred.umask), sudo)
                .await?;
            let st: Stat = serde_json::from_value(val).map_err(|_| Errno::EIO)?;
            Ok(self.record_path_stat(&path, &st).metadata)
        })
    }

    fn setattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        attr: &'a SetAttr,
    ) -> BoxFuture<'a, Metadata> {
        Box::pin(async move {
            if !self.is_remote_mode() {
                return self.mem.setattr(cred, handle, attr).await;
            }
            self.bump_page_mutation();
            if self.is_cloud_denied(cred) {
                return Err(Errno::EACCES);
            }
            if self.has_cloud_token(cred) {
                let (actor, cloud, rcred) = self.connect_cloud(cred).await?;
                let mut meta = self
                    .acted(actor, async {
                        let real = self.ensure_cloud_handle(&cloud, &rcred, handle).await?;
                        cloud.fs.setattr(&rcred, &real, attr).await
                    })
                    .await?;
                self.strip_and_record_writing(handle.node.ino, &mut meta);
                return Ok(meta);
            }
            let path = self.path_for_handle(handle)?;
            let sudo = self.page_sudo.get();
            if let Some(size) = attr.size {
                self.page_rmw_mutate(
                    &path,
                    handle.node,
                    cred.umask,
                    sudo,
                    PageMutation::SetLen(size),
                    None,
                )
                .await?;
            }
            if attr.uid.is_some() || attr.gid.is_some() {
                self.page_sys_one(
                    Call::Chown {
                        path: path.clone(),
                        uid: attr.uid,
                        gid: attr.gid,
                        nofollow: true,
                    },
                    Some(cred.umask),
                    sudo,
                )
                .await?;
            }
            if let Some(mode) = attr.mode {
                self.guarded_page_call(
                    Call::Chmod {
                        path: path.clone(),
                        mode,
                    },
                    Some(cred.umask),
                    sudo,
                    PageTarget::Inode(self.page_ino(handle.node)),
                )
                .await?;
            }
            if !matches!(attr.atime, Time::Omit) || !matches!(attr.mtime, Time::Omit) {
                self.page_sys_one(
                    Call::Utimens {
                        path: path.clone(),
                        atime: attr.atime,
                        mtime: attr.mtime,
                        nofollow: true,
                    },
                    Some(cred.umask),
                    sudo,
                )
                .await?;
            }
            self.path_entries.borrow_mut().remove(&path);
            self.metadata(cred, handle).await
        })
    }

    fn setattr_open<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        open: &'a OpenRef,
        attr: &'a SetAttr,
    ) -> BoxFuture<'a, Metadata> {
        Box::pin(async move {
            let fd = match self.opens.borrow().get(&open.id) {
                Some(OpenRecord::Page { read_fd, .. }) => read_fd.clone(),
                _ => None,
            };
            if let (Some(fd), Some(mode)) = (fd, attr.mode)
                && *attr
                    == (SetAttr {
                        mode: Some(mode),
                        ..SetAttr::default()
                    })
            {
                let value = fd
                    .call(
                        Call::Fchmod {
                            fd: fd.fd.into(),
                            mode,
                        },
                        self.page_sudo.get(),
                    )
                    .await?;
                let stat: Stat = serde_json::from_value(value).map_err(|_| Errno::EIO)?;
                let meta = stat_to_metadata(&stat);
                self.bump_page_mutation();
                if let Some(OpenRecord::Page {
                    read_meta: Some(cached),
                    ..
                }) = self.opens.borrow_mut().get_mut(&open.id)
                {
                    *cached = meta.clone();
                }
                return Ok(meta);
            }
            self.setattr(cred, handle, attr).await
        })
    }

    fn read_dir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle) -> BoxFuture<'a, Vec<DirEntry>> {
        Box::pin(async move {
            if !self.is_remote_mode() {
                return self.mem.read_dir(cred, dir).await;
            }
            if self.is_cloud_denied(cred) {
                return Err(Errno::EACCES);
            }
            if self.has_cloud_token(cred) {
                let (actor, cloud, rcred) = self.connect_cloud(cred).await?;
                let dir_path = self.node_paths.borrow().get(&dir.node).cloned();
                let mut entries = self
                    .acted(actor, async {
                        let real = self.ensure_cloud_handle(&cloud, &rcred, dir).await?;
                        cloud.fs.read_dir(&rcred, &real).await
                    })
                    .await?;
                if let Some(base) = dir_path {
                    let mut paths = self.node_paths.borrow_mut();
                    for item in &mut entries {
                        let child = join_cloud_path(&base, &item.name);
                        item.node = self.wrap_remote_node(item.node, Some(&child));
                        paths.insert(item.node, child);
                    }
                } else {
                    for item in &mut entries {
                        item.node = self.wrap_remote_node(item.node, None);
                    }
                }
                return Ok(entries);
            }

            let dir_path = self.path_for_handle(dir)?;
            if let Some(err) = self.cached_page_transport_err(cred) {
                return Err(err);
            }
            let sudo = self.page_sudo.get();
            let val = self
                .page_sys_one(
                    Call::Getdents {
                        path: dir_path.clone(),
                        cookie: 0,
                        count: None,
                    },
                    Some(cred.umask),
                    sudo,
                )
                .await?;
            let raw_entries: Vec<abi::Dirent> =
                serde_json::from_value(val).map_err(|_| Errno::EIO)?;
            let mut all_have_stat = true;
            let mut out = Vec::with_capacity(raw_entries.len());
            for item in raw_entries {
                let child_path = join_cloud_path(&dir_path, &item.name);
                if let Some(st) = item.stat {
                    let recorded = self.record_path_stat(&child_path, &st);
                    out.push(DirEntry {
                        name: item.name,
                        node: recorded.handle.node,
                        file_type: recorded.metadata.file_type,
                    });
                } else {
                    all_have_stat = false;
                }
            }
            if all_have_stat
                && let Some(dir_entry) = self.cached_page_entry(cred, &dir_path)
                && let Some(cache) = self.page_read_cache.borrow_mut().as_mut()
                && cache.uid == cred.identity.id
                && cache.sudo == sudo
                && cache.mut_epoch == self.page_mut_epoch.get()
            {
                cache.complete_dirs.insert(dir_path, dir_entry.metadata);
            }
            Ok(out)
        })
    }

    fn read_link<'a>(&'a self, cred: &'a Cred, link: &'a Handle) -> BoxFuture<'a, String> {
        Box::pin(async move {
            if !self.is_remote_mode() {
                return self.mem.read_link(cred, link).await;
            }
            if self.is_cloud_denied(cred) {
                let path = self.path_for_handle(link).map_err(|_| Errno::EACCES)?;
                return SEED_SYMLINKS
                    .iter()
                    .find_map(|&(p, target)| (p == path).then(|| target.to_string()))
                    .ok_or(Errno::EACCES);
            }
            let known_link_path = self.node_paths.borrow().get(&link.node).cloned();
            if let Some(path) = known_link_path
                && let Some(target) = SEED_SYMLINKS
                    .iter()
                    .find_map(|&(p, target)| (p == path).then(|| target.to_string()))
            {
                return Ok(target);
            }
            if self.has_cloud_token(cred) {
                let (actor, cloud, rcred) = self.connect_cloud(cred).await?;
                return self
                    .acted(actor, async {
                        let real = self.ensure_cloud_handle(&cloud, &rcred, link).await?;
                        cloud.fs.read_link(&rcred, &real).await
                    })
                    .await;
            }
            let path = self.path_for_handle(link)?;
            if let Some(target) = self.cached_page_link(cred, &path) {
                return Ok(target);
            }
            if let Some(err) = self.cached_page_transport_err(cred) {
                return Err(err);
            }
            let sudo = self.page_sudo.get();
            let val = self
                .page_sys_one(Call::Readlink { path }, Some(cred.umask), sudo)
                .await?;
            val.as_str().map(str::to_string).ok_or(Errno::EIO)
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
            if !self.is_remote_mode() {
                let (entry, oref) = self.mem.create(cred, dir, name, mode, options).await?;
                let wrapped =
                    self.alloc_open(entry.handle.node, oref.access, OpenRecord::Mem(oref));
                return Ok((entry, wrapped));
            }
            self.bump_page_mutation();
            check_component(name)?;
            if self.is_cloud_denied(cred) {
                return Err(Errno::EACCES);
            }
            if self.has_cloud_token(cred) {
                let (actor, cloud, rcred) = self.connect_cloud(cred).await?;
                let dir_path = self.node_paths.borrow().get(&dir.node).cloned();
                let (entry, real_open) = self
                    .acted(actor, async {
                        let real_dir = self.ensure_cloud_handle(&cloud, &rcred, dir).await?;
                        cloud
                            .fs
                            .create(&rcred, &real_dir, name, mode, options)
                            .await
                    })
                    .await?;
                cloud.live_opens.set(cloud.live_opens.get() + 1);
                let child_path = dir_path.map(|p| join_cloud_path(&p, name));
                let wrapped_entry = self.wrap_cloud_entry(entry, child_path);
                let oref = self.alloc_open(
                    wrapped_entry.handle.node,
                    real_open.access,
                    OpenRecord::Remote {
                        cloud,
                        real: real_open,
                    },
                );
                return Ok((wrapped_entry, oref));
            }

            let access = options.access()?;
            let dir_path = self.path_for_handle(dir)?;
            let child_path = join_cloud_path(&dir_path, name);
            let sudo = self.page_sudo.get();
            let fs_session = self.connector.current_session();
            let fs_sess_ref = fs_session.as_ref().map(|(s, k)| (s.as_str(), k.as_str()));
            // The VFS resolved a missing final component. A racing creator owns its inode.
            let st = write_whole_cloud_page(
                &child_path,
                &[],
                mode,
                true,
                cred.umask,
                sudo,
                None,
                fs_sess_ref,
                PageTarget::MissingIn(self.page_ino(dir.node)),
            )
            .await?;
            let entry = self.record_path_stat(&child_path, &st);
            let read_fd = if access.reads() {
                Some(
                    self.page_read_open(&child_path, entry.handle.node, sudo)
                        .await?
                        .0,
                )
            } else {
                None
            };
            let oref = self.alloc_open(
                entry.handle.node,
                access,
                OpenRecord::Page {
                    read_meta: (read_fd.is_some() && !access.writes())
                        .then(|| entry.metadata.clone()),
                    read_fd,
                    path: child_path,
                    node: entry.handle.node,
                    access,
                    sudo,
                    stale: false,
                },
            );
            Ok((entry, oref))
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
            if !self.is_remote_mode() {
                return self.mem.mkdir(cred, dir, name, mode).await;
            }
            self.bump_page_mutation();
            check_component(name)?;
            if self.is_cloud_denied(cred) {
                return Err(Errno::EACCES);
            }
            if self.has_cloud_token(cred) {
                let (actor, cloud, rcred) = self.connect_cloud(cred).await?;
                let dir_path = self.node_paths.borrow().get(&dir.node).cloned();
                let entry = self
                    .acted(actor, async {
                        let real = self.ensure_cloud_handle(&cloud, &rcred, dir).await?;
                        cloud.fs.mkdir(&rcred, &real, name, mode).await
                    })
                    .await?;
                return Ok(
                    self.wrap_cloud_entry(entry, dir_path.map(|p| join_cloud_path(&p, name)))
                );
            }
            let dir_path = self.path_for_handle(dir)?;
            let child_path = join_cloud_path(&dir_path, name);
            let sudo = self.page_sudo.get();
            self.page_sys_one(
                Call::Mkdir {
                    path: child_path.clone(),
                    mode,
                },
                Some(cred.umask),
                sudo,
            )
            .await?;
            let val = self
                .page_sys_one(
                    Call::Lstat {
                        path: child_path.clone(),
                    },
                    Some(cred.umask),
                    sudo,
                )
                .await?;
            let st: Stat = serde_json::from_value(val).map_err(|_| Errno::EIO)?;
            Ok(self.record_path_stat(&child_path, &st))
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
            if !self.is_remote_mode() {
                return self.mem.mknod(cred, dir, name, mode, rdev).await;
            }
            self.bump_page_mutation();
            check_component(name)?;
            if self.is_cloud_denied(cred) {
                return Err(Errno::EACCES);
            }
            if self.has_cloud_token(cred) {
                let (actor, cloud, rcred) = self.connect_cloud(cred).await?;
                let dir_path = self.node_paths.borrow().get(&dir.node).cloned();
                let entry = self
                    .acted(actor, async {
                        let real = self.ensure_cloud_handle(&cloud, &rcred, dir).await?;
                        cloud.fs.mknod(&rcred, &real, name, mode, rdev).await
                    })
                    .await?;
                return Ok(
                    self.wrap_cloud_entry(entry, dir_path.map(|p| join_cloud_path(&p, name)))
                );
            }
            let dir_path = self.path_for_handle(dir)?;
            let child_path = join_cloud_path(&dir_path, name);
            let rdev_opt =
                if (rdev.is_empty() || rdev == "0") && u32::from(mode) & 0o170000 == abi::S_IFCHR {
                    match dir_path.as_str() {
                        "/dev/present" => Some("present".into()),
                        "/dev/snd" => Some("snd".into()),
                        _ => return Err(Errno::EINVAL),
                    }
                } else {
                    (!rdev.is_empty()).then(|| rdev.to_string())
                };
            if let Some(token) = &cred.token {
                let pid = self.active_pid.get().unwrap_or(1);
                let host = BrowserHost {
                    state: self.state.clone(),
                    current: self.current.clone(),
                };
                let body = serde_json::to_vec(&Batch {
                    calls: vec![
                        Call::Mknod {
                            path: child_path.clone(),
                            mode,
                            rdev: rdev_opt,
                        },
                        Call::Lstat {
                            path: child_path.clone(),
                        },
                    ],
                    umask: Some(cred.umask),
                    sudo: false,
                    pid: Some(pid),
                    process: Some(token.clone()),
                })
                .map_err(|_| Errno::EIO)?;
                let reply = host
                    .post(
                        "/api/sys",
                        vec![("Content-Type", "application/json".to_string())],
                        body,
                    )
                    .await?;
                if reply.status != 200 {
                    return Err(Errno::EIO);
                }
                let res: Results = serde_json::from_slice(&reply.body).map_err(|_| Errno::EIO)?;
                let mut iter = res.results.into_iter();
                iter.next()
                    .ok_or(Errno::EIO)?
                    .into_result()
                    .map_err(|e| e.errno)?;
                let st_val = iter
                    .next()
                    .ok_or(Errno::EIO)?
                    .into_result()
                    .map_err(|e| e.errno)?;
                let st: Stat = serde_json::from_value(st_val).map_err(|_| Errno::EIO)?;
                return Ok(self.record_path_stat(&child_path, &st));
            }
            let sudo = self.page_sudo.get();
            self.page_sys_one(
                Call::Mknod {
                    path: child_path.clone(),
                    mode,
                    rdev: rdev_opt,
                },
                Some(cred.umask),
                sudo,
            )
            .await?;
            let val = self
                .page_sys_one(
                    Call::Lstat {
                        path: child_path.clone(),
                    },
                    Some(cred.umask),
                    sudo,
                )
                .await?;
            let st: Stat = serde_json::from_value(val).map_err(|_| Errno::EIO)?;
            Ok(self.record_path_stat(&child_path, &st))
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
            if !self.is_remote_mode() {
                return self.mem.symlink(cred, dir, name, target).await;
            }
            self.bump_page_mutation();
            check_component(name)?;
            if self.is_cloud_denied(cred) {
                return Err(Errno::EACCES);
            }
            if self.has_cloud_token(cred) {
                let (actor, cloud, rcred) = self.connect_cloud(cred).await?;
                let dir_path = self.node_paths.borrow().get(&dir.node).cloned();
                let entry = self
                    .acted(actor, async {
                        let real = self.ensure_cloud_handle(&cloud, &rcred, dir).await?;
                        cloud.fs.symlink(&rcred, &real, name, target).await
                    })
                    .await?;
                return Ok(
                    self.wrap_cloud_entry(entry, dir_path.map(|p| join_cloud_path(&p, name)))
                );
            }
            let dir_path = self.path_for_handle(dir)?;
            let child_path = join_cloud_path(&dir_path, name);
            let sudo = self.page_sudo.get();
            self.page_sys_one(
                Call::Symlink {
                    target: target.to_string(),
                    path: child_path.clone(),
                },
                Some(cred.umask),
                sudo,
            )
            .await?;
            let val = self
                .page_sys_one(
                    Call::Lstat {
                        path: child_path.clone(),
                    },
                    Some(cred.umask),
                    sudo,
                )
                .await?;
            let st: Stat = serde_json::from_value(val).map_err(|_| Errno::EIO)?;
            Ok(self.record_path_stat(&child_path, &st))
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
            if !self.is_remote_mode() {
                return self.mem.link(cred, target, dir, name).await;
            }
            self.bump_page_mutation();
            check_component(name)?;
            if self.is_cloud_denied(cred) {
                return Err(Errno::EACCES);
            }
            if self.has_cloud_token(cred) {
                let (actor, cloud, rcred) = self.connect_cloud(cred).await?;
                let dir_path = self.node_paths.borrow().get(&dir.node).cloned();
                let entry = self
                    .acted(actor, async {
                        let real_target = self.ensure_cloud_handle(&cloud, &rcred, target).await?;
                        let real_dir = self.ensure_cloud_handle(&cloud, &rcred, dir).await?;
                        cloud.fs.link(&rcred, &real_target, &real_dir, name).await
                    })
                    .await?;
                return Ok(
                    self.wrap_cloud_entry(entry, dir_path.map(|p| join_cloud_path(&p, name)))
                );
            }
            let from_path = self.path_for_handle(target)?;
            let dir_path = self.path_for_handle(dir)?;
            let to_path = join_cloud_path(&dir_path, name);
            let sudo = self.page_sudo.get();
            self.page_sys_one(
                Call::Link {
                    from: from_path,
                    to: to_path.clone(),
                    follow: false,
                },
                Some(cred.umask),
                sudo,
            )
            .await?;
            let val = self
                .page_sys_one(
                    Call::Lstat {
                        path: to_path.clone(),
                    },
                    Some(cred.umask),
                    sudo,
                )
                .await?;
            let st: Stat = serde_json::from_value(val).map_err(|_| Errno::EIO)?;
            Ok(self.record_path_stat(&to_path, &st))
        })
    }

    fn unlink<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if !self.is_remote_mode() {
                return self.mem.unlink(cred, dir, name).await;
            }
            self.bump_page_mutation();
            check_component(name)?;
            if self.is_cloud_denied(cred) {
                return Err(Errno::EACCES);
            }
            if self.has_cloud_token(cred) {
                let (actor, cloud, rcred) = self.connect_cloud(cred).await?;
                let dir_path = self.node_paths.borrow().get(&dir.node).cloned();
                self.acted(actor, async {
                    let real = self.ensure_cloud_handle(&cloud, &rcred, dir).await?;
                    cloud.fs.unlink(&rcred, &real, name).await
                })
                .await?;
                if let Some(base) = dir_path {
                    self.invalidate_page_path(&join_cloud_path(&base, name), false);
                }
                return Ok(());
            }
            let dir_path = self.path_for_handle(dir)?;
            let child_path = join_cloud_path(&dir_path, name);
            let sudo = self.page_sudo.get();
            self.page_sys_one(
                Call::Unlink {
                    path: child_path.clone(),
                },
                Some(cred.umask),
                sudo,
            )
            .await?;
            self.invalidate_page_path(&child_path, false);
            Ok(())
        })
    }

    fn unlink_if<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        node: NodeId,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if !self.is_remote_mode() {
                return self.mem.unlink_if(cred, dir, name, node).await;
            }
            if self.is_cloud_denied(cred) || cred.token.is_some() {
                return Err(Errno::EACCES);
            }
            check_component(name)?;
            let path = join_cloud_path(&self.path_for_handle(dir)?, name);
            self.guarded_page_call(
                Call::Unlink { path: path.clone() },
                Some(cred.umask),
                self.page_sudo.get(),
                PageTarget::Inode(self.page_ino(node)),
            )
            .await?;
            self.invalidate_page_path(&path, false);
            Ok(())
        })
    }

    fn rmdir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if !self.is_remote_mode() {
                return self.mem.rmdir(cred, dir, name).await;
            }
            self.bump_page_mutation();
            check_component(name)?;
            if self.is_cloud_denied(cred) {
                return Err(Errno::EACCES);
            }
            if self.has_cloud_token(cred) {
                let (actor, cloud, rcred) = self.connect_cloud(cred).await?;
                let dir_path = self.node_paths.borrow().get(&dir.node).cloned();
                self.acted(actor, async {
                    let real = self.ensure_cloud_handle(&cloud, &rcred, dir).await?;
                    cloud.fs.rmdir(&rcred, &real, name).await
                })
                .await?;
                if let Some(base) = dir_path {
                    self.invalidate_page_path(&join_cloud_path(&base, name), true);
                }
                return Ok(());
            }
            let dir_path = self.path_for_handle(dir)?;
            let child_path = join_cloud_path(&dir_path, name);
            let sudo = self.page_sudo.get();
            self.page_sys_one(
                Call::Rmdir {
                    path: child_path.clone(),
                },
                Some(cred.umask),
                sudo,
            )
            .await?;
            self.invalidate_page_path(&child_path, true);
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
            if !self.is_remote_mode() {
                return self
                    .mem
                    .rename(cred, from_dir, from, to_dir, to, flags)
                    .await;
            }
            self.bump_page_mutation();
            check_component(from)?;
            check_component(to)?;
            if self.is_cloud_denied(cred) {
                return Err(Errno::EACCES);
            }
            if self.has_cloud_token(cred) {
                let (actor, cloud, rcred) = self.connect_cloud(cred).await?;
                let from_base = self.node_paths.borrow().get(&from_dir.node).cloned();
                let to_base = self.node_paths.borrow().get(&to_dir.node).cloned();
                self.acted(actor, async {
                    let rf = self.ensure_cloud_handle(&cloud, &rcred, from_dir).await?;
                    let rt = self.ensure_cloud_handle(&cloud, &rcred, to_dir).await?;
                    cloud.fs.rename(&rcred, &rf, from, &rt, to, flags).await
                })
                .await?;
                if let (Some(fb), Some(tb)) = (from_base, to_base) {
                    let old_prefix = join_cloud_path(&fb, from);
                    let new_prefix = join_cloud_path(&tb, to);
                    self.rename_page_paths(&old_prefix, &new_prefix);
                }
                return Ok(());
            }
            let from_base = self.path_for_handle(from_dir)?;
            let to_base = self.path_for_handle(to_dir)?;
            let old_path = join_cloud_path(&from_base, from);
            let new_path = join_cloud_path(&to_base, to);
            let sudo = self.page_sudo.get();
            self.page_sys_one(
                Call::Rename {
                    from: old_path.clone(),
                    to: new_path.clone(),
                    noreplace: flags.contains(RenameFlags::NOREPLACE),
                },
                Some(cred.umask),
                sudo,
            )
            .await?;
            self.rename_page_paths(&old_path, &new_path);
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
            if !self.is_remote_mode() {
                return self.mem.getxattr(cred, handle, name).await;
            }
            if self.is_cloud_denied(cred) {
                return Err(Errno::EACCES);
            }
            if self.has_cloud_token(cred) {
                let (actor, cloud, rcred) = self.connect_cloud(cred).await?;
                return self
                    .acted(actor, async {
                        let real = self.ensure_cloud_handle(&cloud, &rcred, handle).await?;
                        cloud.fs.getxattr(&rcred, &real, name).await
                    })
                    .await;
            }
            let path = self.path_for_handle(handle)?;
            let sudo = self.page_sudo.get();
            let val = self
                .page_sys_one(
                    Call::Getxattr {
                        path,
                        name: name.to_string(),
                        nofollow: true,
                    },
                    Some(cred.umask),
                    sudo,
                )
                .await?;
            let bytes: Bytes = serde_json::from_value(val).map_err(|_| Errno::EIO)?;
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
            if !self.is_remote_mode() {
                return self.mem.setxattr(cred, handle, name, value, flags).await;
            }
            self.bump_page_mutation();
            if self.is_cloud_denied(cred) {
                return Err(Errno::EACCES);
            }
            if self.has_cloud_token(cred) {
                let (actor, cloud, rcred) = self.connect_cloud(cred).await?;
                return self
                    .acted(actor, async {
                        let real = self.ensure_cloud_handle(&cloud, &rcred, handle).await?;
                        cloud.fs.setxattr(&rcred, &real, name, value, flags).await
                    })
                    .await;
            }
            let path = self.path_for_handle(handle)?;
            let sudo = self.page_sudo.get();
            self.page_sys_one(
                Call::Setxattr {
                    path,
                    name: name.to_string(),
                    value: Bytes(value.to_vec()),
                    flags: flags.bits(),
                    nofollow: true,
                },
                Some(cred.umask),
                sudo,
            )
            .await
            .map(|_| ())
        })
    }

    fn listxattr<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Vec<String>> {
        Box::pin(async move {
            if !self.is_remote_mode() {
                return self.mem.listxattr(cred, handle).await;
            }
            if self.is_cloud_denied(cred) {
                return Err(Errno::EACCES);
            }
            if self.has_cloud_token(cred) {
                let (actor, cloud, rcred) = self.connect_cloud(cred).await?;
                return self
                    .acted(actor, async {
                        let real = self.ensure_cloud_handle(&cloud, &rcred, handle).await?;
                        cloud.fs.listxattr(&rcred, &real).await
                    })
                    .await;
            }
            let path = self.path_for_handle(handle)?;
            let sudo = self.page_sudo.get();
            let val = self
                .page_sys_one(
                    Call::Listxattr {
                        path,
                        nofollow: true,
                    },
                    Some(cred.umask),
                    sudo,
                )
                .await?;
            serde_json::from_value(val).map_err(|_| Errno::EIO)
        })
    }

    fn removexattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if !self.is_remote_mode() {
                return self.mem.removexattr(cred, handle, name).await;
            }
            self.bump_page_mutation();
            if self.is_cloud_denied(cred) {
                return Err(Errno::EACCES);
            }
            if self.has_cloud_token(cred) {
                let (actor, cloud, rcred) = self.connect_cloud(cred).await?;
                return self
                    .acted(actor, async {
                        let real = self.ensure_cloud_handle(&cloud, &rcred, handle).await?;
                        cloud.fs.removexattr(&rcred, &real, name).await
                    })
                    .await;
            }
            let path = self.path_for_handle(handle)?;
            let sudo = self.page_sudo.get();
            self.page_sys_one(
                Call::Removexattr {
                    path,
                    name: name.to_string(),
                    nofollow: true,
                },
                Some(cred.umask),
                sudo,
            )
            .await
            .map(|_| ())
        })
    }

    fn statfs<'a>(&'a self, cred: &'a Cred) -> BoxFuture<'a, StatFs> {
        Box::pin(async move {
            if !self.is_remote_mode() {
                return self.mem.statfs(cred).await;
            }
            if self.is_cloud_denied(cred) {
                return Err(Errno::EACCES);
            }
            if self.has_cloud_token(cred) {
                let (actor, cloud, rcred) = self.connect_cloud(cred).await?;
                return self.acted(actor, cloud.fs.statfs(&rcred)).await;
            }
            let sudo = self.page_sudo.get();
            let val = self
                .page_sys_one(
                    Call::Statfs {
                        path: "/".to_string(),
                    },
                    Some(cred.umask),
                    sudo,
                )
                .await?;
            let sfs: abi::StatFs = serde_json::from_value(val).map_err(|_| Errno::EIO)?;
            Ok(StatFs {
                block_size: sfs.bsize,
                blocks: sfs.blocks,
                blocks_free: sfs.bfree,
                files: sfs.files,
                files_free: sfs.ffree,
                name_max: sfs.namelen,
            })
        })
    }

    fn open<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        options: &'a OpenOptions,
    ) -> BoxFuture<'a, OpenRef> {
        Box::pin(async move {
            if !self.is_remote_mode() {
                let oref = self.mem.open(cred, handle, options).await?;
                return Ok(self.alloc_open(handle.node, oref.access, OpenRecord::Mem(oref)));
            }
            if handle.fs != self.fs_id {
                return Err(Errno::EACCES);
            }
            let access = options.access()?;
            if self.is_cloud_denied(cred) {
                let path = self.path_for_handle(handle).map_err(|_| Errno::EACCES)?;
                if access != Access::Path || !is_local_carrier_path(&path) {
                    return Err(Errno::EACCES);
                }
                return Ok(self.alloc_open(
                    handle.node,
                    Access::Path,
                    OpenRecord::PathOnly { node: handle.node },
                ));
            }
            if access == Access::Path
                && self
                    .node_paths
                    .borrow()
                    .get(&handle.node)
                    .is_some_and(|p| is_local_carrier_path(p))
            {
                return Ok(self.alloc_open(
                    handle.node,
                    Access::Path,
                    OpenRecord::PathOnly { node: handle.node },
                ));
            }
            if self.has_cloud_token(cred) {
                let (actor, cloud, rcred) = self.connect_cloud(cred).await?;
                let real_open = self
                    .acted(actor, async {
                        let real = self.ensure_cloud_handle(&cloud, &rcred, handle).await?;
                        cloud.fs.open(&rcred, &real, options).await
                    })
                    .await?;
                cloud.live_opens.set(cloud.live_opens.get() + 1);
                return Ok(self.alloc_open(
                    handle.node,
                    real_open.access,
                    OpenRecord::Remote {
                        cloud,
                        real: real_open,
                    },
                ));
            }

            if access == Access::Path {
                return Ok(self.alloc_open(
                    handle.node,
                    Access::Path,
                    OpenRecord::PathOnly { node: handle.node },
                ));
            }

            let path = self.path_for_handle(handle)?;
            let meta = self.metadata(cred, handle).await?;
            if meta.is_symlink() {
                return Err(Errno::ELOOP);
            }
            if meta.is_dir() && (access.writes() || options.is_truncate()) {
                return Err(Errno::EISDIR);
            }
            if access == Access::Exec && !meta.is_file() {
                return Err(Errno::EACCES);
            }
            let sudo = self.page_sudo.get();
            let mut mode_bits = 0u16;
            if access == Access::Exec {
                if cred.identity.id == 0 && (meta.mode & 0o111) == 0 {
                    return Err(Errno::EACCES);
                }
                mode_bits |= abi::X_OK;
            } else {
                if access.reads() {
                    mode_bits |= abi::R_OK;
                }
                if access.writes() || options.is_truncate() {
                    mode_bits |= abi::W_OK;
                }
            }
            if mode_bits != 0 && installed("pageSysPost").is_ok() {
                self.guarded_page_call(
                    Call::Access {
                        path: path.clone(),
                        mode: mode_bits,
                    },
                    Some(cred.umask),
                    sudo,
                    PageTarget::Inode(self.page_ino(handle.node)),
                )
                .await?;
            }
            if options.is_truncate() && meta.is_file() {
                self.bump_page_mutation();
                self.path_entries.borrow_mut().remove(&path);
                self.page_rmw_mutate(
                    &path,
                    handle.node,
                    cred.umask,
                    sudo,
                    PageMutation::SetLen(0),
                    None,
                )
                .await?;
            }
            let (read_fd, read_meta) = if access.reads() && meta.is_file() {
                match self.page_read_open(&path, handle.node, sudo).await {
                    Ok((fd, st)) => (
                        Some(fd),
                        (!access.writes()).then(|| self.record_path_stat(&path, &st).metadata),
                    ),
                    Err(Errno::EACCES) if access == Access::Exec => {
                        // F3-16: Execute-only (`0111`/`0100`) cloud WASM cannot be opened O_RDONLY
                        // on the page path; open via `/api/fs` v2 `Access::Exec` with a short-lived
                        // ServiceAuth v2 credential (revoked immediately on `release`).
                        if installed("cloudFsPost").is_ok() && installed("serviceAuthPost").is_ok()
                        {
                            let (instance_id, host_proof) =
                                crate::ensure_remote_attached_state(&self.state)
                                    .await
                                    .map_err(|e| e.errno)?;
                            let resp = crate::service_auth_request(
                                &abi::auth_v2::Request::MintServiceCred(
                                    abi::auth_v2::MintServiceCred {
                                        instance_id,
                                        host_proof,
                                        scope: abi::auth_v2::RemoteScope::cloud_only(),
                                        cloud_access: true,
                                        umask: cred.umask,
                                        cgroup: Some("/user".into()),
                                        generation: None,
                                        sudo,
                                        rbps: None,
                                        wbps: None,
                                    },
                                ),
                            )
                            .await
                            .map_err(|e| e.errno)?;
                            let issued = match resp {
                                abi::auth_v2::Response::Cred(c) => c,
                                _ => return Err(Errno::EIO),
                            };
                            let tok = issued.token.clone();
                            let exec_cred = Cred {
                                identity: Identity {
                                    id: issued.uid,
                                    group: issued.gid,
                                    groups: issued.groups.into_iter().collect(),
                                },
                                umask: issued.umask,
                                token: Some(tok.clone()),
                            };
                            let open_res = async {
                                let cloud = self
                                    .acted(
                                        Actor::Ephemeral(tok.clone()),
                                        self.connector.get(
                                            &self.state,
                                            &self.current,
                                            issued.uid,
                                            &tok,
                                        ),
                                    )
                                    .await?;
                                self.cloud_handles
                                    .borrow_mut()
                                    .insert(cloud.fs.root().node, cloud.fs.root());
                                let real_open = self
                                    .acted(Actor::Ephemeral(tok.clone()), async {
                                        let real = self
                                            .ensure_cloud_handle(&cloud, &exec_cred, handle)
                                            .await?;
                                        cloud.fs.open(&exec_cred, &real, options).await
                                    })
                                    .await?;
                                Ok::<_, Errno>((cloud, real_open))
                            }
                            .await;
                            match open_res {
                                Ok((cloud, real_open)) => {
                                    cloud.live_opens.set(cloud.live_opens.get() + 1);
                                    return Ok(self.alloc_open(
                                        handle.node,
                                        real_open.access,
                                        OpenRecord::RemoteExec {
                                            cloud,
                                            real: real_open,
                                            token: tok,
                                        },
                                    ));
                                }
                                Err(err) => {
                                    crate::revoke_remote_tokens_state(&self.state, vec![tok]).await;
                                    return Err(err);
                                }
                            }
                        }
                        (None, None)
                    }
                    Err(e) => return Err(e),
                }
            } else {
                (None, None)
            };
            Ok(self.alloc_open(
                handle.node,
                access,
                OpenRecord::Page {
                    read_fd,
                    read_meta,
                    path,
                    node: handle.node,
                    access,
                    sudo,
                    stale: false,
                },
            ))
        })
    }

    fn open_metadata<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, Metadata> {
        Box::pin(async move {
            if open.fs != self.fs_id {
                return Err(Errno::EBADF);
            }
            enum MetaDispatch {
                Mem(OpenRef),
                Remote(Rc<Cloud>, OpenRef),
                RemoteExec(Rc<Cloud>, OpenRef, String),
                Page(Option<String>, NodeId, bool),
            }
            let disp = {
                let opens = self.opens.borrow();
                match opens.get(&open.id) {
                    Some(OpenRecord::Mem(m)) => MetaDispatch::Mem(m.clone()),
                    Some(OpenRecord::Remote { cloud, real }) => {
                        MetaDispatch::Remote(Rc::clone(cloud), real.clone())
                    }
                    Some(OpenRecord::RemoteExec { cloud, real, token }) => {
                        MetaDispatch::RemoteExec(Rc::clone(cloud), real.clone(), token.clone())
                    }
                    Some(OpenRecord::Page {
                        read_meta: Some(meta),
                        ..
                    }) => return Ok(meta.clone()),
                    Some(OpenRecord::Page { stale: true, .. }) => return Err(Errno::ESTALE),
                    Some(OpenRecord::Page {
                        path, node, sudo, ..
                    }) => MetaDispatch::Page(Some(path.clone()), *node, *sudo),
                    Some(OpenRecord::PathOnly { node }) => {
                        MetaDispatch::Page(None, *node, self.page_sudo.get())
                    }
                    None => return Err(Errno::EBADF),
                }
            };
            match disp {
                MetaDispatch::Mem(m) => self.mem.open_metadata(&m).await,
                MetaDispatch::Remote(cloud, real) => {
                    let actor = self.active_pid.get().map_or(Actor::None, Actor::Process);
                    let mut meta = self.acted(actor, cloud.fs.open_metadata(&real)).await?;
                    self.strip_and_record_writing(open.node.ino, &mut meta);
                    Ok(meta)
                }
                MetaDispatch::RemoteExec(cloud, real, token) => {
                    let mut meta = self
                        .acted(Actor::Ephemeral(token), cloud.fs.open_metadata(&real))
                        .await?;
                    self.strip_and_record_writing(open.node.ino, &mut meta);
                    Ok(meta)
                }
                MetaDispatch::Page(opt_path, node, open_sudo) => {
                    let path = opt_path
                        .or_else(|| self.node_paths.borrow().get(&node).cloned())
                        .ok_or(Errno::ESTALE)?;
                    if self.is_active_pid_cloud_denied() {
                        return self
                            .cached_or_mem_carrier_entry(&path)
                            .map(|e| e.metadata)
                            .ok_or(Errno::EACCES);
                    }
                    if let Some(cached) = self.cached_page_entry_for_open(node, &path, open_sudo) {
                        return Ok(cached);
                    }
                    let sudo = self.page_sudo.get() || open_sudo;
                    let val = self
                        .guarded_page_call(
                            Call::Lstat { path: path.clone() },
                            None,
                            sudo,
                            PageTarget::Inode(self.page_ino(node)),
                        )
                        .await?;
                    let st: Stat = serde_json::from_value(val).map_err(|_| Errno::EIO)?;
                    Ok(self.record_path_stat(&path, &st).metadata)
                }
            }
        })
    }

    fn read_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a mut [u8],
        offset: u64,
    ) -> BoxFuture<'a, usize> {
        Box::pin(async move {
            if open.fs != self.fs_id {
                return Err(Errno::EBADF);
            }
            if offset > FILE_MAX || buf.len() as u64 > FILE_MAX - offset {
                return Err(Errno::EINVAL);
            }
            enum Dispatch {
                Mem(OpenRef),
                Remote(Rc<Cloud>, OpenRef),
                RemoteExec(Rc<Cloud>, OpenRef, String),
                Page(Option<AuthorityPageFd>, Access, bool),
            }
            let disp = {
                let opens = self.opens.borrow();
                match opens.get(&open.id) {
                    Some(OpenRecord::Mem(m)) => Dispatch::Mem(m.clone()),
                    Some(OpenRecord::Remote { cloud, real }) => {
                        Dispatch::Remote(Rc::clone(cloud), real.clone())
                    }
                    Some(OpenRecord::RemoteExec { cloud, real, token }) => {
                        Dispatch::RemoteExec(Rc::clone(cloud), real.clone(), token.clone())
                    }

                    Some(OpenRecord::Page {
                        read_fd,
                        access,
                        sudo,
                        ..
                    }) => Dispatch::Page(read_fd.clone(), *access, *sudo),
                    Some(OpenRecord::PathOnly { .. }) | None => return Err(Errno::EBADF),
                }
            };
            match disp {
                Dispatch::Mem(m) => self.mem.read_at(&m, buf, offset).await,
                Dispatch::Remote(cloud, real) => {
                    let actor = self.active_pid.get().map_or(Actor::None, Actor::Process);
                    self.acted(actor, cloud.fs.read_at(&real, buf, offset))
                        .await
                }
                Dispatch::RemoteExec(cloud, real, token) => {
                    self.acted(
                        Actor::Ephemeral(token),
                        cloud.fs.read_at(&real, buf, offset),
                    )
                    .await
                }
                Dispatch::Page(Some(fd), _, sudo) => read_page_fd(&fd, offset, buf, sudo).await,
                Dispatch::Page(None, Access::Exec, _) if offset == 0 && buf.len() >= 8 => {
                    // The X_OK check authorized execution. The authority supplies this image.
                    buf[..8].copy_from_slice(b"\0asm\x01\0\0\0");
                    Ok(8)
                }
                Dispatch::Page(None, _, _) => Err(Errno::EBADF),
            }
        })
    }

    fn write_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a [u8],
        at: WriteAt,
    ) -> BoxFuture<'a, Written> {
        Box::pin(async move {
            if open.fs != self.fs_id {
                return Err(Errno::EBADF);
            }
            enum Dispatch {
                Mem(OpenRef),
                Remote(Rc<Cloud>, OpenRef),
                Page(String, NodeId, Access, bool),
            }
            let disp = {
                let opens = self.opens.borrow();
                match opens.get(&open.id) {
                    Some(OpenRecord::Mem(m)) => Dispatch::Mem(m.clone()),
                    Some(OpenRecord::Remote { cloud, real }) => {
                        Dispatch::Remote(Rc::clone(cloud), real.clone())
                    }
                    Some(OpenRecord::Page { stale: true, .. }) => return Err(Errno::ESTALE),
                    Some(OpenRecord::Page {
                        path,
                        node,
                        access,
                        sudo,
                        ..
                    }) => Dispatch::Page(path.clone(), *node, *access, *sudo),
                    Some(OpenRecord::PathOnly { .. })
                    | Some(OpenRecord::RemoteExec { .. })
                    | None => return Err(Errno::EBADF),
                }
            };
            match disp {
                Dispatch::Mem(m) => self.mem.write_at(&m, buf, at).await,
                Dispatch::Remote(cloud, real) => {
                    let actor = self.active_pid.get().map_or(Actor::None, Actor::Process);
                    self.acted(actor, cloud.fs.write_at(&real, buf, at)).await
                }
                Dispatch::Page(path, node, access, open_sudo) => {
                    if !access.writes() {
                        return Err(Errno::EBADF);
                    }
                    let sudo = self.page_sudo.get() || open_sudo;
                    self.page_rmw_mutate(
                        &path,
                        node,
                        0,
                        sudo,
                        PageMutation::WriteAt { buf, at },
                        access.reads().then_some(open.id),
                    )
                    .await
                }
            }
        })
    }

    fn set_len<'a>(&'a self, open: &'a OpenRef, size: u64) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if open.fs != self.fs_id {
                return Err(Errno::EBADF);
            }
            enum Dispatch {
                Mem(OpenRef),
                Remote(Rc<Cloud>, OpenRef),
                Page(String, NodeId, Access, bool),
            }
            let disp = {
                let opens = self.opens.borrow();
                match opens.get(&open.id) {
                    Some(OpenRecord::Mem(m)) => Dispatch::Mem(m.clone()),
                    Some(OpenRecord::Remote { cloud, real }) => {
                        Dispatch::Remote(Rc::clone(cloud), real.clone())
                    }
                    Some(OpenRecord::Page { stale: true, .. }) => return Err(Errno::ESTALE),
                    Some(OpenRecord::Page {
                        path,
                        node,
                        access,
                        sudo,
                        ..
                    }) => Dispatch::Page(path.clone(), *node, *access, *sudo),
                    Some(OpenRecord::PathOnly { .. })
                    | Some(OpenRecord::RemoteExec { .. })
                    | None => return Err(Errno::EBADF),
                }
            };
            match disp {
                Dispatch::Mem(m) => self.mem.set_len(&m, size).await,
                Dispatch::Remote(cloud, real) => {
                    let actor = self.active_pid.get().map_or(Actor::None, Actor::Process);
                    self.acted(actor, cloud.fs.set_len(&real, size)).await
                }
                Dispatch::Page(path, node, access, open_sudo) => {
                    if !access.writes() {
                        return Err(Errno::EBADF);
                    }
                    let sudo = self.page_sudo.get() || open_sudo;
                    self.page_rmw_mutate(
                        &path,
                        node,
                        0,
                        sudo,
                        PageMutation::SetLen(size),
                        access.reads().then_some(open.id),
                    )
                    .await
                    .map(|_| ())
                }
            }
        })
    }

    fn sync_handle<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, ()> {
        // Cloud metadata transactions are durable at acknowledgment. Authenticate the handle
        // without requiring read permission on a write/search-only directory.
        Box::pin(async move { self.metadata(cred, handle).await.map(|_| ()) })
    }

    fn sync_all<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if open.fs != self.fs_id {
                return Err(Errno::EBADF);
            }
            enum SyncDispatch {
                Mem(OpenRef),
                Remote(Rc<Cloud>, OpenRef),
                Page,
            }
            let disp = {
                let opens = self.opens.borrow();
                match opens.get(&open.id) {
                    Some(OpenRecord::Mem(m)) => SyncDispatch::Mem(m.clone()),
                    Some(OpenRecord::Remote { cloud, real }) => {
                        SyncDispatch::Remote(Rc::clone(cloud), real.clone())
                    }
                    Some(OpenRecord::Page { .. }) => SyncDispatch::Page,
                    Some(OpenRecord::PathOnly { .. })
                    | Some(OpenRecord::RemoteExec { .. })
                    | None => return Err(Errno::EBADF),
                }
            };
            match disp {
                SyncDispatch::Mem(m) => self.mem.sync_all(&m).await,
                SyncDispatch::Remote(cloud, real) => {
                    let actor = self.active_pid.get().map_or(Actor::None, Actor::Process);
                    self.acted(actor, cloud.fs.sync_all(&real)).await
                }
                SyncDispatch::Page => Ok(()),
            }
        })
    }

    fn sync_data<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if open.fs != self.fs_id {
                return Err(Errno::EBADF);
            }
            enum SyncDispatch {
                Mem(OpenRef),
                Remote(Rc<Cloud>, OpenRef),
                Page,
            }
            let disp = {
                let opens = self.opens.borrow();
                match opens.get(&open.id) {
                    Some(OpenRecord::Mem(m)) => SyncDispatch::Mem(m.clone()),
                    Some(OpenRecord::Remote { cloud, real }) => {
                        SyncDispatch::Remote(Rc::clone(cloud), real.clone())
                    }
                    Some(OpenRecord::Page { .. }) => SyncDispatch::Page,
                    Some(OpenRecord::PathOnly { .. })
                    | Some(OpenRecord::RemoteExec { .. })
                    | None => return Err(Errno::EBADF),
                }
            };
            match disp {
                SyncDispatch::Mem(m) => self.mem.sync_data(&m).await,
                SyncDispatch::Remote(cloud, real) => {
                    let actor = self.active_pid.get().map_or(Actor::None, Actor::Process);
                    self.acted(actor, cloud.fs.sync_data(&real)).await
                }
                SyncDispatch::Page => Ok(()),
            }
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
            if open.fs != self.fs_id {
                return Err(Errno::EBADF);
            }
            enum LockDispatch {
                Mem(OpenRef),
                Remote(Rc<Cloud>, OpenRef),
            }
            let disp = {
                let opens = self.opens.borrow();
                match opens.get(&open.id) {
                    Some(OpenRecord::Mem(m)) => LockDispatch::Mem(m.clone()),
                    Some(OpenRecord::Remote { cloud, real }) => {
                        LockDispatch::Remote(Rc::clone(cloud), real.clone())
                    }
                    Some(OpenRecord::Page { .. }) => return Err(Errno::ENOLCK),
                    _ => return Err(Errno::EBADF),
                }
            };
            match disp {
                LockDispatch::Mem(m) => self.mem.lock(&m, family, kind, range).await,
                LockDispatch::Remote(cloud, real) => {
                    let actor = self.active_pid.get().map_or(Actor::None, Actor::Process);
                    self.acted(actor, cloud.fs.lock(&real, family, kind, range))
                        .await
                }
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
            if open.fs != self.fs_id {
                return Err(Errno::EBADF);
            }
            enum LockDispatch {
                Mem(OpenRef),
                Remote(Rc<Cloud>, OpenRef),
            }
            let disp = {
                let opens = self.opens.borrow();
                match opens.get(&open.id) {
                    Some(OpenRecord::Mem(m)) => LockDispatch::Mem(m.clone()),
                    Some(OpenRecord::Remote { cloud, real }) => {
                        LockDispatch::Remote(Rc::clone(cloud), real.clone())
                    }
                    Some(OpenRecord::Page { .. }) => return Err(Errno::ENOLCK),
                    _ => return Err(Errno::EBADF),
                }
            };
            match disp {
                LockDispatch::Mem(m) => self.mem.try_lock(&m, family, kind, range).await,
                LockDispatch::Remote(cloud, real) => {
                    let actor = self.active_pid.get().map_or(Actor::None, Actor::Process);
                    self.acted(actor, cloud.fs.try_lock(&real, family, kind, range))
                        .await
                }
            }
        })
    }

    fn unlock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if open.fs != self.fs_id {
                return Err(Errno::EBADF);
            }
            enum LockDispatch {
                Mem(OpenRef),
                Remote(Rc<Cloud>, OpenRef),
            }
            let disp = {
                let opens = self.opens.borrow();
                match opens.get(&open.id) {
                    Some(OpenRecord::Mem(m)) => LockDispatch::Mem(m.clone()),
                    Some(OpenRecord::Remote { cloud, real }) => {
                        LockDispatch::Remote(Rc::clone(cloud), real.clone())
                    }
                    Some(OpenRecord::Page { .. }) => return Err(Errno::ENOLCK),
                    _ => return Err(Errno::EBADF),
                }
            };
            match disp {
                LockDispatch::Mem(m) => self.mem.unlock(&m, family, range).await,
                LockDispatch::Remote(cloud, real) => {
                    let actor = self.active_pid.get().map_or(Actor::None, Actor::Process);
                    self.acted(actor, cloud.fs.unlock(&real, family, range))
                        .await
                }
            }
        })
    }

    fn test_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, Option<Conflict>> {
        Box::pin(async move {
            if open.fs != self.fs_id {
                return Err(Errno::EBADF);
            }
            enum LockDispatch {
                Mem(OpenRef),
                Remote(Rc<Cloud>, OpenRef),
            }
            let disp = {
                let opens = self.opens.borrow();
                match opens.get(&open.id) {
                    Some(OpenRecord::Mem(m)) => LockDispatch::Mem(m.clone()),
                    Some(OpenRecord::Remote { cloud, real }) => {
                        LockDispatch::Remote(Rc::clone(cloud), real.clone())
                    }
                    Some(OpenRecord::Page { .. }) => return Err(Errno::ENOLCK),
                    _ => return Err(Errno::EBADF),
                }
            };
            match disp {
                LockDispatch::Mem(m) => self.mem.test_lock(&m, kind, range).await,
                LockDispatch::Remote(cloud, real) => {
                    let actor = self.active_pid.get().map_or(Actor::None, Actor::Process);
                    self.acted(actor, cloud.fs.test_lock(&real, kind, range))
                        .await
                }
            }
        })
    }

    fn release<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if open.fs != self.fs_id {
                return Err(Errno::EBADF);
            }
            let removed = self.opens.borrow_mut().remove(&open.id);
            match removed {
                Some(OpenRecord::Mem(m)) => self.mem.release(&m).await,
                Some(OpenRecord::Remote { cloud, real }) => {
                    cloud
                        .live_opens
                        .set(cloud.live_opens.get().saturating_sub(1));
                    let actor = self.active_pid.get().map_or(Actor::None, Actor::Process);
                    self.acted(actor, cloud.fs.release(&real)).await
                }
                Some(OpenRecord::RemoteExec { cloud, real, token }) => {
                    cloud
                        .live_opens
                        .set(cloud.live_opens.get().saturating_sub(1));
                    let res = self
                        .acted(Actor::Ephemeral(token.clone()), cloud.fs.release(&real))
                        .await;
                    crate::revoke_remote_tokens_state(&self.state, vec![token]).await;
                    res
                }
                Some(OpenRecord::Page {
                    read_fd: Some(fd),
                    sudo,
                    ..
                }) => fd.close(sudo).await.map(|_| ()),
                Some(OpenRecord::Page { .. }) | Some(OpenRecord::PathOnly { .. }) => Ok(()),
                None => Err(Errno::EBADF),
            }
        })
    }
}

fn update_renamed_paths(map: &mut HashMap<NodeId, String>, old_prefix: &str, new_prefix: &str) {
    let slash_prefix = format!("{old_prefix}/");
    for path in map.values_mut() {
        if path == old_prefix {
            *path = new_prefix.to_string();
        } else if let Some(rest) = path.strip_prefix(&slash_prefix) {
            *path = format!("{new_prefix}/{rest}");
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn write_whole_cloud_page(
    path: &str,
    bytes: &[u8],
    mode: u16,
    excl: bool,
    umask: u16,
    sudo: bool,
    version: Option<&str>,
    fs_session: Option<(&str, &str)>,
    target: PageTarget,
) -> vfs::Result<Stat> {
    let mut flags = abi::O_WRONLY | abi::O_CREAT | abi::O_TRUNC;
    if excl {
        flags |= abi::O_EXCL;
    }
    let sha = image::digest(bytes);
    let opened = page_target_call(
        Call::Open {
            path: path.to_string(),
            flags,
            mode,
            size: Some(bytes.len() as u64),
            sha256: Some(sha),
            version: version.map(str::to_string),
        },
        Some(umask),
        sudo,
        fs_session,
        Some(target),
    )
    .await?;
    let fd: AuthorityPageFd = serde_json::from_value(opened.clone()).map_err(|_| Errno::EIO)?;
    let fd_ref = FdRef::Fd(fd.fd);
    let raw_chunk_size = opened["chunk_size"]
        .as_u64()
        .unwrap_or(wire::DATA_MAX)
        .max(1);
    let chunk_size = usize::try_from(raw_chunk_size).map_err(|_| Errno::EFBIG)?;
    let inline_max = usize::try_from(abi::INLINE_MAX).unwrap_or(usize::MAX);
    for (idx, chunk) in bytes.chunks(chunk_size).enumerate() {
        let write_res: vfs::Result<()> = if chunk.len() <= inline_max {
            fd.call(
                Call::Pwrite {
                    fd: fd_ref,
                    index: idx as u64,
                    data: Bytes(chunk.to_vec()),
                },
                sudo,
            )
            .await
            .map(|_| ())
        } else if let Ok((global, pwrite_fn)) = installed("pagePwrite") {
            let chunk_arr = js_sys::Uint8Array::from(chunk);
            let headers = js_sys::Object::new();
            js_sys::Reflect::set(&headers, &"X-Fd-Epoch".into(), &fd.fd_epoch.as_str().into())
                .map_err(|_| Errno::EIO)?;
            match pwrite_fn.call4(
                &global,
                &JsValue::from_f64(fd.fd as f64),
                &JsValue::from_f64(idx as f64),
                &chunk_arr.into(),
                &headers,
            ) {
                Ok(answer) => match promised(answer).await {
                    Ok(raw) => {
                        let reply_str = raw.as_string().ok_or(Errno::EIO)?;
                        parse_page_reply(&reply_str).map(|_| ())
                    }
                    Err(e) => Err(e),
                },
                Err(_) => Err(Errno::EIO),
            }
        } else {
            Err(Errno::E2BIG)
        };
        if let Err(err) = write_res {
            let _ = fd.call(Call::Discard { fd: fd_ref }, sudo).await;
            return Err(err);
        }
    }
    fd.close(sudo).await?;
    serde_json::from_value(opened["stat"].clone()).map_err(|_| Errno::EIO)
}

impl Kernel {
    /// Close `pid`'s VFS descriptors and drain deferred `CloudFs` releases upon process exit.
    pub(crate) async fn cloud_exited(&self, pid: u32, token: Option<String>) {
        self.vfs_process_exit_cleanup(pid, token.clone()).await;
        let clouds = self.cloud.all();
        if clouds.is_empty() {
            return;
        }
        Acted {
            current: self.current.clone(),
            actor: Actor::Exiting(pid, token),
            future: async {
                for cloud in clouds {
                    let _ = cloud.fs.drain().await;
                }
            },
        }
        .await;
    }
}

#[wasm_bindgen]
impl Kernel {
    /// Renew the `ServiceAuth v2` instance lease and `CloudFs` session leases (called periodically
    /// by `web/kernel/client.js`). Completely silent (ZERO network calls) when `!remote_attached`
    /// and no `CloudFs` session is open.
    pub async fn cloud_renew(&self) -> JsResult<()> {
        if self.state.borrow().remote_attached {
            let _ = self.renew_instance().await;
        }
        let clouds = self.cloud.all();
        if clouds.is_empty() {
            return Ok(());
        }
        let tokens: Vec<String> = self.state.borrow().table.active_remote_tokens();
        Acted {
            current: self.current.clone(),
            actor: Actor::None,
            future: async {
                let mut final_res: vfs::Result<()> = Ok(());
                for cloud in clouds {
                    let mut result = Err(Errno::EACCES);
                    for token in &tokens {
                        let cred = Cred {
                            identity: Identity::guest(),
                            umask: 0,
                            token: Some(token.clone()),
                        };
                        result = cloud.fs.renew(&cred).await;
                        if result.is_ok() || matches!(result, Err(Errno::ENOTCONN)) {
                            break;
                        }
                    }
                    if let Err(err) = result {
                        if err == Errno::ENOTCONN {
                            self.cloud.drop_if_same(&cloud);
                        } else if cloud.live_opens.get() == 0
                            && cloud.fs.pending_cancellations() == 0
                        {
                            self.cloud.drop_if_same(&cloud);
                            continue;
                        }
                        final_res = Err(err);
                    }
                }
                if let Some(vfs) = self.vfs_instance() {
                    crate::vfs_engine::drain_releases(&vfs);
                }
                final_res.map_err(errno)
            },
        }
        .await
    }
}
