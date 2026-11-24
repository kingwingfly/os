//! Optional feature-frozen CloudFs driver (`FsType::Cloud`, `#57` L3d, Contract v2 §2.1 & §2.12).
//!
//! **Clean break:** `RootCloudDriver` and `seed_from_authority` are DELETED completely from `/`
//! construction. `/` is always local `os-cowfs` (or Stage 1 `tmpfs`).
//!
//! [`CloudMountDriver`] provides optional `FsType::Cloud` strictly when explicitly mounted (e.g.
//! `/mnt/cloud` via `cloud.mount` after Cloud Sign-In, or `/dev/{present,snd}` remote device
//! mounts). When signed out of Cloud it fails immediately with `Errno::ENOTCONN` (0 network RPCs).
//! Remote `EACCES` revocations fail only the individual `/mnt/cloud` syscall and NEVER kill local
//! processes.

use crate::vfs_engine::SCOPED_PAGE_PID_BASE;
use crate::{Kernel, State, fail};
use abi::contract::FsCapabilities;
use abi::{Batch, Call, Errno, Error, ProcState, Results, Return};
use serde_json::Value;
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};
use vfs::cloud::CloudFs;
use vfs::cloud_http::{Host, HttpTransport, PageTarget, Reply};
use vfs::{
    BoxFuture, Conflict, Cred, DirEntry, Entry, Filesystem, FsId, Handle, Identity, LockFamily,
    LockKind, LockRange, Metadata, NodeId, OpenOptions, OpenRef, RenameFlags, SetAttr, StatFs,
    Walked, WriteAt, Written, XattrFlags, profiles,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

type JsResult<T> = std::result::Result<T, JsValue>;

pub(crate) fn installed(name: &str) -> vfs::Result<(JsValue, js_sys::Function)> {
    let global: JsValue = js_sys::global().into();
    let function = js_sys::Reflect::get(&global, &JsValue::from_str(name))
        .ok()
        .and_then(|f| f.dyn_into::<js_sys::Function>().ok())
        .ok_or(Errno::ENOTCONN)?;
    Ok((global, function))
}

pub(crate) async fn promised(value: JsValue) -> vfs::Result<JsValue> {
    let promise = value
        .dyn_into::<js_sys::Promise>()
        .map_err(|_| Errno::EIO)?;
    JsFuture::from(promise).await.map_err(|_| Errno::ENOTCONN)
}

/// Which kernel actor drives the `CloudFs` HTTP transport across a poll.
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

/// Browser transport adapter for `CloudFs<HttpTransport<BrowserHost>>`:
/// `self.cloudFsPost(path, headers, body)`, `cloudFsSleep(ms)`, `cloudFsTicket()`.
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

    pub(crate) fn clear(&self) {
        self.0.clouds.borrow_mut().clear();
        self.0.latest_uid.set(None);
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

pub(crate) async fn page_sys_batch_with_session(
    batch: Batch,
    fs_session: Option<(&str, &str)>,
) -> vfs::Result<Vec<Return>> {
    page_batch_target(batch, fs_session, None, None).await
}

pub(crate) async fn page_batch_target(
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

struct CloudOpenRecord {
    cloud: Rc<Cloud>,
    real: OpenRef,
    actor: Actor,
}

fn join_cloud_path(parent: &str, name: &str) -> String {
    if parent == "/" || parent.is_empty() {
        format!("/{name}")
    } else {
        format!("{}/{name}", parent.trim_end_matches('/'))
    }
}

/// Optional `FsType::Cloud` filesystem driver mounted ONLY on demand at `/mnt/cloud` (or
/// `/dev/{present,snd}` after explicit Cloud Sign-In). NEVER mounted at `/`.
pub(crate) struct CloudMountDriver {
    fs_id: FsId,
    state: Rc<RefCell<State>>,
    current: Rc<RefCell<Actor>>,
    connector: Connector,
    pub(crate) active_pid: Rc<Cell<Option<u32>>>,
    pub(crate) page_sudo: Rc<Cell<bool>>,
    denied_pids: RefCell<HashSet<u32>>,
    opens: RefCell<HashMap<u64, CloudOpenRecord>>,
    next_open_id: Cell<u64>,
    paths: RefCell<HashMap<NodeId, String>>,
    on_lazy_mint: LazyMintSlot,
}

type LazyMintSlot = RefCell<Option<Rc<dyn Fn(u32)>>>;

impl CloudMountDriver {
    pub(crate) fn new(
        state: Rc<RefCell<State>>,
        current: Rc<RefCell<Actor>>,
        connector: Connector,
        active_pid: Rc<Cell<Option<u32>>>,
        page_sudo: Rc<Cell<bool>>,
    ) -> Self {
        let mut paths = HashMap::new();
        paths.insert(
            NodeId {
                ino: 1,
                generation: 1,
            },
            "/".to_string(),
        );
        Self {
            fs_id: FsId("cloud:mnt".to_string()),
            state,
            current,
            connector,
            active_pid,
            page_sudo,
            denied_pids: RefCell::new(HashSet::new()),
            opens: RefCell::new(HashMap::new()),
            next_open_id: Cell::new(1),
            paths: RefCell::new(paths),
            on_lazy_mint: RefCell::new(None),
        }
    }

    pub(crate) fn set_on_lazy_mint(&self, hook: Rc<dyn Fn(u32)>) {
        *self.on_lazy_mint.borrow_mut() = Some(hook);
    }

    pub(crate) fn set_cloud_access(&self, pid: u32, allowed: bool) {
        let mut denied = self.denied_pids.borrow_mut();
        if allowed {
            denied.remove(&pid);
        } else {
            denied.insert(pid);
        }
    }

    pub(crate) fn is_pid_cloud_denied(&self, pid: u32) -> bool {
        self.denied_pids.borrow().contains(&pid)
    }

    pub(crate) fn is_cloud_signed_in(&self) -> bool {
        self.state.borrow().cloud_session.is_some()
    }

    pub(crate) fn page_cloud_token(&self) -> Option<String> {
        let session = self.verify_cloud_session_binding(None).ok()?;
        if !session.scope.cloud_fs || session.page_token.is_empty() {
            return None;
        }
        Some(session.page_token)
    }

    pub(crate) fn current_fs_session(&self) -> Option<(String, String)> {
        self.connector.current_session()
    }

    pub(crate) fn canonical_cloud_path(&self, node: NodeId) -> Option<String> {
        self.paths.borrow().get(&node).cloned()
    }

    pub(crate) fn real_cloud_open_ref(&self, open: &OpenRef) -> Option<OpenRef> {
        if open.fs != self.fs_id {
            return None;
        }
        self.opens
            .borrow()
            .get(&open.id)
            .map(|rec| rec.real.clone())
    }

    pub(crate) fn clear_cached_state(&self) {
        self.opens.borrow_mut().clear();
        let mut paths = self.paths.borrow_mut();
        paths.clear();
        paths.insert(
            NodeId {
                ino: 1,
                generation: 1,
            },
            "/".to_string(),
        );
    }

    fn record_path(&self, parent: NodeId, name: &str, child: NodeId) {
        let mut paths = self.paths.borrow_mut();
        if let Some(base) = paths.get(&parent).cloned() {
            paths.insert(child, join_cloud_path(&base, name));
        }
    }

    fn to_cloud_handle(&self, cloud: &Cloud, handle: &Handle) -> vfs::Result<Handle> {
        if handle.fs != self.fs_id {
            return Err(Errno::EACCES);
        }
        if handle.node.ino == 1 && handle.proof.is_empty() {
            return Ok(cloud.fs.root());
        }
        Ok(Handle {
            fs: cloud.fs.id().clone(),
            node: handle.node,
            proof: handle.proof.clone(),
        })
    }

    fn wrap_cloud_handle(&self, handle: Handle) -> Handle {
        Handle {
            fs: self.fs_id.clone(),
            node: handle.node,
            proof: handle.proof,
        }
    }

    fn wrap_cloud_entry(&self, entry: Entry) -> Entry {
        Entry {
            handle: self.wrap_cloud_handle(entry.handle),
            metadata: entry.metadata,
        }
    }

    fn register_open(&self, cloud: Rc<Cloud>, real: OpenRef, actor: Actor) -> OpenRef {
        cloud.live_opens.set(cloud.live_opens.get() + 1);
        let id = self.next_open_id.get();
        self.next_open_id.set(id.wrapping_add(1).max(1));
        let node = real.node;
        let access = real.access;
        self.opens
            .borrow_mut()
            .insert(id, CloudOpenRecord { cloud, real, actor });
        OpenRef {
            fs: self.fs_id.clone(),
            id,
            node,
            access,
        }
    }

    async fn acted<F: Future>(&self, actor: Actor, future: F) -> F::Output {
        Acted {
            current: Rc::clone(&self.current),
            actor,
            future,
        }
        .await
    }

    /// Verify that the currently active `CloudSession` is live, unrevoked, and still bound to the
    /// active local account `(state.account.uid, state.account_epoch)`. When `expected` is
    /// provided (post-await recheck), also verify that `(cloud_uid, local_uid, login_generation)`
    /// did not change across the `.await`.
    fn verify_cloud_session_binding(
        &self,
        expected: Option<(u32, u32, u64)>,
    ) -> vfs::Result<crate::CloudSession> {
        let st = self.state.borrow();
        let session = st.cloud_session.as_ref().ok_or(Errno::ENOTCONN)?;
        if session.revoked {
            return Err(Errno::EACCES);
        }
        if session.local_uid != st.account.uid || session.login_generation != st.account_epoch {
            return Err(Errno::EACCES);
        }
        if let Some((exp_cloud_uid, exp_local_uid, exp_gen)) = expected
            && (session.cloud_uid != exp_cloud_uid
                || session.local_uid != exp_local_uid
                || session.login_generation != exp_gen)
        {
            return Err(Errno::EACCES);
        }
        Ok(session.clone())
    }

    /// Re-verify process cloud authorization + active `CloudSession` binding after an `.await`
    /// (`lazy_mint_remote_cred` or `connector.get`).
    fn recheck_proc_cloud_access(
        &self,
        pid: u32,
        expected_binding: (u32, u32, u64),
        expected_token: &str,
    ) -> vfs::Result<()> {
        self.verify_cloud_session_binding(Some(expected_binding))?;
        if self.is_pid_cloud_denied(pid) {
            return Err(Errno::EACCES);
        }
        let st = self.state.borrow();
        let proc = st
            .table
            .proc(pid)
            .filter(|p| p.state != ProcState::Zombie)
            .ok_or(Errno::EACCES)?;
        if !proc.cred.cloud_access {
            return Err(Errno::EACCES);
        }
        let rem = proc.cred.remote.as_ref().ok_or(Errno::EACCES)?;
        if !rem.cloud_access || rem.token != expected_token {
            return Err(Errno::EACCES);
        }
        Ok(())
    }

    /// Re-verify page-scoped cloud session binding and token stability after an `.await`.
    fn recheck_page_cloud_access(
        &self,
        expected_binding: (u32, u32, u64),
        expected_token: &str,
    ) -> vfs::Result<()> {
        let post = self.verify_cloud_session_binding(Some(expected_binding))?;
        if post.page_token.is_empty() || post.page_token != expected_token {
            return Err(Errno::EACCES);
        }
        Ok(())
    }

    /// Re-verify an ALREADY-MINTED live process credential after an `.await` (`connector.get`).
    /// Requires the `CloudSession` to remain signed-in and unrevoked for the same `cloud_uid`,
    /// while allowing an already-running process (or an `SCM_RIGHTS` attenuated fd scoped to that
    /// live sender) to keep using its own minted `ServiceAuth v2` token even if the browser's
    /// ambient local account switches before the process exits or Cloud signs out.
    fn recheck_existing_proc_cloud_access(
        &self,
        pid: u32,
        expected_cloud_uid: u32,
        expected_token: &str,
    ) -> vfs::Result<()> {
        if self.is_pid_cloud_denied(pid) {
            return Err(Errno::EACCES);
        }
        let st = self.state.borrow();
        let session = st.cloud_session.as_ref().ok_or(Errno::ENOTCONN)?;
        if session.revoked || session.cloud_uid != expected_cloud_uid {
            return Err(Errno::EACCES);
        }
        let proc = st
            .table
            .proc(pid)
            .filter(|p| p.state != ProcState::Zombie)
            .ok_or(Errno::EACCES)?;
        if !proc.cred.cloud_access {
            return Err(Errno::EACCES);
        }
        let rem = proc.cred.remote.as_ref().ok_or(Errno::EACCES)?;
        if !rem.cloud_access || rem.token != expected_token {
            return Err(Errno::EACCES);
        }
        Ok(())
    }

    /// Resolve the active `CloudFs` connection and remote `Actor` + remote `Cred`.
    /// - Signed out of Cloud -> `Err(Errno::ENOTCONN)` with ZERO network RPCs.
    /// - Page-scoped access and lazy process credential minting enforce `(local_uid, login_generation)`
    ///   binding against the active local account before and after every `.await` (Codex Finding #1).
    /// - A live process that ALREADY holds its own minted `ServiceAuth v2` token (including `SCM_RIGHTS`
    ///   attenuated fds scoped to a live sender) keeps access until it exits, drops privileges, or the
    ///   Cloud session is signed out / revoked.
    /// - Process without `cloud_access` or after privilege drop -> `Err(Errno::EACCES)` with ZERO RPCs.
    /// - Local `uid 0` / `sudo` NEVER synthesizes remote root: always acts strictly with the
    ///   signed-in cloud user's own non-elevated `ServiceAuth v2` token!
    async fn resolve_cloud(&self, cred: &Cred) -> vfs::Result<(Rc<Cloud>, Actor, Cred)> {
        let proc_pid = self.active_pid.get().filter(|&p| p < SCOPED_PAGE_PID_BASE);

        if let Some(pid) = proc_pid {
            if self.is_pid_cloud_denied(pid) {
                return Err(Errno::EACCES);
            }
            let existing = {
                let st = self.state.borrow();
                let proc = st
                    .table
                    .proc(pid)
                    .filter(|p| p.state != ProcState::Zombie)
                    .ok_or(Errno::EACCES)?;
                if !proc.cred.cloud_access {
                    return Err(Errno::EACCES);
                }
                proc.cred.remote.clone()
            };
            let (rem, minted_binding) = match existing {
                Some(r) => {
                    let st = self.state.borrow();
                    let session = st.cloud_session.as_ref().ok_or(Errno::ENOTCONN)?;
                    if session.revoked || session.cloud_uid != r.uid {
                        return Err(Errno::EACCES);
                    }
                    (r, None)
                }
                None => {
                    let session = self.verify_cloud_session_binding(None)?;
                    let binding = (
                        session.cloud_uid,
                        session.local_uid,
                        session.login_generation,
                    );
                    let minted = crate::lazy_mint_remote_cred(&self.state, pid)
                        .await
                        .map_err(|e| e.errno)?;
                    // Recheck `(local_uid, login_generation, !revoked)` and process state after
                    // awaiting `lazy_mint_remote_cred` so a mid-await local user switch or
                    // revocation is rejected immediately!
                    if let Err(err) = self.recheck_proc_cloud_access(pid, binding, &minted.token) {
                        self.state
                            .borrow_mut()
                            .table
                            .drop_revoked_remote_token(&minted.token);
                        crate::revoke_remote_tokens_state(&self.state, vec![minted.token]).await;
                        return Err(err);
                    }
                    if let Some(hook) = self.on_lazy_mint.borrow().clone() {
                        hook(pid);
                    }
                    (minted, Some(binding))
                }
            };
            if !rem.cloud_access {
                return Err(Errno::EACCES);
            }
            let actor = Actor::Process(pid);
            let cloud = self
                .acted(
                    actor.clone(),
                    self.connector
                        .get(&self.state, &self.current, rem.uid, &rem.token),
                )
                .await?;
            // Recheck cloud session binding and process state after awaiting `connector.get`.
            if let Some(binding) = minted_binding {
                self.recheck_proc_cloud_access(pid, binding, &rem.token)?;
            } else {
                self.recheck_existing_proc_cloud_access(pid, rem.uid, &rem.token)?;
            }
            let remote_cred = Cred {
                identity: Identity {
                    id: rem.uid,
                    group: rem.gid,
                    groups: rem.groups.iter().copied().collect(),
                },
                umask: cred.umask,
                token: Some(rem.token),
            };
            return Ok((cloud, actor, remote_cred));
        }

        let session = self.verify_cloud_session_binding(None)?;
        let binding = (
            session.cloud_uid,
            session.local_uid,
            session.login_generation,
        );

        // Page-scoped access: uses the signed-in CloudSession's non-elevated `ServiceAuth v2`
        // page token bound to `(state.account.uid, state.account_epoch)` (NEVER elevates to remote
        // root, and rejects stale sessions after a local user switch!).
        let token = session.page_token.clone();
        if token.is_empty() {
            return Err(Errno::ENOTCONN);
        }
        let actor = Actor::Ephemeral(token.clone());
        let cloud = self
            .acted(
                actor.clone(),
                self.connector
                    .get(&self.state, &self.current, session.cloud_uid, &token),
            )
            .await?;
        // Recheck `(local_uid, login_generation, !revoked, page_token)` after awaiting
        // `connector.get` so a mid-await local user switch or logout rejects immediately!
        self.recheck_page_cloud_access(binding, &token)?;
        let remote_cred = Cred {
            identity: Identity {
                id: session.cloud_uid,
                group: session.cloud_gid,
                groups: session.cloud_groups.iter().copied().collect(),
            },
            umask: cred.umask,
            token: Some(token),
        };
        Ok((cloud, actor, remote_cred))
    }

    pub(crate) async fn real_cloud_handle(
        &self,
        cred: &Cred,
        handle: &Handle,
    ) -> vfs::Result<Handle> {
        let (cloud, _, _) = self.resolve_cloud(cred).await?;
        self.to_cloud_handle(&cloud, handle)
    }

    pub(crate) async fn lookup_remote_dir_handle(&self, path: &str) -> vfs::Result<Entry> {
        let cred = Cred::root();
        let mut cur = self.root();
        let mut last_entry: Option<Entry> = None;
        for part in path.split('/').filter(|s| !s.is_empty()) {
            let entry = self.lookup(&cred, &cur, part).await?;
            cur = entry.handle.clone();
            last_entry = Some(entry);
        }
        match last_entry {
            Some(e) => Ok(e),
            None => {
                let meta = self.metadata(&cred, &cur).await?;
                Ok(Entry {
                    handle: cur,
                    metadata: meta,
                })
            }
        }
    }

    pub(crate) async fn clone_file(
        &self,
        _pid: u32,
        cred: &Cred,
        src: &OpenRef,
        dst: &OpenRef,
    ) -> vfs::Result<()> {
        if src.fs != self.fs_id || dst.fs != self.fs_id {
            return Err(Errno::EXDEV);
        }
        let (cloud, src_real, dst_real, actor) = {
            let opens = self.opens.borrow();
            let s = opens.get(&src.id).ok_or(Errno::EBADF)?;
            let d = opens.get(&dst.id).ok_or(Errno::EBADF)?;
            if !Rc::ptr_eq(&s.cloud, &d.cloud) {
                return Err(Errno::EXDEV);
            }
            (
                Rc::clone(&s.cloud),
                s.real.clone(),
                d.real.clone(),
                d.actor.clone(),
            )
        };
        self.acted(actor, cloud.fs.reflink(cred, &src_real, &dst_real))
            .await
    }

    fn open_dispatch(&self, open: &OpenRef) -> vfs::Result<(Rc<Cloud>, OpenRef, Actor)> {
        if open.fs != self.fs_id {
            return Err(Errno::EBADF);
        }
        let opens = self.opens.borrow();
        let rec = opens.get(&open.id).ok_or(Errno::EBADF)?;
        let actor = match self.active_pid.get().filter(|&p| p < SCOPED_PAGE_PID_BASE) {
            Some(pid) => {
                if self.is_pid_cloud_denied(pid) {
                    return Err(Errno::EACCES);
                }
                Actor::Process(pid)
            }
            None => {
                let cs = self.verify_cloud_session_binding(None)?;
                if cs.cloud_uid != rec.cloud.session_uid || cs.page_token.is_empty() {
                    return Err(Errno::EACCES);
                }
                if let Actor::Ephemeral(ref tok) = rec.actor
                    && cs.page_token != *tok
                {
                    return Err(Errno::EACCES);
                }
                rec.actor.clone()
            }
        };
        Ok((Rc::clone(&rec.cloud), rec.real.clone(), actor))
    }
}

impl Filesystem for CloudMountDriver {
    fn id(&self) -> &FsId {
        &self.fs_id
    }

    fn capabilities(&self) -> FsCapabilities {
        profiles::CLOUD
    }

    fn root(&self) -> Handle {
        Handle {
            fs: self.fs_id.clone(),
            node: NodeId {
                ino: 1,
                generation: 1,
            },
            proof: String::new(),
        }
    }

    fn lookup<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Entry> {
        Box::pin(async move {
            let (cloud, actor, rcred) = self.resolve_cloud(cred).await?;
            let rdir = self.to_cloud_handle(&cloud, dir)?;
            let entry = self
                .acted(actor, cloud.fs.lookup(&rcred, &rdir, name))
                .await?;
            self.record_path(dir.node, name, entry.handle.node);
            Ok(self.wrap_cloud_entry(entry))
        })
    }

    fn walk<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        names: &'a [String],
    ) -> BoxFuture<'a, Walked> {
        Box::pin(async move {
            let (cloud, actor, rcred) = self.resolve_cloud(cred).await?;
            let rdir = self.to_cloud_handle(&cloud, dir)?;
            let walked = self
                .acted(actor, cloud.fs.walk(&rcred, &rdir, names))
                .await?;
            let mut cur_node = dir.node;
            let mut entries = Vec::with_capacity(walked.entries.len());
            for (idx, e) in walked.entries.into_iter().enumerate() {
                if let Some(seg) = names.get(idx) {
                    self.record_path(cur_node, seg, e.handle.node);
                }
                cur_node = e.handle.node;
                entries.push(self.wrap_cloud_entry(e));
            }
            Ok(Walked {
                entries,
                stop: walked.stop,
            })
        })
    }

    fn parent<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
    ) -> BoxFuture<'a, Option<(Entry, String)>> {
        Box::pin(async move {
            let (cloud, actor, rcred) = self.resolve_cloud(cred).await?;
            let rdir = self.to_cloud_handle(&cloud, dir)?;
            let res = self.acted(actor, cloud.fs.parent(&rcred, &rdir)).await?;
            Ok(res.map(|(e, name)| (self.wrap_cloud_entry(e), name)))
        })
    }

    fn metadata<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Metadata> {
        Box::pin(async move {
            let (cloud, actor, rcred) = self.resolve_cloud(cred).await?;
            let rhandle = self.to_cloud_handle(&cloud, handle)?;
            self.acted(actor, cloud.fs.metadata(&rcred, &rhandle)).await
        })
    }

    fn setattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        attr: &'a SetAttr,
    ) -> BoxFuture<'a, Metadata> {
        Box::pin(async move {
            let (cloud, actor, rcred) = self.resolve_cloud(cred).await?;
            let rhandle = self.to_cloud_handle(&cloud, handle)?;
            self.acted(actor, cloud.fs.setattr(&rcred, &rhandle, attr))
                .await
        })
    }

    fn read_dir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle) -> BoxFuture<'a, Vec<DirEntry>> {
        Box::pin(async move {
            let (cloud, actor, rcred) = self.resolve_cloud(cred).await?;
            let rdir = self.to_cloud_handle(&cloud, dir)?;
            self.acted(actor, cloud.fs.read_dir(&rcred, &rdir)).await
        })
    }

    fn read_link<'a>(&'a self, cred: &'a Cred, link: &'a Handle) -> BoxFuture<'a, String> {
        Box::pin(async move {
            let (cloud, actor, rcred) = self.resolve_cloud(cred).await?;
            let rlink = self.to_cloud_handle(&cloud, link)?;
            self.acted(actor, cloud.fs.read_link(&rcred, &rlink)).await
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
            let (cloud, actor, rcred) = self.resolve_cloud(cred).await?;
            let rdir = self.to_cloud_handle(&cloud, dir)?;
            let (entry, real_open) = self
                .acted(
                    actor.clone(),
                    cloud.fs.create(&rcred, &rdir, name, mode, options),
                )
                .await?;
            self.record_path(dir.node, name, entry.handle.node);
            let mapped_open = self.register_open(cloud, real_open, actor);
            Ok((self.wrap_cloud_entry(entry), mapped_open))
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
            let (cloud, actor, rcred) = self.resolve_cloud(cred).await?;
            let rdir = self.to_cloud_handle(&cloud, dir)?;
            let entry = self
                .acted(actor, cloud.fs.mkdir(&rcred, &rdir, name, mode))
                .await?;
            self.record_path(dir.node, name, entry.handle.node);
            Ok(self.wrap_cloud_entry(entry))
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
            let (cloud, actor, rcred) = self.resolve_cloud(cred).await?;
            let rdir = self.to_cloud_handle(&cloud, dir)?;
            let entry = self
                .acted(actor, cloud.fs.mknod(&rcred, &rdir, name, mode, rdev))
                .await?;
            self.record_path(dir.node, name, entry.handle.node);
            Ok(self.wrap_cloud_entry(entry))
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
            let (cloud, actor, rcred) = self.resolve_cloud(cred).await?;
            let rdir = self.to_cloud_handle(&cloud, dir)?;
            let entry = self
                .acted(actor, cloud.fs.symlink(&rcred, &rdir, name, target))
                .await?;
            self.record_path(dir.node, name, entry.handle.node);
            Ok(self.wrap_cloud_entry(entry))
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
            let (cloud, actor, rcred) = self.resolve_cloud(cred).await?;
            let rtarget = self.to_cloud_handle(&cloud, target)?;
            let rdir = self.to_cloud_handle(&cloud, dir)?;
            let entry = self
                .acted(actor, cloud.fs.link(&rcred, &rtarget, &rdir, name))
                .await?;
            self.record_path(dir.node, name, entry.handle.node);
            Ok(self.wrap_cloud_entry(entry))
        })
    }

    fn unlink<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let (cloud, actor, rcred) = self.resolve_cloud(cred).await?;
            let rdir = self.to_cloud_handle(&cloud, dir)?;
            self.acted(actor, cloud.fs.unlink(&rcred, &rdir, name))
                .await
        })
    }

    fn rmdir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let (cloud, actor, rcred) = self.resolve_cloud(cred).await?;
            let rdir = self.to_cloud_handle(&cloud, dir)?;
            self.acted(actor, cloud.fs.rmdir(&rcred, &rdir, name)).await
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
            let (cloud, actor, rcred) = self.resolve_cloud(cred).await?;
            let rfrom = self.to_cloud_handle(&cloud, from_dir)?;
            let rto = self.to_cloud_handle(&cloud, to_dir)?;
            self.acted(
                actor,
                cloud.fs.rename(&rcred, &rfrom, from, &rto, to, flags),
            )
            .await
        })
    }

    fn getxattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let (cloud, actor, rcred) = self.resolve_cloud(cred).await?;
            let rhandle = self.to_cloud_handle(&cloud, handle)?;
            self.acted(actor, cloud.fs.getxattr(&rcred, &rhandle, name))
                .await
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
            let (cloud, actor, rcred) = self.resolve_cloud(cred).await?;
            let rhandle = self.to_cloud_handle(&cloud, handle)?;
            self.acted(
                actor,
                cloud.fs.setxattr(&rcred, &rhandle, name, value, flags),
            )
            .await
        })
    }

    fn listxattr<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Vec<String>> {
        Box::pin(async move {
            let (cloud, actor, rcred) = self.resolve_cloud(cred).await?;
            let rhandle = self.to_cloud_handle(&cloud, handle)?;
            self.acted(actor, cloud.fs.listxattr(&rcred, &rhandle))
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
            let (cloud, actor, rcred) = self.resolve_cloud(cred).await?;
            let rhandle = self.to_cloud_handle(&cloud, handle)?;
            self.acted(actor, cloud.fs.removexattr(&rcred, &rhandle, name))
                .await
        })
    }

    fn statfs<'a>(&'a self, cred: &'a Cred) -> BoxFuture<'a, StatFs> {
        Box::pin(async move {
            let (cloud, actor, rcred) = self.resolve_cloud(cred).await?;
            self.acted(actor, cloud.fs.statfs(&rcred)).await
        })
    }

    fn open<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        options: &'a OpenOptions,
    ) -> BoxFuture<'a, OpenRef> {
        Box::pin(async move {
            let (cloud, actor, rcred) = self.resolve_cloud(cred).await?;
            let rhandle = self.to_cloud_handle(&cloud, handle)?;
            let real_open = self
                .acted(actor.clone(), cloud.fs.open(&rcred, &rhandle, options))
                .await?;
            Ok(self.register_open(cloud, real_open, actor))
        })
    }

    fn open_metadata<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, Metadata> {
        Box::pin(async move {
            let (cloud, real, actor) = self.open_dispatch(open)?;
            self.acted(actor, cloud.fs.open_metadata(&real)).await
        })
    }

    fn read_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a mut [u8],
        offset: u64,
    ) -> BoxFuture<'a, usize> {
        Box::pin(async move {
            let (cloud, real, actor) = self.open_dispatch(open)?;
            self.acted(actor, cloud.fs.read_at(&real, buf, offset))
                .await
        })
    }

    fn write_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a [u8],
        at: WriteAt,
    ) -> BoxFuture<'a, Written> {
        Box::pin(async move {
            let (cloud, real, actor) = self.open_dispatch(open)?;
            self.acted(actor, cloud.fs.write_at(&real, buf, at)).await
        })
    }

    fn set_len<'a>(&'a self, open: &'a OpenRef, size: u64) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let (cloud, real, actor) = self.open_dispatch(open)?;
            self.acted(actor, cloud.fs.set_len(&real, size)).await
        })
    }

    fn sync_all<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let (cloud, real, actor) = self.open_dispatch(open)?;
            self.acted(actor, cloud.fs.sync_all(&real)).await
        })
    }

    fn sync_data<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let (cloud, real, actor) = self.open_dispatch(open)?;
            self.acted(actor, cloud.fs.sync_data(&real)).await
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
            let (cloud, real, actor) = self.open_dispatch(open)?;
            self.acted(actor, cloud.fs.lock(&real, family, kind, range))
                .await
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
            let (cloud, real, actor) = self.open_dispatch(open)?;
            self.acted(actor, cloud.fs.try_lock(&real, family, kind, range))
                .await
        })
    }

    fn unlock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let (cloud, real, actor) = self.open_dispatch(open)?;
            self.acted(actor, cloud.fs.unlock(&real, family, range))
                .await
        })
    }

    fn test_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, Option<Conflict>> {
        Box::pin(async move {
            let (cloud, real, actor) = self.open_dispatch(open)?;
            self.acted(actor, cloud.fs.test_lock(&real, kind, range))
                .await
        })
    }

    fn release<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if open.fs != self.fs_id {
                return Err(Errno::EBADF);
            }
            let Some(rec) = self.opens.borrow_mut().remove(&open.id) else {
                return Err(Errno::EBADF);
            };
            rec.cloud
                .live_opens
                .set(rec.cloud.live_opens.get().saturating_sub(1));
            match self.acted(rec.actor, rec.cloud.fs.release(&rec.real)).await {
                Ok(()) | Err(Errno::EACCES | Errno::ENOTCONN | Errno::EBADF | Errno::ESTALE) => {
                    Ok(())
                }
                Err(err) => Err(err),
            }
        })
    }
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
    /// Renew the `ServiceAuth v2` instance lease and active optional `CloudFs` session leases.
    /// Completely silent (ZERO network calls) when signed out of Cloud (`!remote_attached` and no
    /// active `CloudFs` sessions).
    pub async fn cloud_renew(&self) -> JsResult<()> {
        if self.state.borrow().remote_attached {
            let _ = self.renew_instance().await;
        }
        let clouds = self.cloud.all();
        if clouds.is_empty() {
            return Ok(());
        }
        let mut tokens: Vec<String> = self.state.borrow().table.active_remote_tokens();
        if let Some(ref cs) = self.state.borrow().cloud_session
            && !cs.page_token.is_empty()
            && !tokens.contains(&cs.page_token)
        {
            tokens.push(cs.page_token.clone());
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CloudSession, LocalAccount};
    use abi::auth_v2::RemoteScope;
    use abi::contract::InstanceIdentity;
    use kernel::init::Init;
    use kernel::login::Session as LoginSession;
    use kernel::proc_table::{LocalCred, LocalProcessTable, RemoteCredRef, SpawnSpec};
    use std::collections::BTreeMap;
    use std::task::{RawWaker, RawWakerVTable, Waker};

    fn noop_waker() -> Waker {
        unsafe fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(std::ptr::null(), &VTABLE)
        }
        unsafe fn wake(_: *const ()) {}
        unsafe fn wake_by_ref(_: *const ()) {}
        unsafe fn drop(_: *const ()) {}
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop);
        unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
    }

    fn block_on<F: Future>(fut: F) -> F::Output {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut fut = std::pin::pin!(fut);
        loop {
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    fn make_test_state_and_driver(id: &str) -> (Rc<RefCell<State>>, CloudMountDriver) {
        let now = 1_700_000_000;
        let mut table = LocalProcessTable::new(
            InstanceIdentity {
                instance: id.into(),
                host: "browser".into(),
            },
            now,
        );
        let _ = table.boot_init("boot", now);
        let account = LocalAccount::default();
        let state = Rc::new(RefCell::new(State {
            instance_id: id.into(),
            host_proof: "proof".into(),
            boot: "boot-1".into(),
            namespace: id.into(),
            table,
            account: account.clone(),
            account_epoch: 1,
            proc_account_epoch: HashMap::new(),
            cloud_session: None,
            sudo_timestamps: BTreeMap::new(),
            remote_attached: false,
            host_epoch: 0,
            pending_revocations: Vec::new(),
            volume_tokens: Default::default(),
            pending_detach: false,
            attached_devices: BTreeMap::new(),
            init_state: Init::new("boot-1".into(), now),
            login_session: LoginSession::new(format!("{id}:s1"), account.uid, now + 86_400, now),
            login_profiles: BTreeMap::new(),
            seat_policies: BTreeMap::new(),
            boot_seq: 1,
            session_seq: 1,
        }));
        let driver = CloudMountDriver::new(
            Rc::clone(&state),
            Rc::default(),
            Connector::default(),
            Rc::new(Cell::new(None)),
            Rc::new(Cell::new(false)),
        );
        (state, driver)
    }

    fn make_session(local_uid: u32, login_generation: u64, token: &str) -> CloudSession {
        CloudSession {
            cloud_user: "cloud-alice".into(),
            cloud_uid: 2001,
            cloud_gid: 2001,
            cloud_groups: vec![2001],
            local_uid,
            login_generation,
            scope: RemoteScope::full(),
            page_token: token.into(),
            signed_in_at: 100,
            revoked: false,
        }
    }

    #[test]
    fn page_resolve_cloud_rejects_local_user_switch_stale_generation_and_revocation() {
        let (state, driver) = make_test_state_and_driver("inst-cloud-1");
        let cred = Cred::root();

        // 1. Signed out -> ENOTCONN.
        assert_eq!(
            block_on(driver.resolve_cloud(&cred)).err(),
            Some(Errno::ENOTCONN)
        );

        // 2. User A (uid 1000, epoch 1) signs into Cloud.
        let epoch1 = state.borrow().account_epoch;
        state.borrow_mut().cloud_session = Some(make_session(1000, epoch1, "tok-alice"));
        assert!(driver.verify_cloud_session_binding(None).is_ok());
        assert_eq!(driver.page_cloud_token().as_deref(), Some("tok-alice"));

        // 2b. Scope without cloud_fs or revoked session returns None for page_cloud_token.
        state
            .borrow_mut()
            .cloud_session
            .as_mut()
            .unwrap()
            .scope
            .cloud_fs = false;
        assert_eq!(driver.page_cloud_token(), None);
        state
            .borrow_mut()
            .cloud_session
            .as_mut()
            .unwrap()
            .scope
            .cloud_fs = true;
        state.borrow_mut().cloud_session.as_mut().unwrap().revoked = true;
        assert_eq!(driver.page_cloud_token(), None);
        state.borrow_mut().cloud_session.as_mut().unwrap().revoked = false;
        assert_eq!(driver.page_cloud_token().as_deref(), Some("tok-alice"));

        // 3. Page switches local user from A (1000) to B (1001) via sync_account.
        state.borrow_mut().sync_account(LocalAccount {
            uid: 1001,
            gid: 1001,
            groups: vec![1001],
            user: "bob".into(),
            group: "bob".into(),
            home: "/home/bob".into(),
            shell: "/bin/sh".into(),
            signed_in: true,
        });
        assert!(state.borrow().account_epoch > epoch1);
        assert_eq!(driver.page_cloud_token(), None);
        // Page-scoped `/mnt/cloud` MUST reject user A's stale CloudSession with EACCES!
        assert_eq!(
            block_on(driver.resolve_cloud(&cred)).err(),
            Some(Errno::EACCES)
        );

        // 4. Even if the page switches BACK to user A (uid 1000), `account_epoch` advanced so the
        //    old CloudSession bound to `epoch1` is STILL rejected!
        state.borrow_mut().sync_account(LocalAccount::default());
        assert_eq!(state.borrow().account.uid, 1000);
        assert!(state.borrow().account_epoch > epoch1);
        assert_eq!(
            block_on(driver.resolve_cloud(&cred)).err(),
            Some(Errno::EACCES)
        );

        // 5. Re-binding a fresh CloudSession to the new epoch succeeds until revoked.
        let epoch3 = state.borrow().account_epoch;
        state.borrow_mut().cloud_session = Some(make_session(1000, epoch3, "tok-alice-2"));
        assert!(driver.verify_cloud_session_binding(None).is_ok());
        state.borrow_mut().cloud_session.as_mut().unwrap().revoked = true;
        assert_eq!(
            block_on(driver.resolve_cloud(&cred)).err(),
            Some(Errno::EACCES)
        );
    }

    #[test]
    fn post_await_rechecks_reject_mid_await_user_switch_for_page_and_process() {
        let (state, driver) = make_test_state_and_driver("inst-cloud-2");
        let epoch1 = state.borrow().account_epoch;
        state.borrow_mut().cloud_session = Some(make_session(1000, epoch1, "tok-page-1"));
        let binding = (2001, 1000, epoch1);

        // Spawn a real process owned by uid 1000 with an active remote cred.
        let proc_token = "tok-proc-1".to_string();
        let pid = {
            let mut st = state.borrow_mut();
            let mut cred = LocalCred::local_only(st.account.identity(), 0o022);
            cred.cloud_access = true;
            cred.remote = Some(RemoteCredRef {
                token: proc_token.clone(),
                uid: 2001,
                gid: 2001,
                groups: vec![2001],
                instance_id: st.instance_id.clone(),
                lineage: "lin-1".into(),
                cloud_access: true,
                scope: RemoteScope::full(),
            });
            st.table
                .spawn(SpawnSpec::new("/bin/sh", cred, "browser"), 100)
                .unwrap()
                .pid
        };

        // While suspended on connector.get (connector.0.busy == true), verify resolve_cloud passes
        // the pre-await check and yields Pending.
        driver.connector.0.busy.set(true);
        let cred = Cred::root();
        let mut fut = Box::pin(driver.resolve_cloud(&cred));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(fut.as_mut().poll(&mut cx), Poll::Pending));
        drop(fut);
        driver.connector.0.busy.set(false);

        // Before switching users, both page and process post-await rechecks pass.
        assert!(
            driver
                .recheck_page_cloud_access(binding, "tok-page-1")
                .is_ok()
        );
        assert!(
            driver
                .recheck_proc_cloud_access(pid, binding, &proc_token)
                .is_ok()
        );

        // Simulate a local user switch happening mid-await!
        state.borrow_mut().sync_account(LocalAccount {
            uid: 1001,
            gid: 1001,
            groups: vec![1001],
            user: "bob".into(),
            group: "bob".into(),
            home: "/home/bob".into(),
            shell: "/bin/sh".into(),
            signed_in: true,
        });

        // Both page-scoped and process-scoped post-await rechecks MUST fail closed with EACCES!
        assert_eq!(
            driver.recheck_page_cloud_access(binding, "tok-page-1"),
            Err(Errno::EACCES)
        );
        assert_eq!(
            driver.recheck_proc_cloud_access(pid, binding, &proc_token),
            Err(Errno::EACCES)
        );
    }
}
