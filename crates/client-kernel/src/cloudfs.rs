//! Client-kernel root `/` cloud filesystem driver (`CloudFs` v2 + cookie page session bridge +
//! seeded offline `MemFs` fallback for headless tests).
//!
//! Legacy `Descriptions::open_with`, `inside()`, and `{"fallback": true}` are retired completely
//! (#51, contract §2.3, §2.10, §2.12). Every `/` operation runs through [`os_vfs::Vfs`] as the
//! root [`Filesystem`] driver.

use crate::{Kernel, State, fail};
use abi::contract::FsCapabilities;
use abi::remote_fs as wire;
use abi::{Batch, Bytes, Call, Creds, Errno, Error, FdRef, Results, Return, Stat, Time};
use serde_json::Value;
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};
use vfs::cloud::{CloudFs, Transport};
use vfs::cloud_http::{Host, HttpTransport, Reply};
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
            | "/dev/present"
            | "/dev/snd"
            | "/run"
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

pub(crate) struct Cloud {
    pub(crate) fs: Rc<Fs>,
    pub(crate) live_opens: Cell<usize>,
}

/// Connects the session once, for every caller that needs it meanwhile.
#[derive(Default)]
pub(crate) struct ConnectorInner {
    pub(crate) cloud: RefCell<Option<Rc<Cloud>>>,
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
        self.0.cloud.borrow().clone()
    }

    pub(crate) fn drop_if_same(&self, cloud: &Rc<Cloud>) {
        let mut slot = self.0.cloud.borrow_mut();
        if slot.as_ref().is_some_and(|cur| Rc::ptr_eq(cur, cloud)) {
            *slot = None;
        }
    }

    pub(crate) async fn get(
        &self,
        state: &Rc<RefCell<State>>,
        current: &Rc<RefCell<Actor>>,
        token: &str,
    ) -> vfs::Result<Rc<Cloud>> {
        poll_fn(|context| {
            if self.0.cloud.borrow().is_some() || !self.0.busy.get() {
                Poll::Ready(())
            } else {
                self.0.waiters.borrow_mut().push(context.waker().clone());
                Poll::Pending
            }
        })
        .await;
        if let Some(cloud) = self.current() {
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
        });
        *self.0.cloud.borrow_mut() = Some(cloud.clone());
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
    let kind_bits = st.mode & abi::S_IFMT;
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

/// Send an unprivileged or `sudo` cookie-authenticated batch to `/api/sys` on `OsAuthority`
/// (NEVER `X-Registry`), installed as `self.pageSysPost(bodyJson)` by `web/kernel/client.js`.
pub(crate) async fn page_sys_batch(batch: Batch) -> vfs::Result<Vec<Return>> {
    let (global, post) = installed("pageSysPost")?;
    let body = serde_json::to_string(&batch).map_err(|_| Errno::EIO)?;
    let answer = post
        .call1(&global, &JsValue::from_str(&body))
        .map_err(|_| Errno::EIO)?;
    let raw = promised(answer).await?;
    let reply_str = raw.as_string().ok_or(Errno::EIO)?;
    let reply: Value = serde_json::from_str(&reply_str).map_err(|_| Errno::EIO)?;
    let status = reply["status"].as_u64().unwrap_or(0);
    let text = reply["text"].as_str().unwrap_or("");
    if status != 200 {
        if let Ok(err_val) = serde_json::from_str::<Value>(text)
            && let Some(code) = err_val["errno"].as_str()
            && let Ok(parsed) = serde_json::from_value::<Errno>(Value::String(code.to_string()))
        {
            return Err(parsed);
        }
        return Err(Errno::EIO);
    }
    let results: Results = serde_json::from_str(text).map_err(|_| Errno::EIO)?;
    Ok(results.results)
}

async fn page_sys_one(call: Call, umask: Option<u16>, sudo: bool) -> vfs::Result<Value> {
    let mut results = page_sys_batch(Batch {
        calls: vec![call],
        umask,
        sudo,
        pid: None,
        process: None,
    })
    .await?;
    let ret = results.pop().ok_or(Errno::EIO)?;
    ret.into_result().map_err(|e| e.errno)
}

async fn page_file_read_range(path: &str, offset: u64, len: usize) -> vfs::Result<Vec<u8>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    if let Ok((global, read_fn)) = installed("pageFileRead") {
        let answer = read_fn
            .call3(
                &global,
                &JsValue::from_str(path),
                &JsValue::from_f64(offset as f64),
                &JsValue::from_f64(len as f64),
            )
            .map_err(|_| Errno::EIO)?;
        let reply = promised(answer).await?;
        let status = js_sys::Reflect::get(&reply, &"status".into())
            .ok()
            .and_then(|s| s.as_f64())
            .unwrap_or(0.0) as u16;
        if status == 416 {
            return Ok(Vec::new());
        }
        if status == 200 || status == 206 {
            let body = js_sys::Reflect::get(&reply, &"body".into()).map_err(|_| Errno::EIO)?;
            return Ok(js_sys::Uint8Array::new(&body).to_vec());
        }
        if status == 404 {
            return Err(Errno::ENOENT);
        }
        if status == 403 || status == 401 {
            return Err(Errno::EACCES);
        }
    }
    // Fallback to chunked `Call::Pread` on `/api/sys` (`<= INLINE_MAX`).
    let mut out = Vec::with_capacity(len);
    let mut cur = offset;
    while out.len() < len {
        let chunk = (len - out.len()).min(abi::INLINE_MAX as usize);
        let val = page_sys_one(
            Call::Pread {
                fd: None,
                path: Some(path.to_string()),
                offset: cur,
                count: chunk as u64,
            },
            None,
            false,
        )
        .await?;
        let data: Bytes = serde_json::from_value(val["data"].clone()).map_err(|_| Errno::EIO)?;
        if data.0.is_empty() {
            break;
        }
        cur += data.0.len() as u64;
        out.extend_from_slice(&data.0);
        if data.0.len() < chunk {
            break;
        }
    }
    Ok(out)
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
    Page {
        path: String,
        node: NodeId,
        access: Access,
    },
}

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
    cloud_handles: RefCell<HashMap<NodeId, Handle>>,
    next_open: Cell<u64>,
    opens: RefCell<HashMap<u64, OpenRecord>>,
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

        for &(path, target) in SEED_SYMLINKS {
            let (parent_path, name) = split_cloud_parent(path).expect("symlink parent");
            let parent = dir_handles
                .get(&parent_path)
                .expect("parent seeded")
                .clone();
            let _ = now_or_never(mem.symlink(&root_cred, &parent, &name, target))
                .expect("sync memfs symlink");
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

        let mut node_paths = HashMap::new();
        for (path, handle) in &dir_handles {
            node_paths.insert(handle.node, path.clone());
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
            canonical_nodes: RefCell::new(HashMap::new()),
            node_paths: RefCell::new(node_paths),
            path_entries: RefCell::new(HashMap::new()),
            cloud_handles: RefCell::new(HashMap::new()),
            next_open: Cell::new(1),
            opens: RefCell::new(HashMap::new()),
        }
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

    fn record_path_stat(&self, path: &str, st: &Stat) -> Entry {
        let node = self
            .canonical_nodes
            .borrow()
            .get(path)
            .copied()
            .unwrap_or(NodeId {
                ino: st.ino.max(1),
                generation: 1,
            });
        let entry = Entry {
            handle: Handle {
                fs: self.fs_id.clone(),
                node,
                proof: String::new(),
            },
            metadata: stat_to_metadata(st),
        };
        self.node_paths.borrow_mut().insert(node, path.to_string());
        self.path_entries
            .borrow_mut()
            .insert(path.to_string(), entry.clone());
        entry
    }

    fn wrap_cloud_entry(&self, real: Entry, known_path: Option<String>) -> Entry {
        let canon_node = known_path
            .as_deref()
            .and_then(|p| self.canonical_nodes.borrow().get(p).copied());
        let node = canon_node.unwrap_or(real.handle.node);
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

    /// Query `OsAuthority` via `pageSysPost` so root mountpoints (`/usr`, `/proc`, `/dev`,
    /// `/dev/present`, `/dev/snd`, `/run`, `/mnt/local`, `/mnt/shared`, `/opt/private`, etc.)
    /// carry the server's exact `NodeId`s before mounting `system_mnt_ns`.
    pub(crate) async fn seed_from_authority(&self) -> vfs::Result<bool> {
        if installed("pageSysPost").is_err() {
            return Ok(false);
        }
        let mut paths: Vec<&str> = SEED_DIRS.iter().map(|(p, _)| *p).collect();
        for &(p, _) in SEED_SYMLINKS {
            paths.push(p);
        }
        let calls: Vec<Call> = paths
            .iter()
            .map(|p| Call::Lstat {
                path: (*p).to_string(),
            })
            .collect();
        let results = page_sys_batch(Batch {
            calls,
            umask: None,
            sudo: false,
            pid: None,
            process: None,
        })
        .await?;

        self.canonical_nodes.borrow_mut().clear();
        self.node_paths.borrow_mut().clear();
        self.path_entries.borrow_mut().clear();
        let mountpoints = [
            "/",
            "/usr",
            "/proc",
            "/dev",
            "/run",
            "/mnt",
            "/mnt/local",
            "/mnt/shared",
            "/opt",
            "/opt/private",
        ];
        for (path, ret) in paths.into_iter().zip(results) {
            if let Return::Ok(val) = ret
                && let Ok(st) = serde_json::from_value::<Stat>(val)
            {
                let entry = self.record_path_stat(path, &st);
                if mountpoints.contains(&path) {
                    self.canonical_nodes
                        .borrow_mut()
                        .insert(path.to_string(), entry.handle.node);
                }
            }
        }
        self.node_paths
            .borrow_mut()
            .entry(NodeId {
                ino: 1,
                generation: 1,
            })
            .or_insert_with(|| "/".to_string());
        self.server_seeded.set(true);
        Ok(true)
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
            if let Some((&pid, _)) = state
                .processes
                .iter()
                .find(|(_, local)| local.ended.is_none() && &local.token == token)
            {
                return Actor::Process(pid);
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

    async fn connect_cloud(&self, cred: &Cred) -> vfs::Result<(Actor, Rc<Cloud>)> {
        let token = cred.token.as_deref().ok_or(Errno::EACCES)?;
        let actor = self.actor_for_cred(cred);
        let cloud = self
            .acted(
                actor.clone(),
                self.connector.get(&self.state, &self.current, token),
            )
            .await?;
        self.cloud_handles
            .borrow_mut()
            .insert(cloud.fs.root().node, cloud.fs.root());
        Ok((actor, cloud))
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
        let names: Vec<String> = path
            .split('/')
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        if names.is_empty() {
            return Ok(cloud.fs.root());
        }
        let walked = cloud.fs.walk(cred, &cloud.fs.root(), &names).await?;
        let mut cur_path = String::new();
        for (seg, entry) in names.iter().zip(walked.entries.iter()) {
            cur_path = format!("{cur_path}/{seg}");
            self.cloud_handles
                .borrow_mut()
                .insert(entry.handle.node, entry.handle.clone());
            self.node_paths
                .borrow_mut()
                .insert(entry.handle.node, cur_path.clone());
        }
        if walked.stop.is_some() {
            return Err(Errno::ESTALE);
        }
        walked
            .entries
            .last()
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
        if !self.is_remote_mode() || cred.token.is_none() || installed("cloudFsPost").is_err() {
            return Ok(handle.clone());
        }
        let (actor, cloud) = self.connect_cloud(cred).await?;
        self.acted(actor, self.ensure_cloud_handle(&cloud, cred, handle))
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

        let token = cred.token.as_deref().ok_or(Errno::EACCES)?;
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
        if denied.is_empty() {
            return false;
        }
        if let Some(pid) = self.active_pid.get() {
            return denied.contains(&pid);
        }
        if let Some(token) = &cred.token
            && let Ok(state) = self.state.try_borrow()
            && let Some((&pid, _)) = state
                .processes
                .iter()
                .find(|(_, local)| local.ended.is_none() && &local.token == token)
        {
            return denied.contains(&pid);
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
        !self.is_cloud_denied(cred) && cred.token.is_some() && installed("cloudFsPost").is_ok()
    }
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
                let child_path = join_cloud_path(&dir_path, name);
                return self
                    .cached_or_mem_carrier_entry(&child_path)
                    .ok_or(Errno::EACCES);
            }
            if self.has_cloud_token(cred) {
                let (actor, cloud) = self.connect_cloud(cred).await?;
                let dir_path = self.node_paths.borrow().get(&dir.node).cloned();
                let res = self
                    .acted(actor, async {
                        let real_dir = self.ensure_cloud_handle(&cloud, cred, dir).await?;
                        cloud.fs.lookup(cred, &real_dir, name).await
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
            let sudo = self.page_sudo.get();
            let val = page_sys_one(
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
            if self.has_cloud_token(cred) {
                let (actor, cloud) = self.connect_cloud(cred).await?;
                let base_path = self.node_paths.borrow().get(&dir.node).cloned();
                let res = self
                    .acted(actor, async {
                        let real_dir = self.ensure_cloud_handle(&cloud, cred, dir).await?;
                        cloud.fs.walk(cred, &real_dir, names).await
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
            if self.has_cloud_token(cred) {
                let (actor, cloud) = self.connect_cloud(cred).await?;
                let child_path = self.node_paths.borrow().get(&dir.node).cloned();
                let res = self
                    .acted(actor, async {
                        let real_dir = self.ensure_cloud_handle(&cloud, cred, dir).await?;
                        cloud.fs.parent(cred, &real_dir).await
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
            let sudo = self.page_sudo.get();
            let val = page_sys_one(
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
            if self.has_cloud_token(cred) {
                let (actor, cloud) = self.connect_cloud(cred).await?;
                return self
                    .acted(actor, async {
                        let real = self.ensure_cloud_handle(&cloud, cred, handle).await?;
                        cloud.fs.metadata(cred, &real).await
                    })
                    .await;
            }
            if (self.use_seed_cache.get() || installed("pageSysPost").is_err())
                && let Some(path) = self.node_paths.borrow().get(&handle.node).cloned()
                && let Some(cached) = self.path_entries.borrow().get(&path).cloned()
            {
                return Ok(cached.metadata);
            }
            let path = self.path_for_handle(handle)?;
            let sudo = self.page_sudo.get();
            let val =
                page_sys_one(Call::Lstat { path: path.clone() }, Some(cred.umask), sudo).await?;
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
            if self.is_cloud_denied(cred) {
                return Err(Errno::EACCES);
            }
            if self.has_cloud_token(cred) {
                let (actor, cloud) = self.connect_cloud(cred).await?;
                return self
                    .acted(actor, async {
                        let real = self.ensure_cloud_handle(&cloud, cred, handle).await?;
                        cloud.fs.setattr(cred, &real, attr).await
                    })
                    .await;
            }
            let path = self.path_for_handle(handle)?;
            let sudo = self.page_sudo.get();
            if let Some(size) = attr.size {
                // Truncate via open + close with size if supported, or O_TRUNC for 0.
                if size == 0 {
                    let opened = page_sys_one(
                        Call::Open {
                            path: path.clone(),
                            flags: abi::O_WRONLY | abi::O_TRUNC,
                            mode: 0o666,
                            size: Some(0),
                            sha256: Some(image::digest(&[])),
                            version: None,
                        },
                        Some(cred.umask),
                        sudo,
                    )
                    .await?;
                    if let Some(fd) = opened["fd"].as_u64() {
                        let _ = page_sys_one(
                            Call::Close {
                                fd: FdRef::Fd(fd as u32),
                            },
                            Some(cred.umask),
                            sudo,
                        )
                        .await;
                    }
                } else {
                    let cur = page_file_read_range(&path, 0, size as usize).await?;
                    let mut resized = cur;
                    resized.resize(size as usize, 0);
                    write_whole_cloud_page(&path, &resized, 0o666, false, cred.umask, sudo).await?;
                }
            }
            if attr.uid.is_some() || attr.gid.is_some() {
                page_sys_one(
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
                page_sys_one(
                    Call::Chmod {
                        path: path.clone(),
                        mode,
                    },
                    Some(cred.umask),
                    sudo,
                )
                .await?;
            }
            if !matches!(attr.atime, Time::Omit) || !matches!(attr.mtime, Time::Omit) {
                page_sys_one(
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
            self.metadata(cred, handle).await
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
                let (actor, cloud) = self.connect_cloud(cred).await?;
                let dir_path = self.node_paths.borrow().get(&dir.node).cloned();
                let mut entries = self
                    .acted(actor, async {
                        let real = self.ensure_cloud_handle(&cloud, cred, dir).await?;
                        cloud.fs.read_dir(cred, &real).await
                    })
                    .await?;
                if let Some(base) = dir_path {
                    let canon = self.canonical_nodes.borrow();
                    let mut paths = self.node_paths.borrow_mut();
                    for item in &mut entries {
                        let child = join_cloud_path(&base, &item.name);
                        if let Some(&cnode) = canon.get(&child) {
                            item.node = cnode;
                        }
                        paths.insert(item.node, child);
                    }
                }
                return Ok(entries);
            }

            let dir_path = self.path_for_handle(dir)?;
            let sudo = self.page_sudo.get();
            let val = page_sys_one(
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
                }
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
            if self.has_cloud_token(cred) {
                let (actor, cloud) = self.connect_cloud(cred).await?;
                return self
                    .acted(actor, async {
                        let real = self.ensure_cloud_handle(&cloud, cred, link).await?;
                        cloud.fs.read_link(cred, &real).await
                    })
                    .await;
            }
            let path = self.path_for_handle(link)?;
            let sudo = self.page_sudo.get();
            let val = page_sys_one(Call::Readlink { path }, Some(cred.umask), sudo).await?;
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
            check_component(name)?;
            if self.is_cloud_denied(cred) {
                return Err(Errno::EACCES);
            }
            if self.has_cloud_token(cred) {
                let (actor, cloud) = self.connect_cloud(cred).await?;
                let dir_path = self.node_paths.borrow().get(&dir.node).cloned();
                let (entry, real_open) = self
                    .acted(actor, async {
                        let real_dir = self.ensure_cloud_handle(&cloud, cred, dir).await?;
                        cloud.fs.create(cred, &real_dir, name, mode, options).await
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
            let existing = page_sys_one(
                Call::Lstat {
                    path: child_path.clone(),
                },
                Some(cred.umask),
                sudo,
            )
            .await;
            if existing.is_ok() && options.is_create_new() {
                return Err(Errno::EEXIST);
            }
            if existing.is_err() || options.is_truncate() {
                write_whole_cloud_page(
                    &child_path,
                    &[],
                    mode,
                    options.is_create_new(),
                    cred.umask,
                    sudo,
                )
                .await?;
            }
            let val = page_sys_one(
                Call::Lstat {
                    path: child_path.clone(),
                },
                Some(cred.umask),
                sudo,
            )
            .await?;
            let st: Stat = serde_json::from_value(val).map_err(|_| Errno::EIO)?;
            let entry = self.record_path_stat(&child_path, &st);
            let oref = self.alloc_open(
                entry.handle.node,
                access,
                OpenRecord::Page {
                    path: child_path,
                    node: entry.handle.node,
                    access,
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
            check_component(name)?;
            if self.is_cloud_denied(cred) {
                return Err(Errno::EACCES);
            }
            if self.has_cloud_token(cred) {
                let (actor, cloud) = self.connect_cloud(cred).await?;
                let dir_path = self.node_paths.borrow().get(&dir.node).cloned();
                let entry = self
                    .acted(actor, async {
                        let real = self.ensure_cloud_handle(&cloud, cred, dir).await?;
                        cloud.fs.mkdir(cred, &real, name, mode).await
                    })
                    .await?;
                return Ok(
                    self.wrap_cloud_entry(entry, dir_path.map(|p| join_cloud_path(&p, name)))
                );
            }
            let dir_path = self.path_for_handle(dir)?;
            let child_path = join_cloud_path(&dir_path, name);
            let sudo = self.page_sudo.get();
            page_sys_one(
                Call::Mkdir {
                    path: child_path.clone(),
                    mode,
                },
                Some(cred.umask),
                sudo,
            )
            .await?;
            let val = page_sys_one(
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
            check_component(name)?;
            if self.is_cloud_denied(cred) {
                return Err(Errno::EACCES);
            }
            if self.has_cloud_token(cred) && rdev.is_empty() {
                let (actor, cloud) = self.connect_cloud(cred).await?;
                let dir_path = self.node_paths.borrow().get(&dir.node).cloned();
                let entry = self
                    .acted(actor, async {
                        let real = self.ensure_cloud_handle(&cloud, cred, dir).await?;
                        cloud.fs.mknod(cred, &real, name, mode, rdev).await
                    })
                    .await?;
                return Ok(
                    self.wrap_cloud_entry(entry, dir_path.map(|p| join_cloud_path(&p, name)))
                );
            }
            let dir_path = self.path_for_handle(dir)?;
            let child_path = join_cloud_path(&dir_path, name);
            let rdev_opt = (!rdev.is_empty()).then(|| rdev.to_string());
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
            page_sys_one(
                Call::Mknod {
                    path: child_path.clone(),
                    mode,
                    rdev: rdev_opt,
                },
                Some(cred.umask),
                sudo,
            )
            .await?;
            let val = page_sys_one(
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
            check_component(name)?;
            if self.is_cloud_denied(cred) {
                return Err(Errno::EACCES);
            }
            if self.has_cloud_token(cred) {
                let (actor, cloud) = self.connect_cloud(cred).await?;
                let dir_path = self.node_paths.borrow().get(&dir.node).cloned();
                let entry = self
                    .acted(actor, async {
                        let real = self.ensure_cloud_handle(&cloud, cred, dir).await?;
                        cloud.fs.symlink(cred, &real, name, target).await
                    })
                    .await?;
                return Ok(
                    self.wrap_cloud_entry(entry, dir_path.map(|p| join_cloud_path(&p, name)))
                );
            }
            let dir_path = self.path_for_handle(dir)?;
            let child_path = join_cloud_path(&dir_path, name);
            let sudo = self.page_sudo.get();
            page_sys_one(
                Call::Symlink {
                    target: target.to_string(),
                    path: child_path.clone(),
                },
                Some(cred.umask),
                sudo,
            )
            .await?;
            let val = page_sys_one(
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
            check_component(name)?;
            if self.is_cloud_denied(cred) {
                return Err(Errno::EACCES);
            }
            if self.has_cloud_token(cred) {
                let (actor, cloud) = self.connect_cloud(cred).await?;
                let dir_path = self.node_paths.borrow().get(&dir.node).cloned();
                let entry = self
                    .acted(actor, async {
                        let real_target = self.ensure_cloud_handle(&cloud, cred, target).await?;
                        let real_dir = self.ensure_cloud_handle(&cloud, cred, dir).await?;
                        cloud.fs.link(cred, &real_target, &real_dir, name).await
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
            page_sys_one(
                Call::Link {
                    from: from_path,
                    to: to_path.clone(),
                    follow: false,
                },
                Some(cred.umask),
                sudo,
            )
            .await?;
            let val = page_sys_one(
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
            check_component(name)?;
            if self.is_cloud_denied(cred) {
                return Err(Errno::EACCES);
            }
            if self.has_cloud_token(cred) {
                let (actor, cloud) = self.connect_cloud(cred).await?;
                return self
                    .acted(actor, async {
                        let real = self.ensure_cloud_handle(&cloud, cred, dir).await?;
                        cloud.fs.unlink(cred, &real, name).await
                    })
                    .await;
            }
            let dir_path = self.path_for_handle(dir)?;
            let child_path = join_cloud_path(&dir_path, name);
            let sudo = self.page_sudo.get();
            page_sys_one(Call::Unlink { path: child_path }, Some(cred.umask), sudo)
                .await
                .map(|_| ())
        })
    }

    fn rmdir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if !self.is_remote_mode() {
                return self.mem.rmdir(cred, dir, name).await;
            }
            check_component(name)?;
            if self.is_cloud_denied(cred) {
                return Err(Errno::EACCES);
            }
            if self.has_cloud_token(cred) {
                let (actor, cloud) = self.connect_cloud(cred).await?;
                return self
                    .acted(actor, async {
                        let real = self.ensure_cloud_handle(&cloud, cred, dir).await?;
                        cloud.fs.rmdir(cred, &real, name).await
                    })
                    .await;
            }
            let dir_path = self.path_for_handle(dir)?;
            let child_path = join_cloud_path(&dir_path, name);
            let sudo = self.page_sudo.get();
            page_sys_one(Call::Rmdir { path: child_path }, Some(cred.umask), sudo)
                .await
                .map(|_| ())
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
            check_component(from)?;
            check_component(to)?;
            if self.is_cloud_denied(cred) {
                return Err(Errno::EACCES);
            }
            if self.has_cloud_token(cred) {
                let (actor, cloud) = self.connect_cloud(cred).await?;
                let from_base = self.node_paths.borrow().get(&from_dir.node).cloned();
                let to_base = self.node_paths.borrow().get(&to_dir.node).cloned();
                self.acted(actor, async {
                    let rf = self.ensure_cloud_handle(&cloud, cred, from_dir).await?;
                    let rt = self.ensure_cloud_handle(&cloud, cred, to_dir).await?;
                    cloud.fs.rename(cred, &rf, from, &rt, to, flags).await
                })
                .await?;
                if let (Some(fb), Some(tb)) = (from_base, to_base) {
                    let old_prefix = join_cloud_path(&fb, from);
                    let new_prefix = join_cloud_path(&tb, to);
                    update_renamed_paths(
                        &mut self.node_paths.borrow_mut(),
                        &old_prefix,
                        &new_prefix,
                    );
                }
                return Ok(());
            }
            let from_base = self.path_for_handle(from_dir)?;
            let to_base = self.path_for_handle(to_dir)?;
            let old_path = join_cloud_path(&from_base, from);
            let new_path = join_cloud_path(&to_base, to);
            let sudo = self.page_sudo.get();
            page_sys_one(
                Call::Rename {
                    from: old_path.clone(),
                    to: new_path.clone(),
                    noreplace: flags.contains(RenameFlags::NOREPLACE),
                },
                Some(cred.umask),
                sudo,
            )
            .await?;
            update_renamed_paths(&mut self.node_paths.borrow_mut(), &old_path, &new_path);
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
                let (actor, cloud) = self.connect_cloud(cred).await?;
                return self
                    .acted(actor, async {
                        let real = self.ensure_cloud_handle(&cloud, cred, handle).await?;
                        cloud.fs.getxattr(cred, &real, name).await
                    })
                    .await;
            }
            let path = self.path_for_handle(handle)?;
            let sudo = self.page_sudo.get();
            let val = page_sys_one(
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
            if self.is_cloud_denied(cred) {
                return Err(Errno::EACCES);
            }
            if self.has_cloud_token(cred) {
                let (actor, cloud) = self.connect_cloud(cred).await?;
                return self
                    .acted(actor, async {
                        let real = self.ensure_cloud_handle(&cloud, cred, handle).await?;
                        cloud.fs.setxattr(cred, &real, name, value, flags).await
                    })
                    .await;
            }
            let path = self.path_for_handle(handle)?;
            let sudo = self.page_sudo.get();
            page_sys_one(
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
                let (actor, cloud) = self.connect_cloud(cred).await?;
                return self
                    .acted(actor, async {
                        let real = self.ensure_cloud_handle(&cloud, cred, handle).await?;
                        cloud.fs.listxattr(cred, &real).await
                    })
                    .await;
            }
            let path = self.path_for_handle(handle)?;
            let sudo = self.page_sudo.get();
            let val = page_sys_one(
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
            if self.is_cloud_denied(cred) {
                return Err(Errno::EACCES);
            }
            if self.has_cloud_token(cred) {
                let (actor, cloud) = self.connect_cloud(cred).await?;
                return self
                    .acted(actor, async {
                        let real = self.ensure_cloud_handle(&cloud, cred, handle).await?;
                        cloud.fs.removexattr(cred, &real, name).await
                    })
                    .await;
            }
            let path = self.path_for_handle(handle)?;
            let sudo = self.page_sudo.get();
            page_sys_one(
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
                let (actor, cloud) = self.connect_cloud(cred).await?;
                return self.acted(actor, cloud.fs.statfs(cred)).await;
            }
            let sudo = self.page_sudo.get();
            let val = page_sys_one(
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
            if self.has_cloud_token(cred) {
                let (actor, cloud) = self.connect_cloud(cred).await?;
                let real_open = self
                    .acted(actor, async {
                        let real = self.ensure_cloud_handle(&cloud, cred, handle).await?;
                        cloud.fs.open(cred, &real, options).await
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
                page_sys_one(
                    Call::Access {
                        path: path.clone(),
                        mode: mode_bits,
                    },
                    Some(cred.umask),
                    sudo,
                )
                .await?;
            }
            if options.is_truncate() && meta.is_file() {
                write_whole_cloud_page(&path, &[], meta.mode, false, cred.umask, sudo).await?;
            }
            Ok(self.alloc_open(
                handle.node,
                access,
                OpenRecord::Page {
                    path,
                    node: handle.node,
                    access,
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
                Page(Option<String>, NodeId),
            }
            let disp = {
                let opens = self.opens.borrow();
                match opens.get(&open.id) {
                    Some(OpenRecord::Mem(m)) => MetaDispatch::Mem(m.clone()),
                    Some(OpenRecord::Remote { cloud, real }) => {
                        MetaDispatch::Remote(Rc::clone(cloud), real.clone())
                    }
                    Some(OpenRecord::Page { path, node, .. }) => {
                        MetaDispatch::Page(Some(path.clone()), *node)
                    }
                    Some(OpenRecord::PathOnly { node }) => MetaDispatch::Page(None, *node),
                    None => return Err(Errno::EBADF),
                }
            };
            match disp {
                MetaDispatch::Mem(m) => self.mem.open_metadata(&m).await,
                MetaDispatch::Remote(cloud, real) => {
                    let actor = self.active_pid.get().map_or(Actor::None, Actor::Process);
                    self.acted(actor, cloud.fs.open_metadata(&real)).await
                }
                MetaDispatch::Page(opt_path, node) => {
                    let path = opt_path
                        .or_else(|| self.node_paths.borrow().get(&node).cloned())
                        .ok_or(Errno::ESTALE)?;
                    if self.is_active_pid_cloud_denied() {
                        return self
                            .cached_or_mem_carrier_entry(&path)
                            .map(|e| e.metadata)
                            .ok_or(Errno::EACCES);
                    }
                    let sudo = self.page_sudo.get();
                    let val = page_sys_one(Call::Lstat { path: path.clone() }, None, sudo).await?;
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
                Page(String, Access),
            }
            let disp = {
                let opens = self.opens.borrow();
                match opens.get(&open.id) {
                    Some(OpenRecord::Mem(m)) => Dispatch::Mem(m.clone()),
                    Some(OpenRecord::Remote { cloud, real }) => {
                        Dispatch::Remote(Rc::clone(cloud), real.clone())
                    }
                    Some(OpenRecord::Page { path, access, .. }) => {
                        Dispatch::Page(path.clone(), *access)
                    }
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
                Dispatch::Page(path, access) => {
                    if !access.reads() {
                        return Err(Errno::EBADF);
                    }
                    if buf.is_empty() {
                        return Ok(0);
                    }
                    let data = page_file_read_range(&path, offset, buf.len()).await?;
                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    Ok(n)
                }
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
                Page(String, Access),
            }
            let disp = {
                let opens = self.opens.borrow();
                match opens.get(&open.id) {
                    Some(OpenRecord::Mem(m)) => Dispatch::Mem(m.clone()),
                    Some(OpenRecord::Remote { cloud, real }) => {
                        Dispatch::Remote(Rc::clone(cloud), real.clone())
                    }
                    Some(OpenRecord::Page { path, access, .. }) => {
                        Dispatch::Page(path.clone(), *access)
                    }
                    Some(OpenRecord::PathOnly { .. }) | None => return Err(Errno::EBADF),
                }
            };
            match disp {
                Dispatch::Mem(m) => self.mem.write_at(&m, buf, at).await,
                Dispatch::Remote(cloud, real) => {
                    let actor = self.active_pid.get().map_or(Actor::None, Actor::Process);
                    self.acted(actor, cloud.fs.write_at(&real, buf, at)).await
                }
                Dispatch::Page(path, access) => {
                    if !access.writes() {
                        return Err(Errno::EBADF);
                    }
                    let sudo = self.page_sudo.get();
                    let st_val =
                        page_sys_one(Call::Lstat { path: path.clone() }, None, sudo).await?;
                    let st: Stat = serde_json::from_value(st_val).map_err(|_| Errno::EIO)?;
                    let cur = if st.size > 0 {
                        page_file_read_range(&path, 0, st.size as usize).await?
                    } else {
                        Vec::new()
                    };
                    let write_off = match at {
                        WriteAt::Offset(off) => off,
                        WriteAt::End => cur.len() as u64,
                    };
                    if write_off > FILE_MAX || buf.len() as u64 > FILE_MAX - write_off {
                        return Err(Errno::EINVAL);
                    }
                    if buf.is_empty() {
                        return Ok(Written {
                            offset: write_off,
                            len: 0,
                        });
                    }
                    let end = (write_off as usize) + buf.len();
                    let mut next = cur;
                    if next.len() < end {
                        next.resize(end, 0);
                    }
                    next[write_off as usize..end].copy_from_slice(buf);
                    write_whole_cloud_page(&path, &next, (st.mode & 0o7777) as u16, false, 0, sudo)
                        .await?;
                    Ok(Written {
                        offset: write_off,
                        len: buf.len(),
                    })
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
                Page(String, Access),
            }
            let disp = {
                let opens = self.opens.borrow();
                match opens.get(&open.id) {
                    Some(OpenRecord::Mem(m)) => Dispatch::Mem(m.clone()),
                    Some(OpenRecord::Remote { cloud, real }) => {
                        Dispatch::Remote(Rc::clone(cloud), real.clone())
                    }
                    Some(OpenRecord::Page { path, access, .. }) => {
                        Dispatch::Page(path.clone(), *access)
                    }
                    Some(OpenRecord::PathOnly { .. }) | None => return Err(Errno::EBADF),
                }
            };
            match disp {
                Dispatch::Mem(m) => self.mem.set_len(&m, size).await,
                Dispatch::Remote(cloud, real) => {
                    let actor = self.active_pid.get().map_or(Actor::None, Actor::Process);
                    self.acted(actor, cloud.fs.set_len(&real, size)).await
                }
                Dispatch::Page(path, access) => {
                    if !access.writes() {
                        return Err(Errno::EBADF);
                    }
                    if size > FILE_MAX {
                        return Err(Errno::EFBIG);
                    }
                    let sudo = self.page_sudo.get();
                    let mut bytes = if size > 0 {
                        page_file_read_range(&path, 0, size as usize).await?
                    } else {
                        Vec::new()
                    };
                    bytes.resize(size as usize, 0);
                    write_whole_cloud_page(&path, &bytes, 0o666, false, 0, sudo).await
                }
            }
        })
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
                    Some(OpenRecord::PathOnly { .. }) | None => return Err(Errno::EBADF),
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
                    Some(OpenRecord::PathOnly { .. }) | None => return Err(Errno::EBADF),
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

async fn write_whole_cloud_page(
    path: &str,
    bytes: &[u8],
    mode: u16,
    excl: bool,
    umask: u16,
    sudo: bool,
) -> vfs::Result<()> {
    let mut flags = abi::O_WRONLY | abi::O_CREAT | abi::O_TRUNC;
    if excl {
        flags |= abi::O_EXCL;
    }
    let sha = image::digest(bytes);
    let opened = page_sys_one(
        Call::Open {
            path: path.to_string(),
            flags,
            mode,
            size: Some(bytes.len() as u64),
            sha256: Some(sha),
            version: None,
        },
        Some(umask),
        sudo,
    )
    .await?;
    let fd = opened["fd"].as_u64().ok_or(Errno::EIO)? as u32;
    let fd_ref = FdRef::Fd(fd);
    for (idx, chunk) in bytes.chunks(abi::INLINE_MAX as usize).enumerate() {
        if let Err(err) = page_sys_one(
            Call::Pwrite {
                fd: fd_ref,
                index: idx as u64,
                data: Bytes(chunk.to_vec()),
            },
            Some(umask),
            sudo,
        )
        .await
        {
            let _ = page_sys_one(Call::Discard { fd: fd_ref }, Some(umask), sudo).await;
            return Err(err);
        }
    }
    page_sys_one(Call::Close { fd: fd_ref }, Some(umask), sudo)
        .await
        .map(|_| ())
}

impl Kernel {
    /// Fetch and cache the acting process's authenticated identity from `/api/sys` on the
    /// authority (never `X-Registry`).
    pub(crate) async fn cloud_identity(&self, pid: u32, token: &str) -> JsResult<Identity> {
        if let Some(identity) = self.state.borrow().identities.get(token).cloned() {
            return Ok(identity);
        }
        if installed("cloudFsPost").is_err() {
            return Ok(Identity::root());
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
        let results: Results = serde_json::from_slice(&reply.body)
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

    /// Close `pid`'s VFS descriptors and drain deferred `CloudFs` releases upon process exit.
    pub(crate) async fn cloud_exited(&self, pid: u32, token: Option<String>) {
        self.vfs_process_exit_cleanup(pid, token.clone()).await;
        let Some(cloud) = self.cloud.current() else {
            return;
        };
        Acted {
            current: self.current.clone(),
            actor: Actor::Exiting(pid, token),
            future: async {
                let _ = cloud.fs.drain().await;
            },
        }
        .await;
    }
}

#[wasm_bindgen]
impl Kernel {
    /// Renew the `CloudFs` session's lease with a live process's credential (called periodically
    /// by `web/kernel/client.js`), draining deferred cleanup first.
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
        Acted {
            current: self.current.clone(),
            actor: Actor::None,
            future: async {
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
                if let Some(vfs) = self.vfs_instance() {
                    let _ = vfs.releases().flush().await;
                }
                if let Err(err) = result {
                    if err == Errno::ENOTCONN {
                        self.cloud.drop_if_same(&cloud);
                    }
                    if cloud.live_opens.get() == 0 && cloud.fs.pending_cancellations() == 0 {
                        self.cloud.drop_if_same(&cloud);
                        return Ok(());
                    }
                }
                result.map_err(errno)
            },
        }
        .await
    }
}
