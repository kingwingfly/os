//! Unified `os_vfs::Vfs` runtime engine inside `crates/client-kernel` (#51, #52, #53).
//!
//! Owns `system_mnt_ns`, per-login-session derived `MountNamespace`s, user mounts (`opfs`,
//! `hostfs`, `snapshot`, `helperfs`, `sharefs`, and private `image` extensions), per-process
//! `MountNamespace`/`FsContext`/`FdTable` state, service `MountNamespaceGrant` instantiation,
//! all L2 mount/namespace/`chroot`/`cwd` syscalls, `*at` & `kfd_*` operations, `proc_sys`,
//! `vfs_sys`, and `proc_resolve_exec`.

use crate::cloudfs::{RootCloudDriver, installed, page_sys_batch, promised};
use crate::mounts::{Grant, LocalMount, errno_code};
use crate::share_bridge::build_share_backing;
use crate::{INIT, Kernel};
use abi::accelerator::{self, Operation, PathAt, Submit};
use abi::contract::{mount_flags, umount_flags, unshare_flags};
use abi::{
    Batch, Bytes, Call, Dirent, Errno, FICLONE, FdRef, LocalExecutable, OS_FD_CWD, OS_FD_ROOT,
    Return, Time,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;
use vfs::devfs::{DefaultDeviceBackend, DevPtsFs, DevTmpFs, DeviceBackend};
use vfs::imagefs::{
    BlobStore, BuildAssetSizes, ImageEntry, ImageFs, ImageNodeKind, MemoryBlobStore,
};
use vfs::memfs::MemFs;
use vfs::procfs::{ProcDynamicEntry, ProcFs, ProcProvider};
use vfs::{
    BoxFuture, Cred, FILE_MAX, FileRef, FileType, Filesystem, FsId, Handle, Identity, LockFamily,
    LockKind, LockRange, MountBacking, MountFlags, MountId, MountNamespace, ProviderHealth,
    ProviderState, RenameFlags, SeekFrom, SetAttr, StartAnchor, Timespec, Vfs, XattrFlags,
    format_mountinfo, now_or_never,
};
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;

const MAX_USER_MOUNTS: usize = 16;
const CLIENT_PAGE_FD_BASE: u32 = 0x4000_0000;
const SCOPED_PAGE_PID_BASE: u32 = 0x7fff_0000;
const MANIFEST_MAX_BYTES: u64 = 4 * 1024 * 1024;
const PRIVATE_EXT_MAX_BYTES: u64 = 128 * 1024 * 1024;
const WASM_HEADER_STUB: [u8; 8] = [0x00, b'a', b's', b'm', 0x01, 0x00, 0x00, 0x00];

pub(crate) fn vfs_js_err(errno: Errno, detail: impl Into<String>) -> JsValue {
    let detail_str = detail.into();
    let msg = if detail_str.is_empty() {
        errno.text().to_string()
    } else {
        detail_str.clone()
    };
    let code = errno_code(errno);
    let err = js_sys::Error::new(&msg);
    let _ = js_sys::Reflect::set(&err, &"errno".into(), &JsValue::from_str(&code));
    let _ = js_sys::Reflect::set(&err, &"code".into(), &JsValue::from_str(&code));
    let _ = js_sys::Reflect::set(&err, &"detail".into(), &JsValue::from_str(&msg));
    let _ = js_sys::Reflect::set(
        &err,
        &"errnoNum".into(),
        &JsValue::from_f64(wasi_errno_num(errno) as f64),
    );
    err.into()
}

fn map_errno(errno: Errno) -> JsValue {
    vfs_js_err(errno, "")
}

fn wasi_errno_num(errno: Errno) -> i32 {
    match errno {
        Errno::E2BIG => 1,
        Errno::EACCES => 2,
        Errno::EAGAIN => 6,
        Errno::EBADF => 8,
        Errno::EBUSY => 10,
        Errno::ECANCELED => 11,
        Errno::ECHILD => 12,
        Errno::EDEADLK => 16,
        Errno::EDQUOT => 19,
        Errno::EEXIST => 20,
        Errno::EFBIG => 22,
        Errno::EINTR => 27,
        Errno::EINVAL => 28,
        Errno::EIO => 29,
        Errno::EISDIR => 31,
        Errno::ELOOP => 32,
        Errno::EMFILE => 33,
        Errno::EMLINK => 34,
        Errno::ENAMETOOLONG => 37,
        Errno::ENODEV => 43,
        Errno::ENOENT => 44,
        Errno::ENOEXEC => 45,
        Errno::ENOLCK => 46,
        Errno::ENOSPC => 51,
        Errno::ENOSYS => 52,
        Errno::ENOTCONN => 53,
        Errno::ENOTDIR => 54,
        Errno::ENOTEMPTY => 55,
        Errno::EOPNOTSUPP => 58,
        Errno::ENOTTY => 59,
        Errno::ENXIO => 60,
        Errno::ENODATA => 61,
        Errno::EPERM => 63,
        Errno::EPIPE => 64,
        Errno::EPROTONOSUPPORT => 66,
        Errno::ERANGE => 68,
        Errno::EROFS => 69,
        Errno::ESRCH => 71,
        Errno::ESTALE => 72,
        Errno::ETIMEDOUT => 73,
        Errno::ETXTBSY => 74,
        Errno::EXDEV => 75,
    }
}

fn json_to_js(val: &Value) -> Result<JsValue, JsValue> {
    let text = serde_json::to_string(val).map_err(|e| vfs_js_err(Errno::EIO, e.to_string()))?;
    js_sys::JSON::parse(&text).map_err(|_| vfs_js_err(Errno::EIO, "JSON parse failed"))
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

fn parse_anchor(anchor_kfd: i32) -> vfs::Result<StartAnchor> {
    if anchor_kfd == -100 {
        return Ok(StartAnchor::AtFdCwd);
    }
    StartAnchor::from_kfd(anchor_kfd)
}

fn parse_fd_ref(fd_ref: FdRef, refs: &[Option<u32>]) -> vfs::Result<u32> {
    match fd_ref {
        FdRef::Fd(fd) => Ok(fd),
        FdRef::Ref { call } => refs.get(call).copied().flatten().ok_or(Errno::EBADF),
    }
}

fn parse_mount_flags_js(val: &JsValue) -> Result<u64, JsValue> {
    if val.is_undefined() || val.is_null() {
        return Ok(0);
    }
    if let Some(n) = val.as_f64() {
        if !n.is_finite() || n < 0.0 || n.fract() != 0.0 {
            return Err(vfs_js_err(Errno::EINVAL, "invalid mount flags"));
        }
        return Ok(n as u64);
    }
    if val.is_bigint() {
        let s = js_sys::BigInt::from(val.clone())
            .to_string(10)
            .map_err(|_| vfs_js_err(Errno::EINVAL, "invalid mount flags"))?
            .as_string()
            .ok_or_else(|| vfs_js_err(Errno::EINVAL, "invalid mount flags"))?;
        return s
            .parse::<u64>()
            .map_err(|_| vfs_js_err(Errno::EINVAL, "mount flags out of u64 range"));
    }
    if let Some(s) = val.as_string() {
        return s
            .parse::<u64>()
            .map_err(|_| vfs_js_err(Errno::EINVAL, "invalid mount flags string"));
    }
    Err(vfs_js_err(Errno::EINVAL, "invalid mount flags"))
}

fn emit_mounts_changed(session_id: &str, generation: u64) {
    if let Ok((global, cb)) = installed("onKernelMountsChanged") {
        let payload = js_sys::Object::new();
        let _ = js_sys::Reflect::set(
            &payload,
            &"sessionId".into(),
            &JsValue::from_str(session_id),
        );
        let _ = js_sys::Reflect::set(
            &payload,
            &"generation".into(),
            &JsValue::from_f64(generation as f64),
        );
        let _ = cb.call1(&global, &payload);
    }
}

/// Device backend using browser/Node WebCrypto (`crypto.getRandomValues`) when present.
#[derive(Clone, Default)]
pub(crate) struct JsDeviceBackend {
    fallback: DefaultDeviceBackend,
}

impl DeviceBackend for JsDeviceBackend {
    fn fill_random(&self, buf: &mut [u8]) -> vfs::Result<()> {
        let global = js_sys::global();
        if let Ok(crypto) = js_sys::Reflect::get(&global, &"crypto".into())
            && let Ok(func) = js_sys::Reflect::get(&crypto, &"getRandomValues".into())
                .and_then(|v| v.dyn_into::<js_sys::Function>())
        {
            for chunk in buf.chunks_mut(65536) {
                let arr = js_sys::Uint8Array::new_with_length(chunk.len() as u32);
                if func.call1(&crypto, &arr).is_err() {
                    return self.fallback.fill_random(buf);
                }
                arr.copy_to(chunk);
            }
            return Ok(());
        }
        self.fallback.fill_random(buf)
    }
}

/// Blob store fetching `/usr/bin/*.wasm` or `/boot/blobs/<sha>` via `self.imageBlobRead`,
/// falling back to a valid 8-byte Wasm header stub in headless unit tests.
#[derive(Clone, Default)]
pub(crate) struct JsAssetBlobStore {
    cache: Rc<RefCell<HashMap<String, Vec<u8>>>>,
}

impl BlobStore for JsAssetBlobStore {
    fn read_at<'a>(
        &'a self,
        blob_id: &'a str,
        offset: u64,
        buf: &'a mut [u8],
    ) -> BoxFuture<'a, usize> {
        Box::pin(async move {
            if buf.is_empty() {
                return Ok(0);
            }
            if let Some(bytes) = self.cache.borrow().get(blob_id) {
                if offset >= bytes.len() as u64 {
                    return Ok(0);
                }
                let start = offset as usize;
                let n = (bytes.len() - start).min(buf.len());
                buf[..n].copy_from_slice(&bytes[start..start + n]);
                return Ok(n);
            }
            if let Ok((global, reader)) = installed("imageBlobRead") {
                let answer = reader
                    .call3(
                        &global,
                        &JsValue::from_str(blob_id),
                        &JsValue::from_f64(offset as f64),
                        &JsValue::from_f64(buf.len() as f64),
                    )
                    .map_err(|_| Errno::EIO)?;
                let val = promised(answer).await?;
                let data = js_sys::Uint8Array::new(&val).to_vec();
                if offset == 0 && data.len() < buf.len() {
                    self.cache
                        .borrow_mut()
                        .insert(blob_id.to_string(), data.clone());
                }
                let n = data.len().min(buf.len());
                buf[..n].copy_from_slice(&data[..n]);
                return Ok(n);
            }
            // Headless unit test fallback: serve 8-byte valid Wasm magic header.
            if offset >= WASM_HEADER_STUB.len() as u64 {
                return Ok(0);
            }
            let start = offset as usize;
            let n = (WASM_HEADER_STUB.len() - start).min(buf.len());
            buf[..n].copy_from_slice(&WASM_HEADER_STUB[start..start + n]);
            Ok(n)
        })
    }
}

/// `/proc` fallback provider querying `/api/sys` for server-authoritative `status`, `cmdline`,
/// `stat`, and top-level `/proc` entries until L2b (#54).
#[derive(Clone, Default)]
pub(crate) struct BrowserProcProvider;

impl BrowserProcProvider {
    async fn proc_call(&self, cred: &Cred, call: Call) -> vfs::Result<Value> {
        if let Some(token) = &cred.token
            && let Ok((global, post)) = installed("cloudFsPost")
        {
            let body = serde_json::to_vec(&Batch {
                calls: vec![call],
                umask: None,
                sudo: false,
                pid: None,
                process: Some(token.clone()),
            })
            .map_err(|_| Errno::EIO)?;
            let headers = js_sys::Object::new();
            let _ =
                js_sys::Reflect::set(&headers, &"Content-Type".into(), &"application/json".into());
            let arr = js_sys::Uint8Array::from(body.as_slice());
            let answer = post
                .call3(&global, &"/api/sys".into(), &headers, &arr)
                .map_err(|_| Errno::EIO)?;
            let reply = promised(answer).await?;
            let status = js_sys::Reflect::get(&reply, &"status".into())
                .ok()
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0) as u16;
            if status != 200 {
                return Err(Errno::ENOENT);
            }
            let raw = js_sys::Reflect::get(&reply, &"body".into()).map_err(|_| Errno::EIO)?;
            let bytes = js_sys::Uint8Array::new(&raw).to_vec();
            let res: abi::Results = serde_json::from_slice(&bytes).map_err(|_| Errno::EIO)?;
            return res
                .results
                .into_iter()
                .next()
                .ok_or(Errno::EIO)?
                .into_result()
                .map_err(|e| e.errno);
        }
        if installed("pageSysPost").is_ok() {
            let mut res = page_sys_batch(Batch {
                calls: vec![call],
                umask: None,
                sudo: false,
                pid: None,
                process: None,
            })
            .await?;
            return res
                .pop()
                .ok_or(Errno::EIO)?
                .into_result()
                .map_err(|e| e.errno);
        }
        Err(Errno::ENOENT)
    }

    async fn read_proc_file(&self, cred: &Cred, path: &str) -> vfs::Result<Vec<u8>> {
        let val = self
            .proc_call(
                cred,
                Call::Pread {
                    fd: None,
                    path: Some(path.to_string()),
                    offset: 0,
                    count: abi::INLINE_MAX,
                },
            )
            .await?;
        let data: Bytes = serde_json::from_value(val["data"].clone()).map_err(|_| Errno::EIO)?;
        Ok(data.0)
    }
}

impl ProcProvider for BrowserProcProvider {
    fn list_pids<'a>(&'a self, cred: &'a Cred) -> BoxFuture<'a, Vec<u32>> {
        Box::pin(async move {
            let Ok(val) = self
                .proc_call(
                    cred,
                    Call::Getdents {
                        path: "/proc".to_string(),
                        cookie: 0,
                        count: None,
                    },
                )
                .await
            else {
                return Ok(Vec::new());
            };
            let Ok(entries) = serde_json::from_value::<Vec<Dirent>>(val) else {
                return Ok(Vec::new());
            };
            Ok(entries
                .into_iter()
                .filter_map(|e| e.name.parse::<u32>().ok())
                .collect())
        })
    }

    fn top_entries<'a>(&'a self, cred: &'a Cred) -> BoxFuture<'a, Vec<ProcDynamicEntry>> {
        Box::pin(async move {
            let Ok(val) = self
                .proc_call(
                    cred,
                    Call::Getdents {
                        path: "/proc".to_string(),
                        cookie: 0,
                        count: None,
                    },
                )
                .await
            else {
                return Ok(Vec::new());
            };
            let Ok(entries) = serde_json::from_value::<Vec<Dirent>>(val) else {
                return Ok(Vec::new());
            };
            let mut out = Vec::new();
            for e in entries {
                if e.name == "self" || e.name == "mounts" || e.name.parse::<u32>().is_ok() {
                    continue;
                }
                let st = e.stat.unwrap_or_default();
                let kind_bits = st.mode & abi::S_IFMT;
                let file_type = if kind_bits == abi::S_IFDIR {
                    FileType::Dir
                } else if kind_bits == abi::S_IFLNK {
                    FileType::Symlink
                } else {
                    FileType::File
                };
                out.push(ProcDynamicEntry {
                    name: e.name,
                    file_type,
                    mode: (st.mode & 0o7777) as u16,
                    uid: st.uid,
                    gid: st.gid,
                });
            }
            Ok(out)
        })
    }

    fn read_top<'a>(&'a self, cred: &'a Cred, name: &'a str) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(async move { self.read_proc_file(cred, &format!("/proc/{name}")).await })
    }

    fn pid_entries<'a>(&'a self, cred: &'a Cred, pid: u32) -> BoxFuture<'a, Vec<ProcDynamicEntry>> {
        Box::pin(async move {
            let Ok(val) = self
                .proc_call(
                    cred,
                    Call::Getdents {
                        path: format!("/proc/{pid}"),
                        cookie: 0,
                        count: None,
                    },
                )
                .await
            else {
                return Ok(Vec::new());
            };
            let Ok(entries) = serde_json::from_value::<Vec<Dirent>>(val) else {
                return Ok(Vec::new());
            };
            let mut out = Vec::new();
            for e in entries {
                if matches!(
                    e.name.as_str(),
                    "mountinfo" | "mounts" | "ns" | "root" | "cwd" | "fd" | "fdinfo"
                ) {
                    continue;
                }
                let st = e.stat.unwrap_or_default();
                let kind_bits = st.mode & abi::S_IFMT;
                let file_type = if kind_bits == abi::S_IFDIR {
                    FileType::Dir
                } else if kind_bits == abi::S_IFLNK {
                    FileType::Symlink
                } else {
                    FileType::File
                };
                out.push(ProcDynamicEntry {
                    name: e.name,
                    file_type,
                    mode: (st.mode & 0o7777) as u16,
                    uid: st.uid,
                    gid: st.gid,
                });
            }
            Ok(out)
        })
    }

    fn read_pid<'a>(&'a self, cred: &'a Cred, pid: u32, name: &'a str) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(async move {
            self.read_proc_file(cred, &format!("/proc/{pid}/{name}"))
                .await
        })
    }
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BootVfsOptions {
    #[serde(default)]
    build_asset_sizes: Option<BuildAssetSizes>,
    #[serde(default)]
    system_composition: Option<String>,
    #[serde(default)]
    bind_mounts: Vec<ServiceBindSpec>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServiceBindSpec {
    source: String,
    target: String,
    #[serde(default, alias = "read_only")]
    read_only: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServiceGrantSpec {
    #[serde(default, alias = "mount_namespace")]
    mount_namespace: String,
    #[serde(default, alias = "bind_mounts")]
    bind_mounts: Vec<ServiceBindSpec>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProcSpawnInitOpts {
    pid: u32,
    #[serde(default = "default_ppid")]
    ppid: u32,
    #[serde(default)]
    parent_pid: Option<u32>,
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    uid: u32,
    #[serde(default)]
    gid: u32,
    #[serde(default)]
    groups: Vec<u32>,
    #[serde(default = "default_umask")]
    umask: u16,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    clone_flags: u32,
    #[serde(default)]
    token: Option<String>,
    #[serde(default = "default_true")]
    cloud_access: bool,
    #[serde(default)]
    service_grant: Option<ServiceGrantSpec>,
}

fn default_ppid() -> u32 {
    INIT
}
fn default_umask() -> u16 {
    0o022
}
fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MountUserSpec {
    kind: String,
    name: String,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    writable: bool,
    #[serde(default)]
    execute: bool,
    #[serde(default)]
    cloud: bool,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    sources: Vec<String>,
    #[serde(default)]
    manifests: Vec<String>,
}

struct PageOpenFd {
    file: FileRef,
    path: String,
    discard_on_abort: bool,
}

pub(crate) struct AttachedUserMount {
    pub(crate) mount_id: MountId,
    pub(crate) kind: String,
    pub(crate) name: String,
    pub(crate) cloud: bool,
    pub(crate) provider: Rc<ProviderState>,
    pub(crate) local_mount: Option<LocalMount>,
    pub(crate) cleanup: Option<Box<dyn FnOnce()>>,
}

pub(crate) struct SessionVfs {
    pub(crate) session_id: String,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) groups: BTreeSet<u32>,
    pub(crate) mnt_ns: Rc<RefCell<MountNamespace>>,
    pub(crate) baseline_mounts: BTreeSet<MountId>,
    pub(crate) generation: u64,
    pub(crate) user_mounts: BTreeMap<String, AttachedUserMount>,
    page_fds: HashMap<u32, PageOpenFd>,
    next_page_fd: u32,
}

impl SessionVfs {
    fn identity(&self) -> Identity {
        let mut groups = self.groups.clone();
        groups.insert(self.gid);
        Identity {
            id: self.uid,
            group: self.gid,
            groups,
        }
    }

    fn cred(&self, umask: u16) -> Cred {
        Cred {
            identity: self.identity(),
            umask: umask & 0o777,
            token: None,
        }
    }
}

pub(crate) struct ProcessVfsMeta {
    pub(crate) session_id: Option<String>,
    pub(crate) cloud_access: bool,
}

#[derive(Default)]
pub(crate) struct LockCancel {
    cancelled: Cell<bool>,
    waker: RefCell<Option<std::task::Waker>>,
}

impl LockCancel {
    pub(crate) fn cancel(&self) {
        self.cancelled.set(true);
        if let Some(w) = self.waker.borrow_mut().take() {
            w.wake();
        }
    }

    pub(crate) async fn run<F: std::future::Future<Output = vfs::Result<()>>>(
        &self,
        fut: F,
    ) -> vfs::Result<()> {
        let mut pinned = Box::pin(fut);
        std::future::poll_fn(|cx| {
            if self.cancelled.get() {
                return std::task::Poll::Ready(Err(Errno::EINTR));
            }
            match pinned.as_mut().poll(cx) {
                std::task::Poll::Ready(res) => std::task::Poll::Ready(res),
                std::task::Poll::Pending => {
                    *self.waker.borrow_mut() = Some(cx.waker().clone());
                    if self.cancelled.get() {
                        std::task::Poll::Ready(Err(Errno::EINTR))
                    } else {
                        std::task::Poll::Pending
                    }
                }
            }
        })
        .await
    }
}

pub(crate) struct VfsRuntime {
    pub(crate) vfs: Vfs,
    pub(crate) root_cloud: Rc<RootCloudDriver>,
    pub(crate) dev_pts: Rc<DevPtsFs<JsDeviceBackend>>,
    pub(crate) usr_fs_id: FsId,
    pub(crate) usr_blob_paths: HashMap<u64, String>,
    pub(crate) sessions: HashMap<String, SessionVfs>,
    pub(crate) active_session_id: Option<String>,
    pub(crate) proc_meta: HashMap<u32, ProcessVfsMeta>,
    pub(crate) cloud_exec_by_fs: HashMap<FsId, bool>,
    pub(crate) cached_local_execs: HashMap<String, (Vec<u8>, Rc<ProviderState>)>,
    pub(crate) lock_waits: HashMap<(u32, u32), Rc<LockCancel>>,
    pub(crate) uid_names: HashMap<u32, String>,
    pub(crate) gid_names: HashMap<u32, String>,
    next_tmp_id: u64,
    next_scoped_pid: u32,
}

fn default_uid_names() -> HashMap<u32, String> {
    HashMap::from([(0u32, "root".to_string()), (65534u32, "guest".to_string())])
}

fn default_gid_names() -> HashMap<u32, String> {
    HashMap::from([(0u32, "root".to_string()), (65534u32, "guest".to_string())])
}

fn default_asset_sizes() -> BuildAssetSizes {
    BuildAssetSizes {
        coreutils: 64 * 1024,
        utilities: 64 * 1024,
        dash: 64 * 1024,
        supervise: 64 * 1024,
        init: 64 * 1024,
    }
}

async fn construct_vfs(
    instance_id: &str,
    root_cloud: Rc<RootCloudDriver>,
    opts: Option<BootVfsOptions>,
) -> vfs::Result<(
    Vfs,
    Rc<DevPtsFs<JsDeviceBackend>>,
    FsId,
    HashMap<u64, String>,
)> {
    let factory = Rc::new(vfs::DefaultFilesystemFactory::new(Rc::new(js_now_timespec)));
    let root_backing = Rc::new(MountBacking::new(
        Rc::clone(&root_cloud) as Rc<dyn Filesystem>,
        vfs::FsType::Cloud,
    ));
    let vfs = Vfs::boot(instance_id, root_backing.clone(), "cloud", factory).await?;
    let sys_ns = vfs.system_namespace();
    let mut root_cred = Cred::root();
    root_cred.umask = 0;

    // 1. `/usr` (`ImageFs`)
    let mounted_at = Timespec::from(js_now_timespec());
    let usr_fs_id = FsId("image:usr".to_string());
    let sizes = opts
        .as_ref()
        .and_then(|o| o.build_asset_sizes)
        .unwrap_or_else(default_asset_sizes);
    let blob_store = JsAssetBlobStore::default();
    let usr_image = if let Some(comp_json) =
        opts.as_ref().and_then(|o| o.system_composition.as_ref())
    {
        ImageFs::from_composition_json(usr_fs_id.clone(), true, mounted_at, comp_json, blob_store)?
    } else {
        ImageFs::from_build_assets(usr_fs_id.clone(), sizes, mounted_at, blob_store)
    };
    let mut usr_blob_paths = HashMap::new();
    for (bin_path, asset_url) in [
        ("/usr/bin/init", "/usr/bin/init.wasm"),
        ("/usr/bin/supervise", "/usr/bin/supervise.wasm"),
        ("/usr/bin/dash", "/usr/bin/dash.wasm"),
        ("/usr/bin/coreutils", "/usr/bin/coreutils.wasm"),
        ("/usr/bin/utilities", "/usr/bin/utilities.wasm"),
    ] {
        if let Some(h) = usr_image.handle_at(bin_path) {
            usr_blob_paths.insert(h.node.ino, asset_url.to_string());
        }
    }
    let usr_subroot = usr_image.handle_at("/usr").map(|h| (h, "/usr".to_string()));
    let usr_backing = Rc::new(
        MountBacking::new(Rc::new(usr_image), vfs::FsType::Image).with_ceilings(true, false),
    );
    vfs.mount_on_namespace(
        &sys_ns,
        &root_cred,
        usr_backing,
        usr_subroot,
        "image:/usr",
        "/usr",
        MountFlags {
            rdonly: true,
            nodev: true,
            ..MountFlags::default()
        },
        mount_flags::MS_RDONLY | mount_flags::MS_NODEV,
        None,
    )
    .await?;

    // 2. `/proc` (`ProcFs` bound to `vfs.proc_bridge()` + `BrowserProcProvider`)
    let proc_fs = Rc::new(ProcFs::new(
        FsId("proc".to_string()),
        mounted_at,
        BrowserProcProvider,
    ));
    proc_fs.bind_bridge(vfs.proc_bridge());
    let proc_backing = Rc::new(
        MountBacking::new(proc_fs as Rc<dyn Filesystem>, vfs::FsType::Proc)
            .with_ceilings(true, true),
    );
    vfs.mount_on_namespace(
        &sys_ns,
        &root_cred,
        proc_backing,
        None,
        "proc",
        "/proc",
        MountFlags {
            rdonly: true,
            nosuid: true,
            nodev: true,
            noexec: true,
            ..MountFlags::default()
        },
        mount_flags::MS_RDONLY
            | mount_flags::MS_NOSUID
            | mount_flags::MS_NODEV
            | mount_flags::MS_NOEXEC,
        None,
    )
    .await?;

    // 3. `/dev` (`DevTmpFs`), `/dev/pts` (`DevPtsFs`), and `/dev/{present,snd}` (`CloudFs` bind)
    let dev_fs = Rc::new(DevTmpFs::new(
        FsId("devtmpfs".to_string()),
        1,
        Box::new(js_now_timespec),
        JsDeviceBackend::default(),
    ));
    let dev_backing = Rc::new(MountBacking::new(
        dev_fs as Rc<dyn Filesystem>,
        vfs::FsType::DevTmpFs,
    ));
    vfs.mount_on_namespace(
        &sys_ns,
        &root_cred,
        dev_backing,
        None,
        "devtmpfs",
        "/dev",
        MountFlags {
            nosuid: true,
            noexec: true,
            ..MountFlags::default()
        },
        mount_flags::MS_NOSUID | mount_flags::MS_NOEXEC,
        None,
    )
    .await?;

    let dev_pts = Rc::new(DevPtsFs::new(
        FsId("devpts".to_string()),
        1,
        Box::new(js_now_timespec),
        JsDeviceBackend::default(),
    ));
    let pts_backing = Rc::new(MountBacking::new(
        Rc::clone(&dev_pts) as Rc<dyn Filesystem>,
        vfs::FsType::DevPts,
    ));
    vfs.mount_on_namespace(
        &sys_ns,
        &root_cred,
        pts_backing,
        None,
        "devpts",
        "/dev/pts",
        MountFlags {
            nosuid: true,
            noexec: true,
            ..MountFlags::default()
        },
        mount_flags::MS_NOSUID | mount_flags::MS_NOEXEC,
        None,
    )
    .await?;

    let cloud_root = root_cloud.root();
    if let Ok(dev_on_cloud) = root_cloud.lookup(&root_cred, &cloud_root, "dev").await {
        for sub in ["present", "snd"] {
            if let Ok(sub_entry) = root_cloud
                .lookup(&root_cred, &dev_on_cloud.handle, sub)
                .await
            {
                let target = format!("/dev/{sub}");
                let _ = vfs
                    .mount_on_namespace(
                        &sys_ns,
                        &root_cred,
                        Rc::clone(&root_backing),
                        Some((sub_entry.handle, target.clone())),
                        "cloud",
                        &target,
                        MountFlags {
                            nosuid: true,
                            noexec: true,
                            ..MountFlags::default()
                        },
                        0,
                        None,
                    )
                    .await;
            }
        }
    }

    // 4. `/run`, `/mnt/local`, `/mnt/shared`, `/opt/private` (`MemFs` tmpfs carriers)
    for (idx, target) in [
        (1u64, "/run"),
        (2u64, "/mnt/local"),
        (3u64, "/mnt/shared"),
        (4u64, "/opt/private"),
    ] {
        let fs = Rc::new(MemFs::new(
            FsId(format!("tmpfs:boot:{idx}")),
            idx,
            0,
            0,
            0o755,
            Box::new(js_now_timespec),
        ));
        let backing = Rc::new(MountBacking::new(fs, vfs::FsType::TmpFs));
        vfs.mount_on_namespace(
            &sys_ns,
            &root_cred,
            backing,
            None,
            "tmpfs",
            target,
            MountFlags {
                nosuid: true,
                nodev: true,
                ..MountFlags::default()
            },
            mount_flags::MS_NOSUID | mount_flags::MS_NODEV,
            None,
        )
        .await?;
    }

    // Optional sysext / confext bind mounts from `boot_vfs`
    if let Some(o) = opts {
        for bm in o.bind_mounts {
            let mut mflags = mount_flags::MS_BIND;
            if bm.read_only {
                mflags |= mount_flags::MS_RDONLY;
            }
            let _ = vfs
                .mount(INIT, &bm.source, &bm.target, None, mflags, None)
                .await;
        }
    }

    Ok((vfs, dev_pts, usr_fs_id, usr_blob_paths))
}

impl VfsRuntime {
    pub(crate) fn new_sync(instance_id: &str, root_cloud: Rc<RootCloudDriver>) -> Self {
        let id = if instance_id.is_empty() {
            "local-instance"
        } else {
            instance_id
        };
        root_cloud.sync_boot_mem.set(true);
        let booted = now_or_never(construct_vfs(id, Rc::clone(&root_cloud), None));
        root_cloud.sync_boot_mem.set(false);
        let (vfs, dev_pts, usr_fs_id, usr_blob_paths) = booted
            .expect("initial boot_vfs must resolve synchronously")
            .expect("initial boot_vfs must succeed");
        let mut proc_meta = HashMap::new();
        proc_meta.insert(
            INIT,
            ProcessVfsMeta {
                session_id: None,
                cloud_access: true,
            },
        );
        Self {
            vfs,
            root_cloud,
            dev_pts,
            usr_fs_id,
            usr_blob_paths,
            sessions: HashMap::new(),
            active_session_id: None,
            proc_meta,
            cloud_exec_by_fs: HashMap::new(),
            cached_local_execs: HashMap::new(),
            lock_waits: HashMap::new(),
            uid_names: default_uid_names(),
            gid_names: default_gid_names(),
            next_tmp_id: 100,
            next_scoped_pid: SCOPED_PAGE_PID_BASE,
        }
    }

    fn alloc_tmp_id(&mut self) -> u64 {
        let id = self.next_tmp_id;
        self.next_tmp_id += 1;
        id
    }

    fn alloc_scoped_pid(&mut self) -> u32 {
        let pid = self.next_scoped_pid;
        self.next_scoped_pid = if pid >= 0x7fff_fff0 {
            SCOPED_PAGE_PID_BASE
        } else {
            pid + 1
        };
        pid
    }
}

struct RootCloudScope<F> {
    active_pid_cell: Rc<Cell<Option<u32>>>,
    page_sudo_cell: Rc<Cell<bool>>,
    active_pid: Option<u32>,
    page_sudo: bool,
    fut: F,
}

impl<F: std::future::Future> std::future::Future for RootCloudScope<F> {
    type Output = F::Output;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        struct Reset<'a> {
            active_pid_cell: &'a Cell<Option<u32>>,
            page_sudo_cell: &'a Cell<bool>,
            prev_pid: Option<u32>,
            prev_sudo: bool,
        }
        impl Drop for Reset<'_> {
            fn drop(&mut self) {
                self.active_pid_cell.set(self.prev_pid);
                self.page_sudo_cell.set(self.prev_sudo);
            }
        }
        // SAFETY: only `fut` is structurally pinned; the Rc/Cell/Option/bool fields are not.
        let this = unsafe { self.get_unchecked_mut() };
        let prev_pid = this.active_pid_cell.replace(this.active_pid);
        let prev_sudo = this.page_sudo_cell.replace(this.page_sudo);
        let _reset = Reset {
            active_pid_cell: &this.active_pid_cell,
            page_sudo_cell: &this.page_sudo_cell,
            prev_pid,
            prev_sudo,
        };
        unsafe { std::pin::Pin::new_unchecked(&mut this.fut) }.poll(cx)
    }
}

fn clean_mount_name(raw: &str) -> vfs::Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed == "."
        || trimmed == ".."
        || trimmed.len() > 64
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains('\0')
    {
        return Err(Errno::EINVAL);
    }
    Ok(trimmed.to_string())
}

impl Kernel {
    async fn refresh_account_names(&self, vfs: &Vfs, pid: u32) {
        let mut uids = default_uid_names();
        let mut gids = default_gid_names();
        let temp_pid = if vfs.process_fds(pid).is_ok() {
            None
        } else {
            let spid = self.vfs_rt.borrow_mut().alloc_scoped_pid();
            let ns = vfs.system_namespace();
            if vfs
                .spawn_process(spid, 0o022, Cred::root(), Some(ns), None, None)
                .is_ok()
            {
                Some(spid)
            } else {
                None
            }
        };
        let use_pid = temp_pid.unwrap_or(pid);
        let fetch = async {
            if let Ok((f, _)) = vfs
                .open_file(use_pid, StartAnchor::Root, "/etc/passwd", abi::O_RDONLY, 0)
                .await
            {
                let mut buf = vec![0u8; 64 * 1024];
                if let Ok(n) = f.read_at(&mut buf, 0).await
                    && let Ok(text) = std::str::from_utf8(&buf[..n])
                {
                    for line in text.lines() {
                        let mut parts = line.split(':');
                        if let (Some(name), Some(_), Some(uid_str)) =
                            (parts.next(), parts.next(), parts.next())
                            && let Ok(uid) = uid_str.parse::<u32>()
                            && !name.is_empty()
                        {
                            uids.insert(uid, name.to_string());
                        }
                    }
                }
                let _ = f.close().await;
                let _ = vfs.releases().flush().await;
            }
            if let Ok((f, _)) = vfs
                .open_file(use_pid, StartAnchor::Root, "/etc/group", abi::O_RDONLY, 0)
                .await
            {
                let mut buf = vec![0u8; 64 * 1024];
                if let Ok(n) = f.read_at(&mut buf, 0).await
                    && let Ok(text) = std::str::from_utf8(&buf[..n])
                {
                    for line in text.lines() {
                        let mut parts = line.split(':');
                        if let (Some(name), Some(_), Some(gid_str)) =
                            (parts.next(), parts.next(), parts.next())
                            && let Ok(gid) = gid_str.parse::<u32>()
                            && !name.is_empty()
                        {
                            gids.insert(gid, name.to_string());
                        }
                    }
                }
                let _ = f.close().await;
                let _ = vfs.releases().flush().await;
            }
        };
        if use_pid < SCOPED_PAGE_PID_BASE {
            self.with_proc_scope(use_pid, fetch).await;
        } else {
            self.with_page_scope(false, fetch).await;
        }
        if let Some(spid) = temp_pid {
            let _ = vfs.exit_process(spid).await;
        }
        let mut rt = self.vfs_rt.borrow_mut();
        rt.uid_names = uids;
        rt.gid_names = gids;
    }

    async fn fill_stat_names(&self, vfs: &Vfs, pid: u32, st: &mut abi::Stat) {
        let missing = {
            let rt = self.vfs_rt.borrow();
            (st.user.is_empty() && !rt.uid_names.contains_key(&st.uid))
                || (st.group.is_empty() && !rt.gid_names.contains_key(&st.gid))
        };
        if missing {
            self.refresh_account_names(vfs, pid).await;
        }
        let mut rt = self.vfs_rt.borrow_mut();
        if st.user.is_empty() {
            st.user = rt
                .uid_names
                .entry(st.uid)
                .or_insert_with(|| st.uid.to_string())
                .clone();
        }
        if st.group.is_empty() {
            st.group = rt
                .gid_names
                .entry(st.gid)
                .or_insert_with(|| st.gid.to_string())
                .clone();
        }
    }

    pub(crate) fn vfs_instance(&self) -> Option<Vfs> {
        Some(self.vfs_rt.borrow().vfs.clone())
    }

    /// Re-seed `RootCloudDriver` from `OsAuthority` during `Kernel::init()` when running in browser.
    pub(crate) async fn sync_vfs_with_authority(&self, namespace: &str) -> vfs::Result<()> {
        let root_cloud = Rc::clone(&self.vfs_rt.borrow().root_cloud);
        if !root_cloud.seed_from_authority().await? {
            return Ok(());
        }
        let sizes = query_authority_asset_sizes().await;
        let opts = BootVfsOptions {
            build_asset_sizes: sizes,
            system_composition: None,
            bind_mounts: Vec::new(),
        };
        let inst_id = if namespace.is_empty() {
            "browser-instance"
        } else {
            namespace
        };
        root_cloud.use_seed_cache.set(true);
        let built = construct_vfs(inst_id, Rc::clone(&root_cloud), Some(opts)).await;
        root_cloud.use_seed_cache.set(false);
        let (vfs, dev_pts, usr_fs_id, usr_blob_paths) = built?;
        let mut rt = self.vfs_rt.borrow_mut();
        rt.vfs = vfs;
        rt.dev_pts = dev_pts;
        rt.usr_fs_id = usr_fs_id;
        rt.usr_blob_paths = usr_blob_paths;
        Ok(())
    }

    pub(crate) async fn vfs_process_exit_cleanup(&self, pid: u32, _token: Option<String>) {
        let (vfs, root_cloud, waits) = {
            let mut rt = self.vfs_rt.borrow_mut();
            rt.proc_meta.remove(&pid);
            let keys: Vec<(u32, u32)> = rt
                .lock_waits
                .keys()
                .filter(|(p, _)| *p == pid)
                .copied()
                .collect();
            let waits: Vec<_> = keys
                .into_iter()
                .filter_map(|k| rt.lock_waits.remove(&k))
                .collect();
            (rt.vfs.clone(), Rc::clone(&rt.root_cloud), waits)
        };
        for w in waits {
            w.cancel();
        }
        let _ = self
            .with_proc_scope(pid, async { vfs.exit_process(pid).await })
            .await;
        root_cloud.set_cloud_access(pid, true);
    }

    /// Register a newly admitted `Execve` process in `Vfs` (`execs_of`).
    pub(crate) async fn register_exec_in_vfs(
        &self,
        pid: u32,
        ppid: u32,
        token: &str,
        cwd: &str,
        session_id: Option<&str>,
        cloud_access: bool,
    ) {
        let identity = self
            .cloud_identity(pid, token)
            .await
            .unwrap_or_else(|_| Identity::root());
        let cred = Cred {
            identity,
            umask: 0o022,
            token: Some(token.to_string()),
        };
        let (vfs, root_cloud, mnt_ns, chosen_session) = {
            let mut rt = self.vfs_rt.borrow_mut();
            let sid = session_id
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .or_else(|| rt.active_session_id.clone());
            let ns = sid
                .as_ref()
                .and_then(|s| rt.sessions.get(s))
                .map(|sess| Rc::clone(&sess.mnt_ns));
            rt.proc_meta.insert(
                pid,
                ProcessVfsMeta {
                    session_id: sid.clone(),
                    cloud_access,
                },
            );
            (rt.vfs.clone(), Rc::clone(&rt.root_cloud), ns, sid)
        };
        let _ = chosen_session;
        let _ = self
            .with_proc_scope(pid, async { vfs.exit_process(pid).await })
            .await;
        root_cloud.set_cloud_access(pid, cloud_access);
        if vfs
            .spawn_process(pid, ppid, cred, mnt_ns, None, None)
            .is_ok()
            && !cwd.is_empty()
            && cwd != "/"
        {
            let _ = self
                .with_proc_scope(pid, async { vfs.chdir(pid, cwd).await })
                .await;
        }
    }

    /// Notify active sessions whose `MountNamespace` matches `target_ns_id` that mounts changed.
    fn notify_ns_changed(&self, target_ns_id: vfs::NamespaceId) {
        let mut notifications = Vec::new();
        {
            let mut rt = self.vfs_rt.borrow_mut();
            for sess in rt.sessions.values_mut() {
                if sess.mnt_ns.borrow().id() == target_ns_id {
                    sess.generation = sess.generation.wrapping_add(1);
                    notifications.push((sess.session_id.clone(), sess.generation));
                }
            }
        }
        for (sid, generation) in notifications {
            emit_mounts_changed(&sid, generation);
        }
    }

    fn with_root_cloud_scope<F>(
        &self,
        active_pid: Option<u32>,
        page_sudo: bool,
        fut: F,
    ) -> RootCloudScope<F>
    where
        F: std::future::Future,
    {
        let root_cloud = Rc::clone(&self.vfs_rt.borrow().root_cloud);
        RootCloudScope {
            active_pid_cell: Rc::clone(&root_cloud.active_pid),
            page_sudo_cell: Rc::clone(&root_cloud.page_sudo),
            active_pid,
            page_sudo,
            fut,
        }
    }

    fn with_proc_scope<F>(&self, pid: u32, fut: F) -> RootCloudScope<F>
    where
        F: std::future::Future,
    {
        self.with_root_cloud_scope(Some(pid), false, fut)
    }

    fn with_page_scope<F>(&self, sudo: bool, fut: F) -> RootCloudScope<F>
    where
        F: std::future::Future,
    {
        self.with_root_cloud_scope(None, sudo, fut)
    }
}

async fn query_authority_asset_sizes() -> Option<BuildAssetSizes> {
    if installed("pageSysPost").is_err() {
        return None;
    }
    let paths = [
        "/usr/bin/coreutils",
        "/usr/bin/utilities",
        "/usr/bin/dash",
        "/usr/bin/supervise",
        "/usr/bin/init",
    ];
    let calls = paths
        .iter()
        .map(|p| Call::Stat {
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
    .await
    .ok()?;
    let mut nums = [FILE_MAX; 5];
    for (idx, ret) in results.into_iter().enumerate() {
        if let Return::Ok(val) = ret
            && let Some(sz) = val["size"].as_u64()
            && sz >= 8
        {
            nums[idx] = sz;
        }
    }
    Some(BuildAssetSizes {
        coreutils: nums[0],
        utilities: nums[1],
        dash: nums[2],
        supervise: nums[3],
        init: nums[4],
    })
}

async fn read_vfs_file_bounded(
    vfs: &Vfs,
    pid: u32,
    path: &str,
    max_bytes: u64,
    err_on_too_big: Errno,
) -> Result<Vec<u8>, JsValue> {
    let (file_ref, entry) = vfs
        .open_file(
            pid,
            StartAnchor::Root,
            path,
            abi::O_RDONLY | abi::O_NOFOLLOW,
            0,
        )
        .await
        .map_err(map_errno)?;
    if !entry.metadata.is_file() {
        let _ = file_ref.close().await;
        return Err(vfs_js_err(Errno::EISDIR, "expected a regular file"));
    }
    if entry.metadata.size > max_bytes {
        let _ = file_ref.close().await;
        return Err(vfs_js_err(
            err_on_too_big,
            "private package exceeds its size limit",
        ));
    }
    let expected = entry.metadata.size as usize;
    let mut out = vec![0u8; expected];
    let mut off = 0usize;
    while off < expected {
        let chunk = (expected - off).min(256 * 1024);
        match file_ref
            .read_at(&mut out[off..off + chunk], off as u64)
            .await
        {
            Ok(0) => {
                let _ = file_ref.close().await;
                return Err(vfs_js_err(
                    Errno::ESTALE,
                    "package changed during activation",
                ));
            }
            Ok(n) => off += n,
            Err(e) => {
                let _ = file_ref.close().await;
                return Err(map_errno(e));
            }
        }
    }
    let _ = file_ref.close().await;
    Ok(out)
}

#[wasm_bindgen]
impl Kernel {
    // =========================================================================
    // 1. Boot, Login Session Lifecycle & User Mount Service
    // =========================================================================

    /// Re-initialize `system_mnt_ns` with optional composition / build asset options.
    pub async fn boot_vfs(&self, opts_json: Option<String>) -> Result<(), JsValue> {
        let opts: Option<BootVfsOptions> = opts_json
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|s| serde_json::from_str(s).map_err(|e| vfs_js_err(Errno::EINVAL, e.to_string())))
            .transpose()?;
        let (inst_id, root_cloud) = {
            let state = self.state.borrow();
            let id = if state.namespace.is_empty() {
                if state.id.is_empty() {
                    "local-instance".to_string()
                } else {
                    state.id.clone()
                }
            } else {
                state.namespace.clone()
            };
            (id, Rc::clone(&self.vfs_rt.borrow().root_cloud))
        };
        let _ = root_cloud.seed_from_authority().await;
        let (vfs, dev_pts, usr_fs_id, usr_blob_paths) = construct_vfs(&inst_id, root_cloud, opts)
            .await
            .map_err(map_errno)?;
        let mut rt = self.vfs_rt.borrow_mut();
        rt.vfs = vfs;
        rt.dev_pts = dev_pts;
        rt.usr_fs_id = usr_fs_id;
        rt.usr_blob_paths = usr_blob_paths;
        rt.sessions.clear();
        Ok(())
    }

    /// Derive or resume a private `MountNamespace` for login session `session_id`.
    pub async fn session_begin(
        &self,
        session_id: String,
        uid: u32,
        gid: u32,
        groups: Vec<u32>,
    ) -> Result<JsValue, JsValue> {
        if session_id.trim().is_empty() {
            return Err(vfs_js_err(Errno::EINVAL, "session_id is required"));
        }
        let existing_ns = {
            let mut rt = self.vfs_rt.borrow_mut();
            let ns_opt = if let Some(existing) = rt.sessions.get_mut(&session_id) {
                if existing.uid != uid {
                    return Err(vfs_js_err(
                        Errno::EACCES,
                        "session_id is already bound to a different uid",
                    ));
                }
                existing.gid = gid;
                existing.groups = groups.iter().copied().collect();
                existing.groups.insert(gid);
                Some((existing.mnt_ns.borrow().id().0, existing.generation))
            } else {
                None
            };
            if ns_opt.is_some() {
                rt.active_session_id = Some(session_id.clone());
            }
            ns_opt
        };
        if let Some((ns_id, generation)) = existing_ns {
            return json_to_js(&json!({ "nsId": ns_id, "generation": generation }));
        }

        let (vfs, tmp_ids) = {
            let mut rt = self.vfs_rt.borrow_mut();
            let ids = [rt.alloc_tmp_id(), rt.alloc_tmp_id(), rt.alloc_tmp_id()];
            (rt.vfs.clone(), ids)
        };
        let sys_ns = vfs.system_namespace();
        let (sess_ns, _) = vfs.clone_namespace(&sys_ns);
        let mut root_cred = Cred::root();
        root_cred.umask = 0;

        for (tmp_id, target, mode) in [
            (tmp_ids[0], "/mnt/local", 0o700u16),
            (tmp_ids[1], "/mnt/shared", 0o755u16),
            (tmp_ids[2], "/opt/private", 0o700u16),
        ] {
            let fs = Rc::new(MemFs::new(
                FsId(format!("tmpfs:sess:{session_id}:{tmp_id}")),
                tmp_id,
                uid,
                gid,
                mode,
                Box::new(js_now_timespec),
            ));
            let backing = Rc::new(MountBacking::new(fs, vfs::FsType::TmpFs));
            vfs.mount_on_namespace(
                &sess_ns,
                &root_cred,
                backing,
                None,
                "tmpfs",
                target,
                MountFlags {
                    nosuid: true,
                    nodev: true,
                    ..MountFlags::default()
                },
                mount_flags::MS_NOSUID | mount_flags::MS_NODEV,
                None,
            )
            .await
            .map_err(map_errno)?;
        }

        let ns_id = sess_ns.borrow().id().0;
        let baseline_mounts = sess_ns.borrow().mounts().keys().copied().collect();
        let mut group_set: BTreeSet<u32> = groups.into_iter().collect();
        group_set.insert(gid);
        {
            let mut rt = self.vfs_rt.borrow_mut();
            rt.active_session_id = Some(session_id.clone());
            rt.sessions.insert(
                session_id.clone(),
                SessionVfs {
                    session_id: session_id.clone(),
                    uid,
                    gid,
                    groups: group_set,
                    mnt_ns: sess_ns,
                    baseline_mounts,
                    generation: 1,
                    user_mounts: BTreeMap::new(),
                    page_fds: HashMap::new(),
                    next_page_fd: CLIENT_PAGE_FD_BASE,
                },
            );
        }
        emit_mounts_changed(&session_id, 1);
        json_to_js(&json!({ "nsId": ns_id, "generation": 1u64 }))
    }

    pub fn set_active_session(&self, session_id: Option<String>) {
        self.vfs_rt.borrow_mut().active_session_id = session_id.filter(|s| !s.is_empty());
    }

    /// Tear down login session `session_id` and detach all its user mounts cleanly.
    pub async fn session_end(&self, session_id: String) -> Result<(), JsValue> {
        let removed = {
            let mut rt = self.vfs_rt.borrow_mut();
            if rt.active_session_id.as_deref() == Some(session_id.as_str()) {
                rt.active_session_id = None;
            }
            let vfs = rt.vfs.clone();
            rt.sessions.remove(&session_id).map(|sess| (vfs, sess))
        };
        let Some((vfs, mut sess)) = removed else {
            return Ok(());
        };
        for (_, fd_entry) in sess.page_fds.drain() {
            let _ = fd_entry.file.close().await;
        }
        for (_, mut um) in sess.user_mounts {
            let _ = sess.mnt_ns.borrow_mut().detach_subtree(um.mount_id);
            if let Some(lm) = um.local_mount.take() {
                lm.shutdown_provider();
            }
            if let Some(cleanup) = um.cleanup.take() {
                cleanup();
            }
        }
        let _ = vfs.releases().flush().await;
        emit_mounts_changed(&session_id, 0);
        Ok(())
    }

    /// Attach a user mount (`opfs`, `hostfs`, `snapshot`, `helperfs`, `sharefs`, or `image`)
    /// inside `session_id`'s private `MountNamespace` with `owner_uid = Some(session.uid)` and
    /// locked `MS_NOSUID | MS_NODEV`.
    pub async fn mount_user(
        &self,
        session_id: String,
        spec_json: String,
        host_obj: JsValue,
    ) -> Result<JsValue, JsValue> {
        let spec: MountUserSpec = serde_json::from_str(&spec_json)
            .map_err(|e| vfs_js_err(Errno::EINVAL, e.to_string()))?;
        let clean_name = clean_mount_name(&spec.name).map_err(map_errno)?;

        let (vfs, sess_ns, uid, gid, sess_cred, tmp_seq) = {
            let mut rt = self.vfs_rt.borrow_mut();
            let seq = rt.alloc_tmp_id();
            let vfs = rt.vfs.clone();
            let sess = rt
                .sessions
                .get(&session_id)
                .ok_or_else(|| vfs_js_err(Errno::ENOENT, "no active login session"))?;
            if sess.user_mounts.len() >= MAX_USER_MOUNTS {
                return Err(vfs_js_err(
                    Errno::ENOSPC,
                    "maximum of 16 user mounts reached",
                ));
            }
            (
                vfs,
                Rc::clone(&sess.mnt_ns),
                sess.uid,
                sess.gid,
                sess.cred(0o022),
                seq,
            )
        };

        let normalized_kind = match spec.kind.as_str() {
            "browser-storage" | "opfs" => "opfs",
            "directory" | "hostfs" => "hostfs",
            "snapshot" => "snapshot",
            "native-directory" | "helperfs" => "helperfs",
            "shared" | "sharefs" => "sharefs",
            "private-extension" | "image" => "image",
            _ => return Err(vfs_js_err(Errno::ENODEV, "unsupported user mount kind")),
        };

        let default_base = match normalized_kind {
            "sharefs" => "/mnt/shared",
            "image" => "/opt/private",
            _ => "/mnt/local",
        };
        let target_path = match &spec.target {
            Some(t) if !t.is_empty() => {
                let expected_prefix = format!("{default_base}/");
                if !t.starts_with(&expected_prefix) {
                    return Err(vfs_js_err(
                        Errno::EPERM,
                        "user mount target is outside its allowed directory",
                    ));
                }
                let suffix = &t[expected_prefix.len()..];
                let validated = clean_mount_name(suffix).map_err(map_errno)?;
                format!("{default_base}/{validated}")
            }
            _ => format!("{default_base}/{clean_name}"),
        };

        {
            let rt = self.vfs_rt.borrow();
            let sess = rt
                .sessions
                .get(&session_id)
                .ok_or_else(|| vfs_js_err(Errno::ENOENT, "no active login session"))?;
            if sess.user_mounts.contains_key(&target_path) {
                return Err(vfs_js_err(Errno::EBUSY, "mount point is already in use"));
            }
        }

        let grant = Grant {
            kind: match normalized_kind {
                "opfs" => "browser-storage".to_string(),
                "hostfs" => "directory".to_string(),
                "snapshot" => "snapshot".to_string(),
                "helperfs" => "native-directory".to_string(),
                "sharefs" => "shared".to_string(),
                _ => "private-extension".to_string(),
            },
            name: clean_name.clone(),
            read_only: !spec.writable || matches!(normalized_kind, "snapshot" | "image"),
            execute: if normalized_kind == "image" {
                true
            } else {
                spec.execute
            },
            owner: sess_cred.identity.clone(),
        };
        let grant_json =
            serde_json::to_string(&grant).map_err(|e| vfs_js_err(Errno::EINVAL, e.to_string()))?;

        type PreparedMount = (
            Rc<MountBacking>,
            Option<(Handle, String)>,
            String,
            bool,
            bool,
            Rc<ProviderState>,
            Option<LocalMount>,
            Option<Box<dyn FnOnce()>>,
        );
        let (backing, subroot, source_str, read_only, execute, provider, local_mount, cleanup): PreparedMount =
            match normalized_kind {
            "opfs" => {
                let lm = crate::hostfs::mount_opfs(host_obj, &grant_json).await?;
                let ro = lm.grant_info().read_only;
                let ex = lm.grant_info().execute;
                let b = lm.mount_backing(vfs::FsType::Opfs);
                let p = lm.provider_state();
                (b, None, format!("opfs:{clean_name}"), ro, ex, p, Some(lm), None)
            }
            "hostfs" => {
                let lm = crate::hostfs::mount_directory(host_obj, &grant_json).await?;
                let ro = lm.grant_info().read_only;
                let ex = lm.grant_info().execute;
                let b = lm.mount_backing(vfs::FsType::HostFs);
                let p = lm.provider_state();
                (
                    b,
                    None,
                    format!("hostfs:{clean_name}"),
                    ro,
                    ex,
                    p,
                    Some(lm),
                    None,
                )
            }
            "snapshot" => {
                let lm = crate::hostfs::mount_snapshot(host_obj, &grant_json).await?;
                let ex = lm.grant_info().execute;
                let b = lm.mount_backing(vfs::FsType::HostFs);
                let p = lm.provider_state();
                (
                    b,
                    None,
                    format!("snapshot:{clean_name}"),
                    true,
                    ex,
                    p,
                    Some(lm),
                    None,
                )
            }
            "helperfs" => {
                let lm = crate::helper::connect_helper_mount(host_obj, &grant_json).await?;
                let ro = lm.grant_info().read_only;
                let ex = lm.grant_info().execute;
                let b = lm.mount_backing(vfs::FsType::HelperFs);
                let p = lm.provider_state();
                (
                    b,
                    None,
                    format!("helperfs:{clean_name}"),
                    ro,
                    ex,
                    p,
                    Some(lm),
                    None,
                )
            }
            "sharefs" => {
                let (b, root_h, p, ro, ex, clean_fn) =
                    build_share_backing(host_obj, &format!("{session_id}:{tmp_seq}"))
                        .await
                        .map_err(map_errno)?;
                (
                    b,
                    Some((root_h, "/".to_string())),
                    format!("sharefs:{clean_name}"),
                    ro,
                    ex,
                    p,
                    None,
                    Some(clean_fn),
                )
            }
            "image" => {
                let (b, label, p) = self
                    .build_private_extension_backing(
                        &vfs,
                        &sess_ns,
                        &sess_cred,
                        uid,
                        gid,
                        tmp_seq,
                        &target_path,
                        &spec,
                        &host_obj,
                    )
                    .await?;
                (
                    b,
                    None,
                    format!("image:{label}"),
                    true,
                    true,
                    p,
                    None,
                    None,
                )
            }
            _ => unreachable!(),
        };

        // Re-check session mount limit after async provider setup (`workspace.test.mjs` concurrency gate!).
        let scoped_pid = {
            let mut rt = self.vfs_rt.borrow_mut();
            let spid = rt.alloc_scoped_pid();
            let sess = rt
                .sessions
                .get(&session_id)
                .ok_or_else(|| vfs_js_err(Errno::ENOENT, "login session ended during mount"))?;
            if sess.user_mounts.len() >= MAX_USER_MOUNTS {
                if let Some(lm) = local_mount {
                    lm.shutdown_provider();
                }
                if let Some(c) = cleanup {
                    c();
                }
                return Err(vfs_js_err(
                    Errno::ENOSPC,
                    "maximum of 16 user mounts reached",
                ));
            }
            if sess.user_mounts.contains_key(&target_path) {
                if let Some(lm) = local_mount {
                    lm.shutdown_provider();
                }
                if let Some(c) = cleanup {
                    c();
                }
                return Err(vfs_js_err(Errno::EBUSY, "mount point is already in use"));
            }
            spid
        };

        // Ensure target directory `/mnt/local/<name>` / `/mnt/shared/<name>` / `/opt/private/<name>`
        // exists in `sess_ns`, owned by `(uid, gid)`.
        vfs.spawn_process(
            scoped_pid,
            INIT,
            sess_cred.clone(),
            Some(Rc::clone(&sess_ns)),
            None,
            None,
        )
        .map_err(map_errno)?;
        let mkdir_res = vfs
            .mkdirat(scoped_pid, StartAnchor::Root, &target_path, 0o700)
            .await;
        let _ = vfs.exit_process(scoped_pid).await;
        if let Err(err) = mkdir_res
            && err != Errno::EEXIST
        {
            if let Some(lm) = local_mount {
                lm.shutdown_provider();
            }
            if let Some(c) = cleanup {
                c();
            }
            return Err(map_errno(err));
        }

        let is_snapshot = normalized_kind == "snapshot";
        let mflags = MountFlags {
            rdonly: read_only && !is_snapshot,
            nosuid: true,
            nodev: true,
            noexec: !execute,
            ..MountFlags::default()
        };
        let mut locked = mount_flags::MS_NOSUID | mount_flags::MS_NODEV;
        if read_only && !is_snapshot {
            locked |= mount_flags::MS_RDONLY;
        }
        if !execute {
            locked |= mount_flags::MS_NOEXEC;
        }

        let fs_id = backing.fs.id().clone();
        let mount_id = match vfs
            .mount_on_namespace(
                &sess_ns,
                &sess_cred,
                backing,
                subroot,
                &source_str,
                &target_path,
                mflags,
                locked,
                Some(uid),
            )
            .await
        {
            Ok(id) => id,
            Err(err) => {
                if let Some(lm) = local_mount {
                    lm.shutdown_provider();
                }
                if let Some(c) = cleanup {
                    c();
                }
                return Err(map_errno(err));
            }
        };

        let (generation, summary) = {
            let mut rt = self.vfs_rt.borrow_mut();
            rt.cloud_exec_by_fs.insert(fs_id.clone(), spec.cloud);
            let sess = rt
                .sessions
                .get_mut(&session_id)
                .ok_or_else(|| vfs_js_err(Errno::ENOENT, "login session ended"))?;
            sess.generation = sess.generation.wrapping_add(1);
            let gen_num = sess.generation;
            let kind_out = grant.kind.clone();
            sess.user_mounts.insert(
                target_path.clone(),
                AttachedUserMount {
                    mount_id,
                    kind: kind_out.clone(),
                    name: clean_name.clone(),
                    cloud: spec.cloud,
                    provider,
                    local_mount,
                    cleanup,
                },
            );
            (
                gen_num,
                json!({
                    "mountId": mount_id.0,
                    "path": target_path,
                    "target": target_path,
                    "name": clean_name,
                    "kind": kind_out,
                    "fstype": normalized_kind,
                    "readOnly": read_only,
                    "execute": execute,
                    "cloud": spec.cloud,
                    "dev": fs_id.dev(),
                }),
            )
        };
        emit_mounts_changed(&session_id, generation);
        json_to_js(&summary)
    }

    #[allow(clippy::too_many_arguments)]
    async fn build_private_extension_backing(
        &self,
        vfs: &Vfs,
        sess_ns: &Rc<RefCell<MountNamespace>>,
        sess_cred: &Cred,
        uid: u32,
        gid: u32,
        seq: u64,
        target_path: &str,
        spec: &MountUserSpec,
        host_obj: &JsValue,
    ) -> Result<(Rc<MountBacking>, String, Rc<ProviderState>), JsValue> {
        let mut sources = spec.sources.clone();
        if let Some(single) = &spec.source
            && !single.is_empty()
            && sources.is_empty()
        {
            sources.push(single.clone());
        }

        let mut manifest_texts: Vec<String> = Vec::new();
        let mut blob_store = MemoryBlobStore::new();
        let mut total_bytes: u64 = 0;

        if !spec.manifests.is_empty() {
            if spec.manifests.len() > 16 {
                return Err(vfs_js_err(
                    Errno::EINVAL,
                    "select 1 to 16 private extensions",
                ));
            }
            manifest_texts = spec.manifests.clone();
            if host_obj.is_object()
                && !host_obj.is_null()
                && let Ok(blobs_obj) = js_sys::Reflect::get(host_obj, &"blobs".into())
                && blobs_obj.is_object()
                && !blobs_obj.is_null()
            {
                let keys = js_sys::Object::keys(&js_sys::Object::from(blobs_obj.clone()));
                for i in 0..keys.length() {
                    if let Some(sha) = keys.get(i).as_string()
                        && let Ok(val) = js_sys::Reflect::get(&blobs_obj, &JsValue::from_str(&sha))
                    {
                        let bytes = js_sys::Uint8Array::new(&val).to_vec();
                        total_bytes = total_bytes.saturating_add(bytes.len() as u64);
                        if total_bytes > PRIVATE_EXT_MAX_BYTES {
                            return Err(vfs_js_err(
                                Errno::EFBIG,
                                "private package exceeds 128 MiB",
                            ));
                        }
                        if image::digest(&bytes) != sha {
                            return Err(vfs_js_err(
                                Errno::EIO,
                                "private package content digest mismatch",
                            ));
                        }
                        blob_store.insert(sha, bytes);
                    }
                }
            }
        } else {
            if sources.is_empty() || sources.len() > 16 {
                return Err(vfs_js_err(
                    Errno::EINVAL,
                    "select 1 to 16 private extension directories",
                ));
            }
            let scoped_pid = self.vfs_rt.borrow_mut().alloc_scoped_pid();
            vfs.spawn_process(
                scoped_pid,
                INIT,
                sess_cred.clone(),
                Some(Rc::clone(sess_ns)),
                None,
                None,
            )
            .map_err(map_errno)?;

            let load_res: Result<(), JsValue> = async {
                let mut parsed_imgs = Vec::new();
                for src_dir in &sources {
                    let clean_src = src_dir.trim_end_matches('/');
                    let mpath = format!("{clean_src}/manifest.json");
                    let raw = read_vfs_file_bounded(
                        vfs,
                        scoped_pid,
                        &mpath,
                        MANIFEST_MAX_BYTES,
                        Errno::EFBIG,
                    )
                    .await?;
                    let text = std::str::from_utf8(&raw)
                        .map_err(|_| vfs_js_err(Errno::EINVAL, "manifest is not valid UTF-8"))?
                        .to_string();
                    let img = image::Image::parse(text.as_bytes())
                        .map_err(|e| vfs_js_err(Errno::EINVAL, e.to_string()))?;
                    manifest_texts.push(text);
                    parsed_imgs.push((clean_src.to_string(), img));
                }
                let _ = image::Composition::private(
                    &parsed_imgs
                        .iter()
                        .map(|(_, img)| img.clone())
                        .collect::<Vec<_>>(),
                )
                .map_err(|e| vfs_js_err(Errno::EINVAL, e.to_string()))?;

                let mut seen_blobs = BTreeSet::new();
                for (src_dir, img) in &parsed_imgs {
                    for entry in &img.entries {
                        if let image::Node::File { sha256, size } = &entry.node {
                            if !seen_blobs.insert(sha256.clone()) {
                                continue;
                            }
                            total_bytes = total_bytes.saturating_add(*size);
                            if total_bytes > PRIVATE_EXT_MAX_BYTES {
                                return Err(vfs_js_err(
                                    Errno::EFBIG,
                                    "private package exceeds 128 MiB",
                                ));
                            }
                            let bpath = format!("{src_dir}/blobs/{sha256}");
                            let bytes =
                                read_vfs_file_bounded(vfs, scoped_pid, &bpath, *size, Errno::EFBIG)
                                    .await?;
                            if bytes.len() as u64 != *size || image::digest(&bytes) != *sha256 {
                                return Err(vfs_js_err(
                                    Errno::EIO,
                                    "private package content digest mismatch",
                                ));
                            }
                            blob_store.insert(sha256.clone(), bytes);
                        }
                    }
                }
                Ok(())
            }
            .await;
            let _ = vfs.exit_process(scoped_pid).await;
            load_res?;
        }

        let images: Vec<image::Image> = manifest_texts
            .iter()
            .map(|t| image::Image::parse(t.as_bytes()))
            .collect::<image::Result<Vec<_>>>()
            .map_err(|e| vfs_js_err(Errno::EINVAL, e.to_string()))?;
        let composition = image::Composition::private(&images)
            .map_err(|e| vfs_js_err(Errno::EINVAL, e.to_string()))?;

        // Verify all referenced blobs are present when loaded via `spec.manifests`.
        for entry in composition.entries.values() {
            if let image::Node::File { sha256, size } = &entry.node {
                let mut probe = [0u8; 1];
                if *size > 0
                    && now_or_never(blob_store.read_at(sha256, 0, &mut probe)) != Some(Ok(1))
                {
                    return Err(vfs_js_err(Errno::EIO, "missing private package blob"));
                }
            }
        }

        let label = images
            .iter()
            .map(|img| img.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let img_entries: Vec<ImageEntry> = composition
            .entries
            .into_values()
            .map(|e| ImageEntry {
                path: e.path,
                uid,
                gid,
                mode: e.mode & 0o0777,
                node: match e.node {
                    image::Node::Directory => ImageNodeKind::Directory,
                    image::Node::File { sha256, size } => ImageNodeKind::File {
                        blob_id: sha256,
                        size,
                    },
                    image::Node::Symlink { target } => {
                        let rebased = if target.starts_with('/') {
                            let rel = target.trim_start_matches('/');
                            if rel.is_empty() {
                                target_path.to_string()
                            } else {
                                format!("{target_path}/{rel}")
                            }
                        } else {
                            target
                        };
                        ImageNodeKind::Symlink { target: rebased }
                    }
                },
            })
            .collect();
        let fs_id = FsId(format!("image:priv:{seq}"));
        let mounted_at = Timespec::from(js_now_timespec());
        let img_fs =
            ImageFs::new(fs_id, false, mounted_at, img_entries, blob_store).map_err(map_errno)?;
        let provider = ProviderState::new();
        let backing = Rc::new(
            MountBacking::new(Rc::new(img_fs), vfs::FsType::Image)
                .with_provider(Rc::clone(&provider))
                .with_ceilings(true, false),
        );
        Ok((backing, label, provider))
    }

    /// Unmount or lazily detach (`MNT_DETACH`) a mount inside `session_id`'s `MountNamespace`.
    pub async fn unmount_user(
        &self,
        session_id: String,
        target: String,
        flags: u32,
    ) -> Result<(), JsValue> {
        let clean = umount_flags::accepted(flags).map_err(map_errno)?;
        let (vfs, sess_ns, sess_cred, scoped_pid) = {
            let mut rt = self.vfs_rt.borrow_mut();
            let spid = rt.alloc_scoped_pid();
            let vfs = rt.vfs.clone();
            let sess = rt
                .sessions
                .get(&session_id)
                .ok_or_else(|| vfs_js_err(Errno::ENOENT, "no active login session"))?;
            (vfs, Rc::clone(&sess.mnt_ns), sess.cred(0o022), spid)
        };

        // Identify the topmost mount at `target` in `sess_ns`.
        vfs.spawn_process(
            scoped_pid,
            INIT,
            sess_cred,
            Some(Rc::clone(&sess_ns)),
            None,
            None,
        )
        .map_err(map_errno)?;
        let umount_res = vfs.umount2(scoped_pid, &target, clean).await;
        let _ = vfs.exit_process(scoped_pid).await;
        umount_res.map_err(map_errno)?;

        let (generation, cleanup_dir) = {
            let mut rt = self.vfs_rt.borrow_mut();
            let spid2 = rt.alloc_scoped_pid();
            let sess = rt
                .sessions
                .get_mut(&session_id)
                .ok_or_else(|| vfs_js_err(Errno::ENOENT, "no active login session"))?;
            if let Some(mut um) = sess.user_mounts.remove(&target) {
                if let Some(lm) = um.local_mount.take() {
                    lm.shutdown_provider();
                }
                if let Some(c) = um.cleanup.take() {
                    c();
                }
                let scred2 = sess.cred(0o022);
                let sns2 = Rc::clone(&sess.mnt_ns);
                sess.generation = sess.generation.wrapping_add(1);
                (sess.generation, Some((spid2, scred2, sns2)))
            } else {
                sess.generation = sess.generation.wrapping_add(1);
                (sess.generation, None)
            }
        };
        if let Some((spid2, scred2, sns2)) = cleanup_dir
            && vfs
                .spawn_process(spid2, INIT, scred2, Some(sns2), None, None)
                .is_ok()
        {
            let _ = vfs.unlinkat(spid2, StartAnchor::Root, &target, true).await;
            let _ = vfs.exit_process(spid2).await;
        }
        let _ = vfs.releases().flush().await;
        emit_mounts_changed(&session_id, generation);
        Ok(())
    }

    /// Transition a user mount's `ProviderState` to `Revoked` (`EACCES` on all new & open-fd ops,
    /// while remaining visible in `mountinfo` until `umount2`, contract §4 Ending 3).
    pub fn revoke_mount_provider(&self, session_id: String, target: String) -> Result<(), JsValue> {
        let generation = {
            let mut rt = self.vfs_rt.borrow_mut();
            let sess = rt
                .sessions
                .get_mut(&session_id)
                .ok_or_else(|| vfs_js_err(Errno::ENOENT, "no active login session"))?;
            let um = sess
                .user_mounts
                .get(&target)
                .ok_or_else(|| vfs_js_err(Errno::ENOENT, "no such user mount"))?;
            um.provider.revoke();
            sess.generation = sess.generation.wrapping_add(1);
            sess.generation
        };
        emit_mounts_changed(&session_id, generation);
        Ok(())
    }

    /// Transition a user mount's `ProviderState` to `Lost` (`ENOTCONN` on ops, `EIO` + uncertain
    /// writes on in-flight mutations, while remaining in `mountinfo` until `umount2`, Ending 4).
    pub fn lose_mount_provider(&self, session_id: String, target: String) -> Result<(), JsValue> {
        let generation = {
            let mut rt = self.vfs_rt.borrow_mut();
            let sess = rt
                .sessions
                .get_mut(&session_id)
                .ok_or_else(|| vfs_js_err(Errno::ENOENT, "no active login session"))?;
            let um = sess
                .user_mounts
                .get(&target)
                .ok_or_else(|| vfs_js_err(Errno::ENOENT, "no such user mount"))?;
            um.provider.lose();
            sess.generation = sess.generation.wrapping_add(1);
            sess.generation
        };
        emit_mounts_changed(&session_id, generation);
        Ok(())
    }

    /// Look up the underlying `LocalMount` provider for `exportMount` (`mount-sharing.js`).
    pub fn export_provider(&self, session_id: String, path: String) -> Result<JsValue, JsValue> {
        let rt = self.vfs_rt.borrow();
        let sess = rt
            .sessions
            .get(&session_id)
            .ok_or_else(|| vfs_js_err(Errno::ENOENT, "no active login session"))?;
        let clean = if path.len() > 1 {
            path.trim_end_matches('/')
        } else {
            path.as_str()
        };
        let mut best: Option<(&String, &AttachedUserMount)> = None;
        for (mp, um) in &sess.user_mounts {
            if (clean == mp || clean.strip_prefix(mp).is_some_and(|r| r.starts_with('/')))
                && best.is_none_or(|(b, _)| mp.len() > b.len())
            {
                best = Some((mp, um));
            }
        }
        let Some((mp, um)) = best else {
            return Err(vfs_js_err(Errno::EACCES, "publish a local filesystem"));
        };
        let Some(lm) = &um.local_mount else {
            return Err(vfs_js_err(Errno::EACCES, "publish a local filesystem"));
        };
        let rel = clean
            .strip_prefix(mp.as_str())
            .unwrap_or("")
            .trim_start_matches('/');
        let owner_view = lm.clone_owner();
        let grant_js = owner_view.grant_js();
        let out = js_sys::Object::new();
        let _ = js_sys::Reflect::set(&out, &"mountPath".into(), &JsValue::from_str(mp));
        let _ = js_sys::Reflect::set(&out, &"relative".into(), &JsValue::from_str(rel));
        let _ = js_sys::Reflect::set(&out, &"grant".into(), &grant_js);
        let _ = js_sys::Reflect::set(&out, &"provider".into(), &owner_view.into());
        Ok(out.into())
    }

    /// Return structured mount table entries (both system/CLI mounts and user mounts) for
    /// `session_id` (or `system_mnt_ns` when `session_id` is empty).
    pub async fn list_mounts(&self, session_id: String) -> Result<JsValue, JsValue> {
        #[derive(Clone)]
        struct UserMountMeta {
            mount_id: MountId,
            kind: String,
            name: String,
            cloud: bool,
        }
        let (ns, cred, user_meta, baseline_mounts, generation) = {
            let rt = self.vfs_rt.borrow();
            if session_id.is_empty() {
                let sys_ns = rt.vfs.system_namespace();
                let base = sys_ns
                    .borrow()
                    .mounts()
                    .keys()
                    .copied()
                    .collect::<BTreeSet<_>>();
                (sys_ns, Cred::root(), Vec::new(), base, 0)
            } else {
                let sess = rt
                    .sessions
                    .get(&session_id)
                    .ok_or_else(|| vfs_js_err(Errno::ENOENT, "no active login session"))?;
                let meta = sess
                    .user_mounts
                    .values()
                    .map(|u| UserMountMeta {
                        mount_id: u.mount_id,
                        kind: u.kind.clone(),
                        name: u.name.clone(),
                        cloud: u.cloud,
                    })
                    .collect::<Vec<_>>();
                (
                    Rc::clone(&sess.mnt_ns),
                    sess.cred(0o022),
                    meta,
                    sess.baseline_mounts.clone(),
                    sess.generation,
                )
            }
        };

        let root_anchor = ns.borrow().root_anchor();
        let mountinfo_text = format_mountinfo(&cred, &ns, &root_anchor, true).await;
        let ns_borrow = ns.borrow();
        let mut mounts_json = Vec::new();

        for line in mountinfo_text.lines() {
            // Format: "<id> <parent> <maj:min> <root> <target> <opts> - <fstype> <source> <super_opts>"
            let Some((lhs, rhs)) = line.split_once(" - ") else {
                continue;
            };
            let lparts: Vec<&str> = lhs.split_whitespace().collect();
            let rparts: Vec<&str> = rhs.split_whitespace().collect();
            if lparts.len() < 6 || rparts.len() < 2 {
                continue;
            }
            let Ok(mid) = lparts[0].parse::<u64>() else {
                continue;
            };
            let parent_id = lparts[1].parse::<u64>().unwrap_or(0);
            let target = unescape_mountinfo(lparts[4]);
            let fstype = rparts[0];
            let source = unescape_mountinfo(rparts[1]);
            let entry = ns_borrow.entry(MountId(mid));
            let flags = entry.map(|e| e.slot.effective_flags()).unwrap_or_default();
            let owner_uid = entry.and_then(|e| e.slot.owner_uid);
            let health = entry
                .map(|e| match e.slot.backing.provider.health() {
                    ProviderHealth::Connected => "connected",
                    ProviderHealth::Revoked => "revoked",
                    ProviderHealth::Lost => "lost",
                })
                .unwrap_or("connected");
            let uncertain = entry
                .map(|e| e.slot.backing.provider.uncertain_writes())
                .unwrap_or(0);
            let um = user_meta.iter().find(|u| u.mount_id == MountId(mid));
            mounts_json.push(json!({
                "mountId": mid,
                "parentId": parent_id,
                "path": target,
                "target": target,
                "fstype": fstype,
                "source": source,
                "readOnly": flags.rdonly,
                "nosuid": flags.nosuid,
                "nodev": flags.nodev,
                "noexec": flags.noexec,
                "ownerUid": owner_uid,
                "baseline": baseline_mounts.contains(&MountId(mid)),
                "userMount": um.is_some() || owner_uid.is_some(),
                "kind": um.map(|u| u.kind.as_str()).unwrap_or(fstype),
                "name": um.map(|u| u.name.as_str()).unwrap_or(""),
                "execute": !flags.noexec,
                "cloud": um.map(|u| u.cloud).unwrap_or(owner_uid.is_none()),
                "health": health,
                "uncertainWrites": uncertain,
            }));
        }

        json_to_js(&json!({
            "nsId": ns_borrow.id().0,
            "generation": generation,
            "mountinfo": mountinfo_text,
            "mounts": mounts_json,
        }))
    }

    /// Execute a page `abi::Batch` (`POST /api/sys` filesystem calls from `Files` / `shell.rs` /
    /// `upload.mjs`) inside `session_id`'s `MountNamespace`.
    pub async fn vfs_sys(&self, session_id: String, batch_json: String) -> Result<String, JsValue> {
        let batch: Batch = serde_json::from_str(&batch_json)
            .map_err(|e| vfs_js_err(Errno::EINVAL, e.to_string()))?;
        let umask = batch.umask.unwrap_or(0o022);
        let sudo = batch.sudo;

        let (vfs, mnt_ns, mut cred, scoped_pid) = {
            let mut rt = self.vfs_rt.borrow_mut();
            let spid = rt.alloc_scoped_pid();
            let vfs = rt.vfs.clone();
            if session_id.is_empty() {
                (
                    vfs,
                    rt.vfs.system_namespace(),
                    Cred {
                        identity: if sudo {
                            Identity::root()
                        } else {
                            Identity::guest()
                        },
                        umask,
                        token: None,
                    },
                    spid,
                )
            } else {
                let sess = rt
                    .sessions
                    .get(&session_id)
                    .ok_or_else(|| vfs_js_err(Errno::ENOENT, "no active login session"))?;
                let mut c = sess.cred(umask);
                if sudo {
                    c.identity = Identity::root();
                }
                (vfs, Rc::clone(&sess.mnt_ns), c, spid)
            }
        };
        cred.umask = umask;

        vfs.spawn_process(
            scoped_pid,
            INIT,
            cred.clone(),
            Some(Rc::clone(&mnt_ns)),
            None,
            None,
        )
        .map_err(map_errno)?;

        let results = self
            .with_page_scope(sudo, async {
                let results = self
                    .execute_batch_on_pid(
                        &vfs,
                        scoped_pid,
                        Some(&session_id),
                        batch.calls,
                        sudo,
                        batch.umask.is_none(),
                    )
                    .await;
                let _ = vfs.exit_process(scoped_pid).await;
                results
            })
            .await;
        serde_json::to_string(&abi::Results { results })
            .map_err(|e| vfs_js_err(Errno::EIO, e.to_string()))
    }

    /// Read a byte range from a path in `session_id`'s `MountNamespace` (`GET /api/file?path=...`).
    pub async fn vfs_read_file(
        &self,
        session_id: String,
        path: String,
        offset: u64,
        len: u32,
    ) -> Result<JsValue, JsValue> {
        let (vfs, mnt_ns, cred, scoped_pid) = {
            let mut rt = self.vfs_rt.borrow_mut();
            let spid = rt.alloc_scoped_pid();
            let vfs = rt.vfs.clone();
            if session_id.is_empty() {
                (
                    vfs,
                    rt.vfs.system_namespace(),
                    Cred::new(Identity::guest()),
                    spid,
                )
            } else {
                let sess = rt
                    .sessions
                    .get(&session_id)
                    .ok_or_else(|| vfs_js_err(Errno::ENOENT, "no active login session"))?;
                (vfs, Rc::clone(&sess.mnt_ns), sess.cred(0o022), spid)
            }
        };

        vfs.spawn_process(scoped_pid, INIT, cred, Some(mnt_ns), None, None)
            .map_err(map_errno)?;
        let res = self
            .with_page_scope(false, async {
                let res = async {
                    let (file_ref, entry) = vfs
                        .open_file(scoped_pid, StartAnchor::Root, &path, abi::O_RDONLY, 0)
                        .await?;
                    if !entry.metadata.is_file() {
                        let _ = file_ref.close().await;
                        return Err(Errno::EISDIR);
                    }
                    let cap = (len as usize).min(4 * 1024 * 1024);
                    let mut buf = vec![0u8; cap];
                    let read_res = if cap > 0 {
                        file_ref.read_at(&mut buf, offset).await
                    } else {
                        Ok(0)
                    };
                    let _ = file_ref.close().await;
                    let n = read_res?;
                    buf.truncate(n);
                    let stat =
                        vfs::stat::stat(&entry.handle.fs, entry.handle.node, &entry.metadata);
                    Ok((stat, buf))
                }
                .await;
                let _ = vfs.exit_process(scoped_pid).await;
                res
            })
            .await;

        let (mut stat, bytes) = res.map_err(map_errno)?;
        self.with_page_scope(
            false,
            self.fill_stat_names(&vfs, SCOPED_PAGE_PID_BASE, &mut stat),
        )
        .await;
        let out = js_sys::Object::new();
        let _ = js_sys::Reflect::set(&out, &"stat".into(), &json_to_js(&json!(stat))?);
        let _ = js_sys::Reflect::set(
            &out,
            &"bytes".into(),
            &js_sys::Uint8Array::from(bytes.as_slice()).into(),
        );
        Ok(out.into())
    }

    /// Write an upload chunk to a client-side page upload `fd` (`>= 0x4000_0000`).
    pub async fn vfs_pwrite_chunk(
        &self,
        session_id: String,
        fd: u32,
        offset: u64,
        bytes: &[u8],
    ) -> Result<JsValue, JsValue> {
        let (file_ref, cred) = {
            let rt = self.vfs_rt.borrow();
            let sess = rt
                .sessions
                .get(&session_id)
                .ok_or_else(|| vfs_js_err(Errno::EBADF, "no active session"))?;
            let entry = sess
                .page_fds
                .get(&fd)
                .ok_or_else(|| vfs_js_err(Errno::EBADF, "bad file descriptor"))?;
            (entry.file.clone(), sess.cred(0o022))
        };
        let written = self
            .with_page_scope(false, file_ref.write_at_as(&cred, bytes, offset))
            .await
            .map_err(map_errno)?;
        json_to_js(&json!({ "written": written }))
    }

    pub async fn vfs_fstat_fd(&self, session_id: String, fd: u32) -> Result<JsValue, JsValue> {
        let (file_ref, cred) = {
            let rt = self.vfs_rt.borrow();
            let sess = rt
                .sessions
                .get(&session_id)
                .ok_or_else(|| vfs_js_err(Errno::EBADF, "no active session"))?;
            let file = sess
                .page_fds
                .get(&fd)
                .ok_or_else(|| vfs_js_err(Errno::EBADF, "bad file descriptor"))?
                .file
                .clone();
            (file, sess.cred(0o022))
        };
        let meta = self
            .with_page_scope(false, file_ref.metadata_as(&cred))
            .await
            .map_err(map_errno)?;
        let mut st = vfs::stat::stat(file_ref.fs().id(), file_ref.handle().node, &meta);
        let vfs = self.vfs_rt.borrow().vfs.clone();
        self.with_page_scope(
            false,
            self.fill_stat_names(&vfs, SCOPED_PAGE_PID_BASE, &mut st),
        )
        .await;
        json_to_js(&json!(st))
    }

    pub async fn vfs_fsync_fd(
        &self,
        session_id: String,
        fd: u32,
        data_only: bool,
    ) -> Result<(), JsValue> {
        let file_ref = {
            let rt = self.vfs_rt.borrow();
            let sess = rt
                .sessions
                .get(&session_id)
                .ok_or_else(|| vfs_js_err(Errno::EBADF, "no active session"))?;
            sess.page_fds
                .get(&fd)
                .ok_or_else(|| vfs_js_err(Errno::EBADF, "bad file descriptor"))?
                .file
                .clone()
        };
        let res = self
            .with_page_scope(false, async {
                if data_only {
                    file_ref.sync_data().await
                } else {
                    file_ref.sync_all().await
                }
            })
            .await;
        res.map_err(map_errno)
    }

    pub async fn vfs_ftruncate_fd(
        &self,
        session_id: String,
        fd: u32,
        size: u64,
    ) -> Result<(), JsValue> {
        let file_ref = {
            let rt = self.vfs_rt.borrow();
            let sess = rt
                .sessions
                .get(&session_id)
                .ok_or_else(|| vfs_js_err(Errno::EBADF, "no active session"))?;
            sess.page_fds
                .get(&fd)
                .ok_or_else(|| vfs_js_err(Errno::EBADF, "bad file descriptor"))?
                .file
                .clone()
        };
        self.with_page_scope(false, file_ref.set_len(size))
            .await
            .map_err(map_errno)
    }

    // =========================================================================
    // 2. Process Lifecycle & Service MountNamespaceGrant Instantiation
    // =========================================================================

    pub async fn proc_spawn_init(&self, opts_json: String) -> Result<JsValue, JsValue> {
        let opts: ProcSpawnInitOpts = serde_json::from_str(&opts_json)
            .map_err(|e| vfs_js_err(Errno::EINVAL, e.to_string()))?;

        let mut groups_set: BTreeSet<u32> = opts.groups.iter().copied().collect();
        groups_set.insert(opts.gid);
        let cred = Cred {
            identity: Identity {
                id: opts.uid,
                group: opts.gid,
                groups: groups_set,
            },
            umask: opts.umask & 0o777,
            token: opts.token.clone(),
        };

        // If `parentPid` is given without a service grant, fork from `parentPid` with `cloneFlags`
        // and update credentials/umask!
        if let Some(parent_pid) = opts.parent_pid
            && opts.service_grant.is_none()
        {
            let (vfs, root_cloud, parent_sess) = {
                let mut rt = self.vfs_rt.borrow_mut();
                let psess = rt
                    .proc_meta
                    .get(&parent_pid)
                    .and_then(|m| m.session_id.clone());
                rt.proc_meta.insert(
                    opts.pid,
                    ProcessVfsMeta {
                        session_id: opts.session_id.clone().or(psess.clone()),
                        cloud_access: opts.cloud_access,
                    },
                );
                (rt.vfs.clone(), Rc::clone(&rt.root_cloud), psess)
            };
            let _ = parent_sess;
            let _ = self
                .with_proc_scope(opts.pid, async { vfs.exit_process(opts.pid).await })
                .await;
            root_cloud.set_cloud_access(opts.pid, opts.cloud_access);
            if let Err(err) = vfs.fork_process(parent_pid, opts.pid, opts.clone_flags) {
                root_cloud.set_cloud_access(opts.pid, true);
                return Err(map_errno(err));
            }
            vfs.set_cred(opts.pid, cred).map_err(map_errno)?;
            vfs.set_umask(opts.pid, opts.umask).map_err(map_errno)?;
            if let Some(cwd) = &opts.cwd
                && !cwd.is_empty()
            {
                self.with_proc_scope(opts.pid, vfs.chdir(opts.pid, cwd))
                    .await
                    .map_err(map_errno)?;
            }
            let ns_id = vfs
                .process_namespace(opts.pid)
                .map_err(map_errno)?
                .borrow()
                .id()
                .0;
            return json_to_js(&json!({ "pid": opts.pid, "nsId": ns_id }));
        }

        let (vfs, root_cloud, base_ns, resolved_sess) = {
            let rt = self.vfs_rt.borrow();
            let vfs = rt.vfs.clone();
            let rc = Rc::clone(&rt.root_cloud);
            if let Some(grant) = &opts.service_grant {
                match grant.mount_namespace.as_str() {
                    "" | "system" => {
                        if !grant.bind_mounts.is_empty() {
                            return Err(vfs_js_err(
                                Errno::EINVAL,
                                "bind_mounts require isolated or session mount_namespace",
                            ));
                        }
                        (vfs.clone(), rc, vfs.system_namespace(), None)
                    }
                    "isolated" => {
                        let parent_ns = opts
                            .parent_pid
                            .and_then(|pp| vfs.process_namespace(pp).ok())
                            .unwrap_or_else(|| vfs.system_namespace());
                        let (cloned, _) = vfs.clone_namespace(&parent_ns);
                        (vfs, rc, cloned, None)
                    }
                    "session" => {
                        if opts.uid == 0 {
                            return Err(vfs_js_err(
                                Errno::EPERM,
                                "session mount_namespace is forbidden for root units",
                            ));
                        }
                        let sid = opts
                            .session_id
                            .as_ref()
                            .ok_or_else(|| vfs_js_err(Errno::EPERM, "missing user session"))?;
                        let sess = rt
                            .sessions
                            .get(sid)
                            .ok_or_else(|| vfs_js_err(Errno::EPERM, "missing user session"))?;
                        if sess.uid != opts.uid {
                            return Err(vfs_js_err(Errno::EPERM, "session uid mismatch"));
                        }
                        let (cloned, _) = vfs.clone_namespace(&sess.mnt_ns);
                        (vfs, rc, cloned, Some(sid.clone()))
                    }
                    _ => {
                        return Err(vfs_js_err(
                            Errno::EINVAL,
                            "unknown service mount_namespace grant",
                        ));
                    }
                }
            } else if let Some(sid) = &opts.session_id {
                let sess = rt
                    .sessions
                    .get(sid)
                    .ok_or_else(|| vfs_js_err(Errno::ENOENT, "no such login session"))?;
                (vfs, rc, Rc::clone(&sess.mnt_ns), Some(sid.clone()))
            } else {
                (vfs.clone(), rc, vfs.system_namespace(), None)
            }
        };

        let _ = self
            .with_proc_scope(opts.pid, async { vfs.exit_process(opts.pid).await })
            .await;
        root_cloud.set_cloud_access(opts.pid, opts.cloud_access);
        if let Err(err) = vfs.spawn_process(
            opts.pid,
            opts.ppid,
            cred.clone(),
            Some(Rc::clone(&base_ns)),
            None,
            None,
        ) {
            root_cloud.set_cloud_access(opts.pid, true);
            return Err(map_errno(err));
        }

        if let Some(grant) = &opts.service_grant
            && !grant.bind_mounts.is_empty()
        {
            // Temporarily elevate to root only for system-configured bind_mounts on non-user trees,
            // Note: user-mount `owner_uid` is STILL enforced by `Vfs` (`uid 0` -> `EACCES` on foreign user mounts!).
            let mut bind_cred = cred.clone();
            if opts.uid == 0 {
                bind_cred = Cred::root();
            }
            let _ = vfs.set_cred(opts.pid, bind_cred);
            for bm in &grant.bind_mounts {
                let mut mflags = mount_flags::MS_BIND;
                if bm.read_only {
                    mflags |= mount_flags::MS_RDONLY;
                }
                // Bind mount inside the private service namespace using `mount_on_namespace` so
                // non-root user-session units can apply their declared read-only/rw bind_mounts
                // within their own `owner_uid` ceiling.
                let src_res = self
                    .with_proc_scope(opts.pid, apply_service_bind(&vfs, &base_ns, &cred, bm))
                    .await;
                if let Err(err) = src_res {
                    let _ = self
                        .with_proc_scope(opts.pid, async { vfs.exit_process(opts.pid).await })
                        .await;
                    root_cloud.set_cloud_access(opts.pid, true);
                    return Err(map_errno(err));
                }
                let _ = mflags;
            }
            let _ = vfs.set_cred(opts.pid, cred);
        }

        if let Some(cwd) = &opts.cwd
            && !cwd.is_empty()
            && cwd != "/"
            && let Err(err) = self
                .with_proc_scope(opts.pid, vfs.chdir(opts.pid, cwd))
                .await
        {
            let _ = self
                .with_proc_scope(opts.pid, async { vfs.exit_process(opts.pid).await })
                .await;
            root_cloud.set_cloud_access(opts.pid, true);
            return Err(map_errno(err));
        }

        {
            let mut rt = self.vfs_rt.borrow_mut();
            rt.proc_meta.insert(
                opts.pid,
                ProcessVfsMeta {
                    session_id: resolved_sess,
                    cloud_access: opts.cloud_access,
                },
            );
        }
        let ns_id = base_ns.borrow().id().0;
        json_to_js(&json!({ "pid": opts.pid, "nsId": ns_id }))
    }

    pub fn proc_fork(
        &self,
        parent_pid: u32,
        child_pid: u32,
        clone_flags: u32,
    ) -> Result<JsValue, JsValue> {
        let (vfs, root_cloud, parent_meta) = {
            let rt = self.vfs_rt.borrow();
            let meta = rt.proc_meta.get(&parent_pid).map(|m| ProcessVfsMeta {
                session_id: m.session_id.clone(),
                cloud_access: m.cloud_access,
            });
            (rt.vfs.clone(), Rc::clone(&rt.root_cloud), meta)
        };
        vfs.fork_process(parent_pid, child_pid, clone_flags)
            .map_err(map_errno)?;
        if let Some(meta) = parent_meta {
            root_cloud.set_cloud_access(child_pid, meta.cloud_access);
            self.vfs_rt.borrow_mut().proc_meta.insert(child_pid, meta);
        } else {
            root_cloud.set_cloud_access(child_pid, true);
        }
        let ns_id = vfs
            .process_namespace(child_pid)
            .map_err(map_errno)?
            .borrow()
            .id()
            .0;
        json_to_js(&json!({ "pid": child_pid, "nsId": ns_id }))
    }

    pub async fn proc_exec_preserve(&self, pid: u32) -> Result<(), JsValue> {
        let vfs = self.vfs_rt.borrow().vfs.clone();
        self.with_proc_scope(pid, async move { vfs.exec_preserve(pid).await })
            .await
            .map_err(map_errno)
    }

    pub fn proc_set_creds(
        &self,
        pid: u32,
        uid: u32,
        gid: u32,
        groups: Vec<u32>,
        token: Option<String>,
        cloud_access: bool,
    ) -> Result<(), JsValue> {
        let (vfs, old_umask) = {
            let mut rt = self.vfs_rt.borrow_mut();
            rt.root_cloud.set_cloud_access(pid, cloud_access);
            if let Some(meta) = rt.proc_meta.get_mut(&pid) {
                meta.cloud_access = cloud_access;
            }
            let um = rt
                .vfs
                .process_fs_context(pid)
                .map(|c| c.borrow().umask)
                .unwrap_or(0o022);
            (rt.vfs.clone(), um)
        };
        let mut gset: BTreeSet<u32> = groups.into_iter().collect();
        gset.insert(gid);
        vfs.set_cred(
            pid,
            Cred {
                identity: Identity {
                    id: uid,
                    group: gid,
                    groups: gset,
                },
                umask: old_umask,
                token,
            },
        )
        .map_err(map_errno)
    }

    pub fn proc_set_umask(&self, pid: u32, umask: u16) -> Result<u16, JsValue> {
        let vfs = self.vfs_rt.borrow().vfs.clone();
        vfs.set_umask(pid, umask).map_err(map_errno)
    }

    pub async fn proc_exit(&self, pid: u32) -> Result<(), JsValue> {
        let (vfs, root_cloud, waits) = {
            let mut rt = self.vfs_rt.borrow_mut();
            rt.proc_meta.remove(&pid);
            let keys: Vec<(u32, u32)> = rt
                .lock_waits
                .keys()
                .filter(|(p, _)| *p == pid)
                .copied()
                .collect();
            let waits: Vec<_> = keys
                .into_iter()
                .filter_map(|k| rt.lock_waits.remove(&k))
                .collect();
            (rt.vfs.clone(), Rc::clone(&rt.root_cloud), waits)
        };
        for w in waits {
            w.cancel();
        }
        let res = self
            .with_proc_scope(pid, async move { vfs.exit_process(pid).await })
            .await;
        root_cloud.set_cloud_access(pid, true);
        res.map_err(map_errno)
    }

    // =========================================================================
    // 3. Working Directory, Chroot, Mount, Umount2, Statfs, Unshare, Setns
    // =========================================================================

    pub async fn sys_chdir(&self, pid: u32, path: String) -> Result<(), JsValue> {
        let vfs = self.vfs_rt.borrow().vfs.clone();
        self.with_proc_scope(pid, async move { vfs.chdir(pid, &path).await })
            .await
            .map_err(map_errno)
    }

    pub async fn sys_fchdir(&self, pid: u32, kfd: u32) -> Result<(), JsValue> {
        let vfs = self.vfs_rt.borrow().vfs.clone();
        self.with_proc_scope(pid, async move { vfs.fchdir(pid, kfd).await })
            .await
            .map_err(map_errno)
    }

    pub async fn sys_chroot(&self, pid: u32, path: String) -> Result<(), JsValue> {
        let vfs = self.vfs_rt.borrow().vfs.clone();
        self.with_proc_scope(pid, async move { vfs.chroot(pid, &path).await })
            .await
            .map_err(map_errno)
    }

    pub async fn sys_getcwd(&self, pid: u32) -> Result<String, JsValue> {
        let vfs = self.vfs_rt.borrow().vfs.clone();
        self.with_proc_scope(pid, async move { vfs.getcwd(pid).await })
            .await
            .map_err(map_errno)
    }

    pub async fn sys_mount(
        &self,
        pid: u32,
        source: Option<String>,
        target: String,
        fstype: Option<String>,
        flags: JsValue,
        data: Option<String>,
    ) -> Result<(), JsValue> {
        let raw_flags = parse_mount_flags_js(&flags)?;
        let src = source.unwrap_or_default();
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let ns_id = vfs.process_namespace(pid).map_err(map_errno)?.borrow().id();
        self.with_proc_scope(pid, async move {
            vfs.mount(
                pid,
                &src,
                &target,
                fstype.as_deref(),
                raw_flags,
                data.as_deref(),
            )
            .await
        })
        .await
        .map_err(map_errno)?;
        self.notify_ns_changed(ns_id);
        Ok(())
    }

    pub async fn sys_umount2(&self, pid: u32, target: String, flags: u32) -> Result<(), JsValue> {
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let ns_id = vfs.process_namespace(pid).map_err(map_errno)?.borrow().id();
        self.with_proc_scope(pid, async move { vfs.umount2(pid, &target, flags).await })
            .await
            .map_err(map_errno)?;
        self.notify_ns_changed(ns_id);
        Ok(())
    }

    pub async fn sys_statfs(
        &self,
        pid: u32,
        anchor_kfd: i32,
        path: String,
    ) -> Result<JsValue, JsValue> {
        let anchor = parse_anchor(anchor_kfd).map_err(map_errno)?;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let sfs = self
            .with_proc_scope(pid, async move { vfs.statfs(pid, anchor, &path).await })
            .await
            .map_err(map_errno)?;
        json_to_js(&json!(safe_statfs_for_js(sfs)))
    }

    pub async fn sys_fstatfs(&self, pid: u32, kfd: u32) -> Result<JsValue, JsValue> {
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let sfs = self
            .with_proc_scope(pid, async move { vfs.fstatfs(pid, kfd).await })
            .await
            .map_err(map_errno)?;
        json_to_js(&json!(safe_statfs_for_js(sfs)))
    }

    pub fn sys_unshare(&self, pid: u32, flags: u32) -> Result<(), JsValue> {
        let vfs = self.vfs_rt.borrow().vfs.clone();
        vfs.unshare(pid, flags).map_err(map_errno)?;
        if flags & unshare_flags::CLONE_NEWNS != 0
            && let Some(meta) = self.vfs_rt.borrow_mut().proc_meta.get_mut(&pid)
        {
            meta.session_id = None;
        }
        Ok(())
    }

    pub fn sys_setns(&self, pid: u32, kfd: u32, nstype: i32) -> Result<(), JsValue> {
        if nstype < 0 {
            return Err(map_errno(Errno::EINVAL));
        }
        let vfs = self.vfs_rt.borrow().vfs.clone();
        vfs.setns(pid, kfd, nstype as u32).map_err(map_errno)
    }

    // =========================================================================
    // 4. Per-Process *at Operations, `proc_sys` & Open `kfd_*` Operations
    // =========================================================================

    pub async fn proc_openat(
        &self,
        pid: u32,
        anchor_kfd: i32,
        path: String,
        oflags: u32,
        mode: u16,
        cloexec: Option<bool>,
    ) -> Result<JsValue, JsValue> {
        let anchor = parse_anchor(anchor_kfd).map_err(map_errno)?;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let cloexec = cloexec.unwrap_or(false) || (oflags & vfs::vfs::O_CLOEXEC != 0);
        let (kfd, mut stat, entry_meta, is_ns, pin_fstype) = self
            .with_proc_scope(pid, async move {
                let pass_flags = if (oflags & abi::O_PATH) != 0 && (oflags & abi::O_NOFOLLOW) != 0 {
                    oflags & !abi::O_DIRECTORY
                } else {
                    oflags
                };
                let (file_ref, entry) = vfs.open_file(pid, anchor, &path, pass_flags, mode).await?;
                if (oflags & abi::O_DIRECTORY) != 0 && !entry.metadata.is_dir() {
                    let _ = file_ref.close().await;
                    let _ = vfs.releases().flush().await;
                    return Err(Errno::ENOTDIR);
                }
                let is_ns = file_ref.mount_ns().is_some();
                let fstype = file_ref.mount_pin().map(|p| p.fstype());
                let st = vfs::stat::stat(&entry.handle.fs, entry.handle.node, &entry.metadata);
                let fds = vfs.process_fds(pid)?;
                let insert_res = fds.borrow_mut().insert(file_ref, cloexec);
                let fd = match insert_res {
                    Ok(fd) => fd,
                    Err(e) => {
                        let _ = vfs.releases().flush().await;
                        return Err(e);
                    }
                };
                Ok::<_, Errno>((fd, st, entry.metadata, is_ns, fstype))
            })
            .await
            .map_err(map_errno)?;
        let vfs_for_names = self.vfs_rt.borrow().vfs.clone();
        self.fill_stat_names(&vfs_for_names, pid, &mut stat).await;

        let device = if entry_meta.file_type == FileType::CharDevice {
            entry_meta.rdev.clone()
        } else {
            None
        };
        json_to_js(&json!({
            "fd": kfd,
            "kfd": kfd,
            "stat": stat,
            "isDir": entry_meta.is_dir(),
            "mountNs": is_ns,
            "device": device,
            "fstype": pin_fstype.map(|f| f.as_str()),
        }))
    }

    pub async fn proc_statat(
        &self,
        pid: u32,
        anchor_kfd: i32,
        path: String,
        follow: bool,
    ) -> Result<JsValue, JsValue> {
        let anchor = parse_anchor(anchor_kfd).map_err(map_errno)?;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let mut st = self
            .with_proc_scope(
                pid,
                async move { vfs.statat(pid, anchor, &path, follow).await },
            )
            .await
            .map_err(map_errno)?;
        let vfs_for_names = self.vfs_rt.borrow().vfs.clone();
        self.fill_stat_names(&vfs_for_names, pid, &mut st).await;
        json_to_js(&json!(st))
    }

    pub async fn proc_accessat(
        &self,
        pid: u32,
        anchor_kfd: i32,
        path: String,
        mode: u16,
        follow: bool,
    ) -> Result<(), JsValue> {
        let anchor = parse_anchor(anchor_kfd).map_err(map_errno)?;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        self.with_proc_scope(pid, async move {
            vfs.accessat(pid, anchor, &path, mode, follow).await
        })
        .await
        .map_err(map_errno)
    }

    pub async fn proc_mkdirat(
        &self,
        pid: u32,
        anchor_kfd: i32,
        path: String,
        mode: u16,
    ) -> Result<(), JsValue> {
        let anchor = parse_anchor(anchor_kfd).map_err(map_errno)?;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        self.with_proc_scope(
            pid,
            async move { vfs.mkdirat(pid, anchor, &path, mode).await },
        )
        .await
        .map(|_| ())
        .map_err(map_errno)
    }

    pub async fn proc_mknodat(
        &self,
        pid: u32,
        anchor_kfd: i32,
        path: String,
        mode: u16,
        rdev: Option<String>,
    ) -> Result<(), JsValue> {
        let anchor = parse_anchor(anchor_kfd).map_err(map_errno)?;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let rdev_str = rdev.unwrap_or_default();
        self.with_proc_scope(pid, async move {
            vfs.mknodat(pid, anchor, &path, mode, &rdev_str).await
        })
        .await
        .map(|_| ())
        .map_err(map_errno)
    }

    pub async fn proc_unlinkat(
        &self,
        pid: u32,
        anchor_kfd: i32,
        path: String,
        dir: bool,
    ) -> Result<(), JsValue> {
        let anchor = parse_anchor(anchor_kfd).map_err(map_errno)?;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        self.with_proc_scope(
            pid,
            async move { vfs.unlinkat(pid, anchor, &path, dir).await },
        )
        .await
        .map_err(map_errno)
    }

    pub async fn proc_renameat(
        &self,
        pid: u32,
        old_kfd: i32,
        old_path: String,
        new_kfd: i32,
        new_path: String,
        noreplace: bool,
    ) -> Result<(), JsValue> {
        let from_anchor = parse_anchor(old_kfd).map_err(map_errno)?;
        let to_anchor = parse_anchor(new_kfd).map_err(map_errno)?;
        let flags = if noreplace {
            RenameFlags::NOREPLACE
        } else {
            RenameFlags::empty()
        };
        let vfs = self.vfs_rt.borrow().vfs.clone();
        self.with_proc_scope(pid, async move {
            vfs.renameat(pid, from_anchor, &old_path, to_anchor, &new_path, flags)
                .await
        })
        .await
        .map_err(map_errno)
    }

    pub async fn proc_linkat(
        &self,
        pid: u32,
        old_kfd: i32,
        old_path: String,
        new_kfd: i32,
        new_path: String,
        follow: bool,
    ) -> Result<(), JsValue> {
        let from_anchor = parse_anchor(old_kfd).map_err(map_errno)?;
        let to_anchor = parse_anchor(new_kfd).map_err(map_errno)?;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        self.with_proc_scope(pid, async move {
            vfs.linkat(pid, from_anchor, &old_path, to_anchor, &new_path, follow)
                .await
        })
        .await
        .map(|_| ())
        .map_err(map_errno)
    }

    pub async fn proc_symlinkat(
        &self,
        pid: u32,
        target: String,
        dir_kfd: i32,
        link_path: String,
    ) -> Result<(), JsValue> {
        let anchor = parse_anchor(dir_kfd).map_err(map_errno)?;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        self.with_proc_scope(pid, async move {
            vfs.symlinkat(pid, &target, anchor, &link_path).await
        })
        .await
        .map(|_| ())
        .map_err(map_errno)
    }

    pub async fn proc_readlinkat(
        &self,
        pid: u32,
        anchor_kfd: i32,
        path: String,
    ) -> Result<String, JsValue> {
        let anchor = parse_anchor(anchor_kfd).map_err(map_errno)?;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        self.with_proc_scope(pid, async move { vfs.readlinkat(pid, anchor, &path).await })
            .await
            .map_err(map_errno)
    }

    pub async fn proc_utimensat(
        &self,
        pid: u32,
        anchor_kfd: i32,
        path: String,
        atime_json: String,
        mtime_json: String,
        follow: bool,
    ) -> Result<(), JsValue> {
        let anchor = parse_anchor(anchor_kfd).map_err(map_errno)?;
        let atime: Time = serde_json::from_str(&atime_json)
            .map_err(|e| vfs_js_err(Errno::EINVAL, e.to_string()))?;
        let mtime: Time = serde_json::from_str(&mtime_json)
            .map_err(|e| vfs_js_err(Errno::EINVAL, e.to_string()))?;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        self.with_proc_scope(pid, async move {
            vfs.setattrat(
                pid,
                anchor,
                &path,
                &SetAttr {
                    atime,
                    mtime,
                    ..SetAttr::default()
                },
                follow,
            )
            .await
        })
        .await
        .map(|_| ())
        .map_err(map_errno)
    }

    /// Execute an `abi::Batch` for process `pid` against `Vfs`, forwarding permitted non-VFS
    /// authority calls (`Getcreds`, `/dev/*` device ops, `InotifyAddWatch` with `CloudFs` handle,
    /// `Useradd`/`Passwd`/etc.) to `/api/sys` with `pid`'s process token.
    pub async fn proc_sys(&self, pid: u32, batch_json: String) -> Result<String, JsValue> {
        let batch: Batch = serde_json::from_str(&batch_json)
            .map_err(|e| vfs_js_err(Errno::EINVAL, e.to_string()))?;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        if let Some(um) = batch.umask {
            let _ = vfs.set_umask(pid, um);
        }
        let results = self
            .with_proc_scope(
                pid,
                self.execute_batch_on_pid(&vfs, pid, None, batch.calls, false, false),
            )
            .await;
        serde_json::to_string(&abi::Results { results })
            .map_err(|e| vfs_js_err(Errno::EIO, e.to_string()))
    }

    pub async fn kfd_read(&self, pid: u32, kfd: u32, len: u32) -> Result<Vec<u8>, JsValue> {
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let cap = (len as usize).min(abi::remote_fs::DATA_MAX as usize);
        let mut buf = vec![0u8; cap];
        let n = self
            .with_proc_scope(pid, async { vfs.read(pid, kfd, &mut buf).await })
            .await
            .map_err(map_errno)?;
        buf.truncate(n);
        Ok(buf)
    }

    pub async fn kfd_write(&self, pid: u32, kfd: u32, data: &[u8]) -> Result<u32, JsValue> {
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let n = self
            .with_proc_scope(pid, async { vfs.write(pid, kfd, data).await })
            .await
            .map_err(map_errno)?;
        Ok(n as u32)
    }

    pub async fn kfd_pread(
        &self,
        pid: u32,
        kfd: u32,
        len: u32,
        offset: u64,
    ) -> Result<Vec<u8>, JsValue> {
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let cap = (len as usize).min(abi::remote_fs::DATA_MAX as usize);
        let mut buf = vec![0u8; cap];
        let n = self
            .with_proc_scope(pid, async { vfs.pread(pid, kfd, &mut buf, offset).await })
            .await
            .map_err(map_errno)?;
        buf.truncate(n);
        Ok(buf)
    }

    pub async fn kfd_pwrite(
        &self,
        pid: u32,
        kfd: u32,
        data: &[u8],
        offset: u64,
    ) -> Result<u32, JsValue> {
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let n = self
            .with_proc_scope(pid, async { vfs.pwrite(pid, kfd, data, offset).await })
            .await
            .map_err(map_errno)?;
        Ok(n as u32)
    }

    pub async fn kfd_seek(
        &self,
        pid: u32,
        kfd: u32,
        offset: i64,
        whence: u8,
    ) -> Result<u64, JsValue> {
        let from = match whence {
            0 => SeekFrom::Start(u64::try_from(offset).map_err(|_| map_errno(Errno::EINVAL))?),
            1 => SeekFrom::Current(offset),
            2 => SeekFrom::End(offset),
            _ => return Err(map_errno(Errno::EINVAL)),
        };
        let vfs = self.vfs_rt.borrow().vfs.clone();
        self.with_proc_scope(pid, async move { vfs.lseek(pid, kfd, from).await })
            .await
            .map_err(map_errno)
    }

    pub async fn kfd_readdir(&self, pid: u32, kfd: u32) -> Result<JsValue, JsValue> {
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let entries = self
            .with_proc_scope(pid, async move { vfs.fd_readdir(pid, kfd).await })
            .await
            .map_err(map_errno)?;
        let out: Vec<Value> = entries
            .into_iter()
            .map(|e| {
                json!({
                    "name": e.name,
                    "ino": e.node.ino,
                    "type": match e.file_type {
                        FileType::Dir => "dir",
                        FileType::Symlink => "symlink",
                        FileType::CharDevice => "char",
                        FileType::File => "file",
                    },
                })
            })
            .collect();
        json_to_js(&Value::Array(out))
    }

    pub async fn kfd_fstat(&self, pid: u32, kfd: u32) -> Result<JsValue, JsValue> {
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let mut st = self
            .with_proc_scope(pid, async move { vfs.fstat(pid, kfd).await })
            .await
            .map_err(map_errno)?;
        let vfs_for_names = self.vfs_rt.borrow().vfs.clone();
        self.fill_stat_names(&vfs_for_names, pid, &mut st).await;
        json_to_js(&json!(st))
    }

    pub async fn kfd_ftruncate(&self, pid: u32, kfd: u32, size: u64) -> Result<(), JsValue> {
        let vfs = self.vfs_rt.borrow().vfs.clone();
        self.with_proc_scope(pid, async move { vfs.ftruncate(pid, kfd, size).await })
            .await
            .map_err(map_errno)
    }

    pub async fn kfd_fsync(&self, pid: u32, kfd: u32, data_only: bool) -> Result<(), JsValue> {
        let vfs = self.vfs_rt.borrow().vfs.clone();
        self.with_proc_scope(pid, async move {
            if data_only {
                vfs.fdatasync(pid, kfd).await
            } else {
                vfs.fsync(pid, kfd).await
            }
        })
        .await
        .map_err(map_errno)
    }

    pub fn kfd_set_append(&self, pid: u32, kfd: u32, append: bool) -> Result<(), JsValue> {
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let fds = vfs.process_fds(pid).map_err(map_errno)?;
        let file = fds.borrow().get(kfd).map_err(map_errno)?;
        file.set_append(append);
        Ok(())
    }

    pub fn kfd_is_append(&self, pid: u32, kfd: u32) -> Result<bool, JsValue> {
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let fds = vfs.process_fds(pid).map_err(map_errno)?;
        let file = fds.borrow().get(kfd).map_err(map_errno)?;
        Ok(file.is_append())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn kfd_lock(
        &self,
        pid: u32,
        kfd: u32,
        family: String,
        kind: String,
        start: u64,
        end: Option<u64>,
        wait: bool,
    ) -> Result<(), JsValue> {
        let fam = match family.as_str() {
            "flock" => LockFamily::Flock,
            "posix" => LockFamily::Posix,
            _ => return Err(map_errno(Errno::EINVAL)),
        };
        let lk = match kind.as_str() {
            "shared" => LockKind::Shared,
            "exclusive" => LockKind::Exclusive,
            _ => return Err(map_errno(Errno::EINVAL)),
        };
        let range = LockRange::new(start, end).ok_or_else(|| map_errno(Errno::EINVAL))?;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let cancel = if wait {
            let c = Rc::new(LockCancel::default());
            if let Some(prev) = self
                .vfs_rt
                .borrow_mut()
                .lock_waits
                .insert((pid, kfd), Rc::clone(&c))
            {
                prev.cancel();
            }
            Some(c)
        } else {
            None
        };
        let res = self
            .with_proc_scope(pid, async move {
                let fds = vfs.process_fds(pid)?;
                let file = fds.borrow().get(kfd)?;
                if let Some(c) = &cancel {
                    c.run(file.lock(fam, lk, range)).await
                } else {
                    file.try_lock(fam, lk, range).await
                }
            })
            .await;
        if wait {
            self.vfs_rt.borrow_mut().lock_waits.remove(&(pid, kfd));
        }
        res.map_err(map_errno)
    }

    pub fn kfd_cancel(&self, pid: u32, kfd: u32) {
        if let Some(cancel) = self.vfs_rt.borrow_mut().lock_waits.remove(&(pid, kfd)) {
            cancel.cancel();
        }
    }

    pub async fn kfd_unlock(
        &self,
        pid: u32,
        kfd: u32,
        family: String,
        start: u64,
        end: Option<u64>,
    ) -> Result<(), JsValue> {
        let fam = match family.as_str() {
            "flock" => LockFamily::Flock,
            "posix" => LockFamily::Posix,
            _ => return Err(map_errno(Errno::EINVAL)),
        };
        let range = LockRange::new(start, end).ok_or_else(|| map_errno(Errno::EINVAL))?;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        self.with_proc_scope(pid, async move {
            let fds = vfs.process_fds(pid)?;
            let file = fds.borrow().get(kfd)?;
            file.unlock(fam, range).await
        })
        .await
        .map_err(map_errno)
    }

    pub async fn kfd_test_lock(
        &self,
        pid: u32,
        kfd: u32,
        kind: String,
        start: u64,
        end: Option<u64>,
    ) -> Result<JsValue, JsValue> {
        let lk = match kind.as_str() {
            "shared" => LockKind::Shared,
            "exclusive" => LockKind::Exclusive,
            _ => return Err(map_errno(Errno::EINVAL)),
        };
        let range = LockRange::new(start, end).ok_or_else(|| map_errno(Errno::EINVAL))?;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let conflict = self
            .with_proc_scope(pid, async move {
                let fds = vfs.process_fds(pid)?;
                let file = fds.borrow().get(kfd)?;
                file.test_lock(lk, range).await
            })
            .await
            .map_err(map_errno)?;
        json_to_js(&json!(conflict))
    }

    pub fn kfd_dup(&self, pid: u32, kfd: u32) -> Result<u32, JsValue> {
        let vfs = self.vfs_rt.borrow().vfs.clone();
        vfs.dup(pid, kfd, 0, false).map_err(map_errno)
    }

    pub async fn kfd_dup2(&self, pid: u32, old_kfd: u32, new_kfd: u32) -> Result<u32, JsValue> {
        let vfs = self.vfs_rt.borrow().vfs.clone();
        vfs.dup2(pid, old_kfd, new_kfd).await.map_err(map_errno)
    }

    pub fn kfd_set_cloexec(&self, pid: u32, kfd: u32, cloexec: bool) -> Result<(), JsValue> {
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let fds = vfs.process_fds(pid).map_err(map_errno)?;
        fds.borrow_mut()
            .set_cloexec(kfd, cloexec)
            .map_err(map_errno)
    }

    pub fn kfd_is_cloexec(&self, pid: u32, kfd: u32) -> Result<bool, JsValue> {
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let fds = vfs.process_fds(pid).map_err(map_errno)?;
        fds.borrow().get_cloexec(kfd).map_err(map_errno)
    }

    pub async fn kfd_close(&self, pid: u32, kfd: u32) -> Result<(), JsValue> {
        let vfs = self.vfs_rt.borrow().vfs.clone();
        self.with_proc_scope(pid, async move { vfs.close(pid, kfd).await })
            .await
            .map_err(map_errno)
    }

    /// Synchronize `/dev/pts/<index>` PTY slave nodes with `web/wasi/devices.mjs`.
    pub fn pty_register(&self, index: u32, uid: u32, gid: u32, mode: u16) {
        self.vfs_rt
            .borrow()
            .dev_pts
            .register_pty(index, uid, gid, mode);
    }

    pub fn pty_close(&self, index: u32) -> bool {
        self.vfs_rt.borrow().dev_pts.close_pty(index)
    }

    // =========================================================================
    // 5. Chroot- & MountNamespace-Faithful Executable + `#!` Shebang Resolution
    // =========================================================================

    pub async fn proc_resolve_exec(
        &self,
        pid: u32,
        file: String,
        argv_json: String,
        path_env: Option<String>,
        search_path: bool,
    ) -> Result<JsValue, JsValue> {
        self.proc_resolve_exec_scoped(pid, file, argv_json, path_env, search_path, None)
            .await
    }

    async fn proc_resolve_exec_scoped(
        &self,
        pid: u32,
        file: String,
        argv_json: String,
        path_env: Option<String>,
        search_path: bool,
        page_sudo: Option<bool>,
    ) -> Result<JsValue, JsValue> {
        let argv: Vec<String> = if argv_json.is_empty() {
            Vec::new()
        } else {
            serde_json::from_str(&argv_json)
                .map_err(|e| vfs_js_err(Errno::EINVAL, e.to_string()))?
        };
        let (vfs, root_cloud, usr_fs_id, usr_blob_paths) = {
            let rt = self.vfs_rt.borrow();
            (
                rt.vfs.clone(),
                Rc::clone(&rt.root_cloud),
                rt.usr_fs_id.clone(),
                rt.usr_blob_paths.clone(),
            )
        };

        let chrooted = {
            let fs_ctx = vfs.process_fs_context(pid).map_err(map_errno)?;
            let sys_root = vfs.system_namespace().borrow().root_anchor();
            let proc_root = fs_ctx.borrow().root.clone();
            !proc_root.same_anchor(&sys_root)
        };

        enum ResolveOut {
            Immediate(Value),
            LocalWasm {
                resolved_path: String,
                argv: Vec<String>,
                nosuid: bool,
                fs_id: FsId,
                pin_owner: Option<u32>,
                provider: Rc<ProviderState>,
                bytes: Vec<u8>,
            },
        }

        let runtime = if chrooted {
            "resources-v1:chroot"
        } else {
            "resources-v1:no-usr-fallback"
        };

        let active_pid = if page_sudo.is_some() { None } else { Some(pid) };
        let sudo = page_sudo.unwrap_or(false);
        let out = self
            .with_root_cloud_scope(active_pid, sudo, async {
                let resolved = vfs
                    .resolve_exec(pid, &file, argv, path_env.as_deref(), search_path)
                    .await?;

                // Case 1: System `/usr` `ImageFs` (either at `/usr` or bind-mounted inside a `chroot`).
                if resolved.entry.handle.fs == usr_fs_id
                    && let Some(asset_url) =
                        usr_blob_paths.get(&resolved.entry.handle.node.ino).cloned()
                {
                    let canonical_usr_path = asset_url
                        .strip_suffix(".wasm")
                        .unwrap_or(&asset_url)
                        .to_string();
                    let _ = resolved.file.close().await;
                    let _ = vfs.releases().flush().await;
                    if !chrooted {
                        return Ok(ResolveOut::Immediate(json!({
                            "path": resolved.resolved_path,
                            "argv": resolved.argv,
                            "resolvedPath": resolved.resolved_path,
                            "execPath": canonical_usr_path,
                            "asset": asset_url,
                            "runtime": "resources-v1",
                            "noUsrFallback": false,
                            "chroot": false,
                            "chrooted": false,
                            "nosuid": resolved.nosuid,
                            "local": Value::Null,
                        })));
                    }
                    // Inside `chroot` with `/usr` bind-mounted: `/internal/exec` requires `local` when
                    // `chroot == true` so outside-root server `/usr` fallback is completely disabled.
                    let synth_digest = image::digest(asset_url.as_bytes());
                    return Ok(ResolveOut::Immediate(json!({
                        "path": resolved.resolved_path,
                        "argv": resolved.argv,
                        "resolvedPath": resolved.resolved_path,
                        "execPath": canonical_usr_path,
                        "asset": asset_url,
                        "runtime": runtime,
                        "noUsrFallback": true,
                        "chroot": true,
                        "chrooted": true,
                        "nosuid": resolved.nosuid,
                        "local": LocalExecutable {
                            digest: synth_digest,
                            size: 64,
                            cloud: true,
                        },
                    })));
                }

                // Case 2: Cloud `/` executable when NOT chrooted and `!nosuid`.
                if resolved.pin.fstype() == vfs::FsType::Cloud
                    && !chrooted
                    && !resolved.nosuid
                    && let Some(cloud_path) =
                        root_cloud.canonical_cloud_path(resolved.entry.handle.node)
                {
                    let _ = resolved.file.close().await;
                    let _ = vfs.releases().flush().await;
                    return Ok(ResolveOut::Immediate(json!({
                        "path": resolved.resolved_path,
                        "argv": resolved.argv,
                        "resolvedPath": resolved.resolved_path,
                        "execPath": cloud_path,
                        "asset": Value::Null,
                        "runtime": runtime,
                        "noUsrFallback": true,
                        "chroot": false,
                        "chrooted": false,
                        "nosuid": false,
                        "local": Value::Null,
                    })));
                }

                // Case 3: Local mount (`opfs`, `hostfs`, `helperfs`, `sharefs`), `tmpfs`, private
                // extension `image`, or chrooted executable -> snapshot & SHA-256 verify bytes!
                let size = resolved.entry.metadata.size;
                if size > abi::EXEC_MAX {
                    let _ = resolved.file.close().await;
                    let _ = vfs.releases().flush().await;
                    return Err(Errno::E2BIG);
                }
                let mut bytes = vec![0u8; size as usize];
                let mut off = 0usize;
                while off < bytes.len() {
                    let chunk = (bytes.len() - off).min(256 * 1024);
                    match resolved
                        .file
                        .read_at(&mut bytes[off..off + chunk], off as u64)
                        .await
                    {
                        Ok(0) => break,
                        Ok(n) => off += n,
                        Err(err) => {
                            let _ = resolved.file.close().await;
                            let _ = vfs.releases().flush().await;
                            return Err(err);
                        }
                    }
                }
                bytes.truncate(off);
                let provider_state = Rc::clone(resolved.pin.provider());
                let pin_owner = resolved.pin.owner_uid();
                let fs_id = resolved.entry.handle.fs.clone();
                let _ = resolved.file.close().await;
                let _ = vfs.releases().flush().await;
                Ok(ResolveOut::LocalWasm {
                    resolved_path: resolved.resolved_path,
                    argv: resolved.argv,
                    nosuid: resolved.nosuid,
                    fs_id,
                    pin_owner,
                    provider: provider_state,
                    bytes,
                })
            })
            .await
            .map_err(map_errno)?;

        let (resolved_path, resolved_argv, nosuid, fs_id, pin_owner, provider_state, bytes) =
            match out {
                ResolveOut::Immediate(val) => return json_to_js(&val),
                ResolveOut::LocalWasm {
                    resolved_path,
                    argv,
                    nosuid,
                    fs_id,
                    pin_owner,
                    provider,
                    bytes,
                } => (
                    resolved_path,
                    argv,
                    nosuid,
                    fs_id,
                    pin_owner,
                    provider,
                    bytes,
                ),
            };

        if bytes.len() < 8 || !bytes.starts_with(b"\0asm") {
            return Err(map_errno(Errno::ENOEXEC));
        }
        let off = bytes.len();
        let digest = image::digest(&bytes);
        let cloud_allowed = {
            let mut rt = self.vfs_rt.borrow_mut();
            let fs_cloud = rt
                .cloud_exec_by_fs
                .get(&fs_id)
                .copied()
                .unwrap_or_else(|| pin_owner.is_none());
            let proc_cloud = rt
                .proc_meta
                .get(&pid)
                .map(|m| m.cloud_access)
                .unwrap_or(true);
            rt.cached_local_execs
                .insert(digest.clone(), (bytes, provider_state));
            fs_cloud && proc_cloud
        };
        let exec_path = if resolved_path.starts_with('/') {
            resolved_path.clone()
        } else {
            format!("/{resolved_path}")
        };
        let local = LocalExecutable {
            digest: digest.clone(),
            size: off as u64,
            cloud: cloud_allowed,
        };
        json_to_js(&json!({
            "path": resolved_path,
            "argv": resolved_argv,
            "resolvedPath": resolved_path,
            "execPath": exec_path,
            "asset": Value::Null,
            "runtime": runtime,
            "noUsrFallback": true,
            "chroot": chrooted,
            "chrooted": chrooted,
            "nosuid": nosuid,
            "local": local,
            "digest": digest,
        }))
    }

    /// Retrieve cached verified bytes for a local executable resolved by `proc_resolve_exec`,
    /// re-checking its mount `ProviderState` (`Revoked` -> `EACCES`, `Lost` -> `ENOTCONN`).
    pub fn take_local_exec_bytes(&self, digest: String) -> Result<Option<Vec<u8>>, JsValue> {
        let rt = self.vfs_rt.borrow();
        let Some((bytes, provider)) = rt.cached_local_execs.get(&digest) else {
            return Ok(None);
        };
        match provider.health() {
            ProviderHealth::Connected => {}
            ProviderHealth::Revoked => return Err(map_errno(Errno::EACCES)),
            ProviderHealth::Lost => return Err(map_errno(Errno::ENOTCONN)),
        }
        Ok(Some(bytes.clone()))
    }

    /// Resolve a `session_begin`-free page execution request (e.g. shell command resolution
    /// against `session_id`'s `MountNamespace`).
    #[allow(clippy::too_many_arguments)]
    pub async fn session_resolve_exec(
        &self,
        session_id: String,
        file: String,
        argv_json: String,
        cwd: String,
        path_env: Option<String>,
        search_path: bool,
        sudo: bool,
    ) -> Result<JsValue, JsValue> {
        let (vfs, mnt_ns, mut cred, scoped_pid) = {
            let mut rt = self.vfs_rt.borrow_mut();
            let spid = rt.alloc_scoped_pid();
            let vfs = rt.vfs.clone();
            if session_id.is_empty() {
                (
                    vfs,
                    rt.vfs.system_namespace(),
                    Cred::new(if sudo {
                        Identity::root()
                    } else {
                        Identity::guest()
                    }),
                    spid,
                )
            } else {
                let sess = rt
                    .sessions
                    .get(&session_id)
                    .ok_or_else(|| vfs_js_err(Errno::ENOENT, "no active login session"))?;
                let mut c = sess.cred(0o022);
                if sudo {
                    c.identity = Identity::root();
                }
                (vfs, Rc::clone(&sess.mnt_ns), c, spid)
            }
        };
        cred.umask = 0o022;
        vfs.spawn_process(scoped_pid, INIT, cred, Some(mnt_ns), None, None)
            .map_err(map_errno)?;
        self.with_page_scope(sudo, async {
            if !cwd.is_empty()
                && cwd != "/"
                && let Err(err) = vfs.chdir(scoped_pid, &cwd).await
            {
                let _ = vfs.exit_process(scoped_pid).await;
                return Err(map_errno(err));
            }
            let res = self
                .proc_resolve_exec_scoped(
                    scoped_pid,
                    file,
                    argv_json,
                    path_env,
                    search_path,
                    Some(sudo),
                )
                .await;
            let _ = vfs.exit_process(scoped_pid).await;
            res
        })
        .await
    }
}

async fn apply_service_bind(
    vfs: &Vfs,
    ns: &Rc<RefCell<MountNamespace>>,
    cred: &Cred,
    bm: &ServiceBindSpec,
) -> vfs::Result<()> {
    let ns_root = ns.borrow().root_anchor();
    let temp_ctx = vfs::FsContext {
        root: ns_root.clone(),
        cwd: ns_root,
        umask: cred.umask,
    };
    let empty_fds = vfs::FdTable::new();
    let bridge = vfs.proc_bridge().upgrade();
    let walked = vfs::walk::walk(
        cred,
        ns,
        &temp_ctx,
        &empty_fds,
        bridge.as_deref(),
        &StartAnchor::Root,
        &bm.source,
        vfs::WalkFlags::FOLLOW_LAST,
    )
    .await?;
    let vfs::WalkResult::Found {
        pin: src_pin,
        entry: src_entry,
        ..
    } = walked
    else {
        return Err(Errno::ENOENT);
    };
    let mut flags = src_pin.effective_flags();
    let mut locked = src_pin.locked_flags();
    if bm.read_only {
        flags.rdonly = true;
        locked |= mount_flags::MS_RDONLY;
    }
    let source_str = ns
        .borrow()
        .entry(src_pin.id())
        .map(|e| e.source.clone())
        .unwrap_or_else(|| "bind".to_string());
    vfs.mount_on_namespace(
        ns,
        cred,
        Rc::clone(src_pin.backing()),
        Some((src_entry.handle, bm.source.clone())),
        &source_str,
        &bm.target,
        flags,
        locked,
        src_pin.owner_uid(),
    )
    .await
    .map(|_| ())
}

/// Clamp large 64-bit `StatFs` counters (e.g. `MemFs` returning `u64::MAX` for `files_free`)
/// to IEEE-754 `Number.MAX_SAFE_INTEGER` before passing through the JS JSON bridge, so
/// `JSON.parse` -> `JSON.stringify` never emits floats `>= 2^64` that fail `serde_json::from_value::<StatFs>`.
fn safe_statfs_for_js(mut sfs: abi::StatFs) -> abi::StatFs {
    const MAX_SAFE: u64 = (1u64 << 53) - 1;
    sfs.blocks = sfs.blocks.min(MAX_SAFE);
    sfs.bfree = sfs.bfree.min(MAX_SAFE);
    sfs.bavail = sfs.bavail.min(MAX_SAFE);
    sfs.files = sfs.files.min(MAX_SAFE);
    sfs.ffree = sfs.ffree.min(MAX_SAFE);
    sfs
}

fn unescape_mountinfo(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && (b'0'..=b'7').contains(&bytes[i + 1])
            && (b'0'..=b'7').contains(&bytes[i + 2])
            && (b'0'..=b'7').contains(&bytes[i + 3])
        {
            let val =
                ((bytes[i + 1] - b'0') << 6) | ((bytes[i + 2] - b'0') << 3) | (bytes[i + 3] - b'0');
            out.push(val as char);
            i += 4;
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

async fn resolve_default_creation_umask(
    vfs: &Vfs,
    pid: u32,
    anchor: StartAnchor,
    path: &str,
) -> Option<u16> {
    let trimmed = path.trim_end_matches('/');
    let parent_dir = match trimmed.rsplit_once('/') {
        Some(("", _)) => "/",
        Some((p, _)) if !p.is_empty() => p,
        _ => ".",
    };
    if let Ok(sfs) = vfs.statfs(pid, anchor, parent_dir).await
        && matches!(
            sfs.fstype.as_str(),
            "opfs" | "hostfs" | "helperfs" | "sharefs"
        )
    {
        return vfs.set_umask(pid, 0o077).ok();
    }
    None
}

impl Kernel {
    /// Execute a list of `abi::Call`s on `pid` (either a live process in `proc_sys` or a scoped
    /// page caller in `vfs_sys`).
    async fn execute_batch_on_pid(
        &self,
        vfs: &Vfs,
        pid: u32,
        page_session_id: Option<&str>,
        calls: Vec<Call>,
        page_sudo: bool,
        default_private_user_umask: bool,
    ) -> Vec<Return> {
        let mut results = Vec::with_capacity(calls.len());
        let mut fd_refs: Vec<Option<u32>> = Vec::with_capacity(calls.len());

        for call in calls {
            let prev_umask = if default_private_user_umask {
                match &call {
                    Call::Mkdir { path, .. } | Call::Mknod { path, .. } => {
                        resolve_default_creation_umask(vfs, pid, StartAnchor::AtFdCwd, path).await
                    }
                    Call::Open { path, flags, .. } if (flags & abi::O_CREAT) != 0 => {
                        resolve_default_creation_umask(vfs, pid, StartAnchor::AtFdCwd, path).await
                    }
                    Call::MkdirAt { dirfd, path, .. } => {
                        if let Ok(anchor) =
                            parse_fd_ref(*dirfd, &fd_refs).and_then(|d| parse_anchor(d as i32))
                        {
                            resolve_default_creation_umask(vfs, pid, anchor, path).await
                        } else {
                            None
                        }
                    }
                    Call::OpenAt {
                        dirfd, path, flags, ..
                    } if (flags & abi::O_CREAT) != 0 => {
                        if let Ok(anchor) =
                            parse_fd_ref(*dirfd, &fd_refs).and_then(|d| parse_anchor(d as i32))
                        {
                            resolve_default_creation_umask(vfs, pid, anchor, path).await
                        } else {
                            None
                        }
                    }
                    _ => None,
                }
            } else {
                None
            };
            let mut opened_fd: Option<u32> = None;
            let outcome: std::result::Result<Value, abi::Error> = match call {
                Call::Stat { path } => {
                    match vfs.statat(pid, StartAnchor::AtFdCwd, &path, true).await {
                        Ok(mut s) => {
                            self.fill_stat_names(vfs, pid, &mut s).await;
                            Ok(json!(s))
                        }
                        Err(e) => Err(e.into()),
                    }
                }
                Call::Lstat { path } => {
                    match vfs.statat(pid, StartAnchor::AtFdCwd, &path, false).await {
                        Ok(mut s) => {
                            self.fill_stat_names(vfs, pid, &mut s).await;
                            Ok(json!(s))
                        }
                        Err(e) => Err(e.into()),
                    }
                }
                Call::FstatAt {
                    dirfd,
                    path,
                    nofollow,
                } => match parse_fd_ref(dirfd, &fd_refs).and_then(|d| parse_anchor(d as i32)) {
                    Ok(anchor) => match vfs.statat(pid, anchor, &path, !nofollow).await {
                        Ok(mut s) => {
                            self.fill_stat_names(vfs, pid, &mut s).await;
                            Ok(json!(s))
                        }
                        Err(e) => Err(e.into()),
                    },
                    Err(e) => Err(e.into()),
                },
                Call::Getdents {
                    path,
                    cookie,
                    count,
                } => self.eval_getdents(vfs, pid, &path, cookie, count).await,
                Call::Access { path, mode } => vfs
                    .accessat(pid, StartAnchor::AtFdCwd, &path, mode, true)
                    .await
                    .map(|()| Value::Null)
                    .map_err(Into::into),
                Call::Readlink { path } => vfs
                    .readlinkat(pid, StartAnchor::AtFdCwd, &path)
                    .await
                    .map(|s| json!(s))
                    .map_err(Into::into),
                Call::ReadlinkAt { dirfd, path } => {
                    match parse_fd_ref(dirfd, &fd_refs).and_then(|d| parse_anchor(d as i32)) {
                        Ok(anchor) => vfs
                            .readlinkat(pid, anchor, &path)
                            .await
                            .map(|s| json!(s))
                            .map_err(Into::into),
                        Err(e) => Err(e.into()),
                    }
                }
                Call::Mkdir { path, mode } => vfs
                    .mkdirat(pid, StartAnchor::AtFdCwd, &path, mode)
                    .await
                    .map(|_| Value::Null)
                    .map_err(Into::into),
                Call::MkdirAt { dirfd, path, mode } => {
                    match parse_fd_ref(dirfd, &fd_refs).and_then(|d| parse_anchor(d as i32)) {
                        Ok(anchor) => vfs
                            .mkdirat(pid, anchor, &path, mode)
                            .await
                            .map(|_| Value::Null)
                            .map_err(Into::into),
                        Err(e) => Err(e.into()),
                    }
                }
                Call::Mknod { path, mode, rdev } => vfs
                    .mknodat(
                        pid,
                        StartAnchor::AtFdCwd,
                        &path,
                        mode,
                        rdev.as_deref().unwrap_or(""),
                    )
                    .await
                    .map(|_| Value::Null)
                    .map_err(Into::into),
                Call::Rmdir { path } => vfs
                    .unlinkat(pid, StartAnchor::AtFdCwd, &path, true)
                    .await
                    .map(|()| Value::Null)
                    .map_err(Into::into),
                Call::Unlink { path } => vfs
                    .unlinkat(pid, StartAnchor::AtFdCwd, &path, false)
                    .await
                    .map(|()| Value::Null)
                    .map_err(Into::into),
                Call::UnlinkAt { dirfd, path, rmdir } => {
                    match parse_fd_ref(dirfd, &fd_refs).and_then(|d| parse_anchor(d as i32)) {
                        Ok(anchor) => vfs
                            .unlinkat(pid, anchor, &path, rmdir)
                            .await
                            .map(|()| Value::Null)
                            .map_err(Into::into),
                        Err(e) => Err(e.into()),
                    }
                }
                Call::Rename {
                    from,
                    to,
                    noreplace,
                } => {
                    let rf = if noreplace {
                        RenameFlags::NOREPLACE
                    } else {
                        RenameFlags::empty()
                    };
                    vfs.renameat(
                        pid,
                        StartAnchor::AtFdCwd,
                        &from,
                        StartAnchor::AtFdCwd,
                        &to,
                        rf,
                    )
                    .await
                    .map(|()| Value::Null)
                    .map_err(Into::into)
                }
                Call::RenameAt {
                    from_dirfd,
                    from,
                    to_dirfd,
                    to,
                    noreplace,
                } => match (
                    parse_fd_ref(from_dirfd, &fd_refs).and_then(|d| parse_anchor(d as i32)),
                    parse_fd_ref(to_dirfd, &fd_refs).and_then(|d| parse_anchor(d as i32)),
                ) {
                    (Ok(fa), Ok(ta)) => {
                        let rf = if noreplace {
                            RenameFlags::NOREPLACE
                        } else {
                            RenameFlags::empty()
                        };
                        vfs.renameat(pid, fa, &from, ta, &to, rf)
                            .await
                            .map(|()| Value::Null)
                            .map_err(Into::into)
                    }
                    (Err(e), _) | (_, Err(e)) => Err(e.into()),
                },
                Call::Link { from, to, follow } => vfs
                    .linkat(
                        pid,
                        StartAnchor::AtFdCwd,
                        &from,
                        StartAnchor::AtFdCwd,
                        &to,
                        follow,
                    )
                    .await
                    .map(|_| Value::Null)
                    .map_err(Into::into),
                Call::LinkAt {
                    from_dirfd,
                    from,
                    to_dirfd,
                    to,
                    follow,
                } => match (
                    parse_fd_ref(from_dirfd, &fd_refs).and_then(|d| parse_anchor(d as i32)),
                    parse_fd_ref(to_dirfd, &fd_refs).and_then(|d| parse_anchor(d as i32)),
                ) {
                    (Ok(fa), Ok(ta)) => vfs
                        .linkat(pid, fa, &from, ta, &to, follow)
                        .await
                        .map(|_| Value::Null)
                        .map_err(Into::into),
                    (Err(e), _) | (_, Err(e)) => Err(e.into()),
                },
                Call::Symlink { target, path } => vfs
                    .symlinkat(pid, &target, StartAnchor::AtFdCwd, &path)
                    .await
                    .map(|_| Value::Null)
                    .map_err(Into::into),
                Call::SymlinkAt {
                    target,
                    dirfd,
                    path,
                } => match parse_fd_ref(dirfd, &fd_refs).and_then(|d| parse_anchor(d as i32)) {
                    Ok(anchor) => vfs
                        .symlinkat(pid, &target, anchor, &path)
                        .await
                        .map(|_| Value::Null)
                        .map_err(Into::into),
                    Err(e) => Err(e.into()),
                },
                Call::Chmod { path, mode } => vfs
                    .setattrat(
                        pid,
                        StartAnchor::AtFdCwd,
                        &path,
                        &SetAttr {
                            mode: Some(mode),
                            ..SetAttr::default()
                        },
                        true,
                    )
                    .await
                    .map(|_| Value::Null)
                    .map_err(Into::into),
                Call::Chown {
                    path,
                    uid,
                    gid,
                    nofollow,
                } => vfs
                    .setattrat(
                        pid,
                        StartAnchor::AtFdCwd,
                        &path,
                        &SetAttr {
                            uid,
                            gid,
                            ..SetAttr::default()
                        },
                        !nofollow,
                    )
                    .await
                    .map(|_| Value::Null)
                    .map_err(Into::into),
                Call::Utimens {
                    path,
                    atime,
                    mtime,
                    nofollow,
                } => vfs
                    .setattrat(
                        pid,
                        StartAnchor::AtFdCwd,
                        &path,
                        &SetAttr {
                            atime,
                            mtime,
                            ..SetAttr::default()
                        },
                        !nofollow,
                    )
                    .await
                    .map(|_| Value::Null)
                    .map_err(Into::into),
                Call::UtimensAt {
                    dirfd,
                    path,
                    atime,
                    mtime,
                    nofollow,
                } => match parse_fd_ref(dirfd, &fd_refs).and_then(|d| parse_anchor(d as i32)) {
                    Ok(anchor) => vfs
                        .setattrat(
                            pid,
                            anchor,
                            &path,
                            &SetAttr {
                                atime,
                                mtime,
                                ..SetAttr::default()
                            },
                            !nofollow,
                        )
                        .await
                        .map(|_| Value::Null)
                        .map_err(Into::into),
                    Err(e) => Err(e.into()),
                },
                Call::Statfs { path } => vfs
                    .statfs(pid, StartAnchor::AtFdCwd, &path)
                    .await
                    .map(|s| json!(safe_statfs_for_js(s)))
                    .map_err(Into::into),
                Call::Fstatfs { fd } => match parse_fd_ref(fd, &fd_refs) {
                    Ok(kfd) => vfs
                        .fstatfs(pid, kfd)
                        .await
                        .map(|s| json!(safe_statfs_for_js(s)))
                        .map_err(Into::into),
                    Err(e) => Err(e.into()),
                },
                Call::Mount {
                    source,
                    target,
                    fstype,
                    flags,
                    data,
                } => {
                    let ns_id = vfs.process_namespace(pid).map(|n| n.borrow().id()).ok();
                    let res = vfs
                        .mount(
                            pid,
                            &source,
                            &target,
                            fstype.as_deref(),
                            flags,
                            data.as_deref(),
                        )
                        .await
                        .map(|()| Value::Null)
                        .map_err(Into::into);
                    if res.is_ok()
                        && let Some(nid) = ns_id
                    {
                        self.notify_ns_changed(nid);
                    }
                    res
                }
                Call::Umount2 { target, flags } => {
                    let ns_id = vfs.process_namespace(pid).map(|n| n.borrow().id()).ok();
                    let res = vfs
                        .umount2(pid, &target, flags)
                        .await
                        .map(|()| Value::Null)
                        .map_err(Into::into);
                    if res.is_ok()
                        && let Some(nid) = ns_id
                    {
                        self.notify_ns_changed(nid);
                    }
                    res
                }
                Call::Chdir { path } => vfs
                    .chdir(pid, &path)
                    .await
                    .map(|()| Value::Null)
                    .map_err(Into::into),
                Call::Fchdir { fd } => match parse_fd_ref(fd, &fd_refs) {
                    Ok(kfd) => vfs
                        .fchdir(pid, kfd)
                        .await
                        .map(|()| Value::Null)
                        .map_err(Into::into),
                    Err(e) => Err(e.into()),
                },
                Call::Getcwd => vfs.getcwd(pid).await.map(|s| json!(s)).map_err(Into::into),
                Call::Chroot { path } => vfs
                    .chroot(pid, &path)
                    .await
                    .map(|()| Value::Null)
                    .map_err(Into::into),
                Call::Unshare { flags } => vfs
                    .unshare(pid, flags)
                    .map(|()| Value::Null)
                    .map_err(Into::into),
                Call::Setns { fd, nstype } => match parse_fd_ref(fd, &fd_refs) {
                    Ok(kfd) => vfs
                        .setns(pid, kfd, nstype)
                        .map(|()| Value::Null)
                        .map_err(Into::into),
                    Err(e) => Err(e.into()),
                },
                Call::OpenAt {
                    dirfd,
                    path,
                    flags,
                    mode,
                } => match parse_fd_ref(dirfd, &fd_refs).and_then(|d| parse_anchor(d as i32)) {
                    Ok(anchor) => {
                        let follow_for_exist = (flags & abi::O_NOFOLLOW) == 0;
                        let created = if (flags & abi::O_CREAT) != 0 {
                            if (flags & abi::O_EXCL) != 0 {
                                true
                            } else {
                                vfs.statat(pid, anchor.clone(), &path, follow_for_exist)
                                    .await
                                    .is_err()
                            }
                        } else {
                            false
                        };
                        match vfs.open_file(pid, anchor, &path, flags, mode).await {
                            Ok((file_ref, entry)) => {
                                let mut st = vfs::stat::stat(
                                    &entry.handle.fs,
                                    entry.handle.node,
                                    &entry.metadata,
                                );
                                self.fill_stat_names(vfs, pid, &mut st).await;
                                let cloexec = flags & vfs::vfs::O_CLOEXEC != 0;
                                match vfs
                                    .process_fds(pid)
                                    .and_then(|fds| fds.borrow_mut().insert(file_ref, cloexec))
                                {
                                    Ok(fd) => {
                                        opened_fd = Some(fd);
                                        Ok(json!({
                                            "fd": fd,
                                            "size": st.size,
                                            "created": created,
                                            "stat": st,
                                        }))
                                    }
                                    Err(e) => {
                                        let _ = vfs.releases().flush().await;
                                        Err(e.into())
                                    }
                                }
                            }
                            Err(e) => Err(e.into()),
                        }
                    }
                    Err(e) => Err(e.into()),
                },
                Call::Getxattr {
                    path,
                    name,
                    nofollow,
                } => vfs
                    .getxattrat(pid, StartAnchor::AtFdCwd, &path, &name, !nofollow)
                    .await
                    .map(|b| json!(Bytes(b)))
                    .map_err(Into::into),
                Call::Setxattr {
                    path,
                    name,
                    value,
                    flags,
                    nofollow,
                } => match XattrFlags::from_bits(flags) {
                    Some(xf) => vfs
                        .setxattrat(
                            pid,
                            StartAnchor::AtFdCwd,
                            &path,
                            &name,
                            &value.0,
                            xf,
                            !nofollow,
                        )
                        .await
                        .map(|()| Value::Null)
                        .map_err(Into::into),
                    None => Err(Errno::EINVAL.into()),
                },
                Call::Listxattr { path, nofollow } => vfs
                    .listxattrat(pid, StartAnchor::AtFdCwd, &path, !nofollow)
                    .await
                    .map(|names| json!(names))
                    .map_err(Into::into),
                Call::Removexattr {
                    path,
                    name,
                    nofollow,
                } => vfs
                    .removexattrat(pid, StartAnchor::AtFdCwd, &path, &name, !nofollow)
                    .await
                    .map(|()| Value::Null)
                    .map_err(Into::into),
                Call::Open {
                    path,
                    flags,
                    mode,
                    size,
                    sha256,
                    version,
                } => {
                    match self
                        .eval_open_call(
                            vfs,
                            pid,
                            page_session_id,
                            page_sudo,
                            &path,
                            flags,
                            mode,
                            size,
                            sha256,
                            version,
                        )
                        .await
                    {
                        Ok((fd, val)) => {
                            opened_fd = Some(fd);
                            Ok(val)
                        }
                        Err(e) => Err(e),
                    }
                }
                Call::Close { fd } => match parse_fd_ref(fd, &fd_refs) {
                    Ok(raw_fd) => {
                        self.eval_close_call(vfs, pid, page_session_id, page_sudo, raw_fd, false)
                            .await
                    }
                    Err(e) => Err(e.into()),
                },
                Call::Discard { fd } => match parse_fd_ref(fd, &fd_refs) {
                    Ok(raw_fd) => {
                        self.eval_close_call(vfs, pid, page_session_id, page_sudo, raw_fd, true)
                            .await
                    }
                    Err(e) => Err(e.into()),
                },
                Call::Fchmod { fd, mode } => match parse_fd_ref(fd, &fd_refs) {
                    Ok(raw_fd) => {
                        self.eval_fchmod(vfs, pid, page_session_id, page_sudo, raw_fd, mode)
                            .await
                    }
                    Err(e) => Err(e.into()),
                },
                Call::Pread {
                    fd,
                    path,
                    offset,
                    count,
                } => {
                    self.eval_pread(
                        vfs,
                        pid,
                        page_session_id,
                        page_sudo,
                        fd,
                        path,
                        offset,
                        count,
                        &fd_refs,
                    )
                    .await
                }
                Call::Pwrite { fd, index, data } => match parse_fd_ref(fd, &fd_refs) {
                    Ok(raw_fd) => {
                        self.eval_pwrite(
                            vfs,
                            pid,
                            page_session_id,
                            page_sudo,
                            raw_fd,
                            index,
                            data.0,
                        )
                        .await
                    }
                    Err(e) => Err(e.into()),
                },
                Call::InotifyAddWatch { path, mask, .. } => {
                    self.eval_inotify_add(vfs, pid, page_sudo, &path, mask)
                        .await
                }
                Call::InotifyRmWatch { wd } => {
                    self.forward_server_call(pid, page_sudo, Call::InotifyRmWatch { wd })
                        .await
                }
                Call::Ioctl { fd, request, arg } => match parse_fd_ref(fd, &fd_refs) {
                    Ok(raw_fd) => {
                        self.eval_ioctl(vfs, pid, page_sudo, raw_fd, request, arg, &fd_refs)
                            .await
                    }
                    Err(e) => Err(e.into()),
                },
                other => {
                    let invalidates_accounts = matches!(
                        other,
                        Call::Useradd { .. }
                            | Call::Usermod { .. }
                            | Call::Userdel { .. }
                            | Call::Groupadd { .. }
                            | Call::Groupmod { .. }
                            | Call::Groupdel { .. }
                            | Call::Login { .. }
                            | Call::Logout
                    );
                    let res = self.forward_server_call(pid, page_sudo, other).await;
                    if invalidates_accounts && res.is_ok() {
                        let mut rt = self.vfs_rt.borrow_mut();
                        rt.uid_names = default_uid_names();
                        rt.gid_names = default_gid_names();
                    }
                    res
                }
            };

            if let Some(prev) = prev_umask {
                let _ = vfs.set_umask(pid, prev);
            }
            fd_refs.push(opened_fd);
            results.push(match outcome {
                Ok(v) => Return::Ok(v),
                Err(e) => Return::Err(e),
            });
        }

        results
    }

    async fn eval_getdents(
        &self,
        vfs: &Vfs,
        pid: u32,
        path: &str,
        cookie: u64,
        count: Option<u64>,
    ) -> std::result::Result<Value, abi::Error> {
        let dir_entries = vfs.readdir(pid, StartAnchor::AtFdCwd, path).await?;
        let total = dir_entries.len();
        let start = (cookie as usize).min(total);
        let max_items = count.map(|c| c as usize).unwrap_or(total);
        let end = start.saturating_add(max_items).min(total);
        let base = if path == "/" {
            ""
        } else {
            path.trim_end_matches('/')
        };
        let mut out = Vec::with_capacity(end.saturating_sub(start));
        for de in &dir_entries[start..end] {
            let child_path = format!("{base}/{}", de.name);
            let mut stat = vfs
                .statat(pid, StartAnchor::AtFdCwd, &child_path, false)
                .await
                .ok();
            if let Some(st) = stat.as_mut() {
                self.fill_stat_names(vfs, pid, st).await;
            }
            out.push(Dirent {
                name: de.name.clone(),
                stat,
            });
        }
        Ok(json!(out))
    }

    #[allow(clippy::too_many_arguments)]
    async fn eval_open_call(
        &self,
        vfs: &Vfs,
        pid: u32,
        page_session_id: Option<&str>,
        page_sudo: bool,
        path: &str,
        flags: u32,
        mode: u16,
        size: Option<u64>,
        sha256: Option<String>,
        version: Option<String>,
    ) -> std::result::Result<(u32, Value), abi::Error> {
        // Page caller with `size`/`sha256`/`version` targeting remote `/` `CloudFs` delegates
        // directly to `OsAuthority` so resumable XHR `/api/pwrite` upload progress works!
        if page_session_id.is_some() && (size.is_some() || sha256.is_some() || version.is_some()) {
            let root_cloud = Rc::clone(&self.vfs_rt.borrow().root_cloud);
            if root_cloud.is_remote_mode() {
                // Walk parent in `Vfs` to determine whether `path` resolves on `FsType::Cloud`!
                let (parent_dir, _) = match path.rsplit_once('/') {
                    Some(("", name)) => ("/", name),
                    Some((p, name)) if !p.is_empty() => (p, name),
                    _ => (".", path),
                };
                if let Ok(sfs) = vfs.statfs(pid, StartAnchor::AtFdCwd, parent_dir).await
                    && sfs.fstype == "cloud"
                {
                    let umask = vfs
                        .process_fs_context(pid)
                        .map(|c| c.borrow().umask)
                        .unwrap_or(0o022);
                    let mut res = page_sys_batch(Batch {
                        calls: vec![Call::Open {
                            path: path.to_string(),
                            flags,
                            mode,
                            size,
                            sha256,
                            version,
                        }],
                        umask: Some(umask),
                        sudo: page_sudo,
                        pid: None,
                        process: None,
                    })
                    .await
                    .map_err(abi::Error::from)?;
                    let val = res.pop().ok_or(Errno::EIO)?.into_result()?;
                    let sfd = val["fd"].as_u64().ok_or(Errno::EIO)? as u32;
                    return Ok((sfd, val));
                }
            }
        }

        // Device character node opened by a process (`pid < SCOPED_PAGE_PID_BASE`): check VFS
        // path resolution & permissions first (so `chroot` without `/dev` returns `ENOENT`!),
        // then forward server-backed devices (`present:*`, `snd:*`, `archive`, `media`, `system`)
        // to `/api/sys`!
        let pass_flags = if (flags & abi::O_PATH) != 0 && (flags & abi::O_NOFOLLOW) != 0 {
            flags & !abi::O_DIRECTORY
        } else {
            flags
        };
        let follow_for_exist = (pass_flags & abi::O_NOFOLLOW) == 0;
        let created = if (pass_flags & abi::O_CREAT) != 0 {
            if (pass_flags & abi::O_EXCL) != 0 {
                true
            } else {
                vfs.statat(pid, StartAnchor::AtFdCwd, path, follow_for_exist)
                    .await
                    .is_err()
            }
        } else {
            false
        };
        let (file_ref, entry) = vfs
            .open_file(pid, StartAnchor::AtFdCwd, path, pass_flags, mode)
            .await?;
        if (flags & abi::O_DIRECTORY) != 0 && !entry.metadata.is_dir() {
            let _ = file_ref.close().await;
            let _ = vfs.releases().flush().await;
            return Err(Errno::ENOTDIR.into());
        }
        if entry.metadata.file_type == FileType::CharDevice
            && let Some(rdev) = &entry.metadata.rdev
            && (rdev.starts_with("present")
                || rdev.starts_with("snd")
                || matches!(rdev.as_str(), "archive" | "media" | "system"))
        {
            let _ = file_ref.close().await;
            let canonical_dev = if rdev.starts_with("present:") || rdev.starts_with("snd:") {
                path.to_string()
            } else {
                format!("/dev/{rdev}")
            };
            let val = self
                .forward_server_call(
                    pid,
                    page_sudo,
                    Call::Open {
                        path: canonical_dev,
                        flags,
                        mode,
                        size,
                        sha256,
                        version,
                    },
                )
                .await?;
            let sfd = val["fd"].as_u64().ok_or(Errno::EIO)? as u32;
            return Ok((sfd, val));
        }

        let mut st = vfs::stat::stat(&entry.handle.fs, entry.handle.node, &entry.metadata);
        self.fill_stat_names(vfs, pid, &mut st).await;
        if let Some(sid) = page_session_id
            && !sid.is_empty()
        {
            if let Some(sz) = size
                && (flags & (abi::O_WRONLY | abi::O_RDWR)) != 0
                && entry.metadata.is_file()
            {
                let _ = file_ref.set_len(0).await;
                let _ = sz;
            }
            let pfd = {
                let mut rt = self.vfs_rt.borrow_mut();
                let sess = rt.sessions.get_mut(sid).ok_or(Errno::ENOENT)?;
                let fd = sess.next_page_fd;
                sess.next_page_fd = sess.next_page_fd.saturating_add(1);
                sess.page_fds.insert(
                    fd,
                    PageOpenFd {
                        file: file_ref,
                        path: path.to_string(),
                        discard_on_abort: (flags & abi::O_CREAT) != 0,
                    },
                );
                fd
            };
            return Ok((
                pfd,
                json!({
                    "fd": pfd,
                    "size": st.size,
                    "created": created,
                    "stat": st,
                    "committed": [],
                    "resumed": false,
                }),
            ));
        }

        let cloexec = flags & vfs::vfs::O_CLOEXEC != 0;
        let fd = match vfs
            .process_fds(pid)
            .and_then(|fds| fds.borrow_mut().insert(file_ref, cloexec))
        {
            Ok(fd) => fd,
            Err(e) => {
                let _ = vfs.releases().flush().await;
                return Err(e.into());
            }
        };
        Ok((
            fd,
            json!({
                "fd": fd,
                "size": st.size,
                "created": created,
                "stat": st,
            }),
        ))
    }

    async fn eval_close_call(
        &self,
        vfs: &Vfs,
        pid: u32,
        page_session_id: Option<&str>,
        page_sudo: bool,
        raw_fd: u32,
        discard: bool,
    ) -> std::result::Result<Value, abi::Error> {
        if let Some(sid) = page_session_id {
            if raw_fd >= CLIENT_PAGE_FD_BASE {
                let removed = {
                    let mut rt = self.vfs_rt.borrow_mut();
                    rt.sessions
                        .get_mut(sid)
                        .and_then(|s| s.page_fds.remove(&raw_fd))
                };
                let Some(entry) = removed else {
                    return Err(Errno::EBADF.into());
                };
                if discard {
                    let _ = entry.file.close().await;
                    if entry.discard_on_abort {
                        let _ = vfs
                            .unlinkat(pid, StartAnchor::AtFdCwd, &entry.path, false)
                            .await;
                    }
                    return Ok(Value::Null);
                }
                let _ = entry.file.sync_all().await;
                let meta = entry.file.metadata().await.ok();
                let mut st = meta
                    .map(|m| vfs::stat::stat(entry.file.fs().id(), entry.file.handle().node, &m));
                entry.file.close().await?;
                let _ = vfs.releases().flush().await;
                if let Some(stat) = st.as_mut() {
                    self.fill_stat_names(vfs, pid, stat).await;
                }
                return Ok(match st {
                    Some(stat) => json!({ "stat": stat }),
                    None => Value::Null,
                });
            }
            let call = if discard {
                Call::Discard {
                    fd: FdRef::Fd(raw_fd),
                }
            } else {
                Call::Close {
                    fd: FdRef::Fd(raw_fd),
                }
            };
            return self.forward_server_call(pid, page_sudo, call).await;
        }

        if let Ok(fds) = vfs.process_fds(pid)
            && fds.borrow().get(raw_fd).is_ok()
        {
            vfs.close(pid, raw_fd).await?;
            return Ok(Value::Null);
        }
        let call = if discard {
            Call::Discard {
                fd: FdRef::Fd(raw_fd),
            }
        } else {
            Call::Close {
                fd: FdRef::Fd(raw_fd),
            }
        };
        self.forward_server_call(pid, page_sudo, call).await
    }

    async fn eval_fchmod(
        &self,
        vfs: &Vfs,
        pid: u32,
        page_session_id: Option<&str>,
        page_sudo: bool,
        raw_fd: u32,
        mode: u16,
    ) -> std::result::Result<Value, abi::Error> {
        if let Some(sid) = page_session_id
            && raw_fd >= CLIENT_PAGE_FD_BASE
        {
            let file = {
                let rt = self.vfs_rt.borrow();
                rt.sessions
                    .get(sid)
                    .and_then(|s| s.page_fds.get(&raw_fd))
                    .map(|e| e.file.clone())
                    .ok_or(Errno::EBADF)?
            };
            if file.access() == vfs::Access::Path {
                return Err(Errno::EBADF.into());
            }
            file.fs()
                .setattr(
                    file.cred(),
                    file.handle(),
                    &SetAttr {
                        mode: Some(mode),
                        ..SetAttr::default()
                    },
                )
                .await?;
            return Ok(Value::Null);
        }
        let opt_file = if page_session_id.is_none() {
            vfs.process_fds(pid)
                .ok()
                .and_then(|fds| fds.borrow().get(raw_fd).ok())
        } else {
            None
        };
        if let Some(file) = opt_file {
            if file.access() == vfs::Access::Path {
                return Err(Errno::EBADF.into());
            }
            file.fs()
                .setattr(
                    file.cred(),
                    file.handle(),
                    &SetAttr {
                        mode: Some(mode),
                        ..SetAttr::default()
                    },
                )
                .await?;
            return Ok(Value::Null);
        }
        self.forward_server_call(
            pid,
            page_sudo,
            Call::Fchmod {
                fd: FdRef::Fd(raw_fd),
                mode,
            },
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn eval_pread(
        &self,
        vfs: &Vfs,
        pid: u32,
        page_session_id: Option<&str>,
        page_sudo: bool,
        fd: Option<FdRef>,
        path: Option<String>,
        offset: u64,
        count: u64,
        fd_refs: &[Option<u32>],
    ) -> std::result::Result<Value, abi::Error> {
        let cap = (count as usize).min(abi::INLINE_MAX as usize);
        if let Some(p) = path {
            let (file_ref, entry) = vfs
                .open_file(pid, StartAnchor::AtFdCwd, &p, abi::O_RDONLY, 0)
                .await?;
            if entry.metadata.is_dir() {
                let _ = file_ref.close().await;
                return Err(Errno::EISDIR.into());
            }
            let mut buf = vec![0u8; cap];
            let res = file_ref.read_at(&mut buf, offset).await;
            let _ = file_ref.close().await;
            let n = res?;
            buf.truncate(n);
            let mut st = vfs::stat::stat(&entry.handle.fs, entry.handle.node, &entry.metadata);
            self.fill_stat_names(vfs, pid, &mut st).await;
            return Ok(json!({ "data": Bytes(buf), "stat": st }));
        }
        let raw_fd = parse_fd_ref(fd.ok_or(Errno::EBADF)?, fd_refs)?;
        if let Some(sid) = page_session_id
            && raw_fd >= CLIENT_PAGE_FD_BASE
        {
            let file = {
                let rt = self.vfs_rt.borrow();
                rt.sessions
                    .get(sid)
                    .and_then(|s| s.page_fds.get(&raw_fd))
                    .map(|e| e.file.clone())
                    .ok_or(Errno::EBADF)?
            };
            let mut buf = vec![0u8; cap];
            let n = file.read_at(&mut buf, offset).await?;
            buf.truncate(n);
            return Ok(json!({ "data": Bytes(buf) }));
        }
        if page_session_id.is_none()
            && let Ok(fds) = vfs.process_fds(pid)
            && fds.borrow().get(raw_fd).is_ok()
        {
            let mut buf = vec![0u8; cap];
            let n = vfs.pread(pid, raw_fd, &mut buf, offset).await?;
            buf.truncate(n);
            return Ok(json!({ "data": Bytes(buf) }));
        }
        self.forward_server_call(
            pid,
            page_sudo,
            Call::Pread {
                fd: Some(FdRef::Fd(raw_fd)),
                path: None,
                offset,
                count,
            },
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn eval_pwrite(
        &self,
        vfs: &Vfs,
        pid: u32,
        page_session_id: Option<&str>,
        page_sudo: bool,
        raw_fd: u32,
        index: u64,
        data: Vec<u8>,
    ) -> std::result::Result<Value, abi::Error> {
        let offset = index.saturating_mul(abi::INLINE_MAX);
        if let Some(sid) = page_session_id
            && raw_fd >= CLIENT_PAGE_FD_BASE
        {
            let file = {
                let rt = self.vfs_rt.borrow();
                rt.sessions
                    .get(sid)
                    .and_then(|s| s.page_fds.get(&raw_fd))
                    .map(|e| e.file.clone())
                    .ok_or(Errno::EBADF)?
            };
            let written = file.write_at(&data, offset).await?;
            return Ok(json!({ "written": written }));
        }
        if page_session_id.is_none()
            && let Ok(fds) = vfs.process_fds(pid)
            && fds.borrow().get(raw_fd).is_ok()
        {
            let written = vfs.pwrite(pid, raw_fd, &data, offset).await?;
            return Ok(json!({ "written": written }));
        }
        self.forward_server_call(
            pid,
            page_sudo,
            Call::Pwrite {
                fd: FdRef::Fd(raw_fd),
                index,
                data: Bytes(data),
            },
        )
        .await
    }

    async fn eval_inotify_add(
        &self,
        vfs: &Vfs,
        pid: u32,
        page_sudo: bool,
        path: &str,
        mask: u32,
    ) -> std::result::Result<Value, abi::Error> {
        let (file_ref, entry) = vfs
            .open_file(
                pid,
                StartAnchor::AtFdCwd,
                path,
                abi::O_RDONLY | abi::O_DIRECTORY,
                0,
            )
            .await?;
        let fstype = file_ref.mount_pin().map(|p| p.fstype());
        let cred = file_ref.cred().clone();
        let _ = file_ref.close().await;
        if fstype != Some(vfs::FsType::Cloud) {
            return Err(Errno::EOPNOTSUPP.into());
        }
        let root_cloud = Rc::clone(&self.vfs_rt.borrow().root_cloud);
        let cloud_path = root_cloud
            .canonical_cloud_path(entry.handle.node)
            .unwrap_or_else(|| path.to_string());
        let handle = if cred.token.is_some() {
            let real_handle = root_cloud.real_cloud_handle(&cred, &entry.handle).await?;
            (!real_handle.proof.is_empty()).then_some(real_handle)
        } else {
            None
        };
        self.forward_server_call(
            pid,
            page_sudo,
            Call::InotifyAddWatch {
                path: cloud_path,
                mask,
                handle,
            },
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn eval_ioctl(
        &self,
        vfs: &Vfs,
        pid: u32,
        page_sudo: bool,
        raw_fd: u32,
        request: u32,
        mut arg: Value,
        fd_refs: &[Option<u32>],
    ) -> std::result::Result<Value, abi::Error> {
        // 1. `FICLONE` (`0x4004_9409`): clone file contents within the same `MountId` on `CloudFs`;
        //    different `MountId`s -> `EXDEV`!
        if request == FICLONE {
            let src_ref: FdRef =
                serde_json::from_value(arg).map_err(|_| abi::Error::from(Errno::EINVAL))?;
            let src_fd = parse_fd_ref(src_ref, fd_refs)?;
            let fds = vfs.process_fds(pid)?;
            let (src_file, dst_file) = {
                let tbl = fds.borrow();
                (tbl.get(src_fd)?, tbl.get(raw_fd)?)
            };
            let src_pin = src_file.mount_pin().ok_or(Errno::EBADF)?;
            let dst_pin = dst_file.mount_pin().ok_or(Errno::EBADF)?;
            if src_pin.id() != dst_pin.id() {
                return Err(Errno::EXDEV.into());
            }
            if dst_pin.effective_rdonly() {
                return Err(Errno::EROFS.into());
            }
            if src_pin.fstype() != vfs::FsType::Cloud {
                return Err(Errno::EOPNOTSUPP.into());
            }
            let root_cloud = Rc::clone(&self.vfs_rt.borrow().root_cloud);
            root_cloud
                .clone_file(
                    pid,
                    dst_file.cred(),
                    src_file.open_ref(),
                    dst_file.open_ref(),
                )
                .await?;
            return Ok(Value::Null);
        }

        // 2. `/dev/archive` & `/dev/media` (`accelerator::SUBMIT`): translate `PathAt.directory`
        //    client descriptors (`kfd`, `OS_FD_CWD`, `OS_FD_ROOT`) into `PathAt.open` (`OpenRef`)!
        if request == accelerator::SUBMIT {
            let mut submit: Submit =
                serde_json::from_value(arg).map_err(|_| abi::Error::from(Errno::EINVAL))?;
            match &mut submit.operation {
                Operation::Create { output, inputs, .. } => {
                    self.rewrite_accel_path_at(vfs, pid, output)?;
                    for inp in inputs {
                        self.rewrite_accel_path_at(vfs, pid, &mut inp.source)?;
                    }
                }
                Operation::Extract {
                    source,
                    destination,
                    ..
                } => {
                    self.rewrite_accel_path_at(vfs, pid, source)?;
                    self.rewrite_accel_path_at(vfs, pid, destination)?;
                }
                Operation::List { source, .. } => {
                    self.rewrite_accel_path_at(vfs, pid, source)?;
                }
                Operation::Faststart { file } => {
                    self.rewrite_accel_path_at(vfs, pid, file)?;
                }
            }
            arg = serde_json::to_value(submit).map_err(|_| abi::Error::from(Errno::EIO))?;
        }

        self.forward_server_call(
            pid,
            page_sudo,
            Call::Ioctl {
                fd: FdRef::Fd(raw_fd),
                request,
                arg,
            },
        )
        .await
    }

    fn rewrite_accel_path_at(&self, vfs: &Vfs, pid: u32, pat: &mut PathAt) -> vfs::Result<()> {
        if pat.open.is_some() {
            return Ok(());
        }
        let root_cloud = Rc::clone(&self.vfs_rt.borrow().root_cloud);
        let dir_fd = pat.directory as i32;
        if dir_fd == OS_FD_ROOT {
            let fs_ctx = vfs.process_fs_context(pid)?;
            let root_anchor = fs_ctx.borrow().root.clone();
            if root_anchor.pin.fstype() != vfs::FsType::Cloud {
                return Err(Errno::EXDEV);
            }
            let real_open = root_cloud
                .real_cloud_open_ref(root_anchor.open.open_ref())
                .ok_or(Errno::EBADF)?;
            pat.open = Some(real_open);
        } else if dir_fd == OS_FD_CWD || dir_fd == -100 {
            let fs_ctx = vfs.process_fs_context(pid)?;
            let cwd_anchor = fs_ctx.borrow().cwd.clone();
            if cwd_anchor.pin.fstype() != vfs::FsType::Cloud {
                return Err(Errno::EXDEV);
            }
            let real_open = root_cloud
                .real_cloud_open_ref(cwd_anchor.open.open_ref())
                .ok_or(Errno::EBADF)?;
            pat.open = Some(real_open);
        } else {
            let fds = vfs.process_fds(pid)?;
            let dir_file = fds.borrow().get(pat.directory)?;
            if dir_file.mount_pin().map(|p| p.fstype()) != Some(vfs::FsType::Cloud) {
                return Err(Errno::EXDEV);
            }
            let real_open = root_cloud
                .real_cloud_open_ref(dir_file.open_ref())
                .ok_or(Errno::EBADF)?;
            pat.open = Some(real_open);
        }
        Ok(())
    }

    async fn forward_server_call(
        &self,
        pid: u32,
        page_sudo: bool,
        call: Call,
    ) -> std::result::Result<Value, abi::Error> {
        let token = {
            let state = self.state.borrow();
            state
                .processes
                .get(&pid)
                .filter(|l| l.ended.is_none())
                .map(|l| l.token.clone())
        };
        if let Some(tok) = token
            && let Ok((global, post)) = installed("cloudFsPost")
        {
            let body = serde_json::to_vec(&Batch {
                calls: vec![call],
                umask: None,
                sudo: false,
                pid: Some(pid),
                process: Some(tok),
            })
            .map_err(|e| abi::Error::because(Errno::EIO, e.to_string()))?;
            let headers = js_sys::Object::new();
            let _ =
                js_sys::Reflect::set(&headers, &"Content-Type".into(), &"application/json".into());
            let arr = js_sys::Uint8Array::from(body.as_slice());
            let answer = post
                .call3(&global, &"/api/sys".into(), &headers, &arr)
                .map_err(|_| abi::Error::from(Errno::EIO))?;
            let reply = promised(answer).await?;
            let status = js_sys::Reflect::get(&reply, &"status".into())
                .ok()
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0) as u16;
            let raw = js_sys::Reflect::get(&reply, &"body".into())
                .map_err(|_| abi::Error::from(Errno::EIO))?;
            let bytes = js_sys::Uint8Array::new(&raw).to_vec();
            if status != 200 {
                return Err(abi::Error::because(
                    Errno::EIO,
                    String::from_utf8_lossy(&bytes).into_owned(),
                ));
            }
            let res: abi::Results = serde_json::from_slice(&bytes)
                .map_err(|e| abi::Error::because(Errno::EIO, e.to_string()))?;
            return res
                .results
                .into_iter()
                .next()
                .ok_or_else(|| abi::Error::from(Errno::EIO))?
                .into_result();
        }
        if installed("pageSysPost").is_ok() {
            let mut res = page_sys_batch(Batch {
                calls: vec![call],
                umask: None,
                sudo: page_sudo,
                pid: None,
                process: None,
            })
            .await?;
            return res.pop().ok_or(Errno::EIO)?.into_result();
        }
        Err(Errno::ENOSYS.into())
    }
}
