//! Unified `os_vfs::Vfs` runtime engine inside `crates/client-kernel` (#51, #52, #53).
//!
//! Owns `system_mnt_ns`, per-login-session derived `MountNamespace`s, user mounts (`opfs`,
//! `hostfs`, `snapshot`, `helperfs`, `sharefs`, and private `image` extensions), per-process
//! `MountNamespace`/`FsContext`/`FdTable` state, service `MountNamespaceGrant` instantiation,
//! all L2 mount/namespace/`chroot`/`cwd` syscalls, `*at` & `kfd_*` operations, `proc_sys`,
//! `vfs_sys`, and `proc_resolve_exec`.

use crate::cloudfs::{
    AuthorityPageFd, PageReadScope, RootCloudDriver, installed, page_sys_batch_with_session,
    promised,
};
use crate::mounts::{Grant, LocalMount, errno_code};
use crate::share_bridge::build_share_backing;
use crate::{INIT, Kernel};
use abi::accelerator::{self, Operation, PathAt, Submit};
use abi::contract::{mount_flags, umount_flags, unshare_flags};
use abi::{
    Batch, Bytes, Call, Creds, Dirent, Errno, FICLONE, FdRef, LocalExecutable, OS_FD_CWD,
    OS_FD_ROOT, Return, Time,
};
use futures_util::lock::Mutex;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::rc::Rc;
use vfs::devfs::{DefaultDeviceBackend, DevPtsFs, DevTmpFs, DeviceBackend};
use vfs::imagefs::{
    BlobStore, BuildAssetSizes, ImageEntry, ImageFs, ImageNodeKind, MemoryBlobStore,
};
use vfs::memfs::MemFs;
use vfs::procfs::{ProcDynamicEntry, ProcFs, ProcProvider};
use vfs::{
    BoxFuture, Cred, FILE_MAX, FileRef, FileType, Filesystem, FsId, Handle, Identity, LockFamily,
    LockKind, LockRange, MountBacking, MountFlags, MountId, MountNamespace, NodeId, ProviderHealth,
    ProviderState, RenameFlags, SeekFrom, SetAttr, StartAnchor, Timespec, Vfs, XattrFlags,
    check_component, format_mountinfo, now_or_never,
};
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;

const MAX_USER_MOUNTS: usize = 16;
const SERVER_DEV_FD_BASE: u32 = 0x2000_0000;
const CLIENT_PAGE_FD_BASE: u32 = 0x4000_0000;
const CLIENT_PAGE_FD_LIMIT: u32 = 0x7000_0000;
const SCOPED_PAGE_PID_BASE: u32 = 0x7fff_0000;
const READ_STREAM_MAX: usize = 64;
const MANIFEST_MAX_BYTES: u64 = 4 * 1024 * 1024;
const PRIVATE_EXT_MAX_BYTES: u64 = 128 * 1024 * 1024;
#[allow(dead_code)]
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

pub(crate) fn map_errno(errno: Errno) -> JsValue {
    let detail = crate::cloudfs::take_last_page_error_detail(errno).unwrap_or_default();
    vfs_js_err(errno, detail)
}

pub(crate) fn wasi_errno_num(errno: Errno) -> i32 {
    match errno {
        Errno::E2BIG => 1,
        Errno::EACCES => 2,
        Errno::EADDRINUSE => 3,
        Errno::EADDRNOTAVAIL => 4,
        Errno::EAFNOSUPPORT => 5,
        Errno::EAGAIN => 6,
        Errno::EBADF => 8,
        Errno::EBUSY => 10,
        Errno::ECANCELED => 11,
        Errno::ECHILD => 12,
        Errno::ECONNABORTED => 13,
        Errno::ECONNREFUSED => 14,
        Errno::ECONNRESET => 15,
        Errno::EDEADLK => 16,
        Errno::EDQUOT => 19,
        Errno::EEXIST => 20,
        Errno::EFBIG => 22,
        Errno::EINTR => 27,
        Errno::EINVAL => 28,
        Errno::EIO => 29,
        Errno::EISCONN => 30,
        Errno::EISDIR => 31,
        Errno::ELOOP => 32,
        Errno::EMFILE => 33,
        Errno::EMLINK => 34,
        Errno::EMSGSIZE => 35,
        Errno::ENAMETOOLONG => 37,
        Errno::ENOBUFS => 42,
        Errno::ENODEV => 43,
        Errno::ENOENT => 44,
        Errno::ENOEXEC => 45,
        Errno::ENOLCK => 46,
        Errno::ENOSPC => 51,
        Errno::ENOSYS => 52,
        Errno::ENOTCONN => 53,
        Errno::ENOTDIR => 54,
        Errno::ENOTEMPTY => 55,
        Errno::ENOTSOCK => 57,
        Errno::EOPNOTSUPP => 58,
        Errno::ENOTTY => 59,
        Errno::ENXIO => 60,
        Errno::ENODATA => 61,
        Errno::ENOTBLK => 218,
        Errno::EPERM => 63,
        Errno::EPIPE => 64,
        Errno::EPROTONOSUPPORT => 66,
        Errno::EPROTOTYPE => 67,
        Errno::ERANGE => 68,
        Errno::EROFS => 69,
        Errno::ESRCH => 71,
        Errno::ESTALE => 72,
        Errno::ETIMEDOUT => 73,
        Errno::ETXTBSY => 74,
        Errno::EXDEV => 75,
        Errno::ETOOMANYREFS => 109,
    }
}

pub(crate) fn json_to_js(val: &Value) -> Result<JsValue, JsValue> {
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
#[allow(dead_code)]
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

/// `/proc` provider: numeric PIDs (`1`, `2`, ...), `self`, `mounts`, and `uptime` are served 100%
/// locally inside `os_vfs::ProcFs` via `ProcBridge` hooks with ZERO network RPCs (#54 L3a).
/// Non-numeric remote server accelerator/container job entries (`/proc/<hex-job-id>`) are queried
/// ONLY when remote accelerator devices (`archive` or `media`) are attached on this instance.
#[derive(Clone)]
pub(crate) struct BrowserProcProvider {
    state: Rc<RefCell<crate::State>>,
    root_cloud: Rc<RootCloudDriver>,
}

impl BrowserProcProvider {
    fn new(state: Rc<RefCell<crate::State>>, root_cloud: Rc<RootCloudDriver>) -> Self {
        Self { state, root_cloud }
    }

    fn can_query_remote(&self, cred: &Cred) -> bool {
        let (remote_attached, has_accel) = {
            let st = self.state.borrow();
            (
                st.remote_attached,
                st.attached_devices.contains_key("archive")
                    || st.attached_devices.contains_key("media"),
            )
        };
        if !remote_attached || !has_accel || !self.root_cloud.is_remote_mode() {
            return false;
        }
        if cred.token.as_deref().is_some_and(|t| !t.is_empty()) {
            return installed("cloudFsPost").is_ok();
        }
        if let Some(pid) = self
            .root_cloud
            .active_pid
            .get()
            .filter(|&p| p < SCOPED_PAGE_PID_BASE)
        {
            if self.root_cloud.is_pid_cloud_denied(pid) {
                return false;
            }
            let cloud_allowed = self
                .state
                .borrow()
                .table
                .proc(pid)
                .is_some_and(|p| p.state != abi::ProcState::Zombie && p.cred.cloud_access);
            return cloud_allowed
                && installed("cloudFsPost").is_ok()
                && installed("serviceAuthPost").is_ok();
        }
        installed("pageSysPost").is_ok()
    }

    async fn proc_call(&self, cred: &Cred, call: Call) -> vfs::Result<Value> {
        if !self.can_query_remote(cred) {
            return Err(Errno::ENOENT);
        }
        let proc_pid = self
            .root_cloud
            .active_pid
            .get()
            .filter(|&p| p < SCOPED_PAGE_PID_BASE);
        let token = if let Some(tok) = cred.token.as_deref().filter(|t| !t.is_empty()) {
            Some(tok.to_string())
        } else if let Some(pid) = proc_pid {
            let existing = self.state.borrow().table.proc(pid).and_then(|p| {
                p.cred
                    .remote
                    .as_ref()
                    .filter(|r| r.cloud_access)
                    .map(|r| r.token.clone())
            });
            if let Some(tok) = existing {
                Some(tok)
            } else {
                let rem = crate::lazy_mint_remote_cred(&self.state, pid)
                    .await
                    .map_err(|_| Errno::ENOENT)?;
                Some(rem.token)
            }
        } else {
            None
        };
        if let Some(token) = token {
            let Ok((global, post)) = installed("cloudFsPost") else {
                return Err(Errno::ENOENT);
            };
            let instance_id = self.state.borrow().instance_id.clone();
            let body = serde_json::to_vec(&Batch {
                calls: vec![call],
                umask: None,
                sudo: false,
                pid: proc_pid,
                process: Some(token.clone()),
            })
            .map_err(|_| Errno::EIO)?;
            let headers = js_sys::Object::new();
            let _ =
                js_sys::Reflect::set(&headers, &"Content-Type".into(), &"application/json".into());
            let _ = js_sys::Reflect::set(&headers, &"X-Process-Token".into(), &token.into());
            if !instance_id.is_empty() {
                let _ =
                    js_sys::Reflect::set(&headers, &"X-OS-Instance".into(), &instance_id.into());
            }
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
        if proc_pid.is_some() {
            return Err(Errno::ENOENT);
        }
        if installed("pageSysPost").is_ok() {
            let mut res = crate::cloudfs::page_sys_batch(Batch {
                calls: vec![call],
                umask: None,
                sudo: self.root_cloud.page_sudo.get(),
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
    async fn remote_job_entries(&self, cred: &Cred) -> Vec<(String, FileType)> {
        if !self.can_query_remote(cred) {
            return Vec::new();
        }
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
            return Vec::new();
        };
        let Ok(entries) = serde_json::from_value::<Vec<Dirent>>(val) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for e in entries {
            if !proc_is_remote_job_id(&e.name) {
                continue;
            }
            let file_type = e
                .stat
                .as_ref()
                .map_or(FileType::Dir, |s| proc_file_type_from_mode(s.mode));
            out.push((e.name, file_type));
        }
        out
    }
}

impl ProcProvider for BrowserProcProvider {
    fn list_pids<'a>(&'a self, _cred: &'a Cred) -> BoxFuture<'a, Vec<u32>> {
        // Numeric PIDs are 100% instance-local in `LocalProcessTable` (ZERO network RPCs).
        Box::pin(async { Ok(Vec::new()) })
    }

    fn top_entries<'a>(&'a self, _cred: &'a Cred) -> BoxFuture<'a, Vec<ProcDynamicEntry>> {
        // Keep `ProcFs::lookup` 100% local (ZERO network RPCs for `/proc/uptime`, `/proc/mounts`,
        // `/proc/self`, or `/proc/<pid>`). Remote accelerator jobs are merged directly in
        // `BrowserProcFs::read_dir` and resolved on demand in `BrowserProcFs::lookup`.
        Box::pin(async { Ok(Vec::new()) })
    }

    fn read_top<'a>(&'a self, cred: &'a Cred, name: &'a str) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(async move { self.read_proc_file(cred, &format!("/proc/{name}")).await })
    }

    fn pid_entries<'a>(
        &'a self,
        _cred: &'a Cred,
        _pid: u32,
    ) -> BoxFuture<'a, Vec<ProcDynamicEntry>> {
        // All numeric `/proc/<pid>/*` entries render 100% locally (ZERO network RPCs).
        Box::pin(async { Ok(Vec::new()) })
    }

    fn read_pid<'a>(
        &'a self,
        _cred: &'a Cred,
        _pid: u32,
        _name: &'a str,
    ) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(async { Err(Errno::ENOENT) })
    }
}

const PROC_GENERATION: u64 = 1;
const PROC_ROOT_INO: u64 = 1;
const PROC_REMOTE_TAG: u64 = 8;
const PROC_REMOTE_OPEN_BIT: u64 = 1 << 63;

fn proc_is_remote_ino(ino: u64) -> bool {
    ino <= abi::fs::JS_SAFE && (ino >> 48) == PROC_REMOTE_TAG
}

fn proc_is_local_only_root_child(name: &str) -> bool {
    name == "mounts"
        || name == "self"
        || name == "uptime"
        || name.parse::<u32>().is_ok_and(|pid| pid.to_string() == name)
}

fn proc_is_remote_job_id(name: &str) -> bool {
    !name.is_empty()
        && !proc_is_local_only_root_child(name)
        && (name.len() == 32 || !name.bytes().all(|b| b.is_ascii_digit()))
        && name.bytes().all(|b| b.is_ascii_hexdigit())
}

fn proc_file_type_from_mode(mode: u32) -> FileType {
    match mode & abi::S_IFMT {
        abi::S_IFDIR => FileType::Dir,
        abi::S_IFLNK => FileType::Symlink,
        abi::S_IFCHR => FileType::CharDevice,
        abi::S_IFSOCK => FileType::Socket,
        _ => FileType::File,
    }
}

fn proc_metadata_from_stat(st: &abi::Stat) -> vfs::Metadata {
    vfs::Metadata {
        file_type: proc_file_type_from_mode(st.mode),
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

struct BrowserProcOpen {
    ino: u64,
    access: vfs::Access,
    bytes: Option<Vec<u8>>,
    metadata: vfs::Metadata,
}

struct BrowserProcState {
    next_remote_id: u64,
    paths: HashMap<u64, String>,
    path_to_ino: HashMap<String, u64>,
    parents: HashMap<u64, (u64, String)>,
    next_open: u64,
    opens: HashMap<u64, BrowserProcOpen>,
}

impl Default for BrowserProcState {
    fn default() -> Self {
        Self {
            next_remote_id: 1,
            paths: HashMap::new(),
            path_to_ino: HashMap::new(),
            parents: HashMap::new(),
            next_open: 1,
            opens: HashMap::new(),
        }
    }
}

impl BrowserProcState {
    fn intern_remote(&mut self, parent_ino: u64, name: &str, path: &str) -> vfs::Result<u64> {
        if let Some(&ino) = self.path_to_ino.get(path) {
            self.parents
                .entry(ino)
                .or_insert_with(|| (parent_ino, name.to_string()));
            return Ok(ino);
        }
        let seq = self.next_remote_id;
        if seq > 0xffff_ffff_ffff {
            return Err(Errno::ENOSPC);
        }
        self.next_remote_id += 1;
        let ino = (PROC_REMOTE_TAG << 48) | seq;
        self.paths.insert(ino, path.to_string());
        self.path_to_ino.insert(path.to_string(), ino);
        self.parents.insert(ino, (parent_ino, name.to_string()));
        Ok(ino)
    }
}

/// Wrapper over [`ProcFs`] delegating non-numeric `/proc/<job-id>` directory hierarchies
/// (`/proc/<job>/{status,cmdline,fd,fd/<n>}`) to `/api/sys` while keeping local PID and namespace
/// entries inside `os_vfs::ProcFs`.
pub(crate) struct BrowserProcFs {
    fs_id: FsId,
    inner: Rc<ProcFs<BrowserProcProvider>>,
    provider: BrowserProcProvider,
    state: RefCell<BrowserProcState>,
}

impl BrowserProcFs {
    fn new(
        fs_id: FsId,
        inner: Rc<ProcFs<BrowserProcProvider>>,
        provider: BrowserProcProvider,
    ) -> Self {
        Self {
            fs_id,
            inner,
            provider,
            state: RefCell::new(BrowserProcState::default()),
        }
    }

    fn handle(&self, ino: u64) -> Handle {
        Handle {
            fs: self.fs_id.clone(),
            node: NodeId {
                ino,
                generation: PROC_GENERATION,
            },
            proof: String::new(),
        }
    }

    fn check_remote_handle(&self, handle: &Handle) -> vfs::Result<String> {
        if handle.fs != self.fs_id || !handle.proof.is_empty() {
            return Err(Errno::EACCES);
        }
        if handle.node.generation != PROC_GENERATION {
            return Err(Errno::ESTALE);
        }
        if !proc_is_remote_ino(handle.node.ino) {
            return Err(Errno::ESTALE);
        }
        self.state
            .borrow()
            .paths
            .get(&handle.node.ino)
            .cloned()
            .ok_or(Errno::ESTALE)
    }

    async fn remote_meta(&self, cred: &Cred, path: &str) -> vfs::Result<vfs::Metadata> {
        let val = self
            .provider
            .proc_call(
                cred,
                Call::Lstat {
                    path: path.to_string(),
                },
            )
            .await?;
        let st: abi::Stat = serde_json::from_value(val).map_err(|_| Errno::EIO)?;
        Ok(proc_metadata_from_stat(&st))
    }

    async fn lookup_remote(
        &self,
        cred: &Cred,
        parent_ino: u64,
        parent_path: &str,
        name: &str,
    ) -> vfs::Result<vfs::Entry> {
        check_component(name)?;
        let child_path = format!("{parent_path}/{name}");
        let metadata = self.remote_meta(cred, &child_path).await?;
        let ino = self
            .state
            .borrow_mut()
            .intern_remote(parent_ino, name, &child_path)?;
        Ok(vfs::Entry {
            handle: self.handle(ino),
            metadata,
        })
    }

    async fn walk_via_lookup(
        &self,
        cred: &Cred,
        dir: &Handle,
        names: &[String],
    ) -> vfs::Result<vfs::Walked> {
        for name in names {
            check_component(name)?;
        }
        let cur_meta = self.metadata(cred, dir).await?;
        if !cur_meta.is_dir() {
            return Err(Errno::ENOTDIR);
        }
        let mut cur_handle = dir.clone();
        let mut cur_type = FileType::Dir;
        let mut entries = Vec::new();
        for (idx, name) in names.iter().enumerate() {
            if idx > 0 {
                let stop = match cur_type {
                    FileType::Dir => None,
                    FileType::Symlink => Some(vfs::Stop::Symlink(idx - 1)),
                    _ => Some(vfs::Stop::NotDirectory(idx - 1)),
                };
                if stop.is_some() {
                    return Ok(vfs::Walked { entries, stop });
                }
            }
            match self.lookup(cred, &cur_handle, name).await {
                Ok(entry) => {
                    cur_handle = entry.handle.clone();
                    cur_type = entry.metadata.file_type;
                    entries.push(entry);
                }
                Err(Errno::ENOENT) => {
                    return Ok(vfs::Walked {
                        entries,
                        stop: Some(vfs::Stop::Missing(idx)),
                    });
                }
                Err(e) => return Err(e),
            }
        }
        Ok(vfs::Walked {
            entries,
            stop: None,
        })
    }
}

impl Filesystem for BrowserProcFs {
    fn id(&self) -> &FsId {
        &self.fs_id
    }

    fn capabilities(&self) -> abi::contract::FsCapabilities {
        self.inner.capabilities()
    }

    fn root(&self) -> Handle {
        self.inner.root()
    }

    fn lookup<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, vfs::Entry> {
        Box::pin(async move {
            if proc_is_remote_ino(dir.node.ino) {
                let parent_path = self.check_remote_handle(dir)?;
                if !self.remote_meta(cred, &parent_path).await?.is_dir() {
                    return Err(Errno::ENOTDIR);
                }
                return self
                    .lookup_remote(cred, dir.node.ino, &parent_path, name)
                    .await;
            }
            check_component(name)?;
            if dir.node.ino == PROC_ROOT_INO && !proc_is_local_only_root_child(name) {
                if !proc_is_remote_job_id(name) || !self.provider.can_query_remote(cred) {
                    return Err(Errno::ENOENT);
                }
                return self.lookup_remote(cred, PROC_ROOT_INO, "/proc", name).await;
            }
            let entry = self.inner.lookup(cred, dir, name).await?;
            // Promote dynamic directory entries under a remote numeric PID (`TAG_PID_DYN = 5`)
            // so `fd/<n>` inside remote PID directories can be traversed too.
            if entry.metadata.is_dir()
                && ((entry.handle.node.ino >> 48) == 5 || (entry.handle.node.ino >> 48) == 1)
                && (dir.node.ino >> 48) == 2
                && (dir.node.ino & 0xffff) == 0
            {
                let pid = ((dir.node.ino >> 16) & 0xffff_ffff) as u32;
                let path = format!("/proc/{pid}/{name}");
                let ino = self
                    .state
                    .borrow_mut()
                    .intern_remote(dir.node.ino, name, &path)?;
                return Ok(vfs::Entry {
                    handle: self.handle(ino),
                    metadata: entry.metadata,
                });
            }
            Ok(entry)
        })
    }

    fn walk<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        names: &'a [String],
    ) -> BoxFuture<'a, vfs::Walked> {
        Box::pin(async move {
            if proc_is_remote_ino(dir.node.ino) {
                return self.walk_via_lookup(cred, dir, names).await;
            }
            if dir.node.ino == PROC_ROOT_INO
                && names
                    .first()
                    .is_some_and(|n| !proc_is_local_only_root_child(n))
            {
                return self.walk_via_lookup(cred, dir, names).await;
            }
            match self.inner.walk(cred, dir, names).await {
                Ok(mut walked) => {
                    if dir.node.ino == PROC_ROOT_INO
                        && let Some(first) = walked.entries.first_mut()
                        && first.metadata.is_dir()
                        && ((first.handle.node.ino >> 48) == 1
                            || (first.handle.node.ino >> 48) == 5)
                    {
                        return self.walk_via_lookup(cred, dir, names).await;
                    }
                    Ok(walked)
                }
                Err(Errno::ENOTDIR) if names.len() > 1 => {
                    self.walk_via_lookup(cred, dir, names).await
                }
                Err(e) => Err(e),
            }
        })
    }

    fn parent<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
    ) -> BoxFuture<'a, Option<(vfs::Entry, String)>> {
        Box::pin(async move {
            if !proc_is_remote_ino(dir.node.ino) {
                return self.inner.parent(cred, dir).await;
            }
            let _ = self.check_remote_handle(dir)?;
            let parent = self.state.borrow().parents.get(&dir.node.ino).cloned();
            let Some((parent_ino, name)) = parent else {
                return Ok(None);
            };
            let parent_handle = self.handle(parent_ino);
            let metadata = self.metadata(cred, &parent_handle).await?;
            Ok(Some((
                vfs::Entry {
                    handle: parent_handle,
                    metadata,
                },
                name,
            )))
        })
    }

    fn metadata<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, vfs::Metadata> {
        Box::pin(async move {
            if proc_is_remote_ino(handle.node.ino) {
                let path = self.check_remote_handle(handle)?;
                return self.remote_meta(cred, &path).await;
            }
            self.inner.metadata(cred, handle).await
        })
    }

    fn setattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        attr: &'a SetAttr,
    ) -> BoxFuture<'a, vfs::Metadata> {
        Box::pin(async move {
            if proc_is_remote_ino(handle.node.ino) {
                let path = self.check_remote_handle(handle)?;
                let meta = self.remote_meta(cred, &path).await?;
                if *attr == SetAttr::default() {
                    return Ok(meta);
                }
                return Err(Errno::EPERM);
            }
            self.inner.setattr(cred, handle, attr).await
        })
    }

    fn read_dir<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
    ) -> BoxFuture<'a, Vec<vfs::DirEntry>> {
        Box::pin(async move {
            if proc_is_remote_ino(dir.node.ino) {
                let dir_path = self.check_remote_handle(dir)?;
                if !self.remote_meta(cred, &dir_path).await?.is_dir() {
                    return Err(Errno::ENOTDIR);
                }
                let val = self
                    .provider
                    .proc_call(
                        cred,
                        Call::Getdents {
                            path: dir_path.clone(),
                            cookie: 0,
                            count: None,
                        },
                    )
                    .await?;
                let entries: Vec<Dirent> = serde_json::from_value(val).map_err(|_| Errno::EIO)?;
                let mut state = self.state.borrow_mut();
                let mut out = Vec::with_capacity(entries.len());
                for de in entries {
                    if de.name == "." || de.name == ".." {
                        continue;
                    }
                    let child_path = format!("{dir_path}/{}", de.name);
                    let ino = state.intern_remote(dir.node.ino, &de.name, &child_path)?;
                    let file_type = de
                        .stat
                        .as_ref()
                        .map(|s| proc_file_type_from_mode(s.mode))
                        .unwrap_or(FileType::File);
                    out.push(vfs::DirEntry {
                        name: de.name,
                        node: NodeId {
                            ino,
                            generation: PROC_GENERATION,
                        },
                        file_type,
                    });
                }
                return Ok(out);
            }
            let mut entries = self.inner.read_dir(cred, dir).await?;
            if dir.node.ino == PROC_ROOT_INO {
                let remote_jobs = self.provider.remote_job_entries(cred).await;
                let mut state = self.state.borrow_mut();
                for de in &mut entries {
                    if !proc_is_local_only_root_child(&de.name) {
                        let child_path = format!("/proc/{}", de.name);
                        de.node.ino = state.intern_remote(PROC_ROOT_INO, &de.name, &child_path)?;
                    }
                }
                for (name, file_type) in remote_jobs {
                    if entries.iter().any(|de| de.name == name) {
                        continue;
                    }
                    let child_path = format!("/proc/{name}");
                    let ino = state.intern_remote(PROC_ROOT_INO, &name, &child_path)?;
                    entries.push(vfs::DirEntry {
                        name,
                        node: NodeId {
                            ino,
                            generation: PROC_GENERATION,
                        },
                        file_type,
                    });
                }
            }
            Ok(entries)
        })
    }

    fn read_link<'a>(&'a self, cred: &'a Cred, link: &'a Handle) -> BoxFuture<'a, String> {
        Box::pin(async move {
            if proc_is_remote_ino(link.node.ino) {
                let path = self.check_remote_handle(link)?;
                let val = self
                    .provider
                    .proc_call(cred, Call::Readlink { path })
                    .await?;
                return serde_json::from_value::<String>(val).map_err(|_| Errno::EIO);
            }
            self.inner.read_link(cred, link).await
        })
    }

    fn create<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
        options: &'a vfs::OpenOptions,
    ) -> BoxFuture<'a, (vfs::Entry, vfs::OpenRef)> {
        Box::pin(async move {
            if proc_is_remote_ino(dir.node.ino) || dir.node.ino == PROC_ROOT_INO {
                check_component(name)?;
                match self.lookup(cred, dir, name).await {
                    Ok(entry) => {
                        if options.is_create_new() {
                            return Err(Errno::EEXIST);
                        }
                        if entry.metadata.is_dir() {
                            return Err(Errno::EISDIR);
                        }
                        let open = self.open(cred, &entry.handle, options).await?;
                        return Ok((entry, open));
                    }
                    Err(Errno::ENOENT) if proc_is_remote_ino(dir.node.ino) => {
                        return Err(Errno::EACCES);
                    }
                    Err(e) if proc_is_remote_ino(dir.node.ino) => return Err(e),
                    Err(_) => {}
                }
            }
            self.inner.create(cred, dir, name, mode, options).await
        })
    }

    fn mkdir<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
    ) -> BoxFuture<'a, vfs::Entry> {
        Box::pin(async move {
            if proc_is_remote_ino(dir.node.ino) {
                let _ = self.check_remote_handle(dir)?;
                check_component(name)?;
                return Err(Errno::EPERM);
            }
            self.inner.mkdir(cred, dir, name, mode).await
        })
    }

    fn mknod<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
        rdev: &'a str,
    ) -> BoxFuture<'a, vfs::Entry> {
        Box::pin(async move {
            if proc_is_remote_ino(dir.node.ino) {
                let _ = self.check_remote_handle(dir)?;
                check_component(name)?;
                return Err(Errno::EPERM);
            }
            self.inner.mknod(cred, dir, name, mode, rdev).await
        })
    }

    fn symlink<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        target: &'a str,
    ) -> BoxFuture<'a, vfs::Entry> {
        Box::pin(async move {
            if proc_is_remote_ino(dir.node.ino) {
                let _ = self.check_remote_handle(dir)?;
                return self
                    .inner
                    .symlink(cred, &self.inner.root(), name, target)
                    .await;
            }
            self.inner.symlink(cred, dir, name, target).await
        })
    }

    fn link<'a>(
        &'a self,
        cred: &'a Cred,
        target: &'a Handle,
        dir: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, vfs::Entry> {
        Box::pin(async move {
            if proc_is_remote_ino(target.node.ino) || proc_is_remote_ino(dir.node.ino) {
                if proc_is_remote_ino(target.node.ino) {
                    let _ = self.check_remote_handle(target)?;
                }
                if proc_is_remote_ino(dir.node.ino) {
                    let _ = self.check_remote_handle(dir)?;
                }
                check_component(name)?;
                return Err(Errno::EPERM);
            }
            self.inner.link(cred, target, dir, name).await
        })
    }

    fn unlink<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if proc_is_remote_ino(dir.node.ino) {
                let _ = self.check_remote_handle(dir)?;
                check_component(name)?;
                return Err(Errno::EPERM);
            }
            self.inner.unlink(cred, dir, name).await
        })
    }

    fn rmdir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if proc_is_remote_ino(dir.node.ino) {
                let _ = self.check_remote_handle(dir)?;
                check_component(name)?;
                return Err(Errno::EPERM);
            }
            self.inner.rmdir(cred, dir, name).await
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
            if proc_is_remote_ino(from_dir.node.ino) || proc_is_remote_ino(to_dir.node.ino) {
                if proc_is_remote_ino(from_dir.node.ino) {
                    let _ = self.check_remote_handle(from_dir)?;
                }
                if proc_is_remote_ino(to_dir.node.ino) {
                    let _ = self.check_remote_handle(to_dir)?;
                }
                check_component(from)?;
                check_component(to)?;
                return Err(Errno::EPERM);
            }
            self.inner
                .rename(cred, from_dir, from, to_dir, to, flags)
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
            if proc_is_remote_ino(handle.node.ino) {
                let _ = self.check_remote_handle(handle)?;
                return self.inner.getxattr(cred, &self.inner.root(), name).await;
            }
            self.inner.getxattr(cred, handle, name).await
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
            if proc_is_remote_ino(handle.node.ino) {
                let _ = self.check_remote_handle(handle)?;
                return self
                    .inner
                    .setxattr(cred, &self.inner.root(), name, value, flags)
                    .await;
            }
            self.inner.setxattr(cred, handle, name, value, flags).await
        })
    }

    fn listxattr<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Vec<String>> {
        Box::pin(async move {
            if proc_is_remote_ino(handle.node.ino) {
                let _ = self.check_remote_handle(handle)?;
                return Ok(Vec::new());
            }
            self.inner.listxattr(cred, handle).await
        })
    }

    fn removexattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if proc_is_remote_ino(handle.node.ino) {
                let _ = self.check_remote_handle(handle)?;
                return self.inner.removexattr(cred, &self.inner.root(), name).await;
            }
            self.inner.removexattr(cred, handle, name).await
        })
    }

    fn statfs<'a>(&'a self, cred: &'a Cred) -> BoxFuture<'a, vfs::StatFs> {
        self.inner.statfs(cred)
    }

    fn open<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        options: &'a vfs::OpenOptions,
    ) -> BoxFuture<'a, vfs::OpenRef> {
        Box::pin(async move {
            if !proc_is_remote_ino(handle.node.ino) {
                return self.inner.open(cred, handle, options).await;
            }
            let path = self.check_remote_handle(handle)?;
            let access = options.access()?;
            let mut metadata = self.remote_meta(cred, &path).await?;
            if access != vfs::Access::Path {
                if metadata.is_symlink() {
                    return Err(Errno::ELOOP);
                }
                if metadata.is_dir() {
                    if access.writes() || options.is_truncate() {
                        return Err(Errno::EISDIR);
                    }
                } else if access.writes() || options.is_truncate() || access == vfs::Access::Exec {
                    return Err(Errno::EACCES);
                }
            }
            let bytes = if metadata.is_file() && access != vfs::Access::Path {
                let data = self.provider.read_proc_file(cred, &path).await?;
                metadata.size = data.len() as u64;
                Some(data)
            } else {
                None
            };
            let mut state = self.state.borrow_mut();
            let id = state.next_open | PROC_REMOTE_OPEN_BIT;
            state.next_open += 1;
            state.opens.insert(
                id,
                BrowserProcOpen {
                    ino: handle.node.ino,
                    access,
                    bytes,
                    metadata,
                },
            );
            Ok(vfs::OpenRef {
                fs: self.fs_id.clone(),
                id,
                node: handle.node,
                access,
            })
        })
    }

    fn open_metadata<'a>(&'a self, open: &'a vfs::OpenRef) -> BoxFuture<'a, vfs::Metadata> {
        Box::pin(async move {
            if (open.id & PROC_REMOTE_OPEN_BIT) == 0 {
                return self.inner.open_metadata(open).await;
            }
            let state = self.state.borrow();
            let rec = state
                .opens
                .get(&open.id)
                .filter(|r| open.fs == self.fs_id && r.ino == open.node.ino)
                .ok_or(Errno::EBADF)?;
            Ok(rec.metadata.clone())
        })
    }

    fn read_at<'a>(
        &'a self,
        open: &'a vfs::OpenRef,
        buf: &'a mut [u8],
        offset: u64,
    ) -> BoxFuture<'a, usize> {
        Box::pin(async move {
            if (open.id & PROC_REMOTE_OPEN_BIT) == 0 {
                return self.inner.read_at(open, buf, offset).await;
            }
            let state = self.state.borrow();
            let rec = state
                .opens
                .get(&open.id)
                .filter(|r| open.fs == self.fs_id && r.ino == open.node.ino)
                .ok_or(Errno::EBADF)?;
            if !rec.access.reads() {
                return Err(Errno::EBADF);
            }
            if rec.metadata.is_dir() {
                return Err(Errno::EISDIR);
            }
            let Some(bytes) = rec.bytes.as_deref() else {
                return Err(Errno::EINVAL);
            };
            if offset > FILE_MAX || buf.len() as u64 > FILE_MAX - offset {
                return Err(Errno::EINVAL);
            }
            if offset >= bytes.len() as u64 || buf.is_empty() {
                return Ok(0);
            }
            let start = offset as usize;
            let len = (bytes.len() - start).min(buf.len());
            buf[..len].copy_from_slice(&bytes[start..start + len]);
            Ok(len)
        })
    }

    fn write_at<'a>(
        &'a self,
        open: &'a vfs::OpenRef,
        buf: &'a [u8],
        at: vfs::WriteAt,
    ) -> BoxFuture<'a, vfs::Written> {
        Box::pin(async move {
            if (open.id & PROC_REMOTE_OPEN_BIT) == 0 {
                return self.inner.write_at(open, buf, at).await;
            }
            let state = self.state.borrow();
            let _ = state
                .opens
                .get(&open.id)
                .filter(|r| open.fs == self.fs_id && r.ino == open.node.ino)
                .ok_or(Errno::EBADF)?;
            Err(Errno::EBADF)
        })
    }

    fn set_len<'a>(&'a self, open: &'a vfs::OpenRef, size: u64) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if (open.id & PROC_REMOTE_OPEN_BIT) == 0 {
                return self.inner.set_len(open, size).await;
            }
            let state = self.state.borrow();
            let _ = state
                .opens
                .get(&open.id)
                .filter(|r| open.fs == self.fs_id && r.ino == open.node.ino)
                .ok_or(Errno::EBADF)?;
            Err(Errno::EINVAL)
        })
    }

    fn sync_all<'a>(&'a self, open: &'a vfs::OpenRef) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if (open.id & PROC_REMOTE_OPEN_BIT) == 0 {
                return self.inner.sync_all(open).await;
            }
            let state = self.state.borrow();
            let rec = state
                .opens
                .get(&open.id)
                .filter(|r| open.fs == self.fs_id && r.ino == open.node.ino)
                .ok_or(Errno::EBADF)?;
            if rec.access == vfs::Access::Path {
                return Err(Errno::EBADF);
            }
            Ok(())
        })
    }

    fn lock<'a>(
        &'a self,
        open: &'a vfs::OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if (open.id & PROC_REMOTE_OPEN_BIT) == 0 {
                return self.inner.lock(open, family, kind, range).await;
            }
            let state = self.state.borrow();
            let rec = state
                .opens
                .get(&open.id)
                .filter(|r| open.fs == self.fs_id && r.ino == open.node.ino)
                .ok_or(Errno::EBADF)?;
            if rec.access == vfs::Access::Path {
                return Err(Errno::EBADF);
            }
            Err(Errno::ENOLCK)
        })
    }

    fn try_lock<'a>(
        &'a self,
        open: &'a vfs::OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        self.lock(open, family, kind, range)
    }

    fn unlock<'a>(
        &'a self,
        open: &'a vfs::OpenRef,
        family: LockFamily,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if (open.id & PROC_REMOTE_OPEN_BIT) == 0 {
                return self.inner.unlock(open, family, range).await;
            }
            let state = self.state.borrow();
            let rec = state
                .opens
                .get(&open.id)
                .filter(|r| open.fs == self.fs_id && r.ino == open.node.ino)
                .ok_or(Errno::EBADF)?;
            if rec.access == vfs::Access::Path {
                return Err(Errno::EBADF);
            }
            Ok(())
        })
    }

    fn test_lock<'a>(
        &'a self,
        open: &'a vfs::OpenRef,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, Option<vfs::Conflict>> {
        Box::pin(async move {
            if (open.id & PROC_REMOTE_OPEN_BIT) == 0 {
                return self.inner.test_lock(open, kind, range).await;
            }
            let state = self.state.borrow();
            let rec = state
                .opens
                .get(&open.id)
                .filter(|r| open.fs == self.fs_id && r.ino == open.node.ino)
                .ok_or(Errno::EBADF)?;
            if rec.access == vfs::Access::Path {
                return Err(Errno::EBADF);
            }
            Ok(None)
        })
    }

    fn release<'a>(&'a self, open: &'a vfs::OpenRef) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if (open.id & PROC_REMOTE_OPEN_BIT) == 0 {
                return self.inner.release(open).await;
            }
            let mut state = self.state.borrow_mut();
            if state
                .opens
                .get(&open.id)
                .is_none_or(|r| open.fs != self.fs_id || r.ino != open.node.ino)
            {
                return Err(Errno::EBADF);
            }
            state.opens.remove(&open.id);
            Ok(())
        })
    }
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BootVfsOptions {
    #[serde(default, alias = "build_asset_sizes")]
    build_asset_sizes: Option<BuildAssetSizes>,
    #[serde(default, alias = "system_composition")]
    system_composition: Option<String>,
    #[serde(default, alias = "bind_mounts")]
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

pub(crate) fn drain_releases(vfs: &Vfs) {
    for release in vfs.releases().take_pending() {
        wasm_bindgen_futures::spawn_local(async move {
            let _ = release.await;
        });
    }
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

struct UploadDigest {
    expected: String,
    // None after a non-sequential change. Only the verifier may read the underlying bytes.
    sequential: Mutex<Option<(u64, Sha256)>>,
    fresh_contents: bool,
}

#[derive(Clone)]
struct PageOpenFd {
    file: FileRef,
    path: String,
    creation: Option<(Handle, String)>,
    cloexec: bool,
    append: bool,
    created: bool,
    chunk_size: u64,
    expected_size: Option<u64>,
    digest: Option<Rc<UploadDigest>>,
}

impl PageOpenFd {
    async fn write(&self, cred: &Cred, bytes: &[u8], offset: u64) -> vfs::Result<usize> {
        let mut progress = match &self.digest {
            Some(digest) => Some(digest.sequential.lock().await),
            None => None,
        };
        let (n, start) = if self.append {
            let n = self.file.write_as(cred, bytes).await?;
            (n, self.file.position() - n as u64)
        } else {
            (self.file.write_at_as(cred, bytes, offset).await?, offset)
        };
        if n > 0
            && let Some(state) = progress.as_deref_mut()
            && let Some((next, hash)) = state
        {
            if start == *next {
                hash.update(&bytes[..n]);
                *next += n as u64;
            } else {
                *state = None;
            }
        }
        Ok(n)
    }
}

pub(crate) struct AttachedUserMount {
    pub(crate) mount_id: MountId,
    pub(crate) kind: String,
    pub(crate) name: String,
    pub(crate) cloud: bool,
    pub(crate) provider: Rc<ProviderState>,
    pub(crate) local_mount: Option<LocalMount>,
}

pub(crate) struct SessionVfs {
    epoch: Rc<()>,
    pub(crate) session_id: String,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) groups: BTreeSet<u32>,
    pub(crate) mnt_ns: Rc<RefCell<MountNamespace>>,
    pub(crate) baseline_mounts: BTreeSet<MountId>,
    pub(crate) generation: u64,
    pub(crate) user_mounts: BTreeMap<String, AttachedUserMount>,
    pending_mounts: HashSet<String>,
    page_fds: HashMap<u32, PageOpenFd>,
    delegated_uploads: HashMap<u32, (AuthorityPageFd, vfs::mount::WritableMountPin)>,
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

    fn alloc_page_fd(&mut self, entry: PageOpenFd) -> vfs::Result<u32> {
        if self.page_fds.len() >= 1024 {
            return Err(Errno::EMFILE);
        }
        let span = CLIENT_PAGE_FD_LIMIT - CLIENT_PAGE_FD_BASE;
        let mut cur = self.next_page_fd;
        if !(CLIENT_PAGE_FD_BASE..CLIENT_PAGE_FD_LIMIT).contains(&cur) {
            cur = CLIENT_PAGE_FD_BASE;
        }
        for _ in 0..span {
            let candidate = cur;
            cur = if cur + 1 >= CLIENT_PAGE_FD_LIMIT {
                CLIENT_PAGE_FD_BASE
            } else {
                cur + 1
            };
            if !self.page_fds.contains_key(&candidate) {
                self.next_page_fd = cur;
                self.page_fds.insert(candidate, entry);
                return Ok(candidate);
            }
        }
        Err(Errno::EMFILE)
    }
}

#[derive(Clone)]
pub(crate) struct ServerFdEntry {
    pub(crate) sfd: Rc<u32>,
    pub(crate) closing: bool,
    pub(crate) cloexec: bool,
    /// When transferred over `SCM_RIGHTS` (`U-10`), pins this single fd to the sender's
    /// originating `(owner_pid, token)` without granting the receiver broader cloud scope.
    pub(crate) attenuated_token: Option<(u32, String)>,
}

pub(crate) struct ProcessVfsMeta {
    pub(crate) supervisor: bool,
    login_session: Option<String>,
    pub(crate) session_id: Option<String>,
    pub(crate) cloud_access: bool,
    pub(crate) cred: Cred,
    pub(crate) server_fds: HashMap<u32, ServerFdEntry>,
    pub(crate) next_server_fd: u32,
    /// Single-fd `CloudFs` open refs received via `SCM_RIGHTS` (`kfd -> (origin_pid, origin_token)`).
    pub(crate) attenuated_kfds: HashMap<u32, (u32, Option<String>)>,
}

impl ProcessVfsMeta {
    pub(crate) fn new(session_id: Option<String>, cloud_access: bool) -> Self {
        Self::with_cred(session_id, cloud_access, Cred::new(Identity::guest()))
    }

    pub(crate) fn with_cred(session_id: Option<String>, cloud_access: bool, cred: Cred) -> Self {
        Self {
            supervisor: false,
            login_session: session_id.clone(),
            session_id,
            cloud_access,
            cred,
            server_fds: HashMap::new(),
            next_server_fd: SERVER_DEV_FD_BASE,
            attenuated_kfds: HashMap::new(),
        }
    }

    pub(crate) fn alloc_server_fd(&mut self, sfd: Rc<u32>, cloexec: bool) -> vfs::Result<u32> {
        self.alloc_server_fd_with_attenuation(sfd, cloexec, None)
    }

    pub(crate) fn alloc_server_fd_with_attenuation(
        &mut self,
        sfd: Rc<u32>,
        cloexec: bool,
        attenuated_token: Option<(u32, String)>,
    ) -> vfs::Result<u32> {
        if self.server_fds.len() >= 1024 {
            return Err(Errno::EMFILE);
        }
        let span = CLIENT_PAGE_FD_BASE - SERVER_DEV_FD_BASE;
        let mut cur = self.next_server_fd;
        if !(SERVER_DEV_FD_BASE..CLIENT_PAGE_FD_BASE).contains(&cur) {
            cur = SERVER_DEV_FD_BASE;
        }
        for _ in 0..span {
            let candidate = cur;
            cur = if cur + 1 >= CLIENT_PAGE_FD_BASE {
                SERVER_DEV_FD_BASE
            } else {
                cur + 1
            };
            if !self.server_fds.contains_key(&candidate) {
                self.next_server_fd = cur;
                self.server_fds.insert(
                    candidate,
                    ServerFdEntry {
                        sfd,
                        cloexec,
                        closing: false,
                        attenuated_token,
                    },
                );
                return Ok(candidate);
            }
        }
        Err(Errno::EMFILE)
    }
}

struct CachedExecTicket {
    session_id: Option<String>,
    bytes: Option<Vec<u8>>,
    mount_id: MountId,
    provider: Rc<ProviderState>,
}

struct ReadStreamEntry {
    session_id: String,
    file: FileRef,
    offset: u64,
    remaining: u64,
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
    pub(crate) dev_fs: Rc<DevTmpFs<JsDeviceBackend>>,
    pub(crate) dev_pts: Rc<DevPtsFs<JsDeviceBackend>>,
    pub(crate) usr_fs_id: FsId,
    pub(crate) usr_blob_paths: HashMap<u64, String>,
    pub(crate) sessions: HashMap<String, SessionVfs>,
    guest_page: Option<SessionVfs>,
    pub(crate) active_session_id: Option<String>,
    pub(crate) proc_meta: HashMap<u32, ProcessVfsMeta>,
    pub(crate) cloud_exec_by_fs: HashMap<FsId, bool>,
    exec_tickets: HashMap<String, CachedExecTicket>,
    next_exec_ticket: u64,
    read_streams: HashMap<u32, ReadStreamEntry>,
    next_read_stream: u32,
    pub(crate) lock_waits: HashMap<(u32, u32), Rc<LockCancel>>,
    pub(crate) unix_sock: Rc<RefCell<vfs::unix_sock::UnixSocketTable>>,
    pub(crate) pending_sock_cleanup: crate::unix_sock_bridge::PendingSockCleanup,
    pub(crate) uid_names: HashMap<u32, String>,
    pub(crate) gid_names: HashMap<u32, String>,
    next_tmp_id: u64,
    next_scoped_pid: u32,
}

fn install_vfs_proc_hooks(vfs: &Vfs, state: &Rc<RefCell<crate::State>>) {
    let s1 = Rc::clone(state);
    vfs.set_proc_snapshot_hook(Rc::new(move |pid| {
        let state = s1.try_borrow().ok()?;
        let snap = state.table.proc_snapshot(pid)?;
        Some(vfs::procfs::ProcMetaSnapshot {
            ppid: snap.ppid,
            pgid: snap.pgid,
            sid: snap.sid,
            uid: snap.uid,
            gid: snap.gid,
            state: snap.state,
            cgroup: snap.cgroup,
            comm: snap.comm,
            argv: snap.argv,
            start_ticks: snap.started_ticks,
            tty: snap.tty,
            tty_fds: snap.tty_fds,
        })
    }));
    let s2 = Rc::clone(state);
    vfs.set_proc_list_hook(Rc::new(move || {
        s2.try_borrow()
            .map(|st| st.table.all_pids())
            .unwrap_or_default()
    }));
    let s3 = Rc::clone(state);
    vfs.set_uptime_hook(Rc::new(move || {
        s3.try_borrow()
            .map(|st| st.table.uptime_secs(crate::now_secs()))
            .unwrap_or(0)
    }));
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
    state: Rc<RefCell<crate::State>>,
    opts: Option<BootVfsOptions>,
) -> vfs::Result<(
    Vfs,
    Rc<DevTmpFs<JsDeviceBackend>>,
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
    install_vfs_proc_hooks(&vfs, &state);
    {
        let vfs_hook = vfs.clone();
        let state_hook = Rc::clone(&state);
        root_cloud.set_on_lazy_mint(Rc::new(move |pid| {
            let info = state_hook.try_borrow().ok().and_then(|st| {
                st.table.proc(pid).map(|p| {
                    (
                        p.cred.identity.clone(),
                        p.cred.remote.as_ref().map(|r| r.token.clone()),
                    )
                })
            });
            if let Some((identity, token)) = info {
                let umask = vfs_hook
                    .process_fs_context(pid)
                    .map(|c| c.borrow().umask)
                    .unwrap_or(0o022);
                let _ = vfs_hook.set_cred(
                    pid,
                    Cred {
                        identity,
                        umask,
                        token,
                    },
                );
            }
        }));
    }
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
    let blob_store = crate::release_v2::VerifiedAssetBlobStore;
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
        "usr",
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

    // 2. `/proc` (`ProcFs` bound to `vfs.proc_bridge()` — 100% local rendering for all numeric
    // PIDs, `self`, `mounts`, and `uptime`; `BrowserProcFs` handles remote container job ids only
    // when a remote credential is attached).
    let proc_provider = BrowserProcProvider::new(Rc::clone(&state), Rc::clone(&root_cloud));
    let proc_fs = Rc::new(ProcFs::new(
        FsId("proc".to_string()),
        mounted_at,
        proc_provider.clone(),
    ));
    proc_fs.bind_bridge(vfs.proc_bridge());
    let proc_wrapper = Rc::new(BrowserProcFs::new(
        FsId("proc".to_string()),
        proc_fs,
        proc_provider,
    ));
    let proc_backing = Rc::new(
        MountBacking::new(proc_wrapper as Rc<dyn Filesystem>, vfs::FsType::Proc)
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

    // 3. `/dev` (`DevTmpFs` with instance-local devices only; remote devices `archive`, `media`,
    // `present`, `snd` require explicit credentialed `attach_remote` per Contract §2.7) and
    // `/dev/pts` (`DevPtsFs`).
    let dev_fs = Rc::new(DevTmpFs::new(
        FsId("devtmpfs".to_string()),
        1,
        Box::new(js_now_timespec),
        JsDeviceBackend::default(),
    ));
    {
        let active_pid = Rc::clone(&root_cloud.active_pid);
        let st_hook = Rc::clone(&state);
        dev_fs.set_remote_open_hook(Rc::new(move |_cred, driver| {
            let Some(pid) = active_pid.get() else {
                // Page-scoped operation (e.g. built-in app / page API): permitted once attached.
                return Ok(());
            };
            if pid >= SCOPED_PAGE_PID_BASE {
                return Ok(());
            }
            let st = st_hook.try_borrow().map_err(|_| Errno::EACCES)?;
            let proc = st.table.proc(pid).ok_or(Errno::EACCES)?;
            if let Some(rem) = &proc.cred.remote {
                if !rem.scope.allows_device(driver) {
                    return Err(Errno::EACCES);
                }
                return Ok(());
            }
            if !proc.cred.cloud_access {
                return Err(Errno::EACCES);
            }
            Ok(())
        }));
    }
    let dev_backing = Rc::new(MountBacking::new(
        Rc::clone(&dev_fs) as Rc<dyn Filesystem>,
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

    // 4. Instance-local `/run`, `/tmp` (`01777` sticky tmpfs, Contract §2.1), `/mnt/local`,
    // `/mnt/shared`, `/opt/private` (`MemFs` tmpfs carriers).
    for (idx, target, mode) in [
        (1u64, "/run", 0o755u16),
        (2u64, "/tmp", 0o1777u16),
        (3u64, "/mnt/local", 0o755u16),
        (4u64, "/mnt/shared", 0o755u16),
        (5u64, "/opt/private", 0o755u16),
    ] {
        let fs = Rc::new(MemFs::new(
            FsId(format!("tmpfs:boot:{idx}")),
            idx,
            0,
            0,
            mode,
            Box::new(js_now_timespec),
        ));
        if mode & 0o7000 != 0 {
            let root = fs.root();
            let _ = fs
                .setattr(
                    &root_cred,
                    &root,
                    &SetAttr {
                        mode: Some(mode),
                        ..SetAttr::default()
                    },
                )
                .await;
        }
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

    Ok((vfs, dev_fs, dev_pts, usr_fs_id, usr_blob_paths))
}

impl VfsRuntime {
    pub(crate) fn new_sync(
        instance_id: &str,
        root_cloud: Rc<RootCloudDriver>,
        state: Rc<RefCell<crate::State>>,
    ) -> Self {
        let id = if instance_id.is_empty() {
            "local-instance"
        } else {
            instance_id
        };
        root_cloud.sync_boot_mem.set(true);
        let booted = now_or_never(construct_vfs(id, Rc::clone(&root_cloud), state, None));
        root_cloud.sync_boot_mem.set(false);
        let (vfs, dev_fs, dev_pts, usr_fs_id, usr_blob_paths) = booted
            .expect("initial boot_vfs must resolve synchronously")
            .expect("initial boot_vfs must succeed");
        let mut proc_meta = HashMap::new();
        proc_meta.insert(INIT, ProcessVfsMeta::new(None, false));
        Self {
            vfs,
            root_cloud,
            dev_fs,
            dev_pts,
            usr_fs_id,
            usr_blob_paths,
            sessions: HashMap::new(),
            guest_page: None,
            active_session_id: None,
            proc_meta,
            cloud_exec_by_fs: HashMap::new(),
            exec_tickets: HashMap::new(),
            next_exec_ticket: 1,
            read_streams: HashMap::new(),
            next_read_stream: 1,
            lock_waits: HashMap::new(),
            unix_sock: Rc::new(RefCell::new(vfs::unix_sock::UnixSocketTable::new())),
            pending_sock_cleanup: crate::unix_sock_bridge::PendingSockCleanup::default(),
            uid_names: default_uid_names(),
            gid_names: default_gid_names(),
            next_tmp_id: 100,
            next_scoped_pid: SCOPED_PAGE_PID_BASE,
        }
    }

    fn alloc_exec_ticket(&mut self, entry: CachedExecTicket) -> vfs::Result<String> {
        // Tickets belong to pending launches, including every stage of one admission batch.
        if self.exec_tickets.len() >= abi::BATCH_MAX {
            return Err(Errno::EAGAIN);
        }
        let seq = self.next_exec_ticket;
        self.next_exec_ticket = self.next_exec_ticket.wrapping_add(1).max(1);
        let rand_bits = js_sys::Math::random().to_bits();
        let ticket = format!("xt:{seq}:{rand_bits:016x}");
        self.exec_tickets.insert(ticket.clone(), entry);
        Ok(ticket)
    }

    fn evict_mount_execs(&mut self, mount_id: MountId) {
        self.exec_tickets.retain(|_, v| v.mount_id != mount_id);
    }

    fn alloc_tmp_id(&mut self) -> u64 {
        let id = self.next_tmp_id;
        self.next_tmp_id += 1;
        id
    }

    fn page_session(&self, sid: &str) -> Option<&SessionVfs> {
        if sid.is_empty() {
            self.guest_page.as_ref()
        } else {
            self.sessions.get(sid)
        }
    }

    fn page_session_mut(&mut self, sid: &str) -> Option<&mut SessionVfs> {
        if sid.is_empty() {
            self.guest_page.as_mut()
        } else {
            self.sessions.get_mut(sid)
        }
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

pub(crate) struct RootCloudScope<F> {
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
                drain_releases(vfs);
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
                drain_releases(vfs);
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
        let root_cloud = Rc::clone(&self.vfs_rt.borrow().root_cloud);
        let is_cloud = st.dev == root_cloud.fs_id().dev();
        if (st.mode & abi::S_IFMT) == abi::S_IFREG && is_cloud {
            st.writing = root_cloud.writing_of(st.ino);
        } else {
            st.writing = None;
        }
        // Harvest any real usernames/group names learned from cloud `Lstat` responses first.
        {
            let mut rt = self.vfs_rt.borrow_mut();
            if st.user.is_empty()
                && !rt.uid_names.contains_key(&st.uid)
                && let Some(name) = root_cloud.cached_uid_name(st.uid)
            {
                rt.uid_names.insert(st.uid, name);
            }
            if st.group.is_empty()
                && !rt.gid_names.contains_key(&st.gid)
                && let Some(name) = root_cloud.cached_gid_name(st.gid)
            {
                rt.gid_names.insert(st.gid, name);
            }
        }
        let missing = {
            let rt = self.vfs_rt.borrow();
            (st.user.is_empty() && !rt.uid_names.contains_key(&st.uid))
                || (st.group.is_empty() && !rt.gid_names.contains_key(&st.gid))
        };
        // Only query `/etc/passwd` + `/etc/group` when remote-attached OR statting an actual
        // cloud inode (preserving Gate 2's 0 `/api/*` RPCs for `/tmp`, `/run`, `/usr`, `/dev`).
        if missing
            && (self.state.borrow().remote_attached
                || (is_cloud && crate::cloudfs::installed("pageSysPost").is_ok()))
        {
            self.refresh_account_names(vfs, pid).await;
        }
        let rt = self.vfs_rt.borrow();
        if st.user.is_empty() {
            st.user = rt
                .uid_names
                .get(&st.uid)
                .cloned()
                .or_else(|| root_cloud.cached_uid_name(st.uid))
                .unwrap_or_else(|| st.uid.to_string());
        }
        if st.group.is_empty() {
            st.group = rt
                .gid_names
                .get(&st.gid)
                .cloned()
                .or_else(|| root_cloud.cached_gid_name(st.gid))
                .unwrap_or_else(|| st.gid.to_string());
        }
    }

    async fn fill_symlink_target(
        &self,
        vfs: &Vfs,
        pid: u32,
        anchor: StartAnchor,
        path: &str,
        st: &mut abi::Stat,
    ) {
        if st.link.is_none()
            && (st.mode & abi::S_IFMT) == abi::S_IFLNK
            && let Ok(target) = vfs.readlinkat(pid, anchor, path).await
        {
            st.link = Some(target);
        }
    }

    pub(crate) fn vfs_instance(&self) -> Option<Vfs> {
        Some(self.vfs_rt.borrow().vfs.clone())
    }

    /// Bind-mount `root_cloud`'s `/dev/{driver}` (`present` or `snd`) onto `/dev/{driver}` in
    /// `system_mnt_ns` and every active session namespace (F3-11 / E2E A1).
    pub(crate) async fn mount_remote_cloud_dev(&self, driver: &str) {
        if !matches!(driver, "present" | "snd") {
            return;
        }
        let target = format!("/dev/{driver}");
        let (vfs, root_cloud, namespaces) = {
            let rt = self.vfs_rt.borrow();
            let mut nss = vec![rt.vfs.system_namespace()];
            for sess in rt.sessions.values() {
                nss.push(Rc::clone(&sess.mnt_ns));
            }
            if let Some(guest) = &rt.guest_page {
                nss.push(Rc::clone(&guest.mnt_ns));
            }
            (rt.vfs.clone(), Rc::clone(&rt.root_cloud), nss)
        };
        let entry = match self
            .with_page_scope(false, root_cloud.lookup_remote_dir_handle(&target))
            .await
        {
            Ok(e) => e,
            Err(_) => return,
        };
        let backing = Rc::new(MountBacking::new(
            Rc::clone(&root_cloud) as Rc<dyn Filesystem>,
            vfs::FsType::Cloud,
        ));
        let mut root_cred = Cred::root();
        root_cred.umask = 0;
        for ns in namespaces {
            let already = ns
                .borrow()
                .mounts()
                .values()
                .any(|m| m.slot.backing.fstype == vfs::FsType::Cloud && m.root_in_fs == target);
            if already {
                continue;
            }
            if let Ok(mount_id) = self
                .with_page_scope(
                    false,
                    vfs.mount_on_namespace(
                        &ns,
                        &root_cred,
                        Rc::clone(&backing),
                        Some((entry.handle.clone(), target.clone())),
                        "cloud",
                        &target,
                        MountFlags {
                            nosuid: true,
                            noexec: true,
                            ..MountFlags::default()
                        },
                        mount_flags::MS_NOSUID | mount_flags::MS_NOEXEC,
                        None,
                    ),
                )
                .await
            {
                let mut rt = self.vfs_rt.borrow_mut();
                for sess in rt.sessions.values_mut() {
                    if Rc::ptr_eq(&sess.mnt_ns, &ns) {
                        sess.baseline_mounts.insert(mount_id);
                    }
                }
                if let Some(guest) = &mut rt.guest_page
                    && Rc::ptr_eq(&guest.mnt_ns, &ns)
                {
                    guest.baseline_mounts.insert(mount_id);
                }
            }
        }
    }

    /// Unmount any cloud bind-mount for `/dev/{driver}` from `system_mnt_ns` and all active
    /// session namespaces before detaching the `DevTmpFs` node.
    pub(crate) fn unmount_remote_cloud_dev(&self, driver: &str) {
        if !matches!(driver, "present" | "snd") {
            return;
        }
        let target = format!("/dev/{driver}");
        let namespaces = {
            let rt = self.vfs_rt.borrow();
            let mut nss = vec![rt.vfs.system_namespace()];
            for sess in rt.sessions.values() {
                nss.push(Rc::clone(&sess.mnt_ns));
            }
            if let Some(guest) = &rt.guest_page {
                nss.push(Rc::clone(&guest.mnt_ns));
            }
            nss
        };
        for ns in namespaces {
            let ids: Vec<MountId> = ns
                .borrow()
                .mounts()
                .iter()
                .filter(|(_, m)| {
                    m.slot.backing.fstype == vfs::FsType::Cloud && m.root_in_fs == target
                })
                .map(|(&id, _)| id)
                .collect();
            for id in ids {
                let _ = ns.borrow_mut().detach_subtree(id);
            }
        }
    }

    pub(crate) async fn close_process_server_fds(&self, pid: u32) {
        if self.close_server_descriptors(pid, false).await.is_err() {
            let _ = self.close_server_descriptors(pid, false).await;
        }
    }

    async fn close_server_descriptors(&self, pid: u32, on_exec: bool) -> vfs::Result<()> {
        let closing: Vec<_> = {
            let rt = self.vfs_rt.borrow();
            rt.proc_meta
                .get(&pid)
                .into_iter()
                .flat_map(|meta| meta.server_fds.iter())
                .filter(|(_, e)| !on_exec || e.cloexec)
                .map(|(&fd, _)| fd)
                .collect()
        };
        let mut result = Ok(());
        for fd in closing {
            if let Err(e) = self.release_server_fd(pid, fd, false).await {
                result = Err(e.errno);
            }
        }
        result
    }

    pub(crate) async fn release_server_fd(
        &self,
        pid: u32,
        fd: u32,
        discard: bool,
    ) -> Result<Value, abi::Error> {
        let (sfd, attenuated) = {
            let mut rt = self.vfs_rt.borrow_mut();
            let table = &mut rt.proc_meta.get_mut(&pid).ok_or(Errno::EBADF)?.server_fds;
            let entry = table
                .get_mut(&fd)
                .filter(|e| !e.closing)
                .ok_or(Errno::EBADF)?;
            if Rc::strong_count(&entry.sfd) > 1 {
                table.remove(&fd);
                return Ok(Value::Null);
            }
            entry.closing = true;
            (*entry.sfd, entry.attenuated_token.clone())
        };
        let remote = FdRef::Fd(sfd);
        let call = if discard {
            Call::Discard { fd: remote }
        } else {
            Call::Close { fd: remote }
        };
        let is_attenuated = attenuated.is_some();
        let result = match attenuated {
            Some((owner_pid, owner_tok)) => {
                self.forward_server_call_attenuated(owner_pid, &owner_tok, call)
                    .await
            }
            None => {
                self.with_proc_scope(pid, self.forward_server_call(pid, false, call))
                    .await
            }
        };
        let revoked_attenuated =
            is_attenuated && result.as_ref().is_err_and(|e| e.errno == Errno::EACCES);
        if let Some(meta) = self.vfs_rt.borrow_mut().proc_meta.get_mut(&pid) {
            if result.is_ok()
                || result.as_ref().is_err_and(|e| e.errno == Errno::EBADF)
                || revoked_attenuated
            {
                meta.server_fds.remove(&fd);
            } else if let Some(entry) = meta.server_fds.get_mut(&fd) {
                entry.closing = false;
            }
        }
        if revoked_attenuated {
            return Ok(Value::Null);
        }
        result
    }

    pub(crate) async fn vfs_process_exit_cleanup(&self, pid: u32, _token: Option<String>) {
        self.close_process_server_fds(pid).await;
        let (vfs, root_cloud, waits, unix_sock) = {
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
            (
                rt.vfs.clone(),
                Rc::clone(&rt.root_cloud),
                waits,
                Rc::clone(&rt.unix_sock),
            )
        };
        let sock_cleanup = unix_sock.borrow_mut().release_process(pid);
        self.record_unix_sock_cleanup(sock_cleanup).await;
        for w in waits {
            w.cancel();
        }
        let _ = self
            .with_proc_scope(pid, async { vfs.exit_process(pid).await })
            .await;
        root_cloud.set_cloud_access(pid, true);
    }

    /// Register a newly admitted local process in `Vfs` (`execs_of`) with ZERO network RPCs.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn register_local_exec_in_vfs(
        &self,
        pid: u32,
        ppid: u32,
        identity: Identity,
        token: Option<String>,
        cwd: &str,
        session_id: Option<&str>,
        cloud_access: bool,
        service_grant_json: Option<&str>,
    ) -> Result<(), JsValue> {
        let cred = Cred {
            identity,
            umask: 0o022,
            token,
        };
        let grant = service_grant_json
            .map(serde_json::from_str::<ServiceGrantSpec>)
            .transpose()
            .map_err(|e| vfs_js_err(Errno::EINVAL, e.to_string()))?;
        let (vfs, cloud, ns, sid) = {
            let rt = self.vfs_rt.borrow();
            let sid = session_id
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .or_else(|| rt.active_session_id.clone());
            let ns = match &grant {
                Some(g) => {
                    resolve_service_namespace_locked(
                        &rt.vfs,
                        &rt.sessions,
                        g,
                        cred.identity.id,
                        None,
                        sid.as_deref(),
                    )?
                    .0
                }
                None => match &sid {
                    Some(id) => rt
                        .sessions
                        .get(id)
                        .map(|s| Rc::clone(&s.mnt_ns))
                        .unwrap_or_else(|| rt.vfs.system_namespace()),
                    None => rt.vfs.system_namespace(),
                },
            };
            (rt.vfs.clone(), Rc::clone(&rt.root_cloud), ns, sid)
        };
        cloud.set_cloud_access(pid, cloud_access);
        vfs.spawn_process(pid, ppid, cred.clone(), Some(Rc::clone(&ns)), None, None)
            .map_err(map_errno)?;
        self.vfs_rt.borrow_mut().proc_meta.insert(
            pid,
            ProcessVfsMeta::with_cred(sid, cloud_access, cred.clone()),
        );
        self.with_proc_scope(pid, async {
            if let Some(grant) = grant {
                for bind in &grant.bind_mounts {
                    apply_service_bind(&vfs, &ns, &cred, bind).await?;
                }
            }
            if !cwd.is_empty() && cwd != "/" {
                vfs.chdir(pid, cwd).await?;
            }
            Ok(())
        })
        .await
        .map_err(map_errno)?;
        Ok(())
    }

    /// Notify active sessions whose `MountNamespace` matches `target_ns_id` that mounts changed,
    /// pruning any user mounts that were detached (e.g. by CLI `umount`).
    fn notify_ns_changed(&self, target_ns_id: vfs::NamespaceId) {
        let mut notifications = Vec::new();
        {
            let mut rt = self.vfs_rt.borrow_mut();
            let mut detached_mounts = Vec::new();
            for sess in rt.sessions.values_mut() {
                if sess.mnt_ns.borrow().id() == target_ns_id {
                    let ns = sess.mnt_ns.borrow();
                    sess.user_mounts.retain(|_, um| {
                        let live = ns.contains_mount(um.mount_id);
                        if !live {
                            detached_mounts.push(um.mount_id);
                        }
                        live
                    });
                    drop(ns);
                    sess.generation = sess.generation.wrapping_add(1);
                    notifications.push((sess.session_id.clone(), sess.generation));
                }
            }
            for mid in detached_mounts {
                rt.evict_mount_execs(mid);
            }
        }
        for (sid, generation) in notifications {
            emit_mounts_changed(&sid, generation);
        }
    }

    fn collect_mount_ids(ns: &Rc<RefCell<MountNamespace>>) -> Vec<MountId> {
        ns.borrow().mounts().keys().copied().collect()
    }

    fn evict_detached_mount_ids(&self, ns: &Rc<RefCell<MountNamespace>>, before: Vec<MountId>) {
        let ns_b = ns.borrow();
        let gone: Vec<MountId> = before
            .into_iter()
            .filter(|mid| !ns_b.contains_mount(*mid))
            .collect();
        drop(ns_b);
        if !gone.is_empty() {
            let mut rt = self.vfs_rt.borrow_mut();
            for mid in gone {
                rt.evict_mount_execs(mid);
            }
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

    pub(crate) fn with_proc_scope<F>(&self, pid: u32, fut: F) -> RootCloudScope<F>
    where
        F: std::future::Future,
    {
        self.with_root_cloud_scope(Some(pid), false, fut)
    }

    /// Resolve which PID's `RootCloudDriver` scope should execute a single-fd `kfd_*` I/O call.
    /// Ordinarily returns `pid`. For a `CloudFs` open reference transferred over `SCM_RIGHTS`
    /// (`U-10`) to a receiver without cloud scope, permits ONLY single-fd I/O under the
    /// originating sender's scope while the sender's originating token remains active and unrevoked.
    pub(crate) fn scope_pid_for_kfd(&self, pid: u32, kfd: u32) -> vfs::Result<u32> {
        let attenuated = {
            let rt = self.vfs_rt.borrow();
            let Some(meta) = rt.proc_meta.get(&pid) else {
                return Ok(pid);
            };
            meta.attenuated_kfds.get(&kfd).cloned()
        };
        let Some((origin_pid, origin_token)) = attenuated else {
            return Ok(pid);
        };
        let state = self.state.borrow();
        if let Some(ref tok) = origin_token {
            if state.pending_revocations.contains(tok) {
                return Err(Errno::EACCES);
            }
            let valid_owner = state.table.proc(origin_pid).is_some_and(|p| {
                p.state != abi::ProcState::Zombie
                    && p.cred.cloud_access
                    && p.cred.remote.as_ref().is_some_and(|r| r.token == *tok)
            });
            if !valid_owner {
                return Err(Errno::EACCES);
            }
        } else {
            let valid_owner = state
                .table
                .proc(origin_pid)
                .is_some_and(|p| p.state != abi::ProcState::Zombie && p.cred.cloud_access);
            if !valid_owner {
                return Err(Errno::EACCES);
            }
        }
        Ok(origin_pid)
    }

    pub(crate) async fn with_proc_scope_retry<T, F, Fut>(
        &self,
        pid: u32,
        mut make: F,
    ) -> vfs::Result<T>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = vfs::Result<T>>,
    {
        let before_uid = self
            .state
            .borrow()
            .table
            .proc(pid)
            .map(|p| p.cred.identity.id);
        let res = self.with_proc_scope(pid, make()).await;
        let after_uid = self
            .state
            .borrow()
            .table
            .proc(pid)
            .map(|p| p.cred.identity.id);
        let hydrated = before_uid == Some(os_core::permissions::GUEST)
            && after_uid.is_some_and(os_core::permissions::is_guest_id);
        if hydrated || after_uid != before_uid {
            self.sync_vfs_proc_creds(pid);
            if hydrated {
                let other_pids: Vec<u32> = self
                    .state
                    .borrow()
                    .table
                    .all_pids()
                    .into_iter()
                    .filter(|&p| p != pid && p != 1)
                    .collect();
                for opid in other_pids {
                    self.sync_vfs_proc_creds(opid);
                }
            }
        }
        if hydrated && matches!(res, Err(Errno::EACCES | Errno::EPERM)) {
            return self.with_proc_scope(pid, make()).await;
        }
        res
    }

    fn with_page_scope<F>(&self, sudo: bool, fut: F) -> RootCloudScope<F>
    where
        F: std::future::Future,
    {
        self.with_root_cloud_scope(None, sudo, fut)
    }
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

    /// Re-initialize `system_mnt_ns` with optional composition / build asset options (ZERO RPCs).
    pub async fn boot_vfs(&self, opts_json: Option<String>) -> Result<(), JsValue> {
        let opts: Option<BootVfsOptions> = opts_json
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|s| serde_json::from_str(s).map_err(|e| vfs_js_err(Errno::EINVAL, e.to_string())))
            .transpose()?;
        let (inst_id, root_cloud) = {
            let state = self.state.borrow();
            let id = if state.namespace.is_empty() {
                if state.instance_id.is_empty() {
                    "local-instance".to_string()
                } else {
                    state.instance_id.clone()
                }
            } else {
                state.namespace.clone()
            };
            (id, Rc::clone(&self.vfs_rt.borrow().root_cloud))
        };
        let (vfs, dev_fs, dev_pts, usr_fs_id, usr_blob_paths) =
            construct_vfs(&inst_id, root_cloud, Rc::clone(&self.state), opts)
                .await
                .map_err(map_errno)?;
        let (old_vfs, old_sessions, old_streams) = {
            let mut rt = self.vfs_rt.borrow_mut();
            let old_vfs = std::mem::replace(&mut rt.vfs, vfs);
            rt.dev_fs = dev_fs;
            rt.dev_pts = dev_pts;
            rt.usr_fs_id = usr_fs_id;
            rt.usr_blob_paths = usr_blob_paths;
            rt.active_session_id = None;
            rt.exec_tickets.clear();
            rt.proc_meta.clear();
            rt.proc_meta.insert(INIT, ProcessVfsMeta::new(None, false));
            let mut old_sessions: Vec<_> = rt.sessions.drain().collect();
            if let Some(guest) = rt.guest_page.take() {
                old_sessions.push((String::new(), guest));
            }
            let old_streams: Vec<(u32, ReadStreamEntry)> = rt.read_streams.drain().collect();
            (old_vfs, old_sessions, old_streams)
        };
        for (_, stream) in old_streams {
            let _ = stream.file.close().await;
        }
        for (sid, mut sess) in old_sessions {
            for (_, (remote, _pin)) in sess.delegated_uploads.drain() {
                let _ = remote.close(false).await;
            }
            for (_, fd_entry) in sess.page_fds.drain() {
                let _ = fd_entry.file.close().await;
            }
            for (_, um) in sess.user_mounts {
                let _ = sess.mnt_ns.borrow_mut().detach_subtree(um.mount_id);
            }
            emit_mounts_changed(&sid, 0);
        }
        drain_releases(&old_vfs);
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
        if self.vfs_rt.borrow().guest_page.is_some() {
            self.session_end(String::new()).await?;
        }
        {
            let mut rt = self.vfs_rt.borrow_mut();
            rt.active_session_id = Some(session_id.clone());
            rt.sessions.insert(
                session_id.clone(),
                SessionVfs {
                    epoch: Rc::new(()),
                    session_id: session_id.clone(),
                    uid,
                    gid,
                    groups: group_set,
                    mnt_ns: sess_ns,
                    baseline_mounts,
                    generation: 1,
                    user_mounts: BTreeMap::new(),
                    pending_mounts: HashSet::new(),
                    page_fds: HashMap::new(),
                    delegated_uploads: HashMap::new(),
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
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let removed = {
            let mut rt = self.vfs_rt.borrow_mut();
            if rt.active_session_id.as_deref() == Some(session_id.as_str()) {
                rt.active_session_id = None;
            }
            let streams: Vec<_> = rt
                .read_streams
                .extract_if(|_, entry| entry.session_id == session_id)
                .map(|(_, e)| e.file)
                .collect();
            rt.exec_tickets
                .retain(|_, ticket| ticket.session_id.as_deref() != Some(&session_id));
            let removed = if session_id.is_empty() {
                rt.guest_page.take()
            } else {
                rt.sessions.remove(&session_id)
            };
            (removed, streams)
        };
        for file in removed.1 {
            let _ = file.close().await;
        }
        let Some(mut sess) = removed.0 else {
            return Ok(());
        };
        for (_, (remote, _pin)) in sess.delegated_uploads.drain() {
            let _ = remote.close(false).await;
        }
        for (_, fd_entry) in sess.page_fds.drain() {
            if fd_entry.expected_size.is_some() || fd_entry.digest.is_some() || fd_entry.append {
                let _ = Self::discard_created_file(&fd_entry).await;
            }
            let _ = fd_entry.file.close().await;
        }
        let detached_ids: Vec<MountId> = sess.user_mounts.values().map(|u| u.mount_id).collect();
        for (_, um) in sess.user_mounts {
            let _ = sess.mnt_ns.borrow_mut().detach_subtree(um.mount_id);
        }
        {
            let mut rt = self.vfs_rt.borrow_mut();
            for mid in detached_ids {
                rt.evict_mount_execs(mid);
            }
        }
        drain_releases(&vfs);
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

        struct PendingMountGuard<'a> {
            rt: &'a RefCell<VfsRuntime>,
            sid: String,
            target: String,
            ns: Rc<RefCell<MountNamespace>>,
        }
        impl Drop for PendingMountGuard<'_> {
            fn drop(&mut self) {
                if let Ok(mut rt) = self.rt.try_borrow_mut()
                    && let Some(sess) = rt.sessions.get_mut(&self.sid)
                    && Rc::ptr_eq(&sess.mnt_ns, &self.ns)
                {
                    sess.pending_mounts.remove(&self.target);
                }
            }
        }

        let (vfs, sess_ns, uid, gid, sess_cred, tmp_seq) = {
            let mut rt = self.vfs_rt.borrow_mut();
            let seq = rt.alloc_tmp_id();
            let vfs = rt.vfs.clone();
            let sess = rt
                .sessions
                .get_mut(&session_id)
                .ok_or_else(|| vfs_js_err(Errno::ENOENT, "no active login session"))?;
            if sess.user_mounts.len() + sess.pending_mounts.len() >= MAX_USER_MOUNTS {
                return Err(vfs_js_err(
                    Errno::ENOSPC,
                    "maximum of 16 user mounts reached",
                ));
            }
            if sess.user_mounts.contains_key(&target_path)
                || sess.pending_mounts.contains(&target_path)
            {
                return Err(vfs_js_err(Errno::EBUSY, "mount point is already in use"));
            }
            sess.pending_mounts.insert(target_path.clone());
            (
                vfs,
                Rc::clone(&sess.mnt_ns),
                sess.uid,
                sess.gid,
                sess.cred(0o022),
                seq,
            )
        };
        let _pending_guard = PendingMountGuard {
            rt: &self.vfs_rt,
            sid: session_id.clone(),
            target: target_path.clone(),
            ns: sess_ns.clone(),
        };

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
            bool,
            Rc<ProviderState>,
            Option<LocalMount>,
        );
        let (
            backing,
            subroot,
            source_str,
            read_only,
            execute,
            nosymfollow,
            provider,
            local_mount,
        ): PreparedMount = match normalized_kind {
            "opfs" => {
                let lm = crate::hostfs::mount_opfs(host_obj, &grant_json).await?;
                let ro = lm.grant_info().read_only;
                let ex = lm.grant_info().execute;
                let b = lm.mount_backing(vfs::FsType::Opfs);
                let p = lm.provider_state();
                (b, None, format!("opfs:{clean_name}"), ro, ex, false, p, Some(lm))
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
                    false,
                    p,
                    Some(lm),
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
                    false,
                    p,
                    Some(lm),
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
                    true,
                    p,
                    Some(lm),
                )
            }
            "sharefs" => {
                let (b, root_h, p, ro, ex, nosymfollow) =
                    build_share_backing(host_obj, &format!("{session_id}:{tmp_seq}"))
                        .await
                        .map_err(map_errno)?;
                (
                    b,
                    Some((root_h, "/".to_string())),
                    format!("sharefs:{clean_name}"),
                    ro,
                    ex,
                    nosymfollow,
                    p,
                    None,
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
                    false,
                    p,
                    None,
                )
            }
            _ => unreachable!(),
        };

        // Re-check session existence & target slot after async provider setup (`MountBacking`
        // handles teardown automatically on drop if aborted).
        let scoped_pid = {
            let mut rt = self.vfs_rt.borrow_mut();
            let spid = rt.alloc_scoped_pid();
            let sess = rt
                .sessions
                .get(&session_id)
                .ok_or_else(|| vfs_js_err(Errno::ENOENT, "login session ended during mount"))?;
            if sess.user_mounts.len() >= MAX_USER_MOUNTS {
                return Err(vfs_js_err(
                    Errno::ENOSPC,
                    "maximum of 16 user mounts reached",
                ));
            }
            if sess.user_mounts.contains_key(&target_path) {
                return Err(vfs_js_err(Errno::EBUSY, "mount point is already in use"));
            }
            spid
        };

        // Ensure target directory `/mnt/local/<name>` / `/mnt/shared/<name>` / `/opt/private/<name>`
        // exists in `sess_ns` and is an actual directory (never follow a pre-existing symlink).
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
        let created_dir = mkdir_res.is_ok();
        if let Err(err) = mkdir_res {
            if err != Errno::EEXIST {
                let _ = vfs.exit_process(scoped_pid).await;
                return Err(map_errno(err));
            }
            let st_res = vfs
                .statat(scoped_pid, StartAnchor::Root, &target_path, false)
                .await;
            match st_res {
                Ok(st) if (st.mode & abi::S_IFMT) == abi::S_IFDIR => {}
                Ok(_) => {
                    let _ = vfs.exit_process(scoped_pid).await;
                    return Err(map_errno(Errno::ENOTDIR));
                }
                Err(se) => {
                    let _ = vfs.exit_process(scoped_pid).await;
                    return Err(map_errno(se));
                }
            }
        }

        let is_snapshot = normalized_kind == "snapshot";
        let mflags = MountFlags {
            rdonly: read_only && !is_snapshot,
            nosuid: true,
            nodev: true,
            noexec: !execute,
            nosymfollow,
            ..MountFlags::default()
        };
        let mut locked = mount_flags::MS_NOSUID | mount_flags::MS_NODEV;
        if read_only && !is_snapshot {
            locked |= mount_flags::MS_RDONLY;
        }
        if !execute {
            locked |= mount_flags::MS_NOEXEC;
        }
        if nosymfollow {
            locked |= mount_flags::MS_NOSYMFOLLOW;
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
            Ok(id) => {
                let _ = vfs.exit_process(scoped_pid).await;
                id
            }
            Err(err) => {
                if created_dir {
                    let _ = vfs
                        .unlinkat(scoped_pid, StartAnchor::Root, &target_path, true)
                        .await;
                }
                let _ = vfs.exit_process(scoped_pid).await;
                return Err(map_errno(err));
            }
        };

        let (generation, summary) = {
            let mut rt = self.vfs_rt.borrow_mut();
            if !rt.sessions.get(&session_id).is_some_and(|s| {
                Rc::ptr_eq(&s.mnt_ns, &sess_ns) && s.pending_mounts.contains(&target_path)
            }) || !sess_ns.borrow().contains_mount(mount_id)
            {
                let _ = sess_ns.borrow_mut().detach_subtree(mount_id);
                return Err(map_errno(Errno::ESTALE));
            }
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
                    "fsId": fs_id.0,
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
                        if let image::Node::File { sha256, size, .. } = &entry.node {
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
            if let image::Node::File { sha256, size, .. } = &entry.node {
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
                    image::Node::File {
                        sha256,
                        size,
                        chunk_size,
                        chunks,
                    } => ImageNodeKind::File {
                        blob_id: sha256,
                        size,
                        chunk_size: Some(chunk_size),
                        chunks,
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
        let (vfs, sess_ns, sess_cred, scoped_pid, expected) = {
            let mut rt = self.vfs_rt.borrow_mut();
            let spid = rt.alloc_scoped_pid();
            let vfs = rt.vfs.clone();
            let sess = rt
                .sessions
                .get(&session_id)
                .ok_or_else(|| vfs_js_err(Errno::ENOENT, "no active login session"))?;
            let expected = sess.user_mounts.get(&target).map(|m| m.mount_id);
            if (target.starts_with("/mnt/") || target.starts_with("/opt/private/"))
                && expected.is_none_or(|id| !sess.mnt_ns.borrow().contains_mount(id))
            {
                return Ok(());
            }
            (
                vfs,
                Rc::clone(&sess.mnt_ns),
                sess.cred(0o022),
                spid,
                expected,
            )
        };

        // Identify the topmost mount at `target` in `sess_ns`.
        let before_ids = Self::collect_mount_ids(&sess_ns);
        vfs.spawn_process(
            scoped_pid,
            INIT,
            sess_cred,
            Some(Rc::clone(&sess_ns)),
            None,
            None,
        )
        .map_err(map_errno)?;
        let umount_res = vfs
            .umount2_expected(scoped_pid, &target, clean, expected)
            .await;
        let _ = vfs.exit_process(scoped_pid).await;
        if let Err(e) = umount_res
            && expected.is_none_or(|id| sess_ns.borrow().contains_mount(id))
        {
            return Err(map_errno(e));
        }
        self.evict_detached_mount_ids(&sess_ns, before_ids);

        let (generation, cleanup_dir, removed_mid) = {
            let mut rt = self.vfs_rt.borrow_mut();
            let spid2 = rt.alloc_scoped_pid();
            let sess = rt
                .sessions
                .get_mut(&session_id)
                .ok_or_else(|| vfs_js_err(Errno::ENOENT, "no active login session"))?;
            if !Rc::ptr_eq(&sess_ns, &sess.mnt_ns)
                || sess.user_mounts.get(&target).map(|um| um.mount_id) != expected
            {
                return Ok(());
            }
            if let Some(um) = sess.user_mounts.remove(&target) {
                let scred2 = sess.cred(0o022);
                let sns2 = Rc::clone(&sess.mnt_ns);
                sess.generation = sess.generation.wrapping_add(1);
                (
                    sess.generation,
                    Some((spid2, scred2, sns2)),
                    Some(um.mount_id),
                )
            } else {
                sess.generation = sess.generation.wrapping_add(1);
                (sess.generation, None, None)
            }
        };
        if let Some(mid) = removed_mid {
            self.vfs_rt.borrow_mut().evict_mount_execs(mid);
        }
        if let Some((spid2, scred2, sns2)) = cleanup_dir
            && vfs
                .spawn_process(spid2, INIT, scred2, Some(sns2), None, None)
                .is_ok()
        {
            let _ = vfs.unlinkat(spid2, StartAnchor::Root, &target, true).await;
            let _ = vfs.exit_process(spid2).await;
        }
        drain_releases(&vfs);
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
                "baseline": baseline_mounts.contains(&MountId(mid))
                    || (um.is_none() && matches!(target.as_str(), "/dev/present" | "/dev/snd")),
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

    async fn resolve_page_creds(
        &self,
        vfs: &Vfs,
        session_id: &str,
        umask: u16,
        requested_sudo: bool,
    ) -> vfs::Result<(Rc<RefCell<MountNamespace>>, Cred, bool)> {
        if session_id.is_empty() {
            if requested_sudo {
                return Err(Errno::EPERM);
            }
            let guest = Identity::guest();
            let mut rt = self.vfs_rt.borrow_mut();
            rt.guest_page.get_or_insert_with(|| SessionVfs {
                epoch: Rc::new(()),
                session_id: String::new(),
                uid: guest.id,
                gid: guest.group,
                groups: guest.groups,
                mnt_ns: vfs.system_namespace(),
                baseline_mounts: BTreeSet::new(),
                generation: 0,
                user_mounts: BTreeMap::new(),
                pending_mounts: HashSet::new(),
                page_fds: HashMap::new(),
                delegated_uploads: HashMap::new(),
                next_page_fd: CLIENT_PAGE_FD_BASE,
            });
            return Ok((
                vfs.system_namespace(),
                Cred {
                    identity: Identity::guest(),
                    umask,
                    token: None,
                },
                false,
            ));
        }
        let (mnt_ns, mut cred, sess_uid, fs_session) = {
            let rt = self.vfs_rt.borrow();
            let sess = rt.sessions.get(session_id).ok_or(Errno::ENOENT)?;
            (
                Rc::clone(&sess.mnt_ns),
                sess.cred(umask),
                sess.uid,
                rt.root_cloud.current_fs_session(),
            )
        };
        if !requested_sudo {
            return Ok((mnt_ns, cred, false));
        }
        if installed("pageSysPost").is_ok() {
            let fs_sess_ref = fs_session.as_ref().map(|(s, k)| (s.as_str(), k.as_str()));
            let results = page_sys_batch_with_session(
                Batch {
                    calls: vec![Call::Getcreds],
                    umask: None,
                    sudo: true,
                    pid: None,
                    process: None,
                },
                fs_sess_ref,
            )
            .await?;
            let val = results
                .into_iter()
                .next()
                .ok_or(Errno::EPERM)?
                .into_result()
                .map_err(|e| {
                    if matches!(e.errno, Errno::EACCES | Errno::EPERM) {
                        Errno::EPERM
                    } else {
                        e.errno
                    }
                })?;
            let creds: Creds = serde_json::from_value(val).map_err(|_| Errno::EIO)?;
            if creds.uid != 0 {
                return Err(Errno::EPERM);
            }
            cred.identity = Identity::root();
            return Ok((mnt_ns, cred, true));
        }
        if sess_uid != 0 {
            return Err(Errno::EPERM);
        }
        cred.identity = Identity::root();
        Ok((mnt_ns, cred, true))
    }

    /// Execute a page `abi::Batch` (`POST /api/sys` filesystem calls from `Files` / `shell.rs` /
    /// `upload.mjs`) inside `session_id`'s `MountNamespace`.
    pub async fn vfs_sys(
        &self,
        session_id: String,
        batch_json: String,
        fd_epoch: Option<String>,
    ) -> Result<String, JsValue> {
        let batch: Batch = serde_json::from_str(&batch_json)
            .map_err(|e| vfs_js_err(Errno::EINVAL, e.to_string()))?;
        let umask = batch.umask.unwrap_or(0o022);
        let requested_sudo = batch.sudo;

        let (vfs, scoped_pid) = {
            let mut rt = self.vfs_rt.borrow_mut();
            let spid = rt.alloc_scoped_pid();
            (rt.vfs.clone(), spid)
        };
        let (mnt_ns, mut cred, effective_sudo) = self
            .resolve_page_creds(&vfs, &session_id, umask, requested_sudo)
            .await
            .map_err(map_errno)?;
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
            .with_page_scope(effective_sudo, async {
                let results = self
                    .execute_batch_on_pid(
                        &vfs,
                        scoped_pid,
                        Some(session_id.as_str()),
                        fd_epoch.as_deref(),
                        batch.calls,
                        effective_sudo,
                        batch.umask.is_none(),
                        cred.identity.id,
                        cred.umask,
                    )
                    .await;
                let _ = vfs.exit_process(scoped_pid).await;
                results
            })
            .await;
        serde_json::to_string(&abi::Results { results })
            .map_err(|e| vfs_js_err(Errno::EIO, e.to_string()))
    }

    /// Open a streaming read handle for page `/api/file?path=...`, probing size-0 virtual files
    /// (such as `/proc/*`) cleanly and validating HTTP `Range` bounds.
    pub async fn vfs_open_read(
        &self,
        session_id: String,
        path: String,
        range_start: Option<u64>,
        range_end: Option<u64>,
        head_only: bool,
    ) -> Result<JsValue, JsValue> {
        crate::cloudfs::clear_last_page_error();
        let (vfs, scoped_pid) = {
            let mut rt = self.vfs_rt.borrow_mut();
            (rt.vfs.clone(), rt.alloc_scoped_pid())
        };
        let (mnt_ns, cred, _) = self
            .resolve_page_creds(&vfs, &session_id, 0o022, false)
            .await
            .map_err(map_errno)?;

        let epoch = self
            .vfs_rt
            .borrow()
            .page_session(&session_id)
            .ok_or_else(|| map_errno(Errno::ESTALE))?
            .epoch
            .clone();
        vfs.spawn_process(scoped_pid, INIT, cred, Some(mnt_ns), None, None)
            .map_err(map_errno)?;
        enum OpenReadOut {
            Range416 {
                total_size: u64,
            },
            Inline {
                status: u16,
                total_size: u64,
                content_range: Option<String>,
                content_type: &'static str,
                bytes: Vec<u8>,
            },
            Stream {
                status: u16,
                total_size: u64,
                content_range: Option<String>,
                content_type: &'static str,
                file_ref: FileRef,
                offset: u64,
                remaining: u64,
            },
        }
        let content_type = content_type_for_path(&path);
        let out = self
            .with_page_scope(false, async {
                let res = async {
                    let (file_ref, entry) = vfs
                        .open_file(scoped_pid, StartAnchor::Root, &path, abi::O_RDONLY, 0)
                        .await?;
                    if !entry.metadata.is_file() {
                        let _ = file_ref.close().await;
                        return Err(if entry.metadata.is_dir() {
                            Errno::EISDIR
                        } else {
                            Errno::EACCES
                        });
                    }
                    let mut total_size = file_ref.metadata().await?.size;
                    if total_size == 0 {
                        // Virtual files (`/proc/*`, dynamic synthetic nodes) report size 0 until read.
                        let mut probe = vec![0u8; 64 * 1024];
                        let read = file_ref.read_at(&mut probe, 0).await;
                        let _ = file_ref.close().await;
                        let n = read?;
                        drain_releases(&vfs);
                        total_size = n as u64;
                        if total_size == 0 {
                            if range_start.is_some() {
                                return Ok(OpenReadOut::Range416 { total_size: 0 });
                            }
                            return Ok(OpenReadOut::Inline {
                                status: 200,
                                total_size: 0,
                                content_range: None,
                                content_type,
                                bytes: Vec::new(),
                            });
                        }
                        if let Some(start) = range_start {
                            let last = total_size - 1;
                            let end = range_end.unwrap_or(last).min(last);
                            if start >= total_size || start > end {
                                return Ok(OpenReadOut::Range416 { total_size });
                            }
                            let slice = if head_only {
                                Vec::new()
                            } else {
                                probe[start as usize..=(end as usize)].to_vec()
                            };
                            return Ok(OpenReadOut::Inline {
                                status: 206,
                                total_size,
                                content_range: Some(format!("bytes {start}-{end}/{total_size}")),
                                content_type,
                                bytes: slice,
                            });
                        }
                        return Ok(OpenReadOut::Inline {
                            status: 200,
                            total_size,
                            content_range: None,
                            content_type,
                            bytes: if head_only {
                                Vec::new()
                            } else {
                                probe[..n].to_vec()
                            },
                        });
                    }

                    let (status, start, remaining, content_range) = match range_start {
                        Some(start) => {
                            let last = total_size - 1;
                            let end = range_end.unwrap_or(last).min(last);
                            if start >= total_size || start > end {
                                let _ = file_ref.close().await;
                                drain_releases(&vfs);
                                return Ok(OpenReadOut::Range416 { total_size });
                            }
                            (
                                206u16,
                                start,
                                end - start + 1,
                                Some(format!("bytes {start}-{end}/{total_size}")),
                            )
                        }
                        None => (200u16, 0u64, total_size, None),
                    };
                    if head_only || remaining == 0 {
                        let _ = file_ref.close().await;
                        drain_releases(&vfs);
                        return Ok(OpenReadOut::Inline {
                            status,
                            total_size,
                            content_range,
                            content_type,
                            bytes: Vec::new(),
                        });
                    }
                    Ok(OpenReadOut::Stream {
                        status,
                        total_size,
                        content_range,
                        content_type,
                        file_ref,
                        offset: start,
                        remaining,
                    })
                }
                .await;
                let _ = vfs.exit_process(scoped_pid).await;
                res
            })
            .await
            .map_err(map_errno)?;

        let result_obj = js_sys::Object::new();
        match out {
            OpenReadOut::Range416 { total_size } => {
                let _ =
                    js_sys::Reflect::set(&result_obj, &"status".into(), &JsValue::from_f64(416.0));
                let _ = js_sys::Reflect::set(
                    &result_obj,
                    &"totalSize".into(),
                    &JsValue::from_f64(total_size as f64),
                );
            }
            OpenReadOut::Inline {
                status,
                total_size,
                content_range,
                content_type,
                bytes,
            } => {
                let _ = js_sys::Reflect::set(
                    &result_obj,
                    &"status".into(),
                    &JsValue::from_f64(f64::from(status)),
                );
                let _ = js_sys::Reflect::set(
                    &result_obj,
                    &"totalSize".into(),
                    &JsValue::from_f64(total_size as f64),
                );
                if let Some(cr) = content_range {
                    let _ = js_sys::Reflect::set(&result_obj, &"contentRange".into(), &cr.into());
                }
                let _ =
                    js_sys::Reflect::set(&result_obj, &"contentType".into(), &content_type.into());
                let _ = js_sys::Reflect::set(
                    &result_obj,
                    &"inlineBytes".into(),
                    &js_sys::Uint8Array::from(bytes.as_slice()).into(),
                );
            }
            OpenReadOut::Stream {
                status,
                total_size,
                content_range,
                content_type,
                file_ref,
                offset,
                remaining,
            } => {
                let alloc_stream = {
                    let mut rt = self.vfs_rt.borrow_mut();
                    if !rt
                        .page_session(&session_id)
                        .is_some_and(|s| Rc::ptr_eq(&s.epoch, &epoch))
                    {
                        Err(Errno::EBADF)
                    } else if rt.read_streams.len() >= READ_STREAM_MAX {
                        Err(Errno::EMFILE)
                    } else {
                        let mut id = rt.next_read_stream;
                        while id == 0 || rt.read_streams.contains_key(&id) {
                            id = id.wrapping_add(1).max(1);
                        }
                        rt.next_read_stream = id.wrapping_add(1).max(1);
                        rt.read_streams.insert(
                            id,
                            ReadStreamEntry {
                                session_id,
                                file: file_ref.clone(),
                                offset,
                                remaining,
                            },
                        );
                        Ok(id)
                    }
                };
                let stream_id = match alloc_stream {
                    Ok(id) => id,
                    Err(Errno::EBADF) => {
                        file_ref.close().await.map_err(map_errno)?;
                        return Err(map_errno(Errno::EBADF));
                    }
                    Err(err) => {
                        let _ = file_ref.close().await;
                        return Err(map_errno(err));
                    }
                };
                let _ = js_sys::Reflect::set(
                    &result_obj,
                    &"status".into(),
                    &JsValue::from_f64(f64::from(status)),
                );
                let _ = js_sys::Reflect::set(
                    &result_obj,
                    &"totalSize".into(),
                    &JsValue::from_f64(total_size as f64),
                );
                if let Some(cr) = content_range {
                    let _ = js_sys::Reflect::set(&result_obj, &"contentRange".into(), &cr.into());
                }
                let _ =
                    js_sys::Reflect::set(&result_obj, &"contentType".into(), &content_type.into());
                let _ = js_sys::Reflect::set(
                    &result_obj,
                    &"streamId".into(),
                    &JsValue::from_f64(f64::from(stream_id)),
                );
            }
        }
        Ok(result_obj.into())
    }

    pub async fn vfs_read_stream_chunk(
        &self,
        session_id: String,
        stream_id: u32,
        max_bytes: Option<u32>,
    ) -> Result<Vec<u8>, JsValue> {
        let (file, offset, remaining) = {
            let rt = self.vfs_rt.borrow();
            let entry = rt
                .read_streams
                .get(&stream_id)
                .filter(|e| e.session_id == session_id)
                .ok_or_else(|| map_errno(Errno::EBADF))?;
            (entry.file.clone(), entry.offset, entry.remaining)
        };
        if remaining == 0 {
            self.vfs_close_read_stream(session_id, stream_id).await?;
            return Ok(Vec::new());
        }
        let max_req = (max_bytes.unwrap_or(256 * 1024) as usize).clamp(1, 4 * 1024 * 1024);
        let to_read = remaining.min(max_req as u64) as usize;
        let mut buf = vec![0u8; to_read];
        let res = self
            .with_page_scope(false, file.read_at(&mut buf, offset))
            .await;
        match res {
            Ok(0) => {
                let _ = self.vfs_close_read_stream(session_id, stream_id).await;
                Ok(Vec::new())
            }
            Ok(n) => {
                buf.truncate(n);
                let mut rt = self.vfs_rt.borrow_mut();
                {
                    let entry = rt
                        .read_streams
                        .get_mut(&stream_id)
                        .filter(|e| {
                            e.session_id == session_id && e.file.ptr_eq(&file) && e.offset == offset
                        })
                        .ok_or_else(|| map_errno(Errno::EBADF))?;
                    entry.offset = entry.offset.saturating_add(n as u64);
                    entry.remaining = entry.remaining.saturating_sub(n as u64);
                }
                Ok(buf)
            }
            Err(err) => {
                let _ = self.vfs_close_read_stream(session_id, stream_id).await;
                Err(map_errno(err))
            }
        }
    }

    pub async fn vfs_close_read_stream(
        &self,
        session_id: String,
        stream_id: u32,
    ) -> Result<(), JsValue> {
        let removed = {
            let mut rt = self.vfs_rt.borrow_mut();
            if rt
                .read_streams
                .get(&stream_id)
                .is_some_and(|e| e.session_id != session_id)
            {
                return Err(map_errno(Errno::EBADF));
            }
            rt.read_streams.remove(&stream_id)
        };
        if let Some(entry) = removed {
            let _ = self.with_page_scope(false, entry.file.close()).await;
        }
        Ok(())
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
        chunk_index: Option<u64>,
    ) -> Result<JsValue, JsValue> {
        crate::cloudfs::clear_last_page_error();
        let (entry, cred) = {
            let rt = self.vfs_rt.borrow();
            let sess = rt
                .page_session(&session_id)
                .ok_or_else(|| map_errno(Errno::EBADF))?;
            let entry = sess
                .page_fds
                .get(&fd)
                .ok_or_else(|| map_errno(Errno::EBADF))?;
            (entry.clone(), sess.cred(0o022))
        };
        let offset = match chunk_index {
            Some(idx) => idx
                .checked_mul(entry.chunk_size)
                .ok_or_else(|| map_errno(Errno::EFBIG))?,
            None => offset,
        };
        let written = self
            .with_page_scope(false, entry.write(&cred, bytes, offset))
            .await
            .map_err(map_errno)?;
        json_to_js(&json!({ "written": written }))
    }

    pub async fn vfs_fstat_fd(&self, session_id: String, fd: u32) -> Result<JsValue, JsValue> {
        let (file_ref, cred) = {
            let rt = self.vfs_rt.borrow();
            let sess = rt
                .page_session(&session_id)
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
                .page_session(&session_id)
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
        let entry = self
            .vfs_rt
            .borrow()
            .page_session(&session_id)
            .and_then(|s| s.page_fds.get(&fd))
            .cloned()
            .ok_or_else(|| map_errno(Errno::EBADF))?;
        let mut progress = match &entry.digest {
            Some(digest) => Some(digest.sequential.lock().await),
            None => None,
        };
        self.with_page_scope(false, entry.file.set_len(size))
            .await
            .map_err(map_errno)?;
        if let Some(state) = progress.as_deref_mut() {
            if size == 0 {
                *state = Some((0, Sha256::new()));
            } else if state.as_ref().is_none_or(|(n, _)| *n != size) {
                *state = None;
            }
        }
        Ok(())
    }

    // =========================================================================
    // 2. Process Lifecycle & Service MountNamespaceGrant Instantiation
    // =========================================================================

    pub async fn proc_spawn_init(&self, opts_json: String) -> Result<JsValue, JsValue> {
        let opts: ProcSpawnInitOpts = serde_json::from_str(&opts_json)
            .map_err(|e| vfs_js_err(Errno::EINVAL, e.to_string()))?;

        if opts.service_grant.is_some() && opts.parent_pid.is_some() {
            return Err(map_errno(Errno::EPERM));
        }
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
                    ProcessVfsMeta::with_cred(
                        opts.session_id.clone().or(psess.clone()),
                        opts.cloud_access,
                        cred.clone(),
                    ),
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
                self.with_proc_scope_retry(opts.pid, || vfs.chdir(opts.pid, cwd))
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
                let (ns, sid) = resolve_service_namespace_locked(
                    &vfs,
                    &rt.sessions,
                    grant,
                    opts.uid,
                    opts.parent_pid,
                    opts.session_id.as_deref(),
                )?;
                (vfs, rc, ns, sid)
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
            let mut bind_cred = cred.clone();
            if opts.uid == 0 {
                bind_cred = Cred::root();
            }
            let _ = vfs.set_cred(opts.pid, bind_cred);
            for bm in &grant.bind_mounts {
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
            }
            let _ = vfs.set_cred(opts.pid, cred.clone());
        }

        if let Some(cwd) = &opts.cwd
            && !cwd.is_empty()
            && cwd != "/"
            && let Err(err) = self
                .with_proc_scope_retry(opts.pid, || vfs.chdir(opts.pid, cwd))
                .await
        {
            let _ = self
                .with_proc_scope(opts.pid, async { vfs.exit_process(opts.pid).await })
                .await;
            root_cloud.set_cloud_access(opts.pid, true);
            return Err(map_errno(err));
        }

        let live_cred = self
            .state
            .borrow()
            .table
            .proc(opts.pid)
            .map(|p| Cred {
                identity: p.cred.identity.clone(),
                umask: opts.umask,
                token: p.cred.remote.as_ref().map(|r| r.token.clone()),
            })
            .unwrap_or(cred);
        {
            let mut rt = self.vfs_rt.borrow_mut();
            rt.proc_meta.insert(
                opts.pid,
                ProcessVfsMeta::with_cred(resolved_sess, opts.cloud_access, live_cred),
            );
        }
        let ns_id = base_ns.borrow().id().0;
        json_to_js(&json!({ "pid": opts.pid, "nsId": ns_id }))
    }

    pub fn proc_authorize_service_grant(&self, pid: u32) -> Result<(), JsValue> {
        let rt = self.vfs_rt.borrow();
        let parent = rt
            .proc_meta
            .get(&pid)
            .ok_or_else(|| map_errno(Errno::EPERM))?;
        if !parent.supervisor
            || parent
                .login_session
                .as_ref()
                .is_some_and(|s| !rt.sessions.contains_key(s))
        {
            return Err(map_errno(Errno::EPERM));
        }
        let ctx = rt.vfs.process_fs_context(pid).map_err(map_errno)?;
        let ns = rt.vfs.process_namespace(pid).map_err(map_errno)?;
        if !ctx.borrow().root.same_anchor(&ns.borrow().root_anchor()) {
            return Err(map_errno(Errno::EPERM));
        }
        Ok(())
    }

    pub async fn proc_apply_service_grant(
        &self,
        pid: u32,
        parent_pid: u32,
        grant_json: String,
    ) -> Result<JsValue, JsValue> {
        let grant: ServiceGrantSpec = serde_json::from_str(&grant_json)
            .map_err(|e| vfs_js_err(Errno::EINVAL, e.to_string()))?;
        let (vfs, cred, base_ns, resolved_sess) = {
            let rt = self.vfs_rt.borrow();
            let parent = rt
                .proc_meta
                .get(&parent_pid)
                .ok_or_else(|| map_errno(Errno::EPERM))?;
            self.proc_authorize_service_grant(parent_pid)?;
            rt.vfs
                .check_service_child(parent_pid, pid)
                .map_err(map_errno)?;
            let child = rt
                .proc_meta
                .get(&pid)
                .ok_or_else(|| map_errno(Errno::ESRCH))?;
            if parent.cred.identity.id != 0
                && (child.cred.identity.id != parent.cred.identity.id
                    || child.login_session != parent.login_session
                    || grant.mount_namespace == "system")
            {
                return Err(map_errno(Errno::EPERM));
            }
            let (ns, session) = resolve_service_namespace_locked(
                &rt.vfs,
                &rt.sessions,
                &grant,
                child.cred.identity.id,
                Some(parent_pid),
                parent.login_session.as_deref(),
            )?;
            (rt.vfs.clone(), child.cred.clone(), ns, session)
        };
        for bind in &grant.bind_mounts {
            self.with_proc_scope(pid, apply_service_bind(&vfs, &base_ns, &cred, bind))
                .await
                .map_err(map_errno)?;
        }
        self.proc_authorize_service_grant(parent_pid)?;
        let mut rt = self.vfs_rt.borrow_mut();
        let child = rt
            .proc_meta
            .get(&pid)
            .ok_or_else(|| map_errno(Errno::ESRCH))?;
        if child.cred.identity.id != cred.identity.id
            || child.cred.identity.group != cred.identity.group
            || child.cred.identity.groups != cred.identity.groups
        {
            return Err(map_errno(Errno::EPERM));
        }
        vfs.install_service_namespace(parent_pid, pid, Rc::clone(&base_ns))
            .map_err(map_errno)?;
        rt.proc_meta
            .get_mut(&pid)
            .ok_or_else(|| map_errno(Errno::ESRCH))?
            .session_id = resolved_sess;
        let ns_id = base_ns.borrow().id().0;
        json_to_js(&json!({ "pid": pid, "nsId": ns_id }))
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
                supervisor: false,
                login_session: m.login_session.clone(),
                session_id: m.session_id.clone(),
                cloud_access: m.cloud_access,
                cred: m.cred.clone(),
                server_fds: m
                    .server_fds
                    .iter()
                    .filter(|(_, e)| !e.closing)
                    .map(|(&fd, e)| (fd, e.clone()))
                    .collect(),
                next_server_fd: m.next_server_fd,
                attenuated_kfds: m.attenuated_kfds.clone(),
            });
            (rt.vfs.clone(), Rc::clone(&rt.root_cloud), meta)
        };
        vfs.fork_process(parent_pid, child_pid, clone_flags)
            .map_err(map_errno)?;
        if let Some(meta) = parent_meta {
            let parent_usr_denied = root_cloud.is_pid_cloud_denied(parent_pid);
            root_cloud.set_cloud_access(child_pid, !parent_usr_denied);
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
        self.with_proc_scope(pid, {
            let vfs = vfs.clone();
            async move { vfs.exec_preserve(pid).await }
        })
        .await
        .map_err(map_errno)?;
        if let Ok(fds) = vfs.process_fds(pid) {
            let table = fds.borrow();
            if let Some(meta) = self.vfs_rt.borrow_mut().proc_meta.get_mut(&pid) {
                meta.attenuated_kfds
                    .retain(|&kfd, _| table.get(kfd).is_ok());
            }
        }
        self.close_server_descriptors(pid, true)
            .await
            .map_err(map_errno)
    }

    /// Strip `pid`'s remote cloud token & `proc_meta.cloud_access` in `Vfs` on `LoginAction::End`
    /// without revoking its local `/usr` system image exec grant so shutdown traps can still run
    /// local utilities while being completely blocked from remote cloud access or token minting.
    pub(crate) fn proc_revoke_remote_creds(
        &self,
        pid: u32,
        uid: u32,
        gid: u32,
        groups: Vec<u32>,
    ) -> Result<(), JsValue> {
        let (vfs, old_umask) = {
            let mut rt = self.vfs_rt.borrow_mut();
            if let Some(meta) = rt.proc_meta.get_mut(&pid) {
                meta.cloud_access = false;
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
        let cred = Cred {
            identity: Identity {
                id: uid,
                group: gid,
                groups: gset,
            },
            umask: old_umask,
            token: None,
        };
        vfs.set_cred(pid, cred.clone()).map_err(map_errno)?;
        if let Some(meta) = self.vfs_rt.borrow_mut().proc_meta.get_mut(&pid) {
            meta.cred = cred;
        }
        Ok(())
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
                if meta.cred.identity.id != uid {
                    meta.supervisor = false;
                }
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
        let new_cred = Cred {
            identity: Identity {
                id: uid,
                group: gid,
                groups: gset,
            },
            umask: old_umask,
            token,
        };
        if let Some(meta) = self.vfs_rt.borrow_mut().proc_meta.get_mut(&pid) {
            meta.cred = new_cred.clone();
        }
        vfs.set_cred(pid, new_cred).map_err(map_errno)
    }

    pub fn proc_set_umask(&self, pid: u32, umask: u16) -> Result<u16, JsValue> {
        let vfs = self.vfs_rt.borrow().vfs.clone();
        vfs.set_umask(pid, umask).map_err(map_errno)
    }

    pub async fn proc_close_server_fds(&self, pid: u32) {
        self.close_process_server_fds(pid).await;
    }

    pub async fn proc_exit(&self, pid: u32) -> Result<(), JsValue> {
        self.close_process_server_fds(pid).await;
        let (vfs, root_cloud, waits, unix_sock) = {
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
            (
                rt.vfs.clone(),
                Rc::clone(&rt.root_cloud),
                waits,
                Rc::clone(&rt.unix_sock),
            )
        };
        let sock_cleanup = unix_sock.borrow_mut().release_process(pid);
        self.record_unix_sock_cleanup(sock_cleanup).await;
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
        self.with_proc_scope_retry(pid, || {
            let vfs = vfs.clone();
            let path = path.clone();
            async move { vfs.chdir(pid, &path).await }
        })
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
        self.with_proc_scope_retry(pid, || {
            let vfs = vfs.clone();
            let path = path.clone();
            async move { vfs.chroot(pid, &path).await }
        })
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
        let ns = vfs.process_namespace(pid).map_err(map_errno)?;
        let ns_id = ns.borrow().id();
        let before_ids = Self::collect_mount_ids(&ns);
        self.with_proc_scope(pid, async move { vfs.umount2(pid, &target, flags).await })
            .await
            .map_err(map_errno)?;
        self.evict_detached_mount_ids(&ns, before_ids);
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
            .with_proc_scope_retry(pid, || {
                let vfs = vfs.clone();
                let anchor = anchor.clone();
                let path = path.clone();
                async move { vfs.statfs(pid, anchor, &path).await }
            })
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
        vfs.setns(pid, kfd, nstype as u32).map_err(map_errno)?;
        if (nstype == 0 || (nstype as u32 & unshare_flags::CLONE_NEWNS) != 0)
            && let Some(meta) = self.vfs_rt.borrow_mut().proc_meta.get_mut(&pid)
        {
            meta.session_id = None;
        }
        Ok(())
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
        let (vfs, root_cloud) = {
            let rt = self.vfs_rt.borrow();
            (rt.vfs.clone(), Rc::clone(&rt.root_cloud))
        };
        let cloexec = cloexec.unwrap_or(false) || (oflags & vfs::vfs::O_CLOEXEC != 0);
        let pass_flags = if (oflags & abi::O_PATH) != 0 && (oflags & abi::O_NOFOLLOW) != 0 {
            oflags & !abi::O_DIRECTORY
        } else {
            oflags
        };
        enum OpenOutcome {
            Kfd {
                kfd: u32,
                stat: abi::Stat,
                entry_meta: vfs::Metadata,
                is_ns: bool,
                pin_fstype: Option<vfs::FsType>,
            },
            ServerDev {
                canonical_dev: String,
                stat: abi::Stat,
                device: Option<String>,
            },
        }
        let outcome = self
            .with_proc_scope_retry(pid, || {
                let vfs = vfs.clone();
                let root_cloud = Rc::clone(&root_cloud);
                let anchor = anchor.clone();
                let path = path.clone();
                async move {
                    let (file_ref, entry) =
                        vfs.open_file(pid, anchor, &path, pass_flags, mode).await?;
                    if (oflags & abi::O_DIRECTORY) != 0 && !entry.metadata.is_dir() {
                        let _ = file_ref.close().await;
                        drain_releases(&vfs);
                        return Err(Errno::ENOTDIR);
                    }
                    let mut st =
                        vfs::stat::stat(&entry.handle.fs, entry.handle.node, &entry.metadata);
                    if (oflags & abi::O_PATH) == 0
                        && entry.metadata.file_type == FileType::CharDevice
                        && let Some(rdev) = &entry.metadata.rdev
                        && let Some(canonical_dev) =
                            canonical_server_dev_path(&root_cloud, &entry.handle, rdev)
                    {
                        let device = Some(rdev.clone());
                        let _ = file_ref.close().await;
                        drain_releases(&vfs);
                        return Ok(OpenOutcome::ServerDev {
                            canonical_dev,
                            stat: st,
                            device,
                        });
                    }
                    let is_ns = file_ref.mount_ns().is_some();
                    let fstype = file_ref.mount_pin().map(|p| p.fstype());
                    let fds = vfs.process_fds(pid)?;
                    let insert_res = fds.borrow_mut().insert(file_ref, cloexec);
                    let fd = match insert_res {
                        Ok(fd) => fd,
                        Err(e) => {
                            drain_releases(&vfs);
                            return Err(e);
                        }
                    };
                    st = vfs::stat::stat(&entry.handle.fs, entry.handle.node, &entry.metadata);
                    Ok::<_, Errno>(OpenOutcome::Kfd {
                        kfd: fd,
                        stat: st,
                        entry_meta: entry.metadata,
                        is_ns,
                        pin_fstype: fstype,
                    })
                }
            })
            .await
            .map_err(map_errno)?;

        match outcome {
            OpenOutcome::ServerDev {
                canonical_dev,
                mut stat,
                device,
            } => {
                let vfs_for_names = self.vfs_rt.borrow().vfs.clone();
                self.fill_stat_names(&vfs_for_names, pid, &mut stat).await;
                let (vfd, _) = self
                    .open_server_device_fd(
                        pid,
                        false,
                        canonical_dev,
                        oflags,
                        mode,
                        cloexec,
                        None,
                        None,
                        None,
                    )
                    .await
                    .map_err(|e| vfs_js_err(e.errno, e.detail.unwrap_or_default()))?;
                json_to_js(&json!({
                    "fd": vfd,
                    "kfd": vfd,
                    "serverDev": true,
                    "stat": stat,
                    "isDir": false,
                    "mountNs": false,
                    "device": device,
                    "fstype": "devtmpfs",
                }))
            }
            OpenOutcome::Kfd {
                kfd,
                mut stat,
                entry_meta,
                is_ns,
                pin_fstype,
            } => {
                if let Some(meta) = self.vfs_rt.borrow_mut().proc_meta.get_mut(&pid) {
                    meta.attenuated_kfds.remove(&kfd);
                }
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
                    "serverDev": false,
                    "stat": stat,
                    "isDir": entry_meta.is_dir(),
                    "mountNs": is_ns,
                    "device": device,
                    "fstype": pin_fstype.map(|f| f.as_str()),
                }))
            }
        }
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
            .with_proc_scope_retry(pid, || {
                let vfs = vfs.clone();
                let anchor = anchor.clone();
                let path = path.clone();
                async move {
                    let mut st = vfs.statat(pid, anchor.clone(), &path, follow).await?;
                    if !follow
                        && st.link.is_none()
                        && (st.mode & abi::S_IFMT) == abi::S_IFLNK
                        && let Ok(target) = vfs.readlinkat(pid, anchor, &path).await
                    {
                        st.link = Some(target);
                    }
                    Ok(st)
                }
            })
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
        self.with_proc_scope_retry(pid, || {
            let vfs = vfs.clone();
            let anchor = anchor.clone();
            let path = path.clone();
            async move { vfs.accessat(pid, anchor, &path, mode, follow).await }
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
        self.with_proc_scope_retry(pid, || {
            let vfs = vfs.clone();
            let anchor = anchor.clone();
            let path = path.clone();
            async move { vfs.mkdirat(pid, anchor, &path, mode).await }
        })
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
        self.with_proc_scope_retry(pid, || {
            let vfs = vfs.clone();
            let anchor = anchor.clone();
            let path = path.clone();
            let rdev_str = rdev_str.clone();
            async move { vfs.mknodat(pid, anchor, &path, mode, &rdev_str).await }
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
        self.with_proc_scope_retry(pid, || {
            let vfs = vfs.clone();
            let anchor = anchor.clone();
            let path = path.clone();
            async move { vfs.unlinkat(pid, anchor, &path, dir).await }
        })
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
        self.with_proc_scope_retry(pid, || {
            let vfs = vfs.clone();
            let from_anchor = from_anchor.clone();
            let to_anchor = to_anchor.clone();
            let old_path = old_path.clone();
            let new_path = new_path.clone();
            async move {
                vfs.renameat(pid, from_anchor, &old_path, to_anchor, &new_path, flags)
                    .await
            }
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
        self.with_proc_scope_retry(pid, || {
            let vfs = vfs.clone();
            let from_anchor = from_anchor.clone();
            let to_anchor = to_anchor.clone();
            let old_path = old_path.clone();
            let new_path = new_path.clone();
            async move {
                vfs.linkat(pid, from_anchor, &old_path, to_anchor, &new_path, follow)
                    .await
            }
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
        self.with_proc_scope_retry(pid, || {
            let vfs = vfs.clone();
            let target = target.clone();
            let anchor = anchor.clone();
            let link_path = link_path.clone();
            async move { vfs.symlinkat(pid, &target, anchor, &link_path).await }
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
        self.with_proc_scope_retry(pid, || {
            let vfs = vfs.clone();
            let anchor = anchor.clone();
            let path = path.clone();
            async move { vfs.readlinkat(pid, anchor, &path).await }
        })
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
        self.with_proc_scope_retry(pid, || {
            let vfs = vfs.clone();
            let anchor = anchor.clone();
            let path = path.clone();
            async move {
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
            }
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
        let before_uid = self
            .state
            .borrow()
            .table
            .proc(pid)
            .map(|p| p.cred.identity.id);
        let results = self
            .with_proc_scope(
                pid,
                self.execute_batch_on_pid(
                    &vfs,
                    pid,
                    None,
                    None,
                    batch.calls,
                    false,
                    false,
                    0,
                    0o022,
                ),
            )
            .await;
        let after_uid = self
            .state
            .borrow()
            .table
            .proc(pid)
            .map(|p| p.cred.identity.id);
        if after_uid != before_uid {
            self.sync_vfs_proc_creds(pid);
        }
        serde_json::to_string(&abi::Results { results })
            .map_err(|e| vfs_js_err(Errno::EIO, e.to_string()))
    }

    pub async fn kfd_read(&self, pid: u32, kfd: u32, len: u32) -> Result<Vec<u8>, JsValue> {
        let scope_pid = self.scope_pid_for_kfd(pid, kfd).map_err(map_errno)?;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let cap = (len as usize).min(abi::remote_fs::DATA_MAX as usize);
        let mut buf = vec![0u8; cap];
        let n = self
            .with_proc_scope(scope_pid, async { vfs.read(pid, kfd, &mut buf).await })
            .await
            .map_err(map_errno)?;
        buf.truncate(n);
        Ok(buf)
    }

    pub async fn kfd_write(&self, pid: u32, kfd: u32, data: &[u8]) -> Result<u32, JsValue> {
        let scope_pid = self.scope_pid_for_kfd(pid, kfd).map_err(map_errno)?;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let n = self
            .with_proc_scope(scope_pid, async { vfs.write(pid, kfd, data).await })
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
        let scope_pid = self.scope_pid_for_kfd(pid, kfd).map_err(map_errno)?;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let cap = (len as usize).min(abi::remote_fs::DATA_MAX as usize);
        let mut buf = vec![0u8; cap];
        let n = self
            .with_proc_scope(scope_pid, async {
                vfs.pread(pid, kfd, &mut buf, offset).await
            })
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
        let scope_pid = self.scope_pid_for_kfd(pid, kfd).map_err(map_errno)?;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let n = self
            .with_proc_scope(scope_pid, async {
                vfs.pwrite(pid, kfd, data, offset).await
            })
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
        let scope_pid = self.scope_pid_for_kfd(pid, kfd).map_err(map_errno)?;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        self.with_proc_scope(scope_pid, async move { vfs.lseek(pid, kfd, from).await })
            .await
            .map_err(map_errno)
    }

    pub async fn kfd_readdir(&self, pid: u32, kfd: u32) -> Result<JsValue, JsValue> {
        let scope_pid = self.scope_pid_for_kfd(pid, kfd).map_err(map_errno)?;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let entries = self
            .with_proc_scope(scope_pid, async move { vfs.fd_readdir(pid, kfd).await })
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
                        FileType::Socket => "socket",
                        FileType::File => "file",
                    },
                })
            })
            .collect();
        json_to_js(&Value::Array(out))
    }

    pub async fn kfd_fstat(&self, pid: u32, kfd: u32) -> Result<JsValue, JsValue> {
        let scope_pid = self.scope_pid_for_kfd(pid, kfd).map_err(map_errno)?;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let mut st = self
            .with_proc_scope(scope_pid, async move { vfs.fstat(pid, kfd).await })
            .await
            .map_err(map_errno)?;
        let vfs_for_names = self.vfs_rt.borrow().vfs.clone();
        self.fill_stat_names(&vfs_for_names, pid, &mut st).await;
        json_to_js(&json!(st))
    }

    pub async fn kfd_ftruncate(&self, pid: u32, kfd: u32, size: u64) -> Result<(), JsValue> {
        let scope_pid = self.scope_pid_for_kfd(pid, kfd).map_err(map_errno)?;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        self.with_proc_scope(
            scope_pid,
            async move { vfs.ftruncate(pid, kfd, size).await },
        )
        .await
        .map_err(map_errno)
    }

    pub async fn kfd_futimens(
        &self,
        pid: u32,
        kfd: u32,
        atime_json: String,
        mtime_json: String,
    ) -> Result<(), JsValue> {
        let atime: Time = serde_json::from_str(&atime_json)
            .map_err(|e| vfs_js_err(Errno::EINVAL, e.to_string()))?;
        let mtime: Time = serde_json::from_str(&mtime_json)
            .map_err(|e| vfs_js_err(Errno::EINVAL, e.to_string()))?;
        let scope_pid = self.scope_pid_for_kfd(pid, kfd).map_err(map_errno)?;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        self.with_proc_scope(scope_pid, async move {
            vfs.fsetattr(
                pid,
                kfd,
                &SetAttr {
                    atime,
                    mtime,
                    ..SetAttr::default()
                },
            )
            .await
        })
        .await
        .map(|_| ())
        .map_err(map_errno)
    }

    pub async fn kfd_fsync(&self, pid: u32, kfd: u32, data_only: bool) -> Result<(), JsValue> {
        let scope_pid = self.scope_pid_for_kfd(pid, kfd).map_err(map_errno)?;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        self.with_proc_scope(scope_pid, async move {
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
        let scope_pid = self.scope_pid_for_kfd(pid, kfd).map_err(map_errno)?;
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
            .with_proc_scope(scope_pid, async move {
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
        let scope_pid = self.scope_pid_for_kfd(pid, kfd).map_err(map_errno)?;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        self.with_proc_scope(scope_pid, async move {
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
        let scope_pid = self.scope_pid_for_kfd(pid, kfd).map_err(map_errno)?;
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let conflict = self
            .with_proc_scope(scope_pid, async move {
                let fds = vfs.process_fds(pid)?;
                let file = fds.borrow().get(kfd)?;
                file.test_lock(lk, range).await
            })
            .await
            .map_err(map_errno)?;
        json_to_js(&json!(conflict))
    }

    pub fn kfd_dup(&self, pid: u32, kfd: u32) -> Result<u32, JsValue> {
        if (SERVER_DEV_FD_BASE..CLIENT_PAGE_FD_BASE).contains(&kfd) {
            let mut rt = self.vfs_rt.borrow_mut();
            let meta = rt
                .proc_meta
                .get_mut(&pid)
                .ok_or_else(|| map_errno(Errno::ESRCH))?;
            let (sfd, attenuated_token) = {
                let entry = meta
                    .server_fds
                    .get(&kfd)
                    .filter(|e| !e.closing)
                    .ok_or_else(|| map_errno(Errno::EBADF))?;
                (entry.sfd.clone(), entry.attenuated_token.clone())
            };
            return meta
                .alloc_server_fd_with_attenuation(sfd, false, attenuated_token)
                .map_err(map_errno);
        }
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let new_kfd = vfs.dup(pid, kfd, 0, false).map_err(map_errno)?;
        if let Some(meta) = self.vfs_rt.borrow_mut().proc_meta.get_mut(&pid) {
            if let Some(att) = meta.attenuated_kfds.get(&kfd).cloned() {
                meta.attenuated_kfds.insert(new_kfd, att);
            } else {
                meta.attenuated_kfds.remove(&new_kfd);
            }
        }
        Ok(new_kfd)
    }

    pub async fn kfd_dup2(&self, pid: u32, old_kfd: u32, new_kfd: u32) -> Result<u32, JsValue> {
        let old_is_server = (SERVER_DEV_FD_BASE..CLIENT_PAGE_FD_BASE).contains(&old_kfd);
        let new_is_server = (SERVER_DEV_FD_BASE..CLIENT_PAGE_FD_BASE).contains(&new_kfd);
        if old_is_server || new_is_server {
            if !old_is_server || !new_is_server {
                return Err(map_errno(Errno::EBADF));
            }
            let (sfd, attenuated_token) = {
                let rt = self.vfs_rt.borrow();
                let meta = rt
                    .proc_meta
                    .get(&pid)
                    .ok_or_else(|| map_errno(Errno::ESRCH))?;
                let entry = meta
                    .server_fds
                    .get(&old_kfd)
                    .filter(|e| !e.closing)
                    .ok_or_else(|| map_errno(Errno::EBADF))?;
                (entry.sfd.clone(), entry.attenuated_token.clone())
            };
            if old_kfd == new_kfd {
                return Ok(new_kfd);
            }
            let target_occupied = self
                .vfs_rt
                .borrow()
                .proc_meta
                .get(&pid)
                .is_some_and(|m| m.server_fds.contains_key(&new_kfd));
            if target_occupied {
                // POSIX dup2 ignores errors when closing the replaced target descriptor.
                let _ = self.release_server_fd(pid, new_kfd, false).await;
            }
            let mut rt = self.vfs_rt.borrow_mut();
            let meta = rt
                .proc_meta
                .get_mut(&pid)
                .ok_or_else(|| map_errno(Errno::ESRCH))?;
            if !meta.server_fds.contains_key(&new_kfd) && meta.server_fds.len() >= 1024 {
                return Err(map_errno(Errno::EMFILE));
            }
            meta.server_fds.insert(
                new_kfd,
                ServerFdEntry {
                    sfd,
                    cloexec: false,
                    closing: false,
                    attenuated_token,
                },
            );
            return Ok(new_kfd);
        }
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let res = vfs.dup2(pid, old_kfd, new_kfd).await.map_err(map_errno)?;
        if old_kfd != res
            && let Some(meta) = self.vfs_rt.borrow_mut().proc_meta.get_mut(&pid)
        {
            if let Some(att) = meta.attenuated_kfds.get(&old_kfd).cloned() {
                meta.attenuated_kfds.insert(res, att);
            } else {
                meta.attenuated_kfds.remove(&res);
            }
        }
        Ok(res)
    }

    pub fn kfd_set_cloexec(&self, pid: u32, kfd: u32, cloexec: bool) -> Result<(), JsValue> {
        if (SERVER_DEV_FD_BASE..CLIENT_PAGE_FD_BASE).contains(&kfd) {
            let mut rt = self.vfs_rt.borrow_mut();
            let entry = rt
                .proc_meta
                .get_mut(&pid)
                .and_then(|m| m.server_fds.get_mut(&kfd))
                .ok_or_else(|| map_errno(Errno::EBADF))?;
            entry.cloexec = cloexec;
            return Ok(());
        }
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let fds = vfs.process_fds(pid).map_err(map_errno)?;
        fds.borrow_mut()
            .set_cloexec(kfd, cloexec)
            .map_err(map_errno)
    }

    pub fn kfd_is_cloexec(&self, pid: u32, kfd: u32) -> Result<bool, JsValue> {
        if (SERVER_DEV_FD_BASE..CLIENT_PAGE_FD_BASE).contains(&kfd) {
            let rt = self.vfs_rt.borrow();
            return rt
                .proc_meta
                .get(&pid)
                .and_then(|m| m.server_fds.get(&kfd))
                .map(|e| e.cloexec)
                .ok_or_else(|| map_errno(Errno::EBADF));
        }
        let vfs = self.vfs_rt.borrow().vfs.clone();
        let fds = vfs.process_fds(pid).map_err(map_errno)?;
        fds.borrow().get_cloexec(kfd).map_err(map_errno)
    }

    pub async fn kfd_close(&self, pid: u32, kfd: u32) -> Result<(), JsValue> {
        if (SERVER_DEV_FD_BASE..CLIENT_PAGE_FD_BASE).contains(&kfd) {
            return self
                .release_server_fd(pid, kfd, false)
                .await
                .map(|_| ())
                .map_err(|e| map_errno(e.errno));
        }
        let scope_pid = self.scope_pid_for_kfd(pid, kfd).unwrap_or(pid);
        if let Some(meta) = self.vfs_rt.borrow_mut().proc_meta.get_mut(&pid) {
            meta.attenuated_kfds.remove(&kfd);
        }
        let vfs = self.vfs_rt.borrow().vfs.clone();
        self.with_proc_scope(scope_pid, async move { vfs.close(pid, kfd).await })
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
        self.proc_resolve_exec_scoped(pid, file, argv_json, path_env, search_path, None, None)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn proc_resolve_exec_scoped(
        &self,
        pid: u32,
        file: String,
        argv_json: String,
        path_env: Option<String>,
        search_path: bool,
        page_sudo: Option<bool>,
        page_session: Option<&str>,
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

        let owner = {
            let rt = self.vfs_rt.borrow();
            if let Some(sid) = page_session {
                Some(
                    rt.sessions
                        .get(sid)
                        .map(|v| (sid.to_owned(), v.mnt_ns.clone()))
                        .ok_or_else(|| map_errno(Errno::ESTALE))?,
                )
            } else {
                // Already-running processes keep their own MountNamespace and ProviderState liveness
                // checks even after login-session rotation or shutdown-scope end (e.g. cleanup
                // handlers forking `/usr/bin/*` after `end-session`, or `sh -i` after login change).
                rt.proc_meta
                    .get(&pid)
                    .and_then(|m| m.login_session.as_ref())
                    .and_then(|s| rt.sessions.get(s).map(|v| (s.clone(), v.mnt_ns.clone())))
            }
        };
        let chrooted = {
            let fs_ctx = vfs.process_fs_context(pid).map_err(map_errno)?;
            let ns_root = vfs
                .process_namespace(pid)
                .unwrap_or_else(|_| vfs.system_namespace())
                .borrow()
                .root_anchor();
            let proc_root = fs_ctx.borrow().root.clone();
            !proc_root.same_anchor(&ns_root)
        };

        enum ResolveOut {
            Immediate(Value),
            LocalWasm {
                resolved_path: String,
                argv: Vec<String>,
                nosuid: bool,
                fs_id: FsId,
                mount_id: MountId,
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

                // Case 1: System `/usr` `ImageFs` (either at `/usr` or bind-mounted inside a `chroot`),
                // requires the system image grant even when reached through a bind.
                if resolved.entry.handle.fs == usr_fs_id && root_cloud.is_pid_cloud_denied(pid) {
                    resolved.file.close().await?;
                    return Err(Errno::EACCES);
                }
                if resolved.entry.handle.fs == usr_fs_id
                    && let Some(asset_url) =
                        usr_blob_paths.get(&resolved.entry.handle.node.ino).cloned()
                {
                    let canonical_usr_path = asset_url
                        .strip_suffix(".wasm")
                        .unwrap_or(&asset_url)
                        .to_string();
                    let _ = resolved.file.close().await;
                    drain_releases(&vfs);
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

                // Case 2: All non-`/usr` executables (cloud files, Release v2 immutable
                // sysext/confext overlays, local mounts, `tmpfs`, private extension `image`, or
                // chrooted/cloud-attenuated executables) snapshot & verify bytes through `Vfs`
                // and run locally without server `/internal/exec`.
                let size = resolved.entry.metadata.size;
                if size > abi::EXEC_MAX {
                    let _ = resolved.file.close().await;
                    drain_releases(&vfs);
                    return Err(Errno::E2BIG);
                }
                let cap = usize::try_from(size).map_err(|_| Errno::E2BIG)?;
                let mut bytes = vec![0u8; cap];
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
                            drain_releases(&vfs);
                            return Err(err);
                        }
                    }
                }
                bytes.truncate(off);
                let provider_state = Rc::clone(resolved.pin.provider());
                let mount_id = resolved.pin.id();
                let pin_owner = resolved.pin.owner_uid();
                let fs_id = resolved.entry.handle.fs.clone();
                let _ = resolved.file.close().await;
                drain_releases(&vfs);
                // Execute-only (`0o111`) remote CloudFs probe stub cannot be executed as snapshot local bytes.
                if fs_id == *root_cloud.id()
                    && root_cloud.is_remote_mode()
                    && bytes.as_slice() == WASM_HEADER_STUB
                {
                    return Err(Errno::EACCES);
                }
                Ok(ResolveOut::LocalWasm {
                    resolved_path: resolved.resolved_path,
                    argv: resolved.argv,
                    nosuid: resolved.nosuid,
                    fs_id,
                    mount_id,
                    pin_owner,
                    provider: provider_state,
                    bytes,
                })
            })
            .await
            .map_err(map_errno)?;

        let (
            resolved_path,
            resolved_argv,
            nosuid,
            fs_id,
            mount_id,
            pin_owner,
            provider_state,
            bytes,
        ) = match out {
            ResolveOut::Immediate(val) => return json_to_js(&val),
            ResolveOut::LocalWasm {
                resolved_path,
                argv,
                nosuid,
                fs_id,
                mount_id,
                pin_owner,
                provider,
                bytes,
            } => (
                resolved_path,
                argv,
                nosuid,
                fs_id,
                mount_id,
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
        let (cloud_allowed, exec_ticket) = {
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
            if let Some((sid, ns)) = &owner
                && !rt
                    .sessions
                    .get(sid)
                    .is_some_and(|s| Rc::ptr_eq(&s.mnt_ns, ns))
            {
                return Err(map_errno(Errno::ESTALE));
            }
            let ticket = rt
                .alloc_exec_ticket(CachedExecTicket {
                    session_id: owner.map(|(sid, _)| sid),
                    bytes: Some(bytes),
                    mount_id,
                    provider: provider_state,
                })
                .map_err(map_errno)?;
            (fs_cloud && proc_cloud, ticket)
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
            "execTicket": exec_ticket,
        }))
    }

    /// Retrieve cached verified bytes using a one-shot `execTicket` (or check post-compile mount
    /// liveness when `check_only == Some(true)`), checking `ProviderState`.
    pub fn take_local_exec_bytes(
        &self,
        key: String,
        check_only: Option<bool>,
    ) -> Result<Option<Vec<u8>>, JsValue> {
        let mut rt = self.vfs_rt.borrow_mut();
        let Some(entry) = rt.exec_tickets.get_mut(&key) else {
            return Ok(None);
        };
        entry.provider.check_health().map_err(map_errno)?;
        if check_only.unwrap_or(false) {
            Ok(Some(vec![1]))
        } else {
            Ok(entry.bytes.take())
        }
    }

    pub fn release_exec_ticket(&self, ticket: String) {
        self.vfs_rt.borrow_mut().exec_tickets.remove(&ticket);
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
        let (vfs, scoped_pid) = {
            let mut rt = self.vfs_rt.borrow_mut();
            (rt.vfs.clone(), rt.alloc_scoped_pid())
        };
        let (mnt_ns, mut cred, effective_sudo) = self
            .resolve_page_creds(&vfs, &session_id, 0o022, sudo)
            .await
            .map_err(map_errno)?;
        cred.umask = 0o022;
        vfs.spawn_process(scoped_pid, INIT, cred, Some(mnt_ns), None, None)
            .map_err(map_errno)?;
        self.with_page_scope(effective_sudo, async {
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
                    Some(effective_sudo),
                    (!session_id.is_empty()).then_some(session_id.as_str()),
                )
                .await;
            let _ = vfs.exit_process(scoped_pid).await;
            res
        })
        .await
    }
}

fn resolve_service_namespace_locked(
    vfs: &Vfs,
    sessions: &HashMap<String, SessionVfs>,
    grant: &ServiceGrantSpec,
    uid: u32,
    parent_pid: Option<u32>,
    session_id: Option<&str>,
) -> Result<(Rc<RefCell<MountNamespace>>, Option<String>), JsValue> {
    match grant.mount_namespace.as_str() {
        "" | "system" => {
            if !grant.bind_mounts.is_empty() {
                return Err(vfs_js_err(
                    Errno::EINVAL,
                    "bind_mounts require isolated or session mount_namespace",
                ));
            }
            if grant.mount_namespace.is_empty()
                && uid != 0
                && let Some(ppid) = parent_pid
            {
                return Ok((
                    vfs.process_namespace(ppid).map_err(map_errno)?,
                    session_id.map(str::to_owned),
                ));
            }
            Ok((vfs.system_namespace(), None))
        }
        "isolated" => {
            let parent_ns = parent_pid
                .and_then(|pp| vfs.process_namespace(pp).ok())
                .unwrap_or_else(|| vfs.system_namespace());
            let (cloned, _) = vfs.clone_namespace(&parent_ns);
            Ok((cloned, None))
        }
        "session" => {
            if uid == 0 {
                return Err(vfs_js_err(
                    Errno::EPERM,
                    "session mount_namespace is forbidden for root units",
                ));
            }
            let sid = session_id.ok_or_else(|| vfs_js_err(Errno::EPERM, "missing user session"))?;
            let sess = sessions
                .get(sid)
                .ok_or_else(|| vfs_js_err(Errno::EPERM, "missing user session"))?;
            if sess.uid != uid {
                return Err(vfs_js_err(Errno::EPERM, "session uid mismatch"));
            }
            let (cloned, _) = vfs.clone_namespace(&sess.mnt_ns);
            Ok((cloned, Some(sid.to_string())))
        }
        _ => Err(vfs_js_err(
            Errno::EINVAL,
            "unknown service mount_namespace grant",
        )),
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
    let owner_uid = src_pin
        .owner_uid()
        .or_else(|| (cred.identity.id != 0).then_some(cred.identity.id));
    vfs.mount_on_namespace(
        ns,
        cred,
        Rc::clone(src_pin.backing()),
        Some((src_entry.handle, bm.source.clone())),
        &source_str,
        &bm.target,
        flags,
        locked,
        owner_uid,
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
    let mut out = Vec::with_capacity(s.len());
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
            out.push(val);
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn content_type_for_path(path: &str) -> &'static str {
    let name = path.rsplit('/').next().unwrap_or(path);
    let Some((_, ext)) = name.rsplit_once('.') else {
        return "application/octet-stream";
    };
    match ext.to_ascii_lowercase().as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "js" | "mjs" => "application/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" | "map" => "application/json; charset=utf-8",
        "wasm" => "application/wasm",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "webp" => "image/webp",
        "gif" => "image/gif",
        "ico" => "image/x-icon",
        "txt" | "md" | "csv" | "log" | "sh" | "rs" | "ts" => "text/plain; charset=utf-8",
        "pdf" => "application/pdf",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        "ogg" => "audio/ogg",
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        _ => "application/octet-stream",
    }
}

fn canonical_server_dev_path(
    root_cloud: &RootCloudDriver,
    handle: &Handle,
    rdev: &str,
) -> Option<String> {
    if rdev.starts_with("present:") || rdev.starts_with("snd:") {
        Some(
            root_cloud
                .canonical_cloud_path(handle.node)
                .unwrap_or_else(|| format!("/dev/{}", rdev.replacen(':', "/", 1))),
        )
    } else if rdev == "present" || rdev == "snd" {
        Some(
            root_cloud
                .canonical_cloud_path(handle.node)
                .unwrap_or_else(|| format!("/dev/{rdev}")),
        )
    } else if matches!(rdev, "archive" | "media" | "system") {
        Some(format!("/dev/{rdev}"))
    } else {
        None
    }
}

fn strip_proc_self_fd(path: &str) -> Option<&str> {
    let clean = path.trim_end_matches('/');
    clean
        .strip_prefix("/proc/self/fd/")
        .filter(|rest| !rest.is_empty() && !rest.contains('/'))
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

fn is_readonly_batch_call(call: &Call) -> bool {
    matches!(
        call,
        Call::Stat { .. }
            | Call::Lstat { .. }
            | Call::FstatAt { .. }
            | Call::Getdents { .. }
            | Call::Access { .. }
            | Call::Readlink { .. }
            | Call::ReadlinkAt { .. }
            | Call::Statfs { .. }
            | Call::Fstatfs { .. }
            | Call::Getcwd
            | Call::Getxattr { .. }
            | Call::Listxattr { .. }
    )
}

struct CloudMountFilter {
    cwd: Option<String>,
    blocked_prefixes: Vec<String>,
    unknown_mp_names: HashSet<String>,
}

impl CloudMountFilter {
    fn for_pid(vfs: &Vfs, root_cloud: &RootCloudDriver, pid: u32) -> Option<Self> {
        let fs_ctx = vfs.process_fs_context(pid).ok()?;
        let ns = vfs.process_namespace(pid).ok()?;
        let ctx_b = fs_ctx.borrow();
        if ctx_b.root.pin.fs().id() != root_cloud.fs_id() || ctx_b.root.handle.node.ino != 1 {
            return None;
        }
        let ns_b = ns.borrow();
        if ns_b
            .top_mount_at(ctx_b.root.pin.id(), ctx_b.root.handle.node)
            .is_some()
        {
            return None;
        }
        let cwd = if ctx_b.cwd.pin.fs().id() == root_cloud.fs_id() {
            if ctx_b.cwd.handle.node.ino == 1 {
                Some("/".to_string())
            } else {
                root_cloud.canonical_cloud_path(ctx_b.cwd.handle.node)
            }
        } else {
            None
        };
        let mut blocked_prefixes: Vec<String> = vec![
            "/usr",
            "/proc",
            "/dev",
            "/run",
            "/sys",
            "/mnt/local",
            "/mnt/shared",
            "/opt/private",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        let mut unknown_mp_names = HashSet::new();
        for entry in ns_b.mounts().values() {
            if entry.slot.pin().fs().id() == root_cloud.fs_id() {
                continue;
            }
            let Some(att) = &entry.parent else {
                return None;
            };
            if att.parent_pin.fs().id() != root_cloud.fs_id() {
                continue;
            }
            if let Some(p) = root_cloud.canonical_cloud_path(att.mountpoint.node) {
                blocked_prefixes.push(p);
            } else if let (Some(pnode), Some(name)) = (att.mp_parent_node, &att.mp_name) {
                if let Some(parent_path) = root_cloud.canonical_cloud_path(pnode) {
                    let full = if parent_path == "/" {
                        format!("/{name}")
                    } else {
                        format!("{}/{name}", parent_path.trim_end_matches('/'))
                    };
                    blocked_prefixes.push(full);
                } else {
                    unknown_mp_names.insert(name.clone());
                }
            } else if let Some(name) = &att.mp_name {
                unknown_mp_names.insert(name.clone());
            } else {
                return None;
            }
        }
        Some(Self {
            cwd,
            blocked_prefixes,
            unknown_mp_names,
        })
    }

    fn is_blocked_prefix(&self, path: &str) -> bool {
        self.blocked_prefixes
            .iter()
            .any(|mp| path == mp || path.starts_with(&format!("{mp}/")))
    }

    fn push_cloud_prefixes(
        &self,
        raw: &str,
        include_leaf_probe: bool,
        seen: &mut HashSet<String>,
        out: &mut Vec<String>,
    ) {
        if raw.is_empty() || strip_proc_self_fd(raw).is_some() {
            return;
        }
        let joined;
        let source = if raw.starts_with('/') {
            raw
        } else if let Some(cwd) = &self.cwd {
            joined = if cwd == "/" {
                format!("/{raw}")
            } else {
                format!("{}/{raw}", cwd.trim_end_matches('/'))
            };
            &joined
        } else {
            return;
        };
        let mut segs = Vec::new();
        for part in source.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    segs.pop();
                }
                name => segs.push(name),
            }
        }
        if segs
            .iter()
            .any(|s| self.unknown_mp_names.contains(*s) || *s == "_")
        {
            return;
        }
        let mut add = |p: String| {
            if seen.insert(p.clone()) {
                out.push(p);
            }
        };
        add("/".to_string());
        add("/_".to_string());
        let mut cur = String::new();
        for (i, seg) in segs.iter().enumerate() {
            cur.push('/');
            cur.push_str(seg);
            if self.is_blocked_prefix(&cur) {
                return;
            }
            add(cur.clone());
            let is_dir_step = i + 1 < segs.len() || include_leaf_probe;
            if is_dir_step {
                add(format!("{cur}/_"));
            }
        }
    }
}

fn collect_cloud_read_prewarm_paths(
    vfs: &Vfs,
    root_cloud: &RootCloudDriver,
    pid: u32,
    calls: &[Call],
) -> Vec<String> {
    let Some(filter) = CloudMountFilter::for_pid(vfs, root_cloud, pid) else {
        return Vec::new();
    };
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for call in calls {
        match call {
            Call::Stat { path } | Call::Lstat { path } | Call::Readlink { path } => {
                filter.push_cloud_prefixes(path, false, &mut seen, &mut out);
            }
            Call::Getdents { path, .. } => {
                filter.push_cloud_prefixes(path, true, &mut seen, &mut out);
            }
            Call::Access { path, mode } => {
                filter.push_cloud_prefixes(path, (*mode & abi::X_OK) != 0, &mut seen, &mut out);
            }
            Call::Getxattr { path, .. } | Call::Listxattr { path, .. } | Call::Statfs { path } => {
                filter.push_cloud_prefixes(path, false, &mut seen, &mut out);
            }
            _ => {}
        }
    }
    out
}

fn require_abs_call_path(path: &str) -> std::result::Result<(), abi::Error> {
    if path.is_empty() {
        return Err(Errno::ENOENT.into());
    }
    if path.len() > abi::PATH_MAX {
        return Err(Errno::ENAMETOOLONG.into());
    }
    if !path.starts_with('/') {
        return Err(abi::Error::because(
            Errno::EINVAL,
            "a path must be absolute",
        ));
    }
    Ok(())
}

fn validate_non_at_call_paths(call: &Call) -> std::result::Result<(), abi::Error> {
    match call {
        Call::Stat { path }
        | Call::Lstat { path }
        | Call::Getdents { path, .. }
        | Call::Access { path, .. }
        | Call::Readlink { path }
        | Call::Mkdir { path, .. }
        | Call::Mknod { path, .. }
        | Call::Rmdir { path }
        | Call::Unlink { path }
        | Call::Symlink { path, .. }
        | Call::Chmod { path, .. }
        | Call::Chown { path, .. }
        | Call::Utimens { path, .. }
        | Call::Statfs { path }
        | Call::Getxattr { path, .. }
        | Call::Setxattr { path, .. }
        | Call::Listxattr { path, .. }
        | Call::Removexattr { path, .. }
        | Call::Open { path, .. }
        | Call::InotifyAddWatch { path, .. } => require_abs_call_path(path),
        Call::Rename { from, to, .. } | Call::Link { from, to, .. } => {
            require_abs_call_path(from)?;
            require_abs_call_path(to)
        }
        Call::Pread {
            path: Some(path), ..
        } => require_abs_call_path(path),
        _ => Ok(()),
    }
}

impl Kernel {
    /// Execute a list of `abi::Call`s on `pid` (either a live process in `proc_sys` or a scoped
    /// page caller in `vfs_sys`).
    /// Install temporary aliases for the page's retained descriptors used by this syscall.
    /// Procfs and the *at walker then operate on the real open descriptions.
    fn bind_page_descriptors(
        &self,
        vfs: &Vfs,
        pid: u32,
        sid: &str,
        call: &mut Call,
        refs: &[Option<u32>],
        aliases: &mut Vec<u32>,
    ) -> vfs::Result<bool> {
        let rt = self.vfs_rt.borrow();
        let session = rt.page_session(sid).ok_or(Errno::EBADF)?;
        let table = vfs.process_fds(pid)?;
        let mut bind = |fd: u32| -> vfs::Result<u32> {
            let entry = session.page_fds.get(&fd).ok_or(Errno::EBADF)?;
            let slot = table
                .borrow_mut()
                .insert(entry.file.clone(), entry.cloexec)?;
            aliases.push(slot);
            Ok(slot)
        };
        let mut dir = |fd: &mut FdRef, path: &str| -> vfs::Result<()> {
            if path.starts_with('/') {
                *fd = FdRef::Fd(abi::OS_FD_ROOT as u32);
                return Ok(());
            }
            let n = parse_fd_ref(*fd, refs)?;
            if !matches!(n as i32, abi::OS_FD_ROOT | abi::OS_FD_CWD | -100) {
                *fd = FdRef::Fd(bind(n)?);
            }
            Ok(())
        };
        match call {
            Call::OpenAt { dirfd, path, .. }
            | Call::ReadlinkAt { dirfd, path }
            | Call::FstatAt { dirfd, path, .. }
            | Call::MkdirAt { dirfd, path, .. }
            | Call::UnlinkAt { dirfd, path, .. }
            | Call::SymlinkAt { dirfd, path, .. }
            | Call::UtimensAt { dirfd, path, .. } => dir(dirfd, path)?,
            Call::RenameAt {
                from_dirfd,
                from,
                to_dirfd,
                to,
                ..
            }
            | Call::LinkAt {
                from_dirfd,
                from,
                to_dirfd,
                to,
                ..
            } => {
                dir(from_dirfd, from)?;
                dir(to_dirfd, to)?;
            }
            Call::Fstatfs { fd } | Call::Setns { fd, .. } | Call::Fchdir { fd } => {
                let n = parse_fd_ref(*fd, refs)?;
                if n < CLIENT_PAGE_FD_BASE {
                    return Ok(true);
                }
                *fd = FdRef::Fd(bind(n)?);
            }
            _ => {}
        }
        let direct_link = matches!(
            call,
            Call::Stat { .. } | Call::Lstat { .. } | Call::Readlink { .. }
        );
        let path = match call {
            Call::Pread { path: Some(p), .. }
            | Call::Stat { path: p }
            | Call::Lstat { path: p }
            | Call::Readlink { path: p }
            | Call::Access { path: p, .. }
            | Call::Open { path: p, .. } => p,
            _ => return Ok(false),
        };
        if let Some((prefix, n)) = path.rsplit_once('/')
            && matches!(prefix, "/proc/self/fdinfo" | "/proc/self/fd")
            && let Ok(n) = n.parse::<u32>()
        {
            if n < CLIENT_PAGE_FD_BASE {
                return Ok(true);
            }
            if prefix.ends_with("fdinfo") || !direct_link {
                let kfd = bind(n).map_err(|_| Errno::ENOENT)?;
                *path = format!("{prefix}/{kfd}");
            }
        }
        Ok(false)
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_batch_on_pid(
        &self,
        vfs: &Vfs,
        pid: u32,
        page_session_id: Option<&str>,
        fd_epoch: Option<&str>,
        calls: Vec<Call>,
        page_sudo: bool,
        default_private_user_umask: bool,
        page_uid: u32,
        page_umask: u16,
    ) -> Vec<Return> {
        let mut results = Vec::with_capacity(calls.len());
        let mut fd_refs: Vec<Option<u32>> = Vec::with_capacity(calls.len());
        let root_cloud = Rc::clone(&self.vfs_rt.borrow().root_cloud);
        let can_page_prewarm = pid >= SCOPED_PAGE_PID_BASE
            && root_cloud.is_remote_mode()
            && installed("pageSysPost").is_ok();
        let mut active_read_scope: Option<PageReadScope> = None;

        for idx in 0..calls.len() {
            let readonly = is_readonly_batch_call(&calls[idx]);
            if !readonly {
                active_read_scope.take();
            } else if can_page_prewarm
                && (active_read_scope.is_none()
                    || root_cloud.ensure_page_read_cache(page_uid, page_sudo))
            {
                let mut run_end = idx + 1;
                while run_end < calls.len() && is_readonly_batch_call(&calls[run_end]) {
                    run_end += 1;
                }
                if active_read_scope.is_none() {
                    active_read_scope = Some(root_cloud.begin_page_read(page_uid, page_sudo));
                }
                let candidates =
                    collect_cloud_read_prewarm_paths(vfs, &root_cloud, pid, &calls[idx..run_end]);
                if !candidates.is_empty() {
                    root_cloud
                        .prewarm_page_paths(&candidates, page_umask, page_uid, page_sudo)
                        .await;
                }
            }
            let mut call = calls[idx].clone();
            crate::cloudfs::clear_last_page_error();
            let mut aliases = Vec::new();
            let bound = page_session_id.map_or(Ok(false), |sid| {
                self.bind_page_descriptors(vfs, pid, sid, &mut call, &fd_refs, &mut aliases)
            });

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
            let page_sid = page_session_id;
            let outcome: std::result::Result<Value, abi::Error> = if let Err(e) = bound {
                Err(e.into())
            } else if matches!(bound, Ok(true)) {
                let value = self.forward_server_call(pid, page_sudo, call).await;
                opened_fd = value
                    .as_ref()
                    .ok()
                    .and_then(|v| v.get("fd"))
                    .and_then(Value::as_u64)
                    .map(|n| n as u32);
                value
            } else if let Err(err) = validate_non_at_call_paths(&call) {
                Err(err)
            } else {
                match call {
                    Call::Stat { path } => {
                        if let Some(sid) = page_sid
                            && let Some(fd_str) = strip_proc_self_fd(&path)
                            && let Ok(fd_num) = fd_str.parse::<u32>()
                        {
                            self.eval_proc_self_fd_stat(vfs, pid, sid, page_sudo, fd_num, true)
                                .await
                        } else {
                            match vfs.statat(pid, StartAnchor::AtFdCwd, &path, true).await {
                                Ok(mut s) => {
                                    self.fill_stat_names(vfs, pid, &mut s).await;
                                    Ok(json!(s))
                                }
                                Err(e) => Err(e.into()),
                            }
                        }
                    }
                    Call::Lstat { path } => {
                        if let Some(sid) = page_sid
                            && let Some(fd_str) = strip_proc_self_fd(&path)
                            && let Ok(fd_num) = fd_str.parse::<u32>()
                        {
                            self.eval_proc_self_fd_stat(vfs, pid, sid, page_sudo, fd_num, false)
                                .await
                        } else {
                            match vfs.statat(pid, StartAnchor::AtFdCwd, &path, false).await {
                                Ok(mut s) => {
                                    self.fill_stat_names(vfs, pid, &mut s).await;
                                    self.fill_symlink_target(
                                        vfs,
                                        pid,
                                        StartAnchor::AtFdCwd,
                                        &path,
                                        &mut s,
                                    )
                                    .await;
                                    Ok(json!(s))
                                }
                                Err(e) => Err(e.into()),
                            }
                        }
                    }
                    Call::FstatAt {
                        dirfd,
                        path,
                        nofollow,
                    } => match parse_fd_ref(dirfd, &fd_refs).and_then(|d| parse_anchor(d as i32)) {
                        Ok(anchor) => match vfs.statat(pid, anchor.clone(), &path, !nofollow).await
                        {
                            Ok(mut s) => {
                                self.fill_stat_names(vfs, pid, &mut s).await;
                                if nofollow {
                                    self.fill_symlink_target(vfs, pid, anchor, &path, &mut s)
                                        .await;
                                }
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
                    } => {
                        self.eval_getdents(
                            vfs, pid, page_sid, page_sudo, page_uid, page_umask, &path, cookie,
                            count,
                        )
                        .await
                    }
                    Call::Access { path, mode } => vfs
                        .accessat(pid, StartAnchor::AtFdCwd, &path, mode, true)
                        .await
                        .map(|()| Value::Null)
                        .map_err(Into::into),
                    Call::Readlink { path } => {
                        if let Some(sid) = page_sid
                            && let Some(fd_str) = strip_proc_self_fd(&path)
                            && let Ok(fd_num) = fd_str.parse::<u32>()
                        {
                            self.eval_proc_self_fd_readlink(pid, sid, page_sudo, fd_num)
                                .await
                        } else {
                            vfs.readlinkat(pid, StartAnchor::AtFdCwd, &path)
                                .await
                                .map(|s| json!(s))
                                .map_err(Into::into)
                        }
                    }
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
                        Ok(raw_fd) => {
                            if page_sid.is_none()
                                && (SERVER_DEV_FD_BASE..CLIENT_PAGE_FD_BASE).contains(&raw_fd)
                            {
                                match self.resolve_process_server_fd(pid, raw_fd) {
                                    Ok(sfd) => {
                                        self.forward_server_call(
                                            pid,
                                            page_sudo,
                                            Call::Fstatfs { fd: FdRef::Fd(sfd) },
                                        )
                                        .await
                                    }
                                    Err(e) => Err(e),
                                }
                            } else {
                                vfs.fstatfs(pid, raw_fd)
                                    .await
                                    .map(|s| json!(safe_statfs_for_js(s)))
                                    .map_err(Into::into)
                            }
                        }
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
                        let ns = vfs.process_namespace(pid).ok();
                        let ns_id = ns.as_ref().map(|n| n.borrow().id());
                        let before_ids =
                            ns.as_ref().map(Self::collect_mount_ids).unwrap_or_default();
                        let res = vfs
                            .umount2(pid, &target, flags)
                            .await
                            .map(|()| Value::Null)
                            .map_err(Into::into);
                        if res.is_ok() {
                            if let Some(ref ns_rc) = ns {
                                self.evict_detached_mount_ids(ns_rc, before_ids);
                            }
                            if let Some(nid) = ns_id {
                                self.notify_ns_changed(nid);
                            }
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
                    Call::Unshare { flags } => match vfs.unshare(pid, flags) {
                        Ok(()) => {
                            if flags & unshare_flags::CLONE_NEWNS != 0
                                && let Some(meta) = self.vfs_rt.borrow_mut().proc_meta.get_mut(&pid)
                            {
                                meta.session_id = None;
                            }
                            Ok(Value::Null)
                        }
                        Err(e) => Err(e.into()),
                    },
                    Call::Setns { fd, nstype } => match parse_fd_ref(fd, &fd_refs) {
                        Ok(kfd) => match vfs.setns(pid, kfd, nstype) {
                            Ok(()) => {
                                if (nstype == 0 || (nstype & unshare_flags::CLONE_NEWNS) != 0)
                                    && let Some(meta) =
                                        self.vfs_rt.borrow_mut().proc_meta.get_mut(&pid)
                                {
                                    meta.session_id = None;
                                }
                                Ok(Value::Null)
                            }
                            Err(e) => Err(e.into()),
                        },
                        Err(e) => Err(e.into()),
                    },
                    Call::OpenAt {
                        dirfd,
                        path,
                        flags,
                        mode,
                    } => match parse_fd_ref(dirfd, &fd_refs).and_then(|d| parse_anchor(d as i32)) {
                        Ok(anchor) => {
                            match self
                                .eval_open_anchor_call(
                                    vfs, pid, anchor, page_sid, page_sudo, &path, flags, mode,
                                    None, None, None,
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
                            .eval_open_anchor_call(
                                vfs,
                                pid,
                                StartAnchor::AtFdCwd,
                                page_sid,
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
                            self.eval_close_call(
                                vfs, pid, page_sid, fd_epoch, page_sudo, raw_fd, false,
                            )
                            .await
                        }
                        Err(e) => Err(e.into()),
                    },
                    Call::Discard { fd } => match parse_fd_ref(fd, &fd_refs) {
                        Ok(raw_fd) => {
                            self.eval_close_call(
                                vfs, pid, page_sid, fd_epoch, page_sudo, raw_fd, true,
                            )
                            .await
                        }
                        Err(e) => Err(e.into()),
                    },
                    Call::Fchmod { fd, mode } => match parse_fd_ref(fd, &fd_refs) {
                        Ok(raw_fd) => {
                            self.eval_fchmod(vfs, pid, page_sid, page_sudo, raw_fd, mode)
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
                            vfs, pid, page_sid, page_sudo, fd, path, offset, count, &fd_refs,
                        )
                        .await
                    }
                    Call::Pwrite { fd, index, data } => match parse_fd_ref(fd, &fd_refs) {
                        Ok(raw_fd) => {
                            self.eval_pwrite(vfs, pid, page_sid, page_sudo, raw_fd, index, data.0)
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
                    Call::Getcreds if page_sid.is_none() && pid < SCOPED_PAGE_PID_BASE => {
                        let host = self
                            .state
                            .borrow()
                            .table
                            .proc(pid)
                            .map(|p| p.owner_host.clone());
                        match host {
                            Some(h) => match self.getcreds_proc(pid, &h) {
                                Ok(raw) => serde_json::from_str::<Value>(&raw)
                                    .map_err(|_| Errno::EIO.into()),
                                Err(_) => Err(Errno::ESRCH.into()),
                            },
                            None => Err(Errno::ESRCH.into()),
                        }
                    }
                    call @ (Call::Getpid
                    | Call::Getpgid { .. }
                    | Call::Getsid { .. }
                    | Call::Setpgid { .. }
                    | Call::Setsid
                    | Call::Prctl { .. }
                    | Call::ProcStopped { .. }
                    | Call::Waitpid { .. }
                    | Call::CgroupCreate { .. }
                    | Call::CgroupRemove { .. }
                    | Call::CgroupSet { .. }
                    | Call::CgroupAttach { .. }
                    | Call::CgroupStat { .. }
                    | Call::CgroupList { .. }) => {
                        let owner_host = self
                            .state
                            .borrow()
                            .table
                            .proc(pid)
                            .map(|p| p.owner_host.clone());
                        if let Some(h) = owner_host {
                            self.eval_local_process_call(pid, &h, call).await
                        } else if page_sid.is_some() || pid >= SCOPED_PAGE_PID_BASE {
                            // Page-scoped cgroup operations act as the instance's local account.
                            match call {
                                Call::CgroupCreate {
                                    path,
                                    controllers,
                                    lifetime,
                                } => {
                                    let mut state = self.state.borrow_mut();
                                    let cred = state.account.identity();
                                    state
                                        .table
                                        .cgroup_create(
                                            &cred,
                                            None,
                                            &path,
                                            controllers.as_deref(),
                                            lifetime,
                                        )
                                        .map(|()| Value::Null)
                                }
                                Call::CgroupRemove { path } => {
                                    let mut state = self.state.borrow_mut();
                                    let cred = state.account.identity();
                                    state
                                        .table
                                        .cgroup_remove(&cred, &path)
                                        .map(|()| Value::Null)
                                }
                                Call::CgroupSet { path, key, value } => {
                                    let res = {
                                        let mut state = self.state.borrow_mut();
                                        let cred = state.account.identity();
                                        state
                                            .table
                                            .cgroup_set_with_revocations(
                                                &cred,
                                                &path,
                                                &key,
                                                &value,
                                                crate::now_secs(),
                                            )
                                            .map(|(d, r)| {
                                                let norm =
                                                    kernel::local_cgroups::normalize_cgroup_path(
                                                        &path,
                                                    )
                                                    .unwrap_or(path);
                                                (d, r, norm)
                                            })
                                    };
                                    match res {
                                        Ok((deliveries, revoked, norm)) => {
                                            for d in deliveries {
                                                if d.killed {
                                                    self.cloud_exited(d.pid, None).await;
                                                }
                                            }
                                            crate::revoke_remote_tokens_state(&self.state, revoked)
                                                .await;
                                            if key == "io.max" {
                                                self.sync_remote_io_quota_subtree(&norm).await;
                                            }
                                            Ok(Value::Null)
                                        }
                                        Err(e) => Err(e),
                                    }
                                }
                                Call::CgroupAttach {
                                    pid: target_pid,
                                    path,
                                } => {
                                    let res = {
                                        let mut state = self.state.borrow_mut();
                                        let cred = state.account.identity();
                                        state.table.cgroup_attach(&cred, target_pid, &path).map(
                                            |()| {
                                                let norm =
                                                    kernel::local_cgroups::normalize_cgroup_path(
                                                        &path,
                                                    )
                                                    .unwrap_or(path);
                                                let tok =
                                                    state.table.proc(target_pid).and_then(|p| {
                                                        p.cred
                                                            .remote
                                                            .as_ref()
                                                            .map(|r| r.token.clone())
                                                    });
                                                (norm, tok)
                                            },
                                        )
                                    };
                                    match res {
                                        Ok((norm, remote_tok)) => {
                                            if let Some(token) = remote_tok {
                                                self.sync_remote_io_quota_for_token(&token, &norm)
                                                    .await;
                                            }
                                            Ok(Value::Null)
                                        }
                                        Err(e) => Err(e),
                                    }
                                }
                                Call::CgroupStat { path } => {
                                    self.state.borrow().table.cgroup_stat(&path)
                                }
                                Call::CgroupList { path } => {
                                    Ok(json!(self.state.borrow().table.cgroup_list(&path)))
                                }
                                _ => Err(Errno::ENOSYS.into()),
                            }
                        } else {
                            Err(Errno::ESRCH.into())
                        }
                    }
                    Call::Kill {
                        pid: target_str,
                        signal,
                    } => {
                        let target = abi::Target::of(&target_str);
                        if !matches!(target, abi::Target::Job(_)) {
                            let sig = signal.unwrap_or(abi::SIGTERM);
                            let from =
                                (page_sid.is_none() && pid < SCOPED_PAGE_PID_BASE).then_some(pid);
                            let kill_res = {
                                let mut state = self.state.borrow_mut();
                                let caller_cred = if let Some(fp) = from {
                                    state
                                        .table
                                        .proc(fp)
                                        .filter(|p| p.state != abi::ProcState::Zombie)
                                        .map(|p| p.cred.identity.clone())
                                        .ok_or_else(|| abi::Error::from(Errno::ESRCH))
                                } else {
                                    Ok(state.account.identity())
                                };
                                caller_cred.and_then(|cred| {
                                    state.table.kill_with_revocations(
                                        &cred,
                                        from,
                                        target,
                                        sig,
                                        crate::now_secs(),
                                    )
                                })
                            };
                            match kill_res {
                                Ok((deliveries, revoked)) => {
                                    for d in deliveries {
                                        if d.killed {
                                            self.cloud_exited(d.pid, None).await;
                                        }
                                    }
                                    crate::revoke_remote_tokens_state(&self.state, revoked).await;
                                    Ok(Value::Null)
                                }
                                Err(e) => Err(e),
                            }
                        } else {
                            self.forward_server_call(
                                pid,
                                page_sudo,
                                Call::Kill {
                                    pid: target_str,
                                    signal,
                                },
                            )
                            .await
                        }
                    }
                    other => {
                        let is_login = matches!(other, Call::Login { .. });
                        let is_logout = matches!(other, Call::Logout);
                        let is_getcreds = matches!(other, Call::Getcreds);
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
                        if let Ok(ref val) = res {
                            if is_logout {
                                self.apply_account_update(crate::LocalAccount::default());
                            } else if (is_login || is_getcreds)
                                && (page_sid.is_some() || pid >= SCOPED_PAGE_PID_BASE)
                                && let Ok(acc) = crate::parse_account_from_value(val)
                            {
                                self.apply_account_update(acc);
                            }
                        }
                        if invalidates_accounts && res.is_ok() {
                            let mut rt = self.vfs_rt.borrow_mut();
                            rt.uid_names = default_uid_names();
                            rt.gid_names = default_gid_names();
                            rt.root_cloud.clear_cached_account_names();
                        }
                        res
                    }
                }
            };

            if let Ok(table) = vfs.process_fds(pid) {
                for alias in aliases {
                    let _ = table.borrow_mut().take(alias);
                }
            }
            if let Some(prev) = prev_umask {
                let _ = vfs.set_umask(pid, prev);
            }
            fd_refs.push(opened_fd);
            results.push(match outcome {
                Ok(v) => Return::Ok(v),
                Err(mut e) => {
                    if e.detail.is_none() {
                        e.detail = crate::cloudfs::take_last_page_error_detail(e.errno);
                    }
                    Return::Err(e)
                }
            });
        }

        results
    }

    fn resolve_process_server_fd_entry(
        &self,
        pid: u32,
        vfd: u32,
    ) -> std::result::Result<(u32, Option<(u32, String)>), abi::Error> {
        let rt = self.vfs_rt.borrow();
        rt.proc_meta
            .get(&pid)
            .and_then(|m| {
                m.server_fds
                    .get(&vfd)
                    .filter(|e| !e.closing)
                    .map(|e| (*e.sfd, e.attenuated_token.clone()))
            })
            .ok_or_else(|| Errno::EBADF.into())
    }

    pub(crate) async fn forward_server_call_attenuated(
        &self,
        owner_pid: u32,
        owner_token: &str,
        call: Call,
    ) -> std::result::Result<Value, abi::Error> {
        // Verify originating token has NOT been revoked locally (e.g. privilege drop / exit / sign-out).
        let (instance_id, revoked_or_gone) = {
            let state = self.state.borrow();
            let gone = state.pending_revocations.iter().any(|t| t == owner_token)
                || !state.table.proc(owner_pid).is_some_and(|p| {
                    p.state != abi::ProcState::Zombie
                        && p.cred.cloud_access
                        && p.cred
                            .remote
                            .as_ref()
                            .is_some_and(|r| r.token == owner_token)
                });
            (state.instance_id.clone(), gone)
        };
        if revoked_or_gone {
            return Err(Errno::EACCES.into());
        }
        let fs_session = self.vfs_rt.borrow().root_cloud.current_fs_session();
        let batch = Batch {
            calls: vec![call],
            umask: None,
            sudo: false,
            pid: Some(owner_pid),
            process: Some(owner_token.to_string()),
        };
        let Ok((global, post)) = installed("cloudFsPost") else {
            return Err(Errno::ENOTCONN.into());
        };
        let body = serde_json::to_vec(&batch)
            .map_err(|e| abi::Error::because(Errno::EIO, e.to_string()))?;
        let headers = js_sys::Object::new();
        let _ = js_sys::Reflect::set(&headers, &"Content-Type".into(), &"application/json".into());
        js_sys::Reflect::set(&headers, &"X-Process-Token".into(), &owner_token.into())
            .map_err(|_| Errno::EIO)?;
        if !instance_id.is_empty() {
            js_sys::Reflect::set(&headers, &"X-OS-Instance".into(), &instance_id.into())
                .map_err(|_| Errno::EIO)?;
        }
        if let Some((ref sid, ref secret)) = fs_session
            && !sid.is_empty()
            && !secret.is_empty()
        {
            let _ = js_sys::Reflect::set(&headers, &"X-Fs-Session".into(), &sid.into());
            let _ = js_sys::Reflect::set(&headers, &"X-Fs-Secret".into(), &secret.into());
        }
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
            let text = String::from_utf8_lossy(&bytes);
            if let Ok(err_val) = serde_json::from_str::<Value>(&text)
                && let Some(code) = err_val["errno"].as_str()
                && let Ok(parsed) = serde_json::from_value::<Errno>(Value::String(code.to_string()))
            {
                return Err(abi::Error::because(
                    parsed,
                    err_val["error"].as_str().unwrap_or(""),
                ));
            }
            return Err(abi::Error::because(Errno::EIO, text.into_owned()));
        }
        let res: abi::Results = serde_json::from_slice(&bytes)
            .map_err(|e| abi::Error::because(Errno::EIO, e.to_string()))?;
        res.results
            .into_iter()
            .next()
            .ok_or_else(|| abi::Error::from(Errno::EIO))?
            .into_result()
    }

    fn resolve_process_server_fd(
        &self,
        pid: u32,
        vfd: u32,
    ) -> std::result::Result<u32, abi::Error> {
        let rt = self.vfs_rt.borrow();
        rt.proc_meta
            .get(&pid)
            .and_then(|m| {
                m.server_fds
                    .get(&vfd)
                    .filter(|e| !e.closing)
                    .map(|e| *e.sfd)
            })
            .ok_or_else(|| Errno::EBADF.into())
    }

    #[allow(clippy::too_many_arguments)]
    async fn open_server_device_fd(
        &self,
        pid: u32,
        page_sudo: bool,
        canonical_dev: String,
        flags: u32,
        mode: u16,
        cloexec: bool,
        size: Option<u64>,
        sha256: Option<String>,
        version: Option<String>,
    ) -> std::result::Result<(u32, Value), abi::Error> {
        let mut val = self
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
        if pid >= SCOPED_PAGE_PID_BASE || page_sudo {
            return Ok((sfd, val));
        }
        let alloc_res = {
            let mut rt = self.vfs_rt.borrow_mut();
            let meta = rt
                .proc_meta
                .entry(pid)
                .or_insert_with(|| ProcessVfsMeta::new(None, true));
            meta.alloc_server_fd(Rc::new(sfd), cloexec)
        };
        let vfd = match alloc_res {
            Ok(v) => v,
            Err(e) => {
                let _ = self
                    .forward_server_call(pid, page_sudo, Call::Close { fd: FdRef::Fd(sfd) })
                    .await;
                return Err(e.into());
            }
        };
        val["fd"] = json!(vfd);
        Ok((vfd, val))
    }

    async fn eval_proc_self_fd_stat(
        &self,
        vfs: &Vfs,
        pid: u32,
        sid: &str,
        page_sudo: bool,
        fd_num: u32,
        follow: bool,
    ) -> std::result::Result<Value, abi::Error> {
        if fd_num < CLIENT_PAGE_FD_BASE {
            let path = format!("/proc/self/fd/{fd_num}");
            let call = if follow {
                Call::Stat { path }
            } else {
                Call::Lstat { path }
            };
            return self.forward_server_call(pid, page_sudo, call).await;
        }
        let (file, path, uid, gid) = {
            let rt = self.vfs_rt.borrow();
            let sess = rt.page_session(sid).ok_or(Errno::ENOENT)?;
            let entry = sess.page_fds.get(&fd_num).ok_or(Errno::ENOENT)?;
            (entry.file.clone(), entry.path.clone(), sess.uid, sess.gid)
        };
        if follow {
            let meta = file.metadata().await?;
            let mut st = vfs::stat::stat(file.fs().id(), file.handle().node, &meta);
            self.fill_stat_names(vfs, pid, &mut st).await;
            return Ok(json!(st));
        }
        let mut st = abi::Stat {
            dev: 0,
            ino: u64::from(fd_num),
            mode: abi::S_IFLNK | 0o700,
            nlink: 1,
            uid,
            gid,
            size: path.len() as u64,
            link: Some(path),
            ..abi::Stat::default()
        };
        self.fill_stat_names(vfs, pid, &mut st).await;
        Ok(json!(st))
    }

    async fn eval_proc_self_fd_readlink(
        &self,
        pid: u32,
        sid: &str,
        page_sudo: bool,
        fd_num: u32,
    ) -> std::result::Result<Value, abi::Error> {
        if fd_num < CLIENT_PAGE_FD_BASE {
            return self
                .forward_server_call(
                    pid,
                    page_sudo,
                    Call::Readlink {
                        path: format!("/proc/self/fd/{fd_num}"),
                    },
                )
                .await;
        }
        let rt = self.vfs_rt.borrow();
        let entry = rt
            .page_session(sid)
            .and_then(|s| s.page_fds.get(&fd_num))
            .ok_or(Errno::ENOENT)?;
        Ok(json!(entry.path))
    }

    #[allow(clippy::too_many_arguments)]
    async fn eval_getdents(
        &self,
        vfs: &Vfs,
        pid: u32,
        page_session_id: Option<&str>,
        page_sudo: bool,
        page_uid: u32,
        page_umask: u16,
        path: &str,
        cookie: u64,
        count: Option<u64>,
    ) -> std::result::Result<Value, abi::Error> {
        if let Some(sid) = page_session_id
            && matches!(
                path.trim_end_matches('/'),
                "/proc/self/fd" | "/proc/self/fdinfo"
            )
        {
            let mut combined: BTreeMap<String, Dirent> = BTreeMap::new();
            if self.state.borrow().remote_attached
                && self.vfs_rt.borrow().root_cloud.is_remote_mode()
                && let Ok(val) = self
                    .forward_server_call(
                        pid,
                        page_sudo,
                        Call::Getdents {
                            path: path.to_string(),
                            cookie: 0,
                            count: None,
                        },
                    )
                    .await
                && let Ok(server_entries) = serde_json::from_value::<Vec<Dirent>>(val)
            {
                for item in server_entries {
                    combined.insert(item.name.clone(), item);
                }
            }
            let (local_fds, uid, gid) = {
                let rt = self.vfs_rt.borrow();
                if let Some(sess) = rt.page_session(sid) {
                    let fds: Vec<(u32, String)> = sess
                        .page_fds
                        .iter()
                        .map(|(&k, v)| (k, v.path.clone()))
                        .collect();
                    (fds, sess.uid, sess.gid)
                } else {
                    (Vec::new(), 0, 0)
                }
            };
            for (fd_num, target_path) in local_fds {
                let name = fd_num.to_string();
                let mut st = abi::Stat {
                    ino: u64::from(fd_num),
                    mode: if path.trim_end_matches('/').ends_with("fdinfo") {
                        abi::S_IFREG | 0o400
                    } else {
                        abi::S_IFLNK | 0o700
                    },
                    nlink: 1,
                    uid,
                    gid,
                    size: target_path.len() as u64,
                    link: (!path.trim_end_matches('/').ends_with("fdinfo")).then_some(target_path),
                    ..abi::Stat::default()
                };
                self.fill_stat_names(vfs, pid, &mut st).await;
                combined.insert(
                    name.clone(),
                    Dirent {
                        name,
                        stat: Some(st),
                    },
                );
            }
            let all: Vec<Dirent> = combined.into_values().collect();
            let total = all.len();
            let start = (cookie as usize).min(total);
            let max_items = count.map(|c| c as usize).unwrap_or(total);
            let end = start.saturating_add(max_items).min(total);
            return Ok(json!(&all[start..end]));
        }

        let root_cloud = Rc::clone(&self.vfs_rt.borrow().root_cloud);
        let can_page_cache = pid >= SCOPED_PAGE_PID_BASE
            && root_cloud.is_remote_mode()
            && installed("pageSysPost").is_ok();
        let _getdents_scope = if can_page_cache {
            let scope = root_cloud.begin_page_read(page_uid, page_sudo);
            if let Some(filter) = CloudMountFilter::for_pid(vfs, &root_cloud, pid) {
                let mut seen = HashSet::new();
                let mut paths = Vec::new();
                filter.push_cloud_prefixes(path, true, &mut seen, &mut paths);
                let uncached = root_cloud.uncached_page_paths(&paths, page_uid, page_sudo);
                if !uncached.is_empty() {
                    root_cloud
                        .prewarm_page_paths(&uncached, page_umask, page_uid, page_sudo)
                        .await;
                }
            }
            Some(scope)
        } else {
            None
        };

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
        if can_page_cache && let Some(filter) = CloudMountFilter::for_pid(vfs, &root_cloud, pid) {
            let mut seen = HashSet::new();
            let mut child_paths = Vec::new();
            for de in &dir_entries[start..end] {
                let child_path = format!("{base}/{}", de.name);
                filter.push_cloud_prefixes(&child_path, false, &mut seen, &mut child_paths);
            }
            let uncached = root_cloud.uncached_page_paths(&child_paths, page_uid, page_sudo);
            if !uncached.is_empty() {
                root_cloud
                    .prewarm_page_paths(&uncached, page_umask, page_uid, page_sudo)
                    .await;
            }
        }
        let mut out = Vec::with_capacity(end.saturating_sub(start));
        for de in &dir_entries[start..end] {
            let child_path = format!("{base}/{}", de.name);
            let mut stat = vfs
                .statat(pid, StartAnchor::AtFdCwd, &child_path, false)
                .await
                .ok();
            if let Some(st) = stat.as_mut() {
                self.fill_stat_names(vfs, pid, st).await;
                if de.name != "." && de.name != ".." {
                    self.fill_symlink_target(vfs, pid, StartAnchor::AtFdCwd, &child_path, st)
                        .await;
                }
            }
            out.push(Dirent {
                name: de.name.clone(),
                stat,
            });
        }
        Ok(json!(out))
    }

    async fn discard_created_file(entry: &PageOpenFd) -> vfs::Result<()> {
        if let Some((parent, name)) = &entry.creation {
            let file = &entry.file;
            let pin = file.mount_pin().ok_or(Errno::ESTALE)?;
            pin.guard_op(
                file.cred(),
                true,
                true,
                file.fs()
                    .unlink_if(file.cred(), parent, name, file.handle().node),
            )
            .await?;
        }
        Ok(())
    }

    async fn verify_page_digest(
        vfs: &Vfs,
        file: &FileRef,
        length: u64,
        digest: &UploadDigest,
        progress: &Option<(u64, Sha256)>,
    ) -> vfs::Result<()> {
        let mut hash = Sha256::new();
        if let Some((n, sequential)) = progress
            && *n == length
        {
            hash = sequential.clone();
        } else if length != 0 {
            let pin = file.mount_pin().ok_or(Errno::EBADF)?;
            let mut options = vfs::OpenOptions::new();
            options.read(true);
            // A private driver read of this exact inode verifies sparse or overwritten bytes.
            // The mount guard and remote grant still use the uploader's authority.
            let open = pin
                .guard_op(file.cred(), false, false, async {
                    let fs = file.fs();
                    match fs.open(file.cred(), file.handle(), &options).await {
                        Err(Errno::EACCES) if digest.fresh_contents => {
                            let mut verifier = file.cred().clone();
                            verifier.identity = Identity::root();
                            fs.open(&verifier, file.handle(), &options).await
                        }
                        result => result,
                    }
                })
                .await?;
            let reader = FileRef::new_mounted_with_type(
                pin.clone(),
                open,
                file.handle().clone(),
                Some(FileType::File),
                file.cred().clone(),
                &options,
                vfs.releases(),
            );
            let result = async {
                let mut buf = vec![0; (256 * 1024).min(length) as usize];
                let mut offset = 0;
                while offset < length {
                    let count = (length - offset).min(buf.len() as u64) as usize;
                    let n = reader.read_at(&mut buf[..count], offset).await?;
                    if n == 0 {
                        return Err(Errno::EIO);
                    }
                    hash.update(&buf[..n]);
                    offset += n as u64;
                }
                Ok(())
            }
            .await;
            let close = reader.close().await;
            result?;
            close?;
        }
        if !image::hex(&hash.finalize()).eq_ignore_ascii_case(&digest.expected) {
            return Err(Errno::EIO);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn eval_open_anchor_call(
        &self,
        vfs: &Vfs,
        pid: u32,
        anchor: StartAnchor,
        page_session_id: Option<&str>,
        page_sudo: bool,
        path: &str,
        flags: u32,
        mode: u16,
        size: Option<u64>,
        sha256: Option<String>,
        version: Option<String>,
    ) -> std::result::Result<(u32, Value), abi::Error> {
        let page_sid = page_session_id;
        let epoch = page_sid.and_then(|sid| {
            self.vfs_rt
                .borrow()
                .page_session(sid)
                .map(|s| s.epoch.clone())
        });
        let root_cloud = Rc::clone(&self.vfs_rt.borrow().root_cloud);
        let pass_flags = if (flags & abi::O_PATH) != 0 && (flags & abi::O_NOFOLLOW) != 0 {
            flags & !abi::O_DIRECTORY
        } else {
            flags
        };
        let cloexec = flags & vfs::vfs::O_CLOEXEC != 0;

        use vfs::cloud_http::PageTarget;
        use vfs::walk::WalkResult;

        let resolved = vfs.resolve_open(pid, anchor, path, pass_flags).await?;
        let (pin, node, creation) = match &resolved {
            WalkResult::Found { pin, entry, .. } => (pin, entry.handle.node, None),
            WalkResult::MissingLast {
                parent_pin,
                parent,
                name,
                trailing_slash,
            } => {
                if *trailing_slash || flags & abi::O_DIRECTORY != 0 {
                    return Err(Errno::EISDIR.into());
                }
                (
                    parent_pin,
                    parent.handle.node,
                    Some((parent.handle.clone(), name.clone())),
                )
            }
        };
        let created = creation.is_some();
        let is_streaming_recording = (flags & abi::O_APPEND) != 0
            && (flags & abi::O_ACCMODE) != abi::O_RDONLY
            && (flags & abi::O_CREAT) != 0;
        if page_sid.is_some()
            && (size.is_some() || sha256.is_some() || version.is_some() || is_streaming_recording)
        {
            if pin.effective_rdonly() {
                return Err(Errno::EROFS.into());
            }
            if let WalkResult::Found { entry, .. } = &resolved {
                if flags & (abi::O_CREAT | abi::O_EXCL) == abi::O_CREAT | abi::O_EXCL {
                    return Err(Errno::EEXIST.into());
                }
                if entry.metadata.is_symlink() {
                    return Err(Errno::ELOOP.into());
                }
                if entry.metadata.is_dir() {
                    return Err(Errno::EISDIR.into());
                }
            }
            if pin.fs().id() == root_cloud.id() && root_cloud.is_remote_mode() {
                let canonical = root_cloud.canonical_cloud_path(node).ok_or(Errno::ESTALE)?;
                let ino = root_cloud.page_ino(node);
                let (path, target) = match &creation {
                    Some((_, leaf)) => (
                        format!("{}/{leaf}", canonical.trim_end_matches('/')),
                        PageTarget::MissingIn(ino),
                    ),
                    None => (canonical, PageTarget::Inode(ino)),
                };
                let umask = vfs.process_fs_context(pid)?.borrow().umask;
                let writer = pin.pin_writer(&vfs.process_cred(pid)?)?;
                let value = root_cloud
                    .guarded_page_call(
                        Call::Open {
                            path,
                            flags,
                            mode,
                            size,
                            sha256,
                            version,
                        },
                        Some(umask),
                        page_sudo,
                        target,
                    )
                    .await?;
                let remote: AuthorityPageFd =
                    serde_json::from_value(value.clone()).map_err(|_| Errno::EIO)?;
                let fd = remote.fd;
                {
                    let mut rt = self.vfs_rt.borrow_mut();
                    if let Some(sess) = page_sid
                        .and_then(|sid| rt.page_session_mut(sid))
                        .filter(|s| epoch.as_ref().is_some_and(|e| Rc::ptr_eq(e, &s.epoch)))
                    {
                        sess.delegated_uploads.insert(fd, (remote, writer));
                        return Ok((fd, value));
                    }
                }
                let _ = remote.close(page_sudo).await;
                return Err(Errno::ESTALE.into());
            }
            if version.is_some() {
                return Err(Errno::EOPNOTSUPP.into());
            }
            if !created && size.is_some() && flags & abi::O_TRUNC == 0 {
                return Err(Errno::EEXIST.into());
            }
            if sha256
                .as_ref()
                .is_some_and(|h| h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()))
            {
                return Err(Errno::EINVAL.into());
            }
        }
        // Only an exclusive driver create establishes ownership for abort cleanup.
        let open_flags = if created && page_sid.is_some() {
            pass_flags | abi::O_EXCL
        } else {
            pass_flags
        };
        let (file_ref, entry) = vfs.open_resolved(pid, resolved, open_flags, mode).await?;
        if (flags & abi::O_DIRECTORY) != 0 && !entry.metadata.is_dir() {
            let _ = file_ref.close().await;
            drain_releases(vfs);
            return Err(Errno::ENOTDIR.into());
        }
        if (flags & abi::O_PATH) == 0
            && entry.metadata.file_type == FileType::CharDevice
            && let Some(rdev) = &entry.metadata.rdev
            && let Some(canonical_dev) = canonical_server_dev_path(&root_cloud, &entry.handle, rdev)
        {
            let _ = file_ref.close().await;
            drain_releases(vfs);
            return self
                .open_server_device_fd(
                    pid,
                    page_sudo,
                    canonical_dev,
                    flags,
                    mode,
                    cloexec,
                    size,
                    sha256,
                    version,
                )
                .await;
        }

        let mut st = vfs::stat::stat(&entry.handle.fs, entry.handle.node, &entry.metadata);
        self.fill_stat_names(vfs, pid, &mut st).await;
        if let Some(sid) = page_sid {
            let append = (flags & abi::O_APPEND) != 0;
            let chunk_size = if append {
                abi::INLINE_MAX
            } else {
                abi::remote_fs::DATA_MAX
            };
            let alloc_res = {
                let mut rt = self.vfs_rt.borrow_mut();
                let sess = rt
                    .page_session_mut(sid)
                    .filter(|s| epoch.as_ref().is_some_and(|e| Rc::ptr_eq(e, &s.epoch)))
                    .ok_or(Errno::ESTALE)?;
                sess.alloc_page_fd(PageOpenFd {
                    file: file_ref,
                    path: path.to_string(),
                    creation,
                    cloexec,
                    append,
                    created,
                    chunk_size,
                    expected_size: size,
                    digest: sha256.map(|expected| {
                        Rc::new(UploadDigest {
                            expected,
                            sequential: Mutex::new(Some((0, Sha256::new()))),
                            fresh_contents: created || flags & abi::O_TRUNC != 0,
                        })
                    }),
                })
            };
            let pfd = alloc_res.map_err(abi::Error::from)?;
            return Ok((
                pfd,
                json!({
                    "fd": pfd,
                    "size": st.size,
                    "chunk_size": chunk_size,
                    "created": created,
                    "stat": st,
                    "committed": [],
                    "resumed": false,
                }),
            ));
        }

        let fd = match vfs
            .process_fds(pid)
            .and_then(|fds| fds.borrow_mut().insert(file_ref, cloexec))
        {
            Ok(fd) => fd,
            Err(e) => {
                drain_releases(vfs);
                return Err(e.into());
            }
        };
        if let Some(meta) = self.vfs_rt.borrow_mut().proc_meta.get_mut(&pid) {
            meta.attenuated_kfds.remove(&fd);
        }
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

    #[allow(clippy::too_many_arguments)]
    async fn eval_close_call(
        &self,
        vfs: &Vfs,
        pid: u32,
        page_session_id: Option<&str>,
        fd_epoch: Option<&str>,
        page_sudo: bool,
        raw_fd: u32,
        discard: bool,
    ) -> std::result::Result<Value, abi::Error> {
        if let Some(sid) = page_session_id {
            if raw_fd >= CLIENT_PAGE_FD_BASE {
                let removed = {
                    let mut rt = self.vfs_rt.borrow_mut();
                    rt.page_session_mut(sid)
                        .and_then(|s| s.page_fds.remove(&raw_fd))
                };
                let Some(entry) = removed else {
                    return Err(Errno::EBADF.into());
                };
                if discard {
                    let unlink = Self::discard_created_file(&entry).await;
                    entry.file.close().await?;
                    unlink?;
                    drain_releases(vfs);
                    return Ok(Value::Null);
                }
                let verify_upload = entry.expected_size.is_some() || entry.digest.is_some();
                if !verify_upload {
                    let mut pre_stat = entry.file.metadata().await.ok().map(|meta| {
                        vfs::stat::stat(entry.file.fs().id(), entry.file.handle().node, &meta)
                    });
                    let sync = if entry.file.access().writes() {
                        entry.file.sync_all().await
                    } else {
                        Ok(())
                    };
                    let close_res = entry.file.close().await;
                    sync?;
                    drain_releases(vfs);
                    if let Err(err) = close_res
                        && err != Errno::ESTALE
                    {
                        return Err(err.into());
                    }
                    if let Some(st) = pre_stat.as_mut() {
                        self.fill_stat_names(vfs, pid, st).await;
                        return Ok(json!({
                            "path": entry.path,
                            "size": st.size,
                            "created": entry.created,
                            "stat": st,
                        }));
                    }
                    return Ok(json!({
                        "path": entry.path,
                        "created": entry.created,
                    }));
                }
                let progress = match &entry.digest {
                    Some(digest) => Some(digest.sequential.lock().await),
                    None => None,
                };
                let verified_meta: std::result::Result<vfs::Metadata, abi::Error> = async {
                    if entry.file.access().writes() {
                        entry.file.sync_all().await?;
                    }
                    let meta = entry.file.metadata().await?;
                    if let Some(exp_size) = entry.expected_size
                        && meta.size != exp_size
                    {
                        return Err(Errno::EIO.into());
                    }
                    if let (Some(digest), Some(progress)) = (&entry.digest, &progress) {
                        Self::verify_page_digest(vfs, &entry.file, meta.size, digest, progress)
                            .await?;
                    }
                    Ok(meta)
                }
                .await;
                let meta = match verified_meta {
                    Ok(m) => m,
                    Err(err) => {
                        let _ = Self::discard_created_file(&entry).await;
                        let _ = entry.file.close().await;
                        drain_releases(vfs);
                        return Err(err);
                    }
                };
                let mut st = vfs::stat::stat(entry.file.fs().id(), entry.file.handle().node, &meta);
                entry.file.close().await?;
                drain_releases(vfs);
                self.fill_stat_names(vfs, pid, &mut st).await;
                return Ok(json!({
                    "path": entry.path,
                    "size": st.size,
                    "created": entry.created,
                    "stat": st,
                }));
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
            let remote = self.vfs_rt.borrow().page_session(sid).and_then(|s| {
                s.delegated_uploads
                    .get(&raw_fd)
                    .map(|(remote, _)| remote.clone())
            });
            if let Some(expected) = fd_epoch
                && remote.as_ref().is_none_or(|fd| fd.fd_epoch != expected)
            {
                return Err(Errno::EBADF.into());
            }
            if let Some(remote) = remote {
                let result = remote.call(call, page_sudo).await;
                // An incomplete upload may have released its fd while reporting a commit error.
                let released = result.is_ok()
                    || matches!(result, Err(Errno::EBADF))
                    || matches!(remote.close(page_sudo).await, Ok(_) | Err(Errno::EBADF));
                if released {
                    let mut rt = self.vfs_rt.borrow_mut();
                    if let Some(session) = rt.page_session_mut(sid)
                        && let std::collections::hash_map::Entry::Occupied(entry) =
                            session.delegated_uploads.entry(raw_fd)
                        && entry.get().0.fd_epoch == remote.fd_epoch
                    {
                        entry.remove();
                    }
                    let closed_path = result.as_ref().ok().and_then(|v| v["path"].as_str());
                    rt.root_cloud.invalidate_uploaded_path(closed_path);
                }
                return result.map_err(Into::into);
            }
            return self.forward_server_call(pid, page_sudo, call).await;
        }

        if (SERVER_DEV_FD_BASE..CLIENT_PAGE_FD_BASE).contains(&raw_fd) {
            return self.release_server_fd(pid, raw_fd, discard).await;
        }

        if let Ok(fds) = vfs.process_fds(pid)
            && fds.borrow().get(raw_fd).is_ok()
        {
            let scope_pid = self.scope_pid_for_kfd(pid, raw_fd).unwrap_or(pid);
            if let Some(meta) = self.vfs_rt.borrow_mut().proc_meta.get_mut(&pid) {
                meta.attenuated_kfds.remove(&raw_fd);
            }
            self.with_proc_scope(scope_pid, async { vfs.close(pid, raw_fd).await })
                .await?;
            return Ok(Value::Null);
        }
        Err(Errno::EBADF.into())
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
        let attr = SetAttr {
            mode: Some(mode),
            ..SetAttr::default()
        };
        if let Some(sid) = page_session_id {
            if raw_fd >= CLIENT_PAGE_FD_BASE {
                let (file, cred) = {
                    let rt = self.vfs_rt.borrow();
                    let sess = rt.page_session(sid).ok_or(Errno::EBADF)?;
                    let file = sess
                        .page_fds
                        .get(&raw_fd)
                        .map(|e| e.file.clone())
                        .ok_or(Errno::EBADF)?;
                    let mut cred = sess.cred(0o022);
                    if page_sudo {
                        cred.identity = Identity::root();
                    }
                    (file, cred)
                };
                file.setattr_as(&cred, &attr).await?;
                return Ok(Value::Null);
            }
            return self
                .forward_server_call(
                    pid,
                    page_sudo,
                    Call::Fchmod {
                        fd: FdRef::Fd(raw_fd),
                        mode,
                    },
                )
                .await;
        }
        if (SERVER_DEV_FD_BASE..CLIENT_PAGE_FD_BASE).contains(&raw_fd) {
            let (sfd, attenuated) = self.resolve_process_server_fd_entry(pid, raw_fd)?;
            let call = Call::Fchmod {
                fd: FdRef::Fd(sfd),
                mode,
            };
            return match attenuated {
                Some((owner_pid, owner_tok)) => {
                    self.forward_server_call_attenuated(owner_pid, &owner_tok, call)
                        .await
                }
                None => self.forward_server_call(pid, page_sudo, call).await,
            };
        }
        let scope_pid = self.scope_pid_for_kfd(pid, raw_fd)?;
        self.with_proc_scope(scope_pid, async { vfs.fsetattr(pid, raw_fd, &attr).await })
            .await?;
        Ok(Value::Null)
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
            let meta = file_ref.metadata().await.ok();
            let _ = file_ref.close().await;
            let n = res?;
            buf.truncate(n);
            let mut st = vfs::stat::stat(&entry.handle.fs, entry.handle.node, &entry.metadata);
            let size = meta.map(|m| m.size).unwrap_or(st.size);
            st.size = size;
            self.fill_stat_names(vfs, pid, &mut st).await;
            return Ok(json!({ "data": Bytes(buf), "size": size, "stat": st }));
        }
        let raw_fd = parse_fd_ref(fd.ok_or(Errno::EBADF)?, fd_refs)?;
        if let Some(sid) = page_session_id {
            if raw_fd >= CLIENT_PAGE_FD_BASE {
                let file = {
                    let rt = self.vfs_rt.borrow();
                    rt.page_session(sid)
                        .and_then(|s| s.page_fds.get(&raw_fd))
                        .map(|e| e.file.clone())
                        .ok_or(Errno::EBADF)?
                };
                let mut buf = vec![0u8; cap];
                let n = file.read_at(&mut buf, offset).await?;
                let size = file.metadata().await.map(|m| m.size).unwrap_or(n as u64);
                buf.truncate(n);
                return Ok(json!({ "data": Bytes(buf), "size": size }));
            }
            return self
                .forward_server_call(
                    pid,
                    page_sudo,
                    Call::Pread {
                        fd: Some(FdRef::Fd(raw_fd)),
                        path: None,
                        offset,
                        count,
                    },
                )
                .await;
        }
        if (SERVER_DEV_FD_BASE..CLIENT_PAGE_FD_BASE).contains(&raw_fd) {
            let (sfd, attenuated) = self.resolve_process_server_fd_entry(pid, raw_fd)?;
            let call = Call::Pread {
                fd: Some(FdRef::Fd(sfd)),
                path: None,
                offset,
                count,
            };
            return match attenuated {
                Some((owner_pid, owner_tok)) => {
                    self.forward_server_call_attenuated(owner_pid, &owner_tok, call)
                        .await
                }
                None => self.forward_server_call(pid, page_sudo, call).await,
            };
        }
        if let Ok(fds) = vfs.process_fds(pid)
            && let Ok(file) = {
                let tbl = fds.borrow();
                tbl.get(raw_fd)
            }
        {
            let scope_pid = self.scope_pid_for_kfd(pid, raw_fd)?;
            let mut buf = vec![0u8; cap];
            let (n, meta) = self
                .with_proc_scope(scope_pid, async {
                    let n = vfs.pread(pid, raw_fd, &mut buf, offset).await?;
                    let meta = file.metadata().await.ok();
                    Ok::<_, Errno>((n, meta))
                })
                .await?;
            let size = meta.map(|m| m.size).unwrap_or(n as u64);
            buf.truncate(n);
            return Ok(json!({ "data": Bytes(buf), "size": size }));
        }
        Err(Errno::EBADF.into())
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
        if let Some(sid) = page_session_id {
            if raw_fd >= CLIENT_PAGE_FD_BASE {
                let entry = self
                    .vfs_rt
                    .borrow()
                    .page_session(sid)
                    .and_then(|s| s.page_fds.get(&raw_fd))
                    .cloned()
                    .ok_or(Errno::EBADF)?;
                let offset = index.checked_mul(entry.chunk_size).ok_or(Errno::EFBIG)?;
                let written = entry.write(entry.file.cred(), &data, offset).await?;
                return Ok(json!({ "written": written }));
            }
            return self
                .forward_server_call(
                    pid,
                    page_sudo,
                    Call::Pwrite {
                        fd: FdRef::Fd(raw_fd),
                        index,
                        data: Bytes(data),
                    },
                )
                .await;
        }
        if (SERVER_DEV_FD_BASE..CLIENT_PAGE_FD_BASE).contains(&raw_fd) {
            let (sfd, attenuated) = self.resolve_process_server_fd_entry(pid, raw_fd)?;
            let call = Call::Pwrite {
                fd: FdRef::Fd(sfd),
                index,
                data: Bytes(data),
            };
            return match attenuated {
                Some((owner_pid, owner_tok)) => {
                    self.forward_server_call_attenuated(owner_pid, &owner_tok, call)
                        .await
                }
                None => self.forward_server_call(pid, page_sudo, call).await,
            };
        }
        if let Ok(fds) = vfs.process_fds(pid)
            && fds.borrow().get(raw_fd).is_ok()
        {
            let scope_pid = self.scope_pid_for_kfd(pid, raw_fd)?;
            let offset = index.checked_mul(abi::INLINE_MAX).ok_or(Errno::EFBIG)?;
            let written = self
                .with_proc_scope(scope_pid, async {
                    vfs.pwrite(pid, raw_fd, &data, offset).await
                })
                .await?;
            return Ok(json!({ "written": written }));
        }
        Err(Errno::EBADF.into())
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
        //    client descriptors (`kfd`, `OS_FD_CWD`, `OS_FD_ROOT`) into `PathAt.open` (`OpenRef`)
        //    for `CloudFs`, or a temporary server `O_PATH | O_DIRECTORY` fd for system `/usr`
        //    `ImageFs` directories!
        let (target_fd, attenuated_dev) =
            if (SERVER_DEV_FD_BASE..CLIENT_PAGE_FD_BASE).contains(&raw_fd) {
                self.resolve_process_server_fd_entry(pid, raw_fd)?
            } else {
                (raw_fd, None)
            };
        let mut temp_usr_fds: Vec<u32> = Vec::new();
        let ioctl_res = async {
            if request == accelerator::SUBMIT {
                // High #1 (`U-10`): `accelerator::SUBMIT` carries external `PathAt` file/dir
                // operands evaluated by the server under the request token's identity. Never
                // delegate a higher-privileged sender's identity to authorize files the receiver
                // cannot access: fail closed with `EACCES` unless the receiver has `cloud_access`
                // and identical `(uid, gid, groups)` to the active, unrevoked sender!
                if let Some((owner_pid, owner_tok)) = &attenuated_dev {
                    let receiver_denied = self.vfs_rt.borrow().root_cloud.is_pid_cloud_denied(pid);
                    let authorized = !receiver_denied && {
                        let st = self.state.borrow();
                        if st.pending_revocations.contains(owner_tok) {
                            false
                        } else if let (Some(recv), Some(owner)) =
                            (st.table.proc(pid), st.table.proc(*owner_pid))
                        {
                            recv.state != abi::ProcState::Zombie
                                && owner.state != abi::ProcState::Zombie
                                && recv.cred.cloud_access
                                && owner.cred.cloud_access
                                && owner
                                    .cred
                                    .remote
                                    .as_ref()
                                    .is_some_and(|r| r.token == *owner_tok)
                                && recv.cred.identity.id == owner.cred.identity.id
                                && recv.cred.identity.group == owner.cred.identity.group
                                && recv.cred.identity.groups == owner.cred.identity.groups
                        } else {
                            false
                        }
                    };
                    if !authorized {
                        return Err(Errno::EACCES.into());
                    }
                }
                let mut submit: Submit =
                    serde_json::from_value(arg).map_err(|_| abi::Error::from(Errno::EINVAL))?;
                match &mut submit.operation {
                    Operation::Create { output, inputs, .. } => {
                        self.rewrite_accel_path_at(
                            vfs,
                            pid,
                            page_sudo,
                            output,
                            true,
                            &mut temp_usr_fds,
                        )
                        .await?;
                        for inp in inputs {
                            self.rewrite_accel_path_at(
                                vfs,
                                pid,
                                page_sudo,
                                &mut inp.source,
                                false,
                                &mut temp_usr_fds,
                            )
                            .await?;
                        }
                    }
                    Operation::Extract {
                        source,
                        destination,
                        ..
                    } => {
                        self.rewrite_accel_path_at(
                            vfs,
                            pid,
                            page_sudo,
                            source,
                            false,
                            &mut temp_usr_fds,
                        )
                        .await?;
                        self.rewrite_accel_path_at(
                            vfs,
                            pid,
                            page_sudo,
                            destination,
                            true,
                            &mut temp_usr_fds,
                        )
                        .await?;
                    }
                    Operation::List { source, .. } => {
                        self.rewrite_accel_path_at(
                            vfs,
                            pid,
                            page_sudo,
                            source,
                            false,
                            &mut temp_usr_fds,
                        )
                        .await?;
                    }
                    Operation::Faststart { file } => {
                        self.rewrite_accel_path_at(
                            vfs,
                            pid,
                            page_sudo,
                            file,
                            true,
                            &mut temp_usr_fds,
                        )
                        .await?;
                    }
                }
                arg = serde_json::to_value(submit).map_err(|_| abi::Error::from(Errno::EIO))?;
            }

            let ioctl_call = Call::Ioctl {
                fd: FdRef::Fd(target_fd),
                request,
                arg,
            };
            match &attenuated_dev {
                Some((owner_pid, owner_tok)) => {
                    self.forward_server_call_attenuated(*owner_pid, owner_tok, ioctl_call)
                        .await
                }
                None => self.forward_server_call(pid, page_sudo, ioctl_call).await,
            }
        }
        .await;
        for sfd in temp_usr_fds {
            let _ = self
                .forward_server_call(pid, page_sudo, Call::Close { fd: FdRef::Fd(sfd) })
                .await;
        }
        ioctl_res
    }

    async fn rewrite_accel_path_at(
        &self,
        vfs: &Vfs,
        pid: u32,
        page_sudo: bool,
        pat: &mut PathAt,
        mutating: bool,
        temp_usr_fds: &mut Vec<u32>,
    ) -> std::result::Result<(), abi::Error> {
        pat.open = None;
        let (root_cloud, usr_fs_id) = {
            let rt = self.vfs_rt.borrow();
            (Rc::clone(&rt.root_cloud), rt.usr_fs_id.clone())
        };
        let dir_fd = pat.directory as i32;
        let (pin, handle, open_ref) = if dir_fd == OS_FD_ROOT {
            let fs_ctx = vfs.process_fs_context(pid)?;
            let root_anchor = fs_ctx.borrow().root.clone();
            (
                root_anchor.pin,
                root_anchor.handle,
                root_anchor.open.open_ref().clone(),
            )
        } else if dir_fd == OS_FD_CWD || dir_fd == -100 {
            let fs_ctx = vfs.process_fs_context(pid)?;
            let cwd_anchor = fs_ctx.borrow().cwd.clone();
            (
                cwd_anchor.pin,
                cwd_anchor.handle,
                cwd_anchor.open.open_ref().clone(),
            )
        } else {
            let fds = vfs.process_fds(pid)?;
            let dir_file = fds.borrow().get(pat.directory)?;
            let pin = dir_file.mount_pin().ok_or(Errno::EXDEV)?.clone();
            (pin, dir_file.handle().clone(), dir_file.open_ref().clone())
        };

        if pin.fs().id() == &usr_fs_id {
            if mutating {
                return Err(Errno::EROFS.into());
            }
            if root_cloud.is_pid_cloud_denied(pid) {
                return Err(Errno::EACCES.into());
            }
            let fs = pin.fs();
            let root_cred = Cred::root();
            let meta = fs.metadata(&root_cred, &handle).await?;
            if !meta.is_dir() {
                return Err(Errno::ENOTDIR.into());
            }
            let mut parts = Vec::new();
            let mut cur = handle;
            let mut seen = std::collections::HashSet::from([cur.node]);
            while let Some((parent_entry, name)) = fs.parent(&root_cred, &cur).await? {
                parts.push(name);
                if !seen.insert(parent_entry.handle.node) {
                    return Err(Errno::ESTALE.into());
                }
                cur = parent_entry.handle;
            }
            parts.reverse();
            let usr_dir_path = if parts.is_empty() {
                "/".to_string()
            } else {
                format!("/{}", parts.join("/"))
            };
            if usr_dir_path != "/usr" && !usr_dir_path.starts_with("/usr/") {
                return Err(Errno::EXDEV.into());
            }
            let opened = self
                .forward_server_call(
                    pid,
                    page_sudo,
                    Call::Open {
                        path: usr_dir_path,
                        flags: abi::O_PATH | abi::O_DIRECTORY,
                        mode: 0,
                        size: None,
                        sha256: None,
                        version: None,
                    },
                )
                .await?;
            let server_fd = opened
                .get("fd")
                .and_then(|v| v.as_u64())
                .and_then(|v| u32::try_from(v).ok())
                .ok_or_else(|| abi::Error::from(Errno::EIO))?;
            temp_usr_fds.push(server_fd);
            pat.open = None;
            pat.directory = server_fd;
            return Ok(());
        }

        if pin.fstype() != vfs::FsType::Cloud {
            return Err(Errno::EXDEV.into());
        }
        if mutating && pin.effective_rdonly() {
            return Err(Errno::EROFS.into());
        }
        let real_open = root_cloud
            .real_cloud_open_ref(&open_ref)
            .ok_or(Errno::EBADF)?;
        pat.open = Some(real_open);
        Ok(())
    }

    async fn forward_server_call(
        &self,
        pid: u32,
        page_sudo: bool,
        call: Call,
    ) -> std::result::Result<Value, abi::Error> {
        let fs_session = self.vfs_rt.borrow().root_cloud.current_fs_session();
        let is_page_call = page_sudo || pid >= SCOPED_PAGE_PID_BASE;
        if !is_page_call {
            if self.vfs_rt.borrow().root_cloud.is_pid_cloud_denied(pid)
                || self
                    .state
                    .borrow()
                    .table
                    .proc(pid)
                    .is_some_and(|p| !p.cred.cloud_access)
            {
                return Err(Errno::EACCES.into());
            }
            let rem = crate::lazy_mint_remote_cred(&self.state, pid).await?;
            self.sync_vfs_proc_creds(pid);
            let tok = rem.token;
            let instance_id = self.state.borrow().instance_id.clone();
            let batch = Batch {
                calls: vec![call],
                umask: None,
                sudo: false,
                pid: Some(pid),
                process: Some(tok.clone()),
            };
            let Ok((global, post)) = installed("cloudFsPost") else {
                return Err(Errno::ENOTCONN.into());
            };
            let body = serde_json::to_vec(&batch)
                .map_err(|e| abi::Error::because(Errno::EIO, e.to_string()))?;
            let headers = js_sys::Object::new();
            let _ =
                js_sys::Reflect::set(&headers, &"Content-Type".into(), &"application/json".into());
            js_sys::Reflect::set(&headers, &"X-Process-Token".into(), &tok.into())
                .map_err(|_| Errno::EIO)?;
            if !instance_id.is_empty() {
                js_sys::Reflect::set(&headers, &"X-OS-Instance".into(), &instance_id.into())
                    .map_err(|_| Errno::EIO)?;
            }
            if let Some((ref sid, ref secret)) = fs_session
                && !sid.is_empty()
                && !secret.is_empty()
            {
                let _ = js_sys::Reflect::set(&headers, &"X-Fs-Session".into(), &sid.into());
                let _ = js_sys::Reflect::set(&headers, &"X-Fs-Secret".into(), &secret.into());
            }
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
                let text = String::from_utf8_lossy(&bytes);
                if let Ok(err_val) = serde_json::from_str::<Value>(&text)
                    && let Some(code) = err_val["errno"].as_str()
                    && let Ok(parsed) =
                        serde_json::from_value::<Errno>(Value::String(code.to_string()))
                {
                    return Err(abi::Error::because(
                        parsed,
                        err_val["error"].as_str().unwrap_or(""),
                    ));
                }
                return Err(abi::Error::because(Errno::EIO, text.into_owned()));
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
            let mut res = page_sys_batch_with_session(
                Batch {
                    calls: vec![call],
                    umask: None,
                    sudo: page_sudo,
                    pid: None,
                    process: None,
                },
                fs_session.as_ref().map(|(s, k)| (s.as_str(), k.as_str())),
            )
            .await?;
            return res.pop().ok_or(Errno::EIO)?.into_result();
        }
        Err(Errno::ENOSYS.into())
    }
}
