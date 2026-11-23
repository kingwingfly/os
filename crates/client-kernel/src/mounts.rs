//! Client-kernel local mount path & descriptor facade over [`vfs::Filesystem`] (Issues #48/#49/#50).
//!
//! Replaces the legacy JavaScript `PermissionMount` (`web/kernel/mount-policy.js`) and `workspace.js`
//! `nextInode` counter: every local mount (`browser-storage` OPFS, `directory` handle, `snapshot`,
//! and `native-directory` helper) runs through `Rc<dyn vfs::Filesystem>` and maps `Metadata` to
//! `abi::Stat` solely via [`vfs::stat::stat`].

use abi::fs::{FileType, LockFamily, LockKind, LockRange, OpenOptions, RenameFlags, XattrFlags};
use abi::{Errno, O_CREAT, O_DIRECTORY, O_EXCL, O_TRUNC, Time};

const O_NOFOLLOW: u32 = 0o400000;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet, VecDeque};
use std::rc::{Rc, Weak};
use vfs::{
    Access, Cred, Entry, Filesystem, FsId, Handle, Identity, Metadata, NodeId, OpenRef, SetAttr,
    WriteAt,
};
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

const SYMLINK_MAX: usize = 40;
const CHUNK_READ_MAX: usize = 1024 * 1024;
const IMAGE_MAX: u64 = 128 * 1024 * 1024;

/// Host capability grant shared by `hostfs.rs` and `helper.rs`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Grant {
    pub kind: String,
    pub name: String,
    #[serde(rename = "readOnly", alias = "read_only")]
    pub read_only: bool,
    pub execute: bool,
    pub owner: Identity,
}

#[derive(Deserialize)]
struct JsIdentityInput {
    #[serde(alias = "uid")]
    id: u32,
    #[serde(default, alias = "gid")]
    group: Option<u32>,
    #[serde(default)]
    groups: Vec<u32>,
}

impl JsIdentityInput {
    fn into_identity(self) -> Identity {
        let group = self.group.unwrap_or(self.id);
        let mut groups: std::collections::BTreeSet<u32> = self.groups.into_iter().collect();
        groups.insert(group);
        Identity {
            id: self.id,
            group,
            groups,
        }
    }
}

pub(crate) fn parse_identity(val: &JsValue) -> Result<Identity, JsValue> {
    let text = js_sys::JSON::stringify(val)
        .map_err(|_| js_errno(Errno::EINVAL, "invalid identity"))?
        .as_string()
        .ok_or_else(|| js_errno(Errno::EINVAL, "invalid identity"))?;
    let parsed: JsIdentityInput =
        serde_json::from_str(&text).map_err(|_| js_errno(Errno::EINVAL, "invalid identity"))?;
    Ok(parsed.into_identity())
}

pub(crate) fn errno_code(errno: Errno) -> String {
    serde_json::to_value(errno)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "EIO".to_string())
}

pub(crate) fn js_errno(errno: Errno, detail: &str) -> JsValue {
    let msg = if detail.is_empty() {
        errno.text()
    } else {
        detail
    };
    let err = js_sys::Error::new(msg);
    let _ = js_sys::Reflect::set(
        &err,
        &JsValue::from_str("errno"),
        &JsValue::from_str(&errno_code(errno)),
    );
    err.into()
}

pub(crate) fn map_vfs_err(errno: Errno) -> JsValue {
    js_errno(errno, "")
}

pub(crate) fn extract_js_errno(err: &JsValue) -> Errno {
    if let Some(code) = js_sys::Reflect::get(err, &JsValue::from_str("errno"))
        .ok()
        .and_then(|v| v.as_string())
        && let Ok(parsed) = serde_json::from_value::<Errno>(Value::String(code))
    {
        return parsed;
    }
    if let Some(name) = js_sys::Reflect::get(err, &JsValue::from_str("name"))
        .ok()
        .and_then(|v| v.as_string())
    {
        return match name.as_str() {
            "NotAllowedError" | "SecurityError" => Errno::EACCES,
            "NotFoundError" => Errno::ENOENT,
            "TypeMismatchError" => Errno::ENOTDIR,
            "InvalidModificationError" => Errno::ENOTEMPTY,
            "NoModificationAllowedError" => Errno::EBUSY,
            "QuotaExceededError" => Errno::EDQUOT,
            "NotSupportedError" => Errno::EOPNOTSUPP,
            _ => Errno::EIO,
        };
    }
    Errno::EIO
}

fn json_to_js(value: &Value) -> Result<JsValue, JsValue> {
    let text = serde_json::to_string(value).map_err(|_| js_errno(Errno::EIO, "serialize"))?;
    js_sys::JSON::parse(&text).map_err(|_| js_errno(Errno::EIO, "parse json"))
}

fn js_to_json(val: &JsValue) -> Result<Value, JsValue> {
    if val.is_undefined() || val.is_null() {
        return Ok(Value::Null);
    }
    let text = js_sys::JSON::stringify(val)
        .map_err(|_| js_errno(Errno::EINVAL, "invalid options"))?
        .as_string()
        .ok_or_else(|| js_errno(Errno::EINVAL, "invalid options"))?;
    serde_json::from_str(&text).map_err(|_| js_errno(Errno::EINVAL, "invalid options"))
}

fn build_grant_js(grant: &Grant) -> JsValue {
    let obj = js_sys::Object::new();
    let _ = js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("kind"),
        &JsValue::from_str(&grant.kind),
    );
    let _ = js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("name"),
        &JsValue::from_str(&grant.name),
    );
    let _ = js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("readOnly"),
        &JsValue::from_bool(grant.read_only),
    );
    let _ = js_sys::Reflect::set(
        &obj,
        &JsValue::from_str("execute"),
        &JsValue::from_bool(grant.execute),
    );
    js_sys::Object::freeze(&obj).into()
}

fn clean_rel_path(path: &str) -> std::result::Result<(Vec<String>, bool), Errno> {
    if path.len() > 4096 || path.contains('\0') || path.contains('\\') {
        return Err(Errno::EACCES);
    }
    if path.starts_with('/') {
        return Err(Errno::EACCES);
    }
    let trailing_dir = path.ends_with('/') || path.ends_with("/.");
    let raw_parts: Vec<&str> = path.split('/').collect();
    if raw_parts.len() > 256 {
        return Err(Errno::EACCES);
    }
    let mut out = Vec::new();
    for part in raw_parts {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            return Err(Errno::EACCES);
        }
        if part.len() > abi::NAME_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        out.push(part.to_string());
    }
    Ok((out, trailing_dir))
}

fn parse_u16_field(val: &Value, key: &str) -> std::result::Result<Option<u16>, Errno> {
    match val.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .map(Some)
            .ok_or(Errno::EINVAL),
    }
}

fn parse_u32_field(val: &Value, key: &str) -> std::result::Result<Option<u32>, Errno> {
    match val.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .map(Some)
            .ok_or(Errno::EINVAL),
    }
}

fn parse_off_field(val: &Value, key: &str) -> std::result::Result<Option<u64>, Errno> {
    match val.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .filter(|&n| n <= abi::fs::FILE_MAX)
            .map(Some)
            .ok_or(Errno::EINVAL),
    }
}

fn push_target_segments(
    queue: &mut VecDeque<String>,
    link_target: &str,
) -> std::result::Result<(), Errno> {
    if link_target.is_empty() || link_target.starts_with('/') {
        return Err(Errno::ENOENT);
    }
    let mut segments = Vec::new();
    for seg in link_target.split('/') {
        if seg.is_empty() {
            continue;
        }
        if seg != "." && seg != ".." && seg.len() > abi::NAME_MAX {
            return Err(Errno::ENAMETOOLONG);
        }
        segments.push(seg.to_string());
    }
    for seg in segments.into_iter().rev() {
        queue.push_front(seg);
    }
    Ok(())
}

struct WalkFrame {
    entry: Entry,
    component: Option<String>,
    searchable: bool,
}

enum WalkOutcome {
    Found {
        entry: Entry,
        parts: Vec<String>,
    },
    MissingLast {
        parent: Entry,
        name: String,
        parts: Vec<String>,
    },
}

type OpenTable = RefCell<HashMap<u64, RetainedOpen>>;
type OpenMap = Rc<OpenTable>;

thread_local! {
    static INODE_POLICY_REV: RefCell<HashMap<(FsId, NodeId), u64>> = RefCell::new(HashMap::new());
    static FS_POLICY_REV: RefCell<HashMap<FsId, u64>> = RefCell::new(HashMap::new());
}

fn current_inode_policy_rev(fs: &FsId, node: NodeId) -> u64 {
    INODE_POLICY_REV.with(|m| m.borrow().get(&(fs.clone(), node)).copied().unwrap_or(0))
}

fn current_fs_policy_rev(fs: &FsId) -> u64 {
    FS_POLICY_REV.with(|m| m.borrow().get(fs).copied().unwrap_or(0))
}

fn bump_fs_policy_rev(fs: &FsId) {
    FS_POLICY_REV.with(|m| {
        let mut map = m.borrow_mut();
        let entry = map.entry(fs.clone()).or_insert(0);
        *entry = entry.wrapping_add(1);
    });
}

fn bump_inode_policy_rev(fs: &FsId, node: NodeId) {
    INODE_POLICY_REV.with(|m| {
        let mut map = m.borrow_mut();
        let entry = map.entry((fs.clone(), node)).or_insert(0);
        *entry = entry.wrapping_add(1);
    });
    bump_fs_policy_rev(fs);
}

#[derive(Clone, PartialEq, Eq)]
struct CreatedPolicy {
    rev: u64,
    uid: u32,
    gid: u32,
    mode: u16,
    acl: bool,
    acl_bytes: Option<Vec<u8>>,
}

struct SnapshotFs(Rc<dyn Filesystem>);

impl Filesystem for SnapshotFs {
    fn id(&self) -> &FsId {
        self.0.id()
    }
    fn capabilities(&self) -> abi::contract::FsCapabilities {
        let mut caps = self.0.capabilities();
        caps.open_survives_unlink = abi::contract::Support::Refused(Errno::EROFS);
        caps
    }
    fn root(&self) -> Handle {
        self.0.root()
    }
    fn lookup<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
    ) -> vfs::BoxFuture<'a, Entry> {
        self.0.lookup(cred, dir, name)
    }
    fn walk<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        names: &'a [String],
    ) -> vfs::BoxFuture<'a, vfs::Walked> {
        self.0.walk(cred, dir, names)
    }
    fn parent<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
    ) -> vfs::BoxFuture<'a, Option<(Entry, String)>> {
        self.0.parent(cred, dir)
    }
    fn metadata<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> vfs::BoxFuture<'a, Metadata> {
        self.0.metadata(cred, handle)
    }
    fn setattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        attr: &'a SetAttr,
    ) -> vfs::BoxFuture<'a, Metadata> {
        if attr.size.is_some() {
            return Box::pin(async { Err(Errno::EROFS) });
        }
        self.0.setattr(cred, handle, attr)
    }
    fn read_dir<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
    ) -> vfs::BoxFuture<'a, Vec<vfs::DirEntry>> {
        self.0.read_dir(cred, dir)
    }
    fn read_link<'a>(&'a self, cred: &'a Cred, link: &'a Handle) -> vfs::BoxFuture<'a, String> {
        self.0.read_link(cred, link)
    }
    fn create<'a>(
        &'a self,
        _cred: &'a Cred,
        _dir: &'a Handle,
        _name: &'a str,
        _mode: u16,
        _options: &'a OpenOptions,
    ) -> vfs::BoxFuture<'a, (Entry, OpenRef)> {
        Box::pin(async { Err(Errno::EROFS) })
    }
    fn mkdir<'a>(
        &'a self,
        _cred: &'a Cred,
        _dir: &'a Handle,
        _name: &'a str,
        _mode: u16,
    ) -> vfs::BoxFuture<'a, Entry> {
        Box::pin(async { Err(Errno::EROFS) })
    }
    fn mknod<'a>(
        &'a self,
        _cred: &'a Cred,
        _dir: &'a Handle,
        _name: &'a str,
        _mode: u16,
        _rdev: &'a str,
    ) -> vfs::BoxFuture<'a, Entry> {
        Box::pin(async { Err(Errno::EROFS) })
    }
    fn symlink<'a>(
        &'a self,
        _cred: &'a Cred,
        _dir: &'a Handle,
        _name: &'a str,
        _target: &'a str,
    ) -> vfs::BoxFuture<'a, Entry> {
        Box::pin(async { Err(Errno::EROFS) })
    }
    fn link<'a>(
        &'a self,
        _cred: &'a Cred,
        _target: &'a Handle,
        _dir: &'a Handle,
        _name: &'a str,
    ) -> vfs::BoxFuture<'a, Entry> {
        Box::pin(async { Err(Errno::EROFS) })
    }
    fn unlink<'a>(
        &'a self,
        _cred: &'a Cred,
        _dir: &'a Handle,
        _name: &'a str,
    ) -> vfs::BoxFuture<'a, ()> {
        Box::pin(async { Err(Errno::EROFS) })
    }
    fn rmdir<'a>(
        &'a self,
        _cred: &'a Cred,
        _dir: &'a Handle,
        _name: &'a str,
    ) -> vfs::BoxFuture<'a, ()> {
        Box::pin(async { Err(Errno::EROFS) })
    }
    fn rename<'a>(
        &'a self,
        _cred: &'a Cred,
        _from_dir: &'a Handle,
        _from: &'a str,
        _to_dir: &'a Handle,
        _to: &'a str,
        _flags: RenameFlags,
    ) -> vfs::BoxFuture<'a, ()> {
        Box::pin(async { Err(Errno::EROFS) })
    }
    fn getxattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> vfs::BoxFuture<'a, Vec<u8>> {
        self.0.getxattr(cred, handle, name)
    }
    fn setxattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
        value: &'a [u8],
        flags: XattrFlags,
    ) -> vfs::BoxFuture<'a, ()> {
        self.0.setxattr(cred, handle, name, value, flags)
    }
    fn listxattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
    ) -> vfs::BoxFuture<'a, Vec<String>> {
        self.0.listxattr(cred, handle)
    }
    fn removexattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> vfs::BoxFuture<'a, ()> {
        self.0.removexattr(cred, handle, name)
    }
    fn statfs<'a>(&'a self, cred: &'a Cred) -> vfs::BoxFuture<'a, vfs::StatFs> {
        self.0.statfs(cred)
    }
    fn open<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        options: &'a OpenOptions,
    ) -> vfs::BoxFuture<'a, OpenRef> {
        Box::pin(async move {
            let access = options.access()?;
            if access != Access::Path && (access.writes() || options.is_truncate()) {
                return Err(Errno::EROFS);
            }
            self.0.open(cred, handle, options).await
        })
    }
    fn open_metadata<'a>(&'a self, open: &'a OpenRef) -> vfs::BoxFuture<'a, Metadata> {
        self.0.open_metadata(open)
    }
    fn read_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a mut [u8],
        offset: u64,
    ) -> vfs::BoxFuture<'a, usize> {
        self.0.read_at(open, buf, offset)
    }
    fn write_at<'a>(
        &'a self,
        _open: &'a OpenRef,
        _buf: &'a [u8],
        _at: WriteAt,
    ) -> vfs::BoxFuture<'a, vfs::Written> {
        Box::pin(async { Err(Errno::EROFS) })
    }
    fn set_len<'a>(&'a self, _open: &'a OpenRef, _size: u64) -> vfs::BoxFuture<'a, ()> {
        Box::pin(async { Err(Errno::EROFS) })
    }
    fn sync_all<'a>(&'a self, open: &'a OpenRef) -> vfs::BoxFuture<'a, ()> {
        self.0.sync_all(open)
    }
    fn sync_data<'a>(&'a self, open: &'a OpenRef) -> vfs::BoxFuture<'a, ()> {
        self.0.sync_data(open)
    }
    fn lock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> vfs::BoxFuture<'a, ()> {
        self.0.lock(open, family, kind, range)
    }
    fn try_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> vfs::BoxFuture<'a, ()> {
        self.0.try_lock(open, family, kind, range)
    }
    fn unlock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        range: LockRange,
    ) -> vfs::BoxFuture<'a, ()> {
        self.0.unlock(open, family, range)
    }
    fn test_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        kind: LockKind,
        range: LockRange,
    ) -> vfs::BoxFuture<'a, Option<vfs::Conflict>> {
        self.0.test_lock(open, kind, range)
    }
    fn release<'a>(&'a self, open: &'a OpenRef) -> vfs::BoxFuture<'a, ()> {
        self.0.release(open)
    }
}

struct SharedMountState {
    fs: Rc<dyn Filesystem>,
    provider_state: Rc<vfs::ProviderState>,
    grant: Grant,
    grant_js: JsValue,
    active: Cell<bool>,
    snapshot_data_ro: bool,
    known_paths: RefCell<HashMap<vfs::NodeId, Vec<String>>>,
    unmount_fn: RefCell<Option<Box<dyn FnOnce()>>>,
    views: RefCell<Vec<Weak<OpenTable>>>,
}

impl SharedMountState {
    fn register_view(&self, opens: &OpenMap) {
        let mut views = self.views.borrow_mut();
        views.retain(|w| w.strong_count() > 0);
        views.push(Rc::downgrade(opens));
    }

    fn lose_provider(&self) {
        self.provider_state.lose();
        self.shutdown();
    }

    fn revoke_provider(&self) {
        self.provider_state.revoke();
        self.shutdown();
    }

    fn shutdown(&self) {
        self.active.set(false);
        let mut drained = Vec::new();
        for weak in self.views.borrow().iter() {
            if let Some(map) = weak.upgrade() {
                drained.extend(map.borrow_mut().drain().map(|(_, v)| v));
            }
        }
        self.views.borrow_mut().clear();
        let unmount_cb = self.unmount_fn.borrow_mut().take();
        if drained.is_empty() {
            if let Some(cb) = unmount_cb {
                cb();
            }
            return;
        }
        let fs = Rc::clone(&self.fs);
        wasm_bindgen_futures::spawn_local(async move {
            for item in drained {
                let _ = fs.release(&item.open_ref).await;
            }
            drop(fs);
            if let Some(cb) = unmount_cb {
                cb();
            }
        });
    }
}

struct RetainedOpen {
    token: JsValue,
    open_ref: OpenRef,
    handle: Handle,
    path: String,
    append: bool,
    held: bool,
    created_policy: Option<CreatedPolicy>,
}

struct OpenLookup {
    id: u64,
    open_ref: OpenRef,
    handle: Handle,
    path: String,
    append: bool,
    held: bool,
    created_policy: Option<CreatedPolicy>,
}

/// Wasm-exported local mount provider wrapping an `Rc<dyn vfs::Filesystem>`.
#[wasm_bindgen]
pub struct LocalMount {
    state: Rc<SharedMountState>,
    identity: Identity,
    boundary: Vec<String>,
    remote: bool,
    next_local_open: Rc<Cell<u64>>,
    path_checks: HashMap<Vec<String>, NodeId>,
    opens: OpenMap,
}

/// Construct a [`LocalMount`] over any [`Filesystem`] implementation (used by `hostfs` and `helper`).
#[allow(dead_code)]
pub fn from_fs(fs: Rc<dyn Filesystem>, grant: Grant) -> LocalMount {
    LocalMount::from_fs(fs, grant)
}

/// Construct a [`LocalMount`] with a host cleanup callback invoked once upon `unmount`.
pub fn from_fs_with_unmount(
    fs: Rc<dyn Filesystem>,
    grant: Grant,
    on_unmount: impl FnOnce() + 'static,
) -> LocalMount {
    LocalMount::from_fs_with_unmount(fs, grant, on_unmount)
}

impl LocalMount {
    #[allow(dead_code)]
    pub fn from_fs(fs: Rc<dyn Filesystem>, grant: Grant) -> Self {
        Self::new_internal(fs, grant, false, None)
    }

    pub fn from_fs_with_unmount(
        fs: Rc<dyn Filesystem>,
        grant: Grant,
        on_unmount: impl FnOnce() + 'static,
    ) -> Self {
        Self::new_internal(fs, grant, false, Some(Box::new(on_unmount)))
    }

    pub(crate) fn from_snapshot(fs: Rc<dyn Filesystem>, grant: Grant) -> Self {
        Self::new_internal(fs, grant, true, None)
    }

    fn new_internal(
        fs: Rc<dyn Filesystem>,
        grant: Grant,
        snapshot_data_ro: bool,
        on_unmount: Option<Box<dyn FnOnce()>>,
    ) -> Self {
        let identity = grant.owner.clone();
        let grant_js = build_grant_js(&grant);
        let opens = Rc::new(RefCell::new(HashMap::new()));
        let state = Rc::new(SharedMountState {
            fs,
            provider_state: vfs::ProviderState::new(),
            grant,
            grant_js,
            active: Cell::new(true),
            snapshot_data_ro,
            known_paths: RefCell::new(HashMap::new()),
            unmount_fn: RefCell::new(on_unmount),
            views: RefCell::new(Vec::new()),
        });
        state.register_view(&opens);
        Self {
            state,
            identity,
            boundary: Vec::new(),
            remote: false,
            next_local_open: Rc::new(Cell::new(1)),
            path_checks: HashMap::new(),
            opens,
        }
    }

    pub(crate) fn lose_callback(&self) -> Rc<dyn Fn()> {
        let state = Rc::clone(&self.state);
        Rc::new(move || state.lose_provider())
    }

    pub(crate) fn revoke_callback(&self) -> Rc<dyn Fn()> {
        let state = Rc::clone(&self.state);
        Rc::new(move || state.revoke_provider())
    }

    pub(crate) fn mount_backing(&self, fstype: vfs::FsType) -> Rc<vfs::MountBacking> {
        let fs: Rc<dyn Filesystem> = if self.state.snapshot_data_ro {
            Rc::new(SnapshotFs(Rc::clone(&self.state.fs)))
        } else {
            Rc::clone(&self.state.fs)
        };
        let rdonly_ceiling = self.state.grant.read_only && !self.state.snapshot_data_ro;
        let noexec_ceiling = !self.state.grant.execute;
        let state_for_release = Rc::clone(&self.state);
        Rc::new(
            vfs::MountBacking::new(fs, fstype)
                .with_provider(Rc::clone(&self.state.provider_state))
                .with_ceilings(rdonly_ceiling, noexec_ceiling)
                .with_on_release(move || state_for_release.shutdown()),
        )
    }

    pub(crate) fn provider_state(&self) -> Rc<vfs::ProviderState> {
        Rc::clone(&self.state.provider_state)
    }

    pub(crate) fn grant_info(&self) -> &Grant {
        &self.state.grant
    }

    fn check_grant(&self, grant: &JsValue) -> std::result::Result<(), Errno> {
        if !js_sys::Object::is(grant, &self.state.grant_js) {
            return Err(Errno::EACCES);
        }
        if !self.state.active.get() {
            return Err(Errno::ENODEV);
        }
        Ok(())
    }

    fn require_data_writable(&self) -> std::result::Result<(), Errno> {
        if self.state.grant.read_only || self.state.snapshot_data_ro {
            return Err(Errno::EROFS);
        }
        Ok(())
    }

    fn cred(&self, umask: Option<u16>) -> Cred {
        Cred {
            identity: self.identity.clone(),
            umask: umask.unwrap_or(0o077) & 0o777,
            token: None,
        }
    }

    fn owner_cred(&self) -> Cred {
        Cred {
            identity: self.state.grant.owner.clone(),
            umask: 0o077,
            token: None,
        }
    }

    fn check_within_boundary(&self, parts: &[String]) -> std::result::Result<(), Errno> {
        if parts.len() < self.boundary.len() {
            return Err(Errno::EACCES);
        }
        for (a, b) in self.boundary.iter().zip(parts.iter()) {
            if a != b {
                return Err(Errno::EACCES);
            }
        }
        Ok(())
    }

    fn mint_js_handle(
        &self,
        open_ref: OpenRef,
        handle: Handle,
        path: String,
        append: bool,
        held: bool,
        created_policy: Option<CreatedPolicy>,
    ) -> JsValue {
        let id = self.next_local_open.get();
        self.next_local_open.set(id + 1);
        let token_obj = js_sys::Object::new();
        let _ = js_sys::Reflect::set(
            &token_obj,
            &JsValue::from_str("__localHandle"),
            &JsValue::from_f64(id as f64),
        );
        let token: JsValue = js_sys::Object::freeze(&token_obj).into();
        {
            let mut kp = self.state.known_paths.borrow_mut();
            let list = kp.entry(handle.node).or_default();
            if !list.contains(&path) {
                list.push(path.clone());
            }
        }
        self.opens.borrow_mut().insert(
            id,
            RetainedOpen {
                token: token.clone(),
                open_ref,
                handle,
                path,
                append,
                held,
                created_policy,
            },
        );
        token
    }

    fn lookup_open(&self, val: &JsValue) -> std::result::Result<OpenLookup, Errno> {
        let id = js_sys::Reflect::get(val, &JsValue::from_str("__localHandle"))
            .ok()
            .and_then(|v| v.as_f64())
            .map(|n| n as u64)
            .ok_or(Errno::EBADF)?;
        let opens = self.opens.borrow();
        let entry = opens.get(&id).ok_or(Errno::EBADF)?;
        if !js_sys::Object::is(&entry.token, val) {
            return Err(Errno::EBADF);
        }
        Ok(OpenLookup {
            id,
            open_ref: entry.open_ref.clone(),
            handle: entry.handle.clone(),
            path: entry.path.clone(),
            append: entry.append,
            held: entry.held,
            created_policy: entry.created_policy.clone(),
        })
    }

    async fn walk_to_boundary(&self, cred: &Cred) -> std::result::Result<Vec<WalkFrame>, Errno> {
        let fs = &self.state.fs;
        let owner_cred = self.owner_cred();
        let root_cred = if self.boundary.is_empty() {
            cred
        } else {
            &owner_cred
        };
        let root_handle = fs.root();
        let root_meta = fs.metadata(root_cred, &root_handle).await?;
        let mut stack = vec![WalkFrame {
            entry: Entry {
                handle: root_handle,
                metadata: root_meta,
            },
            component: None,
            searchable: false,
        }];
        for comp in &self.boundary {
            let parent_handle = stack.last().expect("root").entry.handle.clone();
            let entry = fs.lookup(&owner_cred, &parent_handle, comp).await?;
            if self.remote && entry.metadata.file_type == FileType::Symlink {
                return Err(Errno::ELOOP);
            }
            if entry.metadata.file_type != FileType::Dir {
                return Err(Errno::ENOTDIR);
            }
            stack.last_mut().expect("root").searchable = true;
            stack.push(WalkFrame {
                entry,
                component: Some(comp.clone()),
                searchable: false,
            });
        }
        // Reset search check on the boundary directory so the acting credential is verified
        // whenever stepping into user-supplied segments or `.` / `..`.
        stack.last_mut().expect("boundary").searchable = false;
        Ok(stack)
    }

    async fn ensure_searchable(
        &self,
        cred: &Cred,
        frame: &mut WalkFrame,
    ) -> std::result::Result<(), Errno> {
        if frame.searchable {
            return Ok(());
        }
        if frame.entry.metadata.file_type != FileType::Dir {
            return Err(Errno::ENOTDIR);
        }
        match self.state.fs.lookup(cred, &frame.entry.handle, "_").await {
            Ok(_) | Err(Errno::ENOENT) => {
                frame.searchable = true;
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    async fn resolve_walk(
        &self,
        cred: &Cred,
        initial_parts: Vec<String>,
        follow_last: bool,
        mut trailing_dir: bool,
        allow_missing_last: bool,
    ) -> std::result::Result<WalkOutcome, Errno> {
        self.check_within_boundary(&initial_parts)?;
        let fs = &self.state.fs;
        let mut stack = self.walk_to_boundary(cred).await?;
        if self
            .path_checks
            .get(&self.boundary)
            .is_some_and(|n| *n != stack.last().expect("boundary").entry.handle.node)
        {
            return Err(Errno::ESTALE);
        }
        let boundary_stack_len = stack.len();
        let mut queue: VecDeque<String> = initial_parts[self.boundary.len()..]
            .iter()
            .cloned()
            .collect();
        let mut depth = 0usize;

        while let Some(front) = queue.front().map(String::as_str) {
            match front {
                "." => {
                    self.ensure_searchable(cred, stack.last_mut().expect("boundary"))
                        .await?;
                    queue.pop_front();
                }
                ".." => {
                    self.ensure_searchable(cred, stack.last_mut().expect("boundary"))
                        .await?;
                    queue.pop_front();
                    if stack.len() <= boundary_stack_len {
                        return Err(Errno::ELOOP);
                    }
                    stack.pop();
                }
                _ => {
                    let name = queue.pop_front().expect("front");
                    if name.len() > abi::NAME_MAX {
                        return Err(Errno::ENAMETOOLONG);
                    }
                    let is_last = queue.is_empty();
                    let parent_entry = stack.last().expect("boundary").entry.clone();
                    let checked_prefix: Vec<_> = if self.path_checks.is_empty() {
                        Vec::new()
                    } else {
                        stack
                            .iter()
                            .filter_map(|frame| frame.component.clone())
                            .chain(std::iter::once(name.clone()))
                            .collect()
                    };
                    let expected = self.path_checks.get(&checked_prefix);
                    match fs.lookup(cred, &parent_entry.handle, &name).await {
                        Ok(next) => {
                            if expected.is_some_and(|node| *node != next.handle.node)
                                || next.metadata.is_symlink()
                                    && self.path_checks.keys().any(|path| {
                                        path.len() > checked_prefix.len()
                                            && path.starts_with(&checked_prefix)
                                    })
                            {
                                return Err(Errno::ESTALE);
                            }
                            stack.last_mut().expect("boundary").searchable = true;
                            if next.metadata.file_type == FileType::Symlink
                                && (!is_last || follow_last || trailing_dir)
                            {
                                if matches!(
                                    fs.capabilities().identity,
                                    abi::contract::IdentityScope::HostLocal
                                ) {
                                    return Err(Errno::ELOOP);
                                }
                                if !vfs::descriptions::may_follow_link(
                                    cred,
                                    &parent_entry.metadata,
                                    &next.metadata,
                                ) {
                                    return Err(Errno::EACCES);
                                }
                                depth += 1;
                                if depth > SYMLINK_MAX {
                                    return Err(Errno::ELOOP);
                                }
                                let link_target = fs.read_link(cred, &next.handle).await?;
                                push_target_segments(&mut queue, &link_target)?;
                                if is_last
                                    && (link_target.ends_with('/') || link_target.ends_with("/."))
                                {
                                    trailing_dir = true;
                                }
                                continue;
                            }
                            if is_last {
                                if trailing_dir && next.metadata.file_type != FileType::Dir {
                                    return Err(Errno::ENOTDIR);
                                }
                                let parts = stack
                                    .iter()
                                    .filter_map(|f| f.component.clone())
                                    .chain(std::iter::once(name))
                                    .collect();
                                return Ok(WalkOutcome::Found { entry: next, parts });
                            }
                            if next.metadata.file_type != FileType::Dir {
                                return Err(Errno::ENOTDIR);
                            }
                            stack.push(WalkFrame {
                                entry: next,
                                component: Some(name),
                                searchable: false,
                            });
                        }
                        Err(Errno::ENOENT) if expected.is_some() => return Err(Errno::ESTALE),
                        Err(Errno::ENOENT) if allow_missing_last && is_last => {
                            if trailing_dir {
                                return Err(Errno::EISDIR);
                            }
                            let parts = stack
                                .iter()
                                .filter_map(|f| f.component.clone())
                                .chain(std::iter::once(name.clone()))
                                .collect();
                            return Ok(WalkOutcome::MissingLast {
                                parent: parent_entry,
                                name,
                                parts,
                            });
                        }
                        Err(err) => return Err(err),
                    }
                }
            }
        }

        let top = stack.last().expect("boundary");
        if trailing_dir && top.entry.metadata.file_type != FileType::Dir {
            return Err(Errno::ENOTDIR);
        }
        let parts = stack.iter().filter_map(|f| f.component.clone()).collect();
        Ok(WalkOutcome::Found {
            entry: top.entry.clone(),
            parts,
        })
    }

    async fn resolve_parts(
        &self,
        cred: &Cred,
        initial_parts: Vec<String>,
        follow_last: bool,
        trailing_dir: bool,
    ) -> std::result::Result<(Entry, Vec<String>), Errno> {
        match self
            .resolve_walk(cred, initial_parts, follow_last, trailing_dir, false)
            .await?
        {
            WalkOutcome::Found { entry, parts } => Ok((entry, parts)),
            WalkOutcome::MissingLast { .. } => Err(Errno::ENOENT),
        }
    }

    async fn resolve_parent(
        &self,
        cred: &Cred,
        path: &str,
    ) -> std::result::Result<(Entry, String, Vec<String>), Errno> {
        let (parts, trailing_dir) = clean_rel_path(path)?;
        if parts.is_empty() || parts == self.boundary {
            return Err(Errno::EBUSY);
        }
        let mut parent_parts = parts.clone();
        let name = parent_parts.pop().ok_or(Errno::EBUSY)?;
        let (parent_entry, mut resolved_parent) =
            self.resolve_parts(cred, parent_parts, true, true).await?;
        if parent_entry.metadata.file_type != FileType::Dir {
            return Err(Errno::ENOTDIR);
        }
        let _ = trailing_dir;
        resolved_parent.push(name.clone());
        self.check_within_boundary(&resolved_parent)?;
        Ok((parent_entry, name, resolved_parent))
    }

    async fn verify_boundary_search(&self, cred: &Cred) -> std::result::Result<(), Errno> {
        let fs = &self.state.fs;
        let owner_cred = self.owner_cred();
        let mut cur = fs.root();
        for comp in &self.boundary {
            let entry = fs.lookup(&owner_cred, &cur, comp).await?;
            if self.remote && entry.metadata.file_type == FileType::Symlink {
                return Err(Errno::ELOOP);
            }
            cur = entry.handle;
        }
        // Check search (`EXEC`) permission on the boundary directory itself by probing `"."`-free
        // directory open/read_dir? No: `lookup` of any missing child checks `require_searchable`
        // BEFORE looking up the child! Even cleaner: lookup a reserved name? Wait: if boundary
        // lacks `EXEC`, `lookup(cred, &cur, ...)` fails with `EACCES` before returning `ENOENT`!
        match fs.lookup(cred, &cur, ".__os_search_probe__").await {
            Ok(_) | Err(Errno::ENOENT) => Ok(()),
            Err(err) => Err(err),
        }
    }

    async fn check_access_entry(
        &self,
        cred: &Cred,
        entry: &Entry,
        mode: u16,
    ) -> std::result::Result<(), Errno> {
        if mode & 2 != 0 {
            self.require_data_writable()?;
        }
        if mode & 1 != 0 && entry.metadata.file_type != FileType::Dir && !self.state.grant.execute {
            return Err(Errno::EACCES);
        }
        let fs = &self.state.fs;
        if mode == 0 {
            return Ok(());
        }
        if entry.metadata.file_type == FileType::Dir {
            if mode & 4 != 0 {
                let _ = fs.read_dir(cred, &entry.handle).await?;
            }
            if mode & 1 != 0 {
                match fs.lookup(cred, &entry.handle, ".__os_search_probe__").await {
                    Ok(_) | Err(Errno::ENOENT) => {}
                    Err(err) => return Err(err),
                }
            }
            if mode & 2 != 0 {
                // Check directory write permission via `os_core` / inode rules: on directories,
                // owner/group/ACL write bit is required alongside search (`3` in POSIX).
                // Probe `unlink` of a guaranteed-absent name? Wait: `do_remove` resolves child BEFORE
                // `may_delete`, whereas `mknod` checks `ENOENT` then `may_create` only for root!
                // Instead, check directory mode / ACL directly from `Metadata` + `ACL_ACCESS`!
                self.check_dir_write_perm(cred, entry).await?;
            }
            return Ok(());
        }
        if mode & 4 != 0 {
            let o = fs
                .open(cred, &entry.handle, OpenOptions::new().read(true))
                .await?;
            let _ = fs.release(&o).await;
        }
        if mode & 2 != 0 {
            let o = fs
                .open(cred, &entry.handle, OpenOptions::new().write(true))
                .await?;
            let _ = fs.release(&o).await;
        }
        if mode & 1 != 0 {
            let o = fs
                .open(cred, &entry.handle, OpenOptions::new().exec(true))
                .await?;
            let _ = fs.release(&o).await;
        }
        Ok(())
    }

    async fn check_dir_write_perm(
        &self,
        cred: &Cred,
        entry: &Entry,
    ) -> std::result::Result<(), Errno> {
        if cred.identity.id == 0 {
            return Ok(());
        }
        let m = &entry.metadata;
        if m.acl
            && let Ok(raw) = self
                .state
                .fs
                .getxattr(cred, &entry.handle, abi::ACL_ACCESS)
                .await
            && let Ok(acl) = serde_json::from_slice::<Value>(&raw)
        {
            let mask = acl
                .get("mask")
                .and_then(Value::as_u64)
                .unwrap_or(((m.mode >> 3) & 7) as u64) as u16;
            if cred.identity.id == m.uid {
                let u = acl
                    .get("user")
                    .and_then(Value::as_u64)
                    .unwrap_or(((m.mode >> 6) & 7) as u64) as u16;
                return if u & 2 != 0 {
                    Ok(())
                } else {
                    Err(Errno::EACCES)
                };
            }
            if let Some(u_map) = acl.get("users").and_then(Value::as_object)
                && let Some(bits) = u_map
                    .get(&cred.identity.id.to_string())
                    .and_then(Value::as_u64)
            {
                return if (bits as u16 & mask & 2) != 0 {
                    Ok(())
                } else {
                    Err(Errno::EACCES)
                };
            }
            let mut group_matched = false;
            let mut group_allowed = false;
            if cred.identity.groups.contains(&m.gid) {
                group_matched = true;
                let g = acl
                    .get("group")
                    .and_then(Value::as_u64)
                    .unwrap_or(((m.mode >> 3) & 7) as u64) as u16;
                if (g & mask & 2) != 0 {
                    group_allowed = true;
                }
            }
            if let Some(g_map) = acl.get("groups").and_then(Value::as_object) {
                for gid in &cred.identity.groups {
                    if let Some(bits) = g_map.get(&gid.to_string()).and_then(Value::as_u64) {
                        group_matched = true;
                        if (bits as u16 & mask & 2) != 0 {
                            group_allowed = true;
                        }
                    }
                }
            }
            if group_matched {
                return if group_allowed {
                    Ok(())
                } else {
                    Err(Errno::EACCES)
                };
            }
            let other = acl
                .get("other")
                .and_then(Value::as_u64)
                .unwrap_or((m.mode & 7) as u64) as u16;
            return if other & 2 != 0 {
                Ok(())
            } else {
                Err(Errno::EACCES)
            };
        }

        let bits = if cred.identity.id == m.uid {
            (m.mode >> 6) & 7
        } else if cred.identity.groups.contains(&m.gid) {
            (m.mode >> 3) & 7
        } else {
            m.mode & 7
        };
        if bits & 2 != 0 {
            Ok(())
        } else {
            Err(Errno::EACCES)
        }
    }

    fn record_known_path(&self, node: NodeId, rel: String) {
        if rel.is_empty() {
            return;
        }
        let mut kp = self.state.known_paths.borrow_mut();
        let list = kp.entry(node).or_default();
        if !list.contains(&rel) {
            list.push(rel);
        }
    }

    fn prune_known_paths(&self, rel: &str, is_dir: bool, keep_node: Option<NodeId>) {
        if rel.is_empty() {
            return;
        }
        let prefix = format!("{rel}/");
        let mut kp = self.state.known_paths.borrow_mut();
        kp.retain(|node, paths| {
            if keep_node == Some(*node) {
                return true;
            }
            paths.retain(|p| p != rel && (!is_dir || !p.starts_with(&prefix)));
            !paths.is_empty()
        });
    }

    async fn revalidate_live_path(
        &self,
        cred: &Cred,
        open: &OpenLookup,
        meta: &Metadata,
    ) -> std::result::Result<(), Errno> {
        let fs = &self.state.fs;
        let owner_cred = self.owner_cred();
        let boundary_stack = self.walk_to_boundary(cred).await?;
        let boundary_handle = boundary_stack
            .last()
            .expect("boundary")
            .entry
            .handle
            .clone();

        if meta.file_type == FileType::Dir {
            if open.handle.node == boundary_handle.node {
                let rel = self.boundary.join("/");
                self.record_known_path(open.handle.node, rel);
                return Ok(());
            }
            let mut rev_names = Vec::new();
            let mut cur = open.handle.clone();
            let mut seen = HashSet::from([cur.node]);
            while cur.node != boundary_handle.node {
                let Some((parent_entry, name)) = fs.parent(&owner_cred, &cur).await? else {
                    return Err(Errno::ESTALE);
                };
                rev_names.push(name);
                if !seen.insert(parent_entry.handle.node) {
                    return Err(Errno::ESTALE);
                }
                cur = parent_entry.handle;
            }
            rev_names.reverse();
            let mut parts = self.boundary.clone();
            parts.extend(rev_names);
            let (live, _) = self
                .resolve_parts(cred, parts.clone(), false, false)
                .await?;
            if live.handle.node != open.handle.node {
                return Err(Errno::ESTALE);
            }
            self.record_known_path(open.handle.node, parts.join("/"));
            return Ok(());
        }

        let mut queue = VecDeque::from([(boundary_handle.clone(), self.boundary.clone())]);
        let mut visited = HashSet::from([boundary_handle.node]);
        let mut saw_eacces = false;
        while let Some((dir_handle, dir_parts)) = queue.pop_front() {
            let Ok(entries) = fs.read_dir(&owner_cred, &dir_handle).await else {
                continue;
            };
            for entry in entries {
                let mut child_parts = dir_parts.clone();
                child_parts.push(entry.name.clone());
                if entry.node == open.handle.node {
                    match self
                        .resolve_parts(cred, child_parts.clone(), false, false)
                        .await
                    {
                        Ok((live, _)) if live.handle.node == open.handle.node => {
                            self.record_known_path(open.handle.node, child_parts.join("/"));
                            return Ok(());
                        }
                        Err(Errno::EACCES) => {
                            saw_eacces = true;
                        }
                        _ => {}
                    }
                }
                if entry.file_type == FileType::Dir
                    && visited.insert(entry.node)
                    && let Ok(sub) = fs.lookup(&owner_cred, &dir_handle, &entry.name).await
                {
                    queue.push_back((sub.handle, child_parts));
                }
            }
        }
        Err(if saw_eacces {
            Errno::EACCES
        } else {
            Errno::ESTALE
        })
    }

    async fn verify_remote_open_live(
        &self,
        cred: &Cred,
        open: &OpenLookup,
        required_access: Access,
    ) -> std::result::Result<(), Errno> {
        if !self.remote {
            return Ok(());
        }
        self.verify_boundary_search(cred).await?;
        let meta = self.state.fs.open_metadata(&open.open_ref).await?;
        let creator_keeps_access = if let Some(ref created) = open.created_policy {
            let access_ok = match required_access {
                Access::Read => open.open_ref.access.reads(),
                Access::Write => open.open_ref.access.writes(),
                Access::ReadWrite => open.open_ref.access.reads() && open.open_ref.access.writes(),
                Access::Exec | Access::Path => false,
            };
            let same_rev =
                current_inode_policy_rev(self.state.fs.id(), open.handle.node) == created.rev;
            let same_meta = meta.uid == created.uid
                && meta.gid == created.gid
                && meta.mode == created.mode
                && meta.acl == created.acl;
            let same_acl = if !created.acl {
                true
            } else if !meta.acl {
                false
            } else {
                self.state
                    .fs
                    .getxattr(&self.owner_cred(), &open.handle, "system.posix_acl_access")
                    .await
                    .ok()
                    == created.acl_bytes
            };
            access_ok && same_rev && same_meta && same_acl
        } else {
            false
        };
        if required_access != Access::Path && !creator_keeps_access {
            let mut opts = OpenOptions::new();
            match required_access {
                Access::Read => {
                    opts.read(true);
                }
                Access::Write => {
                    opts.write(true);
                }
                Access::ReadWrite => {
                    opts.read(true).write(true);
                }
                Access::Exec => {
                    opts.exec(true);
                }
                Access::Path => {}
            }
            let probe = self.state.fs.open(cred, &open.handle, &opts).await?;
            let _ = self.state.fs.release(&probe).await;
        }
        if meta.nlink > 0 {
            let mut candidates: Vec<String> = self
                .state
                .known_paths
                .borrow()
                .get(&open.handle.node)
                .cloned()
                .unwrap_or_default();
            if !open.path.is_empty() && !candidates.iter().any(|p| p == &open.path) {
                candidates.push(open.path.clone());
            }
            let mut reachable = false;
            for cand in candidates {
                let Ok((parts, _)) = clean_rel_path(&cand) else {
                    continue;
                };
                if self.check_within_boundary(&parts).is_err() {
                    continue;
                }
                if let Ok((live, _)) = self.resolve_parts(cred, parts, false, false).await
                    && live.handle.node == open.handle.node
                {
                    reachable = true;
                    break;
                }
            }
            if !reachable {
                self.revalidate_live_path(cred, open, &meta).await?;
            }
        }
        Ok(())
    }

    async fn open_or_create_target(
        &self,
        cred: &Cred,
        path: &str,
        nofollow: bool,
        mode: u16,
        options: &OpenOptions,
    ) -> std::result::Result<(Entry, OpenRef, Vec<String>, bool), Errno> {
        let (initial_parts, trailing_dir) = clean_rel_path(path)?;
        if trailing_dir {
            return Err(Errno::EISDIR);
        }
        let access = options.access()?;
        let follow_last = !options.is_create_new() && !nofollow;
        let mut retries = 0usize;

        loop {
            match self
                .resolve_walk(cred, initial_parts.clone(), follow_last, false, true)
                .await?
            {
                WalkOutcome::Found {
                    entry: existing,
                    parts: resolved_parts,
                } => {
                    if options.is_create_new() {
                        return Err(Errno::EEXIST);
                    }
                    if nofollow && existing.metadata.file_type == FileType::Symlink {
                        return Err(Errno::ELOOP);
                    }
                    if existing.metadata.file_type == FileType::Dir {
                        return Err(Errno::EISDIR);
                    }
                    if access != Access::Path && (access.writes() || options.is_truncate()) {
                        self.require_data_writable()?;
                    }
                    let mut open_opts = *options;
                    open_opts.create(false).create_new(false);
                    let open_ref = self
                        .state
                        .fs
                        .open(cred, &existing.handle, &open_opts)
                        .await?;
                    return Ok((existing, open_ref, resolved_parts, false));
                }
                WalkOutcome::MissingLast {
                    parent: parent_entry,
                    name,
                    parts: resolved_parts,
                } => {
                    self.require_data_writable()?;
                    // On shared exports (`self.remote`), until #59 adds multi-owner export policy,
                    // newly created nodes remain owned by the publishing account after verifying
                    // `self.identity` may create in `parent_entry`.
                    let create_cred = if self.remote {
                        self.check_access_entry(cred, &parent_entry, 3).await?;
                        Cred {
                            identity: self.state.grant.owner.clone(),
                            umask: cred.umask,
                            token: None,
                        }
                    } else {
                        cred.clone()
                    };
                    let mut create_opts = *options;
                    create_opts.create(true).create_new(true);
                    match self
                        .state
                        .fs
                        .create(
                            &create_cred,
                            &parent_entry.handle,
                            &name,
                            mode,
                            &create_opts,
                        )
                        .await
                    {
                        Ok((created_entry, open_ref)) => {
                            return Ok((created_entry, open_ref, resolved_parts, true));
                        }
                        Err(Errno::EEXIST) if !options.is_create_new() => {
                            retries += 1;
                            if retries > SYMLINK_MAX {
                                return Err(Errno::EEXIST);
                            }
                            continue;
                        }
                        Err(err) => return Err(err),
                    }
                }
            }
        }
    }

    async fn format_stat_js(
        &self,
        cred: &Cred,
        handle: &Handle,
        meta: &Metadata,
        name: &str,
    ) -> Result<JsValue, JsValue> {
        let fs = &self.state.fs;
        let mut st = vfs::stat::stat(fs.id(), handle.node, meta);
        let kind_str = match meta.file_type {
            FileType::Dir => "directory",
            FileType::Symlink => {
                if let Ok(target) = fs.read_link(cred, handle).await {
                    st.link = Some(target);
                }
                "symlink"
            }
            _ => "file",
        };
        let last_modified_ms =
            (meta.mtime.sec as f64) * 1000.0 + (meta.mtime.nsec as f64) / 1_000_000.0;
        let executable = meta.file_type == FileType::Dir
            || (self.state.grant.execute && (meta.mode & 0o111) != 0);
        let mut st_val = serde_json::to_value(&st).unwrap_or(Value::Null);
        st_val["generation"] = json!(handle.node.generation);
        let mut obj = json!({
            "kind": kind_str,
            "name": name,
            "size": if meta.file_type == FileType::File { meta.size } else { 0 },
            "lastModified": last_modified_ms,
            "readOnly": self.state.grant.read_only || self.state.snapshot_data_ro,
            "executable": executable,
            "nosymfollow": matches!(fs.capabilities().identity, abi::contract::IdentityScope::HostLocal),
            "fsId": fs.id().0,
            "vfs": st_val,
        });
        if let Some(ref link) = st.link {
            obj["link"] = Value::String(link.clone());
        }
        json_to_js(&obj)
    }
}

#[wasm_bindgen]
impl LocalMount {
    #[wasm_bindgen(getter)]
    pub fn grant(&self) -> JsValue {
        self.state.grant_js.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn owner(&self) -> Result<JsValue, JsValue> {
        let groups: Vec<u32> = self.state.grant.owner.groups.iter().copied().collect();
        json_to_js(&json!({
            "id": self.state.grant.owner.id,
            "group": self.state.grant.owner.group,
            "groups": groups,
        }))
    }

    #[wasm_bindgen(getter, js_name = identitySupported)]
    pub fn identity_supported(&self) -> bool {
        !self.state.fs.id().0.is_empty()
    }

    #[wasm_bindgen(getter, js_name = fsId)]
    pub fn fs_id(&self) -> String {
        self.state.fs.id().0.clone()
    }

    #[wasm_bindgen(js_name = withPathChecks)]
    pub fn with_path_checks(&self, checks: JsValue) -> Result<LocalMount, JsValue> {
        let checks: Vec<(String, NodeId)> =
            serde_json::from_value(js_to_json(&checks)?).map_err(|_| map_vfs_err(Errno::EINVAL))?;
        let mut path_checks = HashMap::new();
        for (path, node) in checks {
            let (parts, _) = clean_rel_path(&path).map_err(map_vfs_err)?;
            self.check_within_boundary(&parts).map_err(map_vfs_err)?;
            path_checks.insert(parts, node);
        }
        Ok(Self {
            state: self.state.clone(),
            identity: self.identity.clone(),
            boundary: self.boundary.clone(),
            remote: self.remote,
            next_local_open: self.next_local_open.clone(),
            opens: self.opens.clone(),
            path_checks,
        })
    }

    #[wasm_bindgen(js_name = forIdentity)]
    pub fn for_identity(&self, identity: JsValue, boundary: &str) -> Result<LocalMount, JsValue> {
        let parsed = parse_identity(&identity)?;
        let (boundary_parts, _) = clean_rel_path(boundary).map_err(map_vfs_err)?;
        let opens = Rc::new(RefCell::new(HashMap::new()));
        self.state.register_view(&opens);
        Ok(Self {
            state: Rc::clone(&self.state),
            identity: parsed,
            boundary: boundary_parts,
            remote: true,
            next_local_open: Rc::new(Cell::new(1)),
            path_checks: HashMap::new(),
            opens,
        })
    }

    pub async fn stat(
        &self,
        grant: JsValue,
        target: JsValue,
        options: JsValue,
    ) -> Result<JsValue, JsValue> {
        self.check_grant(&grant).map_err(map_vfs_err)?;
        let opts = js_to_json(&options)?;
        let follow = opts.get("follow").and_then(Value::as_bool).unwrap_or(true);
        let cred = self.cred(None);

        if target.is_object() {
            let open = self.lookup_open(&target).map_err(map_vfs_err)?;
            self.verify_remote_open_live(&cred, &open, open.open_ref.access)
                .await
                .map_err(map_vfs_err)?;
            let meta = self
                .state
                .fs
                .open_metadata(&open.open_ref)
                .await
                .map_err(map_vfs_err)?;
            let name = open.path.rsplit('/').next().unwrap_or("");
            return self.format_stat_js(&cred, &open.handle, &meta, name).await;
        }

        let path = target.as_string().unwrap_or_default();
        let (parts, trailing_dir) = clean_rel_path(&path).map_err(map_vfs_err)?;
        let (entry, resolved) = self
            .resolve_parts(&cred, parts, follow, trailing_dir)
            .await
            .map_err(map_vfs_err)?;
        let name = resolved.last().map_or("", String::as_str);
        self.format_stat_js(&cred, &entry.handle, &entry.metadata, name)
            .await
    }

    pub async fn access(&self, grant: JsValue, path: &str, mode: u16) -> Result<JsValue, JsValue> {
        self.check_grant(&grant).map_err(map_vfs_err)?;
        let cred = self.cred(None);
        let (parts, trailing_dir) = clean_rel_path(path).map_err(map_vfs_err)?;
        let (entry, _) = self
            .resolve_parts(&cred, parts, true, trailing_dir)
            .await
            .map_err(map_vfs_err)?;
        self.check_access_entry(&cred, &entry, mode)
            .await
            .map_err(map_vfs_err)?;
        Ok(JsValue::NULL)
    }

    pub async fn policy(
        &self,
        grant: JsValue,
        target: JsValue,
        name: &str,
        args: JsValue,
    ) -> Result<JsValue, JsValue> {
        self.check_grant(&grant).map_err(map_vfs_err)?;
        let arg_val = js_to_json(&args)?;
        let nofollow = arg_val
            .get("nofollow")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let follow = !nofollow && name != "lstat";
        let cred = self.cred(None);

        if matches!(
            name,
            "chmod" | "chown" | "setxattr" | "removexattr" | "utimens"
        ) && self.remote
        {
            return Err(map_vfs_err(Errno::EPERM));
        }

        let entry = if target.is_object() {
            let open = self.lookup_open(&target).map_err(map_vfs_err)?;
            if open.open_ref.access == Access::Path
                && !open.held
                && !matches!(name, "stat" | "lstat" | "statfs")
            {
                return Err(map_vfs_err(Errno::EBADF));
            }
            self.verify_remote_open_live(&cred, &open, open.open_ref.access)
                .await
                .map_err(map_vfs_err)?;
            let meta = self
                .state
                .fs
                .open_metadata(&open.open_ref)
                .await
                .map_err(map_vfs_err)?;
            Entry {
                handle: open.handle,
                metadata: meta,
            }
        } else {
            let path = target
                .as_string()
                .ok_or_else(|| map_vfs_err(Errno::EINVAL))?;
            if matches!(name, "unlink" | "rmdir") {
                return self.remove(grant, &path, name == "rmdir").await;
            }
            let (parts, trailing_dir) = clean_rel_path(&path).map_err(map_vfs_err)?;
            let (resolved_entry, _) = self
                .resolve_parts(&cred, parts, follow, trailing_dir)
                .await
                .map_err(map_vfs_err)?;
            resolved_entry
        };

        let fs = &self.state.fs;
        match name {
            "stat" | "lstat" => {
                let mut st = vfs::stat::stat(fs.id(), entry.handle.node, &entry.metadata);
                if entry.metadata.file_type == FileType::Symlink
                    && let Ok(link) = fs.read_link(&cred, &entry.handle).await
                {
                    st.link = Some(link);
                }
                json_to_js(&serde_json::to_value(st).unwrap_or(Value::Null))
            }
            "access" => {
                let mode = parse_u16_field(&arg_val, "mode")
                    .map_err(map_vfs_err)?
                    .unwrap_or(0);
                self.check_access_entry(&cred, &entry, mode)
                    .await
                    .map_err(map_vfs_err)?;
                Ok(JsValue::NULL)
            }
            "chmod" => {
                let mode = parse_u16_field(&arg_val, "mode")
                    .map_err(map_vfs_err)?
                    .ok_or_else(|| map_vfs_err(Errno::EINVAL))?;
                fs.setattr(
                    &cred,
                    &entry.handle,
                    &SetAttr {
                        mode: Some(mode),
                        ..SetAttr::default()
                    },
                )
                .await
                .map_err(map_vfs_err)?;
                bump_inode_policy_rev(fs.id(), entry.handle.node);
                Ok(JsValue::NULL)
            }
            "chown" => {
                let uid = parse_u32_field(&arg_val, "uid").map_err(map_vfs_err)?;
                let gid = parse_u32_field(&arg_val, "gid").map_err(map_vfs_err)?;
                fs.setattr(
                    &cred,
                    &entry.handle,
                    &SetAttr {
                        uid,
                        gid,
                        ..SetAttr::default()
                    },
                )
                .await
                .map_err(map_vfs_err)?;
                bump_inode_policy_rev(fs.id(), entry.handle.node);
                Ok(JsValue::NULL)
            }
            "utimens" => {
                let atime = arg_val
                    .get("atime")
                    .cloned()
                    .map(serde_json::from_value::<Time>)
                    .transpose()
                    .map_err(|_| map_vfs_err(Errno::EINVAL))?
                    .unwrap_or(Time::Now);
                let mtime = arg_val
                    .get("mtime")
                    .cloned()
                    .map(serde_json::from_value::<Time>)
                    .transpose()
                    .map_err(|_| map_vfs_err(Errno::EINVAL))?
                    .unwrap_or(Time::Now);
                fs.setattr(
                    &cred,
                    &entry.handle,
                    &SetAttr {
                        atime,
                        mtime,
                        ..SetAttr::default()
                    },
                )
                .await
                .map_err(map_vfs_err)?;
                Ok(JsValue::NULL)
            }
            "getxattr" => {
                let attr_name = arg_val
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| map_vfs_err(Errno::EINVAL))?;
                let bytes = fs
                    .getxattr(&cred, &entry.handle, attr_name)
                    .await
                    .map_err(map_vfs_err)?;
                json_to_js(&serde_json::to_value(abi::Bytes(bytes)).unwrap_or(Value::Null))
            }
            "setxattr" => {
                let attr_name = arg_val
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| map_vfs_err(Errno::EINVAL))?;
                let value: abi::Bytes =
                    serde_json::from_value(arg_val.get("value").cloned().unwrap_or(Value::Null))
                        .map_err(|_| map_vfs_err(Errno::EINVAL))?;
                let flags_raw = parse_u16_field(&arg_val, "flags")
                    .map_err(map_vfs_err)?
                    .unwrap_or(0);
                let flags_bits = u8::try_from(flags_raw).map_err(|_| map_vfs_err(Errno::EINVAL))?;
                let xflags =
                    XattrFlags::from_bits(flags_bits).ok_or_else(|| map_vfs_err(Errno::EINVAL))?;
                fs.setxattr(&cred, &entry.handle, attr_name, &value.0, xflags)
                    .await
                    .map_err(map_vfs_err)?;
                bump_inode_policy_rev(fs.id(), entry.handle.node);
                Ok(JsValue::NULL)
            }
            "listxattr" => {
                let list = fs
                    .listxattr(&cred, &entry.handle)
                    .await
                    .map_err(map_vfs_err)?;
                json_to_js(&serde_json::to_value(list).unwrap_or(Value::Null))
            }
            "removexattr" => {
                let attr_name = arg_val
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| map_vfs_err(Errno::EINVAL))?;
                fs.removexattr(&cred, &entry.handle, attr_name)
                    .await
                    .map_err(map_vfs_err)?;
                bump_inode_policy_rev(fs.id(), entry.handle.node);
                Ok(JsValue::NULL)
            }
            "statfs" => {
                let sfs = fs.statfs(&cred).await.map_err(map_vfs_err)?;
                let out = abi::StatFs {
                    bsize: sfs.block_size,
                    blocks: sfs.blocks,
                    bfree: sfs.blocks_free,
                    bavail: sfs.blocks_free,
                    files: sfs.files,
                    ffree: sfs.files_free,
                    namelen: sfs.name_max,
                    ..abi::StatFs::default()
                };
                json_to_js(&serde_json::to_value(out).unwrap_or(Value::Null))
            }
            _ => Err(map_vfs_err(Errno::EOPNOTSUPP)),
        }
    }

    pub async fn open(
        &self,
        grant: JsValue,
        path: &str,
        flags: u32,
        mode: Option<u16>,
        umask: Option<u16>,
        exec: Option<bool>,
    ) -> Result<JsValue, JsValue> {
        self.check_grant(&grant).map_err(map_vfs_err)?;
        if self.opens.borrow().len() >= 1024 {
            return Err(map_vfs_err(Errno::EMFILE));
        }
        let allowed_mask = abi::O_ACCMODE
            | O_CREAT
            | O_EXCL
            | O_TRUNC
            | abi::O_APPEND
            | O_DIRECTORY
            | O_NOFOLLOW
            | 0o2000000
            | 0o4000
            | abi::O_PATH;
        if flags & !allowed_mask != 0 {
            return Err(map_vfs_err(Errno::EOPNOTSUPP));
        }
        let exec_open = exec.unwrap_or(false);
        let mut options = OpenOptions::from_flags(flags).map_err(map_vfs_err)?;
        if exec_open {
            if flags & abi::O_PATH != 0
                || (flags & abi::O_ACCMODE) != abi::O_RDONLY
                || flags & O_DIRECTORY != 0
                || options.is_create()
                || options.is_truncate()
            {
                return Err(map_vfs_err(Errno::EINVAL));
            }
            if !self.state.grant.execute {
                return Err(map_vfs_err(Errno::EACCES));
            }
            options = *OpenOptions::new().exec(true);
        }
        let access = options.access().map_err(map_vfs_err)?;

        let cred = self.cred(umask);
        let nofollow = flags & O_NOFOLLOW != 0;
        let want_dir = flags & O_DIRECTORY != 0;

        if options.is_create() {
            if want_dir {
                return Err(map_vfs_err(Errno::EINVAL));
            }
            let req_mode = mode.unwrap_or(0o666);
            let (entry, open_ref, resolved_parts, created) = self
                .open_or_create_target(&cred, path, nofollow, req_mode, &options)
                .await
                .map_err(map_vfs_err)?;
            let created_policy = if created {
                let acl_bytes = if entry.metadata.acl {
                    self.state
                        .fs
                        .getxattr(&self.owner_cred(), &entry.handle, "system.posix_acl_access")
                        .await
                        .ok()
                } else {
                    None
                };
                Some(CreatedPolicy {
                    rev: current_inode_policy_rev(self.state.fs.id(), entry.handle.node),
                    uid: entry.metadata.uid,
                    gid: entry.metadata.gid,
                    mode: entry.metadata.mode,
                    acl: entry.metadata.acl,
                    acl_bytes,
                })
            } else {
                None
            };
            return Ok(self.mint_js_handle(
                open_ref,
                entry.handle,
                resolved_parts.join("/"),
                options.is_append(),
                false,
                created_policy,
            ));
        }

        let (parts, trailing_dir) = clean_rel_path(path).map_err(map_vfs_err)?;
        let (entry, resolved) = self
            .resolve_parts(&cred, parts, !nofollow, trailing_dir)
            .await
            .map_err(map_vfs_err)?;
        if access != Access::Path && nofollow && entry.metadata.file_type == FileType::Symlink {
            return Err(map_vfs_err(Errno::ELOOP));
        }
        if access == Access::Exec && entry.metadata.file_type == FileType::Dir {
            return Err(map_vfs_err(Errno::EACCES));
        }
        if access != Access::Path
            && (access.writes() || options.is_truncate())
            && entry.metadata.file_type == FileType::Dir
        {
            return Err(map_vfs_err(Errno::EISDIR));
        }
        if want_dir && entry.metadata.file_type != FileType::Dir {
            return Err(map_vfs_err(Errno::ENOTDIR));
        }
        if access != Access::Path && (access.writes() || options.is_truncate()) {
            self.require_data_writable().map_err(map_vfs_err)?;
        }
        let open_ref = self
            .state
            .fs
            .open(&cred, &entry.handle, &options)
            .await
            .map_err(map_vfs_err)?;
        Ok(self.mint_js_handle(
            open_ref,
            entry.handle,
            resolved.join("/"),
            options.is_append(),
            false,
            None,
        ))
    }

    pub async fn hold(
        &self,
        grant: JsValue,
        path: &str,
        root: Option<String>,
    ) -> Result<JsValue, JsValue> {
        self.check_grant(&grant).map_err(map_vfs_err)?;
        if let Some(ref r) = root
            && !r.is_empty()
        {
            let (r_parts, _) = clean_rel_path(r).map_err(map_vfs_err)?;
            let (p_parts, _) = clean_rel_path(path).map_err(map_vfs_err)?;
            if p_parts.len() < r_parts.len() || p_parts[..r_parts.len()] != r_parts[..] {
                return Err(map_vfs_err(Errno::EACCES));
            }
        }
        let cred = self.cred(None);
        let (parts, trailing_dir) = clean_rel_path(path).map_err(map_vfs_err)?;
        let (entry, resolved) = self
            .resolve_parts(&cred, parts, true, trailing_dir)
            .await
            .map_err(map_vfs_err)?;
        if entry.metadata.file_type == FileType::Dir {
            return Err(map_vfs_err(Errno::EISDIR));
        }
        let open_ref = self
            .state
            .fs
            .open(&cred, &entry.handle, OpenOptions::new().path(true))
            .await
            .map_err(map_vfs_err)?;
        Ok(self.mint_js_handle(
            open_ref,
            entry.handle,
            resolved.join("/"),
            false,
            true,
            None,
        ))
    }

    pub async fn release(&self, grant: JsValue, handle: JsValue) -> Result<JsValue, JsValue> {
        if !js_sys::Object::is(&grant, &self.state.grant_js) {
            return Err(map_vfs_err(Errno::EACCES));
        }
        let open = self.lookup_open(&handle).map_err(map_vfs_err)?;
        self.opens.borrow_mut().remove(&open.id);
        self.state
            .fs
            .release(&open.open_ref)
            .await
            .map_err(map_vfs_err)?;
        Ok(JsValue::NULL)
    }

    pub async fn read(
        &self,
        grant: JsValue,
        target: JsValue,
        offset: f64,
        count: u32,
    ) -> Result<js_sys::Uint8Array, JsValue> {
        self.check_grant(&grant).map_err(map_vfs_err)?;
        if !offset.is_finite() || offset < 0.0 || offset > (abi::fs::JS_SAFE as f64) {
            return Err(map_vfs_err(Errno::EINVAL));
        }
        let len = (count as usize).min(CHUNK_READ_MAX);
        let off = offset as u64;
        let cred = self.cred(None);

        if target.is_object() {
            let open = self.lookup_open(&target).map_err(map_vfs_err)?;
            if !open.held && !open.open_ref.access.reads() {
                return Err(map_vfs_err(Errno::EBADF));
            }
            let access = if open.open_ref.access == Access::Exec {
                Access::Exec
            } else {
                Access::Read
            };
            self.verify_remote_open_live(&cred, &open, access)
                .await
                .map_err(map_vfs_err)?;
            if open.open_ref.access == Access::Path {
                // `hold()` creates a path reference for `PermissionMount`-compatible callers;
                // verify live read access and read via a transient read OpenRef.
                let r_open = self
                    .state
                    .fs
                    .open(&cred, &open.handle, OpenOptions::new().read(true))
                    .await
                    .map_err(map_vfs_err)?;
                let mut buf = vec![0u8; len];
                let res = self.state.fs.read_at(&r_open, &mut buf, off).await;
                let _ = self.state.fs.release(&r_open).await;
                let n = res.map_err(map_vfs_err)?;
                return Ok(js_sys::Uint8Array::from(&buf[..n]));
            }
            let mut buf = vec![0u8; len];
            let n = self
                .state
                .fs
                .read_at(&open.open_ref, &mut buf, off)
                .await
                .map_err(map_vfs_err)?;
            return Ok(js_sys::Uint8Array::from(&buf[..n]));
        }

        let path = target
            .as_string()
            .ok_or_else(|| map_vfs_err(Errno::EINVAL))?;
        let (parts, trailing_dir) = clean_rel_path(&path).map_err(map_vfs_err)?;
        let (entry, _) = self
            .resolve_parts(&cred, parts, true, trailing_dir)
            .await
            .map_err(map_vfs_err)?;
        if entry.metadata.file_type == FileType::Dir {
            return Err(map_vfs_err(Errno::EISDIR));
        }
        let open_ref = self
            .state
            .fs
            .open(&cred, &entry.handle, OpenOptions::new().read(true))
            .await
            .map_err(map_vfs_err)?;
        let mut buf = vec![0u8; len];
        let res = self.state.fs.read_at(&open_ref, &mut buf, off).await;
        let _ = self.state.fs.release(&open_ref).await;
        let n = res.map_err(map_vfs_err)?;
        Ok(js_sys::Uint8Array::from(&buf[..n]))
    }

    pub async fn write(
        &self,
        grant: JsValue,
        target: JsValue,
        bytes: &[u8],
        options: JsValue,
    ) -> Result<JsValue, JsValue> {
        self.check_grant(&grant).map_err(map_vfs_err)?;
        self.require_data_writable().map_err(map_vfs_err)?;
        let opts = js_to_json(&options)?;
        let offset = parse_off_field(&opts, "offset")
            .map_err(map_vfs_err)?
            .unwrap_or(0);
        let append_opt = opts.get("append").and_then(Value::as_bool);
        let truncate = parse_off_field(&opts, "truncate").map_err(map_vfs_err)?;
        let create = opts.get("create").and_then(Value::as_bool).unwrap_or(false);
        let umask = parse_u16_field(&opts, "umask").map_err(map_vfs_err)?;
        let cred = self.cred(umask);

        if target.is_object() {
            let open = self.lookup_open(&target).map_err(map_vfs_err)?;
            if !open.held && !open.open_ref.access.writes() {
                return Err(map_vfs_err(Errno::EBADF));
            }
            self.verify_remote_open_live(&cred, &open, Access::Write)
                .await
                .map_err(map_vfs_err)?;
            let append = append_opt.unwrap_or(open.append);
            if open.open_ref.access == Access::Path {
                let w_open = self
                    .state
                    .fs
                    .open(&cred, &open.handle, OpenOptions::new().write(true))
                    .await
                    .map_err(map_vfs_err)?;
                let res = async {
                    if let Some(sz) = truncate {
                        self.state.fs.set_len(&w_open, sz).await?;
                    }
                    let written = if !bytes.is_empty() || truncate.is_none() {
                        self.state
                            .fs
                            .write_at(
                                &w_open,
                                bytes,
                                if append {
                                    WriteAt::End
                                } else {
                                    WriteAt::Offset(offset)
                                },
                            )
                            .await?
                    } else {
                        vfs::Written { offset, len: 0 }
                    };
                    let meta = self.state.fs.open_metadata(&w_open).await?;
                    Ok::<_, Errno>((written, meta.size))
                }
                .await;
                let _ = self.state.fs.release(&w_open).await;
                let (written, size) = res.map_err(map_vfs_err)?;
                return json_to_js(&json!({
                    "written": written.len,
                    "offset": written.offset,
                    "size": size,
                }));
            }

            if let Some(sz) = truncate {
                self.state
                    .fs
                    .set_len(&open.open_ref, sz)
                    .await
                    .map_err(map_vfs_err)?;
            }
            let written = if !bytes.is_empty() || truncate.is_none() {
                self.state
                    .fs
                    .write_at(
                        &open.open_ref,
                        bytes,
                        if append {
                            WriteAt::End
                        } else {
                            WriteAt::Offset(offset)
                        },
                    )
                    .await
                    .map_err(map_vfs_err)?
            } else {
                vfs::Written { offset, len: 0 }
            };
            let meta = self
                .state
                .fs
                .open_metadata(&open.open_ref)
                .await
                .map_err(map_vfs_err)?;
            return json_to_js(&json!({
                "written": written.len,
                "offset": written.offset,
                "size": meta.size,
            }));
        }

        let path = target
            .as_string()
            .ok_or_else(|| map_vfs_err(Errno::EINVAL))?;
        let append = append_opt.unwrap_or(false);
        let w_open = if create {
            let mut create_opts = OpenOptions::new();
            create_opts.write(true).create(true);
            let (_, o, _, _) = self
                .open_or_create_target(&cred, &path, false, 0o666, &create_opts)
                .await
                .map_err(map_vfs_err)?;
            o
        } else {
            let (parts, trailing_dir) = clean_rel_path(&path).map_err(map_vfs_err)?;
            let (entry, _) = self
                .resolve_parts(&cred, parts, true, trailing_dir)
                .await
                .map_err(map_vfs_err)?;
            self.state
                .fs
                .open(&cred, &entry.handle, OpenOptions::new().write(true))
                .await
                .map_err(map_vfs_err)?
        };

        let res = async {
            if let Some(sz) = truncate {
                self.state.fs.set_len(&w_open, sz).await?;
            }
            let written = if !bytes.is_empty() || truncate.is_none() {
                self.state
                    .fs
                    .write_at(
                        &w_open,
                        bytes,
                        if append {
                            WriteAt::End
                        } else {
                            WriteAt::Offset(offset)
                        },
                    )
                    .await?
            } else {
                vfs::Written { offset, len: 0 }
            };
            let meta = self.state.fs.open_metadata(&w_open).await?;
            Ok::<_, Errno>((written, meta.size))
        }
        .await;
        let _ = self.state.fs.release(&w_open).await;
        let (written, size) = res.map_err(map_vfs_err)?;
        json_to_js(&json!({
            "written": written.len,
            "offset": written.offset,
            "size": size,
        }))
    }

    pub async fn ftruncate(
        &self,
        grant: JsValue,
        handle: JsValue,
        size: f64,
    ) -> Result<JsValue, JsValue> {
        self.check_grant(&grant).map_err(map_vfs_err)?;
        self.require_data_writable().map_err(map_vfs_err)?;
        if !size.is_finite() || size < 0.0 || size > (abi::fs::FILE_MAX as f64) {
            return Err(map_vfs_err(Errno::EINVAL));
        }
        let cred = self.cred(None);
        let open = self.lookup_open(&handle).map_err(map_vfs_err)?;
        if open.open_ref.access == Access::Path {
            return Err(map_vfs_err(Errno::EBADF));
        }
        self.verify_remote_open_live(&cred, &open, Access::Write)
            .await
            .map_err(map_vfs_err)?;
        self.state
            .fs
            .set_len(&open.open_ref, size as u64)
            .await
            .map_err(map_vfs_err)?;
        Ok(JsValue::NULL)
    }

    pub async fn fsync(
        &self,
        grant: JsValue,
        handle: JsValue,
        data_only: bool,
    ) -> Result<JsValue, JsValue> {
        self.check_grant(&grant).map_err(map_vfs_err)?;
        let open = self.lookup_open(&handle).map_err(map_vfs_err)?;
        if open.open_ref.access == Access::Path {
            return Err(map_vfs_err(Errno::EBADF));
        }
        if data_only {
            self.state
                .fs
                .sync_data(&open.open_ref)
                .await
                .map_err(map_vfs_err)?;
        } else {
            self.state
                .fs
                .sync_all(&open.open_ref)
                .await
                .map_err(map_vfs_err)?;
        }
        Ok(JsValue::NULL)
    }

    pub async fn list(
        &self,
        grant: JsValue,
        target: JsValue,
        options: JsValue,
    ) -> Result<JsValue, JsValue> {
        self.check_grant(&grant).map_err(map_vfs_err)?;
        let opts = js_to_json(&options)?;
        let offset = opts.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
        let limit = opts
            .get("limit")
            .and_then(Value::as_u64)
            .unwrap_or(256)
            .clamp(1, 256) as usize;
        let cred = self.cred(None);

        let dir_handle = if target.is_object() {
            let open = self.lookup_open(&target).map_err(map_vfs_err)?;
            if open.open_ref.access == Access::Path && !open.held {
                return Err(map_vfs_err(Errno::EBADF));
            }
            self.verify_remote_open_live(&cred, &open, Access::Read)
                .await
                .map_err(map_vfs_err)?;
            open.handle
        } else {
            let path = target.as_string().unwrap_or_default();
            let (parts, _) = clean_rel_path(&path).map_err(map_vfs_err)?;
            let (entry, _) = self
                .resolve_parts(&cred, parts, true, true)
                .await
                .map_err(map_vfs_err)?;
            entry.handle
        };

        // POSIX opendir/readdir requires directory READ permission; `workspace.entries` also
        // stats children (`EXEC`), so check directory `access(5)` as `PermissionMount` did.
        let dir_meta = self
            .state
            .fs
            .metadata(&cred, &dir_handle)
            .await
            .map_err(map_vfs_err)?;
        let dir_entry = Entry {
            handle: dir_handle,
            metadata: dir_meta,
        };
        self.check_access_entry(&cred, &dir_entry, 5)
            .await
            .map_err(map_vfs_err)?;

        let all = self
            .state
            .fs
            .read_dir(&cred, &dir_entry.handle)
            .await
            .map_err(map_vfs_err)?;
        let slice: Vec<Value> = all
            .iter()
            .skip(offset)
            .take(limit)
            .map(|e| {
                let k = match e.file_type {
                    FileType::Dir => "directory",
                    FileType::Symlink => "symlink",
                    _ => "file",
                };
                json!({ "name": e.name, "kind": k, "ino": e.node.ino })
            })
            .collect();
        let next = if offset + slice.len() < all.len() && !slice.is_empty() {
            Value::from((offset + slice.len()) as u64)
        } else {
            Value::Null
        };
        json_to_js(&json!({ "entries": slice, "next": next }))
    }

    pub async fn mkdir(
        &self,
        grant: JsValue,
        path: &str,
        mode: Option<u16>,
        umask: Option<u16>,
    ) -> Result<JsValue, JsValue> {
        self.check_grant(&grant).map_err(map_vfs_err)?;
        self.require_data_writable().map_err(map_vfs_err)?;
        let cred = self.cred(umask);
        let (parent_entry, name, _) = self
            .resolve_parent(&cred, path)
            .await
            .map_err(map_vfs_err)?;
        let mkdir_cred = if self.remote {
            self.check_access_entry(&cred, &parent_entry, 3)
                .await
                .map_err(map_vfs_err)?;
            Cred {
                identity: self.state.grant.owner.clone(),
                umask: cred.umask,
                token: None,
            }
        } else {
            cred
        };
        self.state
            .fs
            .mkdir(
                &mkdir_cred,
                &parent_entry.handle,
                &name,
                mode.unwrap_or(0o777),
            )
            .await
            .map_err(map_vfs_err)?;
        Ok(JsValue::NULL)
    }

    #[wasm_bindgen(js_name = parentOf)]
    pub async fn parent_of(
        &self,
        grant: JsValue,
        path: &str,
        node: JsValue,
    ) -> Result<JsValue, JsValue> {
        self.check_grant(&grant).map_err(map_vfs_err)?;
        let expected: NodeId =
            serde_json::from_value(js_to_json(&node)?).map_err(|_| map_vfs_err(Errno::EINVAL))?;
        let cred = self.cred(None);
        let (parent, name, _) = self
            .resolve_parent(&cred, path)
            .await
            .map_err(map_vfs_err)?;
        let child = self
            .state
            .fs
            .lookup(&cred, &parent.handle, &name)
            .await
            .map_err(map_vfs_err)?;
        if child.handle.node != expected {
            return Err(map_vfs_err(Errno::ESTALE));
        }
        self.format_stat_js(&cred, &parent.handle, &parent.metadata, "")
            .await
    }

    #[wasm_bindgen(js_name = removeIf)]
    pub async fn remove_if(
        &self,
        grant: JsValue,
        path: &str,
        node: JsValue,
    ) -> Result<(), JsValue> {
        self.check_grant(&grant).map_err(map_vfs_err)?;
        self.require_data_writable().map_err(map_vfs_err)?;
        let node =
            serde_json::from_value(js_to_json(&node)?).map_err(|_| map_vfs_err(Errno::EINVAL))?;
        let cred = self.cred(None);
        let (parent, name, parts) = self
            .resolve_parent(&cred, path)
            .await
            .map_err(map_vfs_err)?;
        self.state
            .fs
            .unlink_if(&cred, &parent.handle, &name, node)
            .await
            .map_err(map_vfs_err)?;
        self.prune_known_paths(&parts.join("/"), false, None);
        bump_fs_policy_rev(self.state.fs.id());
        Ok(())
    }

    pub async fn remove(
        &self,
        grant: JsValue,
        path: &str,
        directory: bool,
    ) -> Result<JsValue, JsValue> {
        self.check_grant(&grant).map_err(map_vfs_err)?;
        self.require_data_writable().map_err(map_vfs_err)?;
        let cred = self.cred(None);
        let (parent_entry, name, resolved_parts) = self
            .resolve_parent(&cred, path)
            .await
            .map_err(map_vfs_err)?;
        if directory {
            self.state
                .fs
                .rmdir(&cred, &parent_entry.handle, &name)
                .await
                .map_err(map_vfs_err)?;
        } else {
            self.state
                .fs
                .unlink(&cred, &parent_entry.handle, &name)
                .await
                .map_err(map_vfs_err)?;
        }
        self.prune_known_paths(&resolved_parts.join("/"), directory, None);
        bump_fs_policy_rev(self.state.fs.id());
        Ok(JsValue::NULL)
    }

    pub async fn rename(
        &self,
        grant: JsValue,
        from: &str,
        to: &str,
        noreplace: Option<bool>,
    ) -> Result<JsValue, JsValue> {
        self.check_grant(&grant).map_err(map_vfs_err)?;
        self.require_data_writable().map_err(map_vfs_err)?;
        let cred = self.cred(None);
        let (from_parent, from_name, from_resolved) = self
            .resolve_parent(&cred, from)
            .await
            .map_err(map_vfs_err)?;
        let (to_parent, to_name, to_resolved) =
            self.resolve_parent(&cred, to).await.map_err(map_vfs_err)?;
        let moved = self
            .state
            .fs
            .lookup(&cred, &from_parent.handle, &from_name)
            .await
            .ok();
        let moved_node = moved.as_ref().map(|e| e.handle.node);
        let overwritten = self
            .state
            .fs
            .lookup(&cred, &to_parent.handle, &to_name)
            .await
            .ok()
            .map(|e| (e.handle.node, e.metadata.file_type == FileType::Dir));
        let flags = if noreplace.unwrap_or(false) {
            RenameFlags::NOREPLACE
        } else {
            RenameFlags::empty()
        };
        self.state
            .fs
            .rename(
                &cred,
                &from_parent.handle,
                &from_name,
                &to_parent.handle,
                &to_name,
                flags,
            )
            .await
            .map_err(map_vfs_err)?;
        let old_rel = from_resolved.join("/");
        let new_rel = to_resolved.join("/");
        if let Some((over_node, over_dir)) = overwritten
            && Some(over_node) != moved_node
        {
            self.prune_known_paths(&new_rel, over_dir, moved_node);
        }
        let prefix = format!("{old_rel}/");
        {
            let mut kp = self.state.known_paths.borrow_mut();
            for paths in kp.values_mut() {
                for p in paths.iter_mut() {
                    if *p == old_rel {
                        *p = new_rel.clone();
                    } else if let Some(rest) = p.strip_prefix(&prefix) {
                        *p = format!("{new_rel}/{rest}");
                    }
                }
                let mut dedup = HashSet::new();
                paths.retain(|p| dedup.insert(p.clone()));
            }
            if let Some(node) = moved_node {
                let list = kp.entry(node).or_default();
                if !list.contains(&new_rel) {
                    list.push(new_rel);
                }
            }
        }
        bump_fs_policy_rev(self.state.fs.id());
        Ok(JsValue::NULL)
    }

    pub async fn link(
        &self,
        grant: JsValue,
        from: &str,
        to: &str,
        follow: Option<bool>,
    ) -> Result<JsValue, JsValue> {
        self.check_grant(&grant).map_err(map_vfs_err)?;
        self.require_data_writable().map_err(map_vfs_err)?;
        let cred = self.cred(None);
        let (from_parts, trailing_dir) = clean_rel_path(from).map_err(map_vfs_err)?;
        let (target_entry, _) = self
            .resolve_parts(&cred, from_parts, follow.unwrap_or(false), trailing_dir)
            .await
            .map_err(map_vfs_err)?;
        let (to_parent, to_name, to_resolved) =
            self.resolve_parent(&cred, to).await.map_err(map_vfs_err)?;
        self.state
            .fs
            .link(&cred, &target_entry.handle, &to_parent.handle, &to_name)
            .await
            .map_err(map_vfs_err)?;
        let new_rel = to_resolved.join("/");
        {
            let mut kp = self.state.known_paths.borrow_mut();
            let list = kp.entry(target_entry.handle.node).or_default();
            if !list.contains(&new_rel) {
                list.push(new_rel);
            }
        }
        Ok(JsValue::NULL)
    }

    pub async fn symlink(
        &self,
        grant: JsValue,
        target: &str,
        path: &str,
    ) -> Result<JsValue, JsValue> {
        self.check_grant(&grant).map_err(map_vfs_err)?;
        self.require_data_writable().map_err(map_vfs_err)?;
        let cred = self.cred(None);
        let (parent_entry, name, _) = self
            .resolve_parent(&cred, path)
            .await
            .map_err(map_vfs_err)?;
        let sym_cred = if self.remote {
            self.check_access_entry(&cred, &parent_entry, 3)
                .await
                .map_err(map_vfs_err)?;
            Cred {
                identity: self.state.grant.owner.clone(),
                umask: cred.umask,
                token: None,
            }
        } else {
            cred
        };
        self.state
            .fs
            .symlink(&sym_cred, &parent_entry.handle, &name, target)
            .await
            .map_err(map_vfs_err)?;
        Ok(JsValue::NULL)
    }

    pub async fn readlink(&self, grant: JsValue, path: &str) -> Result<JsValue, JsValue> {
        self.check_grant(&grant).map_err(map_vfs_err)?;
        let cred = self.cred(None);
        let (parts, trailing_dir) = clean_rel_path(path).map_err(map_vfs_err)?;
        if trailing_dir {
            return Err(map_vfs_err(Errno::EINVAL));
        }
        let (entry, _) = self
            .resolve_parts(&cred, parts, false, false)
            .await
            .map_err(map_vfs_err)?;
        let target = self
            .state
            .fs
            .read_link(&cred, &entry.handle)
            .await
            .map_err(map_vfs_err)?;
        Ok(JsValue::from_str(&target))
    }

    #[wasm_bindgen(js_name = tryLock)]
    pub async fn try_lock(
        &self,
        grant: JsValue,
        handle: JsValue,
        family: &str,
        kind: &str,
        start: f64,
        end: Option<f64>,
    ) -> Result<JsValue, JsValue> {
        self.check_grant(&grant).map_err(map_vfs_err)?;
        let open = self.lookup_open(&handle).map_err(map_vfs_err)?;
        if open.open_ref.access == Access::Path {
            return Err(map_vfs_err(Errno::EBADF));
        }
        let fam = parse_family(family)?;
        let lk = parse_kind(kind)?;
        let range = parse_range(start, end)?;
        self.state
            .fs
            .try_lock(&open.open_ref, fam, lk, range)
            .await
            .map_err(map_vfs_err)?;
        Ok(JsValue::NULL)
    }

    pub async fn lock(
        &self,
        grant: JsValue,
        handle: JsValue,
        family: &str,
        kind: &str,
        start: f64,
        end: Option<f64>,
    ) -> Result<JsValue, JsValue> {
        self.check_grant(&grant).map_err(map_vfs_err)?;
        let open = self.lookup_open(&handle).map_err(map_vfs_err)?;
        if open.open_ref.access == Access::Path {
            return Err(map_vfs_err(Errno::EBADF));
        }
        let fam = parse_family(family)?;
        let lk = parse_kind(kind)?;
        let range = parse_range(start, end)?;
        self.state
            .fs
            .lock(&open.open_ref, fam, lk, range)
            .await
            .map_err(map_vfs_err)?;
        Ok(JsValue::NULL)
    }

    pub async fn unlock(
        &self,
        grant: JsValue,
        handle: JsValue,
        family: &str,
        start: f64,
        end: Option<f64>,
    ) -> Result<JsValue, JsValue> {
        self.check_grant(&grant).map_err(map_vfs_err)?;
        let open = self.lookup_open(&handle).map_err(map_vfs_err)?;
        if open.open_ref.access == Access::Path {
            return Err(map_vfs_err(Errno::EBADF));
        }
        let fam = parse_family(family)?;
        let range = parse_range(start, end)?;
        self.state
            .fs
            .unlock(&open.open_ref, fam, range)
            .await
            .map_err(map_vfs_err)?;
        Ok(JsValue::NULL)
    }

    #[wasm_bindgen(js_name = testLock)]
    pub async fn test_lock(
        &self,
        grant: JsValue,
        handle: JsValue,
        kind: &str,
        start: f64,
        end: Option<f64>,
    ) -> Result<JsValue, JsValue> {
        self.check_grant(&grant).map_err(map_vfs_err)?;
        let open = self.lookup_open(&handle).map_err(map_vfs_err)?;
        if open.open_ref.access == Access::Path {
            return Err(map_vfs_err(Errno::EBADF));
        }
        let lk = parse_kind(kind)?;
        let range = parse_range(start, end)?;
        let conflict = self
            .state
            .fs
            .test_lock(&open.open_ref, lk, range)
            .await
            .map_err(map_vfs_err)?;
        json_to_js(&serde_json::to_value(conflict).unwrap_or(Value::Null))
    }

    pub async fn pin(&self, grant: JsValue, target: JsValue) -> Result<JsValue, JsValue> {
        self.check_grant(&grant).map_err(map_vfs_err)?;
        if !self.state.grant.execute {
            return Err(map_vfs_err(Errno::EACCES));
        }
        let cred = self.cred(None);
        let (entry, resolved_path) = if target.is_object() {
            let open = self.lookup_open(&target).map_err(map_vfs_err)?;
            if open.open_ref.access == Access::Path && !open.held {
                return Err(map_vfs_err(Errno::EBADF));
            }
            self.verify_remote_open_live(&cred, &open, Access::Exec)
                .await
                .map_err(map_vfs_err)?;
            let meta = self
                .state
                .fs
                .open_metadata(&open.open_ref)
                .await
                .map_err(map_vfs_err)?;
            (
                Entry {
                    handle: open.handle,
                    metadata: meta,
                },
                open.path,
            )
        } else {
            let path = target
                .as_string()
                .ok_or_else(|| map_vfs_err(Errno::EINVAL))?;
            let (parts, trailing_dir) = clean_rel_path(&path).map_err(map_vfs_err)?;
            let (e, r) = self
                .resolve_parts(&cred, parts, true, trailing_dir)
                .await
                .map_err(map_vfs_err)?;
            (e, r.join("/"))
        };

        if entry.metadata.file_type == FileType::Dir {
            return Err(map_vfs_err(Errno::EISDIR));
        }
        if entry.metadata.file_type != FileType::File {
            return Err(map_vfs_err(Errno::EINVAL));
        }
        if entry.metadata.size > IMAGE_MAX {
            return Err(map_vfs_err(Errno::EFBIG));
        }

        let exec_open = self
            .state
            .fs
            .open(&cred, &entry.handle, OpenOptions::new().exec(true))
            .await
            .map_err(map_vfs_err)?;
        let expected_size = entry.metadata.size as usize;
        let mut bytes = vec![0u8; expected_size];
        let mut read_total = 0usize;
        let read_res = async {
            while read_total < expected_size {
                let chunk = (expected_size - read_total).min(CHUNK_READ_MAX);
                let n = self
                    .state
                    .fs
                    .read_at(
                        &exec_open,
                        &mut bytes[read_total..read_total + chunk],
                        read_total as u64,
                    )
                    .await?;
                if n == 0 {
                    return Err(Errno::EIO);
                }
                read_total += n;
            }
            Ok::<_, Errno>(())
        }
        .await;
        let _ = self.state.fs.release(&exec_open).await;
        read_res.map_err(map_vfs_err)?;

        let pinned_revision = current_fs_policy_rev(self.state.fs.id());
        let pinned_node = entry.handle.node;
        let state = Rc::clone(&self.state);
        let identity = self.identity.clone();
        let boundary = self.boundary.clone();
        let remote = self.remote;

        let check_cb = Closure::<dyn Fn() -> js_sys::Promise>::new(move || {
            let state = Rc::clone(&state);
            let identity = identity.clone();
            let boundary = boundary.clone();
            let path = resolved_path.clone();
            wasm_bindgen_futures::future_to_promise(async move {
                if !state.active.get() {
                    return Err(map_vfs_err(Errno::ENODEV));
                }
                if current_fs_policy_rev(state.fs.id()) != pinned_revision {
                    return Err(map_vfs_err(Errno::ESTALE));
                }
                let view = LocalMount {
                    state,
                    identity,
                    boundary,
                    remote,
                    next_local_open: Rc::new(Cell::new(1)),
                    path_checks: HashMap::new(),
                    opens: Rc::new(RefCell::new(HashMap::new())),
                };
                let check_cred = view.cred(None);
                let (parts, _) = clean_rel_path(&path).map_err(|_| map_vfs_err(Errno::ESTALE))?;
                let (live_entry, _) = view
                    .resolve_parts(&check_cred, parts, true, false)
                    .await
                    .map_err(|e| {
                        if e == Errno::ENODEV {
                            map_vfs_err(Errno::ENODEV)
                        } else {
                            map_vfs_err(Errno::ESTALE)
                        }
                    })?;
                if live_entry.handle.node != pinned_node {
                    return Err(map_vfs_err(Errno::ESTALE));
                }
                let probe = view
                    .state
                    .fs
                    .open(
                        &check_cred,
                        &live_entry.handle,
                        OpenOptions::new().exec(true),
                    )
                    .await
                    .map_err(|_| map_vfs_err(Errno::ESTALE))?;
                let _ = view.state.fs.release(&probe).await;
                Ok(JsValue::UNDEFINED)
            })
        });

        let global = js_sys::global();
        let pin_fn = js_sys::Reflect::get(&global, &JsValue::from_str("__osPinImage"))?
            .dyn_into::<js_sys::Function>()
            .map_err(|_| js_errno(Errno::ENOSYS, "pinImage host callback is not installed"))?;
        let u8_bytes = js_sys::Uint8Array::from(bytes.as_slice());
        let promise = pin_fn
            .call2(&global, &u8_bytes, check_cb.as_ref())?
            .dyn_into::<js_sys::Promise>()
            .map_err(|_| js_errno(Errno::EIO, "pinImage did not return a Promise"))?;
        let pin_obj = JsFuture::from(promise).await?;
        // Retain the check closure for the lifetime of the pinned image capability.
        let _ = js_sys::Reflect::set(
            &js_sys::Object::new(),
            &JsValue::from_str("keep"),
            check_cb.as_ref(),
        );
        check_cb.forget();
        Ok(pin_obj)
    }

    pub fn unmount(&self, grant: JsValue) -> Result<(), JsValue> {
        if !js_sys::Object::is(&grant, &self.state.grant_js) {
            return Err(map_vfs_err(Errno::EACCES));
        }
        if self.state.active.get() {
            self.state.shutdown();
        }
        Ok(())
    }
}

fn parse_family(family: &str) -> Result<LockFamily, JsValue> {
    match family {
        "flock" => Ok(LockFamily::Flock),
        "posix" | "fcntl" => Ok(LockFamily::Posix),
        _ => Err(map_vfs_err(Errno::EINVAL)),
    }
}

fn parse_kind(kind: &str) -> Result<LockKind, JsValue> {
    match kind {
        "shared" => Ok(LockKind::Shared),
        "exclusive" => Ok(LockKind::Exclusive),
        _ => Err(map_vfs_err(Errno::EINVAL)),
    }
}

fn parse_range(start: f64, end: Option<f64>) -> Result<LockRange, JsValue> {
    if !start.is_finite() || start < 0.0 || start > (abi::fs::FILE_MAX as f64) {
        return Err(map_vfs_err(Errno::EINVAL));
    }
    let s = start as u64;
    let e = match end {
        Some(v) => {
            if !v.is_finite() || v < 0.0 || v > (abi::fs::FILE_MAX as f64) {
                return Err(map_vfs_err(Errno::EINVAL));
            }
            Some(v as u64)
        }
        None => None,
    };
    LockRange::new(s, e).ok_or_else(|| map_vfs_err(Errno::EINVAL))
}
