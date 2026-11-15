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
use std::collections::HashMap;
use std::rc::{Rc, Weak};
use vfs::{Access, Cred, Entry, Filesystem, Handle, Identity, Metadata, OpenRef, SetAttr, WriteAt};
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

fn expand_symlink(
    prefix: &[String],
    boundary_len: usize,
    link_target: &str,
) -> std::result::Result<Vec<String>, Errno> {
    if link_target.starts_with('/') {
        return Err(Errno::ENOENT);
    }
    let mut resolved = prefix.to_vec();
    for seg in link_target.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            if resolved.len() <= boundary_len {
                return Err(Errno::ELOOP);
            }
            resolved.pop();
        } else {
            if seg.len() > abi::NAME_MAX {
                return Err(Errno::ENAMETOOLONG);
            }
            resolved.push(seg.to_string());
        }
    }
    Ok(resolved)
}

type OpenTable = RefCell<HashMap<u64, RetainedOpen>>;
type OpenMap = Rc<OpenTable>;

struct SharedMountState {
    fs: Rc<dyn Filesystem>,
    grant: Grant,
    grant_js: JsValue,
    active: Cell<bool>,
    snapshot_data_ro: bool,
    policy_revision: Cell<u64>,
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
    created_at_rev: Option<u64>,
}

struct OpenLookup {
    id: u64,
    open_ref: OpenRef,
    handle: Handle,
    path: String,
    append: bool,
    held: bool,
    created_at_rev: Option<u64>,
}

/// Wasm-exported local mount provider wrapping an `Rc<dyn vfs::Filesystem>`.
#[wasm_bindgen]
pub struct LocalMount {
    state: Rc<SharedMountState>,
    identity: Identity,
    boundary: Vec<String>,
    remote: bool,
    next_local_open: Cell<u64>,
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
            grant,
            grant_js,
            active: Cell::new(true),
            snapshot_data_ro,
            policy_revision: Cell::new(0),
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
            next_local_open: Cell::new(1),
            opens,
        }
    }

    pub(crate) fn detach_callback(&self) -> Rc<dyn Fn()> {
        let state = Rc::clone(&self.state);
        Rc::new(move || state.shutdown())
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
        created_at_rev: Option<u64>,
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
                created_at_rev,
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
            created_at_rev: entry.created_at_rev,
        })
    }

    async fn resolve_parts(
        &self,
        cred: &Cred,
        initial_parts: Vec<String>,
        follow_last: bool,
        trailing_dir: bool,
    ) -> std::result::Result<(Entry, Vec<String>), Errno> {
        self.check_within_boundary(&initial_parts)?;
        let fs = &self.state.fs;
        let mut parts = initial_parts;
        let mut depth = 0usize;

        'restart: loop {
            self.check_within_boundary(&parts)?;
            let owner_cred = self.owner_cred();
            let root_handle = fs.root();
            let root_meta = fs
                .metadata(
                    if self.boundary.is_empty() {
                        cred
                    } else {
                        &owner_cred
                    },
                    &root_handle,
                )
                .await?;
            let mut current = Entry {
                handle: root_handle,
                metadata: root_meta,
            };

            if parts.is_empty() {
                return Ok((current, parts));
            }

            for i in 0..parts.len() {
                let is_last = i + 1 == parts.len();
                let step_cred = if i < self.boundary.len() {
                    &owner_cred
                } else {
                    cred
                };
                let next = fs.lookup(step_cred, &current.handle, &parts[i]).await?;
                if i < self.boundary.len()
                    && self.remote
                    && next.metadata.file_type == FileType::Symlink
                {
                    return Err(Errno::ELOOP);
                }
                if next.metadata.file_type == FileType::Symlink && (!is_last || follow_last) {
                    depth += 1;
                    if depth > SYMLINK_MAX {
                        return Err(Errno::ELOOP);
                    }
                    let link_target = fs.read_link(step_cred, &next.handle).await?;
                    let mut resolved =
                        expand_symlink(&parts[..i], self.boundary.len(), &link_target)?;
                    resolved.extend_from_slice(&parts[i + 1..]);
                    parts = resolved;
                    continue 'restart;
                }
                if !is_last && next.metadata.file_type != FileType::Dir {
                    return Err(Errno::ENOTDIR);
                }
                current = next;
            }

            if trailing_dir && current.metadata.file_type != FileType::Dir {
                return Err(Errno::ENOTDIR);
            }
            return Ok((current, parts));
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
        let creator_keeps_access = open.created_at_rev == Some(self.state.policy_revision.get())
            && match required_access {
                Access::Read => open.open_ref.access.reads(),
                Access::Write => open.open_ref.access.writes(),
                Access::ReadWrite => open.open_ref.access.reads() && open.open_ref.access.writes(),
                Access::Exec | Access::Path => false,
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
        let meta = self.state.fs.open_metadata(&open.open_ref).await?;
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
                return Err(Errno::ESTALE);
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
        let mut parts = initial_parts;
        let mut depth = 0usize;
        let ro_grant = self.state.grant.read_only || self.state.snapshot_data_ro;

        loop {
            self.check_within_boundary(&parts)?;
            if parts.is_empty() || parts == self.boundary {
                return Err(Errno::EISDIR);
            }
            let name = parts.last().cloned().ok_or(Errno::EISDIR)?;
            let parent_parts = parts[..parts.len() - 1].to_vec();
            let (parent_entry, mut resolved_parts) =
                self.resolve_parts(cred, parent_parts, true, true).await?;
            if parent_entry.metadata.file_type != FileType::Dir {
                return Err(Errno::ENOTDIR);
            }
            resolved_parts.push(name.clone());
            self.check_within_boundary(&resolved_parts)?;

            match self
                .state
                .fs
                .lookup(cred, &parent_entry.handle, &name)
                .await
            {
                Ok(existing) => {
                    if options.is_create_new() {
                        return Err(Errno::EEXIST);
                    }
                    if existing.metadata.file_type == FileType::Symlink {
                        if nofollow {
                            return Err(Errno::ELOOP);
                        }
                        depth += 1;
                        if depth > SYMLINK_MAX {
                            return Err(Errno::ELOOP);
                        }
                        let link_target = self.state.fs.read_link(cred, &existing.handle).await?;
                        parts = expand_symlink(
                            &resolved_parts[..resolved_parts.len() - 1],
                            self.boundary.len(),
                            &link_target,
                        )?;
                        continue;
                    }
                    if existing.metadata.file_type == FileType::Dir {
                        return Err(Errno::EISDIR);
                    }
                    // Existing targets always authorize against the caller's own credentials.
                    let mut open_opts = *options;
                    open_opts.create(false).create_new(false);
                    if ro_grant {
                        let mut ro_opts = OpenOptions::new();
                        ro_opts.read(true);
                        open_opts = ro_opts;
                    }
                    let open_ref = self
                        .state
                        .fs
                        .open(cred, &existing.handle, &open_opts)
                        .await?;
                    return Ok((existing, open_ref, resolved_parts, false));
                }
                Err(Errno::ENOENT) => {
                    if ro_grant {
                        return Err(Errno::EROFS);
                    }
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
                            depth += 1;
                            if depth > SYMLINK_MAX {
                                return Err(Errno::EEXIST);
                            }
                            continue;
                        }
                        Err(err) => return Err(err),
                    }
                }
                Err(err) => return Err(err),
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
        let mut obj = json!({
            "kind": kind_str,
            "name": name,
            "size": if meta.file_type == FileType::File { meta.size } else { 0 },
            "lastModified": last_modified_ms,
            "readOnly": self.state.grant.read_only || self.state.snapshot_data_ro,
            "executable": executable,
            "vfs": st,
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
            next_local_open: Cell::new(1),
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
                let mode = arg_val.get("mode").and_then(Value::as_u64).unwrap_or(0) as u16;
                self.check_access_entry(&cred, &entry, mode)
                    .await
                    .map_err(map_vfs_err)?;
                Ok(JsValue::NULL)
            }
            "chmod" => {
                let mode = arg_val
                    .get("mode")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| map_vfs_err(Errno::EINVAL))? as u16;
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
                self.state
                    .policy_revision
                    .set(self.state.policy_revision.get().wrapping_add(1));
                Ok(JsValue::NULL)
            }
            "chown" => {
                let uid = arg_val
                    .get("uid")
                    .and_then(|v| if v.is_null() { None } else { v.as_u64() })
                    .map(|n| n as u32);
                let gid = arg_val
                    .get("gid")
                    .and_then(|v| if v.is_null() { None } else { v.as_u64() })
                    .map(|n| n as u32);
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
                self.state
                    .policy_revision
                    .set(self.state.policy_revision.get().wrapping_add(1));
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
                let flags_bits = arg_val.get("flags").and_then(Value::as_u64).unwrap_or(0) as u8;
                let xflags =
                    XattrFlags::from_bits(flags_bits).ok_or_else(|| map_vfs_err(Errno::EINVAL))?;
                fs.setxattr(&cred, &entry.handle, attr_name, &value.0, xflags)
                    .await
                    .map_err(map_vfs_err)?;
                self.state
                    .policy_revision
                    .set(self.state.policy_revision.get().wrapping_add(1));
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
                self.state
                    .policy_revision
                    .set(self.state.policy_revision.get().wrapping_add(1));
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
        let options = OpenOptions::from_flags(flags).map_err(map_vfs_err)?;
        let access = options.access().map_err(map_vfs_err)?;
        if options.is_truncate() && !access.writes() && !options.is_create() {
            return Err(map_vfs_err(Errno::EACCES));
        }
        if access.writes() || options.is_truncate() {
            self.require_data_writable().map_err(map_vfs_err)?;
        }

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
            return Ok(self.mint_js_handle(
                open_ref,
                entry.handle,
                resolved_parts.join("/"),
                options.is_append(),
                false,
                created.then(|| self.state.policy_revision.get()),
            ));
        }

        let (parts, trailing_dir) = clean_rel_path(path).map_err(map_vfs_err)?;
        let (entry, resolved) = self
            .resolve_parts(
                &cred,
                parts,
                !nofollow && access != Access::Path,
                trailing_dir,
            )
            .await
            .map_err(map_vfs_err)?;
        if access != Access::Path && nofollow && entry.metadata.file_type == FileType::Symlink {
            return Err(map_vfs_err(Errno::ELOOP));
        }
        if want_dir && entry.metadata.file_type != FileType::Dir {
            return Err(map_vfs_err(Errno::ENOTDIR));
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
            self.verify_remote_open_live(&cred, &open, Access::Read)
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
        let offset = opts.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let append_opt = opts.get("append").and_then(Value::as_bool);
        let truncate = opts
            .get("truncate")
            .and_then(|v| if v.is_null() { None } else { v.as_u64() });
        let create = opts.get("create").and_then(Value::as_bool).unwrap_or(false);
        let umask = opts.get("umask").and_then(Value::as_u64).map(|n| n as u16);
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

    pub async fn remove(
        &self,
        grant: JsValue,
        path: &str,
        directory: bool,
    ) -> Result<JsValue, JsValue> {
        self.check_grant(&grant).map_err(map_vfs_err)?;
        self.require_data_writable().map_err(map_vfs_err)?;
        let cred = self.cred(None);
        let (parent_entry, name, _) = self
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
        self.state
            .policy_revision
            .set(self.state.policy_revision.get().wrapping_add(1));
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
        let moved_node = self
            .state
            .fs
            .lookup(&cred, &from_parent.handle, &from_name)
            .await
            .ok()
            .map(|e| e.handle.node);
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
            }
            if let Some(node) = moved_node {
                let list = kp.entry(node).or_default();
                if !list.contains(&new_rel) {
                    list.push(new_rel);
                }
            }
        }
        self.state
            .policy_revision
            .set(self.state.policy_revision.get().wrapping_add(1));
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

        let pinned_revision = self.state.policy_revision.get();
        let pinned_node = entry.handle.node;
        let state = Rc::clone(&self.state);
        let identity = self.identity.clone();
        let boundary = self.boundary.clone();

        let check_cb = Closure::<dyn Fn() -> js_sys::Promise>::new(move || {
            let state = Rc::clone(&state);
            let identity = identity.clone();
            let boundary = boundary.clone();
            let path = resolved_path.clone();
            wasm_bindgen_futures::future_to_promise(async move {
                if !state.active.get() {
                    return Err(map_vfs_err(Errno::ENODEV));
                }
                if state.policy_revision.get() != pinned_revision {
                    return Err(map_vfs_err(Errno::ESTALE));
                }
                let view = LocalMount {
                    state,
                    identity,
                    boundary,
                    remote: false,
                    next_local_open: Cell::new(1),
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
