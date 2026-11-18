//! Client-kernel JS bridge for [`vfs::sharefs::ShareFs`] wrapping `RemoteMount`
//! (`web/kernel/mount-sharing.js`, contract §2.5, §3, §4).

use crate::mounts::extract_js_errno;
use abi::Errno;
use serde_json::{Value, json};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use vfs::sharefs::{ShareError, ShareFs, ShareFuture, ShareTransport};
use vfs::{
    Access, Conflict, Cred, DirEntry, Entry, FILE_MAX, FileType, FsId, Handle, LockFamily,
    LockKind, LockRange, Metadata, MountBacking, NodeId, OpenOptions, OpenRef, ProviderState,
    RenameFlags, SetAttr, StatFs, Timespec, WriteAt, Written, XattrFlags, check_component,
};
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

struct ShareOpen {
    js_handle: Option<JsValue>,
    path: String,
    access: Access,
}

pub(crate) struct JsShareTransport {
    fs_id: FsId,
    root_node: NodeId,
    remote: JsValue,
    grant: JsValue,
    node_paths: RefCell<HashMap<NodeId, String>>,
    next_open: Cell<u64>,
    opens: RefCell<HashMap<u64, ShareOpen>>,
    next_synth_ino: Cell<u64>,
    provider_cb: Option<Closure<dyn FnMut(JsValue)>>,
}

impl Drop for JsShareTransport {
    fn drop(&mut self) {
        if self.provider_cb.take().is_some() {
            let _ = js_sys::Reflect::set(&self.remote, &"onProviderEvent".into(), &JsValue::NULL);
        }
        let _ = call_remote_sync(&self.remote, "unmount", std::slice::from_ref(&self.grant));
    }
}

fn map_js_share_err(remote: &JsValue, err: &JsValue) -> ShareError {
    if js_sys::Reflect::get(err, &JsValue::from_str("revoked"))
        .ok()
        .and_then(|v| v.as_bool())
        == Some(true)
    {
        return ShareError::Revoked;
    }
    if js_sys::Reflect::get(err, &JsValue::from_str("disconnected"))
        .ok()
        .and_then(|v| v.as_bool())
        == Some(true)
    {
        return ShareError::Disconnected;
    }
    let conn_active = js_sys::Reflect::get(remote, &JsValue::from_str("connection"))
        .ok()
        .filter(|v| v.is_object() && !v.is_null())
        .and_then(|c| js_sys::Reflect::get(&c, &JsValue::from_str("active")).ok())
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let code = js_sys::Reflect::get(err, &JsValue::from_str("errno"))
        .ok()
        .and_then(|v| v.as_string());
    match code.as_deref() {
        Some("ENODEV" | "ENOTCONN" | "ETIMEDOUT") => ShareError::Disconnected,
        Some("ESTALE") if !conn_active => ShareError::Disconnected,
        Some("EACCES") if !conn_active => ShareError::Revoked,
        _ => ShareError::Remote(extract_js_errno(err)),
    }
}

async fn call_remote(
    remote: &JsValue,
    method: &str,
    args: &[JsValue],
) -> Result<JsValue, ShareError> {
    let func = js_sys::Reflect::get(remote, &JsValue::from_str(method))
        .ok()
        .and_then(|v| v.dyn_into::<js_sys::Function>().ok())
        .ok_or(ShareError::Remote(Errno::EOPNOTSUPP))?;
    let arr = js_sys::Array::new();
    for arg in args {
        arr.push(arg);
    }
    let res =
        js_sys::Reflect::apply(&func, remote, &arr).map_err(|e| map_js_share_err(remote, &e))?;
    if let Ok(promise) = res.clone().dyn_into::<js_sys::Promise>() {
        JsFuture::from(promise)
            .await
            .map_err(|e| map_js_share_err(remote, &e))
    } else {
        Ok(res)
    }
}

fn join_rel(base: &str, name: &str) -> String {
    if base.is_empty() {
        name.to_string()
    } else {
        format!("{base}/{name}")
    }
}

fn split_rel_parent(path: &str) -> Option<(String, String)> {
    if path.is_empty() {
        return None;
    }
    match path.rsplit_once('/') {
        Some((p, n)) => Some((p.to_string(), n.to_string())),
        None => Some((String::new(), path.to_string())),
    }
}

fn parse_remote_stat(
    val: &JsValue,
    fallback_ino: &Cell<u64>,
) -> Result<(NodeId, Metadata), ShareError> {
    let text = js_sys::JSON::stringify(val)
        .ok()
        .and_then(|s| s.as_string())
        .ok_or(ShareError::Remote(Errno::EIO))?;
    let raw: Value = serde_json::from_str(&text).map_err(|_| ShareError::Remote(Errno::EIO))?;
    let kind_str = raw["kind"].as_str().unwrap_or("file");
    let file_type = match kind_str {
        "directory" => FileType::Dir,
        "symlink" => FileType::Symlink,
        _ => FileType::File,
    };
    if let Some(vfs_obj) = raw.get("vfs").filter(|v| v.is_object()) {
        let ino = vfs_obj["ino"].as_u64().unwrap_or_else(|| {
            let n = fallback_ino.get();
            fallback_ino.set(n + 1);
            n
        });
        let mode = (vfs_obj["mode"].as_u64().unwrap_or(0o755) & 0o7777) as u16;
        let nlink = vfs_obj["nlink"]
            .as_u64()
            .unwrap_or(if file_type == FileType::Dir { 2 } else { 1 }) as u32;
        let uid = vfs_obj["uid"].as_u64().unwrap_or(0) as u32;
        let gid = vfs_obj["gid"].as_u64().unwrap_or(0) as u32;
        let size = vfs_obj["size"].as_u64().unwrap_or(0);
        let atime = Timespec {
            sec: vfs_obj["atime"].as_u64().unwrap_or(0),
            nsec: vfs_obj["atime_nsec"].as_u64().unwrap_or(0) as u32,
        };
        let mtime = Timespec {
            sec: vfs_obj["mtime"].as_u64().unwrap_or(0),
            nsec: vfs_obj["mtime_nsec"].as_u64().unwrap_or(0) as u32,
        };
        let ctime = Timespec {
            sec: vfs_obj["ctime"].as_u64().unwrap_or(0),
            nsec: vfs_obj["ctime_nsec"].as_u64().unwrap_or(0) as u32,
        };
        let generation = vfs_obj["generation"]
            .as_u64()
            .filter(|&g| g > 0)
            .unwrap_or(1);
        let rdev = vfs_obj["rdev"].as_str().map(str::to_string);
        let acl = vfs_obj["acl"].as_bool().unwrap_or(false);
        return Ok((
            NodeId { ino, generation },
            Metadata {
                file_type,
                mode,
                nlink,
                uid,
                gid,
                size,
                atime,
                mtime,
                ctime,
                rdev,
                acl,
            },
        ));
    }
    let ino = {
        let n = fallback_ino.get();
        fallback_ino.set(n + 1);
        n
    };
    let size = raw["size"].as_u64().unwrap_or(0);
    let read_only = raw["readOnly"].as_bool().unwrap_or(false);
    let executable = raw["executable"].as_bool().unwrap_or(false);
    let mode = match file_type {
        FileType::Dir => {
            if read_only {
                0o555
            } else {
                0o755
            }
        }
        FileType::Symlink => 0o777,
        _ => 0o444 | if !read_only { 0o200 } else { 0 } | if executable { 0o111 } else { 0 },
    };
    Ok((
        NodeId { ino, generation: 1 },
        Metadata {
            file_type,
            mode,
            nlink: if file_type == FileType::Dir { 2 } else { 1 },
            uid: 0,
            gid: 0,
            size,
            atime: Timespec::default(),
            mtime: Timespec::default(),
            ctime: Timespec::default(),
            rdev: None,
            acl: false,
        },
    ))
}

fn lock_family_str(family: LockFamily) -> &'static str {
    match family {
        LockFamily::Flock => "flock",
        LockFamily::Posix => "posix",
    }
}

fn lock_kind_str(kind: LockKind) -> &'static str {
    match kind {
        LockKind::Shared => "shared",
        LockKind::Exclusive => "exclusive",
    }
}

impl JsShareTransport {
    fn lock_handle(&self, open: &OpenRef) -> Result<JsValue, ShareError> {
        let opens = self.opens.borrow();
        let rec = opens
            .get(&open.id)
            .ok_or(ShareError::Remote(Errno::EBADF))?;
        if rec.access == Access::Path {
            return Err(ShareError::Remote(Errno::EBADF));
        }
        rec.js_handle
            .clone()
            .ok_or(ShareError::Remote(Errno::EBADF))
    }

    fn rel_path(&self, handle: &Handle) -> Result<String, ShareError> {
        if handle.fs != self.fs_id {
            return Err(ShareError::Remote(Errno::EACCES));
        }
        if handle.node == self.root_node {
            return Ok(String::new());
        }
        self.node_paths
            .borrow()
            .get(&handle.node)
            .cloned()
            .ok_or(ShareError::Remote(Errno::ESTALE))
    }

    fn record_entry(&self, rel: String, node: NodeId, metadata: Metadata) -> Entry {
        self.node_paths.borrow_mut().insert(node, rel);
        Entry {
            handle: Handle {
                fs: self.fs_id.clone(),
                node,
                proof: String::new(),
            },
            metadata,
        }
    }

    async fn stat_rel(&self, rel: &str, follow: bool) -> Result<Entry, ShareError> {
        let opts = js_sys::Object::new();
        let _ = js_sys::Reflect::set(&opts, &"follow".into(), &JsValue::from_bool(follow));
        let val = call_remote(
            &self.remote,
            "stat",
            &[self.grant.clone(), JsValue::from_str(rel), opts.into()],
        )
        .await?;
        let (node, meta) = parse_remote_stat(&val, &self.next_synth_ino)?;
        Ok(self.record_entry(rel.to_string(), node, meta))
    }
}

impl ShareTransport for JsShareTransport {
    fn id(&self) -> &FsId {
        &self.fs_id
    }

    fn root(&self) -> Handle {
        Handle {
            fs: self.fs_id.clone(),
            node: self.root_node,
            proof: String::new(),
        }
    }

    fn lookup<'a>(
        &'a self,
        _cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
    ) -> ShareFuture<'a, Entry> {
        Box::pin(async move {
            check_component(name).map_err(ShareError::Remote)?;
            let base = self.rel_path(dir)?;
            let rel = join_rel(&base, name);
            self.stat_rel(&rel, false).await
        })
    }

    fn parent<'a>(
        &'a self,
        _cred: &'a Cred,
        dir: &'a Handle,
    ) -> ShareFuture<'a, Option<(Entry, String)>> {
        Box::pin(async move {
            let rel = self.rel_path(dir)?;
            let Some((parent_rel, name)) = split_rel_parent(&rel) else {
                return Ok(None);
            };
            let parent_entry = self.stat_rel(&parent_rel, true).await?;
            Ok(Some((parent_entry, name)))
        })
    }

    fn metadata<'a>(&'a self, _cred: &'a Cred, handle: &'a Handle) -> ShareFuture<'a, Metadata> {
        Box::pin(async move {
            let rel = self.rel_path(handle)?;
            Ok(self.stat_rel(&rel, false).await?.metadata)
        })
    }

    fn open_metadata<'a>(&'a self, open: &'a OpenRef) -> ShareFuture<'a, Metadata> {
        Box::pin(async move {
            let (js_handle, path) = {
                let opens = self.opens.borrow();
                let rec = opens
                    .get(&open.id)
                    .ok_or(ShareError::Remote(Errno::EBADF))?;
                (rec.js_handle.clone(), rec.path.clone())
            };
            let target = js_handle.unwrap_or_else(|| JsValue::from_str(&path));
            let opts = js_sys::Object::new();
            let _ = js_sys::Reflect::set(&opts, &"follow".into(), &JsValue::from_bool(false));
            let val = call_remote(
                &self.remote,
                "stat",
                &[self.grant.clone(), target, opts.into()],
            )
            .await?;
            let (_, meta) = parse_remote_stat(&val, &self.next_synth_ino)?;
            Ok(meta)
        })
    }

    fn setattr<'a>(
        &'a self,
        _cred: &'a Cred,
        handle: &'a Handle,
        attr: &'a SetAttr,
    ) -> ShareFuture<'a, Metadata> {
        Box::pin(async move {
            let rel = self.rel_path(handle)?;
            if let Some(size) = attr.size {
                call_remote(
                    &self.remote,
                    "ftruncate",
                    &[
                        self.grant.clone(),
                        JsValue::from_str(&rel),
                        JsValue::from_f64(size as f64),
                    ],
                )
                .await?;
            }
            if attr.uid.is_some() || attr.gid.is_some() {
                let opts =
                    js_sys::JSON::parse(&json!({ "uid": attr.uid, "gid": attr.gid }).to_string())
                        .map_err(|_| ShareError::Remote(Errno::EINVAL))?;
                call_remote(
                    &self.remote,
                    "policy",
                    &[
                        self.grant.clone(),
                        JsValue::from_str(&rel),
                        JsValue::from_str("chown"),
                        opts,
                    ],
                )
                .await?;
            }
            if let Some(mode) = attr.mode {
                let opts = js_sys::JSON::parse(&json!({ "mode": mode }).to_string())
                    .map_err(|_| ShareError::Remote(Errno::EINVAL))?;
                call_remote(
                    &self.remote,
                    "policy",
                    &[
                        self.grant.clone(),
                        JsValue::from_str(&rel),
                        JsValue::from_str("chmod"),
                        opts,
                    ],
                )
                .await?;
            }
            if !matches!(attr.atime, abi::Time::Omit) || !matches!(attr.mtime, abi::Time::Omit) {
                let opts = js_sys::JSON::parse(
                    &json!({ "atime": attr.atime, "mtime": attr.mtime }).to_string(),
                )
                .map_err(|_| ShareError::Remote(Errno::EINVAL))?;
                call_remote(
                    &self.remote,
                    "policy",
                    &[
                        self.grant.clone(),
                        JsValue::from_str(&rel),
                        JsValue::from_str("utimens"),
                        opts,
                    ],
                )
                .await?;
            }
            Ok(self.stat_rel(&rel, false).await?.metadata)
        })
    }

    fn read_dir<'a>(&'a self, _cred: &'a Cred, dir: &'a Handle) -> ShareFuture<'a, Vec<DirEntry>> {
        Box::pin(async move {
            let base = self.rel_path(dir)?;
            let mut out = Vec::new();
            let mut offset = 0usize;
            loop {
                let opts =
                    js_sys::JSON::parse(&json!({ "offset": offset, "limit": 16 }).to_string())
                        .map_err(|_| ShareError::Remote(Errno::EINVAL))?;
                let page = call_remote(
                    &self.remote,
                    "list",
                    &[self.grant.clone(), JsValue::from_str(&base), opts],
                )
                .await?;
                let entries_val = js_sys::Reflect::get(&page, &"entries".into())
                    .map_err(|_| ShareError::Remote(Errno::EIO))?;
                let arr = js_sys::Array::from(&entries_val);
                for i in 0..arr.length() {
                    let item = arr.get(i);
                    let name = js_sys::Reflect::get(&item, &"name".into())
                        .ok()
                        .and_then(|v| v.as_string())
                        .ok_or(ShareError::Remote(Errno::EIO))?;
                    let st_val = js_sys::Reflect::get(&item, &"stat".into())
                        .map_err(|_| ShareError::Remote(Errno::EIO))?;
                    let (node, meta) = parse_remote_stat(&st_val, &self.next_synth_ino)?;
                    let child_rel = join_rel(&base, &name);
                    self.record_entry(child_rel, node, meta.clone());
                    out.push(DirEntry {
                        name,
                        node,
                        file_type: meta.file_type,
                    });
                }
                let next = js_sys::Reflect::get(&page, &"next".into())
                    .ok()
                    .and_then(|v| v.as_f64());
                match next {
                    Some(n) if n.is_finite() && (n as usize) > offset => offset = n as usize,
                    _ => break,
                }
            }
            Ok(out)
        })
    }

    fn read_link<'a>(&'a self, _cred: &'a Cred, link: &'a Handle) -> ShareFuture<'a, String> {
        Box::pin(async move {
            let rel = self.rel_path(link)?;
            let val = call_remote(
                &self.remote,
                "readlink",
                &[self.grant.clone(), JsValue::from_str(&rel)],
            )
            .await?;
            val.as_string().ok_or(ShareError::Remote(Errno::EIO))
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
        Box::pin(async move {
            check_component(name).map_err(ShareError::Remote)?;
            let access = options.access().map_err(ShareError::Remote)?;
            let base = self.rel_path(dir)?;
            let rel = join_rel(&base, name);
            let mut flags: u32 = match access {
                Access::Read => abi::O_RDONLY,
                Access::Write => abi::O_WRONLY,
                Access::ReadWrite => abi::O_RDWR,
                Access::Exec => abi::O_RDONLY,
                Access::Path => 0o1000_0000,
            };
            flags |= abi::O_CREAT;
            if options.is_create_new() {
                flags |= abi::O_EXCL;
            }
            if options.is_truncate() {
                flags |= abi::O_TRUNC;
            }
            let js_handle = call_remote(
                &self.remote,
                "open",
                &[
                    self.grant.clone(),
                    JsValue::from_str(&rel),
                    JsValue::from_f64(flags as f64),
                    JsValue::from_f64(mode as f64),
                    JsValue::from_f64(cred.umask as f64),
                ],
            )
            .await?;
            let entry = match self.stat_rel(&rel, false).await {
                Ok(e) => e,
                Err(err) => {
                    let _ = call_remote(&self.remote, "release", &[self.grant.clone(), js_handle])
                        .await;
                    return Err(err);
                }
            };
            let id = self.next_open.get();
            self.next_open.set(id + 1);
            self.opens.borrow_mut().insert(
                id,
                ShareOpen {
                    js_handle: Some(js_handle),
                    path: rel,
                    access,
                },
            );
            Ok((
                entry.clone(),
                OpenRef {
                    fs: self.fs_id.clone(),
                    id,
                    node: entry.handle.node,
                    access,
                },
            ))
        })
    }

    fn mkdir<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
    ) -> ShareFuture<'a, Entry> {
        Box::pin(async move {
            check_component(name).map_err(ShareError::Remote)?;
            let base = self.rel_path(dir)?;
            let rel = join_rel(&base, name);
            call_remote(
                &self.remote,
                "mkdir",
                &[
                    self.grant.clone(),
                    JsValue::from_str(&rel),
                    JsValue::from_f64(mode as f64),
                    JsValue::from_f64(cred.umask as f64),
                ],
            )
            .await?;
            self.stat_rel(&rel, false).await
        })
    }

    fn mknod<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
        rdev: &'a str,
    ) -> ShareFuture<'a, Entry> {
        Box::pin(async move {
            if !rdev.is_empty() {
                return Err(ShareError::Remote(Errno::EPERM));
            }
            let (entry, oref) = self
                .create(
                    cred,
                    dir,
                    name,
                    mode,
                    OpenOptions::new().write(true).create_new(true),
                )
                .await?;
            let _ = self.release(&oref).await;
            Ok(entry)
        })
    }

    fn symlink<'a>(
        &'a self,
        _cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        target: &'a str,
    ) -> ShareFuture<'a, Entry> {
        Box::pin(async move {
            check_component(name).map_err(ShareError::Remote)?;
            let base = self.rel_path(dir)?;
            let rel = join_rel(&base, name);
            call_remote(
                &self.remote,
                "symlink",
                &[
                    self.grant.clone(),
                    JsValue::from_str(target),
                    JsValue::from_str(&rel),
                ],
            )
            .await?;
            self.stat_rel(&rel, false).await
        })
    }

    fn link<'a>(
        &'a self,
        _cred: &'a Cred,
        target: &'a Handle,
        dir: &'a Handle,
        name: &'a str,
    ) -> ShareFuture<'a, Entry> {
        Box::pin(async move {
            check_component(name).map_err(ShareError::Remote)?;
            let from_rel = self.rel_path(target)?;
            let base = self.rel_path(dir)?;
            let to_rel = join_rel(&base, name);
            call_remote(
                &self.remote,
                "link",
                &[
                    self.grant.clone(),
                    JsValue::from_str(&from_rel),
                    JsValue::from_str(&to_rel),
                    JsValue::from_bool(false),
                ],
            )
            .await?;
            self.stat_rel(&to_rel, false).await
        })
    }

    fn unlink<'a>(
        &'a self,
        _cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
    ) -> ShareFuture<'a, ()> {
        Box::pin(async move {
            check_component(name).map_err(ShareError::Remote)?;
            let base = self.rel_path(dir)?;
            let rel = join_rel(&base, name);
            call_remote(
                &self.remote,
                "remove",
                &[
                    self.grant.clone(),
                    JsValue::from_str(&rel),
                    JsValue::from_bool(false),
                ],
            )
            .await
            .map(|_| ())
        })
    }

    fn rmdir<'a>(&'a self, _cred: &'a Cred, dir: &'a Handle, name: &'a str) -> ShareFuture<'a, ()> {
        Box::pin(async move {
            check_component(name).map_err(ShareError::Remote)?;
            let base = self.rel_path(dir)?;
            let rel = join_rel(&base, name);
            call_remote(
                &self.remote,
                "remove",
                &[
                    self.grant.clone(),
                    JsValue::from_str(&rel),
                    JsValue::from_bool(true),
                ],
            )
            .await
            .map(|_| ())
        })
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
        Box::pin(async move {
            check_component(from).map_err(ShareError::Remote)?;
            check_component(to).map_err(ShareError::Remote)?;
            let from_rel = join_rel(&self.rel_path(from_dir)?, from);
            let to_rel = join_rel(&self.rel_path(to_dir)?, to);
            call_remote(
                &self.remote,
                "rename",
                &[
                    self.grant.clone(),
                    JsValue::from_str(&from_rel),
                    JsValue::from_str(&to_rel),
                    JsValue::from_bool(flags.contains(RenameFlags::NOREPLACE)),
                ],
            )
            .await?;
            let prefix = format!("{from_rel}/");
            for p in self.node_paths.borrow_mut().values_mut() {
                if *p == from_rel {
                    *p = to_rel.clone();
                } else if let Some(rest) = p.strip_prefix(&prefix) {
                    *p = format!("{to_rel}/{rest}");
                }
            }
            for rec in self.opens.borrow_mut().values_mut() {
                if rec.path == from_rel {
                    rec.path = to_rel.clone();
                } else if let Some(rest) = rec.path.strip_prefix(&prefix) {
                    rec.path = format!("{to_rel}/{rest}");
                }
            }
            Ok(())
        })
    }

    fn getxattr<'a>(
        &'a self,
        _cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> ShareFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let rel = self.rel_path(handle)?;
            let opts = js_sys::JSON::parse(&json!({ "name": name, "nofollow": true }).to_string())
                .map_err(|_| ShareError::Remote(Errno::EINVAL))?;
            let val = call_remote(
                &self.remote,
                "policy",
                &[
                    self.grant.clone(),
                    JsValue::from_str(&rel),
                    JsValue::from_str("getxattr"),
                    opts,
                ],
            )
            .await?;
            if let Some(b64) = val.as_string() {
                let decoded: abi::Bytes = serde_json::from_value(Value::String(b64))
                    .map_err(|_| ShareError::Remote(Errno::EIO))?;
                return Ok(decoded.0);
            }
            if val.is_instance_of::<js_sys::Uint8Array>() {
                return Ok(js_sys::Uint8Array::new(&val).to_vec());
            }
            if val.is_null() || val.is_undefined() {
                return Ok(Vec::new());
            }
            let text = js_sys::JSON::stringify(&val)
                .ok()
                .and_then(|s| s.as_string())
                .ok_or(ShareError::Remote(Errno::EIO))?;
            let decoded: abi::Bytes =
                serde_json::from_str(&text).map_err(|_| ShareError::Remote(Errno::EIO))?;
            Ok(decoded.0)
        })
    }

    fn setxattr<'a>(
        &'a self,
        _cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
        value: &'a [u8],
        flags: XattrFlags,
    ) -> ShareFuture<'a, ()> {
        Box::pin(async move {
            let rel = self.rel_path(handle)?;
            let opts = js_sys::Object::new();
            let _ = js_sys::Reflect::set(&opts, &"name".into(), &JsValue::from_str(name));
            let encoded = serde_json::to_value(abi::Bytes(value.to_vec()))
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_default();
            let _ = js_sys::Reflect::set(&opts, &"value".into(), &JsValue::from_str(&encoded));
            let _ = js_sys::Reflect::set(
                &opts,
                &"flags".into(),
                &JsValue::from_f64(flags.bits() as f64),
            );
            let _ = js_sys::Reflect::set(&opts, &"nofollow".into(), &JsValue::from_bool(true));
            call_remote(
                &self.remote,
                "policy",
                &[
                    self.grant.clone(),
                    JsValue::from_str(&rel),
                    JsValue::from_str("setxattr"),
                    opts.into(),
                ],
            )
            .await
            .map(|_| ())
        })
    }

    fn listxattr<'a>(
        &'a self,
        _cred: &'a Cred,
        handle: &'a Handle,
    ) -> ShareFuture<'a, Vec<String>> {
        Box::pin(async move {
            let rel = self.rel_path(handle)?;
            let opts = js_sys::JSON::parse(&json!({ "nofollow": true }).to_string())
                .map_err(|_| ShareError::Remote(Errno::EINVAL))?;
            let val = call_remote(
                &self.remote,
                "policy",
                &[
                    self.grant.clone(),
                    JsValue::from_str(&rel),
                    JsValue::from_str("listxattr"),
                    opts,
                ],
            )
            .await?;
            let arr = js_sys::Array::from(&val);
            let mut out = Vec::with_capacity(arr.length() as usize);
            for i in 0..arr.length() {
                if let Some(s) = arr.get(i).as_string() {
                    out.push(s);
                }
            }
            Ok(out)
        })
    }

    fn removexattr<'a>(
        &'a self,
        _cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> ShareFuture<'a, ()> {
        Box::pin(async move {
            let rel = self.rel_path(handle)?;
            let opts = js_sys::JSON::parse(&json!({ "name": name, "nofollow": true }).to_string())
                .map_err(|_| ShareError::Remote(Errno::EINVAL))?;
            call_remote(
                &self.remote,
                "policy",
                &[
                    self.grant.clone(),
                    JsValue::from_str(&rel),
                    JsValue::from_str("removexattr"),
                    opts,
                ],
            )
            .await
            .map(|_| ())
        })
    }

    fn statfs<'a>(&'a self, _cred: &'a Cred) -> ShareFuture<'a, StatFs> {
        Box::pin(async move {
            let val = call_remote(
                &self.remote,
                "policy",
                &[
                    self.grant.clone(),
                    JsValue::from_str(""),
                    JsValue::from_str("statfs"),
                    JsValue::NULL,
                ],
            )
            .await?;
            let text = js_sys::JSON::stringify(&val)
                .ok()
                .and_then(|s| s.as_string())
                .ok_or(ShareError::Remote(Errno::EIO))?;
            let sfs: abi::StatFs =
                serde_json::from_str(&text).map_err(|_| ShareError::Remote(Errno::EIO))?;
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
    ) -> ShareFuture<'a, OpenRef> {
        Box::pin(async move {
            let access = options.access().map_err(ShareError::Remote)?;
            let rel = self.rel_path(handle)?;
            if access != Access::Path {
                let meta = self.stat_rel(&rel, false).await?.metadata;
                if meta.is_dir() {
                    if access == Access::Exec {
                        return Err(ShareError::Remote(Errno::EACCES));
                    }
                    if access.writes() || options.is_truncate() {
                        return Err(ShareError::Remote(Errno::EISDIR));
                    }
                }
            }
            let mut flags: u32 = match access {
                Access::Read | Access::Exec => abi::O_RDONLY,
                Access::Write => abi::O_WRONLY,
                Access::ReadWrite => abi::O_RDWR,
                Access::Path => abi::O_PATH,
            };
            if options.is_truncate() {
                flags |= abi::O_TRUNC;
            }
            let js_handle = call_remote(
                &self.remote,
                "open",
                &[
                    self.grant.clone(),
                    JsValue::from_str(&rel),
                    JsValue::from_f64(flags as f64),
                    JsValue::from_f64(f64::from(0o666u16)),
                    JsValue::from_f64(cred.umask as f64),
                    JsValue::from_bool(access == Access::Exec),
                ],
            )
            .await?;
            let id = self.next_open.get();
            self.next_open.set(id + 1);
            self.opens.borrow_mut().insert(
                id,
                ShareOpen {
                    js_handle: Some(js_handle),
                    path: rel,
                    access,
                },
            );
            Ok(OpenRef {
                fs: self.fs_id.clone(),
                id,
                node: handle.node,
                access,
            })
        })
    }

    fn read_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a mut [u8],
        offset: u64,
    ) -> ShareFuture<'a, usize> {
        Box::pin(async move {
            if offset > FILE_MAX || buf.len() as u64 > FILE_MAX - offset {
                return Err(ShareError::Remote(Errno::EINVAL));
            }
            let (js_handle, path, access) = {
                let opens = self.opens.borrow();
                let rec = opens
                    .get(&open.id)
                    .ok_or(ShareError::Remote(Errno::EBADF))?;
                (rec.js_handle.clone(), rec.path.clone(), rec.access)
            };
            if !access.reads() {
                return Err(ShareError::Remote(Errno::EBADF));
            }
            if buf.is_empty() {
                return Ok(0);
            }
            let target = js_handle.unwrap_or_else(|| JsValue::from_str(&path));
            let mut total = 0usize;
            while total < buf.len() {
                let chunk_len = (buf.len() - total).min(24 * 1024);
                let val = call_remote(
                    &self.remote,
                    "read",
                    &[
                        self.grant.clone(),
                        target.clone(),
                        JsValue::from_f64((offset + total as u64) as f64),
                        JsValue::from_f64(chunk_len as f64),
                    ],
                )
                .await?;
                let bytes = js_sys::Uint8Array::new(&val).to_vec();
                if bytes.is_empty() {
                    break;
                }
                let n = bytes.len().min(buf.len() - total);
                buf[total..total + n].copy_from_slice(&bytes[..n]);
                total += n;
                if bytes.len() < chunk_len {
                    break;
                }
            }
            Ok(total)
        })
    }

    fn write_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a [u8],
        at: WriteAt,
    ) -> ShareFuture<'a, Written> {
        Box::pin(async move {
            let (js_handle, path, access) = {
                let opens = self.opens.borrow();
                let rec = opens
                    .get(&open.id)
                    .ok_or(ShareError::Remote(Errno::EBADF))?;
                (rec.js_handle.clone(), rec.path.clone(), rec.access)
            };
            if !access.writes() {
                return Err(ShareError::Remote(Errno::EBADF));
            }
            let target = js_handle.unwrap_or_else(|| JsValue::from_str(&path));
            let opts = js_sys::Object::new();
            match at {
                WriteAt::Offset(off) => {
                    let _ = js_sys::Reflect::set(
                        &opts,
                        &"offset".into(),
                        &JsValue::from_f64(off as f64),
                    );
                }
                WriteAt::End => {
                    let _ =
                        js_sys::Reflect::set(&opts, &"append".into(), &JsValue::from_bool(true));
                }
            }
            let val = call_remote(
                &self.remote,
                "write",
                &[
                    self.grant.clone(),
                    target,
                    js_sys::Uint8Array::from(buf).into(),
                    opts.into(),
                ],
            )
            .await?;
            let written = js_sys::Reflect::get(&val, &"written".into())
                .ok()
                .and_then(|v| v.as_f64())
                .unwrap_or(buf.len() as f64) as usize;
            let offset_out = js_sys::Reflect::get(&val, &"offset".into())
                .ok()
                .and_then(|v| v.as_f64())
                .unwrap_or(match at {
                    WriteAt::Offset(off) => off as f64,
                    WriteAt::End => 0.0,
                }) as u64;
            Ok(Written {
                offset: offset_out,
                len: written,
            })
        })
    }

    fn set_len<'a>(&'a self, open: &'a OpenRef, size: u64) -> ShareFuture<'a, ()> {
        Box::pin(async move {
            let (js_handle, path, access) = {
                let opens = self.opens.borrow();
                let rec = opens
                    .get(&open.id)
                    .ok_or(ShareError::Remote(Errno::EBADF))?;
                (rec.js_handle.clone(), rec.path.clone(), rec.access)
            };
            if !access.writes() {
                return Err(ShareError::Remote(Errno::EBADF));
            }
            let target = js_handle.unwrap_or_else(|| JsValue::from_str(&path));
            call_remote(
                &self.remote,
                "ftruncate",
                &[self.grant.clone(), target, JsValue::from_f64(size as f64)],
            )
            .await
            .map(|_| ())
        })
    }

    fn sync_all<'a>(&'a self, open: &'a OpenRef) -> ShareFuture<'a, ()> {
        Box::pin(async move {
            let js_handle = {
                let opens = self.opens.borrow();
                let rec = opens
                    .get(&open.id)
                    .ok_or(ShareError::Remote(Errno::EBADF))?;
                rec.js_handle.clone()
            };
            let Some(h) = js_handle else {
                return Err(ShareError::Remote(Errno::EINVAL));
            };
            call_remote(
                &self.remote,
                "fsync",
                &[self.grant.clone(), h, JsValue::from_bool(false)],
            )
            .await
            .map(|_| ())
        })
    }

    fn sync_data<'a>(&'a self, open: &'a OpenRef) -> ShareFuture<'a, ()> {
        Box::pin(async move {
            let js_handle = {
                let opens = self.opens.borrow();
                let rec = opens
                    .get(&open.id)
                    .ok_or(ShareError::Remote(Errno::EBADF))?;
                rec.js_handle.clone()
            };
            let Some(h) = js_handle else {
                return Err(ShareError::Remote(Errno::EINVAL));
            };
            call_remote(
                &self.remote,
                "fsync",
                &[self.grant.clone(), h, JsValue::from_bool(true)],
            )
            .await
            .map(|_| ())
        })
    }

    fn lock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> ShareFuture<'a, ()> {
        Box::pin(async move {
            let h = self.lock_handle(open)?;
            let end_js = range
                .end()
                .map(|e| JsValue::from_f64(e as f64))
                .unwrap_or(JsValue::NULL);
            call_remote(
                &self.remote,
                "lock",
                &[
                    self.grant.clone(),
                    h,
                    JsValue::from_str(lock_family_str(family)),
                    JsValue::from_str(lock_kind_str(kind)),
                    JsValue::from_f64(range.start() as f64),
                    end_js,
                ],
            )
            .await
            .map(|_| ())
        })
    }

    fn try_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> ShareFuture<'a, ()> {
        Box::pin(async move {
            let h = self.lock_handle(open)?;
            let end_js = range
                .end()
                .map(|e| JsValue::from_f64(e as f64))
                .unwrap_or(JsValue::NULL);
            call_remote(
                &self.remote,
                "tryLock",
                &[
                    self.grant.clone(),
                    h,
                    JsValue::from_str(lock_family_str(family)),
                    JsValue::from_str(lock_kind_str(kind)),
                    JsValue::from_f64(range.start() as f64),
                    end_js,
                ],
            )
            .await
            .map(|_| ())
        })
    }

    fn unlock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        range: LockRange,
    ) -> ShareFuture<'a, ()> {
        Box::pin(async move {
            let h = self.lock_handle(open)?;
            let end_js = range
                .end()
                .map(|e| JsValue::from_f64(e as f64))
                .unwrap_or(JsValue::NULL);
            call_remote(
                &self.remote,
                "unlock",
                &[
                    self.grant.clone(),
                    h,
                    JsValue::from_str(lock_family_str(family)),
                    JsValue::from_f64(range.start() as f64),
                    end_js,
                ],
            )
            .await
            .map(|_| ())
        })
    }

    fn test_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        kind: LockKind,
        range: LockRange,
    ) -> ShareFuture<'a, Option<Conflict>> {
        Box::pin(async move {
            let h = self.lock_handle(open)?;
            let end_js = range
                .end()
                .map(|e| JsValue::from_f64(e as f64))
                .unwrap_or(JsValue::NULL);
            let val = call_remote(
                &self.remote,
                "testLock",
                &[
                    self.grant.clone(),
                    h,
                    JsValue::from_str(lock_kind_str(kind)),
                    JsValue::from_f64(range.start() as f64),
                    end_js,
                ],
            )
            .await?;
            if val.is_null() || val.is_undefined() {
                return Ok(None);
            }
            let text = js_sys::JSON::stringify(&val)
                .ok()
                .and_then(|s| s.as_string())
                .ok_or(ShareError::Remote(Errno::EIO))?;
            serde_json::from_str::<Option<Conflict>>(&text)
                .map_err(|_| ShareError::Remote(Errno::EIO))
        })
    }

    fn release<'a>(&'a self, open: &'a OpenRef) -> ShareFuture<'a, ()> {
        Box::pin(async move {
            let removed = self.opens.borrow_mut().remove(&open.id);
            let Some(rec) = removed else {
                return Err(ShareError::Remote(Errno::EBADF));
            };
            if let Some(h) = rec.js_handle {
                let _ = call_remote(&self.remote, "release", &[self.grant.clone(), h]).await;
            }
            Ok(())
        })
    }
}

pub(crate) async fn build_share_backing(
    remote: JsValue,
    share_id: &str,
) -> Result<(Rc<MountBacking>, Handle, Rc<ProviderState>, bool, bool), Errno> {
    let grant =
        js_sys::Reflect::get(&remote, &JsValue::from_str("grant")).map_err(|_| Errno::EINVAL)?;
    let read_only = js_sys::Reflect::get(&grant, &JsValue::from_str("readOnly"))
        .ok()
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let execute = js_sys::Reflect::get(&grant, &JsValue::from_str("execute"))
        .ok()
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let synth = Cell::new(2);
    let opts = js_sys::Object::new();
    let _ = js_sys::Reflect::set(&opts, &"follow".into(), &JsValue::from_bool(true));
    let root_stat_val = call_remote(
        &remote,
        "stat",
        &[grant.clone(), JsValue::from_str(""), opts.into()],
    )
    .await
    .map_err(|e| match e {
        ShareError::Remote(err) => err,
        ShareError::Revoked => Errno::EACCES,
        ShareError::Disconnected => Errno::ENOTCONN,
    })?;
    let pub_fs_id = js_sys::Reflect::get(&root_stat_val, &JsValue::from_str("fsId"))
        .ok()
        .and_then(|v| v.as_string())
        .filter(|s| !s.is_empty());
    let fs_id = FsId(match pub_fs_id {
        Some(pub_id) => format!("share:{share_id}:{pub_id}"),
        None => format!("share:{share_id}"),
    });
    let (root_node, _) = parse_remote_stat(&root_stat_val, &synth).map_err(|_| Errno::EIO)?;
    let mut node_paths = HashMap::new();
    node_paths.insert(root_node, String::new());

    let provider = ProviderState::new();
    // Install push revocation / disconnect hook on `remote` if supported.
    let prov_cb = Rc::clone(&provider);
    let closure = Closure::wrap(Box::new(move |kind: JsValue| {
        if kind.as_string().as_deref() == Some("revoked") {
            prov_cb.revoke();
        } else {
            prov_cb.lose();
        }
    }) as Box<dyn FnMut(JsValue)>);
    let _ = js_sys::Reflect::set(
        &remote,
        &JsValue::from_str("onProviderEvent"),
        closure.as_ref().unchecked_ref(),
    );

    let transport = JsShareTransport {
        fs_id,
        root_node,
        remote,
        grant,
        node_paths: RefCell::new(node_paths),
        next_open: Cell::new(1),
        opens: RefCell::new(HashMap::new()),
        next_synth_ino: synth,
        provider_cb: Some(closure),
    };
    let share_fs = ShareFs::new(transport, Rc::clone(&provider), read_only, !execute);
    let (backing, root_handle) = share_fs.into_backing();
    Ok((backing, root_handle, provider, read_only, execute))
}

fn call_remote_sync(remote: &JsValue, method: &str, args: &[JsValue]) -> Result<JsValue, ()> {
    let func = js_sys::Reflect::get(remote, &JsValue::from_str(method))
        .ok()
        .and_then(|v| v.dyn_into::<js_sys::Function>().ok())
        .ok_or(())?;
    let arr = js_sys::Array::new();
    for arg in args {
        arr.push(arg);
    }
    js_sys::Reflect::apply(&func, remote, &arr).map_err(|_| ())
}
