//! Client-kernel JS bridge for [`vfs::hostfs::HostFs`] (`mount_opfs`, `mount_directory`,
//! `mount_snapshot`, Issues #48/#49/#50, contract §2.2, §2.5, §2.12).
//!
//! All portable POSIX permission, ACL, xattr, open-unlink/rename, fingerprint, store-version,
//! and advisory lock decisions execute in `os-vfs`; this adapter strictly translates primitive
//! host I/O, IndexedDB record transactions, and Web Locks calls across `wasm-bindgen`.

use crate::mounts::{self, Grant, LocalMount, extract_js_errno, js_errno, map_vfs_err};
use abi::fs::{FileType, LockKind, OpenOptions, Timespec, Written};
use abi::{Errno, Time};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashSet};
use std::rc::Rc;
use vfs::hostfs::mem::SimProfile;
use vfs::hostfs::{
    Backing, Clock, Fingerprint, HostEntry, HostFs, HostGrant, HostTree, InodeRecord, LockGuard,
    MetaBatch, MetaStore, ProfileLocks, StoreHeader,
};
use vfs::locks::Locks;
use vfs::{BoxFuture, Cred, Filesystem, Handle, SetAttr, WriteAt};
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

const FILES_MAX: u32 = 1024;
const IMAGE_MAX: u64 = 128 * 1024 * 1024;
const WASM_MAGIC: [u8; 8] = [0x00, b'a', b's', b'm', 0x01, 0x00, 0x00, 0x00];

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = Blob)]
    type JsBlob;
}

thread_local! {
    static NEXT_GENERATION: Cell<u64> = const { Cell::new(1) };
    static NEXT_SNAPSHOT_ID: Cell<u64> = const { Cell::new(1) };
}

fn next_generation() -> u64 {
    NEXT_GENERATION.with(|c| {
        let g = c.get();
        c.set(g.wrapping_add(1));
        g
    })
}

fn next_snapshot_uuid() -> String {
    let id = NEXT_SNAPSHOT_ID.with(|c| {
        let cur = c.get();
        c.set(cur.wrapping_add(1));
        cur
    });
    let suffix = js_sys::Reflect::get(&js_sys::global(), &JsValue::from_str("crypto"))
        .ok()
        .and_then(|c| {
            let f = js_sys::Reflect::get(&c, &JsValue::from_str("randomUUID"))
                .ok()?
                .dyn_into::<js_sys::Function>()
                .ok()?;
            f.call0(&c).ok()?.as_string()
        })
        .unwrap_or_else(|| format!("{id:012x}"));
    format!("snapshot-{id}-{suffix}")
}

fn ensure_js_safe(value: u64) -> vfs::Result<()> {
    if value > abi::fs::JS_SAFE {
        return Err(Errno::EFBIG);
    }
    Ok(())
}

fn now_timespec() -> (u64, u32) {
    let ms = js_sys::Date::now();
    if !ms.is_finite() || ms <= 0.0 {
        return (0, 0);
    }
    let whole_ms = ms.trunc() as u64;
    let sub_ns = ((ms.fract() * 1_000_000.0).round() as u64).min(999_999);
    let total_ns = whole_ms.saturating_mul(1_000_000).saturating_add(sub_ns);
    (total_ns / 1_000_000_000, (total_ns % 1_000_000_000) as u32)
}

fn js_clock() -> Clock {
    Box::new(now_timespec)
}

fn mtime_ms_to_ns(mtime_ms: f64) -> u64 {
    if !mtime_ms.is_finite() || mtime_ms <= 0.0 {
        return 0;
    }
    let whole_ms = mtime_ms.trunc() as u64;
    let sub_ns = ((mtime_ms.fract() * 1_000_000.0).round() as u64).min(999_999);
    whole_ms.saturating_mul(1_000_000).saturating_add(sub_ns)
}

fn fingerprint_from_ms(size: u64, mtime_ms: f64) -> Fingerprint {
    Fingerprint {
        size,
        mtime_ns: mtime_ms_to_ns(mtime_ms),
    }
}

#[derive(Deserialize)]
struct JsHostEntryWire {
    #[serde(rename = "fileType")]
    file_type: String,
    size: u64,
    #[serde(rename = "mtimeMs")]
    mtime_ms: f64,
    #[serde(default)]
    executable: bool,
}

impl JsHostEntryWire {
    fn into_host_entry(self) -> vfs::Result<HostEntry> {
        let file_type = match self.file_type.as_str() {
            "file" => FileType::File,
            "dir" => FileType::Dir,
            _ => return Err(Errno::EIO),
        };
        let fp = fingerprint_from_ms(self.size, self.mtime_ms);
        Ok(HostEntry {
            file_type,
            size: self.size,
            mtime: Timespec {
                sec: fp.mtime_ns / 1_000_000_000,
                nsec: (fp.mtime_ns % 1_000_000_000) as u32,
            },
            fingerprint: fp,
            executable: self.executable,
        })
    }
}

#[derive(Deserialize)]
struct JsFingerprintWire {
    size: u64,
    #[serde(rename = "mtimeMs")]
    mtime_ms: f64,
}

impl JsFingerprintWire {
    fn into_fingerprint(self) -> Fingerprint {
        fingerprint_from_ms(self.size, self.mtime_ms)
    }
}

#[derive(Serialize)]
struct JsExpectedFingerprintWire {
    size: u64,
    #[serde(rename = "mtimeWholeMs")]
    mtime_whole_ms: u64,
    #[serde(rename = "mtimeSubNs")]
    mtime_sub_ns: u32,
}

#[derive(Deserialize)]
struct JsWrittenWire {
    offset: u64,
    len: usize,
    size: u64,
    #[serde(rename = "mtimeMs")]
    mtime_ms: f64,
}

#[derive(Serialize)]
struct JsInodeRow {
    ino: u64,
    backing: Option<String>,
    json: String,
}

#[derive(Serialize)]
struct JsLockRow {
    ino: u64,
    json: String,
}

#[derive(Serialize)]
struct JsCommitBatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<u32>,
    #[serde(rename = "headerJson", skip_serializing_if = "Option::is_none")]
    header_json: Option<String>,
    #[serde(rename = "putInodes")]
    put_inodes: Vec<JsInodeRow>,
    #[serde(rename = "deleteInodes")]
    delete_inodes: Vec<u64>,
    #[serde(rename = "putLocks")]
    put_locks: Vec<JsLockRow>,
    #[serde(rename = "deleteLocks")]
    delete_locks: Vec<u64>,
}

fn inode_to_row(rec: &InodeRecord) -> vfs::Result<JsInodeRow> {
    let json = serde_json::to_string(rec).map_err(|_| Errno::EIO)?;
    let backing = match (rec.stale, &rec.backing) {
        (false, Backing::Path(p)) => Some(p.clone()),
        _ => None,
    };
    Ok(JsInodeRow {
        ino: rec.ino,
        backing,
        json,
    })
}

fn backing_args(backing: &Backing) -> vfs::Result<(&'static str, String)> {
    match backing {
        Backing::Path(p) => Ok(("path", p.clone())),
        Backing::Orphan(ino) => Ok(("orphan", ino.to_string())),
        Backing::MetaOnly => Err(Errno::EINVAL),
    }
}

fn js_to_json_vfs(val: &JsValue) -> vfs::Result<Value> {
    if val.is_null() || val.is_undefined() {
        return Ok(Value::Null);
    }
    let text = js_sys::JSON::stringify(val)
        .map_err(|_| Errno::EIO)?
        .as_string()
        .ok_or(Errno::EIO)?;
    serde_json::from_str(&text).map_err(|_| Errno::EIO)
}

fn json_to_js_vfs(val: &Value) -> vfs::Result<JsValue> {
    let text = serde_json::to_string(val).map_err(|_| Errno::EIO)?;
    js_sys::JSON::parse(&text).map_err(|_| Errno::EIO)
}

fn expected_fp_to_js(expected_fp: Option<Fingerprint>) -> vfs::Result<JsValue> {
    match expected_fp {
        None => Ok(JsValue::NULL),
        Some(fp) => json_to_js_vfs(
            &serde_json::to_value(JsExpectedFingerprintWire {
                size: fp.size,
                mtime_whole_ms: fp.mtime_ns / 1_000_000,
                mtime_sub_ns: (fp.mtime_ns % 1_000_000) as u32,
            })
            .map_err(|_| Errno::EIO)?,
        ),
    }
}

fn expected_ino_to_js(expected_ino: Option<u64>) -> JsValue {
    expected_ino.map_or(JsValue::NULL, |ino| JsValue::from_str(&ino.to_string()))
}

struct JsStore {
    obj: JsValue,
    revoke_cb: RefCell<Option<Closure<dyn FnMut()>>>,
    next_ticket: Cell<u64>,
}

impl JsStore {
    fn new(obj: JsValue) -> Rc<Self> {
        Rc::new(Self {
            obj,
            revoke_cb: RefCell::new(None),
            next_ticket: Cell::new(1),
        })
    }

    fn method(&self, name: &str) -> vfs::Result<js_sys::Function> {
        js_sys::Reflect::get(&self.obj, &JsValue::from_str(name))
            .map_err(|e| extract_js_errno(&e))?
            .dyn_into::<js_sys::Function>()
            .map_err(|_| Errno::EIO)
    }

    async fn call_async(&self, name: &str, args: &[JsValue]) -> vfs::Result<JsValue> {
        let func = self.method(name)?;
        let arr = js_sys::Array::new();
        for arg in args {
            arr.push(arg);
        }
        let ret =
            js_sys::Reflect::apply(&func, &self.obj, &arr).map_err(|e| extract_js_errno(&e))?;
        let promise = ret.dyn_into::<js_sys::Promise>().map_err(|_| Errno::EIO)?;
        JsFuture::from(promise)
            .await
            .map_err(|e| extract_js_errno(&e))
    }

    fn set_on_revoke(&self, detach: Rc<dyn Fn()>) {
        if let Ok(func) = self.method("setOnRevoke") {
            let closure = Closure::wrap(Box::new(move || detach()) as Box<dyn FnMut()>);
            let _ = func.call1(&self.obj, closure.as_ref().unchecked_ref());
            *self.revoke_cb.borrow_mut() = Some(closure);
        }
    }

    fn close(&self) {
        if let Ok(func) = self.method("close") {
            let _ = func.call0(&self.obj);
        }
        let _ = self.revoke_cb.borrow_mut().take();
    }
}

struct JsHostTree(Rc<JsStore>);

impl HostTree for JsHostTree {
    fn stat_path<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Option<HostEntry>> {
        Box::pin(async move {
            let val = self
                .0
                .call_async("statPath", &[JsValue::from_str(path)])
                .await?;
            if val.is_null() || val.is_undefined() {
                return Ok(None);
            }
            let wire: JsHostEntryWire =
                serde_json::from_value(js_to_json_vfs(&val)?).map_err(|_| Errno::EIO)?;
            Ok(Some(wire.into_host_entry()?))
        })
    }

    fn list_dir<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Vec<(String, HostEntry)>> {
        Box::pin(async move {
            let val = self
                .0
                .call_async("listDir", &[JsValue::from_str(path)])
                .await?;
            let raw: Vec<(String, JsHostEntryWire)> =
                serde_json::from_value(js_to_json_vfs(&val)?).map_err(|_| Errno::EIO)?;
            let mut out = Vec::with_capacity(raw.len());
            for (name, wire) in raw {
                out.push((name, wire.into_host_entry()?));
            }
            Ok(out)
        })
    }

    fn create_file<'a>(
        &'a self,
        path: &'a str,
        create_new: bool,
        truncate: bool,
    ) -> BoxFuture<'a, HostEntry> {
        Box::pin(async move {
            let val = self
                .0
                .call_async(
                    "createFile",
                    &[
                        JsValue::from_str(path),
                        JsValue::from_bool(create_new),
                        JsValue::from_bool(truncate),
                    ],
                )
                .await?;
            let wire: JsHostEntryWire =
                serde_json::from_value(js_to_json_vfs(&val)?).map_err(|_| Errno::EIO)?;
            wire.into_host_entry()
        })
    }

    fn create_dir<'a>(&'a self, path: &'a str) -> BoxFuture<'a, HostEntry> {
        Box::pin(async move {
            let val = self
                .0
                .call_async("createDir", &[JsValue::from_str(path)])
                .await?;
            let wire: JsHostEntryWire =
                serde_json::from_value(js_to_json_vfs(&val)?).map_err(|_| Errno::EIO)?;
            wire.into_host_entry()
        })
    }

    fn read_file<'a>(
        &'a self,
        backing: &'a Backing,
        offset: u64,
        len: usize,
        expected_fp: Option<Fingerprint>,
        expected_ino: Option<u64>,
    ) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(async move {
            ensure_js_safe(offset)?;
            ensure_js_safe(len as u64)?;
            let (kind, target) = backing_args(backing)?;
            let val = self
                .0
                .call_async(
                    "readFile",
                    &[
                        JsValue::from_str(kind),
                        JsValue::from_str(&target),
                        JsValue::from_f64(offset as f64),
                        JsValue::from_f64(len as f64),
                        expected_fp_to_js(expected_fp)?,
                        expected_ino_to_js(expected_ino),
                    ],
                )
                .await?;
            let arr = val
                .dyn_into::<js_sys::Uint8Array>()
                .map_err(|_| Errno::EIO)?;
            Ok(arr.to_vec())
        })
    }

    fn write_file<'a>(
        &'a self,
        backing: &'a Backing,
        offset: u64,
        data: &'a [u8],
        append: bool,
        expected_fp: Option<Fingerprint>,
        expected_ino: Option<u64>,
    ) -> BoxFuture<'a, (Written, Fingerprint)> {
        Box::pin(async move {
            ensure_js_safe(offset)?;
            ensure_js_safe(data.len() as u64)?;
            let (kind, target) = backing_args(backing)?;
            let bytes = js_sys::Uint8Array::from(data);
            let val = self
                .0
                .call_async(
                    "writeFile",
                    &[
                        JsValue::from_str(kind),
                        JsValue::from_str(&target),
                        JsValue::from_f64(offset as f64),
                        bytes.into(),
                        JsValue::from_bool(append),
                        expected_fp_to_js(expected_fp)?,
                        expected_ino_to_js(expected_ino),
                    ],
                )
                .await?;
            let wire: JsWrittenWire =
                serde_json::from_value(js_to_json_vfs(&val)?).map_err(|_| Errno::EIO)?;
            Ok((
                Written {
                    offset: wire.offset,
                    len: wire.len,
                },
                fingerprint_from_ms(wire.size, wire.mtime_ms),
            ))
        })
    }

    fn set_file_len<'a>(
        &'a self,
        backing: &'a Backing,
        size: u64,
        expected_fp: Option<Fingerprint>,
        expected_ino: Option<u64>,
    ) -> BoxFuture<'a, Fingerprint> {
        Box::pin(async move {
            ensure_js_safe(size)?;
            let (kind, target) = backing_args(backing)?;
            let val = self
                .0
                .call_async(
                    "setFileLen",
                    &[
                        JsValue::from_str(kind),
                        JsValue::from_str(&target),
                        JsValue::from_f64(size as f64),
                        expected_fp_to_js(expected_fp)?,
                        expected_ino_to_js(expected_ino),
                    ],
                )
                .await?;
            let wire: JsFingerprintWire =
                serde_json::from_value(js_to_json_vfs(&val)?).map_err(|_| Errno::EIO)?;
            Ok(wire.into_fingerprint())
        })
    }

    fn flush_file<'a>(
        &'a self,
        backing: &'a Backing,
        data_only: bool,
        expected_fp: Option<Fingerprint>,
        expected_ino: Option<u64>,
    ) -> BoxFuture<'a, Fingerprint> {
        Box::pin(async move {
            let (kind, target) = backing_args(backing)?;
            let val = self
                .0
                .call_async(
                    "flushFile",
                    &[
                        JsValue::from_str(kind),
                        JsValue::from_str(&target),
                        JsValue::from_bool(data_only),
                        expected_fp_to_js(expected_fp)?,
                        expected_ino_to_js(expected_ino),
                    ],
                )
                .await?;
            let wire: JsFingerprintWire =
                serde_json::from_value(js_to_json_vfs(&val)?).map_err(|_| Errno::EIO)?;
            Ok(wire.into_fingerprint())
        })
    }

    fn retain_host_entry<'a>(&'a self, ino: u64, path: &'a str, is_dir: bool) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let ino_str = ino.to_string();
            self.0
                .call_async(
                    "retainEntryHandle",
                    &[
                        JsValue::from_str(&ino_str),
                        JsValue::from_str(path),
                        JsValue::from_bool(is_dir),
                    ],
                )
                .await?;
            Ok(())
        })
    }

    fn verify_host_entry<'a>(
        &'a self,
        ino: u64,
        path: &'a str,
        is_dir: bool,
    ) -> BoxFuture<'a, bool> {
        Box::pin(async move {
            let ino_str = ino.to_string();
            let val = self
                .0
                .call_async(
                    "verifyEntryHandle",
                    &[
                        JsValue::from_str(&ino_str),
                        JsValue::from_str(path),
                        JsValue::from_bool(is_dir),
                    ],
                )
                .await?;
            Ok(val.as_bool().unwrap_or(false))
        })
    }

    fn forget_host_entry<'a>(&'a self, ino: u64) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let ino_str = ino.to_string();
            self.0
                .call_async("forgetEntryHandle", &[JsValue::from_str(&ino_str)])
                .await?;
            Ok(())
        })
    }

    fn remove_file<'a>(&'a self, path: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.0
                .call_async("removeFile", &[JsValue::from_str(path)])
                .await?;
            Ok(())
        })
    }

    fn remove_dir<'a>(&'a self, path: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.0
                .call_async("removeDir", &[JsValue::from_str(path)])
                .await?;
            Ok(())
        })
    }

    fn move_entry<'a>(
        &'a self,
        from: &'a str,
        to: &'a str,
        is_dir: bool,
    ) -> BoxFuture<'a, Vec<(String, Fingerprint)>> {
        Box::pin(async move {
            let val = self
                .0
                .call_async(
                    "moveEntry",
                    &[
                        JsValue::from_str(from),
                        JsValue::from_str(to),
                        JsValue::from_bool(is_dir),
                    ],
                )
                .await?;
            let raw: Vec<(String, JsFingerprintWire)> =
                serde_json::from_value(js_to_json_vfs(&val)?).map_err(|_| Errno::EIO)?;
            Ok(raw
                .into_iter()
                .map(|(p, fp)| (p, fp.into_fingerprint()))
                .collect())
        })
    }

    fn move_to_orphan<'a>(&'a self, path: &'a str, ino: u64) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let ino_str = ino.to_string();
            self.0
                .call_async(
                    "moveToOrphan",
                    &[JsValue::from_str(path), JsValue::from_str(&ino_str)],
                )
                .await?;
            Ok(())
        })
    }

    fn restore_orphan<'a>(&'a self, ino: u64, to: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let ino_str = ino.to_string();
            self.0
                .call_async(
                    "restoreOrphan",
                    &[JsValue::from_str(&ino_str), JsValue::from_str(to)],
                )
                .await?;
            Ok(())
        })
    }

    fn remove_orphan(&self, ino: u64) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let ino_str = ino.to_string();
            self.0
                .call_async("removeOrphan", &[JsValue::from_str(&ino_str)])
                .await?;
            Ok(())
        })
    }

    fn list_orphans(&self) -> BoxFuture<'_, Vec<u64>> {
        Box::pin(async move {
            let val = self.0.call_async("listOrphans", &[]).await?;
            let raw: Vec<String> =
                serde_json::from_value(js_to_json_vfs(&val)?).map_err(|_| Errno::EIO)?;
            Ok(raw
                .into_iter()
                .filter_map(|s| s.parse::<u64>().ok())
                .collect())
        })
    }
}

struct JsMetaStore(Rc<JsStore>);

impl MetaStore for JsMetaStore {
    fn read_version(&self) -> BoxFuture<'_, Option<u32>> {
        Box::pin(async move {
            let val = self.0.call_async("readVersion", &[]).await?;
            if val.is_null() || val.is_undefined() {
                return Ok(None);
            }
            let n = val.as_f64().ok_or(Errno::EIO)?;
            if !n.is_finite() || n < 0.0 || n > (u32::MAX as f64) {
                return Err(Errno::EPROTONOSUPPORT);
            }
            Ok(Some(n as u32))
        })
    }

    fn read_header(&self) -> BoxFuture<'_, Option<StoreHeader>> {
        Box::pin(async move {
            let val = self.0.call_async("readHeader", &[]).await?;
            if val.is_null() || val.is_undefined() {
                return Ok(None);
            }
            let text = val.as_string().ok_or(Errno::EIO)?;
            let header: StoreHeader = serde_json::from_str(&text).map_err(|_| Errno::EIO)?;
            Ok(Some(header))
        })
    }

    fn reset_to_current(&self, header: StoreHeader, root: InodeRecord) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let header_json = serde_json::to_string(&header).map_err(|_| Errno::EIO)?;
            let root_row = inode_to_row(&root)?;
            let backing_js = match root_row.backing {
                Some(ref b) => JsValue::from_str(b),
                None => JsValue::NULL,
            };
            self.0
                .call_async(
                    "resetToCurrent",
                    &[
                        JsValue::from_f64(header.format_version as f64),
                        JsValue::from_str(&header_json),
                        JsValue::from_f64(root_row.ino as f64),
                        backing_js,
                        JsValue::from_str(&root_row.json),
                    ],
                )
                .await?;
            Ok(())
        })
    }

    fn mint_uuid(&self) -> BoxFuture<'_, String> {
        Box::pin(async move {
            let val = self.0.call_async("mintUuid", &[]).await?;
            val.as_string().ok_or(Errno::EIO)
        })
    }

    fn get_inode(&self, ino: u64) -> BoxFuture<'_, Option<InodeRecord>> {
        Box::pin(async move {
            let val = self
                .0
                .call_async("getInode", &[JsValue::from_f64(ino as f64)])
                .await?;
            if val.is_null() || val.is_undefined() {
                return Ok(None);
            }
            let text = val.as_string().ok_or(Errno::EIO)?;
            let rec: InodeRecord = serde_json::from_str(&text).map_err(|_| Errno::EIO)?;
            Ok(Some(rec))
        })
    }

    fn find_by_backing<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Option<InodeRecord>> {
        Box::pin(async move {
            let val = self
                .0
                .call_async("findByBacking", &[JsValue::from_str(path)])
                .await?;
            if val.is_null() || val.is_undefined() {
                return Ok(None);
            }
            let text = val.as_string().ok_or(Errno::EIO)?;
            let rec: InodeRecord = serde_json::from_str(&text).map_err(|_| Errno::EIO)?;
            Ok(Some(rec))
        })
    }

    fn list_all_inodes(&self) -> BoxFuture<'_, Vec<InodeRecord>> {
        Box::pin(async move {
            let val = self.0.call_async("listAllInodes", &[]).await?;
            let arr = val.dyn_into::<js_sys::Array>().map_err(|_| Errno::EIO)?;
            let mut out = Vec::with_capacity(arr.length() as usize);
            for item in arr.iter() {
                let text = item.as_string().ok_or(Errno::EIO)?;
                let rec: InodeRecord = serde_json::from_str(&text).map_err(|_| Errno::EIO)?;
                out.push(rec);
            }
            Ok(out)
        })
    }

    fn get_locks(&self, ino: u64) -> BoxFuture<'_, Locks> {
        Box::pin(async move {
            let val = self
                .0
                .call_async("getLocks", &[JsValue::from_f64(ino as f64)])
                .await?;
            if val.is_null() || val.is_undefined() {
                return Ok(Locks::default());
            }
            let text = val.as_string().ok_or(Errno::EIO)?;
            let table: Locks = serde_json::from_str(&text).map_err(|_| Errno::EIO)?;
            Ok(table)
        })
    }

    fn list_all_locks(&self) -> BoxFuture<'_, Vec<(u64, Locks)>> {
        Box::pin(async move {
            let val = self.0.call_async("listAllLocks", &[]).await?;
            let raw: Vec<(u64, String)> =
                serde_json::from_value(js_to_json_vfs(&val)?).map_err(|_| Errno::EIO)?;
            let mut out = Vec::with_capacity(raw.len());
            for (ino, text) in raw {
                let table: Locks = serde_json::from_str(&text).map_err(|_| Errno::EIO)?;
                out.push((ino, table));
            }
            Ok(out)
        })
    }

    fn commit(&self, batch: MetaBatch, strict: bool) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let (version, header_json) = match batch.header {
                Some(ref h) => (
                    Some(h.format_version),
                    Some(serde_json::to_string(h).map_err(|_| Errno::EIO)?),
                ),
                None => (None, None),
            };
            let mut put_inodes = Vec::with_capacity(batch.put_inodes.len());
            for rec in &batch.put_inodes {
                put_inodes.push(inode_to_row(rec)?);
            }
            let mut put_locks = Vec::with_capacity(batch.put_locks.len());
            for (ino, table) in &batch.put_locks {
                let json = serde_json::to_string(table).map_err(|_| Errno::EIO)?;
                put_locks.push(JsLockRow { ino: *ino, json });
            }
            let wire = JsCommitBatch {
                version,
                header_json,
                put_inodes,
                delete_inodes: batch.delete_inodes,
                put_locks,
                delete_locks: batch.delete_locks,
            };
            let js_batch = json_to_js_vfs(&serde_json::to_value(&wire).map_err(|_| Errno::EIO)?)?;
            self.0
                .call_async("commit", &[js_batch, JsValue::from_bool(strict)])
                .await?;
            Ok(())
        })
    }

    fn sync_strict(&self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.0.call_async("syncStrict", &[]).await?;
            Ok(())
        })
    }
}

struct JsLockGuard {
    release: Option<js_sys::Function>,
}

impl LockGuard for JsLockGuard {}

impl Drop for JsLockGuard {
    fn drop(&mut self) {
        if let Some(func) = self.release.take() {
            let _ = func.call0(&JsValue::NULL);
        }
    }
}

struct CancelJsOpOnDrop {
    cancel: Option<js_sys::Function>,
}

impl CancelJsOpOnDrop {
    fn disarm(&mut self) {
        self.cancel = None;
    }
}

impl Drop for CancelJsOpOnDrop {
    fn drop(&mut self) {
        if let Some(func) = self.cancel.take() {
            let _ = func.call0(&JsValue::NULL);
        }
    }
}

struct JsProfileLocks(Rc<JsStore>);

impl ProfileLocks for JsProfileLocks {
    fn acquire<'a>(&'a self, name: &'a str, kind: LockKind) -> BoxFuture<'a, Box<dyn LockGuard>> {
        Box::pin(async move {
            let func = self
                .0
                .method("startAcquireLock")
                .map_err(|_| Errno::ENOLCK)?;
            let shared = matches!(kind, LockKind::Shared);
            let handle = func
                .call2(
                    &self.0.obj,
                    &JsValue::from_str(name),
                    &JsValue::from_bool(shared),
                )
                .map_err(|e| extract_js_errno(&e))?;
            let promise = js_sys::Reflect::get(&handle, &JsValue::from_str("promise"))
                .map_err(|_| Errno::ENOLCK)?
                .dyn_into::<js_sys::Promise>()
                .map_err(|_| Errno::ENOLCK)?;
            let cancel = js_sys::Reflect::get(&handle, &JsValue::from_str("cancel"))
                .map_err(|_| Errno::ENOLCK)?
                .dyn_into::<js_sys::Function>()
                .map_err(|_| Errno::ENOLCK)?;
            let mut drop_guard = CancelJsOpOnDrop {
                cancel: Some(cancel),
            };
            let release_val = JsFuture::from(promise)
                .await
                .map_err(|e| extract_js_errno(&e))?;
            drop_guard.disarm();
            let release = release_val
                .dyn_into::<js_sys::Function>()
                .map_err(|_| Errno::ENOLCK)?;
            Ok(Box::new(JsLockGuard {
                release: Some(release),
            }) as Box<dyn LockGuard>)
        })
    }

    fn try_acquire<'a>(
        &'a self,
        name: &'a str,
        kind: LockKind,
    ) -> BoxFuture<'a, Option<Box<dyn LockGuard>>> {
        Box::pin(async move {
            let shared = matches!(kind, LockKind::Shared);
            let val = self
                .0
                .call_async(
                    "tryAcquireLock",
                    &[JsValue::from_str(name), JsValue::from_bool(shared)],
                )
                .await?;
            if val.is_null() || val.is_undefined() {
                return Ok(None);
            }
            let release = val
                .dyn_into::<js_sys::Function>()
                .map_err(|_| Errno::ENOLCK)?;
            Ok(Some(Box::new(JsLockGuard {
                release: Some(release),
            }) as Box<dyn LockGuard>))
        })
    }

    fn held_locks(&self) -> BoxFuture<'_, HashSet<String>> {
        Box::pin(async move {
            let val = self.0.call_async("heldLocks", &[]).await?;
            let names: Vec<String> =
                serde_json::from_value(js_to_json_vfs(&val)?).map_err(|_| Errno::ENOLCK)?;
            Ok(names.into_iter().collect())
        })
    }

    fn notify_locks(&self) {
        if let Ok(func) = self.0.method("notifyLocks") {
            let _ = func.call0(&self.0.obj);
        }
    }

    fn wait_for_change<'a>(&'a self, blocking_locks: &'a [String]) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let func = self
                .0
                .method("startWaitForChange")
                .map_err(|_| Errno::ENOLCK)?;
            let arr = js_sys::Array::new();
            for lock_name in blocking_locks {
                arr.push(&JsValue::from_str(lock_name));
            }
            let handle = func
                .call1(&self.0.obj, &arr)
                .map_err(|e| extract_js_errno(&e))?;
            let promise = js_sys::Reflect::get(&handle, &JsValue::from_str("promise"))
                .map_err(|_| Errno::ENOLCK)?
                .dyn_into::<js_sys::Promise>()
                .map_err(|_| Errno::ENOLCK)?;
            let cancel = js_sys::Reflect::get(&handle, &JsValue::from_str("cancel"))
                .map_err(|_| Errno::ENOLCK)?
                .dyn_into::<js_sys::Function>()
                .map_err(|_| Errno::ENOLCK)?;
            let mut drop_guard = CancelJsOpOnDrop {
                cancel: Some(cancel),
            };
            JsFuture::from(promise)
                .await
                .map_err(|e| extract_js_errno(&e))?;
            drop_guard.disarm();
            Ok(())
        })
    }

    fn new_ticket(&self) -> String {
        let id = self.0.next_ticket.get();
        self.0.next_ticket.set(id.wrapping_add(1));
        if let Ok(func) = self.0.method("newTicket")
            && let Ok(val) = func.call0(&self.0.obj)
            && let Some(s) = val.as_string()
        {
            return s;
        }
        format!("t-{id}")
    }
}

fn parse_grant(grant_json: &str) -> Result<(Grant, HostGrant), JsValue> {
    let grant: Grant =
        serde_json::from_str(grant_json).map_err(|_| js_errno(Errno::EINVAL, "invalid grant"))?;
    let host_grant = HostGrant {
        owner: grant.owner.clone(),
        read_only: grant.read_only,
        execute: grant.execute,
    };
    Ok((grant, host_grant))
}

/// Mount browser storage (`os-workspace` in OPFS) over a JS `fs-store.js` adapter.
#[wasm_bindgen]
pub async fn mount_opfs(store: JsValue, grant_json: &str) -> Result<LocalMount, JsValue> {
    let (grant, host_grant) = parse_grant(grant_json)?;
    let js_store = JsStore::new(store);
    let fs = match HostFs::opfs(
        host_grant,
        next_generation(),
        JsHostTree(Rc::clone(&js_store)),
        JsMetaStore(Rc::clone(&js_store)),
        JsProfileLocks(Rc::clone(&js_store)),
        js_clock(),
    )
    .await
    {
        Ok(fs) => fs,
        Err(err) => {
            js_store.close();
            return Err(map_vfs_err(err));
        }
    };
    let close_store = Rc::clone(&js_store);
    let mount = mounts::from_fs_with_unmount(Rc::new(fs), grant, move || close_store.close());
    js_store.set_on_revoke(mount.detach_callback());
    Ok(mount)
}

/// Mount a host directory handle (`FileSystemDirectoryHandle`) over a JS `fs-store.js` adapter.
#[wasm_bindgen]
pub async fn mount_directory(store: JsValue, grant_json: &str) -> Result<LocalMount, JsValue> {
    let (grant, host_grant) = parse_grant(grant_json)?;
    let js_store = JsStore::new(store);
    let fs = match HostFs::directory(
        host_grant,
        next_generation(),
        JsHostTree(Rc::clone(&js_store)),
        JsMetaStore(Rc::clone(&js_store)),
        JsProfileLocks(Rc::clone(&js_store)),
        js_clock(),
    )
    .await
    {
        Ok(fs) => fs,
        Err(err) => {
            js_store.close();
            return Err(map_vfs_err(err));
        }
    };
    let close_store = Rc::clone(&js_store);
    let mount = mounts::from_fs_with_unmount(Rc::new(fs), grant, move || close_store.close());
    js_store.set_on_revoke(mount.detach_callback());
    Ok(mount)
}

fn parse_snapshot_parts(raw: &str) -> Result<Vec<String>, JsValue> {
    if raw.len() > 4096 || raw.contains('\0') || raw.contains('\\') {
        return Err(js_errno(Errno::EINVAL, "invalid mount-relative path"));
    }
    if raw.starts_with('/') || raw.split('/').any(|p| p == "..") {
        return Err(js_errno(Errno::EACCES, "path escapes local mount"));
    }
    let names: Vec<String> = raw
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .map(str::to_owned)
        .collect();
    if names.len() > 256 || names.iter().any(|n| n.len() > abi::NAME_MAX) {
        return Err(js_errno(Errno::ENAMETOOLONG, "local path is too long"));
    }
    Ok(names)
}

struct SnapshotMeta(vfs::hostfs::mem::SimMeta, String);

impl MetaStore for SnapshotMeta {
    fn read_version(&self) -> BoxFuture<'_, Option<u32>> {
        self.0.read_version()
    }
    fn read_header(&self) -> BoxFuture<'_, Option<StoreHeader>> {
        self.0.read_header()
    }
    fn reset_to_current(&self, header: StoreHeader, root: InodeRecord) -> BoxFuture<'_, ()> {
        self.0.reset_to_current(header, root)
    }
    fn mint_uuid(&self) -> BoxFuture<'_, String> {
        let uuid = self.1.clone();
        Box::pin(async move { Ok(uuid) })
    }
    fn get_inode(&self, ino: u64) -> BoxFuture<'_, Option<InodeRecord>> {
        self.0.get_inode(ino)
    }
    fn find_by_backing<'a>(&'a self, path: &'a str) -> BoxFuture<'a, Option<InodeRecord>> {
        self.0.find_by_backing(path)
    }
    fn list_all_inodes(&self) -> BoxFuture<'_, Vec<InodeRecord>> {
        self.0.list_all_inodes()
    }
    fn get_locks(&self, ino: u64) -> BoxFuture<'_, Locks> {
        self.0.get_locks(ino)
    }
    fn list_all_locks(&self) -> BoxFuture<'_, Vec<(u64, Locks)>> {
        self.0.list_all_locks()
    }
    fn commit(&self, batch: MetaBatch, strict: bool) -> BoxFuture<'_, ()> {
        self.0.commit(batch, strict)
    }
    fn sync_strict(&self) -> BoxFuture<'_, ()> {
        self.0.sync_strict()
    }
}

/// Mount an immutable selected-files snapshot (`<input type="file">`) over in-memory [`HostFs`].
///
/// Copies file bytes eagerly at selection time so later host edits cannot invalidate the snapshot,
/// enforces data/namespace `EROFS`, and keeps in-memory POSIX ACLs/modes mutable by the owner for
/// peer export sharing.
#[wasm_bindgen]
pub async fn mount_snapshot(files: JsValue, grant_json: &str) -> Result<LocalMount, JsValue> {
    let (mut grant, _) = parse_grant(grant_json)?;
    grant.read_only = true;

    if !js_sys::Array::is_array(&files) {
        return Err(js_errno(Errno::EINVAL, "select between 1 and 1024 files"));
    }
    let arr = js_sys::Array::from(&files);
    let len = arr.length();
    if len == 0 || len > FILES_MAX {
        return Err(js_errno(Errno::EINVAL, "select between 1 and 1024 files"));
    }

    let blob_ctor = js_sys::Reflect::get(&js_sys::global(), &JsValue::from_str("Blob")).ok();

    struct PendingFile {
        parts: Vec<String>,
        bytes: Vec<u8>,
        mtime_ns: u64,
    }

    let mut seen_files = HashSet::new();
    let mut seen_dirs = HashSet::new();
    let mut total_size: u64 = 0;
    let mut staged = Vec::with_capacity(len as usize);

    for i in 0..len {
        let item = arr.get(i);
        if !item.is_object() || item.is_null() {
            return Err(js_errno(Errno::EINVAL, "a selected File is required"));
        }
        if let Some(ref ctor) = blob_ctor
            && ctor.is_function()
            && !item.is_instance_of::<JsBlob>()
        {
            return Err(js_errno(Errno::EINVAL, "a selected File is required"));
        }
        let name = js_sys::Reflect::get(&item, &JsValue::from_str("name"))
            .ok()
            .and_then(|v| v.as_string())
            .ok_or_else(|| js_errno(Errno::EINVAL, "a selected File is required"))?;
        let rel = js_sys::Reflect::get(&item, &JsValue::from_str("webkitRelativePath"))
            .ok()
            .and_then(|v| v.as_string())
            .filter(|s| !s.is_empty())
            .unwrap_or(name);

        let parts = parse_snapshot_parts(&rel)?;
        let joined = parts.join("/");
        if joined.is_empty() || seen_files.contains(&joined) || seen_dirs.contains(&joined) {
            return Err(js_errno(Errno::EEXIST, "duplicate or empty selected path"));
        }

        let declared_size = js_sys::Reflect::get(&item, &JsValue::from_str("size"))
            .ok()
            .and_then(|v| v.as_f64())
            .ok_or_else(|| js_errno(Errno::EINVAL, "a selected File is required"))?;
        if !declared_size.is_finite() || declared_size < 0.0 {
            return Err(js_errno(Errno::EINVAL, "invalid file size"));
        }
        let size_u64 = declared_size as u64;
        total_size = total_size.saturating_add(size_u64);
        if total_size > IMAGE_MAX {
            return Err(js_errno(Errno::EFBIG, "selected files exceed 128 MiB"));
        }

        for depth in 1..parts.len() {
            let parent = parts[..depth].join("/");
            if seen_files.contains(&parent) {
                return Err(js_errno(
                    Errno::ENOTDIR,
                    "a selected file is also a directory",
                ));
            }
            seen_dirs.insert(parent);
        }

        let ab_fn = js_sys::Reflect::get(&item, &JsValue::from_str("arrayBuffer"))
            .map_err(|_| js_errno(Errno::EINVAL, "a selected File is required"))?
            .dyn_into::<js_sys::Function>()
            .map_err(|_| js_errno(Errno::EINVAL, "a selected File is required"))?;
        let ab_promise = ab_fn
            .call0(&item)
            .map_err(|e| map_vfs_err(extract_js_errno(&e)))?
            .dyn_into::<js_sys::Promise>()
            .map_err(|_| js_errno(Errno::EIO, "invalid arrayBuffer promise"))?;
        let ab = JsFuture::from(ab_promise)
            .await
            .map_err(|e| map_vfs_err(extract_js_errno(&e)))?;
        let bytes = js_sys::Uint8Array::new(&ab).to_vec();
        if bytes.len() as u64 != size_u64 {
            return Err(js_errno(Errno::EIO, "selected file changed while reading"));
        }

        let last_mod = js_sys::Reflect::get(&item, &JsValue::from_str("lastModified"))
            .ok()
            .and_then(|v| v.as_f64())
            .unwrap_or_else(js_sys::Date::now);
        let mtime_ns = mtime_ms_to_ns(last_mod);

        seen_files.insert(joined);
        staged.push(PendingFile {
            parts,
            bytes,
            mtime_ns,
        });
    }

    let sim = SimProfile::new();
    let host_grant = HostGrant {
        owner: grant.owner.clone(),
        read_only: false,
        execute: grant.execute,
    };
    let meta = SnapshotMeta(sim.meta_handle(), next_snapshot_uuid());
    let fs = HostFs::opfs(
        host_grant,
        next_generation(),
        sim.tree_handle(),
        meta,
        sim.locks_handle(1),
        js_clock(),
    )
    .await
    .map_err(map_vfs_err)?;

    let cred = Cred {
        identity: grant.owner.clone(),
        umask: 0,
        token: None,
    };

    let mut dir_handles: BTreeMap<String, Handle> = BTreeMap::new();
    dir_handles.insert(String::new(), fs.root());

    for file in staged {
        let mut cur_path = String::new();
        let mut parent_handle = fs.root();
        for seg in &file.parts[..file.parts.len() - 1] {
            let next_path = if cur_path.is_empty() {
                seg.clone()
            } else {
                format!("{cur_path}/{seg}")
            };
            if let Some(h) = dir_handles.get(&next_path) {
                parent_handle = h.clone();
            } else {
                let entry = fs
                    .mkdir(&cred, &parent_handle, seg, 0o700)
                    .await
                    .map_err(map_vfs_err)?;
                dir_handles.insert(next_path.clone(), entry.handle.clone());
                parent_handle = entry.handle;
            }
            cur_path = next_path;
        }

        let leaf = file.parts.last().expect("non-empty parts");
        let is_wasm = file.bytes.len() >= 8 && file.bytes[..8] == WASM_MAGIC;
        let file_mode = 0o400 | if grant.execute && is_wasm { 0o100 } else { 0 };
        let (entry, open_ref) = fs
            .create(
                &cred,
                &parent_handle,
                leaf,
                0o600,
                OpenOptions::new().write(true).create_new(true),
            )
            .await
            .map_err(map_vfs_err)?;
        if !file.bytes.is_empty() {
            fs.write_at(&open_ref, &file.bytes, WriteAt::Offset(0))
                .await
                .map_err(map_vfs_err)?;
        }
        fs.release(&open_ref).await.map_err(map_vfs_err)?;

        let sec = file.mtime_ns / 1_000_000_000;
        let nsec = (file.mtime_ns % 1_000_000_000) as u32;
        fs.setattr(
            &cred,
            &entry.handle,
            &SetAttr {
                mode: Some(file_mode),
                atime: Time::At { sec, nsec },
                mtime: Time::At { sec, nsec },
                ..SetAttr::default()
            },
        )
        .await
        .map_err(map_vfs_err)?;
    }

    // Set snapshot directories (including root) to read+search `0o500` by default; owner retains
    // `chmod` / `setxattr` authority for sharing exports while `LocalMount::from_snapshot` enforces
    // `EROFS` on all data and namespace mutations.
    for (_, dh) in dir_handles {
        let _ = fs
            .setattr(
                &cred,
                &dh,
                &SetAttr {
                    mode: Some(0o500),
                    ..SetAttr::default()
                },
            )
            .await;
    }
    let _ = json!({});

    Ok(LocalMount::from_snapshot(Rc::new(fs), grant))
}
