//! Thin `wasm-bindgen` bridge connecting portable `os-cowtree` / `os-cowfs` + `os-vfs` (`/dev/vdN`)
//! to the browser OPFS + IndexedDB + Web Locks adapter (`web/kernel/cowfs-store.js`, #77).
//!
//! Zero filesystem policy lives in JavaScript: all B+tree verification, POSIX permissions/ACLs/
//! xattrs, `DIR_INDEX` paging, `ORPHAN_ITEM` reaping, `FICLONE`, `32 MiB` slab arena accounting,
//! reachability GC, `cowfsck`, and `/dev/vdN` ioctl authorization run in portable Rust.

use crate::mounts::{extract_js_errno, js_errno, map_vfs_err, parse_identity};
use abi::Errno;
use abi::contract::mount_flags;
use abi::fs::{
    Access, Conflict, DirEntry, DirPage, Entry, FileType, FsId, Handle, LockFamily, LockKind,
    LockRange, Metadata, NodeId, OpenOptions, OpenRef, RenameFlags, SetAttr, StatFs, Stop,
    Timespec, Walked, WriteAt, Written, XattrFlags,
};
use cowfs::{CowFs, CowFsConfig, CowFsOpenMode, CowFsVolumeDevice, cowfs_ioctl_mounted};
use cowtree::pack::{PACK_FOOTER_BYTES, decode_pack_footer, decode_pack_trailer_bytes};
use cowtree::{
    ArenaConfig, BlockLoc, CommitRequest, Digest, ForkRequest, GcLockGuard, GcRoot, HeadStore,
    PACK_MAX_BYTES, PackId, PackMeta, PackStore, PackTrailer, RoPinGuard, SnapshotRecord,
    VolumeHead, VolumeId, WriterLease, WriterLockGuard, WriterMode, digest_to_hex,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::rc::{Rc, Weak};
use vfs::devfs::{DefaultDeviceBackend, DevTmpFs};
use vfs::vblk::{VblkDeviceBackend, VblkRegistry};
use vfs::{
    BoxFuture, Cred, DefaultFilesystemFactory, Filesystem, FsType, MountBacking, MountFlags,
    StartAnchor, Vfs,
};
use wasm_bindgen::JsCast;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::closure::Closure;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen_futures::spawn_local;

/// Maximum integer exactly representable as an IEEE-754 `f64` (`2^53 - 1`).
const JS_MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

/// Validate a JS `f64` length/offset/cookie parameter before converting to `u64`.
/// Rejects negative values, `NaN`, infinities, non-integers, and values above `MAX_SAFE_INTEGER`
/// with `Errno::EINVAL` instead of silently truncating to `0`.
fn validate_js_u64(value: f64) -> vfs::Result<u64> {
    if !value.is_finite() || value < 0.0 || value.fract() != 0.0 || value > JS_MAX_SAFE_INTEGER {
        return Err(Errno::EINVAL);
    }
    Ok(value as u64)
}

fn cowfs_extract_js_errno(err: &JsValue) -> Errno {
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
        && name == "QuotaExceededError"
    {
        return Errno::ENOSPC;
    }
    extract_js_errno(err)
}

fn call_js_method(target: &JsValue, method: &str, args: &[JsValue]) -> vfs::Result<JsValue> {
    let func = js_sys::Reflect::get(target, &JsValue::from_str(method))
        .map_err(|e| cowfs_extract_js_errno(&e))?
        .dyn_into::<js_sys::Function>()
        .map_err(|_| Errno::EOPNOTSUPP)?;
    let arr = js_sys::Array::new();
    for a in args {
        arr.push(a);
    }
    func.apply(target, &arr)
        .map_err(|e| cowfs_extract_js_errno(&e))
}

async fn call_js_async(target: &JsValue, method: &str, args: &[JsValue]) -> vfs::Result<JsValue> {
    let val = call_js_method(target, method, args)?;
    if let Ok(promise) = val.clone().dyn_into::<js_sys::Promise>() {
        JsFuture::from(promise)
            .await
            .map_err(|e| cowfs_extract_js_errno(&e))
    } else {
        Ok(val)
    }
}

pub(crate) fn now_timespec() -> Timespec {
    #[cfg(target_arch = "wasm32")]
    {
        let ms = js_sys::Date::now();
        if !ms.is_finite() || ms <= 0.0 {
            return Timespec { sec: 0, nsec: 0 };
        }
        let whole_ms = ms.trunc() as u64;
        let sub_ns = ((ms.fract() * 1_000_000.0).round() as u64).min(999_999);
        let total_ns = whole_ms.saturating_mul(1_000_000).saturating_add(sub_ns);
        Timespec {
            sec: total_ns / 1_000_000_000,
            nsec: (total_ns % 1_000_000_000) as u32,
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| Timespec {
                sec: d.as_secs(),
                nsec: d.subsec_nanos(),
            })
            .unwrap_or(Timespec {
                sec: 1_700_000_000,
                nsec: 0,
            })
    }
}

pub(crate) fn to_js_json<T: Serialize>(value: &T) -> Result<JsValue, JsValue> {
    let s = serde_json::to_string(value).map_err(|_| js_errno(Errno::EIO, "serialize"))?;
    js_sys::JSON::parse(&s).map_err(|_| js_errno(Errno::EIO, "json parse"))
}

pub(crate) fn from_js_json<T: for<'de> Deserialize<'de>>(val: &JsValue) -> vfs::Result<T> {
    let s = js_sys::JSON::stringify(val)
        .map_err(|_| Errno::EIO)?
        .as_string()
        .ok_or(Errno::EIO)?;
    serde_json::from_str(&s).map_err(|_| Errno::EIO)
}

fn js_nodes_array(nodes: &[(Digest, Vec<u8>)]) -> JsValue {
    let arr = js_sys::Array::new();
    for (digest, bytes) in nodes {
        let obj = js_sys::Object::new();
        let _ = js_sys::Reflect::set(
            &obj,
            &JsValue::from_str("digest"),
            &JsValue::from_str(&digest_to_hex(digest)),
        );
        let u8arr = js_sys::Uint8Array::from(bytes.as_slice());
        let _ = js_sys::Reflect::set(&obj, &JsValue::from_str("bytes"), &u8arr);
        arr.push(&obj);
    }
    arr.into()
}

fn js_to_vec_u8(val: &JsValue) -> vfs::Result<Vec<u8>> {
    if let Ok(u8arr) = val.clone().dyn_into::<js_sys::Uint8Array>() {
        return Ok(u8arr.to_vec());
    }
    if let Ok(ab) = val.clone().dyn_into::<js_sys::ArrayBuffer>() {
        return Ok(js_sys::Uint8Array::new(&ab).to_vec());
    }
    Err(Errno::EIO)
}

// -----------------------------------------------------------------------------
// JS-backed HeadStore & PackStore
// -----------------------------------------------------------------------------

#[derive(Clone)]
pub(crate) struct JsCowfsStore {
    pub(crate) obj: JsValue,
}

struct JsWriterGuard {
    store: JsValue,
    lease_id: String,
    released: Rc<Cell<bool>>,
}

impl WriterLockGuard for JsWriterGuard {
    fn lease_id(&self) -> Option<&str> {
        Some(&self.lease_id)
    }
}

impl Drop for JsWriterGuard {
    fn drop(&mut self) {
        if !self.released.replace(true) {
            let _ = call_js_method(
                &self.store,
                "releaseWriter",
                &[JsValue::from_str(&self.lease_id)],
            );
        }
    }
}

struct JsGcGuard {
    store: JsValue,
    lock_id: String,
}

impl GcLockGuard for JsGcGuard {}

impl Drop for JsGcGuard {
    fn drop(&mut self) {
        let _ = call_js_method(
            &self.store,
            "releaseGcLock",
            &[JsValue::from_str(&self.lock_id)],
        );
    }
}

struct JsRoPinGuard {
    store: JsValue,
    pin_id: String,
    released: Rc<Cell<bool>>,
}

impl RoPinGuard for JsRoPinGuard {}

impl Drop for JsRoPinGuard {
    fn drop(&mut self) {
        if !self.released.replace(true) {
            let _ = call_js_method(
                &self.store,
                "unpinRoRootSync",
                &[JsValue::from_str(&self.pin_id)],
            );
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsLeaseWire {
    lease_id: String,
    volume: String,
    incarnation: u64,
    fence: u64,
    epoch: u64,
    head: VolumeHead,
    forked_from: Option<String>,
    expires_at: Option<Timespec>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JsRoPinWire {
    pin_id: String,
    head: VolumeHead,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsCommitMetaWire<'a> {
    op_id: String,
    volume: &'a str,
    expected_incarnation: u64,
    expected_fence: u64,
    expected_epoch: u64,
    new_root: String,
    put_packs: &'a [PackMeta],
    put_blocks: Vec<JsBlockEntryWire<'a>>,
    committed_at: Timespec,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsBlockEntryWire<'a> {
    digest: String,
    pack_id: &'a str,
    offset: u32,
    len: u32,
    raw_len: u32,
    flags: u16,
}

fn hex_16(bytes: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(32);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

impl HeadStore for JsCowfsStore {
    fn format_version(&self) -> BoxFuture<'_, Option<u32>> {
        Box::pin(async move {
            let val = call_js_async(&self.obj, "formatVersion", &[]).await?;
            if val.is_null() || val.is_undefined() {
                return Ok(None);
            }
            let num = val.as_f64().ok_or(Errno::EIO)?;
            if !num.is_finite() || num < 0.0 || num > f64::from(u32::MAX) {
                return Err(Errno::EIO);
            }
            Ok(Some(num as u32))
        })
    }

    fn grace_window_secs(&self) -> u64 {
        js_sys::Reflect::get(&self.obj, &JsValue::from_str("graceWindowSecs"))
            .ok()
            .and_then(|v| v.as_f64())
            .filter(|n| n.is_finite() && *n >= 0.0)
            .map_or(600, |n| n as u64)
    }

    fn create_volume<'a>(
        &'a self,
        head: &'a VolumeHead,
        initial_nodes: &'a [(Digest, Vec<u8>)],
    ) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async move {
            let head_json = serde_json::to_string(head).map_err(|_| Errno::EIO)?;
            let nodes = js_nodes_array(initial_nodes);
            let res = call_js_async(
                &self.obj,
                "createVolume",
                &[JsValue::from_str(&head_json), nodes],
            )
            .await?;
            from_js_json(&res)
        })
    }

    fn read_head<'a>(&'a self, volume: &'a VolumeId) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async move {
            let res = call_js_async(&self.obj, "readHead", &[JsValue::from_str(&volume.0)]).await?;
            from_js_json(&res)
        })
    }

    fn pin_ro_root<'a>(
        &'a self,
        volume: &'a VolumeId,
        snapshot: Option<&'a str>,
    ) -> BoxFuture<'a, (VolumeHead, Box<dyn RoPinGuard>)> {
        Box::pin(async move {
            let snap_js = match snapshot {
                Some(s) => JsValue::from_str(s),
                None => JsValue::NULL,
            };
            let res = call_js_async(
                &self.obj,
                "pinRoRoot",
                &[JsValue::from_str(&volume.0), snap_js],
            )
            .await?;
            let wire: JsRoPinWire = from_js_json(&res)?;
            Ok((
                wire.head,
                Box::new(JsRoPinGuard {
                    store: self.obj.clone(),
                    pin_id: wire.pin_id,
                    released: Rc::new(Cell::new(false)),
                }) as Box<dyn RoPinGuard>,
            ))
        })
    }

    fn unpin_ro_root<'a>(&'a self, pin: Box<dyn RoPinGuard>) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            drop(pin);
            let _ = call_js_async(&self.obj, "flushLocks", &[]).await;
            Ok(())
        })
    }

    fn acquire_writer<'a>(
        &'a self,
        volume: &'a VolumeId,
        mode: WriterMode,
    ) -> BoxFuture<'a, WriterLease> {
        Box::pin(async move {
            let mode_str = match mode {
                WriterMode::Exclusive => "exclusive",
                WriterMode::ForkOnBusy => "fork-on-busy",
                WriterMode::ForceTakeover => "force-takeover",
            };
            let res = call_js_async(
                &self.obj,
                "acquireWriter",
                &[JsValue::from_str(&volume.0), JsValue::from_str(mode_str)],
            )
            .await?;
            let wire: JsLeaseWire = from_js_json(&res)?;
            let released = Rc::new(Cell::new(false));
            Ok(WriterLease {
                volume: VolumeId(wire.volume),
                incarnation: wire.incarnation,
                fence: wire.fence,
                epoch: wire.epoch,
                head: wire.head,
                forked_from: wire.forked_from.map(VolumeId),
                expires_at: wire.expires_at,
                guard: Box::new(JsWriterGuard {
                    store: self.obj.clone(),
                    lease_id: wire.lease_id,
                    released,
                }),
            })
        })
    }

    fn renew_writer<'a>(&'a self, lease: &'a mut WriterLease) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let payload = serde_json::to_string(&json!({
                "volume": lease.volume.0,
                "incarnation": lease.incarnation,
                "fence": lease.fence,
            }))
            .map_err(|_| Errno::EIO)?;
            let _ = call_js_async(&self.obj, "renewWriter", &[JsValue::from_str(&payload)]).await?;
            Ok(())
        })
    }

    fn release_writer<'a>(&'a self, lease: WriterLease) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            // Dropping the lease fires `JsWriterGuard::drop`, which triggers JS lock release;
            // yield one microtask so the Web Lock callback resolves cleanly.
            drop(lease);
            let _ = call_js_async(&self.obj, "flushLocks", &[]).await;
            Ok(())
        })
    }

    fn get_node<'a>(&'a self, digest: &'a Digest) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let hex = digest_to_hex(digest);
            let res = call_js_async(&self.obj, "getNode", &[JsValue::from_str(&hex)]).await?;
            js_to_vec_u8(&res)
        })
    }

    fn lookup_block<'a>(&'a self, digest: &'a Digest) -> BoxFuture<'a, Option<BlockLoc>> {
        Box::pin(async move {
            let hex = digest_to_hex(digest);
            let res = call_js_async(&self.obj, "lookupBlock", &[JsValue::from_str(&hex)]).await?;
            if res.is_null() || res.is_undefined() {
                return Ok(None);
            }
            from_js_json(&res).map(Some)
        })
    }

    fn commit_head<'a>(&'a self, req: &'a CommitRequest) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async move {
            let meta = JsCommitMetaWire {
                op_id: hex_16(&req.op_id),
                volume: &req.volume.0,
                expected_incarnation: req.expected_incarnation,
                expected_fence: req.expected_fence,
                expected_epoch: req.expected_epoch,
                new_root: digest_to_hex(&req.new_root),
                put_packs: &req.put_packs,
                put_blocks: req
                    .put_blocks
                    .iter()
                    .map(|(d, loc)| JsBlockEntryWire {
                        digest: digest_to_hex(d),
                        pack_id: &loc.pack_id.0,
                        offset: loc.offset,
                        len: loc.len,
                        raw_len: loc.raw_len,
                        flags: loc.flags,
                    })
                    .collect(),
                committed_at: req.committed_at,
            };
            let meta_json = serde_json::to_string(&meta).map_err(|_| Errno::EIO)?;
            let nodes = js_nodes_array(&req.put_nodes);
            let res = call_js_async(
                &self.obj,
                "commitHead",
                &[JsValue::from_str(&meta_json), nodes],
            )
            .await?;
            from_js_json(&res)
        })
    }

    fn create_snapshot<'a>(
        &'a self,
        volume: &'a VolumeId,
        name: &'a str,
        head: &'a VolumeHead,
        now: Timespec,
    ) -> BoxFuture<'a, SnapshotRecord> {
        Box::pin(async move {
            let payload = serde_json::to_string(&json!({
                "volume": volume.0,
                "name": name,
                "head": head,
                "now": now,
            }))
            .map_err(|_| Errno::EIO)?;
            let res =
                call_js_async(&self.obj, "createSnapshot", &[JsValue::from_str(&payload)]).await?;
            from_js_json(&res)
        })
    }

    fn get_snapshot<'a>(
        &'a self,
        volume: &'a VolumeId,
        name: &'a str,
    ) -> BoxFuture<'a, SnapshotRecord> {
        Box::pin(async move {
            let res = call_js_async(
                &self.obj,
                "getSnapshot",
                &[JsValue::from_str(&volume.0), JsValue::from_str(name)],
            )
            .await?;
            from_js_json(&res)
        })
    }

    fn list_snapshots<'a>(&'a self, volume: &'a VolumeId) -> BoxFuture<'a, Vec<SnapshotRecord>> {
        Box::pin(async move {
            let res =
                call_js_async(&self.obj, "listSnapshots", &[JsValue::from_str(&volume.0)]).await?;
            from_js_json(&res)
        })
    }

    fn delete_snapshot<'a>(&'a self, volume: &'a VolumeId, name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let _ = call_js_async(
                &self.obj,
                "deleteSnapshot",
                &[JsValue::from_str(&volume.0), JsValue::from_str(name)],
            )
            .await?;
            Ok(())
        })
    }

    fn fork_volume<'a>(&'a self, req: &'a ForkRequest) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async move {
            let payload = serde_json::to_string(req).map_err(|_| Errno::EIO)?;
            let res =
                call_js_async(&self.obj, "forkVolume", &[JsValue::from_str(&payload)]).await?;
            from_js_json(&res)
        })
    }

    fn delete_volume<'a>(&'a self, volume: &'a VolumeId) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let _ =
                call_js_async(&self.obj, "deleteVolume", &[JsValue::from_str(&volume.0)]).await?;
            Ok(())
        })
    }

    fn delete_volume_with_lease<'a>(
        &'a self,
        lease: WriterLease,
        only_if_unmodified_ephemeral: bool,
    ) -> BoxFuture<'a, bool> {
        Box::pin(async move {
            let lease_id = lease.guard.lease_id().ok_or(Errno::EIO)?.to_string();
            let res = call_js_async(
                &self.obj,
                "deleteVolumeWithLease",
                &[
                    JsValue::from_str(&lease_id),
                    JsValue::from_str(&lease.volume.0),
                    JsValue::from_f64(lease.incarnation as f64),
                    JsValue::from_f64(lease.fence as f64),
                    JsValue::from_f64(lease.epoch as f64),
                    JsValue::from_bool(only_if_unmodified_ephemeral),
                ],
            )
            .await;
            drop(lease);
            res.map(|v| v.as_bool().unwrap_or(false))
        })
    }

    fn reformat_volume_with_lease<'a>(
        &'a self,
        lease: WriterLease,
        new_head: &'a VolumeHead,
        initial_nodes: &'a [(Digest, Vec<u8>)],
    ) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async move {
            let lease_id = lease.guard.lease_id().ok_or(Errno::EIO)?.to_string();
            let head_json = serde_json::to_string(new_head).map_err(|_| Errno::EIO)?;
            let nodes = js_nodes_array(initial_nodes);
            let res = call_js_async(
                &self.obj,
                "reformatVolumeWithLease",
                &[
                    JsValue::from_str(&lease_id),
                    JsValue::from_str(&lease.volume.0),
                    JsValue::from_f64(lease.incarnation as f64),
                    JsValue::from_f64(lease.fence as f64),
                    JsValue::from_f64(lease.epoch as f64),
                    JsValue::from_str(&head_json),
                    nodes,
                ],
            )
            .await;
            drop(lease);
            let val = res?;
            from_js_json(&val)
        })
    }

    fn acquire_gc_lock(&self, exclusive: bool) -> BoxFuture<'_, Box<dyn GcLockGuard>> {
        Box::pin(async move {
            let res =
                call_js_async(&self.obj, "acquireGcLock", &[JsValue::from_bool(exclusive)]).await?;
            let lock_id = res.as_string().ok_or(Errno::EIO)?;
            Ok(Box::new(JsGcGuard {
                store: self.obj.clone(),
                lock_id,
            }) as Box<dyn GcLockGuard>)
        })
    }

    fn list_all_roots(&self) -> BoxFuture<'_, Vec<GcRoot>> {
        Box::pin(async move {
            let res = call_js_async(&self.obj, "listAllRoots", &[]).await?;
            from_js_json(&res)
        })
    }

    fn list_indexed_packs(&self) -> BoxFuture<'_, HashSet<PackId>> {
        Box::pin(async move {
            let res = call_js_async(&self.obj, "listIndexedPacks", &[]).await?;
            let ids: Vec<String> = from_js_json(&res)?;
            Ok(ids.into_iter().map(PackId).collect())
        })
    }

    fn prune_abandoned_ephemeral_forks(
        &self,
        now: Timespec,
        grace_window_secs: u64,
    ) -> BoxFuture<'_, usize> {
        Box::pin(async move {
            let now_json = serde_json::to_string(&now).map_err(|_| Errno::EIO)?;
            let res = call_js_async(
                &self.obj,
                "pruneAbandonedEphemeralForks",
                &[
                    JsValue::from_str(&now_json),
                    JsValue::from_f64(grace_window_secs as f64),
                ],
            )
            .await?;
            Ok(res.as_f64().unwrap_or(0.0).max(0.0) as usize)
        })
    }

    fn sweep_metadata<'a>(
        &'a self,
        keep_nodes: &'a HashSet<Digest>,
        keep_packs: &'a HashSet<PackId>,
        now: Timespec,
        grace_window_secs: u64,
    ) -> BoxFuture<'a, Vec<PackId>> {
        Box::pin(async move {
            let keep_nodes_hex: Vec<String> = keep_nodes.iter().map(digest_to_hex).collect();
            let keep_packs_str: Vec<&str> = keep_packs.iter().map(|p| p.0.as_str()).collect();
            let payload = serde_json::to_string(&json!({
                "keepNodes": keep_nodes_hex,
                "keepPacks": keep_packs_str,
                "now": now,
                "graceWindowSecs": grace_window_secs,
            }))
            .map_err(|_| Errno::EIO)?;
            let res =
                call_js_async(&self.obj, "sweepMetadata", &[JsValue::from_str(&payload)]).await?;
            let ids: Vec<String> = from_js_json(&res)?;
            Ok(ids.into_iter().map(PackId).collect())
        })
    }
}

impl PackStore for JsCowfsStore {
    fn write_pack<'a>(&'a self, pack_id: &'a PackId, bytes: &'a [u8]) -> BoxFuture<'a, PackMeta> {
        Box::pin(async move {
            let u8arr = js_sys::Uint8Array::from(bytes);
            let res = call_js_async(
                &self.obj,
                "writePack",
                &[JsValue::from_str(&pack_id.0), u8arr.into()],
            )
            .await?;
            from_js_json(&res)
        })
    }

    fn read_pack_range<'a>(
        &'a self,
        pack_id: &'a PackId,
        offset: u32,
        len: u32,
    ) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let res = call_js_async(
                &self.obj,
                "readPackRange",
                &[
                    JsValue::from_str(&pack_id.0),
                    JsValue::from_f64(f64::from(offset)),
                    JsValue::from_f64(f64::from(len)),
                ],
            )
            .await?;
            js_to_vec_u8(&res)
        })
    }

    fn read_pack_trailer<'a>(&'a self, pack_id: &'a PackId) -> BoxFuture<'a, PackTrailer> {
        Box::pin(async move {
            let size = self.stat_pack(pack_id).await?.ok_or(Errno::ENOENT)?;
            if size < PACK_FOOTER_BYTES as u64 || size > PACK_MAX_BYTES as u64 {
                return Err(Errno::EIO);
            }
            let footer_off = (size - PACK_FOOTER_BYTES as u64) as u32;
            let footer = self
                .read_pack_range(pack_id, footer_off, PACK_FOOTER_BYTES as u32)
                .await?;
            let (trailer_len, trailer_sha) = decode_pack_footer(&footer)?;
            let trailer_off = footer_off.checked_sub(trailer_len).ok_or(Errno::EIO)?;
            let trailer_bytes = self
                .read_pack_range(pack_id, trailer_off, trailer_len)
                .await?;
            decode_pack_trailer_bytes(&trailer_bytes, trailer_sha, trailer_off)
        })
    }

    fn stat_pack<'a>(&'a self, pack_id: &'a PackId) -> BoxFuture<'a, Option<u64>> {
        Box::pin(async move {
            let res =
                call_js_async(&self.obj, "statPack", &[JsValue::from_str(&pack_id.0)]).await?;
            if res.is_null() || res.is_undefined() {
                return Ok(None);
            }
            let num = res.as_f64().ok_or(Errno::EIO)?;
            if !num.is_finite() || num < 0.0 {
                return Err(Errno::EIO);
            }
            Ok(Some(num as u64))
        })
    }

    fn list_packs(&self) -> BoxFuture<'_, Vec<PackId>> {
        Box::pin(async move {
            let res = call_js_async(&self.obj, "listPacks", &[]).await?;
            let ids: Vec<String> = from_js_json(&res)?;
            Ok(ids.into_iter().map(PackId).collect())
        })
    }

    fn delete_pack<'a>(&'a self, pack_id: &'a PackId) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let _ =
                call_js_async(&self.obj, "deletePack", &[JsValue::from_str(&pack_id.0)]).await?;
            Ok(())
        })
    }
}

// -----------------------------------------------------------------------------
// Virtual `/dev` mountpoint wrapper so `/dev/vd0` is ALWAYS mounted and reachable
// on RW, RO, Snapshot, and unmodified ForkOnBusy mounts without mutating the volume.
// -----------------------------------------------------------------------------

const VIRTUAL_DEV_INO: u64 = u64::MAX - 1;
const VIRTUAL_DEV_GEN: u64 = 1;

struct BridgeRootFs {
    inner: Rc<CowFs<JsCowfsStore, JsCowfsStore>>,
}

impl BridgeRootFs {
    fn virtual_dev_handle(&self) -> Handle {
        Handle {
            fs: self.inner.id().clone(),
            node: NodeId {
                ino: VIRTUAL_DEV_INO,
                generation: VIRTUAL_DEV_GEN,
            },
            proof: String::new(),
        }
    }

    fn virtual_dev_meta(&self) -> Metadata {
        Metadata {
            file_type: FileType::Dir,
            mode: 0o755,
            nlink: 2,
            uid: 0,
            gid: 0,
            size: 0,
            atime: Timespec { sec: 0, nsec: 0 },
            mtime: Timespec { sec: 0, nsec: 0 },
            ctime: Timespec { sec: 0, nsec: 0 },
            rdev: None,
            acl: false,
        }
    }

    fn virtual_dev_entry(&self) -> Entry {
        Entry {
            handle: self.virtual_dev_handle(),
            metadata: self.virtual_dev_meta(),
        }
    }

    fn is_virtual_dev(handle: &Handle) -> bool {
        handle.node.ino == VIRTUAL_DEV_INO && handle.node.generation == VIRTUAL_DEV_GEN
    }
}

impl Filesystem for BridgeRootFs {
    fn id(&self) -> &FsId {
        self.inner.id()
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
    ) -> BoxFuture<'a, Entry> {
        Box::pin(async move {
            if Self::is_virtual_dev(dir) {
                return Err(Errno::ENOENT);
            }
            if dir.node == self.inner.root().node && name == "dev" {
                match self.inner.lookup(cred, dir, name).await {
                    Ok(e) => return Ok(e),
                    Err(Errno::ENOENT) => return Ok(self.virtual_dev_entry()),
                    Err(e) => return Err(e),
                }
            }
            self.inner.lookup(cred, dir, name).await
        })
    }

    fn walk<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        names: &'a [String],
    ) -> BoxFuture<'a, Walked> {
        Box::pin(async move {
            if Self::is_virtual_dev(dir) {
                return Ok(Walked {
                    entries: Vec::new(),
                    stop: if names.is_empty() {
                        None
                    } else {
                        Some(Stop::Missing(0))
                    },
                });
            }
            if dir.node == self.inner.root().node
                && let Some(first) = names.first()
                && first == "dev"
            {
                match self.inner.lookup(cred, dir, "dev").await {
                    Ok(_) => return self.inner.walk(cred, dir, names).await,
                    Err(Errno::ENOENT) => {
                        return Ok(Walked {
                            entries: vec![self.virtual_dev_entry()],
                            stop: if names.len() > 1 {
                                Some(Stop::Missing(1))
                            } else {
                                None
                            },
                        });
                    }
                    Err(e) => return Err(e),
                }
            }
            self.inner.walk(cred, dir, names).await
        })
    }

    fn parent<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
    ) -> BoxFuture<'a, Option<(Entry, String)>> {
        Box::pin(async move {
            if Self::is_virtual_dev(dir) {
                let root_h = self.inner.root();
                let root_meta = self.inner.metadata(cred, &root_h).await?;
                return Ok(Some((
                    Entry {
                        handle: root_h,
                        metadata: root_meta,
                    },
                    "dev".to_string(),
                )));
            }
            self.inner.parent(cred, dir).await
        })
    }

    fn metadata<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Metadata> {
        Box::pin(async move {
            if Self::is_virtual_dev(handle) {
                return Ok(self.virtual_dev_meta());
            }
            self.inner.metadata(cred, handle).await
        })
    }

    fn setattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        attr: &'a SetAttr,
    ) -> BoxFuture<'a, Metadata> {
        if Self::is_virtual_dev(handle) {
            return Box::pin(async { Err(Errno::EROFS) });
        }
        self.inner.setattr(cred, handle, attr)
    }

    fn read_dir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle) -> BoxFuture<'a, Vec<DirEntry>> {
        if Self::is_virtual_dev(dir) {
            return Box::pin(async { Ok(Vec::new()) });
        }
        self.inner.read_dir(cred, dir)
    }

    fn read_dir_page<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        cookie: u64,
        max_entries: usize,
    ) -> BoxFuture<'a, DirPage> {
        if Self::is_virtual_dev(dir) {
            return Box::pin(async {
                Ok(DirPage {
                    entries: Vec::new(),
                    next_cookie: None,
                })
            });
        }
        self.inner.read_dir_page(cred, dir, cookie, max_entries)
    }

    fn read_link<'a>(&'a self, cred: &'a Cred, link: &'a Handle) -> BoxFuture<'a, String> {
        self.inner.read_link(cred, link)
    }

    fn create<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
        options: &'a OpenOptions,
    ) -> BoxFuture<'a, (Entry, OpenRef)> {
        if Self::is_virtual_dev(dir) {
            return Box::pin(async { Err(Errno::EROFS) });
        }
        self.inner.create(cred, dir, name, mode, options)
    }

    fn mkdir<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
    ) -> BoxFuture<'a, Entry> {
        if Self::is_virtual_dev(dir) {
            return Box::pin(async { Err(Errno::EROFS) });
        }
        self.inner.mkdir(cred, dir, name, mode)
    }

    fn mknod<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        mode: u16,
        rdev: &'a str,
    ) -> BoxFuture<'a, Entry> {
        if Self::is_virtual_dev(dir) {
            return Box::pin(async { Err(Errno::EROFS) });
        }
        self.inner.mknod(cred, dir, name, mode, rdev)
    }

    fn symlink<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        target: &'a str,
    ) -> BoxFuture<'a, Entry> {
        if Self::is_virtual_dev(dir) {
            return Box::pin(async { Err(Errno::EROFS) });
        }
        self.inner.symlink(cred, dir, name, target)
    }

    fn link<'a>(
        &'a self,
        cred: &'a Cred,
        target: &'a Handle,
        dir: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Entry> {
        if Self::is_virtual_dev(dir) {
            return Box::pin(async { Err(Errno::EROFS) });
        }
        self.inner.link(cred, target, dir, name)
    }

    fn unlink<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()> {
        if Self::is_virtual_dev(dir) {
            return Box::pin(async { Err(Errno::EROFS) });
        }
        self.inner.unlink(cred, dir, name)
    }

    fn unlink_if<'a>(
        &'a self,
        cred: &'a Cred,
        dir: &'a Handle,
        name: &'a str,
        node: NodeId,
    ) -> BoxFuture<'a, ()> {
        if Self::is_virtual_dev(dir) {
            return Box::pin(async { Err(Errno::EROFS) });
        }
        self.inner.unlink_if(cred, dir, name, node)
    }

    fn rmdir<'a>(&'a self, cred: &'a Cred, dir: &'a Handle, name: &'a str) -> BoxFuture<'a, ()> {
        if Self::is_virtual_dev(dir) {
            return Box::pin(async { Err(Errno::EROFS) });
        }
        self.inner.rmdir(cred, dir, name)
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
        if Self::is_virtual_dev(from_dir) || Self::is_virtual_dev(to_dir) {
            return Box::pin(async { Err(Errno::EROFS) });
        }
        self.inner.rename(cred, from_dir, from, to_dir, to, flags)
    }

    fn getxattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, Vec<u8>> {
        if Self::is_virtual_dev(handle) {
            return Box::pin(async { Err(Errno::ENODATA) });
        }
        self.inner.getxattr(cred, handle, name)
    }

    fn setxattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
        value: &'a [u8],
        flags: XattrFlags,
    ) -> BoxFuture<'a, ()> {
        if Self::is_virtual_dev(handle) {
            return Box::pin(async { Err(Errno::EROFS) });
        }
        self.inner.setxattr(cred, handle, name, value, flags)
    }

    fn listxattr<'a>(&'a self, cred: &'a Cred, handle: &'a Handle) -> BoxFuture<'a, Vec<String>> {
        if Self::is_virtual_dev(handle) {
            return Box::pin(async { Ok(Vec::new()) });
        }
        self.inner.listxattr(cred, handle)
    }

    fn removexattr<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        name: &'a str,
    ) -> BoxFuture<'a, ()> {
        if Self::is_virtual_dev(handle) {
            return Box::pin(async { Err(Errno::EROFS) });
        }
        self.inner.removexattr(cred, handle, name)
    }

    fn statfs<'a>(&'a self, cred: &'a Cred) -> BoxFuture<'a, StatFs> {
        self.inner.statfs(cred)
    }

    fn open<'a>(
        &'a self,
        cred: &'a Cred,
        handle: &'a Handle,
        options: &'a OpenOptions,
    ) -> BoxFuture<'a, OpenRef> {
        if Self::is_virtual_dev(handle) {
            return Box::pin(async move {
                let access = options.access()?;
                if access == Access::Path {
                    return Ok(OpenRef {
                        fs: self.inner.id().clone(),
                        id: u64::MAX - 1,
                        node: handle.node,
                        access,
                    });
                }
                Err(Errno::EISDIR)
            });
        }
        self.inner.open(cred, handle, options)
    }

    fn open_metadata<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, Metadata> {
        if open.node.ino == VIRTUAL_DEV_INO {
            let meta = self.virtual_dev_meta();
            return Box::pin(async move { Ok(meta) });
        }
        self.inner.open_metadata(open)
    }

    fn read_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a mut [u8],
        offset: u64,
    ) -> BoxFuture<'a, usize> {
        self.inner.read_at(open, buf, offset)
    }

    fn write_at<'a>(
        &'a self,
        open: &'a OpenRef,
        buf: &'a [u8],
        at: WriteAt,
    ) -> BoxFuture<'a, Written> {
        self.inner.write_at(open, buf, at)
    }

    fn set_len<'a>(&'a self, open: &'a OpenRef, size: u64) -> BoxFuture<'a, ()> {
        self.inner.set_len(open, size)
    }

    fn sync_all<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        self.inner.sync_all(open)
    }

    fn sync_fs<'a>(&'a self, cred: &'a Cred) -> BoxFuture<'a, ()> {
        self.inner.sync_fs(cred)
    }

    fn reflink<'a>(
        &'a self,
        cred: &'a Cred,
        src_open: &'a OpenRef,
        dst_open: &'a OpenRef,
    ) -> BoxFuture<'a, ()> {
        self.inner.reflink(cred, src_open, dst_open)
    }

    fn lock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        self.inner.lock(open, family, kind, range)
    }

    fn try_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        self.inner.try_lock(open, family, kind, range)
    }

    fn unlock<'a>(
        &'a self,
        open: &'a OpenRef,
        family: LockFamily,
        range: LockRange,
    ) -> BoxFuture<'a, ()> {
        self.inner.unlock(open, family, range)
    }

    fn test_lock<'a>(
        &'a self,
        open: &'a OpenRef,
        kind: LockKind,
        range: LockRange,
    ) -> BoxFuture<'a, Option<Conflict>> {
        self.inner.test_lock(open, kind, range)
    }

    fn release<'a>(&'a self, open: &'a OpenRef) -> BoxFuture<'a, ()> {
        if open.node.ino == VIRTUAL_DEV_INO {
            return Box::pin(async { Ok(()) });
        }
        self.inner.release(open)
    }
}

// -----------------------------------------------------------------------------
// 5-second dirty commit deadline timer (`contract.md` §2.15)
// -----------------------------------------------------------------------------

#[cfg(target_arch = "wasm32")]
const DIRTY_RETRY_INITIAL_MS: u64 = 1_000;
#[cfg(target_arch = "wasm32")]
const DIRTY_RETRY_MAX_MS: u64 = 30_000;

#[derive(Default)]
struct DirtyFlushTimer {
    #[cfg(target_arch = "wasm32")]
    handle: Option<JsValue>,
    #[cfg(target_arch = "wasm32")]
    closure: Option<Closure<dyn FnMut()>>,
    canceled: bool,
    #[cfg(target_arch = "wasm32")]
    consecutive_errors: u32,
    #[cfg(not(target_arch = "wasm32"))]
    armed_count: u64,
}

#[cfg(target_arch = "wasm32")]
fn clear_js_timeout(handle: &JsValue) {
    let global = js_sys::global();
    if let Ok(func) = js_sys::Reflect::get(&global, &JsValue::from_str("clearTimeout"))
        && let Ok(f) = func.dyn_into::<js_sys::Function>()
    {
        let _ = f.call1(&global, handle);
    }
}

#[cfg(target_arch = "wasm32")]
fn schedule_js_timeout(cb: &Closure<dyn FnMut()>, delay_ms: u64) -> Option<JsValue> {
    let global = js_sys::global();
    let func = js_sys::Reflect::get(&global, &JsValue::from_str("setTimeout"))
        .ok()?
        .dyn_into::<js_sys::Function>()
        .ok()?;
    let handle = func
        .call2(
            &global,
            cb.as_ref().unchecked_ref(),
            &JsValue::from_f64(delay_ms as f64),
        )
        .ok()?;
    // In Node.js tests, unref() would let process exit, while real handles still fire normally;
    // we also explicitly `clearTimeout` in `close_clean` and `Drop`.
    Some(handle)
}

#[cfg(target_arch = "wasm32")]
fn arm_dirty_timer_with_delay<H: HeadStore + 'static, P: PackStore + 'static>(
    fs: &Rc<CowFs<H, P>>,
    timer: &Rc<RefCell<DirtyFlushTimer>>,
    min_delay_ms: u64,
) {
    let mut t = timer.borrow_mut();
    if t.canceled || t.handle.is_some() {
        return;
    }
    let Some(delay_ms) = fs.ms_until_dirty_deadline() else {
        return;
    };
    let fs_c = Rc::clone(fs);
    let timer_c = Rc::clone(timer);
    let cb = Closure::once(move || {
        {
            let mut st = timer_c.borrow_mut();
            st.handle = None;
            if st.canceled {
                return;
            }
        }
        spawn_local(async move {
            // Drop the fired closure after the JS trampoline has unwound.
            let _old_closure = timer_c.borrow_mut().closure.take();
            if timer_c.borrow().canceled || fs_c.is_closed() {
                return;
            }
            match fs_c.flush_if_dirty_deadline_elapsed().await {
                Ok(_) => {
                    timer_c.borrow_mut().consecutive_errors = 0;
                    // Re-arm if still dirty (e.g., newly arrived writes while committing).
                    if !timer_c.borrow().canceled && !fs_c.is_closed() {
                        arm_dirty_timer_with_delay(&fs_c, &timer_c, 10);
                    }
                }
                Err(Errno::ESTALE | Errno::EBADF | Errno::EROFS) => {
                    // Terminal mount state (fenced/closed/RO) — stop retrying.
                }
                Err(_) => {
                    // Transient flush error (e.g., `ENOSPC`, `EIO`): retry with bounded backoff
                    // while the filesystem remains open and uncanceled.
                    let err_count = {
                        let mut st = timer_c.borrow_mut();
                        st.consecutive_errors = st.consecutive_errors.saturating_add(1);
                        st.consecutive_errors
                    };
                    let shift = err_count.saturating_sub(1).min(5);
                    let backoff_ms = DIRTY_RETRY_INITIAL_MS
                        .saturating_mul(1u64 << shift)
                        .min(DIRTY_RETRY_MAX_MS);
                    if !timer_c.borrow().canceled && !fs_c.is_closed() {
                        arm_dirty_timer_with_delay(&fs_c, &timer_c, backoff_ms);
                    }
                }
            }
        });
    });
    if let Some(handle) = schedule_js_timeout(&cb, delay_ms.max(min_delay_ms)) {
        t.handle = Some(handle);
        t.closure = Some(cb);
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn arm_dirty_timer_with_delay<H: HeadStore + 'static, P: PackStore + 'static>(
    fs: &Rc<CowFs<H, P>>,
    timer: &Rc<RefCell<DirtyFlushTimer>>,
    _min_delay_ms: u64,
) {
    let mut t = timer.borrow_mut();
    if t.canceled {
        return;
    }
    if fs.ms_until_dirty_deadline().is_some() {
        t.armed_count = t.armed_count.saturating_add(1);
    }
}

fn arm_dirty_timer<H: HeadStore + 'static, P: PackStore + 'static>(
    fs: &Rc<CowFs<H, P>>,
    timer: &Rc<RefCell<DirtyFlushTimer>>,
) {
    arm_dirty_timer_with_delay(fs, timer, 10);
}

fn cancel_dirty_timer(timer: &Rc<RefCell<DirtyFlushTimer>>) {
    let mut t = timer.borrow_mut();
    t.canceled = true;
    #[cfg(target_arch = "wasm32")]
    {
        if let Some(h) = t.handle.take() {
            clear_js_timeout(&h);
        }
        t.closure = None;
    }
}

/// RAII guard for a mounted `CowFs` 5-second dirty commit deadline timer; cancels on `Drop` or
/// explicit [`Self::cancel`].
pub(crate) struct DirtyFlushGuard {
    timer: Rc<RefCell<DirtyFlushTimer>>,
}

impl DirtyFlushGuard {
    pub(crate) fn cancel(&self) {
        cancel_dirty_timer(&self.timer);
    }

    #[allow(dead_code)]
    pub(crate) fn arm<H: HeadStore + 'static, P: PackStore + 'static>(&self, fs: &Rc<CowFs<H, P>>) {
        arm_dirty_timer(fs, &self.timer);
    }

    #[cfg(all(test, not(target_arch = "wasm32")))]
    pub(crate) fn armed_count(&self) -> u64 {
        self.timer.borrow().armed_count
    }
}

impl Drop for DirtyFlushGuard {
    fn drop(&mut self) {
        cancel_dirty_timer(&self.timer);
    }
}

type WeakCowFsSlot<H, P> = Rc<RefCell<Option<Weak<CowFs<H, P>>>>>;

/// Pre-open timer binder returned by [`bind_dirty_flush_timer`]; call [`Self::attach`] right after
/// `CowFs::open` succeeds so every clean->dirty transition arms the 5-second flush timer without
/// creating an `Rc` reference cycle.
pub(crate) struct DirtyFlushBinder<H: HeadStore + 'static, P: PackStore + 'static> {
    timer: Rc<RefCell<DirtyFlushTimer>>,
    fs_slot: WeakCowFsSlot<H, P>,
}

impl<H: HeadStore + 'static, P: PackStore + 'static> DirtyFlushBinder<H, P> {
    pub(crate) fn attach(self, fs: &Rc<CowFs<H, P>>) -> DirtyFlushGuard {
        *self.fs_slot.borrow_mut() = Some(Rc::downgrade(fs));
        arm_dirty_timer(fs, &self.timer);
        DirtyFlushGuard { timer: self.timer }
    }
}

/// Attach an `on_dirty` callback to `config` that arms the 5-second dirty flush timer on every
/// clean->dirty transition (and retries transient flush failures with bounded backoff while open).
/// Call `binder.attach(&fs)` once `CowFs::open` completes to activate it and obtain a
/// [`DirtyFlushGuard`].
pub(crate) fn bind_dirty_flush_timer<H: HeadStore + 'static, P: PackStore + 'static>(
    config: CowFsConfig,
) -> (CowFsConfig, DirtyFlushBinder<H, P>) {
    let timer = Rc::new(RefCell::new(DirtyFlushTimer::default()));
    let fs_slot: WeakCowFsSlot<H, P> = Rc::new(RefCell::new(None));
    let timer_cb = Rc::clone(&timer);
    let slot_cb = Rc::clone(&fs_slot);
    let config = config.with_on_dirty(Rc::new(move || {
        let fs_opt = slot_cb.borrow().as_ref().and_then(Weak::upgrade);
        if let Some(fs) = fs_opt {
            arm_dirty_timer(&fs, &timer_cb);
        }
    }));
    (config, DirtyFlushBinder { timer, fs_slot })
}

/// Attach a dirty-flush timer directly to an already-open [`CowFs`] (arms immediately if dirty;
/// prefer [`bind_dirty_flush_timer`] prior to `CowFs::open` so future clean->dirty transitions arm
/// automatically).
#[allow(dead_code)]
pub(crate) fn attach_dirty_flush_timer<H: HeadStore + 'static, P: PackStore + 'static>(
    fs: &Rc<CowFs<H, P>>,
) -> DirtyFlushGuard {
    let timer = Rc::new(RefCell::new(DirtyFlushTimer::default()));
    arm_dirty_timer(fs, &timer);
    DirtyFlushGuard { timer }
}

// -----------------------------------------------------------------------------
// Exported `wasm-bindgen` CowFs volume handle & helpers
// -----------------------------------------------------------------------------

fn parse_writer_mode(mode: &str) -> vfs::Result<WriterMode> {
    match mode {
        "exclusive" => Ok(WriterMode::Exclusive),
        "fork-on-busy" => Ok(WriterMode::ForkOnBusy),
        "force-takeover" => Ok(WriterMode::ForceTakeover),
        _ => Err(Errno::EINVAL),
    }
}

/// Result of a clean `os-cowfs` unmount/shutdown with automatic unmodified-fork pruning.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloseCleanPruneOutcome {
    pub volume_uuid: String,
    pub forked_from: Option<String>,
    pub base_epoch: u64,
    pub final_epoch: u64,
    pub pruned: bool,
    pub retained: bool,
}

/// Result of `open_for_boot`: either a newly created & atomically seeded root volume (epoch 1)
/// or a verified existing volume / O(1) `ForkOnBusy` fork.
pub struct BootOpenResult<H: HeadStore + 'static, P: PackStore + 'static> {
    pub fs: Rc<CowFs<H, P>>,
    pub volume_uuid: String,
    pub forked_from: Option<String>,
    pub base_epoch: u64,
    pub ephemeral_if_unmodified: bool,
    pub first_boot_seeded: bool,
    pub fsck_report: Option<cowfs::FsckReport>,
}

/// Atomically seed every directory, regular file, and symlink from a verified `Kind::RootTemplate`
/// image into `fs`, setting exact `uid`/`gid`/`mode` (`shadow` `0600`, `sudoers` `0440`,
/// `/home/user` `0750`, `/root` `0700`) and committing epoch 1 in a single transaction group.
///
/// Also ensures merged-`/usr` compatibility symlinks (`/bin -> usr/bin`, `/sbin -> usr/bin`,
/// `/lib -> usr/lib`, `/lib64 -> usr/lib`) and `/mnt/cloud` exist on the newly provisioned root.
pub async fn seed_root_template_fs<
    H: HeadStore + 'static,
    P: PackStore + 'static,
    B: vfs::imagefs::BlobStore,
>(
    fs: &CowFs<H, P>,
    template: &image::Image,
    blobs: &B,
) -> vfs::Result<VolumeHead> {
    if template.kind != image::Kind::RootTemplate {
        return Err(Errno::EINVAL);
    }
    let mut root_cred = Cred::root();
    root_cred.umask = 0;

    let mut handles: HashMap<String, Handle> = HashMap::new();
    handles.insert("/".to_string(), fs.root());

    for entry in &template.entries {
        if entry.path == "/" {
            continue;
        }
        let (parent_path, name) = match entry.path.rsplit_once('/') {
            Some(("", n)) => ("/", n),
            Some((p, n)) => (p, n),
            None => return Err(Errno::EINVAL),
        };
        let parent_h = handles.get(parent_path).cloned().ok_or(Errno::ENOENT)?;
        match &entry.node {
            image::Node::Directory => {
                let created = match fs.mkdir(&root_cred, &parent_h, name, entry.mode).await {
                    Ok(e) => e,
                    Err(Errno::EEXIST) => fs.lookup(&root_cred, &parent_h, name).await?,
                    Err(e) => return Err(e),
                };
                fs.setattr(
                    &root_cred,
                    &created.handle,
                    &SetAttr {
                        mode: Some(entry.mode),
                        uid: Some(entry.uid),
                        gid: Some(entry.gid),
                        ..SetAttr::default()
                    },
                )
                .await?;
                handles.insert(entry.path.clone(), created.handle);
            }
            image::Node::File {
                sha256,
                size,
                chunk_size,
                chunks,
            } => {
                let bytes = crate::release_v2::read_verified_image_file(
                    blobs,
                    sha256,
                    *size,
                    *chunk_size,
                    chunks,
                )
                .await?;
                let mut opts = OpenOptions::new();
                opts.write(true).create(true).truncate(true);
                let (created, open) = fs
                    .create(&root_cred, &parent_h, name, entry.mode, &opts)
                    .await?;
                let mut written_off = 0u64;
                while (written_off as usize) < bytes.len() {
                    let slice = &bytes[written_off as usize..];
                    let w = fs
                        .write_at(&open, slice, WriteAt::Offset(written_off))
                        .await?;
                    if w.len == 0 {
                        let _ = fs.release(&open).await;
                        return Err(Errno::EIO);
                    }
                    written_off += w.len as u64;
                }
                fs.release(&open).await?;
                fs.setattr(
                    &root_cred,
                    &created.handle,
                    &SetAttr {
                        mode: Some(entry.mode),
                        uid: Some(entry.uid),
                        gid: Some(entry.gid),
                        ..SetAttr::default()
                    },
                )
                .await?;
                handles.insert(entry.path.clone(), created.handle);
            }
            image::Node::Symlink { target } => {
                let created = fs.symlink(&root_cred, &parent_h, name, target).await?;
                handles.insert(entry.path.clone(), created.handle);
            }
        }
    }

    // Ensure `/mnt/cloud` optional mountpoint directory exists alongside `/mnt/{local,shared}`.
    if let Some(mnt_h) = handles.get("/mnt").cloned()
        && fs.lookup(&root_cred, &mnt_h, "cloud").await.is_err()
    {
        let _ = fs.mkdir(&root_cred, &mnt_h, "cloud", 0o755).await;
    }

    // Ensure merged-`/usr` compatibility symlinks exist on the local root so `/bin/sh` etc. work
    // immediately after `switch_root` once Release v2 `/usr` is mounted.
    let root_h = fs.root();
    for (name, target) in [
        ("bin", "usr/bin"),
        ("sbin", "usr/bin"),
        ("lib", "usr/lib"),
        ("lib64", "usr/lib"),
    ] {
        if fs.lookup(&root_cred, &root_h, name).await.is_err() {
            let _ = fs.symlink(&root_cred, &root_h, name, target).await;
        }
    }

    fs.commit_tx_group().await
}

/// Pre-mount integrity & format-version verifier (`cowfsck`) that NEVER mutates user data and
/// fails closed with `Errno::EPROTONOSUPPORT` on any incompatible `COWFS_FORMAT_VERSION`.
pub async fn cowfsck_volume_stores<H: HeadStore, P: PackStore>(
    head_store: &H,
    pack_store: &P,
    volume: &VolumeId,
) -> vfs::Result<cowfs::FsckReport> {
    if let Some(ver) = head_store.format_version().await?
        && ver != cowtree::COWFS_FORMAT_VERSION
    {
        return Err(Errno::EPROTONOSUPPORT);
    }
    cowfs::verify_volume(head_store, pack_store, volume).await
}

/// Detailed failure returned by [`open_for_boot_stores_detailed`], preserving the exact
/// [`cowfs::FsckReport`] when post-acquire Merkle verification detects corruption on the mounted
/// or forked head.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub enum BootOpenError {
    Corrupt {
        volume: String,
        report: Box<cowfs::FsckReport>,
    },
    Errno(Errno),
}

impl BootOpenError {
    pub fn errno(&self) -> Errno {
        match self {
            Self::Corrupt { .. } => Errno::EIO,
            Self::Errno(e) => *e,
        }
    }
}

/// Open or provision an `os-cowfs` root volume for Stage 1 boot, returning structured corruption
/// diagnostics (`BootOpenError::Corrupt`) when post-acquire verification fails:
/// - Always checks `COWFS_FORMAT_VERSION` FIRST (`EPROTONOSUPPORT`, NEVER wipes/formats!).
/// - On first boot (`volume_uuid == None`): formats a fresh volume, atomically seeds
///   `RootTemplate`, and commits epoch 1.
/// - On subsequent boot (`volume_uuid == Some(uuid)`): acquires the writer lease / creates the
///   `ForkOnBusy` fork FIRST (with deferred orphan reaping so zero mutations happen prior to
///   verification), then runs `cowfs::fsck::verify_head` on THAT EXACT live-leased head while
///   holding the shared GC lock. If verification fails, cleanly closes `fs` (releasing the writer
///   lease and pruning any unmodified `ForkOnBusy` fork while preserving the parent untouched).
#[allow(clippy::too_many_arguments)]
pub async fn open_for_boot_stores_detailed<
    H: HeadStore + 'static,
    P: PackStore + 'static,
    B: vfs::imagefs::BlobStore,
>(
    head_store: Rc<H>,
    pack_store: Rc<P>,
    volume_uuid: Option<String>,
    writer_mode: WriterMode,
    template: Option<&image::Image>,
    blobs: Option<&B>,
    config: CowFsConfig,
    new_volume_uuid: impl FnOnce() -> String,
) -> std::result::Result<BootOpenResult<H, P>, BootOpenError> {
    // 1. Check store-wide format version FIRST — NEVER format or wipe an incompatible store!
    if let Some(ver) = head_store
        .format_version()
        .await
        .map_err(BootOpenError::Errno)?
        && ver != cowtree::COWFS_FORMAT_VERSION
    {
        return Err(BootOpenError::Errno(Errno::EPROTONOSUPPORT));
    }

    match volume_uuid {
        None => {
            let uuid = new_volume_uuid();
            let vol_id = VolumeId(uuid.clone());
            let now = (config.clock)();
            CowFs::format_volume(&*head_store, &*pack_store, vol_id.clone(), 0, 0, 0o755, now)
                .await
                .map_err(BootOpenError::Errno)?;
            let fs = Rc::new(
                CowFs::open(
                    Rc::clone(&head_store),
                    Rc::clone(&pack_store),
                    vol_id,
                    CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
                    config,
                )
                .await
                .map_err(BootOpenError::Errno)?,
            );
            let mut seeded = false;
            if let (Some(tpl), Some(blob_store)) = (template, blobs) {
                if let Err(e) = seed_root_template_fs(&fs, tpl, blob_store).await {
                    let _ = fs.close_clean().await;
                    return Err(BootOpenError::Errno(e));
                }
                seeded = true;
            }
            let head = fs.current_head();
            Ok(BootOpenResult {
                fs,
                volume_uuid: uuid,
                forked_from: None,
                base_epoch: head.epoch,
                ephemeral_if_unmodified: false,
                first_boot_seeded: seeded,
                fsck_report: None,
            })
        }
        Some(uuid) => {
            let vol_id = VolumeId(uuid);
            // 2. Acquire writer lease / create `ForkOnBusy` fork FIRST (without mutating via
            //    orphan reap yet), so the exact head to be mounted is pinned against both
            //    concurrent writers and GC before Merkle verification runs.
            let open_cfg = config.with_defer_orphan_reap(true);
            let fs = Rc::new(
                CowFs::open(
                    Rc::clone(&head_store),
                    Rc::clone(&pack_store),
                    vol_id,
                    CowFsOpenMode::ReadWrite(writer_mode),
                    open_cfg,
                )
                .await
                .map_err(BootOpenError::Errno)?,
            );

            // 3. Verify THAT EXACT acquired/forked head while holding the live writer lease
            //    (and shared GC lock inside `verify_head`) BEFORE exposing `fs` or reaping.
            let mounted_head = fs.current_head();
            let report =
                match cowfs::fsck::verify_head(&*head_store, &*pack_store, &mounted_head).await {
                    Ok(rep) => rep,
                    Err(e) => {
                        let _ = fs.close_clean().await;
                        return Err(BootOpenError::Errno(e));
                    }
                };
            if !report.ok {
                // Releases the writer lease AND prunes an unmodified `ForkOnBusy` fork while
                // leaving the parent volume completely untouched!
                let _ = fs.close_clean().await;
                return Err(BootOpenError::Corrupt {
                    volume: mounted_head.volume.0,
                    report: Box::new(report),
                });
            }

            // 4. Head verified clean: reap any persisted crash orphans now.
            if let Err(e) = fs.reap_orphans().await {
                let _ = fs.close_clean().await;
                return Err(BootOpenError::Errno(e));
            }
            let head = fs.current_head();
            Ok(BootOpenResult {
                volume_uuid: fs.volume_id().0.clone(),
                forked_from: fs.forked_from().map(|v| v.0),
                base_epoch: head.epoch,
                ephemeral_if_unmodified: head.ephemeral_if_unmodified,
                first_boot_seeded: false,
                fsck_report: Some(report),
                fs,
            })
        }
    }
}

/// Open or provision an `os-cowfs` root volume for Stage 1 boot:
/// - Always checks `COWFS_FORMAT_VERSION` FIRST (`EPROTONOSUPPORT`, NEVER wipes/formats!).
/// - On first boot (`volume_uuid == None`): formats a fresh volume, atomically seeds
///   `RootTemplate`, and commits epoch 1.
/// - On subsequent boot (`volume_uuid == Some(uuid)`): acquires the writer lease / `ForkOnBusy`
///   fork FIRST and verifies THAT EXACT head via `cowfs::fsck::verify_head` before exposing `fs`
///   (closing cleanly and returning `EIO` if corrupt, or `EPROTONOSUPPORT` on format mismatch).
#[allow(dead_code, clippy::too_many_arguments)]
pub async fn open_for_boot_stores<
    H: HeadStore + 'static,
    P: PackStore + 'static,
    B: vfs::imagefs::BlobStore,
>(
    head_store: Rc<H>,
    pack_store: Rc<P>,
    volume_uuid: Option<String>,
    writer_mode: WriterMode,
    template: Option<&image::Image>,
    blobs: Option<&B>,
    config: CowFsConfig,
    new_volume_uuid: impl FnOnce() -> String,
) -> vfs::Result<BootOpenResult<H, P>> {
    open_for_boot_stores_detailed(
        head_store,
        pack_store,
        volume_uuid,
        writer_mode,
        template,
        blobs,
        config,
        new_volume_uuid,
    )
    .await
    .map_err(|e| e.errno())
}

/// Clean shutdown helper: flushes dirty transactions if modified, invokes `CowFs::close_clean()`,
/// and verifies whether an unmodified `ForkOnBusy` fork (`epoch == base_epoch`) was pruned vs
/// retained.
pub async fn close_clean_with_prune_fs<H: HeadStore + 'static, P: PackStore + 'static>(
    fs: &CowFs<H, P>,
    base_epoch: u64,
) -> vfs::Result<CloseCleanPruneOutcome> {
    let volume_uuid = fs.volume_id().0.clone();
    let forked_from = fs.forked_from().map(|v| v.0);
    let head_store = fs.head_store_rc();
    fs.close_clean().await?;
    let head_after = fs.current_head();
    let still_exists = match head_store.read_head(&VolumeId(volume_uuid.clone())).await {
        Ok(_) => true,
        Err(Errno::ENOENT) => false,
        Err(_) => true,
    };
    Ok(CloseCleanPruneOutcome {
        volume_uuid,
        forked_from,
        base_epoch,
        final_epoch: head_after.epoch,
        pruned: !still_exists,
        retained: still_exists,
    })
}

/// Format a new `os-cowfs` volume on the supplied JS `cowfs-store.js` adapter.
#[wasm_bindgen]
pub async fn cowfs_format_volume(
    store: JsValue,
    volume_id: String,
    mode: Option<u16>,
) -> Result<JsValue, JsValue> {
    let adapter = JsCowfsStore { obj: store };
    let head = CowFs::format_volume(
        &adapter,
        &adapter,
        VolumeId(volume_id),
        0,
        0,
        mode.unwrap_or(0o755),
        now_timespec(),
    )
    .await
    .map_err(map_vfs_err)?;
    to_js_json(&head)
}

/// Verify a `cowfs` volume via `os_cowfs::fsck::verify_volume`.
#[wasm_bindgen]
pub async fn cowfs_verify_volume(store: JsValue, volume_id: String) -> Result<JsValue, JsValue> {
    let adapter = JsCowfsStore { obj: store };
    let report = cowfsck_volume_stores(&adapter, &adapter, &VolumeId(volume_id))
        .await
        .map_err(map_vfs_err)?;
    to_js_json(&report)
}

/// Alias exported for Stage 1 `cowfsck` browser callers.
#[wasm_bindgen]
pub async fn cowfsck_volume(store: JsValue, volume_id: String) -> Result<JsValue, JsValue> {
    cowfs_verify_volume(store, volume_id).await
}

/// Run reachability GC over `store` at wall-clock timestamp `now_sec`.
#[wasm_bindgen]
pub async fn cowfs_collect_garbage(store: JsValue, now_sec: f64) -> Result<JsValue, JsValue> {
    let adapter = JsCowfsStore { obj: store };
    let sec = validate_js_u64(now_sec).map_err(map_vfs_err)?;
    let report = cowfs::collect_garbage(&adapter, &adapter, Timespec { sec, nsec: 0 })
        .await
        .map_err(map_vfs_err)?;
    to_js_json(&report)
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct IdentityKey {
    uid: u32,
    gid: u32,
    groups: Vec<u32>,
}

impl IdentityKey {
    fn from_cred(cred: &Cred) -> Self {
        Self {
            uid: cred.identity.id,
            gid: cred.identity.group,
            groups: cred.identity.groups.iter().copied().collect(),
        }
    }
}

/// Mounted `os-cowfs` volume handle exposed to browser JS/Workers (backed by portable `CowFs` +
/// `os_vfs::Vfs` + `/dev/vd0` `VblkRegistry`).
#[wasm_bindgen]
pub struct CowFsVolume {
    fs: Rc<CowFs<JsCowfsStore, JsCowfsStore>>,
    vfs: Vfs,
    vblk: VblkRegistry,
    identity_pids: RefCell<HashMap<IdentityKey, u32>>,
    next_pid: Cell<u32>,
    dirty_guard: DirtyFlushGuard,
}

#[wasm_bindgen]
impl CowFsVolume {
    /// Open a volume read-write with `writer_mode` (`"exclusive"`, `"fork-on-busy"`,
    /// `"force-takeover"`) using the fixed `32 MiB` wasm32 slab arena.
    pub async fn open_rw(
        store: JsValue,
        volume_id: String,
        writer_mode: String,
    ) -> Result<CowFsVolume, JsValue> {
        let mode = parse_writer_mode(&writer_mode).map_err(map_vfs_err)?;
        Self::open_internal(store, volume_id, CowFsOpenMode::ReadWrite(mode)).await
    }

    /// Open a volume read-only (acquires NO writer lock; pins root against GC; uses lock-free
    /// `getFile().slice()`).
    pub async fn open_ro(store: JsValue, volume_id: String) -> Result<CowFsVolume, JsValue> {
        Self::open_internal(store, volume_id, CowFsOpenMode::ReadOnly).await
    }

    /// Open a pinned read-only named snapshot.
    pub async fn open_snapshot(
        store: JsValue,
        volume_id: String,
        snapshot_name: String,
    ) -> Result<CowFsVolume, JsValue> {
        Self::open_internal(store, volume_id, CowFsOpenMode::Snapshot(snapshot_name)).await
    }

    async fn open_internal(
        store: JsValue,
        volume_id: String,
        mode: CowFsOpenMode,
    ) -> Result<CowFsVolume, JsValue> {
        let adapter = Rc::new(JsCowfsStore { obj: store });
        let base_config = CowFsConfig::local_browser(Rc::new(now_timespec))
            .with_arena(ArenaConfig::fixed_32mib());
        let (config, dirty_binder) =
            bind_dirty_flush_timer::<JsCowfsStore, JsCowfsStore>(base_config);
        let fs = Rc::new(
            CowFs::open(
                Rc::clone(&adapter),
                adapter,
                VolumeId(volume_id),
                mode,
                config,
            )
            .await
            .map_err(map_vfs_err)?,
        );
        let dirty_guard = dirty_binder.attach(&fs);

        let root_wrapper = Rc::new(BridgeRootFs {
            inner: Rc::clone(&fs),
        });
        let backing = Rc::new(MountBacking::new(root_wrapper, FsType::Cowfs));
        let factory = Rc::new(DefaultFilesystemFactory::new(Rc::new(|| {
            let ts = now_timespec();
            (ts.sec, ts.nsec)
        })));
        let vfs = Vfs::boot("cowfs-browser", backing, "cowfs", factory)
            .await
            .map_err(map_vfs_err)?;

        // Mount `DevTmpFs` at `/dev` with `/dev/vd0` pointing to this volume so `stat("/dev/vd0")`,
        // `BLK_INFO`, `COWFS_IOC_*`, and `mkfs_target("/dev/vd0", ...)` work directly on the
        // volume's mounted namespace without mutating the underlying `CowFs` root tree.
        let vblk = VblkRegistry::new();
        let dev_node = Rc::new(CowFsVolumeDevice::from_mounted(Rc::clone(&fs)));
        let vd_name = vblk.attach(dev_node);
        let dev_fs = Rc::new(DevTmpFs::new(
            FsId("devtmpfs:cowfs".into()),
            1,
            Box::new(|| {
                let ts = now_timespec();
                (ts.sec, ts.nsec)
            }),
            VblkDeviceBackend::new(DefaultDeviceBackend),
        ));
        dev_fs.register_vblk(&vd_name, 0o660).map_err(map_vfs_err)?;
        let sys_ns = vfs.system_namespace();
        vfs.mount_on_namespace(
            &sys_ns,
            &Cred::root(),
            Rc::new(MountBacking::new(dev_fs, FsType::DevTmpFs)),
            None,
            "devtmpfs",
            "/dev",
            MountFlags::from_accepted(mount_flags::MS_NOSUID),
            0,
            None,
        )
        .await
        .map_err(map_vfs_err)?;

        let mut identity_pids = HashMap::new();
        identity_pids.insert(IdentityKey::from_cred(&Cred::root()), 1);

        Ok(CowFsVolume {
            fs,
            vfs,
            vblk,
            identity_pids: RefCell::new(identity_pids),
            next_pid: Cell::new(2),
            dirty_guard,
        })
    }

    pub fn volume_id(&self) -> String {
        self.fs.volume_id().0.clone()
    }

    pub fn forked_from(&self) -> Option<String> {
        self.fs.forked_from().map(|v| v.0)
    }

    pub fn info(&self) -> Result<JsValue, JsValue> {
        to_js_json(&self.fs.volume_info())
    }

    pub fn arena_stats(&self) -> Result<JsValue, JsValue> {
        to_js_json(&self.fs.arena_stats())
    }

    pub fn drop_clean_caches(&self) {
        self.fs.drop_clean_caches();
    }

    pub async fn mkdir(&self, path: String, mode: u16, identity: JsValue) -> Result<(), JsValue> {
        let cred = self.cred_or_root(&identity)?;
        let pid = self.ensure_pid(&cred)?;
        self.vfs
            .mkdirat(pid, StartAnchor::Root, &path, mode)
            .await
            .map(|_| ())
            .map_err(map_vfs_err)
    }

    pub async fn write_file(
        &self,
        path: String,
        bytes: &[u8],
        mode: u16,
        identity: JsValue,
    ) -> Result<usize, JsValue> {
        let cred = self.cred_or_root(&identity)?;
        let pid = self.ensure_pid(&cred)?;
        let fd = self
            .vfs
            .openat(
                pid,
                StartAnchor::Root,
                &path,
                abi::O_CREAT | abi::O_TRUNC | abi::O_WRONLY,
                mode,
            )
            .await
            .map_err(map_vfs_err)?;
        let res = self.vfs.write(pid, fd, bytes).await;
        let _ = self.vfs.close(pid, fd).await;
        res.map_err(map_vfs_err)
    }

    pub async fn write_at_offset(
        &self,
        path: String,
        offset: f64,
        bytes: &[u8],
        mode: u16,
        identity: JsValue,
    ) -> Result<usize, JsValue> {
        let off = validate_js_u64(offset).map_err(map_vfs_err)?;
        let cred = self.cred_or_root(&identity)?;
        let pid = self.ensure_pid(&cred)?;
        let fd = self
            .vfs
            .openat(
                pid,
                StartAnchor::Root,
                &path,
                abi::O_CREAT | abi::O_RDWR,
                mode,
            )
            .await
            .map_err(map_vfs_err)?;
        let res = self.vfs.pwrite(pid, fd, bytes, off).await;
        let _ = self.vfs.close(pid, fd).await;
        res.map_err(map_vfs_err)
    }

    pub async fn read_file(&self, path: String, identity: JsValue) -> Result<Vec<u8>, JsValue> {
        let cred = self.cred_or_root(&identity)?;
        let pid = self.ensure_pid(&cred)?;
        let fd = self
            .vfs
            .openat(pid, StartAnchor::Root, &path, abi::O_RDONLY, 0)
            .await
            .map_err(map_vfs_err)?;
        let mut out = Vec::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match self.vfs.read(pid, fd, &mut buf).await {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(e) => {
                    let _ = self.vfs.close(pid, fd).await;
                    return Err(map_vfs_err(e));
                }
            }
        }
        let _ = self.vfs.close(pid, fd).await;
        Ok(out)
    }

    pub async fn read_range(
        &self,
        path: String,
        offset: f64,
        len: usize,
        identity: JsValue,
    ) -> Result<Vec<u8>, JsValue> {
        let off = validate_js_u64(offset).map_err(map_vfs_err)?;
        let cred = self.cred_or_root(&identity)?;
        let pid = self.ensure_pid(&cred)?;
        let fd = self
            .vfs
            .openat(pid, StartAnchor::Root, &path, abi::O_RDONLY, 0)
            .await
            .map_err(map_vfs_err)?;
        let mut buf = vec![0u8; len];
        let res = self.vfs.pread(pid, fd, &mut buf, off).await;
        let _ = self.vfs.close(pid, fd).await;
        let n = res.map_err(map_vfs_err)?;
        buf.truncate(n);
        Ok(buf)
    }

    pub async fn truncate(
        &self,
        path: String,
        size: f64,
        identity: JsValue,
    ) -> Result<(), JsValue> {
        let sz = validate_js_u64(size).map_err(map_vfs_err)?;
        let cred = self.cred_or_root(&identity)?;
        let pid = self.ensure_pid(&cred)?;
        self.vfs
            .setattrat(
                pid,
                StartAnchor::Root,
                &path,
                &SetAttr {
                    size: Some(sz),
                    ..SetAttr::default()
                },
                true,
            )
            .await
            .map(|_| ())
            .map_err(map_vfs_err)
    }

    pub async fn stat(
        &self,
        path: String,
        follow: bool,
        identity: JsValue,
    ) -> Result<JsValue, JsValue> {
        let cred = self.cred_or_root(&identity)?;
        let pid = self.ensure_pid(&cred)?;
        let st = self
            .vfs
            .statat(pid, StartAnchor::Root, &path, follow)
            .await
            .map_err(map_vfs_err)?;
        to_js_json(&st)
    }

    pub async fn chmod(&self, path: String, mode: u16, identity: JsValue) -> Result<(), JsValue> {
        let cred = self.cred_or_root(&identity)?;
        let pid = self.ensure_pid(&cred)?;
        self.vfs
            .setattrat(
                pid,
                StartAnchor::Root,
                &path,
                &SetAttr {
                    mode: Some(mode),
                    ..SetAttr::default()
                },
                true,
            )
            .await
            .map(|_| ())
            .map_err(map_vfs_err)
    }

    pub async fn setxattr(
        &self,
        path: String,
        name: String,
        value: &[u8],
        flags: u8,
        identity: JsValue,
    ) -> Result<(), JsValue> {
        let cred = self.cred_or_root(&identity)?;
        let pid = self.ensure_pid(&cred)?;
        let xf = XattrFlags::from_bits(flags).ok_or_else(|| map_vfs_err(Errno::EINVAL))?;
        self.vfs
            .setxattrat(pid, StartAnchor::Root, &path, &name, value, xf, true)
            .await
            .map_err(map_vfs_err)
    }

    pub async fn getxattr(
        &self,
        path: String,
        name: String,
        identity: JsValue,
    ) -> Result<Vec<u8>, JsValue> {
        let cred = self.cred_or_root(&identity)?;
        let pid = self.ensure_pid(&cred)?;
        self.vfs
            .getxattrat(pid, StartAnchor::Root, &path, &name, true)
            .await
            .map_err(map_vfs_err)
    }

    pub async fn symlink(
        &self,
        target: String,
        linkpath: String,
        identity: JsValue,
    ) -> Result<(), JsValue> {
        let cred = self.cred_or_root(&identity)?;
        let pid = self.ensure_pid(&cred)?;
        self.vfs
            .symlinkat(pid, &target, StartAnchor::Root, &linkpath)
            .await
            .map(|_| ())
            .map_err(map_vfs_err)
    }

    pub async fn readlink(&self, path: String, identity: JsValue) -> Result<String, JsValue> {
        let cred = self.cred_or_root(&identity)?;
        let pid = self.ensure_pid(&cred)?;
        self.vfs
            .readlinkat(pid, StartAnchor::Root, &path)
            .await
            .map_err(map_vfs_err)
    }

    pub async fn link(
        &self,
        oldpath: String,
        newpath: String,
        identity: JsValue,
    ) -> Result<(), JsValue> {
        let cred = self.cred_or_root(&identity)?;
        let pid = self.ensure_pid(&cred)?;
        self.vfs
            .linkat(
                pid,
                StartAnchor::Root,
                &oldpath,
                StartAnchor::Root,
                &newpath,
                false,
            )
            .await
            .map(|_| ())
            .map_err(map_vfs_err)
    }

    pub async fn unlink(&self, path: String, identity: JsValue) -> Result<(), JsValue> {
        let cred = self.cred_or_root(&identity)?;
        let pid = self.ensure_pid(&cred)?;
        self.vfs
            .unlinkat(pid, StartAnchor::Root, &path, false)
            .await
            .map_err(map_vfs_err)
    }

    pub async fn rmdir(&self, path: String, identity: JsValue) -> Result<(), JsValue> {
        let cred = self.cred_or_root(&identity)?;
        let pid = self.ensure_pid(&cred)?;
        self.vfs
            .unlinkat(pid, StartAnchor::Root, &path, true)
            .await
            .map_err(map_vfs_err)
    }

    pub async fn rename(
        &self,
        from: String,
        to: String,
        noreplace: bool,
        identity: JsValue,
    ) -> Result<(), JsValue> {
        let cred = self.cred_or_root(&identity)?;
        let pid = self.ensure_pid(&cred)?;
        let flags = if noreplace {
            RenameFlags::NOREPLACE
        } else {
            RenameFlags::empty()
        };
        self.vfs
            .renameat(pid, StartAnchor::Root, &from, StartAnchor::Root, &to, flags)
            .await
            .map_err(map_vfs_err)
    }

    pub async fn read_dir_page(
        &self,
        path: String,
        cookie: f64,
        max_entries: usize,
        identity: JsValue,
    ) -> Result<JsValue, JsValue> {
        let ck = validate_js_u64(cookie).map_err(map_vfs_err)?;
        let cred = self.cred_or_root(&identity)?;
        let pid = self.ensure_pid(&cred)?;
        let page = self
            .vfs
            .read_dir_page(pid, StartAnchor::Root, &path, ck, max_entries)
            .await
            .map_err(map_vfs_err)?;
        to_js_json(&page)
    }

    /// Open a retained descriptor (supports open-unlink orphan tests and `ficlone`).
    pub async fn open_fd(
        &self,
        path: String,
        flags: u32,
        mode: u16,
        identity: JsValue,
    ) -> Result<u32, JsValue> {
        let cred = self.cred_or_root(&identity)?;
        let pid = self.ensure_pid(&cred)?;
        self.vfs
            .openat(pid, StartAnchor::Root, &path, flags, mode)
            .await
            .map_err(map_vfs_err)
    }

    pub async fn fd_read_at(
        &self,
        fd: u32,
        offset: f64,
        len: usize,
        identity: JsValue,
    ) -> Result<Vec<u8>, JsValue> {
        let off = validate_js_u64(offset).map_err(map_vfs_err)?;
        let cred = self.cred_or_root(&identity)?;
        let pid = self.ensure_pid(&cred)?;
        let mut buf = vec![0u8; len];
        let n = self
            .vfs
            .pread(pid, fd, &mut buf, off)
            .await
            .map_err(map_vfs_err)?;
        buf.truncate(n);
        Ok(buf)
    }

    pub async fn fd_write_at(
        &self,
        fd: u32,
        offset: f64,
        bytes: &[u8],
        identity: JsValue,
    ) -> Result<usize, JsValue> {
        let off = validate_js_u64(offset).map_err(map_vfs_err)?;
        let cred = self.cred_or_root(&identity)?;
        let pid = self.ensure_pid(&cred)?;
        self.vfs
            .pwrite(pid, fd, bytes, off)
            .await
            .map_err(map_vfs_err)
    }

    pub async fn fd_close(&self, fd: u32, identity: JsValue) -> Result<(), JsValue> {
        let cred = self.cred_or_root(&identity)?;
        let pid = self.ensure_pid(&cred)?;
        self.vfs.close(pid, fd).await.map_err(map_vfs_err)
    }

    /// Intra-volume `FICLONE` between two paths (creates `dst` if needed).
    pub async fn ficlone(
        &self,
        src_path: String,
        dst_path: String,
        identity: JsValue,
    ) -> Result<(), JsValue> {
        let cred = self.cred_or_root(&identity)?;
        let pid = self.ensure_pid(&cred)?;
        let src_fd = self
            .vfs
            .openat(pid, StartAnchor::Root, &src_path, abi::O_RDONLY, 0)
            .await
            .map_err(map_vfs_err)?;
        let dst_fd = match self
            .vfs
            .openat(
                pid,
                StartAnchor::Root,
                &dst_path,
                abi::O_CREAT | abi::O_WRONLY,
                0o644,
            )
            .await
        {
            Ok(fd) => fd,
            Err(e) => {
                let _ = self.vfs.close(pid, src_fd).await;
                return Err(map_vfs_err(e));
            }
        };
        let res = self.vfs.ficlone(pid, dst_fd, src_fd).await;
        let _ = self.vfs.close(pid, src_fd).await;
        let _ = self.vfs.close(pid, dst_fd).await;
        res.map_err(map_vfs_err)
    }

    /// Cross-volume `FICLONE` check against another `CowFsVolume` (always returns `EXDEV`).
    pub async fn ficlone_from_other(
        &self,
        other: &CowFsVolume,
        src_path: String,
        dst_path: String,
        identity: JsValue,
    ) -> Result<(), JsValue> {
        let cred = self.cred_or_root(&identity)?;
        // Open src directly on `other.fs` and dst on `self.fs` and invoke `self.fs.reflink`.
        let src_name = src_path.trim_start_matches('/');
        let dst_name = dst_path.trim_start_matches('/');
        let src_entry = other
            .fs
            .lookup(&cred, &other.fs.root(), src_name)
            .await
            .map_err(map_vfs_err)?;
        let mut ro = OpenOptions::new();
        ro.read(true);
        let src_open = other
            .fs
            .open(&cred, &src_entry.handle, &ro)
            .await
            .map_err(map_vfs_err)?;
        let mut wo = OpenOptions::new();
        wo.write(true).create(true);
        let (_, dst_open) = match self
            .fs
            .create(&cred, &self.fs.root(), dst_name, 0o644, &wo)
            .await
        {
            Ok(pair) => pair,
            Err(e) => {
                let _ = other.fs.release(&src_open).await;
                return Err(map_vfs_err(e));
            }
        };
        let res = self.fs.reflink(&cred, &src_open, &dst_open).await;
        let _ = other.fs.release(&src_open).await;
        let _ = self.fs.release(&dst_open).await;
        res.map_err(map_vfs_err)
    }

    pub async fn sync_fs(&self) -> Result<JsValue, JsValue> {
        let head = self.fs.commit_tx_group().await.map_err(map_vfs_err)?;
        to_js_json(&head)
    }

    pub async fn snapshot(&self, name: String) -> Result<JsValue, JsValue> {
        let snap = self.fs.create_snapshot(&name).await.map_err(map_vfs_err)?;
        to_js_json(&snap)
    }

    pub async fn fork(
        &self,
        snapshot: Option<String>,
        new_volume: String,
        ephemeral_if_unmodified: bool,
    ) -> Result<JsValue, JsValue> {
        let head = self
            .fs
            .fork_volume(
                snapshot.as_deref(),
                VolumeId(new_volume),
                ephemeral_if_unmodified,
            )
            .await
            .map_err(map_vfs_err)?;
        to_js_json(&head)
    }

    pub async fn ioctl(
        &self,
        request: u32,
        payload_json: String,
        identity: JsValue,
    ) -> Result<JsValue, JsValue> {
        let cred = self.cred_or_root(&identity)?;
        let bytes = if request == abi::contract::cowfs_ioctl::BLK_INFO
            || request == abi::contract::cowfs_ioctl::BLK_LEASE
        {
            self.vblk
                .ioctl_rdev(&cred, "vblk:vd0", request, payload_json.as_bytes())
                .await
                .map_err(map_vfs_err)?
        } else {
            cowfs_ioctl_mounted(&self.fs, &cred, request, payload_json.as_bytes())
                .await
                .map_err(map_vfs_err)?
        };
        let text = String::from_utf8(bytes).map_err(|_| map_vfs_err(Errno::EIO))?;
        js_sys::JSON::parse(&text).map_err(|_| map_vfs_err(Errno::EIO))
    }

    pub async fn mkfs_target(
        &self,
        target: String,
        force: bool,
        identity: JsValue,
    ) -> Result<JsValue, JsValue> {
        let cred = self.cred_or_root(&identity)?;
        let pid = self.ensure_pid(&cred)?;
        let resp = self
            .vblk
            .mkfs_cowfs(&self.vfs, pid, &target, force)
            .await
            .map_err(map_vfs_err)?;
        to_js_json(&resp)
    }

    pub async fn seed_root_template(&self, root_template_json: String) -> Result<JsValue, JsValue> {
        let tpl = image::Image::parse(root_template_json.as_bytes())
            .map_err(|e| js_errno(Errno::EINVAL, &e.to_string()))?;
        let blobs = crate::release_v2::VerifiedAssetBlobStore;
        let head = seed_root_template_fs(&self.fs, &tpl, &blobs)
            .await
            .map_err(map_vfs_err)?;
        to_js_json(&head)
    }

    pub async fn flush_for_suspend(&self) -> Result<JsValue, JsValue> {
        let head = self.fs.flush_for_suspend().await.map_err(map_vfs_err)?;
        to_js_json(&head)
    }

    pub async fn close_clean(&self) -> Result<(), JsValue> {
        self.fs.close_clean().await.map_err(map_vfs_err)?;
        self.dirty_guard.cancel();
        Ok(())
    }

    pub async fn close_clean_with_prune(&self, base_epoch: f64) -> Result<JsValue, JsValue> {
        let base = validate_js_u64(base_epoch).map_err(map_vfs_err)?;
        let outcome = close_clean_with_prune_fs(&self.fs, base)
            .await
            .map_err(map_vfs_err)?;
        self.dirty_guard.cancel();
        to_js_json(&outcome)
    }

    // Internal helpers
    fn cred_or_root(&self, identity: &JsValue) -> Result<Cred, JsValue> {
        if identity.is_undefined() || identity.is_null() {
            Ok(Cred::root())
        } else {
            Ok(Cred::new(parse_identity(identity)?))
        }
    }

    /// Allocate a unique monotonic VFS PID per distinct `(uid, gid, groups)` identity with an
    /// empty `FdTable` (never colliding modulo 10,000 and never inheriting PID 1's descriptors).
    fn ensure_pid(&self, cred: &Cred) -> Result<u32, JsValue> {
        let key = IdentityKey::from_cred(cred);
        if let Some(&pid) = self.identity_pids.borrow().get(&key) {
            return Ok(pid);
        }
        let pid = self.next_pid.get();
        let next = pid
            .checked_add(1)
            .ok_or_else(|| map_vfs_err(Errno::EAGAIN))?;
        self.vfs
            .spawn_process(pid, 1, cred.clone(), None, None, None)
            .map_err(map_vfs_err)?;
        self.next_pid.set(next);
        self.identity_pids.borrow_mut().insert(key, pid);
        Ok(pid)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use cowtree::COWFS_FORMAT_VERSION;
    use cowtree::pack::decode_pack_trailer;
    use std::collections::{HashMap, HashSet};
    use std::future::Future;

    struct TestWriterGuard {
        state: Rc<RefCell<TestHeadState>>,
        volume: VolumeId,
        token: u64,
    }
    impl WriterLockGuard for TestWriterGuard {}
    impl Drop for TestWriterGuard {
        fn drop(&mut self) {
            let mut st = self.state.borrow_mut();
            if st.active_locks.get(&self.volume) == Some(&self.token) {
                st.active_locks.remove(&self.volume);
            }
        }
    }

    struct TestGcGuard;
    impl GcLockGuard for TestGcGuard {}

    struct TestRoPinGuard;
    impl RoPinGuard for TestRoPinGuard {}

    #[derive(Default)]
    struct TestHeadState {
        format_version: Option<u32>,
        heads: HashMap<VolumeId, VolumeHead>,
        nodes: HashMap<Digest, Vec<u8>>,
        packs: HashMap<PackId, PackMeta>,
        blocks: HashMap<Digest, BlockLoc>,
        snapshots: HashMap<(VolumeId, String), SnapshotRecord>,
        active_locks: HashMap<VolumeId, u64>,
        next_lock_token: u64,
        next_fork_seq: u64,
    }

    #[derive(Clone, Default)]
    struct TestHeadStore {
        state: Rc<RefCell<TestHeadState>>,
    }

    impl TestHeadStore {
        fn new() -> Self {
            Self::default()
        }
    }

    impl HeadStore for TestHeadStore {
        fn format_version(&self) -> BoxFuture<'_, Option<u32>> {
            Box::pin(async move { Ok(self.state.borrow().format_version) })
        }

        fn grace_window_secs(&self) -> u64 {
            600
        }

        fn create_volume<'a>(
            &'a self,
            head: &'a VolumeHead,
            initial_nodes: &'a [(Digest, Vec<u8>)],
        ) -> BoxFuture<'a, VolumeHead> {
            Box::pin(async move {
                let mut st = self.state.borrow_mut();
                if let Some(ver) = st.format_version
                    && ver != COWFS_FORMAT_VERSION
                {
                    return Err(Errno::EPROTONOSUPPORT);
                }
                if st.heads.contains_key(&head.volume) {
                    return Err(Errno::EEXIST);
                }
                st.format_version = Some(COWFS_FORMAT_VERSION);
                for (d, b) in initial_nodes {
                    st.nodes.insert(*d, b.clone());
                }
                st.heads.insert(head.volume.clone(), head.clone());
                Ok(head.clone())
            })
        }

        fn read_head<'a>(&'a self, volume: &'a VolumeId) -> BoxFuture<'a, VolumeHead> {
            Box::pin(async move {
                self.state
                    .borrow()
                    .heads
                    .get(volume)
                    .cloned()
                    .ok_or(Errno::ENOENT)
            })
        }

        fn pin_ro_root<'a>(
            &'a self,
            volume: &'a VolumeId,
            snapshot: Option<&'a str>,
        ) -> BoxFuture<'a, (VolumeHead, Box<dyn RoPinGuard>)> {
            Box::pin(async move {
                let st = self.state.borrow();
                let mut head = st.heads.get(volume).cloned().ok_or(Errno::ENOENT)?;
                if let Some(snap_name) = snapshot {
                    let snap = st
                        .snapshots
                        .get(&(volume.clone(), snap_name.to_string()))
                        .ok_or(Errno::ENOENT)?;
                    head.root = snap.root;
                    head.epoch = snap.epoch;
                }
                Ok((head, Box::new(TestRoPinGuard) as Box<dyn RoPinGuard>))
            })
        }

        fn unpin_ro_root<'a>(&'a self, _pin: Box<dyn RoPinGuard>) -> BoxFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }

        fn acquire_writer<'a>(
            &'a self,
            volume: &'a VolumeId,
            mode: WriterMode,
        ) -> BoxFuture<'a, WriterLease> {
            Box::pin(async move {
                let mut st = self.state.borrow_mut();
                if let Some(ver) = st.format_version
                    && ver != COWFS_FORMAT_VERSION
                {
                    return Err(Errno::EPROTONOSUPPORT);
                }
                if st.active_locks.contains_key(volume) {
                    match mode {
                        WriterMode::Exclusive => return Err(Errno::EBUSY),
                        WriterMode::ForkOnBusy => {
                            let parent = st.heads.get(volume).cloned().ok_or(Errno::ENOENT)?;
                            st.next_fork_seq += 1;
                            let fork_id =
                                VolumeId(format!("{}-fork-{}", volume.0, st.next_fork_seq));
                            let fork_head = VolumeHead {
                                format_version: COWFS_FORMAT_VERSION,
                                volume: fork_id.clone(),
                                incarnation: 1,
                                fence: 1,
                                epoch: parent.epoch,
                                root: parent.root,
                                parent_volume: Some(volume.clone()),
                                ephemeral_if_unmodified: true,
                                modified: false,
                                updated_at: parent.updated_at,
                            };
                            st.heads.insert(fork_id.clone(), fork_head.clone());
                            st.next_lock_token += 1;
                            let token = st.next_lock_token;
                            st.active_locks.insert(fork_id.clone(), token);
                            return Ok(WriterLease {
                                volume: fork_id.clone(),
                                incarnation: fork_head.incarnation,
                                fence: fork_head.fence,
                                epoch: fork_head.epoch,
                                head: fork_head,
                                forked_from: Some(volume.clone()),
                                expires_at: None,
                                guard: Box::new(TestWriterGuard {
                                    state: Rc::clone(&self.state),
                                    volume: fork_id,
                                    token,
                                }),
                            });
                        }
                        WriterMode::ForceTakeover => {}
                    }
                }
                let head = st.heads.get_mut(volume).ok_or(Errno::ENOENT)?;
                head.fence += 1;
                let updated = head.clone();
                st.next_lock_token += 1;
                let token = st.next_lock_token;
                st.active_locks.insert(volume.clone(), token);
                Ok(WriterLease {
                    volume: volume.clone(),
                    incarnation: updated.incarnation,
                    fence: updated.fence,
                    epoch: updated.epoch,
                    head: updated,
                    forked_from: None,
                    expires_at: None,
                    guard: Box::new(TestWriterGuard {
                        state: Rc::clone(&self.state),
                        volume: volume.clone(),
                        token,
                    }),
                })
            })
        }

        fn renew_writer<'a>(&'a self, _lease: &'a mut WriterLease) -> BoxFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }

        fn release_writer<'a>(&'a self, lease: WriterLease) -> BoxFuture<'a, ()> {
            Box::pin(async move {
                drop(lease);
                Ok(())
            })
        }

        fn get_node<'a>(&'a self, digest: &'a Digest) -> BoxFuture<'a, Vec<u8>> {
            Box::pin(async move {
                self.state
                    .borrow()
                    .nodes
                    .get(digest)
                    .cloned()
                    .ok_or(Errno::ENOENT)
            })
        }

        fn lookup_block<'a>(&'a self, digest: &'a Digest) -> BoxFuture<'a, Option<BlockLoc>> {
            Box::pin(async move { Ok(self.state.borrow().blocks.get(digest).cloned()) })
        }

        fn commit_head<'a>(&'a self, req: &'a CommitRequest) -> BoxFuture<'a, VolumeHead> {
            Box::pin(async move {
                let mut st = self.state.borrow_mut();
                let cur = st.heads.get(&req.volume).cloned().ok_or(Errno::ENOENT)?;
                if cur.incarnation != req.expected_incarnation
                    || cur.fence != req.expected_fence
                    || cur.epoch != req.expected_epoch
                {
                    return Err(Errno::ESTALE);
                }
                for (d, b) in &req.put_nodes {
                    st.nodes.insert(*d, b.clone());
                }
                for pm in &req.put_packs {
                    st.packs.insert(pm.pack_id.clone(), pm.clone());
                }
                for (d, loc) in &req.put_blocks {
                    st.blocks.insert(*d, loc.clone());
                }
                let next = VolumeHead {
                    epoch: cur.epoch + 1,
                    root: req.new_root,
                    modified: true,
                    ephemeral_if_unmodified: false,
                    updated_at: req.committed_at,
                    ..cur
                };
                st.heads.insert(req.volume.clone(), next.clone());
                Ok(next)
            })
        }

        fn create_snapshot<'a>(
            &'a self,
            volume: &'a VolumeId,
            name: &'a str,
            head: &'a VolumeHead,
            now: Timespec,
        ) -> BoxFuture<'a, SnapshotRecord> {
            Box::pin(async move {
                let mut st = self.state.borrow_mut();
                let key = (volume.clone(), name.to_string());
                if st.snapshots.contains_key(&key) {
                    return Err(Errno::EEXIST);
                }
                let rec = SnapshotRecord {
                    volume: volume.clone(),
                    name: name.to_string(),
                    root: head.root,
                    epoch: head.epoch,
                    created_at: now,
                };
                st.snapshots.insert(key, rec.clone());
                Ok(rec)
            })
        }

        fn get_snapshot<'a>(
            &'a self,
            volume: &'a VolumeId,
            name: &'a str,
        ) -> BoxFuture<'a, SnapshotRecord> {
            Box::pin(async move {
                self.state
                    .borrow()
                    .snapshots
                    .get(&(volume.clone(), name.to_string()))
                    .cloned()
                    .ok_or(Errno::ENOENT)
            })
        }

        fn list_snapshots<'a>(
            &'a self,
            volume: &'a VolumeId,
        ) -> BoxFuture<'a, Vec<SnapshotRecord>> {
            Box::pin(async move {
                let st = self.state.borrow();
                let mut out: Vec<_> = st
                    .snapshots
                    .iter()
                    .filter(|((v, _), _)| v == volume)
                    .map(|(_, s)| s.clone())
                    .collect();
                out.sort_by(|a, b| a.name.cmp(&b.name));
                Ok(out)
            })
        }

        fn delete_snapshot<'a>(&'a self, volume: &'a VolumeId, name: &'a str) -> BoxFuture<'a, ()> {
            Box::pin(async move {
                self.state
                    .borrow_mut()
                    .snapshots
                    .remove(&(volume.clone(), name.to_string()))
                    .map(|_| ())
                    .ok_or(Errno::ENOENT)
            })
        }

        fn fork_volume<'a>(&'a self, req: &'a ForkRequest) -> BoxFuture<'a, VolumeHead> {
            Box::pin(async move {
                let mut st = self.state.borrow_mut();
                if st.heads.contains_key(&req.new_volume) {
                    return Err(Errno::EEXIST);
                }
                let epoch = st
                    .heads
                    .get(&req.source_volume)
                    .map(|h| h.epoch)
                    .ok_or(Errno::ENOENT)?;
                let head = VolumeHead {
                    format_version: COWFS_FORMAT_VERSION,
                    volume: req.new_volume.clone(),
                    incarnation: 1,
                    fence: 0,
                    epoch,
                    root: req.source_root,
                    parent_volume: Some(req.source_volume.clone()),
                    ephemeral_if_unmodified: req.ephemeral_if_unmodified,
                    modified: false,
                    updated_at: req.created_at,
                };
                st.heads.insert(req.new_volume.clone(), head.clone());
                Ok(head)
            })
        }

        fn delete_volume<'a>(&'a self, volume: &'a VolumeId) -> BoxFuture<'a, ()> {
            Box::pin(async move {
                let mut st = self.state.borrow_mut();
                if st.active_locks.contains_key(volume) {
                    return Err(Errno::EBUSY);
                }
                st.heads.remove(volume).ok_or(Errno::ENOENT)?;
                st.snapshots.retain(|(v, _), _| v != volume);
                Ok(())
            })
        }

        fn delete_volume_with_lease<'a>(
            &'a self,
            lease: WriterLease,
            only_if_unmodified_ephemeral: bool,
        ) -> BoxFuture<'a, bool> {
            Box::pin(async move {
                let deleted = {
                    let mut st = self.state.borrow_mut();
                    let cur = st.heads.get(&lease.volume).cloned().ok_or(Errno::ENOENT)?;
                    if cur.incarnation != lease.incarnation
                        || cur.fence != lease.fence
                        || cur.epoch != lease.epoch
                    {
                        return Err(Errno::ESTALE);
                    }
                    if only_if_unmodified_ephemeral
                        && (!cur.ephemeral_if_unmodified || cur.modified)
                    {
                        false
                    } else {
                        st.heads.remove(&lease.volume);
                        st.snapshots.retain(|(v, _), _| v != &lease.volume);
                        true
                    }
                };
                drop(lease);
                Ok(deleted)
            })
        }

        fn reformat_volume_with_lease<'a>(
            &'a self,
            lease: WriterLease,
            new_head: &'a VolumeHead,
            initial_nodes: &'a [(Digest, Vec<u8>)],
        ) -> BoxFuture<'a, VolumeHead> {
            Box::pin(async move {
                let next = {
                    let mut st = self.state.borrow_mut();
                    let cur = st.heads.get(&lease.volume).cloned().ok_or(Errno::ENOENT)?;
                    for (d, b) in initial_nodes {
                        st.nodes.insert(*d, b.clone());
                    }
                    let updated = VolumeHead {
                        incarnation: cur.incarnation + 1,
                        fence: 1,
                        epoch: 0,
                        ..new_head.clone()
                    };
                    st.heads.insert(lease.volume.clone(), updated.clone());
                    st.snapshots.retain(|(v, _), _| v != &lease.volume);
                    updated
                };
                drop(lease);
                Ok(next)
            })
        }

        fn acquire_gc_lock(&self, _exclusive: bool) -> BoxFuture<'_, Box<dyn GcLockGuard>> {
            Box::pin(async { Ok(Box::new(TestGcGuard) as Box<dyn GcLockGuard>) })
        }

        fn list_all_roots(&self) -> BoxFuture<'_, Vec<GcRoot>> {
            Box::pin(async move {
                Ok(self
                    .state
                    .borrow()
                    .heads
                    .values()
                    .map(|h| GcRoot {
                        volume: h.volume.clone(),
                        root: h.root,
                        pinned_until: None,
                    })
                    .collect())
            })
        }

        fn list_indexed_packs(&self) -> BoxFuture<'_, HashSet<PackId>> {
            Box::pin(async move { Ok(self.state.borrow().packs.keys().cloned().collect()) })
        }

        fn prune_abandoned_ephemeral_forks(
            &self,
            _now: Timespec,
            _grace_window_secs: u64,
        ) -> BoxFuture<'_, usize> {
            Box::pin(async { Ok(0) })
        }

        fn sweep_metadata<'a>(
            &'a self,
            _keep_nodes: &'a HashSet<Digest>,
            _keep_packs: &'a HashSet<PackId>,
            _now: Timespec,
            _grace_window_secs: u64,
        ) -> BoxFuture<'a, Vec<PackId>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    #[derive(Clone, Default)]
    struct TestPackStore {
        packs: Rc<RefCell<HashMap<PackId, Vec<u8>>>>,
    }

    impl TestPackStore {
        fn new() -> Self {
            Self::default()
        }

        fn corrupt_pack_byte(&self, pack_id: &PackId, offset: usize) {
            let mut map = self.packs.borrow_mut();
            let bytes = map.get_mut(pack_id).expect("pack exists");
            bytes[offset] ^= 0xff;
        }
    }

    impl PackStore for TestPackStore {
        fn write_pack<'a>(
            &'a self,
            pack_id: &'a PackId,
            bytes: &'a [u8],
        ) -> BoxFuture<'a, PackMeta> {
            Box::pin(async move {
                let trailer = decode_pack_trailer(bytes)?;
                self.packs
                    .borrow_mut()
                    .insert(pack_id.clone(), bytes.to_vec());
                Ok(PackMeta {
                    pack_id: pack_id.clone(),
                    size: bytes.len() as u32,
                    entry_count: trailer.entries.len() as u32,
                    created_at: Timespec { sec: 0, nsec: 0 },
                })
            })
        }

        fn read_pack_range<'a>(
            &'a self,
            pack_id: &'a PackId,
            offset: u32,
            len: u32,
        ) -> BoxFuture<'a, Vec<u8>> {
            Box::pin(async move {
                let map = self.packs.borrow();
                let bytes = map.get(pack_id).ok_or(Errno::ENOENT)?;
                let start = offset as usize;
                let end = start.checked_add(len as usize).ok_or(Errno::EINVAL)?;
                if end > bytes.len() {
                    return Err(Errno::EIO);
                }
                Ok(bytes[start..end].to_vec())
            })
        }

        fn read_pack_trailer<'a>(&'a self, pack_id: &'a PackId) -> BoxFuture<'a, PackTrailer> {
            Box::pin(async move {
                let map = self.packs.borrow();
                let bytes = map.get(pack_id).ok_or(Errno::ENOENT)?;
                decode_pack_trailer(bytes)
            })
        }

        fn stat_pack<'a>(&'a self, pack_id: &'a PackId) -> BoxFuture<'a, Option<u64>> {
            Box::pin(async move { Ok(self.packs.borrow().get(pack_id).map(|b| b.len() as u64)) })
        }

        fn list_packs(&self) -> BoxFuture<'_, Vec<PackId>> {
            Box::pin(async move { Ok(self.packs.borrow().keys().cloned().collect()) })
        }

        fn delete_pack<'a>(&'a self, pack_id: &'a PackId) -> BoxFuture<'a, ()> {
            Box::pin(async move {
                self.packs.borrow_mut().remove(pack_id);
                Ok(())
            })
        }
    }

    fn block_on<F: Future>(fut: F) -> F::Output {
        vfs::now_or_never(fut).expect("memory cowfs_bridge future ready")
    }

    fn fixed_clock() -> Rc<dyn Fn() -> Timespec> {
        Rc::new(|| Timespec {
            sec: 1_700_000_000,
            nsec: 0,
        })
    }

    #[test]
    fn codex_13_open_for_boot_verifies_exact_head_and_prunes_corrupt_fork_without_leaks() {
        let hs = Rc::new(TestHeadStore::new());
        let ps = Rc::new(TestPackStore::new());
        let vol = VolumeId("vol-codex-13-boot".into());
        let now = Timespec {
            sec: 1_700_000_000,
            nsec: 0,
        };
        block_on(CowFs::format_volume(
            &*hs,
            &*ps,
            vol.clone(),
            0,
            0,
            0o755,
            now,
        ))
        .unwrap();

        // Write a 64 KiB out-of-line file so a pack is created in `ps`, then keep `tab1` holding
        // the exclusive writer lease so a second opener with `ForkOnBusy` creates a fork.
        let tab1 = block_on(CowFs::open(
            Rc::clone(&hs),
            Rc::clone(&ps),
            vol.clone(),
            CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
            CowFsConfig::local_browser(fixed_clock()),
        ))
        .unwrap();
        let admin = Cred::root();
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true);
        let (_, fd) =
            block_on(tab1.create(&admin, &tab1.root(), "payload.bin", 0o644, &opts)).unwrap();
        let payload = vec![0x5au8; 64 * 1024];
        block_on(tab1.write_at(&fd, &payload, WriteAt::Offset(0))).unwrap();
        block_on(tab1.release(&fd)).unwrap();
        block_on(tab1.commit_tx_group()).unwrap();

        // Corrupt a byte in the backing pack while `tab1` holds the writer lease.
        let packs = block_on(ps.list_packs()).unwrap();
        assert_eq!(packs.len(), 1);
        ps.corrupt_pack_byte(&packs[0], 16);

        // 1. `ForkOnBusy` boot open MUST verify the exact newly forked head, fail closed with
        //    `BootOpenError::Corrupt`, and prune the unmodified fork head without leaking it!
        let roots_before = block_on(hs.list_all_roots()).unwrap();
        let res = block_on(open_for_boot_stores_detailed(
            Rc::clone(&hs),
            Rc::clone(&ps),
            Some(vol.0.clone()),
            WriterMode::ForkOnBusy,
            None,
            None::<&vfs::imagefs::MemoryBlobStore>,
            CowFsConfig::local_browser(fixed_clock()),
            || "unused".into(),
        ));
        match res {
            Err(BootOpenError::Corrupt { volume, report }) => {
                assert!(
                    volume.starts_with(&format!("{}-fork-", vol.0)),
                    "expected verification of exact forked volume, got {volume}"
                );
                assert!(!report.ok);
                assert!(!report.errors.is_empty());
            }
            Ok(_) => panic!("corrupt ForkOnBusy volume must fail closed"),
            Err(BootOpenError::Errno(e)) => panic!("expected Corrupt, got Errno({e:?})"),
        }
        // Unmodified fork head MUST have been pruned cleanly!
        let roots_after = block_on(hs.list_all_roots()).unwrap();
        assert_eq!(
            roots_after.len(),
            roots_before.len(),
            "failed corrupt ForkOnBusy must not leak fork heads"
        );
        assert!(block_on(hs.read_head(&vol)).is_ok());

        // Release `tab1`, then test direct `Exclusive` boot open on the same corrupt volume:
        // MUST fail closed (`Errno::EIO` via `open_for_boot_stores`) AND release the writer lock!
        block_on(tab1.close_clean()).unwrap();
        let err = block_on(open_for_boot_stores(
            Rc::clone(&hs),
            Rc::clone(&ps),
            Some(vol.0.clone()),
            WriterMode::Exclusive,
            None,
            None::<&vfs::imagefs::MemoryBlobStore>,
            CowFsConfig::local_browser(fixed_clock()),
            || "unused".into(),
        ))
        .err()
        .expect("corrupt exclusive boot must fail");
        assert_eq!(err, Errno::EIO);

        // Writer lease MUST NOT be leaked: exclusive lock acquisition succeeds immediately!
        let lease = block_on(hs.acquire_writer(&vol, WriterMode::Exclusive))
            .expect("writer lease must be released when boot verification fails");
        block_on(hs.release_writer(lease)).unwrap();
    }

    #[test]
    fn codex_14_bind_dirty_flush_timer_arms_on_first_dirty_transition_of_bare_cowfs() {
        let hs = Rc::new(TestHeadStore::new());
        let ps = Rc::new(TestPackStore::new());
        let vol = VolumeId("vol-codex-14-binder".into());
        block_on(CowFs::format_volume(
            &*hs,
            &*ps,
            vol.clone(),
            0,
            0,
            0o755,
            fixed_clock()(),
        ))
        .unwrap();

        let (config, binder) = bind_dirty_flush_timer::<TestHeadStore, TestPackStore>(
            CowFsConfig::local_browser(fixed_clock()),
        );
        let fs = Rc::new(
            block_on(CowFs::open(
                Rc::clone(&hs),
                Rc::clone(&ps),
                vol,
                CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
                config,
            ))
            .unwrap(),
        );
        let guard = binder.attach(&fs);
        // Binder uses `Weak<CowFs>`, so `fs` has no Rc reference cycle!
        assert_eq!(Rc::strong_count(&fs), 1);
        assert_eq!(guard.armed_count(), 0);

        let admin = Cred::root();
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true);

        // First write on bare `CowFs` automatically arms the dirty timer.
        let (_, fd1) = block_on(fs.create(&admin, &fs.root(), "f1.txt", 0o644, &opts)).unwrap();
        block_on(fs.write_at(&fd1, b"abc", WriteAt::Offset(0))).unwrap();
        block_on(fs.release(&fd1)).unwrap();
        assert_eq!(guard.armed_count(), 1);

        // Second write while already dirty does not re-arm redundantly.
        let (_, fd2) = block_on(fs.create(&admin, &fs.root(), "f2.txt", 0o644, &opts)).unwrap();
        block_on(fs.write_at(&fd2, b"def", WriteAt::Offset(0))).unwrap();
        block_on(fs.release(&fd2)).unwrap();
        assert_eq!(guard.armed_count(), 1);

        // Commit resets dirty state; next write arms again!
        block_on(fs.commit_tx_group()).unwrap();
        let (_, fd3) = block_on(fs.create(&admin, &fs.root(), "f3.txt", 0o644, &opts)).unwrap();
        block_on(fs.write_at(&fd3, b"ghi", WriteAt::Offset(0))).unwrap();
        block_on(fs.release(&fd3)).unwrap();
        assert_eq!(guard.armed_count(), 2);

        // Canceling the guard prevents any further arming.
        guard.cancel();
        block_on(fs.commit_tx_group()).unwrap();
        let (_, fd4) = block_on(fs.create(&admin, &fs.root(), "f4.txt", 0o644, &opts)).unwrap();
        block_on(fs.write_at(&fd4, b"jkl", WriteAt::Offset(0))).unwrap();
        block_on(fs.release(&fd4)).unwrap();
        assert_eq!(guard.armed_count(), 2);

        block_on(fs.close_clean()).unwrap();
    }
}
