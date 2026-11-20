//! Thin `wasm-bindgen` bridge connecting portable `os-cowtree` / `os-cowfs` + `os-vfs` (`/dev/vdN`)
//! to the browser OPFS + IndexedDB + Web Locks adapter (`web/kernel/cowfs-store.js`, #77).
//!
//! Zero filesystem policy lives in JavaScript: all B+tree verification, POSIX permissions/ACLs/
//! xattrs, `DIR_INDEX` paging, `ORPHAN_ITEM` reaping, `FICLONE`, `32 MiB` slab arena accounting,
//! reachability GC, `cowfsck`, and `/dev/vdN` ioctl authorization run in portable Rust.

use crate::mounts::{extract_js_errno, js_errno, map_vfs_err, parse_identity};
use abi::Errno;
use abi::fs::{OpenOptions, RenameFlags, SetAttr, Timespec, XattrFlags};
use cowfs::{CowFs, CowFsConfig, CowFsOpenMode, CowFsVolumeDevice, cowfs_ioctl_mounted};
use cowtree::pack::{PACK_FOOTER_BYTES, decode_pack_footer, decode_pack_trailer_bytes};
use cowtree::{
    ArenaConfig, BlockLoc, CommitRequest, Digest, ForkRequest, GcLockGuard, GcRoot, HeadStore,
    PACK_MAX_BYTES, PackId, PackMeta, PackStore, PackTrailer, SnapshotRecord, VolumeHead, VolumeId,
    WriterLease, WriterLockGuard, WriterMode, digest_to_hex,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::cell::Cell;
use std::collections::HashSet;
use std::rc::Rc;
use vfs::devfs::{DefaultDeviceBackend, DevTmpFs};
use vfs::vblk::{VblkDeviceBackend, VblkRegistry};
use vfs::{
    BoxFuture, Cred, DefaultFilesystemFactory, Filesystem, FsId, FsType, MountBacking, StartAnchor,
    Vfs,
};
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

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

fn now_timespec() -> Timespec {
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

fn to_js_json<T: Serialize>(value: &T) -> Result<JsValue, JsValue> {
    let s = serde_json::to_string(value).map_err(|_| js_errno(Errno::EIO, "serialize"))?;
    js_sys::JSON::parse(&s).map_err(|_| js_errno(Errno::EIO, "json parse"))
}

fn from_js_json<T: for<'de> Deserialize<'de>>(val: &JsValue) -> vfs::Result<T> {
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
struct JsCowfsStore {
    obj: JsValue,
}

struct JsWriterGuard {
    store: JsValue,
    lease_id: String,
    released: Rc<Cell<bool>>,
}

impl WriterLockGuard for JsWriterGuard {}

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

    fn sweep_metadata<'a>(
        &'a self,
        keep_nodes: &'a HashSet<Digest>,
        keep_packs: &'a HashSet<PackId>,
        grace_before: Timespec,
    ) -> BoxFuture<'a, Vec<PackId>> {
        Box::pin(async move {
            let keep_nodes_hex: Vec<String> = keep_nodes.iter().map(digest_to_hex).collect();
            let keep_packs_str: Vec<&str> = keep_packs.iter().map(|p| p.0.as_str()).collect();
            let payload = serde_json::to_string(&json!({
                "keepNodes": keep_nodes_hex,
                "keepPacks": keep_packs_str,
                "graceBefore": grace_before,
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
    let report = cowfs::verify_volume(&adapter, &adapter, &VolumeId(volume_id))
        .await
        .map_err(map_vfs_err)?;
    to_js_json(&report)
}

/// Run reachability GC over `store`, sweeping unreachable nodes/packs older than `grace_before_sec`.
#[wasm_bindgen]
pub async fn cowfs_collect_garbage(
    store: JsValue,
    grace_before_sec: f64,
) -> Result<JsValue, JsValue> {
    let adapter = JsCowfsStore { obj: store };
    let sec = if grace_before_sec.is_finite() && grace_before_sec >= 0.0 {
        grace_before_sec as u64
    } else {
        0
    };
    let report = cowfs::collect_garbage(&adapter, &adapter, Timespec { sec, nsec: 0 })
        .await
        .map_err(map_vfs_err)?;
    to_js_json(&report)
}

/// Mounted `os-cowfs` volume handle exposed to browser JS/Workers (backed by portable `CowFs` +
/// `os_vfs::Vfs` + `/dev/vd0` `VblkRegistry`).
#[wasm_bindgen]
pub struct CowFsVolume {
    fs: Rc<CowFs<JsCowfsStore, JsCowfsStore>>,
    vfs: Vfs,
    vblk: VblkRegistry,
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

    /// Open a volume read-only (acquires NO writer lock; uses lock-free `getFile().slice()`).
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
        let config = CowFsConfig::local_browser(Rc::new(now_timespec))
            .with_arena(ArenaConfig::fixed_32mib());
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

        let backing = Rc::new(MountBacking::new(fs.clone(), FsType::Cowfs));
        let factory = Rc::new(DefaultFilesystemFactory::new(Rc::new(|| {
            let ts = now_timespec();
            (ts.sec, ts.nsec)
        })));
        let vfs = Vfs::boot("cowfs-browser", backing, "cowfs", factory)
            .await
            .map_err(map_vfs_err)?;

        // Wire `/dev` with `/dev/vd0` pointing to this volume for `BLK_INFO` / `COWFS_IOC_*` / `mkfs` tests.
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
        let _ = dev_fs.register_vblk(&vd_name, 0o660);
        // Mount `/dev` if `/dev` exists or mount lazily on demand (keep root clean for POSIX tests).
        let _ = dev_fs;

        Ok(CowFsVolume { fs, vfs, vblk })
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
        let pid = self.ensure_pid(&cred);
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
        let pid = self.ensure_pid(&cred);
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
        let cred = self.cred_or_root(&identity)?;
        let pid = self.ensure_pid(&cred);
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
        let res = self.vfs.pwrite(pid, fd, bytes, offset as u64).await;
        let _ = self.vfs.close(pid, fd).await;
        res.map_err(map_vfs_err)
    }

    pub async fn read_file(&self, path: String, identity: JsValue) -> Result<Vec<u8>, JsValue> {
        let cred = self.cred_or_root(&identity)?;
        let pid = self.ensure_pid(&cred);
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
        let cred = self.cred_or_root(&identity)?;
        let pid = self.ensure_pid(&cred);
        let fd = self
            .vfs
            .openat(pid, StartAnchor::Root, &path, abi::O_RDONLY, 0)
            .await
            .map_err(map_vfs_err)?;
        let mut buf = vec![0u8; len];
        let res = self.vfs.pread(pid, fd, &mut buf, offset as u64).await;
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
        let cred = self.cred_or_root(&identity)?;
        let pid = self.ensure_pid(&cred);
        self.vfs
            .setattrat(
                pid,
                StartAnchor::Root,
                &path,
                &SetAttr {
                    size: Some(size as u64),
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
        let pid = self.ensure_pid(&cred);
        let st = self
            .vfs
            .statat(pid, StartAnchor::Root, &path, follow)
            .await
            .map_err(map_vfs_err)?;
        to_js_json(&st)
    }

    pub async fn chmod(&self, path: String, mode: u16, identity: JsValue) -> Result<(), JsValue> {
        let cred = self.cred_or_root(&identity)?;
        let pid = self.ensure_pid(&cred);
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
        let pid = self.ensure_pid(&cred);
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
        let pid = self.ensure_pid(&cred);
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
        let pid = self.ensure_pid(&cred);
        self.vfs
            .symlinkat(pid, &target, StartAnchor::Root, &linkpath)
            .await
            .map(|_| ())
            .map_err(map_vfs_err)
    }

    pub async fn readlink(&self, path: String, identity: JsValue) -> Result<String, JsValue> {
        let cred = self.cred_or_root(&identity)?;
        let pid = self.ensure_pid(&cred);
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
        let pid = self.ensure_pid(&cred);
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
        let pid = self.ensure_pid(&cred);
        self.vfs
            .unlinkat(pid, StartAnchor::Root, &path, false)
            .await
            .map_err(map_vfs_err)
    }

    pub async fn rmdir(&self, path: String, identity: JsValue) -> Result<(), JsValue> {
        let cred = self.cred_or_root(&identity)?;
        let pid = self.ensure_pid(&cred);
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
        let pid = self.ensure_pid(&cred);
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
        let cred = self.cred_or_root(&identity)?;
        let pid = self.ensure_pid(&cred);
        let page = self
            .vfs
            .read_dir_page(pid, StartAnchor::Root, &path, cookie as u64, max_entries)
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
        let pid = self.ensure_pid(&cred);
        let fd = self
            .vfs
            .openat(pid, StartAnchor::Root, &path, flags, mode)
            .await
            .map_err(map_vfs_err)?;
        Ok(fd)
    }

    pub async fn fd_read_at(
        &self,
        fd: u32,
        offset: f64,
        len: usize,
        identity: JsValue,
    ) -> Result<Vec<u8>, JsValue> {
        let cred = self.cred_or_root(&identity)?;
        let pid = self.ensure_pid(&cred);
        let mut buf = vec![0u8; len];
        let n = self
            .vfs
            .pread(pid, fd, &mut buf, offset as u64)
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
        let cred = self.cred_or_root(&identity)?;
        let pid = self.ensure_pid(&cred);
        self.vfs
            .pwrite(pid, fd, bytes, offset as u64)
            .await
            .map_err(map_vfs_err)
    }

    pub async fn fd_close(&self, fd: u32, identity: JsValue) -> Result<(), JsValue> {
        let cred = self.cred_or_root(&identity)?;
        let pid = self.ensure_pid(&cred);
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
        let pid = self.ensure_pid(&cred);
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
        let pid = self.ensure_pid(&cred);
        let resp = self
            .vblk
            .mkfs_cowfs(&self.vfs, pid, &target, force)
            .await
            .map_err(map_vfs_err)?;
        to_js_json(&resp)
    }

    pub async fn close_clean(&self) -> Result<(), JsValue> {
        self.fs.close_clean().await.map_err(map_vfs_err)
    }

    // Internal helpers
    fn cred_or_root(&self, identity: &JsValue) -> Result<Cred, JsValue> {
        if identity.is_undefined() || identity.is_null() {
            Ok(Cred::root())
        } else {
            Ok(Cred::new(parse_identity(identity)?))
        }
    }

    fn ensure_pid(&self, cred: &Cred) -> u32 {
        let pid = if cred.identity.id == 0 {
            1
        } else {
            1000 + (cred.identity.id % 10_000)
        };
        if self.vfs.process_cred(pid).is_err() {
            let _ = self.vfs.fork_process(1, pid, 0);
        }
        let _ = self.vfs.set_cred(pid, cred.clone());
        pid
    }
}
