//! Ephemeral, isolated browser/Node WASM `SandboxKernel` for `kubelet` task execution (#84).
//!
//! Instantiated by `kubelet-agent.js` with ZERO shared state with the tab's host OS kernel:
//! - Fresh `LocalProcessTable` (PID 1 only, `memory.max` & `pids.max` enforced on `/`)
//! - Fresh `Vfs` + `MountNamespace` over an O(1)-forked `cowfs` root (`SandboxCowStore`)
//! - Minimal `/dev` (`null`, `zero`, `full`, `random`, `urandom` ONLY — zero host devices!)
//! - Isolated `/proc` (PID 1 only), fresh `tmpfs` `/tmp`, strictly read-only `/input` (lazy
//!   range-verified OCI snapshot and/or `extra_inputs` at `/input/<name>`), writable `cowfs` `/output`
//! - Explicit rejection of ELF (`\x7fELF`) and non-Wasm binaries with `Errno::ENOEXEC`
//! - Direct `cowfs::push_cowfs_snapshot` staging with attempt-unique manifest annotations.

use crate::vfs_engine::{json_to_js, map_errno, wasi_errno_num};
use abi::Errno;
use abi::contract::{InstanceIdentity, mount_flags};
use abi::fs::Timespec;
use abi::registry::{
    COWFS_SNAPSHOT_ARTIFACT_TYPE, COWFS_SNAPSHOT_CONFIG_MEDIA_TYPE, OciImageConfig,
    OciImageManifest, OciReference, parse_sha256_digest,
};
use cowfs::{
    CowFs, CowFsConfig, CowFsOpenMode, OciClient, OciHttpReply, OciPushOptions,
    OciTarImportOptions, OciTarLayerInput, OciTransport, import_oci_tar_layers,
    open_oci_snapshot_cowfs, pull_cowfs_snapshot, push_cowfs_snapshot,
};
use cowtree::pack::decode_pack_trailer;
use cowtree::{
    BlockLoc, COWFS_FORMAT_VERSION, CommitRequest, Digest, ForkRequest, GcLockGuard, GcRoot,
    HeadStore, PackId, PackMeta, PackStore, PackTrailer, ReceiveCommitRequest, RoPinGuard,
    SnapshotRecord, VolumeHead, VolumeId, WriterLease, WriterLockGuard, WriterMode,
};
use js_sys::{Array, Function, Object, Promise, Reflect, Uint8Array};
use kernel::proc_table::{LocalProcessTable, ReexecSpec};
use os_core::permissions::Identity;
use serde::Deserialize;
use serde_json::{Value, json};
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::rc::Rc;
use vfs::devfs::{DefaultDeviceBackend, DevTmpFs};
use vfs::memfs::MemFs;
use vfs::procfs::{EmptyProcProvider, ProcFs, ProcMetaSnapshot};
use vfs::{
    BoxFuture, Cred, DefaultFilesystemFactory, FileType, Filesystem, FsId, FsType, MountBacking,
    MountFlags, SeekFrom, StartAnchor, Vfs,
};
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

const SANDBOX_HOST_LABEL: &str = "browser-sandbox";
const MAX_SUMMARY_BYTES: usize = 4 * 1024;

struct EphemeralGuard;
impl WriterLockGuard for EphemeralGuard {}
impl GcLockGuard for EphemeralGuard {}
impl RoPinGuard for EphemeralGuard {}

/// Per-attempt ephemeral `HeadStore` + `PackStore` strictly scoped to a single `SandboxKernel`.
/// Never shared with or used as a fallback for the tab's persistent root OS volume.
#[derive(Default)]
struct SandboxCowStoreInner {
    volumes: HashMap<VolumeId, VolumeHead>,
    snapshots: HashMap<(VolumeId, String), SnapshotRecord>,
    nodes: HashMap<Digest, Vec<u8>>,
    packs: HashMap<PackId, (PackMeta, Vec<u8>)>,
    blocks: HashMap<Digest, BlockLoc>,
}

#[derive(Default)]
struct SandboxCowStore {
    inner: RefCell<SandboxCowStoreInner>,
}

impl HeadStore for SandboxCowStore {
    fn format_version(&self) -> BoxFuture<'_, Option<u32>> {
        Box::pin(async { Ok(Some(COWFS_FORMAT_VERSION)) })
    }

    fn grace_window_secs(&self) -> u64 {
        0
    }

    fn create_volume<'a>(
        &'a self,
        head: &'a VolumeHead,
        initial_nodes: &'a [(Digest, Vec<u8>)],
    ) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async move {
            let mut st = self.inner.borrow_mut();
            if st.volumes.contains_key(&head.volume) {
                return Err(Errno::EEXIST);
            }
            for (d, raw) in initial_nodes {
                st.nodes.insert(*d, raw.clone());
            }
            st.volumes.insert(head.volume.clone(), head.clone());
            Ok(head.clone())
        })
    }

    fn read_head<'a>(&'a self, volume: &'a VolumeId) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async move {
            self.inner
                .borrow()
                .volumes
                .get(volume)
                .cloned()
                .ok_or(Errno::ENOENT)
        })
    }

    fn list_volumes(&self) -> BoxFuture<'_, Vec<VolumeHead>> {
        Box::pin(async move { Ok(self.inner.borrow().volumes.values().cloned().collect()) })
    }

    fn commit_received_root<'a>(
        &'a self,
        req: &'a ReceiveCommitRequest,
    ) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async move {
            let mut st = self.inner.borrow_mut();
            for (d, raw) in &req.put_nodes {
                st.nodes.insert(*d, raw.clone());
            }
            for (d, loc) in &req.put_blocks {
                st.blocks.insert(*d, loc.clone());
            }
            let next_head = if let Some(prev) = st.volumes.get(&req.volume) {
                VolumeHead {
                    format_version: COWFS_FORMAT_VERSION,
                    volume: req.volume.clone(),
                    incarnation: prev.incarnation,
                    fence: prev.fence,
                    epoch: prev.epoch.saturating_add(1),
                    root: req.new_root,
                    parent_volume: prev.parent_volume.clone(),
                    ephemeral_if_unmodified: false,
                    modified: true,
                    updated_at: req.committed_at,
                }
            } else {
                VolumeHead {
                    format_version: COWFS_FORMAT_VERSION,
                    volume: req.volume.clone(),
                    incarnation: 1,
                    fence: 1,
                    epoch: 1,
                    root: req.new_root,
                    parent_volume: None,
                    ephemeral_if_unmodified: false,
                    modified: true,
                    updated_at: req.committed_at,
                }
            };
            st.volumes.insert(req.volume.clone(), next_head.clone());
            if let Some(ref snap) = req.snapshot_name {
                st.snapshots.insert(
                    (req.volume.clone(), snap.clone()),
                    SnapshotRecord {
                        volume: req.volume.clone(),
                        name: snap.clone(),
                        root: next_head.root,
                        epoch: next_head.epoch,
                        created_at: req.committed_at,
                    },
                );
            }
            Ok(next_head)
        })
    }

    fn stage_objects<'a>(
        &'a self,
        nodes: &'a [(Digest, Vec<u8>)],
        _packs: &'a [PackMeta],
        blocks: &'a [(Digest, BlockLoc)],
        _now: Timespec,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let mut st = self.inner.borrow_mut();
            for (d, raw) in nodes {
                st.nodes.insert(*d, raw.clone());
            }
            for (d, loc) in blocks {
                st.blocks.insert(*d, loc.clone());
            }
            Ok(())
        })
    }

    fn pin_ro_root<'a>(
        &'a self,
        volume: &'a VolumeId,
        snapshot: Option<&'a str>,
    ) -> BoxFuture<'a, (VolumeHead, Box<dyn RoPinGuard>)> {
        Box::pin(async move {
            let st = self.inner.borrow();
            let mut head = st.volumes.get(volume).cloned().ok_or(Errno::ENOENT)?;
            if let Some(snap_name) = snapshot {
                let snap = st
                    .snapshots
                    .get(&(volume.clone(), snap_name.to_string()))
                    .ok_or(Errno::ENOENT)?;
                head.root = snap.root;
                head.epoch = snap.epoch;
            }
            Ok((head, Box::new(EphemeralGuard) as Box<dyn RoPinGuard>))
        })
    }

    fn unpin_ro_root<'a>(&'a self, _pin: Box<dyn RoPinGuard>) -> BoxFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn acquire_writer<'a>(
        &'a self,
        volume: &'a VolumeId,
        _mode: WriterMode,
    ) -> BoxFuture<'a, WriterLease> {
        Box::pin(async move {
            let mut st = self.inner.borrow_mut();
            let head = st.volumes.get_mut(volume).ok_or(Errno::ENOENT)?;
            head.fence = head.fence.saturating_add(1);
            let h = head.clone();
            Ok(WriterLease {
                volume: h.volume.clone(),
                incarnation: h.incarnation,
                fence: h.fence,
                epoch: h.epoch,
                head: h,
                forked_from: None,
                expires_at: None,
                guard: Rc::new(EphemeralGuard),
            })
        })
    }

    fn renew_writer<'a>(&'a self, _lease: &'a mut WriterLease) -> BoxFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn release_writer<'a>(&'a self, _lease: WriterLease) -> BoxFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }

    fn get_node<'a>(&'a self, digest: &'a Digest) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(async move {
            self.inner
                .borrow()
                .nodes
                .get(digest)
                .cloned()
                .ok_or(Errno::ENOENT)
        })
    }

    fn lookup_block<'a>(&'a self, digest: &'a Digest) -> BoxFuture<'a, Option<BlockLoc>> {
        Box::pin(async move { Ok(self.inner.borrow().blocks.get(digest).cloned()) })
    }

    fn commit_head<'a>(&'a self, req: &'a CommitRequest) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async move {
            let mut st = self.inner.borrow_mut();
            for (d, raw) in &req.put_nodes {
                st.nodes.insert(*d, raw.clone());
            }
            for (d, loc) in &req.put_blocks {
                st.blocks.insert(*d, loc.clone());
            }
            let head = st.volumes.get_mut(&req.volume).ok_or(Errno::ENOENT)?;
            if head.incarnation != req.expected_incarnation
                || head.fence != req.expected_fence
                || head.epoch != req.expected_epoch
            {
                return Err(Errno::ESTALE);
            }
            head.epoch = head.epoch.saturating_add(1);
            head.root = req.new_root;
            head.modified = true;
            head.updated_at = req.committed_at;
            Ok(head.clone())
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
            let rec = SnapshotRecord {
                volume: volume.clone(),
                name: name.to_string(),
                root: head.root,
                epoch: head.epoch,
                created_at: now,
            };
            self.inner
                .borrow_mut()
                .snapshots
                .insert((volume.clone(), name.to_string()), rec.clone());
            Ok(rec)
        })
    }

    fn get_snapshot<'a>(
        &'a self,
        volume: &'a VolumeId,
        name: &'a str,
    ) -> BoxFuture<'a, SnapshotRecord> {
        Box::pin(async move {
            self.inner
                .borrow()
                .snapshots
                .get(&(volume.clone(), name.to_string()))
                .cloned()
                .ok_or(Errno::ENOENT)
        })
    }

    fn list_snapshots<'a>(&'a self, volume: &'a VolumeId) -> BoxFuture<'a, Vec<SnapshotRecord>> {
        Box::pin(async move {
            Ok(self
                .inner
                .borrow()
                .snapshots
                .iter()
                .filter(|((v, _), _)| v == volume)
                .map(|(_, r)| r.clone())
                .collect())
        })
    }

    fn delete_snapshot<'a>(&'a self, volume: &'a VolumeId, name: &'a str) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.inner
                .borrow_mut()
                .snapshots
                .remove(&(volume.clone(), name.to_string()));
            Ok(())
        })
    }

    fn fork_volume<'a>(&'a self, req: &'a ForkRequest) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async move {
            let mut st = self.inner.borrow_mut();
            if st.volumes.contains_key(&req.new_volume) {
                return Err(Errno::EEXIST);
            }
            let head = VolumeHead {
                format_version: COWFS_FORMAT_VERSION,
                volume: req.new_volume.clone(),
                incarnation: 1,
                fence: 0,
                epoch: 0,
                root: req.source_root,
                parent_volume: Some(req.source_volume.clone()),
                ephemeral_if_unmodified: req.ephemeral_if_unmodified,
                modified: false,
                updated_at: req.created_at,
            };
            st.volumes.insert(req.new_volume.clone(), head.clone());
            Ok(head)
        })
    }

    fn delete_volume<'a>(&'a self, volume: &'a VolumeId) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let mut st = self.inner.borrow_mut();
            st.volumes.remove(volume);
            st.snapshots.retain(|(v, _), _| v != volume);
            Ok(())
        })
    }

    fn delete_volume_with_lease<'a>(
        &'a self,
        lease: WriterLease,
        _only_if_unmodified_ephemeral: bool,
    ) -> BoxFuture<'a, bool> {
        Box::pin(async move {
            let removed = self
                .inner
                .borrow_mut()
                .volumes
                .remove(&lease.volume)
                .is_some();
            Ok(removed)
        })
    }

    fn reformat_volume_with_lease<'a>(
        &'a self,
        _lease: WriterLease,
        _new_head: &'a VolumeHead,
        _initial_nodes: &'a [(Digest, Vec<u8>)],
    ) -> BoxFuture<'a, VolumeHead> {
        Box::pin(async { Err(Errno::EOPNOTSUPP) })
    }

    fn acquire_gc_lock(&self, _exclusive: bool) -> BoxFuture<'_, Box<dyn GcLockGuard>> {
        Box::pin(async { Ok(Box::new(EphemeralGuard) as Box<dyn GcLockGuard>) })
    }

    fn list_all_roots(&self) -> BoxFuture<'_, Vec<GcRoot>> {
        Box::pin(async move {
            let st = self.inner.borrow();
            let mut roots = Vec::new();
            for h in st.volumes.values() {
                roots.push(GcRoot {
                    volume: h.volume.clone(),
                    root: h.root,
                    pinned_until: None,
                });
            }
            for s in st.snapshots.values() {
                roots.push(GcRoot {
                    volume: s.volume.clone(),
                    root: s.root,
                    pinned_until: None,
                });
            }
            Ok(roots)
        })
    }

    fn list_indexed_packs(&self) -> BoxFuture<'_, HashSet<PackId>> {
        Box::pin(async move { Ok(self.inner.borrow().packs.keys().cloned().collect()) })
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

impl PackStore for SandboxCowStore {
    fn write_pack<'a>(&'a self, pack_id: &'a PackId, bytes: &'a [u8]) -> BoxFuture<'a, PackMeta> {
        Box::pin(async move {
            let entry_count = decode_pack_trailer(bytes)
                .map(|t| t.entries.len() as u32)
                .unwrap_or(0);
            let meta = PackMeta {
                pack_id: pack_id.clone(),
                size: bytes.len() as u32,
                entry_count,
                created_at: Timespec {
                    sec: crate::now_secs(),
                    nsec: 0,
                },
            };
            self.inner
                .borrow_mut()
                .packs
                .insert(pack_id.clone(), (meta.clone(), bytes.to_vec()));
            Ok(meta)
        })
    }

    fn read_pack_range<'a>(
        &'a self,
        pack_id: &'a PackId,
        offset: u32,
        len: u32,
    ) -> BoxFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let st = self.inner.borrow();
            let (_, bytes) = st.packs.get(pack_id).ok_or(Errno::ENOENT)?;
            let start = offset as usize;
            let end = start.checked_add(len as usize).ok_or(Errno::EIO)?;
            if end > bytes.len() {
                return Err(Errno::EIO);
            }
            Ok(bytes[start..end].to_vec())
        })
    }

    fn read_pack_trailer<'a>(&'a self, pack_id: &'a PackId) -> BoxFuture<'a, PackTrailer> {
        Box::pin(async move {
            let st = self.inner.borrow();
            let (_, bytes) = st.packs.get(pack_id).ok_or(Errno::ENOENT)?;
            decode_pack_trailer(bytes)
        })
    }

    fn stat_pack<'a>(&'a self, pack_id: &'a PackId) -> BoxFuture<'a, Option<u64>> {
        Box::pin(async move {
            Ok(self
                .inner
                .borrow()
                .packs
                .get(pack_id)
                .map(|(_, b)| b.len() as u64))
        })
    }

    fn list_packs(&self) -> BoxFuture<'_, Vec<PackId>> {
        Box::pin(async move { Ok(self.inner.borrow().packs.keys().cloned().collect()) })
    }

    fn delete_pack<'a>(&'a self, pack_id: &'a PackId) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.inner.borrow_mut().packs.remove(pack_id);
            Ok(())
        })
    }
}

/// OCI HTTP transport scoped strictly to one sandbox attempt's derived storage credential.
struct SandboxOciTransport {
    fetch_fn: Function,
    token: String,
    instance_id: String,
}

impl OciTransport for SandboxOciTransport {
    fn request<'a>(
        &'a self,
        method: &'a str,
        url: &'a str,
        headers: &'a [(String, String)],
        body: &'a [u8],
    ) -> BoxFuture<'a, OciHttpReply> {
        let method_s = method.to_string();
        let url_s = url.to_string();
        let hdrs = headers.to_vec();
        let body_v = body.to_vec();
        Box::pin(async move {
            let fields = Object::new();
            for (k, v) in &hdrs {
                Reflect::set(&fields, &k.as_str().into(), &v.as_str().into())
                    .map_err(|_| Errno::EINVAL)?;
            }
            let args = Array::new();
            args.push(&JsValue::from_str(&method_s));
            args.push(&JsValue::from_str(&url_s));
            args.push(&fields);
            args.push(&Uint8Array::from(body_v.as_slice()));
            let raw = self
                .fetch_fn
                .apply(&JsValue::UNDEFINED, &args)
                .map_err(|_| Errno::ENOTCONN)?;
            let reply = JsFuture::from(Promise::resolve(&raw))
                .await
                .map_err(|_| Errno::ENOTCONN)?;
            let get = |k: &str| Reflect::get(&reply, &k.into()).map_err(|_| Errno::EIO);
            let status = get("status")?.as_f64().ok_or(Errno::EIO)? as u16;
            let raw_headers = get("headers")?;
            let mut out_headers = Vec::new();
            if Array::is_array(&raw_headers) {
                let arr = Array::from(&raw_headers);
                for i in 0..arr.length() {
                    let pair = arr.get(i);
                    if Array::is_array(&pair) {
                        let p = Array::from(&pair);
                        if let (Some(k), Some(v)) = (p.get(0).as_string(), p.get(1).as_string()) {
                            out_headers.push((k, v));
                        }
                    }
                }
            }
            let body_bytes = get("body")?
                .dyn_into::<Uint8Array>()
                .map_err(|_| Errno::EIO)?
                .to_vec();
            Ok(OciHttpReply {
                status,
                headers: out_headers,
                body: body_bytes,
            })
        })
    }

    fn token_auth_headers(&self) -> Vec<(String, String)> {
        vec![
            ("X-OS-Instance".into(), self.instance_id.clone()),
            ("X-Process-Token".into(), self.token.clone()),
        ]
    }
}

#[derive(Deserialize)]
struct SandboxBootConfig {
    workload_id: String,
    attempt_generation: u64,
    #[serde(default)]
    node_generation: u64,
    node_id: String,
    image_ref: String,
    entrypoint: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    #[serde(default)]
    input_ref: Option<String>,
    #[serde(default)]
    extra_inputs: BTreeMap<String, String>,
    base_url: String,
    storage_token: String,
    instance_id: String,
    #[serde(default = "default_mem_max")]
    memory_max_bytes: u64,
    #[serde(default = "default_pids_max")]
    pids_max: u32,
}

fn default_mem_max() -> u64 {
    64 * 1024 * 1024
}
fn default_pids_max() -> u32 {
    8
}

fn sandbox_clock() -> Rc<dyn Fn() -> Timespec> {
    Rc::new(|| Timespec {
        sec: crate::now_secs(),
        nsec: 0,
    })
}

fn sandbox_cowfs_cfg() -> CowFsConfig {
    CowFsConfig::local_browser(sandbox_clock())
}

fn wasi_errno(e: Errno) -> u16 {
    wasi_errno_num(e) as u16
}

fn wasi_filetype(ft: FileType) -> u8 {
    match ft {
        FileType::Dir => 3,
        FileType::File => 4,
        FileType::Symlink => 7,
        FileType::CharDevice => 2,
        FileType::Socket => 6,
    }
}

async fn pull_image_into_sandbox(
    store: &Rc<SandboxCowStore>,
    client: &OciClient<SandboxOciTransport>,
    image_ref: &str,
) -> Result<(VolumeId, String), Errno> {
    let parsed = OciReference::parse(image_ref).ok_or(Errno::EINVAL)?;
    let (digest, _mt, raw_manifest) = client.get_manifest(&parsed.repo, &parsed.reference).await?;
    let hex = parse_sha256_digest(&digest).ok_or(Errno::EIO)?;
    let vol = VolumeId(format!("img:{hex}"));
    let snap = "base".to_string();

    let val: Value = image::parse(&raw_manifest).map_err(|_| Errno::EIO)?;
    let obj = val.as_object().ok_or(Errno::EIO)?;
    let is_cowfs_snapshot = if obj.contains_key("manifests") {
        obj.get("artifactType").and_then(|v| v.as_str()) == Some(COWFS_SNAPSHOT_ARTIFACT_TYPE)
    } else {
        let art =
            obj.get("artifactType").and_then(|v| v.as_str()) == Some(COWFS_SNAPSHOT_ARTIFACT_TYPE);
        let cfg = obj
            .get("config")
            .and_then(|c| c.get("mediaType"))
            .and_then(|v| v.as_str())
            == Some(COWFS_SNAPSHOT_CONFIG_MEDIA_TYPE);
        art || cfg
    };

    let now = Timespec {
        sec: crate::now_secs(),
        nsec: 0,
    };
    if is_cowfs_snapshot {
        pull_cowfs_snapshot(
            client,
            &parsed.repo,
            &digest,
            &**store,
            &**store,
            &vol,
            Some(&snap),
            now,
            None,
        )
        .await?;
    } else {
        let manifest: OciImageManifest = serde_json::from_value(val).map_err(|_| Errno::EINVAL)?;
        let cfg_bytes = client
            .get_blob(&parsed.repo, &manifest.config.digest)
            .await?;
        let cfg: OciImageConfig = image::parse(&cfg_bytes).map_err(|_| Errno::EINVAL)?;
        let mut layer_blobs = Vec::with_capacity(manifest.layers.len());
        for desc in &manifest.layers {
            layer_blobs.push(client.get_blob(&parsed.repo, &desc.digest).await?);
        }
        let inputs: Vec<OciTarLayerInput<'_>> = layer_blobs
            .iter()
            .enumerate()
            .map(|(idx, bytes)| OciTarLayerInput {
                bytes: bytes.as_slice(),
                expected_diff_id: cfg.rootfs.diff_ids.get(idx).map(String::as_str),
            })
            .collect();
        import_oci_tar_layers(
            Rc::clone(store),
            Rc::clone(store),
            vol.clone(),
            &inputs,
            &OciTarImportOptions::default(), // StrictConfined + SetuidPolicy::Reject
            Some(&snap),
            sandbox_cowfs_cfg(),
        )
        .await?;
    }
    Ok((vol, snap))
}

async fn mount_oci_ro_input(
    client: OciClient<SandboxOciTransport>,
    raw_ref: &str,
) -> Result<Rc<MountBacking>, Errno> {
    let parsed = OciReference::parse(raw_ref).ok_or(Errno::EINVAL)?;
    let fs = Rc::new(
        open_oci_snapshot_cowfs(client, &parsed.repo, &parsed.reference, sandbox_cowfs_cfg())
            .await?,
    );
    Ok(Rc::new(
        MountBacking::new(fs as Rc<dyn Filesystem>, FsType::Cowfs).with_ceilings(true, true),
    ))
}

#[derive(Clone)]
struct SandboxGuestFd {
    kfd: u32,
    is_dir: bool,
}

/// Isolated per-attempt browser/Node WASM sandbox kernel (`#[wasm_bindgen]`).
#[wasm_bindgen]
pub struct SandboxKernel {
    vfs: Vfs,
    _proc_table: Rc<RefCell<LocalProcessTable>>,
    store: Rc<SandboxCowStore>,
    root_fs: Rc<CowFs<SandboxCowStore, SandboxCowStore>>,
    output_fs: Rc<CowFs<SandboxCowStore, SandboxCowStore>>,
    output_vol: VolumeId,
    oci_client: OciClient<SandboxOciTransport>,
    wasm_bytes: Vec<u8>,
    argv: Vec<String>,
    env: Vec<String>,
    memory_max_bytes: u64,
    guest_fds: RefCell<BTreeMap<u32, SandboxGuestFd>>,
    stdout_buf: RefCell<Vec<u8>>,
    stderr_buf: RefCell<Vec<u8>>,
}

fn valid_input_mount_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name != "."
        && name != ".."
        && name != "primary"
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

#[wasm_bindgen]
impl SandboxKernel {
    /// Boot an isolated ephemeral `SandboxKernel` for a single kubelet attempt.
    /// Rejects ELF (`\x7fELF`) binaries with `ENOEXEC`.
    pub async fn boot(config_json: &str, oci_fetch: Function) -> Result<SandboxKernel, JsValue> {
        let cfg: SandboxBootConfig =
            serde_json::from_str(config_json).map_err(|_| map_errno(Errno::EINVAL))?;
        if !cfg.entrypoint.starts_with('/')
            || cfg.entrypoint.len() > 512
            || cfg.entrypoint.contains('\0')
            || cfg.entrypoint.split('/').any(|s| s == "..")
            || cfg.memory_max_bytes < 1024 * 1024
            || cfg.memory_max_bytes > 512 * 1024 * 1024
            || cfg.pids_max == 0
            || cfg.pids_max > 256
            || cfg.extra_inputs.len() > 16
            || cfg.extra_inputs.keys().any(|k| !valid_input_mount_name(k))
        {
            return Err(map_errno(Errno::EINVAL));
        }
        let boot_ts = Timespec {
            sec: crate::now_secs(),
            nsec: 0,
        };
        let store = Rc::new(SandboxCowStore::default());
        let transport = Rc::new(SandboxOciTransport {
            fetch_fn: oci_fetch,
            token: cfg.storage_token.clone(),
            instance_id: cfg.instance_id.clone(),
        });
        let oci_client = OciClient::new(&cfg.base_url, transport);

        // 1. Pull OCI image (cowfs snapshot OR standard OCI tar) & O(1) fork ephemeral rootfs.
        let (img_vol, img_snap) = pull_image_into_sandbox(&store, &oci_client, &cfg.image_ref)
            .await
            .map_err(map_errno)?;
        let snap_rec = store
            .get_snapshot(&img_vol, &img_snap)
            .await
            .map_err(map_errno)?;
        let root_vol = VolumeId(format!(
            "sb-root-{}-{}",
            cfg.workload_id, cfg.attempt_generation
        ));
        let output_vol = VolumeId(format!(
            "sb-out-{}-{}",
            cfg.workload_id, cfg.attempt_generation
        ));
        store
            .fork_volume(&ForkRequest {
                source_volume: img_vol,
                source_snapshot: Some(img_snap),
                source_root: snap_rec.root,
                new_volume: root_vol.clone(),
                ephemeral_if_unmodified: false,
                created_at: boot_ts,
            })
            .await
            .map_err(map_errno)?;

        let root_fs = Rc::new(
            CowFs::open(
                Rc::clone(&store),
                Rc::clone(&store),
                root_vol,
                CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
                sandbox_cowfs_cfg(),
            )
            .await
            .map_err(map_errno)?,
        );
        {
            let mut root_cred = Cred::root();
            root_cred.umask = 0;
            let root_h = root_fs.root();
            for dir in ["dev", "proc", "tmp", "input", "output"] {
                if root_fs.lookup(&root_cred, &root_h, dir).await.is_err() {
                    let _ = root_fs.mkdir(&root_cred, &root_h, dir, 0o755).await;
                }
            }
        }

        CowFs::format_volume(&*store, &*store, output_vol.clone(), 0, 0, 0o755, boot_ts)
            .await
            .map_err(map_errno)?;
        let output_fs = Rc::new(
            CowFs::open(
                Rc::clone(&store),
                Rc::clone(&store),
                output_vol.clone(),
                CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
                sandbox_cowfs_cfg(),
            )
            .await
            .map_err(map_errno)?,
        );

        // 2. Isolated `LocalProcessTable` (PID 1 only, `memory.max` + `pids.max` on `/`).
        let sb_instance = format!(
            "sb-{}-{}-{}",
            cfg.workload_id, cfg.attempt_generation, cfg.node_generation
        );
        let proc_table = Rc::new(RefCell::new(LocalProcessTable::new(
            InstanceIdentity {
                instance: sb_instance.clone(),
                host: SANDBOX_HOST_LABEL.to_string(),
            },
            boot_ts.sec,
        )));
        let root_ident = Identity {
            id: 0,
            group: 0,
            groups: BTreeSet::from([0]),
        };
        {
            let mut tbl = proc_table.borrow_mut();
            if cfg.memory_max_bytes > 0 {
                tbl.cgroup_set(
                    &root_ident,
                    "/",
                    "memory.max",
                    &cfg.memory_max_bytes.to_string(),
                    boot_ts.sec,
                )
                .map_err(|e| map_errno(e.errno))?;
            }
            if cfg.pids_max > 0 {
                tbl.cgroup_set(
                    &root_ident,
                    "/",
                    "pids.max",
                    &cfg.pids_max.to_string(),
                    boot_ts.sec,
                )
                .map_err(|e| map_errno(e.errno))?;
            }
            tbl.boot_init(SANDBOX_HOST_LABEL, boot_ts.sec)
                .map_err(|e| map_errno(e.errno))?;
        }

        let mut argv = Vec::with_capacity(1 + cfg.args.len());
        argv.push(cfg.entrypoint.clone());
        argv.extend(cfg.args.iter().cloned());
        let mut env_map = BTreeMap::new();
        for (k, v) in &cfg.env {
            env_map.insert(k.clone(), v.clone());
        }
        env_map.insert("PATH".to_string(), "/usr/bin:/bin".to_string());
        env_map.insert("HOME".to_string(), "/tmp".to_string());
        env_map.insert("OS_TASK_SDK_VERSION".to_string(), "1".to_string());
        env_map.insert("OS_TASK_WORKLOAD_ID".to_string(), cfg.workload_id.clone());
        env_map.insert(
            "OS_TASK_ATTEMPT_GEN".to_string(),
            cfg.attempt_generation.to_string(),
        );
        env_map.insert("OS_TASK_NODE_ID".to_string(), cfg.node_id.clone());
        env_map.insert(
            "OS_TASK_NODE_GEN".to_string(),
            cfg.node_generation.to_string(),
        );
        env_map.insert("OS_TASK_INPUT_DIR".to_string(), "/input".to_string());
        env_map.insert("OS_TASK_OUTPUT_DIR".to_string(), "/output".to_string());
        let env_vec: Vec<String> = env_map
            .into_iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect();

        {
            let mut tbl = proc_table.borrow_mut();
            let _ = tbl
                .reexec(
                    SANDBOX_HOST_LABEL,
                    1,
                    ReexecSpec {
                        path: cfg.entrypoint.clone(),
                        argv: argv.clone(),
                        env: env_vec.clone(),
                        cwd: Some("/".to_string()),
                        runtime: Some("resources-v1".to_string()),
                        cloud_access: false,
                        new_remote: None,
                    },
                    boot_ts.sec,
                )
                .map_err(|e| map_errno(e.errno))?;
        }

        // 3. Isolated `Vfs` + `/proc` + minimal `/dev` + `/tmp` + RO `/input` + RW `/output`.
        let factory = Rc::new(DefaultFilesystemFactory::new(Rc::new(|| {
            (crate::now_secs(), 0)
        })));
        let root_backing = Rc::new(MountBacking::new(
            Rc::clone(&root_fs) as Rc<dyn Filesystem>,
            FsType::Cowfs,
        ));
        let vfs = Vfs::boot(&sb_instance, root_backing, "sandbox-root", factory)
            .await
            .map_err(map_errno)?;

        {
            let pt1 = Rc::clone(&proc_table);
            vfs.set_proc_snapshot_hook(Rc::new(move |pid| {
                let tbl = pt1.try_borrow().ok()?;
                let snap = tbl.proc_snapshot(pid)?;
                Some(ProcMetaSnapshot {
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
            let pt2 = Rc::clone(&proc_table);
            vfs.set_proc_list_hook(Rc::new(move || {
                pt2.try_borrow()
                    .map(|tbl| tbl.all_pids())
                    .unwrap_or_default()
            }));
            let pt3 = Rc::clone(&proc_table);
            vfs.set_uptime_hook(Rc::new(move || {
                pt3.try_borrow()
                    .map(|tbl| tbl.uptime_secs(crate::now_secs()))
                    .unwrap_or(0)
            }));
        }

        let sys_ns = vfs.system_namespace();
        let mut root_cred = Cred::root();
        root_cred.umask = 0;

        // `/proc`
        let proc_fs = Rc::new(ProcFs::new(
            FsId("proc:sandbox".to_string()),
            boot_ts,
            EmptyProcProvider,
        ));
        proc_fs.bind_bridge(vfs.proc_bridge());
        vfs.mount_on_namespace(
            &sys_ns,
            &root_cred,
            Rc::new(
                MountBacking::new(proc_fs as Rc<dyn Filesystem>, FsType::Proc)
                    .with_ceilings(true, true),
            ),
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
        .await
        .map_err(map_errno)?;

        // Minimal `/dev` (`null`, `zero`, `full`, `random`, `urandom` ONLY!).
        let dev_fs = Rc::new(DevTmpFs::new(
            FsId("devtmpfs:sandbox".to_string()),
            1,
            Box::new(|| (crate::now_secs(), 0)),
            DefaultDeviceBackend,
        ));
        {
            let dev_root = dev_fs.root();
            for drop_name in ["tty", "console", "ptmx", "system"] {
                let _ = dev_fs.unlink(&root_cred, &dev_root, drop_name).await;
            }
            for drop_dir in ["pts", "shm"] {
                let _ = dev_fs.rmdir(&root_cred, &dev_root, drop_dir).await;
            }
        }
        vfs.mount_on_namespace(
            &sys_ns,
            &root_cred,
            Rc::new(MountBacking::new(
                dev_fs as Rc<dyn Filesystem>,
                FsType::DevTmpFs,
            )),
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
        .await
        .map_err(map_errno)?;

        // Fresh `/tmp`
        let tmp_fs = Rc::new(MemFs::new(
            FsId("tmpfs:sandbox-tmp".to_string()),
            2,
            0,
            0,
            0o1777,
            Box::new(|| (crate::now_secs(), 0)),
        ));
        vfs.mount_on_namespace(
            &sys_ns,
            &root_cred,
            Rc::new(MountBacking::new(
                tmp_fs as Rc<dyn Filesystem>,
                FsType::TmpFs,
            )),
            None,
            "tmpfs",
            "/tmp",
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

        // Strictly read-only `/input` (lazy range-verified OCI snapshot & optional `extra_inputs`).
        let ro_flags = MountFlags {
            rdonly: true,
            nosuid: true,
            nodev: true,
            noexec: true,
            ..MountFlags::default()
        };
        let ro_raw = mount_flags::MS_RDONLY
            | mount_flags::MS_NOSUID
            | mount_flags::MS_NODEV
            | mount_flags::MS_NOEXEC;
        if cfg.extra_inputs.is_empty() {
            let backing = if let Some(ref inp) = cfg.input_ref {
                mount_oci_ro_input(oci_client.clone(), inp)
                    .await
                    .map_err(map_errno)?
            } else {
                let empty = Rc::new(MemFs::new(
                    FsId("tmpfs:sandbox-input-empty".to_string()),
                    3,
                    0,
                    0,
                    0o555,
                    Box::new(|| (crate::now_secs(), 0)),
                ));
                Rc::new(
                    MountBacking::new(empty as Rc<dyn Filesystem>, FsType::TmpFs)
                        .with_ceilings(true, true),
                )
            };
            vfs.mount_on_namespace(
                &sys_ns,
                &root_cred,
                backing,
                None,
                "sandbox-input",
                "/input",
                ro_flags,
                ro_raw,
                None,
            )
            .await
            .map_err(map_errno)?;
        } else {
            let inp_dir = Rc::new(MemFs::new(
                FsId("tmpfs:sandbox-input-dir".to_string()),
                3,
                0,
                0,
                0o555,
                Box::new(|| (crate::now_secs(), 0)),
            ));
            let inp_root = inp_dir.root();
            if cfg.input_ref.is_some() {
                inp_dir
                    .mkdir(&root_cred, &inp_root, "primary", 0o555)
                    .await
                    .map_err(map_errno)?;
            }
            for name in cfg.extra_inputs.keys() {
                if !valid_input_mount_name(name) {
                    return Err(map_errno(Errno::EINVAL));
                }
                inp_dir
                    .mkdir(&root_cred, &inp_root, name, 0o555)
                    .await
                    .map_err(map_errno)?;
            }
            vfs.mount_on_namespace(
                &sys_ns,
                &root_cred,
                Rc::new(
                    MountBacking::new(inp_dir as Rc<dyn Filesystem>, FsType::TmpFs)
                        .with_ceilings(true, true),
                ),
                None,
                "sandbox-input",
                "/input",
                ro_flags,
                ro_raw,
                None,
            )
            .await
            .map_err(map_errno)?;
            if let Some(ref inp) = cfg.input_ref {
                let b = mount_oci_ro_input(oci_client.clone(), inp)
                    .await
                    .map_err(map_errno)?;
                vfs.mount_on_namespace(
                    &sys_ns,
                    &root_cred,
                    b,
                    None,
                    "sandbox-input-primary",
                    "/input/primary",
                    ro_flags,
                    ro_raw,
                    None,
                )
                .await
                .map_err(map_errno)?;
            }
            for (name, extra_ref) in &cfg.extra_inputs {
                let b = mount_oci_ro_input(oci_client.clone(), extra_ref)
                    .await
                    .map_err(map_errno)?;
                vfs.mount_on_namespace(
                    &sys_ns,
                    &root_cred,
                    b,
                    None,
                    &format!("sandbox-input-{name}"),
                    &format!("/input/{name}"),
                    ro_flags,
                    ro_raw,
                    None,
                )
                .await
                .map_err(map_errno)?;
            }
        }

        // Writable `/output` (`cowfs`).
        vfs.mount_on_namespace(
            &sys_ns,
            &root_cred,
            Rc::new(MountBacking::new(
                Rc::clone(&output_fs) as Rc<dyn Filesystem>,
                FsType::Cowfs,
            )),
            None,
            "sandbox-output",
            "/output",
            MountFlags {
                nosuid: true,
                nodev: true,
                noexec: true,
                ..MountFlags::default()
            },
            mount_flags::MS_NOSUID | mount_flags::MS_NODEV | mount_flags::MS_NOEXEC,
            None,
        )
        .await
        .map_err(map_errno)?;

        // 4. Resolve & load entrypoint executable — EXPLICITLY reject ELF (`\x7fELF`) with ENOEXEC!
        let resolved = vfs
            .resolve_exec(1, &cfg.entrypoint, argv, Some("/usr/bin:/bin"), false)
            .await
            .map_err(map_errno)?;
        let cred = vfs.process_cred(1).map_err(map_errno)?;
        let size = resolved.entry.metadata.size;
        if size > abi::EXEC_MAX {
            let _ = resolved.file.close().await;
            return Err(map_errno(Errno::EFBIG));
        }
        let mut raw = Vec::with_capacity(size as usize);
        let mut off = 0u64;
        let mut buf = vec![0u8; 256 * 1024];
        loop {
            match resolved.file.read_at_as(&cred, &mut buf, off).await {
                Ok(0) => break,
                Ok(n) => {
                    raw.extend_from_slice(&buf[..n]);
                    off += n as u64;
                }
                Err(e) => {
                    let _ = resolved.file.close().await;
                    return Err(map_errno(e));
                }
            }
        }
        let _ = resolved.file.close().await;

        if raw.starts_with(b"\x7fELF") || !raw.starts_with(b"\0asm") {
            return Err(map_errno(Errno::ENOEXEC));
        }

        Ok(SandboxKernel {
            vfs,
            _proc_table: proc_table,
            store,
            root_fs,
            output_fs,
            output_vol,
            oci_client,
            wasm_bytes: raw,
            argv: resolved.argv,
            env: env_vec,
            memory_max_bytes: cfg.memory_max_bytes,
            guest_fds: RefCell::new(BTreeMap::new()),
            stdout_buf: RefCell::new(Vec::new()),
            stderr_buf: RefCell::new(Vec::new()),
        })
    }

    pub fn executable_bytes(&self) -> Uint8Array {
        Uint8Array::from(self.wasm_bytes.as_slice())
    }

    pub fn argv_json(&self) -> String {
        serde_json::to_string(&self.argv).unwrap_or_else(|_| "[]".into())
    }

    pub fn env_json(&self) -> String {
        serde_json::to_string(&self.env).unwrap_or_else(|_| "[]".into())
    }

    pub fn memory_max_bytes(&self) -> f64 {
        self.memory_max_bytes as f64
    }

    pub fn stdout_bytes(&self) -> Uint8Array {
        Uint8Array::from(self.stdout_buf.borrow().as_slice())
    }

    pub fn stderr_bytes(&self) -> Uint8Array {
        Uint8Array::from(self.stderr_buf.borrow().as_slice())
    }

    /// Execute one WASI filesystem/device/proc syscall against this isolated sandbox's `Vfs`.
    pub async fn wasi_call(&self, req_json: &str, data: &[u8]) -> Result<JsValue, JsValue> {
        let req: Value = serde_json::from_str(req_json).map_err(|_| map_errno(Errno::EINVAL))?;
        let op = req["op"].as_str().unwrap_or("");

        let reply_obj =
            |errno: u16, extra: Value, bytes: Option<&[u8]>| -> Result<JsValue, JsValue> {
                let out = Object::new();
                Reflect::set(&out, &"errno".into(), &JsValue::from(errno))?;
                if let Some(map) = extra.as_object() {
                    for (k, v) in map {
                        Reflect::set(&out, &k.as_str().into(), &json_to_js(v)?)?;
                    }
                }
                if let Some(b) = bytes {
                    Reflect::set(&out, &"bytes".into(), &Uint8Array::from(b))?;
                }
                Ok(out.into())
            };

        let resolve_anchor = |dir_fd: u32| -> Result<StartAnchor, Errno> {
            if dir_fd == 3 {
                Ok(StartAnchor::Root)
            } else {
                let g = self.guest_fds.borrow();
                let entry = g.get(&dir_fd).ok_or(Errno::EBADF)?;
                Ok(StartAnchor::DirFd(entry.kfd))
            }
        };

        match op {
            "path_open" => {
                let dir_fd = req["dir_fd"].as_u64().unwrap_or(3) as u32;
                let path = req["path"].as_str().unwrap_or("");
                let oflags = req["oflags"].as_u64().unwrap_or(0) as u32;
                let fdflags = req["fdflags"].as_u64().unwrap_or(0) as u32;
                let rights = req["rights_base"].as_u64().unwrap_or(0);
                let anchor = match resolve_anchor(dir_fd) {
                    Ok(a) => a,
                    Err(e) => return reply_obj(wasi_errno(e), json!({}), None),
                };
                let want_read = (rights & (1 << 1)) != 0 || (rights & (1 << 14)) != 0;
                let want_write = (rights & (1 << 6)) != 0
                    || (oflags & 1) != 0
                    || (oflags & 8) != 0
                    || (fdflags & 1) != 0;
                let mut flags = match (want_read, want_write) {
                    (true, true) => abi::O_RDWR,
                    (false, true) => abi::O_WRONLY,
                    _ => abi::O_RDONLY,
                };
                if (oflags & 1) != 0 {
                    flags |= abi::O_CREAT;
                }
                if (oflags & 2) != 0 {
                    flags |= abi::O_DIRECTORY;
                }
                if (oflags & 4) != 0 {
                    flags |= abi::O_EXCL;
                }
                if (oflags & 8) != 0 {
                    flags |= abi::O_TRUNC;
                }
                if (fdflags & 1) != 0 {
                    flags |= abi::O_APPEND;
                }
                match self.vfs.openat(1, anchor, path, flags, 0o644).await {
                    Ok(kfd) => {
                        let is_dir = self
                            .vfs
                            .fstat(1, kfd)
                            .await
                            .map(|s| s.is_dir())
                            .unwrap_or(false);
                        let mut g = self.guest_fds.borrow_mut();
                        let mut new_fd = 4u32;
                        while g.contains_key(&new_fd) {
                            new_fd += 1;
                        }
                        g.insert(new_fd, SandboxGuestFd { kfd, is_dir });
                        reply_obj(0, json!({ "fd": new_fd, "is_dir": is_dir }), None)
                    }
                    Err(e) => reply_obj(wasi_errno(e), json!({}), None),
                }
            }
            "fd_close" => {
                let fd = req["fd"].as_u64().unwrap_or(0) as u32;
                if fd <= 3 {
                    return reply_obj(0, json!({}), None);
                }
                let entry = self.guest_fds.borrow_mut().remove(&fd);
                match entry {
                    Some(ent) => {
                        let _ = self.vfs.close(1, ent.kfd).await;
                        reply_obj(0, json!({}), None)
                    }
                    None => reply_obj(wasi_errno(Errno::EBADF), json!({}), None),
                }
            }
            "fd_read" => {
                let fd = req["fd"].as_u64().unwrap_or(0) as u32;
                let max_len = (req["len"].as_u64().unwrap_or(0) as usize).min(1024 * 1024);
                if fd == 0 {
                    return reply_obj(0, json!({}), Some(&[]));
                }
                let kfd = match self.guest_fds.borrow().get(&fd) {
                    Some(e) => e.kfd,
                    None => return reply_obj(wasi_errno(Errno::EBADF), json!({}), None),
                };
                let mut buf = vec![0u8; max_len];
                match self.vfs.read(1, kfd, &mut buf).await {
                    Ok(n) => {
                        buf.truncate(n);
                        reply_obj(0, json!({}), Some(&buf))
                    }
                    Err(e) => reply_obj(wasi_errno(e), json!({}), None),
                }
            }
            "fd_write" => {
                let fd = req["fd"].as_u64().unwrap_or(0) as u32;
                if fd == 1 {
                    let mut out = self.stdout_buf.borrow_mut();
                    let take = data.len().min((64 * 1024usize).saturating_sub(out.len()));
                    out.extend_from_slice(&data[..take]);
                    return reply_obj(0, json!({ "written": data.len() }), None);
                }
                if fd == 2 {
                    let mut err = self.stderr_buf.borrow_mut();
                    let take = data.len().min((64 * 1024usize).saturating_sub(err.len()));
                    err.extend_from_slice(&data[..take]);
                    return reply_obj(0, json!({ "written": data.len() }), None);
                }
                let kfd = match self.guest_fds.borrow().get(&fd) {
                    Some(e) => e.kfd,
                    None => return reply_obj(wasi_errno(Errno::EBADF), json!({}), None),
                };
                match self.vfs.write(1, kfd, data).await {
                    Ok(n) => reply_obj(0, json!({ "written": n }), None),
                    Err(e) => reply_obj(wasi_errno(e), json!({}), None),
                }
            }
            "fd_seek" => {
                let fd = req["fd"].as_u64().unwrap_or(0) as u32;
                let offset = req["offset"].as_i64().unwrap_or(0);
                let whence = req["whence"].as_u64().unwrap_or(0) as u8;
                let kfd = match self.guest_fds.borrow().get(&fd) {
                    Some(e) => e.kfd,
                    None => return reply_obj(wasi_errno(Errno::EBADF), json!({}), None),
                };
                let from = match whence {
                    0 => {
                        if offset < 0 {
                            return reply_obj(wasi_errno(Errno::EINVAL), json!({}), None);
                        }
                        SeekFrom::Start(offset as u64)
                    }
                    1 => SeekFrom::Current(offset),
                    2 => SeekFrom::End(offset),
                    _ => return reply_obj(wasi_errno(Errno::EINVAL), json!({}), None),
                };
                match self.vfs.lseek(1, kfd, from).await {
                    Ok(pos) => reply_obj(0, json!({ "pos": pos }), None),
                    Err(e) => reply_obj(wasi_errno(e), json!({}), None),
                }
            }
            "fd_fdstat_get" => {
                let fd = req["fd"].as_u64().unwrap_or(0) as u32;
                if fd == 3 {
                    return reply_obj(0, json!({ "filetype": 3, "fdflags": 0 }), None);
                }
                if fd <= 2 {
                    return reply_obj(0, json!({ "filetype": 2, "fdflags": 0 }), None);
                }
                let Some(entry) = self.guest_fds.borrow().get(&fd).cloned() else {
                    return reply_obj(wasi_errno(Errno::EBADF), json!({}), None);
                };
                let ft = if entry.is_dir { 3 } else { 4 };
                reply_obj(0, json!({ "filetype": ft, "fdflags": 0 }), None)
            }
            "fd_filestat_get" => {
                let fd = req["fd"].as_u64().unwrap_or(0) as u32;
                if fd == 3 {
                    return reply_obj(
                        0,
                        json!({ "dev": 1, "ino": 1, "filetype": 3, "nlink": 2, "size": 0 }),
                        None,
                    );
                }
                let kfd = match self.guest_fds.borrow().get(&fd) {
                    Some(e) => e.kfd,
                    None => return reply_obj(wasi_errno(Errno::EBADF), json!({}), None),
                };
                match self.vfs.fstat(1, kfd).await {
                    Ok(st) => reply_obj(
                        0,
                        json!({
                            "dev": st.dev,
                            "ino": st.ino,
                            "filetype": if st.is_dir() { 3 } else if st.is_link() { 7 } else if st.is_file() { 4 } else { 2 },
                            "nlink": st.nlink,
                            "size": st.size,
                        }),
                        None,
                    ),
                    Err(e) => reply_obj(wasi_errno(e), json!({}), None),
                }
            }
            "fd_readdir" => {
                let fd = req["fd"].as_u64().unwrap_or(0) as u32;
                let list_res = if fd == 3 {
                    match self
                        .vfs
                        .openat(
                            1,
                            StartAnchor::Root,
                            "/",
                            abi::O_RDONLY | abi::O_DIRECTORY,
                            0,
                        )
                        .await
                    {
                        Ok(tmp_kfd) => {
                            let r = self.vfs.fd_readdir(1, tmp_kfd).await;
                            let _ = self.vfs.close(1, tmp_kfd).await;
                            r
                        }
                        Err(e) => Err(e),
                    }
                } else {
                    let maybe_kfd = self.guest_fds.borrow().get(&fd).map(|e| e.kfd);
                    match maybe_kfd {
                        Some(kfd) => self.vfs.fd_readdir(1, kfd).await,
                        None => Err(Errno::EBADF),
                    }
                };
                match list_res {
                    Ok(entries) => {
                        let mapped: Vec<Value> = entries
                            .into_iter()
                            .map(|e| {
                                json!({
                                    "name": e.name,
                                    "ino": e.node.ino,
                                    "filetype": wasi_filetype(e.file_type),
                                })
                            })
                            .collect();
                        reply_obj(0, json!({ "entries": mapped }), None)
                    }
                    Err(e) => reply_obj(wasi_errno(e), json!({}), None),
                }
            }
            "path_filestat_get" => {
                let dir_fd = req["dir_fd"].as_u64().unwrap_or(3) as u32;
                let path = req["path"].as_str().unwrap_or("");
                let follow = req["follow"].as_bool().unwrap_or(true);
                let anchor = match resolve_anchor(dir_fd) {
                    Ok(a) => a,
                    Err(e) => return reply_obj(wasi_errno(e), json!({}), None),
                };
                match self.vfs.statat(1, anchor, path, follow).await {
                    Ok(st) => reply_obj(
                        0,
                        json!({
                            "dev": st.dev,
                            "ino": st.ino,
                            "filetype": if st.is_dir() { 3 } else if st.is_link() { 7 } else if st.is_file() { 4 } else { 2 },
                            "nlink": st.nlink,
                            "size": st.size,
                        }),
                        None,
                    ),
                    Err(e) => reply_obj(wasi_errno(e), json!({}), None),
                }
            }
            "path_create_directory" => {
                let dir_fd = req["dir_fd"].as_u64().unwrap_or(3) as u32;
                let path = req["path"].as_str().unwrap_or("");
                let anchor = match resolve_anchor(dir_fd) {
                    Ok(a) => a,
                    Err(e) => return reply_obj(wasi_errno(e), json!({}), None),
                };
                match self.vfs.mkdirat(1, anchor, path, 0o755).await {
                    Ok(_) => reply_obj(0, json!({}), None),
                    Err(e) => reply_obj(wasi_errno(e), json!({}), None),
                }
            }
            "path_unlink_file" => {
                let dir_fd = req["dir_fd"].as_u64().unwrap_or(3) as u32;
                let path = req["path"].as_str().unwrap_or("");
                let anchor = match resolve_anchor(dir_fd) {
                    Ok(a) => a,
                    Err(e) => return reply_obj(wasi_errno(e), json!({}), None),
                };
                match self.vfs.unlinkat(1, anchor, path, false).await {
                    Ok(_) => reply_obj(0, json!({}), None),
                    Err(e) => reply_obj(wasi_errno(e), json!({}), None),
                }
            }
            "path_remove_directory" => {
                let dir_fd = req["dir_fd"].as_u64().unwrap_or(3) as u32;
                let path = req["path"].as_str().unwrap_or("");
                let anchor = match resolve_anchor(dir_fd) {
                    Ok(a) => a,
                    Err(e) => return reply_obj(wasi_errno(e), json!({}), None),
                };
                match self.vfs.unlinkat(1, anchor, path, true).await {
                    Ok(_) => reply_obj(0, json!({}), None),
                    Err(e) => reply_obj(wasi_errno(e), json!({}), None),
                }
            }
            "path_rename" => {
                let old_fd = req["old_fd"].as_u64().unwrap_or(3) as u32;
                let old_path = req["old_path"].as_str().unwrap_or("");
                let new_fd = req["new_fd"].as_u64().unwrap_or(3) as u32;
                let new_path = req["new_path"].as_str().unwrap_or("");
                let a1 = match resolve_anchor(old_fd) {
                    Ok(a) => a,
                    Err(e) => return reply_obj(wasi_errno(e), json!({}), None),
                };
                let a2 = match resolve_anchor(new_fd) {
                    Ok(a) => a,
                    Err(e) => return reply_obj(wasi_errno(e), json!({}), None),
                };
                match self
                    .vfs
                    .renameat(1, a1, old_path, a2, new_path, vfs::RenameFlags::empty())
                    .await
                {
                    Ok(_) => reply_obj(0, json!({}), None),
                    Err(e) => reply_obj(wasi_errno(e), json!({}), None),
                }
            }
            "path_readlink" => {
                let dir_fd = req["dir_fd"].as_u64().unwrap_or(3) as u32;
                let path = req["path"].as_str().unwrap_or("");
                let anchor = match resolve_anchor(dir_fd) {
                    Ok(a) => a,
                    Err(e) => return reply_obj(wasi_errno(e), json!({}), None),
                };
                match self.vfs.readlinkat(1, anchor, path).await {
                    Ok(target) => reply_obj(0, json!({ "target": target }), None),
                    Err(e) => reply_obj(wasi_errno(e), json!({}), None),
                }
            }
            "fd_sync" | "fd_datasync" | "fd_fdstat_set_flags" => reply_obj(0, json!({}), None),
            "fd_tell" => {
                let fd = req["fd"].as_u64().unwrap_or(0) as u32;
                let kfd = match self.guest_fds.borrow().get(&fd) {
                    Some(e) => e.kfd,
                    None => return reply_obj(wasi_errno(Errno::EBADF), json!({}), None),
                };
                match self.vfs.lseek(1, kfd, SeekFrom::Current(0)).await {
                    Ok(pos) => reply_obj(0, json!({ "pos": pos }), None),
                    Err(e) => reply_obj(wasi_errno(e), json!({}), None),
                }
            }
            "fd_pread" => {
                let fd = req["fd"].as_u64().unwrap_or(0) as u32;
                let max_len = (req["len"].as_u64().unwrap_or(0) as usize).min(1024 * 1024);
                let offset = req["offset"].as_u64().unwrap_or(0);
                let kfd = match self.guest_fds.borrow().get(&fd) {
                    Some(e) => e.kfd,
                    None => return reply_obj(wasi_errno(Errno::EBADF), json!({}), None),
                };
                let mut buf = vec![0u8; max_len];
                match self.vfs.pread(1, kfd, &mut buf, offset).await {
                    Ok(n) => {
                        buf.truncate(n);
                        reply_obj(0, json!({}), Some(&buf))
                    }
                    Err(e) => reply_obj(wasi_errno(e), json!({}), None),
                }
            }
            "fd_pwrite" => {
                let fd = req["fd"].as_u64().unwrap_or(0) as u32;
                let offset = req["offset"].as_u64().unwrap_or(0);
                let kfd = match self.guest_fds.borrow().get(&fd) {
                    Some(e) => e.kfd,
                    None => return reply_obj(wasi_errno(Errno::EBADF), json!({}), None),
                };
                match self.vfs.pwrite(1, kfd, data, offset).await {
                    Ok(n) => reply_obj(0, json!({ "written": n }), None),
                    Err(e) => reply_obj(wasi_errno(e), json!({}), None),
                }
            }
            "fd_filestat_set_size" => {
                let fd = req["fd"].as_u64().unwrap_or(0) as u32;
                let size = req["size"].as_u64().unwrap_or(0);
                let kfd = match self.guest_fds.borrow().get(&fd) {
                    Some(e) => e.kfd,
                    None => return reply_obj(wasi_errno(Errno::EBADF), json!({}), None),
                };
                match self.vfs.ftruncate(1, kfd, size).await {
                    Ok(_) => reply_obj(0, json!({}), None),
                    Err(e) => reply_obj(wasi_errno(e), json!({}), None),
                }
            }
            _ => reply_obj(wasi_errno(Errno::ENOSYS), json!({}), None),
        }
    }

    /// Read optional `/output/.os-task-summary.txt` written by the guest task.
    pub async fn read_summary(&self) -> Option<String> {
        let root_cred = Cred::root();
        let out_root = self.output_fs.root();
        let ent = self
            .output_fs
            .lookup(&root_cred, &out_root, ".os-task-summary.txt")
            .await
            .ok()?;
        let mut open_opts = vfs::OpenOptions::new();
        open_opts.read(true);
        let open_ref = self
            .output_fs
            .open(&root_cred, &ent.handle, &open_opts)
            .await
            .ok()?;
        let mut buf = vec![0u8; MAX_SUMMARY_BYTES];
        let n = self
            .output_fs
            .read_at(&open_ref, &mut buf, 0)
            .await
            .unwrap_or(0);
        let _ = self.output_fs.release(&open_ref).await;
        if n == 0 {
            return None;
        }
        buf.truncate(n);
        Some(String::from_utf8_lossy(&buf).trim().to_string())
    }

    /// Commit `/output` `cowfs` volume and push a `COWFS_SNAPSHOT_ARTIFACT_TYPE` staging artifact
    /// to OCI with attempt-unique `org.os.kubelet.attempt` annotation.
    pub async fn stage_output(
        &self,
        repo: &str,
        staging_tag: &str,
        attempt_annotation: &str,
    ) -> Result<String, JsValue> {
        self.output_fs.commit_tx_group().await.map_err(map_errno)?;
        let mut opts = OciPushOptions::default();
        opts.extra_annotations.insert(
            "org.os.kubelet.attempt".into(),
            attempt_annotation.to_string(),
        );
        let pushed = push_cowfs_snapshot(
            &*self.store,
            &*self.store,
            &self.output_vol,
            None,
            &self.oci_client,
            repo,
            staging_tag,
            opts,
        )
        .await
        .map_err(map_errno)?;
        serde_json::to_string(&json!({
            "repo": pushed.repo,
            "staging_tag": staging_tag,
            "manifest_digest": pushed.manifest_digest,
            "media_type": pushed.media_type,
            "output_ref": format!("oci:{}@{}", pushed.repo, pushed.manifest_digest),
        }))
        .map_err(|_| map_errno(Errno::EIO))
    }

    /// Close open sandbox filesystems cleanly.
    pub async fn close(&self) {
        let fds: Vec<SandboxGuestFd> = self.guest_fds.borrow_mut().values().cloned().collect();
        for f in fds {
            let _ = self.vfs.close(1, f.kfd).await;
        }
        let _ = self.output_fs.close_clean().await;
        let _ = self.root_fs.close_clean().await;
    }
}
