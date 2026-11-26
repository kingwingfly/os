//! Ephemeral, isolated `SandboxInstance` execution for `os-native` kubelet pods (#84).
//!
//! Each attempt boots a brand-new `KernelActor` with:
//! - Isolated `LocalProcessTable` (PID 1 only, cgroup `memory.max` & `pids.max` enforced on `/`)
//! - Isolated `Vfs` + `MountNamespace` over an O(1)-forked `cowfs` root (`$STATE/kubelet-store/`)
//! - Minimal `/dev` (`null`, `zero`, `full`, `random`, `urandom` ONLY — ZERO `/dev/vd0`,
//!   ZERO `/dev/loop*`, ZERO `/dev/display`, ZERO `/dev/input`, ZERO host devices!)
//! - Isolated `/proc` (PID 1 only), fresh `tmpfs` `/tmp`, strictly read-only `/input` (lazy
//!   range-verified OCI snapshot and/or remote snapshot with RAII RO pins), writable `cowfs` `/output`
//! - Explicit rejection of ELF (`\x7fELF`) binaries with `Errno::ENOEXEC`
//! - Wasmtime 51 `EpochTickerGuard` preemption (`< 200 ms` on cancel / timeout / self-fence)
//! - Guaranteed cleanup of ephemeral root/output volumes and remote pins on exit or abort.

use crate::cluster_http::{NativeOciTransport, NativeVolumeTransport};
use crate::dev_backend::{build_native_dev_backend, new_uuid_v4, random_hex};
use crate::export_host::NativeExportBridge;
use crate::kernel_actor::{KernelActor, NativeBootProfile, now_timespec};
use crate::kernel_rpc::{GuestFdEntry, GuestFdKind, KernelClient, KernelCmd, WakeBus};
use crate::mount_host::MountHostServer;
use crate::pipes::PipeHandle;
use crate::proc_runner::{EpochTickerGuard, WasmRuntime, spawn_process_thread_with_cancel};
use crate::pty::PtyTable;
use crate::signals::SignalControl;
use abi::Errno;
use abi::contract::{InstanceIdentity, mount_flags};
use abi::registry::{
    COWFS_SNAPSHOT_ARTIFACT_TYPE, COWFS_SNAPSHOT_CONFIG_MEDIA_TYPE, OciImageConfig,
    OciImageManifest, OciReference, parse_sha256_digest,
};
use cowtree::{ForkRequest, HeadStore, VolumeId, WriterMode};
use os_core::permissions::Identity;
use os_cowfs::native_sqlite::{NativePackStore, NativeSqliteHeadStore};
use os_cowfs::oci_client::OciClient;
use os_cowfs::{
    CowFs, CowFsConfig, CowFsOpenMode, OciTarImportOptions, OciTarLayerInput, RemoteVolumeStore,
    import_oci_tar_layers, open_oci_snapshot_cowfs, pull_cowfs_snapshot,
};
use os_kernel::accounts::LocalAccountStore;
use os_kernel::proc_table::{LocalProcessTable, ReexecSpec};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use vfs::devfs::{DefaultDeviceBackend, DevPtsFs, DevTmpFs};
use vfs::gui_headless::HeadlessHostAdapter;
use vfs::guidev::GuiDeviceRegistry;
use vfs::loopdev::LoopRegistry;
use vfs::memfs::MemFs;
use vfs::procfs::{EmptyProcProvider, ProcFs, ProcMetaSnapshot};
use vfs::unix_sock::UnixSocketTable;
use vfs::vblk::VblkRegistry;
use vfs::{
    Cred, DefaultFilesystemFactory, Filesystem, FsId, FsType, MountBacking, MountFlags, Timespec,
    Vfs,
};

const SANDBOX_HOST_LABEL: &str = crate::kernel_actor::HOST_LABEL;
const MAX_CAPTURE_BYTES: usize = 64 * 1024;
const MAX_SUMMARY_BYTES: usize = 4 * 1024;

/// Parsed OCI / remote / local snapshot reference accepted by `os-native` sandboxes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SandboxRef {
    Oci { repo: String, reference: String },
    RemoteSnapshot { volume: String, snapshot: String },
    LocalSnapshot { volume: String, snapshot: String },
}

pub fn parse_sandbox_ref(raw: &str) -> Result<SandboxRef, Errno> {
    if raw.starts_with("oci:") {
        let parsed = OciReference::parse(raw).ok_or(Errno::EINVAL)?;
        Ok(SandboxRef::Oci {
            repo: parsed.repo,
            reference: parsed.reference,
        })
    } else if let Some(rest) = raw.strip_prefix("remote:snapshot:") {
        let (vol, snap) = rest.split_once('@').ok_or(Errno::EINVAL)?;
        if vol.is_empty() || snap.is_empty() {
            return Err(Errno::EINVAL);
        }
        Ok(SandboxRef::RemoteSnapshot {
            volume: vol.to_string(),
            snapshot: snap.to_string(),
        })
    } else if let Some(rest) = raw.strip_prefix("local:snapshot:") {
        let (vol, snap) = rest.split_once('@').ok_or(Errno::EINVAL)?;
        if vol.is_empty() || snap.is_empty() {
            return Err(Errno::EINVAL);
        }
        Ok(SandboxRef::LocalSnapshot {
            volume: vol.to_string(),
            snapshot: snap.to_string(),
        })
    } else {
        Err(Errno::EINVAL)
    }
}

/// Optional credentials for lazy OCI / remote-volume pulls and mounts inside a sandbox.
#[derive(Clone, Debug)]
pub struct SandboxRemoteAuth {
    pub base_url: String,
    pub storage_token: String,
    pub instance_id: String,
}

/// Complete specification for running a single sandboxed task attempt on `os-native`.
#[derive(Clone, Debug)]
pub struct SandboxRunSpec {
    pub kubelet_store_dir: PathBuf,
    pub workload_id: String,
    pub attempt_generation: u64,
    pub node_generation: u64,
    pub node_id: String,
    pub image_ref: String,
    pub entrypoint: String,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub input_ref: Option<String>,
    pub extra_inputs: BTreeMap<String, String>,
    pub remote_auth: Option<SandboxRemoteAuth>,
    pub memory_max_bytes: u64,
    pub pids_max: u32,
    pub timeout: Duration,
    pub cancel_flag: Arc<AtomicBool>,
}

/// Result of executing one ephemeral sandbox attempt.
#[derive(Clone, Debug)]
pub struct SandboxExecOutcome {
    pub exit_code: i32,
    pub signal: Option<u8>,
    pub timed_out: bool,
    pub canceled: bool,
    pub summary: Option<String>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Preserved `/output` `cowfs` volume ID (ONLY present on clean `exit_code == 0`!).
    /// Caller MUST delete it via `delete_kubelet_volume` after staging/publishing!
    pub output_volume: Option<String>,
}

/// Delete a volume from `$STATE/kubelet-store/` safely on a LocalSet.
pub fn delete_kubelet_volume(kubelet_store_dir: &Path, volume_id: &str) {
    let dir = kubelet_store_dir.to_path_buf();
    let vid = VolumeId(volume_id.to_string());
    let _ = std::thread::Builder::new()
        .name("os-sb-del".into())
        .spawn(move || {
            let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            let local = tokio::task::LocalSet::new();
            local.block_on(&rt, async move {
                if let Ok(hs) = NativeSqliteHeadStore::open(&dir) {
                    let _ = hs.delete_volume(&vid).await;
                }
            });
        })
        .and_then(|h| h.join().map_err(|_| std::io::Error::other("join")));
}

/// Pull an OCI image (native `cowfs` snapshot OR standard OCI tar/tar+gzip image) into the
/// isolated `$STATE/kubelet-store/` cache as `img:<digest_hex>@base`.
async fn ensure_image_cached(
    head_store: &Rc<NativeSqliteHeadStore>,
    pack_store: &Rc<NativePackStore>,
    image_ref: &str,
    remote_auth: Option<&SandboxRemoteAuth>,
    clock: Rc<dyn Fn() -> Timespec>,
) -> Result<(VolumeId, String), Errno> {
    match parse_sandbox_ref(image_ref)? {
        SandboxRef::LocalSnapshot { volume, snapshot } => {
            let vid = VolumeId(volume);
            let _ = head_store.get_snapshot(&vid, &snapshot).await?;
            Ok((vid, snapshot))
        }
        SandboxRef::RemoteSnapshot { .. } => Err(Errno::EINVAL),
        SandboxRef::Oci { repo, reference } => {
            let auth = remote_auth.ok_or(Errno::EACCES)?;
            let transport = Rc::new(NativeOciTransport::new(
                &auth.base_url,
                &auth.storage_token,
                &auth.instance_id,
            ));
            let client = OciClient::new(&auth.base_url, transport);
            let (digest, _mt, raw_manifest) = client.get_manifest(&repo, &reference).await?;
            let hex = parse_sha256_digest(&digest).ok_or(Errno::EIO)?;
            let cache_vol = VolumeId(format!("img:{hex}"));
            let snap_name = "base".to_string();
            if head_store
                .get_snapshot(&cache_vol, &snap_name)
                .await
                .is_ok()
            {
                return Ok((cache_vol, snap_name));
            }

            let val: serde_json::Value = os_image::parse(&raw_manifest).map_err(|_| Errno::EIO)?;
            let obj = val.as_object().ok_or(Errno::EIO)?;
            let is_cowfs_snapshot = if obj.contains_key("manifests") {
                obj.get("artifactType").and_then(|v| v.as_str())
                    == Some(COWFS_SNAPSHOT_ARTIFACT_TYPE)
            } else {
                let art_is_cowfs = obj.get("artifactType").and_then(|v| v.as_str())
                    == Some(COWFS_SNAPSHOT_ARTIFACT_TYPE);
                let cfg_is_cowfs = obj
                    .get("config")
                    .and_then(|c| c.get("mediaType"))
                    .and_then(|v| v.as_str())
                    == Some(COWFS_SNAPSHOT_CONFIG_MEDIA_TYPE);
                art_is_cowfs || cfg_is_cowfs
            };

            let now = (clock)();
            if is_cowfs_snapshot {
                pull_cowfs_snapshot(
                    &client,
                    &repo,
                    &digest,
                    &**head_store,
                    &**pack_store,
                    &cache_vol,
                    Some(&snap_name),
                    now,
                    None,
                )
                .await?;
            } else {
                // Standard OCI runnable image (tar / tar+gzip layers).
                let manifest: OciImageManifest =
                    serde_json::from_value(val).map_err(|_| Errno::EINVAL)?;
                let cfg_bytes = client.get_blob(&repo, &manifest.config.digest).await?;
                let cfg: OciImageConfig = os_image::parse(&cfg_bytes).map_err(|_| Errno::EINVAL)?;
                let mut layer_blobs: Vec<Vec<u8>> = Vec::with_capacity(manifest.layers.len());
                for desc in &manifest.layers {
                    let b = client.get_blob(&repo, &desc.digest).await?;
                    layer_blobs.push(b);
                }
                let inputs: Vec<OciTarLayerInput<'_>> = layer_blobs
                    .iter()
                    .enumerate()
                    .map(|(idx, bytes)| OciTarLayerInput {
                        bytes: bytes.as_slice(),
                        expected_diff_id: cfg.rootfs.diff_ids.get(idx).map(String::as_str),
                    })
                    .collect();
                let opts = OciTarImportOptions::default(); // StrictConfined + SetuidPolicy::Reject
                import_oci_tar_layers(
                    Rc::clone(head_store),
                    Rc::clone(pack_store),
                    cache_vol.clone(),
                    &inputs,
                    &opts,
                    Some(&snap_name),
                    CowFsConfig::local_native(clock),
                )
                .await?;
            }
            Ok((cache_vol, snap_name))
        }
    }
}

async fn open_input_backing(
    raw_ref: &str,
    head_store: &Rc<NativeSqliteHeadStore>,
    pack_store: &Rc<NativePackStore>,
    remote_auth: Option<&SandboxRemoteAuth>,
    clock: Rc<dyn Fn() -> Timespec>,
) -> Result<Rc<MountBacking>, Errno> {
    match parse_sandbox_ref(raw_ref)? {
        SandboxRef::Oci { repo, reference } => {
            let auth = remote_auth.ok_or(Errno::EACCES)?;
            let transport = Rc::new(NativeOciTransport::new(
                &auth.base_url,
                &auth.storage_token,
                &auth.instance_id,
            ));
            let client = OciClient::new(&auth.base_url, transport);
            let fs = Rc::new(
                open_oci_snapshot_cowfs(
                    client,
                    &repo,
                    &reference,
                    CowFsConfig::local_native(clock),
                )
                .await?,
            );
            Ok(Rc::new(
                MountBacking::new(fs as Rc<dyn Filesystem>, FsType::Cowfs)
                    .with_ceilings(true, true),
            ))
        }
        SandboxRef::RemoteSnapshot { volume, snapshot } => {
            let auth = remote_auth.ok_or(Errno::EACCES)?;
            let transport =
                NativeVolumeTransport::new(&auth.base_url, &auth.storage_token, &auth.instance_id);
            let vid = VolumeId(volume);
            let store = Rc::new(RemoteVolumeStore::new(vid.clone(), transport));
            let fs = Rc::new(
                CowFs::open(
                    Rc::clone(&store),
                    store,
                    vid,
                    CowFsOpenMode::Snapshot(snapshot),
                    CowFsConfig::local_native(clock),
                )
                .await?,
            );
            Ok(Rc::new(
                MountBacking::new(fs as Rc<dyn Filesystem>, FsType::Cowfs)
                    .with_ceilings(true, true),
            ))
        }
        SandboxRef::LocalSnapshot { volume, snapshot } => {
            let fs = Rc::new(
                CowFs::open(
                    Rc::clone(head_store),
                    Rc::clone(pack_store),
                    VolumeId(volume),
                    CowFsOpenMode::Snapshot(snapshot),
                    CowFsConfig::local_native(clock),
                )
                .await?,
            );
            Ok(Rc::new(
                MountBacking::new(fs as Rc<dyn Filesystem>, FsType::Cowfs)
                    .with_ceilings(true, true),
            ))
        }
    }
}

/// Execute one completely isolated sandboxed attempt synchronously (blocking caller thread; wrap
/// with `tokio::task::spawn_blocking` from async callers).
pub fn run_sandbox_attempt_blocking(spec: SandboxRunSpec) -> Result<SandboxExecOutcome, Errno> {
    std::fs::create_dir_all(&spec.kubelet_store_dir).map_err(|_| Errno::EIO)?;
    let runtime = WasmRuntime::shared().map_err(|_| Errno::EIO)?;

    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<
        Result<
            (
                Arc<SignalControl>,
                crate::kernel_rpc::LoadedImage,
                String,
                String,
            ),
            Errno,
        >,
    >();
    let (done_tx, done_rx) =
        std::sync::mpsc::channel::<Result<(Option<String>, Option<String>), Errno>>();

    let wake = WakeBus::new();
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<KernelCmd>();
    let hook_tx = cmd_tx.clone();
    let hangup_tx = cmd_tx.clone();
    let ptys = PtyTable::new(
        Arc::new(move |pgrp, signal| {
            let _ = hook_tx.send(KernelCmd::KillPgrp { pgrp, signal });
        }),
        Arc::new(move |number, pgrp, sid| {
            let _ = hangup_tx.send(KernelCmd::PtyHangup { number, pgrp, sid });
        }),
    );

    let actor_spec = spec.clone();
    let actor_wake = Arc::clone(&wake);
    let actor_ptys = Arc::clone(&ptys);

    let actor_thread = std::thread::Builder::new()
        .name(format!("os-sb-actor-{}", spec.workload_id))
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                let _ = ready_tx.send(Err(Errno::EIO));
                return;
            };
            let local = tokio::task::LocalSet::new();
            local.block_on(&rt, async move {
                match boot_sandbox_actor(&actor_spec, actor_wake, actor_ptys).await {
                    Ok((mut actor, pid1_sig, pid1_img, root_fork_vol, output_vol, output_fs)) => {
                        let _ = ready_tx.send(Ok((
                            pid1_sig,
                            pid1_img,
                            root_fork_vol.0.clone(),
                            output_vol.0.clone(),
                        )));
                        // Run event loop until `Shutdown`.
                        actor.run_sandbox_loop(cmd_rx).await;

                        // Read optional summary directly from `output_fs` (PID 1 has already exited
                        // its VFS process slot) & commit output volume before closing cleanly.
                        let mut summary: Option<String> = None;
                        {
                            let root_cred = Cred::root();
                            let out_root = output_fs.root();
                            let mut open_opts = vfs::OpenOptions::new();
                            open_opts.read(true);
                            if let Ok(ent) = output_fs
                                .lookup(&root_cred, &out_root, ".os-task-summary.txt")
                                .await
                                && let Ok(open_ref) =
                                    output_fs.open(&root_cred, &ent.handle, &open_opts).await
                            {
                                let mut buf = vec![0u8; MAX_SUMMARY_BYTES];
                                if let Ok(n) = output_fs.read_at(&open_ref, &mut buf, 0).await
                                    && n > 0
                                {
                                    buf.truncate(n);
                                    summary =
                                        Some(String::from_utf8_lossy(&buf).trim().to_string());
                                }
                                let _ = output_fs.release(&open_ref).await;
                            }
                        }
                        let commit_res = output_fs.commit_tx_group().await;
                        let hs = Rc::clone(&actor.head_store);
                        let _ = actor.close_all_cowfs_clean_pub().await;
                        drop(output_fs);
                        drop(actor);
                        // Always delete ephemeral root fork volume!
                        let _ = hs.delete_volume(&root_fork_vol).await;
                        match commit_res {
                            Ok(_) => {
                                let _ = done_tx.send(Ok((summary, Some(output_vol.0))));
                            }
                            Err(e) => {
                                let _ = hs.delete_volume(&output_vol).await;
                                let _ = done_tx.send(Err(e));
                            }
                        }
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                    }
                }
            });
        })
        .map_err(|_| Errno::EIO)?;

    let (pid1_sig, pid1_img, _root_vol_id, output_vol_id) = match ready_rx.recv() {
        Ok(Ok(tuple)) => tuple,
        Ok(Err(e)) => {
            let _ = actor_thread.join();
            return Err(e);
        }
        Err(_) => {
            let _ = actor_thread.join();
            return Err(Errno::EIO);
        }
    };

    let kernel = KernelClient {
        tx: cmd_tx,
        wake: Arc::clone(&wake),
        ptys,
    };

    let (stdout_r, stdout_w) = PipeHandle::pair();
    let (stderr_r, stderr_w) = PipeHandle::pair();
    let mut fds = BTreeMap::new();
    fds.insert(
        0,
        GuestFdEntry {
            kind: GuestFdKind::NullIn,
            cloexec: false,
        },
    );
    fds.insert(
        1,
        GuestFdEntry {
            kind: GuestFdKind::Pipe {
                handle: stdout_w,
                nonblock: false,
            },
            cloexec: false,
        },
    );
    fds.insert(
        2,
        GuestFdEntry {
            kind: GuestFdKind::Pipe {
                handle: stderr_w,
                nonblock: false,
            },
            cloexec: false,
        },
    );

    let stdout_thread = std::thread::spawn(move || {
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match stdout_r.buf.read(&mut buf, false, || Ok(())) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let take = n.min(MAX_CAPTURE_BYTES.saturating_sub(out.len()));
                    out.extend_from_slice(&buf[..take]);
                }
            }
        }
        out
    });
    let stderr_thread = std::thread::spawn(move || {
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match stderr_r.buf.read(&mut buf, false, || Ok(())) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let take = n.min(MAX_CAPTURE_BYTES.saturating_sub(out.len()));
                    out.extend_from_slice(&buf[..take]);
                }
            }
        }
        out
    });

    let _epoch_ticker = EpochTickerGuard::start(runtime.engine.clone());
    let proc_handle = spawn_process_thread_with_cancel(
        1,
        pid1_sig,
        fds,
        pid1_img,
        0o022,
        None,
        kernel.clone(),
        Arc::clone(&runtime),
        Some(Arc::clone(&spec.cancel_flag)),
    );

    let deadline = Instant::now() + spec.timeout;
    let mut timed_out = false;
    let mut canceled = false;
    let mut exit_code = 0i32;
    let mut exit_sig: Option<u8> = None;

    loop {
        if spec.cancel_flag.load(Ordering::SeqCst) {
            canceled = true;
            let _ = kernel.try_call_sync(|reply| KernelCmd::Kill {
                pid: 1,
                target: "-1".to_string(),
                signal: 9,
                reply,
            });
            runtime.engine.increment_epoch();
            break;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            spec.cancel_flag.store(true, Ordering::SeqCst);
            let _ = kernel.try_call_sync(|reply| KernelCmd::Kill {
                pid: 1,
                target: "-1".to_string(),
                signal: 9,
                reply,
            });
            runtime.engine.increment_epoch();
            break;
        }
        let seq = kernel.wake.current();
        if let Some(Ok(res)) = kernel.try_call_sync(|reply| KernelCmd::Waitpid {
            pid: 0,
            target: 1,
            options: 1, // WNOHANG
            host_reap: true,
            reply,
        }) && !res.nothing
        {
            if let Some(sig) = res.signal {
                exit_code = 128 + i32::from(sig);
                exit_sig = Some(sig);
            } else {
                exit_code = (res.status >> 8) & 0xff;
            }
            break;
        }
        if proc_handle.as_ref().is_some_and(|h| h.is_finished()) {
            // Reap final status if thread already finished.
            if let Some(Ok(res)) = kernel.try_call_sync(|reply| KernelCmd::Waitpid {
                pid: 0,
                target: 1,
                options: 1,
                host_reap: true,
                reply,
            }) && !res.nothing
            {
                if let Some(sig) = res.signal {
                    exit_code = 128 + i32::from(sig);
                    exit_sig = Some(sig);
                } else {
                    exit_code = (res.status >> 8) & 0xff;
                }
            }
            break;
        }
        kernel.wake.wait_since(seq, Duration::from_millis(15));
    }

    if canceled || timed_out {
        exit_code = 128 + 9;
        exit_sig = Some(9);
        // Bump epoch repeatedly until guest thread unwinds.
        for _ in 0..10 {
            runtime.engine.increment_epoch();
            if proc_handle.as_ref().is_none_or(|h| h.is_finished()) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    if let Some(h) = proc_handle {
        let _ = h.join();
    }
    drop(_epoch_ticker);

    let _ = kernel.try_call_sync(|reply| KernelCmd::Shutdown { reply });
    let _ = actor_thread.join();

    let stdout = stdout_thread.join().unwrap_or_default();
    let stderr = stderr_thread.join().unwrap_or_default();

    let (summary, committed_out_vol) = match done_rx.recv() {
        Ok(Ok(pair)) => pair,
        Ok(Err(_)) | Err(_) => (None, None),
    };

    let keep_output = exit_code == 0 && !canceled && !timed_out;
    let output_volume = if keep_output {
        committed_out_vol
    } else {
        delete_kubelet_volume(&spec.kubelet_store_dir, &output_vol_id);
        None
    };

    Ok(SandboxExecOutcome {
        exit_code,
        signal: exit_sig,
        timed_out,
        canceled,
        summary,
        stdout,
        stderr,
        output_volume,
    })
}

async fn boot_sandbox_actor(
    spec: &SandboxRunSpec,
    wake: Arc<WakeBus>,
    ptys: Arc<PtyTable>,
) -> Result<
    (
        KernelActor,
        Arc<SignalControl>,
        crate::kernel_rpc::LoadedImage,
        VolumeId,
        VolumeId,
        Rc<CowFs<NativeSqliteHeadStore, NativePackStore>>,
    ),
    Errno,
> {
    let head_store = Rc::new(NativeSqliteHeadStore::open(&spec.kubelet_store_dir)?);
    let pack_store = Rc::new(NativePackStore::open(&spec.kubelet_store_dir)?);
    let clock: Rc<dyn Fn() -> Timespec> = Rc::new(now_timespec);
    let clock_pair: Rc<dyn Fn() -> (u64, u32)> = Rc::new(|| {
        let ts = now_timespec();
        (ts.sec, ts.nsec)
    });
    let boot_ts = (clock)();

    // 1. Pull/cache image in isolated `$STATE/kubelet-store/` and O(1) fork ephemeral rootfs.
    let (img_vol, img_snap) = ensure_image_cached(
        &head_store,
        &pack_store,
        &spec.image_ref,
        spec.remote_auth.as_ref(),
        Rc::clone(&clock),
    )
    .await?;

    let suffix = random_hex(4);
    let root_fork_vol = VolumeId(format!(
        "sb-root-{}-{}-{suffix}",
        spec.workload_id, spec.attempt_generation
    ));
    let output_vol = VolumeId(format!(
        "sb-out-{}-{}-{suffix}",
        spec.workload_id, spec.attempt_generation
    ));

    let img_snap_rec = head_store.get_snapshot(&img_vol, &img_snap).await?;
    head_store
        .fork_volume(&ForkRequest {
            source_volume: img_vol,
            source_snapshot: Some(img_snap),
            source_root: img_snap_rec.root,
            new_volume: root_fork_vol.clone(),
            created_at: boot_ts,
            ephemeral_if_unmodified: false,
        })
        .await?;

    let root_fs = match CowFs::open(
        Rc::clone(&head_store),
        Rc::clone(&pack_store),
        root_fork_vol.clone(),
        CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
        CowFsConfig::local_native(Rc::clone(&clock)),
    )
    .await
    {
        Ok(fs) => Rc::new(fs),
        Err(e) => {
            let _ = head_store.delete_volume(&root_fork_vol).await;
            return Err(e);
        }
    };

    // Ensure mountpoints exist on the forked rootfs.
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

    // Format fresh writable `/output` cowfs volume.
    if let Err(e) = CowFs::format_volume(
        &*head_store,
        &*pack_store,
        output_vol.clone(),
        0,
        0,
        0o755,
        boot_ts,
    )
    .await
    {
        let _ = root_fs.close_clean().await;
        let _ = head_store.delete_volume(&root_fork_vol).await;
        return Err(e);
    }

    let output_fs = match CowFs::open(
        Rc::clone(&head_store),
        Rc::clone(&pack_store),
        output_vol.clone(),
        CowFsOpenMode::ReadWrite(WriterMode::Exclusive),
        CowFsConfig::local_native(Rc::clone(&clock)),
    )
    .await
    {
        Ok(fs) => Rc::new(fs),
        Err(e) => {
            let _ = root_fs.close_clean().await;
            let _ = head_store.delete_volume(&root_fork_vol).await;
            let _ = head_store.delete_volume(&output_vol).await;
            return Err(e);
        }
    };

    let setup_res: Result<
        (
            KernelActor,
            Arc<SignalControl>,
            crate::kernel_rpc::LoadedImage,
        ),
        Errno,
    > = async {
        let sandbox_instance_id = new_uuid_v4();

        // 2. Isolated `LocalProcessTable` with `memory.max` & `pids.max` enforced on `/`.
        let proc_table = Rc::new(RefCell::new(LocalProcessTable::new(
            InstanceIdentity {
                instance: sandbox_instance_id.clone(),
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
            if spec.memory_max_bytes > 0 {
                tbl.cgroup_set(
                    &root_ident,
                    "/",
                    "memory.max",
                    &spec.memory_max_bytes.to_string(),
                    boot_ts.sec,
                )
                .map_err(|e| e.errno)?;
            }
            if spec.pids_max > 0 {
                tbl.cgroup_set(
                    &root_ident,
                    "/",
                    "pids.max",
                    &spec.pids_max.to_string(),
                    boot_ts.sec,
                )
                .map_err(|e| e.errno)?;
            }
            tbl.boot_init(SANDBOX_HOST_LABEL, boot_ts.sec)
                .map_err(|e| e.errno)?;
        }

        // Build clean task argv and environment (ZERO host env/tokens!).
        let mut argv = Vec::with_capacity(1 + spec.args.len());
        argv.push(spec.entrypoint.clone());
        argv.extend(spec.args.iter().cloned());

        let mut env_map = BTreeMap::new();
        for (k, v) in &spec.env {
            env_map.insert(k.clone(), v.clone());
        }
        env_map.insert("PATH".to_string(), "/usr/bin:/bin".to_string());
        env_map.insert("HOME".to_string(), "/tmp".to_string());
        env_map.insert("OS_TASK_SDK_VERSION".to_string(), "1".to_string());
        env_map.insert("OS_TASK_WORKLOAD_ID".to_string(), spec.workload_id.clone());
        env_map.insert(
            "OS_TASK_ATTEMPT_GEN".to_string(),
            spec.attempt_generation.to_string(),
        );
        env_map.insert("OS_TASK_NODE_ID".to_string(), spec.node_id.clone());
        env_map.insert(
            "OS_TASK_NODE_GEN".to_string(),
            spec.node_generation.to_string(),
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
                        path: spec.entrypoint.clone(),
                        argv: argv.clone(),
                        env: env_vec.clone(),
                        cwd: Some("/".to_string()),
                        runtime: Some("resources-v1".to_string()),
                        cloud_access: false,
                        new_remote: None,
                    },
                    boot_ts.sec,
                )
                .map_err(|e| e.errno)?;
        }

        // 3. Isolated VFS booted directly on the forked root `CowFs`.
        let factory = Rc::new(DefaultFilesystemFactory::new(Rc::clone(&clock_pair)));
        let root_backing = Rc::new(MountBacking::new(
            Rc::clone(&root_fs) as Rc<dyn Filesystem>,
            FsType::Cowfs,
        ));
        let vfs = Vfs::boot(&sandbox_instance_id, root_backing, "sandbox-root", factory).await?;

        // Wire sandbox-local `/proc` hooks ONLY (never host processes!).
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
            let clk = Rc::clone(&clock);
            vfs.set_uptime_hook(Rc::new(move || {
                pt3.try_borrow()
                    .map(|tbl| tbl.uptime_secs((clk)().sec))
                    .unwrap_or(0)
            }));
        }

        let sys_ns = vfs.system_namespace();
        let mut root_cred = Cred::root();
        root_cred.umask = 0;

        // 4. Isolated `/proc` (PID 1 only).
        let proc_fs = Rc::new(ProcFs::new(
            FsId("proc:sandbox".to_string()),
            boot_ts,
            EmptyProcProvider,
        ));
        proc_fs.bind_bridge(vfs.proc_bridge());
        let proc_backing = Rc::new(
            MountBacking::new(proc_fs as Rc<dyn Filesystem>, FsType::Proc)
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

        // 5. Minimal `/dev` (`null`, `zero`, `full`, `random`, `urandom` ONLY!).
        let vblk = Rc::new(VblkRegistry::new());
        let loop_reg = LoopRegistry::new();
        let gui_caller = Rc::new(Cell::new(None));
        let headless_gui = Rc::new(HeadlessHostAdapter::default());
        let gui_reg = GuiDeviceRegistry::new(
            Rc::clone(&headless_gui) as Rc<dyn abi::gui::GuiHostSink>,
            Rc::clone(&gui_caller),
        );
        let dev_backend = build_native_dev_backend(loop_reg.clone(), gui_reg);
        let dev_fs = Rc::new(DevTmpFs::new(
            FsId("devtmpfs:sandbox".to_string()),
            1,
            Box::new(|| {
                let ts = now_timespec();
                (ts.sec, ts.nsec)
            }),
            dev_backend,
        ));
        let gui_reg = Rc::clone(&dev_fs.backend().registry);
        {
            let dev_root = dev_fs.root();
            // Strip tty/console/ptmx/system/pts/shm so ONLY null/zero/full/random/urandom remain.
            for drop_name in ["tty", "console", "ptmx", "system"] {
                let _ = dev_fs.unlink(&root_cred, &dev_root, drop_name).await;
            }
            for drop_dir in ["pts", "shm"] {
                let _ = dev_fs.rmdir(&root_cred, &dev_root, drop_dir).await;
            }
        }
        let dev_backing = Rc::new(MountBacking::new(
            Rc::clone(&dev_fs) as Rc<dyn Filesystem>,
            FsType::DevTmpFs,
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
            FsId("devpts:sandbox".to_string()),
            1,
            Box::new(|| {
                let ts = now_timespec();
                (ts.sec, ts.nsec)
            }),
            DefaultDeviceBackend,
        ));

        // 6. Fresh `/tmp` (`tmpfs`, `01777`).
        let tmp_fs = Rc::new(MemFs::new(
            FsId("tmpfs:sandbox-tmp".to_string()),
            2,
            0,
            0,
            0o1777,
            Box::new(|| {
                let ts = now_timespec();
                (ts.sec, ts.nsec)
            }),
        ));
        let tmp_backing = Rc::new(MountBacking::new(
            tmp_fs as Rc<dyn Filesystem>,
            FsType::TmpFs,
        ));
        vfs.mount_on_namespace(
            &sys_ns,
            &root_cred,
            tmp_backing,
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
        .await?;

        // 7. Strictly read-only `/input` (lazy OCI snapshot, remote snapshot, and/or extra_inputs).
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
        if spec.extra_inputs.is_empty() {
            let input_backing = if let Some(ref inp) = spec.input_ref {
                open_input_backing(
                    inp,
                    &head_store,
                    &pack_store,
                    spec.remote_auth.as_ref(),
                    Rc::clone(&clock),
                )
                .await?
            } else {
                let empty = Rc::new(MemFs::new(
                    FsId("tmpfs:sandbox-input-empty".to_string()),
                    3,
                    0,
                    0,
                    0o555,
                    Box::new(|| {
                        let ts = now_timespec();
                        (ts.sec, ts.nsec)
                    }),
                ));
                Rc::new(
                    MountBacking::new(empty as Rc<dyn Filesystem>, FsType::TmpFs)
                        .with_ceilings(true, true),
                )
            };
            vfs.mount_on_namespace(
                &sys_ns,
                &root_cred,
                input_backing,
                None,
                "sandbox-input",
                "/input",
                ro_flags,
                ro_raw,
                None,
            )
            .await?;
        } else {
            let inp_dir = Rc::new(MemFs::new(
                FsId("tmpfs:sandbox-input-dir".to_string()),
                3,
                0,
                0,
                0o555,
                Box::new(|| {
                    let ts = now_timespec();
                    (ts.sec, ts.nsec)
                }),
            ));
            let inp_root = inp_dir.root();
            if spec.input_ref.is_some() {
                inp_dir
                    .mkdir(&root_cred, &inp_root, "primary", 0o555)
                    .await?;
            }
            for name in spec.extra_inputs.keys() {
                if name.is_empty()
                    || name.len() > 64
                    || name == "."
                    || name == ".."
                    || name == "primary"
                    || !name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
                {
                    return Err(Errno::EINVAL);
                }
                inp_dir.mkdir(&root_cred, &inp_root, name, 0o555).await?;
            }
            let dir_backing = Rc::new(
                MountBacking::new(inp_dir as Rc<dyn Filesystem>, FsType::TmpFs)
                    .with_ceilings(true, true),
            );
            vfs.mount_on_namespace(
                &sys_ns,
                &root_cred,
                dir_backing,
                None,
                "sandbox-input",
                "/input",
                ro_flags,
                ro_raw,
                None,
            )
            .await?;
            if let Some(ref inp) = spec.input_ref {
                let b = open_input_backing(
                    inp,
                    &head_store,
                    &pack_store,
                    spec.remote_auth.as_ref(),
                    Rc::clone(&clock),
                )
                .await?;
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
                .await?;
            }
            for (name, extra_ref) in &spec.extra_inputs {
                let b = open_input_backing(
                    extra_ref,
                    &head_store,
                    &pack_store,
                    spec.remote_auth.as_ref(),
                    Rc::clone(&clock),
                )
                .await?;
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
                .await?;
            }
        }

        // 8. Writable `/output` (`cowfs`).
        let out_backing = Rc::new(MountBacking::new(
            Rc::clone(&output_fs) as Rc<dyn Filesystem>,
            FsType::Cowfs,
        ));
        vfs.mount_on_namespace(
            &sys_ns,
            &root_cred,
            out_backing,
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
        .await?;

        let cowfs_mounts = Rc::new(RefCell::new(vec![
            Rc::clone(&root_fs),
            Rc::clone(&output_fs),
        ]));
        let root_cowfs = Rc::new(RefCell::new(Some(Rc::clone(&root_fs))));
        let root_volume_uuid = Rc::new(RefCell::new(Some(root_fork_vol.0.clone())));
        let pid1_sig = SignalControl::new();
        let mut sig_ctrls = HashMap::new();
        sig_ctrls.insert(1, Arc::clone(&pid1_sig));

        let actor = KernelActor {
            instance_id: sandbox_instance_id,
            state_dir: spec.kubelet_store_dir.clone(),
            release: None,
            boot_profile: NativeBootProfile::default(),
            vfs,
            proc_table,
            accounts: LocalAccountStore::new(),
            head_store: Rc::clone(&head_store),
            pack_store: Rc::clone(&pack_store),
            cowfs_mounts,
            root_cowfs,
            root_volume_uuid,
            dev_fs,
            dev_pts,
            vblk,
            loop_reg,
            gui_reg,
            gui_caller,
            _headless_gui: headless_gui,
            socks: UnixSocketTable::new(),
            mount_host: MountHostServer::new(),
            kubelet_host: crate::kubelet::KubeletHostServer::new(),
            export_bridge: NativeExportBridge::default(),
            exportd_pids: HashSet::new(),
            exportd_sha256: None,
            init_pids: HashSet::new(),
            init_sha256: None,
            kubelet_pids: HashSet::new(),
            kubelet_sha256: None,
            sig_ctrls,
            rights_side_table: HashMap::new(),
            next_rights_handle: 1,
            wake,
            ptys,
            clock,
            closed: false,
        };

        // 9. Resolve & load entrypoint executable (rejects `\x7fELF` with `Errno::ENOEXEC`!).
        let pid1_img = actor
            .load_executable_pub(1, &spec.entrypoint, argv, env_vec, false)
            .await?;

        Ok((actor, pid1_sig, pid1_img))
    }
    .await;

    match setup_res {
        Ok((actor, sig, img)) => Ok((actor, sig, img, root_fork_vol, output_vol, output_fs)),
        Err(e) => {
            let _ = root_fs.close_clean().await;
            let _ = output_fs.close_clean().await;
            let _ = head_store.delete_volume(&root_fork_vol).await;
            let _ = head_store.delete_volume(&output_vol).await;
            Err(e)
        }
    }
}
