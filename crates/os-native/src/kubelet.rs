//! Native `kubelet` worker-node runtime (`os-native kubelet enroll|run|submit|cancel|status|revoke-node`)
//! and in-kernel `/run/kubelet/host.sock` host controller for `/usr/bin/kubelet` (#84).

use crate::cluster_http::{
    HttpClusterClient, NativeOciTransport, NativeServiceAuthClient, NodeEnrollment,
};
use crate::dev_backend::{new_uuid_v4, random_hex};
use crate::sandbox::{
    SandboxRemoteAuth, SandboxRunSpec, delete_kubelet_volume, run_sandbox_attempt_blocking,
};
use abi::Errno;
use abi::cluster_state::{ClusterError, WatchServerFrame};
use abi::kubelet_ctl::{
    KUBELET_CTL_VERSION, KUBELET_HOST_SOCK, KubeletHostReply, KubeletHostRequest, KubeletStatus,
    decode_payload, encode_frame,
};
use abi::socket::PeerCred;
use cowtree::VolumeId;
use os_cluster_state::fencing::FencedPublishFailure;
use os_cluster_state::{BoxFuture as ClusterBoxFuture, ClusterGrant};
use os_cowfs::native_sqlite::{NativePackStore, NativeSqliteHeadStore};
use os_cowfs::oci_client::OciClient;
use os_cowfs::{OciPushOptions, push_cowfs_snapshot};
use os_task_sdk::agent::{
    ArtifactStager, AttemptExecutionReport, KubeletConfig, KubeletEngine, SandboxRunOutcome,
    SandboxRunRequest, SandboxRunner, StagedArtifact,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Notify, watch};
use vfs::unix_sock::{SockId, SockType, SocketInodeKey, UnixSocketTable};
use vfs::{StartAnchor, Vfs};

const KERNEL_HOST_PID: u32 = 1;

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(1_700_000_000)
}

pub fn enrollment_path(state_dir: &Path) -> PathBuf {
    state_dir.join("kubelet").join("enrollment.json")
}

pub fn kubelet_store_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("kubelet-store")
}

/// Exchange a single-use bootstrap token (`osbt_*`) and persist `$STATE/kubelet/enrollment.json` (`0600`).
pub async fn enroll_native_node(
    state_dir: &Path,
    base_url: &str,
    bootstrap_token: &str,
) -> Result<NodeEnrollment, String> {
    let instance_id = new_uuid_v4();
    let host_proof = random_hex(32);
    let client = NativeServiceAuthClient::new(base_url);
    let issued = client
        .exchange_bootstrap(bootstrap_token.trim(), &instance_id, &host_proof)
        .await?;
    let enrollment = NodeEnrollment {
        base_url: base_url.trim_end_matches('/').to_string(),
        cluster: issued.cluster,
        node_id: issued.node_id,
        tenant: issued.tenant,
        enrollment_id: issued.enrollment_id,
        ns: issued.ns,
        instance_id: issued.instance_id,
        host_proof,
        token: issued.token,
        scope: issued.scope,
        lease_seconds: issued.lease_seconds,
        expires: issued.expires,
    };
    enrollment.save_0600(&enrollment_path(state_dir))?;
    Ok(enrollment)
}

/// Live shared state for an in-flight sandbox attempt so keepalive self-fencing, WS cancellation,
/// artifact staging, and cleanup coordinate atomically.
struct ActiveAttempt {
    workload_id: String,
    _attempt_generation: u64,
    cancel_flag: Arc<AtomicBool>,
    derived_token: Option<String>,
    output_volume: Option<String>,
}

/// Options for running `NativeKubeletRuntime`.
#[derive(Clone, Debug)]
pub struct NativeKubeletRunOptions {
    pub state_dir: PathBuf,
    pub lease_ttl_secs: u64,
    pub labels: BTreeMap<String, String>,
    pub capabilities: Vec<String>,
    pub ready_file: Option<PathBuf>,
    pub drain_flag: Option<Arc<AtomicBool>>,
}

impl NativeKubeletRunOptions {
    pub fn new(state_dir: PathBuf) -> Self {
        Self {
            state_dir,
            lease_ttl_secs: 15,
            labels: BTreeMap::new(),
            capabilities: vec!["wasix".into(), "cowfs".into(), "oci".into()],
            ready_file: None,
            drain_flag: None,
        }
    }
}

/// Snapshot emitted to `--ready-file` / `status` for observability & tests.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NativeKubeletReadyInfo {
    pub node_id: String,
    pub cluster: String,
    pub tenant: String,
    pub enrollment_id: String,
    pub instance_id: String,
    pub node_generation: u64,
    pub lease_id: u64,
    pub lease_ttl_secs: u64,
    pub status: String,
    pub pid: u32,
}

struct NativeSandboxRunner {
    enroll: NodeEnrollment,
    auth_client: NativeServiceAuthClient,
    store_dir: PathBuf,
    active: Arc<Mutex<Option<ActiveAttempt>>>,
}

impl SandboxRunner for NativeSandboxRunner {
    fn run_attempt<'a>(
        &'a self,
        req: &'a SandboxRunRequest,
    ) -> ClusterBoxFuture<'a, Result<SandboxRunOutcome, ClusterError>> {
        Box::pin(async move {
            // 1. Derive strictly attenuated per-attempt storage credential (OCI + RO volumes ONLY;
            //    ZERO cluster_* or cloud_fs permissions!).
            let ttl = req.spec.timeout_secs.saturating_add(120).clamp(60, 3600);
            let derived = self
                .auth_client
                .derive_attempt_storage_cred(&self.enroll, &req.workload_id, ttl)
                .await
                .map_err(|e| ClusterError::because(Errno::EACCES, e))?;

            let cancel_flag = Arc::new(AtomicBool::new(false));
            {
                let mut g = self.active.lock().unwrap();
                *g = Some(ActiveAttempt {
                    workload_id: req.workload_id.clone(),
                    _attempt_generation: req.attempt_generation,
                    cancel_flag: Arc::clone(&cancel_flag),
                    derived_token: Some(derived.token.clone()),
                    output_volume: None,
                });
            }

            let sb_spec = SandboxRunSpec {
                kubelet_store_dir: self.store_dir.clone(),
                workload_id: req.workload_id.clone(),
                attempt_generation: req.attempt_generation,
                node_generation: req.node_generation,
                node_id: req.node_id.clone(),
                image_ref: req.spec.image_ref.clone(),
                entrypoint: req.spec.entrypoint.clone(),
                args: req.spec.args.clone(),
                env: req.spec.env.clone(),
                input_ref: req.spec.input_snapshot_ref.clone(),
                extra_inputs: req.spec.extra_inputs.clone(),
                remote_auth: Some(SandboxRemoteAuth {
                    base_url: self.enroll.base_url.clone(),
                    storage_token: derived.token,
                    instance_id: self.enroll.instance_id.clone(),
                }),
                memory_max_bytes: req.spec.memory_max_bytes,
                pids_max: req.spec.pids_max,
                timeout: Duration::from_secs(req.spec.timeout_secs.max(1)),
                cancel_flag,
            };

            let exec_res =
                tokio::task::spawn_blocking(move || run_sandbox_attempt_blocking(sb_spec))
                    .await
                    .map_err(|_| ClusterError::because(Errno::EIO, "sandbox thread panicked"))?;

            match exec_res {
                Ok(outcome) => {
                    if outcome.canceled {
                        return Err(ClusterError::because(
                            Errno::ECANCELED,
                            "sandbox canceled or self-fenced",
                        ));
                    }
                    if outcome.timed_out {
                        return Ok(SandboxRunOutcome {
                            exit_code: 124,
                            summary: Some("ETIMEDOUT: task exceeded timeout_secs".into()),
                            output_handle: None,
                        });
                    }
                    if let Some(ref vol) = outcome.output_volume
                        && let Ok(mut g) = self.active.lock()
                        && let Some(ref mut a) = *g
                    {
                        a.output_volume = Some(vol.clone());
                    }
                    let summary = outcome.summary.or_else(|| {
                        if !outcome.stderr.is_empty() && outcome.exit_code != 0 {
                            Some(
                                String::from_utf8_lossy(&outcome.stderr)
                                    .trim()
                                    .chars()
                                    .take(512)
                                    .collect(),
                            )
                        } else if !outcome.stdout.is_empty() {
                            Some(
                                String::from_utf8_lossy(&outcome.stdout)
                                    .trim()
                                    .chars()
                                    .take(512)
                                    .collect(),
                            )
                        } else {
                            None
                        }
                    });
                    Ok(SandboxRunOutcome {
                        exit_code: outcome.exit_code,
                        summary,
                        output_handle: outcome.output_volume,
                    })
                }
                Err(Errno::ENOEXEC) => Ok(SandboxRunOutcome {
                    exit_code: 126,
                    summary: Some(
                        "ENOEXEC: unsupported executable format (ELF delegation is out of scope)"
                            .into(),
                    ),
                    output_handle: None,
                }),
                Err(errno) => Ok(SandboxRunOutcome {
                    exit_code: 125,
                    summary: Some(format!("{errno:?}: sandbox setup failed")),
                    output_handle: None,
                }),
            }
        })
    }

    fn cleanup_attempt<'a>(
        &'a self,
        _workload_id: &'a str,
        _attempt_generation: u64,
    ) -> ClusterBoxFuture<'a, ()> {
        Box::pin(async move {
            let taken = self.active.lock().unwrap().take();
            if let Some(att) = taken {
                if let Some(vol) = att.output_volume {
                    let dir = self.store_dir.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        delete_kubelet_volume(&dir, &vol);
                    })
                    .await;
                }
                if let Some(tok) = att.derived_token {
                    let _ = self
                        .auth_client
                        .revoke_tokens(&self.enroll, vec![tok])
                        .await;
                }
            }
        })
    }
}

struct NativeArtifactStager {
    enroll: NodeEnrollment,
    store_dir: PathBuf,
    active: Arc<Mutex<Option<ActiveAttempt>>>,
}

impl NativeArtifactStager {
    fn current_storage_token(&self) -> String {
        self.active
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|a| a.derived_token.clone())
            .unwrap_or_else(|| self.enroll.token.clone())
    }
}

impl ArtifactStager for NativeArtifactStager {
    fn stage_output<'a>(
        &'a self,
        req: &'a SandboxRunRequest,
        outcome: &'a SandboxRunOutcome,
    ) -> ClusterBoxFuture<'a, Result<Option<StagedArtifact>, ClusterError>> {
        Box::pin(async move {
            let Some(ref out_vol_id) = outcome.output_handle else {
                return Ok(None);
            };
            let staging_tag = format!(
                "staging-{}-{}-{}",
                req.workload_id, req.attempt_generation, req.node_generation
            );
            let attempt_annotation = format!(
                "{}:{}:{}",
                req.workload_id, req.attempt_generation, req.node_generation
            );
            let base_url = self.enroll.base_url.clone();
            let token = self.current_storage_token();
            let instance_id = self.enroll.instance_id.clone();
            let store_dir = self.store_dir.clone();
            let vol_id = VolumeId(out_vol_id.clone());
            let repo = req.spec.output_repo.clone();
            let tag_clone = staging_tag.clone();

            let pushed = tokio::task::spawn_blocking(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| Errno::EIO)?;
                let local = tokio::task::LocalSet::new();
                local.block_on(&rt, async move {
                    let hs = Rc::new(NativeSqliteHeadStore::open(&store_dir)?);
                    let ps = Rc::new(NativePackStore::open(&store_dir)?);
                    let transport =
                        Rc::new(NativeOciTransport::new(&base_url, &token, &instance_id));
                    let client = OciClient::new(&base_url, transport);
                    let mut opts = OciPushOptions::default();
                    opts.extra_annotations
                        .insert("org.os.kubelet.attempt".into(), attempt_annotation);
                    push_cowfs_snapshot(&*hs, &*ps, &vol_id, None, &client, &repo, &tag_clone, opts)
                        .await
                })
            })
            .await
            .map_err(|_| ClusterError::because(Errno::EIO, "stage thread failed"))?
            .map_err(|e| ClusterError::because(e, format!("OCI stage push failed: {e:?}")))?;

            Ok(Some(StagedArtifact {
                repo: pushed.repo.clone(),
                staging_tag,
                manifest_digest: pushed.manifest_digest.clone(),
                media_type: pushed.media_type,
                output_ref: format!("oci:{}@{}", pushed.repo, pushed.manifest_digest),
            }))
        })
    }

    fn promote_staged<'a>(
        &'a self,
        req: &'a SandboxRunRequest,
        staged: &'a StagedArtifact,
    ) -> ClusterBoxFuture<'a, Result<String, ClusterError>> {
        Box::pin(async move {
            let base_url = self.enroll.base_url.clone();
            let token = self.current_storage_token();
            let instance_id = self.enroll.instance_id.clone();
            let repo = staged.repo.clone();
            let digest = staged.manifest_digest.clone();
            let staging_tag = staged.staging_tag.clone();
            let result_tag = format!("result-{}", req.workload_id);

            let res: Result<(), Errno> = tokio::task::spawn_blocking(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| Errno::EIO)?;
                let local = tokio::task::LocalSet::new();
                local.block_on(&rt, async move {
                    let transport =
                        Rc::new(NativeOciTransport::new(&base_url, &token, &instance_id));
                    let client = OciClient::new(&base_url, transport);
                    let (_d, mt, raw) = client.get_manifest(&repo, &digest).await?;
                    let _ = client.put_manifest(&repo, &result_tag, &mt, &raw).await?;
                    let _ = client.delete_manifest(&repo, &staging_tag).await;
                    Ok(())
                })
            })
            .await
            .map_err(|_| ClusterError::new(Errno::EIO))?;
            res.map_err(|e| ClusterError::because(e, format!("OCI promote failed: {e:?}")))?;
            Ok(staged.output_ref.clone())
        })
    }

    fn cleanup_staged<'a>(
        &'a self,
        _req: &'a SandboxRunRequest,
        staged: &'a StagedArtifact,
    ) -> ClusterBoxFuture<'a, ()> {
        Box::pin(async move {
            let base_url = self.enroll.base_url.clone();
            let token = self.current_storage_token();
            let instance_id = self.enroll.instance_id.clone();
            let repo = staged.repo.clone();
            let staging_tag = staged.staging_tag.clone();
            let digest = staged.manifest_digest.clone();

            let _ = tokio::task::spawn_blocking(move || {
                let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    return;
                };
                let local = tokio::task::LocalSet::new();
                local.block_on(&rt, async move {
                    let transport =
                        Rc::new(NativeOciTransport::new(&base_url, &token, &instance_id));
                    let client = OciClient::new(&base_url, transport);
                    let _ = client.delete_manifest(&repo, &staging_tag).await;
                    let _ = client.delete_manifest(&repo, &digest).await;
                });
            })
            .await;
        })
    }
}

/// Run the standalone `os-native kubelet run` daemon loop until `stop_rx` signals shutdown.
pub async fn run_native_kubelet_loop(
    enroll: NodeEnrollment,
    opts: NativeKubeletRunOptions,
    mut stop_rx: watch::Receiver<bool>,
) -> Result<(), String> {
    let store_dir = kubelet_store_dir(&opts.state_dir);
    std::fs::create_dir_all(&store_dir)
        .map_err(|e| format!("create {}: {e}", store_dir.display()))?;

    let cluster_client = HttpClusterClient::from_enrollment(&enroll);
    let auth_client = NativeServiceAuthClient::new(&enroll.base_url);
    let grant = ClusterGrant {
        tenant: enroll.tenant.clone(),
        owner: format!("node:{}", enroll.node_id),
        admin: false,
        scope: enroll.scope.clone(),
    };

    let cfg = KubeletConfig {
        node_id: enroll.node_id.clone(),
        host_kind: "os-native".into(),
        instance_id: enroll.instance_id.clone(),
        labels: opts.labels.clone(),
        capabilities: opts.capabilities.clone(),
        lease_ttl_secs: opts.lease_ttl_secs.clamp(5, 300),
    };

    let boot_mono = Instant::now();
    let mono_ms = move || boot_mono.elapsed().as_millis() as u64;

    let mut engine = KubeletEngine::new(cluster_client.clone(), grant.clone(), cfg)
        .map_err(|e| format!("init KubeletEngine: {e}"))?;

    let lease_state = engine
        .register(now_unix_secs(), mono_ms())
        .await
        .map_err(|e| format!("register kubelet node: {e}"))?;

    let ready_info = NativeKubeletReadyInfo {
        node_id: enroll.node_id.clone(),
        cluster: enroll.cluster.clone(),
        tenant: enroll.tenant.clone(),
        enrollment_id: enroll.enrollment_id.clone(),
        instance_id: enroll.instance_id.clone(),
        node_generation: lease_state.node_generation,
        lease_id: lease_state.lease_id,
        lease_ttl_secs: lease_state.ttl_secs,
        status: lease_state.status.clone(),
        pid: std::process::id(),
    };
    if let Some(ref rf) = opts.ready_file {
        let _ = std::fs::write(
            rf,
            serde_json::to_vec_pretty(&ready_info).unwrap_or_default(),
        );
    }
    eprintln!(
        "os-native kubelet: ready node={} cluster={} gen={} lease_id={} ttl={}s",
        ready_info.node_id,
        ready_info.cluster,
        ready_info.node_generation,
        ready_info.lease_id,
        ready_info.lease_ttl_secs
    );

    let active: Arc<Mutex<Option<ActiveAttempt>>> = Arc::new(Mutex::new(None));
    let work_notify = Arc::new(Notify::new());
    let fenced_flag = Arc::new(AtomicBool::new(false));
    let auth_revoked_flag = Arc::new(AtomicBool::new(false));
    let shared_lease_id = Arc::new(AtomicU64::new(lease_state.lease_id));
    let shared_fence_deadline = Arc::new(AtomicU64::new(lease_state.self_fence_deadline_ms));

    // Task 1: ClusterState LeaseKeepAlive + self-fencing watchdog + ServiceAuth RenewInstance.
    let keepalive_task = {
        let cc = cluster_client.clone();
        let ac = auth_client.clone();
        let en = enroll.clone();
        let gr = grant.clone();
        let act = Arc::clone(&active);
        let fenced = Arc::clone(&fenced_flag);
        let auth_revoked = Arc::clone(&auth_revoked_flag);
        let lid_atom = Arc::clone(&shared_lease_id);
        let deadline_atom = Arc::clone(&shared_fence_deadline);
        let ttl = lease_state.ttl_secs;
        let mut stop = stop_rx.clone();
        let mono_origin = boot_mono;
        let wake_main = Arc::clone(&work_notify);

        tokio::spawn(async move {
            let ka_period = Duration::from_secs((ttl / 3).max(1));
            let mut ka_tick = tokio::time::interval(ka_period);
            ka_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut auth_tick = tokio::time::interval(Duration::from_secs(30));
            auth_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut fence_check = tokio::time::interval(Duration::from_millis(250));
            fence_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            loop {
                tokio::select! {
                    _ = stop.changed() => break,
                    _ = fence_check.tick() => {
                        let now_m = mono_origin.elapsed().as_millis() as u64;
                        let dl = deadline_atom.load(Ordering::SeqCst);
                        if dl > 0 && now_m >= dl {
                            fenced.store(true, Ordering::SeqCst);
                            if let Some(ref a) = *act.lock().unwrap() {
                                a.cancel_flag.store(true, Ordering::SeqCst);
                            }
                            wake_main.notify_one();
                        }
                    }
                    _ = ka_tick.tick() => {
                        let lid = lid_atom.load(Ordering::SeqCst);
                        if lid == 0 {
                            continue;
                        }
                        let send_m = mono_origin.elapsed().as_millis() as u64;
                        let dl = deadline_atom.load(Ordering::SeqCst);
                        if dl > 0 && send_m >= dl {
                            fenced.store(true, Ordering::SeqCst);
                            if let Some(ref a) = *act.lock().unwrap() {
                                a.cancel_flag.store(true, Ordering::SeqCst);
                            }
                            wake_main.notify_one();
                            continue;
                        }
                        use os_cluster_state::ClusterStore;
                        match cc
                            .rpc(
                                &gr,
                                abi::cluster_state::ClusterCall::LeaseKeepAlive { lease_id: lid },
                                now_unix_secs(),
                            )
                            .await
                        {
                            Ok(abi::cluster_state::ClusterReply::LeaseKeptAlive { ttl_secs, .. }) => {
                                let new_dl = os_task_sdk::agent::compute_self_fence_deadline_ms(
                                    send_m, ttl_secs,
                                );
                                deadline_atom.store(new_dl, Ordering::SeqCst);
                            }
                            Err(e) if matches!(e.errno, Errno::ENOENT | Errno::EACCES | Errno::ESTALE) => {
                                fenced.store(true, Ordering::SeqCst);
                                deadline_atom.store(0, Ordering::SeqCst);
                                if e.errno == Errno::EACCES {
                                    auth_revoked.store(true, Ordering::SeqCst);
                                }
                                if let Some(ref a) = *act.lock().unwrap() {
                                    a.cancel_flag.store(true, Ordering::SeqCst);
                                }
                                wake_main.notify_one();
                            }
                            _ => {}
                        }
                    }
                    _ = auth_tick.tick() => {
                        match ac.renew_node_instance(&en).await {
                            Ok(res) => {
                                if res.revoked.iter().any(|t| t == &en.token) {
                                    eprintln!("os-native kubelet: node token revoked on renew");
                                    auth_revoked.store(true, Ordering::SeqCst);
                                    fenced.store(true, Ordering::SeqCst);
                                    deadline_atom.store(0, Ordering::SeqCst);
                                    if let Some(ref a) = *act.lock().unwrap() {
                                        a.cancel_flag.store(true, Ordering::SeqCst);
                                    }
                                    wake_main.notify_one();
                                    break;
                                }
                            }
                            Err(err) => {
                                eprintln!("os-native kubelet: renew_node_instance failed: {err}");
                                if err.contains("403") || err.contains("404") || err.contains("EACCES") {
                                    auth_revoked.store(true, Ordering::SeqCst);
                                    fenced.store(true, Ordering::SeqCst);
                                    deadline_atom.store(0, Ordering::SeqCst);
                                    if let Some(ref a) = *act.lock().unwrap() {
                                        a.cancel_flag.store(true, Ordering::SeqCst);
                                    }
                                    wake_main.notify_one();
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        })
    };

    // Task 2: Live WebSocket watch on `workloads/` (including `workloads/<wid>/canceled`) and
    // `nodes/` (for instant dead-node lease expiry failover).
    let watch_task = {
        let cc = cluster_client.clone();
        let tenant = enroll.tenant.clone();
        let act = Arc::clone(&active);
        let notify = Arc::clone(&work_notify);
        let mut stop = stop_rx.clone();

        tokio::spawn(async move {
            let wl_prefix = format!("/t/{tenant}/workloads/");
            let nodes_prefix = format!("/t/{tenant}/nodes/");
            let mut next_rev = 0u64;
            loop {
                if *stop.borrow() {
                    break;
                }
                let subs = vec![
                    (1u64, wl_prefix.clone(), next_rev),
                    (2u64, nodes_prefix.clone(), next_rev),
                ];
                if let Ok(mut ws) = cc.connect_watch(&subs).await {
                    loop {
                        tokio::select! {
                            _ = stop.changed() => {
                                ws.close().await;
                                return;
                            }
                            msg = ws.recv_text() => {
                                match msg {
                                    Ok(Some(text)) => {
                                        if let Ok(frame) = serde_json::from_str::<WatchServerFrame>(&text) {
                                            match frame {
                                                WatchServerFrame::Events { revision, events, .. } => {
                                                    next_rev = revision.saturating_add(1);
                                                    for ev in &events {
                                                        if let Some(rest) = ev.kv.key.strip_prefix(&wl_prefix)
                                                            && let Some(wid) = rest.strip_suffix("/canceled")
                                                            && let Some(ref a) = *act.lock().unwrap()
                                                            && a.workload_id == wid
                                                        {
                                                            a.cancel_flag.store(true, Ordering::SeqCst);
                                                        }
                                                    }
                                                    notify.notify_one();
                                                }
                                                WatchServerFrame::Compacted { floor, .. } => {
                                                    next_rev = floor.saturating_add(1);
                                                    notify.notify_one();
                                                }
                                                WatchServerFrame::Error { .. } => {
                                                    notify.notify_one();
                                                    break;
                                                }
                                                _ => {}
                                            }
                                        }
                                    }
                                    Ok(None) | Err(_) => {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
                tokio::select! {
                    _ = stop.changed() => break,
                    _ = tokio::time::sleep(Duration::from_millis(500)) => {}
                }
            }
        })
    };

    let runner = NativeSandboxRunner {
        enroll: enroll.clone(),
        auth_client: auth_client.clone(),
        store_dir: store_dir.clone(),
        active: Arc::clone(&active),
    };
    let stager = NativeArtifactStager {
        enroll: enroll.clone(),
        store_dir,
        active: Arc::clone(&active),
    };

    let mut poll_tick = tokio::time::interval(Duration::from_millis(750));
    poll_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let drain_flag = opts.drain_flag.clone();
    let mut drained_notified = false;

    loop {
        if *stop_rx.borrow() || auth_revoked_flag.load(Ordering::SeqCst) {
            break;
        }

        if drain_flag
            .as_ref()
            .is_some_and(|f| f.load(Ordering::SeqCst))
            && !drained_notified
        {
            drained_notified = true;
            let _ = engine.drain(now_unix_secs()).await;
        }

        // Sync latest keepalive deadline into engine's lease view.
        engine.update_self_fence_deadline_ms(shared_fence_deadline.load(Ordering::SeqCst));

        // If self-fenced (e.g. after SIGSTOP/SIGCONT or network blip), re-register cleanly with
        // a strictly higher monotonic `node_generation`!
        if fenced_flag.load(Ordering::SeqCst) || engine.is_self_fenced(mono_ms()) {
            if auth_revoked_flag.load(Ordering::SeqCst) {
                break;
            }
            match engine.register(now_unix_secs(), mono_ms()).await {
                Ok(new_lease) => {
                    fenced_flag.store(false, Ordering::SeqCst);
                    shared_lease_id.store(new_lease.lease_id, Ordering::SeqCst);
                    shared_fence_deadline.store(new_lease.self_fence_deadline_ms, Ordering::SeqCst);
                    eprintln!(
                        "os-native kubelet: re-registered node={} gen={} lease_id={}",
                        enroll.node_id, new_lease.node_generation, new_lease.lease_id
                    );
                }
                Err(e) => {
                    eprintln!("os-native kubelet: re-register failed: {e}");
                    if e.errno == Errno::EACCES {
                        break;
                    }
                    tokio::select! {
                        _ = stop_rx.changed() => break,
                        _ = tokio::time::sleep(Duration::from_secs(1)) => continue,
                    }
                }
            }
        }

        match engine
            .poll_and_execute_one_live(&runner, &stager, now_unix_secs, mono_ms, || {
                if fenced_flag.load(Ordering::SeqCst) || auth_revoked_flag.load(Ordering::SeqCst) {
                    Some(0)
                } else {
                    Some(shared_fence_deadline.load(Ordering::SeqCst))
                }
            })
            .await
        {
            Ok(Some(AttemptExecutionReport::Published {
                workload_id,
                attempt_generation,
                exit_code,
                output_ref,
                ..
            })) => {
                eprintln!(
                    "os-native kubelet: published wid={workload_id} attempt={attempt_generation} exit={exit_code} out={output_ref:?}"
                );
                continue;
            }
            Ok(Some(AttemptExecutionReport::Rejected {
                workload_id,
                attempt_generation,
                failure,
            })) => {
                eprintln!(
                    "os-native kubelet: rejected wid={workload_id} attempt={attempt_generation} reason={failure:?}"
                );
                if failure == FencedPublishFailure::NodeFenced {
                    fenced_flag.store(true, Ordering::SeqCst);
                }
                continue;
            }
            Ok(Some(AttemptExecutionReport::AbortedBeforePublish {
                workload_id,
                attempt_generation,
                errno,
            })) => {
                eprintln!(
                    "os-native kubelet: aborted wid={workload_id} attempt={attempt_generation} errno={errno:?}"
                );
                if errno == Errno::ESTALE {
                    fenced_flag.store(true, Ordering::SeqCst);
                }
                continue;
            }
            Ok(None) => {}
            Err(e) => {
                if e.errno == Errno::EACCES {
                    eprintln!("os-native kubelet: credential rejected ({e}); stopping");
                    break;
                }
                if e.errno == Errno::ESTALE {
                    fenced_flag.store(true, Ordering::SeqCst);
                    continue;
                }
            }
        }

        tokio::select! {
            _ = stop_rx.changed() => break,
            _ = work_notify.notified() => {}
            _ = poll_tick.tick() => {}
        }
    }

    // Clean drain + deregister + detach!
    if let Some(ref a) = *active.lock().unwrap() {
        a.cancel_flag.store(true, Ordering::SeqCst);
    }
    keepalive_task.abort();
    watch_task.abort();
    let _ = engine.drain(now_unix_secs()).await;
    let _ = engine.deregister(now_unix_secs()).await;
    let _ = auth_client.detach_node_instance(&enroll).await;
    eprintln!("os-native kubelet: stopped cleanly");
    Ok(())
}

/// Maximum simultaneous connected `/run/kubelet/host.sock` control clients.
const MAX_KUBELET_HOST_CLIENTS: usize = 16;

/// Kernel-side `/run/kubelet/host.sock` (`0600`, uid 0, verified `/usr/bin/kubelet` image)
/// controller inside `os-native` so `/usr/bin/kubelet` managed by `kubelet.service` can enroll,
/// start, inspect, drain, and stop the host's native kubelet runtime cleanly without blocking
/// the `KernelActor` event loop.
pub struct KubeletHostServer {
    listener_id: Option<SockId>,
    clients: HashMap<SockId, Vec<u8>>,
    pending_enroll: Option<(
        SockId,
        std::sync::mpsc::Receiver<Result<NodeEnrollment, String>>,
    )>,
    running: bool,
    status: KubeletStatus,
    drain_flag: Arc<AtomicBool>,
    stop_tx: Option<watch::Sender<bool>>,
    bg_thread: Option<std::thread::JoinHandle<()>>,
    stopping_threads: Vec<std::thread::JoinHandle<()>>,
}

impl Default for KubeletHostServer {
    fn default() -> Self {
        Self::new()
    }
}

impl KubeletHostServer {
    pub fn new() -> Self {
        Self {
            listener_id: None,
            clients: HashMap::new(),
            pending_enroll: None,
            running: false,
            status: KubeletStatus {
                state: "stopped".into(),
                enrolled: false,
                running: false,
                node_id: None,
                cluster: None,
                tenant: None,
                enrollment_id: None,
                instance_id: None,
                node_generation: 0,
                active_attempts: 0,
                completed_attempts: 0,
                last_error: None,
            },
            drain_flag: Arc::new(AtomicBool::new(false)),
            stop_tx: None,
            bg_thread: None,
            stopping_threads: Vec::new(),
        }
    }

    /// Ensure `/run/kubelet/host.sock` (`0600`, uid 0) is bound and listening on `/run`.
    /// Lazily called ONLY when verified `/usr/bin/kubelet` is launched by `init`.
    pub async fn ensure_bound(&mut self, vfs: &Vfs, socks: &mut UnixSocketTable) {
        if let Some(id) = self.listener_id {
            if socks.describe(KERNEL_HOST_PID, id).is_ok() {
                return;
            }
            self.listener_id = None;
        }
        match vfs
            .mkdirat(KERNEL_HOST_PID, StartAnchor::Root, "/run/kubelet", 0o755)
            .await
        {
            Ok(_) | Err(Errno::EEXIST) => {}
            Err(_) => return,
        }
        let Ok(dir) = vfs
            .statat(KERNEL_HOST_PID, StartAnchor::Root, "/run/kubelet", false)
            .await
        else {
            return;
        };
        if dir.uid != 0 || dir.mode & abi::S_IFMT != abi::S_IFDIR || dir.mode & 0o022 != 0 {
            return;
        }
        let _ = vfs
            .unlinkat(KERNEL_HOST_PID, StartAnchor::Root, KUBELET_HOST_SOCK, false)
            .await;
        let cred = PeerCred {
            pid: 1,
            uid: 0,
            gid: 0,
        };
        let Ok(sock_id) = socks.create(KERNEL_HOST_PID, SockType::Stream, cred) else {
            return;
        };
        let _ = socks.set_nonblock(KERNEL_HOST_PID, sock_id, true);
        if socks
            .begin_bind(KERNEL_HOST_PID, sock_id, KUBELET_HOST_SOCK)
            .is_err()
        {
            let _ = socks.close(KERNEL_HOST_PID, sock_id, 1);
            return;
        }
        match vfs
            .mksockat_with_parent(KERNEL_HOST_PID, StartAnchor::Root, KUBELET_HOST_SOCK, 0o600)
            .await
        {
            Ok((entry, _pin, _parent, _name)) => {
                let key = SocketInodeKey {
                    fs_id: entry.handle.fs.clone(),
                    node: entry.handle.node,
                };
                if socks
                    .finish_bind(KERNEL_HOST_PID, sock_id, key, KUBELET_HOST_SOCK.to_string())
                    .is_ok()
                    && socks.listen(KERNEL_HOST_PID, sock_id, 16, cred).is_ok()
                {
                    let _ = vfs
                        .setattrat(
                            KERNEL_HOST_PID,
                            StartAnchor::Root,
                            KUBELET_HOST_SOCK,
                            &vfs::SetAttr {
                                mode: Some(0o600),
                                uid: Some(0),
                                gid: Some(0),
                                ..vfs::SetAttr::default()
                            },
                            false,
                        )
                        .await;
                    self.listener_id = Some(sock_id);
                } else {
                    socks.abort_bind(sock_id);
                    let _ = socks.close(KERNEL_HOST_PID, sock_id, 1);
                }
            }
            Err(_) => {
                socks.abort_bind(sock_id);
                let _ = socks.close(KERNEL_HOST_PID, sock_id, 1);
            }
        }
    }

    fn send_reply_and_close(
        socks: &mut UnixSocketTable,
        cid: SockId,
        root_cred: PeerCred,
        reply: &KubeletHostReply,
    ) {
        if let Ok(encoded) = encode_frame(reply) {
            let _ = socks.sendmsg(
                KERNEL_HOST_PID,
                cid,
                &encoded,
                Vec::new(),
                None,
                root_cred,
                None,
            );
        }
        let _ = socks.close(KERNEL_HOST_PID, cid, 1);
    }

    pub async fn tick(
        &mut self,
        state_dir: &Path,
        socks: &mut UnixSocketTable,
        kubelet_pids: &std::collections::HashSet<u32>,
    ) -> bool {
        let mut did_work = false;
        let root_cred = PeerCred {
            pid: 1,
            uid: 0,
            gid: 0,
        };

        // Reap any finished stopped background threads without blocking KernelActor.
        let mut idx = 0;
        while idx < self.stopping_threads.len() {
            if self.stopping_threads[idx].is_finished() {
                let h = self.stopping_threads.swap_remove(idx);
                let _ = h.join();
            } else {
                idx += 1;
            }
        }
        if self.bg_thread.as_ref().is_some_and(|h| h.is_finished()) {
            if let Some(h) = self.bg_thread.take() {
                let _ = h.join();
            }
            self.running = false;
            self.status.running = false;
            self.stop_tx = None;
        }

        // Complete any non-blocking background Enroll RPC.
        if let Some((cid, rx)) = self.pending_enroll.take() {
            match rx.try_recv() {
                Ok(res) => {
                    did_work = true;
                    let reply = match res {
                        Ok(en) => {
                            self.status.state = "enrolled".into();
                            self.status.enrolled = true;
                            self.status.node_id = Some(en.node_id.clone());
                            self.status.cluster = Some(en.cluster.clone());
                            self.status.tenant = Some(en.tenant.clone());
                            self.status.enrollment_id = Some(en.enrollment_id.clone());
                            self.status.instance_id = Some(en.instance_id.clone());
                            self.status.last_error = None;
                            KubeletHostReply::Enrolled {
                                node_id: en.node_id,
                                cluster: en.cluster,
                                tenant: en.tenant,
                                enrollment_id: en.enrollment_id,
                                instance_id: en.instance_id,
                            }
                        }
                        Err(msg) => KubeletHostReply::Error {
                            errno: Errno::EACCES,
                            message: msg,
                        },
                    };
                    Self::send_reply_and_close(socks, cid, root_cred, &reply);
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    self.pending_enroll = Some((cid, rx));
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    did_work = true;
                    let reply = KubeletHostReply::Error {
                        errno: Errno::EIO,
                        message: "enroll worker terminated".into(),
                    };
                    Self::send_reply_and_close(socks, cid, root_cred, &reply);
                }
            }
        }

        let Some(listener_id) = self.listener_id else {
            return did_work;
        };
        while let Ok(accepted) = socks.accept(KERNEL_HOST_PID, listener_id, root_cred) {
            did_work = true;
            if accepted.peer_cred.uid != 0
                || !kubelet_pids.contains(&accepted.peer_cred.pid)
                || self.clients.len() >= MAX_KUBELET_HOST_CLIENTS
            {
                let _ = socks.close(KERNEL_HOST_PID, accepted.sock_id, 1);
                continue;
            }
            let _ = socks.set_nonblock(KERNEL_HOST_PID, accepted.sock_id, true);
            self.clients.insert(accepted.sock_id, Vec::new());
        }

        let client_ids: Vec<SockId> = self.clients.keys().copied().collect();
        for cid in client_ids {
            match socks.recvmsg(KERNEL_HOST_PID, cid, 65_536, 0, 0, None) {
                Ok(recv) => {
                    did_work = true;
                    if recv.data.is_empty() {
                        self.clients.remove(&cid);
                        let _ = socks.close(KERNEL_HOST_PID, cid, 1);
                        continue;
                    }
                    let buf = self.clients.entry(cid).or_default();
                    if buf.len().saturating_add(recv.data.len())
                        > abi::kubelet_ctl::MAX_FRAME_BYTES + 4
                    {
                        self.clients.remove(&cid);
                        let _ = socks.close(KERNEL_HOST_PID, cid, 1);
                        continue;
                    }
                    buf.extend_from_slice(&recv.data);
                    if buf.len() >= 4 {
                        let expected =
                            u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
                        if expected == 0 || expected > abi::kubelet_ctl::MAX_FRAME_BYTES {
                            self.clients.remove(&cid);
                            let _ = socks.close(KERNEL_HOST_PID, cid, 1);
                            continue;
                        }
                        if buf.len() >= 4 + expected {
                            let payload = buf[4..4 + expected].to_vec();
                            self.clients.remove(&cid);
                            match decode_payload::<KubeletHostRequest>(&payload) {
                                Ok(KubeletHostRequest::Enroll {
                                    bootstrap_token,
                                    control_plane_url,
                                    ..
                                }) => {
                                    if self.pending_enroll.is_some() {
                                        let reply = KubeletHostReply::Error {
                                            errno: Errno::EBUSY,
                                            message: "enrollment already in progress".into(),
                                        };
                                        Self::send_reply_and_close(socks, cid, root_cred, &reply);
                                        continue;
                                    }
                                    let Some(url) = control_plane_url else {
                                        let reply = KubeletHostReply::Error {
                                            errno: Errno::EINVAL,
                                            message: "control_plane_url required on os-native"
                                                .into(),
                                        };
                                        Self::send_reply_and_close(socks, cid, root_cred, &reply);
                                        continue;
                                    };
                                    let dir = state_dir.to_path_buf();
                                    let (tx, rx) = std::sync::mpsc::channel();
                                    let _ = std::thread::Builder::new()
                                        .name("os-native-kubelet-enroll".into())
                                        .spawn(move || {
                                            let res = tokio::runtime::Builder::new_current_thread()
                                                .enable_all()
                                                .build()
                                                .map_err(|e| e.to_string())
                                                .and_then(|rt| {
                                                    rt.block_on(enroll_native_node(
                                                        &dir,
                                                        &url,
                                                        &bootstrap_token,
                                                    ))
                                                });
                                            let _ = tx.send(res);
                                        });
                                    self.pending_enroll = Some((cid, rx));
                                }
                                Ok(req) => {
                                    let reply = self.handle_req(state_dir, req);
                                    Self::send_reply_and_close(socks, cid, root_cred, &reply);
                                }
                                Err(e) => {
                                    let reply = KubeletHostReply::Error {
                                        errno: e.errno,
                                        message: e.to_string(),
                                    };
                                    Self::send_reply_and_close(socks, cid, root_cred, &reply);
                                }
                            }
                        }
                    }
                }
                Err(Errno::EAGAIN) => {}
                Err(_) => {
                    self.clients.remove(&cid);
                    let _ = socks.close(KERNEL_HOST_PID, cid, 1);
                }
            }
        }
        did_work
    }

    fn handle_req(&mut self, state_dir: &Path, req: KubeletHostRequest) -> KubeletHostReply {
        match req {
            KubeletHostRequest::Hello { versions } => {
                if !versions.contains(&KUBELET_CTL_VERSION) {
                    KubeletHostReply::Error {
                        errno: Errno::EPROTONOSUPPORT,
                        message: format!("unsupported kubelet ctl versions {versions:?}"),
                    }
                } else {
                    KubeletHostReply::Welcome {
                        version: KUBELET_CTL_VERSION,
                        host_kind: "os-native".into(),
                    }
                }
            }
            KubeletHostRequest::Enroll { .. } => KubeletHostReply::Error {
                errno: Errno::EINVAL,
                message: "enroll handled asynchronously".into(),
            },
            KubeletHostRequest::Start {
                control_plane_url,
                lease_ttl_secs,
                labels,
                ..
            } => {
                let enroll_file = enrollment_path(state_dir);
                let mut enroll = match NodeEnrollment::load(&enroll_file) {
                    Ok(e) => e,
                    Err(msg) => {
                        return KubeletHostReply::Error {
                            errno: Errno::ENOENT,
                            message: msg,
                        };
                    }
                };
                if let Some(url) = control_plane_url {
                    enroll.base_url = url.trim_end_matches('/').to_string();
                }
                if !self.running {
                    let (tx, rx) = watch::channel(false);
                    let drain_flag = Arc::new(AtomicBool::new(false));
                    let mut opts = NativeKubeletRunOptions::new(state_dir.to_path_buf());
                    if let Some(ttl) = lease_ttl_secs {
                        opts.lease_ttl_secs = ttl;
                    }
                    opts.labels = labels;
                    opts.drain_flag = Some(Arc::clone(&drain_flag));
                    let en_clone = enroll.clone();
                    let handle = std::thread::Builder::new()
                        .name("os-native-kubelet".into())
                        .spawn(move || {
                            if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                                .enable_all()
                                .build()
                            {
                                let _ = rt.block_on(run_native_kubelet_loop(en_clone, opts, rx));
                            }
                        })
                        .ok();
                    self.drain_flag = drain_flag;
                    self.stop_tx = Some(tx);
                    self.bg_thread = handle;
                    self.running = true;
                }
                self.status.state = "running".into();
                self.status.enrolled = true;
                self.status.running = true;
                self.status.node_id = Some(enroll.node_id);
                self.status.cluster = Some(enroll.cluster);
                self.status.tenant = Some(enroll.tenant);
                self.status.enrollment_id = Some(enroll.enrollment_id);
                self.status.instance_id = Some(enroll.instance_id);
                KubeletHostReply::Started {
                    status: self.status.clone(),
                }
            }
            KubeletHostRequest::Status {} => {
                if !self.status.enrolled
                    && let Ok(en) = NodeEnrollment::load(&enrollment_path(state_dir))
                {
                    self.status.state = "enrolled".into();
                    self.status.enrolled = true;
                    self.status.node_id = Some(en.node_id);
                    self.status.cluster = Some(en.cluster);
                    self.status.tenant = Some(en.tenant);
                    self.status.enrollment_id = Some(en.enrollment_id);
                    self.status.instance_id = Some(en.instance_id);
                }
                KubeletHostReply::Status {
                    status: self.status.clone(),
                }
            }
            KubeletHostRequest::Drain {} => {
                self.drain_flag.store(true, Ordering::SeqCst);
                self.status.state = "draining".into();
                KubeletHostReply::Draining {
                    status: self.status.clone(),
                }
            }
            KubeletHostRequest::Stop {} => {
                self.drain_flag.store(true, Ordering::SeqCst);
                if let Some(tx) = self.stop_tx.take() {
                    let _ = tx.send(true);
                }
                if let Some(h) = self.bg_thread.take() {
                    self.stopping_threads.push(h);
                }
                self.running = false;
                self.status.running = false;
                self.status.state = if self.status.enrolled {
                    "enrolled".into()
                } else {
                    "stopped".into()
                };
                KubeletHostReply::Stopped {
                    status: self.status.clone(),
                }
            }
        }
    }
}

impl Drop for KubeletHostServer {
    fn drop(&mut self) {
        self.drain_flag.store(true, Ordering::SeqCst);
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(true);
        }
        if let Some(h) = self.bg_thread.take() {
            let _ = h.join();
        }
        for h in self.stopping_threads.drain(..) {
            let _ = h.join();
        }
    }
}
