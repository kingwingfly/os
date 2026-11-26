//! Conformance suite `KB-01`: pure-Rust `os-task-sdk` codec, guest path confinement,
//! `TaskSubmitter` (including Map-Reduce fan-out/fan-in), and `KubeletEngine` fencing/reclaim/cleanup
//! against `MemoryClusterStore`.
use abi::auth_v2::RemoteScope;
use abi::cluster_state::NodeMetaRecord;
use os_cluster_state::fencing::FencedPublishFailure;
use os_cluster_state::memory::MemoryClusterStore;
use os_cluster_state::{BoxFuture, ClusterGrant, ClusterStore};
use os_task_sdk::agent::{
    ArtifactStager, AttemptExecutionReport, KubeletConfig, KubeletEngine, SandboxRunOutcome,
    SandboxRunRequest, SandboxRunner, StagedArtifact,
};
use os_task_sdk::client::TaskSubmitter;
use os_task_sdk::guest::TaskEnv;
use os_task_sdk::{MapReduceSpec, MapShardSpec, TaskSpec, matches_node};
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

fn block_on<F: Future>(fut: F) -> F::Output {
    fn clone(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    fn noop(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&waker);
    let mut fut = Box::pin(fut);
    match Pin::as_mut(&mut fut).poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("MemoryClusterStore future unexpectedly returned Pending"),
    }
}

#[derive(Clone)]
struct SharedMemStore(Arc<MemoryClusterStore>);

impl ClusterStore for SharedMemStore {
    fn rpc<'a>(
        &'a self,
        grant: &'a ClusterGrant,
        call: abi::cluster_state::ClusterCall,
        now_secs: u64,
    ) -> BoxFuture<'a, Result<abi::cluster_state::ClusterReply, abi::cluster_state::ClusterError>>
    {
        self.0.rpc(grant, call, now_secs)
    }

    fn poll_watch<'a>(
        &'a self,
        grant: &'a ClusterGrant,
        cursor: &'a mut os_cluster_state::WatchCursor,
        limit: u32,
        now_secs: u64,
    ) -> BoxFuture<'a, Result<os_cluster_state::WatchBatch, abi::cluster_state::ClusterError>> {
        self.0.poll_watch(grant, cursor, limit, now_secs)
    }
}

fn admin_grant() -> ClusterGrant {
    ClusterGrant {
        tenant: "u0".into(),
        owner: "admin".into(),
        admin: true,
        scope: RemoteScope::full(),
    }
}

fn node_grant(node_id: &str) -> ClusterGrant {
    ClusterGrant {
        tenant: "u0".into(),
        owner: format!("node:{node_id}"),
        admin: false,
        scope: RemoteScope::node_ceiling(node_id),
    }
}

#[derive(Default)]
struct MockRunner {
    cleaned: Mutex<Vec<(String, u64)>>,
}

impl SandboxRunner for MockRunner {
    fn run_attempt<'a>(
        &'a self,
        req: &'a SandboxRunRequest,
    ) -> BoxFuture<'a, Result<SandboxRunOutcome, abi::cluster_state::ClusterError>> {
        Box::pin(async move {
            Ok(SandboxRunOutcome {
                exit_code: 0,
                summary: Some(format!("ran {} on {}", req.workload_id, req.node_id)),
                output_handle: Some(format!(
                    "out-{}-{}",
                    req.workload_id, req.attempt_generation
                )),
            })
        })
    }

    fn cleanup_attempt<'a>(
        &'a self,
        workload_id: &'a str,
        attempt_generation: u64,
    ) -> BoxFuture<'a, ()> {
        let wid = workload_id.to_string();
        Box::pin(async move {
            self.cleaned.lock().unwrap().push((wid, attempt_generation));
        })
    }
}

#[derive(Default)]
struct MockStager {
    promoted: Mutex<Vec<String>>,
    cleaned_staged: Mutex<Vec<String>>,
}

impl ArtifactStager for MockStager {
    fn stage_output<'a>(
        &'a self,
        req: &'a SandboxRunRequest,
        outcome: &'a SandboxRunOutcome,
    ) -> BoxFuture<'a, Result<Option<StagedArtifact>, abi::cluster_state::ClusterError>> {
        Box::pin(async move {
            let Some(_) = outcome.output_handle else {
                return Ok(None);
            };
            let digest = format!(
                "sha256:{:064x}",
                (req.attempt_generation << 8) + req.node_generation
            );
            Ok(Some(StagedArtifact {
                repo: req.spec.output_repo.clone(),
                staging_tag: format!(
                    "staging-{}-{}-{}",
                    req.workload_id, req.attempt_generation, req.node_generation
                ),
                manifest_digest: digest.clone(),
                media_type: abi::registry::OCI_IMAGE_MANIFEST_MEDIA_TYPE.into(),
                output_ref: format!("oci:{}@{digest}", req.spec.output_repo),
            }))
        })
    }

    fn promote_staged<'a>(
        &'a self,
        _req: &'a SandboxRunRequest,
        staged: &'a StagedArtifact,
    ) -> BoxFuture<'a, Result<String, abi::cluster_state::ClusterError>> {
        let out_ref = staged.output_ref.clone();
        Box::pin(async move {
            self.promoted.lock().unwrap().push(out_ref.clone());
            Ok(out_ref)
        })
    }

    fn cleanup_staged<'a>(
        &'a self,
        _req: &'a SandboxRunRequest,
        staged: &'a StagedArtifact,
    ) -> BoxFuture<'a, ()> {
        let tag = staged.staging_tag.clone();
        Box::pin(async move {
            self.cleaned_staged.lock().unwrap().push(tag);
        })
    }
}

#[test]
fn kb01_task_spec_codec_and_guest_confinement() {
    let mut env = BTreeMap::new();
    env.insert("FOO".into(), "bar".into());
    let mut extra_inputs = BTreeMap::new();
    extra_inputs.insert("shard-0".into(), "oci:tasks/out@sha256:aa".into());
    let spec = TaskSpec {
        workload_id: "wl-codec-1".into(),
        image_ref: "oci:tasks/app@sha256:00".into(),
        entrypoint: "/usr/bin/task.wasm".into(),
        args: vec!["--mode".into(), "fast".into()],
        env,
        input_snapshot_ref: Some("oci:tasks/in@sha256:11".into()),
        extra_inputs,
        output_repo: "tasks/results".into(),
        timeout_secs: 60,
        memory_max_bytes: 32 * 1024 * 1024,
        pids_max: 8,
        required_host: Some("os-native".into()),
        required_node: None,
        required_caps: vec!["wasix".into()],
        user_labels: BTreeMap::from([("team".into(), "core".into())]),
    };
    let wl = spec.to_workload_record(1000).unwrap();
    let decoded = TaskSpec::from_workload_record(&wl).unwrap();
    assert_eq!(decoded, spec);

    let meta_native = NodeMetaRecord {
        node_id: "node-a".into(),
        host_kind: "os-native".into(),
        labels: BTreeMap::new(),
        capabilities: vec!["wasix".into()],
        enrolled_at: 1000,
    };
    let meta_browser = NodeMetaRecord {
        host_kind: "browser".into(),
        ..meta_native.clone()
    };
    assert!(matches_node(&spec, &meta_native));
    assert!(!matches_node(&spec, &meta_browser));

    // Guest confinement rejects `..`, absolute paths, and NUL.
    let tmp = std::env::temp_dir().join(format!("os-task-sdk-kb01-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let in_dir = tmp.join("input");
    let out_dir = tmp.join("output");
    std::fs::create_dir_all(&in_dir).unwrap();
    std::fs::create_dir_all(&out_dir).unwrap();
    std::fs::write(in_dir.join("data.json"), br#"{"x":42}"#).unwrap();

    let guest_env = TaskEnv::with_dirs(&in_dir, &out_dir);
    let parsed: serde_json::Value = guest_env.read_input_json("data.json").unwrap();
    assert_eq!(parsed["x"], 42);
    assert_eq!(guest_env.list_inputs("").unwrap(), vec!["data.json"]);
    guest_env
        .write_output_json("nested/res.json", &serde_json::json!({"ok": true}))
        .unwrap();
    guest_env.write_summary("done").unwrap();
    assert!(guest_env.read_input_bytes("../etc/shadow").is_err());
    assert!(guest_env.read_input_bytes("/etc/shadow").is_err());
    assert!(guest_env.write_output_bytes("../escape", b"x").is_err());
    assert!(guest_env.write_output_bytes("/tmp/escape", b"x").is_err());
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn kb01_kubelet_engine_failover_reclaim_stale_cleanup_and_map_reduce() {
    let mem = Arc::new(MemoryClusterStore::new("default"));
    let shared = SharedMemStore(Arc::clone(&mem));
    let clock_val = Arc::new(std::sync::atomic::AtomicU64::new(1000));
    let clock = {
        let c = Arc::clone(&clock_val);
        Arc::new(move || c.load(std::sync::atomic::Ordering::SeqCst))
    };
    let submitter = TaskSubmitter::new(shared.clone(), admin_grant(), clock);

    let mut engine_a = KubeletEngine::new(
        shared.clone(),
        node_grant("node-a"),
        KubeletConfig {
            node_id: "node-a".into(),
            host_kind: "os-native".into(),
            instance_id: "inst-a".into(),
            labels: BTreeMap::new(),
            capabilities: vec!["wasix".into()],
            lease_ttl_secs: 10,
        },
    )
    .unwrap();
    let mut engine_b = KubeletEngine::new(
        shared.clone(),
        node_grant("node-b"),
        KubeletConfig {
            node_id: "node-b".into(),
            host_kind: "browser".into(),
            instance_id: "inst-b".into(),
            labels: BTreeMap::new(),
            capabilities: vec!["wasix".into()],
            lease_ttl_secs: 60,
        },
    )
    .unwrap();

    let lease_a = block_on(engine_a.register(1000, 1000)).unwrap();
    assert_eq!(lease_a.node_generation, 1);
    let lease_b = block_on(engine_b.register(1000, 1000)).unwrap();
    assert_eq!(lease_b.node_generation, 1);

    // 1. Failover test: Node A claims attempt 1, pauses until its lease expires, Node B reclaims
    //    attempt 2 and publishes, then stale Node A tries to publish and gets NodeFenced + cleanup!
    let failover_spec = TaskSpec {
        workload_id: "wl-failover".into(),
        image_ref: "oci:tasks/work@sha256:00".into(),
        entrypoint: "/usr/bin/work.wasm".into(),
        args: vec![],
        env: BTreeMap::new(),
        input_snapshot_ref: None,
        extra_inputs: BTreeMap::new(),
        output_repo: "tasks/out".into(),
        timeout_secs: 60,
        memory_max_bytes: 32 * 1024 * 1024,
        pids_max: 8,
        required_host: None,
        required_node: None,
        required_caps: vec!["wasix".into()],
        user_labels: BTreeMap::new(),
    };
    block_on(submitter.submit_task(&failover_spec)).unwrap();

    let claimed_a = block_on(engine_a.try_claim_next(1001, 2000))
        .unwrap()
        .expect("node-a claims attempt 1");
    assert_eq!(claimed_a.attempt.attempt_generation, 1);

    // While Node A's lease is live, Node B cannot reclaim!
    assert!(
        block_on(engine_b.try_claim_next(1005, 6000))
            .unwrap()
            .is_none()
    );

    // Node A's lease expires at t=1011; Node B reclaims attempt 2 and publishes cleanly!
    assert_eq!(mem.expire_due_leases(1011), 1);
    let runner_b = MockRunner::default();
    let stager_b = MockStager::default();
    let rep_b = block_on(engine_b.poll_and_execute_one(&runner_b, &stager_b, 1012, 13_000))
        .unwrap()
        .expect("node-b reclaims and runs attempt 2");
    assert!(matches!(
        rep_b,
        AttemptExecutionReport::Published {
            attempt_generation: 2,
            ..
        }
    ));
    assert_eq!(stager_b.promoted.lock().unwrap().len(), 1);

    // Stale Node A (pretending its monotonic clock was paused during SIGSTOP) tries to commit
    // attempt 1 -> rejected as AlreadyPublished (EEXIST) or NodeFenced (ESTALE) & cleans staged artifact!
    let runner_a = MockRunner::default();
    let stager_a = MockStager::default();
    let rep_a =
        block_on(engine_a.execute_claimed(claimed_a, &runner_a, &stager_a, 1013, 2500)).unwrap();
    assert!(matches!(
        rep_a,
        AttemptExecutionReport::Rejected {
            failure: FencedPublishFailure::AlreadyPublished | FencedPublishFailure::NodeFenced,
            ..
        }
    ));
    assert_eq!(stager_a.cleaned_staged.lock().unwrap().len(), 1);
    assert_eq!(runner_a.cleaned.lock().unwrap().len(), 1);

    // Re-registering Node A rotates node_generation monotonically to 2!
    let lease_a2 = block_on(engine_a.register(1015, 16_000)).unwrap();
    assert_eq!(lease_a2.node_generation, 2);

    // 2. End-to-end 2-shard Map-Reduce split across Node A (os-native) and Node B (browser)!
    let mr = MapReduceSpec {
        job_id: "mr-1".into(),
        map_image_ref: "oci:tasks/mr@sha256:01".into(),
        map_entrypoint: "/usr/bin/map.wasm".into(),
        reduce_image_ref: "oci:tasks/mr@sha256:01".into(),
        reduce_entrypoint: "/usr/bin/reduce.wasm".into(),
        shards: vec![
            MapShardSpec {
                input_snapshot_ref: Some("oci:tasks/in@sha256:aa".into()),
                args: vec!["0".into()],
                env: BTreeMap::new(),
                required_host: Some("os-native".into()),
                required_node: None,
            },
            MapShardSpec {
                input_snapshot_ref: Some("oci:tasks/in@sha256:bb".into()),
                args: vec!["1".into()],
                env: BTreeMap::new(),
                required_host: Some("browser".into()),
                required_node: None,
            },
        ],
        reduce_args: vec![],
        reduce_env: BTreeMap::new(),
        reduce_required_host: Some("os-native".into()),
        reduce_required_node: None,
        output_repo: "tasks/mr-out".into(),
        timeout_secs: 60,
        memory_max_bytes: 32 * 1024 * 1024,
        pids_max: 8,
    };

    // Drive submitter + both engines interleaved via deterministic single-threaded poll step!
    let engines = Arc::new(Mutex::new(Some((engine_a, engine_b))));
    let runner_mr = Arc::new(MockRunner::default());
    let stager_mr = Arc::new(MockStager::default());
    let mr_res = block_on(submitter.submit_map_reduce(
        &mr,
        || {
            let engs = Arc::clone(&engines);
            let r = Arc::clone(&runner_mr);
            let s = Arc::clone(&stager_mr);
            Box::pin(async move {
                let (mut ea, mut eb) = engs.lock().unwrap().take().unwrap();
                let _ = ea.poll_and_execute_one(&*r, &*s, 1016, 17_000).await;
                let _ = eb.poll_and_execute_one(&*r, &*s, 1016, 17_000).await;
                *engs.lock().unwrap() = Some((ea, eb));
            })
        },
        16,
    ))
    .unwrap();

    assert_eq!(mr_res.map_results.len(), 2);
    assert_eq!(mr_res.map_results[0].node_id(), "node-a");
    assert_eq!(mr_res.map_results[1].node_id(), "node-b");
    assert_eq!(mr_res.reduce_result.node_id(), "node-a");
    assert!(mr_res.reduce_result.succeeded());
    assert!(mr_res.reduce_result.output_ref().is_some());
}

#[test]
fn kb01_live_post_execution_self_fence_aborts_before_staging() {
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    let store = SharedMemStore(Arc::new(MemoryClusterStore::new("default")));
    let submitter = TaskSubmitter::new(store.clone(), admin_grant(), Arc::new(|| 2001));
    let mut engine = KubeletEngine::new(
        store.clone(),
        node_grant("node-slow"),
        KubeletConfig {
            node_id: "node-slow".into(),
            host_kind: "os-native".into(),
            instance_id: "inst-slow".into(),
            labels: BTreeMap::new(),
            capabilities: vec!["wasix".into()],
            lease_ttl_secs: 6,
        },
    )
    .unwrap();
    let lease = block_on(engine.register(2000, 1000)).unwrap();

    let spec = TaskSpec {
        workload_id: "wl-fence-live".into(),
        image_ref: "oci:tasks/demo@sha256:aa".into(),
        entrypoint: "/usr/bin/app.wasm".into(),
        args: vec![],
        env: BTreeMap::new(),
        input_snapshot_ref: None,
        extra_inputs: BTreeMap::new(),
        output_repo: "tasks/out".into(),
        timeout_secs: 60,
        memory_max_bytes: 32 * 1024 * 1024,
        pids_max: 8,
        required_host: None,
        required_node: Some("node-slow".into()),
        required_caps: vec![],
        user_labels: BTreeMap::new(),
    };
    block_on(submitter.submit_task(&spec)).unwrap();

    // Runner advances the live monotonic clock past self_fence_deadline_ms during execution!
    struct AdvancingClockRunner {
        mono: Arc<AtomicU64>,
        advance_to: u64,
        cleaned: Mutex<Vec<(String, u64)>>,
    }
    impl SandboxRunner for AdvancingClockRunner {
        fn run_attempt<'a>(
            &'a self,
            _req: &'a SandboxRunRequest,
        ) -> BoxFuture<'a, Result<SandboxRunOutcome, abi::cluster_state::ClusterError>> {
            Box::pin(async move {
                self.mono.store(self.advance_to, Ordering::SeqCst);
                Ok(SandboxRunOutcome {
                    exit_code: 0,
                    summary: Some("should-never-stage".into()),
                    output_handle: Some("out-stale".into()),
                })
            })
        }
        fn cleanup_attempt<'a>(
            &'a self,
            workload_id: &'a str,
            attempt_generation: u64,
        ) -> BoxFuture<'a, ()> {
            let wid = workload_id.to_string();
            Box::pin(async move {
                self.cleaned.lock().unwrap().push((wid, attempt_generation));
            })
        }
    }

    #[derive(Default)]
    struct CountingStager {
        stage_calls: AtomicUsize,
    }
    impl ArtifactStager for CountingStager {
        fn stage_output<'a>(
            &'a self,
            _req: &'a SandboxRunRequest,
            _outcome: &'a SandboxRunOutcome,
        ) -> BoxFuture<'a, Result<Option<StagedArtifact>, abi::cluster_state::ClusterError>>
        {
            self.stage_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(None) })
        }
        fn promote_staged<'a>(
            &'a self,
            _req: &'a SandboxRunRequest,
            staged: &'a StagedArtifact,
        ) -> BoxFuture<'a, Result<String, abi::cluster_state::ClusterError>> {
            let r = staged.output_ref.clone();
            Box::pin(async move { Ok(r) })
        }
        fn cleanup_staged<'a>(
            &'a self,
            _req: &'a SandboxRunRequest,
            _staged: &'a StagedArtifact,
        ) -> BoxFuture<'a, ()> {
            Box::pin(async {})
        }
    }

    let mono = Arc::new(AtomicU64::new(1500));
    let runner = AdvancingClockRunner {
        mono: Arc::clone(&mono),
        advance_to: lease.self_fence_deadline_ms + 500,
        cleaned: Mutex::new(Vec::new()),
    };
    let stager = CountingStager::default();
    let report = block_on(engine.poll_and_execute_one_live(
        &runner,
        &stager,
        || 2002,
        || mono.load(Ordering::SeqCst),
        || Some(lease.self_fence_deadline_ms),
    ))
    .unwrap();
    assert_eq!(
        report,
        Some(AttemptExecutionReport::AbortedBeforePublish {
            workload_id: "wl-fence-live".into(),
            attempt_generation: 1,
            errno: abi::Errno::ESTALE,
        })
    );
    assert_eq!(
        stager.stage_calls.load(Ordering::SeqCst),
        0,
        "self-fenced node must abort BEFORE staging any OCI artifact"
    );
    assert_eq!(
        *runner.cleaned.lock().unwrap(),
        vec![("wl-fence-live".to_string(), 1)]
    );
}
