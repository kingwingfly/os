//! Portable `kubelet` execution engine encapsulating registration, monotonic `node_generation`,
//! self-fencing, workload discovery, pending claim, dead-node failover reclaim, fenced result
//! publication, and guaranteed cleanup on `ESTALE`/`ECANCELED`/`EEXIST` (`Phase 9.1b #84`).
use crate::{TaskSpec, matches_node};
use abi::Errno;
use abi::cluster_state::{
    AttemptRecord, CLUSTER_LEASE_MAX_TTL_SECS, CLUSTER_LEASE_MIN_TTL_SECS, ClusterCall,
    ClusterError, ClusterReply, NodeMetaRecord, NodeRecord, OutboxRecord, RangeEnd, ResultRecord,
    TxnOp, WorkloadRecord,
};
use os_cluster_state::fencing::{
    FencedPublishFailure, FencedPublishOutcome, attempt_key, build_claim_attempt_txn,
    build_publish_result_txn, build_reclaim_attempt_txn, build_register_node_txn,
    classify_fenced_publish_result, decode_record, encode_record, node_key, node_meta_key,
    result_key, workload_canceled_key,
};
use os_cluster_state::{BoxFuture, ClusterGrant, ClusterStore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Label stored in durable `node-meta/<node_id>` to preserve strictly monotonic `node_generation`
/// across lease expirations and node restarts.
pub const NODE_META_LAST_GEN_LABEL: &str = "os.node/last_generation";

/// Static identity & scheduling configuration for a `KubeletEngine`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KubeletConfig {
    pub node_id: String,
    pub host_kind: String, // "browser" | "os-native" | "container"
    pub instance_id: String,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    pub lease_ttl_secs: u64,
}

/// Active lease & fencing state of a registered node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeLeaseState {
    pub node_generation: u64,
    pub node_mod_revision: u64,
    pub lease_id: u64,
    pub ttl_secs: u64,
    /// Client-local monotonic millisecond deadline after which the node MUST self-fence.
    pub self_fence_deadline_ms: u64,
    pub status: String,
}

/// Self-fence safety margin in seconds: `max(2, ttl / 5)`, clamped below `ttl`.
pub fn self_fence_margin_secs(ttl_secs: u64) -> u64 {
    let margin = (ttl_secs / 5).max(2);
    margin.min(ttl_secs.saturating_sub(1))
}

/// Compute client monotonic self-fence deadline from the request transmission timestamp.
pub fn compute_self_fence_deadline_ms(send_mono_ms: u64, ttl_secs: u64) -> u64 {
    let valid_secs = ttl_secs.saturating_sub(self_fence_margin_secs(ttl_secs));
    send_mono_ms.saturating_add(valid_secs.saturating_mul(1000))
}

/// Request handed to a host [`SandboxRunner`] after an attempt is atomically claimed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SandboxRunRequest {
    pub workload_id: String,
    pub attempt_generation: u64,
    pub node_id: String,
    pub node_generation: u64,
    pub spec: TaskSpec,
}

/// Outcome returned by a host [`SandboxRunner`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SandboxRunOutcome {
    pub exit_code: i32,
    pub summary: Option<String>,
    /// Opaque local output volume handle or snapshot identifier passed to [`ArtifactStager`].
    pub output_handle: Option<String>,
}

/// Reference to a staged output snapshot uploaded before the fenced commit transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedArtifact {
    pub repo: String,
    pub staging_tag: String,
    pub manifest_digest: String,
    pub media_type: String,
    /// Canonical immutable reference (`oci:<repo>@<manifest_digest>`).
    pub output_ref: String,
}

/// Host sandbox runner abstraction (implemented by `os-native` `SandboxInstance`,
/// browser `SandboxKernel`, or pure-Rust mocks in unit conformance tests).
pub trait SandboxRunner {
    fn run_attempt<'a>(
        &'a self,
        req: &'a SandboxRunRequest,
    ) -> BoxFuture<'a, Result<SandboxRunOutcome, ClusterError>>;

    fn cleanup_attempt<'a>(
        &'a self,
        workload_id: &'a str,
        attempt_generation: u64,
    ) -> BoxFuture<'a, ()>;
}

/// Output snapshot staging/promotion/cleanup abstraction.
pub trait ArtifactStager {
    fn stage_output<'a>(
        &'a self,
        req: &'a SandboxRunRequest,
        outcome: &'a SandboxRunOutcome,
    ) -> BoxFuture<'a, Result<Option<StagedArtifact>, ClusterError>>;

    fn promote_staged<'a>(
        &'a self,
        req: &'a SandboxRunRequest,
        staged: &'a StagedArtifact,
    ) -> BoxFuture<'a, Result<String, ClusterError>>;

    fn cleanup_staged<'a>(
        &'a self,
        req: &'a SandboxRunRequest,
        staged: &'a StagedArtifact,
    ) -> BoxFuture<'a, ()>;
}

/// Summary of one claimed & executed attempt cycle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttemptExecutionReport {
    Published {
        workload_id: String,
        attempt_generation: u64,
        revision: u64,
        exit_code: i32,
        output_ref: Option<String>,
    },
    Rejected {
        workload_id: String,
        attempt_generation: u64,
        failure: FencedPublishFailure,
    },
    AbortedBeforePublish {
        workload_id: String,
        attempt_generation: u64,
        errno: Errno,
    },
}

/// Portable kubelet state machine driving fenced registration, claim/reclaim, execution,
/// staging, publication, and cleanup over any [`ClusterStore`].
pub struct KubeletEngine<S: ClusterStore> {
    store: S,
    grant: ClusterGrant,
    config: KubeletConfig,
    meta: NodeMetaRecord,
    lease: Option<NodeLeaseState>,
    draining: bool,
    completed_attempts: u64,
}

impl<S: ClusterStore> KubeletEngine<S> {
    pub fn new(store: S, grant: ClusterGrant, config: KubeletConfig) -> Result<Self, ClusterError> {
        if !(CLUSTER_LEASE_MIN_TTL_SECS..=CLUSTER_LEASE_MAX_TTL_SECS)
            .contains(&config.lease_ttl_secs)
        {
            return Err(ClusterError::because(
                Errno::EINVAL,
                "invalid kubelet lease_ttl_secs",
            ));
        }
        let meta = NodeMetaRecord {
            node_id: config.node_id.clone(),
            host_kind: config.host_kind.clone(),
            labels: config.labels.clone(),
            capabilities: config.capabilities.clone(),
            enrolled_at: 0,
        };
        meta.validate()?;
        Ok(Self {
            store,
            grant,
            config,
            meta,
            lease: None,
            draining: false,
            completed_attempts: 0,
        })
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn grant(&self) -> &ClusterGrant {
        &self.grant
    }

    pub fn config(&self) -> &KubeletConfig {
        &self.config
    }

    pub fn meta(&self) -> &NodeMetaRecord {
        &self.meta
    }

    pub fn lease_state(&self) -> Option<&NodeLeaseState> {
        self.lease.as_ref()
    }

    pub fn completed_attempts(&self) -> u64 {
        self.completed_attempts
    }

    pub fn is_draining(&self) -> bool {
        self.draining
    }

    pub fn is_self_fenced(&self, now_mono_ms: u64) -> bool {
        match &self.lease {
            Some(l) => now_mono_ms >= l.self_fence_deadline_ms,
            None => true,
        }
    }

    pub fn update_self_fence_deadline_ms(&mut self, deadline_ms: u64) {
        if let Some(ref mut l) = self.lease {
            l.self_fence_deadline_ms = deadline_ms;
        }
    }

    /// Register (or rotate generation for) this node in `ClusterState` with a fresh lease.
    pub async fn register(
        &mut self,
        now_secs: u64,
        now_mono_ms: u64,
    ) -> Result<NodeLeaseState, ClusterError> {
        let tenant = self.grant.tenant.clone();
        let node_k = node_key(&tenant, &self.config.node_id)?;
        let meta_k = node_meta_key(&tenant, &self.config.node_id)?;

        let prev_meta: Option<NodeMetaRecord> = match self
            .store
            .rpc(
                &self.grant,
                ClusterCall::Range {
                    key: meta_k,
                    range_end: RangeEnd::Exact,
                    revision: 0,
                    limit: Some(1),
                    keys_only: false,
                    count_only: false,
                },
                now_secs,
            )
            .await?
        {
            ClusterReply::Range { kvs, .. } => kvs.first().and_then(|kv| decode_record(kv).ok()),
            _ => None,
        };

        let prev_node_kv = match self
            .store
            .rpc(
                &self.grant,
                ClusterCall::Range {
                    key: node_k,
                    range_end: RangeEnd::Exact,
                    revision: 0,
                    limit: Some(1),
                    keys_only: false,
                    count_only: false,
                },
                now_secs,
            )
            .await?
        {
            ClusterReply::Range { kvs, .. } => kvs.into_iter().next(),
            _ => None,
        };

        let prev_live_gen = prev_node_kv
            .as_ref()
            .and_then(|kv| decode_record::<NodeRecord>(kv).ok())
            .map_or(0, |r| r.node_generation);
        let prev_meta_gen = prev_meta
            .as_ref()
            .and_then(|m| m.labels.get(NODE_META_LAST_GEN_LABEL))
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        let next_gen = prev_live_gen
            .max(prev_meta_gen)
            .max(self.lease.as_ref().map_or(0, |l| l.node_generation))
            .saturating_add(1);
        let expected_prev_mod = prev_node_kv.as_ref().map(|kv| kv.mod_revision);

        let send_mono = now_mono_ms;
        let lease_id = match self
            .store
            .rpc(
                &self.grant,
                ClusterCall::LeaseGrant {
                    ttl_secs: self.config.lease_ttl_secs,
                    node_id: Some(self.config.node_id.clone()),
                },
                now_secs,
            )
            .await?
        {
            ClusterReply::LeaseGranted { lease_id, .. } => lease_id,
            _ => return Err(ClusterError::new(Errno::EIO)),
        };

        let mut labels = self.config.labels.clone();
        labels.insert(NODE_META_LAST_GEN_LABEL.into(), next_gen.to_string());
        let meta = NodeMetaRecord {
            node_id: self.config.node_id.clone(),
            host_kind: self.config.host_kind.clone(),
            labels,
            capabilities: self.config.capabilities.clone(),
            enrolled_at: prev_meta.map_or(now_secs, |m| m.enrolled_at.max(1)),
        };
        let status = if self.draining { "draining" } else { "ready" }.to_string();
        let node = NodeRecord {
            node_id: self.config.node_id.clone(),
            node_generation: next_gen,
            instance_id: self.config.instance_id.clone(),
            lease_id,
            status: status.clone(),
            heartbeat_at: now_secs,
        };
        let txn = build_register_node_txn(&tenant, &meta, &node, expected_prev_mod)?;
        let reply = self.store.rpc(&self.grant, txn, now_secs).await?;
        let ClusterReply::Txn {
            revision,
            succeeded,
            ..
        } = reply
        else {
            return Err(ClusterError::new(Errno::EIO));
        };
        if !succeeded {
            let _ = self
                .store
                .rpc(&self.grant, ClusterCall::LeaseRevoke { lease_id }, now_secs)
                .await;
            return Err(ClusterError::because(
                Errno::ESTALE,
                "concurrent node registration rotated node record",
            ));
        }
        self.meta = meta;
        let state = NodeLeaseState {
            node_generation: next_gen,
            node_mod_revision: revision,
            lease_id,
            ttl_secs: self.config.lease_ttl_secs,
            self_fence_deadline_ms: compute_self_fence_deadline_ms(
                send_mono,
                self.config.lease_ttl_secs,
            ),
            status,
        };
        self.lease = Some(state.clone());
        Ok(state)
    }

    /// Renew the node's `ClusterState` lease using client-monotonic self-fencing.
    /// Returns `Ok(true)` if renewed, `Ok(false)` if already self-fenced, or `Err` on failure.
    pub async fn keepalive(
        &mut self,
        now_secs: u64,
        send_mono_ms: u64,
    ) -> Result<bool, ClusterError> {
        let Some(ref mut lease) = self.lease else {
            return Ok(false);
        };
        if send_mono_ms >= lease.self_fence_deadline_ms {
            return Ok(false);
        }
        let lease_id = lease.lease_id;
        match self
            .store
            .rpc(
                &self.grant,
                ClusterCall::LeaseKeepAlive { lease_id },
                now_secs,
            )
            .await
        {
            Ok(ClusterReply::LeaseKeptAlive { ttl_secs, .. }) => {
                lease.ttl_secs = ttl_secs;
                lease.self_fence_deadline_ms =
                    compute_self_fence_deadline_ms(send_mono_ms, ttl_secs);
                Ok(true)
            }
            Ok(_) => Err(ClusterError::new(Errno::EIO)),
            Err(err) => {
                if matches!(err.errno, Errno::ENOENT | Errno::EACCES | Errno::ESTALE) {
                    lease.self_fence_deadline_ms = 0;
                }
                Err(err)
            }
        }
    }

    /// Transition node into `draining` so it stops claiming new attempts while finishing active ones.
    pub async fn drain(&mut self, now_secs: u64) -> Result<(), ClusterError> {
        self.draining = true;
        let Some(ref mut lease) = self.lease else {
            return Ok(());
        };
        let tenant = self.grant.tenant.clone();
        let node_k = node_key(&tenant, &self.config.node_id)?;
        let node = NodeRecord {
            node_id: self.config.node_id.clone(),
            node_generation: lease.node_generation,
            instance_id: self.config.instance_id.clone(),
            lease_id: lease.lease_id,
            status: "draining".into(),
            heartbeat_at: now_secs,
        };
        let call = ClusterCall::Txn {
            compare: vec![
                abi::cluster_state::Compare {
                    key: node_k.clone(),
                    op: abi::cluster_state::CompareOp::Equal,
                    target: abi::cluster_state::CompareTarget::ModRevision(lease.node_mod_revision),
                },
                abi::cluster_state::Compare {
                    key: node_k.clone(),
                    op: abi::cluster_state::CompareOp::Equal,
                    target: abi::cluster_state::CompareTarget::Lease(lease.lease_id),
                },
            ],
            success: vec![TxnOp::Put {
                key: node_k,
                value_b64: encode_record(&node)?,
                lease_id: lease.lease_id,
                prev_kv: false,
            }],
            failure: vec![],
        };
        if let ClusterReply::Txn {
            revision,
            succeeded: true,
            ..
        } = self.store.rpc(&self.grant, call, now_secs).await?
        {
            lease.node_mod_revision = revision;
            lease.status = "draining".into();
        }
        Ok(())
    }

    /// Cleanly revoke the node's lease on shutdown, immediately removing `/t/<tenant>/nodes/<id>`.
    pub async fn deregister(&mut self, now_secs: u64) -> Result<(), ClusterError> {
        if let Some(lease) = self.lease.take() {
            let _ = self
                .store
                .rpc(
                    &self.grant,
                    ClusterCall::LeaseRevoke {
                        lease_id: lease.lease_id,
                    },
                    now_secs,
                )
                .await;
        }
        Ok(())
    }

    /// Claim one eligible pending or orphaned-running workload, run it via `runner`, stage output
    /// via `stager`, and attempt atomic fenced publication (guaranteeing full cleanup on rejection).
    pub async fn poll_and_execute_one<R: SandboxRunner, T: ArtifactStager>(
        &mut self,
        runner: &R,
        stager: &T,
        now_secs: u64,
        now_mono_ms: u64,
    ) -> Result<Option<AttemptExecutionReport>, ClusterError> {
        self.poll_and_execute_one_live(runner, stager, || now_secs, || now_mono_ms, || None)
            .await
    }

    /// Claim and execute one workload using live wall/monotonic clock samplers and an optional
    /// live self-fence deadline reader so post-execution self-fencing and publish timestamps
    /// reflect real post-execution time rather than pre-claim snapshots.
    pub async fn poll_and_execute_one_live<R, T, FWall, FMono, FDeadline>(
        &mut self,
        runner: &R,
        stager: &T,
        wall_secs: FWall,
        mono_ms: FMono,
        latest_deadline_ms: FDeadline,
    ) -> Result<Option<AttemptExecutionReport>, ClusterError>
    where
        R: SandboxRunner,
        T: ArtifactStager,
        FWall: Fn() -> u64,
        FMono: Fn() -> u64,
        FDeadline: Fn() -> Option<u64>,
    {
        if let Some(dl) = latest_deadline_ms() {
            self.update_self_fence_deadline_ms(dl);
        }
        let pre_mono = mono_ms();
        if self.draining || self.is_self_fenced(pre_mono) {
            return Ok(None);
        }
        let Some(claimed) = self.try_claim_next(wall_secs(), pre_mono).await? else {
            return Ok(None);
        };
        let report = self
            .execute_claimed_live(
                claimed,
                runner,
                stager,
                wall_secs,
                mono_ms,
                latest_deadline_ms,
            )
            .await?;
        Ok(Some(report))
    }

    /// Scan `/t/<tenant>/workloads/` and atomically claim one pending workload or reclaim one
    /// orphaned running workload whose prior node lease has expired/rotated.
    pub async fn try_claim_next(
        &self,
        now_secs: u64,
        now_mono_ms: u64,
    ) -> Result<Option<ClaimedAttempt>, ClusterError> {
        if self.draining || self.is_self_fenced(now_mono_ms) {
            return Ok(None);
        }
        let Some(lease) = self.lease.as_ref() else {
            return Ok(None);
        };
        let tenant = &self.grant.tenant;
        let wl_prefix = format!("/t/{tenant}/workloads/");
        let reply = self
            .store
            .rpc(
                &self.grant,
                ClusterCall::Range {
                    key: wl_prefix.clone(),
                    range_end: RangeEnd::Prefix,
                    revision: 0,
                    limit: Some(256),
                    keys_only: false,
                    count_only: false,
                },
                now_secs,
            )
            .await?;
        let ClusterReply::Range { kvs, .. } = reply else {
            return Err(ClusterError::new(Errno::EIO));
        };

        let mut canceled_ids = std::collections::BTreeSet::new();
        for kv in &kvs {
            if let Some(rest) = kv.key.strip_prefix(&wl_prefix)
                && let Some(wid) = rest.strip_suffix("/canceled")
            {
                canceled_ids.insert(wid.to_string());
            }
        }

        for kv in &kvs {
            let Some(rel) = kv.key.strip_prefix(&wl_prefix) else {
                continue;
            };
            if rel.contains('/') || canceled_ids.contains(rel) {
                continue;
            }
            let Ok(wl) = decode_record::<WorkloadRecord>(kv) else {
                continue;
            };
            let Ok(spec) = TaskSpec::from_workload_record(&wl) else {
                continue;
            };
            if !matches_node(&spec, &self.meta) {
                continue;
            }
            if wl.desired_state == "pending" && wl.current_attempt == 0 {
                let mut updated = wl.clone();
                updated.desired_state = "running".into();
                updated.current_attempt = 1;
                let attempt = AttemptRecord {
                    workload_id: wl.workload_id.clone(),
                    attempt_generation: 1,
                    node_id: self.config.node_id.clone(),
                    node_generation: lease.node_generation,
                    node_lease_id: lease.lease_id,
                    state: "claimed".into(),
                    claimed_at: now_secs,
                    finished_at: None,
                };
                let txn = build_claim_attempt_txn(
                    tenant,
                    kv.mod_revision,
                    lease.node_mod_revision,
                    lease.lease_id,
                    &updated,
                    &attempt,
                )?;
                if let ClusterReply::Txn {
                    revision,
                    succeeded: true,
                    ..
                } = self.store.rpc(&self.grant, txn, now_secs).await?
                {
                    return Ok(Some(ClaimedAttempt {
                        spec,
                        workload: updated,
                        attempt,
                        workload_mod_revision: revision,
                        attempt_mod_revision: revision,
                        node_mod_revision: lease.node_mod_revision,
                        node_lease_id: lease.lease_id,
                    }));
                }
            } else if wl.desired_state == "running" && wl.current_attempt >= 1 {
                // Skip if already published.
                let res_k = result_key(tenant, &wl.workload_id)?;
                if let Ok(ClusterReply::Range { kvs: rkvs, .. }) = self
                    .store
                    .rpc(
                        &self.grant,
                        ClusterCall::Range {
                            key: res_k,
                            range_end: RangeEnd::Exact,
                            revision: 0,
                            limit: Some(1),
                            keys_only: true,
                            count_only: false,
                        },
                        now_secs,
                    )
                    .await
                    && !rkvs.is_empty()
                {
                    continue;
                }
                let prev_att_k = attempt_key(tenant, &wl.workload_id, wl.current_attempt)?;
                let prev_att_kv = match self
                    .store
                    .rpc(
                        &self.grant,
                        ClusterCall::Range {
                            key: prev_att_k,
                            range_end: RangeEnd::Exact,
                            revision: 0,
                            limit: Some(1),
                            keys_only: false,
                            count_only: false,
                        },
                        now_secs,
                    )
                    .await?
                {
                    ClusterReply::Range { kvs: akvs, .. } => akvs.into_iter().next(),
                    _ => None,
                };
                let Some(prev_att_kv) = prev_att_kv else {
                    continue;
                };
                let Ok(prev_attempt) = decode_record::<AttemptRecord>(&prev_att_kv) else {
                    continue;
                };
                // Check whether prior node's lease expired or rotated before sending reclaim Txn.
                let prev_node_k = node_key(tenant, &prev_attempt.node_id)?;
                let prev_node_alive_same_lease = match self
                    .store
                    .rpc(
                        &self.grant,
                        ClusterCall::Range {
                            key: prev_node_k,
                            range_end: RangeEnd::Exact,
                            revision: 0,
                            limit: Some(1),
                            keys_only: true,
                            count_only: false,
                        },
                        now_secs,
                    )
                    .await?
                {
                    ClusterReply::Range { kvs: nkvs, .. } => nkvs
                        .first()
                        .is_some_and(|nkv| nkv.lease_id == prev_attempt.node_lease_id),
                    _ => true,
                };
                if prev_node_alive_same_lease {
                    continue;
                }
                let next_gen = wl.current_attempt.saturating_add(1);
                let mut updated = wl.clone();
                updated.desired_state = "running".into();
                updated.current_attempt = next_gen;
                let new_attempt = AttemptRecord {
                    workload_id: wl.workload_id.clone(),
                    attempt_generation: next_gen,
                    node_id: self.config.node_id.clone(),
                    node_generation: lease.node_generation,
                    node_lease_id: lease.lease_id,
                    state: "claimed".into(),
                    claimed_at: now_secs,
                    finished_at: None,
                };
                let txn = build_reclaim_attempt_txn(
                    tenant,
                    kv.mod_revision,
                    prev_att_kv.mod_revision,
                    lease.node_mod_revision,
                    lease.lease_id,
                    &prev_attempt,
                    &updated,
                    &new_attempt,
                )?;
                if let ClusterReply::Txn {
                    revision,
                    succeeded: true,
                    ..
                } = self.store.rpc(&self.grant, txn, now_secs).await?
                {
                    return Ok(Some(ClaimedAttempt {
                        spec,
                        workload: updated,
                        attempt: new_attempt,
                        workload_mod_revision: revision,
                        attempt_mod_revision: revision,
                        node_mod_revision: lease.node_mod_revision,
                        node_lease_id: lease.lease_id,
                    }));
                }
            }
        }
        Ok(None)
    }

    /// Execute an already-claimed attempt, stage its output, commit behind the 5-way fence,
    /// and guarantee staged + local cleanup on `ESTALE`/`ECANCELED`/`EEXIST`.
    pub async fn execute_claimed<R: SandboxRunner, T: ArtifactStager>(
        &mut self,
        claimed: ClaimedAttempt,
        runner: &R,
        stager: &T,
        now_secs: u64,
        now_mono_ms: u64,
    ) -> Result<AttemptExecutionReport, ClusterError> {
        self.execute_claimed_live(
            claimed,
            runner,
            stager,
            || now_secs,
            || now_mono_ms,
            || None,
        )
        .await
    }

    /// Execute an already-claimed attempt using live wall/monotonic clocks and an optional live
    /// self-fence deadline reader sampled AFTER `run_attempt` finishes (before staging/publish).
    pub async fn execute_claimed_live<R, T, FWall, FMono, FDeadline>(
        &mut self,
        claimed: ClaimedAttempt,
        runner: &R,
        stager: &T,
        wall_secs: FWall,
        mono_ms: FMono,
        latest_deadline_ms: FDeadline,
    ) -> Result<AttemptExecutionReport, ClusterError>
    where
        R: SandboxRunner,
        T: ArtifactStager,
        FWall: Fn() -> u64,
        FMono: Fn() -> u64,
        FDeadline: Fn() -> Option<u64>,
    {
        let req = SandboxRunRequest {
            workload_id: claimed.attempt.workload_id.clone(),
            attempt_generation: claimed.attempt.attempt_generation,
            node_id: claimed.attempt.node_id.clone(),
            node_generation: claimed.attempt.node_generation,
            spec: claimed.spec.clone(),
        };

        let outcome = match runner.run_attempt(&req).await {
            Ok(out) => out,
            Err(err) => {
                runner
                    .cleanup_attempt(&req.workload_id, req.attempt_generation)
                    .await;
                return Ok(AttemptExecutionReport::AbortedBeforePublish {
                    workload_id: req.workload_id,
                    attempt_generation: req.attempt_generation,
                    errno: err.errno,
                });
            }
        };

        // Sync latest keepalive deadline and sample fresh clocks AFTER execution before staging!
        if let Some(dl) = latest_deadline_ms() {
            self.update_self_fence_deadline_ms(dl);
        }
        let post_mono_ms = mono_ms();
        let post_wall_secs = wall_secs();

        // Re-check self-fence & cancellation before staging/committing.
        if self.is_self_fenced(post_mono_ms) {
            runner
                .cleanup_attempt(&req.workload_id, req.attempt_generation)
                .await;
            return Ok(AttemptExecutionReport::AbortedBeforePublish {
                workload_id: req.workload_id,
                attempt_generation: req.attempt_generation,
                errno: Errno::ESTALE,
            });
        }
        let cancel_k = workload_canceled_key(&self.grant.tenant, &req.workload_id)?;
        if let Ok(ClusterReply::Range { kvs, .. }) = self
            .store
            .rpc(
                &self.grant,
                ClusterCall::Range {
                    key: cancel_k,
                    range_end: RangeEnd::Exact,
                    revision: 0,
                    limit: Some(1),
                    keys_only: true,
                    count_only: false,
                },
                post_wall_secs,
            )
            .await
            && !kvs.is_empty()
        {
            runner
                .cleanup_attempt(&req.workload_id, req.attempt_generation)
                .await;
            return Ok(AttemptExecutionReport::AbortedBeforePublish {
                workload_id: req.workload_id,
                attempt_generation: req.attempt_generation,
                errno: Errno::ECANCELED,
            });
        }

        let staged = if outcome.exit_code == 0 {
            match stager.stage_output(&req, &outcome).await {
                Ok(s) => s,
                Err(err) => {
                    runner
                        .cleanup_attempt(&req.workload_id, req.attempt_generation)
                        .await;
                    return Ok(AttemptExecutionReport::AbortedBeforePublish {
                        workload_id: req.workload_id,
                        attempt_generation: req.attempt_generation,
                        errno: err.errno,
                    });
                }
            }
        } else {
            None
        };

        // Re-sample wall/mono after staging so publish timestamps and self-fence stay fresh.
        if let Some(dl) = latest_deadline_ms() {
            self.update_self_fence_deadline_ms(dl);
        }
        let pub_wall_secs = wall_secs();
        if self.is_self_fenced(mono_ms()) {
            if let Some(ref s) = staged {
                stager.cleanup_staged(&req, s).await;
            }
            runner
                .cleanup_attempt(&req.workload_id, req.attempt_generation)
                .await;
            return Ok(AttemptExecutionReport::AbortedBeforePublish {
                workload_id: req.workload_id,
                attempt_generation: req.attempt_generation,
                errno: Errno::ESTALE,
            });
        }

        let terminal_state = if outcome.exit_code == 0 {
            "succeeded"
        } else {
            "failed"
        };
        let mut finished_wl = claimed.workload.clone();
        finished_wl.desired_state = terminal_state.into();
        let mut finished_att = claimed.attempt.clone();
        finished_att.state = terminal_state.into();
        finished_att.finished_at = Some(pub_wall_secs);

        let result_rec = ResultRecord {
            workload_id: req.workload_id.clone(),
            attempt_generation: req.attempt_generation,
            node_id: req.node_id.clone(),
            node_generation: req.node_generation,
            exit_code: outcome.exit_code,
            output_ref: staged.as_ref().map(|s| s.output_ref.clone()),
            summary: outcome
                .summary
                .as_ref()
                .map(|s| s.chars().take(1024).collect()),
            published_at: pub_wall_secs,
        };
        let outbox = OutboxRecord {
            outbox_id: format!("pub-{}-{}", req.workload_id, req.attempt_generation),
            workload_id: req.workload_id.clone(),
            attempt_generation: req.attempt_generation,
            kind: "result_published".into(),
            created_at: pub_wall_secs,
        };

        let pub_call = build_publish_result_txn(
            &self.grant.tenant,
            claimed.workload_mod_revision,
            claimed.node_mod_revision,
            claimed.node_lease_id,
            claimed.attempt_mod_revision,
            &finished_wl,
            &finished_att,
            &result_rec,
            Some(&outbox),
        )?;
        let pub_reply = match self.store.rpc(&self.grant, pub_call, pub_wall_secs).await {
            Ok(r) => r,
            Err(err) => {
                if let Some(ref s) = staged {
                    stager.cleanup_staged(&req, s).await;
                }
                runner
                    .cleanup_attempt(&req.workload_id, req.attempt_generation)
                    .await;
                return Err(err);
            }
        };

        let classified = classify_fenced_publish_result(
            &pub_reply,
            claimed.workload_mod_revision,
            claimed.node_mod_revision,
            claimed.node_lease_id,
            claimed.attempt_mod_revision,
        )?;

        match classified {
            FencedPublishOutcome::Published { revision } => {
                let final_ref = if let Some(ref s) = staged {
                    Some(
                        stager
                            .promote_staged(&req, s)
                            .await
                            .unwrap_or_else(|_| s.output_ref.clone()),
                    )
                } else {
                    None
                };
                runner
                    .cleanup_attempt(&req.workload_id, req.attempt_generation)
                    .await;
                self.completed_attempts = self.completed_attempts.saturating_add(1);
                Ok(AttemptExecutionReport::Published {
                    workload_id: req.workload_id,
                    attempt_generation: req.attempt_generation,
                    revision,
                    exit_code: outcome.exit_code,
                    output_ref: final_ref,
                })
            }
            FencedPublishOutcome::Rejected(failure) => {
                if let Some(ref s) = staged {
                    stager.cleanup_staged(&req, s).await;
                }
                runner
                    .cleanup_attempt(&req.workload_id, req.attempt_generation)
                    .await;
                Ok(AttemptExecutionReport::Rejected {
                    workload_id: req.workload_id,
                    attempt_generation: req.attempt_generation,
                    failure,
                })
            }
        }
    }
}

/// Snapshot of a successfully claimed attempt ready for execution and fenced publication.
#[derive(Clone, Debug)]
pub struct ClaimedAttempt {
    pub spec: TaskSpec,
    pub workload: WorkloadRecord,
    pub attempt: AttemptRecord,
    pub workload_mod_revision: u64,
    pub attempt_mod_revision: u64,
    pub node_mod_revision: u64,
    pub node_lease_id: u64,
}
