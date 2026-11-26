//! Portable task submission, cancellation, observation, and Map-Reduce orchestration client
//! layered directly over [`os_cluster_state::ClusterStore`].
use crate::{MapReduceResult, MapReduceSpec, TaskResultView, TaskSpec};
use abi::Errno;
use abi::cluster_state::{
    ClusterCall, ClusterError, ClusterReply, NodeMetaRecord, NodeRecord, OutboxRecord, RangeEnd,
    ResultRecord, WorkloadRecord,
};
use os_cluster_state::fencing::{
    build_admit_workload_txn, build_cancel_workload_txn, decode_record, node_meta_key, result_key,
    workload_canceled_key, workload_key,
};
use os_cluster_state::{BoxFuture, ClusterGrant, ClusterStore};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Portable task control-plane client over any [`ClusterStore`] backend.
pub struct TaskSubmitter<S: ClusterStore> {
    store: S,
    grant: ClusterGrant,
    clock: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl<S: ClusterStore> TaskSubmitter<S> {
    pub fn new(store: S, grant: ClusterGrant, clock: Arc<dyn Fn() -> u64 + Send + Sync>) -> Self {
        Self {
            store,
            grant,
            clock,
        }
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn grant(&self) -> &ClusterGrant {
        &self.grant
    }

    pub fn now_secs(&self) -> u64 {
        (self.clock)()
    }

    /// Admit a new task workload atomically (fails with `EEXIST` if `workload_id` already exists).
    pub async fn submit_task(&self, spec: &TaskSpec) -> Result<WorkloadRecord, ClusterError> {
        let now = self.now_secs();
        let wl = spec.to_workload_record(now)?;
        let ob = OutboxRecord {
            outbox_id: format!("admit-{}", wl.workload_id),
            workload_id: wl.workload_id.clone(),
            attempt_generation: 0,
            kind: "attempt_ready".into(),
            created_at: now,
        };
        let call = build_admit_workload_txn(&self.grant.tenant, &wl, Some(&ob))?;
        let reply = self.store.rpc(&self.grant, call, now).await?;
        match reply {
            ClusterReply::Txn {
                succeeded: true, ..
            } => Ok(wl),
            ClusterReply::Txn {
                succeeded: false, ..
            } => Err(ClusterError::because(
                Errno::EEXIST,
                format!("workload '{}' already exists", wl.workload_id),
            )),
            _ => Err(ClusterError::because(
                Errno::EIO,
                "unexpected reply admitting workload",
            )),
        }
    }

    /// Atomically cancel a workload before a terminal result is published.
    /// Returns `ENOENT` if the workload does not exist, or `EEXIST` if already published.
    pub async fn cancel_task(&self, workload_id: &str, reason: &str) -> Result<(), ClusterError> {
        let now = self.now_secs();
        let ob = OutboxRecord {
            outbox_id: format!("cancel-{workload_id}-{now}"),
            workload_id: workload_id.into(),
            attempt_generation: 0,
            kind: "workload_canceled".into(),
            created_at: now,
        };
        let call =
            build_cancel_workload_txn(&self.grant.tenant, workload_id, reason, now, Some(&ob))?;
        let reply = self.store.rpc(&self.grant, call, now).await?;
        match reply {
            ClusterReply::Txn {
                succeeded: true, ..
            } => Ok(()),
            ClusterReply::Txn {
                succeeded: false,
                responses,
                ..
            } => {
                let wl_missing = match responses.first() {
                    Some(abi::cluster_state::TxnOpReply::Range { kvs, .. }) => kvs.is_empty(),
                    _ => false,
                };
                if wl_missing {
                    Err(ClusterError::because(
                        Errno::ENOENT,
                        format!("workload '{workload_id}' not found"),
                    ))
                } else {
                    Err(ClusterError::because(
                        Errno::EEXIST,
                        format!("workload '{workload_id}' already published a terminal result"),
                    ))
                }
            }
            _ => Err(ClusterError::because(
                Errno::EIO,
                "unexpected reply canceling workload",
            )),
        }
    }

    /// Fetch the current `WorkloadRecord` and its `mod_revision`.
    pub async fn get_workload(
        &self,
        workload_id: &str,
    ) -> Result<Option<(WorkloadRecord, u64)>, ClusterError> {
        let key = workload_key(&self.grant.tenant, workload_id)?;
        let reply = self
            .store
            .rpc(
                &self.grant,
                ClusterCall::Range {
                    key,
                    range_end: RangeEnd::Exact,
                    revision: 0,
                    limit: Some(1),
                    keys_only: false,
                    count_only: false,
                },
                self.now_secs(),
            )
            .await?;
        let ClusterReply::Range { kvs, .. } = reply else {
            return Err(ClusterError::new(Errno::EIO));
        };
        match kvs.first() {
            Some(kv) => Ok(Some((decode_record(kv)?, kv.mod_revision))),
            None => Ok(None),
        }
    }

    /// Check whether a workload's cancellation marker exists.
    pub async fn is_canceled(&self, workload_id: &str) -> Result<bool, ClusterError> {
        let key = workload_canceled_key(&self.grant.tenant, workload_id)?;
        let reply = self
            .store
            .rpc(
                &self.grant,
                ClusterCall::Range {
                    key,
                    range_end: RangeEnd::Exact,
                    revision: 0,
                    limit: Some(1),
                    keys_only: true,
                    count_only: false,
                },
                self.now_secs(),
            )
            .await?;
        match reply {
            ClusterReply::Range { kvs, .. } => Ok(!kvs.is_empty()),
            _ => Err(ClusterError::new(Errno::EIO)),
        }
    }

    /// Read the at-most-once terminal [`TaskResultView`] for `workload_id`, if published.
    pub async fn get_result(
        &self,
        workload_id: &str,
    ) -> Result<Option<TaskResultView>, ClusterError> {
        let key = result_key(&self.grant.tenant, workload_id)?;
        let reply = self
            .store
            .rpc(
                &self.grant,
                ClusterCall::Range {
                    key,
                    range_end: RangeEnd::Exact,
                    revision: 0,
                    limit: Some(1),
                    keys_only: false,
                    count_only: false,
                },
                self.now_secs(),
            )
            .await?;
        let ClusterReply::Range { kvs, .. } = reply else {
            return Err(ClusterError::new(Errno::EIO));
        };
        match kvs.first() {
            Some(kv) => {
                let record: ResultRecord = decode_record(kv)?;
                Ok(Some(TaskResultView { record }))
            }
            None => Ok(None),
        }
    }

    /// Wait for `workload_id` to publish a terminal result or be canceled (`ECANCELED`).
    /// Calls `wait_step` between polls (bounded by `max_polls`, returning `ETIMEDOUT` on expiry).
    pub async fn wait_task<F>(
        &self,
        workload_id: &str,
        mut wait_step: F,
        max_polls: usize,
    ) -> Result<TaskResultView, ClusterError>
    where
        F: FnMut() -> BoxFuture<'static, ()>,
    {
        for attempt in 0..=max_polls {
            if let Some(res) = self.get_result(workload_id).await? {
                return Ok(res);
            }
            if self.is_canceled(workload_id).await? {
                return Err(ClusterError::because(
                    Errno::ECANCELED,
                    format!("workload '{workload_id}' was canceled"),
                ));
            }
            if attempt == max_polls {
                break;
            }
            wait_step().await;
        }
        Err(ClusterError::because(
            Errno::ETIMEDOUT,
            format!("timed out waiting for workload '{workload_id}'"),
        ))
    }

    /// List all currently live nodes (`nodes/*`) paired with their durable `node-meta/*` records.
    pub async fn list_nodes(
        &self,
    ) -> Result<Vec<(NodeRecord, Option<NodeMetaRecord>)>, ClusterError> {
        let now = self.now_secs();
        let reply = self
            .store
            .rpc(
                &self.grant,
                ClusterCall::Range {
                    key: format!("/t/{}/nodes/", self.grant.tenant),
                    range_end: RangeEnd::Prefix,
                    revision: 0,
                    limit: Some(256),
                    keys_only: false,
                    count_only: false,
                },
                now,
            )
            .await?;
        let ClusterReply::Range { kvs, .. } = reply else {
            return Err(ClusterError::new(Errno::EIO));
        };
        let mut out = Vec::with_capacity(kvs.len());
        for kv in kvs {
            let Ok(node) = decode_record::<NodeRecord>(&kv) else {
                continue;
            };
            let meta_k = node_meta_key(&self.grant.tenant, &node.node_id)?;
            let meta = match self
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
                    now,
                )
                .await
            {
                Ok(ClusterReply::Range { kvs: mkvs, .. }) => {
                    mkvs.first().and_then(|mkv| decode_record(mkv).ok())
                }
                _ => None,
            };
            out.push((node, meta));
        }
        Ok(out)
    }

    /// Fan out `N` map shard tasks, wait for all map `ResultRecord`s, then admit and await the
    /// reducer task wired with every map shard's immutable output snapshot reference.
    pub async fn submit_map_reduce<F>(
        &self,
        spec: &MapReduceSpec,
        mut wait_step: F,
        max_polls_per_stage: usize,
    ) -> Result<MapReduceResult, ClusterError>
    where
        F: FnMut() -> BoxFuture<'static, ()>,
    {
        spec.validate()?;
        let mut map_ids = Vec::with_capacity(spec.shards.len());
        for (idx, shard) in spec.shards.iter().enumerate() {
            let task = spec.map_task_spec(idx, shard);
            map_ids.push(task.workload_id.clone());
            self.submit_task(&task).await?;
        }

        let mut map_results: Vec<Option<TaskResultView>> = vec![None; map_ids.len()];
        for poll in 0..=max_polls_per_stage {
            let mut remaining = 0usize;
            for (idx, wid) in map_ids.iter().enumerate() {
                if map_results[idx].is_some() {
                    continue;
                }
                if let Some(res) = self.get_result(wid).await? {
                    if !res.succeeded() {
                        return Err(ClusterError::because(
                            Errno::EIO,
                            format!(
                                "map shard '{}' failed with exit_code {}",
                                wid,
                                res.exit_code()
                            ),
                        ));
                    }
                    map_results[idx] = Some(res);
                } else if self.is_canceled(wid).await? {
                    return Err(ClusterError::because(
                        Errno::ECANCELED,
                        format!("map shard '{wid}' was canceled"),
                    ));
                } else {
                    remaining += 1;
                }
            }
            if remaining == 0 {
                break;
            }
            if poll == max_polls_per_stage {
                return Err(ClusterError::because(
                    Errno::ETIMEDOUT,
                    format!("timed out waiting for {remaining} map shards"),
                ));
            }
            wait_step().await;
        }

        let finished_maps: Vec<TaskResultView> = map_results
            .into_iter()
            .map(|r| r.expect("checked complete"))
            .collect();
        let mut shard_outputs = BTreeMap::new();
        for (idx, res) in finished_maps.iter().enumerate() {
            let out_ref = res.output_ref().ok_or_else(|| {
                ClusterError::because(
                    Errno::EIO,
                    format!("map shard '{}' produced no output_ref", res.workload_id()),
                )
            })?;
            shard_outputs.insert(format!("shard-{idx}"), out_ref.to_string());
        }

        let reduce_spec = spec.reduce_task_spec(&shard_outputs);
        let reduce_id = reduce_spec.workload_id.clone();
        self.submit_task(&reduce_spec).await?;
        let reduce_result = self
            .wait_task(&reduce_id, wait_step, max_polls_per_stage)
            .await?;

        Ok(MapReduceResult {
            job_id: spec.job_id.clone(),
            map_results: finished_maps,
            reduce_result,
        })
    }
}
