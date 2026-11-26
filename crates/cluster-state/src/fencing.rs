//! Canonical `/t/<tenant>/...` key builders, typed record codecs, and atomic fenced
//! transaction builders for nodes, workloads, attempts, cancellations, results, and outbox
//! notices (`Contract v2` §2.13, §2.16).
use abi::Errno;
use abi::auth_v2::valid_cluster_record_id;
use abi::cluster_state::{
    AttemptRecord, ClusterCall, ClusterError, ClusterReply, Compare, CompareOp, CompareTarget,
    KeyValue, NodeMetaRecord, NodeRecord, OutboxRecord, RangeEnd, ResultRecord, TxnOp, TxnOpReply,
    WorkloadRecord, encode_value_b64, valid_tenant_name,
};
use serde::Serialize;
use serde::de::DeserializeOwned;

fn check_tenant_and_id(tenant: &str, id: &str) -> Result<(), ClusterError> {
    if !valid_tenant_name(tenant) || !valid_cluster_record_id(id) {
        return Err(ClusterError::because(
            Errno::EINVAL,
            "invalid tenant or cluster record identifier",
        ));
    }
    Ok(())
}

pub fn node_meta_key(tenant: &str, node_id: &str) -> Result<String, ClusterError> {
    check_tenant_and_id(tenant, node_id)?;
    Ok(format!("/t/{tenant}/node-meta/{node_id}"))
}

pub fn node_key(tenant: &str, node_id: &str) -> Result<String, ClusterError> {
    check_tenant_and_id(tenant, node_id)?;
    Ok(format!("/t/{tenant}/nodes/{node_id}"))
}

pub fn workload_key(tenant: &str, workload_id: &str) -> Result<String, ClusterError> {
    check_tenant_and_id(tenant, workload_id)?;
    Ok(format!("/t/{tenant}/workloads/{workload_id}"))
}

pub fn workload_canceled_key(tenant: &str, workload_id: &str) -> Result<String, ClusterError> {
    check_tenant_and_id(tenant, workload_id)?;
    Ok(format!("/t/{tenant}/workloads/{workload_id}/canceled"))
}

pub fn attempt_key(
    tenant: &str,
    workload_id: &str,
    attempt_generation: u64,
) -> Result<String, ClusterError> {
    check_tenant_and_id(tenant, workload_id)?;
    if attempt_generation == 0 {
        return Err(ClusterError::because(
            Errno::EINVAL,
            "attempt_generation must be >= 1",
        ));
    }
    Ok(format!(
        "/t/{tenant}/attempts/{workload_id}/{attempt_generation}"
    ))
}

pub fn result_key(tenant: &str, workload_id: &str) -> Result<String, ClusterError> {
    check_tenant_and_id(tenant, workload_id)?;
    Ok(format!("/t/{tenant}/results/{workload_id}"))
}

pub fn outbox_key(tenant: &str, outbox_id: &str) -> Result<String, ClusterError> {
    check_tenant_and_id(tenant, outbox_id)?;
    Ok(format!("/t/{tenant}/outbox/{outbox_id}"))
}

pub fn encode_record<T: Serialize>(record: &T) -> Result<String, ClusterError> {
    let bytes = serde_json::to_vec(record)
        .map_err(|_| ClusterError::because(Errno::EINVAL, "failed to serialize cluster record"))?;
    encode_value_b64(&bytes)
}

pub fn decode_record<T: DeserializeOwned>(kv: &KeyValue) -> Result<T, ClusterError> {
    let bytes = kv.decode_value()?;
    serde_json::from_slice(&bytes)
        .map_err(|_| ClusterError::because(Errno::EIO, "failed to decode cluster record"))
}

fn exact_range_op(key: String) -> TxnOp {
    TxnOp::Range {
        key,
        range_end: RangeEnd::Exact,
        limit: Some(1),
        keys_only: false,
        count_only: false,
    }
}

/// Atomically register or rotate a node generation: writes durable `node-meta/<id>` (unleased)
/// and ephemeral `nodes/<id>` (bound to `node.lease_id`), CAS-guarded on `expected_prev_node_mod_rev`.
pub fn build_register_node_txn(
    tenant: &str,
    meta: &NodeMetaRecord,
    node: &NodeRecord,
    expected_prev_node_mod_rev: Option<u64>,
) -> Result<ClusterCall, ClusterError> {
    meta.validate()?;
    node.validate()?;
    if meta.node_id != node.node_id {
        return Err(ClusterError::because(
            Errno::EINVAL,
            "node_meta and node records must reference the same node_id",
        ));
    }
    let meta_k = node_meta_key(tenant, &meta.node_id)?;
    let node_k = node_key(tenant, &node.node_id)?;
    let guard = match expected_prev_node_mod_rev {
        Some(rev) => Compare {
            key: node_k.clone(),
            op: CompareOp::Equal,
            target: CompareTarget::ModRevision(rev),
        },
        None => Compare {
            key: node_k.clone(),
            op: CompareOp::Equal,
            target: CompareTarget::Version(0),
        },
    };
    Ok(ClusterCall::Txn {
        compare: vec![guard],
        success: vec![
            TxnOp::Put {
                key: meta_k,
                value_b64: encode_record(meta)?,
                lease_id: 0,
                prev_kv: false,
            },
            TxnOp::Put {
                key: node_k.clone(),
                value_b64: encode_record(node)?,
                lease_id: node.lease_id,
                prev_kv: false,
            },
        ],
        failure: vec![exact_range_op(node_k)],
    })
}

/// Atomically admit a new workload (requires `workload` absent) and optionally enqueue a
/// Contract §2.13 notice-only outbox record in the same transaction.
pub fn build_admit_workload_txn(
    tenant: &str,
    workload: &WorkloadRecord,
    outbox: Option<&OutboxRecord>,
) -> Result<ClusterCall, ClusterError> {
    workload.validate()?;
    let wl_k = workload_key(tenant, &workload.workload_id)?;
    let mut success = vec![TxnOp::Put {
        key: wl_k.clone(),
        value_b64: encode_record(workload)?,
        lease_id: 0,
        prev_kv: false,
    }];
    if let Some(ob) = outbox {
        ob.validate()?;
        if ob.workload_id != workload.workload_id {
            return Err(ClusterError::because(
                Errno::EINVAL,
                "outbox workload_id mismatch",
            ));
        }
        success.push(TxnOp::Put {
            key: outbox_key(tenant, &ob.outbox_id)?,
            value_b64: encode_record(ob)?,
            lease_id: 0,
            prev_kv: false,
        });
    }
    Ok(ClusterCall::Txn {
        compare: vec![Compare {
            key: wl_k.clone(),
            op: CompareOp::Equal,
            target: CompareTarget::Version(0),
        }],
        success,
        failure: vec![exact_range_op(wl_k)],
    })
}

/// Atomically claim an execution attempt fenced against cancellation, concurrent claims,
/// stale node liveness/lease, and duplicate attempt generation.
#[allow(clippy::too_many_arguments)]
pub fn build_claim_attempt_txn(
    tenant: &str,
    expected_workload_mod_rev: u64,
    expected_node_mod_rev: u64,
    expected_node_lease_id: u64,
    updated_workload: &WorkloadRecord,
    attempt: &AttemptRecord,
) -> Result<ClusterCall, ClusterError> {
    updated_workload.validate()?;
    attempt.validate()?;
    if expected_workload_mod_rev == 0
        || expected_node_mod_rev == 0
        || expected_node_lease_id == 0
        || updated_workload.workload_id != attempt.workload_id
        || updated_workload.current_attempt != attempt.attempt_generation
        || attempt.node_lease_id != expected_node_lease_id
    {
        return Err(ClusterError::because(
            Errno::EINVAL,
            "mismatched workload/attempt claim fields",
        ));
    }
    let cancel_k = workload_canceled_key(tenant, &attempt.workload_id)?;
    let wl_k = workload_key(tenant, &attempt.workload_id)?;
    let node_k = node_key(tenant, &attempt.node_id)?;
    let att_k = attempt_key(tenant, &attempt.workload_id, attempt.attempt_generation)?;
    Ok(ClusterCall::Txn {
        compare: vec![
            Compare {
                key: cancel_k.clone(),
                op: CompareOp::Equal,
                target: CompareTarget::Version(0),
            },
            Compare {
                key: wl_k.clone(),
                op: CompareOp::Equal,
                target: CompareTarget::ModRevision(expected_workload_mod_rev),
            },
            Compare {
                key: node_k.clone(),
                op: CompareOp::Equal,
                target: CompareTarget::ModRevision(expected_node_mod_rev),
            },
            Compare {
                key: node_k.clone(),
                op: CompareOp::Equal,
                target: CompareTarget::Lease(expected_node_lease_id),
            },
            Compare {
                key: att_k.clone(),
                op: CompareOp::Equal,
                target: CompareTarget::Version(0),
            },
        ],
        success: vec![
            TxnOp::Put {
                key: wl_k.clone(),
                value_b64: encode_record(updated_workload)?,
                lease_id: 0,
                prev_kv: false,
            },
            TxnOp::Put {
                key: att_k.clone(),
                value_b64: encode_record(attempt)?,
                lease_id: 0,
                prev_kv: false,
            },
        ],
        failure: vec![
            exact_range_op(cancel_k),
            exact_range_op(wl_k),
            exact_range_op(node_k),
            exact_range_op(att_k),
        ],
    })
}

/// Atomically reclaim a workload whose previous attempt belonged to a dead or rotated node.
/// Guards ALL preconditions of [`build_claim_attempt_txn`] PLUS:
/// - `results/<wid>` is still absent (`Version == 0`),
/// - `attempts/<wid>/<prev_gen>` still has `ModRevision == expected_prev_attempt_mod_rev`,
/// - `nodes/<prev_node_id>` no longer holds `prev_attempt.node_lease_id`
///   (`CompareOp::NotEqual`, `CompareTarget::Lease(prev_attempt.node_lease_id)`), atomically
///   proving the prior node's lease expired or rotated so a live node's attempt can never be stolen.
///
/// Marks the stale previous attempt `"aborted"` and writes the new attempt (`prev_gen + 1`) +
/// updated workload in the same single-winner transaction.
#[allow(clippy::too_many_arguments)]
pub fn build_reclaim_attempt_txn(
    tenant: &str,
    expected_workload_mod_rev: u64,
    expected_prev_attempt_mod_rev: u64,
    expected_node_mod_rev: u64,
    expected_node_lease_id: u64,
    prev_attempt: &AttemptRecord,
    updated_workload: &WorkloadRecord,
    new_attempt: &AttemptRecord,
) -> Result<ClusterCall, ClusterError> {
    prev_attempt.validate()?;
    updated_workload.validate()?;
    new_attempt.validate()?;
    if expected_workload_mod_rev == 0
        || expected_prev_attempt_mod_rev == 0
        || expected_node_mod_rev == 0
        || expected_node_lease_id == 0
        || prev_attempt.workload_id != new_attempt.workload_id
        || updated_workload.workload_id != new_attempt.workload_id
        || new_attempt.attempt_generation != prev_attempt.attempt_generation.saturating_add(1)
        || updated_workload.current_attempt != new_attempt.attempt_generation
        || new_attempt.node_lease_id != expected_node_lease_id
    {
        return Err(ClusterError::because(
            Errno::EINVAL,
            "mismatched workload/attempt reclaim fields",
        ));
    }
    let cancel_k = workload_canceled_key(tenant, &new_attempt.workload_id)?;
    let res_k = result_key(tenant, &new_attempt.workload_id)?;
    let wl_k = workload_key(tenant, &new_attempt.workload_id)?;
    let prev_node_k = node_key(tenant, &prev_attempt.node_id)?;
    let prev_att_k = attempt_key(
        tenant,
        &prev_attempt.workload_id,
        prev_attempt.attempt_generation,
    )?;
    let node_k = node_key(tenant, &new_attempt.node_id)?;
    let att_k = attempt_key(
        tenant,
        &new_attempt.workload_id,
        new_attempt.attempt_generation,
    )?;

    let mut aborted_prev = prev_attempt.clone();
    aborted_prev.state = "aborted".into();
    aborted_prev.finished_at = Some(new_attempt.claimed_at);

    Ok(ClusterCall::Txn {
        compare: vec![
            Compare {
                key: cancel_k.clone(),
                op: CompareOp::Equal,
                target: CompareTarget::Version(0),
            },
            Compare {
                key: res_k.clone(),
                op: CompareOp::Equal,
                target: CompareTarget::Version(0),
            },
            Compare {
                key: wl_k.clone(),
                op: CompareOp::Equal,
                target: CompareTarget::ModRevision(expected_workload_mod_rev),
            },
            Compare {
                key: prev_att_k.clone(),
                op: CompareOp::Equal,
                target: CompareTarget::ModRevision(expected_prev_attempt_mod_rev),
            },
            Compare {
                key: prev_node_k.clone(),
                op: CompareOp::NotEqual,
                target: CompareTarget::Lease(prev_attempt.node_lease_id),
            },
            Compare {
                key: node_k.clone(),
                op: CompareOp::Equal,
                target: CompareTarget::ModRevision(expected_node_mod_rev),
            },
            Compare {
                key: node_k.clone(),
                op: CompareOp::Equal,
                target: CompareTarget::Lease(expected_node_lease_id),
            },
            Compare {
                key: att_k.clone(),
                op: CompareOp::Equal,
                target: CompareTarget::Version(0),
            },
        ],
        success: vec![
            TxnOp::Put {
                key: prev_att_k,
                value_b64: encode_record(&aborted_prev)?,
                lease_id: 0,
                prev_kv: false,
            },
            TxnOp::Put {
                key: wl_k.clone(),
                value_b64: encode_record(updated_workload)?,
                lease_id: 0,
                prev_kv: false,
            },
            TxnOp::Put {
                key: att_k.clone(),
                value_b64: encode_record(new_attempt)?,
                lease_id: 0,
                prev_kv: false,
            },
        ],
        failure: vec![
            exact_range_op(cancel_k),
            exact_range_op(res_k),
            exact_range_op(wl_k),
            exact_range_op(prev_node_k),
            exact_range_op(node_k),
            exact_range_op(att_k),
        ],
    })
}

/// Atomically mark a workload canceled if it exists and has not yet published a final result.
pub fn build_cancel_workload_txn(
    tenant: &str,
    workload_id: &str,
    reason: &str,
    canceled_at: u64,
    outbox: Option<&OutboxRecord>,
) -> Result<ClusterCall, ClusterError> {
    let wl_k = workload_key(tenant, workload_id)?;
    let cancel_k = workload_canceled_key(tenant, workload_id)?;
    let res_k = result_key(tenant, workload_id)?;
    let marker = serde_json::json!({
        "workload_id": workload_id,
        "reason": reason,
        "canceled_at": canceled_at,
    });
    let mut success = vec![TxnOp::Put {
        key: cancel_k,
        value_b64: encode_record(&marker)?,
        lease_id: 0,
        prev_kv: false,
    }];
    if let Some(ob) = outbox {
        ob.validate()?;
        if ob.workload_id != workload_id {
            return Err(ClusterError::because(
                Errno::EINVAL,
                "outbox workload_id mismatch",
            ));
        }
        success.push(TxnOp::Put {
            key: outbox_key(tenant, &ob.outbox_id)?,
            value_b64: encode_record(ob)?,
            lease_id: 0,
            prev_kv: false,
        });
    }
    Ok(ClusterCall::Txn {
        compare: vec![
            Compare {
                key: wl_k.clone(),
                op: CompareOp::Greater,
                target: CompareTarget::Version(0),
            },
            Compare {
                key: res_k.clone(),
                op: CompareOp::Equal,
                target: CompareTarget::Version(0),
            },
        ],
        success,
        failure: vec![exact_range_op(wl_k), exact_range_op(res_k)],
    })
}

/// Atomically publish an attempt's terminal result behind the 5-way fence:
/// 1. `canceled` absent (`Version == 0`),
/// 2. `workload` unchanged (`ModRevision == expected_workload_mod_rev`),
/// 3. `node` still alive at exact generation + lease (`ModRevision` + `Lease`),
/// 4. `attempt` unchanged (`ModRevision == expected_attempt_mod_rev`),
/// 5. `result` absent (`Version == 0`, at-most-once publication).
#[allow(clippy::too_many_arguments)]
pub fn build_publish_result_txn(
    tenant: &str,
    expected_workload_mod_rev: u64,
    expected_node_mod_rev: u64,
    expected_node_lease_id: u64,
    expected_attempt_mod_rev: u64,
    finished_workload: &WorkloadRecord,
    finished_attempt: &AttemptRecord,
    result: &ResultRecord,
    outbox: Option<&OutboxRecord>,
) -> Result<ClusterCall, ClusterError> {
    finished_workload.validate()?;
    finished_attempt.validate()?;
    result.validate()?;
    if expected_workload_mod_rev == 0
        || expected_node_mod_rev == 0
        || expected_node_lease_id == 0
        || expected_attempt_mod_rev == 0
        || finished_workload.workload_id != result.workload_id
        || finished_workload.current_attempt != result.attempt_generation
        || finished_attempt.workload_id != result.workload_id
        || finished_attempt.attempt_generation != result.attempt_generation
        || finished_attempt.node_id != result.node_id
        || finished_attempt.node_generation != result.node_generation
        || finished_attempt.node_lease_id != expected_node_lease_id
    {
        return Err(ClusterError::because(
            Errno::EINVAL,
            "mismatched fenced publish record fields",
        ));
    }
    let cancel_k = workload_canceled_key(tenant, &result.workload_id)?;
    let wl_k = workload_key(tenant, &result.workload_id)?;
    let node_k = node_key(tenant, &result.node_id)?;
    let att_k = attempt_key(tenant, &result.workload_id, result.attempt_generation)?;
    let res_k = result_key(tenant, &result.workload_id)?;
    let mut success = vec![
        TxnOp::Put {
            key: res_k.clone(),
            value_b64: encode_record(result)?,
            lease_id: 0,
            prev_kv: false,
        },
        TxnOp::Put {
            key: att_k.clone(),
            value_b64: encode_record(finished_attempt)?,
            lease_id: 0,
            prev_kv: false,
        },
        TxnOp::Put {
            key: wl_k.clone(),
            value_b64: encode_record(finished_workload)?,
            lease_id: 0,
            prev_kv: false,
        },
    ];
    if let Some(ob) = outbox {
        ob.validate()?;
        if ob.workload_id != result.workload_id {
            return Err(ClusterError::because(
                Errno::EINVAL,
                "outbox workload_id mismatch",
            ));
        }
        success.push(TxnOp::Put {
            key: outbox_key(tenant, &ob.outbox_id)?,
            value_b64: encode_record(ob)?,
            lease_id: 0,
            prev_kv: false,
        });
    }
    Ok(ClusterCall::Txn {
        compare: vec![
            Compare {
                key: cancel_k.clone(),
                op: CompareOp::Equal,
                target: CompareTarget::Version(0),
            },
            Compare {
                key: wl_k.clone(),
                op: CompareOp::Equal,
                target: CompareTarget::ModRevision(expected_workload_mod_rev),
            },
            Compare {
                key: node_k.clone(),
                op: CompareOp::Equal,
                target: CompareTarget::ModRevision(expected_node_mod_rev),
            },
            Compare {
                key: node_k.clone(),
                op: CompareOp::Equal,
                target: CompareTarget::Lease(expected_node_lease_id),
            },
            Compare {
                key: att_k.clone(),
                op: CompareOp::Equal,
                target: CompareTarget::ModRevision(expected_attempt_mod_rev),
            },
            Compare {
                key: res_k.clone(),
                op: CompareOp::Equal,
                target: CompareTarget::Version(0),
            },
        ],
        success,
        failure: vec![
            exact_range_op(cancel_k),
            exact_range_op(res_k),
            exact_range_op(node_k),
            exact_range_op(att_k),
            exact_range_op(wl_k),
        ],
    })
}

/// Classification of a `build_publish_result_txn` reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FencedPublishFailure {
    Canceled,
    AlreadyPublished,
    NodeFenced,
    AttemptStale,
    WorkloadStale,
}

impl FencedPublishFailure {
    pub const fn errno(self) -> Errno {
        match self {
            Self::Canceled => Errno::ECANCELED,
            Self::AlreadyPublished => Errno::EEXIST,
            Self::NodeFenced | Self::AttemptStale | Self::WorkloadStale => Errno::ESTALE,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FencedPublishOutcome {
    Published { revision: u64 },
    Rejected(FencedPublishFailure),
}

/// Inspect the diagnostic `failure` branch replies from `build_publish_result_txn` to classify
/// why a fenced publish did not commit.
pub fn classify_fenced_publish_result(
    reply: &ClusterReply,
    expected_workload_mod_rev: u64,
    expected_node_mod_rev: u64,
    expected_node_lease_id: u64,
    expected_attempt_mod_rev: u64,
) -> Result<FencedPublishOutcome, ClusterError> {
    let ClusterReply::Txn {
        revision,
        succeeded,
        responses,
        ..
    } = reply
    else {
        return Err(ClusterError::because(
            Errno::EIO,
            "expected Txn reply for fenced publish",
        ));
    };
    if *succeeded {
        return Ok(FencedPublishOutcome::Published {
            revision: *revision,
        });
    }
    let first_kv = |idx: usize| -> Option<&KeyValue> {
        match responses.get(idx)? {
            TxnOpReply::Range { kvs, .. } => kvs.first(),
            _ => None,
        }
    };
    if first_kv(0).is_some() {
        return Ok(FencedPublishOutcome::Rejected(
            FencedPublishFailure::Canceled,
        ));
    }
    if first_kv(1).is_some() {
        return Ok(FencedPublishOutcome::Rejected(
            FencedPublishFailure::AlreadyPublished,
        ));
    }
    let node_ok = first_kv(2).is_some_and(|kv| {
        kv.mod_revision == expected_node_mod_rev && kv.lease_id == expected_node_lease_id
    });
    if !node_ok {
        return Ok(FencedPublishOutcome::Rejected(
            FencedPublishFailure::NodeFenced,
        ));
    }
    let att_ok = first_kv(3).is_some_and(|kv| kv.mod_revision == expected_attempt_mod_rev);
    if !att_ok {
        return Ok(FencedPublishOutcome::Rejected(
            FencedPublishFailure::AttemptStale,
        ));
    }
    let _ = first_kv(4).is_some_and(|kv| kv.mod_revision == expected_workload_mod_rev);
    Ok(FencedPublishOutcome::Rejected(
        FencedPublishFailure::WorkloadStale,
    ))
}
