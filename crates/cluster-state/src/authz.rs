//! Shared authorization, tenant range clamping, prefix containment, node-id binding, and
//! transaction validation enforced identically by `MemoryClusterStore` and `ClusterState` DO.
use crate::ClusterGrant;
use abi::Errno;
use abi::auth_v2::{cluster_prefix_matches, valid_cluster_prefix_pattern, valid_cluster_record_id};
use abi::cluster_state::{
    CLUSTER_LEASE_MAX_TTL_SECS, CLUSTER_LEASE_MIN_TTL_SECS, CLUSTER_MAX_PREFIX_GRANTS,
    CLUSTER_TXN_MAX_COMPARES, CLUSTER_TXN_MAX_OPS, CLUSTER_TXN_MAX_WRITE_BYTES, ClusterError,
    Compare, CompareOp, CompareTarget, KeyValue, RangeEnd, TxnOp, decode_value_b64,
    prefix_range_end, split_tenant_key, valid_cluster_key, valid_cluster_range_key,
    valid_tenant_name,
};
use std::collections::BTreeSet;

/// Half-open byte interval `[start, end)` strictly contained inside `/t/<tenant>/`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedRange {
    pub start: String,
    pub end: String,
}

impl ResolvedRange {
    pub fn contains_key(&self, key: &str) -> bool {
        key >= self.start.as_str() && key < self.end.as_str()
    }
}

/// Exact-key exclusive upper bound with no NUL bytes (`'!'` < `'-'`, the lowest allowed key byte).
pub fn exact_key_end(key: &str) -> String {
    format!("{key}!")
}

/// Validate that a `ClusterGrant` itself is well-formed (fail closed on malformed scopes).
pub fn validate_grant(grant: &ClusterGrant) -> Result<(), ClusterError> {
    if !valid_tenant_name(&grant.tenant) {
        return Err(ClusterError::because(Errno::EACCES, "invalid tenant"));
    }
    if grant.scope.cluster_prefixes.len() > CLUSTER_MAX_PREFIX_GRANTS {
        return Err(ClusterError::because(
            Errno::EACCES,
            "too many cluster prefix grants",
        ));
    }
    if grant
        .scope
        .cluster_prefixes
        .iter()
        .any(|p| !valid_cluster_prefix_pattern(p))
    {
        return Err(ClusterError::because(
            Errno::EACCES,
            "invalid cluster prefix pattern in credential scope",
        ));
    }
    if let Some(ref node_id) = grant.scope.cluster_node_id
        && !valid_cluster_record_id(node_id)
    {
        return Err(ClusterError::because(
            Errno::EACCES,
            "invalid cluster_node_id in credential scope",
        ));
    }
    Ok(())
}

/// Resolve `[start, end)` strictly clamped inside `/t/<tenant>/`.
/// Cross-tenant keys or upper bounds return `EACCES`; malformed keys return `EINVAL`.
pub fn resolve_range(
    tenant: &str,
    key: &str,
    range_end: &RangeEnd,
) -> Result<ResolvedRange, ClusterError> {
    if !valid_tenant_name(tenant) {
        return Err(ClusterError::because(Errno::EACCES, "invalid tenant"));
    }
    let Some((key_tenant, _)) = split_tenant_key(key) else {
        return Err(ClusterError::because(
            Errno::EINVAL,
            "invalid cluster key syntax",
        ));
    };
    if key_tenant != tenant {
        return Err(ClusterError::because(
            Errno::EACCES,
            "cross-tenant key access denied",
        ));
    }
    let tenant_prefix = format!("/t/{tenant}/");
    let tenant_end = prefix_range_end(&tenant_prefix)
        .ok_or_else(|| ClusterError::because(Errno::EIO, "tenant upper bound overflow"))?;
    let end = match range_end {
        RangeEnd::Exact => {
            if !valid_cluster_key(key) {
                return Err(ClusterError::because(
                    Errno::EINVAL,
                    "exact key must not end with '/'",
                ));
            }
            exact_key_end(key)
        }
        RangeEnd::Prefix => {
            let bound = prefix_range_end(key)
                .ok_or_else(|| ClusterError::because(Errno::EINVAL, "invalid prefix key"))?;
            bound.min(tenant_end)
        }
        RangeEnd::OpenEnded => tenant_end,
        RangeEnd::Key(end_key) => {
            if !valid_cluster_range_key(end_key) {
                return Err(ClusterError::because(
                    Errno::EINVAL,
                    "invalid range_end key syntax",
                ));
            }
            let Some((end_tenant, _)) = split_tenant_key(end_key) else {
                return Err(ClusterError::because(
                    Errno::EINVAL,
                    "invalid range_end key syntax",
                ));
            };
            if end_tenant != tenant {
                return Err(ClusterError::because(
                    Errno::EACCES,
                    "cross-tenant range_end denied",
                ));
            }
            if end_key.as_str() <= key {
                return Err(ClusterError::because(
                    Errno::EINVAL,
                    "range_end must be strictly greater than key",
                ));
            }
            end_key.clone().min(tenant_end)
        }
    };
    Ok(ResolvedRange {
        start: key.to_string(),
        end,
    })
}

fn pattern_interval(tenant: &str, pattern: &str) -> Option<(String, String)> {
    if !valid_cluster_prefix_pattern(pattern) {
        return None;
    }
    if let Some(base) = pattern
        .strip_suffix("/*")
        .or_else(|| pattern.strip_suffix('/'))
    {
        let lo = format!("/t/{tenant}/{base}/");
        let hi = prefix_range_end(&lo)?;
        Some((lo, hi))
    } else {
        let lo = format!("/t/{tenant}/{pattern}");
        let hi = exact_key_end(&lo);
        Some((lo, hi))
    }
}

fn check_key_prefix(grant: &ClusterGrant, key: &str) -> Result<(), ClusterError> {
    if !valid_cluster_key(key) {
        return Err(ClusterError::because(
            Errno::EINVAL,
            "invalid exact cluster key",
        ));
    }
    let Some((key_tenant, rel)) = split_tenant_key(key) else {
        return Err(ClusterError::because(Errno::EINVAL, "invalid cluster key"));
    };
    if key_tenant != grant.tenant {
        return Err(ClusterError::because(
            Errno::EACCES,
            "cross-tenant key access denied",
        ));
    }
    if grant.scope.cluster_prefixes.is_empty()
        || grant
            .scope
            .cluster_prefixes
            .iter()
            .any(|p| cluster_prefix_matches(p, rel))
    {
        Ok(())
    } else {
        Err(ClusterError::because(
            Errno::EACCES,
            "key is outside credential cluster_prefixes",
        ))
    }
}

fn check_range_prefix(
    grant: &ClusterGrant,
    key: &str,
    range_end: &RangeEnd,
    resolved: &ResolvedRange,
) -> Result<(), ClusterError> {
    if grant.scope.cluster_prefixes.is_empty() {
        return Ok(());
    }
    if *range_end == RangeEnd::Exact {
        return check_key_prefix(grant, key);
    }
    let mut intervals: Vec<(String, String)> = grant
        .scope
        .cluster_prefixes
        .iter()
        .filter_map(|p| pattern_interval(&grant.tenant, p))
        .collect();
    if intervals.is_empty() {
        return Err(ClusterError::because(
            Errno::EACCES,
            "range is outside credential cluster_prefixes",
        ));
    }
    intervals.sort();
    let mut merged: Vec<(String, String)> = Vec::with_capacity(intervals.len());
    for (lo, hi) in intervals {
        if let Some(last) = merged.last_mut()
            && lo <= last.1
        {
            if hi > last.1 {
                last.1 = hi;
            }
            continue;
        }
        merged.push((lo, hi));
    }
    if merged.iter().any(|(lo, hi)| {
        lo.as_str() <= resolved.start.as_str() && resolved.end.as_str() <= hi.as_str()
    }) {
        Ok(())
    } else {
        Err(ClusterError::because(
            Errno::EACCES,
            "range extends outside credential cluster_prefixes",
        ))
    }
}

fn intervals_overlap(a_start: &str, a_end: &str, b_start: &str, b_end: &str) -> bool {
    a_start < b_end && b_start < a_end
}

fn check_node_write_key(grant: &ClusterGrant, key: &str) -> Result<(), ClusterError> {
    let Some(bound_node) = grant.scope.cluster_node_id.as_deref() else {
        return Ok(());
    };
    let Some((_, rel)) = split_tenant_key(key) else {
        return Err(ClusterError::because(Errno::EINVAL, "invalid key"));
    };
    for protected in ["nodes/", "node-meta/"] {
        if let Some(rest) = rel.strip_prefix(protected) {
            let target_node = rest.split('/').next().unwrap_or("");
            if target_node != bound_node {
                return Err(ClusterError::because(
                    Errno::EACCES,
                    "credential cluster_node_id cannot mutate another node's record",
                ));
            }
        }
    }
    Ok(())
}

fn check_node_delete_range(
    grant: &ClusterGrant,
    resolved: &ResolvedRange,
) -> Result<(), ClusterError> {
    let Some(bound_node) = grant.scope.cluster_node_id.as_deref() else {
        return Ok(());
    };
    for dir in ["nodes", "node-meta"] {
        let dir_start = format!("/t/{}/{dir}/", grant.tenant);
        let dir_end = prefix_range_end(&dir_start).unwrap_or_default();
        if !intervals_overlap(&resolved.start, &resolved.end, &dir_start, &dir_end) {
            continue;
        }
        let own_exact = format!("/t/{}/{dir}/{bound_node}", grant.tenant);
        let own_exact_end = exact_key_end(&own_exact);
        let own_sub = format!("{own_exact}/");
        let own_sub_end = prefix_range_end(&own_sub).unwrap_or_default();
        let within_exact = resolved.start >= own_exact && resolved.end <= own_exact_end;
        let within_sub = resolved.start >= own_sub && resolved.end <= own_sub_end;
        if !within_exact && !within_sub {
            return Err(ClusterError::because(
                Errno::EACCES,
                "credential cluster_node_id cannot delete outside its own node record",
            ));
        }
    }
    Ok(())
}

/// Authorize a `Range` call and return its tenant-clamped byte interval.
pub fn authorize_range(
    grant: &ClusterGrant,
    key: &str,
    range_end: &RangeEnd,
) -> Result<ResolvedRange, ClusterError> {
    validate_grant(grant)?;
    if !grant.scope.cluster_read {
        return Err(ClusterError::because(
            Errno::EACCES,
            "cluster_read capability required",
        ));
    }
    let resolved = resolve_range(&grant.tenant, key, range_end)?;
    check_range_prefix(grant, key, range_end, &resolved)?;
    Ok(resolved)
}

/// Authorize a `Watch` subscription/pull and return its tenant-clamped byte interval.
pub fn authorize_watch(
    grant: &ClusterGrant,
    key: &str,
    range_end: &RangeEnd,
) -> Result<ResolvedRange, ClusterError> {
    validate_grant(grant)?;
    if !grant.scope.cluster_watch {
        return Err(ClusterError::because(
            Errno::EACCES,
            "cluster_watch capability required",
        ));
    }
    let resolved = resolve_range(&grant.tenant, key, range_end)?;
    check_range_prefix(grant, key, range_end, &resolved)?;
    Ok(resolved)
}

fn authorize_txn_branch(grant: &ClusterGrant, ops: &[TxnOp]) -> Result<(), ClusterError> {
    if ops.len() > CLUSTER_TXN_MAX_OPS {
        return Err(ClusterError::because(
            Errno::E2BIG,
            format!("transaction branch exceeds {CLUSTER_TXN_MAX_OPS} ops"),
        ));
    }
    let mut put_keys: BTreeSet<&str> = BTreeSet::new();
    let mut del_ranges: Vec<ResolvedRange> = Vec::new();
    let mut total_write_bytes: usize = 0;

    for op in ops {
        match op {
            TxnOp::Range { key, range_end, .. } => {
                authorize_range(grant, key, range_end)?;
            }
            TxnOp::Put {
                key,
                value_b64,
                lease_id,
                ..
            } => {
                if !grant.scope.cluster_write {
                    return Err(ClusterError::because(
                        Errno::EACCES,
                        "cluster_write capability required",
                    ));
                }
                if *lease_id != 0 && !grant.scope.cluster_lease {
                    return Err(ClusterError::because(
                        Errno::EACCES,
                        "cluster_lease capability required to attach a lease",
                    ));
                }
                check_key_prefix(grant, key)?;
                check_node_write_key(grant, key)?;
                let decoded = decode_value_b64(value_b64)?;
                total_write_bytes = total_write_bytes.saturating_add(decoded.len());
                if total_write_bytes > CLUSTER_TXN_MAX_WRITE_BYTES {
                    return Err(ClusterError::because(
                        Errno::EFBIG,
                        format!(
                            "transaction write payload exceeds {CLUSTER_TXN_MAX_WRITE_BYTES} bytes"
                        ),
                    ));
                }
                if !put_keys.insert(key.as_str()) {
                    return Err(ClusterError::because(
                        Errno::EINVAL,
                        "duplicate key put in transaction branch",
                    ));
                }
            }
            TxnOp::DeleteRange { key, range_end, .. } => {
                if !grant.scope.cluster_write {
                    return Err(ClusterError::because(
                        Errno::EACCES,
                        "cluster_write capability required",
                    ));
                }
                let resolved = resolve_range(&grant.tenant, key, range_end)?;
                check_range_prefix(grant, key, range_end, &resolved)?;
                check_node_delete_range(grant, &resolved)?;
                if del_ranges.iter().any(|prev| {
                    intervals_overlap(&prev.start, &prev.end, &resolved.start, &resolved.end)
                }) {
                    return Err(ClusterError::because(
                        Errno::EINVAL,
                        "overlapping delete ranges in transaction branch",
                    ));
                }
                del_ranges.push(resolved);
            }
        }
    }

    for k in &put_keys {
        if del_ranges.iter().any(|r| r.contains_key(k)) {
            return Err(ClusterError::because(
                Errno::EINVAL,
                "conflicting put and delete on same key in transaction branch",
            ));
        }
    }
    Ok(())
}

/// Authorize EVERY `compare`, `success`, and `failure` operation of a `Txn` BEFORE evaluating
/// any compare predicate (preventing unauthorized branches from acting as side channels).
pub fn authorize_txn(
    grant: &ClusterGrant,
    compare: &[Compare],
    success: &[TxnOp],
    failure: &[TxnOp],
) -> Result<(), ClusterError> {
    validate_grant(grant)?;
    if compare.len() > CLUSTER_TXN_MAX_COMPARES {
        return Err(ClusterError::because(
            Errno::E2BIG,
            format!("transaction exceeds {CLUSTER_TXN_MAX_COMPARES} compares"),
        ));
    }
    for cmp in compare {
        if !grant.scope.cluster_read {
            return Err(ClusterError::because(
                Errno::EACCES,
                "cluster_read capability required for transaction compare",
            ));
        }
        check_key_prefix(grant, &cmp.key)?;
        if let CompareTarget::Value(ref b64) = cmp.target {
            decode_value_b64(b64)?;
        }
    }
    authorize_txn_branch(grant, success)?;
    authorize_txn_branch(grant, failure)?;
    Ok(())
}

/// Authorize `LeaseGrant` and return the effective `node_id` binding for the new lease.
pub fn authorize_lease_grant(
    grant: &ClusterGrant,
    ttl_secs: u64,
    requested_node_id: Option<&str>,
) -> Result<Option<String>, ClusterError> {
    validate_grant(grant)?;
    if !grant.scope.cluster_lease {
        return Err(ClusterError::because(
            Errno::EACCES,
            "cluster_lease capability required",
        ));
    }
    if !(CLUSTER_LEASE_MIN_TTL_SECS..=CLUSTER_LEASE_MAX_TTL_SECS).contains(&ttl_secs) {
        return Err(ClusterError::because(
            Errno::EINVAL,
            format!(
                "lease ttl_secs must be between {CLUSTER_LEASE_MIN_TTL_SECS} and {CLUSTER_LEASE_MAX_TTL_SECS}"
            ),
        ));
    }
    if let Some(req_node) = requested_node_id
        && !valid_cluster_record_id(req_node)
    {
        return Err(ClusterError::because(Errno::EINVAL, "invalid node_id"));
    }
    let effective_node = match (grant.scope.cluster_node_id.as_deref(), requested_node_id) {
        (Some(bound), Some(req)) if bound != req => {
            return Err(ClusterError::because(
                Errno::EACCES,
                "lease node_id does not match credential cluster_node_id",
            ));
        }
        (Some(bound), _) => Some(bound.to_string()),
        (None, Some(req)) => Some(req.to_string()),
        (None, None) => None,
    };
    if let Some(ref nid) = effective_node
        && !grant.scope.cluster_prefixes.is_empty()
    {
        check_key_prefix(grant, &format!("/t/{}/nodes/{nid}", grant.tenant))?;
    }
    Ok(effective_node)
}

/// Validate caller capability for a lease operation BEFORE looking up `lease_id` so cross-tenant
/// lease existence is never leaked through differing `EACCES` vs `ENOENT` responses.
pub fn authorize_lease_capability(grant: &ClusterGrant, mutate: bool) -> Result<(), ClusterError> {
    validate_grant(grant)?;
    if mutate {
        if !grant.scope.cluster_lease {
            return Err(ClusterError::because(
                Errno::EACCES,
                "cluster_lease capability required",
            ));
        }
    } else if !grant.scope.cluster_lease && !grant.scope.cluster_read {
        return Err(ClusterError::because(
            Errno::EACCES,
            "cluster_lease or cluster_read capability required",
        ));
    }
    Ok(())
}

/// Authorize lease mutation (`KeepAlive`, `Revoke`, `Put(lease_id)`) or inspection (`TimeToLive`),
/// enforcing tenant ownership, `cluster_node_id` binding, and `cluster_prefixes` containment over
/// both `lease_node_id` and every attached key.
#[allow(clippy::too_many_arguments)]
pub fn authorize_lease_access(
    grant: &ClusterGrant,
    mutate: bool,
    is_revoke: bool,
    lease_tenant: &str,
    lease_node_id: Option<&str>,
    attached_keys: &[String],
) -> Result<(), ClusterError> {
    authorize_lease_capability(grant, mutate)?;
    if lease_tenant != grant.tenant {
        // Never leak cross-tenant lease existence.
        return Err(ClusterError::because(Errno::ENOENT, "lease not found"));
    }
    if let Some(bound) = grant.scope.cluster_node_id.as_deref()
        && lease_node_id != Some(bound)
    {
        return Err(ClusterError::because(
            Errno::EACCES,
            "lease is not bound to credential cluster_node_id",
        ));
    }
    if !grant.scope.cluster_prefixes.is_empty() {
        if let Some(nid) = lease_node_id {
            check_key_prefix(grant, &format!("/t/{}/nodes/{nid}", grant.tenant))?;
        }
        for key in attached_keys {
            check_key_prefix(grant, key)?;
        }
    }
    if is_revoke {
        for key in attached_keys {
            check_node_write_key(grant, key)?;
        }
    }
    Ok(())
}

/// Authorize `Compact` (strictly admin + `cluster_compact` + unrestricted prefixes & node_id).
pub fn authorize_compact(grant: &ClusterGrant) -> Result<(), ClusterError> {
    validate_grant(grant)?;
    if !grant.admin
        || !grant.scope.cluster_compact
        || !grant.scope.cluster_prefixes.is_empty()
        || grant.scope.cluster_node_id.is_some()
    {
        return Err(ClusterError::because(
            Errno::EACCES,
            "unrestricted admin cluster_compact capability required",
        ));
    }
    Ok(())
}

/// Evaluate a single `Compare` against the live key (or `None` if absent).
pub fn eval_compare(kv: Option<&KeyValue>, cmp: &Compare) -> Result<bool, ClusterError> {
    let ord = match &cmp.target {
        CompareTarget::Version(expected) => kv.map_or(0, |k| k.version).cmp(expected),
        CompareTarget::CreateRevision(expected) => {
            kv.map_or(0, |k| k.create_revision).cmp(expected)
        }
        CompareTarget::ModRevision(expected) => kv.map_or(0, |k| k.mod_revision).cmp(expected),
        CompareTarget::Lease(expected) => kv.map_or(0, |k| k.lease_id).cmp(expected),
        CompareTarget::Value(expected_b64) => {
            let expected = decode_value_b64(expected_b64)?;
            let actual = match kv {
                Some(k) => k.decode_value()?,
                None => Vec::new(),
            };
            actual.as_slice().cmp(expected.as_slice())
        }
    };
    Ok(match cmp.op {
        CompareOp::Equal => ord.is_eq(),
        CompareOp::NotEqual => ord.is_ne(),
        CompareOp::Less => ord.is_lt(),
        CompareOp::Greater => ord.is_gt(),
    })
}
