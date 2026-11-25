//! Pure-Rust reference `MemoryClusterStore` implementing `ClusterStore` with full MVCC history,
//! linearizable conditional transactions, lazy + explicit lease expiration, persisted watch event
//! log, MVCC compaction, and per-tenant quota enforcement.
use crate::authz::{
    ResolvedRange, authorize_compact, authorize_lease_access, authorize_lease_capability,
    authorize_lease_grant, authorize_range, authorize_txn, authorize_watch, eval_compare,
    resolve_range, validate_grant,
};
use crate::{BoxFuture, ClusterGrant, ClusterStore, WatchBatch, WatchCursor};
use abi::Errno;
use abi::cluster_state::{
    CLUSTER_MAX_KEYS_PER_LEASE, CLUSTER_MAX_LEASES_PER_TENANT, CLUSTER_MAX_LIVE_BYTES_PER_TENANT,
    CLUSTER_MAX_LIVE_KEYS_PER_TENANT, CLUSTER_RANGE_DEFAULT_LIMIT, CLUSTER_RANGE_MAX_LIMIT,
    CLUSTER_STATE_PROTOCOL, CLUSTER_WATCH_CATCHUP_BATCH, ClusterCall, ClusterError, ClusterReply,
    KeyValue, TxnOp, TxnOpReply, WatchEvent, WatchEventType, decode_value_b64,
};
use abi::contract::{Boundary, Hello, negotiate};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

#[derive(Clone, Debug)]
struct LiveEntry {
    tenant: String,
    kv: KeyValue,
    value_bytes: u64,
}

#[derive(Clone, Debug)]
struct RevEntry {
    revision: u64,
    tenant: String,
    tombstone: bool,
    kv: KeyValue,
}

#[derive(Clone, Debug)]
struct LeaseEntry {
    lease_id: u64,
    tenant: String,
    #[allow(dead_code)]
    owner: String,
    node_id: Option<String>,
    ttl_secs: u64,
    expires_at: u64,
    keys: BTreeSet<String>,
}

#[derive(Clone, Debug)]
struct StoredEvent {
    seq: u64,
    tenant: String,
    event: WatchEvent,
}

#[derive(Clone, Debug, Default)]
struct TenantUsage {
    live_keys: usize,
    live_bytes: u64,
    live_leases: usize,
}

#[derive(Debug)]
struct MemoryState {
    cluster: String,
    current_revision: u64,
    compacted_floor: u64,
    next_lease_id: u64,
    next_event_seq: u64,
    current: BTreeMap<String, LiveEntry>,
    revisions: BTreeMap<String, Vec<RevEntry>>,
    leases: BTreeMap<u64, LeaseEntry>,
    events: Vec<StoredEvent>,
    usage: BTreeMap<String, TenantUsage>,
}

impl MemoryState {
    fn new(cluster: String) -> Self {
        Self {
            cluster,
            current_revision: 0,
            compacted_floor: 0,
            next_lease_id: 1,
            next_event_seq: 1,
            current: BTreeMap::new(),
            revisions: BTreeMap::new(),
            leases: BTreeMap::new(),
            events: Vec::new(),
            usage: BTreeMap::new(),
        }
    }

    fn append_event(&mut self, tenant: &str, event: WatchEvent) {
        let seq = self.next_event_seq;
        self.next_event_seq = self.next_event_seq.saturating_add(1);
        self.events.push(StoredEvent {
            seq,
            tenant: tenant.to_string(),
            event,
        });
    }

    fn delete_key_at(&mut self, key: &str, rev: u64) -> Option<KeyValue> {
        let removed = self.current.remove(key)?;
        if removed.kv.lease_id != 0
            && let Some(lease) = self.leases.get_mut(&removed.kv.lease_id)
        {
            lease.keys.remove(key);
        }
        if let Some(u) = self.usage.get_mut(&removed.tenant) {
            u.live_keys = u.live_keys.saturating_sub(1);
            u.live_bytes = u.live_bytes.saturating_sub(removed.value_bytes);
        }
        let tombstone_kv = KeyValue {
            key: key.to_string(),
            value_b64: String::new(),
            create_revision: 0,
            mod_revision: rev,
            version: 0,
            lease_id: 0,
        };
        self.revisions
            .entry(key.to_string())
            .or_default()
            .push(RevEntry {
                revision: rev,
                tenant: removed.tenant.clone(),
                tombstone: true,
                kv: tombstone_kv.clone(),
            });
        self.append_event(
            &removed.tenant,
            WatchEvent {
                event_type: WatchEventType::Delete,
                revision: rev,
                kv: tombstone_kv,
                prev_kv: Some(removed.kv.clone()),
            },
        );
        Some(removed.kv)
    }

    fn expire_due_leases(&mut self, now_secs: u64) -> usize {
        let due_ids: Vec<u64> = self
            .leases
            .values()
            .filter(|l| l.expires_at <= now_secs)
            .map(|l| l.lease_id)
            .collect();
        let mut expired_count = 0;
        for id in due_ids {
            let Some(lease) = self.leases.remove(&id) else {
                continue;
            };
            expired_count += 1;
            if let Some(u) = self.usage.get_mut(&lease.tenant) {
                u.live_leases = u.live_leases.saturating_sub(1);
            }
            if !lease.keys.is_empty() {
                let rev = self.current_revision.saturating_add(1);
                let mut deleted_any = false;
                for key in lease.keys {
                    if self.delete_key_at(&key, rev).is_some() {
                        deleted_any = true;
                    }
                }
                if deleted_any {
                    self.current_revision = rev;
                }
            }
        }
        expired_count
    }

    fn range_at(
        &self,
        tenant: &str,
        resolved: &ResolvedRange,
        revision: u64,
        limit: Option<u32>,
        keys_only: bool,
        count_only: bool,
    ) -> Result<(Vec<KeyValue>, bool, u64), ClusterError> {
        let eff_limit = match limit {
            Some(0) | None => CLUSTER_RANGE_DEFAULT_LIMIT,
            Some(n) => n.min(CLUSTER_RANGE_MAX_LIMIT),
        } as usize;

        let mut matched: Vec<KeyValue> = Vec::new();
        if revision == 0 || revision == self.current_revision {
            for (k, entry) in self
                .current
                .range(resolved.start.clone()..resolved.end.clone())
            {
                debug_assert_eq!(k, &entry.kv.key);
                if entry.tenant == tenant {
                    matched.push(entry.kv.clone());
                }
            }
        } else {
            if revision > self.current_revision {
                return Err(ClusterError::because(
                    Errno::ERANGE,
                    "requested revision is in the future",
                ));
            }
            if revision < self.compacted_floor {
                return Err(ClusterError::compacted(self.compacted_floor));
            }
            for (_k, history) in self
                .revisions
                .range(resolved.start.clone()..resolved.end.clone())
            {
                if let Some(latest) = history
                    .iter()
                    .rev()
                    .find(|e| e.revision <= revision && e.tenant == tenant)
                    && !latest.tombstone
                {
                    matched.push(latest.kv.clone());
                }
            }
        }

        let count = matched.len() as u64;
        if count_only {
            return Ok((Vec::new(), false, count));
        }
        let more = matched.len() > eff_limit;
        matched.truncate(eff_limit);
        if keys_only {
            for kv in &mut matched {
                kv.value_b64.clear();
            }
        }
        Ok((matched, more, count))
    }

    fn precheck_txn_writes(
        &self,
        grant: &ClusterGrant,
        ops: &[TxnOp],
    ) -> Result<bool, ClusterError> {
        let usage = self.usage.get(&grant.tenant).cloned().unwrap_or_default();
        let mut live_keys = usage.live_keys as i64;
        let mut live_bytes = usage.live_bytes as i128;
        let mut lease_deltas: BTreeMap<u64, i64> = BTreeMap::new();
        let mut deleted_keys: BTreeSet<String> = BTreeSet::new();
        let mut mutates = false;

        for op in ops {
            match op {
                TxnOp::Range { .. } => {}
                TxnOp::Put {
                    key,
                    value_b64,
                    lease_id,
                    ..
                } => {
                    mutates = true;
                    let new_len = decode_value_b64(value_b64)?.len() as i128;
                    if *lease_id != 0 {
                        authorize_lease_capability(grant, true)?;
                        if *lease_id > i64::MAX as u64 {
                            return Err(ClusterError::because(Errno::ENOENT, "lease not found"));
                        }
                        let Some(lease) = self.leases.get(lease_id) else {
                            return Err(ClusterError::because(Errno::ENOENT, "lease not found"));
                        };
                        let attached: Vec<String> = lease.keys.iter().cloned().collect();
                        authorize_lease_access(
                            grant,
                            true,
                            false,
                            &lease.tenant,
                            lease.node_id.as_deref(),
                            &attached,
                        )?;
                    }
                    if let Some(existing) = self.current.get(key) {
                        live_bytes -= existing.value_bytes as i128;
                        live_bytes += new_len;
                        if existing.kv.lease_id != *lease_id {
                            if existing.kv.lease_id != 0 {
                                *lease_deltas.entry(existing.kv.lease_id).or_insert(0) -= 1;
                            }
                            if *lease_id != 0 {
                                *lease_deltas.entry(*lease_id).or_insert(0) += 1;
                            }
                        }
                    } else {
                        live_keys += 1;
                        live_bytes += new_len;
                        if *lease_id != 0 {
                            *lease_deltas.entry(*lease_id).or_insert(0) += 1;
                        }
                    }
                }
                TxnOp::DeleteRange { key, range_end, .. } => {
                    let resolved = resolve_range(&grant.tenant, key, range_end)?;
                    for (k, entry) in self
                        .current
                        .range(resolved.start.clone()..resolved.end.clone())
                    {
                        if entry.tenant == grant.tenant && deleted_keys.insert(k.clone()) {
                            mutates = true;
                            live_keys -= 1;
                            live_bytes -= entry.value_bytes as i128;
                            if entry.kv.lease_id != 0 {
                                *lease_deltas.entry(entry.kv.lease_id).or_insert(0) -= 1;
                            }
                        }
                    }
                }
            }
        }

        if live_keys > CLUSTER_MAX_LIVE_KEYS_PER_TENANT as i64
            || live_bytes > CLUSTER_MAX_LIVE_BYTES_PER_TENANT as i128
        {
            return Err(ClusterError::because(
                Errno::EDQUOT,
                "tenant cluster storage quota exceeded",
            ));
        }
        for (lid, delta) in lease_deltas {
            if delta > 0
                && let Some(lease) = self.leases.get(&lid)
                && (lease.keys.len() as i64 + delta) > CLUSTER_MAX_KEYS_PER_LEASE as i64
            {
                return Err(ClusterError::because(
                    Errno::EDQUOT,
                    "lease key attachment limit exceeded",
                ));
            }
        }
        Ok(mutates)
    }

    fn execute_rpc(
        &mut self,
        grant: &ClusterGrant,
        call: ClusterCall,
        now_secs: u64,
    ) -> Result<ClusterReply, ClusterError> {
        validate_grant(grant)?;
        self.expire_due_leases(now_secs);
        match call {
            ClusterCall::Hello { versions } => {
                let ours = Hello {
                    boundary: Boundary::ClusterState,
                    versions: vec![CLUSTER_STATE_PROTOCOL],
                };
                let theirs = Hello {
                    boundary: Boundary::ClusterState,
                    versions,
                };
                let Some(version) = negotiate(&ours, &theirs) else {
                    return Err(ClusterError::because(
                        Errno::EPROTONOSUPPORT,
                        format!("ClusterState protocol v{CLUSTER_STATE_PROTOCOL} required"),
                    ));
                };
                Ok(ClusterReply::Welcome {
                    boundary: Boundary::ClusterState,
                    version,
                    cluster: self.cluster.clone(),
                    tenant: grant.tenant.clone(),
                    revision: self.current_revision,
                    compacted_floor: self.compacted_floor,
                })
            }
            ClusterCall::Range {
                key,
                range_end,
                revision,
                limit,
                keys_only,
                count_only,
            } => {
                let resolved = authorize_range(grant, &key, &range_end)?;
                let (kvs, more, count) = self.range_at(
                    &grant.tenant,
                    &resolved,
                    revision,
                    limit,
                    keys_only,
                    count_only,
                )?;
                Ok(ClusterReply::Range {
                    revision: self.current_revision,
                    compacted_floor: self.compacted_floor,
                    kvs,
                    more,
                    count,
                })
            }
            ClusterCall::Txn {
                compare,
                success,
                failure,
            } => {
                authorize_txn(grant, &compare, &success, &failure)?;
                let mut succeeded = true;
                for cmp in &compare {
                    let kv = self
                        .current
                        .get(&cmp.key)
                        .filter(|e| e.tenant == grant.tenant)
                        .map(|e| &e.kv);
                    if !eval_compare(kv, cmp)? {
                        succeeded = false;
                        break;
                    }
                }
                let chosen = if succeeded { success } else { failure };
                let mutates = self.precheck_txn_writes(grant, &chosen)?;
                let write_rev = if mutates {
                    self.current_revision
                        .checked_add(1)
                        .filter(|r| *r <= i64::MAX as u64)
                        .ok_or_else(|| ClusterError::new(Errno::ENOSPC))?
                } else {
                    self.current_revision
                };
                let mut responses = Vec::with_capacity(chosen.len());
                for op in chosen {
                    match op {
                        TxnOp::Range {
                            key,
                            range_end,
                            limit,
                            keys_only,
                            count_only,
                        } => {
                            let resolved = resolve_range(&grant.tenant, &key, &range_end)?;
                            let (kvs, more, count) = self.range_at(
                                &grant.tenant,
                                &resolved,
                                0,
                                limit,
                                keys_only,
                                count_only,
                            )?;
                            responses.push(TxnOpReply::Range { kvs, more, count });
                        }
                        TxnOp::Put {
                            key,
                            value_b64,
                            lease_id,
                            prev_kv,
                        } => {
                            let new_bytes = decode_value_b64(&value_b64)?.len() as u64;
                            let prev = self.current.get(&key).map(|e| e.kv.clone());
                            let (create_revision, version) = match self.current.get(&key) {
                                Some(existing) => {
                                    if existing.kv.lease_id != 0
                                        && existing.kv.lease_id != lease_id
                                        && let Some(old_lease) =
                                            self.leases.get_mut(&existing.kv.lease_id)
                                    {
                                        old_lease.keys.remove(&key);
                                    }
                                    let u = self.usage.entry(grant.tenant.clone()).or_default();
                                    u.live_bytes =
                                        u.live_bytes.saturating_sub(existing.value_bytes)
                                            + new_bytes;
                                    (existing.kv.create_revision, existing.kv.version + 1)
                                }
                                None => {
                                    let u = self.usage.entry(grant.tenant.clone()).or_default();
                                    u.live_keys += 1;
                                    u.live_bytes += new_bytes;
                                    (write_rev, 1)
                                }
                            };
                            if lease_id != 0
                                && let Some(lease) = self.leases.get_mut(&lease_id)
                            {
                                lease.keys.insert(key.clone());
                            }
                            let kv = KeyValue {
                                key: key.clone(),
                                value_b64,
                                create_revision,
                                mod_revision: write_rev,
                                version,
                                lease_id,
                            };
                            self.current.insert(
                                key.clone(),
                                LiveEntry {
                                    tenant: grant.tenant.clone(),
                                    kv: kv.clone(),
                                    value_bytes: new_bytes,
                                },
                            );
                            self.revisions.entry(key).or_default().push(RevEntry {
                                revision: write_rev,
                                tenant: grant.tenant.clone(),
                                tombstone: false,
                                kv: kv.clone(),
                            });
                            self.append_event(
                                &grant.tenant,
                                WatchEvent {
                                    event_type: WatchEventType::Put,
                                    revision: write_rev,
                                    kv,
                                    prev_kv: prev.clone(),
                                },
                            );
                            responses.push(TxnOpReply::Put {
                                prev_kv: if prev_kv { prev } else { None },
                            });
                        }
                        TxnOp::DeleteRange {
                            key,
                            range_end,
                            prev_kv,
                        } => {
                            let resolved = resolve_range(&grant.tenant, &key, &range_end)?;
                            let victims: Vec<String> = self
                                .current
                                .range(resolved.start.clone()..resolved.end.clone())
                                .filter(|(_, e)| e.tenant == grant.tenant)
                                .map(|(k, _)| k.clone())
                                .collect();
                            let mut prev_kvs = Vec::new();
                            let mut deleted = 0u64;
                            for victim in victims {
                                if let Some(prev) = self.delete_key_at(&victim, write_rev) {
                                    deleted += 1;
                                    if prev_kv {
                                        prev_kvs.push(prev);
                                    }
                                }
                            }
                            responses.push(TxnOpReply::DeleteRange { deleted, prev_kvs });
                        }
                    }
                }
                if mutates {
                    self.current_revision = write_rev;
                }
                Ok(ClusterReply::Txn {
                    revision: self.current_revision,
                    compacted_floor: self.compacted_floor,
                    succeeded,
                    responses,
                })
            }
            ClusterCall::LeaseGrant { ttl_secs, node_id } => {
                let effective_node = authorize_lease_grant(grant, ttl_secs, node_id.as_deref())?;
                let u = self.usage.entry(grant.tenant.clone()).or_default();
                if u.live_leases >= CLUSTER_MAX_LEASES_PER_TENANT {
                    return Err(ClusterError::because(
                        Errno::EDQUOT,
                        "tenant lease limit exceeded",
                    ));
                }
                let lease_id = self.next_lease_id;
                self.next_lease_id = self
                    .next_lease_id
                    .checked_add(1)
                    .filter(|v| *v <= i64::MAX as u64)
                    .ok_or_else(|| ClusterError::new(Errno::ENOSPC))?;
                let expires_at = now_secs.saturating_add(ttl_secs);
                self.leases.insert(
                    lease_id,
                    LeaseEntry {
                        lease_id,
                        tenant: grant.tenant.clone(),
                        owner: grant.owner.clone(),
                        node_id: effective_node,
                        ttl_secs,
                        expires_at,
                        keys: BTreeSet::new(),
                    },
                );
                u.live_leases += 1;
                Ok(ClusterReply::LeaseGranted {
                    revision: self.current_revision,
                    lease_id,
                    ttl_secs,
                    expires_at,
                })
            }
            ClusterCall::LeaseKeepAlive { lease_id } => {
                authorize_lease_capability(grant, true)?;
                if lease_id == 0 || lease_id > i64::MAX as u64 {
                    return Err(ClusterError::because(Errno::ENOENT, "lease not found"));
                }
                let Some(lease) = self.leases.get_mut(&lease_id) else {
                    return Err(ClusterError::because(Errno::ENOENT, "lease not found"));
                };
                let attached: Vec<String> = lease.keys.iter().cloned().collect();
                authorize_lease_access(
                    grant,
                    true,
                    false,
                    &lease.tenant,
                    lease.node_id.as_deref(),
                    &attached,
                )?;
                lease.expires_at = now_secs.saturating_add(lease.ttl_secs);
                Ok(ClusterReply::LeaseKeptAlive {
                    revision: self.current_revision,
                    lease_id,
                    ttl_secs: lease.ttl_secs,
                    expires_at: lease.expires_at,
                })
            }
            ClusterCall::LeaseRevoke { lease_id } => {
                authorize_lease_capability(grant, true)?;
                if lease_id == 0 || lease_id > i64::MAX as u64 {
                    return Err(ClusterError::because(Errno::ENOENT, "lease not found"));
                }
                let Some(lease) = self.leases.get(&lease_id) else {
                    return Err(ClusterError::because(Errno::ENOENT, "lease not found"));
                };
                let attached: Vec<String> = lease.keys.iter().cloned().collect();
                authorize_lease_access(
                    grant,
                    true,
                    true,
                    &lease.tenant,
                    lease.node_id.as_deref(),
                    &attached,
                )?;
                let lease = self.leases.remove(&lease_id).unwrap();
                if let Some(u) = self.usage.get_mut(&lease.tenant) {
                    u.live_leases = u.live_leases.saturating_sub(1);
                }
                let mut deleted = 0u64;
                if !lease.keys.is_empty() {
                    let rev = self.current_revision.saturating_add(1);
                    for key in lease.keys {
                        if self.delete_key_at(&key, rev).is_some() {
                            deleted += 1;
                        }
                    }
                    if deleted > 0 {
                        self.current_revision = rev;
                    }
                }
                Ok(ClusterReply::LeaseRevoked {
                    revision: self.current_revision,
                    lease_id,
                    deleted,
                })
            }
            ClusterCall::LeaseTimeToLive { lease_id, keys } => {
                authorize_lease_capability(grant, false)?;
                if lease_id == 0 || lease_id > i64::MAX as u64 {
                    return Err(ClusterError::because(Errno::ENOENT, "lease not found"));
                }
                let Some(lease) = self.leases.get(&lease_id) else {
                    return Err(ClusterError::because(Errno::ENOENT, "lease not found"));
                };
                let attached: Vec<String> = lease.keys.iter().cloned().collect();
                authorize_lease_access(
                    grant,
                    false,
                    false,
                    &lease.tenant,
                    lease.node_id.as_deref(),
                    &attached,
                )?;
                let remaining = lease.expires_at.saturating_sub(now_secs);
                let returned_keys = if keys { attached } else { Vec::new() };
                Ok(ClusterReply::LeaseTtl {
                    revision: self.current_revision,
                    lease_id,
                    granted_ttl_secs: lease.ttl_secs,
                    remaining_ttl_secs: remaining,
                    expires_at: lease.expires_at,
                    keys: returned_keys,
                })
            }
            ClusterCall::Compact { revision } => {
                authorize_compact(grant)?;
                if revision == 0 || revision > self.current_revision {
                    return Err(ClusterError::because(
                        Errno::EINVAL,
                        "compact revision must be in 1..=current_revision",
                    ));
                }
                if revision < self.compacted_floor {
                    return Err(ClusterError::compacted(self.compacted_floor));
                }
                if revision > self.compacted_floor {
                    self.compacted_floor = revision;
                    self.revisions.retain(|_, history| {
                        // Keep at most the single latest live entry <= revision, plus all entries > revision.
                        let latest_at_rev = history.iter().rposition(|e| e.revision <= revision);
                        let mut kept = Vec::new();
                        if let Some(idx) = latest_at_rev
                            && !history[idx].tombstone
                        {
                            kept.push(history[idx].clone());
                        }
                        for e in history.iter().filter(|e| e.revision > revision) {
                            kept.push(e.clone());
                        }
                        *history = kept;
                        !history.is_empty()
                    });
                    self.events.retain(|e| e.event.revision >= revision);
                }
                Ok(ClusterReply::Compacted {
                    revision: self.current_revision,
                    compacted_floor: self.compacted_floor,
                })
            }
        }
    }

    fn poll_watch(
        &mut self,
        grant: &ClusterGrant,
        cursor: &mut WatchCursor,
        limit: u32,
        now_secs: u64,
    ) -> Result<WatchBatch, ClusterError> {
        let resolved = authorize_watch(grant, &cursor.key, &cursor.range_end)?;
        if cursor.next_revision > i64::MAX as u64 {
            return Err(ClusterError::because(
                Errno::EINVAL,
                "from_revision exceeds maximum supported revision",
            ));
        }
        self.expire_due_leases(now_secs);
        if cursor.next_revision == 0 {
            cursor.next_revision = self.current_revision.saturating_add(1);
            cursor.last_seq = 0;
            return Ok(WatchBatch {
                revision: self.current_revision,
                compacted_floor: self.compacted_floor,
                events: Vec::new(),
                more: false,
            });
        }
        if cursor.next_revision < self.compacted_floor {
            return Err(ClusterError::compacted(self.compacted_floor));
        }
        let eff_limit = if limit == 0 {
            CLUSTER_WATCH_CATCHUP_BATCH
        } else {
            limit.min(CLUSTER_WATCH_CATCHUP_BATCH)
        } as usize;

        let mut matched: Vec<&StoredEvent> = self
            .events
            .iter()
            .filter(|e| {
                e.tenant == grant.tenant
                    && ((e.event.revision > cursor.next_revision)
                        || (e.event.revision == cursor.next_revision && e.seq > cursor.last_seq))
                    && resolved.contains_key(&e.event.kv.key)
            })
            .take(eff_limit + 1)
            .collect();

        let more = matched.len() > eff_limit;
        matched.truncate(eff_limit);

        if let Some(last) = matched.last() {
            if more {
                cursor.next_revision = last.event.revision;
                cursor.last_seq = last.seq;
            } else {
                cursor.next_revision = self.current_revision.saturating_add(1);
                cursor.last_seq = last.seq;
            }
        } else if cursor.next_revision <= self.current_revision {
            cursor.next_revision = self.current_revision.saturating_add(1);
        }

        let events = matched
            .into_iter()
            .map(|e| {
                let mut ev = e.event.clone();
                if !cursor.prev_kv {
                    ev.prev_kv = None;
                }
                ev
            })
            .collect();

        Ok(WatchBatch {
            revision: self.current_revision,
            compacted_floor: self.compacted_floor,
            events,
            more,
        })
    }
}

/// Thread-safe pure-Rust reference `ClusterStore` for unit & conformance testing.
#[derive(Debug)]
pub struct MemoryClusterStore {
    inner: Mutex<MemoryState>,
}

impl Default for MemoryClusterStore {
    fn default() -> Self {
        Self::new("default")
    }
}

impl MemoryClusterStore {
    pub fn new(cluster: impl Into<String>) -> Self {
        Self {
            inner: Mutex::new(MemoryState::new(cluster.into())),
        }
    }

    /// Explicitly expire all leases with `expires_at <= now_secs`, returning how many expired.
    pub fn expire_due_leases(&self, now_secs: u64) -> usize {
        self.inner.lock().unwrap().expire_due_leases(now_secs)
    }

    pub fn current_revision(&self) -> u64 {
        self.inner.lock().unwrap().current_revision
    }

    pub fn compacted_floor(&self) -> u64 {
        self.inner.lock().unwrap().compacted_floor
    }
}

impl ClusterStore for MemoryClusterStore {
    fn rpc<'a>(
        &'a self,
        grant: &'a ClusterGrant,
        call: ClusterCall,
        now_secs: u64,
    ) -> BoxFuture<'a, Result<ClusterReply, ClusterError>> {
        let res = self
            .inner
            .lock()
            .unwrap()
            .execute_rpc(grant, call, now_secs);
        Box::pin(async move { res })
    }

    fn poll_watch<'a>(
        &'a self,
        grant: &'a ClusterGrant,
        cursor: &'a mut WatchCursor,
        limit: u32,
        now_secs: u64,
    ) -> BoxFuture<'a, Result<WatchBatch, ClusterError>> {
        let res = self
            .inner
            .lock()
            .unwrap()
            .poll_watch(grant, cursor, limit, now_secs);
        Box::pin(async move { res })
    }
}
