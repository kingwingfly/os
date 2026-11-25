//! SQLite-backed `ClusterState` Durable Object (`Boundary::ClusterState` v1, Phase 9.1a #83).
//!
//! Provides linearizable etcd-subset semantics (revisioned MVCC KV, conditional `Txn`,
//! persistent Hibernatable WebSocket `Watch`, alarm-driven `Lease` expiration, and `Compact`).
//! All `u64` columns are read via `CAST(col AS TEXT)` + `db::exact_u64` for JS float53 safety.
use crate::auth;
use crate::cluster_gateway::{
    self, ClusterDoRpc, ClusterIssueTicket, SessionCheck, VerifiedClusterCred,
};
use crate::db::{self, Db, int, text};
use abi::Errno;
use abi::cluster_state::{
    CLUSTER_MAX_KEYS_PER_LEASE, CLUSTER_MAX_LEASES_PER_TENANT, CLUSTER_MAX_LIVE_BYTES_PER_TENANT,
    CLUSTER_MAX_LIVE_KEYS_PER_TENANT, CLUSTER_RANGE_DEFAULT_LIMIT, CLUSTER_RANGE_MAX_LIMIT,
    CLUSTER_STATE_PROTOCOL, CLUSTER_WATCH_CATCHUP_BATCH, CLUSTER_WATCH_MAX_PER_SOCKET,
    CLUSTER_WATCH_MAX_SOCKETS, CLUSTER_WATCH_TICKET_TTL_SECS, CLUSTER_WS_FRAME_MAX_BYTES,
    ClusterCall, ClusterError, ClusterReply, KeyValue, TxnOp, TxnOpReply, WatchClientFrame,
    WatchEvent, WatchEventType, WatchServerFrame, WatchTicketReply, decode_value_b64,
    valid_cluster_name,
};
use abi::contract::{Boundary, Hello, negotiate};
use futures_util::lock::Mutex;
use os_cluster_state::ClusterGrant;
use os_cluster_state::authz::{
    ResolvedRange, authorize_compact, authorize_lease_access, authorize_lease_capability,
    authorize_lease_grant, authorize_range, authorize_txn, authorize_watch, eval_compare,
    resolve_range, validate_grant,
};
use os_cluster_state::schema::{CLUSTER_SCHEMA_VERSION, SCHEMA_V1};
use serde::{Deserialize, Serialize};
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use worker::*;

type CResult<T> = std::result::Result<T, ClusterError>;

/// Minimal WebSocket hibernation attachment (`< 200` bytes; well below the 2 KiB DO cap).
#[derive(Clone, Debug, Serialize, Deserialize)]
struct WsAttachment {
    conn_id: String,
    proto: u32,
    tenant: String,
}

#[derive(Deserialize)]
struct StrRow {
    v: String,
}

#[derive(Deserialize)]
struct NumRow {
    #[serde(deserialize_with = "db::exact_u64")]
    n: u64,
}

#[derive(Deserialize)]
struct OptNumRow {
    n: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct SchemaMeta {
    cluster: String,
    #[serde(deserialize_with = "db::exact_u64")]
    current_revision: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    compacted_floor: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    next_lease_id: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    next_event_seq: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct KvRow {
    key: String,
    tenant: String,
    value_b64: String,
    #[serde(deserialize_with = "db::exact_u64")]
    value_bytes: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    create_revision: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    mod_revision: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    version: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    lease_id: u64,
}

impl KvRow {
    fn into_kv(self) -> KeyValue {
        KeyValue {
            key: self.key,
            value_b64: self.value_b64,
            create_revision: self.create_revision,
            mod_revision: self.mod_revision,
            version: self.version,
            lease_id: self.lease_id,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct HistKvRow {
    key: String,
    value_b64: String,
    #[serde(deserialize_with = "db::exact_u64")]
    create_revision: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    mod_revision: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    version: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    lease_id: u64,
}

impl HistKvRow {
    fn into_kv(self) -> KeyValue {
        KeyValue {
            key: self.key,
            value_b64: self.value_b64,
            create_revision: self.create_revision,
            mod_revision: self.mod_revision,
            version: self.version,
            lease_id: self.lease_id,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct LeaseRow {
    #[serde(deserialize_with = "db::exact_u64")]
    lease_id: u64,
    tenant: String,
    node_id: Option<String>,
    #[serde(deserialize_with = "db::exact_u64")]
    ttl_secs: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    expires_at: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct UsageRow {
    #[serde(deserialize_with = "db::exact_u64")]
    live_keys: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    live_bytes: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    live_leases: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct WatchEventRow {
    #[serde(deserialize_with = "db::exact_u64")]
    seq: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    revision: u64,
    key: String,
    event_type: u8,
    value_b64: String,
    #[serde(deserialize_with = "db::exact_u64")]
    create_revision: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    mod_revision: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    version: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    lease_id: u64,
    prev_present: u8,
    prev_value_b64: String,
    #[serde(deserialize_with = "db::exact_u64")]
    prev_create_revision: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    prev_mod_revision: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    prev_version: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    prev_lease_id: u64,
}

impl WatchEventRow {
    fn into_event(self, include_prev: bool) -> (u64, WatchEvent) {
        let seq = self.seq;
        let event_type = if self.event_type == 2 {
            WatchEventType::Delete
        } else {
            WatchEventType::Put
        };
        let prev_kv = if include_prev && self.prev_present != 0 {
            Some(KeyValue {
                key: self.key.clone(),
                value_b64: self.prev_value_b64,
                create_revision: self.prev_create_revision,
                mod_revision: self.prev_mod_revision,
                version: self.prev_version,
                lease_id: self.prev_lease_id,
            })
        } else {
            None
        };
        (
            seq,
            WatchEvent {
                event_type,
                revision: self.revision,
                kv: KeyValue {
                    key: self.key,
                    value_b64: self.value_b64,
                    create_revision: self.create_revision,
                    mod_revision: self.mod_revision,
                    version: self.version,
                    lease_id: self.lease_id,
                },
                prev_kv,
            },
        )
    }
}

#[derive(Clone, Debug, Deserialize)]
struct WatchSessionRow {
    conn_id: String,
    tenant: String,
    owner: String,
    ns: String,
    cred_hash: String,
    instance_id: String,
    admin: u8,
    scope_json: String,
}

impl WatchSessionRow {
    fn to_check(&self) -> SessionCheck {
        SessionCheck {
            conn_id: self.conn_id.clone(),
            tenant: self.tenant.clone(),
            ns: self.ns.clone(),
            cred_hash: self.cred_hash.clone(),
            instance_id: self.instance_id.clone(),
        }
    }

    fn to_grant(&self) -> CResult<ClusterGrant> {
        let scope =
            serde_json::from_str(&self.scope_json).map_err(|_| ClusterError::new(Errno::EACCES))?;
        Ok(ClusterGrant {
            tenant: self.tenant.clone(),
            owner: self.owner.clone(),
            admin: self.admin != 0,
            scope,
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
struct WatchSubRow {
    #[serde(deserialize_with = "db::exact_u64")]
    watch_id: u64,
    tenant: String,
    start_key: String,
    end_key: String,
    #[serde(deserialize_with = "db::exact_u64")]
    next_revision: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    last_seq: u64,
    prev_kv: u8,
}

#[derive(Clone, Debug, Deserialize)]
struct TicketRow {
    tenant: String,
    owner: String,
    ns: String,
    cred_hash: String,
    instance_id: String,
    admin: u8,
    scope_json: String,
    #[serde(deserialize_with = "db::exact_u64")]
    expires_at: u64,
}

fn strings(db: &Db, sql: &str, args: Vec<SqlStorageValue>) -> Vec<String> {
    db.rows::<StrRow>(sql, args)
        .into_iter()
        .map(|r| r.v)
        .collect()
}

fn number(db: &Db, sql: &str, args: Vec<SqlStorageValue>) -> Option<u64> {
    db.rows::<NumRow>(sql, args).pop().map(|r| r.n)
}

fn opt_number(db: &Db, sql: &str, args: Vec<SqlStorageValue>) -> Option<u64> {
    db.rows::<OptNumRow>(sql, args)
        .pop()
        .and_then(|r| r.n)
        .and_then(|s| s.parse().ok())
}

fn tx<T: 'static>(state: &State, f: impl FnOnce(&mut Db) -> CResult<T> + 'static) -> CResult<T> {
    db::transact(state, move |db| {
        let r = f(db);
        let commit = r.is_ok();
        (r, commit)
    })
    .map_err(|_| ClusterError::because(Errno::EIO, "storage transaction failed"))?
}

fn read_meta(db: &Db) -> CResult<SchemaMeta> {
    db.rows::<SchemaMeta>(
        "SELECT cluster,
                CAST(current_revision AS TEXT) AS current_revision,
                CAST(compacted_floor AS TEXT) AS compacted_floor,
                CAST(next_lease_id AS TEXT) AS next_lease_id,
                CAST(next_event_seq AS TEXT) AS next_event_seq
         FROM schema_meta WHERE singleton = 1",
        vec![],
    )
    .pop()
    .ok_or_else(|| ClusterError::because(Errno::EIO, "missing schema_meta"))
}

fn save_meta(db: &mut Db, meta: &SchemaMeta) {
    db.run(
        "UPDATE schema_meta
         SET current_revision = ?1, compacted_floor = ?2, next_lease_id = ?3, next_event_seq = ?4
         WHERE singleton = 1",
        vec![
            int(meta.current_revision),
            int(meta.compacted_floor),
            int(meta.next_lease_id),
            int(meta.next_event_seq),
        ],
    );
}

fn get_usage(db: &Db, tenant: &str) -> UsageRow {
    db.rows::<UsageRow>(
        "SELECT CAST(live_keys AS TEXT) AS live_keys,
                CAST(live_bytes AS TEXT) AS live_bytes,
                CAST(live_leases AS TEXT) AS live_leases
         FROM tenant_usage WHERE tenant = ?1",
        vec![text(tenant)],
    )
    .pop()
    .unwrap_or(UsageRow {
        live_keys: 0,
        live_bytes: 0,
        live_leases: 0,
    })
}

fn ensure_usage_row(db: &mut Db, tenant: &str) {
    db.run(
        "INSERT OR IGNORE INTO tenant_usage(tenant, live_keys, live_bytes, live_leases) VALUES(?1, 0, 0, 0)",
        vec![text(tenant)],
    );
}

fn get_kv(db: &Db, key: &str) -> Option<KvRow> {
    db.rows::<KvRow>(
        "SELECT key, tenant, value_b64,
                CAST(value_bytes AS TEXT) AS value_bytes,
                CAST(create_revision AS TEXT) AS create_revision,
                CAST(mod_revision AS TEXT) AS mod_revision,
                CAST(version AS TEXT) AS version,
                CAST(lease_id AS TEXT) AS lease_id
         FROM kv_current WHERE key = ?1",
        vec![text(key)],
    )
    .pop()
}

fn get_lease(db: &Db, lease_id: u64) -> Option<LeaseRow> {
    if lease_id == 0 || lease_id > i64::MAX as u64 {
        return None;
    }
    db.rows::<LeaseRow>(
        "SELECT CAST(lease_id AS TEXT) AS lease_id, tenant, node_id,
                CAST(ttl_secs AS TEXT) AS ttl_secs,
                CAST(expires_at AS TEXT) AS expires_at
         FROM leases WHERE lease_id = ?1",
        vec![int(lease_id)],
    )
    .pop()
}

fn lease_attached_keys(db: &Db, lease_id: u64) -> Vec<String> {
    if lease_id == 0 || lease_id > i64::MAX as u64 {
        return Vec::new();
    }
    strings(
        db,
        "SELECT key AS v FROM kv_current WHERE lease_id = ?1 ORDER BY key ASC",
        vec![int(lease_id)],
    )
}

fn append_watch_event(
    db: &mut Db,
    meta: &mut SchemaMeta,
    tenant: &str,
    event_type: u8,
    revision: u64,
    kv: &KeyValue,
    prev: Option<&KeyValue>,
) {
    let seq = meta.next_event_seq;
    meta.next_event_seq = meta.next_event_seq.saturating_add(1);
    let (pp, pv, pcr, pmr, pver, pl) = match prev {
        Some(p) => (
            1u8,
            p.value_b64.as_str(),
            p.create_revision,
            p.mod_revision,
            p.version,
            p.lease_id,
        ),
        None => (0u8, "", 0, 0, 0, 0),
    };
    db.run(
        "INSERT INTO watch_events(
           seq, revision, tenant, key, event_type,
           value_b64, create_revision, mod_revision, version, lease_id,
           prev_present, prev_value_b64, prev_create_revision, prev_mod_revision, prev_version, prev_lease_id
         ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        vec![
            int(seq),
            int(revision),
            text(tenant),
            text(&kv.key),
            int(event_type),
            text(&kv.value_b64),
            int(kv.create_revision),
            int(kv.mod_revision),
            int(kv.version),
            int(kv.lease_id),
            int(pp),
            text(pv),
            int(pcr),
            int(pmr),
            int(pver),
            int(pl),
        ],
    );
}

fn delete_kv_row(db: &mut Db, meta: &mut SchemaMeta, row: &KvRow, rev: u64) {
    db.run(
        "DELETE FROM kv_current WHERE key = ?1",
        vec![text(&row.key)],
    );
    db.run(
        "UPDATE tenant_usage
         SET live_keys = MAX(0, live_keys - 1),
             live_bytes = MAX(0, live_bytes - ?1)
         WHERE tenant = ?2",
        vec![int(row.value_bytes), text(&row.tenant)],
    );
    db.run(
        "INSERT INTO kv_revisions(key, revision, tenant, tombstone, value_b64, create_revision, mod_revision, version, lease_id)
         VALUES(?1, ?2, ?3, 1, '', 0, ?2, 0, 0)",
        vec![text(&row.key), int(rev), text(&row.tenant)],
    );
    let tombstone_kv = KeyValue {
        key: row.key.clone(),
        value_b64: String::new(),
        create_revision: 0,
        mod_revision: rev,
        version: 0,
        lease_id: 0,
    };
    let prev_kv = row.clone().into_kv();
    append_watch_event(db, meta, &row.tenant, 2, rev, &tombstone_kv, Some(&prev_kv));
}

/// Lazily expire all leases with `expires_at <= now_secs`. Returns `true` if any keys were deleted.
fn expire_due_leases_tx(db: &mut Db, meta: &mut SchemaMeta, now_secs: u64) -> bool {
    let due = db.rows::<LeaseRow>(
        "SELECT CAST(l.lease_id AS TEXT) AS lease_id, l.tenant, l.node_id,
                CAST(l.ttl_secs AS TEXT) AS ttl_secs,
                CAST(l.expires_at AS TEXT) AS expires_at
         FROM leases l
         WHERE l.expires_at <= ?1
         ORDER BY l.lease_id ASC",
        vec![int(now_secs)],
    );
    let mut emitted_events = false;
    for lease in due {
        db.run(
            "DELETE FROM leases WHERE lease_id = ?1",
            vec![int(lease.lease_id)],
        );
        db.run(
            "UPDATE tenant_usage SET live_leases = MAX(0, live_leases - 1) WHERE tenant = ?1",
            vec![text(&lease.tenant)],
        );
        let attached = db.rows::<KvRow>(
            "SELECT key, tenant, value_b64,
                    CAST(value_bytes AS TEXT) AS value_bytes,
                    CAST(create_revision AS TEXT) AS create_revision,
                    CAST(mod_revision AS TEXT) AS mod_revision,
                    CAST(version AS TEXT) AS version,
                    CAST(lease_id AS TEXT) AS lease_id
             FROM kv_current
             WHERE lease_id = ?1
             ORDER BY key ASC",
            vec![int(lease.lease_id)],
        );
        if !attached.is_empty() {
            let rev = meta.current_revision.saturating_add(1);
            for row in &attached {
                delete_kv_row(db, meta, row, rev);
            }
            meta.current_revision = rev;
            emitted_events = true;
        }
    }
    if emitted_events {
        save_meta(db, meta);
    }
    emitted_events
}

#[allow(clippy::too_many_arguments)]
fn range_query(
    db: &Db,
    meta: &SchemaMeta,
    tenant: &str,
    resolved: &ResolvedRange,
    revision: u64,
    limit: Option<u32>,
    keys_only: bool,
    count_only: bool,
) -> CResult<(Vec<KeyValue>, bool, u64)> {
    let eff_limit = match limit {
        Some(0) | None => CLUSTER_RANGE_DEFAULT_LIMIT,
        Some(n) => n.min(CLUSTER_RANGE_MAX_LIMIT),
    };
    if revision == 0 || revision == meta.current_revision {
        let count = number(
            db,
            "SELECT CAST(COUNT(*) AS TEXT) AS n
             FROM kv_current
             WHERE tenant = ?1 AND key >= ?2 AND key < ?3",
            vec![text(tenant), text(&resolved.start), text(&resolved.end)],
        )
        .unwrap_or(0);
        if count_only {
            return Ok((Vec::new(), false, count));
        }
        let mut rows = db.rows::<KvRow>(
            "SELECT key, tenant, value_b64,
                    CAST(value_bytes AS TEXT) AS value_bytes,
                    CAST(create_revision AS TEXT) AS create_revision,
                    CAST(mod_revision AS TEXT) AS mod_revision,
                    CAST(version AS TEXT) AS version,
                    CAST(lease_id AS TEXT) AS lease_id
             FROM kv_current
             WHERE tenant = ?1 AND key >= ?2 AND key < ?3
             ORDER BY key ASC
             LIMIT ?4",
            vec![
                text(tenant),
                text(&resolved.start),
                text(&resolved.end),
                int(eff_limit + 1),
            ],
        );
        let more = rows.len() > eff_limit as usize;
        rows.truncate(eff_limit as usize);
        let kvs = rows
            .into_iter()
            .map(|r| {
                let mut kv = r.into_kv();
                if keys_only {
                    kv.value_b64.clear();
                }
                kv
            })
            .collect();
        Ok((kvs, more, count))
    } else {
        if revision > meta.current_revision {
            return Err(ClusterError::because(
                Errno::ERANGE,
                "requested revision is in the future",
            ));
        }
        if revision < meta.compacted_floor {
            return Err(ClusterError::compacted(meta.compacted_floor));
        }
        let count = number(
            db,
            "SELECT CAST(COUNT(*) AS TEXT) AS n
             FROM kv_revisions r
             WHERE r.tenant = ?1
               AND r.key >= ?2 AND r.key < ?3
               AND r.revision = (
                 SELECT MAX(r2.revision) FROM kv_revisions r2
                 WHERE r2.key = r.key AND r2.revision <= ?4
               )
               AND r.tombstone = 0",
            vec![
                text(tenant),
                text(&resolved.start),
                text(&resolved.end),
                int(revision),
            ],
        )
        .unwrap_or(0);
        if count_only {
            return Ok((Vec::new(), false, count));
        }
        let mut rows = db.rows::<HistKvRow>(
            "SELECT r.key, r.value_b64,
                    CAST(r.create_revision AS TEXT) AS create_revision,
                    CAST(r.mod_revision AS TEXT) AS mod_revision,
                    CAST(r.version AS TEXT) AS version,
                    CAST(r.lease_id AS TEXT) AS lease_id
             FROM kv_revisions r
             WHERE r.tenant = ?1
               AND r.key >= ?2 AND r.key < ?3
               AND r.revision = (
                 SELECT MAX(r2.revision) FROM kv_revisions r2
                 WHERE r2.key = r.key AND r2.revision <= ?4
               )
               AND r.tombstone = 0
             ORDER BY r.key ASC
             LIMIT ?5",
            vec![
                text(tenant),
                text(&resolved.start),
                text(&resolved.end),
                int(revision),
                int(eff_limit + 1),
            ],
        );
        let more = rows.len() > eff_limit as usize;
        rows.truncate(eff_limit as usize);
        let kvs = rows
            .into_iter()
            .map(|r| {
                let mut kv = r.into_kv();
                if keys_only {
                    kv.value_b64.clear();
                }
                kv
            })
            .collect();
        Ok((kvs, more, count))
    }
}

fn precheck_txn_writes_sql(db: &Db, grant: &ClusterGrant, ops: &[TxnOp]) -> CResult<bool> {
    let usage = get_usage(db, &grant.tenant);
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
                    let Some(lease) = get_lease(db, *lease_id) else {
                        return Err(ClusterError::because(Errno::ENOENT, "lease not found"));
                    };
                    let attached = if lease.tenant == grant.tenant
                        && !grant.scope.cluster_prefixes.is_empty()
                    {
                        lease_attached_keys(db, *lease_id)
                    } else {
                        Vec::new()
                    };
                    authorize_lease_access(
                        grant,
                        true,
                        false,
                        &lease.tenant,
                        lease.node_id.as_deref(),
                        &attached,
                    )?;
                }
                if let Some(existing) = get_kv(db, key) {
                    live_bytes -= existing.value_bytes as i128;
                    live_bytes += new_len;
                    if existing.lease_id != *lease_id {
                        if existing.lease_id != 0 {
                            *lease_deltas.entry(existing.lease_id).or_insert(0) -= 1;
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
                let victims = db.rows::<KvRow>(
                    "SELECT key, tenant, value_b64,
                            CAST(value_bytes AS TEXT) AS value_bytes,
                            CAST(create_revision AS TEXT) AS create_revision,
                            CAST(mod_revision AS TEXT) AS mod_revision,
                            CAST(version AS TEXT) AS version,
                            CAST(lease_id AS TEXT) AS lease_id
                     FROM kv_current
                     WHERE tenant = ?1 AND key >= ?2 AND key < ?3",
                    vec![
                        text(&grant.tenant),
                        text(&resolved.start),
                        text(&resolved.end),
                    ],
                );
                for v in victims {
                    if deleted_keys.insert(v.key.clone()) {
                        mutates = true;
                        live_keys -= 1;
                        live_bytes -= v.value_bytes as i128;
                        if v.lease_id != 0 {
                            *lease_deltas.entry(v.lease_id).or_insert(0) -= 1;
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
        if delta > 0 {
            let current_attached = number(
                db,
                "SELECT CAST(COUNT(*) AS TEXT) AS n FROM kv_current WHERE lease_id = ?1",
                vec![int(lid)],
            )
            .unwrap_or(0);
            if (current_attached as i64 + delta) > CLUSTER_MAX_KEYS_PER_LEASE as i64 {
                return Err(ClusterError::because(
                    Errno::EDQUOT,
                    "lease key attachment limit exceeded",
                ));
            }
        }
    }
    Ok(mutates)
}

fn dispatch_rpc_tx(
    db: &mut Db,
    grant: &ClusterGrant,
    call: ClusterCall,
    now_secs: u64,
) -> CResult<(ClusterReply, bool, bool)> {
    validate_grant(grant)?;
    let mut meta = read_meta(db)?;
    let expired_events = expire_due_leases_tx(db, &mut meta, now_secs);

    let (reply, mutated_or_compacted, touched_alarm) = match call {
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
            (
                ClusterReply::Welcome {
                    boundary: Boundary::ClusterState,
                    version,
                    cluster: meta.cluster.clone(),
                    tenant: grant.tenant.clone(),
                    revision: meta.current_revision,
                    compacted_floor: meta.compacted_floor,
                },
                false,
                false,
            )
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
            let (kvs, more, count) = range_query(
                db,
                &meta,
                &grant.tenant,
                &resolved,
                revision,
                limit,
                keys_only,
                count_only,
            )?;
            (
                ClusterReply::Range {
                    revision: meta.current_revision,
                    compacted_floor: meta.compacted_floor,
                    kvs,
                    more,
                    count,
                },
                false,
                false,
            )
        }
        ClusterCall::Txn {
            compare,
            success,
            failure,
        } => {
            authorize_txn(grant, &compare, &success, &failure)?;
            let mut succeeded = true;
            for cmp in &compare {
                let kv = get_kv(db, &cmp.key)
                    .filter(|row| row.tenant == grant.tenant)
                    .map(KvRow::into_kv);
                if !eval_compare(kv.as_ref(), cmp)? {
                    succeeded = false;
                    break;
                }
            }
            let chosen = if succeeded { success } else { failure };
            let mutates = precheck_txn_writes_sql(db, grant, &chosen)?;
            let write_rev = if mutates {
                meta.current_revision
                    .checked_add(1)
                    .filter(|r| *r <= i64::MAX as u64)
                    .ok_or_else(|| ClusterError::new(Errno::ENOSPC))?
            } else {
                meta.current_revision
            };
            let mut responses = Vec::with_capacity(chosen.len());
            if mutates {
                ensure_usage_row(db, &grant.tenant);
            }
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
                        let (kvs, more, count) = range_query(
                            db,
                            &meta,
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
                        let existing = get_kv(db, &key);
                        let (create_revision, version) = match &existing {
                            Some(old) => {
                                db.run(
                                    "UPDATE tenant_usage
                                     SET live_bytes = MAX(0, live_bytes - ?1) + ?2
                                     WHERE tenant = ?3",
                                    vec![int(old.value_bytes), int(new_bytes), text(&grant.tenant)],
                                );
                                (old.create_revision, old.version + 1)
                            }
                            None => {
                                db.run(
                                    "UPDATE tenant_usage
                                     SET live_keys = live_keys + 1,
                                         live_bytes = live_bytes + ?1
                                     WHERE tenant = ?2",
                                    vec![int(new_bytes), text(&grant.tenant)],
                                );
                                (write_rev, 1)
                            }
                        };
                        db.run(
                            "INSERT OR REPLACE INTO kv_current(
                               key, tenant, value_b64, value_bytes, create_revision, mod_revision, version, lease_id
                             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                            vec![
                                text(&key),
                                text(&grant.tenant),
                                text(&value_b64),
                                int(new_bytes),
                                int(create_revision),
                                int(write_rev),
                                int(version),
                                int(lease_id),
                            ],
                        );
                        db.run(
                            "INSERT INTO kv_revisions(
                               key, revision, tenant, tombstone, value_b64, create_revision, mod_revision, version, lease_id
                             ) VALUES(?1, ?2, ?3, 0, ?4, ?5, ?6, ?7, ?8)",
                            vec![
                                text(&key),
                                int(write_rev),
                                text(&grant.tenant),
                                text(&value_b64),
                                int(create_revision),
                                int(write_rev),
                                int(version),
                                int(lease_id),
                            ],
                        );
                        let prev_converted = existing.map(KvRow::into_kv);
                        let kv = KeyValue {
                            key,
                            value_b64,
                            create_revision,
                            mod_revision: write_rev,
                            version,
                            lease_id,
                        };
                        append_watch_event(
                            db,
                            &mut meta,
                            &grant.tenant,
                            1,
                            write_rev,
                            &kv,
                            prev_converted.as_ref(),
                        );
                        responses.push(TxnOpReply::Put {
                            prev_kv: if prev_kv { prev_converted } else { None },
                        });
                    }
                    TxnOp::DeleteRange {
                        key,
                        range_end,
                        prev_kv,
                    } => {
                        let resolved = resolve_range(&grant.tenant, &key, &range_end)?;
                        let victims = db.rows::<KvRow>(
                            "SELECT key, tenant, value_b64,
                                    CAST(value_bytes AS TEXT) AS value_bytes,
                                    CAST(create_revision AS TEXT) AS create_revision,
                                    CAST(mod_revision AS TEXT) AS mod_revision,
                                    CAST(version AS TEXT) AS version,
                                    CAST(lease_id AS TEXT) AS lease_id
                             FROM kv_current
                             WHERE tenant = ?1 AND key >= ?2 AND key < ?3
                             ORDER BY key ASC",
                            vec![
                                text(&grant.tenant),
                                text(&resolved.start),
                                text(&resolved.end),
                            ],
                        );
                        let mut prev_kvs = Vec::new();
                        let deleted = victims.len() as u64;
                        for row in victims {
                            delete_kv_row(db, &mut meta, &row, write_rev);
                            if prev_kv {
                                prev_kvs.push(row.into_kv());
                            }
                        }
                        responses.push(TxnOpReply::DeleteRange { deleted, prev_kvs });
                    }
                }
            }
            if mutates {
                meta.current_revision = write_rev;
                save_meta(db, &meta);
            }
            (
                ClusterReply::Txn {
                    revision: meta.current_revision,
                    compacted_floor: meta.compacted_floor,
                    succeeded,
                    responses,
                },
                mutates,
                false,
            )
        }
        ClusterCall::LeaseGrant { ttl_secs, node_id } => {
            let effective_node = authorize_lease_grant(grant, ttl_secs, node_id.as_deref())?;
            let usage = get_usage(db, &grant.tenant);
            if usage.live_leases >= CLUSTER_MAX_LEASES_PER_TENANT as u64 {
                return Err(ClusterError::because(
                    Errno::EDQUOT,
                    "tenant lease limit exceeded",
                ));
            }
            let lease_id = meta.next_lease_id;
            meta.next_lease_id = meta
                .next_lease_id
                .checked_add(1)
                .filter(|v| *v <= i64::MAX as u64)
                .ok_or_else(|| ClusterError::new(Errno::ENOSPC))?;
            let expires_at = now_secs.saturating_add(ttl_secs);
            ensure_usage_row(db, &grant.tenant);
            db.run(
                "INSERT INTO leases(lease_id, tenant, owner, node_id, ttl_secs, created_at, expires_at)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                vec![
                    int(lease_id),
                    text(&grant.tenant),
                    text(&grant.owner),
                    effective_node.as_deref().into(),
                    int(ttl_secs),
                    int(now_secs),
                    int(expires_at),
                ],
            );
            db.run(
                "UPDATE tenant_usage SET live_leases = live_leases + 1 WHERE tenant = ?1",
                vec![text(&grant.tenant)],
            );
            save_meta(db, &meta);
            (
                ClusterReply::LeaseGranted {
                    revision: meta.current_revision,
                    lease_id,
                    ttl_secs,
                    expires_at,
                },
                false,
                true,
            )
        }
        ClusterCall::LeaseKeepAlive { lease_id } => {
            authorize_lease_capability(grant, true)?;
            let Some(lease) = get_lease(db, lease_id) else {
                return Err(ClusterError::because(Errno::ENOENT, "lease not found"));
            };
            let attached =
                if lease.tenant == grant.tenant && !grant.scope.cluster_prefixes.is_empty() {
                    lease_attached_keys(db, lease_id)
                } else {
                    Vec::new()
                };
            authorize_lease_access(
                grant,
                true,
                false,
                &lease.tenant,
                lease.node_id.as_deref(),
                &attached,
            )?;
            let expires_at = now_secs.saturating_add(lease.ttl_secs);
            db.run(
                "UPDATE leases SET expires_at = ?1 WHERE lease_id = ?2",
                vec![int(expires_at), int(lease_id)],
            );
            (
                ClusterReply::LeaseKeptAlive {
                    revision: meta.current_revision,
                    lease_id,
                    ttl_secs: lease.ttl_secs,
                    expires_at,
                },
                false,
                true,
            )
        }
        ClusterCall::LeaseRevoke { lease_id } => {
            authorize_lease_capability(grant, true)?;
            let Some(lease) = get_lease(db, lease_id) else {
                return Err(ClusterError::because(Errno::ENOENT, "lease not found"));
            };
            let attached = if lease.tenant == grant.tenant {
                db.rows::<KvRow>(
                    "SELECT key, tenant, value_b64,
                            CAST(value_bytes AS TEXT) AS value_bytes,
                            CAST(create_revision AS TEXT) AS create_revision,
                            CAST(mod_revision AS TEXT) AS mod_revision,
                            CAST(version AS TEXT) AS version,
                            CAST(lease_id AS TEXT) AS lease_id
                     FROM kv_current
                     WHERE lease_id = ?1
                     ORDER BY key ASC",
                    vec![int(lease_id)],
                )
            } else {
                Vec::new()
            };
            let attached_keys: Vec<String> = attached.iter().map(|r| r.key.clone()).collect();
            authorize_lease_access(
                grant,
                true,
                true,
                &lease.tenant,
                lease.node_id.as_deref(),
                &attached_keys,
            )?;
            db.run(
                "DELETE FROM leases WHERE lease_id = ?1",
                vec![int(lease_id)],
            );
            db.run(
                "UPDATE tenant_usage SET live_leases = MAX(0, live_leases - 1) WHERE tenant = ?1",
                vec![text(&lease.tenant)],
            );
            let deleted = attached.len() as u64;
            if deleted > 0 {
                let rev = meta.current_revision.saturating_add(1);
                for row in &attached {
                    delete_kv_row(db, &mut meta, row, rev);
                }
                meta.current_revision = rev;
                save_meta(db, &meta);
            }
            (
                ClusterReply::LeaseRevoked {
                    revision: meta.current_revision,
                    lease_id,
                    deleted,
                },
                deleted > 0,
                true,
            )
        }
        ClusterCall::LeaseTimeToLive { lease_id, keys } => {
            authorize_lease_capability(grant, false)?;
            let Some(lease) = get_lease(db, lease_id) else {
                return Err(ClusterError::because(Errno::ENOENT, "lease not found"));
            };
            let attached = if lease.tenant == grant.tenant
                && (keys || !grant.scope.cluster_prefixes.is_empty())
            {
                lease_attached_keys(db, lease_id)
            } else {
                Vec::new()
            };
            authorize_lease_access(
                grant,
                false,
                false,
                &lease.tenant,
                lease.node_id.as_deref(),
                &attached,
            )?;
            let returned_keys = if keys { attached } else { Vec::new() };
            (
                ClusterReply::LeaseTtl {
                    revision: meta.current_revision,
                    lease_id,
                    granted_ttl_secs: lease.ttl_secs,
                    remaining_ttl_secs: lease.expires_at.saturating_sub(now_secs),
                    expires_at: lease.expires_at,
                    keys: returned_keys,
                },
                false,
                false,
            )
        }
        ClusterCall::Compact { revision } => {
            authorize_compact(grant)?;
            if revision == 0 || revision > meta.current_revision {
                return Err(ClusterError::because(
                    Errno::EINVAL,
                    "compact revision must be in 1..=current_revision",
                ));
            }
            if revision < meta.compacted_floor {
                return Err(ClusterError::compacted(meta.compacted_floor));
            }
            let advanced = revision > meta.compacted_floor;
            if advanced {
                meta.compacted_floor = revision;
                save_meta(db, &meta);
                // Two-step order-independent MVCC prune:
                // 1) Remove strictly older rows first (keeping MAX(revision <= rev) invariant).
                db.run(
                    "DELETE FROM kv_revisions
                     WHERE revision <= ?1
                       AND revision < (
                         SELECT MAX(r2.revision)
                         FROM kv_revisions r2
                         WHERE r2.key = kv_revisions.key AND r2.revision <= ?1
                       )",
                    vec![int(revision)],
                );
                // 2) Now remove any remaining tombstones <= rev without resurrecting older rows.
                db.run(
                    "DELETE FROM kv_revisions WHERE revision <= ?1 AND tombstone != 0",
                    vec![int(revision)],
                );
                // 3) Remove watch_events strictly older than compacted_floor.
                db.run(
                    "DELETE FROM watch_events WHERE revision < ?1",
                    vec![int(revision)],
                );
            }
            (
                ClusterReply::Compacted {
                    revision: meta.current_revision,
                    compacted_floor: meta.compacted_floor,
                },
                advanced,
                false,
            )
        }
    };

    Ok((
        reply,
        mutated_or_compacted || expired_events,
        touched_alarm || expired_events,
    ))
}

fn pull_subscription_tx(
    db: &mut Db,
    meta: &SchemaMeta,
    conn_id: &str,
    sub: &WatchSubRow,
    limit: u32,
) -> Option<WatchServerFrame> {
    if sub.next_revision < meta.compacted_floor {
        db.run(
            "DELETE FROM watch_subscriptions WHERE conn_id = ?1 AND watch_id = ?2",
            vec![text(conn_id), int(sub.watch_id)],
        );
        return Some(WatchServerFrame::Compacted {
            watch_id: sub.watch_id,
            floor: meta.compacted_floor,
            revision: meta.current_revision,
        });
    }
    let eff_limit = if limit == 0 {
        CLUSTER_WATCH_CATCHUP_BATCH
    } else {
        limit.min(CLUSTER_WATCH_CATCHUP_BATCH)
    };
    let mut rows = db.rows::<WatchEventRow>(
        "SELECT CAST(w.seq AS TEXT) AS seq,
                CAST(w.revision AS TEXT) AS revision,
                w.key, w.event_type, w.value_b64,
                CAST(w.create_revision AS TEXT) AS create_revision,
                CAST(w.mod_revision AS TEXT) AS mod_revision,
                CAST(w.version AS TEXT) AS version,
                CAST(w.lease_id AS TEXT) AS lease_id,
                w.prev_present, w.prev_value_b64,
                CAST(w.prev_create_revision AS TEXT) AS prev_create_revision,
                CAST(w.prev_mod_revision AS TEXT) AS prev_mod_revision,
                CAST(w.prev_version AS TEXT) AS prev_version,
                CAST(w.prev_lease_id AS TEXT) AS prev_lease_id
         FROM watch_events w
         WHERE w.tenant = ?1
           AND ((w.revision > ?2) OR (w.revision = ?2 AND w.seq > ?3))
           AND w.key >= ?4 AND w.key < ?5
         ORDER BY w.seq ASC
         LIMIT ?6",
        vec![
            text(&sub.tenant),
            int(sub.next_revision),
            int(sub.last_seq),
            text(&sub.start_key),
            text(&sub.end_key),
            int(eff_limit + 1),
        ],
    );
    let more = rows.len() > eff_limit as usize;
    rows.truncate(eff_limit as usize);

    let include_prev = sub.prev_kv != 0;
    let pairs: Vec<(u64, WatchEvent)> = rows
        .into_iter()
        .map(|r| r.into_event(include_prev))
        .collect();

    if let Some((last_seq, last_ev)) = pairs.last() {
        let next_rev = if more {
            last_ev.revision
        } else {
            meta.current_revision.saturating_add(1)
        };
        db.run(
            "UPDATE watch_subscriptions
             SET next_revision = ?1, last_seq = ?2
             WHERE conn_id = ?3 AND watch_id = ?4",
            vec![
                int(next_rev),
                int(*last_seq),
                text(conn_id),
                int(sub.watch_id),
            ],
        );
        let events = pairs.into_iter().map(|(_, ev)| ev).collect();
        Some(WatchServerFrame::Events {
            watch_id: sub.watch_id,
            revision: meta.current_revision,
            compacted_floor: meta.compacted_floor,
            events,
            more,
        })
    } else {
        if sub.next_revision <= meta.current_revision {
            db.run(
                "UPDATE watch_subscriptions
                 SET next_revision = ?1
                 WHERE conn_id = ?2 AND watch_id = ?3",
                vec![
                    int(meta.current_revision.saturating_add(1)),
                    text(conn_id),
                    int(sub.watch_id),
                ],
            );
        }
        None
    }
}

fn send_frame(ws: &WebSocket, frame: &WatchServerFrame) {
    if let Ok(json) = serde_json::to_string(frame) {
        let _ = ws.send_with_str(json);
    }
}

fn read_attachment(ws: &WebSocket) -> Option<WsAttachment> {
    ws.deserialize_attachment::<WsAttachment>().ok().flatten()
}

#[durable_object]
pub struct ClusterState {
    state: State,
    env: Env,
    ready: Cell<bool>,
    notify_gate: Mutex<()>,
}

impl DurableObject for ClusterState {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            ready: Cell::new(false),
            notify_gate: Mutex::new(()),
        }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let path = req.path();
        match (req.method(), path.as_str()) {
            (Method::Post, "/internal/rpc") => self.handle_rpc(&mut req).await,
            (Method::Post, "/internal/watch-ticket") => self.handle_issue_ticket(&mut req).await,
            (Method::Get, "/internal/watch") => self.handle_watch_upgrade(&req).await,
            _ => Response::error("Not found", 404),
        }
    }

    async fn websocket_message(
        &self,
        ws: WebSocket,
        message: WebSocketIncomingMessage,
    ) -> Result<()> {
        if let Err((err, _)) = self.ensure_ready(None) {
            send_frame(
                &ws,
                &WatchServerFrame::Error {
                    watch_id: None,
                    error: err,
                },
            );
            let _ = ws.close(Some(1011), Some("incompatible schema"));
            return Ok(());
        }
        let text = match message {
            WebSocketIncomingMessage::String(s) => s,
            WebSocketIncomingMessage::Binary(_) => {
                send_frame(
                    &ws,
                    &WatchServerFrame::Error {
                        watch_id: None,
                        error: ClusterError::because(Errno::EINVAL, "text JSON frames required"),
                    },
                );
                return Ok(());
            }
        };
        if text.len() > CLUSTER_WS_FRAME_MAX_BYTES {
            send_frame(
                &ws,
                &WatchServerFrame::Error {
                    watch_id: None,
                    error: ClusterError::because(
                        Errno::EMSGSIZE,
                        "WebSocket frame exceeds maximum size",
                    ),
                },
            );
            return Ok(());
        }
        let frame: WatchClientFrame = match serde_json::from_str(&text) {
            Ok(f) => f,
            Err(_) => {
                send_frame(
                    &ws,
                    &WatchServerFrame::Error {
                        watch_id: None,
                        error: ClusterError::because(Errno::EINVAL, "invalid watch frame"),
                    },
                );
                return Ok(());
            }
        };
        let Some(mut att) = read_attachment(&ws) else {
            let _ = ws.close(Some(1008), Some("missing session attachment"));
            return Ok(());
        };
        let expired_events = {
            let _guard = self.notify_gate.lock().await;
            self.handle_ws_frame(&ws, &mut att, frame).await
        };
        if expired_events {
            let _ = self.reschedule_alarm().await;
            self.notify_watchers().await;
        }
        Ok(())
    }

    async fn websocket_close(
        &self,
        ws: WebSocket,
        _code: usize,
        _reason: String,
        _was_clean: bool,
    ) -> Result<()> {
        self.cleanup_socket(&ws);
        let _ = ws.close(Some(1000), Some("closed"));
        Ok(())
    }

    async fn websocket_error(&self, ws: WebSocket, _error: Error) -> Result<()> {
        self.cleanup_socket(&ws);
        Ok(())
    }

    async fn alarm(&self) -> Result<Response> {
        if let Err((err, _)) = self.ensure_ready(None) {
            return Err(Error::RustError(err.to_string()));
        }
        let now = auth::now();
        let active_ids: BTreeSet<String> = self
            .state
            .get_websockets()
            .iter()
            .filter_map(read_attachment)
            .map(|a| a.conn_id)
            .collect();
        let _ = tx(&self.state, move |db| {
            let mut meta = read_meta(db)?;
            expire_due_leases_tx(db, &mut meta, now);
            db.run(
                "DELETE FROM watch_tickets WHERE expires_at <= ?1",
                vec![int(now)],
            );
            let stored_conns = strings(db, "SELECT conn_id AS v FROM watch_sessions", vec![]);
            for cid in stored_conns {
                if !active_ids.contains(&cid) {
                    db.run(
                        "DELETE FROM watch_subscriptions WHERE conn_id = ?1",
                        vec![text(&cid)],
                    );
                    db.run(
                        "DELETE FROM watch_sessions WHERE conn_id = ?1",
                        vec![text(&cid)],
                    );
                }
            }
            Ok(())
        });
        self.notify_watchers().await;
        let _ = self.reschedule_alarm().await;
        Response::ok("")
    }
}

impl ClusterState {
    fn verify_do_identity(&self, cluster: &str) -> CResult<()> {
        if !valid_cluster_name(cluster) {
            return Err(ClusterError::because(Errno::EINVAL, "invalid cluster name"));
        }
        let ns = self
            .env
            .durable_object("CLUSTER_STATE")
            .map_err(|_| ClusterError::new(Errno::EIO))?;
        let expected = ns
            .id_from_name(&format!("cluster:{cluster}"))
            .map_err(|_| ClusterError::new(Errno::EIO))?;
        if expected != self.state.id() {
            return Err(ClusterError::new(Errno::EACCES));
        }
        Ok(())
    }

    fn ensure_ready(
        &self,
        expected_cluster: Option<&str>,
    ) -> std::result::Result<(), (ClusterError, bool)> {
        if self.ready.get() {
            if let Some(expected) = expected_cluster {
                let stored =
                    tx(&self.state, |db| Ok(read_meta(db)?.cluster)).map_err(|e| (e, false))?;
                if stored != expected {
                    return Err((ClusterError::new(Errno::EACCES), false));
                }
            }
            return Ok(());
        }
        let expected_owned = expected_cluster.map(str::to_string);
        let init_res = db::transact(&self.state, move |db| {
            let tables = strings(
                db,
                "SELECT name AS v FROM sqlite_master
                 WHERE type = 'table'
                   AND name NOT GLOB '__miniflare_*'
                   AND name NOT GLOB '_cf_*'
                   AND name NOT GLOB 'sqlite_*'",
                vec![],
            );
            if tables.is_empty() {
                for stmt in SCHEMA_V1 {
                    db.run(stmt, vec![]);
                }
                let cname = expected_owned.as_deref().unwrap_or("default");
                db.run(
                    "INSERT INTO schema_meta(
                       singleton, version, cluster, current_revision, compacted_floor, next_lease_id, next_event_seq
                     ) VALUES(1, ?1, ?2, 0, 0, 1, 1)",
                    vec![int(CLUSTER_SCHEMA_VERSION), text(cname)],
                );
                return (Ok(()), true);
            }
            let has_meta = tables.iter().any(|t| t == "schema_meta");
            let has_ver_col = has_meta
                && number(
                    db,
                    "SELECT CAST(1 AS TEXT) AS n FROM pragma_table_info('schema_meta') WHERE name = 'version'",
                    vec![],
                )
                .is_some();
            let stored_ver = if has_ver_col {
                number(
                    db,
                    "SELECT CAST(version AS TEXT) AS n FROM schema_meta WHERE singleton = 1",
                    vec![],
                )
            } else {
                None
            };
            if stored_ver != Some(u64::from(CLUSTER_SCHEMA_VERSION)) {
                return (
                    Err((
                        ClusterError::because(
                            Errno::EPROTONOSUPPORT,
                            format!(
                                "incompatible ClusterState schema version (expected {CLUSTER_SCHEMA_VERSION})"
                            ),
                        ),
                        true,
                    )),
                    false,
                );
            }
            if let Some(expected) = expected_owned.as_deref() {
                let stored = db
                    .rows::<StrRow>(
                        "SELECT cluster AS v FROM schema_meta WHERE singleton = 1",
                        vec![],
                    )
                    .pop()
                    .map(|r| r.v);
                if stored.as_deref() != Some(expected) {
                    return (Err((ClusterError::new(Errno::EACCES), false)), false);
                }
            }
            (Ok(()), false)
        })
        .map_err(|_| (ClusterError::because(Errno::EIO, "storage init failed"), false))?;
        init_res?;
        self.ready.set(true);
        Ok(())
    }

    async fn reschedule_alarm(&self) -> Result<()> {
        let next_due = tx(&self.state, |db| {
            let lease_due = opt_number(
                db,
                "SELECT CAST(MIN(expires_at) AS TEXT) AS n FROM leases",
                vec![],
            );
            let ticket_due = opt_number(
                db,
                "SELECT CAST(MIN(expires_at) AS TEXT) AS n FROM watch_tickets",
                vec![],
            );
            Ok(match (lease_due, ticket_due) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            })
        });
        if let Ok(Some(due_secs)) = next_due {
            let delay_ms = due_secs
                .saturating_sub(auth::now())
                .saturating_mul(1000)
                .max(1000)
                .min(i64::MAX as u64) as i64;
            self.state.storage().set_alarm(delay_ms).await?;
        }
        Ok(())
    }

    async fn handle_rpc(&self, req: &mut Request) -> Result<Response> {
        let cmd: ClusterDoRpc = match serde_json::from_str(&req.text().await?) {
            Ok(c) => c,
            Err(_) => {
                return cluster_gateway::error_response(&ClusterError::new(Errno::EINVAL), false);
            }
        };
        if let Err(err) = self.verify_do_identity(&cmd.cluster) {
            return cluster_gateway::error_response(&err, false);
        }
        if let Err((err, schema_mismatch)) = self.ensure_ready(Some(&cmd.cluster)) {
            return cluster_gateway::error_response(&err, schema_mismatch);
        }
        let now = auth::now();
        let grant = cmd.grant;
        let call = cmd.call;
        let result = tx(&self.state, move |db| {
            dispatch_rpc_tx(db, &grant, call, now)
        });
        match result {
            Ok((reply, notify, touch_alarm)) => {
                if touch_alarm {
                    let _ = self.reschedule_alarm().await;
                }
                if notify {
                    self.notify_watchers().await;
                }
                Response::from_json(&reply)
            }
            Err(err) => cluster_gateway::error_response(&err, false),
        }
    }

    async fn handle_issue_ticket(&self, req: &mut Request) -> Result<Response> {
        let cmd: ClusterIssueTicket = match serde_json::from_str(&req.text().await?) {
            Ok(c) => c,
            Err(_) => {
                return cluster_gateway::error_response(&ClusterError::new(Errno::EINVAL), false);
            }
        };
        if let Err(err) = self.verify_do_identity(&cmd.cluster) {
            return cluster_gateway::error_response(&err, false);
        }
        if let Err((err, schema_mismatch)) = self.ensure_ready(Some(&cmd.cluster)) {
            return cluster_gateway::error_response(&err, schema_mismatch);
        }
        if let Err(err) = validate_grant(&cmd.cred.grant) {
            return cluster_gateway::error_response(&err, false);
        }
        if !cmd.cred.grant.scope.cluster_watch {
            return cluster_gateway::error_response(
                &ClusterError::because(Errno::EACCES, "cluster_watch capability required"),
                false,
            );
        }
        let now = auth::now();
        let raw_ticket = auth::random_token();
        let ticket_hash = auth::token_hash(&raw_ticket);
        let expires_at = now.saturating_add(CLUSTER_WATCH_TICKET_TTL_SECS);
        let cred: VerifiedClusterCred = cmd.cred;
        let tenant = cred.grant.tenant.clone();
        let scope_json = serde_json::to_string(&cred.grant.scope)
            .map_err(|_| Error::RustError("encode scope".into()))?;
        let inserted = tx(&self.state, move |db| {
            db.run(
                "DELETE FROM watch_tickets WHERE expires_at <= ?1",
                vec![int(now)],
            );
            let tenant_active = number(
                db,
                "SELECT CAST(COUNT(*) AS TEXT) AS n FROM watch_tickets WHERE tenant = ?1",
                vec![text(&cred.grant.tenant)],
            )
            .unwrap_or(0);
            if tenant_active >= CLUSTER_WATCH_MAX_SOCKETS as u64 {
                return Err(ClusterError::because(
                    Errno::EAGAIN,
                    "too many pending watch tickets for tenant",
                ));
            }
            let total_active = number(
                db,
                "SELECT CAST(COUNT(*) AS TEXT) AS n FROM watch_tickets",
                vec![],
            )
            .unwrap_or(0);
            if total_active >= (CLUSTER_WATCH_MAX_SOCKETS as u64) * 4 {
                return Err(ClusterError::because(
                    Errno::EAGAIN,
                    "too many pending watch tickets",
                ));
            }
            db.run(
                "INSERT INTO watch_tickets(
                   ticket_hash, tenant, owner, ns, cred_hash, instance_id, admin, scope_json, expires_at
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                vec![
                    text(&ticket_hash),
                    text(&cred.grant.tenant),
                    text(&cred.grant.owner),
                    text(&cred.ns),
                    text(&cred.cred_hash),
                    text(&cred.instance_id),
                    int(u8::from(cred.grant.admin)),
                    text(&scope_json),
                    int(expires_at),
                ],
            );
            Ok(())
        });
        if let Err(err) = inserted {
            return cluster_gateway::error_response(&err, false);
        }
        let _ = self.reschedule_alarm().await;
        Response::from_json(&WatchTicketReply {
            ticket: raw_ticket,
            expires_at,
            cluster: cmd.cluster,
            tenant,
        })
    }

    async fn handle_watch_upgrade(&self, req: &Request) -> Result<Response> {
        if !req
            .headers()
            .get("Upgrade")?
            .is_some_and(|u| u.eq_ignore_ascii_case("websocket"))
        {
            return Response::error("Expected a WebSocket", 426);
        }
        let url = req.url()?;
        let cluster = url
            .query_pairs()
            .find(|(k, _)| k == "cluster")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_else(|| "default".into());
        let raw_ticket = url
            .query_pairs()
            .find(|(k, _)| k == "ticket")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default();
        if let Err(err) = self.verify_do_identity(&cluster) {
            return cluster_gateway::error_response(&err, false);
        }
        if let Err((err, schema_mismatch)) = self.ensure_ready(Some(&cluster)) {
            return cluster_gateway::error_response(&err, schema_mismatch);
        }
        if raw_ticket.is_empty() {
            return cluster_gateway::error_response(
                &ClusterError::because(Errno::EACCES, "missing watch ticket"),
                false,
            );
        }
        if self.state.get_websockets().len() >= CLUSTER_WATCH_MAX_SOCKETS {
            return cluster_gateway::error_response(
                &ClusterError::because(Errno::EAGAIN, "too many active watch sockets"),
                false,
            );
        }

        // Atomically consume single-use ticket.
        let ticket_hash = auth::token_hash(&raw_ticket);
        let now = auth::now();
        let consumed = tx(&self.state, move |db| {
            let row = db
                .rows::<TicketRow>(
                    "DELETE FROM watch_tickets
                     WHERE ticket_hash = ?1
                     RETURNING tenant, owner, ns, cred_hash, instance_id, admin, scope_json,
                               CAST(expires_at AS TEXT) AS expires_at",
                    vec![text(&ticket_hash)],
                )
                .pop();
            Ok(row)
        });
        let ticket = match consumed {
            Ok(Some(t)) if t.expires_at > now => t,
            Ok(_) => {
                return cluster_gateway::error_response(
                    &ClusterError::because(Errno::EACCES, "invalid or expired watch ticket"),
                    false,
                );
            }
            Err(err) => return cluster_gateway::error_response(&err, false),
        };

        // Live-revalidate the credential BEFORE accepting the WebSocket so a ticket minted
        // prior to revocation / account lock / instance expiry fails closed immediately.
        let conn_id = auth::random_token();
        let check = SessionCheck {
            conn_id: conn_id.clone(),
            tenant: ticket.tenant.clone(),
            ns: ticket.ns.clone(),
            cred_hash: ticket.cred_hash.clone(),
            instance_id: ticket.instance_id.clone(),
        };
        match cluster_gateway::revalidate_sessions(&self.env, &[check]).await {
            Ok(revoked) if !revoked.contains(&conn_id) => {}
            _ => {
                return cluster_gateway::error_response(
                    &ClusterError::because(Errno::EACCES, "watch credential revoked or expired"),
                    false,
                );
            }
        }

        // Re-check active socket cap synchronously AFTER awaiting revalidation with zero awaits
        // between this check, inserting watch_sessions, and accepting the WebSocket.
        if self.state.get_websockets().len() >= CLUSTER_WATCH_MAX_SOCKETS {
            return cluster_gateway::error_response(
                &ClusterError::because(Errno::EAGAIN, "too many active watch sockets"),
                false,
            );
        }

        let pair = WebSocketPair::new()?;
        let cid_store = conn_id.clone();
        let tenant_store = ticket.tenant.clone();
        let inserted = tx(&self.state, move |db| {
            db.run(
                "INSERT INTO watch_sessions(
                   conn_id, tenant, owner, ns, cred_hash, instance_id, admin, scope_json, created_at, last_seen
                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9)",
                vec![
                    text(&cid_store),
                    text(&ticket.tenant),
                    text(&ticket.owner),
                    text(&ticket.ns),
                    text(&ticket.cred_hash),
                    text(&ticket.instance_id),
                    int(ticket.admin),
                    text(&ticket.scope_json),
                    int(now),
                ],
            );
            Ok(())
        });
        if let Err(err) = inserted {
            return cluster_gateway::error_response(&err, false);
        }

        self.state.accept_web_socket(&pair.server);
        if let Err(err) = pair.server.serialize_attachment(WsAttachment {
            conn_id: conn_id.clone(),
            proto: 0,
            tenant: tenant_store,
        }) {
            self.delete_session_rows(&conn_id);
            let _ = pair.server.close(Some(1011), Some("attachment error"));
            return Err(err);
        }
        Response::from_websocket(pair.client)
    }

    async fn load_and_verify_session(
        &self,
        ws: &WebSocket,
        conn_id: &str,
    ) -> Option<WatchSessionRow> {
        let cid = conn_id.to_string();
        let session = match tx(&self.state, move |db| {
            Ok(db
                .rows::<WatchSessionRow>(
                    "SELECT conn_id, tenant, owner, ns, cred_hash, instance_id, admin, scope_json
                     FROM watch_sessions WHERE conn_id = ?1",
                    vec![text(&cid)],
                )
                .pop())
        }) {
            Ok(Some(row)) => row,
            Ok(None) => {
                send_frame(
                    ws,
                    &WatchServerFrame::Error {
                        watch_id: None,
                        error: ClusterError::because(Errno::EACCES, "watch session expired"),
                    },
                );
                let _ = ws.close(Some(1008), Some("session gone"));
                return None;
            }
            Err(_) => {
                send_frame(
                    ws,
                    &WatchServerFrame::Error {
                        watch_id: None,
                        error: ClusterError::because(Errno::EIO, "storage transaction failed"),
                    },
                );
                let _ = ws.close(Some(1011), Some("storage error"));
                return None;
            }
        };
        let check = session.to_check();
        match cluster_gateway::revalidate_sessions(&self.env, &[check]).await {
            Ok(revoked) if !revoked.contains(conn_id) => Some(session),
            _ => {
                send_frame(
                    ws,
                    &WatchServerFrame::Error {
                        watch_id: None,
                        error: ClusterError::because(
                            Errno::EACCES,
                            "credential revoked or expired",
                        ),
                    },
                );
                self.delete_session_rows(conn_id);
                let _ = ws.close(Some(1008), Some("credential revoked"));
                None
            }
        }
    }

    fn delete_session_rows(&self, conn_id: &str) {
        let cid = conn_id.to_string();
        let _ = tx(&self.state, move |db| {
            db.run(
                "DELETE FROM watch_subscriptions WHERE conn_id = ?1",
                vec![text(&cid)],
            );
            db.run(
                "DELETE FROM watch_sessions WHERE conn_id = ?1",
                vec![text(&cid)],
            );
            Ok(())
        });
    }

    fn cleanup_socket(&self, ws: &WebSocket) {
        if self.ensure_ready(None).is_ok()
            && let Some(att) = read_attachment(ws)
        {
            self.delete_session_rows(&att.conn_id);
        }
    }

    async fn handle_ws_frame(
        &self,
        ws: &WebSocket,
        att: &mut WsAttachment,
        frame: WatchClientFrame,
    ) -> bool {
        let Some(session) = self.load_and_verify_session(ws, &att.conn_id).await else {
            return false;
        };
        let now = auth::now();
        match frame {
            WatchClientFrame::Hello { versions } => {
                let ours = Hello {
                    boundary: Boundary::ClusterState,
                    versions: vec![CLUSTER_STATE_PROTOCOL],
                };
                let theirs = Hello {
                    boundary: Boundary::ClusterState,
                    versions,
                };
                let Some(version) = negotiate(&ours, &theirs) else {
                    send_frame(
                        ws,
                        &WatchServerFrame::Error {
                            watch_id: None,
                            error: ClusterError::because(
                                Errno::EPROTONOSUPPORT,
                                format!("ClusterState protocol v{CLUSTER_STATE_PROTOCOL} required"),
                            ),
                        },
                    );
                    self.delete_session_rows(&att.conn_id);
                    let _ = ws.close(Some(1002), Some("unsupported version"));
                    return false;
                };
                att.proto = version;
                let _ = ws.serialize_attachment(&*att);
                let cid = att.conn_id.clone();
                if let Ok((meta, expired)) = tx(&self.state, move |db| {
                    let mut meta = read_meta(db)?;
                    let expired = expire_due_leases_tx(db, &mut meta, now);
                    db.run(
                        "UPDATE watch_sessions SET last_seen = ?1 WHERE conn_id = ?2",
                        vec![int(now), text(&cid)],
                    );
                    Ok((meta, expired))
                }) {
                    send_frame(
                        ws,
                        &WatchServerFrame::Welcome {
                            boundary: Boundary::ClusterState,
                            version,
                            cluster: meta.cluster,
                            tenant: session.tenant,
                            revision: meta.current_revision,
                            compacted_floor: meta.compacted_floor,
                        },
                    );
                    return expired;
                }
                false
            }
            WatchClientFrame::Ping { seq } => {
                let cid = att.conn_id.clone();
                if let Ok(rev) = tx(&self.state, move |db| {
                    db.run(
                        "UPDATE watch_sessions SET last_seen = ?1 WHERE conn_id = ?2",
                        vec![int(now), text(&cid)],
                    );
                    Ok(read_meta(db)?.current_revision)
                }) {
                    send_frame(ws, &WatchServerFrame::Pong { seq, revision: rev });
                }
                false
            }
            other => {
                if att.proto != CLUSTER_STATE_PROTOCOL {
                    send_frame(
                        ws,
                        &WatchServerFrame::Error {
                            watch_id: None,
                            error: ClusterError::because(
                                Errno::EPROTONOSUPPORT,
                                "must negotiate Hello v1 before subscribing",
                            ),
                        },
                    );
                    return false;
                }
                match other {
                    WatchClientFrame::Subscribe {
                        watch_id,
                        key,
                        range_end,
                        from_revision,
                        prev_kv,
                    } => {
                        if watch_id == 0 || watch_id > i64::MAX as u64 {
                            send_frame(
                                ws,
                                &WatchServerFrame::Error {
                                    watch_id: Some(watch_id),
                                    error: ClusterError::because(
                                        Errno::EINVAL,
                                        "watch_id must be in 1..=i64::MAX",
                                    ),
                                },
                            );
                            return false;
                        }
                        if from_revision > i64::MAX as u64 {
                            send_frame(
                                ws,
                                &WatchServerFrame::Error {
                                    watch_id: Some(watch_id),
                                    error: ClusterError::because(
                                        Errno::EINVAL,
                                        "from_revision exceeds maximum supported revision",
                                    ),
                                },
                            );
                            return false;
                        }
                        let grant = match session.to_grant() {
                            Ok(g) => g,
                            Err(err) => {
                                send_frame(
                                    ws,
                                    &WatchServerFrame::Error {
                                        watch_id: Some(watch_id),
                                        error: err,
                                    },
                                );
                                return false;
                            }
                        };
                        let resolved = match authorize_watch(&grant, &key, &range_end) {
                            Ok(r) => r,
                            Err(err) => {
                                send_frame(
                                    ws,
                                    &WatchServerFrame::Error {
                                        watch_id: Some(watch_id),
                                        error: err,
                                    },
                                );
                                return false;
                            }
                        };
                        let range_end_json = serde_json::to_string(&range_end).unwrap_or_default();
                        let cid = att.conn_id.clone();
                        let tenant = grant.tenant.clone();
                        let frames_res = tx(&self.state, move |db| {
                            let mut meta = read_meta(db)?;
                            let expired = expire_due_leases_tx(db, &mut meta, now);
                            db.run(
                                "UPDATE watch_sessions SET last_seen = ?1 WHERE conn_id = ?2",
                                vec![int(now), text(&cid)],
                            );
                            let existing = number(
                                db,
                                "SELECT CAST(COUNT(*) AS TEXT) AS n FROM watch_subscriptions WHERE conn_id = ?1 AND watch_id = ?2",
                                vec![text(&cid), int(watch_id)],
                            )
                            .unwrap_or(0);
                            if existing > 0 {
                                return Err(ClusterError::because(
                                    Errno::EEXIST,
                                    "watch_id already active on this socket",
                                ));
                            }
                            let total = number(
                                db,
                                "SELECT CAST(COUNT(*) AS TEXT) AS n FROM watch_subscriptions WHERE conn_id = ?1",
                                vec![text(&cid)],
                            )
                            .unwrap_or(0);
                            if total >= CLUSTER_WATCH_MAX_PER_SOCKET as u64 {
                                return Err(ClusterError::because(
                                    Errno::ENOSPC,
                                    "maximum watches per socket exceeded",
                                ));
                            }
                            if from_revision > 0 && from_revision < meta.compacted_floor {
                                return Ok((
                                    vec![WatchServerFrame::Compacted {
                                        watch_id,
                                        floor: meta.compacted_floor,
                                        revision: meta.current_revision,
                                    }],
                                    expired,
                                ));
                            }
                            let start_rev = if from_revision == 0 {
                                meta.current_revision.saturating_add(1)
                            } else {
                                from_revision
                            };
                            db.run(
                                "INSERT INTO watch_subscriptions(
                                   conn_id, watch_id, tenant, key, range_end_json, start_key, end_key, next_revision, last_seq, prev_kv
                                 ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9)",
                                vec![
                                    text(&cid),
                                    int(watch_id),
                                    text(&tenant),
                                    text(&key),
                                    text(&range_end_json),
                                    text(&resolved.start),
                                    text(&resolved.end),
                                    int(start_rev),
                                    int(u8::from(prev_kv)),
                                ],
                            );
                            let mut out = vec![WatchServerFrame::Subscribed {
                                watch_id,
                                revision: meta.current_revision,
                                compacted_floor: meta.compacted_floor,
                                start_revision: start_rev,
                            }];
                            if start_rev <= meta.current_revision {
                                let sub = WatchSubRow {
                                    watch_id,
                                    tenant,
                                    start_key: resolved.start,
                                    end_key: resolved.end,
                                    next_revision: start_rev,
                                    last_seq: 0,
                                    prev_kv: u8::from(prev_kv),
                                };
                                if let Some(batch) = pull_subscription_tx(
                                    db,
                                    &meta,
                                    &cid,
                                    &sub,
                                    CLUSTER_WATCH_CATCHUP_BATCH,
                                ) {
                                    out.push(batch);
                                }
                            }
                            Ok((out, expired))
                        });
                        match frames_res {
                            Ok((frames, expired)) => {
                                for f in frames {
                                    send_frame(ws, &f);
                                }
                                expired
                            }
                            Err(err) => {
                                send_frame(
                                    ws,
                                    &WatchServerFrame::Error {
                                        watch_id: Some(watch_id),
                                        error: err,
                                    },
                                );
                                false
                            }
                        }
                    }
                    WatchClientFrame::Pull { watch_id, limit } => {
                        if watch_id == 0 || watch_id > i64::MAX as u64 {
                            send_frame(
                                ws,
                                &WatchServerFrame::Error {
                                    watch_id: Some(watch_id),
                                    error: ClusterError::because(
                                        Errno::EINVAL,
                                        "watch_id must be in 1..=i64::MAX",
                                    ),
                                },
                            );
                            return false;
                        }
                        let cid = att.conn_id.clone();
                        let res = tx(&self.state, move |db| {
                            let mut meta = read_meta(db)?;
                            let expired = expire_due_leases_tx(db, &mut meta, now);
                            db.run(
                                "UPDATE watch_sessions SET last_seen = ?1 WHERE conn_id = ?2",
                                vec![int(now), text(&cid)],
                            );
                            let Some(sub) = db
                                .rows::<WatchSubRow>(
                                    "SELECT CAST(watch_id AS TEXT) AS watch_id, tenant, start_key, end_key,
                                            CAST(next_revision AS TEXT) AS next_revision,
                                            CAST(last_seq AS TEXT) AS last_seq, prev_kv
                                     FROM watch_subscriptions
                                     WHERE conn_id = ?1 AND watch_id = ?2",
                                    vec![text(&cid), int(watch_id)],
                                )
                                .pop()
                            else {
                                return Err(ClusterError::because(
                                    Errno::ENOENT,
                                    "watch subscription not found",
                                ));
                            };
                            let eff = limit
                                .unwrap_or(CLUSTER_WATCH_CATCHUP_BATCH)
                                .clamp(1, CLUSTER_WATCH_CATCHUP_BATCH);
                            let frame = pull_subscription_tx(db, &meta, &cid, &sub, eff).unwrap_or(
                                WatchServerFrame::Events {
                                    watch_id,
                                    revision: meta.current_revision,
                                    compacted_floor: meta.compacted_floor,
                                    events: Vec::new(),
                                    more: false,
                                },
                            );
                            Ok((frame, expired))
                        });
                        match res {
                            Ok((frame, expired)) => {
                                send_frame(ws, &frame);
                                expired
                            }
                            Err(err) => {
                                send_frame(
                                    ws,
                                    &WatchServerFrame::Error {
                                        watch_id: Some(watch_id),
                                        error: err,
                                    },
                                );
                                false
                            }
                        }
                    }
                    WatchClientFrame::Cancel { watch_id } => {
                        if watch_id == 0 || watch_id > i64::MAX as u64 {
                            send_frame(
                                ws,
                                &WatchServerFrame::Error {
                                    watch_id: Some(watch_id),
                                    error: ClusterError::because(
                                        Errno::EINVAL,
                                        "watch_id must be in 1..=i64::MAX",
                                    ),
                                },
                            );
                            return false;
                        }
                        let cid = att.conn_id.clone();
                        let _ = tx(&self.state, move |db| {
                            db.run(
                                "DELETE FROM watch_subscriptions WHERE conn_id = ?1 AND watch_id = ?2",
                                vec![text(&cid), int(watch_id)],
                            );
                            Ok(())
                        });
                        send_frame(
                            ws,
                            &WatchServerFrame::Canceled {
                                watch_id,
                                reason: Some("client canceled".into()),
                            },
                        );
                        false
                    }
                    WatchClientFrame::Hello { .. } | WatchClientFrame::Ping { .. } => false,
                }
            }
        }
    }

    /// Serialized fan-out delivering newly committed watch events (or compaction notices) to all
    /// live WebSockets AFTER batch live-revalidation against `OsAuthority` and `Machine`.
    async fn notify_watchers(&self) {
        let _guard = self.notify_gate.lock().await;
        let sockets = self.state.get_websockets();
        if sockets.is_empty() {
            return;
        }
        let mut by_conn: Vec<(WebSocket, WsAttachment)> = Vec::with_capacity(sockets.len());
        let mut conn_ids: Vec<String> = Vec::with_capacity(sockets.len());
        for ws in sockets {
            if let Some(att) = read_attachment(&ws) {
                conn_ids.push(att.conn_id.clone());
                by_conn.push((ws, att));
            }
        }
        if by_conn.is_empty() {
            return;
        }
        let sessions = match tx(&self.state, move |db| {
            let mut out = BTreeMap::new();
            for cid in conn_ids {
                if let Some(row) = db
                    .rows::<WatchSessionRow>(
                        "SELECT conn_id, tenant, owner, ns, cred_hash, instance_id, admin, scope_json
                         FROM watch_sessions WHERE conn_id = ?1",
                        vec![text(&cid)],
                    )
                    .pop()
                {
                    out.insert(cid, row);
                }
            }
            Ok(out)
        }) {
            Ok(s) => s,
            Err(_) => return,
        };

        let checks: Vec<SessionCheck> = sessions.values().map(WatchSessionRow::to_check).collect();
        let Ok(revoked) = cluster_gateway::revalidate_sessions(&self.env, &checks).await else {
            // Fail closed if authority/machine verification fails transiently; never leak events.
            return;
        };

        let mut to_delete: Vec<String> = Vec::new();
        let mut live_conns: Vec<String> = Vec::new();
        for (ws, att) in &by_conn {
            let missing_row = !sessions.contains_key(&att.conn_id);
            if missing_row || revoked.contains(&att.conn_id) {
                send_frame(
                    ws,
                    &WatchServerFrame::Error {
                        watch_id: None,
                        error: ClusterError::because(
                            Errno::EACCES,
                            "credential revoked or expired",
                        ),
                    },
                );
                let _ = ws.close(Some(1008), Some("credential revoked"));
                to_delete.push(att.conn_id.clone());
            } else if att.proto == CLUSTER_STATE_PROTOCOL {
                live_conns.push(att.conn_id.clone());
            }
        }

        let delivered = tx(&self.state, move |db| {
            for cid in &to_delete {
                db.run(
                    "DELETE FROM watch_subscriptions WHERE conn_id = ?1",
                    vec![text(cid)],
                );
                db.run(
                    "DELETE FROM watch_sessions WHERE conn_id = ?1",
                    vec![text(cid)],
                );
            }
            let meta = read_meta(db)?;
            let mut per_conn: BTreeMap<String, Vec<WatchServerFrame>> = BTreeMap::new();
            for cid in live_conns {
                let subs = db.rows::<WatchSubRow>(
                    "SELECT CAST(s.watch_id AS TEXT) AS watch_id, s.tenant, s.start_key, s.end_key,
                            CAST(s.next_revision AS TEXT) AS next_revision,
                            CAST(s.last_seq AS TEXT) AS last_seq, s.prev_kv
                     FROM watch_subscriptions s
                     WHERE s.conn_id = ?1
                     ORDER BY s.watch_id ASC",
                    vec![text(&cid)],
                );
                let mut frames = Vec::new();
                for sub in subs {
                    if let Some(frame) =
                        pull_subscription_tx(db, &meta, &cid, &sub, CLUSTER_WATCH_CATCHUP_BATCH)
                    {
                        frames.push(frame);
                    }
                }
                if !frames.is_empty() {
                    per_conn.insert(cid, frames);
                }
            }
            Ok(per_conn)
        });
        if let Ok(per_conn) = delivered {
            for (ws, att) in &by_conn {
                if let Some(frames) = per_conn.get(&att.conn_id) {
                    for frame in frames {
                        send_frame(ws, frame);
                    }
                }
            }
        }
    }
}
