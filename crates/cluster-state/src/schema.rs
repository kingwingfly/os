//! SQLite Schema v1 DDL for the `ClusterState` Durable Object (`Contract v2` §2.12, §2.16).
//!
//! Opening storage with an incompatible `schema_meta.version` fails closed with
//! `EPROTONOSUPPORT` without silently migrating or wiping cluster state.

pub const CLUSTER_SCHEMA_VERSION: u32 = 1;

pub const SCHEMA_V1: &[&str] = &[
    "CREATE TABLE schema_meta(\
       singleton INTEGER PRIMARY KEY CHECK(singleton = 1),\
       version INTEGER NOT NULL,\
       cluster TEXT NOT NULL,\
       current_revision INTEGER NOT NULL DEFAULT 0,\
       compacted_floor INTEGER NOT NULL DEFAULT 0,\
       next_lease_id INTEGER NOT NULL DEFAULT 1,\
       next_event_seq INTEGER NOT NULL DEFAULT 1\
     )",
    "CREATE TABLE kv_current(\
       key TEXT PRIMARY KEY,\
       tenant TEXT NOT NULL,\
       value_b64 TEXT NOT NULL,\
       value_bytes INTEGER NOT NULL,\
       create_revision INTEGER NOT NULL,\
       mod_revision INTEGER NOT NULL,\
       version INTEGER NOT NULL,\
       lease_id INTEGER NOT NULL DEFAULT 0\
     )",
    "CREATE INDEX kv_current_tenant_key ON kv_current(tenant, key)",
    "CREATE INDEX kv_current_lease ON kv_current(lease_id) WHERE lease_id != 0",
    "CREATE TABLE kv_revisions(\
       key TEXT NOT NULL,\
       revision INTEGER NOT NULL,\
       tenant TEXT NOT NULL,\
       tombstone INTEGER NOT NULL,\
       value_b64 TEXT NOT NULL,\
       create_revision INTEGER NOT NULL,\
       mod_revision INTEGER NOT NULL,\
       version INTEGER NOT NULL,\
       lease_id INTEGER NOT NULL DEFAULT 0,\
       PRIMARY KEY(key, revision)\
     )",
    "CREATE INDEX kv_revisions_rev ON kv_revisions(revision)",
    "CREATE INDEX kv_revisions_tenant_key_rev ON kv_revisions(tenant, key, revision)",
    "CREATE TABLE watch_events(\
       seq INTEGER PRIMARY KEY,\
       revision INTEGER NOT NULL,\
       tenant TEXT NOT NULL,\
       key TEXT NOT NULL,\
       event_type INTEGER NOT NULL,\
       value_b64 TEXT NOT NULL,\
       create_revision INTEGER NOT NULL,\
       mod_revision INTEGER NOT NULL,\
       version INTEGER NOT NULL,\
       lease_id INTEGER NOT NULL DEFAULT 0,\
       prev_present INTEGER NOT NULL DEFAULT 0,\
       prev_value_b64 TEXT NOT NULL DEFAULT '',\
       prev_create_revision INTEGER NOT NULL DEFAULT 0,\
       prev_mod_revision INTEGER NOT NULL DEFAULT 0,\
       prev_version INTEGER NOT NULL DEFAULT 0,\
       prev_lease_id INTEGER NOT NULL DEFAULT 0\
     )",
    "CREATE INDEX watch_events_rev ON watch_events(tenant, revision, seq)",
    "CREATE INDEX watch_events_compact ON watch_events(revision)",
    "CREATE TABLE leases(\
       lease_id INTEGER PRIMARY KEY,\
       tenant TEXT NOT NULL,\
       owner TEXT NOT NULL,\
       node_id TEXT,\
       ttl_secs INTEGER NOT NULL,\
       created_at INTEGER NOT NULL,\
       expires_at INTEGER NOT NULL\
     )",
    "CREATE INDEX leases_tenant ON leases(tenant)",
    "CREATE INDEX leases_expiry ON leases(expires_at)",
    "CREATE TABLE tenant_usage(\
       tenant TEXT PRIMARY KEY,\
       live_keys INTEGER NOT NULL DEFAULT 0,\
       live_bytes INTEGER NOT NULL DEFAULT 0,\
       live_leases INTEGER NOT NULL DEFAULT 0\
     )",
    "CREATE TABLE watch_sessions(\
       conn_id TEXT PRIMARY KEY,\
       tenant TEXT NOT NULL,\
       owner TEXT NOT NULL,\
       ns TEXT NOT NULL,\
       cred_hash TEXT NOT NULL,\
       instance_id TEXT NOT NULL,\
       admin INTEGER NOT NULL,\
       scope_json TEXT NOT NULL,\
       created_at INTEGER NOT NULL,\
       last_seen INTEGER NOT NULL\
     )",
    "CREATE INDEX watch_sessions_tenant ON watch_sessions(tenant)",
    "CREATE TABLE watch_subscriptions(\
       conn_id TEXT NOT NULL,\
       watch_id INTEGER NOT NULL,\
       tenant TEXT NOT NULL,\
       key TEXT NOT NULL,\
       range_end_json TEXT NOT NULL,\
       start_key TEXT NOT NULL,\
       end_key TEXT NOT NULL,\
       next_revision INTEGER NOT NULL,\
       last_seq INTEGER NOT NULL DEFAULT 0,\
       prev_kv INTEGER NOT NULL DEFAULT 0,\
       PRIMARY KEY(conn_id, watch_id)\
     )",
    "CREATE INDEX watch_subs_tenant ON watch_subscriptions(tenant, next_revision)",
    "CREATE TABLE watch_tickets(\
       ticket_hash TEXT PRIMARY KEY,\
       tenant TEXT NOT NULL,\
       owner TEXT NOT NULL,\
       ns TEXT NOT NULL,\
       cred_hash TEXT NOT NULL,\
       instance_id TEXT NOT NULL,\
       admin INTEGER NOT NULL,\
       scope_json TEXT NOT NULL,\
       expires_at INTEGER NOT NULL\
     )",
    "CREATE INDEX watch_tickets_expiry ON watch_tickets(expires_at)",
];
