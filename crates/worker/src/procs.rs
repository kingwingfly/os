//! Narrowed `Machine` Durable Object SQLite store (`MACHINE_SCHEMA_VERSION = 2`).
//!
//! Holds ONLY:
//! - `instances`: active remote-attached instance leases and host-proof fences (one live host per `instance_id`)
//! - `service_tokens`: active remote service credentials bound to `(ns, instance_id)`
//! - `pending_revocations`: durable revocation queue flushed to `OsAuthority` `/internal/revoke`
//! - `io_quotas`: server-side per-credential remote `io.max` accounting & pacing state
//!
//! Retired process, PID-lending, signal, seat, terminal, init-owner, login-session, and
//! process-memory tables have been removed cleanly (Contract §2.12 — no legacy `ALTER TABLE`
//! migrations).
use crate::auth;
use crate::db::{Db, int, text};
use abi::auth_v2::{INSTANCE_LEASE_SECONDS, RemoteScope};
use abi::{Errno, Error};
use serde::Deserialize;
use worker::{SqlStorage, SqlStorageValue};

/// Independent schema version for `Machine` DO (decoupled from `OsAuthority` `SCHEMA_VERSION = "10"`).
pub const MACHINE_SCHEMA_VERSION: u32 = 2;

impl crate::db::Db {
    /// Process/credential namespace for a browser session or guest cookie.
    pub fn namespace(key: Option<&str>, guest: Option<&str>) -> String {
        guest
            .map(str::to_string)
            .or_else(|| key.map(|key| format!("session.{key}")))
            .unwrap_or_else(|| "anonymous".into())
    }
}

/// Maximum attached instances per namespace.
pub const INSTANCES_MAX: usize = 64;

/// Maximum active remote service tokens per namespace.
pub const SERVICE_TOKENS_MAX: usize = 512;

/// Clean-break initialization of `Machine` DO SQLite schema (`MACHINE_SCHEMA_VERSION = 2`).
pub fn create(sql: &SqlStorage) -> worker::Result<()> {
    sql.exec(
        "CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL)",
        None,
    )?;
    #[derive(Deserialize)]
    struct Ver {
        v: String,
    }
    let current = sql
        .exec("SELECT v FROM meta WHERE k = 'machine_schema'", None)?
        .to_array::<Ver>()?
        .into_iter()
        .next()
        .map(|row| row.v);
    let expected = MACHINE_SCHEMA_VERSION.to_string();
    if current.as_deref() != Some(expected.as_str()) {
        // Clean break: drop all retired v1 tables (and any previous v2 tables) with zero legacy migrations.
        for table in [
            "processes",
            "spare",
            "pending_signals",
            "terminals",
            "account_boots",
            "init_owner",
            "login_sessions",
            "login_profiles",
            "seat_policies",
            "process_resources",
            "cgroup_lifetimes",
            "cgroups",
            "cgroup_io",
            "revocations",
            "instances",
            "service_tokens",
            "pending_revocations",
            "io_quotas",
        ] {
            sql.exec(&format!("DROP TABLE IF EXISTS {table}"), None)?;
        }
        sql.exec(
            "CREATE TABLE instances(instance_id TEXT PRIMARY KEY, ns TEXT NOT NULL, host TEXT NOT NULL, host_proof_hash TEXT NOT NULL, host_epoch INTEGER NOT NULL, expires INTEGER NOT NULL, updated INTEGER NOT NULL)",
            None,
        )?;
        sql.exec("CREATE INDEX instances_ns ON instances(ns, expires)", None)?;
        sql.exec(
            "CREATE TABLE service_tokens(token_hash TEXT PRIMARY KEY, ns TEXT NOT NULL, instance_id TEXT NOT NULL, uid INTEGER NOT NULL, gid INTEGER NOT NULL, lineage TEXT NOT NULL, cgroup TEXT NOT NULL, scope TEXT NOT NULL, cloud_access INTEGER NOT NULL, expires INTEGER NOT NULL)",
            None,
        )?;
        sql.exec(
            "CREATE INDEX service_tokens_instance ON service_tokens(ns, instance_id)",
            None,
        )?;
        sql.exec(
            "CREATE TABLE pending_revocations(token_hash TEXT PRIMARY KEY, ns TEXT NOT NULL, created INTEGER NOT NULL)",
            None,
        )?;
        sql.exec(
            "CREATE TABLE io_quotas(token_hash TEXT PRIMARY KEY, ns TEXT NOT NULL, instance_id TEXT NOT NULL, cgroup TEXT NOT NULL, rbps INTEGER, wbps INTEGER, read_end INTEGER NOT NULL DEFAULT 0, write_end INTEGER NOT NULL DEFAULT 0, read_bytes INTEGER NOT NULL DEFAULT 0, write_bytes INTEGER NOT NULL DEFAULT 0)",
            None,
        )?;
        sql.exec(
            "CREATE INDEX io_quotas_instance ON io_quotas(ns, instance_id)",
            None,
        )?;
        sql.exec(
            "INSERT OR REPLACE INTO meta(k, v) VALUES('machine_schema', ?)",
            Some(vec![text(&expected)]),
        )?;
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize)]
#[allow(dead_code)]
pub struct InstanceRow {
    pub instance_id: String,
    pub ns: String,
    pub host: String,
    pub host_proof_hash: String,
    pub host_epoch: u64,
    pub expires: u64,
    pub updated: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[allow(dead_code)]
pub struct ServiceTokenRow {
    pub token_hash: String,
    pub ns: String,
    pub instance_id: String,
    pub uid: u32,
    pub gid: u32,
    pub lineage: String,
    pub cgroup: String,
    pub scope: String,
    pub cloud_access: u8,
    pub expires: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PendingRevocation {
    pub token_hash: String,
    pub ns: String,
}

#[derive(Clone, Debug, Deserialize)]
#[allow(dead_code)]
pub struct IoQuotaRow {
    pub token_hash: String,
    pub ns: String,
    pub instance_id: String,
    pub cgroup: String,
    pub rbps: Option<u64>,
    pub wbps: Option<u64>,
    pub read_end: u64,
    pub write_end: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
}

#[derive(Deserialize)]
struct CountRow {
    n: usize,
}

#[derive(Deserialize)]
struct MinRow {
    min_exp: Option<u64>,
}

impl Db {
    /// Attach or renew an instance lease with strict single-host `host_proof` fencing.
    /// Presenting a mismatched or stale `host_proof` for a live `instance_id` fails closed
    /// with `ESTALE` (same namespace) or `EACCES` (cross-namespace).
    pub fn attach_instance(
        &mut self,
        ns: &str,
        instance_id: &str,
        host: &str,
        host_proof: &str,
        now: u64,
    ) -> Result<InstanceRow, Error> {
        let proof_hash = auth::token_hash(host_proof);
        let expires = now.saturating_add(INSTANCE_LEASE_SECONDS);
        if let Some(existing) = self
            .rows::<InstanceRow>(
                "SELECT * FROM instances WHERE instance_id = ?",
                vec![text(instance_id)],
            )
            .pop()
        {
            if existing.expires > now {
                if existing.ns != ns {
                    return Err(Error::because(
                        Errno::EACCES,
                        "instance_id is bound to another session",
                    ));
                }
                if existing.host_proof_hash != proof_hash {
                    return Err(Error::because(
                        Errno::ESTALE,
                        "instance_id is fenced to another live host",
                    ));
                }
                self.run(
                    "UPDATE instances SET host = ?, expires = ?, updated = ? WHERE instance_id = ?",
                    vec![text(host), int(expires), int(now), text(instance_id)],
                );
                return Ok(InstanceRow {
                    host: host.to_string(),
                    expires,
                    updated: now,
                    ..existing
                });
            }
            // Expired previous host: queue all of its tokens for revocation before taking over.
            self.queue_instance_revocations(&existing.ns, instance_id, now);
            let next_epoch = existing.host_epoch.saturating_add(1);
            self.run(
                "UPDATE instances SET ns = ?, host = ?, host_proof_hash = ?, host_epoch = ?, expires = ?, updated = ? WHERE instance_id = ?",
                vec![
                    text(ns),
                    text(host),
                    text(&proof_hash),
                    int(next_epoch),
                    int(expires),
                    int(now),
                    text(instance_id),
                ],
            );
            return Ok(InstanceRow {
                instance_id: instance_id.to_string(),
                ns: ns.to_string(),
                host: host.to_string(),
                host_proof_hash: proof_hash,
                host_epoch: next_epoch,
                expires,
                updated: now,
            });
        }

        let count = self
            .rows::<CountRow>(
                "SELECT COUNT(*) AS n FROM instances WHERE ns = ? AND expires > ?",
                vec![text(ns), int(now)],
            )
            .pop()
            .map_or(0, |r| r.n);
        if count >= INSTANCES_MAX {
            return Err(Errno::ENOSPC.into());
        }
        self.run(
            "INSERT INTO instances(instance_id, ns, host, host_proof_hash, host_epoch, expires, updated) VALUES(?, ?, ?, ?, 1, ?, ?)",
            vec![
                text(instance_id),
                text(ns),
                text(host),
                text(&proof_hash),
                int(expires),
                int(now),
            ],
        );
        Ok(InstanceRow {
            instance_id: instance_id.to_string(),
            ns: ns.to_string(),
            host: host.to_string(),
            host_proof_hash: proof_hash,
            host_epoch: 1,
            expires,
            updated: now,
        })
    }

    /// Verify that `(ns, instance_id, host_proof)` names a currently live, fenced host.
    pub fn verify_instance(
        &self,
        ns: &str,
        instance_id: &str,
        host_proof: &str,
        now: u64,
    ) -> Result<InstanceRow, Error> {
        let row = self
            .rows::<InstanceRow>(
                "SELECT * FROM instances WHERE instance_id = ?",
                vec![text(instance_id)],
            )
            .pop()
            .ok_or_else(|| Error::because(Errno::EACCES, "unknown or detached instance"))?;
        if row.ns != ns {
            return Err(Error::because(
                Errno::EACCES,
                "instance_id does not belong to this session",
            ));
        }
        if row.expires <= now {
            return Err(Error::because(Errno::ESTALE, "instance lease expired"));
        }
        if row.host_proof_hash != auth::token_hash(host_proof) {
            return Err(Error::because(
                Errno::EACCES,
                "forged or stale host_proof for instance",
            ));
        }
        Ok(row)
    }

    /// Record a freshly minted or derived remote service credential bound to `(ns, instance_id)`.
    #[allow(clippy::too_many_arguments)]
    pub fn record_service_token(
        &mut self,
        ns: &str,
        instance_id: &str,
        raw_token: &str,
        uid: u32,
        gid: u32,
        lineage: &str,
        cgroup: &str,
        scope: &RemoteScope,
        cloud_access: bool,
        expires: u64,
        now: u64,
    ) -> Result<String, Error> {
        let count = self
            .rows::<CountRow>(
                "SELECT COUNT(*) AS n FROM service_tokens WHERE ns = ? AND expires > ?",
                vec![text(ns), int(now)],
            )
            .pop()
            .map_or(0, |r| r.n);
        if count >= SERVICE_TOKENS_MAX {
            return Err(Errno::ENOSPC.into());
        }
        let hash = auth::token_hash(raw_token);
        let scope_json = serde_json::to_string(scope).map_err(|_| Errno::EIO)?;
        self.run(
            "INSERT OR REPLACE INTO service_tokens(token_hash, ns, instance_id, uid, gid, lineage, cgroup, scope, cloud_access, expires) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            vec![
                text(&hash),
                text(ns),
                text(instance_id),
                int(uid),
                int(gid),
                text(lineage),
                text(cgroup),
                text(&scope_json),
                int(u8::from(cloud_access)),
                int(expires),
            ],
        );
        Ok(hash)
    }

    pub fn service_token_for_instance(
        &self,
        ns: &str,
        instance_id: &str,
        raw_token: &str,
        now: u64,
    ) -> Option<ServiceTokenRow> {
        let hash = auth::token_hash(raw_token);
        self.rows::<ServiceTokenRow>(
            "SELECT * FROM service_tokens WHERE token_hash = ? AND ns = ? AND instance_id = ? AND expires > ?",
            vec![text(&hash), text(ns), text(instance_id), int(now)],
        )
        .pop()
    }

    pub fn service_token_by_raw(
        &self,
        ns: &str,
        raw_token: &str,
        now: u64,
    ) -> Option<ServiceTokenRow> {
        let hash = auth::token_hash(raw_token);
        self.rows::<ServiceTokenRow>(
            "SELECT * FROM service_tokens WHERE token_hash = ? AND ns = ? AND expires > ?",
            vec![text(&hash), text(ns), int(now)],
        )
        .pop()
    }

    /// Renew an instance lease and return the token hashes owned by `(ns, instance_id)` that
    /// match `active_tokens` (so only tokens belonging to this instance are renewed at `OsAuthority`).
    pub fn renew_instance_tokens(
        &mut self,
        ns: &str,
        instance_id: &str,
        host_proof: &str,
        active_tokens: &[String],
        now: u64,
    ) -> Result<Vec<(String, String)>, Error> {
        self.verify_instance(ns, instance_id, host_proof, now)?;
        let inst_expires = now.saturating_add(INSTANCE_LEASE_SECONDS);
        let tok_expires = now.saturating_add(abi::PROCESS_TOKEN_TTL);
        self.run(
            "UPDATE instances SET expires = ?, updated = ? WHERE instance_id = ? AND ns = ?",
            vec![int(inst_expires), int(now), text(instance_id), text(ns)],
        );
        let mut owned = Vec::new();
        for raw in active_tokens {
            let hash = auth::token_hash(raw);
            let exists = !self
                .rows::<ServiceTokenRow>(
                    "SELECT * FROM service_tokens WHERE token_hash = ? AND ns = ? AND instance_id = ?",
                    vec![text(&hash), text(ns), text(instance_id)],
                )
                .is_empty();
            if exists {
                self.run(
                    "UPDATE service_tokens SET expires = ? WHERE token_hash = ?",
                    vec![int(tok_expires), text(&hash)],
                );
                owned.push((raw.clone(), hash));
            }
        }
        Ok(owned)
    }

    pub fn drop_service_token_hash(&mut self, ns: &str, token_hash: &str) {
        self.run(
            "DELETE FROM service_tokens WHERE token_hash = ? AND ns = ?",
            vec![text(token_hash), text(ns)],
        );
        self.run(
            "DELETE FROM io_quotas WHERE token_hash = ? AND ns = ?",
            vec![text(token_hash), text(ns)],
        );
    }

    /// Queue explicit token revocations owned by `(ns, instance_id)` into `pending_revocations`.
    pub fn queue_token_revocations(
        &mut self,
        ns: &str,
        instance_id: &str,
        raw_tokens: &[String],
        now: u64,
    ) -> usize {
        let mut count = 0usize;
        for raw in raw_tokens {
            let hash = auth::token_hash(raw);
            let deleted = self.rows::<ServiceTokenRow>(
                "DELETE FROM service_tokens WHERE token_hash = ? AND ns = ? AND instance_id = ? RETURNING *",
                vec![text(&hash), text(ns), text(instance_id)],
            );
            if !deleted.is_empty() {
                count += 1;
                self.run(
                    "DELETE FROM io_quotas WHERE token_hash = ? AND ns = ?",
                    vec![text(&hash), text(ns)],
                );
                self.run(
                    "INSERT OR IGNORE INTO pending_revocations(token_hash, ns, created) VALUES(?, ?, ?)",
                    vec![text(&hash), text(ns), int(now)],
                );
            }
        }
        count
    }

    /// Queue revocation of EVERY token belonging to `(ns, instance_id)` (used on detach & host-loss expiry).
    pub fn queue_instance_revocations(&mut self, ns: &str, instance_id: &str, now: u64) -> usize {
        let rows = self.rows::<ServiceTokenRow>(
            "DELETE FROM service_tokens WHERE ns = ? AND instance_id = ? RETURNING *",
            vec![text(ns), text(instance_id)],
        );
        let count = rows.len();
        for row in rows {
            self.run(
                "INSERT OR IGNORE INTO pending_revocations(token_hash, ns, created) VALUES(?, ?, ?)",
                vec![text(&row.token_hash), text(&row.ns), int(now)],
            );
        }
        self.run(
            "DELETE FROM io_quotas WHERE ns = ? AND instance_id = ?",
            vec![text(ns), text(instance_id)],
        );
        count
    }

    pub fn detach_instance(
        &mut self,
        ns: &str,
        instance_id: &str,
        host_proof: &str,
        now: u64,
    ) -> Result<usize, Error> {
        self.verify_instance(ns, instance_id, host_proof, now)?;
        let revoked = self.queue_instance_revocations(ns, instance_id, now);
        self.run(
            "DELETE FROM instances WHERE instance_id = ? AND ns = ?",
            vec![text(instance_id), text(ns)],
        );
        Ok(revoked)
    }

    /// Expire lost hosts & stale tokens, queueing their tokens into `pending_revocations`.
    pub fn expire_machine_leases(&mut self, now: u64) -> usize {
        let expired_instances = self.rows::<InstanceRow>(
            "DELETE FROM instances WHERE expires <= ? RETURNING *",
            vec![int(now)],
        );
        let mut count = 0usize;
        for inst in expired_instances {
            count += self.queue_instance_revocations(&inst.ns, &inst.instance_id, now);
        }
        let expired_tokens = self.rows::<ServiceTokenRow>(
            "DELETE FROM service_tokens WHERE expires <= ? RETURNING *",
            vec![int(now)],
        );
        for tok in expired_tokens {
            count += 1;
            self.run(
                "DELETE FROM io_quotas WHERE token_hash = ? AND ns = ?",
                vec![text(&tok.token_hash), text(&tok.ns)],
            );
            self.run(
                "INSERT OR IGNORE INTO pending_revocations(token_hash, ns, created) VALUES(?, ?, ?)",
                vec![text(&tok.token_hash), text(&tok.ns), int(now)],
            );
        }
        count
    }

    /// Configure or clear server-side remote `io.max` policy for a live token owned by `(ns, instance_id)`.
    #[allow(clippy::too_many_arguments)]
    pub fn set_remote_io_quota(
        &mut self,
        ns: &str,
        instance_id: &str,
        host_proof: &str,
        raw_token: &str,
        cgroup: &str,
        rbps: Option<u64>,
        wbps: Option<u64>,
        now: u64,
    ) -> Result<(), Error> {
        self.verify_instance(ns, instance_id, host_proof, now)?;
        let tok = self
            .service_token_for_instance(ns, instance_id, raw_token, now)
            .ok_or_else(|| Error::because(Errno::EACCES, "unknown service token for instance"))?;
        let rbps_val = rbps.map_or(SqlStorageValue::Null, int);
        let wbps_val = wbps.map_or(SqlStorageValue::Null, int);
        self.run(
            "INSERT INTO io_quotas(token_hash, ns, instance_id, cgroup, rbps, wbps) VALUES(?, ?, ?, ?, ?, ?) \
             ON CONFLICT(token_hash) DO UPDATE SET cgroup = excluded.cgroup, rbps = excluded.rbps, wbps = excluded.wbps",
            vec![
                text(&tok.token_hash),
                text(ns),
                text(instance_id),
                text(cgroup),
                rbps_val,
                wbps_val,
            ],
        );
        Ok(())
    }

    /// Atomically inherit any existing `io_quotas` policy and pacing debt (`rbps`, `wbps`,
    /// `read_end`, `write_end`, `read_bytes`, `write_bytes`) from `parent_hash` onto a derived
    /// token so `reexec` / `DeriveServiceCred` can never escape server-side `io.max` or reset debt.
    pub fn inherit_remote_io_quota(
        &mut self,
        ns: &str,
        instance_id: &str,
        parent_hash: &str,
        new_raw: &str,
        cgroup: &str,
    ) {
        let new_hash = auth::token_hash(new_raw);
        self.run(
            "INSERT INTO io_quotas(token_hash, ns, instance_id, cgroup, rbps, wbps, read_end, write_end, read_bytes, write_bytes) \
             SELECT ?, ns, ?, ?, rbps, wbps, read_end, write_end, read_bytes, write_bytes \
             FROM io_quotas WHERE token_hash = ? AND ns = ? \
             ON CONFLICT(token_hash) DO UPDATE SET \
               cgroup = excluded.cgroup, rbps = excluded.rbps, wbps = excluded.wbps, \
               read_end = excluded.read_end, write_end = excluded.write_end, \
               read_bytes = excluded.read_bytes, write_bytes = excluded.write_bytes",
            vec![
                text(&new_hash),
                text(instance_id),
                text(cgroup),
                text(parent_hash),
                text(ns),
            ],
        );
    }

    /// Enforce server-side remote `io.max` pacing/rate limits per credential regardless of client claims.
    pub fn charge_remote_io(
        &mut self,
        ns: &str,
        raw_token: &str,
        write: bool,
        bytes: u64,
        now_secs: u64,
        now_ms: u64,
    ) -> Result<u64, Error> {
        let tok = self
            .service_token_by_raw(ns, raw_token, now_secs)
            .ok_or_else(|| {
                Error::because(Errno::EPERM, "service token not registered or expired")
            })?;
        // Verify owning instance is still attached & live (host-loss enforcement!).
        let live_inst = !self
            .rows::<InstanceRow>(
                "SELECT * FROM instances WHERE instance_id = ? AND ns = ? AND expires > ?",
                vec![text(&tok.instance_id), text(ns), int(now_secs)],
            )
            .is_empty();
        if !live_inst {
            return Err(Error::because(
                Errno::EACCES,
                "owning instance lease has expired",
            ));
        }
        let Some(quota) = self
            .rows::<IoQuotaRow>(
                "SELECT * FROM io_quotas WHERE token_hash = ? AND ns = ?",
                vec![text(&tok.token_hash), text(ns)],
            )
            .pop()
        else {
            return Ok(0);
        };
        let rate = if write { quota.wbps } else { quota.rbps };
        let prev = if write {
            quota.write_end
        } else {
            quota.read_end
        };
        let end = kernel::resource::io_deadline(now_ms, prev, rate, bytes)?;
        let (col_end, col_bytes) = if write {
            ("write_end", "write_bytes")
        } else {
            ("read_end", "read_bytes")
        };
        self.run(
            &format!(
                "UPDATE io_quotas SET {col_end} = ?, {col_bytes} = {col_bytes} + ? WHERE token_hash = ? AND ns = ?"
            ),
            vec![int(end), int(bytes), text(&tok.token_hash), text(ns)],
        );
        Ok(end.saturating_sub(now_ms))
    }

    pub fn pending_revocations(&self) -> Vec<PendingRevocation> {
        self.rows(
            "SELECT token_hash, ns FROM pending_revocations ORDER BY created LIMIT 256",
            vec![],
        )
    }

    pub fn clear_revocations(&mut self, ns: &str, hashes: &[String]) {
        for hash in hashes {
            self.run(
                "DELETE FROM pending_revocations WHERE token_hash = ? AND ns = ?",
                vec![text(hash), text(ns)],
            );
        }
    }

    pub fn next_machine_expiry(&self) -> Option<u64> {
        let a = self
            .rows::<MinRow>("SELECT MIN(expires) AS min_exp FROM instances", vec![])
            .pop()
            .and_then(|r| r.min_exp);
        let b = self
            .rows::<MinRow>("SELECT MIN(expires) AS min_exp FROM service_tokens", vec![])
            .pop()
            .and_then(|r| r.min_exp);
        match (a, b) {
            (Some(x), Some(y)) => Some(x.min(y)),
            (x, y) => x.or(y),
        }
    }
}
