//! One SQLite metadata authority per authenticated tenant. Only the pack gateway speaks the
//! internal staging protocol. All head, graph, quota and deletion decisions are synchronous.
use crate::{
    auth,
    db::{self, Db, int, text},
};
use abi::{
    Errno,
    auth_v2::{RemoteScope, valid_id},
    fs::Timespec,
    remote_volume::{self as w, Operation as Op, Response as Reply},
    volume::CowfsGcResp,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use cowtree::{
    BlockLoc, Digest, Node, PackId, PackIndexEntry, PackMeta, RootObject, SnapshotRecord,
    VolumeHead, VolumeId, WriterMode, digest_from_hex, digest_to_hex as hex, sha256,
};
use futures_util::lock::Mutex;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    cell::{Cell, RefCell},
    collections::{HashMap, HashSet},
    rc::Rc,
};
use worker::*;

pub(crate) type VResult<T> = std::result::Result<T, Errno>;
const STORAGE_SCHEMA_VERSION: u32 = 1;
const SCHEMA: &[&str] = &[
    "CREATE TABLE schema_meta(version INTEGER NOT NULL,tenant TEXT NOT NULL,store_incarnation INTEGER NOT NULL,checkpoint_seq INTEGER NOT NULL,checkpoint_nonce TEXT NOT NULL,publication_seq INTEGER NOT NULL,prev_checkpoint TEXT,pending_publish INTEGER NOT NULL DEFAULT 0,verify_restore INTEGER NOT NULL DEFAULT 0,inventory_cursor TEXT)",
    "CREATE TABLE volumes(volume TEXT PRIMARY KEY, format_version INTEGER NOT NULL, incarnation INTEGER NOT NULL, fence INTEGER NOT NULL, epoch INTEGER NOT NULL, root TEXT NOT NULL, parent_volume TEXT, ephemeral INTEGER NOT NULL, modified INTEGER NOT NULL, updated_at INTEGER NOT NULL)",
    "CREATE TABLE writer_leases(volume TEXT PRIMARY KEY,incarnation INTEGER NOT NULL,fence INTEGER NOT NULL,owner TEXT NOT NULL,expires INTEGER NOT NULL)",
    "CREATE TABLE ro_pins(pin_id TEXT PRIMARY KEY,volume TEXT NOT NULL,owner TEXT NOT NULL,root TEXT NOT NULL,expires INTEGER NOT NULL)",
    "CREATE INDEX ro_pins_root ON ro_pins(volume,root,expires)",
    "CREATE TABLE grace_pins(volume TEXT NOT NULL,root TEXT NOT NULL,expires INTEGER NOT NULL,PRIMARY KEY(volume,root))",
    "CREATE TABLE snapshots(volume TEXT NOT NULL,name TEXT NOT NULL,root TEXT NOT NULL,epoch INTEGER NOT NULL,created_at INTEGER NOT NULL,PRIMARY KEY(volume,name))",
    "CREATE INDEX snapshots_root ON snapshots(volume,root)",
    "CREATE TABLE receipts(volume TEXT NOT NULL,op_id TEXT NOT NULL,payload_hash TEXT NOT NULL,status TEXT NOT NULL,PRIMARY KEY(volume,op_id))",
    "CREATE TABLE nodes(digest TEXT PRIMARY KEY,kind INTEGER NOT NULL,data_b64 TEXT NOT NULL,created_at INTEGER NOT NULL)",
    "CREATE TABLE node_edges(parent TEXT NOT NULL,child TEXT NOT NULL,PRIMARY KEY(parent,child))",
    "CREATE TABLE node_blocks(parent TEXT NOT NULL,digest TEXT NOT NULL,PRIMARY KEY(parent,digest))",
    "CREATE TABLE packs(pack_id TEXT PRIMARY KEY,size INTEGER NOT NULL,entry_count INTEGER NOT NULL,status TEXT NOT NULL,created_at INTEGER NOT NULL,retain_until INTEGER NOT NULL DEFAULT 0)",
    "CREATE TABLE pack_entries(pack_id TEXT NOT NULL,offset INTEGER NOT NULL,end_offset INTEGER NOT NULL,digest TEXT NOT NULL,PRIMARY KEY(pack_id,offset))",
    "CREATE TABLE blocks(digest TEXT PRIMARY KEY,pack_id TEXT NOT NULL,loc TEXT NOT NULL)",
    "CREATE INDEX blocks_pack ON blocks(pack_id)",
    "CREATE TABLE staging_pins(id TEXT PRIMARY KEY,volume TEXT NOT NULL,incarnation INTEGER NOT NULL,fence INTEGER NOT NULL,pack_id TEXT NOT NULL,expires INTEGER NOT NULL,verified INTEGER NOT NULL)",
    "CREATE INDEX staging_pack ON staging_pins(pack_id)",
    "CREATE TABLE staged_pack_entries(pin TEXT NOT NULL,digest TEXT NOT NULL,offset INTEGER NOT NULL,loc TEXT NOT NULL,PRIMARY KEY(pin,digest,offset))",
    "CREATE TABLE staged_nodes(volume TEXT NOT NULL,incarnation INTEGER NOT NULL,fence INTEGER NOT NULL,digest TEXT NOT NULL,data_b64 TEXT NOT NULL,expires INTEGER NOT NULL,PRIMARY KEY(volume,incarnation,fence,digest))",
    "CREATE TABLE staged_blocks(pin TEXT NOT NULL,digest TEXT NOT NULL,offset INTEGER NOT NULL,PRIMARY KEY(pin,digest,offset))",
    "CREATE TABLE gc_state(singleton INTEGER PRIMARY KEY, last_mark INTEGER NOT NULL)",
    "CREATE TABLE gc_pending_deletes(pack_id TEXT PRIMARY KEY,in_flight INTEGER NOT NULL,delete_after INTEGER NOT NULL DEFAULT 0)",
    "CREATE TABLE quarantined_volumes(volume TEXT PRIMARY KEY)",
];
// Additive upgrade of existing v1 metadata. Old staged locations already contain their offset.
fn upgrade_v1(db: &mut Db, retain: u64) {
    if number(
        db,
        "SELECT 1 n FROM pragma_table_info('schema_meta') WHERE name='pending_publish'",
        vec![],
    )
    .is_some()
    {
        return;
    }
    for sql in [
        "ALTER TABLE schema_meta ADD COLUMN prev_checkpoint TEXT",
        "ALTER TABLE schema_meta ADD COLUMN pending_publish INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE schema_meta ADD COLUMN verify_restore INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE gc_pending_deletes ADD COLUMN delete_after INTEGER NOT NULL DEFAULT 0",
        "CREATE TABLE quarantined_volumes(volume TEXT PRIMARY KEY)",
        "ALTER TABLE staged_pack_entries RENAME TO old_staged_entries",
        "CREATE TABLE staged_pack_entries(pin TEXT NOT NULL,digest TEXT NOT NULL,offset INTEGER NOT NULL,loc TEXT NOT NULL,PRIMARY KEY(pin,digest,offset))",
        "INSERT INTO staged_pack_entries SELECT pin,digest,json_extract(loc,'$.offset'),loc FROM old_staged_entries",
        "DROP TABLE old_staged_entries",
        "ALTER TABLE schema_meta ADD COLUMN inventory_cursor TEXT",
        "ALTER TABLE packs ADD COLUMN retain_until INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE staged_blocks RENAME TO old_staged_blocks",
        "CREATE TABLE staged_blocks(pin TEXT NOT NULL,digest TEXT NOT NULL,offset INTEGER NOT NULL,PRIMARY KEY(pin,digest,offset))",
        "INSERT INTO staged_blocks SELECT b.pin,b.digest,e.offset FROM old_staged_blocks b JOIN staged_pack_entries e USING(pin,digest)",
        "DROP TABLE old_staged_blocks",
    ] {
        db.run(sql, vec![]);
    }
    db.run(
        "UPDATE gc_pending_deletes SET delete_after=? WHERE in_flight=0",
        vec![int(auth::now().saturating_add(retain))],
    );
    db.run("UPDATE packs SET retain_until=(SELECT delete_after FROM gc_pending_deletes d WHERE d.pack_id=packs.pack_id) WHERE pack_id IN(SELECT pack_id FROM gc_pending_deletes)", vec![]);
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Grant {
    pub tenant: String,
    pub ns: String,
    pub owner: String,
    pub scope: RemoteScope,
    pub admin: bool,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Command {
    pub grant: Grant,
    pub volume: VolumeId,
    pub action: Action,
}

/// These operations are reachable only through the STORAGE binding.
#[derive(Serialize, Deserialize)]
pub(crate) enum Action {
    Rpc(Op),
    Begin {
        pack_id: PackId,
        size: u32,
        lease: w::Fence,
    },
    Seal {
        pack_id: PackId,
        id: String,
        lease: w::Fence,
        entries: Vec<PackIndexEntry>,
    },
    Abandon {
        pack_id: PackId,
        id: String,
    },
    Stat {
        pack_id: PackId,
        read: bool,
        range: Option<String>,
    },
}

#[derive(Deserialize)]
struct StrRow {
    v: String,
}
fn strings(db: &Db, sql: &str, args: Vec<SqlStorageValue>) -> Vec<String> {
    db.rows::<StrRow>(sql, args)
        .into_iter()
        .map(|r| r.v)
        .collect()
}
fn string(db: &Db, sql: &str, args: Vec<SqlStorageValue>) -> Option<String> {
    strings(db, sql, args).pop()
}
#[derive(Deserialize)]
struct NumRow {
    #[serde(deserialize_with = "db::exact_u64")]
    n: u64,
}
fn number(db: &Db, sql: &str, args: Vec<SqlStorageValue>) -> Option<u64> {
    db.rows::<NumRow>(sql, args).pop().map(|r| r.n)
}
fn json<T: Serialize>(v: &T) -> VResult<String> {
    serde_json::to_string(v).map_err(|_| Errno::EIO)
}
fn parse<T: DeserializeOwned>(s: &str) -> VResult<T> {
    serde_json::from_str(s).map_err(|_| Errno::EIO)
}
fn tx<T: 'static>(state: &State, f: impl FnOnce(&mut Db) -> VResult<T> + 'static) -> VResult<T> {
    db::transact(state, move |db| {
        let r = f(db);
        let commit = r.is_ok();
        (r, commit)
    })
    .map_err(|_| Errno::EIO)?
}
fn now() -> Timespec {
    Timespec {
        sec: auth::now(),
        nsec: 0,
    }
}
fn next(n: u64) -> VResult<u64> {
    n.checked_add(1)
        .filter(|n| *n <= i64::MAX as u64)
        .ok_or(Errno::ENOSPC)
}
pub(crate) fn pack_key(tenant: &str, id: &PackId) -> String {
    format!("t/{tenant}/packs/{}", id.0)
}
pub(crate) fn error(errno: Errno) -> Result<Response> {
    let status = match errno {
        Errno::EACCES | Errno::EPERM => 403,
        Errno::ENOENT => 404,
        Errno::ESTALE => 412,
        Errno::EBUSY | Errno::EAGAIN | Errno::EEXIST => 409,
        Errno::EFBIG => 413,
        Errno::EDQUOT => 507,
        Errno::EIO => 500,
        _ => 400,
    };
    let mut resp = Response::from_json(&w::VolumeError { errno })?.with_status(status);
    resp.headers_mut()
        .set("X-OS-Errno", &format!("{errno:?}"))?;
    Ok(resp)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    #[serde(deserialize_with = "db::exact_u64")]
    store_incarnation: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    checkpoint_seq: u64,
    checkpoint_nonce: String,
}
fn checkpoint(db: &Db) -> VResult<Checkpoint> {
    let sql = "SELECT CAST(store_incarnation AS TEXT) store_incarnation, CAST(checkpoint_seq AS TEXT) checkpoint_seq,checkpoint_nonce FROM schema_meta";
    db.rows(sql, vec![]).pop().ok_or(Errno::EIO)
}
fn advance(db: &mut Db, previous: &Checkpoint) -> VResult<()> {
    db.run(
        "UPDATE schema_meta SET prev_checkpoint=?,pending_publish=1,checkpoint_seq=?,checkpoint_nonce=?",
        vec![text(&json(previous)?), int(next(previous.checkpoint_seq)?), text(&auth::random_token())],
    );
    Ok(())
}
fn rotate(db: &mut Db, anchor: &Checkpoint) -> VResult<()> {
    let local = checkpoint(db)?;
    let inc = next(local.store_incarnation.max(anchor.store_incarnation))?;
    db.run(
        "UPDATE schema_meta SET store_incarnation=?,checkpoint_seq=?,checkpoint_nonce=?,prev_checkpoint=?,pending_publish=1,verify_restore=1",
        vec![int(inc), int(next(local.checkpoint_seq.max(anchor.checkpoint_seq))?), text(&auth::random_token()), text(&json(anchor)?)],
    );
    db.run("UPDATE volumes SET incarnation=?", vec![int(inc)]);
    for t in [
        "writer_leases",
        "staged_pack_entries",
        "staged_nodes",
        "staged_blocks",
        "staging_pins",
    ] {
        db.run(&format!("DELETE FROM {t}"), vec![]);
    }
    Ok(())
}

#[durable_object]
pub struct StorageVolume {
    state: State,
    env: Env,
    ready: Cell<bool>,
    gate: Mutex<()>,
    draining: Cell<bool>,
    visibility: Rc<VisibilityCache>,
}

impl DurableObject for StorageVolume {
    fn new(state: State, env: Env) -> Self {
        Self {
            state,
            env,
            ready: Cell::new(false),
            gate: Mutex::new(()),
            draining: Cell::new(false),
            visibility: Default::default(),
        }
    }
    async fn fetch(&self, mut req: Request) -> Result<Response> {
        if req.path() != "/internal/volume" || req.method() != Method::Post {
            return Response::error("Not found", 404);
        }
        let mut cmd: Command = match serde_json::from_str(&req.text().await?) {
            Ok(c) => c,
            Err(_) => return error(Errno::EINVAL),
        };
        let tenant = cmd.grant.tenant.clone();
        if self
            .env
            .durable_object("STORAGE")?
            .id_from_name(&format!("tenant:{tenant}"))?
            != self.state.id()
        {
            return error(Errno::EACCES);
        }
        let guard = self.gate.lock().await;
        if let Err(e) = self.ensure_ready(&tenant).await {
            return error(e);
        }
        let checkpoint_write = matches!(&cmd.action, Action::Rpc(op) if op.writes() &&
            !matches!(op, Op::Renew {..} | Op::DetachRw {..} | Op::StageObjects {..} | Op::RunGc {} | Op::RotateIncarnation {}));
        let rotate_request = matches!(cmd.action, Action::Rpc(Op::RotateIncarnation {}));
        let gc = matches!(cmd.action, Action::Rpc(Op::RunGc {}));
        let changes_roots = checkpoint_write
            || rotate_request
            || gc
            || matches!(
                cmd.action,
                Action::Rpc(Op::PinRo { .. } | Op::UnpinRo { .. })
            );
        let retain = self.retention()?;
        let quota = match self.env.var("VOLUME_QUOTA_BYTES") {
            Ok(v) => v
                .to_string()
                .parse()
                .map_err(|_| Error::RustError("invalid volume quota".into()))?,
            Err(_) => 1024u64 * 1024 * 1024,
        };
        // Persist the wakeup before accepting work which may outlive this instance.
        if self.state.storage().get_alarm().await?.is_none() {
            self.state.storage().set_alarm(60_000).await?;
        }
        // Revalidate after asynchronous readiness/alarm work, immediately before the SQL transaction.
        // Abandon only releases the reservation identified by the gateway's random upload ID.
        if !matches!(cmd.action, Action::Abandon { .. }) {
            match crate::pack_gateway::verify(&req, &self.env).await {
                Ok(live) if live.tenant == tenant && live.owner == cmd.grant.owner => {
                    cmd.grant = live
                }
                Ok(_) => return error(Errno::EACCES),
                Err(e) => return error(e),
            }
        }
        let aborted = match &cmd.action {
            Action::Rpc(Op::Commit { request } | Op::Receive { request, .. })
                if cmd.grant.scope.allows_volume(&cmd.volume.0, true)
                    && request.volume == cmd.volume =>
            {
                Some((
                    cmd.volume.clone(),
                    request.op_id,
                    publication_hash(
                        request,
                        match &cmd.action {
                            Action::Rpc(Op::Receive { snapshot, .. }) => snapshot.as_deref(),
                            _ => None,
                        },
                    )
                    .map_err(|_| Error::RustError("invalid commit".into()))?,
                ))
            }
            _ => None,
        };
        let cache = self.visibility.clone();
        let result = tx(&self.state, move |db| {
            let replay = match &cmd.action {
                Action::Rpc(Op::Commit { request } | Op::Receive { request, .. }) => {
                    !matches!(status(db, &cmd.volume, &request.op_id)?, w::Status::Pending)
                }
                _ => false,
            };
            let previous = (checkpoint_write && !replay)
                .then(|| checkpoint(db))
                .transpose()?;
            let value = dispatch(db, cmd, quota, retain, &cache)?;
            if let Some(previous) = previous {
                advance(db, &previous)?;
            }
            Ok(value)
        });
        let value = match result {
            Err(e) => {
                if let Some((v, id, hash)) = aborted
                    && matches!(e, Errno::ESTALE | Errno::EAGAIN | Errno::EIO)
                {
                    tx(&self.state, move |db| {
                        save_status(db, &v, &id, &hash, &w::Status::Aborted { errno: e })
                    })
                    .map_err(|_| Error::RustError("receipt storage".into()))?;
                }
                return error(e);
            }
            Ok(v) => v,
        };
        if changes_roots {
            self.visibility.0.borrow_mut().clear();
        }
        if checkpoint_write || rotate_request || gc {
            self.ready.set(false);
            if let Err(e) = self.finish_checkpoint(&tenant).await {
                return error(e);
            }
            self.ready.set(true);
        }
        drop(guard);
        if gc {
            self.drain(&tenant).await?;
        }
        Response::from_json(&value)
    }
    async fn alarm(&self) -> Result<Response> {
        let guard = self.gate.lock().await;
        let tenant = tx(&self.state, |db| {
            string(db, "SELECT tenant v FROM schema_meta", vec![]).ok_or(Errno::EIO)
        })
        .map_err(|_| Error::RustError("missing storage tenant".into()))?;
        self.ensure_ready(&tenant)
            .await
            .map_err(|e| Error::RustError(format!("{e:?}")))?;
        let retain = self.retention()?;
        self.visibility.0.borrow_mut().clear();
        tx(&self.state, move |db| collect(db, retain))
            .map_err(|e| Error::RustError(format!("GC mark: {e:?}")))?;
        self.ready.set(false);
        self.finish_checkpoint(&tenant)
            .await
            .map_err(|e| Error::RustError(format!("GC checkpoint: {e:?}")))?;
        self.ready.set(true);
        drop(guard);
        self.inventory(&tenant, retain).await?;
        self.drain(&tenant).await?;
        self.state.storage().set_alarm(60_000).await?;
        Response::ok("")
    }
}
impl StorageVolume {
    fn retention(&self) -> Result<u64> {
        self.env
            .var("VOLUME_GC_RETAIN_SECS")
            .map_or(Ok(w::GC_GRACE_WINDOW_SECS), |v| {
                v.to_string()
                    .parse::<u32>()
                    .map(u64::from)
                    .map_err(|_| Error::RustError("invalid GC retention".into()))
            })
    }
    async fn ensure_ready(&self, tenant: &str) -> VResult<()> {
        if self.ready.get() {
            return Ok(());
        }
        let t = tenant.to_owned();
        let retain = self.retention().map_err(|_| Errno::EIO)?;
        let (local, previous, pending) = tx(&self.state, move |db| {
            let tables = strings(
                db,
                "SELECT name v FROM sqlite_master WHERE type='table' AND name NOT GLOB '__miniflare_*' AND name NOT GLOB '_cf_*' AND name NOT GLOB 'sqlite_*'",
                vec![],
            );
            let fresh = tables.is_empty();
            if fresh {
                for sql in SCHEMA {
                    db.run(sql, vec![]);
                }
                db.run(
                    "INSERT INTO schema_meta(version,tenant,store_incarnation,checkpoint_seq,checkpoint_nonce,publication_seq,pending_publish) VALUES(?,?,1,0,?,0,1)",
                    vec![
                        int(STORAGE_SCHEMA_VERSION),
                        text(&t),
                        text(&auth::random_token()),
                    ],
                );
            } else if !tables.iter().any(|s| s == "schema_meta")
                || number(
                    db,
                    "SELECT 1 n FROM pragma_table_info('schema_meta') WHERE name='version'",
                    vec![],
                )
                .is_none()
                || number(db, "SELECT version n FROM schema_meta", vec![])
                    != Some(STORAGE_SCHEMA_VERSION.into())
            {
                return Err(Errno::EPROTONOSUPPORT);
            }
            if string(db, "SELECT tenant v FROM schema_meta", vec![]).as_ref() != Some(&t) {
                return Err(Errno::EACCES);
            }
            if !fresh {
                upgrade_v1(db, retain);
            }
            Ok((
                checkpoint(db)?,
                string(
                    db,
                    "SELECT prev_checkpoint v FROM schema_meta WHERE prev_checkpoint IS NOT NULL",
                    vec![],
                )
                .map(|s| parse::<Checkpoint>(&s))
                .transpose()?,
                number(db, "SELECT pending_publish n FROM schema_meta", vec![]) == Some(1),
            ))
        })?;
        let bucket = self.env.bucket("FILES").map_err(|_| Errno::EIO)?;
        let key = format!("t/{tenant}/meta/checkpoint.json");
        let stored = bucket.get(key).execute().await.map_err(|_| Errno::EIO)?;
        let anchor = if let Some(obj) = stored {
            Some(parse::<Checkpoint>(
                &obj.body()
                    .ok_or(Errno::EIO)?
                    .text()
                    .await
                    .map_err(|_| Errno::EIO)?,
            )?)
        } else {
            None
        };
        if anchor.as_ref() != Some(&local) && !(pending && anchor == previous) {
            let old = anchor.ok_or(Errno::EIO)?;
            tx(&self.state, move |db| rotate(db, &old))?;
            self.visibility.0.borrow_mut().clear();
        }
        self.finish_checkpoint(tenant).await?;
        self.ready.set(true);
        Ok(())
    }
    async fn finish_checkpoint(&self, tenant: &str) -> VResult<()> {
        let (pending, verify) = tx(&self.state, |db| {
            Ok((
                number(db, "SELECT pending_publish n FROM schema_meta", vec![]) == Some(1),
                number(db, "SELECT verify_restore n FROM schema_meta", vec![]) == Some(1),
            ))
        })?;
        if !pending {
            return Ok(());
        }
        if verify {
            let bucket = self.env.bucket("FILES").map_err(|_| Errno::EIO)?;
            let volumes = tx(&self.state, |db| {
                Ok(strings(db, "SELECT volume v FROM volumes", vec![]))
            })?;
            for v in volumes {
                let id = v.clone();
                let packs = tx(&self.state, move |db| {
                    let roots = strings(
                        db,
                        "SELECT root v FROM volumes WHERE volume=?1 UNION SELECT root FROM snapshots WHERE volume=?1 UNION SELECT root FROM ro_pins WHERE volume=?1 AND expires>?2",
                        vec![text(&id), int(auth::now())],
                    );
                    Ok(mark(db, roots).map(|m| m.packs))
                })?;
                let mut missing = packs.is_err();
                for p in packs.into_iter().flatten() {
                    if bucket
                        .head(pack_key(tenant, &PackId(p)))
                        .await
                        .map_err(|_| Errno::EIO)?
                        .is_none()
                    {
                        missing = true;
                        break;
                    }
                }
                tx(&self.state, move |db| {
                    if missing {
                        db.run(
                            "INSERT OR IGNORE INTO quarantined_volumes VALUES(?)",
                            vec![text(&v)],
                        );
                    } else {
                        db.run(
                            "DELETE FROM quarantined_volumes WHERE volume=?",
                            vec![text(&v)],
                        );
                    }
                    Ok(())
                })?;
            }
        }
        let cp = tx(&self.state, |db| checkpoint(db))?;
        self.env
            .bucket("FILES")
            .map_err(|_| Errno::EIO)?
            .put(format!("t/{tenant}/meta/checkpoint.json"), json(&cp)?)
            .execute()
            .await
            .map_err(|_| Errno::EIO)?;
        tx(&self.state, |db| {
            db.run(
                "UPDATE schema_meta SET pending_publish=0,verify_restore=0",
                vec![],
            );
            Ok(())
        })
    }
    /// Reconcile a bounded page on each alarm. A PUT can finish after the gateway and its
    /// SQLite reservation have disappeared, including after a restore or an earlier sweep.
    async fn inventory(&self, tenant: &str, retain: u64) -> Result<()> {
        let cursor = tx(&self.state, |db| {
            Ok(string(
                db,
                "SELECT inventory_cursor v FROM schema_meta WHERE inventory_cursor IS NOT NULL",
                vec![],
            ))
        })
        .map_err(|_| Error::RustError("pack inventory cursor".into()))?;
        let bucket = self.env.bucket("FILES")?;
        let prefix = format!("t/{tenant}/packs/");
        let mut listing = bucket.list().prefix(&prefix).limit(100);
        if let Some(cursor) = cursor {
            listing = listing.cursor(cursor);
        }
        let page = listing.execute().await?;
        let next = page.cursor();
        let ids: Vec<String> = page
            .objects()
            .into_iter()
            .filter_map(|obj| obj.key().strip_prefix(&prefix).map(str::to_owned))
            .collect();
        tx(&self.state, move |db| {
            for id in ids {
                if digest_from_hex(&id).is_ok() {
                    db.run("INSERT OR IGNORE INTO gc_pending_deletes SELECT ?1,0,?2 WHERE NOT EXISTS(SELECT 1 FROM packs WHERE pack_id=?1)",
                        vec![text(&id),int(auth::now()+retain)]);
                }
            }
            db.run("UPDATE schema_meta SET inventory_cursor=?",vec![next.as_deref().into()]);
            Ok(())
        }).map_err(|_| Error::RustError("pack inventory".into()))
    }
    async fn drain(&self, tenant: &str) -> Result<()> {
        if self.draining.replace(true) {
            return Ok(());
        }
        let result = async {
            loop {
                let batch = tx(&self.state, |db| {
                    let ids = strings(
                        db,
                        "SELECT d.pack_id v FROM gc_pending_deletes d
                         WHERE d.delete_after<=?1 AND NOT EXISTS(SELECT 1 FROM staging_pins s WHERE s.pack_id=d.pack_id AND s.expires>?1)
                           AND NOT EXISTS(SELECT 1 FROM packs p WHERE p.pack_id=d.pack_id AND p.status!='deleting')
                         ORDER BY d.pack_id LIMIT 100",
                        vec![int(auth::now())],
                    );
                    for id in &ids {
                        db.run(
                            "UPDATE gc_pending_deletes SET in_flight=1 WHERE pack_id=?",
                            vec![text(id)],
                        );
                    }
                    Ok(ids)
                })
                .map_err(|_| Error::RustError("GC reservation".into()))?;
                if batch.is_empty() {
                    break;
                }
                let keys = batch
                    .iter()
                    .map(|id| pack_key(tenant, &PackId(id.clone())))
                    .collect();
                self.env.bucket("FILES")?.delete_multiple(keys).await?;
                tx(&self.state, move |db| {
                    for id in batch {
                        db.run("DELETE FROM pack_entries WHERE pack_id=?", vec![text(&id)]);
                        db.run(
                            "DELETE FROM packs WHERE pack_id=? AND status='deleting'",
                            vec![text(&id)],
                        );
                        db.run(
                            "DELETE FROM gc_pending_deletes WHERE pack_id=? AND in_flight=1",
                            vec![text(&id)],
                        );
                    }
                    Ok(())
                })
                .map_err(|_| Error::RustError("GC completion".into()))?;
            }
            Ok(())
        }
        .await;
        self.draining.set(false);
        result
    }
}

#[derive(Deserialize)]
struct HeadRow {
    volume: VolumeId,
    format_version: u32,
    #[serde(deserialize_with = "db::exact_u64")]
    incarnation: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    fence: u64,
    #[serde(deserialize_with = "db::exact_u64")]
    epoch: u64,
    root: String,
    parent_volume: Option<VolumeId>,
    ephemeral: u8,
    modified: u8,
    #[serde(deserialize_with = "db::exact_u64")]
    updated_at: u64,
}
fn head(db: &Db, v: &VolumeId) -> VResult<VolumeHead> {
    let sql = "SELECT volume,format_version,CAST(incarnation AS TEXT) incarnation,CAST(fence AS TEXT) fence,CAST(epoch AS TEXT) epoch,root,parent_volume,ephemeral,modified,CAST(updated_at AS TEXT) updated_at FROM volumes WHERE volume=?";
    let h = db
        .rows::<HeadRow>(sql, vec![text(&v.0)])
        .pop()
        .ok_or(Errno::ENOENT)?;
    if h.format_version != cowtree::COWFS_FORMAT_VERSION {
        return Err(Errno::EPROTONOSUPPORT);
    }
    Ok(VolumeHead {
        volume: h.volume,
        format_version: h.format_version,
        incarnation: h.incarnation,
        fence: h.fence,
        epoch: h.epoch,
        root: digest_from_hex(&h.root)?,
        parent_volume: h.parent_volume,
        ephemeral_if_unmodified: h.ephemeral != 0,
        modified: h.modified != 0,
        updated_at: Timespec {
            sec: h.updated_at,
            nsec: 0,
        },
    })
}
fn save(db: &mut Db, h: &VolumeHead) {
    db.run(
        "INSERT OR REPLACE INTO volumes VALUES(?,?,?,?,?,?,?,?,?,?)",
        vec![
            text(&h.volume.0),
            int(h.format_version),
            int(h.incarnation),
            int(h.fence),
            int(h.epoch),
            text(&hex(&h.root)),
            h.parent_volume.as_ref().map(|v| v.0.as_str()).into(),
            int(h.ephemeral_if_unmodified as u8),
            int(h.modified as u8),
            int(h.updated_at.sec),
        ],
    );
}
fn verify_lease(db: &Db, h: &VolumeHead, l: w::Fence, g: &Grant) -> VResult<()> {
    let sql = "SELECT 1 n FROM writer_leases WHERE volume=? AND incarnation=? AND fence=? AND owner=? AND expires>?";
    let args = vec![
        text(&h.volume.0),
        int(l.incarnation),
        int(l.fence),
        text(&g.owner),
        int(auth::now()),
    ];
    if w::Fence::from(h) != l || number(db, sql, args).is_none() {
        return Err(Errno::ESTALE);
    }
    Ok(())
}
fn compare(db: &Db, h: &VolumeHead, expected: &VolumeHead, g: &Grant) -> VResult<()> {
    verify_lease(db, h, expected.into(), g)?;
    if h.volume != expected.volume || h.epoch != expected.epoch || h.root != expected.root {
        Err(Errno::EAGAIN)
    } else {
        Ok(())
    }
}
fn validate_volume(v: &VolumeId) -> VResult<()> {
    let id = &v.0;
    if id.starts_with('/')
        || ["hostfs:", "opfs:", "helperfs:", "sharefs:", "cloud:"]
            .iter()
            .any(|prefix| id.starts_with(prefix))
    {
        Err(Errno::ENOTBLK)
    } else if !valid_id(id) {
        Err(Errno::EINVAL)
    } else {
        Ok(())
    }
}
fn fresh(db: &mut Db, v: &VolumeId, root: Digest) -> VResult<VolumeHead> {
    validate_volume(v)?;
    if number(
        db,
        "SELECT 1 n FROM volumes WHERE volume=?",
        vec![text(&v.0)],
    )
    .is_some()
    {
        return Err(Errno::EEXIST);
    }
    if number(
        db,
        "SELECT 1 n FROM writer_leases WHERE volume=? AND expires>?",
        vec![text(&v.0), int(auth::now())],
    )
    .is_some()
    {
        return Err(Errno::EBUSY);
    }
    let incarnation = next(checkpoint(db)?.store_incarnation)?;
    db.run(
        "UPDATE schema_meta SET store_incarnation=?",
        vec![int(incarnation)],
    );
    Ok(empty_head(v, root, incarnation))
}

fn empty_head(v: &VolumeId, root: Digest, incarnation: u64) -> VolumeHead {
    VolumeHead {
        volume: v.clone(),
        format_version: cowtree::COWFS_FORMAT_VERSION,
        incarnation,
        fence: 0,
        epoch: 0,
        root,
        parent_volume: None,
        ephemeral_if_unmodified: false,
        modified: false,
        updated_at: now(),
    }
}
/// A receive reservation grants exclusive staging rights without publishing a volume.
fn writer_head(db: &Db, v: &VolumeId, g: &Grant) -> VResult<VolumeHead> {
    match head(db, v) {
        Err(Errno::ENOENT) => {
            let incarnation = number(db, "SELECT CAST(incarnation AS TEXT) n FROM writer_leases WHERE volume=? AND owner=? AND expires>?", vec![text(&v.0), text(&g.owner),int(auth::now())]).ok_or(Errno::ENOENT)?;
            let mut h = empty_head(v, [0; 32], incarnation);
            h.fence = 1;
            Ok(h)
        }
        result => result,
    }
}
fn grant_writer(db: &mut Db, g: &Grant, h: VolumeHead, forked_from: Option<VolumeId>) -> Reply {
    let expires = auth::now() + w::WRITER_LEASE_TTL_SECS;
    db.run(
        "INSERT OR REPLACE INTO writer_leases VALUES(?,?,?,?,?)",
        vec![
            text(&h.volume.0),
            int(h.incarnation),
            int(h.fence),
            text(&g.owner),
            int(expires),
        ],
    );
    Reply::Attached {
        head: h,
        forked_from,
        expires,
    }
}
fn authorized_root(db: &Db, v: &VolumeId, root: &Digest) -> bool {
    number(
        db,
        "SELECT 1 n WHERE EXISTS(SELECT 1 FROM volumes WHERE volume=?1 AND root=?2)
         OR EXISTS(SELECT 1 FROM snapshots WHERE volume=?1 AND root=?2)
         OR EXISTS(SELECT 1 FROM ro_pins WHERE volume=?1 AND root=?2 AND expires>?3)
         OR EXISTS(SELECT 1 FROM grace_pins WHERE volume=?1 AND root=?2 AND expires>?3)",
        vec![text(&v.0), text(&hex(root)), int(auth::now())],
    )
    .is_some()
}
fn snapshot(db: &Db, v: &VolumeId, name: &str) -> VResult<SnapshotRecord> {
    #[derive(Deserialize)]
    struct Row {
        root: String,
        #[serde(deserialize_with = "db::exact_u64")]
        epoch: u64,
        #[serde(deserialize_with = "db::exact_u64")]
        created_at: u64,
    }
    let sql = "SELECT root,CAST(epoch AS TEXT) epoch,CAST(created_at AS TEXT) created_at FROM snapshots WHERE volume=? AND name=?";
    let s = db
        .rows::<Row>(sql, vec![text(&v.0), text(name)])
        .pop()
        .ok_or(Errno::ENOENT)?;
    Ok(SnapshotRecord {
        volume: v.clone(),
        name: name.into(),
        root: digest_from_hex(&s.root)?,
        epoch: s.epoch,
        created_at: Timespec {
            sec: s.created_at,
            nsec: 0,
        },
    })
}
fn readers(db: &Db, v: &VolumeId) -> VResult<()> {
    if number(
        db,
        "SELECT 1 n FROM ro_pins WHERE volume=? AND expires>? LIMIT 1",
        vec![text(&v.0), int(auth::now())],
    )
    .is_some()
    {
        Err(Errno::EBUSY)
    } else {
        Ok(())
    }
}
fn grace(db: &mut Db, h: &VolumeHead) {
    db.run(
        "INSERT OR REPLACE INTO grace_pins VALUES(?,?,?)",
        vec![
            text(&h.volume.0),
            text(&hex(&h.root)),
            int(auth::now() + w::GC_GRACE_WINDOW_SECS),
        ],
    );
}
fn clear_volume(db: &mut Db, v: &VolumeId) {
    for table in [
        "writer_leases",
        "staging_pins",
        "receipts",
        "ro_pins",
        "snapshots",
        "volumes",
    ] {
        db.run(
            &format!("DELETE FROM {table} WHERE volume=?"),
            vec![text(&v.0)],
        );
    }
    db.run(
        "DELETE FROM staged_pack_entries WHERE pin NOT IN (SELECT id FROM staging_pins)",
        vec![],
    );
}
fn save_status(
    db: &mut Db,
    v: &VolumeId,
    id: &[u8; 16],
    hash: &Digest,
    status: &w::Status,
) -> VResult<()> {
    db.run(
        "INSERT OR IGNORE INTO receipts VALUES(?,?,?,?)",
        vec![
            text(&v.0),
            text(&STANDARD.encode(id)),
            text(&hex(hash)),
            text(&json(status)?),
        ],
    );
    Ok(())
}
fn status(db: &Db, v: &VolumeId, id: &[u8; 16]) -> VResult<w::Status> {
    string(
        db,
        "SELECT status v FROM receipts WHERE volume=? AND op_id=?",
        vec![text(&v.0), text(&STANDARD.encode(id))],
    )
    .map(|s| parse(&s))
    .unwrap_or(Ok(w::Status::Pending))
}

fn dispatch(
    db: &mut Db,
    cmd: Command,
    quota: u64,
    retain: u64,
    cache: &VisibilityCache,
) -> VResult<serde_json::Value> {
    let Command {
        grant: g,
        volume: v,
        action,
    } = cmd;
    validate_volume(&v)?;
    let write = match &action {
        Action::Rpc(op) => op.writes(),
        Action::Stat { .. } => false,
        _ => true,
    };
    if !g.scope.allows_volume(&v.0, write) {
        return Err(Errno::EACCES);
    }
    if number(
        db,
        "SELECT 1 n FROM quarantined_volumes WHERE volume=?",
        vec![text(&v.0)],
    )
    .is_some()
        && !matches!(
            action,
            Action::Rpc(Op::Hello { .. } | Op::FormatVersion {} | Op::RunGc {} | Op::Status { .. })
        )
    {
        return Err(Errno::EIO);
    }
    let scoped = if !g.scope.volume_ids.is_empty()
        && matches!(
            action,
            Action::Stat { .. }
                | Action::Rpc(Op::GetNode { .. } | Op::LookupBlock { .. } | Op::ListPacks {})
        ) {
        Some(cache.get(db, &v)?)
    } else {
        None
    };
    let value = match action {
        Action::Rpc(Op::RunGc {}) if g.scope.volume_ids.is_empty() => {
            serde_json::to_value(Reply::Gc(collect(db, retain)?))
        }
        Action::Rpc(op) => serde_json::to_value(rpc(db, &g, &v, op, scoped.as_deref())?),
        Action::Begin {
            pack_id,
            size,
            lease,
        } => serde_json::to_value(begin(db, &g, &v, lease, &pack_id, size, quota)?),
        Action::Seal {
            pack_id,
            id,
            lease,
            entries,
        } => serde_json::to_value(seal(db, &g, &v, lease, &pack_id, &id, entries)?),
        Action::Abandon { pack_id, id } => {
            abandon(db, &v, &pack_id, &id);
            Ok(serde_json::Value::Null)
        }
        Action::Stat {
            pack_id,
            read,
            range,
        } => {
            writer_head(db, &v, &g)?;
            let uploading = number(db, "SELECT p.size n FROM packs p JOIN staging_pins s USING(pack_id) JOIN writer_leases l USING(volume,incarnation,fence)
                   WHERE p.pack_id=? AND s.volume=? AND l.owner=? AND s.verified=1 AND s.expires>?4 AND l.expires>?4
                   AND EXISTS(SELECT 1 FROM staged_blocks WHERE pin=s.id)",vec![text(&pack_id.0),text(&v.0),text(&g.owner),int(auth::now())]);
            if let Some(size) = uploading {
                return Ok(serde_json::json!(size));
            }
            let graph = scoped;
            if graph
                .as_ref()
                .is_some_and(|m| !m.packs.contains(&pack_id.0))
            {
                return Err(Errno::ENOENT);
            }
            let size = number(
                db,
                "SELECT size n FROM packs WHERE pack_id=? AND status='sealed'",
                vec![text(&pack_id.0)],
            )
            .ok_or(Errno::ENOENT)?;
            if read && let Some(marks) = graph {
                // Deduplication can put a visible block in a pack shared with a private
                // volume. Only return payload ranges whose blocks this grant can reach.
                let interval = match range {
                    Some(range) => os_core::byte_range(&range, size),
                    None => size.checked_sub(1).map(|last| (0, last)),
                };
                if let Some((first, last)) = interval {
                    let blocks = strings(
                        db,
                        "SELECT digest v FROM pack_entries WHERE pack_id=? AND offset<=? AND end_offset>?",
                        vec![text(&pack_id.0), int(last), int(first)],
                    );
                    if blocks.iter().any(|d| !marks.blocks.contains(d)) {
                        return Err(Errno::EACCES);
                    }
                }
            }
            serde_json::to_value(size)
        }
    };
    value.map_err(|_| Errno::EIO)
}
fn rpc(db: &mut Db, g: &Grant, v: &VolumeId, op: Op, scoped: Option<&Marks>) -> VResult<Reply> {
    match op {
        Op::Hello { versions } => {
            use abi::contract::{Boundary, Hello, negotiate};
            let boundary = Boundary::Volume;
            let ours = Hello {
                boundary,
                versions: vec![boundary.version()],
            };
            let version =
                negotiate(&ours, &Hello { boundary, versions }).ok_or(Errno::EPROTONOSUPPORT)?;
            Ok(Reply::Version {
                version,
                tenant: g.tenant.clone(),
            })
        }
        Op::FormatVersion {} => Ok(Reply::Version {
            version: cowtree::COWFS_FORMAT_VERSION,
            tenant: g.tenant.clone(),
        }),
        Op::CreateVolume { head: h, nodes } => {
            if h.volume != *v {
                return Err(Errno::EINVAL);
            }
            if h.format_version != cowtree::COWFS_FORMAT_VERSION {
                return Err(Errno::EPROTONOSUPPORT);
            }
            let new = fresh(db, v, h.root)?;
            verify_nodes(db, h.root, &nodes, Some(&Marks::default()))?;
            save(db, &new);
            Ok(Reply::Head(new))
        }
        Op::ReadHead {} => Ok(Reply::Head(head(db, v)?)),
        Op::ListVolumes {} => Ok(Reply::Heads(
            strings(db, "SELECT volume v FROM volumes ORDER BY volume", vec![])
                .into_iter()
                .filter(|id| g.scope.allows_volume(id, false))
                .map(|id| head(db, &VolumeId(id)))
                .collect::<VResult<_>>()?,
        )),
        Op::AttachRw { mode } => {
            let mut h = head(db, v)?;
            let busy = number(
                db,
                "SELECT 1 n FROM writer_leases WHERE volume=? AND expires>?",
                vec![text(&v.0), int(auth::now())],
            )
            .is_some();
            let mut forked_from = None;
            if mode == WriterMode::ForceTakeover && !g.admin {
                return Err(Errno::EACCES);
            }
            if busy {
                match mode {
                    WriterMode::Exclusive => return Err(Errno::EBUSY),
                    WriterMode::ForkOnBusy => {
                        let dest = VolumeId(auth::random_token());
                        if !g.scope.allows_volume(&dest.0, true) {
                            return Err(Errno::EACCES);
                        }
                        h = fresh(db, &dest, h.root)?;
                        h.parent_volume = Some(v.clone());
                        h.ephemeral_if_unmodified = true;
                        forked_from = Some(v.clone());
                    }
                    WriterMode::ForceTakeover => {}
                }
            }
            h.fence = next(h.fence)?;
            save(db, &h);
            Ok(grant_writer(db, g, h, forked_from))
        }
        Op::BeginReceive {} => {
            let mut h = fresh(db, v, [0; 32])?;
            h.fence = 1;
            Ok(grant_writer(db, g, h, None))
        }
        Op::Renew { lease } => {
            verify_lease(db, &writer_head(db, v, g)?, lease, g)?;
            let expires = auth::now() + w::WRITER_LEASE_TTL_SECS;
            db.run(
                "UPDATE writer_leases SET expires=? WHERE volume=?",
                vec![int(expires), text(&v.0)],
            );
            Ok(Reply::Renewed { expires })
        }
        Op::DetachRw { lease } => {
            verify_lease(db, &writer_head(db, v, g)?, lease, g)?;
            db.run("DELETE FROM writer_leases WHERE volume=?", vec![text(&v.0)]);
            Ok(Reply::Done)
        }
        Op::PinRo {
            snapshot: name,
            root,
        } => {
            let mut h = head(db, v)?;
            if let Some(s) = name {
                let snap = snapshot(db, v, &s)?;
                h.root = snap.root;
                h.epoch = snap.epoch;
            }
            if let Some(root) = root {
                let prior_pin = number(
                    db,
                    "SELECT 1 n FROM ro_pins WHERE volume=? AND root=? AND owner=? LIMIT 1",
                    vec![text(&v.0), text(&hex(&root)), text(&g.owner)],
                )
                .is_some();
                if !(authorized_root(db, v, &root) || prior_pin)
                    || node_kind(db, &root, -1).is_err()
                {
                    return Err(Errno::ESTALE);
                }
                h.root = root;
            }
            node_kind(db, &h.root, -1)?;
            let pin_id = auth::random_token();
            db.run(
                "INSERT INTO ro_pins VALUES(?,?,?,?,?)",
                vec![
                    text(&pin_id),
                    text(&v.0),
                    text(&g.owner),
                    text(&hex(&h.root)),
                    int(auth::now() + w::RO_PIN_TTL_SECS),
                ],
            );
            Ok(Reply::Pinned {
                head: h,
                pin_id,
                expires: auth::now() + w::RO_PIN_TTL_SECS,
            })
        }
        Op::RenewRo { pin_id } => {
            let sql = "UPDATE ro_pins SET expires=? WHERE pin_id=? AND volume=? AND owner=? AND expires>? RETURNING 1 n";
            let args = vec![
                int(auth::now() + w::RO_PIN_TTL_SECS),
                text(&pin_id),
                text(&v.0),
                text(&g.owner),
                int(auth::now()),
            ];
            if number(db, sql, args).is_none() {
                return Err(Errno::ESTALE);
            }
            Ok(Reply::Renewed {
                expires: auth::now() + w::RO_PIN_TTL_SECS,
            })
        }
        Op::UnpinRo { pin_id } => {
            db.run(
                "DELETE FROM ro_pins WHERE pin_id=? AND volume=? AND owner=?",
                vec![text(&pin_id), text(&v.0), text(&g.owner)],
            );
            Ok(Reply::Done)
        }
        Op::GetNode { digest } => {
            writer_head(db, v, g)?;
            let key = hex(&digest);
            if let Some(bytes) = staged_node(db, g, v, &key) {
                return Ok(Reply::Node(STANDARD.decode(bytes).map_err(|_| Errno::EIO)?));
            }
            if scoped.is_some_and(|m| !m.nodes.contains(&key)) {
                return Err(Errno::ENOENT);
            }
            let data = string(
                db,
                "SELECT data_b64 v FROM nodes WHERE digest=?",
                vec![text(&key)],
            )
            .ok_or(Errno::ENOENT)?;
            Ok(Reply::Node(STANDARD.decode(data).map_err(|_| Errno::EIO)?))
        }
        Op::LookupBlock { digest } => {
            writer_head(db, v, g)?;
            let key = hex(&digest);
            if let Some(loc) = staged_loc(db, g, v, &key)? {
                return Ok(Reply::Block(Some(loc)));
            }
            if scoped.is_some_and(|m| !m.blocks.contains(&key)) {
                return Ok(Reply::Block(None));
            }
            Ok(Reply::Block(block(db, &key)?))
        }
        Op::Commit { request } => commit(db, g, v, request, None, false),
        Op::Receive { request, snapshot } => commit(db, g, v, request, snapshot, true),
        Op::StageObjects {
            lease,
            nodes,
            packs,
            blocks,
        } => stage_objects(db, g, v, lease, nodes, packs, blocks),
        Op::Status { op_id, lease } => {
            let mut outcome = status(db, v, &op_id)?;
            if matches!(outcome, w::Status::Pending)
                && let Some(f) = lease
                && number(db, "SELECT 1 n FROM writer_leases WHERE volume=? AND incarnation=? AND fence=? AND expires>?",
                    vec![text(&v.0),int(f.incarnation),int(f.fence),int(auth::now())]).is_none()
            {
                outcome = w::Status::Aborted { errno: Errno::ESTALE };
            }
            Ok(Reply::Status(outcome))
        }
        Op::CreateSnapshot {
            name,
            head: expected,
        } => {
            let h = head(db, v)?;
            compare(db, &h, &expected, g)?;
            if !valid_id(&name) {
                return Err(Errno::EINVAL);
            }
            if snapshot(db, v, &name).is_ok() {
                return Err(Errno::EEXIST);
            }
            db.run(
                "INSERT INTO snapshots VALUES(?,?,?,?,?)",
                vec![
                    text(&v.0),
                    text(&name),
                    text(&hex(&h.root)),
                    int(h.epoch),
                    int(auth::now()),
                ],
            );
            Ok(Reply::Snapshot(snapshot(db, v, &name)?))
        }
        Op::GetSnapshot { name } => Ok(Reply::Snapshot(snapshot(db, v, &name)?)),
        Op::ListSnapshots {} => Ok(Reply::Snapshots(
            strings(
                db,
                "SELECT name v FROM snapshots WHERE volume=? ORDER BY name",
                vec![text(&v.0)],
            )
            .iter()
            .map(|n| snapshot(db, v, n))
            .collect::<VResult<_>>()?,
        )),
        Op::DeleteSnapshot {
            name,
            head: expected,
        } => {
            compare(db, &head(db, v)?, &expected, g)?;
            snapshot(db, v, &name)?;
            db.run(
                "DELETE FROM snapshots WHERE volume=? AND name=?",
                vec![text(&v.0), text(&name)],
            );
            Ok(Reply::Done)
        }
        Op::Fork { request: r } => {
            if r.source_volume != *v || !g.scope.allows_volume(&r.new_volume.0, true) {
                return Err(Errno::EACCES);
            }
            let root = r.source_root;
            let authorized = if let Some(n) = r.source_snapshot {
                snapshot(db, v, &n)?.root == root
            } else {
                authorized_root(db, v, &root)
            };
            if !authorized {
                return Err(Errno::ESTALE);
            }
            let mut h = fresh(db, &r.new_volume, root)?;
            h.parent_volume = Some(v.clone());
            h.ephemeral_if_unmodified = r.ephemeral_if_unmodified;
            save(db, &h);
            Ok(Reply::Head(h))
        }
        Op::CheckNoReaders {} => {
            readers(db, v)?;
            Ok(Reply::Done)
        }
        Op::DeleteVolume {
            expected,
            only_unmodified,
        } => {
            let h = head(db, v)?;
            if let Some(e) = expected {
                compare(db, &h, &e, g)?;
            } else if number(
                db,
                "SELECT 1 n FROM writer_leases WHERE volume=? AND expires>?",
                vec![text(&v.0), int(auth::now())],
            )
            .is_some()
            {
                return Err(Errno::EBUSY);
            }
            if only_unmodified && (!h.ephemeral_if_unmodified || h.modified) {
                return Ok(Reply::Deleted(false));
            }
            readers(db, v)?;
            grace(db, &h);
            clear_volume(db, v);
            Ok(Reply::Deleted(true))
        }
        Op::ReformatVolume {
            expected,
            head: new,
            nodes,
        } => {
            let h = head(db, v)?;
            compare(db, &h, &expected, g)?;
            readers(db, v)?;
            if new.volume != *v {
                return Err(Errno::EINVAL);
            }
            if new.format_version != cowtree::COWFS_FORMAT_VERSION {
                return Err(Errno::EPROTONOSUPPORT);
            }
            verify_nodes(db, new.root, &nodes, Some(&Marks::default()))?;
            grace(db, &h);
            clear_volume(db, v);
            let mut h = fresh(db, v, new.root)?;
            h.fence = 1;
            save(db, &h);
            Ok(Reply::Head(h))
        }
        Op::RotateIncarnation {} => {
            if !g.admin || !g.scope.volume_ids.is_empty() {
                return Err(Errno::EACCES);
            }
            rotate(db, &checkpoint(db)?)?;
            Ok(Reply::Head(head(db, v)?))
        }
        Op::ListPacks {} => {
            head(db, v)?;

            Ok(Reply::Packs(
                strings(
                    db,
                    "SELECT pack_id v FROM packs WHERE status='sealed' ORDER BY pack_id",
                    vec![],
                )
                .into_iter()
                .filter(|id| scoped.as_ref().is_none_or(|m| m.packs.contains(id)))
                .map(PackId)
                .collect(),
            ))
        }
        Op::RunGc {} => Err(Errno::EACCES),
    }
}

fn block(db: &Db, key: &str) -> VResult<Option<BlockLoc>> {
    string(
        db,
        "SELECT loc v FROM blocks JOIN packs USING(pack_id) WHERE digest=? AND status='sealed'",
        vec![text(key)],
    )
    .map(|s| parse(&s))
    .transpose()
}
fn node_kind(db: &Db, d: &Digest, level: i16) -> VResult<()> {
    if number(
        db,
        "SELECT 1 n FROM nodes WHERE digest=? AND kind=?",
        vec![text(&hex(d)), int(level)],
    )
    .is_none()
    {
        return Err(Errno::EIO);
    }
    Ok(())
}
type CachedMarks = (u64, Rc<Marks>);
#[derive(Default)]
struct VisibilityCache(RefCell<HashMap<VolumeId, CachedMarks>>);
impl VisibilityCache {
    fn get(&self, db: &Db, v: &VolumeId) -> VResult<Rc<Marks>> {
        let now = auth::now();
        if let Some((until, marks)) = self.0.borrow().get(v)
            && now < *until
        {
            return Ok(marks.clone());
        }
        let marks = Rc::new(mark(db, roots(db, Some(v)))?);
        let until = number(db, "SELECT expires n FROM (SELECT expires FROM grace_pins WHERE volume=?1 UNION ALL SELECT expires FROM ro_pins WHERE volume=?1) WHERE expires>?2 ORDER BY expires LIMIT 1",
            vec![text(&v.0), int(now)]).unwrap_or(u64::MAX);
        self.0
            .borrow_mut()
            .insert(v.clone(), (until, marks.clone()));
        Ok(marks)
    }
}
#[derive(Default)]
struct Marks {
    nodes: HashSet<String>,
    blocks: HashSet<String>,
    packs: HashSet<String>,
}
fn roots(db: &Db, v: Option<&VolumeId>) -> Vec<String> {
    strings(
        db,
        "SELECT root v FROM (SELECT volume,root FROM volumes UNION ALL SELECT volume,root FROM snapshots UNION ALL SELECT volume,root FROM ro_pins WHERE expires>? UNION ALL SELECT volume,root FROM grace_pins WHERE expires>?) WHERE (? IS NULL OR volume=?)",
        vec![
            int(auth::now()),
            int(auth::now()),
            v.map(|v| v.0.as_str()).into(),
            v.map(|v| v.0.as_str()).into(),
        ],
    )
}
fn mark(db: &Db, mut stack: Vec<String>) -> VResult<Marks> {
    let mut marks = Marks::default();
    while let Some(node) = stack.pop() {
        if !marks.nodes.insert(node.clone()) {
            continue;
        }
        if number(
            db,
            "SELECT 1 n FROM nodes WHERE digest=?",
            vec![text(&node)],
        )
        .is_none()
        {
            return Err(Errno::EIO);
        }
        stack.extend(strings(
            db,
            "SELECT child v FROM node_edges WHERE parent=?",
            vec![text(&node)],
        ));
        for d in strings(
            db,
            "SELECT digest v FROM node_blocks WHERE parent=?",
            vec![text(&node)],
        ) {
            if marks.blocks.insert(d.clone()) {
                marks
                    .packs
                    .insert(block(db, &d)?.ok_or(Errno::EIO)?.pack_id.0);
            }
        }
    }
    Ok(marks)
}
fn visibility(db: &Db, g: &Grant, v: &VolumeId) -> VResult<Option<Marks>> {
    if g.scope.volume_ids.is_empty() {
        Ok(None)
    } else {
        Ok(Some(mark(db, roots(db, Some(v)))?))
    }
}

/// Index each newly verified node's direct edges. Previously committed nodes carry the same
/// invariant. GC follows the same edges, including children of young, unpublished nodes.
fn verify_nodes(
    db: &mut Db,
    root: Digest,
    nodes: &[(Digest, Vec<u8>)],
    visible: Option<&Marks>,
) -> VResult<()> {
    let mut supplied = HashSet::new();
    let mut children = Vec::new();
    for (d, bytes) in nodes {
        let key = hex(d);
        supplied.insert(key.clone());
        let kind = if bytes.starts_with(&cowtree::COWFS_ROOT_MAGIC) {
            let r = RootObject::decode_verified(d, bytes)?;
            if r.subvols.is_empty() {
                return Err(Errno::EIO);
            }
            for child in r.subvols.values() {
                children.push((key.clone(), *child, None));
            }
            -1i16
        } else {
            let n = Node::decode_verified(d, bytes)?;
            let level = n.level();
            match n {
                Node::Internal { entries, .. } => {
                    for e in entries {
                        children.push((key.clone(), e.child, Some(i16::from(level) - 1)));
                    }
                }
                Node::Leaf { entries } => {
                    for e in entries {
                        if e.key.kind == cowtree::KIND_EXTENT_DATA
                            && let cowtree::node::ExtentDataValue::Extent {
                                digest,
                                len,
                                block_offset,
                            } = cowtree::node::ExtentDataValue::decode(&e.value)?
                        {
                            let d = hex(&digest);
                            if visible.is_some_and(|m| !m.blocks.contains(&d)) {
                                return Err(Errno::EIO);
                            }
                            let loc = block(db, &d)?.ok_or(Errno::EIO)?;
                            if block_offset
                                .checked_add(len)
                                .is_none_or(|end| end > loc.raw_len)
                            {
                                return Err(Errno::EIO);
                            }
                            db.run(
                                "INSERT OR IGNORE INTO node_blocks VALUES(?,?)",
                                vec![text(&key), text(&d)],
                            );
                        }
                    }
                }
            }
            i16::from(level)
        };
        db.run(
            "INSERT OR IGNORE INTO nodes VALUES(?,?,?,?)",
            vec![
                text(&key),
                int(kind),
                text(&STANDARD.encode(bytes)),
                int(auth::now()),
            ],
        );
    }
    for (parent, child, level) in children {
        let key = hex(&child);
        if visible.is_some_and(|m| !supplied.contains(&key) && !m.nodes.contains(&key)) {
            return Err(Errno::EIO);
        }
        if let Some(l) = level {
            node_kind(db, &child, l)?;
        } else if number(
            db,
            "SELECT 1 n FROM nodes WHERE digest=? AND kind>=0",
            vec![text(&key)],
        )
        .is_none()
        {
            return Err(Errno::EIO);
        }
        db.run(
            "INSERT OR IGNORE INTO node_edges VALUES(?,?)",
            vec![text(&parent), text(&key)],
        );
    }
    if visible.is_some_and(|m| !supplied.contains(&hex(&root)) && !m.nodes.contains(&hex(&root))) {
        return Err(Errno::EIO);
    }
    node_kind(db, &root, -1)
}

/// Staging admits immutable objects for a bounded time without making a head visible.
/// These joins bind every provisional read to the current writer and DO clock.
fn staged_node(db: &Db, g: &Grant, v: &VolumeId, key: &str) -> Option<String> {
    string(db, "SELECT n.data_b64 v FROM staged_nodes n JOIN writer_leases l USING(volume,incarnation,fence)
            WHERE n.volume=? AND n.digest=? AND l.owner=? AND n.expires>?4 AND l.expires>?4",
           vec![text(&v.0), text(key), text(&g.owner), int(auth::now())])
}
fn staged_loc(db: &Db, g: &Grant, v: &VolumeId, key: &str) -> VResult<Option<BlockLoc>> {
    string(db, "SELECT e.loc v FROM staged_blocks b JOIN staged_pack_entries e USING(pin,digest,offset)
           JOIN staging_pins s ON s.id=b.pin JOIN writer_leases l USING(volume,incarnation,fence)
           WHERE s.volume=? AND b.digest=? AND l.owner=? AND s.verified=1 AND s.expires>?4 AND l.expires>?4 LIMIT 1",
           vec![text(&v.0), text(key), text(&g.owner), int(auth::now())]).map(|s| parse(&s)).transpose()
}
fn stage_objects(
    db: &mut Db,
    g: &Grant,
    v: &VolumeId,
    lease: w::Fence,
    nodes: Vec<(Digest, Vec<u8>)>,
    packs: Vec<PackMeta>,
    blocks: Vec<(Digest, BlockLoc)>,
) -> VResult<Reply> {
    verify_lease(db, &writer_head(db, v, g)?, lease, g)?;
    let mut pins = std::collections::HashMap::new();
    for pack in packs {
        let pin = string(db, "SELECT s.id v FROM staging_pins s JOIN packs p USING(pack_id)
                    WHERE s.volume=? AND s.incarnation=? AND s.fence=? AND s.pack_id=? AND s.verified=1
                    AND s.expires>? AND p.size=? AND p.entry_count=? LIMIT 1",
                    vec![text(&v.0),int(lease.incarnation),int(lease.fence),text(&pack.pack_id.0),
                         int(auth::now()),int(pack.size),int(pack.entry_count)]).ok_or(Errno::EIO)?;
        pins.insert(pack.pack_id, pin);
    }
    for (d, loc) in blocks {
        let pin = pins.get(&loc.pack_id).ok_or(Errno::EIO)?;
        let digest = hex(&d);
        let verified = string(
            db,
            "SELECT loc v FROM staged_pack_entries WHERE pin=? AND digest=? AND offset=?",
            vec![text(pin), text(&digest), int(loc.offset)],
        )
        .ok_or(Errno::EIO)?;
        if parse::<BlockLoc>(&verified)? != loc {
            return Err(Errno::EIO);
        }
        db.run(
            "INSERT OR IGNORE INTO staged_blocks VALUES(?,?,?)",
            vec![text(pin), text(&digest), int(loc.offset)],
        );
    }
    for (d, bytes) in nodes {
        if bytes.starts_with(&cowtree::COWFS_ROOT_MAGIC) {
            RootObject::decode_verified(&d, &bytes)?;
        } else {
            Node::decode_verified(&d, &bytes)?;
        }
        db.run(
            "INSERT OR REPLACE INTO staged_nodes VALUES(?,?,?,?,?,?)",
            vec![
                text(&v.0),
                int(lease.incarnation),
                int(lease.fence),
                text(&hex(&d)),
                text(&STANDARD.encode(bytes)),
                int(auth::now() + w::STAGING_PIN_TTL_SECS),
            ],
        );
    }
    Ok(Reply::Done)
}

/// Fold only provisional objects reached by this publication into its ordinary commit checks.
fn discover_staged(db: &Db, g: &Grant, r: &mut w::CommitRequest) -> VResult<()> {
    if number(
        db,
        "SELECT 1 n FROM staged_nodes WHERE volume=? AND incarnation=? AND fence=? LIMIT 1",
        vec![
            text(&r.volume.0),
            int(r.expected_incarnation),
            int(r.expected_fence),
        ],
    )
    .is_none()
    {
        return Ok(());
    }
    let mut work = vec![r.new_root];
    let mut found = HashSet::new();
    let mut blocks = HashSet::new();
    let mut packs: HashSet<_> = r.put_packs.iter().map(|p| p.pack_id.clone()).collect();
    let supplied: std::collections::HashMap<_, _> =
        r.put_nodes.iter().map(|(d, b)| (*d, b)).collect();
    work.extend(supplied.keys().copied());
    let mut extra = Vec::new();
    while let Some(d) = work.pop() {
        if !found.insert(d) {
            continue;
        }
        let staged;
        let bytes = if let Some(bytes) = supplied.get(&d) {
            bytes.as_slice()
        } else {
            let Some(encoded) = staged_node(db, g, &r.volume, &hex(&d)) else {
                continue;
            };
            staged = STANDARD.decode(encoded).map_err(|_| Errno::EIO)?;
            extra.push((d, staged.clone()));
            staged.as_slice()
        };
        if bytes.starts_with(&cowtree::COWFS_ROOT_MAGIC) {
            work.extend(
                RootObject::decode_verified(&d, bytes)?
                    .subvols
                    .into_values(),
            );
        } else {
            match Node::decode_verified(&d, bytes)? {
                Node::Internal { entries, .. } => work.extend(entries.into_iter().map(|e| e.child)),
                Node::Leaf { entries } => {
                    for e in entries {
                        if e.key.kind == cowtree::KIND_EXTENT_DATA
                            && let cowtree::node::ExtentDataValue::Extent { digest, .. } =
                                cowtree::node::ExtentDataValue::decode(&e.value)?
                            && blocks.insert(digest)
                            && let Some(loc) = staged_loc(db, g, &r.volume, &hex(&digest))?
                        {
                            if packs.insert(loc.pack_id.clone()) {
                                #[derive(Deserialize)]
                                struct Size {
                                    size: u32,
                                    entry_count: u32,
                                }
                                let p=db.rows::<Size>("SELECT size,entry_count FROM packs WHERE pack_id=? AND status!='deleting'",vec![text(&loc.pack_id.0)]).pop().ok_or(Errno::EIO)?;
                                r.put_packs.push(PackMeta {
                                    pack_id: loc.pack_id.clone(),
                                    size: p.size,
                                    entry_count: p.entry_count,
                                    created_at: now(),
                                });
                            }
                            r.put_blocks.push((digest, loc));
                        }
                    }
                }
            }
        }
    }
    r.put_nodes.extend(extra);
    Ok(())
}
fn publication_hash(r: &w::CommitRequest, snapshot: Option<&str>) -> VResult<Digest> {
    let bytes = match snapshot {
        Some(name) => json(&(r, name))?,
        None => json(r)?,
    };
    Ok(sha256(bytes.as_bytes()))
}
fn commit(
    db: &mut Db,
    g: &Grant,
    v: &VolumeId,
    mut r: w::CommitRequest,
    snapshot_name: Option<String>,
    receive: bool,
) -> VResult<Reply> {
    if r.volume != *v {
        return Err(Errno::EINVAL);
    }
    let hash = publication_hash(&r, snapshot_name.as_deref())?;
    if let Some(saved) = string(
        db,
        "SELECT payload_hash v FROM receipts WHERE volume=? AND op_id=?",
        vec![text(&v.0), text(&STANDARD.encode(r.op_id))],
    ) {
        if saved != hex(&hash) {
            return Err(Errno::EINVAL);
        }
        return match status(db, v, &r.op_id)? {
            w::Status::Committed(rec) => Ok(Reply::Receipt(rec)),
            w::Status::Aborted { errno } => Err(errno),
            _ => Err(Errno::EIO),
        };
    }
    let mut h = if receive {
        writer_head(db, v, g)?
    } else {
        head(db, v)?
    };
    verify_lease(
        db,
        &h,
        w::Fence {
            incarnation: r.expected_incarnation,
            fence: r.expected_fence,
        },
        g,
    )?;
    if h.epoch != r.expected_epoch {
        return Err(Errno::EAGAIN);
    }
    discover_staged(db, g, &mut r)?;
    let mut visible = visibility(db, g, v)?;
    let mut consumed = Vec::new();
    for p in &r.put_packs {
        let args = vec![
            text(&p.pack_id.0),
            text(&v.0),
            int(h.incarnation),
            int(h.fence),
            int(auth::now()),
        ];
        let pins = strings(
            db,
            "SELECT id v FROM staging_pins WHERE pack_id=? AND volume=? AND incarnation=? AND fence=? AND expires>? AND verified=1",
            args,
        );
        let sealed = number(
            db,
            "SELECT 1 n FROM packs WHERE pack_id=? AND status='sealed'",
            vec![text(&p.pack_id.0)],
        )
        .is_some();
        if pins.is_empty()
            && (!sealed
                || visible
                    .as_ref()
                    .is_some_and(|m| !m.packs.contains(&p.pack_id.0)))
        {
            return Err(Errno::EIO);
        }
        let sql = "SELECT 1 n FROM packs WHERE pack_id=? AND size=? AND entry_count=? AND status!='deleting'";
        let args = vec![text(&p.pack_id.0), int(p.size), int(p.entry_count)];
        if number(db, sql, args).is_none() {
            return Err(Errno::EIO);
        }
        db.run(
            "UPDATE packs SET status='sealed' WHERE pack_id=?",
            vec![text(&p.pack_id.0)],
        );
        consumed.extend(pins);
    }
    for (d, loc) in &r.put_blocks {
        loc.validate_v1()?;
        let key = hex(d);
        let existing = block(db, &key)?;
        let authorized = existing.as_ref() == Some(loc)
            && visible.as_ref().is_none_or(|m| m.blocks.contains(&key));
        if !authorized
            && !consumed.iter().any(|pin| {
                string(
                    db,
                    "SELECT loc v FROM staged_pack_entries WHERE pin=? AND digest=? AND offset=?",
                    vec![text(pin), text(&key), int(loc.offset)],
                )
                .and_then(|s| parse::<BlockLoc>(&s).ok())
                .as_ref()
                    == Some(loc)
            })
        {
            return Err(Errno::EIO);
        }
        db.run(
            "INSERT OR IGNORE INTO blocks VALUES(?,?,?)",
            vec![text(&key), text(&loc.pack_id.0), text(&json(loc)?)],
        );
        if let Some(m) = &mut visible {
            m.blocks.insert(key);
        }
    }
    verify_nodes(db, r.new_root, &r.put_nodes, visible.as_ref())?;
    for pin in consumed {
        db.run(
            "DELETE FROM staged_pack_entries WHERE pin=?",
            vec![text(&pin)],
        );
        db.run("DELETE FROM staging_pins WHERE id=?", vec![text(&pin)]);
    }
    if h.root != [0; 32] {
        grace(db, &h);
    }
    h.root = r.new_root;
    h.epoch = next(h.epoch)?;
    h.modified = true;
    h.updated_at = now();
    save(db, &h);
    db.run(
        "UPDATE schema_meta SET publication_seq=publication_seq+1",
        vec![],
    );
    if let Some(name) = snapshot_name {
        rpc(
            db,
            g,
            v,
            Op::CreateSnapshot {
                name,
                head: h.clone(),
            },
            None,
        )?;
    }
    let rec = w::Receipt {
        op_id: r.op_id,
        payload_hash: hash,
        head: h,
    };
    save_status(db, v, &r.op_id, &hash, &w::Status::Committed(rec.clone()))?;
    Ok(Reply::Receipt(rec))
}

fn begin(
    db: &mut Db,
    g: &Grant,
    v: &VolumeId,
    lease: w::Fence,
    p: &PackId,
    size: u32,
    quota: u64,
) -> VResult<String> {
    verify_lease(db, &writer_head(db, v, g)?, lease, g)?;
    digest_from_hex(&p.0)?;
    if size as usize > w::PACK_MAX_BYTES {
        return Err(Errno::EFBIG);
    }
    if number(
        db,
        "SELECT in_flight n FROM gc_pending_deletes WHERE pack_id=?",
        vec![text(&p.0)],
    ) == Some(1)
    {
        return Err(Errno::EAGAIN);
    }
    db.run(
        "DELETE FROM gc_pending_deletes WHERE pack_id=?",
        vec![text(&p.0)],
    );
    db.run(
        "UPDATE packs SET status='staged' WHERE pack_id=? AND status='deleting'",
        vec![text(&p.0)],
    );
    if let Some(existing) = number(
        db,
        "SELECT size n FROM packs WHERE pack_id=?",
        vec![text(&p.0)],
    ) {
        if existing != size as u64 {
            return Err(Errno::EIO);
        }
    } else {
        let used = number(
            db,
            "SELECT CAST(COALESCE(SUM(size),0) AS TEXT) n FROM packs",
            vec![],
        )
        .ok_or(Errno::EIO)?;
        if used.saturating_add(size.into()) > quota {
            return Err(Errno::EDQUOT);
        }
        db.run(
            "INSERT INTO packs(pack_id,size,entry_count,status,created_at) VALUES(?,?,0,'staged',?)",
            vec![text(&p.0), int(size), int(auth::now())],
        );
    }
    let id = auth::random_token();
    db.run(
        "INSERT INTO staging_pins VALUES(?,?,?,?,?,?,0)",
        vec![
            text(&id),
            text(&v.0),
            int(lease.incarnation),
            int(lease.fence),
            text(&p.0),
            int(auth::now() + w::STAGING_PIN_TTL_SECS),
        ],
    );
    Ok(id)
}
fn seal(
    db: &mut Db,
    g: &Grant,
    v: &VolumeId,
    lease: w::Fence,
    p: &PackId,
    id: &str,
    entries: Vec<PackIndexEntry>,
) -> VResult<PackMeta> {
    verify_lease(db, &writer_head(db, v, g)?, lease, g)?;
    let sql = "SELECT 1 n FROM staging_pins WHERE id=? AND volume=? AND incarnation=? AND fence=? AND pack_id=? AND expires>?";
    let args = vec![
        text(id),
        text(&v.0),
        int(lease.incarnation),
        int(lease.fence),
        text(&p.0),
        int(auth::now()),
    ];
    if number(db, sql, args).is_none() {
        return Err(Errno::ESTALE);
    }
    let size = number(
        db,
        "SELECT size n FROM packs WHERE pack_id=? AND status!='deleting'",
        vec![text(&p.0)],
    )
    .ok_or(Errno::ESTALE)? as u32;
    let entry_count = entries.len() as u32;
    for e in entries {
        let loc = BlockLoc {
            pack_id: p.clone(),
            offset: e.offset,
            len: e.len,
            raw_len: e.raw_len,
            flags: e.flags,
        };
        loc.validate_v1()?;
        db.run(
            "INSERT OR IGNORE INTO pack_entries VALUES(?,?,?,?)",
            vec![
                text(&p.0),
                int(e.offset),
                int(e.offset.checked_add(e.len).ok_or(Errno::EIO)?),
                text(&hex(&e.digest)),
            ],
        );
        db.run(
            "INSERT OR REPLACE INTO staged_pack_entries VALUES(?,?,?,?)",
            vec![
                text(id),
                text(&hex(&e.digest)),
                int(e.offset),
                text(&json(&loc)?),
            ],
        );
    }
    db.run(
        "UPDATE packs SET entry_count=? WHERE pack_id=?",
        vec![int(entry_count), text(&p.0)],
    );
    db.run(
        "UPDATE staging_pins SET verified=1,expires=? WHERE id=?",
        vec![int(auth::now() + w::STAGING_PIN_TTL_SECS), text(id)],
    );
    Ok(PackMeta {
        pack_id: p.clone(),
        size,
        entry_count,
        created_at: now(),
    })
}
fn abandon(db: &mut Db, v: &VolumeId, p: &PackId, id: &str) {
    db.run(
        "DELETE FROM staging_pins WHERE id=? AND pack_id=? AND volume=?",
        vec![text(id), text(&p.0), text(&v.0)],
    );
    db.run("DELETE FROM staged_pack_entries WHERE pin=? AND NOT EXISTS(SELECT 1 FROM staging_pins WHERE id=?)",vec![text(id),text(id)]);
    // A very slow stream can finish after its reservation was already swept. Queue the key
    // even if its old row is gone. Any other live uploader or committed head keeps it safe.
    let enqueue = "INSERT OR IGNORE INTO gc_pending_deletes SELECT ?1,0,COALESCE((SELECT retain_until FROM packs WHERE pack_id=?1),0)
                   WHERE NOT EXISTS(SELECT 1 FROM packs WHERE pack_id=?1 AND status='sealed')
                     AND NOT EXISTS(SELECT 1 FROM staging_pins WHERE pack_id=?1)";
    db.run(enqueue, vec![text(&p.0)]);
    let mark = "UPDATE packs SET status='deleting' WHERE pack_id=? AND pack_id IN(SELECT pack_id FROM gc_pending_deletes)";
    db.run(mark, vec![text(&p.0)]);
}
fn collect(db: &mut Db, retain: u64) -> VResult<CowfsGcResp> {
    let time = auth::now();
    let old = time.saturating_sub(w::GC_GRACE_WINDOW_SECS);
    db.run("INSERT OR IGNORE INTO gc_pending_deletes SELECT DISTINCT s.pack_id,0,MAX(p.retain_until,?1) FROM staging_pins s JOIN packs p USING(pack_id) WHERE s.verified=0 AND s.expires<=?1 AND p.status='staged' AND NOT EXISTS(SELECT 1 FROM staging_pins live WHERE live.pack_id=s.pack_id AND live.expires>?1)", vec![int(time)]);
    for table in [
        "writer_leases",
        "staging_pins",
        "staged_nodes",
        "grace_pins",
    ] {
        db.run(
            &format!("DELETE FROM {table} WHERE expires<=?"),
            vec![int(time)],
        );
    }
    db.run(
        "DELETE FROM staged_pack_entries WHERE pin NOT IN(SELECT id FROM staging_pins)",
        vec![],
    );
    let abandoned = strings(
        db,
        "SELECT volume v FROM volumes WHERE ephemeral=1 AND modified=0 AND updated_at<=? AND volume NOT IN(SELECT volume FROM writer_leases UNION SELECT volume FROM ro_pins WHERE expires>? UNION SELECT volume FROM snapshots)",
        vec![int(old), int(time)],
    );
    if !abandoned.is_empty() {
        let previous = checkpoint(db)?;
        for id in abandoned {
            clear_volume(db, &VolumeId(id));
        }
        advance(db, &previous)?;
    }
    db.run(
        "DELETE FROM staged_blocks WHERE pin NOT IN(SELECT id FROM staging_pins)",
        vec![],
    );
    let mut live = roots(db, None);
    let live_roots = live.len();
    live.extend(strings(
        db,
        "SELECT digest v FROM nodes WHERE created_at>?",
        vec![int(old)],
    ));
    let mut m = mark(db, live)?;
    m.packs
        .extend(strings(db, "SELECT pack_id v FROM staging_pins", vec![]));
    for n in strings(
        db,
        "SELECT digest v FROM nodes WHERE created_at<=?",
        vec![int(old)],
    ) {
        if !m.nodes.contains(&n) {
            db.run("DELETE FROM nodes WHERE digest=?", vec![text(&n)]);
            db.run("DELETE FROM node_edges WHERE parent=?", vec![text(&n)]);
            db.run("DELETE FROM node_blocks WHERE parent=?", vec![text(&n)]);
        }
    }
    db.run("DELETE FROM ro_pins WHERE expires<=? AND NOT EXISTS(SELECT 1 FROM nodes WHERE digest=ro_pins.root)", vec![int(time)]);
    let mut swept = Vec::new();
    for p in strings(
        db,
        "SELECT pack_id v FROM packs WHERE status!='deleting' AND (created_at<=? OR status='staged') ORDER BY pack_id",
        vec![int(old)],
    ) {
        if !m.packs.contains(&p) {
            let sealed = number(
                db,
                "SELECT 1 n FROM packs WHERE pack_id=? AND status='sealed'",
                vec![text(&p)],
            )
            .is_some();
            db.run("DELETE FROM blocks WHERE pack_id=?", vec![text(&p)]);
            db.run(
                "UPDATE packs SET status='deleting',retain_until=MAX(retain_until,?) WHERE pack_id=?",
                vec![int(if sealed {time + retain} else {time}),text(&p)],
            );
            db.run(
                "INSERT OR IGNORE INTO gc_pending_deletes SELECT pack_id,0,retain_until FROM packs WHERE pack_id=?",
                vec![text(&p)],
            );
            swept.push(p);
        }
    }
    for d in strings(
        db,
        "SELECT digest v FROM blocks JOIN packs USING(pack_id) WHERE created_at<=?",
        vec![int(old)],
    ) {
        if !m.blocks.contains(&d) {
            db.run("DELETE FROM blocks WHERE digest=?", vec![text(&d)]);
        }
    }
    db.run(
        "INSERT OR REPLACE INTO gc_state VALUES(1,?)",
        vec![int(time)],
    );
    Ok(CowfsGcResp {
        live_roots,
        live_nodes: m.nodes.len(),
        live_blocks: m.blocks.len(),
        live_packs: m.packs.len(),
        swept_packs: swept,
    })
}
