//! Persist init host ownership independently of login records and process credentials.
use crate::{
    auth,
    db::{Db, int, text},
};
use abi::{Errno, Error, InitAction};
use kernel::init::Init;
use serde::Deserialize;
use serde_json::Value;
use worker::{SqlStorage, SqlStorageValue};

pub fn create(sql: &SqlStorage) -> worker::Result<()> {
    sql.exec("CREATE TABLE IF NOT EXISTS init_owner(ns TEXT PRIMARY KEY, boot TEXT NOT NULL, deadline INTEGER, state TEXT NOT NULL)", None)?;
    Ok(())
}
#[derive(Deserialize)]
struct Row {
    ns: String,
    state: String,
}
impl Db {
    pub(crate) fn ensure_init_owner(&mut self, ns: &str, now: u64) {
        if self.machine_boot(ns).is_some() {
            return;
        }
        let init = Init::new(auth::random_token(), now);
        self.run(
            "INSERT OR IGNORE INTO init_owner(ns, boot, deadline, state) VALUES(?, ?, NULL, ?)",
            vec![
                text(ns),
                text(&init.boot),
                text(&serde_json::to_string(&init).unwrap()),
            ],
        );
    }
    pub(crate) fn machine_boot(&self, ns: &str) -> Option<String> {
        #[derive(Deserialize)]
        struct Boot {
            boot: String,
        }
        self.rows::<Boot>("SELECT boot FROM init_owner WHERE ns = ?", vec![text(ns)])
            .pop()
            .map(|row| row.boot)
    }
    fn save_init(&mut self, ns: &str, init: &Init) {
        self.run(
            "UPDATE init_owner SET deadline = ?, state = ?, boot = ? WHERE ns = ?",
            vec![
                init.deadline().map_or(SqlStorageValue::Null, int),
                text(&serde_json::to_string(init).unwrap()),
                text(&init.boot),
                text(ns),
            ],
        );
    }
    fn load_init(&self, ns: &str) -> Option<Init> {
        self.rows::<Row>(
            "SELECT ns, state FROM init_owner WHERE ns = ?",
            vec![text(ns)],
        )
        .pop()
        .and_then(|row| serde_json::from_str(&row.state).ok())
    }
    pub(crate) fn init_active(&self, ns: &str) -> bool {
        self.load_init(ns)
            .is_some_and(|init| init.active(auth::now()))
    }
    pub(crate) fn init_token(&self, ns: &str, hash: &str, now: u64) -> bool {
        self.load_init(ns)
            .is_some_and(|init| init.running(hash, now))
    }
    /// Called in the same transaction that authenticated the active PID 1 proof.
    pub(crate) fn finish_init(&mut self, ns: &str) {
        if let Some(mut init) = self.load_init(ns) {
            init.finish();
            self.save_init(ns, &init);
        }
    }
    pub(crate) fn init_reaped(&mut self, ns: &str) {
        if let Some(mut init) = self.load_init(ns) {
            init.reaped();
            self.save_init(ns, &init);
        }
    }
    pub fn machine_init(&mut self, ns: &str, action: InitAction, now: u64) -> Result<Value, Error> {
        self.ensure_namespace(ns, now);
        let row = self
            .rows::<Row>(
                "SELECT ns, state FROM init_owner WHERE ns = ?",
                vec![text(ns)],
            )
            .pop()
            .ok_or(Errno::EIO)?;
        let mut init: Init =
            serde_json::from_str(&row.state).map_err(|_| Error::from(Errno::EIO))?;
        let hash = match &action {
            InitAction::Inspect | InitAction::Reboot { .. } => String::new(),
            InitAction::Claim { owner }
            | InitAction::Renew { owner }
            | InitAction::Release { owner }
            | InitAction::Start { owner, .. } => {
                if owner.proof.len() != 64 || !owner.proof.bytes().all(|c| c.is_ascii_hexdigit()) {
                    return Err(Errno::EINVAL.into());
                }
                auth::token_hash(&owner.proof)
            }
        };
        let first_stop = init.shutdown.is_none() && matches!(action, InitAction::Reboot { .. });
        init.apply(&action, &hash, now)?;
        if first_stop {
            self.stop_scope(ns, None, now);
        }
        if let InitAction::Start { token, .. } = &action {
            if token.len() != 64 || !token.bytes().all(|c| c.is_ascii_hexdigit()) {
                return Err(Errno::EINVAL.into());
            }
            let hash = auth::token_hash(token);
            init.start(&hash)?;
            // No credential is issued by the filesystem authority. This proof is accepted
            // only for PID 1 bookkeeping, fenced by the live owner generation on every use.
            // Never put a boot proof in the ordinary process-token column. Even code
            // using that column without the boot policy cannot interpret it as root.
            self.run("UPDATE processes SET token = ?, path = '/usr/bin/init', argv = '[\"init\"]', execed = 1 WHERE ns = ? AND pid = 1",
                vec![text(&auth::token_hash(&auth::random_token())), text(ns)]);
        }
        self.advance_reboot(ns, &mut init, now);
        self.save_init(ns, &init);
        Ok(init.view())
    }
    pub(crate) fn admit_boot(&self, ns: &str) -> Result<(), Error> {
        if self
            .load_init(ns)
            .is_some_and(|init| init.shutdown.is_some())
        {
            return Err(Error::because(Errno::EBUSY, "this Machine is restarting"));
        }
        Ok(())
    }
    fn advance_reboot(&mut self, ns: &str, init: &mut Init, now: u64) {
        if init
            .shutdown
            .as_ref()
            .is_some_and(|s| self.drain_scope(ns, None, s.due(now), now))
        {
            self.finish_reboot(ns, now);
            *init = Init::new(auth::random_token(), now);
        }
    }
    pub fn expire_init(&mut self, now: u64) {
        for row in self.rows::<Row>(
            "SELECT ns, state FROM init_owner WHERE deadline <= ?",
            vec![int(now)],
        ) {
            if let Ok(mut init) = serde_json::from_str::<Init>(&row.state) {
                init.expire(now);
                self.advance_reboot(&row.ns, &mut init, now);
                self.save_init(&row.ns, &init);
            }
        }
    }
    pub fn init_deadline(&self) -> Option<u64> {
        #[derive(Deserialize)]
        struct Deadline {
            deadline: Option<u64>,
        }
        self.rows::<Deadline>("SELECT MIN(deadline) AS deadline FROM init_owner", vec![])
            .first()
            .and_then(|row| row.deadline)
    }
}
