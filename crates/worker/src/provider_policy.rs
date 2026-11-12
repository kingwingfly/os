//! Durable account admission/lifetime preferences for the existing container devices.
//! Browser execution and remote task lifetime are distinct; no public task ID is authority.
use crate::db::{Db, int, text};
use abi::{Errno, Error, accelerator::ProviderPolicy};
use serde::Deserialize;
pub fn create(sql: &worker::SqlStorage) -> worker::Result<()> {
    sql.exec("CREATE TABLE IF NOT EXISTS provider_policies(uid INTEGER PRIMARY KEY,policy TEXT NOT NULL)",None)?;
    sql.exec("CREATE TRIGGER IF NOT EXISTS provider_policy_remove AFTER DELETE ON users BEGIN DELETE FROM provider_policies WHERE uid=old.id; END",None)?;
    Ok(())
}
impl Db {
    pub fn provider_policy(&self, uid: u32) -> Result<ProviderPolicy, Error> {
        #[derive(Deserialize)]
        struct Stored {
            policy: String,
        }
        self.rows::<Stored>(
            "SELECT policy FROM provider_policies WHERE uid=?",
            vec![int(uid)],
        )
        .pop()
        .map(|s| serde_json::from_str(&s.policy).map_err(|_| Errno::EIO.into()))
        .unwrap_or_else(|| Ok(ProviderPolicy::default()))
    }
    pub fn configure_provider(
        &mut self,
        uid: u32,
        mut policy: ProviderPolicy,
    ) -> Result<ProviderPolicy, Error> {
        policy.validate()?;
        if self.provider_policy(uid)?.revision != policy.revision {
            return Err(Errno::ESTALE.into());
        }
        policy.revision += 1;
        self.run("INSERT INTO provider_policies(uid,policy) VALUES(?,?) ON CONFLICT(uid) DO UPDATE SET policy=excluded.policy",vec![int(uid),text(&serde_json::to_string(&policy).unwrap())]);
        Ok(policy)
    }
    pub fn provider_deadline(&self, id: &str) -> Option<u64> {
        self.expiry("provider_deadline", id)
    }
}
