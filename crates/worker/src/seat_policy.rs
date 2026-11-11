//! Account preferences persist across login/host replacement. Revisions fence updates;
//! cookies and the exact login context authorize them. No preference grants a device.
use crate::db::{Db, int, text};
use abi::{Errno, Error, SeatPolicy, SharingMode};
use serde::Deserialize;
use worker::SqlStorage;
pub fn create(sql: &SqlStorage) -> worker::Result<()> {
    sql.exec("CREATE TABLE IF NOT EXISTS seat_policies(ns TEXT NOT NULL,uid INTEGER NOT NULL,policy TEXT NOT NULL,PRIMARY KEY(ns,uid))",None)?;
    Ok(())
}
impl Db {
    pub fn seat_policy(&self, ns: &str, uid: u32) -> Result<SeatPolicy, Error> {
        #[derive(Deserialize)]
        struct Stored {
            policy: String,
        }
        self.rows::<Stored>(
            "SELECT policy FROM seat_policies WHERE ns=? AND uid=?",
            vec![text(ns), int(uid)],
        )
        .pop()
        .map(|v| serde_json::from_str(&v.policy).map_err(|_| Errno::EIO.into()))
        .unwrap_or_else(|| Ok(SeatPolicy::default()))
    }
    pub fn set_seat_policy(
        &mut self,
        ns: &str,
        uid: u32,
        expected: u64,
        sharing: SharingMode,
    ) -> Result<(), Error> {
        let current = self.seat_policy(ns, uid)?;
        if current.revision != expected {
            return Err(Errno::ESTALE.into());
        }
        if expected >= (1u64 << 53) - 1 {
            return Err(Errno::ENOSPC.into());
        }
        #[derive(Deserialize)]
        struct Count {
            n: u32,
        }
        if current.revision == 0
            && self.rows::<Count>(
                "SELECT COUNT(*) AS n FROM seat_policies WHERE ns=?",
                vec![text(ns)],
            )[0]
            .n >= 32
        {
            return Err(Errno::ENOSPC.into());
        }
        let policy = SeatPolicy {
            revision: expected + 1,
            sharing,
        };
        self.run("INSERT INTO seat_policies(ns,uid,policy) VALUES(?,?,?) ON CONFLICT(ns,uid) DO UPDATE SET policy=excluded.policy",vec![text(ns),int(uid),text(&serde_json::to_string(&policy).unwrap())]);
        Ok(())
    }
}
