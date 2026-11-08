//! Signed-out browsers as accounts (owner's decision, 2026-11-01): each browser's guest cookie
//! names a stable `guest-<uuid>:guest`, with a uid of its own from a reserved anonymous range,
//! so that what it makes in the shared /guest is its own, and /etc/passwd can name it. No home
//! is made for it until a real `useradd` does; `HOME` stays the shared /guest.
use crate::db::{Db, int, text};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use os_core::permissions::{GUEST, GUEST_HOME, GUEST_UID_MAX, GUEST_UID_MIN, Identity, User};
use serde::Deserialize;
use std::collections::BTreeSet;

/// The uids signed-out browsers draw from, below the accounts a system makes.
pub const UID_MIN: u32 = GUEST_UID_MIN;
pub const UID_MAX: u32 = GUEST_UID_MAX;
/// How often a guest's last sight is written down, in seconds.
const SEEN_EVERY: u64 = 60 * 60;

#[derive(Clone, Debug, PartialEq)]
pub struct Guest {
    pub key: String,
    pub uuid: String,
    pub uid: u32,
    pub gid: u32,
    pub created: u64,
    pub last_seen: u64,
}
impl Guest {
    pub fn name(&self) -> String {
        format!("guest-{}", self.uuid)
    }
    /// The account's identity: its own uid, group guest.
    pub fn identity(&self) -> Identity {
        Identity {
            id: self.uid,
            group: self.gid,
            groups: BTreeSet::from([self.gid]),
        }
    }
    /// Its account, as who owns a file is named and as /etc/passwd tells it. It has the shared
    /// /guest as home, and no password: it cannot be signed in to.
    pub fn user(&self) -> User {
        User {
            id: self.uid,
            group: self.gid,
            groups: BTreeSet::new(),
            home: GUEST_HOME.into(),
            locked: false,
            salt: String::new(),
            hash: String::new(),
        }
    }
}

#[derive(Deserialize)]
struct Row {
    key: String,
    uuid: String,
    uid: u32,
    gid: u32,
    created: u64,
    last_seen: u64,
}
impl Row {
    fn guest(self) -> Guest {
        Guest {
            key: self.key,
            uuid: self.uuid,
            uid: self.uid,
            gid: self.gid,
            created: self.created,
            last_seen: self.last_seen,
        }
    }
}

/// The uuid a guest shows, from the hash its cookie key is: the first 16 hexadecimal digits of
/// the SHA-256 of the cookie's token, as the key holds it.
pub fn uuid_of(key: &str) -> String {
    let digest = key
        .strip_prefix("guest.")
        .and_then(|encoded| URL_SAFE_NO_PAD.decode(encoded).ok())
        .unwrap_or_default();
    digest
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

impl Db {
    /// The guest of `key`, if this browser has been here.
    pub fn guest(&self, key: &str) -> Option<Guest> {
        self.rows::<Row>(
            "SELECT key, uuid, uid, gid, created, last_seen FROM guests WHERE key = ?",
            vec![text(key)],
        )
        .into_iter()
        .next()
        .map(Row::guest)
    }
    /// The guest `uid` owns files as, if it is one.
    pub fn guest_by_uid(&self, uid: u32) -> Option<Guest> {
        self.rows::<Row>(
            "SELECT key, uuid, uid, gid, created, last_seen FROM guests WHERE uid = ?",
            vec![int(uid)],
        )
        .into_iter()
        .next()
        .map(Row::guest)
    }
    /// Every guest this store has seen, oldest first.
    pub fn guests(&self) -> Vec<Guest> {
        self.rows::<Row>(
            "SELECT key, uuid, uid, gid, created, last_seen FROM guests ORDER BY uid",
            vec![],
        )
        .into_iter()
        .map(Row::guest)
        .collect()
    }
    /// The guest of `key`, made if this browser has not been here: its uuid from the key, and
    /// the first free uid of the anonymous range (EMFILE if there is none, as a full table is).
    pub fn ensure_guest(&mut self, key: &str, now: u64) -> Option<Guest> {
        let last = self
            .meta("guest_prune_at")
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        if now >= last + SEEN_EVERY {
            if self.meta("next_guest_uid").is_none() {
                #[derive(Deserialize)]
                struct Highest {
                    uid: Option<u32>,
                }
                let highest = self
                    .rows::<Highest>("SELECT MAX(uid) AS uid FROM guests", vec![])
                    .into_iter()
                    .next()
                    .and_then(|row| row.uid)
                    .unwrap_or(UID_MIN - 1);
                self.set_meta("next_guest_uid", &(highest + 1).to_string());
            }
            // Never recycle an identity still attached to files, open credentials or jobs.
            self.run("DELETE FROM guests WHERE last_seen < ? AND NOT EXISTS (SELECT 1 FROM inodes WHERE owner = guests.uid) AND NOT EXISTS (SELECT 1 FROM credentials WHERE uid = guests.uid AND expires > ?) AND NOT EXISTS (SELECT 1 FROM jobs WHERE owner = guests.uid OR actor = guests.uid)", vec![int(now.saturating_sub(30 * 24 * 3600)), int(now)]);
            self.set_meta("guest_prune_at", &now.to_string());
        }
        if let Some(guest) = self.guest(key) {
            // When it was last seen is kept to the hour: not a write on every request.
            if guest.last_seen + SEEN_EVERY > now {
                return Some(guest);
            }
            self.run(
                "UPDATE guests SET last_seen = ? WHERE key = ?",
                vec![int(now), text(key)],
            );
            return Some(Guest {
                last_seen: now,
                ..guest
            });
        }
        let uid = self.next_guest_uid()?;
        let uuid = uuid_of(key);
        let gid = GUEST;
        self.run(
            "INSERT INTO guests(key, uuid, uid, gid, created, last_seen) VALUES(?, ?, ?, ?, ?, ?)",
            vec![
                text(key),
                text(&uuid),
                int(uid),
                int(gid),
                int(now),
                int(now),
            ],
        );
        Some(Guest {
            key: key.into(),
            uuid,
            uid,
            gid,
            created: now,
            last_seen: now,
        })
    }
    fn next_guest_uid(&mut self) -> Option<u32> {
        #[derive(Deserialize)]
        struct Next {
            uid: Option<u32>,
        }
        let highest = self
            .rows::<Next>("SELECT MAX(uid) AS uid FROM guests", vec![])
            .into_iter()
            .next()
            .and_then(|row| row.uid)
            .unwrap_or(UID_MIN - 1);
        // A pruned uid may still appear in somebody else's named ACL. Never give it to a
        // different browser; the high-water mark survives pruning, including an empty table.
        let next = self
            .meta("next_guest_uid")
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(UID_MIN)
            .max(highest + 1);
        if next > UID_MAX {
            return None;
        }
        self.set_meta("next_guest_uid", &(next + 1).to_string());
        Some(next)
    }
    /// The identity of the guest `key`, made if new.
    pub fn guest_identity(&mut self, key: &str, now: u64) -> Identity {
        self.ensure_guest(key, now)
            .map(|guest| guest.identity())
            .unwrap_or_else(Identity::guest)
    }
}
