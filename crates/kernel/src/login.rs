//! Durable login-session membership and coordinator fencing. Coordination alone grants
//! no resource authority; a managed process requires a separate explicit process proof.
//! The store authenticates the login and process before entry here.
use abi::{Errno, Error};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const LEASE: u64 = 30;
pub const HOSTS_MAX: usize = 64;

#[derive(Clone, Serialize, Deserialize)]
struct Member {
    hash: String,
    expires: u64,
}
#[derive(Clone, Serialize, Deserialize)]
struct Owner {
    host: String,
    expires: u64,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Managed {
    pub pid: u32,
    pub host: String,
    pub generation: u64,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub uid: u32,
    pub created: u64,
    pub expires: u64,
    generation: u64,
    observed: u64,
    hosts: BTreeMap<String, Member>,
    owner: Option<Owner>,
    #[serde(default)]
    pub managed: Option<Managed>,
    #[serde(default)]
    pub startup: Option<crate::startup::Startup>,
    #[serde(default)]
    pub shutdown: Option<crate::lifecycle::Shutdown>,
}
type Result<T> = std::result::Result<T, Error>;

impl Session {
    pub fn new(id: String, uid: u32, expires: u64, now: u64) -> Self {
        Self {
            id,
            uid,
            created: now,
            expires,
            generation: 0,
            observed: now,
            hosts: BTreeMap::new(),
            owner: None,
            managed: None,
            startup: None,
            shutdown: None,
        }
    }
    pub fn expire(&mut self, now: u64) {
        self.observed = self.observed.max(now);
        self.hosts
            .retain(|_, host| host.expires > self.observed && self.expires > self.observed);
        if self.owner.as_ref().is_some_and(|owner| {
            owner.expires <= self.observed || !self.hosts.contains_key(&owner.host)
        }) {
            self.owner = None;
        }
        if let Some(startup) = &mut self.startup {
            startup.expire_owner(
                self.owner.as_ref().map(|owner| owner.host.as_str()),
                self.generation,
            );
        }
    }
    pub fn idle(&self) -> bool {
        self.hosts.is_empty()
            && self.managed.is_none()
            && self.startup.is_none()
            && self.shutdown.is_none()
    }
    pub fn deadline(&self) -> u64 {
        if let Some(shutdown) = &self.shutdown
            && !shutdown.complete
        {
            return shutdown.deadline;
        }
        self.hosts
            .values()
            .map(|host| host.expires)
            .chain(self.owner.iter().map(|owner| owner.expires))
            .chain([self.expires])
            .chain(
                self.shutdown
                    .as_ref()
                    .filter(|s| !s.complete)
                    .map(|s| s.deadline),
            )
            .min()
            .unwrap()
    }
    fn until(&self) -> Result<u64> {
        if self.expires <= self.observed {
            return Err(Errno::ESTALE.into());
        }
        Ok(self.observed.saturating_add(LEASE).min(self.expires))
    }
    pub fn join(&mut self, host: &str, hash: &str) -> Result<()> {
        if host.is_empty()
            || host.len() > 128
            || !host
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
        {
            return Err(Errno::EINVAL.into());
        }
        if let Some(member) = self.hosts.get(host) {
            if member.hash != hash {
                return Err(Errno::EACCES.into());
            }
        } else if self.hosts.len() >= HOSTS_MAX {
            return Err(Errno::ENOSPC.into());
        }
        self.hosts.insert(
            host.into(),
            Member {
                hash: hash.into(),
                expires: self.until()?,
            },
        );
        Ok(())
    }
    fn member(&self, host: &str, hash: &str) -> Result<()> {
        let member = self.hosts.get(host).ok_or(Error::from(Errno::ESTALE))?;
        if member.hash != hash {
            return Err(Errno::EACCES.into());
        }
        Ok(())
    }
    pub fn keep(&mut self, host: &str, hash: &str) -> Result<()> {
        self.member(host, hash)?;
        let expires = self.until()?;
        self.hosts.get_mut(host).unwrap().expires = expires;
        Ok(())
    }
    pub fn claim(&mut self, host: &str, hash: &str, generation: u64) -> Result<()> {
        if self.shutdown.is_some() {
            return Err(Errno::EBUSY.into());
        }
        self.member(host, hash)?;
        if generation != self.generation {
            return Err(Errno::ESTALE.into());
        }
        if let Some(owner) = &self.owner {
            if owner.host != host {
                return Err(Errno::EBUSY.into());
            }
        } else {
            // Bound the public generation to exact JavaScript integers.
            if self.generation >= (1_u64 << 53) - 1 {
                return Err(Errno::ENOSPC.into());
            }
            self.generation += 1;
        }
        self.owner = Some(Owner {
            host: host.into(),
            expires: self.until()?,
        });
        self.keep(host, hash)
    }
    pub fn renew(&mut self, host: &str, hash: &str, generation: u64) -> Result<()> {
        self.authorize(host, hash, generation)?;
        self.owner.as_mut().unwrap().expires = self.until()?;
        self.keep(host, hash)
    }
    /// Check ownership without extending either lease. Process authority is checked separately.
    pub fn authorize(&self, host: &str, hash: &str, generation: u64) -> Result<()> {
        if self.shutdown.is_some() {
            return Err(Errno::EBUSY.into());
        }
        self.member(host, hash)?;
        if generation != self.generation
            || self.owner.as_ref().is_none_or(|owner| owner.host != host)
        {
            return Err(Errno::ESTALE.into());
        }
        Ok(())
    }
    pub fn attach(&mut self, host: &str, hash: &str, generation: u64, pid: u32) -> Result<()> {
        if self
            .startup
            .as_ref()
            .is_some_and(|startup| startup.reserved())
        {
            return Err(Errno::EBUSY.into());
        }
        self.attach_process(host, hash, generation, pid)
    }
    pub fn attach_startup(
        &mut self,
        host: &str,
        hash: &str,
        generation: u64,
        pid: u32,
        revision: &str,
        proof_hash: &str,
    ) -> Result<()> {
        self.startup
            .as_ref()
            .ok_or(Error::from(Errno::ESTALE))?
            .check(host, generation, revision, proof_hash)?;
        self.attach_process(host, hash, generation, pid)?;
        self.startup.as_mut().unwrap().attached(pid);
        Ok(())
    }
    fn attach_process(&mut self, host: &str, hash: &str, generation: u64, pid: u32) -> Result<()> {
        self.authorize(host, hash, generation)?;
        if let Some(managed) = &self.managed {
            // Retrying a lost reply is harmless; takeover cannot relabel a live run.
            if managed.pid == pid && managed.host == host && managed.generation == generation {
                return Ok(());
            }
            return Err(Errno::EBUSY.into());
        }
        self.managed = Some(Managed {
            pid,
            host: host.into(),
            generation,
        });
        Ok(())
    }
    pub fn signal(&self, host: &str, hash: &str, generation: u64, pid: u32) -> Result<()> {
        self.authorize(host, hash, generation)?;
        if self
            .managed
            .as_ref()
            .is_none_or(|managed| managed.pid != pid)
        {
            return Err(Errno::ESTALE.into());
        }
        Ok(())
    }
    pub fn leave(&mut self, host: &str, hash: &str) -> Result<()> {
        self.member(host, hash)?;
        self.hosts.remove(host);
        if self.owner.as_ref().is_some_and(|owner| owner.host == host) {
            self.owner = None;
        }
        Ok(())
    }
    pub fn end(&mut self, expected: &str) -> Result<bool> {
        if expected != self.id {
            return Err(Errno::ESTALE.into());
        }
        if self.shutdown.is_some() {
            return Ok(false);
        }
        self.shutdown = Some(crate::lifecycle::Shutdown::new(self.observed));
        self.owner = None;
        if let Some(startup) = &mut self.startup {
            startup.disable();
        }
        Ok(true)
    }
    /// Public metadata never serializes membership hashes or the cookie binding.
    pub fn view(&self) -> Value {
        json!({"id": self.id, "uid": self.uid, "created": self.created, "expires": self.expires,
            "now": self.observed, "generation": self.generation, "lease": LEASE,
            "owner": self.owner.as_ref().map(|owner| &owner.host),
            "owner_expires": self.owner.as_ref().map(|owner| owner.expires),
            "managed": self.managed,
            "shutdown": self.shutdown,
            "startup": self.startup.as_ref().map(|startup| startup.view()),
            "hosts": self.hosts.iter().map(|(host, member)| json!({"host":host,"expires":member.expires})).collect::<Vec<_>>()})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_shutdown_is_fenced_idempotent_and_disables_admission() {
        let mut s = session();
        s.join("host", "proof").unwrap();
        s.claim("host", "proof", 0).unwrap();
        assert_eq!(s.end("stale").unwrap_err().errno, Errno::ESTALE);
        assert!(s.end("session").unwrap());
        let deadline = s.shutdown.as_ref().unwrap().deadline;
        s.expire(110);
        assert!(!s.end("session").unwrap());
        assert_eq!(s.shutdown.as_ref().unwrap().deadline, deadline);
        assert_eq!(s.claim("host", "proof", 1).unwrap_err().errno, Errno::EBUSY);
        assert_eq!(
            s.authorize("host", "proof", 1).unwrap_err().errno,
            Errno::EBUSY
        );
        s.keep("host", "proof").unwrap();
        assert!(!s.idle());
        assert!(s.view()["owner"].is_null());
        assert!(!s.view().to_string().contains("proof"));
    }
    fn session() -> Session {
        Session::new("session".into(), 1000, 1000, 100)
    }
    #[test]
    fn startup_reservation_requires_its_private_attempt_and_retains_a_receipt() {
        let mut s = session();
        let mut old = serde_json::to_value(&s).unwrap();
        old.as_object_mut().unwrap().remove("startup");
        let loaded: Session = serde_json::from_value(old).unwrap();
        assert!(loaded.startup.is_none());
        s.join("one", "member").unwrap();
        s.claim("one", "member", 0).unwrap();
        s.startup = Some(crate::startup::Startup::new(
            crate::startup::Profile::new("r".into(), "/units.json".into()).unwrap(),
        ));
        s.startup
            .as_mut()
            .unwrap()
            .begin("one", 1, "r", "attempt")
            .unwrap();
        assert_eq!(
            s.attach("one", "member", 1, 42).unwrap_err().errno,
            Errno::EBUSY
        );
        assert_eq!(
            s.attach_startup("one", "member", 1, 42, "r", "wrong")
                .unwrap_err()
                .errno,
            Errno::ESTALE
        );
        s.attach_startup("one", "member", 1, 42, "r", "attempt")
            .unwrap();
        s.attach_startup("one", "member", 1, 42, "r", "attempt")
            .unwrap();
        s.managed = None;
        s.startup
            .as_mut()
            .unwrap()
            .finish("r", "attempt", 0, None)
            .unwrap();
        s.leave("one", "member").unwrap();
        assert!(!s.idle());
        assert!(!s.view().to_string().contains("attempt\""));
    }
    #[test]
    fn managed_process_survives_takeover_but_controls_require_the_new_owner() {
        let mut s = session();
        s.join("one", "key1").unwrap();
        s.join("two", "key2").unwrap();
        s.claim("one", "key1", 0).unwrap();
        s.attach("one", "key1", 1, 42).unwrap();
        s.attach("one", "key1", 1, 42).unwrap();
        assert_eq!(
            s.attach("one", "key1", 1, 43).unwrap_err().errno,
            Errno::EBUSY
        );
        assert_eq!(
            s.signal("one", "forged", 1, 42).unwrap_err().errno,
            Errno::EACCES
        );
        assert_eq!(
            s.signal("one", "key1", 1, 43).unwrap_err().errno,
            Errno::ESTALE
        );
        s.leave("one", "key1").unwrap();
        s.claim("two", "key2", 1).unwrap();
        s.join("one", "key1").unwrap();
        assert_eq!(
            s.signal("one", "key1", 1, 42).unwrap_err().errno,
            Errno::ESTALE
        );
        s.signal("two", "key2", 2, 42).unwrap();
        assert_eq!(
            s.attach("two", "key2", 2, 42).unwrap_err().errno,
            Errno::EBUSY
        );
        assert_eq!(s.view()["managed"]["host"], "one");
        assert_eq!(s.view()["managed"]["generation"], 1);
    }
    #[test]
    fn managed_controls_do_not_renew_leases_or_allow_idle_eviction() {
        let mut s = session();
        s.join("one", "key").unwrap();
        s.claim("one", "key", 0).unwrap();
        s.expire(120);
        s.attach("one", "key", 1, 42).unwrap();
        s.signal("one", "key", 1, 42).unwrap();
        assert_eq!(s.deadline(), 130);
        let mut s: Session = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        s.expire(130);
        assert!(!s.idle());
        assert_eq!(
            s.signal("one", "key", 1, 42).unwrap_err().errno,
            Errno::ESTALE
        );
        s.managed = None;
        assert!(s.idle());
        let mut old = serde_json::to_value(&s).unwrap();
        old.as_object_mut().unwrap().remove("managed");
        assert!(
            serde_json::from_value::<Session>(old)
                .unwrap()
                .managed
                .is_none()
        );
    }
    #[test]
    fn controller_is_exclusive_and_old_generations_cannot_renew_after_takeover() {
        let mut s = session();
        s.join("one", "key1").unwrap();
        s.join("two", "key2").unwrap();
        s.claim("one", "key1", 0).unwrap();
        assert_eq!(s.claim("two", "key2", 0).unwrap_err().errno, Errno::ESTALE);
        assert_eq!(s.claim("two", "key2", 1).unwrap_err().errno, Errno::EBUSY);
        s.expire(120);
        s.keep("two", "key2").unwrap();
        s.expire(130);
        s.claim("two", "key2", 1).unwrap();
        s.join("one", "key1").unwrap();
        assert_eq!(s.renew("one", "key1", 1).unwrap_err().errno, Errno::ESTALE);
        assert_eq!(s.view()["generation"], 2);
    }
    #[test]
    fn names_do_not_authenticate_and_metadata_excludes_hashes() {
        let mut s = session();
        s.join("one", "private").unwrap();
        assert_eq!(s.join("one", "forged").unwrap_err().errno, Errno::EACCES);
        assert_eq!(
            s.claim("one", "forged", 0).unwrap_err().errno,
            Errno::EACCES
        );
        assert_eq!(s.leave("one", "forged").unwrap_err().errno, Errno::EACCES);
        assert!(!s.view().to_string().contains("private"));
    }
    #[test]
    fn durable_round_trip_keeps_fences_and_expired_owners_cannot_resurrect() {
        let mut s = session();
        s.join("one", "key").unwrap();
        s.claim("one", "key", 0).unwrap();
        let mut s: Session = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        s.expire(130);
        s.expire(110);
        assert_eq!(s.renew("one", "key", 1).unwrap_err().errno, Errno::ESTALE);
        assert!(s.view()["owner"].is_null());
        s.join("one", "key").unwrap();
        s.claim("one", "key", 1).unwrap();
        assert_eq!(s.view()["generation"], 2);
    }
    #[test]
    fn membership_capacity_recovers_and_session_expiry_is_final() {
        let mut s = session();
        for i in 0..HOSTS_MAX {
            s.join(&format!("host{i}"), "key").unwrap();
        }
        assert_eq!(s.join("extra", "key").unwrap_err().errno, Errno::ENOSPC);
        s.expire(130);
        s.join("extra", "key").unwrap();
        s.claim("extra", "key", 0).unwrap();
        s.expire(1000);
        assert_eq!(s.join("extra", "key").unwrap_err().errno, Errno::ESTALE);
        assert!(s.idle());
    }
}
