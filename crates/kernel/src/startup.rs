//! Durable admission of one automatic service run per login/configuration revision.
//! The launch proof conveys completion authority only; process credentials stay separate.
use abi::{Errno, Error};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

type Result<T> = std::result::Result<T, Error>;
#[derive(Clone, Serialize, Deserialize)]
pub struct Profile {
    pub revision: String,
    pub file: String,
}
impl Profile {
    pub fn new(revision: String, file: String) -> Result<Self> {
        if !file.starts_with('/') || file.contains('\0') || file.len() > 4096 {
            return Err(Errno::EINVAL.into());
        }
        Ok(Self { revision, file })
    }
}
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Pending,
    Starting,
    Running,
    Finished,
}
#[derive(Clone, Serialize, Deserialize)]
struct Attempt {
    host: String,
    generation: u64,
    hash: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Startup {
    pub profile: Profile,
    enabled: bool,
    phase: Phase,
    attempts: u8,
    attempt: Option<Attempt>,
    pub pid: Option<u32>,
    status: Option<i32>,
    error: Option<String>,
}
impl Startup {
    pub fn new(profile: Profile) -> Self {
        Self {
            profile,
            enabled: true,
            phase: Phase::Pending,
            attempts: 0,
            attempt: None,
            pid: None,
            status: None,
            error: None,
        }
    }
    pub fn disable(&mut self) {
        self.enabled = false;
        if matches!(self.phase, Phase::Pending | Phase::Starting) {
            self.phase = Phase::Finished;
            self.attempt = None;
            self.error = Some("automatic startup disabled".into());
        }
    }
    pub fn reserved(&self) -> bool {
        self.phase == Phase::Starting
    }
    pub fn expire_owner(&mut self, owner: Option<&str>, generation: u64) {
        if self.phase == Phase::Starting
            && self
                .attempt
                .as_ref()
                .is_some_and(|a| owner != Some(a.host.as_str()) || generation != a.generation)
        {
            self.attempt = None;
            self.phase = if self.enabled && self.attempts < 3 {
                Phase::Pending
            } else {
                Phase::Finished
            };
            self.error = Some("startup ownership lost before execution".into());
        }
    }
    pub fn begin(&mut self, host: &str, generation: u64, revision: &str, hash: &str) -> Result<()> {
        if self.profile.revision != revision {
            return Err(Errno::ESTALE.into());
        }
        if !self.enabled {
            return Err(Errno::EPERM.into());
        }
        if self.phase == Phase::Starting {
            return self.check(host, generation, revision, hash);
        }
        if self.phase != Phase::Pending {
            return Err(Errno::EBUSY.into());
        }
        self.attempt = Some(Attempt {
            host: host.into(),
            generation,
            hash: hash.into(),
        });
        self.attempts += 1;
        self.phase = Phase::Starting;
        self.error = None;
        Ok(())
    }
    pub fn check(&self, host: &str, generation: u64, revision: &str, hash: &str) -> Result<()> {
        let attempt = self.attempt.as_ref().ok_or(Error::from(Errno::ESTALE))?;
        if self.profile.revision != revision
            || !matches!(self.phase, Phase::Starting | Phase::Running)
            || attempt.host != host
            || attempt.generation != generation
            || attempt.hash != hash
        {
            return Err(Errno::ESTALE.into());
        }
        Ok(())
    }
    pub fn attached(&mut self, pid: u32) {
        self.pid = Some(pid);
        self.phase = Phase::Running;
    }
    pub fn observed_exit(&mut self) {
        if self.phase == Phase::Running {
            self.phase = Phase::Finished;
            self.error = Some("execution ended before completion was reported".into());
        }
    }
    pub fn finish(
        &mut self,
        revision: &str,
        hash: &str,
        status: i32,
        error: Option<String>,
    ) -> Result<()> {
        if !(0..=255).contains(&status) || error.as_ref().is_some_and(|s| s.len() > 1024) {
            return Err(Errno::EINVAL.into());
        }
        self.authorize_finish(revision, hash)?;
        if let Some(previous) = self.status {
            return if previous == status && self.error == error {
                Ok(())
            } else {
                Err(Errno::ESTALE.into())
            };
        }
        if self.pid.is_none() && status == 0 {
            return Err(Errno::EINVAL.into());
        }
        self.phase = Phase::Finished;
        self.status = Some(status);
        self.error = error;
        Ok(())
    }
    pub fn authorize_finish(&self, revision: &str, hash: &str) -> Result<()> {
        if self.profile.revision != revision || self.attempt.as_ref().is_none_or(|a| a.hash != hash)
        {
            return Err(Errno::ESTALE.into());
        }
        Ok(())
    }
    pub fn view(&self) -> Value {
        json!({"revision": self.profile.revision, "file": self.profile.file,
            "enabled": self.enabled, "state": self.phase, "attempts": self.attempts,
            "pid": self.pid, "status": self.status, "error": self.error})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn startup() -> Startup {
        Startup::new(Profile::new("revision".into(), "/home/user/units.json".into()).unwrap())
    }
    #[test]
    fn admission_is_idempotent_and_public_views_never_contain_proofs() {
        let mut s = startup();
        s.begin("a", 1, "revision", "private-hash").unwrap();
        s.begin("a", 1, "revision", "private-hash").unwrap();
        assert_eq!(s.view()["attempts"], 1);
        for (host, generation, revision, hash) in [
            ("b", 1, "revision", "private-hash"),
            ("a", 2, "revision", "private-hash"),
            ("a", 1, "old", "private-hash"),
            ("a", 1, "revision", "forged"),
        ] {
            assert_eq!(
                s.check(host, generation, revision, hash).unwrap_err().errno,
                Errno::ESTALE
            );
        }
        assert!(!s.view().to_string().contains("private-hash"));
        s.attached(42);
        s.expire_owner(Some("b"), 2);
        assert_eq!(s.view()["state"], "running");
        assert_eq!(
            s.begin("b", 2, "revision", "new").unwrap_err().errno,
            Errno::EBUSY
        );
    }
    #[test]
    fn abandoned_pre_execution_attempts_are_bounded_and_fenced() {
        let mut s = startup();
        for generation in 1..=3 {
            s.begin("a", generation, "revision", &format!("proof{generation}"))
                .unwrap();
            s.expire_owner(None, generation);
            assert_eq!(
                s.authorize_finish("revision", &format!("proof{generation}"))
                    .unwrap_err()
                    .errno,
                Errno::ESTALE
            );
        }
        assert_eq!(s.view()["state"], "finished");
        assert_eq!(s.view()["attempts"], 3);
        assert_eq!(
            s.begin("a", 4, "revision", "fresh").unwrap_err().errno,
            Errno::EBUSY
        );
    }
    #[test]
    fn completion_is_scoped_and_can_refine_an_observed_exit_only_once() {
        let mut s = startup();
        s.begin("a", 1, "revision", "secret").unwrap();
        assert_eq!(
            s.finish("revision", "secret", 0, None).unwrap_err().errno,
            Errno::EINVAL
        );
        s.attached(42);
        s.observed_exit();
        assert_eq!(s.view()["status"], Value::Null);
        assert_eq!(
            s.finish("old", "secret", 0, None).unwrap_err().errno,
            Errno::ESTALE
        );
        assert_eq!(
            s.finish("revision", "forged", 0, None).unwrap_err().errno,
            Errno::ESTALE
        );
        s.finish("revision", "secret", 0, None).unwrap();
        s.finish("revision", "secret", 0, None).unwrap();
        assert_eq!(
            s.finish("revision", "secret", 1, None).unwrap_err().errno,
            Errno::ESTALE
        );
        assert_eq!(s.view()["status"], 0);
        assert_eq!(
            s.begin("a", 1, "revision", "new").unwrap_err().errno,
            Errno::EBUSY
        );
    }
    #[test]
    fn disabling_cancels_pending_admission_but_preserves_a_running_completion_capability() {
        let mut s = startup();
        s.begin("a", 1, "revision", "secret").unwrap();
        s.disable();
        assert_eq!(
            s.check("a", 1, "revision", "secret").unwrap_err().errno,
            Errno::ESTALE
        );
        assert_eq!(
            s.begin("a", 1, "revision", "new").unwrap_err().errno,
            Errno::EPERM
        );
        let mut s = startup();
        s.begin("a", 1, "revision", "secret").unwrap();
        s.attached(42);
        s.disable();
        assert_eq!(s.view()["state"], "running");
        s.finish("revision", "secret", 143, None).unwrap();
        assert_eq!(s.view()["status"], 143);
    }
    #[test]
    fn profile_paths_and_receipt_sizes_are_bounded() {
        for path in ["relative".into(), "/bad\0path".into(), "/".repeat(4097)] {
            assert!(Profile::new("r".into(), path).is_err());
        }
        let mut s = startup();
        s.begin("a", 1, "revision", "secret").unwrap();
        assert_eq!(
            s.finish("revision", "secret", 256, None).unwrap_err().errno,
            Errno::EINVAL
        );
        assert_eq!(
            s.finish("revision", "secret", 126, Some("x".repeat(1025)))
                .unwrap_err()
                .errno,
            Errno::EINVAL
        );
        s.finish("revision", "secret", 126, Some("image unavailable".into()))
            .unwrap();
        let s: Startup = serde_json::from_str(&serde_json::to_string(&s).unwrap()).unwrap();
        assert_eq!(s.view()["state"], "finished");
    }
}
