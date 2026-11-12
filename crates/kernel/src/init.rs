//! One init host per Machine boot. Ownership is coordination, not a root credential.
use abi::{Errno, Error, InitAction, InitOwner};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const LEASE: u64 = 30;
const GENERATION_MAX: u64 = (1_u64 << 53) - 1;

#[derive(Serialize, Deserialize)]
struct Owner {
    host: String,
    hash: String,
    expires: u64,
}

#[derive(Serialize, Deserialize)]
struct Execution {
    hash: String,
    started: u64,
    reaped: u64,
}

#[derive(Serialize, Deserialize)]
pub struct Init {
    pub boot: String,
    created: u64,
    observed: u64,
    generation: u64,
    owner: Option<Owner>,
    #[serde(default)]
    execution: Option<Execution>,
    #[serde(default)]
    pub shutdown: Option<crate::lifecycle::Shutdown>,
}

impl Init {
    pub fn new(boot: String, now: u64) -> Self {
        Self {
            boot,
            created: now,
            observed: now,
            generation: 0,
            owner: None,
            execution: None,
            shutdown: None,
        }
    }
    pub fn expire(&mut self, now: u64) {
        self.observed = self.observed.max(now);
        if self
            .owner
            .as_ref()
            .is_some_and(|owner| owner.expires <= self.observed)
        {
            self.owner = None;
            self.execution = None;
        }
    }
    pub fn deadline(&self) -> Option<u64> {
        self.owner
            .as_ref()
            .map(|owner| owner.expires)
            .into_iter()
            .chain(
                self.shutdown
                    .as_ref()
                    .filter(|s| !s.complete)
                    .map(|s| s.deadline),
            )
            .min()
    }
    fn fence(&self, owner: &InitOwner) -> Result<(), Error> {
        if owner.boot != self.boot || owner.generation != self.generation {
            return Err(Errno::ESTALE.into());
        }
        Ok(())
    }
    fn authenticate(&self, owner: &InitOwner, hash: &str) -> Result<(), Error> {
        self.fence(owner)?;
        let current = self.owner.as_ref().ok_or(Error::from(Errno::ESTALE))?;
        if current.host != owner.host || current.hash != hash {
            return Err(Errno::EACCES.into());
        }
        Ok(())
    }
    /// The store checks the browser context and hashes the private proof before entry.
    pub fn apply(&mut self, action: &InitAction, hash: &str, now: u64) -> Result<(), Error> {
        self.expire(now);
        match action {
            InitAction::Inspect => (),
            InitAction::Reboot { boot } => {
                if boot != &self.boot {
                    return Err(Errno::ESTALE.into());
                }
                self.shutdown
                    .get_or_insert_with(|| crate::lifecycle::Shutdown::new(self.observed));
            }
            InitAction::Claim { owner } => {
                if self.shutdown.is_some() {
                    return Err(Errno::EBUSY.into());
                }
                self.fence(owner)?;
                if owner.host.is_empty()
                    || owner.host.len() > 128
                    || !owner
                        .host
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
                {
                    return Err(Errno::EINVAL.into());
                }
                if self.owner.is_some() {
                    // A claim is a compare-and-swap, not a way to prolong an existing lease.
                    return Err(Errno::EBUSY.into());
                }
                if self.generation == GENERATION_MAX {
                    return Err(Errno::ENOSPC.into());
                }
                self.generation += 1;
                self.owner = Some(Owner {
                    host: owner.host.clone(),
                    hash: hash.into(),
                    expires: self.observed.saturating_add(LEASE),
                });
            }
            InitAction::Renew { owner } => {
                self.authenticate(owner, hash)?;
                self.owner.as_mut().unwrap().expires = self.observed.saturating_add(LEASE);
            }
            InitAction::Release { owner } => {
                self.authenticate(owner, hash)?;
                self.owner = None;
                self.execution = None;
            }
            InitAction::Start { owner, .. } => {
                if self.shutdown.is_some() {
                    return Err(Errno::EBUSY.into());
                }
                self.authenticate(owner, hash)?;
            }
        }
        Ok(())
    }
    /// Called only after Start authenticated the current host. Retries keep one execution.
    pub fn start(&mut self, hash: &str) -> Result<(), Error> {
        if let Some(execution) = &self.execution {
            return if execution.hash == hash {
                Ok(())
            } else {
                Err(Errno::EBUSY.into())
            };
        }
        self.execution = Some(Execution {
            hash: hash.into(),
            started: self.observed,
            reaped: 0,
        });
        Ok(())
    }
    pub fn running(&self, hash: &str, now: u64) -> bool {
        self.owner
            .as_ref()
            .map(|owner| owner.expires)
            .is_some_and(|deadline| deadline > now.max(self.observed))
            && self
                .execution
                .as_ref()
                .is_some_and(|execution| execution.hash == hash)
    }
    pub fn active(&self, now: u64) -> bool {
        self.execution
            .as_ref()
            .is_some_and(|execution| self.running(&execution.hash, now))
    }
    /// The store must authenticate the active execution before completing it.
    pub fn finish(&mut self) {
        self.execution = None;
    }
    pub fn reaped(&mut self) {
        if let Some(execution) = &mut self.execution {
            execution.reaped = execution.reaped.saturating_add(1);
        }
    }
    pub fn view(&self) -> Value {
        json!({ "boot": self.boot, "pid": 1, "created": self.created,
            "now": self.observed, "generation": self.generation, "lease": LEASE,
            "owner": self.owner.as_ref().map(|owner| &owner.host),
            "owner_expires": self.owner.as_ref().map(|owner| owner.expires),
            "shutdown": self.shutdown,
            "execution": self.execution.as_ref().map(|execution| json!({
                "role": "init-reaper", "started": execution.started, "reaped": execution.reaped
            })) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shutdown_retains_its_deadline_and_rejects_new_init_execution() {
        let mut init = Init::new("boot".into(), 100);
        init.apply(
            &InitAction::Claim {
                owner: owner("host", 0),
            },
            "proof",
            100,
        )
        .unwrap();
        assert_eq!(
            init.apply(&InitAction::Reboot { boot: "old".into() }, "", 100)
                .unwrap_err()
                .errno,
            Errno::ESTALE
        );
        let stop = InitAction::Reboot {
            boot: "boot".into(),
        };
        init.apply(&stop, "", 101).unwrap();
        init.apply(&stop, "", 102).unwrap();
        assert_eq!(init.shutdown.as_ref().unwrap().deadline, 136);
        assert_eq!(
            init.apply(
                &InitAction::Start {
                    owner: owner("host", 1),
                    token: "exec".into()
                },
                "proof",
                102
            )
            .unwrap_err()
            .errno,
            Errno::EBUSY
        );
        init.expire(131);
        assert_eq!(init.deadline(), Some(136));
        assert!(!init.running("exec", 131));
    }
    fn owner(host: &str, generation: u64) -> InitOwner {
        InitOwner {
            boot: "boot".into(),
            host: host.into(),
            proof: "raw-proof".into(),
            generation,
        }
    }
    #[test]
    fn execution_is_idempotent_private_and_fenced_by_ownership() {
        let mut init = Init::new("boot".into(), 100);
        init.apply(
            &InitAction::Claim {
                owner: owner("a", 0),
            },
            "host",
            100,
        )
        .unwrap();
        let start = InitAction::Start {
            owner: owner("a", 1),
            token: "raw-token".into(),
        };
        assert_eq!(
            init.apply(&start, "forged", 101).unwrap_err().errno,
            Errno::EACCES
        );
        init.apply(&start, "host", 101).unwrap();
        init.start("execution-a").unwrap();
        init.start("execution-a").unwrap();
        assert_eq!(init.start("execution-b").unwrap_err().errno, Errno::EBUSY);
        assert!(init.running("execution-a", 129));
        assert!(!init.running("execution-a", 130));
        assert!(!init.running("forged", 101));
        init.reaped();
        assert_eq!(init.view()["execution"]["reaped"], 1);
        assert!(!init.view().to_string().contains("execution-a"));
        assert!(!serde_json::to_string(&init).unwrap().contains("raw-token"));
        init.apply(
            &InitAction::Claim {
                owner: owner("b", 1),
            },
            "next-host",
            130,
        )
        .unwrap();
        init.start("execution-b").unwrap();
        assert_eq!(
            init.apply(
                &InitAction::Release {
                    owner: owner("a", 1)
                },
                "host",
                131
            )
            .unwrap_err()
            .errno,
            Errno::ESTALE
        );
        assert!(init.running("execution-b", 131));
        assert!(!init.running("execution-a", 131));
        init.apply(
            &InitAction::Release {
                owner: owner("b", 2),
            },
            "next-host",
            132,
        )
        .unwrap();
        assert!(!init.active(132));
    }
    #[test]
    fn old_records_load_without_execution_and_finish_cannot_revive_a_proof() {
        let mut value = serde_json::to_value(Init::new("boot".into(), 100)).unwrap();
        value.as_object_mut().unwrap().remove("execution");
        let mut init: Init = serde_json::from_value(value).unwrap();
        assert!(!init.active(100));
        init.apply(
            &InitAction::Claim {
                owner: owner("a", 0),
            },
            "host",
            100,
        )
        .unwrap();
        init.start("a").unwrap();
        init.finish();
        init.start("b").unwrap();
        assert!(!init.running("a", 101));
        assert!(init.running("b", 101));
    }
    #[test]
    fn ownership_is_exclusive_and_old_generations_cannot_renew_or_release() {
        let mut init = Init::new("boot".into(), 100);
        init.apply(
            &InitAction::Claim {
                owner: owner("a", 0),
            },
            "hash-a",
            100,
        )
        .unwrap();
        assert_eq!(
            init.apply(
                &InitAction::Claim {
                    owner: owner("b", 0)
                },
                "hash-b",
                101
            )
            .unwrap_err()
            .errno,
            Errno::ESTALE
        );
        assert_eq!(
            init.apply(
                &InitAction::Claim {
                    owner: owner("b", 1)
                },
                "hash-b",
                101
            )
            .unwrap_err()
            .errno,
            Errno::EBUSY
        );
        init.apply(
            &InitAction::Claim {
                owner: owner("b", 1),
            },
            "hash-b",
            130,
        )
        .unwrap();
        for action in [
            InitAction::Renew {
                owner: owner("a", 1),
            },
            InitAction::Release {
                owner: owner("a", 1),
            },
        ] {
            assert_eq!(
                init.apply(&action, "hash-a", 131).unwrap_err().errno,
                Errno::ESTALE
            );
        }
        assert_eq!(init.view()["owner"], "b");
    }
    #[test]
    fn public_names_and_boot_ids_never_prove_ownership() {
        let mut init = Init::new("boot".into(), 100);
        init.apply(
            &InitAction::Claim {
                owner: owner("a", 0),
            },
            "hash-a",
            100,
        )
        .unwrap();
        for action in [
            InitAction::Renew {
                owner: owner("a", 1),
            },
            InitAction::Release {
                owner: owner("a", 1),
            },
        ] {
            assert_eq!(
                init.apply(&action, "forged", 101).unwrap_err().errno,
                Errno::EACCES
            );
        }
        let mut wrong = owner("a", 1);
        wrong.boot = "other-boot".into();
        assert_eq!(
            init.apply(&InitAction::Renew { owner: wrong }, "hash-a", 101)
                .unwrap_err()
                .errno,
            Errno::ESTALE
        );
        assert!(!init.view().to_string().contains("hash"));
        assert!(!serde_json::to_string(&init).unwrap().contains("raw-proof"));
    }
    #[test]
    fn storage_round_trip_and_clock_rollback_cannot_revive_an_expired_owner() {
        let mut init = Init::new("boot".into(), 100);
        init.apply(
            &InitAction::Claim {
                owner: owner("a", 0),
            },
            "hash-a",
            100,
        )
        .unwrap();
        init.expire(130);
        let mut init: Init = serde_json::from_str(&serde_json::to_string(&init).unwrap()).unwrap();
        assert_eq!(
            init.apply(
                &InitAction::Renew {
                    owner: owner("a", 1)
                },
                "hash-a",
                110
            )
            .unwrap_err()
            .errno,
            Errno::ESTALE
        );
        init.apply(
            &InitAction::Claim {
                owner: owner("b", 1),
            },
            "hash-b",
            110,
        )
        .unwrap();
        assert_eq!(init.deadline(), Some(160));
        assert_eq!(init.view()["boot"], "boot");
    }
    #[test]
    fn release_preserves_boot_and_fences_the_same_host_when_it_returns() {
        let mut init = Init::new("boot".into(), 100);
        init.apply(
            &InitAction::Claim {
                owner: owner("a", 0),
            },
            "hash-a",
            100,
        )
        .unwrap();
        init.apply(
            &InitAction::Renew {
                owner: owner("a", 1),
            },
            "hash-a",
            110,
        )
        .unwrap();
        assert_eq!(init.deadline(), Some(140));
        init.apply(
            &InitAction::Release {
                owner: owner("a", 1),
            },
            "hash-a",
            111,
        )
        .unwrap();
        assert_eq!(init.deadline(), None);
        init.apply(
            &InitAction::Claim {
                owner: owner("a", 1),
            },
            "new-hash",
            112,
        )
        .unwrap();
        assert_eq!(
            init.apply(
                &InitAction::Release {
                    owner: owner("a", 1)
                },
                "hash-a",
                113
            )
            .unwrap_err()
            .errno,
            Errno::ESTALE
        );
        assert_eq!(init.view()["generation"], 2);
    }
    #[test]
    fn invalid_names_and_generation_exhaustion_fail_without_claiming() {
        let mut init = Init::new("boot".into(), 100);
        assert_eq!(
            init.apply(
                &InitAction::Claim {
                    owner: owner("a/b", 0)
                },
                "hash",
                100
            )
            .unwrap_err()
            .errno,
            Errno::EINVAL
        );
        init.generation = GENERATION_MAX;
        assert_eq!(
            init.apply(
                &InitAction::Claim {
                    owner: owner("a", GENERATION_MAX)
                },
                "hash",
                100
            )
            .unwrap_err()
            .errno,
            Errno::ENOSPC
        );
        assert_eq!(init.deadline(), None);
    }
}
