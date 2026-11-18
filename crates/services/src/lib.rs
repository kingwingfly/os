//! User-space service policy. Unit metadata conveys no account or resource authority.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u32,
    pub units: Vec<Unit>,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Restart {
    #[default]
    Never,
    OnFailure,
    Always,
}
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Identity {
    #[default]
    Caller,
}
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Readiness {
    #[default]
    Started,
    Notify,
}

/// Mount namespace policy for a supervised service unit (contract §2.7, #52).
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum MountNamespaceGrant {
    /// Default: run in the supervisor's (system) mount namespace; no user mounts visible.
    #[default]
    System,
    /// Clone a fresh private mount namespace from the supervisor's namespace at service start.
    Isolated,
    /// Attach to the owning non-root caller's session mount namespace when started as a user
    /// session unit; rejected with `EPERM` for root/system-boot units.
    Session,
}

impl MountNamespaceGrant {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Isolated => "isolated",
            Self::Session => "session",
        }
    }
}

/// Explicit bind-mount entry applied inside a private (`isolated` or `session`) service namespace.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BindGrant {
    pub source: String,
    pub target: String,
    #[serde(default)]
    pub read_only: bool,
}

fn clean_abs_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= abi::PATH_MAX
        && !path.contains('\0')
        && (path == "/"
            || (!path.ends_with('/')
                && path[1..].split('/').all(|seg| {
                    !seg.is_empty() && seg != "." && seg != ".." && seg.len() <= abi::NAME_MAX
                })))
}

fn root() -> String {
    "/".into()
}
fn delay() -> u64 {
    1000
}
fn timeout() -> u64 {
    5000
}
fn startup_timeout() -> u64 {
    10000
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub pids: Option<u32>,
    pub memory: Option<u64>,
    pub read_bps: Option<u64>,
    pub write_bps: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Unit {
    pub name: String,
    pub argv: Vec<String>,
    #[serde(default = "root")]
    pub cwd: String,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    #[serde(default)]
    pub identity: Identity,
    #[serde(default)]
    pub mount_namespace: MountNamespaceGrant,
    #[serde(default)]
    pub bind_mounts: Vec<BindGrant>,
    #[serde(default)]
    pub limits: Option<Limits>,
    #[serde(default)]
    pub readiness: Readiness,
    #[serde(default)]
    pub requires: Vec<String>,
    #[serde(default)]
    pub after: Vec<String>,
    #[serde(default)]
    pub restart: Restart,
    #[serde(default)]
    pub max_restarts: u32,
    #[serde(default = "delay")]
    pub restart_delay_ms: u64,
    #[serde(default = "startup_timeout")]
    pub startup_timeout_ms: u64,
    #[serde(default = "timeout")]
    pub stop_timeout_ms: u64,
}

impl Unit {
    /// Validate that the caller is authorized to instantiate this unit's `mount_namespace` grant.
    /// `MountNamespaceGrant::Session` is rejected (`EPERM`) for root/system-boot units or callers
    /// without an owning non-root login session.
    pub fn authorize_namespace(
        &self,
        caller_uid: u32,
        has_user_session: bool,
    ) -> Result<(), abi::Errno> {
        if self.mount_namespace == MountNamespaceGrant::Session
            && (caller_uid == 0 || !has_user_session)
        {
            return Err(abi::Errno::EPERM);
        }
        Ok(())
    }
}

impl Manifest {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > 65536 {
            return Err("unit file exceeds 64 KiB".into());
        }
        let manifest: Self = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        if manifest.version != 1 || manifest.units.is_empty() || manifest.units.len() > 32 {
            return Err("expected version 1 and 1 to 32 units".into());
        }
        let valid = |s: &str| !s.contains('\0') && s.len() <= 4096;
        let mut names = HashSet::new();
        for unit in &manifest.units {
            if unit.limits.as_ref().is_some_and(|l| {
                l.pids.is_none()
                    && l.memory.is_none()
                    && l.read_bps.is_none()
                    && l.write_bps.is_none()
            }) {
                return Err("limits must name at least one supported resource".into());
            }
            if unit.name.is_empty()
                || unit.name.len() > 64
                || !unit
                    .name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
                || !names.insert(&unit.name)
            {
                return Err("unit names must be unique and contain only letters, digits, dash, underscore or dot".into());
            }
            if unit.argv.is_empty()
                || unit.argv.len() > 128
                || unit.argv[0].is_empty()
                || !unit.argv.iter().all(|s| valid(s))
                || !unit.cwd.starts_with('/')
                || !valid(&unit.cwd)
            {
                return Err(format!(
                    "{}: invalid argv or absolute working directory",
                    unit.name
                ));
            }
            if unit.environment.len() > 64
                || unit.environment.iter().any(|(k, v)| {
                    k.is_empty() || k.contains('=') || k == "OS_READY_FD" || !valid(k) || !valid(v)
                })
            {
                return Err(format!("{}: invalid environment", unit.name));
            }
            if unit.max_restarts > 16
                || !(100..=60000).contains(&unit.restart_delay_ms)
                || !(100..=30000).contains(&unit.stop_timeout_ms)
                || !(100..=60000).contains(&unit.startup_timeout_ms)
            {
                return Err(format!(
                    "{}: restart/startup/stop bounds exceeded",
                    unit.name
                ));
            }
            if unit.bind_mounts.len() > 32 {
                return Err(format!("{}: too many bind_mounts (max 32)", unit.name));
            }
            if !unit.bind_mounts.is_empty() && unit.mount_namespace == MountNamespaceGrant::System {
                return Err(format!(
                    "{}: bind_mounts require isolated or session mount_namespace",
                    unit.name
                ));
            }
            for bind in &unit.bind_mounts {
                if !clean_abs_path(&bind.source) || !clean_abs_path(&bind.target) {
                    return Err(format!(
                        "{}: bind_mounts paths must be clean absolute paths",
                        unit.name
                    ));
                }
            }
        }
        manifest.order()?;
        Ok(manifest)
    }
    pub fn authorize_namespace(
        &self,
        caller_uid: u32,
        has_user_session: bool,
    ) -> Result<(), abi::Errno> {
        for unit in &self.units {
            unit.authorize_namespace(caller_uid, has_user_session)?;
        }
        Ok(())
    }
    pub fn index(&self, name: &str) -> Option<usize> {
        self.units.iter().position(|u| u.name == name)
    }
    pub fn order(&self) -> Result<Vec<usize>, String> {
        fn visit(
            manifest: &Manifest,
            i: usize,
            seen: &mut [u8],
            order: &mut Vec<usize>,
        ) -> Result<(), String> {
            if seen[i] == 1 {
                return Err("unit dependency cycle".into());
            }
            if seen[i] == 2 {
                return Ok(());
            }
            seen[i] = 1;
            for name in manifest.units[i]
                .requires
                .iter()
                .chain(&manifest.units[i].after)
            {
                let next = manifest
                    .index(name)
                    .ok_or_else(|| format!("unknown dependency {name}"))?;
                visit(manifest, next, seen, order)?;
            }
            seen[i] = 2;
            order.push(i);
            Ok(())
        }
        let mut order = Vec::new();
        let mut seen = vec![0; self.units.len()];
        for i in 0..self.units.len() {
            visit(self, i, &mut seen, &mut order)?;
        }
        Ok(order)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Inactive,
    Starting,
    Ready,
    Backoff,
    Stopping,
    Exited,
    Failed,
}
#[derive(Debug)]
pub struct Service {
    pub state: State,
    pub pid: Option<u32>,
    pub restarts: u32,
    deadline: u64,
    failed_stop: bool,
    startup_failed: bool,
    killed: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Start(usize),
    StartupTimeout(usize),
    Signal { index: usize, pid: u32, signal: u32 },
}

pub struct Supervisor {
    pub manifest: Manifest,
    pub services: Vec<Service>,
    order: Vec<usize>,
    stopping: bool,
}
impl Supervisor {
    pub fn new(manifest: Manifest) -> Self {
        let order = manifest.order().expect("validated manifest");
        let services = manifest
            .units
            .iter()
            .map(|_| Service {
                state: State::Inactive,
                pid: None,
                restarts: 0,
                deadline: 0,
                failed_stop: false,
                startup_failed: false,
                killed: false,
            })
            .collect();
        Self {
            manifest,
            services,
            order,
            stopping: false,
        }
    }
    /// Start the clock when this selected action is dispatched, rather than charging
    /// time spent synchronously launching an earlier independent unit.
    pub fn launching(&mut self, i: usize, now: u64) {
        self.services[i].deadline = now.saturating_add(self.manifest.units[i].startup_timeout_ms);
    }
    /// A successful spawn means the host accepted the image, not application readiness.
    pub fn started(&mut self, i: usize, pid: u32, now: u64) {
        self.services[i].pid = Some(pid);
        if self.manifest.units[i].readiness == Readiness::Started {
            self.ready(i, pid, now);
        }
    }
    /// Only this attempt's descriptor can report readiness, before its deadline.
    pub fn ready(&mut self, i: usize, pid: u32, now: u64) -> bool {
        let service = &mut self.services[i];
        if self.stopping
            || service.state != State::Starting
            || service.pid != Some(pid)
            || service.startup_failed
            || now >= service.deadline
        {
            return false;
        }
        service.state = State::Ready;
        true
    }
    pub fn readiness_failed(&mut self, i: usize, pid: u32) {
        let service = &mut self.services[i];
        if service.state == State::Starting && service.pid == Some(pid) {
            service.startup_failed = true;
        }
    }
    pub fn exited(&mut self, i: usize, success: bool, now: u64) {
        let unit = &self.manifest.units[i];
        let service = &mut self.services[i];
        service.pid = None;
        let success = success && service.state != State::Starting && !service.startup_failed;
        if self.stopping
            || service.failed_stop
            || service.state == State::Stopping && !service.startup_failed
        {
            service.state = if service.failed_stop {
                State::Failed
            } else {
                State::Exited
            };
            return;
        }
        service.startup_failed = false;
        let restart =
            unit.restart == Restart::Always || unit.restart == Restart::OnFailure && !success;
        if restart && service.restarts < unit.max_restarts {
            service.restarts += 1;
            service.deadline = now.saturating_add(unit.restart_delay_ms);
            service.state = State::Backoff;
        } else {
            service.state = if success && !restart {
                State::Exited
            } else {
                State::Failed
            };
        }
    }
    pub fn tick(&mut self, now: u64, stop: bool) -> Vec<Action> {
        self.stopping |= stop;
        let mut actions = Vec::new();
        // Stop dependents first; requirements fail closed when their provider disappears.
        for &i in self.order.iter().rev() {
            let failed = self.manifest.units[i].requires.iter().any(|name| {
                self.services[self.manifest.index(name).unwrap()].state == State::Failed
            });
            let service = &mut self.services[i];
            if !self.stopping
                && !failed
                && service.state == State::Starting
                && now >= service.deadline
            {
                service.startup_failed = true;
                actions.push(Action::StartupTimeout(i));
            }
            if (self.stopping || failed || service.startup_failed)
                && !matches!(
                    service.state,
                    State::Exited | State::Failed | State::Stopping
                )
            {
                service.failed_stop = failed;
                if let Some(pid) = service.pid {
                    service.state = State::Stopping;
                    service.deadline = now.saturating_add(self.manifest.units[i].stop_timeout_ms);
                    actions.push(Action::Signal {
                        index: i,
                        pid,
                        signal: 15,
                    });
                    actions.push(Action::Signal {
                        index: i,
                        pid,
                        signal: 18,
                    });
                } else {
                    service.state = if failed || service.startup_failed {
                        State::Failed
                    } else {
                        State::Exited
                    };
                }
            }
            // Dependency failure during startup cleanup cancels its pending retry too.
            service.failed_stop |= failed;
            if service.state == State::Stopping && now >= service.deadline && !service.killed {
                service.killed = true;
                actions.push(Action::Signal {
                    index: i,
                    pid: service.pid.unwrap(),
                    signal: 9,
                });
            }
        }
        for &i in &self.order {
            let unit = &self.manifest.units[i];
            let ready = unit.requires.iter().all(|n| {
                matches!(
                    self.services[self.manifest.index(n).unwrap()].state,
                    State::Ready | State::Exited
                )
            });
            let ordered = unit.after.iter().all(|n| {
                let predecessor = &self.services[self.manifest.index(n).unwrap()];
                !matches!(predecessor.state, State::Inactive | State::Backoff)
                    && (predecessor.state != State::Starting || predecessor.pid.is_some())
            });
            let service = &mut self.services[i];
            if !self.stopping
                && ready
                && ordered
                && (service.state == State::Inactive
                    || service.state == State::Backoff && now >= service.deadline)
            {
                service.state = State::Starting;
                service.startup_failed = false;
                service.failed_stop = false;
                service.killed = false;
                service.deadline = now.saturating_add(unit.startup_timeout_ms);
                actions.push(Action::Start(i));
            }
        }
        actions
    }
    pub fn done(&self) -> bool {
        self.services
            .iter()
            .all(|s| matches!(s.state, State::Exited | State::Failed))
    }
    pub fn failed(&self) -> bool {
        self.services.iter().any(|s| s.state == State::Failed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn mount_namespace_and_bind_grants_parse_and_default_to_system() {
        let raw = serde_json::to_vec(&json!({
            "version": 1,
            "units": [
                {
                    "name": "sys-worker",
                    "argv": ["/usr/bin/true"]
                },
                {
                    "name": "iso-worker",
                    "argv": ["/usr/bin/true"],
                    "mount_namespace": "isolated",
                    "bind_mounts": [
                        { "source": "/srv/data", "target": "/var/lib/app", "read_only": true },
                        { "source": "/tmp/work", "target": "/work" }
                    ]
                },
                {
                    "name": "session-worker",
                    "argv": ["/usr/bin/true"],
                    "mount_namespace": "session",
                    "bind_mounts": [
                        { "source": "/mnt/shared/docs", "target": "/docs", "read_only": true }
                    ]
                }
            ]
        }))
        .unwrap();
        let manifest = Manifest::parse(&raw).unwrap();
        assert_eq!(
            manifest.units[0].mount_namespace,
            MountNamespaceGrant::System
        );
        assert!(manifest.units[0].bind_mounts.is_empty());

        assert_eq!(
            manifest.units[1].mount_namespace,
            MountNamespaceGrant::Isolated
        );
        assert_eq!(manifest.units[1].bind_mounts.len(), 2);
        assert!(manifest.units[1].bind_mounts[0].read_only);
        assert!(!manifest.units[1].bind_mounts[1].read_only);

        assert_eq!(
            manifest.units[2].mount_namespace,
            MountNamespaceGrant::Session
        );

        // System/root boot cannot use `session` mount namespace; non-root user session can.
        assert_eq!(
            manifest.authorize_namespace(0, false),
            Err(abi::Errno::EPERM)
        );
        assert_eq!(
            manifest.authorize_namespace(0, true),
            Err(abi::Errno::EPERM)
        );
        assert_eq!(
            manifest.authorize_namespace(1000, false),
            Err(abi::Errno::EPERM)
        );
        assert_eq!(manifest.authorize_namespace(1000, true), Ok(()));

        // System and Isolated grants work for both root/system and user callers.
        assert_eq!(manifest.units[0].authorize_namespace(0, false), Ok(()));
        assert_eq!(manifest.units[1].authorize_namespace(0, false), Ok(()));

        assert_eq!(MountNamespaceGrant::System.as_str(), "system");
        assert_eq!(MountNamespaceGrant::Isolated.as_str(), "isolated");
        assert_eq!(MountNamespaceGrant::Session.as_str(), "session");
    }

    #[test]
    fn invalid_mount_namespace_or_bind_mounts_are_rejected() {
        let bad_cases = [
            // Unknown mount_namespace variant
            json!({
                "name": "bad-ns",
                "argv": ["/usr/bin/true"],
                "mount_namespace": "shared"
            }),
            // bind_mounts on default `system` namespace
            json!({
                "name": "sys-bind",
                "argv": ["/usr/bin/true"],
                "bind_mounts": [{ "source": "/srv", "target": "/mnt" }]
            }),
            // Relative source path
            json!({
                "name": "rel-src",
                "argv": ["/usr/bin/true"],
                "mount_namespace": "isolated",
                "bind_mounts": [{ "source": "srv/data", "target": "/mnt" }]
            }),
            // `..` segment in target
            json!({
                "name": "dotdot-tgt",
                "argv": ["/usr/bin/true"],
                "mount_namespace": "isolated",
                "bind_mounts": [{ "source": "/srv", "target": "/mnt/../etc" }]
            }),
            // `.` segment
            json!({
                "name": "dot-src",
                "argv": ["/usr/bin/true"],
                "mount_namespace": "isolated",
                "bind_mounts": [{ "source": "/srv/./a", "target": "/mnt" }]
            }),
            // Double slash
            json!({
                "name": "double-slash",
                "argv": ["/usr/bin/true"],
                "mount_namespace": "isolated",
                "bind_mounts": [{ "source": "/srv//a", "target": "/mnt" }]
            }),
            // Trailing slash
            json!({
                "name": "trailing-slash",
                "argv": ["/usr/bin/true"],
                "mount_namespace": "isolated",
                "bind_mounts": [{ "source": "/srv/a/", "target": "/mnt" }]
            }),
            // NUL byte
            json!({
                "name": "nul-byte",
                "argv": ["/usr/bin/true"],
                "mount_namespace": "isolated",
                "bind_mounts": [{ "source": "/srv/\u{0000}a", "target": "/mnt" }]
            }),
            // Unknown field on BindGrant (`deny_unknown_fields`)
            json!({
                "name": "extra-field",
                "argv": ["/usr/bin/true"],
                "mount_namespace": "isolated",
                "bind_mounts": [{ "source": "/srv", "target": "/mnt", "propagation": "shared" }]
            }),
        ];
        for unit in bad_cases {
            let raw = serde_json::to_vec(&json!({ "version": 1, "units": [unit] })).unwrap();
            assert!(
                Manifest::parse(&raw).is_err(),
                "expected failure for {unit}"
            );
        }
    }
}
