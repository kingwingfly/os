//! Transport-agnostic Service Manager v2 state machine for PID 1 (`/usr/bin/init`) and
//! per-user service managers (`/usr/bin/init --user`, `#57` `L3d`, Contract v2 §2.8, §2.15).
//!
//! Enforces:
//! - Deterministic topological DAG startup and strict reverse topological shutdown.
//! - `Readiness::{Immediate, PipeFd (OS_READY_FD), NotifySocket (NOTIFY_SOCKET)}`.
//! - Kernel `SO_PEERCRED` anti-spoofing on `NOTIFY_SOCKET` (`cred.pid == unit.pid`) and control
//!   sockets (`cred.uid == 0` for mutating system ops; `cred.uid == manager_uid` & no privilege
//!   elevation for per-user managers).
//! - Non-blocking `FailurePolicy::Optional` units (e.g., offline `cloud.mount` never blocks
//!   `multi-user.target` or `MarkBootHealthy`).
//! - Restart backoff (`OnFailure` / `Always`), `SIGTERM` -> `SIGKILL` escalation, and clean root
//!   unmount/close signaling (`CloseCleanRoot`).

use crate::control::{
    ControlRequest, ControlResponse, NotifyMessage, PeerCred, SYSTEM_NOTIFY_SOCKET, UnitStatusView,
    authorize_control,
};
use crate::graph::{GraphError, UnitGraph};
use crate::unit::{FailurePolicy, MountUnitSpec, Readiness, RestartPolicy, UnitKind, UnitSpec};
use abi::{Errno, Error, SIGKILL, SIGTERM};
use std::collections::{BTreeMap, BTreeSet};

/// Lifecycle state of a single unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnitState {
    Inactive,
    Starting,
    Active,
    Backoff,
    Stopping,
    Failed,
}

impl UnitState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inactive => "inactive",
            Self::Starting => "starting",
            Self::Active => "active",
            Self::Backoff => "backoff",
            Self::Stopping => "stopping",
            Self::Failed => "failed",
        }
    }

    pub const fn is_stopped(self) -> bool {
        matches!(self, Self::Inactive | Self::Failed)
    }
}

/// Mutable runtime state tracked per concrete unit.
#[derive(Clone, Debug)]
pub struct UnitRuntime {
    pub state: UnitState,
    pub pid: Option<u32>,
    pub attempts: u32,
    pub deadline_ms: Option<u64>,
    pub status_text: Option<String>,
    pub last_error: Option<String>,
    pub killed: bool,
    pub enabled: bool,
    pub mounted: bool,
    was_active: bool,
}

impl UnitRuntime {
    fn new(enabled: bool) -> Self {
        Self {
            state: UnitState::Inactive,
            pid: None,
            attempts: 0,
            deadline_ms: None,
            status_text: None,
            last_error: None,
            killed: false,
            enabled,
            mounted: false,
            was_active: false,
        }
    }
}

/// Effect emitted by [`ServiceManager`] for the host runner (PID 1 or per-user init) to perform.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManagerAction {
    SpawnService {
        unit: String,
        spec: Box<UnitSpec>,
        use_ready_fd: bool,
        notify_socket: Option<String>,
    },
    MountFs {
        unit: String,
        spec: MountUnitSpec,
    },
    UmountFs {
        unit: String,
        target: String,
    },
    SignalUnit {
        unit: String,
        pid: u32,
        signal: u8,
    },
    /// Emitted once when `multi-user.target` reaches `Active`, confirming Release v2 boot health.
    MarkBootHealthy,
    /// Emitted at the end of ordered reverse shutdown after all active units & non-root mounts stop.
    CloseCleanRoot {
        reboot: bool,
    },
    Log {
        unit: String,
        message: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShutdownMode {
    None,
    Poweroff,
    Reboot,
}

/// Portable, transport-agnostic PID 1 / per-user Service Manager v2 state machine.
pub struct ServiceManager {
    manager_uid: u32,
    notify_socket_path: String,
    graph: UnitGraph,
    units: BTreeMap<String, UnitRuntime>,
    desired_active: BTreeSet<String>,
    explicit_stopping: BTreeSet<String>,
    shutdown_mode: ShutdownMode,
    boot_healthy_marked: bool,
    shutdown_complete: bool,
    spoofed_notify_count: u64,
}

impl ServiceManager {
    /// Construct a PID 1 system service manager (`manager_uid == 0`).
    pub fn new_system(graph: UnitGraph) -> Result<Self, Error> {
        Self::new(0, SYSTEM_NOTIFY_SOCKET.to_owned(), graph)
    }

    /// Construct a strictly attenuated per-user service manager (`manager_uid != 0`).
    pub fn new_user(manager_uid: u32, graph: UnitGraph) -> Result<Self, Error> {
        if manager_uid == 0 {
            return Err(Error::because(
                Errno::EINVAL,
                "per-user service manager requires non-zero uid",
            ));
        }
        let notify = format!("/run/user/{manager_uid}/notify.sock");
        Self::new(manager_uid, notify, graph)
    }

    fn new(manager_uid: u32, notify_socket_path: String, graph: UnitGraph) -> Result<Self, Error> {
        let mut units = BTreeMap::new();
        for (name, spec) in graph.units() {
            spec.authorize_for_manager(manager_uid)?;
            units.insert(name.clone(), UnitRuntime::new(spec.enabled));
        }
        Ok(Self {
            manager_uid,
            notify_socket_path,
            graph,
            units,
            desired_active: BTreeSet::new(),
            explicit_stopping: BTreeSet::new(),
            shutdown_mode: ShutdownMode::None,
            boot_healthy_marked: false,
            shutdown_complete: false,
            spoofed_notify_count: 0,
        })
    }

    pub fn manager_uid(&self) -> u32 {
        self.manager_uid
    }

    pub fn graph(&self) -> &UnitGraph {
        &self.graph
    }

    pub fn is_boot_healthy(&self) -> bool {
        self.boot_healthy_marked
    }

    pub fn is_shutdown_complete(&self) -> bool {
        self.shutdown_complete
    }

    pub fn shutdown_mode(&self) -> ShutdownMode {
        self.shutdown_mode
    }

    pub fn spoofed_notify_count(&self) -> u64 {
        self.spoofed_notify_count
    }

    pub fn unit_runtime(&self, name: &str) -> Option<&UnitRuntime> {
        self.units.get(name)
    }

    pub fn unit_state(&self, name: &str) -> Option<UnitState> {
        self.units.get(name).map(|u| u.state)
    }

    pub fn unit_status(&self, name: &str) -> Option<UnitStatusView> {
        let spec = self.graph.unit(name)?;
        let rt = self.units.get(name)?;
        Some(UnitStatusView {
            name: spec.name.clone(),
            kind: spec.kind,
            state: rt.state.as_str().to_owned(),
            enabled: rt.enabled,
            pid: rt.pid,
            attempts: rt.attempts,
            status_text: rt.status_text.clone(),
            last_error: rt.last_error.clone(),
        })
    }

    pub fn list_statuses(&self) -> Vec<UnitStatusView> {
        self.graph
            .start_order()
            .iter()
            .filter_map(|name| self.unit_status(name))
            .collect()
    }

    /// Activate the initial boot target (typically `"multi-user.target"`).
    /// Does NOT activate `cloud-online.target` or optional cloud mounts until requested explicitly.
    pub fn boot_target(&mut self, target: &str) -> Result<Vec<String>, GraphError> {
        let plan = self.graph.start_plan_for(target)?;
        for name in &plan {
            if self.units.get(name).is_some_and(|u| u.enabled) {
                self.desired_active.insert(name.clone());
            }
        }
        Ok(plan)
    }

    /// Advance the state machine at monotonic time `now_ms`, returning ordered host actions.
    pub fn tick(&mut self, now_ms: u64) -> Vec<ManagerAction> {
        if self.shutdown_mode != ShutdownMode::None {
            return self.tick_shutdown(now_ms);
        }
        let mut actions = Vec::new();
        let order: Vec<String> = self.graph.start_order().to_vec();

        // 1. Handle stopping units (escalate to SIGKILL on stop_timeout_ms) and startup timeouts.
        for name in order.iter().rev() {
            let spec = self.graph.unit(name).unwrap().clone();
            let rt = self.units.get_mut(name).unwrap();
            if rt.state == UnitState::Stopping
                && rt.deadline_ms.is_some_and(|d| now_ms >= d)
                && !rt.killed
                && let Some(pid) = rt.pid
            {
                rt.killed = true;
                actions.push(ManagerAction::SignalUnit {
                    unit: name.clone(),
                    pid,
                    signal: SIGKILL,
                });
            }
            if rt.state == UnitState::Starting && rt.deadline_ms.is_some_and(|d| now_ms >= d) {
                rt.last_error = Some("startup readiness timeout exceeded".into());
                if let Some(pid) = rt.pid {
                    rt.state = UnitState::Stopping;
                    rt.deadline_ms = Some(now_ms.saturating_add(spec.stop_timeout_ms));
                    rt.killed = false;
                    actions.push(ManagerAction::SignalUnit {
                        unit: name.clone(),
                        pid,
                        signal: SIGTERM,
                    });
                } else {
                    self.schedule_failure_or_backoff(name, &spec, now_ms, &mut actions);
                }
            }
        }

        // 2. Process explicit stops in reverse topological order.
        if !self.explicit_stopping.is_empty() {
            for name in order.iter().rev() {
                if !self.explicit_stopping.contains(name) {
                    continue;
                }
                if self.has_active_successors_in(name, &self.explicit_stopping) {
                    continue;
                }
                let spec = self.graph.unit(name).unwrap().clone();
                let rt = self.units.get_mut(name).unwrap();
                match rt.state {
                    UnitState::Inactive | UnitState::Failed => {
                        self.explicit_stopping.remove(name);
                    }
                    UnitState::Backoff => {
                        rt.state = UnitState::Inactive;
                        rt.deadline_ms = None;
                        self.explicit_stopping.remove(name);
                    }
                    UnitState::Stopping => {}
                    UnitState::Starting | UnitState::Active => match spec.kind {
                        UnitKind::Service => {
                            if let Some(pid) = rt.pid {
                                rt.state = UnitState::Stopping;
                                rt.deadline_ms = Some(now_ms.saturating_add(spec.stop_timeout_ms));
                                rt.killed = false;
                                actions.push(ManagerAction::SignalUnit {
                                    unit: name.clone(),
                                    pid,
                                    signal: SIGTERM,
                                });
                            } else {
                                rt.state = UnitState::Inactive;
                                rt.deadline_ms = None;
                                self.explicit_stopping.remove(name);
                            }
                        }
                        UnitKind::Mount => {
                            rt.state = UnitState::Inactive;
                            rt.deadline_ms = None;
                            if rt.mounted
                                && let Some(mount) = &spec.mount
                            {
                                rt.mounted = false;
                                actions.push(ManagerAction::UmountFs {
                                    unit: name.clone(),
                                    target: mount.target.clone(),
                                });
                            }
                            self.explicit_stopping.remove(name);
                        }
                        UnitKind::Target => {
                            rt.state = UnitState::Inactive;
                            rt.deadline_ms = None;
                            self.explicit_stopping.remove(name);
                        }
                    },
                }
            }
        }

        // 3. Evaluate desired units in deterministic topological start order.
        for name in &order {
            if !self.desired_active.contains(name) || self.explicit_stopping.contains(name) {
                continue;
            }
            let spec = self.graph.unit(name).unwrap().clone();
            let current_state = self.units[name].state;
            if !matches!(current_state, UnitState::Inactive | UnitState::Backoff) {
                continue;
            }
            if current_state == UnitState::Backoff
                && self.units[name]
                    .deadline_ms
                    .is_some_and(|deadline| now_ms < deadline)
            {
                continue;
            }

            // Check required dependencies: fail closed if any required dep failed.
            let mut required_failed: Option<String> = None;
            let mut required_ready = true;
            for req in &spec.requires {
                match self.units[req].state {
                    UnitState::Active => {}
                    UnitState::Failed => {
                        required_failed = Some(req.clone());
                        break;
                    }
                    _ => {
                        required_ready = false;
                    }
                }
            }
            if let Some(dep) = required_failed {
                let rt = self.units.get_mut(name).unwrap();
                rt.state = UnitState::Failed;
                rt.last_error = Some(format!("required dependency '{dep}' failed"));
                actions.push(ManagerAction::Log {
                    unit: name.clone(),
                    message: format!("failed: required dependency '{dep}' failed"),
                });
                continue;
            }
            if !required_ready {
                continue;
            }

            // Check `after` ordering dependencies that are desired active: wait until each is
            // Active, OR Failed with `FailurePolicy::Optional` (optional failures NEVER block!).
            let mut after_ready = true;
            for dep in &spec.after {
                if !self.desired_active.contains(dep) {
                    continue;
                }
                let Some(dep_spec) = self.graph.unit(dep) else {
                    continue;
                };
                match self.units[dep].state {
                    UnitState::Active => {}
                    UnitState::Failed if dep_spec.failure_policy == FailurePolicy::Optional => {}
                    _ => {
                        after_ready = false;
                        break;
                    }
                }
            }
            if !after_ready {
                continue;
            }

            // Ready to launch or activate this unit.
            match spec.kind {
                UnitKind::Target => {
                    let rt = self.units.get_mut(name).unwrap();
                    rt.state = UnitState::Active;
                    rt.was_active = true;
                    rt.deadline_ms = None;
                    rt.last_error = None;
                    if name == "multi-user.target" && !self.boot_healthy_marked {
                        self.boot_healthy_marked = true;
                        actions.push(ManagerAction::MarkBootHealthy);
                    }
                }
                UnitKind::Mount => {
                    let mount_spec = spec.mount.clone().expect("validated mount spec");
                    let rt = self.units.get_mut(name).unwrap();
                    rt.state = UnitState::Starting;
                    rt.deadline_ms = Some(now_ms.saturating_add(spec.ready_timeout_ms));
                    rt.last_error = None;
                    actions.push(ManagerAction::MountFs {
                        unit: name.clone(),
                        spec: mount_spec,
                    });
                }
                UnitKind::Service => {
                    let rt = self.units.get_mut(name).unwrap();
                    rt.state = UnitState::Starting;
                    rt.deadline_ms = Some(now_ms.saturating_add(spec.ready_timeout_ms));
                    rt.killed = false;
                    rt.was_active = false;
                    rt.last_error = None;
                    actions.push(ManagerAction::SpawnService {
                        unit: name.clone(),
                        spec: Box::new(spec.clone()),
                        use_ready_fd: spec.readiness == Readiness::PipeFd,
                        notify_socket: (spec.readiness == Readiness::NotifySocket)
                            .then(|| self.notify_socket_path.clone()),
                    });
                }
            }
        }

        actions
    }

    fn has_active_successors_in(&self, unit: &str, scope: &BTreeSet<String>) -> bool {
        self.graph.successors(unit).iter().any(|succ| {
            scope.contains(succ)
                && self
                    .units
                    .get(succ)
                    .is_some_and(|rt| !rt.state.is_stopped())
        })
    }

    fn has_any_active_successor(&self, unit: &str) -> bool {
        self.graph.successors(unit).iter().any(|succ| {
            self.units
                .get(succ)
                .is_some_and(|rt| !rt.state.is_stopped())
        })
    }

    fn tick_shutdown(&mut self, now_ms: u64) -> Vec<ManagerAction> {
        if self.shutdown_complete {
            return Vec::new();
        }
        let mut actions = Vec::new();
        let rev_order = self.graph.shutdown_order();

        for name in &rev_order {
            // Strict reverse topological barrier: do not stop a unit while any dependent ordered
            // after it is still running or stopping!
            if self.has_any_active_successor(name) {
                continue;
            }
            let spec = self.graph.unit(name).unwrap().clone();
            let rt = self.units.get_mut(name).unwrap();
            match rt.state {
                UnitState::Inactive | UnitState::Failed => {}
                UnitState::Backoff => {
                    rt.state = UnitState::Inactive;
                    rt.deadline_ms = None;
                }
                UnitState::Stopping => {
                    if rt.deadline_ms.is_some_and(|d| now_ms >= d)
                        && !rt.killed
                        && let Some(pid) = rt.pid
                    {
                        rt.killed = true;
                        actions.push(ManagerAction::SignalUnit {
                            unit: name.clone(),
                            pid,
                            signal: SIGKILL,
                        });
                    }
                }
                UnitState::Starting | UnitState::Active => match spec.kind {
                    UnitKind::Service => {
                        if let Some(pid) = rt.pid {
                            rt.state = UnitState::Stopping;
                            rt.deadline_ms = Some(now_ms.saturating_add(spec.stop_timeout_ms));
                            rt.killed = false;
                            actions.push(ManagerAction::SignalUnit {
                                unit: name.clone(),
                                pid,
                                signal: SIGTERM,
                            });
                        } else {
                            rt.state = UnitState::Inactive;
                            rt.deadline_ms = None;
                        }
                    }
                    UnitKind::Mount => {
                        rt.state = UnitState::Inactive;
                        rt.deadline_ms = None;
                        if rt.mounted
                            && let Some(mount) = &spec.mount
                        {
                            rt.mounted = false;
                            actions.push(ManagerAction::UmountFs {
                                unit: name.clone(),
                                target: mount.target.clone(),
                            });
                        }
                    }
                    UnitKind::Target => {
                        rt.state = UnitState::Inactive;
                        rt.deadline_ms = None;
                    }
                },
            }
        }

        if self.units.values().all(|rt| rt.state.is_stopped()) {
            self.shutdown_complete = true;
            actions.push(ManagerAction::CloseCleanRoot {
                reboot: self.shutdown_mode == ShutdownMode::Reboot,
            });
        }
        actions
    }

    fn schedule_failure_or_backoff(
        &mut self,
        name: &str,
        spec: &UnitSpec,
        now_ms: u64,
        actions: &mut Vec<ManagerAction>,
    ) {
        let rt = self.units.get_mut(name).unwrap();
        let next_attempt = rt.attempts.saturating_add(1);
        let allow_restart = match spec.restart {
            RestartPolicy::Never => false,
            RestartPolicy::OnFailure { max_attempts, .. } => next_attempt <= max_attempts,
            RestartPolicy::Always { .. } => true,
        };
        if allow_restart && let Some(delay) = spec.restart.delay_ms(next_attempt) {
            rt.attempts = next_attempt;
            rt.state = UnitState::Backoff;
            rt.deadline_ms = Some(now_ms.saturating_add(delay));
            actions.push(ManagerAction::Log {
                unit: name.to_owned(),
                message: format!("backoff attempt {next_attempt} for {delay}ms"),
            });
        } else {
            rt.state = UnitState::Failed;
            rt.deadline_ms = None;
            actions.push(ManagerAction::Log {
                unit: name.to_owned(),
                message: match spec.failure_policy {
                    FailurePolicy::Optional => "optional unit failed (non-blocking)".into(),
                    FailurePolicy::Required => "required unit failed".into(),
                },
            });
        }
    }

    /// Notify the manager that a `SpawnService` action succeeded with child `pid`.
    pub fn on_spawned(&mut self, unit: &str, pid: u32, _now_ms: u64) -> Result<(), Error> {
        let spec = self
            .graph
            .unit(unit)
            .ok_or_else(|| Error::because(Errno::ENOENT, format!("unknown unit '{unit}'")))?
            .clone();
        let rt = self.units.get_mut(unit).unwrap();
        if rt.state != UnitState::Starting {
            return Err(Error::because(
                Errno::EINVAL,
                format!("unit '{unit}' is not starting"),
            ));
        }
        rt.pid = Some(pid);
        if spec.readiness == Readiness::Immediate {
            rt.state = UnitState::Active;
            rt.was_active = true;
            rt.deadline_ms = None;
        }
        Ok(())
    }

    /// Notify the manager that spawning a service failed immediately before obtaining a PID.
    pub fn on_spawn_failed(&mut self, unit: &str, error: &str, now_ms: u64) -> Vec<ManagerAction> {
        let mut actions = Vec::new();
        let Some(spec) = self.graph.unit(unit).cloned() else {
            return actions;
        };
        if let Some(rt) = self.units.get_mut(unit) {
            rt.pid = None;
            rt.last_error = Some(error.to_owned());
        }
        self.schedule_failure_or_backoff(unit, &spec, now_ms, &mut actions);
        actions
    }

    /// Report completion of a `MountFs` action.
    pub fn on_mount_result(
        &mut self,
        unit: &str,
        result: Result<(), String>,
        _now_ms: u64,
    ) -> Vec<ManagerAction> {
        let mut actions = Vec::new();
        let Some(spec) = self.graph.unit(unit).cloned() else {
            return actions;
        };
        let Some(rt) = self.units.get_mut(unit) else {
            return actions;
        };
        rt.deadline_ms = None;
        match result {
            Ok(()) => {
                rt.state = UnitState::Active;
                rt.mounted = true;
                rt.was_active = true;
                rt.last_error = None;
            }
            Err(err) => {
                rt.state = UnitState::Failed;
                rt.mounted = false;
                rt.last_error = Some(err.clone());
                actions.push(ManagerAction::Log {
                    unit: unit.to_owned(),
                    message: format!(
                        "{} mount failed: {err}",
                        if spec.failure_policy == FailurePolicy::Optional {
                            "optional"
                        } else {
                            "required"
                        }
                    ),
                });
            }
        }
        actions
    }

    /// Report readiness over an inherited `OS_READY_FD` pipe (`Readiness::PipeFd`).
    pub fn on_ready_fd(&mut self, unit: &str, pid: u32, now_ms: u64) -> Result<bool, Error> {
        let spec = self
            .graph
            .unit(unit)
            .ok_or_else(|| Error::because(Errno::ENOENT, format!("unknown unit '{unit}'")))?;
        if spec.readiness != Readiness::PipeFd {
            return Err(Error::because(
                Errno::EINVAL,
                format!("unit '{unit}' does not use pipe_fd readiness"),
            ));
        }
        let rt = self.units.get_mut(unit).unwrap();
        if self.shutdown_mode != ShutdownMode::None
            || rt.state != UnitState::Starting
            || rt.pid != Some(pid)
            || rt.deadline_ms.is_some_and(|d| now_ms >= d)
        {
            return Ok(false);
        }
        rt.state = UnitState::Active;
        rt.was_active = true;
        rt.deadline_ms = None;
        Ok(true)
    }

    /// Process a `NOTIFY_SOCKET` datagram authenticated strictly by kernel `SO_PEERCRED`.
    /// Any datagram whose `cred.pid` does not match a supervised unit's live `pid` is rejected
    /// with `Errno::EPERM` (spoofing defense!).
    pub fn on_notify(
        &mut self,
        cred: PeerCred,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<String, Error> {
        let msg = NotifyMessage::parse(payload)?;
        let Some(unit_name) = self
            .units
            .iter()
            .find_map(|(name, rt)| (rt.pid == Some(cred.pid)).then(|| name.clone()))
        else {
            self.spoofed_notify_count = self.spoofed_notify_count.saturating_add(1);
            return Err(Error::because(
                Errno::EPERM,
                format!(
                    "rejected spoofed NOTIFY_SOCKET datagram from non-unit pid {}",
                    cred.pid
                ),
            ));
        };
        let spec = self.graph.unit(&unit_name).unwrap();
        if spec.readiness != Readiness::NotifySocket && msg.ready {
            self.spoofed_notify_count = self.spoofed_notify_count.saturating_add(1);
            return Err(Error::because(
                Errno::EPERM,
                format!("unit '{unit_name}' is not configured for notify_socket readiness"),
            ));
        }
        let rt = self.units.get_mut(&unit_name).unwrap();
        if let Some(status) = msg.status {
            rt.status_text = Some(status);
        }
        if msg.ready
            && self.shutdown_mode == ShutdownMode::None
            && rt.state == UnitState::Starting
            && !rt.deadline_ms.is_some_and(|d| now_ms >= d)
        {
            rt.state = UnitState::Active;
            rt.was_active = true;
            rt.deadline_ms = None;
        }
        if msg.stopping && rt.state == UnitState::Active {
            rt.state = UnitState::Stopping;
        }
        Ok(unit_name)
    }

    /// Handle process exit for a supervised `pid`.
    pub fn on_exited(&mut self, pid: u32, exit_code: i32, now_ms: u64) -> Vec<ManagerAction> {
        let mut actions = Vec::new();
        let Some(unit_name) = self
            .units
            .iter()
            .find_map(|(name, rt)| (rt.pid == Some(pid)).then(|| name.clone()))
        else {
            return actions;
        };
        let spec = self.graph.unit(&unit_name).unwrap().clone();
        let rt = self.units.get_mut(&unit_name).unwrap();
        rt.pid = None;
        let was_stopping = rt.state == UnitState::Stopping;
        let was_active = rt.was_active;
        let explicitly_stopped =
            self.explicit_stopping.remove(&unit_name) || self.shutdown_mode != ShutdownMode::None;

        if explicitly_stopped {
            rt.state = UnitState::Inactive;
            rt.deadline_ms = None;
            return actions;
        }

        // Timeout-induced stop transitions into restart backoff or Failed.
        if was_stopping && rt.last_error.is_some() {
            self.schedule_failure_or_backoff(&unit_name, &spec, now_ms, &mut actions);
            return actions;
        }

        let clean_exit = exit_code == 0 && was_active;
        if clean_exit && !matches!(spec.restart, RestartPolicy::Always { .. }) {
            rt.state = UnitState::Inactive;
            rt.deadline_ms = None;
            self.desired_active.remove(&unit_name);
            return actions;
        }

        if !clean_exit {
            rt.last_error = Some(format!("exited with code {exit_code}"));
        }
        self.schedule_failure_or_backoff(&unit_name, &spec, now_ms, &mut actions);
        actions
    }

    /// Authenticate and execute a framed control request using kernel `SO_PEERCRED`.
    pub fn handle_control(
        &mut self,
        cred: PeerCred,
        req: ControlRequest,
        now_ms: u64,
    ) -> (ControlResponse, Vec<ManagerAction>) {
        if let Err(err) = authorize_control(self.manager_uid, cred, &req) {
            return (
                ControlResponse::Error {
                    errno: err.errno,
                    message: err.to_string(),
                },
                Vec::new(),
            );
        }
        match req {
            ControlRequest::List => (
                ControlResponse::Units {
                    units: self.list_statuses(),
                },
                Vec::new(),
            ),
            ControlRequest::Status { unit: None } => (
                ControlResponse::Units {
                    units: self.list_statuses(),
                },
                Vec::new(),
            ),
            ControlRequest::Status { unit: Some(name) } => match self.unit_status(&name) {
                Some(unit) => (ControlResponse::Unit { unit }, Vec::new()),
                None => (
                    ControlResponse::Error {
                        errno: Errno::ENOENT,
                        message: format!("unknown unit '{name}'"),
                    },
                    Vec::new(),
                ),
            },
            ControlRequest::Start { unit } => {
                if self.shutdown_mode != ShutdownMode::None {
                    return (
                        ControlResponse::Error {
                            errno: Errno::EBUSY,
                            message: "system shutdown is in progress".into(),
                        },
                        Vec::new(),
                    );
                }
                if self.graph.unit(&unit).is_none()
                    && let Ok(spec) = self.graph.instantiate_template(&unit).cloned()
                {
                    if let Err(err) = spec.authorize_for_manager(self.manager_uid) {
                        return (
                            ControlResponse::Error {
                                errno: err.errno,
                                message: err.to_string(),
                            },
                            Vec::new(),
                        );
                    }
                    self.units
                        .insert(unit.clone(), UnitRuntime::new(spec.enabled));
                }
                let plan = match self.graph.start_plan_for(&unit) {
                    Ok(p) => p,
                    Err(err) => {
                        return (
                            ControlResponse::Error {
                                errno: Errno::ENOENT,
                                message: err.to_string(),
                            },
                            Vec::new(),
                        );
                    }
                };
                for name in &plan {
                    self.explicit_stopping.remove(name);
                    self.desired_active.insert(name.clone());
                    if let Some(rt) = self.units.get_mut(name)
                        && rt.state == UnitState::Failed
                    {
                        rt.state = UnitState::Inactive;
                        rt.attempts = 0;
                        rt.last_error = None;
                        rt.deadline_ms = None;
                    }
                }
                let actions = self.tick(now_ms);
                (
                    ControlResponse::Ok {
                        message: Some(format!("starting {unit}")),
                    },
                    actions,
                )
            }
            ControlRequest::Stop { unit } => {
                let plan = match self.graph.stop_plan_for(&unit) {
                    Ok(p) => p,
                    Err(err) => {
                        return (
                            ControlResponse::Error {
                                errno: Errno::ENOENT,
                                message: err.to_string(),
                            },
                            Vec::new(),
                        );
                    }
                };
                for name in &plan {
                    self.desired_active.remove(name);
                    self.explicit_stopping.insert(name.clone());
                }
                let actions = self.tick(now_ms);
                (
                    ControlResponse::Ok {
                        message: Some(format!("stopping {unit}")),
                    },
                    actions,
                )
            }
            ControlRequest::Restart { unit } => {
                if self.graph.unit(&unit).is_none() {
                    return (
                        ControlResponse::Error {
                            errno: Errno::ENOENT,
                            message: format!("unknown unit '{unit}'"),
                        },
                        Vec::new(),
                    );
                }
                self.explicit_stopping.insert(unit.clone());
                self.desired_active.insert(unit.clone());
                if let Some(rt) = self.units.get_mut(&unit) {
                    rt.attempts = 0;
                    if rt.state == UnitState::Failed {
                        rt.state = UnitState::Inactive;
                        rt.last_error = None;
                    }
                }
                let actions = self.tick(now_ms);
                (
                    ControlResponse::Ok {
                        message: Some(format!("restarting {unit}")),
                    },
                    actions,
                )
            }
            ControlRequest::Enable { unit } => match self.units.get_mut(&unit) {
                Some(rt) => {
                    rt.enabled = true;
                    (
                        ControlResponse::Ok {
                            message: Some(format!("enabled {unit}")),
                        },
                        Vec::new(),
                    )
                }
                None => (
                    ControlResponse::Error {
                        errno: Errno::ENOENT,
                        message: format!("unknown unit '{unit}'"),
                    },
                    Vec::new(),
                ),
            },
            ControlRequest::Disable { unit } => match self.units.get_mut(&unit) {
                Some(rt) => {
                    rt.enabled = false;
                    (
                        ControlResponse::Ok {
                            message: Some(format!("disabled {unit}")),
                        },
                        Vec::new(),
                    )
                }
                None => (
                    ControlResponse::Error {
                        errno: Errno::ENOENT,
                        message: format!("unknown unit '{unit}'"),
                    },
                    Vec::new(),
                ),
            },
            ControlRequest::RegisterUnit { spec } => {
                let name = spec.name.clone();
                let enabled = spec.enabled;
                let is_template = spec.is_template();
                match self.graph.register_unit(*spec) {
                    Ok(()) => {
                        if !is_template {
                            self.units.insert(name.clone(), UnitRuntime::new(enabled));
                        }
                        (
                            ControlResponse::Ok {
                                message: Some(format!("registered {name}")),
                            },
                            Vec::new(),
                        )
                    }
                    Err(err) => (
                        ControlResponse::Error {
                            errno: Errno::EINVAL,
                            message: err.to_string(),
                        },
                        Vec::new(),
                    ),
                }
            }
            ControlRequest::Poweroff => {
                self.shutdown_mode = ShutdownMode::Poweroff;
                let actions = self.tick(now_ms);
                (
                    ControlResponse::Ok {
                        message: Some("initiating ordered poweroff".into()),
                    },
                    actions,
                )
            }
            ControlRequest::Reboot => {
                self.shutdown_mode = ShutdownMode::Reboot;
                let actions = self.tick(now_ms);
                (
                    ControlResponse::Ok {
                        message: Some("initiating ordered reboot".into()),
                    },
                    actions,
                )
            }
        }
    }
}
