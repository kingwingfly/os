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
use std::collections::{BTreeMap, BTreeSet, VecDeque};

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
    pub desired_gen: u64,
    pub active_gen: u64,
    launching_gen: u64,
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
            desired_gen: 0,
            active_gen: 0,
            launching_gen: 0,
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
    explicit_roots: BTreeSet<String>,
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
        for spec in graph.templates().values() {
            spec.authorize_for_manager(manager_uid)?;
        }
        Ok(Self {
            manager_uid,
            notify_socket_path,
            graph,
            units,
            explicit_roots: BTreeSet::new(),
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
        if self.units.get(target).is_some_and(|u| u.enabled) {
            self.explicit_roots.insert(target.to_owned());
        }
        for name in &plan {
            if let Some(rt) = self.units.get_mut(name)
                && rt.enabled
            {
                self.desired_active.insert(name.clone());
                if rt.state != UnitState::Active {
                    rt.desired_gen = rt.desired_gen.saturating_add(1);
                }
            }
        }
        Ok(plan)
    }

    /// Initiate a private, manager-local ordered reverse shutdown (e.g. when PID 1 or a per-user
    /// service manager receives `SIGTERM`) without routing through external control-socket
    /// `Poweroff`/`Reboot` authorization.
    pub fn begin_local_shutdown(&mut self, now_ms: u64) -> Vec<ManagerAction> {
        if self.shutdown_mode == ShutdownMode::None {
            self.shutdown_mode = ShutdownMode::Poweroff;
        }
        self.tick(now_ms)
    }

    fn all_desired_required_units_active(&self) -> bool {
        self.desired_active.iter().all(|name| {
            let Some(spec) = self.graph.unit(name) else {
                return true;
            };
            if spec.failure_policy != FailurePolicy::Required {
                return true;
            }
            self.units
                .get(name)
                .is_some_and(|rt| rt.state == UnitState::Active)
        })
    }

    fn compute_stop_set(&mut self, unit: &str) -> Result<Vec<String>, GraphError> {
        if self.graph.unit(unit).is_none() {
            return Err(GraphError::UnknownUnit(unit.to_owned()));
        }

        // 1. Hard-stop set: `unit` itself plus every transitive `requires`-dependent of it.
        let mut hard_stop = BTreeSet::new();
        let mut hard_queue = VecDeque::new();
        hard_stop.insert(unit.to_owned());
        hard_queue.push_back(unit.to_owned());
        while let Some(cur) = hard_queue.pop_front() {
            for (candidate, spec) in self.graph.units() {
                if spec.requires.iter().any(|r| r == &cur) && hard_stop.insert(candidate.clone()) {
                    hard_queue.push_back(candidate.clone());
                }
            }
        }

        // Remove explicitly stopped units (and their hard dependents) from active activation roots.
        for name in &hard_stop {
            self.explicit_roots.remove(name);
        }

        // 2. Compute transitive demand from all REMAINING active roots so shared prerequisites
        //    (e.g. `local-fs.target`, `multi-user.target`, or shared services) stay active!
        let mut still_demanded = BTreeSet::new();
        let mut demand_queue = VecDeque::new();
        for root in &self.explicit_roots {
            if !hard_stop.contains(root) && still_demanded.insert(root.clone()) {
                demand_queue.push_back(root.clone());
            }
        }
        while let Some(cur) = demand_queue.pop_front() {
            for dep in self.graph.activation_edges(&cur) {
                if !hard_stop.contains(dep)
                    && (self.desired_active.contains(dep) || self.explicit_roots.contains(dep))
                    && still_demanded.insert(dep.clone())
                {
                    demand_queue.push_back(dep.clone());
                }
            }
        }

        // 3. When stopping an optional feature target (e.g. `cloud-online.target`), tear down
        //    only its soft `wants`/`wanted_by` children that are NO LONGER demanded by any
        //    remaining active root (plus any hard `requires`-dependents of those torn-down units).
        let mut to_stop = hard_stop.clone();
        let mut soft_queue = VecDeque::new();
        for name in &hard_stop {
            if let Some(spec) = self.graph.unit(name)
                && spec.kind == UnitKind::Target
                && spec.failure_policy == FailurePolicy::Optional
            {
                soft_queue.push_back(name.clone());
            }
        }
        while let Some(cur) = soft_queue.pop_front() {
            let children: Vec<String> = self.graph.optional_children(&cur).cloned().collect();
            for child in children {
                if still_demanded.contains(&child) {
                    continue;
                }
                if to_stop.insert(child.clone()) {
                    self.explicit_roots.remove(&child);
                    soft_queue.push_back(child.clone());
                    let mut req_q = VecDeque::from([child]);
                    while let Some(stopped) = req_q.pop_front() {
                        for (candidate, spec) in self.graph.units() {
                            if spec.requires.iter().any(|r| r == &stopped)
                                && to_stop.insert(candidate.clone())
                            {
                                self.explicit_roots.remove(candidate);
                                req_q.push_back(candidate.clone());
                                soft_queue.push_back(candidate.clone());
                            }
                        }
                    }
                }
            }
        }

        Ok(self
            .graph
            .start_order()
            .iter()
            .rev()
            .filter(|u| to_stop.contains(*u))
            .cloned()
            .collect())
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
            if rt.state == UnitState::Stopping {
                if rt.deadline_ms.is_none() {
                    rt.deadline_ms = Some(now_ms.saturating_add(spec.stop_timeout_ms));
                    rt.killed = false;
                }
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
                    rt.active_gen = rt.desired_gen;
                }
                UnitKind::Mount => {
                    let mount_spec = spec.mount.clone().expect("validated mount spec");
                    let rt = self.units.get_mut(name).unwrap();
                    rt.state = UnitState::Starting;
                    rt.deadline_ms = Some(now_ms.saturating_add(spec.ready_timeout_ms));
                    rt.last_error = None;
                    rt.launching_gen = rt.desired_gen;
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
                    rt.launching_gen = rt.desired_gen;
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

        // Only emit `MarkBootHealthy` once `multi-user.target` AND every desired required unit
        // (including `user-session@<default_uid>.service`) are `Active`.
        if !self.boot_healthy_marked
            && self
                .units
                .get("multi-user.target")
                .is_some_and(|rt| rt.state == UnitState::Active)
            && self.all_desired_required_units_active()
        {
            self.boot_healthy_marked = true;
            actions.push(ManagerAction::MarkBootHealthy);
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
                    if rt.deadline_ms.is_none() {
                        rt.deadline_ms = Some(now_ms.saturating_add(spec.stop_timeout_ms));
                        rt.killed = false;
                    }
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
        rt.active_gen = if rt.launching_gen != 0 {
            rt.launching_gen
        } else {
            rt.desired_gen
        };
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
        let stop_timeout_ms = spec.stop_timeout_ms;
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
        if msg.stopping && matches!(rt.state, UnitState::Starting | UnitState::Active) {
            rt.state = UnitState::Stopping;
            rt.deadline_ms = Some(now_ms.saturating_add(stop_timeout_ms));
            rt.killed = false;
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
        let superseded_by_start = rt.active_gen < rt.desired_gen
            && self.desired_active.contains(&unit_name)
            && self.shutdown_mode == ShutdownMode::None;
        let explicitly_stopped =
            self.explicit_stopping.remove(&unit_name) || self.shutdown_mode != ShutdownMode::None;

        if superseded_by_start {
            // A newer `Start`/`Restart` arrived while this older generation was stopping:
            // preserve `desired_active` so `tick(now_ms)` relaunches cleanly!
            rt.state = UnitState::Inactive;
            rt.deadline_ms = None;
            rt.killed = false;
            rt.attempts = 0;
            rt.last_error = None;
            return actions;
        }

        if explicitly_stopped {
            rt.state = UnitState::Inactive;
            rt.deadline_ms = None;
            rt.killed = false;
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
            rt.killed = false;
            self.desired_active.remove(&unit_name);
            self.explicit_roots.remove(&unit_name);
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
                    && let Ok(spec) = self.graph.preview_template_instance(&unit)
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
                    let enabled = spec.enabled;
                    if let Err(err) = self.graph.register_unit(spec) {
                        return (
                            ControlResponse::Error {
                                errno: Errno::EINVAL,
                                message: err.to_string(),
                            },
                            Vec::new(),
                        );
                    }
                    self.units.insert(unit.clone(), UnitRuntime::new(enabled));
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
                self.explicit_roots.insert(unit.clone());
                for name in &plan {
                    self.explicit_stopping.remove(name);
                    self.desired_active.insert(name.clone());
                    if let Some(rt) = self.units.get_mut(name) {
                        if rt.state != UnitState::Active {
                            rt.desired_gen = rt.desired_gen.saturating_add(1);
                        }
                        if rt.state == UnitState::Failed {
                            rt.state = UnitState::Inactive;
                            rt.attempts = 0;
                            rt.last_error = None;
                            rt.deadline_ms = None;
                        }
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
                let plan = match self.compute_stop_set(&unit) {
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
                    self.explicit_roots.remove(name);
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
                if self.shutdown_mode != ShutdownMode::None {
                    return (
                        ControlResponse::Error {
                            errno: Errno::EBUSY,
                            message: "system shutdown is in progress".into(),
                        },
                        Vec::new(),
                    );
                }
                if self.graph.unit(&unit).is_none() {
                    return (
                        ControlResponse::Error {
                            errno: Errno::ENOENT,
                            message: format!("unknown unit '{unit}'"),
                        },
                        Vec::new(),
                    );
                }
                self.explicit_roots.insert(unit.clone());
                self.explicit_stopping.insert(unit.clone());
                self.desired_active.insert(unit.clone());
                if let Some(rt) = self.units.get_mut(&unit) {
                    rt.desired_gen = rt.desired_gen.saturating_add(1);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::default_boot_graph;
    use crate::unit::{
        CapabilityGrant, DEFAULT_READY_TIMEOUT_MS, MountNsPolicy, UNIT_MANIFEST_VERSION,
    };

    fn root_cred() -> PeerCred {
        PeerCred {
            pid: 1,
            uid: 0,
            gid: 0,
        }
    }

    fn make_service(
        name: &str,
        after: Vec<&str>,
        requires: Vec<&str>,
        wanted_by: Vec<&str>,
    ) -> UnitSpec {
        UnitSpec {
            version: UNIT_MANIFEST_VERSION,
            name: name.into(),
            kind: UnitKind::Service,
            description: String::new(),
            after: after.into_iter().map(String::from).collect(),
            wants: Vec::new(),
            requires: requires.into_iter().map(String::from).collect(),
            wanted_by: wanted_by.into_iter().map(String::from).collect(),
            failure_policy: FailurePolicy::Required,
            readiness: Readiness::NotifySocket,
            ready_timeout_ms: DEFAULT_READY_TIMEOUT_MS,
            stop_timeout_ms: 1_500,
            restart: RestartPolicy::Never,
            exec_start: Some(vec![format!("/usr/bin/{name}")]),
            exec_stop: None,
            cwd: Some("/".into()),
            environment: BTreeMap::new(),
            mount: None,
            grant: CapabilityGrant::default(),
            enabled: true,
        }
    }

    #[test]
    fn boot_healthy_waits_for_user_session_and_all_required_units() {
        let mut graph = default_boot_graph(1000).unwrap();
        // Extra required service wanted by `multi-user.target` without an explicit `after` edge on
        // `multi-user.target`: `MarkBootHealthy` must still wait until it reaches `Active`.
        let extra = make_service(
            "auditd.service",
            vec!["local-fs.target"],
            vec!["local-fs.target"],
            vec!["multi-user.target"],
        );
        graph.register_unit(extra).unwrap();

        let mut mgr = ServiceManager::new_system(graph).unwrap();
        mgr.boot_target("multi-user.target").unwrap();

        let actions = mgr.tick(0);
        assert!(!actions.contains(&ManagerAction::MarkBootHealthy));
        assert!(!mgr.is_boot_healthy());
        assert_eq!(mgr.unit_state("local-fs.target"), Some(UnitState::Active));
        assert_eq!(
            mgr.unit_state("multi-user.target"),
            Some(UnitState::Inactive)
        );
        assert_eq!(
            mgr.unit_state("user-session@1000.service"),
            Some(UnitState::Starting)
        );
        assert_eq!(mgr.unit_state("auditd.service"), Some(UnitState::Starting));

        for (unit, pid, uid) in [("mountd.service", 61, 0), ("exportd.service", 62, 998)] {
            mgr.tick(0);
            assert_eq!(mgr.unit_state(unit), Some(UnitState::Starting));
            mgr.on_spawned(unit, pid, 0).unwrap();
            mgr.on_notify(PeerCred { pid, uid, gid: uid }, b"READY=1\n", 0)
                .unwrap();
        }
        mgr.on_spawned("user-session@1000.service", 10, 5).unwrap();
        mgr.on_spawned("auditd.service", 11, 5).unwrap();
        mgr.on_notify(
            PeerCred {
                pid: 10,
                uid: 1000,
                gid: 1000,
            },
            b"READY=1\n",
            10,
        )
        .unwrap();

        // `multi-user.target` activates once `user-session@1000.service` is ready,
        // but `MarkBootHealthy` STILL waits for `auditd.service` (Required)!
        let actions = mgr.tick(15);
        assert_eq!(mgr.unit_state("multi-user.target"), Some(UnitState::Active));
        assert!(!actions.contains(&ManagerAction::MarkBootHealthy));
        assert!(!mgr.is_boot_healthy());

        mgr.on_notify(
            PeerCred {
                pid: 11,
                uid: 0,
                gid: 0,
            },
            b"READY=1\n",
            20,
        )
        .unwrap();
        let actions = mgr.tick(25);
        assert!(actions.contains(&ManagerAction::MarkBootHealthy));
        assert!(mgr.is_boot_healthy());
    }

    #[test]
    fn stalled_stopping_notify_escalates_to_sigkill_in_tick_and_shutdown() {
        // 1. Stalled `STOPPING=1` during normal runtime (`tick()`).
        let svc = make_service("staller.service", vec![], vec![], vec![]);
        let mut mgr =
            ServiceManager::new_system(UnitGraph::build(vec![svc.clone()]).unwrap()).unwrap();
        mgr.boot_target("staller.service").unwrap();
        let _ = mgr.tick(0);
        mgr.on_spawned("staller.service", 40, 10).unwrap();
        mgr.on_notify(
            PeerCred {
                pid: 40,
                uid: 0,
                gid: 0,
            },
            b"READY=1\n",
            20,
        )
        .unwrap();
        assert_eq!(mgr.unit_state("staller.service"), Some(UnitState::Active));
        assert_eq!(
            mgr.unit_runtime("staller.service").unwrap().deadline_ms,
            None
        );

        // Unit sends `STOPPING=1` at t=100 -> must install stop_timeout_ms (1500ms) deadline!
        mgr.on_notify(
            PeerCred {
                pid: 40,
                uid: 0,
                gid: 0,
            },
            b"STOPPING=1\n",
            100,
        )
        .unwrap();
        assert_eq!(mgr.unit_state("staller.service"), Some(UnitState::Stopping));
        assert_eq!(
            mgr.unit_runtime("staller.service").unwrap().deadline_ms,
            Some(1_600)
        );
        assert!(mgr.tick(1_599).is_empty());
        let actions = mgr.tick(1_600);
        assert!(actions.contains(&ManagerAction::SignalUnit {
            unit: "staller.service".into(),
            pid: 40,
            signal: SIGKILL,
        }));

        // 2. Stalled `STOPPING=1` followed by `Poweroff` (`tick_shutdown()`).
        let mut mgr2 = ServiceManager::new_system(UnitGraph::build(vec![svc]).unwrap()).unwrap();
        mgr2.boot_target("staller.service").unwrap();
        let _ = mgr2.tick(0);
        mgr2.on_spawned("staller.service", 41, 10).unwrap();
        mgr2.on_notify(
            PeerCred {
                pid: 41,
                uid: 0,
                gid: 0,
            },
            b"READY=1\n",
            20,
        )
        .unwrap();
        mgr2.on_notify(
            PeerCred {
                pid: 41,
                uid: 0,
                gid: 0,
            },
            b"STOPPING=1\n",
            200,
        )
        .unwrap();
        let (_, actions) = mgr2.handle_control(root_cred(), ControlRequest::Poweroff, 300);
        assert!(actions.is_empty());
        let actions = mgr2.tick(1_700);
        assert!(actions.contains(&ManagerAction::SignalUnit {
            unit: "staller.service".into(),
            pid: 41,
            signal: SIGKILL,
        }));
        let _ = mgr2.on_exited(41, 137, 1_710);
        let actions = mgr2.tick(1_720);
        assert!(actions.contains(&ManagerAction::CloseCleanRoot { reboot: false }));
    }

    #[test]
    fn user_manager_local_shutdown_stops_units_in_reverse_while_control_poweroff_stays_eperm() {
        let mut a = make_service("a.service", vec![], vec![], vec![]);
        a.readiness = Readiness::Immediate;
        a.grant.mount_namespace = MountNsPolicy::Session;
        let mut b = make_service("b.service", vec!["a.service"], vec!["a.service"], vec![]);
        b.readiness = Readiness::Immediate;
        b.grant.mount_namespace = MountNsPolicy::Session;
        let graph = UnitGraph::build(vec![a, b]).unwrap();
        let mut user_mgr = ServiceManager::new_user(1000, graph).unwrap();
        let owner = PeerCred {
            pid: 50,
            uid: 1000,
            gid: 1000,
        };

        // External control-socket Poweroff / Reboot MUST still fail EPERM!
        for req in [ControlRequest::Poweroff, ControlRequest::Reboot] {
            let (resp, actions) = user_mgr.handle_control(owner, req, 0);
            assert!(matches!(
                resp,
                ControlResponse::Error {
                    errno: Errno::EPERM,
                    ..
                }
            ));
            assert!(actions.is_empty());
        }

        // Start b.service (pulls in a.service first).
        let (resp, actions) = user_mgr.handle_control(
            owner,
            ControlRequest::Start {
                unit: "b.service".into(),
            },
            10,
        );
        assert!(matches!(resp, ControlResponse::Ok { .. }));
        assert_eq!(actions.len(), 1);
        user_mgr.on_spawned("a.service", 101, 10).unwrap();
        let actions = user_mgr.tick(15);
        assert_eq!(actions.len(), 1);
        user_mgr.on_spawned("b.service", 102, 15).unwrap();
        assert_eq!(user_mgr.unit_state("a.service"), Some(UnitState::Active));
        assert_eq!(user_mgr.unit_state("b.service"), Some(UnitState::Active));

        // Private SIGTERM shutdown stops `b.service` FIRST, then `a.service`, then completes!
        let actions = user_mgr.begin_local_shutdown(100);
        assert_eq!(
            actions,
            vec![ManagerAction::SignalUnit {
                unit: "b.service".into(),
                pid: 102,
                signal: SIGTERM,
            }]
        );
        let _ = user_mgr.on_exited(102, 0, 120);
        let actions = user_mgr.tick(130);
        assert_eq!(
            actions,
            vec![ManagerAction::SignalUnit {
                unit: "a.service".into(),
                pid: 101,
                signal: SIGTERM,
            }]
        );
        let _ = user_mgr.on_exited(101, 0, 140);
        let actions = user_mgr.tick(150);
        assert!(actions.contains(&ManagerAction::CloseCleanRoot { reboot: false }));
        assert!(user_mgr.is_shutdown_complete());
    }

    #[test]
    fn stopping_optional_target_requiring_local_fs_keeps_shared_prerequisites_and_multi_user_active()
     {
        let mut graph = default_boot_graph(1000).unwrap();

        // Shared service wanted by BOTH `multi-user.target` AND `opt-feature.target`.
        let mut shared = make_service(
            "shared.service",
            vec!["local-fs.target"],
            vec!["local-fs.target"],
            vec!["multi-user.target", "opt-feature.target"],
        );
        shared.readiness = Readiness::Immediate;

        // Exclusive service wanted ONLY by `opt-feature.target`.
        let mut exclusive = make_service(
            "opt-only.service",
            vec!["local-fs.target"],
            vec!["local-fs.target"],
            vec!["opt-feature.target"],
        );
        exclusive.readiness = Readiness::Immediate;
        exclusive.failure_policy = FailurePolicy::Optional;

        // Optional target that explicitly `requires: ["local-fs.target"]`!
        let opt_target = UnitSpec {
            version: UNIT_MANIFEST_VERSION,
            name: "opt-feature.target".into(),
            kind: UnitKind::Target,
            description: String::new(),
            after: vec![
                "local-fs.target".into(),
                "shared.service".into(),
                "opt-only.service".into(),
            ],
            wants: vec!["shared.service".into(), "opt-only.service".into()],
            requires: vec!["local-fs.target".into()],
            wanted_by: Vec::new(),
            failure_policy: FailurePolicy::Optional,
            readiness: Readiness::Immediate,
            ready_timeout_ms: DEFAULT_READY_TIMEOUT_MS,
            stop_timeout_ms: 1_500,
            restart: RestartPolicy::Never,
            exec_start: None,
            exec_stop: None,
            cwd: None,
            environment: BTreeMap::new(),
            mount: None,
            grant: CapabilityGrant::default(),
            enabled: true,
        };

        graph.register_unit(shared).unwrap();
        graph.register_unit(exclusive).unwrap();
        graph.register_unit(opt_target).unwrap();

        let mut mgr = ServiceManager::new_system(graph).unwrap();
        mgr.boot_target("multi-user.target").unwrap();
        let _ = mgr.tick(0);
        mgr.on_spawned("user-session@1000.service", 10, 0).unwrap();
        mgr.on_spawned("shared.service", 11, 0).unwrap();
        mgr.on_notify(
            PeerCred {
                pid: 10,
                uid: 1000,
                gid: 1000,
            },
            b"READY=1\n",
            5,
        )
        .unwrap();
        let _ = mgr.tick(10);
        assert_eq!(mgr.unit_state("multi-user.target"), Some(UnitState::Active));
        assert_eq!(mgr.unit_state("shared.service"), Some(UnitState::Active));

        // Start optional feature target.
        let (resp, _) = mgr.handle_control(
            root_cred(),
            ControlRequest::Start {
                unit: "opt-feature.target".into(),
            },
            20,
        );
        assert!(matches!(resp, ControlResponse::Ok { .. }));
        mgr.on_spawned("opt-only.service", 12, 20).unwrap();
        let _ = mgr.tick(25);
        assert_eq!(
            mgr.unit_state("opt-feature.target"),
            Some(UnitState::Active)
        );
        assert_eq!(mgr.unit_state("opt-only.service"), Some(UnitState::Active));

        // Stop optional feature target -> MUST stop ONLY `opt-feature.target` and `opt-only.service`!
        let (resp, actions) = mgr.handle_control(
            root_cred(),
            ControlRequest::Stop {
                unit: "opt-feature.target".into(),
            },
            50,
        );
        assert!(matches!(resp, ControlResponse::Ok { .. }));
        assert_eq!(
            mgr.unit_state("opt-feature.target"),
            Some(UnitState::Inactive)
        );
        assert_eq!(
            actions,
            vec![ManagerAction::SignalUnit {
                unit: "opt-only.service".into(),
                pid: 12,
                signal: SIGTERM,
            }]
        );
        let _ = mgr.on_exited(12, 0, 60);
        let _ = mgr.tick(70);

        assert_eq!(
            mgr.unit_state("opt-only.service"),
            Some(UnitState::Inactive)
        );
        assert_eq!(mgr.unit_state("local-fs.target"), Some(UnitState::Active));
        assert_eq!(mgr.unit_state("multi-user.target"), Some(UnitState::Active));
        assert_eq!(
            mgr.unit_state("user-session@1000.service"),
            Some(UnitState::Active)
        );
        assert_eq!(mgr.unit_state("shared.service"), Some(UnitState::Active));
    }

    #[test]
    fn start_accepted_while_stopping_relaunches_after_old_pid_exits() {
        let mut svc = make_service("relaunch.service", vec![], vec![], vec![]);
        svc.readiness = Readiness::Immediate;
        svc.restart = RestartPolicy::Never;
        let mut mgr = ServiceManager::new_system(UnitGraph::build(vec![svc]).unwrap()).unwrap();

        // Start generation 1.
        let (resp, actions) = mgr.handle_control(
            root_cred(),
            ControlRequest::Start {
                unit: "relaunch.service".into(),
            },
            0,
        );
        assert!(matches!(resp, ControlResponse::Ok { .. }));
        assert_eq!(actions.len(), 1);
        mgr.on_spawned("relaunch.service", 200, 5).unwrap();
        assert_eq!(mgr.unit_state("relaunch.service"), Some(UnitState::Active));
        assert_eq!(mgr.unit_runtime("relaunch.service").unwrap().active_gen, 1);

        // Stop -> sends SIGTERM to pid 200, unit enters `Stopping`.
        let (resp, actions) = mgr.handle_control(
            root_cred(),
            ControlRequest::Stop {
                unit: "relaunch.service".into(),
            },
            10,
        );
        assert!(matches!(resp, ControlResponse::Ok { .. }));
        assert_eq!(
            actions,
            vec![ManagerAction::SignalUnit {
                unit: "relaunch.service".into(),
                pid: 200,
                signal: SIGTERM,
            }]
        );
        assert_eq!(
            mgr.unit_state("relaunch.service"),
            Some(UnitState::Stopping)
        );

        // New `Start` arrives while pid 200 is STILL stopping -> bumps `desired_gen` to 2.
        let (resp, actions) = mgr.handle_control(
            root_cred(),
            ControlRequest::Start {
                unit: "relaunch.service".into(),
            },
            15,
        );
        assert!(matches!(resp, ControlResponse::Ok { .. }));
        assert!(
            actions.is_empty(),
            "must wait for old pid to exit before respawning"
        );
        let rt = mgr.unit_runtime("relaunch.service").unwrap();
        assert_eq!(rt.state, UnitState::Stopping);
        assert_eq!(rt.active_gen, 1);
        assert_eq!(rt.desired_gen, 2);

        // Old pid 200 exits cleanly with code 0 -> must NOT drop `desired_active`!
        let _ = mgr.on_exited(200, 0, 20);
        assert_eq!(
            mgr.unit_state("relaunch.service"),
            Some(UnitState::Inactive)
        );

        // Next `tick()` MUST relaunch generation 2!
        let actions = mgr.tick(25);
        assert!(matches!(
            actions.as_slice(),
            [ManagerAction::SpawnService { unit, .. }] if unit == "relaunch.service"
        ));
        mgr.on_spawned("relaunch.service", 201, 25).unwrap();
        let rt = mgr.unit_runtime("relaunch.service").unwrap();
        assert_eq!(rt.state, UnitState::Active);
        assert_eq!(rt.pid, Some(201));
        assert_eq!(rt.active_gen, 2);
        assert_eq!(rt.desired_gen, 2);

        // Once generation 2 exits cleanly on its own (no newer start), it stays Inactive.
        let _ = mgr.on_exited(201, 0, 50);
        assert!(mgr.tick(60).is_empty());
        assert_eq!(
            mgr.unit_state("relaunch.service"),
            Some(UnitState::Inactive)
        );
    }
}
