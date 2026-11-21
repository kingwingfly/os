//! Pure-Rust deterministic unit DAG resolver, cycle detector, reverse shutdown planner,
//! and built-in default system unit catalog (`#57` `L3d`, Contract v2 §2.15).

use crate::unit::{
    CapabilityGrant, DEFAULT_READY_TIMEOUT_MS, DEFAULT_STOP_TIMEOUT_MS, FailurePolicy,
    MountNsPolicy, MountUnitSpec, Readiness, RestartPolicy, UNIT_MANIFEST_VERSION, UnitKind,
    UnitSpec, split_template_instance,
};
use abi::auth_v2::RemoteScope;
use abi::mount_flags::{MS_NODEV, MS_NOSUID};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

/// Default remote device instances activated under `cloud-online.target` when signed into Cloud.
pub const CLOUD_DEVICE_INSTANCES: &[&str] = &["archive", "media", "present", "snd"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GraphError {
    DuplicateUnit(String),
    UnknownUnit(String),
    UnknownDependency { unit: String, dependency: String },
    Cycle(Vec<String>),
    InvalidUnit(String),
}

impl fmt::Display for GraphError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateUnit(u) => write!(f, "duplicate unit '{u}'"),
            Self::UnknownUnit(u) => write!(f, "unknown unit '{u}'"),
            Self::UnknownDependency { unit, dependency } => {
                write!(f, "unit '{unit}' depends on unknown unit '{dependency}'")
            }
            Self::Cycle(cycle) => write!(f, "unit dependency cycle: {}", cycle.join(" -> ")),
            Self::InvalidUnit(msg) => write!(f, "invalid unit: {msg}"),
        }
    }
}

impl std::error::Error for GraphError {}

/// Resolved acyclic dependency graph of concrete units + template blueprints.
#[derive(Clone, Debug)]
pub struct UnitGraph {
    units: BTreeMap<String, UnitSpec>,
    templates: BTreeMap<String, UnitSpec>,
    /// Effective activation edges (`unit -> units activated when starting unit`),
    /// combining `requires`, `wants`, and reverse `wanted_by` declarations.
    activates: BTreeMap<String, BTreeSet<String>>,
    /// Effective ordering edges (`unit -> units that must start before unit`),
    /// combining `after` and `requires` (for concrete units present in the graph).
    ordered_after: BTreeMap<String, BTreeSet<String>>,
    /// Deterministic topological start order across all concrete units.
    start_order: Vec<String>,
}

impl UnitGraph {
    /// Build and validate a unit DAG from a list of concrete units and/or templates.
    pub fn build(specs: Vec<UnitSpec>) -> Result<Self, GraphError> {
        let mut units = BTreeMap::new();
        let mut templates = BTreeMap::new();
        for spec in specs {
            spec.validate().map_err(GraphError::InvalidUnit)?;
            if spec.is_template() {
                if templates.insert(spec.name.clone(), spec.clone()).is_some() {
                    return Err(GraphError::DuplicateUnit(spec.name));
                }
            } else if units.insert(spec.name.clone(), spec.clone()).is_some() {
                return Err(GraphError::DuplicateUnit(spec.name));
            }
        }
        let mut graph = Self {
            units,
            templates,
            activates: BTreeMap::new(),
            ordered_after: BTreeMap::new(),
            start_order: Vec::new(),
        };
        graph.recompute()?;
        Ok(graph)
    }

    fn recompute(&mut self) -> Result<(), GraphError> {
        let mut activates: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut ordered_after: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for name in self.units.keys() {
            activates.insert(name.clone(), BTreeSet::new());
            ordered_after.insert(name.clone(), BTreeSet::new());
        }

        for (name, spec) in &self.units {
            for req in &spec.requires {
                if !self.units.contains_key(req) {
                    return Err(GraphError::UnknownDependency {
                        unit: name.clone(),
                        dependency: req.clone(),
                    });
                }
                activates.get_mut(name).unwrap().insert(req.clone());
                ordered_after.get_mut(name).unwrap().insert(req.clone());
            }
            for want in &spec.wants {
                if self.units.contains_key(want) {
                    activates.get_mut(name).unwrap().insert(want.clone());
                }
            }
            for after in &spec.after {
                if self.units.contains_key(after) {
                    ordered_after.get_mut(name).unwrap().insert(after.clone());
                }
            }
            for target in &spec.wanted_by {
                if let Some(set) = activates.get_mut(target) {
                    set.insert(name.clone());
                }
            }
        }

        // Deterministic Kahn's topological sort using BTreeSet (lexicographic tie-breaking).
        let mut indegree: BTreeMap<String, usize> = BTreeMap::new();
        let mut dependents: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (unit, deps) in &ordered_after {
            indegree.insert(unit.clone(), deps.len());
            for dep in deps {
                dependents
                    .entry(dep.clone())
                    .or_default()
                    .push(unit.clone());
            }
        }

        let mut ready: BTreeSet<String> = indegree
            .iter()
            .filter(|&(_, &deg)| deg == 0)
            .map(|(k, _)| k.clone())
            .collect();
        let mut order = Vec::with_capacity(self.units.len());

        while let Some(next) = ready.pop_first() {
            order.push(next.clone());
            if let Some(children) = dependents.get(&next) {
                for child in children {
                    let deg = indegree.get_mut(child).unwrap();
                    *deg -= 1;
                    if *deg == 0 {
                        ready.insert(child.clone());
                    }
                }
            }
        }

        if order.len() != self.units.len() {
            let cycle = find_cycle(&ordered_after);
            return Err(GraphError::Cycle(cycle));
        }

        self.activates = activates;
        self.ordered_after = ordered_after;
        self.start_order = order;
        Ok(())
    }

    /// Add a concrete unit or template dynamically and re-verify acyclicity.
    pub fn register_unit(&mut self, spec: UnitSpec) -> Result<(), GraphError> {
        spec.validate().map_err(GraphError::InvalidUnit)?;
        if spec.is_template() {
            if self.templates.contains_key(&spec.name) {
                return Err(GraphError::DuplicateUnit(spec.name));
            }
            self.templates.insert(spec.name.clone(), spec);
            return Ok(());
        }
        if self.units.contains_key(&spec.name) {
            return Err(GraphError::DuplicateUnit(spec.name));
        }
        let name = spec.name.clone();
        self.units.insert(name.clone(), spec);
        if let Err(err) = self.recompute() {
            self.units.remove(&name);
            let _ = self.recompute();
            return Err(err);
        }
        Ok(())
    }

    /// Build a concrete instance spec from a registered template WITHOUT mutating the graph,
    /// allowing callers to authorize the instantiated spec before committing it.
    pub fn preview_template_instance(&self, full_name: &str) -> Result<UnitSpec, GraphError> {
        let (template_name, instance) = split_template_instance(full_name)
            .ok_or_else(|| GraphError::UnknownUnit(full_name.to_owned()))?;
        let template = self
            .templates
            .get(&template_name)
            .ok_or(GraphError::UnknownUnit(template_name))?;
        template
            .instantiate(&instance)
            .map_err(GraphError::InvalidUnit)
    }

    /// Instantiate a template unit on demand (e.g. `devattach@snd.service` from `devattach@.service`).
    pub fn instantiate_template(&mut self, full_name: &str) -> Result<&UnitSpec, GraphError> {
        if self.units.contains_key(full_name) {
            return Ok(self.units.get(full_name).unwrap());
        }
        let concrete = self.preview_template_instance(full_name)?;
        self.register_unit(concrete)?;
        Ok(self.units.get(full_name).unwrap())
    }

    pub fn unit(&self, name: &str) -> Option<&UnitSpec> {
        self.units.get(name)
    }

    pub fn template(&self, name: &str) -> Option<&UnitSpec> {
        self.templates.get(name)
    }

    pub fn units(&self) -> &BTreeMap<String, UnitSpec> {
        &self.units
    }

    pub fn templates(&self) -> &BTreeMap<String, UnitSpec> {
        &self.templates
    }

    /// All concrete units in deterministic topological start order.
    pub fn start_order(&self) -> &[String] {
        &self.start_order
    }

    /// Strict reverse topological order for clean ordered shutdown.
    pub fn shutdown_order(&self) -> Vec<String> {
        self.start_order.iter().rev().cloned().collect()
    }

    /// Direct ordering predecessors (`after` ∪ `requires`) of `unit`.
    pub fn predecessors(&self, unit: &str) -> impl Iterator<Item = &String> {
        self.ordered_after
            .get(unit)
            .into_iter()
            .flat_map(|s| s.iter())
    }

    /// Direct ordering successors (units that are ordered `after` or `require` `unit`).
    pub fn successors(&self, unit: &str) -> Vec<String> {
        self.ordered_after
            .iter()
            .filter(|(_, deps)| deps.contains(unit))
            .map(|(candidate, _)| candidate.clone())
            .collect()
    }

    /// Compute the exact set of units to activate for `target` (transitive `requires`/`wants`/
    /// `wanted_by`), returned in deterministic topological start order.
    pub fn start_plan_for(&self, target: &str) -> Result<Vec<String>, GraphError> {
        if !self.units.contains_key(target) {
            return Err(GraphError::UnknownUnit(target.to_owned()));
        }
        let mut needed = BTreeSet::new();
        let mut queue = VecDeque::new();
        needed.insert(target.to_owned());
        queue.push_back(target.to_owned());
        while let Some(cur) = queue.pop_front() {
            if let Some(deps) = self.activates.get(&cur) {
                for dep in deps {
                    if needed.insert(dep.clone()) {
                        queue.push_back(dep.clone());
                    }
                }
            }
        }
        Ok(self
            .start_order
            .iter()
            .filter(|u| needed.contains(*u))
            .cloned()
            .collect())
    }

    /// Compute the units to stop when stopping `unit`: `unit` itself plus any units that
    /// transitively `require` it (or `wants` it if it is a `Target`? No, stopping a `Target`
    /// stops units that `wanted_by` it only when explicitly stopping that target's group —
    /// specifically for `cloud-online.target`, stopping it also tears down its `wants` children
    /// if requested via `stop_target_group`). For `stop_plan_for`, we return `unit` plus all
    /// transitive `requires`-dependents in strict reverse topological order.
    pub fn stop_plan_for(&self, unit: &str) -> Result<Vec<String>, GraphError> {
        if !self.units.contains_key(unit) {
            return Err(GraphError::UnknownUnit(unit.to_owned()));
        }
        let mut to_stop = BTreeSet::new();
        let mut queue = VecDeque::new();
        to_stop.insert(unit.to_owned());
        queue.push_back(unit.to_owned());

        // If stopping an optional/feature target like `cloud-online.target`, stop the units it
        // exclusively activates via `wants`/`wanted_by` too (e.g. `cloud.mount`, `devattach@*`).
        if let Some(spec) = self.units.get(unit)
            && spec.kind == UnitKind::Target
            && spec.failure_policy == FailurePolicy::Optional
            && let Some(children) = self.activates.get(unit)
        {
            for child in children {
                if to_stop.insert(child.clone()) {
                    queue.push_back(child.clone());
                }
            }
        }

        while let Some(cur) = queue.pop_front() {
            for (candidate, spec) in &self.units {
                if spec.requires.iter().any(|r| r == &cur) && to_stop.insert(candidate.clone()) {
                    queue.push_back(candidate.clone());
                }
            }
        }

        Ok(self
            .start_order
            .iter()
            .rev()
            .filter(|u| to_stop.contains(*u))
            .cloned()
            .collect())
    }
}

fn find_cycle(ordered_after: &BTreeMap<String, BTreeSet<String>>) -> Vec<String> {
    let mut state: BTreeMap<&str, u8> = BTreeMap::new();
    let mut stack: Vec<String> = Vec::new();
    fn dfs<'a>(
        node: &'a str,
        adj: &'a BTreeMap<String, BTreeSet<String>>,
        state: &mut BTreeMap<&'a str, u8>,
        stack: &mut Vec<String>,
    ) -> Option<Vec<String>> {
        state.insert(node, 1);
        stack.push(node.to_owned());
        if let Some(deps) = adj.get(node) {
            for dep in deps {
                match state.get(dep.as_str()).copied().unwrap_or(0) {
                    0 => {
                        if let Some(c) = dfs(dep, adj, state, stack) {
                            return Some(c);
                        }
                    }
                    1 => {
                        let start = stack.iter().position(|n| n == dep).unwrap_or(0);
                        let mut cycle = stack[start..].to_vec();
                        cycle.push(dep.clone());
                        return Some(cycle);
                    }
                    _ => {}
                }
            }
        }
        stack.pop();
        state.insert(node, 2);
        None
    }
    for node in ordered_after.keys() {
        if state.get(node.as_str()).copied().unwrap_or(0) == 0
            && let Some(cycle) = dfs(node, ordered_after, &mut state, &mut stack)
        {
            return cycle;
        }
    }
    Vec::new()
}

/// Built-in Contract v2 default system unit catalog (`local-fs.target`, `multi-user.target`,
/// `user-session@.service`, `cloud-online.target`, `cloud.mount`, `devattach@.service`).
pub fn default_system_units() -> Vec<UnitSpec> {
    let cloud_dev_units: Vec<String> = CLOUD_DEVICE_INSTANCES
        .iter()
        .map(|d| format!("devattach@{d}.service"))
        .collect();
    let mut cloud_online_after = vec!["multi-user.target".to_owned(), "cloud.mount".to_owned()];
    cloud_online_after.extend(cloud_dev_units.iter().cloned());
    let mut cloud_online_wants = vec!["cloud.mount".to_owned()];
    cloud_online_wants.extend(cloud_dev_units);

    vec![
        UnitSpec {
            version: UNIT_MANIFEST_VERSION,
            name: "local-fs.target".into(),
            kind: UnitKind::Target,
            description: "Local os-cowfs root, /usr, /tmp, /proc, /dev, and /run".into(),
            after: Vec::new(),
            wants: Vec::new(),
            requires: Vec::new(),
            wanted_by: Vec::new(),
            failure_policy: FailurePolicy::Required,
            readiness: Readiness::Immediate,
            ready_timeout_ms: DEFAULT_READY_TIMEOUT_MS,
            stop_timeout_ms: DEFAULT_STOP_TIMEOUT_MS,
            restart: RestartPolicy::Never,
            exec_start: None,
            exec_stop: None,
            cwd: None,
            environment: BTreeMap::new(),
            mount: None,
            grant: CapabilityGrant::default(),
            enabled: true,
        },
        UnitSpec {
            version: UNIT_MANIFEST_VERSION,
            name: "multi-user.target".into(),
            kind: UnitKind::Target,
            description: "Offline-capable local multi-user system ready".into(),
            after: vec!["local-fs.target".into()],
            wants: Vec::new(),
            requires: vec!["local-fs.target".into()],
            wanted_by: Vec::new(),
            failure_policy: FailurePolicy::Required,
            readiness: Readiness::Immediate,
            ready_timeout_ms: DEFAULT_READY_TIMEOUT_MS,
            stop_timeout_ms: DEFAULT_STOP_TIMEOUT_MS,
            restart: RestartPolicy::Never,
            exec_start: None,
            exec_stop: None,
            cwd: None,
            environment: BTreeMap::new(),
            mount: None,
            grant: CapabilityGrant::default(),
            enabled: true,
        },
        UnitSpec {
            version: UNIT_MANIFEST_VERSION,
            name: "user-session@.service".into(),
            kind: UnitKind::Service,
            description: "Per-user service manager and local auto-login session for uid %i".into(),
            after: vec!["local-fs.target".into(), "multi-user.target".into()],
            wants: Vec::new(),
            requires: vec!["local-fs.target".into()],
            wanted_by: vec!["multi-user.target".into()],
            failure_policy: FailurePolicy::Required,
            readiness: Readiness::NotifySocket,
            ready_timeout_ms: DEFAULT_READY_TIMEOUT_MS,
            stop_timeout_ms: DEFAULT_STOP_TIMEOUT_MS,
            restart: RestartPolicy::OnFailure {
                max_attempts: 3,
                backoff_ms: 500,
            },
            exec_start: Some(vec!["/usr/bin/init".into(), "--user".into(), "%i".into()]),
            exec_stop: None,
            cwd: Some("/".into()),
            environment: BTreeMap::new(),
            mount: None,
            grant: CapabilityGrant {
                user: Some("%i".into()),
                group: None,
                mount_namespace: MountNsPolicy::System,
                bind_mounts: Vec::new(),
                devices: vec![
                    "null".into(),
                    "zero".into(),
                    "urandom".into(),
                    "ptmx".into(),
                ],
                cloud_scope: RemoteScope::default(),
                limits: None,
            },
            enabled: true,
        },
        UnitSpec {
            version: UNIT_MANIFEST_VERSION,
            name: "cloud.mount".into(),
            kind: UnitKind::Mount,
            description: "Optional feature-frozen CloudFs mount at /mnt/cloud".into(),
            after: vec!["local-fs.target".into(), "multi-user.target".into()],
            wants: Vec::new(),
            requires: vec!["local-fs.target".into()],
            wanted_by: vec!["cloud-online.target".into()],
            failure_policy: FailurePolicy::Optional,
            readiness: Readiness::Immediate,
            ready_timeout_ms: DEFAULT_READY_TIMEOUT_MS,
            stop_timeout_ms: DEFAULT_STOP_TIMEOUT_MS,
            restart: RestartPolicy::Never,
            exec_start: None,
            exec_stop: None,
            cwd: None,
            environment: BTreeMap::new(),
            mount: Some(MountUnitSpec {
                source: "cloud".into(),
                target: "/mnt/cloud".into(),
                fstype: "cloud".into(),
                flags: MS_NOSUID | MS_NODEV,
                options: Some("nosuid,nodev".into()),
            }),
            grant: CapabilityGrant {
                cloud_scope: RemoteScope::cloud_only(),
                ..CapabilityGrant::default()
            },
            enabled: true,
        },
        UnitSpec {
            version: UNIT_MANIFEST_VERSION,
            name: "devattach@.service".into(),
            kind: UnitKind::Service,
            description: "Optional credentialed remote device attachment for /dev/%i".into(),
            after: vec![
                "local-fs.target".into(),
                "multi-user.target".into(),
                "cloud.mount".into(),
            ],
            wants: Vec::new(),
            requires: vec!["local-fs.target".into()],
            wanted_by: vec!["cloud-online.target".into()],
            failure_policy: FailurePolicy::Optional,
            readiness: Readiness::NotifySocket,
            ready_timeout_ms: DEFAULT_READY_TIMEOUT_MS,
            stop_timeout_ms: DEFAULT_STOP_TIMEOUT_MS,
            restart: RestartPolicy::OnFailure {
                max_attempts: 2,
                backoff_ms: 500,
            },
            exec_start: Some(vec!["/usr/bin/devattach".into(), "%i".into()]),
            exec_stop: None,
            cwd: Some("/".into()),
            environment: BTreeMap::new(),
            mount: None,
            grant: CapabilityGrant {
                devices: vec!["%i".into()],
                cloud_scope: RemoteScope {
                    cloud_fs: false,
                    devices: vec!["%i".into()],
                    containers: false,
                    relay: false,
                },
                ..CapabilityGrant::default()
            },
            enabled: true,
        },
        UnitSpec {
            version: UNIT_MANIFEST_VERSION,
            name: "cloud-online.target".into(),
            kind: UnitKind::Target,
            description: "Optional post-signin cloud mount and remote device attachments".into(),
            after: cloud_online_after,
            wants: cloud_online_wants,
            requires: Vec::new(),
            wanted_by: Vec::new(),
            failure_policy: FailurePolicy::Optional,
            readiness: Readiness::Immediate,
            ready_timeout_ms: DEFAULT_READY_TIMEOUT_MS,
            stop_timeout_ms: DEFAULT_STOP_TIMEOUT_MS,
            restart: RestartPolicy::Never,
            exec_start: None,
            exec_stop: None,
            cwd: None,
            environment: BTreeMap::new(),
            mount: None,
            grant: CapabilityGrant::default(),
            enabled: true,
        },
    ]
}

/// Build the default boot graph with `user-session@<default_uid>.service` and the 4 optional
/// `devattach@{archive,media,present,snd}.service` instances pre-instantiated.
pub fn default_boot_graph(default_uid: u32) -> Result<UnitGraph, GraphError> {
    let user_session = format!("user-session@{default_uid}.service");
    let mut specs = default_system_units();
    if let Some(cloud_mount) = specs.iter_mut().find(|u| u.name == "cloud.mount") {
        cloud_mount.after.push(user_session.clone());
    }
    let mut graph = UnitGraph::build(specs)?;
    graph.instantiate_template(&user_session)?;
    for device in CLOUD_DEVICE_INSTANCES {
        graph.instantiate_template(&format!("devattach@{device}.service"))?;
    }
    Ok(graph)
}
