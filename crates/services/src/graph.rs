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
    /// Soft child activation edges (`unit -> units pulled via wants or reverse wanted_by`),
    /// explicitly excluding `requires` prerequisites so stopping an optional target never
    /// tears down shared required prerequisites like `local-fs.target`.
    wants_children: BTreeMap<String, BTreeSet<String>>,
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
            wants_children: BTreeMap::new(),
            ordered_after: BTreeMap::new(),
            start_order: Vec::new(),
        };
        graph.recompute()?;
        Ok(graph)
    }

    fn recompute(&mut self) -> Result<(), GraphError> {
        let mut activates: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut wants_children: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut ordered_after: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for name in self.units.keys() {
            activates.insert(name.clone(), BTreeSet::new());
            wants_children.insert(name.clone(), BTreeSet::new());
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
                    if !spec.requires.iter().any(|r| r == want) {
                        wants_children.get_mut(name).unwrap().insert(want.clone());
                    }
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
                if let Some(target_spec) = self.units.get(target)
                    && !target_spec.requires.iter().any(|r| r == name)
                    && let Some(set) = wants_children.get_mut(target)
                {
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
        self.wants_children = wants_children;
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

    /// Direct activation edges (`requires` ∪ `wants` ∪ reverse `wanted_by`) for `unit`.
    pub fn activation_edges(&self, unit: &str) -> impl Iterator<Item = &String> {
        self.activates.get(unit).into_iter().flat_map(|s| s.iter())
    }

    /// Direct soft children (`wants` ∪ reverse `wanted_by`, strictly excluding `requires`) of `unit`.
    pub fn optional_children(&self, unit: &str) -> impl Iterator<Item = &String> {
        self.wants_children
            .get(unit)
            .into_iter()
            .flat_map(|s| s.iter())
    }

    /// Compute the units to stop when stopping `unit`: `unit` itself, soft `wants`/`wanted_by`
    /// children when stopping an optional feature target (NEVER its `requires` prerequisites!),
    /// plus all transitive `requires`-dependents in strict reverse topological order.
    pub fn stop_plan_for(&self, unit: &str) -> Result<Vec<String>, GraphError> {
        if !self.units.contains_key(unit) {
            return Err(GraphError::UnknownUnit(unit.to_owned()));
        }
        let mut to_stop = BTreeSet::new();
        let mut queue = VecDeque::new();
        to_stop.insert(unit.to_owned());
        queue.push_back(unit.to_owned());

        // If stopping an optional/feature target like `cloud-online.target`, include only its
        // `wants`/`wanted_by` children — NEVER its `requires` prerequisites (e.g. `local-fs.target`).
        if let Some(spec) = self.units.get(unit)
            && spec.kind == UnitKind::Target
            && spec.failure_policy == FailurePolicy::Optional
            && let Some(children) = self.wants_children.get(unit)
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

fn filesystem_service(name: &str, user: bool) -> UnitSpec {
    let export = name == "exportd";
    let mut after = Vec::new();
    if !user {
        after.push("local-fs.target".into());
    }
    if export {
        after.push("mountd.service".into());
    }
    let mut argv = vec![format!("/usr/bin/{name}")];
    if user {
        argv.push("--user".into());
    }
    UnitSpec {
        version: UNIT_MANIFEST_VERSION,
        name: format!("{name}.service"),
        kind: UnitKind::Service,
        description: format!("{name} filesystem service"),
        after,
        wants: vec![],
        requires: vec![],
        wanted_by: if user {
            vec![]
        } else {
            vec!["multi-user.target".into()]
        },
        failure_policy: FailurePolicy::Required,
        readiness: Readiness::NotifySocket,
        ready_timeout_ms: DEFAULT_READY_TIMEOUT_MS,
        stop_timeout_ms: DEFAULT_STOP_TIMEOUT_MS,
        restart: RestartPolicy::OnFailure {
            max_attempts: 5,
            backoff_ms: 250,
        },
        exec_start: Some(argv),
        exec_stop: None,
        cwd: Some("/".into()),
        environment: BTreeMap::new(),
        mount: None,
        enabled: true,
        grant: CapabilityGrant {
            user: (export && !user).then(|| "exportd".into()),
            mount_namespace: if user {
                MountNsPolicy::Session
            } else {
                MountNsPolicy::System
            },
            export_impersonate: export,
            builtin_exportd: export,
            ..Default::default()
        },
    }
}

pub fn default_user_units() -> Vec<UnitSpec> {
    vec![
        filesystem_service("mountd", true),
        filesystem_service("exportd", true),
    ]
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

    let mut gui = filesystem_service("compositor", false);
    gui.name = "gui-compositor.service".into();
    gui.description = "Seat 0 display and input compositor".into();
    gui.wanted_by.clear();
    gui.enabled = false;
    gui.failure_policy = FailurePolicy::Optional;
    gui.grant.devices = vec!["display".into(), "input".into()];
    vec![
        gui,
        filesystem_service("mountd", false),
        filesystem_service("exportd", false),
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
            after: vec!["local-fs.target".into()],
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
                export_impersonate: false,
                builtin_exportd: false,
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
                    ..RemoteScope::default()
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

/// Build the default boot graph with `user-session@<default_uid>.service` (when `default_uid != 0`)
/// and the 4 optional `devattach@{archive,media,present,snd}.service` instances pre-instantiated.
///
/// When `default_uid != 0`, `multi-user.target` requires and is ordered `after`
/// `user-session@<default_uid>.service` so boot health (`MarkBootHealthy`) cannot fire until the
/// default user session has notified `READY=1`.
pub fn default_boot_graph(default_uid: u32) -> Result<UnitGraph, GraphError> {
    let mut specs = default_system_units();
    if default_uid != 0 {
        let user_session = format!("user-session@{default_uid}.service");
        if let Some(template) = specs
            .iter()
            .find(|u| u.name == "user-session@.service")
            .cloned()
        {
            let concrete = template
                .instantiate(&default_uid.to_string())
                .map_err(GraphError::InvalidUnit)?;
            specs.push(concrete);
        }
        if let Some(multi_user) = specs.iter_mut().find(|u| u.name == "multi-user.target") {
            if !multi_user.after.contains(&user_session) {
                multi_user.after.push(user_session.clone());
            }
            if !multi_user.requires.contains(&user_session) {
                multi_user.requires.push(user_session.clone());
            }
        }
        if let Some(cloud_mount) = specs.iter_mut().find(|u| u.name == "cloud.mount")
            && !cloud_mount.after.contains(&user_session)
        {
            cloud_mount.after.push(user_session);
        }
    }
    let mut graph = UnitGraph::build(specs)?;
    for device in CLOUD_DEVICE_INSTANCES {
        graph.instantiate_template(&format!("devattach@{device}.service"))?;
    }
    Ok(graph)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_builtin_exportd_manifests_can_request_impersonation() {
        for (user, manager_uid) in [(false, 0), (true, 1000)] {
            let unit = filesystem_service("exportd", user);
            assert!(unit.authorize_for_manager(manager_uid).is_ok());
            let manifest = serde_json::to_string(&unit).unwrap();
            let custom: UnitSpec = serde_json::from_str(&manifest).unwrap();
            assert_eq!(
                custom.authorize_for_manager(manager_uid).unwrap_err().errno,
                abi::Errno::EPERM
            );
            assert!(!filesystem_service("mountd", user).grant.export_impersonate);
        }
    }

    #[test]
    fn default_boot_graph_orders_and_requires_user_session_before_multi_user() {
        let graph = default_boot_graph(1000).unwrap();
        let order = graph.start_order();
        let pos = |name: &str| order.iter().position(|u| u == name).unwrap();
        assert!(pos("local-fs.target") < pos("user-session@1000.service"));
        assert!(pos("user-session@1000.service") < pos("multi-user.target"));
        assert!(pos("multi-user.target") < pos("cloud.mount"));

        let multi = graph.unit("multi-user.target").unwrap();
        assert!(multi.requires.contains(&"user-session@1000.service".into()));
        assert!(multi.after.contains(&"user-session@1000.service".into()));

        // Root-only boot (`default_uid == 0`) does not require `user-session@0.service`.
        let root_graph = default_boot_graph(0).unwrap();
        assert!(root_graph.unit("user-session@0.service").is_none());
        let root_multi = root_graph.unit("multi-user.target").unwrap();
        assert!(
            !root_multi
                .requires
                .iter()
                .any(|r| r.starts_with("user-session@"))
        );
    }

    #[test]
    fn stop_plan_for_optional_target_never_stops_requires_prerequisites() {
        let mut graph = default_boot_graph(1000).unwrap();
        let opt_svc = UnitSpec {
            version: UNIT_MANIFEST_VERSION,
            name: "opt-worker.service".into(),
            kind: UnitKind::Service,
            description: String::new(),
            after: vec!["local-fs.target".into()],
            wants: Vec::new(),
            requires: vec!["local-fs.target".into()],
            wanted_by: vec!["opt-feature.target".into()],
            failure_policy: FailurePolicy::Optional,
            readiness: Readiness::Immediate,
            ready_timeout_ms: DEFAULT_READY_TIMEOUT_MS,
            stop_timeout_ms: DEFAULT_STOP_TIMEOUT_MS,
            restart: RestartPolicy::Never,
            exec_start: Some(vec!["/usr/bin/true".into()]),
            exec_stop: None,
            cwd: Some("/".into()),
            environment: BTreeMap::new(),
            mount: None,
            grant: CapabilityGrant::default(),
            enabled: true,
        };
        let opt_target = UnitSpec {
            version: UNIT_MANIFEST_VERSION,
            name: "opt-feature.target".into(),
            kind: UnitKind::Target,
            description: String::new(),
            after: vec!["local-fs.target".into(), "opt-worker.service".into()],
            wants: vec!["opt-worker.service".into()],
            requires: vec!["local-fs.target".into()],
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
        };
        graph.register_unit(opt_svc).unwrap();
        graph.register_unit(opt_target).unwrap();

        let plan = graph.stop_plan_for("opt-feature.target").unwrap();
        assert_eq!(plan, vec!["opt-feature.target", "opt-worker.service"]);
        assert!(!plan.contains(&"local-fs.target".to_string()));
        assert!(!plan.contains(&"multi-user.target".to_string()));
    }
}
