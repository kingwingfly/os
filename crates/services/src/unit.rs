//! Service Manager v2 unit schema, capability grants, template instantiation, and validation
//! (`#57` `L3d`, Contract v2 §2.4, §2.7, §2.15).
//!
//! Units declare explicit, least-privilege capability grants (`CapabilityGrant`). By default
//! `cloud_scope` is empty (`RemoteScope::default()`), so local services execute 100% offline
//! with zero remote authority.

use abi::auth_v2::RemoteScope;
use abi::{Errno, Error};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Current Service Manager unit manifest schema version (Contract v2 / `#57`).
pub const UNIT_MANIFEST_VERSION: u32 = 2;

/// Maximum serialized size of a single unit specification JSON document (64 KiB).
pub const MAX_UNIT_SPEC_BYTES: usize = 65_536;

pub const DEFAULT_READY_TIMEOUT_MS: u64 = 10_000;
pub const DEFAULT_STOP_TIMEOUT_MS: u64 = 3_000;

/// Kind of managed unit in the PID 1 / per-user DAG.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnitKind {
    Service,
    Mount,
    Target,
}

impl UnitKind {
    pub const fn expected_suffix(self) -> &'static str {
        match self {
            Self::Service => ".service",
            Self::Mount => ".mount",
            Self::Target => ".target",
        }
    }
}

/// How the service manager determines a `Service` unit has reached `Active` state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Readiness {
    /// Active immediately on spawn (or after mount completes).
    #[default]
    Immediate,
    /// Inherited `OS_READY_FD` pipe writes `READY=1\n`.
    PipeFd,
    /// Sends `READY=1` datagram to `NOTIFY_SOCKET` (`/run/init/notify.sock`), authenticated
    /// strictly via kernel `SO_PEERCRED` (`cred.pid == unit.pid`).
    NotifySocket,
}

/// Impact of a unit failure on dependent targets and boot health.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailurePolicy {
    /// Failure degrades dependent targets or aborts boot to recovery.
    #[default]
    Required,
    /// Failure is recorded (`Failed`) without blocking boot or other required targets
    /// (e.g., `cloud.mount` when offline).
    Optional,
}

/// Mount namespace policy granted to a unit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MountNsPolicy {
    #[default]
    System,
    Isolated,
    Session,
}

impl MountNsPolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Isolated => "isolated",
            Self::Session => "session",
        }
    }
}

/// Explicit bind-mount granted inside an `Isolated` or `Session` mount namespace.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindSpec {
    pub source: String,
    pub target: String,
    #[serde(default)]
    pub read_only: bool,
}

/// Cgroup v2 resource limits applied to a supervised unit.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_max: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_max: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pids_max: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub io_read_bps: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub io_write_bps: Option<u64>,
}

impl ResourceLimits {
    pub fn is_empty(&self) -> bool {
        self.cpu_max.is_none()
            && self.memory_max.is_none()
            && self.pids_max.is_none()
            && self.io_read_bps.is_none()
            && self.io_write_bps.is_none()
    }
}

/// Explicit per-unit capability grant. Defaults to zero remote authority (`RemoteScope::default()`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityGrant {
    /// Explicit local user for system units; forbidden (`EPERM`) in per-user manager.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Explicit local group for system units; forbidden (`EPERM`) in per-user manager.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(default)]
    pub mount_namespace: MountNsPolicy,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bind_mounts: Vec<BindSpec>,
    /// Explicit device allowlist (e.g. `["null", "zero", "urandom"]`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<String>,
    /// Explicit `ServiceAuth v2` remote scope attenuation — defaults to empty (100% offline).
    #[serde(default)]
    pub cloud_scope: RemoteScope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<ResourceLimits>,
}

/// Restart and backoff policy for supervised services.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "policy", rename_all = "snake_case", deny_unknown_fields)]
pub enum RestartPolicy {
    #[default]
    Never,
    OnFailure {
        max_attempts: u32,
        backoff_ms: u64,
    },
    Always {
        backoff_ms: u64,
    },
}

impl RestartPolicy {
    /// Deterministic capped exponential backoff for 1-based attempt number.
    pub fn delay_ms(&self, attempt: u32) -> Option<u64> {
        let base = match *self {
            Self::Never => return None,
            Self::OnFailure {
                max_attempts,
                backoff_ms,
            } => {
                if attempt == 0 || attempt > max_attempts {
                    return None;
                }
                backoff_ms
            }
            Self::Always { backoff_ms } => backoff_ms,
        };
        let shift = attempt.saturating_sub(1).min(5);
        Some(base.saturating_mul(1u64 << shift))
    }
}

/// Specification for a `UnitKind::Mount` unit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MountUnitSpec {
    pub source: String,
    pub target: String,
    pub fstype: String,
    #[serde(default)]
    pub flags: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<String>,
}

fn default_ready_timeout_ms() -> u64 {
    DEFAULT_READY_TIMEOUT_MS
}

fn default_stop_timeout_ms() -> u64 {
    DEFAULT_STOP_TIMEOUT_MS
}

fn default_true() -> bool {
    true
}

/// Version 2 unit specification (`service`, `mount`, or `target`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitSpec {
    pub version: u32,
    pub name: String,
    pub kind: UnitKind,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub after: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wants: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wanted_by: Vec<String>,
    #[serde(default)]
    pub failure_policy: FailurePolicy,
    #[serde(default)]
    pub readiness: Readiness,
    #[serde(default = "default_ready_timeout_ms")]
    pub ready_timeout_ms: u64,
    #[serde(default = "default_stop_timeout_ms")]
    pub stop_timeout_ms: u64,
    #[serde(default)]
    pub restart: RestartPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec_start: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec_stop: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub environment: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount: Option<MountUnitSpec>,
    #[serde(default)]
    pub grant: CapabilityGrant,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

pub fn valid_unit_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.starts_with('.')
        && !name.starts_with('@')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'@'))
        && name.matches('@').count() <= 1
}

pub fn valid_instance_arg(instance: &str) -> bool {
    !instance.is_empty()
        && instance.len() <= 64
        && instance
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
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

fn valid_text(s: &str) -> bool {
    !s.contains('\0') && s.len() <= 4096
}

fn valid_account_token(s: &str, allow_template: bool) -> bool {
    if s.is_empty() || s.len() > 64 || s.contains('\0') || s.contains(':') || s.contains('/') {
        return false;
    }
    let check = if allow_template {
        s.replace("%i", "0")
    } else {
        s.to_owned()
    };
    !check.is_empty()
        && check
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn valid_device_token(s: &str, allow_template: bool) -> bool {
    if s.is_empty() || s.len() > 64 || s == "." || s == ".." || s.contains('\0') || s.contains('/')
    {
        return false;
    }
    let check = if allow_template {
        s.replace("%i", "dev")
    } else {
        s.to_owned()
    };
    !check.is_empty()
        && check != "."
        && check != ".."
        && check
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn valid_cpu_max_spec(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed == "max" {
        return true;
    }
    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    if parts.len() != 2 {
        return false;
    }
    let quota_ok = parts[0] == "max"
        || (!parts[0].is_empty()
            && parts[0].bytes().all(|b| b.is_ascii_digit())
            && parts[0].parse::<u64>().is_ok_and(|v| v > 0));
    let period_ok = !parts[1].is_empty()
        && parts[1].bytes().all(|b| b.is_ascii_digit())
        && parts[1].parse::<u64>().is_ok_and(|v| v > 0);
    quota_ok && period_ok
}

/// Split an instantiated unit name like `"devattach@snd.service"` into
/// `(template_name: "devattach@.service", instance: "snd")`.
pub fn split_template_instance(name: &str) -> Option<(String, String)> {
    let (prefix, rest) = name.split_once('@')?;
    let (instance, suffix) = rest.rsplit_once('.')?;
    if prefix.is_empty() || instance.is_empty() || suffix.is_empty() {
        return None;
    }
    Some((format!("{prefix}@.{suffix}"), instance.to_owned()))
}

impl UnitSpec {
    /// Parse and validate a v2 JSON unit specification.
    pub fn parse_json(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_UNIT_SPEC_BYTES {
            return Err("unit specification exceeds 64 KiB".into());
        }
        let spec: Self = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        spec.validate()?;
        Ok(spec)
    }

    /// True if this spec is an uninstantiated template (e.g. `devattach@.service`).
    pub fn is_template(&self) -> bool {
        let suffix = self.kind.expected_suffix();
        self.name
            .strip_suffix(suffix)
            .is_some_and(|stem| stem.ends_with('@'))
    }

    /// Instantiate a template unit with concrete `%i` substitution.
    pub fn instantiate(&self, instance: &str) -> Result<Self, String> {
        if !self.is_template() {
            return Err(format!("'{}' is not a template unit", self.name));
        }
        if !valid_instance_arg(instance) {
            return Err(format!("invalid template instance '{instance}'"));
        }
        let suffix = self.kind.expected_suffix();
        let prefix = self.name.strip_suffix(suffix).unwrap();
        let concrete_name = format!("{prefix}{instance}{suffix}");
        let sub = |s: &str| s.replace("%i", instance);

        let mut out = self.clone();
        out.name = concrete_name;
        out.description = sub(&out.description);
        out.after = out.after.iter().map(|s| sub(s)).collect();
        out.wants = out.wants.iter().map(|s| sub(s)).collect();
        out.requires = out.requires.iter().map(|s| sub(s)).collect();
        out.wanted_by = out.wanted_by.iter().map(|s| sub(s)).collect();
        out.exec_start = out
            .exec_start
            .map(|argv| argv.iter().map(|a| sub(a)).collect());
        out.exec_stop = out
            .exec_stop
            .map(|argv| argv.iter().map(|a| sub(a)).collect());
        out.cwd = out.cwd.map(|c| sub(&c));
        out.environment = out
            .environment
            .into_iter()
            .map(|(k, v)| (k, sub(&v)))
            .collect();
        out.mount = out.mount.map(|m| MountUnitSpec {
            source: sub(&m.source),
            target: sub(&m.target),
            fstype: sub(&m.fstype),
            flags: m.flags,
            options: m.options.map(|o| sub(&o)),
        });
        out.grant.user = out.grant.user.map(|u| sub(&u));
        out.grant.group = out.grant.group.map(|g| sub(&g));
        out.grant.devices = out.grant.devices.iter().map(|d| sub(d)).collect();
        out.grant.cloud_scope.devices = out
            .grant
            .cloud_scope
            .devices
            .iter()
            .map(|d| sub(d))
            .collect();
        out.validate()?;
        Ok(out)
    }

    /// Validate all structural, naming, path, timeout, and capability invariants.
    pub fn validate(&self) -> Result<(), String> {
        if self.version != UNIT_MANIFEST_VERSION {
            return Err(format!(
                "unsupported unit manifest version {} (expected {UNIT_MANIFEST_VERSION})",
                self.version
            ));
        }
        if !valid_unit_name(&self.name) {
            return Err(format!("invalid unit name '{}'", self.name));
        }
        let expected_suffix = self.kind.expected_suffix();
        if !self.name.ends_with(expected_suffix) {
            return Err(format!(
                "unit '{}' of kind {:?} must end with '{expected_suffix}'",
                self.name, self.kind
            ));
        }
        if self.ready_timeout_ms == 0 || self.ready_timeout_ms > 300_000 {
            return Err(format!(
                "{}: ready_timeout_ms must be within 1..=300000",
                self.name
            ));
        }
        if self.stop_timeout_ms == 0 || self.stop_timeout_ms > 60_000 {
            return Err(format!(
                "{}: stop_timeout_ms must be within 1..=60000",
                self.name
            ));
        }
        match self.restart {
            RestartPolicy::Never => {}
            RestartPolicy::OnFailure {
                max_attempts,
                backoff_ms,
            } => {
                if max_attempts == 0 || max_attempts > 32 || !(50..=60_000).contains(&backoff_ms) {
                    return Err(format!("{}: invalid OnFailure restart bounds", self.name));
                }
            }
            RestartPolicy::Always { backoff_ms } => {
                if !(50..=60_000).contains(&backoff_ms) {
                    return Err(format!("{}: invalid Always backoff_ms", self.name));
                }
            }
        }

        for dep in self
            .after
            .iter()
            .chain(&self.wants)
            .chain(&self.requires)
            .chain(&self.wanted_by)
        {
            if !valid_unit_name(dep) {
                return Err(format!("{}: invalid dependency name '{dep}'", self.name));
            }
        }

        match self.kind {
            UnitKind::Service => {
                let Some(argv) = &self.exec_start else {
                    return Err(format!("{}: service unit requires exec_start", self.name));
                };
                if argv.is_empty()
                    || argv.len() > 128
                    || argv[0].is_empty()
                    || !argv.iter().all(|s| valid_text(s))
                {
                    return Err(format!("{}: invalid exec_start argv", self.name));
                }
                if self.mount.is_some() {
                    return Err(format!("{}: service unit must not set mount", self.name));
                }
            }
            UnitKind::Mount => {
                let Some(mount) = &self.mount else {
                    return Err(format!("{}: mount unit requires mount spec", self.name));
                };
                if mount.fstype.is_empty()
                    || !valid_text(&mount.fstype)
                    || !valid_text(&mount.source)
                    || !clean_abs_path(&mount.target)
                {
                    return Err(format!("{}: invalid mount spec", self.name));
                }
                if self.exec_start.is_some() {
                    return Err(format!("{}: mount unit must not set exec_start", self.name));
                }
            }
            UnitKind::Target => {
                if self.exec_start.is_some() || self.mount.is_some() {
                    return Err(format!(
                        "{}: target unit must not set exec_start or mount",
                        self.name
                    ));
                }
            }
        }

        if let Some(exec_stop) = &self.exec_stop
            && (exec_stop.is_empty()
                || exec_stop.len() > 128
                || exec_stop[0].is_empty()
                || !exec_stop.iter().all(|s| valid_text(s)))
        {
            return Err(format!("{}: invalid exec_stop argv", self.name));
        }

        if let Some(cwd) = &self.cwd
            && !clean_abs_path(cwd)
        {
            return Err(format!("{}: cwd must be a clean absolute path", self.name));
        }

        if self.environment.len() > 64
            || self.environment.iter().any(|(k, v)| {
                k.is_empty()
                    || k.contains('=')
                    || k == "OS_READY_FD"
                    || k == "NOTIFY_SOCKET"
                    || !valid_text(k)
                    || !valid_text(v)
            })
        {
            return Err(format!("{}: invalid environment", self.name));
        }

        let is_template = self.is_template();
        if let Some(user) = &self.grant.user
            && !valid_account_token(user, is_template)
        {
            return Err(format!("{}: invalid grant.user '{user}'", self.name));
        }
        if let Some(group) = &self.grant.group
            && !valid_account_token(group, is_template)
        {
            return Err(format!("{}: invalid grant.group '{group}'", self.name));
        }
        if self.grant.devices.len() > 64
            || self
                .grant
                .devices
                .iter()
                .any(|d| !valid_device_token(d, is_template))
        {
            return Err(format!("{}: invalid grant.devices allowlist", self.name));
        }
        if self.grant.cloud_scope.devices.len() > 64
            || self
                .grant
                .cloud_scope
                .devices
                .iter()
                .any(|d| !valid_device_token(d, is_template))
        {
            return Err(format!(
                "{}: invalid grant.cloud_scope.devices allowlist",
                self.name
            ));
        }
        if self.grant.bind_mounts.len() > 32 {
            return Err(format!("{}: too many bind_mounts (max 32)", self.name));
        }
        if !self.grant.bind_mounts.is_empty() && self.grant.mount_namespace == MountNsPolicy::System
        {
            return Err(format!(
                "{}: bind_mounts require isolated or session mount_namespace",
                self.name
            ));
        }
        for bind in &self.grant.bind_mounts {
            if !clean_abs_path(&bind.source) || !clean_abs_path(&bind.target) {
                return Err(format!(
                    "{}: bind_mounts paths must be clean absolute paths",
                    self.name
                ));
            }
        }
        if let Some(limits) = &self.grant.limits {
            if limits.is_empty() {
                return Err(format!(
                    "{}: limits block must specify at least one limit",
                    self.name
                ));
            }
            if let Some(cpu_max) = &limits.cpu_max
                && !valid_cpu_max_spec(cpu_max)
            {
                return Err(format!(
                    "{}: invalid grant.limits.cpu_max '{cpu_max}'",
                    self.name
                ));
            }
            if limits.memory_max == Some(0) {
                return Err(format!(
                    "{}: grant.limits.memory_max must be greater than 0",
                    self.name
                ));
            }
            if limits.io_read_bps == Some(0) || limits.io_write_bps == Some(0) {
                return Err(format!(
                    "{}: grant.limits io bps limits must be greater than 0",
                    self.name
                ));
            }
        }
        match self.kind {
            UnitKind::Service => {}
            UnitKind::Mount => {
                if self.grant.user.is_some()
                    || self.grant.group.is_some()
                    || self.grant.mount_namespace != MountNsPolicy::System
                    || !self.grant.bind_mounts.is_empty()
                    || !self.grant.devices.is_empty()
                    || self.grant.limits.is_some()
                {
                    return Err(format!(
                        "{}: mount units cannot enforce process user/group/namespace/device/limit grants",
                        self.name
                    ));
                }
            }
            UnitKind::Target => {
                if self.grant.user.is_some()
                    || self.grant.group.is_some()
                    || self.grant.mount_namespace != MountNsPolicy::System
                    || !self.grant.bind_mounts.is_empty()
                    || !self.grant.devices.is_empty()
                    || !self.grant.cloud_scope.is_empty()
                    || self.grant.limits.is_some()
                {
                    return Err(format!(
                        "{}: target units cannot enforce capability grants",
                        self.name
                    ));
                }
            }
        }
        Ok(())
    }

    /// Enforce manager-level privilege boundaries for this unit:
    /// - Per-user managers (`manager_uid != 0`) CANNOT elevate `grant.user`/`grant.group`,
    ///   CANNOT request `MountNsPolicy::System`, and CANNOT own `UnitKind::Mount` units.
    /// - System PID 1 manager (`manager_uid == 0`) rejects `MountNsPolicy::Session`.
    pub fn authorize_for_manager(&self, manager_uid: u32) -> Result<(), Error> {
        if manager_uid != 0 {
            if self.grant.user.is_some() || self.grant.group.is_some() {
                return Err(Error::because(
                    Errno::EPERM,
                    "per-user service manager cannot specify grant.user or grant.group elevation",
                ));
            }
            if self.grant.mount_namespace == MountNsPolicy::System {
                return Err(Error::because(
                    Errno::EPERM,
                    "per-user service manager cannot use system mount_namespace",
                ));
            }
            if self.kind == UnitKind::Mount {
                return Err(Error::because(
                    Errno::EPERM,
                    "per-user service manager cannot mount filesystems into root namespace",
                ));
            }
        } else if self.grant.mount_namespace == MountNsPolicy::Session {
            return Err(Error::because(
                Errno::EPERM,
                "system service manager cannot attach to a user session mount_namespace",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_service() -> UnitSpec {
        UnitSpec {
            version: UNIT_MANIFEST_VERSION,
            name: "demo.service".into(),
            kind: UnitKind::Service,
            description: String::new(),
            after: Vec::new(),
            wants: Vec::new(),
            requires: Vec::new(),
            wanted_by: Vec::new(),
            failure_policy: FailurePolicy::Required,
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
        }
    }

    #[test]
    fn validate_and_authorize_enforce_service_grants_and_reject_invalid_restrictions() {
        // Valid service grant with group, devices, limits, and cloud_scope passes system manager.
        let mut ok = base_service();
        ok.grant.user = Some("1000".into());
        ok.grant.group = Some("wheel".into());
        ok.grant.devices = vec!["null".into(), "zero".into()];
        ok.grant.limits = Some(ResourceLimits {
            cpu_max: Some("max 100000".into()),
            memory_max: Some(16 * 1024 * 1024),
            pids_max: Some(32),
            io_read_bps: Some(1024),
            io_write_bps: None,
        });
        assert!(ok.validate().is_ok());
        assert!(ok.authorize_for_manager(0).is_ok());

        // Per-user manager rejects `grant.group` with EPERM (#19).
        let mut user_group = base_service();
        user_group.grant.mount_namespace = MountNsPolicy::Session;
        user_group.grant.group = Some("wheel".into());
        assert!(user_group.validate().is_ok());
        assert_eq!(
            user_group.authorize_for_manager(1000).unwrap_err().errno,
            Errno::EPERM
        );

        // Invalid device path traversal, malformed cpu_max, zero memory_max, and grants on targets fail validation.
        let mut bad_dev = base_service();
        bad_dev.grant.devices = vec!["../secret".into()];
        assert!(bad_dev.validate().is_err());

        let mut bad_cpu = base_service();
        bad_cpu.grant.limits = Some(ResourceLimits {
            cpu_max: Some("not-a-quota".into()),
            ..ResourceLimits::default()
        });
        assert!(bad_cpu.validate().is_err());

        let mut zero_mem = base_service();
        zero_mem.grant.limits = Some(ResourceLimits {
            memory_max: Some(0),
            ..ResourceLimits::default()
        });
        assert!(zero_mem.validate().is_err());

        let mut bad_target = base_service();
        bad_target.name = "bad.target".into();
        bad_target.kind = UnitKind::Target;
        bad_target.exec_start = None;
        bad_target.grant.group = Some("wheel".into());
        assert!(bad_target.validate().is_err());
    }
}
