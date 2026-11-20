//! Portable, instance-local cgroup v2 policy hierarchy (`pids.max`, `memory.max` `resources-v1`,
//! `io.max`, `devices.allow`/`devices.deny`, `cpu.max`, `cpu.weight`, `cgroup.freeze`,
//! `cgroup.kill`, and `CgroupLifetime::Process` automatic subtree retirement).
//!
//! Zero DOM / zero `wasm-bindgen` dependencies so browser `client-kernel` and `os-native` share
//! identical enforcement logic (`docs/architecture/contract.md` §2.1, §2.4).
use crate::registry::{
    CONTROLLERS, DEVICE_RULES_MAX, controllers, in_subtree, may_attach, may_create, may_write,
};
use crate::resource::IoLimit;
use abi::{CgroupLifetime, Errno, Error};
use os_core::permissions::Identity;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// Built-in top-level cgroups seeded for every instance.
pub const ROOT_CGROUPS: [&str; 4] = ["/init", "/user", "/system", "/cluster"];

/// Maximum total cgroups in one instance.
pub const CGROUP_MAX: usize = 512;

/// Maximum cgroup path length in bytes.
pub const CGROUP_PATH_MAX: usize = 256;

/// Linear-memory accounting granularity (64 KiB Wasm page).
pub const MEMORY_GRANULARITY: u64 = 65_536;

/// Upper bound on linear-memory reservation (1 TiB, matching `resources.rs`).
pub const MAX_MEMORY: u64 = 1 << 40;

/// Runtime capability marker indicating local `memory.max` enforcement.
pub const RESOURCE_CONTRACT: &str = "resources-v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalCgroup {
    pub path: String,
    pub owner: u32,
    pub controllers: String,
    pub cpu_max: Option<String>,
    pub cpu_weight: u32,
    pub memory_max: Option<u64>,
    pub pids_max: Option<u32>,
    pub io_max: Option<String>,
    pub io_read_bps: Option<u64>,
    pub io_write_bps: Option<u64>,
    pub frozen: bool,
    pub devices_allow: Vec<String>,
    pub devices_deny: Vec<String>,
    pub lifetime: Option<CgroupLifetime>,
    pub lifetime_owner: Option<u32>,
    pub retired: bool,
}

impl LocalCgroup {
    fn new(
        path: String,
        owner: u32,
        controllers: String,
        lifetime: Option<CgroupLifetime>,
        lifetime_owner: Option<u32>,
    ) -> Self {
        Self {
            path,
            owner,
            controllers,
            cpu_max: None,
            cpu_weight: 100,
            memory_max: None,
            pids_max: None,
            io_max: None,
            io_read_bps: None,
            io_write_bps: None,
            frozen: false,
            devices_allow: Vec::new(),
            devices_deny: Vec::new(),
            lifetime,
            lifetime_owner,
            retired: false,
        }
    }

    pub fn io_limit(&self) -> IoLimit {
        IoLimit {
            read: self.io_read_bps,
            write: self.io_write_bps,
        }
    }
}

/// Side effect requested by a `cgroup.set` mutation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CgroupSetEffect {
    None,
    /// `cgroup.kill = 1`: caller (`LocalProcessTable`) must SIGKILL every process in `path`'s subtree.
    KillSubtree(String),
    /// `io.max` updated: caller may sync effective policy for active remote credentials in subtree.
    IoPolicyChanged {
        path: String,
        rbps: Option<u64>,
        wbps: Option<u64>,
    },
}

/// Validate and canonicalize a cgroup v2 path (`/` or `/a/b/c`).
pub fn normalize_cgroup_path(raw: &str) -> Result<String, Error> {
    if raw.is_empty() || !raw.starts_with('/') || raw.len() > CGROUP_PATH_MAX || raw.contains('\0')
    {
        return Err(Errno::EINVAL.into());
    }
    if raw == "/" {
        return Ok("/".into());
    }
    let trimmed = raw.trim_end_matches('/');
    if trimmed.is_empty() {
        return Ok("/".into());
    }
    let mut parts = Vec::new();
    for seg in trimmed[1..].split('/') {
        if seg.is_empty()
            || seg == "."
            || seg == ".."
            || seg.len() > 64
            || !seg
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err(Errno::EINVAL.into());
        }
        parts.push(seg);
    }
    Ok(format!("/{}", parts.join("/")))
}

/// Parent path of a non-root normalized cgroup path.
pub fn parent_cgroup(path: &str) -> Option<String> {
    if path == "/" {
        return None;
    }
    let idx = path.rfind('/')?;
    if idx == 0 {
        Some("/".into())
    } else {
        Some(path[..idx].to_string())
    }
}

/// All ancestor paths from `"/"` down to `path` inclusive.
pub fn ancestors(path: &str) -> Vec<String> {
    if path == "/" {
        return vec!["/".into()];
    }
    let mut out = vec!["/".into()];
    let mut acc = String::new();
    for seg in path.trim_start_matches('/').split('/') {
        if seg.is_empty() {
            continue;
        }
        acc.push('/');
        acc.push_str(seg);
        out.push(acc.clone());
    }
    out
}

/// Round `bytes` up to the next 64 KiB Wasm linear-memory page boundary, checking `MAX_MEMORY`.
pub fn align_memory(bytes: u64) -> Result<u64, Error> {
    if bytes > MAX_MEMORY {
        return Err(Errno::EINVAL.into());
    }
    if bytes == 0 {
        return Ok(0);
    }
    let rem = bytes % MEMORY_GRANULARITY;
    if rem == 0 {
        Ok(bytes)
    } else {
        bytes
            .checked_add(MEMORY_GRANULARITY - rem)
            .filter(|&v| v <= MAX_MEMORY)
            .ok_or_else(|| Errno::EAGAIN.into())
    }
}

/// Whether a runtime contract string enforces `resources-v1` linear-memory bounds.
pub fn runtime_enforces_memory(runtime: Option<&str>) -> bool {
    runtime
        .is_some_and(|r| r == RESOURCE_CONTRACT || r.starts_with(&format!("{RESOURCE_CONTRACT}:")))
}

#[derive(Clone, Debug)]
pub struct CgroupTable {
    groups: BTreeMap<String, LocalCgroup>,
}

impl Default for CgroupTable {
    fn default() -> Self {
        Self::new()
    }
}

impl CgroupTable {
    pub fn new() -> Self {
        let mut groups = BTreeMap::new();
        let all = CONTROLLERS.join(" ");
        groups.insert(
            "/".into(),
            LocalCgroup::new("/".into(), 0, all.clone(), None, None),
        );
        for root in ROOT_CGROUPS {
            groups.insert(
                root.into(),
                LocalCgroup::new(root.into(), 0, all.clone(), None, None),
            );
        }
        Self { groups }
    }

    pub fn get(&self, path: &str) -> Option<&LocalCgroup> {
        let norm = normalize_cgroup_path(path).ok()?;
        self.groups.get(&norm)
    }

    pub fn create(
        &mut self,
        cred: &Identity,
        owner_pid: Option<u32>,
        raw_path: &str,
        ctrl_spec: Option<&str>,
        lifetime: Option<CgroupLifetime>,
    ) -> Result<(), Error> {
        let path = normalize_cgroup_path(raw_path)?;
        if path == "/" {
            return Err(Errno::EEXIST.into());
        }
        if self.groups.contains_key(&path) {
            return Err(Errno::EEXIST.into());
        }
        if self.groups.len() >= CGROUP_MAX {
            return Err(Errno::ENOSPC.into());
        }
        let parent_path = parent_cgroup(&path).ok_or(Errno::EINVAL)?;
        let parent = self.groups.get(&parent_path).ok_or(Errno::ENOENT)?;
        if parent.retired || self.any_ancestor_retired(&parent_path) {
            return Err(Errno::ENOENT.into());
        }
        if !may_create(cred, &parent_path, parent.owner) {
            return Err(Errno::EACCES.into());
        }
        let lifetime_owner = match lifetime {
            None => None,
            Some(CgroupLifetime::Process) => Some(owner_pid.ok_or(Errno::EPERM)?),
        };
        let enabled = match ctrl_spec {
            Some(spec) => controllers(spec)?,
            None => parent.controllers.clone(),
        };
        self.groups.insert(
            path.clone(),
            LocalCgroup::new(path, cred.id, enabled, lifetime, lifetime_owner),
        );
        Ok(())
    }

    pub fn remove(
        &mut self,
        cred: &Identity,
        raw_path: &str,
        subtree_has_procs: impl Fn(&str) -> bool,
    ) -> Result<(), Error> {
        let path = normalize_cgroup_path(raw_path)?;
        if path == "/" || ROOT_CGROUPS.contains(&path.as_str()) {
            return Err(Errno::EBUSY.into());
        }
        let group = self.groups.get(&path).ok_or(Errno::ENOENT)?;
        if !may_write(cred, group.owner) {
            return Err(Errno::EACCES.into());
        }
        let has_children = self
            .groups
            .keys()
            .any(|p| p != &path && in_subtree(p, &path));
        if has_children || subtree_has_procs(&path) {
            return Err(Errno::EBUSY.into());
        }
        self.groups.remove(&path);
        Ok(())
    }

    pub fn set(
        &mut self,
        cred: &Identity,
        raw_path: &str,
        key: &str,
        value: &str,
    ) -> Result<CgroupSetEffect, Error> {
        let path = normalize_cgroup_path(raw_path)?;
        let group = self.groups.get_mut(&path).ok_or(Errno::ENOENT)?;
        if !may_write(cred, group.owner) {
            return Err(Errno::EACCES.into());
        }
        if group.retired && key != "cgroup.kill" {
            return Err(Errno::ENOENT.into());
        }
        let trimmed = value.trim();
        match key {
            "cgroup.subtree_control" => {
                group.controllers = controllers(trimmed)?;
                Ok(CgroupSetEffect::None)
            }
            "pids.max" => {
                if trimmed == "max" {
                    group.pids_max = None;
                } else {
                    if trimmed.is_empty() || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
                        return Err(Errno::EINVAL.into());
                    }
                    let limit = trimmed.parse::<u32>().map_err(|_| Errno::EINVAL)?;
                    group.pids_max = Some(limit);
                }
                Ok(CgroupSetEffect::None)
            }
            "memory.max" => {
                if trimmed == "max" {
                    group.memory_max = None;
                } else {
                    if trimmed.is_empty() || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
                        return Err(Errno::EINVAL.into());
                    }
                    let limit = trimmed.parse::<u64>().map_err(|_| Errno::EINVAL)?;
                    group.memory_max = Some(limit);
                }
                Ok(CgroupSetEffect::None)
            }
            "io.max" => {
                let parsed = IoLimit::parse(trimmed)?;
                group.io_read_bps = parsed.read;
                group.io_write_bps = parsed.write;
                group.io_max = if parsed.read.is_none() && parsed.write.is_none() {
                    None
                } else {
                    Some(format!(
                        "rbps={} wbps={}",
                        parsed.read.map_or_else(|| "max".into(), |v| v.to_string()),
                        parsed.write.map_or_else(|| "max".into(), |v| v.to_string())
                    ))
                };
                Ok(CgroupSetEffect::IoPolicyChanged {
                    path,
                    rbps: parsed.read,
                    wbps: parsed.write,
                })
            }
            "cpu.max" => {
                if trimmed == "max" {
                    group.cpu_max = None;
                } else {
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() != 2 {
                        return Err(Errno::EINVAL.into());
                    }
                    let quota_ok = parts[0] == "max"
                        || (!parts[0].is_empty()
                            && parts[0].bytes().all(|b| b.is_ascii_digit())
                            && parts[0].parse::<u64>().is_ok_and(|n| n > 0));
                    let period_ok = !parts[1].is_empty()
                        && parts[1].bytes().all(|b| b.is_ascii_digit())
                        && parts[1].parse::<u64>().is_ok_and(|n| n > 0);
                    if !quota_ok || !period_ok {
                        return Err(Errno::EINVAL.into());
                    }
                    group.cpu_max = Some(format!("{} {}", parts[0], parts[1]));
                }
                Ok(CgroupSetEffect::None)
            }
            "cpu.weight" => {
                if trimmed.is_empty() || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(Errno::EINVAL.into());
                }
                let weight = trimmed.parse::<u32>().map_err(|_| Errno::EINVAL)?;
                if !(1..=10_000).contains(&weight) {
                    return Err(Errno::EINVAL.into());
                }
                group.cpu_weight = weight;
                Ok(CgroupSetEffect::None)
            }
            "cgroup.freeze" => {
                match trimmed {
                    "0" => group.frozen = false,
                    "1" => group.frozen = true,
                    _ => return Err(Errno::EINVAL.into()),
                }
                Ok(CgroupSetEffect::None)
            }
            "devices.allow" => {
                if trimmed.is_empty() || trimmed.len() > 128 || trimmed.contains('\0') {
                    return Err(Errno::EINVAL.into());
                }
                if !group.devices_allow.iter().any(|r| r == trimmed) {
                    if group.devices_allow.len() >= DEVICE_RULES_MAX {
                        return Err(Errno::ENOSPC.into());
                    }
                    group.devices_allow.push(trimmed.to_string());
                }
                group.devices_deny.retain(|r| r != trimmed);
                Ok(CgroupSetEffect::None)
            }
            "devices.deny" => {
                if trimmed.is_empty() || trimmed.len() > 128 || trimmed.contains('\0') {
                    return Err(Errno::EINVAL.into());
                }
                if !group.devices_deny.iter().any(|r| r == trimmed) {
                    if group.devices_deny.len() >= DEVICE_RULES_MAX {
                        return Err(Errno::ENOSPC.into());
                    }
                    group.devices_deny.push(trimmed.to_string());
                }
                group.devices_allow.retain(|r| r != trimmed);
                Ok(CgroupSetEffect::None)
            }
            "cgroup.kill" => {
                if trimmed != "1" {
                    return Err(Errno::EINVAL.into());
                }
                Ok(CgroupSetEffect::KillSubtree(path))
            }
            _ => Err(Errno::ENOENT.into()),
        }
    }

    pub fn authorize_attach(
        &self,
        cred: &Identity,
        target_uid: u32,
        raw_path: &str,
    ) -> Result<String, Error> {
        let path = normalize_cgroup_path(raw_path)?;
        let group = self.groups.get(&path).ok_or(Errno::ENOENT)?;
        if group.retired || self.any_ancestor_retired(&path) {
            return Err(Errno::ENOENT.into());
        }
        if !may_attach(cred, target_uid, &path, group.owner) {
            return Err(Errno::EACCES.into());
        }
        Ok(path)
    }

    pub fn any_ancestor_retired(&self, path: &str) -> bool {
        ancestors(path)
            .into_iter()
            .any(|anc| self.groups.get(&anc).is_some_and(|g| g.retired))
    }

    pub fn has_memory_limit(&self, path: &str) -> bool {
        ancestors(path).into_iter().any(|anc| {
            self.groups
                .get(&anc)
                .is_some_and(|g| g.memory_max.is_some())
        })
    }

    /// Effective minimum `(rbps, wbps)` across all ancestors of `path`.
    pub fn effective_io_limit(&self, path: &str) -> IoLimit {
        let mut read: Option<u64> = None;
        let mut write: Option<u64> = None;
        for anc in ancestors(path) {
            if let Some(g) = self.groups.get(&anc) {
                if let Some(r) = g.io_read_bps {
                    read = Some(read.map_or(r, |cur| cur.min(r)));
                }
                if let Some(w) = g.io_write_bps {
                    write = Some(write.map_or(w, |cur| cur.min(w)));
                }
            }
        }
        IoLimit { read, write }
    }

    /// Verify that adding `delta` processes into `target_path` (when migrating from `from_path`,
    /// common ancestors see net zero change) satisfies every ancestor's `pids.max` and is not retired.
    pub fn check_pids_admit(
        &self,
        from_path: Option<&str>,
        target_path: &str,
        delta: usize,
        subtree_count: impl Fn(&str) -> usize,
    ) -> Result<(), Error> {
        let norm = normalize_cgroup_path(target_path)?;
        if !self.groups.contains_key(&norm) {
            return Err(Errno::ENOENT.into());
        }
        for anc in ancestors(&norm) {
            let group = self.groups.get(&anc).ok_or(Errno::ENOENT)?;
            if group.retired {
                return Err(Errno::ENOENT.into());
            }
            // If migrating from `from_path` and `from_path` is already inside `anc`, net delta is 0.
            if from_path.is_some_and(|from| in_subtree(from, &anc)) {
                continue;
            }
            if let Some(limit) = group.pids_max {
                let current = subtree_count(&anc);
                if current.saturating_add(delta) > limit as usize {
                    return Err(Errno::EAGAIN.into());
                }
            }
        }
        Ok(())
    }

    /// Verify that `target_path` (with `delta_bytes` additional memory, or migration of
    /// `moving_bytes` from `from_path`) satisfies every ancestor's `memory.max` and runtime tracking.
    pub fn check_memory_admit(
        &self,
        from_path: Option<&str>,
        target_path: &str,
        delta_bytes: u64,
        runtime_tracked: bool,
        subtree_memory: impl Fn(&str) -> u64,
    ) -> Result<(), Error> {
        let norm = normalize_cgroup_path(target_path)?;
        for anc in ancestors(&norm) {
            let group = self.groups.get(&anc).ok_or(Errno::ENOENT)?;
            let Some(limit) = group.memory_max else {
                continue;
            };
            if !runtime_tracked {
                return Err(Error::because(
                    Errno::EOPNOTSUPP,
                    "memory.max requires resources-v1 runtime enforcement",
                ));
            }
            if from_path.is_some_and(|from| in_subtree(from, &anc)) {
                continue;
            }
            let current = subtree_memory(&anc);
            if delta_bytes > 0 && current.saturating_add(delta_bytes) > limit {
                return Err(Error::because(
                    Errno::EAGAIN,
                    format!("memory.max reached at {anc}"),
                ));
            }
        }
        Ok(())
    }

    /// Mark all `CgroupLifetime::Process` cgroups owned by `owner_pid` as retired and return
    /// their paths so their subtrees can be SIGKILLed immediately.
    pub fn retire_owned_by(&mut self, owner_pid: u32) -> Vec<String> {
        let mut retired_paths = Vec::new();
        for (path, group) in &mut self.groups {
            if group.lifetime == Some(CgroupLifetime::Process)
                && group.lifetime_owner == Some(owner_pid)
                && !group.retired
            {
                group.retired = true;
                retired_paths.push(path.clone());
            }
        }
        // Also mark descendants of newly retired cgroups as retired so no new child can attach.
        if !retired_paths.is_empty() {
            for (path, group) in &mut self.groups {
                if retired_paths.iter().any(|root| in_subtree(path, root)) {
                    group.retired = true;
                }
            }
        }
        retired_paths
    }

    /// Remove any retired cgroup whose subtree contains no processes and no remaining children.
    pub fn prune_retired(&mut self, subtree_has_procs: impl Fn(&str) -> bool) {
        let mut candidates: Vec<String> = self
            .groups
            .iter()
            .filter(|(p, g)| g.retired && *p != "/" && !ROOT_CGROUPS.contains(&p.as_str()))
            .map(|(p, _)| p.clone())
            .collect();
        // Deepest paths first so empty children prune before their retired parent.
        candidates.sort_by_key(|p| std::cmp::Reverse(p.len()));
        for path in candidates {
            let has_children = self
                .groups
                .keys()
                .any(|p| p != &path && in_subtree(p, &path));
            if !has_children && !subtree_has_procs(&path) {
                self.groups.remove(&path);
            }
        }
    }

    pub fn list(&self, raw_path: &str) -> Vec<String> {
        let Ok(root) = normalize_cgroup_path(raw_path) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for (path, group) in &self.groups {
            if group.retired {
                continue;
            }
            if path != &root && parent_cgroup(path).as_deref() == Some(root.as_str()) {
                out.push(path.clone());
            }
        }
        out
    }

    pub fn stat(
        &self,
        raw_path: &str,
        direct_procs: Vec<u32>,
        subtree_procs: Vec<u32>,
        subtree_memory: u64,
        memory_untracked: usize,
    ) -> Result<Value, Error> {
        let path = normalize_cgroup_path(raw_path)?;
        let group = self.groups.get(&path).ok_or(Errno::ENOENT)?;
        let children = self.list(&path);
        let pids_max = match group.pids_max {
            Some(n) => json!(n),
            None => json!("max"),
        };
        let memory_max = match group.memory_max {
            Some(n) => json!(n.to_string()),
            None => json!("max"),
        };
        let io_max = group.io_max.clone().unwrap_or_else(|| "max".to_string());
        let cpu_max = group.cpu_max.clone().unwrap_or_else(|| "max".to_string());
        let enforced = if memory_untracked == 0 {
            vec!["pids.max", "memory.max", "io.max"]
        } else {
            vec!["pids.max", "io.max"]
        };
        Ok(json!({
            "path": group.path,
            "parent": parent_cgroup(&path).unwrap_or_default(),
            "owner": group.owner,
            "controllers": group.controllers,
            "pids.current": subtree_procs.len(),
            "pids.max": pids_max,
            "memory.current": subtree_memory,
            "memory.max": memory_max,
            "memory.untracked": memory_untracked,
            "memory.scope": "WASM linear memory, including runtime scratch; excludes host heap, tables, compiled code and retained GC backing stores",
            "io.max": io_max,
            "io.scope": "authorized filesystem byte transfers; rbps/wbps admission pacing, at most 30 seconds reserved; excludes metadata, local devices and compiler work",
            "cpu.max": cpu_max,
            "cpu.weight": group.cpu_weight,
            "cgroup.freeze": if group.frozen { "1" } else { "0" },
            "devices.allow": group.devices_allow,
            "devices.deny": group.devices_deny,
            "lifetime": group.lifetime,
            "retired": group.retired,
            "cgroup.procs": direct_procs,
            "subtree.procs": subtree_procs,
            "children": children,
            "resource.enforced": enforced,
            "resource.unsupported": ["cpu.max", "cpu.weight", "cgroup.freeze"],
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn user(id: u32) -> Identity {
        Identity {
            id,
            group: id,
            groups: BTreeSet::from([id]),
        }
    }

    #[test]
    fn root_cgroups_and_delegation_rules() {
        let mut table = CgroupTable::new();
        let ann = user(1000);
        let bob = user(1001);

        // Non-root cannot create under /system, can create under /user.
        assert_eq!(
            table
                .create(&ann, Some(2), "/system/denied", None, None)
                .unwrap_err()
                .errno,
            Errno::EACCES
        );
        table
            .create(&ann, Some(2), "/user/ann-app", None, None)
            .unwrap();
        // Bob cannot mutate or remove Ann's cgroup.
        assert_eq!(
            table
                .set(&bob, "/user/ann-app", "pids.max", "5")
                .unwrap_err()
                .errno,
            Errno::EACCES
        );
        assert_eq!(
            table
                .remove(&bob, "/user/ann-app", |_| false)
                .unwrap_err()
                .errno,
            Errno::EACCES
        );
        // Ann sets pids.max, memory.max, io.max, devices.deny.
        table.set(&ann, "/user/ann-app", "pids.max", "2").unwrap();
        table
            .set(&ann, "/user/ann-app", "memory.max", "131072")
            .unwrap();
        let eff = table
            .set(&ann, "/user/ann-app", "io.max", "rbps=4096 wbps=8192")
            .unwrap();
        assert_eq!(
            eff,
            CgroupSetEffect::IoPolicyChanged {
                path: "/user/ann-app".into(),
                rbps: Some(4096),
                wbps: Some(8192),
            }
        );
        assert_eq!(
            table.effective_io_limit("/user/ann-app"),
            IoLimit {
                read: Some(4096),
                write: Some(8192)
            }
        );
    }

    #[test]
    fn hierarchical_pids_and_memory_limits_enforce_strictly() {
        let mut table = CgroupTable::new();
        let root = Identity::root();
        table
            .create(&root, Some(1), "/user/parent", None, None)
            .unwrap();
        table
            .create(&root, Some(1), "/user/parent/child", None, None)
            .unwrap();
        table.set(&root, "/user/parent", "pids.max", "2").unwrap();
        table
            .set(&root, "/user/parent", "memory.max", "131072")
            .unwrap();

        // Overflow pids.max -> EAGAIN.
        assert_eq!(
            table
                .check_pids_admit(None, "/user/parent/child", 1, |_| 2)
                .unwrap_err()
                .errno,
            Errno::EAGAIN
        );
        // Migrating inside same parent subtree sees net-zero pid delta -> Ok.
        table
            .check_pids_admit(Some("/user/parent"), "/user/parent/child", 1, |_| 2)
            .unwrap();

        // Untracked runtime with memory.max -> EOPNOTSUPP.
        assert_eq!(
            table
                .check_memory_admit(None, "/user/parent/child", 65536, false, |_| 0)
                .unwrap_err()
                .errno,
            Errno::EOPNOTSUPP
        );
        // Tracked runtime within limit -> Ok; over limit -> EAGAIN.
        table
            .check_memory_admit(None, "/user/parent/child", 65536, true, |_| 65536)
            .unwrap();
        assert_eq!(
            table
                .check_memory_admit(None, "/user/parent/child", 65537, true, |_| 65536)
                .unwrap_err()
                .errno,
            Errno::EAGAIN
        );

        // Bad limit strings -> EINVAL.
        for bad in ["", "-1", "+5", "abc", "1.5"] {
            assert_eq!(
                table
                    .set(&root, "/user/parent", "pids.max", bad)
                    .unwrap_err()
                    .errno,
                Errno::EINVAL
            );
            assert_eq!(
                table
                    .set(&root, "/user/parent", "memory.max", bad)
                    .unwrap_err()
                    .errno,
                Errno::EINVAL
            );
        }
    }

    #[test]
    fn process_lifetime_cgroup_retires_and_prunes_when_empty() {
        let mut table = CgroupTable::new();
        let ann = user(1000);
        table
            .create(
                &ann,
                Some(42),
                "/user/sup-42",
                None,
                Some(CgroupLifetime::Process),
            )
            .unwrap();
        table
            .create(&ann, Some(42), "/user/sup-42/nested", None, None)
            .unwrap();
        let retired = table.retire_owned_by(42);
        assert_eq!(retired, vec!["/user/sup-42".to_string()]);
        // Retired cgroup rejects new attaches and child creations.
        assert_eq!(
            table
                .authorize_attach(&ann, 1000, "/user/sup-42/nested")
                .unwrap_err()
                .errno,
            Errno::ENOENT
        );
        // While procs remain, prune keeps them; once empty, both nested & parent prune.
        table.prune_retired(|_| true);
        assert!(table.get("/user/sup-42").is_some());
        table.prune_retired(|_| false);
        assert!(table.get("/user/sup-42").is_none());
        assert!(table.get("/user/sup-42/nested").is_none());
    }
}
