//! Versioned Rust-first Own-Device Task SDK (`os-task-sdk`, Phase 9.1b #84).
//!
//! Portable across native hosts (`os-native`), `wasm32-unknown-unknown`, and `wasm32-wasip1`
//! guest pods with zero external runtime dependencies beyond `os-abi`, `os-cluster-state`,
//! and `serde`/`serde_json`.
pub mod agent;
pub mod client;
pub mod guest;

use abi::Errno;
use abi::auth_v2::valid_cluster_record_id;
use abi::cluster_state::{ClusterError, NodeMetaRecord, ResultRecord, WorkloadRecord};
use abi::registry::valid_repo_name;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Active `os-task-sdk` schema version encoded in `os.task/sdk_version`.
pub const TASK_SDK_VERSION: u32 = 1;

pub const LABEL_SDK_VERSION: &str = "os.task/sdk_version";
pub const LABEL_ENTRYPOINT: &str = "os.task/entrypoint";
pub const LABEL_ARGS_JSON: &str = "os.task/args_json";
pub const LABEL_ENV_JSON: &str = "os.task/env_json";
pub const LABEL_OUTPUT_REPO: &str = "os.task/output_repo";
pub const LABEL_TIMEOUT_SECS: &str = "os.task/timeout_secs";
pub const LABEL_MEMORY_MAX_BYTES: &str = "os.task/memory_max_bytes";
pub const LABEL_PIDS_MAX: &str = "os.task/pids_max";
pub const LABEL_REQUIRED_HOST: &str = "os.task/required_host";
pub const LABEL_REQUIRED_NODE: &str = "os.task/required_node";
pub const LABEL_REQUIRED_CAPS: &str = "os.task/required_caps";
pub const LABEL_EXTRA_INPUTS_JSON: &str = "os.task/extra_inputs_json";
pub const LABEL_JOB_ID: &str = "os.task/job_id";
pub const LABEL_STAGE: &str = "os.task/stage";
pub const LABEL_SHARD_INDEX: &str = "os.task/shard_index";
pub const LABEL_SHARD_COUNT: &str = "os.task/shard_count";

pub const DEFAULT_TIMEOUT_SECS: u64 = 300;
pub const MAX_TIMEOUT_SECS: u64 = 86_400;
pub const DEFAULT_MEMORY_MAX_BYTES: u64 = 128 * 1024 * 1024;
pub const MIN_MEMORY_MAX_BYTES: u64 = 1024 * 1024;
pub const MAX_MEMORY_MAX_BYTES: u64 = 4 * 1024 * 1024 * 1024;
pub const DEFAULT_PIDS_MAX: u32 = 16;
pub const MAX_PIDS_MAX: u32 = 1024;

fn default_timeout_secs() -> u64 {
    DEFAULT_TIMEOUT_SECS
}

fn default_memory_max_bytes() -> u64 {
    DEFAULT_MEMORY_MAX_BYTES
}

fn default_pids_max() -> u32 {
    DEFAULT_PIDS_MAX
}

fn valid_input_mount_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn valid_entrypoint(path: &str) -> bool {
    if !path.starts_with('/') || path.len() > 512 || path.contains('\0') {
        return false;
    }
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    !parts.is_empty() && parts.iter().all(|seg| *seg != "." && *seg != "..")
}

/// Canonical task specification translated to/from [`WorkloadRecord`] via `os.task/*` labels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskSpec {
    pub workload_id: String,
    /// Immutable OCI image reference (e.g. `oci:tasks/wordcount@sha256:...` or `oci:tasks/wordcount:v1`).
    pub image_ref: String,
    /// Executable path inside the sandbox rootfs (e.g. `/usr/bin/task.wasm`).
    pub entrypoint: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Optional primary read-only input snapshot mounted at `/input`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_snapshot_ref: Option<String>,
    /// Optional additional read-only input snapshots mounted at `/input/<name>`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra_inputs: BTreeMap<String, String>,
    /// OCI repository where the node stages and promotes the output `cowfs` snapshot.
    pub output_repo: String,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default = "default_memory_max_bytes")]
    pub memory_max_bytes: u64,
    #[serde(default = "default_pids_max")]
    pub pids_max: u32,
    /// Optional placement constraint on `NodeMetaRecord.host_kind` (`browser` | `os-native` | `container`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_host: Option<String>,
    /// Optional placement constraint pinning execution to a specific `node_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_node: Option<String>,
    /// Optional capabilities that must all appear in `NodeMetaRecord.capabilities`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_caps: Vec<String>,
    /// Optional non-reserved application labels preserved on the `WorkloadRecord`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub user_labels: BTreeMap<String, String>,
}

impl TaskSpec {
    pub fn validate(&self) -> Result<(), ClusterError> {
        if !valid_cluster_record_id(&self.workload_id) {
            return Err(ClusterError::because(Errno::EINVAL, "invalid workload_id"));
        }
        if self.image_ref.is_empty() || self.image_ref.len() > 512 {
            return Err(ClusterError::because(Errno::EINVAL, "invalid image_ref"));
        }
        if !valid_entrypoint(&self.entrypoint) {
            return Err(ClusterError::because(Errno::EINVAL, "invalid entrypoint"));
        }
        if !valid_repo_name(&self.output_repo) {
            return Err(ClusterError::because(Errno::EINVAL, "invalid output_repo"));
        }
        if !(1..=MAX_TIMEOUT_SECS).contains(&self.timeout_secs) {
            return Err(ClusterError::because(Errno::EINVAL, "invalid timeout_secs"));
        }
        if !(MIN_MEMORY_MAX_BYTES..=MAX_MEMORY_MAX_BYTES).contains(&self.memory_max_bytes) {
            return Err(ClusterError::because(
                Errno::EINVAL,
                "invalid memory_max_bytes",
            ));
        }
        if !(1..=MAX_PIDS_MAX).contains(&self.pids_max) {
            return Err(ClusterError::because(Errno::EINVAL, "invalid pids_max"));
        }
        if let Some(ref input) = self.input_snapshot_ref
            && (input.is_empty() || input.len() > 512)
        {
            return Err(ClusterError::because(
                Errno::EINVAL,
                "invalid input_snapshot_ref",
            ));
        }
        if self.extra_inputs.len() > 64 {
            return Err(ClusterError::because(
                Errno::E2BIG,
                "too many extra_inputs (max 64)",
            ));
        }
        for (name, target) in &self.extra_inputs {
            if !valid_input_mount_name(name) || target.is_empty() || target.len() > 512 {
                return Err(ClusterError::because(
                    Errno::EINVAL,
                    "invalid extra_inputs entry",
                ));
            }
        }
        if let Some(ref host) = self.required_host
            && !matches!(host.as_str(), "browser" | "os-native" | "container")
        {
            return Err(ClusterError::because(
                Errno::EINVAL,
                "invalid required_host",
            ));
        }
        if let Some(ref node) = self.required_node
            && !valid_cluster_record_id(node)
        {
            return Err(ClusterError::because(
                Errno::EINVAL,
                "invalid required_node",
            ));
        }
        if self.args.len() > 256 || self.env.len() > 128 {
            return Err(ClusterError::because(
                Errno::E2BIG,
                "too many task args or env vars",
            ));
        }
        for k in self.env.keys() {
            if k.is_empty() || k.contains('=') || k.contains('\0') {
                return Err(ClusterError::because(
                    Errno::EINVAL,
                    "invalid environment variable key",
                ));
            }
        }
        Ok(())
    }

    /// Encode this `TaskSpec` into a canonical pending [`WorkloadRecord`].
    pub fn to_workload_record(&self, created_at: u64) -> Result<WorkloadRecord, ClusterError> {
        self.validate()?;
        let mut labels = BTreeMap::new();
        for (k, v) in &self.user_labels {
            if !k.starts_with("os.task/")
                || matches!(
                    k.as_str(),
                    LABEL_JOB_ID | LABEL_STAGE | LABEL_SHARD_INDEX | LABEL_SHARD_COUNT
                )
            {
                labels.insert(k.clone(), v.clone());
            }
        }
        labels.insert(LABEL_SDK_VERSION.into(), TASK_SDK_VERSION.to_string());
        labels.insert(LABEL_ENTRYPOINT.into(), self.entrypoint.clone());
        labels.insert(LABEL_OUTPUT_REPO.into(), self.output_repo.clone());
        labels.insert(LABEL_TIMEOUT_SECS.into(), self.timeout_secs.to_string());
        labels.insert(
            LABEL_MEMORY_MAX_BYTES.into(),
            self.memory_max_bytes.to_string(),
        );
        labels.insert(LABEL_PIDS_MAX.into(), self.pids_max.to_string());
        if !self.args.is_empty() {
            labels.insert(
                LABEL_ARGS_JSON.into(),
                serde_json::to_string(&self.args).map_err(|_| Errno::EINVAL)?,
            );
        }
        if !self.env.is_empty() {
            labels.insert(
                LABEL_ENV_JSON.into(),
                serde_json::to_string(&self.env).map_err(|_| Errno::EINVAL)?,
            );
        }
        if !self.extra_inputs.is_empty() {
            labels.insert(
                LABEL_EXTRA_INPUTS_JSON.into(),
                serde_json::to_string(&self.extra_inputs).map_err(|_| Errno::EINVAL)?,
            );
        }
        if let Some(ref host) = self.required_host {
            labels.insert(LABEL_REQUIRED_HOST.into(), host.clone());
        }
        if let Some(ref node) = self.required_node {
            labels.insert(LABEL_REQUIRED_NODE.into(), node.clone());
        }
        if !self.required_caps.is_empty() {
            labels.insert(LABEL_REQUIRED_CAPS.into(), self.required_caps.join(","));
        }
        let wl = WorkloadRecord {
            workload_id: self.workload_id.clone(),
            image_ref: self.image_ref.clone(),
            input_snapshot_ref: self.input_snapshot_ref.clone(),
            labels,
            desired_state: "pending".into(),
            current_attempt: 0,
            created_at,
        };
        wl.validate()?;
        Ok(wl)
    }

    /// Decode and validate a [`TaskSpec`] from a [`WorkloadRecord`].
    pub fn from_workload_record(wl: &WorkloadRecord) -> Result<Self, ClusterError> {
        wl.validate()?;
        let sdk_ver = wl
            .labels
            .get(LABEL_SDK_VERSION)
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(TASK_SDK_VERSION);
        if sdk_ver != TASK_SDK_VERSION {
            return Err(ClusterError::because(
                Errno::EPROTONOSUPPORT,
                format!("unsupported task sdk_version {sdk_ver}"),
            ));
        }
        let entrypoint =
            wl.labels.get(LABEL_ENTRYPOINT).cloned().ok_or_else(|| {
                ClusterError::because(Errno::EINVAL, "missing os.task/entrypoint")
            })?;
        let output_repo =
            wl.labels.get(LABEL_OUTPUT_REPO).cloned().ok_or_else(|| {
                ClusterError::because(Errno::EINVAL, "missing os.task/output_repo")
            })?;
        let args: Vec<String> = match wl.labels.get(LABEL_ARGS_JSON) {
            Some(raw) => serde_json::from_str(raw)
                .map_err(|_| ClusterError::because(Errno::EINVAL, "invalid os.task/args_json"))?,
            None => Vec::new(),
        };
        let env: BTreeMap<String, String> = match wl.labels.get(LABEL_ENV_JSON) {
            Some(raw) => serde_json::from_str(raw)
                .map_err(|_| ClusterError::because(Errno::EINVAL, "invalid os.task/env_json"))?,
            None => BTreeMap::new(),
        };
        let extra_inputs: BTreeMap<String, String> = match wl.labels.get(LABEL_EXTRA_INPUTS_JSON) {
            Some(raw) => serde_json::from_str(raw).map_err(|_| {
                ClusterError::because(Errno::EINVAL, "invalid os.task/extra_inputs_json")
            })?,
            None => BTreeMap::new(),
        };
        let timeout_secs = wl
            .labels
            .get(LABEL_TIMEOUT_SECS)
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(DEFAULT_TIMEOUT_SECS);
        let memory_max_bytes = wl
            .labels
            .get(LABEL_MEMORY_MAX_BYTES)
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(DEFAULT_MEMORY_MAX_BYTES);
        let pids_max = wl
            .labels
            .get(LABEL_PIDS_MAX)
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(DEFAULT_PIDS_MAX);
        let required_host = wl.labels.get(LABEL_REQUIRED_HOST).cloned();
        let required_node = wl.labels.get(LABEL_REQUIRED_NODE).cloned();
        let required_caps: Vec<String> = wl
            .labels
            .get(LABEL_REQUIRED_CAPS)
            .map(|s| {
                s.split(',')
                    .map(str::trim)
                    .filter(|c| !c.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let mut user_labels = BTreeMap::new();
        for (k, v) in &wl.labels {
            if !k.starts_with("os.task/")
                || matches!(
                    k.as_str(),
                    LABEL_JOB_ID | LABEL_STAGE | LABEL_SHARD_INDEX | LABEL_SHARD_COUNT
                )
            {
                user_labels.insert(k.clone(), v.clone());
            }
        }
        let spec = Self {
            workload_id: wl.workload_id.clone(),
            image_ref: wl.image_ref.clone(),
            entrypoint,
            args,
            env,
            input_snapshot_ref: wl.input_snapshot_ref.clone(),
            extra_inputs,
            output_repo,
            timeout_secs,
            memory_max_bytes,
            pids_max,
            required_host,
            required_node,
            required_caps,
            user_labels,
        };
        spec.validate()?;
        Ok(spec)
    }
}

/// True when `node` satisfies all placement constraints declared on `spec`.
pub fn matches_node(spec: &TaskSpec, node: &NodeMetaRecord) -> bool {
    if let Some(ref host) = spec.required_host
        && node.host_kind != *host
    {
        return false;
    }
    if let Some(ref req_node) = spec.required_node
        && node.node_id != *req_node
    {
        return false;
    }
    for cap in &spec.required_caps {
        if !node.capabilities.iter().any(|c| c == cap) {
            return false;
        }
    }
    true
}

/// One map shard input & optional placement constraint inside [`MapReduceSpec`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MapShardSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_snapshot_ref: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_node: Option<String>,
}

/// High-level fan-out/fan-in Map-Reduce specification built over [`TaskSpec`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MapReduceSpec {
    pub job_id: String,
    pub map_image_ref: String,
    pub map_entrypoint: String,
    pub reduce_image_ref: String,
    pub reduce_entrypoint: String,
    pub shards: Vec<MapShardSpec>,
    #[serde(default)]
    pub reduce_args: Vec<String>,
    #[serde(default)]
    pub reduce_env: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reduce_required_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reduce_required_node: Option<String>,
    pub output_repo: String,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default = "default_memory_max_bytes")]
    pub memory_max_bytes: u64,
    #[serde(default = "default_pids_max")]
    pub pids_max: u32,
}

impl MapReduceSpec {
    pub fn validate(&self) -> Result<(), ClusterError> {
        if !valid_cluster_record_id(&self.job_id) || self.job_id.len() > 96 {
            return Err(ClusterError::because(Errno::EINVAL, "invalid job_id"));
        }
        if self.shards.is_empty() || self.shards.len() > 64 {
            return Err(ClusterError::because(
                Errno::EINVAL,
                "map-reduce requires 1..=64 shards",
            ));
        }
        if !valid_repo_name(&self.output_repo) {
            return Err(ClusterError::because(Errno::EINVAL, "invalid output_repo"));
        }
        for (i, shard) in self.shards.iter().enumerate() {
            self.map_task_spec(i, shard).validate()?;
        }
        self.reduce_task_spec(&BTreeMap::new()).validate()?;
        Ok(())
    }

    pub fn map_task_spec(&self, idx: usize, shard: &MapShardSpec) -> TaskSpec {
        let mut user_labels = BTreeMap::new();
        user_labels.insert(LABEL_JOB_ID.into(), self.job_id.clone());
        user_labels.insert(LABEL_STAGE.into(), "map".into());
        user_labels.insert(LABEL_SHARD_INDEX.into(), idx.to_string());
        user_labels.insert(LABEL_SHARD_COUNT.into(), self.shards.len().to_string());
        TaskSpec {
            workload_id: format!("{}-map-{idx}", self.job_id),
            image_ref: self.map_image_ref.clone(),
            entrypoint: self.map_entrypoint.clone(),
            args: shard.args.clone(),
            env: shard.env.clone(),
            input_snapshot_ref: shard.input_snapshot_ref.clone(),
            extra_inputs: BTreeMap::new(),
            output_repo: self.output_repo.clone(),
            timeout_secs: self.timeout_secs,
            memory_max_bytes: self.memory_max_bytes,
            pids_max: self.pids_max,
            required_host: shard.required_host.clone(),
            required_node: shard.required_node.clone(),
            required_caps: Vec::new(),
            user_labels,
        }
    }

    pub fn reduce_task_spec(&self, shard_outputs: &BTreeMap<String, String>) -> TaskSpec {
        let mut user_labels = BTreeMap::new();
        user_labels.insert(LABEL_JOB_ID.into(), self.job_id.clone());
        user_labels.insert(LABEL_STAGE.into(), "reduce".into());
        user_labels.insert(LABEL_SHARD_COUNT.into(), self.shards.len().to_string());
        TaskSpec {
            workload_id: format!("{}-reduce", self.job_id),
            image_ref: self.reduce_image_ref.clone(),
            entrypoint: self.reduce_entrypoint.clone(),
            args: self.reduce_args.clone(),
            env: self.reduce_env.clone(),
            input_snapshot_ref: None,
            extra_inputs: shard_outputs.clone(),
            output_repo: self.output_repo.clone(),
            timeout_secs: self.timeout_secs,
            memory_max_bytes: self.memory_max_bytes,
            pids_max: self.pids_max,
            required_host: self.reduce_required_host.clone(),
            required_node: self.reduce_required_node.clone(),
            required_caps: Vec::new(),
            user_labels,
        }
    }
}

/// Typed wrapper over a terminal [`ResultRecord`] published in `ClusterState`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskResultView {
    pub record: ResultRecord,
}

impl TaskResultView {
    pub fn succeeded(&self) -> bool {
        self.record.exit_code == 0
    }
    pub fn workload_id(&self) -> &str {
        &self.record.workload_id
    }
    pub fn exit_code(&self) -> i32 {
        self.record.exit_code
    }
    pub fn output_ref(&self) -> Option<&str> {
        self.record.output_ref.as_deref()
    }
    pub fn summary(&self) -> Option<&str> {
        self.record.summary.as_deref()
    }
    pub fn node_id(&self) -> &str {
        &self.record.node_id
    }
    pub fn attempt_generation(&self) -> u64 {
        self.record.attempt_generation
    }
    pub fn node_generation(&self) -> u64 {
        self.record.node_generation
    }
}

/// Aggregated result of a completed Map-Reduce job.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MapReduceResult {
    pub job_id: String,
    pub map_results: Vec<TaskResultView>,
    pub reduce_result: TaskResultView,
}
