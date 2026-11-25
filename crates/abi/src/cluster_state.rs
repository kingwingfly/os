//! Wire protocol types, key grammar, hard bounds, and typed cluster records for
//! `Boundary::ClusterState` v1 (Phase 9.1a #83).
//!
//! Exposes honest **etcd-subset semantics** (linearizable revisioned KV, atomic conditional
//! transactions, persistent prefix watches, node/object leases, and MVCC compaction) behind a
//! portable `ClusterStore` trait. No etcd or Kubernetes wire compatibility is claimed.
use crate::Errno;
use crate::auth_v2::valid_cluster_record_id;
use crate::contract::Boundary;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Active `Boundary::ClusterState` wire protocol version (`contract::CLUSTER_STATE_VERSION`).
pub const CLUSTER_STATE_PROTOCOL: u32 = crate::contract::CLUSTER_STATE_VERSION;

pub const CLUSTER_NAME_MAX_BYTES: usize = 64;
pub const CLUSTER_KEY_MAX_BYTES: usize = 512;
pub const CLUSTER_VALUE_MAX_BYTES: usize = 256 * 1024;
pub const CLUSTER_RPC_BODY_MAX_BYTES: usize = 1024 * 1024;
pub const CLUSTER_WS_FRAME_MAX_BYTES: usize = 64 * 1024;
pub const CLUSTER_TXN_MAX_COMPARES: usize = 64;
pub const CLUSTER_TXN_MAX_OPS: usize = 64;
pub const CLUSTER_TXN_MAX_WRITE_BYTES: usize = 512 * 1024;
pub const CLUSTER_RANGE_DEFAULT_LIMIT: u32 = 256;
pub const CLUSTER_RANGE_MAX_LIMIT: u32 = 1024;
pub const CLUSTER_WATCH_MAX_PER_SOCKET: usize = 16;
pub const CLUSTER_WATCH_MAX_SOCKETS: usize = 256;
pub const CLUSTER_WATCH_CATCHUP_BATCH: u32 = 128;
pub const CLUSTER_WATCH_TICKET_TTL_SECS: u64 = 30;
pub const CLUSTER_LEASE_MIN_TTL_SECS: u64 = 5;
pub const CLUSTER_LEASE_MAX_TTL_SECS: u64 = 3600;
pub const CLUSTER_MAX_KEYS_PER_LEASE: usize = 256;
pub const CLUSTER_MAX_LEASES_PER_TENANT: usize = 1024;
pub const CLUSTER_MAX_LIVE_KEYS_PER_TENANT: usize = 16_384;
pub const CLUSTER_MAX_LIVE_BYTES_PER_TENANT: u64 = 64 * 1024 * 1024;
pub const CLUSTER_MAX_PREFIX_GRANTS: usize = 32;

pub fn default_cluster_name() -> String {
    "default".into()
}

/// Validate a cluster instance name (e.g. `"default"`, `"prod-us1"`).
pub fn valid_cluster_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= CLUSTER_NAME_MAX_BYTES
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// Validate canonical tenant identifier (`u<u32>` with no leading zeroes except `u0`).
pub fn valid_tenant_name(tenant: &str) -> bool {
    tenant
        .strip_prefix('u')
        .and_then(|id| id.parse::<u32>().ok())
        .is_some_and(|id| tenant == format!("u{id}"))
}

/// Validate one path segment of a cluster key (`[A-Za-z0-9._:@-]`, non-empty, never `.` or `..`).
pub fn valid_key_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'@' | b'-'))
}

/// Validate an exact cluster key: `/t/<tenant>/<seg>[/<seg>...]`, no trailing `/`, `<= 512` bytes.
pub fn valid_cluster_key(key: &str) -> bool {
    if key.is_empty() || key.len() > CLUSTER_KEY_MAX_BYTES || key.ends_with('/') {
        return false;
    }
    let Some(rest) = key.strip_prefix("/t/") else {
        return false;
    };
    let Some((tenant, rel)) = rest.split_once('/') else {
        return false;
    };
    valid_tenant_name(tenant) && !rel.is_empty() && rel.split('/').all(valid_key_segment)
}

/// Validate a cluster range/watch key: `/t/<tenant>/` or `/t/<tenant>/<rel>[/]`, `<= 512` bytes.
pub fn valid_cluster_range_key(key: &str) -> bool {
    if key.is_empty() || key.len() > CLUSTER_KEY_MAX_BYTES {
        return false;
    }
    let Some(rest) = key.strip_prefix("/t/") else {
        return false;
    };
    let Some((tenant, rel)) = rest.split_once('/') else {
        return false;
    };
    if !valid_tenant_name(tenant) {
        return false;
    }
    if rel.is_empty() {
        return true;
    }
    let trimmed = rel.strip_suffix('/').unwrap_or(rel);
    !trimmed.is_empty() && trimmed.split('/').all(valid_key_segment)
}

/// Split a valid cluster key or range key into `(tenant, relative_key)`.
/// For `/t/<tenant>/`, returns `Some((tenant, ""))`.
pub fn split_tenant_key(key: &str) -> Option<(&str, &str)> {
    if !valid_cluster_range_key(key) {
        return None;
    }
    let rest = key.strip_prefix("/t/")?;
    rest.split_once('/')
}

/// Compute the exclusive byte-lexicographic upper bound for prefix scans (`[prefix, end)`).
pub fn prefix_range_end(prefix: &str) -> Option<String> {
    if prefix.is_empty() {
        return None;
    }
    let mut bytes = prefix.as_bytes().to_vec();
    while let Some(last) = bytes.last_mut() {
        if *last < 0xff {
            *last += 1;
            return String::from_utf8(bytes).ok();
        }
        bytes.pop();
    }
    None
}

/// Encode raw bytes as standard base64 for cluster values.
pub fn encode_value_b64(bytes: &[u8]) -> Result<String, ClusterError> {
    if bytes.len() > CLUSTER_VALUE_MAX_BYTES {
        return Err(ClusterError::because(
            Errno::EFBIG,
            format!("value exceeds {CLUSTER_VALUE_MAX_BYTES} byte limit"),
        ));
    }
    Ok(STANDARD.encode(bytes))
}

/// Decode standard base64 cluster value bytes, enforcing `CLUSTER_VALUE_MAX_BYTES`.
pub fn decode_value_b64(value_b64: &str) -> Result<Vec<u8>, ClusterError> {
    // Upper bound on base64 length before decoding to avoid unbounded allocation.
    let max_b64 = CLUSTER_VALUE_MAX_BYTES.div_ceil(3) * 4 + 4;
    if value_b64.len() > max_b64 {
        return Err(ClusterError::because(
            Errno::EFBIG,
            format!("value exceeds {CLUSTER_VALUE_MAX_BYTES} byte limit"),
        ));
    }
    let bytes = STANDARD
        .decode(value_b64)
        .map_err(|_| ClusterError::because(Errno::EINVAL, "invalid base64 value"))?;
    if bytes.len() > CLUSTER_VALUE_MAX_BYTES {
        return Err(ClusterError::because(
            Errno::EFBIG,
            format!("value exceeds {CLUSTER_VALUE_MAX_BYTES} byte limit"),
        ));
    }
    Ok(bytes)
}

/// Upper-bound specification for `Range`, `DeleteRange`, and `Watch`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RangeEnd {
    /// Single exact key (`key`).
    #[default]
    Exact,
    /// Prefix scan `[key, prefix_range_end(key))`, clamped to the caller's tenant.
    Prefix,
    /// Explicit exclusive upper key `[key, end)`, strictly within the caller's tenant.
    Key(String),
    /// All keys `>= key` clamped strictly to the caller's tenant (`/t/<tenant>/`).
    OpenEnded,
}

/// Structured compaction floor payload returned when a requested revision has been compacted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactedError {
    pub floor: u64,
}

/// Structured wire error returned by `ClusterState` RPC and Watch endpoints.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterError {
    pub errno: Errno,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compacted: Option<CompactedError>,
}

impl ClusterError {
    pub fn new(errno: Errno) -> Self {
        Self {
            errno,
            detail: None,
            compacted: None,
        }
    }

    pub fn because(errno: Errno, detail: impl Into<String>) -> Self {
        Self {
            errno,
            detail: Some(detail.into()),
            compacted: None,
        }
    }

    pub fn compacted(floor: u64) -> Self {
        Self {
            errno: Errno::ESTALE,
            detail: Some(format!(
                "requested revision has been compacted; floor is {floor}"
            )),
            compacted: Some(CompactedError { floor }),
        }
    }
}

impl From<Errno> for ClusterError {
    fn from(errno: Errno) -> Self {
        Self::new(errno)
    }
}

impl std::fmt::Display for ClusterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.detail.as_deref().unwrap_or(self.errno.text()))
    }
}

impl std::error::Error for ClusterError {}

/// Revisioned key-value entry stored in `ClusterState`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyValue {
    pub key: String,
    pub value_b64: String,
    pub create_revision: u64,
    pub mod_revision: u64,
    pub version: u64,
    #[serde(default)]
    pub lease_id: u64,
}

impl KeyValue {
    pub fn decode_value(&self) -> Result<Vec<u8>, ClusterError> {
        decode_value_b64(&self.value_b64)
    }
}

/// Top-level RPC request envelope for `POST /api/cluster/rpc`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterRpcRequest {
    pub version: u32,
    #[serde(default = "default_cluster_name")]
    pub cluster: String,
    pub call: ClusterCall,
}

impl ClusterRpcRequest {
    /// Decode and validate protocol `version == CLUSTER_STATE_PROTOCOL` BEFORE inspecting the
    /// inner call, returning `EPROTONOSUPPORT` on version mismatch and `EINVAL` on schema errors.
    pub fn decode(bytes: &[u8]) -> Result<Self, ClusterError> {
        if bytes.len() > CLUSTER_RPC_BODY_MAX_BYTES {
            return Err(ClusterError::because(
                Errno::EFBIG,
                "cluster RPC body exceeds maximum size",
            ));
        }
        #[derive(Deserialize)]
        struct Envelope {
            version: u32,
        }
        let Envelope { version } = serde_json::from_slice(bytes)
            .map_err(|_| ClusterError::because(Errno::EINVAL, "invalid cluster RPC envelope"))?;
        if version != CLUSTER_STATE_PROTOCOL {
            return Err(ClusterError::because(
                Errno::EPROTONOSUPPORT,
                format!("ClusterState protocol v{CLUSTER_STATE_PROTOCOL} required"),
            ));
        }
        let req: Self = serde_json::from_slice(bytes)
            .map_err(|_| ClusterError::because(Errno::EINVAL, "invalid cluster RPC request"))?;
        if !valid_cluster_name(&req.cluster) {
            return Err(ClusterError::because(Errno::EINVAL, "invalid cluster name"));
        }
        Ok(req)
    }
}

/// Comparison operator for `Compare`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompareOp {
    Equal,
    NotEqual,
    Less,
    Greater,
}

/// Attribute compared by a `Txn` guard.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum CompareTarget {
    Version(u64),
    CreateRevision(u64),
    ModRevision(u64),
    Value(String),
    Lease(u64),
}

/// Atomic guard evaluated before selecting a `Txn`'s `success` or `failure` branch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Compare {
    pub key: String,
    pub op: CompareOp,
    pub target: CompareTarget,
}

/// Operation executed inside a `Txn`'s `success` or `failure` branch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum TxnOp {
    Range {
        key: String,
        #[serde(default)]
        range_end: RangeEnd,
        #[serde(default)]
        limit: Option<u32>,
        #[serde(default)]
        keys_only: bool,
        #[serde(default)]
        count_only: bool,
    },
    Put {
        key: String,
        value_b64: String,
        #[serde(default)]
        lease_id: u64,
        #[serde(default)]
        prev_kv: bool,
    },
    DeleteRange {
        key: String,
        #[serde(default)]
        range_end: RangeEnd,
        #[serde(default)]
        prev_kv: bool,
    },
}

/// Per-operation result inside `ClusterReply::Txn`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum TxnOpReply {
    Range {
        kvs: Vec<KeyValue>,
        more: bool,
        count: u64,
    },
    Put {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        prev_kv: Option<KeyValue>,
    },
    DeleteRange {
        deleted: u64,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        prev_kvs: Vec<KeyValue>,
    },
}

/// RPC call dispatched inside `ClusterRpcRequest`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClusterCall {
    Hello {
        versions: Vec<u32>,
    },
    Range {
        key: String,
        #[serde(default)]
        range_end: RangeEnd,
        #[serde(default)]
        revision: u64,
        #[serde(default)]
        limit: Option<u32>,
        #[serde(default)]
        keys_only: bool,
        #[serde(default)]
        count_only: bool,
    },
    Txn {
        #[serde(default)]
        compare: Vec<Compare>,
        #[serde(default)]
        success: Vec<TxnOp>,
        #[serde(default)]
        failure: Vec<TxnOp>,
    },
    LeaseGrant {
        ttl_secs: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        node_id: Option<String>,
    },
    LeaseKeepAlive {
        lease_id: u64,
    },
    LeaseRevoke {
        lease_id: u64,
    },
    LeaseTimeToLive {
        lease_id: u64,
        #[serde(default)]
        keys: bool,
    },
    Compact {
        revision: u64,
    },
}

/// RPC reply returned by `ClusterState`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClusterReply {
    Welcome {
        boundary: Boundary,
        version: u32,
        cluster: String,
        tenant: String,
        revision: u64,
        compacted_floor: u64,
    },
    Range {
        revision: u64,
        compacted_floor: u64,
        kvs: Vec<KeyValue>,
        more: bool,
        count: u64,
    },
    Txn {
        revision: u64,
        compacted_floor: u64,
        succeeded: bool,
        responses: Vec<TxnOpReply>,
    },
    LeaseGranted {
        revision: u64,
        lease_id: u64,
        ttl_secs: u64,
        expires_at: u64,
    },
    LeaseKeptAlive {
        revision: u64,
        lease_id: u64,
        ttl_secs: u64,
        expires_at: u64,
    },
    LeaseRevoked {
        revision: u64,
        lease_id: u64,
        deleted: u64,
    },
    LeaseTtl {
        revision: u64,
        lease_id: u64,
        granted_ttl_secs: u64,
        remaining_ttl_secs: u64,
        expires_at: u64,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        keys: Vec<String>,
    },
    Compacted {
        revision: u64,
        compacted_floor: u64,
    },
}

/// Request envelope for `POST /api/cluster/watch-ticket`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchTicketRequest {
    pub version: u32,
    #[serde(default = "default_cluster_name")]
    pub cluster: String,
}

impl WatchTicketRequest {
    pub fn decode(bytes: &[u8]) -> Result<Self, ClusterError> {
        if bytes.is_empty() {
            return Ok(Self {
                version: CLUSTER_STATE_PROTOCOL,
                cluster: default_cluster_name(),
            });
        }
        if bytes.len() > 4096 {
            return Err(ClusterError::because(
                Errno::EFBIG,
                "watch ticket request too large",
            ));
        }
        #[derive(Deserialize)]
        struct Envelope {
            version: u32,
        }
        let Envelope { version } = serde_json::from_slice(bytes)
            .map_err(|_| ClusterError::because(Errno::EINVAL, "invalid watch ticket request"))?;
        if version != CLUSTER_STATE_PROTOCOL {
            return Err(ClusterError::because(
                Errno::EPROTONOSUPPORT,
                format!("ClusterState protocol v{CLUSTER_STATE_PROTOCOL} required"),
            ));
        }
        let req: Self = serde_json::from_slice(bytes)
            .map_err(|_| ClusterError::because(Errno::EINVAL, "invalid watch ticket request"))?;
        if !valid_cluster_name(&req.cluster) {
            return Err(ClusterError::because(Errno::EINVAL, "invalid cluster name"));
        }
        Ok(req)
    }
}

/// Single-use ticket issued by `POST /api/cluster/watch-ticket` for browser WebSocket upgrades.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchTicketReply {
    pub ticket: String,
    pub expires_at: u64,
    pub cluster: String,
    pub tenant: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchEventType {
    Put,
    Delete,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchEvent {
    pub event_type: WatchEventType,
    pub revision: u64,
    pub kv: KeyValue,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_kv: Option<KeyValue>,
}

/// Client-to-server WebSocket JSON frame on `/api/cluster/watch`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum WatchClientFrame {
    Hello {
        versions: Vec<u32>,
    },
    Subscribe {
        watch_id: u64,
        key: String,
        #[serde(default)]
        range_end: RangeEnd,
        /// Inclusive start revision (`0` starts live at `current_revision + 1`).
        #[serde(default)]
        from_revision: u64,
        #[serde(default)]
        prev_kv: bool,
    },
    Pull {
        watch_id: u64,
        #[serde(default)]
        limit: Option<u32>,
    },
    Cancel {
        watch_id: u64,
    },
    Ping {
        #[serde(default)]
        seq: u64,
    },
}

/// Server-to-client WebSocket JSON frame on `/api/cluster/watch`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WatchServerFrame {
    Welcome {
        boundary: Boundary,
        version: u32,
        cluster: String,
        tenant: String,
        revision: u64,
        compacted_floor: u64,
    },
    Subscribed {
        watch_id: u64,
        revision: u64,
        compacted_floor: u64,
        start_revision: u64,
    },
    Events {
        watch_id: u64,
        revision: u64,
        compacted_floor: u64,
        events: Vec<WatchEvent>,
        more: bool,
    },
    Compacted {
        watch_id: u64,
        floor: u64,
        revision: u64,
    },
    Canceled {
        watch_id: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    Pong {
        seq: u64,
        revision: u64,
    },
    Error {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        watch_id: Option<u64>,
        error: ClusterError,
    },
}

// ---------------------------------------------------------------------------
// Typed Cluster Records (Contract §2.13 & §2.16: scoped references only —
// zero bulk payload bytes and zero credentials).
// ---------------------------------------------------------------------------

/// Durable node metadata stored at `/t/<tenant>/node-meta/<node_id>` (not lease-bound).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeMetaRecord {
    pub node_id: String,
    pub host_kind: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    pub enrolled_at: u64,
}

impl NodeMetaRecord {
    pub fn validate(&self) -> Result<(), ClusterError> {
        if !valid_cluster_record_id(&self.node_id)
            || !matches!(
                self.host_kind.as_str(),
                "browser" | "os-native" | "container"
            )
        {
            return Err(ClusterError::because(
                Errno::EINVAL,
                "invalid node metadata record",
            ));
        }
        Ok(())
    }
}

/// Ephemeral lease-bound node liveness record stored at `/t/<tenant>/nodes/<node_id>`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeRecord {
    pub node_id: String,
    pub node_generation: u64,
    pub instance_id: String,
    pub lease_id: u64,
    pub status: String,
    pub heartbeat_at: u64,
}

impl NodeRecord {
    pub fn validate(&self) -> Result<(), ClusterError> {
        if !valid_cluster_record_id(&self.node_id)
            || !crate::auth_v2::valid_id(&self.instance_id)
            || self.node_generation == 0
            || self.lease_id == 0
            || !matches!(self.status.as_str(), "ready" | "draining" | "not_ready")
        {
            return Err(ClusterError::because(
                Errno::EINVAL,
                "invalid node liveness record",
            ));
        }
        Ok(())
    }
}

/// Admitted workload specification & state stored at `/t/<tenant>/workloads/<workload_id>`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadRecord {
    pub workload_id: String,
    /// Scoped immutable image reference (e.g. `oci:<repo>@sha256:<hex>`).
    pub image_ref: String,
    /// Optional scoped immutable input snapshot reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_snapshot_ref: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    pub desired_state: String,
    pub current_attempt: u64,
    pub created_at: u64,
}

impl WorkloadRecord {
    pub fn validate(&self) -> Result<(), ClusterError> {
        if !valid_cluster_record_id(&self.workload_id)
            || self.image_ref.is_empty()
            || self.image_ref.len() > 512
            || !matches!(
                self.desired_state.as_str(),
                "pending" | "running" | "succeeded" | "failed" | "canceled"
            )
        {
            return Err(ClusterError::because(
                Errno::EINVAL,
                "invalid workload record",
            ));
        }
        Ok(())
    }
}

/// Fenced execution attempt stored at `/t/<tenant>/attempts/<workload_id>/<attempt_generation>`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptRecord {
    pub workload_id: String,
    pub attempt_generation: u64,
    pub node_id: String,
    pub node_generation: u64,
    pub node_lease_id: u64,
    pub state: String,
    pub claimed_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<u64>,
}

impl AttemptRecord {
    pub fn validate(&self) -> Result<(), ClusterError> {
        if !valid_cluster_record_id(&self.workload_id)
            || !valid_cluster_record_id(&self.node_id)
            || self.attempt_generation == 0
            || self.node_generation == 0
            || self.node_lease_id == 0
            || !matches!(
                self.state.as_str(),
                "claimed" | "running" | "succeeded" | "failed" | "aborted"
            )
        {
            return Err(ClusterError::because(
                Errno::EINVAL,
                "invalid attempt record",
            ));
        }
        Ok(())
    }
}

/// At-most-once terminal result stored at `/t/<tenant>/results/<workload_id>`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultRecord {
    pub workload_id: String,
    pub attempt_generation: u64,
    pub node_id: String,
    pub node_generation: u64,
    pub exit_code: i32,
    /// Scoped immutable output reference (never bulk payload bytes or credentials).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    pub published_at: u64,
}

impl ResultRecord {
    pub fn validate(&self) -> Result<(), ClusterError> {
        if !valid_cluster_record_id(&self.workload_id)
            || !valid_cluster_record_id(&self.node_id)
            || self.attempt_generation == 0
            || self.node_generation == 0
            || self.output_ref.as_ref().is_some_and(|s| s.len() > 512)
            || self.summary.as_ref().is_some_and(|s| s.len() > 1024)
        {
            return Err(ClusterError::because(
                Errno::EINVAL,
                "invalid result record",
            ));
        }
        Ok(())
    }
}

/// Dispatch notice stored at `/t/<tenant>/outbox/<outbox_id>` (Contract §2.13: notice only,
/// zero task bulk data and zero credentials).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboxRecord {
    pub outbox_id: String,
    pub workload_id: String,
    pub attempt_generation: u64,
    pub kind: String,
    pub created_at: u64,
}

impl OutboxRecord {
    pub fn validate(&self) -> Result<(), ClusterError> {
        if !valid_cluster_record_id(&self.outbox_id)
            || !valid_cluster_record_id(&self.workload_id)
            || !matches!(
                self.kind.as_str(),
                "attempt_ready" | "workload_canceled" | "result_published"
            )
        {
            return Err(ClusterError::because(
                Errno::EINVAL,
                "invalid outbox record",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_and_tenant_grammar_is_strict() {
        assert!(valid_tenant_name("u0"));
        assert!(valid_tenant_name("u1000"));
        assert!(!valid_tenant_name("u00"));
        assert!(!valid_tenant_name("u"));
        assert!(!valid_tenant_name("root"));
        assert!(!valid_tenant_name("u-1"));

        assert!(valid_cluster_key("/t/u0/nodes/node-1"));
        assert!(valid_cluster_key("/t/u1000/workloads/job:2@v1.0_a"));
        assert!(!valid_cluster_key("/t/u0/"));
        assert!(!valid_cluster_key("/t/u0/nodes/"));
        assert!(!valid_cluster_key("/t/u0/nodes//a"));
        assert!(!valid_cluster_key("/t/u0/nodes/../secret"));
        assert!(!valid_cluster_key("/t/u0/nodes/./a"));
        assert!(!valid_cluster_key("/t/u0/nodes/bad key"));
        assert!(!valid_cluster_key("/nodes/n1"));

        assert!(valid_cluster_range_key("/t/u0/"));
        assert!(valid_cluster_range_key("/t/u0/nodes/"));
        assert!(valid_cluster_range_key("/t/u0/nodes/n1"));
        assert!(!valid_cluster_range_key("/t/u0//"));
        assert!(!valid_cluster_range_key("/t/u0/nodes//"));
        assert!(!valid_cluster_range_key("/t/u0"));

        assert_eq!(split_tenant_key("/t/u0/nodes/n1"), Some(("u0", "nodes/n1")));
        assert_eq!(split_tenant_key("/t/u0/nodes/"), Some(("u0", "nodes/")));
        assert_eq!(split_tenant_key("/t/u0/"), Some(("u0", "")));
        assert_eq!(split_tenant_key("/t/u0/../x"), None);
    }

    #[test]
    fn prefix_range_end_computes_exact_upper_bound() {
        assert_eq!(prefix_range_end("/t/u0/").as_deref(), Some("/t/u00"));
        assert_eq!(
            prefix_range_end("/t/u0/nodes/").as_deref(),
            Some("/t/u0/nodes0")
        );
        assert_eq!(prefix_range_end("/t/u0/a").as_deref(), Some("/t/u0/b"));
        assert_eq!(prefix_range_end(""), None);
        assert!("/t/u0/nodes/n1" >= "/t/u0/nodes/" && "/t/u0/nodes/n1" < "/t/u0/nodes0");
        assert!(!("/t/u0/nodes-2/n1" >= "/t/u0/nodes/"));
        assert!(!("/t/u0/nodes0/n1" < "/t/u0/nodes0"));
    }

    #[test]
    fn rpc_decode_checks_version_first_and_denies_unknown_fields() {
        let future = br#"{"version":99,"cluster":"default","call":{"op":"brand_new_op"}}"#;
        let err = ClusterRpcRequest::decode(future).unwrap_err();
        assert_eq!(err.errno, Errno::EPROTONOSUPPORT);

        let unknown_outer =
            br#"{"version":1,"cluster":"default","tenant":"u9","call":{"op":"hello","versions":[1]}}"#;
        assert_eq!(
            ClusterRpcRequest::decode(unknown_outer).unwrap_err().errno,
            Errno::EINVAL
        );

        let unknown_inner =
            br#"{"version":1,"cluster":"default","call":{"op":"hello","versions":[1],"extra":true}}"#;
        assert_eq!(
            ClusterRpcRequest::decode(unknown_inner).unwrap_err().errno,
            Errno::EINVAL
        );

        let valid =
            br#"{"version":1,"call":{"op":"range","key":"/t/u0/nodes/","range_end":"prefix"}}"#;
        let req = ClusterRpcRequest::decode(valid).unwrap();
        assert_eq!(req.version, 1);
        assert_eq!(req.cluster, "default");
        assert!(matches!(
            req.call,
            ClusterCall::Range {
                range_end: RangeEnd::Prefix,
                ..
            }
        ));
    }

    #[test]
    fn typed_records_round_trip_and_deny_unknown_fields() {
        let meta = NodeMetaRecord {
            node_id: "node-1".into(),
            host_kind: "os-native".into(),
            labels: BTreeMap::from([("arch".into(), "wasm32".into())]),
            capabilities: vec!["wasix".into()],
            enrolled_at: 100,
        };
        meta.validate().unwrap();
        let meta_json = serde_json::to_string(&meta).unwrap();
        assert_eq!(
            serde_json::from_str::<NodeMetaRecord>(&meta_json).unwrap(),
            meta
        );
        assert!(
            serde_json::from_str::<NodeMetaRecord>(&meta_json.replace('}', r#","token":"x"}"#))
                .is_err()
        );

        let node = NodeRecord {
            node_id: "node-1".into(),
            node_generation: 1,
            instance_id: "inst-1".into(),
            lease_id: 7,
            status: "ready".into(),
            heartbeat_at: 101,
        };
        node.validate().unwrap();

        let wl = WorkloadRecord {
            workload_id: "wl-1".into(),
            image_ref: "oci:org/app@sha256:00".into(),
            input_snapshot_ref: Some("remote:snapshot:vol1@s1".into()),
            labels: BTreeMap::new(),
            desired_state: "pending".into(),
            current_attempt: 0,
            created_at: 102,
        };
        wl.validate().unwrap();

        let att = AttemptRecord {
            workload_id: "wl-1".into(),
            attempt_generation: 1,
            node_id: "node-1".into(),
            node_generation: 1,
            node_lease_id: 7,
            state: "claimed".into(),
            claimed_at: 103,
            finished_at: None,
        };
        att.validate().unwrap();

        let res = ResultRecord {
            workload_id: "wl-1".into(),
            attempt_generation: 1,
            node_id: "node-1".into(),
            node_generation: 1,
            exit_code: 0,
            output_ref: Some("remote:snapshot:out@r1".into()),
            summary: Some("ok".into()),
            published_at: 104,
        };
        res.validate().unwrap();

        let ob = OutboxRecord {
            outbox_id: "ob-1".into(),
            workload_id: "wl-1".into(),
            attempt_generation: 1,
            kind: "attempt_ready".into(),
            created_at: 102,
        };
        ob.validate().unwrap();
    }
}
