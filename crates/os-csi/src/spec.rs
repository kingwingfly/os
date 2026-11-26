//! CSI v1.9 request/response types, status codes, and async service traits.

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Standard gRPC status codes used by CSI v1.9.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum CsiStatusCode {
    Ok = 0,
    Canceled = 1,
    Unknown = 2,
    InvalidArgument = 3,
    DeadlineExceeded = 4,
    NotFound = 5,
    AlreadyExists = 6,
    PermissionDenied = 7,
    ResourceExhausted = 8,
    FailedPrecondition = 9,
    Aborted = 10,
    OutOfRange = 11,
    Unimplemented = 12,
    Internal = 13,
    Unavailable = 14,
    DataLoss = 15,
    Unauthenticated = 16,
}

impl CsiStatusCode {
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    pub const fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::Ok,
            1 => Self::Canceled,
            2 => Self::Unknown,
            3 => Self::InvalidArgument,
            4 => Self::DeadlineExceeded,
            5 => Self::NotFound,
            6 => Self::AlreadyExists,
            7 => Self::PermissionDenied,
            8 => Self::ResourceExhausted,
            9 => Self::FailedPrecondition,
            10 => Self::Aborted,
            11 => Self::OutOfRange,
            12 => Self::Unimplemented,
            13 => Self::Internal,
            14 => Self::Unavailable,
            15 => Self::DataLoss,
            16 => Self::Unauthenticated,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CsiError {
    pub code: CsiStatusCode,
    pub message: String,
}

impl CsiError {
    pub fn new(code: CsiStatusCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn invalid_argument(msg: impl Into<String>) -> Self {
        Self::new(CsiStatusCode::InvalidArgument, msg)
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::new(CsiStatusCode::NotFound, msg)
    }

    pub fn already_exists(msg: impl Into<String>) -> Self {
        Self::new(CsiStatusCode::AlreadyExists, msg)
    }

    pub fn failed_precondition(msg: impl Into<String>) -> Self {
        Self::new(CsiStatusCode::FailedPrecondition, msg)
    }

    pub fn permission_denied(msg: impl Into<String>) -> Self {
        Self::new(CsiStatusCode::PermissionDenied, msg)
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new(CsiStatusCode::Internal, msg)
    }

    pub fn unimplemented(msg: impl Into<String>) -> Self {
        Self::new(CsiStatusCode::Unimplemented, msg)
    }

    pub fn unavailable(msg: impl Into<String>) -> Self {
        Self::new(CsiStatusCode::Unavailable, msg)
    }

    pub fn resource_exhausted(msg: impl Into<String>) -> Self {
        Self::new(CsiStatusCode::ResourceExhausted, msg)
    }
}

impl fmt::Display for CsiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for CsiError {}

pub type CsiResult<T> = Result<T, CsiError>;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u32)]
pub enum AccessMode {
    #[default]
    Unknown = 0,
    SingleNodeWriter = 1,
    SingleNodeReaderOnly = 2,
    MultiNodeReaderOnly = 3,
    MultiNodeSingleWriter = 4,
    MultiNodeMultiWriter = 5,
    SingleNodeSingleWriter = 6,
    SingleNodeMultiWriter = 7,
}

impl AccessMode {
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    pub const fn from_u32(v: u32) -> Self {
        match v {
            1 => Self::SingleNodeWriter,
            2 => Self::SingleNodeReaderOnly,
            3 => Self::MultiNodeReaderOnly,
            4 => Self::MultiNodeSingleWriter,
            5 => Self::MultiNodeMultiWriter,
            6 => Self::SingleNodeSingleWriter,
            7 => Self::SingleNodeMultiWriter,
            _ => Self::Unknown,
        }
    }

    pub const fn is_read_only(self) -> bool {
        matches!(self, Self::SingleNodeReaderOnly | Self::MultiNodeReaderOnly)
    }

    pub const fn is_multi_node_multi_writer(self) -> bool {
        matches!(self, Self::MultiNodeMultiWriter)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccessType {
    Block,
    Mount {
        fs_type: String,
        mount_flags: Vec<String>,
    },
}

impl Default for AccessType {
    fn default() -> Self {
        Self::Mount {
            fs_type: "cowfs".to_string(),
            mount_flags: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VolumeCapability {
    pub access_type: AccessType,
    pub access_mode: AccessMode,
}

impl VolumeCapability {
    pub fn mount(fs_type: impl Into<String>, access_mode: AccessMode) -> Self {
        Self {
            access_type: AccessType::Mount {
                fs_type: fs_type.into(),
                mount_flags: Vec::new(),
            },
            access_mode,
        }
    }

    pub fn block(access_mode: AccessMode) -> Self {
        Self {
            access_type: AccessType::Block,
            access_mode,
        }
    }

    pub fn is_block(&self) -> bool {
        matches!(self.access_type, AccessType::Block)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CapacityRange {
    pub required_bytes: i64,
    pub limit_bytes: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VolumeContentSource {
    Snapshot { snapshot_id: String },
    Volume { volume_id: String },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Topology {
    pub segments: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timestamp {
    pub seconds: i64,
    pub nanos: i32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Volume {
    pub capacity_bytes: i64,
    pub volume_id: String,
    pub volume_context: BTreeMap<String, String>,
    pub content_source: Option<VolumeContentSource>,
    pub accessible_topology: Vec<Topology>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub size_bytes: i64,
    pub snapshot_id: String,
    pub source_volume_id: String,
    pub creation_time: Option<Timestamp>,
    pub ready_to_use: bool,
}

// ---------------------------------------------------------------------------
// Identity messages
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GetPluginInfoRequest {}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GetPluginInfoResponse {
    pub name: String,
    pub vendor_version: String,
    pub manifest: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PluginServiceCapability {
    Unknown = 0,
    ControllerService = 1,
    VolumeAccessibilityConstraints = 2,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GetPluginCapabilitiesRequest {}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GetPluginCapabilitiesResponse {
    pub service_capabilities: Vec<PluginServiceCapability>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProbeRequest {}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProbeResponse {
    pub ready: Option<bool>,
}

// ---------------------------------------------------------------------------
// Controller messages
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CreateVolumeRequest {
    pub name: String,
    pub capacity_range: Option<CapacityRange>,
    pub volume_capabilities: Vec<VolumeCapability>,
    pub parameters: BTreeMap<String, String>,
    pub secrets: BTreeMap<String, String>,
    pub volume_content_source: Option<VolumeContentSource>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CreateVolumeResponse {
    pub volume: Volume,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeleteVolumeRequest {
    pub volume_id: String,
    pub secrets: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeleteVolumeResponse {}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ControllerPublishVolumeRequest {
    pub volume_id: String,
    pub node_id: String,
    pub volume_capability: Option<VolumeCapability>,
    pub readonly: bool,
    pub secrets: BTreeMap<String, String>,
    pub volume_context: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ControllerPublishVolumeResponse {
    pub publish_context: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ControllerUnpublishVolumeRequest {
    pub volume_id: String,
    pub node_id: String,
    pub secrets: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ControllerUnpublishVolumeResponse {}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ValidateVolumeCapabilitiesRequest {
    pub volume_id: String,
    pub volume_context: BTreeMap<String, String>,
    pub volume_capabilities: Vec<VolumeCapability>,
    pub parameters: BTreeMap<String, String>,
    pub secrets: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ValidateVolumeCapabilitiesConfirmed {
    pub volume_context: BTreeMap<String, String>,
    pub volume_capabilities: Vec<VolumeCapability>,
    pub parameters: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ValidateVolumeCapabilitiesResponse {
    pub confirmed: Option<ValidateVolumeCapabilitiesConfirmed>,
    pub message: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ListVolumesRequest {
    pub max_entries: i32,
    pub starting_token: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ListVolumesEntry {
    pub volume: Volume,
    pub published_node_ids: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ListVolumesResponse {
    pub entries: Vec<ListVolumesEntry>,
    pub next_token: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ControllerRpcCapability {
    Unknown = 0,
    CreateDeleteVolume = 1,
    PublishUnpublishVolume = 2,
    ListVolumes = 3,
    GetCapacity = 4,
    CreateDeleteSnapshot = 5,
    ListSnapshots = 6,
    CloneVolume = 7,
    PublishReadonly = 8,
    SingleNodeMultiWriter = 12,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ControllerGetCapabilitiesRequest {}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ControllerGetCapabilitiesResponse {
    pub capabilities: Vec<ControllerRpcCapability>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CreateSnapshotRequest {
    pub source_volume_id: String,
    pub name: String,
    pub secrets: BTreeMap<String, String>,
    pub parameters: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CreateSnapshotResponse {
    pub snapshot: Snapshot,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeleteSnapshotRequest {
    pub snapshot_id: String,
    pub secrets: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeleteSnapshotResponse {}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ListSnapshotsRequest {
    pub max_entries: i32,
    pub starting_token: String,
    pub source_volume_id: String,
    pub snapshot_id: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ListSnapshotsResponse {
    pub entries: Vec<Snapshot>,
    pub next_token: String,
}

// ---------------------------------------------------------------------------
// Node messages
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeStageVolumeRequest {
    pub volume_id: String,
    pub publish_context: BTreeMap<String, String>,
    pub staging_target_path: String,
    pub volume_capability: Option<VolumeCapability>,
    pub secrets: BTreeMap<String, String>,
    pub volume_context: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeStageVolumeResponse {}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeUnstageVolumeRequest {
    pub volume_id: String,
    pub staging_target_path: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeUnstageVolumeResponse {}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodePublishVolumeRequest {
    pub volume_id: String,
    pub publish_context: BTreeMap<String, String>,
    pub staging_target_path: String,
    pub target_path: String,
    pub volume_capability: Option<VolumeCapability>,
    pub readonly: bool,
    pub secrets: BTreeMap<String, String>,
    pub volume_context: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodePublishVolumeResponse {}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeUnpublishVolumeRequest {
    pub volume_id: String,
    pub target_path: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeUnpublishVolumeResponse {}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeGetVolumeStatsRequest {
    pub volume_id: String,
    pub volume_path: String,
    pub staging_target_path: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u32)]
pub enum VolumeUsageUnit {
    #[default]
    Unknown = 0,
    Bytes = 1,
    Inodes = 2,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VolumeUsage {
    pub available: i64,
    pub total: i64,
    pub used: i64,
    pub unit: VolumeUsageUnit,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeGetVolumeStatsResponse {
    pub usage: Vec<VolumeUsage>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum NodeRpcCapability {
    Unknown = 0,
    StageUnstageVolume = 1,
    GetVolumeStats = 2,
    SingleNodeMultiWriter = 5,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeGetCapabilitiesRequest {}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeGetCapabilitiesResponse {
    pub capabilities: Vec<NodeRpcCapability>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeGetInfoRequest {}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeGetInfoResponse {
    pub node_id: String,
    pub max_volumes_per_node: i64,
    pub accessible_topology: Option<Topology>,
}

// ---------------------------------------------------------------------------
// Async CSI v1.9 service traits
// ---------------------------------------------------------------------------

pub trait CsiIdentity: Send + Sync {
    fn get_plugin_info<'a>(
        &'a self,
        req: GetPluginInfoRequest,
    ) -> BoxFuture<'a, CsiResult<GetPluginInfoResponse>>;

    fn get_plugin_capabilities<'a>(
        &'a self,
        req: GetPluginCapabilitiesRequest,
    ) -> BoxFuture<'a, CsiResult<GetPluginCapabilitiesResponse>>;

    fn probe<'a>(&'a self, req: ProbeRequest) -> BoxFuture<'a, CsiResult<ProbeResponse>>;
}

pub trait CsiController: Send + Sync {
    fn create_volume<'a>(
        &'a self,
        req: CreateVolumeRequest,
    ) -> BoxFuture<'a, CsiResult<CreateVolumeResponse>>;

    fn delete_volume<'a>(
        &'a self,
        req: DeleteVolumeRequest,
    ) -> BoxFuture<'a, CsiResult<DeleteVolumeResponse>>;

    fn controller_publish_volume<'a>(
        &'a self,
        req: ControllerPublishVolumeRequest,
    ) -> BoxFuture<'a, CsiResult<ControllerPublishVolumeResponse>>;

    fn controller_unpublish_volume<'a>(
        &'a self,
        req: ControllerUnpublishVolumeRequest,
    ) -> BoxFuture<'a, CsiResult<ControllerUnpublishVolumeResponse>>;

    fn validate_volume_capabilities<'a>(
        &'a self,
        req: ValidateVolumeCapabilitiesRequest,
    ) -> BoxFuture<'a, CsiResult<ValidateVolumeCapabilitiesResponse>>;

    fn list_volumes<'a>(
        &'a self,
        req: ListVolumesRequest,
    ) -> BoxFuture<'a, CsiResult<ListVolumesResponse>>;

    fn controller_get_capabilities<'a>(
        &'a self,
        req: ControllerGetCapabilitiesRequest,
    ) -> BoxFuture<'a, CsiResult<ControllerGetCapabilitiesResponse>>;

    fn create_snapshot<'a>(
        &'a self,
        req: CreateSnapshotRequest,
    ) -> BoxFuture<'a, CsiResult<CreateSnapshotResponse>>;

    fn delete_snapshot<'a>(
        &'a self,
        req: DeleteSnapshotRequest,
    ) -> BoxFuture<'a, CsiResult<DeleteSnapshotResponse>>;

    fn list_snapshots<'a>(
        &'a self,
        req: ListSnapshotsRequest,
    ) -> BoxFuture<'a, CsiResult<ListSnapshotsResponse>>;
}

pub trait CsiNode: Send + Sync {
    fn node_stage_volume<'a>(
        &'a self,
        req: NodeStageVolumeRequest,
    ) -> BoxFuture<'a, CsiResult<NodeStageVolumeResponse>>;

    fn node_unstage_volume<'a>(
        &'a self,
        req: NodeUnstageVolumeRequest,
    ) -> BoxFuture<'a, CsiResult<NodeUnstageVolumeResponse>>;

    fn node_publish_volume<'a>(
        &'a self,
        req: NodePublishVolumeRequest,
    ) -> BoxFuture<'a, CsiResult<NodePublishVolumeResponse>>;

    fn node_unpublish_volume<'a>(
        &'a self,
        req: NodeUnpublishVolumeRequest,
    ) -> BoxFuture<'a, CsiResult<NodeUnpublishVolumeResponse>>;

    fn node_get_volume_stats<'a>(
        &'a self,
        req: NodeGetVolumeStatsRequest,
    ) -> BoxFuture<'a, CsiResult<NodeGetVolumeStatsResponse>>;

    fn node_get_capabilities<'a>(
        &'a self,
        req: NodeGetCapabilitiesRequest,
    ) -> BoxFuture<'a, CsiResult<NodeGetCapabilitiesResponse>>;

    fn node_get_info<'a>(
        &'a self,
        req: NodeGetInfoRequest,
    ) -> BoxFuture<'a, CsiResult<NodeGetInfoResponse>>;
}
