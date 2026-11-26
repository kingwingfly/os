//! Linux CSI v1.9 Controller & Node plugins (`os-csi`, Phase 9.5 #85):
//! - Spec-compliant `csi.v1.{Identity,Controller,Node}` Protobuf v3 wire codecs + gRPC-h2c over `AF_UNIX`
//! - `ClusterState`-backed atomic fenced leases (`SINGLE_NODE_WRITER`, concurrent RO, refusing `MULTI_NODE_MULTI_WRITER`)
//! - Pure-Rust Linux `/dev/fuse` ABI v7.31 daemon + host-subvol projection for `cowfs` volumes
//! - Per-volume `os-nbd` `0600` Unix socket export for raw block volumes (`ROOT_FEATURE_RAW_BLOCK`).

pub mod controller;
pub mod fencing;
pub mod fuse_cowfs;
pub mod grpc_unix;
pub mod node;
pub mod proto;
pub mod spec;

pub const CSI_DRIVER_NAME: &str = "cowfs.csi.os.dev";
pub const CSI_DRIVER_VERSION: &str = "0.1.0";

pub use controller::{CsiControllerConfig, OsCsiController};
pub use fencing::{
    CsiSnapshotRecord, CsiVolumeKind, CsiVolumeRecord, VolumeAttachmentRecord, VolumeFenceCounter,
    acquire_volume_publish_lease, release_volume_publish_lease, verify_volume_fence,
};
pub use fuse_cowfs::{FUSE_KERNEL_MINOR_VERSION, FUSE_KERNEL_VERSION, FuseCowFsSession};
pub use grpc_unix::{CsiGrpcClient, CsiGrpcServerHandle, CsiServiceRouter};
pub use node::{
    CsiNodeConfig, FenceStateFile, OsCsiNode, PublishedVolumeDescriptor, StageMode,
    check_fence_state_file, write_fence_state_file,
};
pub use spec::{
    AccessMode, AccessType, CapacityRange, CsiController, CsiError, CsiIdentity, CsiNode,
    CsiResult, CsiStatusCode, Volume, VolumeCapability, VolumeContentSource,
};
