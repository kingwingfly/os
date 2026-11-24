//! Boundary::Volume v1. The local stores use these same content addresses and head records.
use crate::{Errno, fs::Timespec, volume::CowfsGcResp};
use serde::{Deserialize, Serialize};

pub const REMOTE_VOLUME_PROTOCOL: u32 = crate::contract::VOLUME_VERSION;
pub const WRITER_LEASE_TTL_SECS: u64 = 60;
pub const WRITER_RENEW_INTERVAL_SECS: u64 = 20;
pub const WRITER_SELF_FENCE_MARGIN_SECS: u64 = 10;
pub const RO_PIN_TTL_SECS: u64 = 120;
pub const STAGING_PIN_TTL_SECS: u64 = 300;
pub const GC_GRACE_WINDOW_SECS: u64 = 600;
pub const PACK_MAX_BYTES: usize = 8 * 1024 * 1024;
pub const NODE_MAX_BYTES: usize = 16 * 1024;
pub const CONTROL_BODY_MAX: usize = 8 * 1024 * 1024;

/// Lowercase 32-byte SHA-256 content address for CoW B+tree nodes and 64 KiB data blocks/extents.
pub type Digest = [u8; 32];

/// Explicit remote target for the existing managed-device MKFS ioctl.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteDeviceFormat {
    pub remote: crate::volume::CowfsMkfsReq,
}

/// Stable volume UUID (`os-vol:<uuid>`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct VolumeId(pub String);

/// Content-addressed immutable pack identifier (64-char lowercase SHA-256 hex of pack bytes).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PackId(pub String);

fn timestamp<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Timespec, D::Error> {
    let time = Timespec::deserialize(deserializer)?;
    if time.nsec >= 1_000_000_000 {
        return Err(serde::de::Error::custom("invalid timestamp nanoseconds"));
    }
    Ok(time)
}

/// Committed volume head. Uses `(incarnation, fence, epoch)` for both local Web Lock/flock
/// fencing (`fence = local_fence`) and remote R2+DO triple-fencing (#80) with zero conversion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeHead {
    pub format_version: u32,
    pub volume: VolumeId,
    /// Rotated on restore/re-seed; never decremented.
    pub incarnation: u64,
    /// Monotonic writer grant counter (`local_fence` locally; DO grant fence remotely).
    pub fence: u64,
    /// Monotonic commit counter; CAS requires `epoch == expected_epoch` -> `epoch + 1`.
    pub epoch: u64,
    /// SHA-256 root digest of the single-map CoW B+tree (`[0; 32]` forbidden after mkfs).
    pub root: Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_volume: Option<VolumeId>,
    /// True for concurrent-tab auto-forks: pruned on clean shutdown if `modified == false`.
    #[serde(default)]
    pub ephemeral_if_unmodified: bool,
    #[serde(default)]
    pub modified: bool,
    #[serde(deserialize_with = "timestamp")]
    pub updated_at: Timespec,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WriterMode {
    /// Fail with `Errno::EBUSY` if another writer holds `os-vol:<uuid>` / `flock`.
    Exclusive,
    /// If held by another tab/host, atomically fork the last committed head (`O(1)`).
    ForkOnBusy,
    /// Increment `fence` to take over writer rights, fencing the prior holder with `ESTALE`.
    ForceTakeover,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockLoc {
    pub pack_id: PackId,
    pub offset: u32,
    /// Stored byte length in the pack.
    pub len: u32,
    /// Uncompressed logical byte length (`<= 1 MiB`).
    pub raw_len: u32,
    /// Bit 0 = zstd/lz4 reserved (0 = raw in v1).
    pub flags: u16,
}

impl BlockLoc {
    pub fn validate_v1(&self) -> Result<(), Errno> {
        if self.flags != 0
            || self.len == 0
            || self.raw_len != self.len
            || self.len > (1024 * 1024)
            || u64::from(self.offset) + u64::from(self.len) > PACK_MAX_BYTES as u64
        {
            return Err(Errno::EIO);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackMeta {
    pub pack_id: PackId,
    pub size: u32,
    pub entry_count: u32,
    #[serde(deserialize_with = "timestamp")]
    pub created_at: Timespec,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackIndexEntry {
    pub digest: Digest,
    pub offset: u32,
    pub len: u32,
    pub raw_len: u32,
    pub flags: u16,
}

/// Self-describing trailer at the end of every immutable `<= 8 MiB` pack file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackTrailer {
    pub magic: [u8; 4],
    pub version: u16,
    pub entries: Vec<PackIndexEntry>,
    pub trailer_sha256: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitRequest {
    /// Idempotency key (`receipts[op_id]` prevents duplicate apply on retry).
    pub op_id: [u8; 16],
    pub volume: VolumeId,
    pub expected_incarnation: u64,
    pub expected_fence: u64,
    pub expected_epoch: u64,
    pub new_root: Digest,
    /// New immutable `<= 16 KiB` CoW B+tree nodes written in the same atomic transaction.
    pub put_nodes: Vec<(Digest, Vec<u8>)>,
    /// Pack metadata for packs already flushed + closed in `PackStore`.
    pub put_packs: Vec<PackMeta>,
    /// Block digest -> `BlockLoc` index entries for blocks in `put_packs`.
    pub put_blocks: Vec<(Digest, BlockLoc)>,
    #[serde(deserialize_with = "timestamp")]
    pub committed_at: Timespec,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotRecord {
    pub volume: VolumeId,
    pub name: String,
    pub root: Digest,
    pub epoch: u64,
    #[serde(deserialize_with = "timestamp")]
    pub created_at: Timespec,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForkRequest {
    pub source_volume: VolumeId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_snapshot: Option<String>,
    pub source_root: Digest,
    pub new_volume: VolumeId,
    pub ephemeral_if_unmodified: bool,
    #[serde(deserialize_with = "timestamp")]
    pub created_at: Timespec,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fence {
    pub incarnation: u64,
    pub fence: u64,
}
impl From<&VolumeHead> for Fence {
    fn from(head: &VolumeHead) -> Self {
        Self {
            incarnation: head.incarnation,
            fence: head.fence,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u32,
    pub volume: VolumeId,
    pub call: Operation,
}

impl Request {
    pub fn decode(bytes: &[u8]) -> Result<Self, Errno> {
        #[derive(Deserialize)]
        struct Envelope {
            version: u32,
        }
        // Parse the original bytes twice to preserve duplicate-field checks inside v1 calls.
        let Envelope { version, .. } = serde_json::from_slice(bytes).map_err(|_| Errno::EINVAL)?;
        if version != REMOTE_VOLUME_PROTOCOL {
            return Err(Errno::EPROTONOSUPPORT);
        }
        serde_json::from_slice(bytes).map_err(|_| Errno::EINVAL)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Hello {
        versions: Vec<u32>,
    },
    FormatVersion {},
    BeginReceive {},
    CreateVolume {
        head: VolumeHead,
        nodes: Vec<(Digest, Vec<u8>)>,
    },
    ReadHead {},
    ListVolumes {},
    AttachRw {
        mode: WriterMode,
    },
    Renew {
        lease: Fence,
    },
    DetachRw {
        lease: Fence,
    },
    PinRo {
        snapshot: Option<String>,
        root: Option<Digest>,
    },
    RenewRo {
        pin_id: String,
    },
    UnpinRo {
        pin_id: String,
    },
    GetNode {
        digest: Digest,
    },
    LookupBlock {
        digest: Digest,
    },
    Commit {
        request: CommitRequest,
    },
    StageObjects {
        lease: Fence,
        nodes: Vec<(Digest, Vec<u8>)>,
        packs: Vec<PackMeta>,
        blocks: Vec<(Digest, BlockLoc)>,
    },
    Receive {
        request: CommitRequest,
        snapshot: Option<String>,
    },
    Status {
        op_id: [u8; 16],
        /// With no receipt, a dead fence proves the operation can no longer publish.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        lease: Option<Fence>,
    },
    CreateSnapshot {
        name: String,
        head: VolumeHead,
    },
    GetSnapshot {
        name: String,
    },
    ListSnapshots {},
    DeleteSnapshot {
        name: String,
        head: VolumeHead,
    },
    Fork {
        request: ForkRequest,
    },
    CheckNoReaders {},
    DeleteVolume {
        expected: Option<VolumeHead>,
        only_unmodified: bool,
    },
    ReformatVolume {
        expected: VolumeHead,
        head: VolumeHead,
        nodes: Vec<(Digest, Vec<u8>)>,
    },
    RotateIncarnation {},
    ListPacks {},
    RunGc {},
}

impl Operation {
    pub fn writes(&self) -> bool {
        !matches!(
            self,
            Self::Hello { .. }
                | Self::FormatVersion {}
                | Self::ReadHead {}
                | Self::ListVolumes {}
                | Self::PinRo { .. }
                | Self::RenewRo { .. }
                | Self::UnpinRo { .. }
                | Self::GetNode { .. }
                | Self::LookupBlock { .. }
                | Self::Status { .. }
                | Self::GetSnapshot { .. }
                | Self::ListSnapshots {}
                | Self::CheckNoReaders {}
                | Self::ListPacks {}
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub op_id: [u8; 16],
    pub payload_hash: Digest,
    pub head: VolumeHead,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Status {
    Pending,
    Committed(Receipt),
    Aborted { errno: Errno },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    Done,
    Version {
        version: u32,
        tenant: String,
    },
    Head(VolumeHead),
    Heads(Vec<VolumeHead>),
    Attached {
        head: VolumeHead,
        forked_from: Option<VolumeId>,
        expires: u64,
    },
    Pinned {
        expires: u64,
        head: VolumeHead,
        pin_id: String,
    },
    Renewed {
        expires: u64,
    },
    Node(Vec<u8>),
    Block(Option<BlockLoc>),
    Receipt(Receipt),
    Status(Status),
    Snapshot(SnapshotRecord),
    Snapshots(Vec<SnapshotRecord>),
    Packs(Vec<PackId>),
    Deleted(bool),
    Gc(CowfsGcResp),
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeError {
    pub errno: Errno,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wire_timestamp_requires_normalized_nanoseconds() {
        for (nsec, valid) in [
            (999_999_999, true),
            (1_000_000_000, false),
            (u32::MAX, false),
        ] {
            let op = Operation::Fork {
                request: ForkRequest {
                    source_volume: VolumeId("src".into()),
                    source_snapshot: None,
                    source_root: [7; 32],
                    new_volume: VolumeId("dst".into()),
                    ephemeral_if_unmodified: false,
                    created_at: Timespec { sec: 3, nsec },
                },
            };
            let raw = serde_json::to_vec(&Request {
                version: 1,
                volume: VolumeId("src".into()),
                call: op,
            })
            .unwrap();
            assert_eq!(
                Request::decode(&raw).map(|_| ()),
                if valid { Ok(()) } else { Err(Errno::EINVAL) }
            );
        }
    }
    #[test]
    fn wire_version_and_strict_fields() {
        assert_eq!(REMOTE_VOLUME_PROTOCOL, 1);
        let raw = r#"{"version":1,"volume":"data","call":{"op":"renew","lease":{"incarnation":2,"fence":3}}}"#;
        let req: Request = serde_json::from_str(raw).unwrap();
        assert_eq!(serde_json::to_string(&req).unwrap(), raw);
        assert!(
            serde_json::from_str::<Request>(
                &raw.replace("\"fence\":3", "\"fence\":3,\"admin\":true")
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<Request>(
                &raw.replace("\"version\":1", "\"version\":1,\"tenant\":0")
            )
            .is_err()
        );
    }
}
