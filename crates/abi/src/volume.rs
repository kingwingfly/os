//! Wire and ioctl payload types for `os-cowfs` volumes and `/dev/vdN` managed volume devices
//! (`docs/architecture/contract.md` §2.15, §2.16, §5).

use crate::contract::{Durability, WriterModel};
use serde::{Deserialize, Serialize};

/// Payload for `COWFS_IOC_SNAPSHOT`: create an O(1) named snapshot of a mounted `cowfs` volume.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CowfsSnapshotReq {
    pub name: String,
    #[serde(default)]
    pub ro: bool,
}

/// Response for `COWFS_IOC_SNAPSHOT`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CowfsSnapshotResp {
    pub volume: String,
    pub name: String,
    pub root: String,
    pub epoch: u64,
}

/// Payload for `COWFS_IOC_FORK`: create an O(1) persistent volume fork seeded from a snapshot or
/// current committed head.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CowfsForkReq {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<String>,
    pub new_volume: String,
    #[serde(default)]
    pub ephemeral_if_unmodified: bool,
}

/// Response for `COWFS_IOC_FORK`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CowfsForkResp {
    pub volume: String,
    pub parent_volume: String,
    pub root: String,
    pub epoch: u64,
}

/// Response for `COWFS_IOC_INFO`: volume metadata, root digest, epoch, writer model, and
/// durability barrier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CowfsInfoResp {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<String>,
    pub format_version: u32,
    pub volume: String,
    pub root: String,
    pub incarnation: u64,
    pub fence: u64,
    pub epoch: u64,
    pub writer_model: WriterModel,
    pub durability: Durability,
    pub read_only: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_volume: Option<String>,
}

/// Payload for `COWFS_IOC_FSCK`: verify a volume's pinned head, named snapshot, or `.cowpack`
/// archive via full Merkle fsck.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CowfsFsckReq {
    /// Optional explicit volume UUID in the same store (must match if provided).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume: Option<String>,
    /// Optional named snapshot within the volume to verify.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<String>,
    /// If `true`, verify the target regular file fd directly as an `OSCOWA1` `.cowpack` archive.
    #[serde(default)]
    pub archive: bool,
}

/// Response for `COWFS_IOC_FSCK`: authoritative Merkle verification result.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CowfsFsckResp {
    pub ok: bool,
    pub volume: String,
    pub format_version: u32,
    pub epoch: u64,
    pub root: String,
    pub subvols_checked: usize,
    pub nodes_verified: usize,
    pub extents_verified: usize,
    pub packs_verified: usize,
    pub orphan_inodes: usize,
    #[serde(default)]
    pub errors: Vec<String>,
}

/// Payload for `COWFS_IOC_MKFS`: format a managed `/dev/vdN` or `volume:<id>` target (root only).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CowfsMkfsReq {
    #[serde(default)]
    pub force: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Optional explicit volume UUID in the same store (for `mkfs.cowfs volume:<id>`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume: Option<String>,
}

/// Payload for `COWFS_IOC_SUBVOL`: list, create, or delete a subvolume.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum CowfsSubvolReq {
    List {},
    Create { name: String },
    Delete { name: String },
}

/// One subvolume entry returned by `COWFS_IOC_SUBVOL`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CowfsSubvolEntry {
    pub name: String,
    pub root: String,
}

/// Response for `COWFS_IOC_SUBVOL`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CowfsSubvolResp {
    pub volume: String,
    pub subvols: Vec<CowfsSubvolEntry>,
}

/// One named snapshot entry returned by `COWFS_IOC_SNAP_LIST`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CowfsSnapEntry {
    pub name: String,
    pub root: String,
    pub epoch: u64,
    pub created_ms: u64,
}

/// Response for `COWFS_IOC_SNAP_LIST`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CowfsSnapListResp {
    pub volume: String,
    pub snapshots: Vec<CowfsSnapEntry>,
}

/// Payload for `COWFS_IOC_SNAP_DELETE`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CowfsSnapDeleteReq {
    pub name: String,
}

/// Payload for `COWFS_IOC_SEND`: emit an `OSCOWS1` delta stream or `OSCOWA1` archive to `stream_fd`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CowfsSendReq {
    /// Snapshot name (or empty / `"@"` for current committed head).
    pub snapshot: String,
    /// Optional incremental parent snapshot name in the same volume.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// Output writable fd (stdout/pipe/file; translated guest fd -> kfd in `web/wasi/process.js`).
    pub stream_fd: u32,
    /// If `true`, emit a self-verifying read-only `.cowpack` (`OSCOWA1`) archive instead of `OSCOWS1`.
    #[serde(default)]
    pub archive: bool,
}

/// Response for `COWFS_IOC_SEND`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CowfsSendResp {
    pub volume: String,
    pub snapshot: String,
    pub root: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_root: Option<String>,
    pub bytes_written: u64,
    pub nodes_sent: u64,
    pub blocks_sent: u64,
    pub subtrees_skipped: u64,
}

/// Payload for `COWFS_IOC_RECEIVE`: ingest and atomically verify/commit an `OSCOWS1` stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CowfsReceiveReq {
    /// Input readable fd (stdin/pipe/file; translated guest fd -> kfd in `web/wasi/process.js`).
    pub stream_fd: u32,
    /// Optional target snapshot name to create atomically on completion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_name: Option<String>,
    /// Optional new or explicit volume UUID to receive into instead of updating the target device's volume.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_volume: Option<String>,
}

/// Response for `COWFS_IOC_RECEIVE`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CowfsReceiveResp {
    pub volume: String,
    pub root: String,
    pub epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<String>,
    pub nodes_received: u64,
    pub blocks_received: u64,
    pub bytes_read: u64,
}

/// Payload for `COWFS_IOC_GC`: run reachability mark-and-sweep GC.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CowfsGcReq {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grace_window_secs: Option<u64>,
}

/// Response for `COWFS_IOC_GC`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CowfsGcResp {
    pub live_roots: usize,
    pub live_nodes: usize,
    pub live_blocks: usize,
    pub live_packs: usize,
    #[serde(default)]
    pub swept_packs: Vec<String>,
}

/// Response for `LOOP_GET_STATUS64` / `LOOP_SET_FD` on `/dev/loopN`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoopStatus64 {
    pub device: String,
    pub bound: bool,
    pub read_only: bool,
    pub mounted: bool,
    pub backing_dev: u64,
    pub backing_ino: u64,
    pub backing_size: u64,
    pub offset: u64,
    pub sizelimit: u64,
    pub archive_format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_digest: Option<String>,
    pub file_name: String,
}

/// Response for `BLK_INFO` on `/dev/vdN`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlkInfoResp {
    pub device: String,
    pub volume: String,
    pub size: u64,
    pub sector: u32,
    pub writer_model: WriterModel,
    pub durability: Durability,
    pub read_only: bool,
    pub formatted: bool,
}

/// Response for `BLK_LEASE` on `/dev/vdN`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlkLeaseResp {
    pub volume: String,
    pub held: bool,
    #[serde(default)]
    pub fenced: bool,
    #[serde(default)]
    pub expired: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_expires_at: Option<u64>,
    pub incarnation: u64,
    pub fence: u64,
    pub epoch: u64,
    pub read_only: bool,
}

/// Payload for `FICLONERANGE` (`_IOW(0x94, 13, struct file_clone_range)`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileCloneRangeReq {
    pub src_fd: u32,
    pub src_offset: u64,
    pub src_length: u64,
    pub dest_offset: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn volume_ioctl_payloads_deny_unknown_fields() {
        let ok: CowfsSnapshotReq = serde_json::from_str(r#"{"name":"snap1","ro":true}"#).unwrap();
        assert_eq!(ok.name, "snap1");
        assert!(ok.ro);
        assert!(serde_json::from_str::<CowfsSnapshotReq>(r#"{"name":"snap1","extra":1}"#).is_err());
        assert!(
            serde_json::from_str::<CowfsForkReq>(r#"{"new_volume":"v2","bogus":true}"#).is_err()
        );

        let mk: CowfsMkfsReq = serde_json::from_str(r#"{"force":true,"label":"data"}"#).unwrap();
        assert!(mk.force);
        assert_eq!(mk.label.as_deref(), Some("data"));
        assert!(serde_json::from_str::<CowfsMkfsReq>(r#"{"force":true,"unknown":1}"#).is_err());

        let sv: CowfsSubvolReq = serde_json::from_str(r#"{"op":"create","name":"@data"}"#).unwrap();
        assert_eq!(
            sv,
            CowfsSubvolReq::Create {
                name: "@data".into()
            }
        );
        assert!(serde_json::from_str::<CowfsSubvolReq>(r#"{"op":"list","bogus":1}"#).is_err());

        let send: CowfsSendReq =
            serde_json::from_str(r#"{"snapshot":"b","parent":"a","stream_fd":1,"archive":false}"#)
                .unwrap();
        assert_eq!(send.snapshot, "b");
        assert_eq!(send.parent.as_deref(), Some("a"));
        assert_eq!(send.stream_fd, 1);
        assert!(
            serde_json::from_str::<CowfsSendReq>(r#"{"snapshot":"b","stream_fd":1,"x":2}"#)
                .is_err()
        );

        let recv: CowfsReceiveReq =
            serde_json::from_str(r#"{"stream_fd":0,"snapshot_name":"s1"}"#).unwrap();
        assert_eq!(recv.stream_fd, 0);
        assert_eq!(recv.snapshot_name.as_deref(), Some("s1"));
        assert!(
            serde_json::from_str::<CowfsReceiveReq>(r#"{"stream_fd":0,"extra":"no"}"#).is_err()
        );

        let ls = LoopStatus64 {
            device: "loop0".into(),
            bound: true,
            read_only: true,
            mounted: false,
            backing_dev: 1,
            backing_ino: 42,
            backing_size: 4096,
            offset: 0,
            sizelimit: 4096,
            archive_format: "cowpack-v1".into(),
            root_digest: Some("a".repeat(64)),
            file_name: "/tmp/a.cowpack".into(),
        };
        let encoded = serde_json::to_string(&ls).unwrap();
        assert_eq!(serde_json::from_str::<LoopStatus64>(&encoded).unwrap(), ls);
    }
}
