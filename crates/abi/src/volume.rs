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
    }
}
