//! MIT pure-Rust POSIX Copy-on-Write filesystem (`os-cowfs`, #77) layered over `os-cowtree`
//! single-map Merkle CoW B+trees and pluggable [`HeadStore`] / [`PackStore`] backends.
//!
//! Portable across native hosts and `wasm32-unknown-unknown` with zero DOM, `web-sys`, or
//! `wasm-bindgen` dependencies (`docs/architecture/contract.md` §2.2, §2.5, §2.15, §3, §5).

pub mod archive_pack;
pub mod fs;
pub mod fsck;
pub mod gc;
pub mod inode;
pub mod ioctl;
#[cfg(not(target_arch = "wasm32"))]
pub mod native_sqlite;
pub mod oci_client;
pub mod oci_snapshot;
pub mod oci_tar;
pub mod orphan;
pub mod raw_lba;
pub mod remote;
pub use remote::{
    RemoteHeadStore, RemoteHttpReply, RemotePackStore, RemoteVolumeBackend, RemoteVolumeStore,
    RemoteVolumeTransport,
};
pub mod send_recv;

pub use archive_pack::{
    ArchiveHeadStore, ArchivePackStore, FileRefArchiveReader, SliceArchiveReader,
    export_archive_pack, open_archive_cowfs,
};
pub use cowtree::store::{
    BlockLoc, CommitRequest, Digest, ForkRequest, GcLockGuard, GcRoot, HeadStore, PackId,
    PackIndexEntry, PackMeta, PackStore, PackTrailer, ReceiveCommitRequest, RoPinGuard,
    SnapshotRecord, VolumeHead, VolumeId, WriterLease, WriterLockGuard, WriterMode,
};
pub use cowtree::{
    ARENA_CLEAN_DATA_BYTES, ARENA_DIRTY_BYTES, ARENA_TREE_LRU_BYTES, ArenaConfig, ArenaStats,
    BLOCK_SIZE, COWFS_FORMAT_VERSION, COWFS_ROOT_MAGIC, EXTENT_MAX_BLOCKS, EXTENT_MAX_BYTES,
    INLINE_MAX_BYTES, KEY_TAIL_MAX_BYTES, KIND_RAW_BLOCK_META, NODE_MAX_BYTES, PACK_MAGIC,
    PACK_MAX_BYTES, PACK_VERSION, RAW_BLOCK_INO, ROOT_FEATURE_ACCOUNTING, ROOT_FEATURE_RAW_BLOCK,
    RawVolumeMeta, digest_from_hex, digest_to_hex, sha256,
};
pub use fs::{
    CowFs, CowFsClock, CowFsConfig, CowFsOpenMode, DEFAULT_SUBVOL, DIRTY_COMMIT_DEADLINE_SECS,
    ROOT_INO,
};
pub use fsck::{
    FsckReport, verify_archive_file, verify_root_reachable, verify_snapshot, verify_volume,
    verify_volume_strict,
};
pub use gc::{GcReport, collect_garbage, collect_garbage_with_grace};
pub use ioctl::{CowFsVolumeDevice, cowfs_ioctl_mounted};
pub use oci_client::{
    BearerChallenge, OciClient, OciHttpReply, OciTransport, attach_ed25519_signature,
    mirror_oci_artifact, parse_www_authenticate, verify_ed25519_referrers,
};
pub use oci_snapshot::{
    BLOCKDIR_MAGIC, NODEPACK_MAGIC, OciPushOptions, OciSnapshotHeadStore, OciSnapshotPackStore,
    decode_blockdir, decode_nodepack, encode_blockdirs, encode_nodepacks, open_oci_snapshot_cowfs,
    pull_cowfs_snapshot, push_cowfs_snapshot,
};
pub use oci_tar::{
    OciExportedLayer, OciImportReport, OciTarExportOptions, OciTarImportOptions, OciTarLayerInput,
    SetuidPolicy, SymlinkPolicy, build_oci_image_config, build_oci_image_manifest,
    export_and_push_oci_image, export_cowfs_oci_tar_layer, import_oci_tar_layers,
    import_oci_tar_layers_into_cowfs,
};
pub use raw_lba::{
    FenceValidator, RawBlockConfig, RawBlockFencingState, RawBlockInfo, RawBlockOpenMode,
    RawBlockVolume, RawBlockVolumeDevice,
};
pub use send_recv::{
    FileRefSink, FileRefSource, ReceiveTarget, SliceSource, StreamSink, StreamSource, VecSink,
    receive_snapshot, send_snapshot,
};
