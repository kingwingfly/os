//! MIT pure-Rust POSIX Copy-on-Write filesystem (`os-cowfs`, #77) layered over `os-cowtree`
//! single-map Merkle CoW B+trees and pluggable [`HeadStore`] / [`PackStore`] backends.
//!
//! Portable across native hosts and `wasm32-unknown-unknown` with zero DOM, `web-sys`, or
//! `wasm-bindgen` dependencies (`docs/architecture/contract.md` §2.2, §2.5, §2.15, §3, §5).

pub mod fs;
pub mod fsck;
pub mod gc;
pub mod inode;
pub mod ioctl;
#[cfg(not(target_arch = "wasm32"))]
pub mod native_sqlite;
pub mod orphan;

pub use cowtree::store::{
    BlockLoc, CommitRequest, Digest, ForkRequest, GcLockGuard, GcRoot, HeadStore, PackId,
    PackIndexEntry, PackMeta, PackStore, PackTrailer, SnapshotRecord, VolumeHead, VolumeId,
    WriterLease, WriterLockGuard, WriterMode,
};
pub use cowtree::{
    ARENA_CLEAN_DATA_BYTES, ARENA_DIRTY_BYTES, ARENA_TREE_LRU_BYTES, ArenaConfig, ArenaStats,
    BLOCK_SIZE, COWFS_FORMAT_VERSION, COWFS_ROOT_MAGIC, EXTENT_MAX_BLOCKS, EXTENT_MAX_BYTES,
    INLINE_MAX_BYTES, NODE_MAX_BYTES, PACK_MAGIC, PACK_MAX_BYTES, PACK_VERSION, digest_from_hex,
    digest_to_hex, sha256,
};
pub use fs::{CowFs, CowFsClock, CowFsConfig, CowFsOpenMode, DEFAULT_SUBVOL, ROOT_INO};
pub use fsck::{FsckReport, verify_volume, verify_volume_strict};
pub use gc::{GcReport, collect_garbage};
pub use ioctl::{CowFsVolumeDevice, cowfs_ioctl_mounted};
