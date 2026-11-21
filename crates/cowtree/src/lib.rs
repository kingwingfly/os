//! MIT pure-Rust single-map Merkle Copy-on-Write B+tree storage engine (`os-cowtree`, #77).
//!
//! Portable across native hosts and `wasm32-unknown-unknown` with zero DOM, `web-sys`, or
//! `wasm-bindgen` types (`docs/architecture/contract.md` §2.2, §2.15).

pub mod arena;
pub mod btree;
pub mod key;
#[cfg(any(test, feature = "test-store"))]
pub mod memory;
pub mod node;
pub mod pack;
pub mod store;

use abi::Errno;
use sha2::{Digest as _, Sha256};

pub use arena::{Arena, ArenaConfig, ArenaStats};
pub use btree::{CowTree, TreeOverlay};
pub use key::{
    KIND_DIR_INDEX, KIND_DIR_ITEM, KIND_EXTENT_DATA, KIND_INODE_ITEM, KIND_INODE_REF,
    KIND_ORPHAN_ITEM, KIND_XATTR_ITEM, TreeKey,
};
pub use node::{
    InternalEntry, KEY_TAIL_MAX_BYTES, LeafEntry, Node, ROOT_FEATURE_ACCOUNTING, RootObject,
};
pub use pack::{PackBuilder, decode_pack_trailer, encode_pack, verify_block_digest};
pub use store::{
    BlockLoc, CommitRequest, Digest, ForkRequest, GcLockGuard, GcRoot, HeadStore, PackId,
    PackIndexEntry, PackMeta, PackStore, PackTrailer, RoPinGuard, SnapshotRecord, VolumeHead,
    VolumeId, WriterLease, WriterLockGuard, WriterMode,
};

/// On-disk / IndexedDB format version (`contract.md` §2.15, §6).
pub const COWFS_FORMAT_VERSION: u32 = abi::contract::COWFS_FORMAT_VERSION;
/// Root object magic (`OSCOWFS1`, `contract.md` §2.15).
pub const COWFS_ROOT_MAGIC: [u8; 8] = *b"OSCOWFS1";
/// Maximum serialized CoW B+tree node size (`16 KiB`).
pub const NODE_MAX_BYTES: usize = 16 * 1024;
/// Fixed aligned logical data block size (`64 KiB`).
pub const BLOCK_SIZE: u32 = 64 * 1024;
/// Maximum contiguous blocks covered by one `EXTENT_DATA` item (`<= 1 MiB`).
pub const EXTENT_MAX_BLOCKS: u32 = 16;
/// Maximum logical extent length (`1 MiB`).
pub const EXTENT_MAX_BYTES: u32 = BLOCK_SIZE * EXTENT_MAX_BLOCKS;
/// Maximum inline regular-file data stored directly inside a B+tree leaf (`2 KiB`).
pub const INLINE_MAX_BYTES: usize = 2 * 1024;
/// Maximum immutable pack file size (`8 MiB`).
pub const PACK_MAX_BYTES: usize = 8 * 1024 * 1024;
/// Pack trailer & footer magic (`COWP`).
pub const PACK_MAGIC: [u8; 4] = *b"COWP";
/// Pack trailer format version.
pub const PACK_VERSION: u16 = 1;

// Fixed wasm32 slab arena budgets (32 MiB total; R7, #77).
pub const ARENA_TREE_LRU_BYTES: usize = 8 * 1024 * 1024;
pub const ARENA_CLEAN_DATA_BYTES: usize = 16 * 1024 * 1024;
pub const ARENA_DIRTY_BYTES: usize = 8 * 1024 * 1024;

/// Compute SHA-256 content address over raw bytes.
pub fn sha256(bytes: &[u8]) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out);
    digest
}

/// Format a 32-byte digest as 64 lowercase hex characters.
pub fn digest_to_hex(digest: &Digest) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &b in digest {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Parse a 64-char lowercase hex string into a 32-byte digest.
pub fn digest_from_hex(hex: &str) -> vfs::Result<Digest> {
    if hex.len() != 64 || !hex.is_ascii() {
        return Err(Errno::EINVAL);
    }
    let bytes = hex.as_bytes();
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = hex_nibble(bytes[i * 2]).ok_or(Errno::EINVAL)?;
        let lo = hex_nibble(bytes[i * 2 + 1]).ok_or(Errno::EINVAL)?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}
