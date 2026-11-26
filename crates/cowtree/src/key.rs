//! Single-map CoW B+tree key schema (`(ino: u64, kind: u8, tail: Vec<u8>)`).

use std::cmp::Ordering;

pub const KIND_INODE_ITEM: u8 = 0x01;
pub const KIND_INODE_REF: u8 = 0x10;
pub const KIND_DIR_ITEM: u8 = 0x20;
pub const KIND_DIR_INDEX: u8 = 0x21;
pub const KIND_EXTENT_DATA: u8 = 0x30;
pub const KIND_XATTR_ITEM: u8 = 0x40;
pub const KIND_ORPHAN_ITEM: u8 = 0x50;
pub const KIND_RAW_BLOCK_META: u8 = 0x60;

/// Fixed synthetic inode key used by raw block-addressable (`ROOT_FEATURE_RAW_BLOCK`) volumes.
pub const RAW_BLOCK_INO: u64 = 1;

/// Canonical ordered key inside a single-map `os-cowtree` B+tree.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TreeKey {
    pub ino: u64,
    pub kind: u8,
    pub tail: Vec<u8>,
}

impl Ord for TreeKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.ino
            .cmp(&other.ino)
            .then_with(|| self.kind.cmp(&other.kind))
            .then_with(|| self.tail.cmp(&other.tail))
    }
}

impl PartialOrd for TreeKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl TreeKey {
    pub fn new(ino: u64, kind: u8, tail: Vec<u8>) -> Self {
        Self { ino, kind, tail }
    }

    pub fn inode_item(ino: u64) -> Self {
        Self::new(ino, KIND_INODE_ITEM, Vec::new())
    }

    pub fn inode_ref(ino: u64, parent_ino: u64, name: &str) -> Self {
        let mut tail = Vec::with_capacity(8 + name.len());
        tail.extend_from_slice(&parent_ino.to_be_bytes());
        tail.extend_from_slice(name.as_bytes());
        Self::new(ino, KIND_INODE_REF, tail)
    }

    pub fn dir_item(dir_ino: u64, name: &str) -> Self {
        Self::new(dir_ino, KIND_DIR_ITEM, name.as_bytes().to_vec())
    }

    pub fn dir_index(dir_ino: u64, dir_index: u64) -> Self {
        Self::new(dir_ino, KIND_DIR_INDEX, dir_index.to_be_bytes().to_vec())
    }

    pub fn extent_data(ino: u64, file_offset: u64) -> Self {
        Self::new(ino, KIND_EXTENT_DATA, file_offset.to_be_bytes().to_vec())
    }

    pub fn xattr_item(ino: u64, attr_name: &str) -> Self {
        Self::new(ino, KIND_XATTR_ITEM, attr_name.as_bytes().to_vec())
    }

    pub fn orphan_item(ino: u64) -> Self {
        Self::new(0, KIND_ORPHAN_ITEM, ino.to_be_bytes().to_vec())
    }

    pub fn raw_block_meta() -> Self {
        Self::new(RAW_BLOCK_INO, KIND_RAW_BLOCK_META, Vec::new())
    }

    /// Raw LBA extent key reusing `KIND_EXTENT_DATA` (`0x30`) so GC, `cowfs send/recv`,
    /// `StorageVolume` DO, and OCI snapshot tooling traverse raw block extents automatically.
    pub fn raw_lba_extent(byte_offset: u64) -> Self {
        Self::extent_data(RAW_BLOCK_INO, byte_offset)
    }

    /// Inclusive lower bound for scanning all items of `(ino, kind)`.
    pub fn kind_start(ino: u64, kind: u8) -> Self {
        Self::new(ino, kind, Vec::new())
    }

    /// Exclusive upper bound for scanning all items of `(ino, kind)`.
    pub fn kind_end(ino: u64, kind: u8) -> Self {
        if let Some(next_kind) = kind.checked_add(1) {
            Self::new(ino, next_kind, Vec::new())
        } else {
            Self::new(ino.saturating_add(1), 0, Vec::new())
        }
    }

    /// Inclusive lower bound for scanning all items of `ino` regardless of `kind`.
    pub fn ino_start(ino: u64) -> Self {
        Self::new(ino, 0, Vec::new())
    }

    /// Exclusive upper bound for scanning all items of `ino` regardless of `kind`.
    pub fn ino_end(ino: u64) -> Self {
        Self::new(ino.saturating_add(1), 0, Vec::new())
    }

    /// Decode the big-endian `u64` offset / index stored in `tail` (`DIR_INDEX`, `EXTENT_DATA`,
    /// `ORPHAN_ITEM`).
    pub fn tail_u64(&self) -> Option<u64> {
        let arr: [u8; 8] = self.tail.as_slice().try_into().ok()?;
        Some(u64::from_be_bytes(arr))
    }

    /// Decode `(parent_ino, name)` from an `INODE_REF` key tail.
    pub fn tail_inode_ref(&self) -> Option<(u64, &str)> {
        if self.tail.len() < 8 {
            return None;
        }
        let parent = u64::from_be_bytes(self.tail[..8].try_into().ok()?);
        let name = std::str::from_utf8(&self.tail[8..]).ok()?;
        Some((parent, name))
    }

    /// Approximate heap footprint in bytes for arena dirty-budget accounting.
    pub fn heap_bytes(&self) -> usize {
        16 + self.tail.len()
    }
}
