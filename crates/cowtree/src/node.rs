//! Deterministic binary encoding and SHA-256 verification for `<= 16 KiB` CoW B+tree nodes and
//! `OSCOWFS1` volume root objects.

use crate::key::TreeKey;
use crate::store::Digest;
use crate::{COWFS_FORMAT_VERSION, COWFS_ROOT_MAGIC, NODE_MAX_BYTES, sha256};
use crate::{EXTENT_MAX_BYTES, INLINE_MAX_BYTES};
use abi::Errno;
use std::collections::BTreeMap;
use vfs::Result;

pub const NODE_MAGIC: [u8; 4] = *b"COWN";
pub const NODE_VERSION: u16 = 1;
pub const NODE_HEADER_BYTES: usize = 12;
/// Maximum key tail length (bytes). Guarantees >= 3 internal separators always fit in one
/// `NODE_MAX_BYTES` (16 KiB) internal node so B+tree root-split passes strictly shrink.
pub const KEY_TAIL_MAX_BYTES: usize = 4096;
/// `RootObject::features` flag indicating trailing `(allocated_bytes, inode_count)` accounting.
pub const ROOT_FEATURE_ACCOUNTING: u64 = 1 << 0;
/// `RootObject::features` flag indicating a raw LBA block-addressable volume (`RawVolumeMeta` +
/// `KIND_EXTENT_DATA` under `RAW_BLOCK_INO`), incompatible with POSIX `CowFs::open`.
pub const ROOT_FEATURE_RAW_BLOCK: u64 = 1 << 1;

pub const RAW_VOLUME_META_VERSION: u8 = 1;
pub const RAW_VOLUME_MIN_BLOCK_SIZE: u32 = 512;
pub const RAW_VOLUME_MAX_BLOCK_SIZE: u32 = 65_536;
/// Maximum raw volume logical size (`16 TiB`).
pub const RAW_VOLUME_MAX_SIZE_BYTES: u64 = 16 * 1024 * 1024 * 1024 * 1024;
pub const RAW_VOLUME_META_BYTES: usize = 41;

/// One sorted item inside a B+tree leaf node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafEntry {
    pub key: TreeKey,
    pub value: Vec<u8>,
}

/// One sorted child pointer inside a B+tree internal node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InternalEntry {
    pub key: TreeKey,
    pub child: Digest,
}

/// A decoded CoW B+tree node (`<= 16 KiB` serialized).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node {
    Leaf {
        entries: Vec<LeafEntry>,
    },
    Internal {
        level: u8,
        entries: Vec<InternalEntry>,
    },
}

impl Node {
    pub fn empty_leaf() -> Self {
        Self::Leaf {
            entries: Vec::new(),
        }
    }

    pub fn level(&self) -> u8 {
        match self {
            Node::Leaf { .. } => 0,
            Node::Internal { level, .. } => *level,
        }
    }

    pub fn leaf_entry_encoded_size(key: &TreeKey, val_len: usize) -> usize {
        8 + 1 + 2 + key.tail.len() + 4 + val_len
    }

    pub fn internal_entry_encoded_size(key: &TreeKey) -> usize {
        8 + 1 + 2 + key.tail.len() + 32
    }

    pub fn encoded_size(&self) -> usize {
        match self {
            Node::Leaf { entries } => {
                NODE_HEADER_BYTES
                    + entries
                        .iter()
                        .map(|e| Self::leaf_entry_encoded_size(&e.key, e.value.len()))
                        .sum::<usize>()
            }
            Node::Internal { entries, .. } => {
                NODE_HEADER_BYTES
                    + entries
                        .iter()
                        .map(|e| Self::internal_entry_encoded_size(&e.key))
                        .sum::<usize>()
            }
        }
    }

    /// Approximate retained heap footprint of the decoded `Node` (struct + `Vec` capacities +
    /// per-entry `tail`/`value` allocations) for accurate `Arena` LRU eviction accounting.
    pub fn heap_bytes(&self) -> usize {
        let base = std::mem::size_of::<Node>();
        match self {
            Node::Leaf { entries } => {
                let vec_buf = entries
                    .capacity()
                    .saturating_mul(std::mem::size_of::<LeafEntry>());
                let items: usize = entries
                    .iter()
                    .map(|e| e.key.tail.capacity().saturating_add(e.value.capacity()))
                    .sum();
                base.saturating_add(vec_buf).saturating_add(items)
            }
            Node::Internal { entries, .. } => {
                let vec_buf = entries
                    .capacity()
                    .saturating_mul(std::mem::size_of::<InternalEntry>());
                let items: usize = entries.iter().map(|e| e.key.tail.capacity()).sum();
                base.saturating_add(vec_buf).saturating_add(items)
            }
        }
    }

    /// Encode node deterministically, enforcing `encoded.len() <= NODE_MAX_BYTES`.
    pub fn encode(&self) -> Result<(Digest, Vec<u8>)> {
        let size = self.encoded_size();
        if size > NODE_MAX_BYTES {
            return Err(Errno::EIO);
        }
        let mut buf = Vec::with_capacity(size);
        buf.extend_from_slice(&NODE_MAGIC);
        buf.extend_from_slice(&NODE_VERSION.to_be_bytes());
        match self {
            Node::Leaf { entries } => {
                buf.push(0); // level 0
                buf.push(0); // flags
                let count = u32::try_from(entries.len()).map_err(|_| Errno::EIO)?;
                buf.extend_from_slice(&count.to_be_bytes());
                for entry in entries {
                    if entry.key.tail.len() > KEY_TAIL_MAX_BYTES {
                        return Err(Errno::E2BIG);
                    }
                    let tail_len = u16::try_from(entry.key.tail.len()).map_err(|_| Errno::EIO)?;
                    let val_len = u32::try_from(entry.value.len()).map_err(|_| Errno::EIO)?;
                    buf.extend_from_slice(&entry.key.ino.to_be_bytes());
                    buf.push(entry.key.kind);
                    buf.extend_from_slice(&tail_len.to_be_bytes());
                    buf.extend_from_slice(&entry.key.tail);
                    buf.extend_from_slice(&val_len.to_be_bytes());
                    buf.extend_from_slice(&entry.value);
                }
            }
            Node::Internal { level, entries } => {
                if *level == 0 {
                    return Err(Errno::EIO);
                }
                buf.push(*level);
                buf.push(0); // flags
                let count = u32::try_from(entries.len()).map_err(|_| Errno::EIO)?;
                buf.extend_from_slice(&count.to_be_bytes());
                for entry in entries {
                    if entry.key.tail.len() > KEY_TAIL_MAX_BYTES {
                        return Err(Errno::E2BIG);
                    }
                    let tail_len = u16::try_from(entry.key.tail.len()).map_err(|_| Errno::EIO)?;
                    buf.extend_from_slice(&entry.key.ino.to_be_bytes());
                    buf.push(entry.key.kind);
                    buf.extend_from_slice(&tail_len.to_be_bytes());
                    buf.extend_from_slice(&entry.key.tail);
                    buf.extend_from_slice(&entry.child);
                }
            }
        }
        debug_assert_eq!(buf.len(), size);
        let digest = sha256(&buf);
        Ok((digest, buf))
    }

    /// Verify `sha256(bytes) == expected` BEFORE decoding any field (`EIO` on bit-flip).
    pub fn decode_verified(expected: &Digest, bytes: &[u8]) -> Result<Self> {
        if bytes.len() > NODE_MAX_BYTES || bytes.len() < NODE_HEADER_BYTES {
            return Err(Errno::EIO);
        }
        if &sha256(bytes) != expected {
            return Err(Errno::EIO);
        }
        Self::decode_unverified(bytes)
    }

    pub fn decode_unverified(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > NODE_MAX_BYTES || bytes.len() < NODE_HEADER_BYTES {
            return Err(Errno::EIO);
        }
        if bytes[0..4] != NODE_MAGIC {
            return Err(Errno::EIO);
        }
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if version != NODE_VERSION {
            return Err(Errno::EPROTONOSUPPORT);
        }
        let level = bytes[6];
        let _flags = bytes[7];
        let count = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as usize;
        let mut cursor = NODE_HEADER_BYTES;

        if level == 0 {
            let max_possible = (bytes.len() - NODE_HEADER_BYTES) / 15;
            if count > max_possible {
                return Err(Errno::EIO);
            }
            let mut entries = Vec::with_capacity(count);
            let mut prev: Option<&TreeKey> = None;
            for _ in 0..count {
                let key = read_key(bytes, &mut cursor)?;
                let val_len = read_u32(bytes, &mut cursor)? as usize;
                let value = read_slice(bytes, &mut cursor, val_len)?.to_vec();
                if let Some(p) = prev
                    && key <= *p
                {
                    return Err(Errno::EIO);
                }
                entries.push(LeafEntry { key, value });
                prev = entries.last().map(|e| &e.key);
            }
            if cursor != bytes.len() {
                return Err(Errno::EIO);
            }
            Ok(Node::Leaf { entries })
        } else {
            if count == 0 {
                return Err(Errno::EIO);
            }
            let max_possible = (bytes.len() - NODE_HEADER_BYTES) / 43;
            if count > max_possible {
                return Err(Errno::EIO);
            }
            let mut entries = Vec::with_capacity(count);
            let mut prev: Option<&TreeKey> = None;
            for _ in 0..count {
                let key = read_key(bytes, &mut cursor)?;
                let child_slice = read_slice(bytes, &mut cursor, 32)?;
                let mut child = [0u8; 32];
                child.copy_from_slice(child_slice);
                if let Some(p) = prev
                    && key <= *p
                {
                    return Err(Errno::EIO);
                }
                entries.push(InternalEntry { key, child });
                prev = entries.last().map(|e| &e.key);
            }
            if cursor != bytes.len() {
                return Err(Errno::EIO);
            }
            Ok(Node::Internal { level, entries })
        }
    }
}

/// Content-addressed volume root object (`OSCOWFS1`, `contract.md` §2.15) pointed to by
/// `VolumeHead.root` and stored as a `<= 16 KiB` node in `HeadStore`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootObject {
    pub format_version: u32,
    pub features: u64,
    pub volume_uuid: String,
    pub subvols: BTreeMap<String, Digest>,
    pub next_ino: u64,
    pub generation: u64,
    pub parent_root: Option<Digest>,
    pub allocated_bytes: u64,
    pub inode_count: u64,
}

impl RootObject {
    pub fn encode(&self) -> Result<(Digest, Vec<u8>)> {
        let include_accounting = (self.features & ROOT_FEATURE_ACCOUNTING) != 0
            || self.allocated_bytes != 0
            || self.inode_count != 0;
        let features = if include_accounting {
            self.features | ROOT_FEATURE_ACCOUNTING
        } else {
            self.features
        };
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(&COWFS_ROOT_MAGIC);
        buf.extend_from_slice(&self.format_version.to_be_bytes());
        buf.extend_from_slice(&features.to_be_bytes());
        let uuid_bytes = self.volume_uuid.as_bytes();
        let uuid_len = u16::try_from(uuid_bytes.len()).map_err(|_| Errno::EINVAL)?;
        buf.extend_from_slice(&uuid_len.to_be_bytes());
        buf.extend_from_slice(uuid_bytes);
        buf.extend_from_slice(&self.next_ino.to_be_bytes());
        buf.extend_from_slice(&self.generation.to_be_bytes());
        match &self.parent_root {
            Some(parent) => {
                buf.push(1);
                buf.extend_from_slice(parent);
            }
            None => buf.push(0),
        }
        let subvol_count = u32::try_from(self.subvols.len()).map_err(|_| Errno::EINVAL)?;
        buf.extend_from_slice(&subvol_count.to_be_bytes());
        for (name, digest) in &self.subvols {
            let nb = name.as_bytes();
            let nlen = u16::try_from(nb.len()).map_err(|_| Errno::EINVAL)?;
            buf.extend_from_slice(&nlen.to_be_bytes());
            buf.extend_from_slice(nb);
            buf.extend_from_slice(digest);
        }
        if include_accounting {
            buf.extend_from_slice(&self.allocated_bytes.to_be_bytes());
            buf.extend_from_slice(&self.inode_count.to_be_bytes());
        }
        if buf.len() > NODE_MAX_BYTES {
            return Err(Errno::ENOSPC);
        }
        let digest = sha256(&buf);
        Ok((digest, buf))
    }

    /// Verify `sha256(bytes) == expected` BEFORE decoding (`EIO` on bit-flip,
    /// `EPROTONOSUPPORT` on incompatible `format_version`).
    pub fn decode_verified(expected: &Digest, bytes: &[u8]) -> Result<Self> {
        if bytes.len() > NODE_MAX_BYTES || bytes.len() < 8 + 4 + 8 + 2 {
            return Err(Errno::EIO);
        }
        if &sha256(bytes) != expected {
            return Err(Errno::EIO);
        }
        if bytes[0..8] != COWFS_ROOT_MAGIC {
            return Err(Errno::EIO);
        }
        let mut cursor = 8;
        let format_version = read_u32(bytes, &mut cursor)?;
        if format_version != COWFS_FORMAT_VERSION {
            return Err(Errno::EPROTONOSUPPORT);
        }
        let features = read_u64(bytes, &mut cursor)?;
        let uuid_len = read_u16(bytes, &mut cursor)? as usize;
        let uuid_slice = read_slice(bytes, &mut cursor, uuid_len)?;
        let volume_uuid = std::str::from_utf8(uuid_slice)
            .map_err(|_| Errno::EIO)?
            .to_string();
        let next_ino = read_u64(bytes, &mut cursor)?;
        let generation = read_u64(bytes, &mut cursor)?;
        let has_parent = read_u8(bytes, &mut cursor)?;
        let parent_root = match has_parent {
            0 => None,
            1 => {
                let slice = read_slice(bytes, &mut cursor, 32)?;
                let mut d = [0u8; 32];
                d.copy_from_slice(slice);
                Some(d)
            }
            _ => return Err(Errno::EIO),
        };
        let subvol_count = read_u32(bytes, &mut cursor)? as usize;
        let mut subvols = BTreeMap::new();
        for _ in 0..subvol_count {
            let nlen = read_u16(bytes, &mut cursor)? as usize;
            let name = std::str::from_utf8(read_slice(bytes, &mut cursor, nlen)?)
                .map_err(|_| Errno::EIO)?
                .to_string();
            let dslice = read_slice(bytes, &mut cursor, 32)?;
            let mut d = [0u8; 32];
            d.copy_from_slice(dslice);
            if subvols.insert(name, d).is_some() {
                return Err(Errno::EIO);
            }
        }
        let (allocated_bytes, inode_count) = if (features & ROOT_FEATURE_ACCOUNTING) != 0 {
            let alloc = read_u64(bytes, &mut cursor)?;
            let inos = read_u64(bytes, &mut cursor)?;
            (alloc, inos)
        } else {
            (0, 0)
        };
        if cursor != bytes.len() {
            return Err(Errno::EIO);
        }
        Ok(Self {
            format_version,
            features,
            volume_uuid,
            subvols,
            next_ino,
            generation,
            parent_root,
            allocated_bytes,
            inode_count,
        })
    }
}

const EXTENT_TAG_INLINE: u8 = 0;
const EXTENT_TAG_OUTLINE: u8 = 1;

/// `0x30` `EXTENT_DATA` value stored at `(ino, 0x30, file_offset_be)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExtentDataValue {
    /// Inline regular-file content (`<= 2 KiB`) residing directly in the B+tree leaf at offset 0.
    Inline(Vec<u8>),
    /// Content-addressed out-of-line data extent (`64 KiB` aligned, `len <= 1 MiB`) in `PackStore`.
    Extent {
        len: u32,
        digest: Digest,
        block_offset: u32,
    },
}

impl ExtentDataValue {
    pub fn byte_len(&self) -> u64 {
        match self {
            Self::Inline(v) => v.len() as u64,
            Self::Extent { len, .. } => u64::from(*len),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        match self {
            ExtentDataValue::Inline(data) => {
                if data.len() > INLINE_MAX_BYTES {
                    return Err(Errno::EIO);
                }
                let mut out = Vec::with_capacity(3 + data.len());
                out.push(EXTENT_TAG_INLINE);
                out.extend_from_slice(&(data.len() as u16).to_be_bytes());
                out.extend_from_slice(data);
                Ok(out)
            }
            ExtentDataValue::Extent {
                len,
                digest,
                block_offset,
            } => {
                if *len == 0 || *len > EXTENT_MAX_BYTES {
                    return Err(Errno::EIO);
                }
                let mut out = Vec::with_capacity(41);
                out.push(EXTENT_TAG_OUTLINE);
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(digest);
                out.extend_from_slice(&block_offset.to_be_bytes());
                Ok(out)
            }
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut c = 0;
        let tag = read_u8(bytes, &mut c)?;
        match tag {
            EXTENT_TAG_INLINE => {
                let len = read_u16(bytes, &mut c)? as usize;
                if len > INLINE_MAX_BYTES {
                    return Err(Errno::EIO);
                }
                let data = read_slice(bytes, &mut c, len)?.to_vec();
                if c != bytes.len() {
                    return Err(Errno::EIO);
                }
                Ok(ExtentDataValue::Inline(data))
            }
            EXTENT_TAG_OUTLINE => {
                let len = read_u32(bytes, &mut c)?;
                let mut digest = [0u8; 32];
                digest.copy_from_slice(read_slice(bytes, &mut c, 32)?);
                let block_offset = read_u32(bytes, &mut c)?;
                if c != bytes.len() || len == 0 || len > EXTENT_MAX_BYTES {
                    return Err(Errno::EIO);
                }
                Ok(ExtentDataValue::Extent {
                    len,
                    digest,
                    block_offset,
                })
            }
            _ => Err(Errno::EIO),
        }
    }
}

/// Deterministic big-endian metadata record stored at [`TreeKey::raw_block_meta`] inside
/// `ROOT_FEATURE_RAW_BLOCK` volumes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawVolumeMeta {
    pub version: u8,
    pub block_size: u32,
    pub size_bytes: u64,
    pub flags: u32,
    pub created_at: abi::fs::Timespec,
    pub modified_at: abi::fs::Timespec,
}

impl RawVolumeMeta {
    pub fn new(
        block_size: u32,
        size_bytes: u64,
        flags: u32,
        now: abi::fs::Timespec,
    ) -> Result<Self> {
        let meta = Self {
            version: RAW_VOLUME_META_VERSION,
            block_size,
            size_bytes,
            flags,
            created_at: now,
            modified_at: now,
        };
        meta.validate()?;
        Ok(meta)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != RAW_VOLUME_META_VERSION {
            return Err(Errno::EPROTONOSUPPORT);
        }
        if self.block_size < RAW_VOLUME_MIN_BLOCK_SIZE
            || self.block_size > RAW_VOLUME_MAX_BLOCK_SIZE
            || !self.block_size.is_power_of_two()
        {
            return Err(Errno::EINVAL);
        }
        if self.size_bytes == 0
            || self.size_bytes > RAW_VOLUME_MAX_SIZE_BYTES
            || !self.size_bytes.is_multiple_of(u64::from(self.block_size))
        {
            return Err(Errno::EINVAL);
        }
        if self.created_at.nsec >= 1_000_000_000 || self.modified_at.nsec >= 1_000_000_000 {
            return Err(Errno::EINVAL);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::with_capacity(RAW_VOLUME_META_BYTES);
        out.push(self.version);
        out.extend_from_slice(&self.block_size.to_be_bytes());
        out.extend_from_slice(&self.size_bytes.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&self.created_at.sec.to_be_bytes());
        out.extend_from_slice(&self.created_at.nsec.to_be_bytes());
        out.extend_from_slice(&self.modified_at.sec.to_be_bytes());
        out.extend_from_slice(&self.modified_at.nsec.to_be_bytes());
        debug_assert_eq!(out.len(), RAW_VOLUME_META_BYTES);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != RAW_VOLUME_META_BYTES {
            return Err(Errno::EIO);
        }
        let mut c = 0usize;
        let version = read_u8(bytes, &mut c)?;
        if version != RAW_VOLUME_META_VERSION {
            return Err(Errno::EPROTONOSUPPORT);
        }
        let block_size = read_u32(bytes, &mut c)?;
        let size_bytes = read_u64(bytes, &mut c)?;
        let flags = read_u32(bytes, &mut c)?;
        let created_sec = read_u64(bytes, &mut c)?;
        let created_nsec = read_u32(bytes, &mut c)?;
        let modified_sec = read_u64(bytes, &mut c)?;
        let modified_nsec = read_u32(bytes, &mut c)?;
        let meta = Self {
            version,
            block_size,
            size_bytes,
            flags,
            created_at: abi::fs::Timespec {
                sec: created_sec,
                nsec: created_nsec,
            },
            modified_at: abi::fs::Timespec {
                sec: modified_sec,
                nsec: modified_nsec,
            },
        };
        meta.validate().map_err(|e| match e {
            Errno::EPROTONOSUPPORT => Errno::EPROTONOSUPPORT,
            _ => Errno::EIO,
        })?;
        Ok(meta)
    }
}

fn read_slice<'a>(bytes: &'a [u8], cursor: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = cursor.checked_add(len).ok_or(Errno::EIO)?;
    if end > bytes.len() {
        return Err(Errno::EIO);
    }
    let slice = &bytes[*cursor..end];
    *cursor = end;
    Ok(slice)
}

fn read_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8> {
    Ok(read_slice(bytes, cursor, 1)?[0])
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16> {
    let s = read_slice(bytes, cursor, 2)?;
    Ok(u16::from_be_bytes([s[0], s[1]]))
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32> {
    let s = read_slice(bytes, cursor, 4)?;
    Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_u64(bytes: &[u8], cursor: &mut usize) -> Result<u64> {
    let s = read_slice(bytes, cursor, 8)?;
    Ok(u64::from_be_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

fn read_key(bytes: &[u8], cursor: &mut usize) -> Result<TreeKey> {
    let ino = read_u64(bytes, cursor)?;
    let kind = read_u8(bytes, cursor)?;
    let tail_len = read_u16(bytes, cursor)? as usize;
    if tail_len > KEY_TAIL_MAX_BYTES {
        return Err(Errno::EIO);
    }
    let tail = read_slice(bytes, cursor, tail_len)?.to_vec();
    Ok(TreeKey { ino, kind, tail })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_roundtrip_and_bitflip_eio() {
        let leaf = Node::Leaf {
            entries: vec![
                LeafEntry {
                    key: TreeKey::inode_item(1),
                    value: vec![1, 2, 3],
                },
                LeafEntry {
                    key: TreeKey::dir_item(1, "hello"),
                    value: vec![4, 5, 6, 7],
                },
            ],
        };
        let (digest, mut bytes) = leaf.encode().unwrap();
        assert_eq!(Node::decode_verified(&digest, &bytes).unwrap(), leaf);
        bytes[10] ^= 0x01;
        assert_eq!(Node::decode_verified(&digest, &bytes), Err(Errno::EIO));
    }

    #[test]
    fn root_object_roundtrip_and_version_refusal() {
        let mut subvols = BTreeMap::new();
        subvols.insert("@".into(), [0xab; 32]);
        let root = RootObject {
            format_version: COWFS_FORMAT_VERSION,
            features: 0,
            volume_uuid: "vol-1".into(),
            subvols,
            next_ino: 2,
            generation: 1,
            parent_root: None,
            allocated_bytes: 0,
            inode_count: 0,
        };
        let (digest, bytes) = root.encode().unwrap();
        assert_eq!(RootObject::decode_verified(&digest, &bytes).unwrap(), root);

        let mut acct = root.clone();
        acct.features = ROOT_FEATURE_ACCOUNTING;
        acct.allocated_bytes = 256 * 1024;
        acct.inode_count = 42;
        let (acct_digest, acct_bytes) = acct.encode().unwrap();
        assert_eq!(
            RootObject::decode_verified(&acct_digest, &acct_bytes).unwrap(),
            acct
        );

        let mut bad = root.clone();
        bad.format_version = COWFS_FORMAT_VERSION + 1;
        let (bad_digest, bad_bytes) = bad.encode().unwrap();
        assert_eq!(
            RootObject::decode_verified(&bad_digest, &bad_bytes),
            Err(Errno::EPROTONOSUPPORT)
        );
    }

    #[test]
    fn raw_volume_meta_roundtrip_and_validation() {
        let now = abi::fs::Timespec {
            sec: 1_700_000_000,
            nsec: 123_456,
        };
        let meta = RawVolumeMeta::new(4096, 1024 * 1024, 0x3, now).unwrap();
        let bytes = meta.encode().unwrap();
        assert_eq!(bytes.len(), RAW_VOLUME_META_BYTES);
        assert_eq!(RawVolumeMeta::decode(&bytes).unwrap(), meta);

        // Non-power-of-two block size rejected.
        assert_eq!(
            RawVolumeMeta::new(3000, 3000 * 4, 0, now),
            Err(Errno::EINVAL)
        );
        // Too small / too large block size rejected.
        assert_eq!(RawVolumeMeta::new(256, 4096, 0, now), Err(Errno::EINVAL));
        assert_eq!(
            RawVolumeMeta::new(131_072, 131_072 * 2, 0, now),
            Err(Errno::EINVAL)
        );
        // Zero size / unaligned size / > 16 TiB rejected.
        assert_eq!(RawVolumeMeta::new(4096, 0, 0, now), Err(Errno::EINVAL));
        assert_eq!(RawVolumeMeta::new(4096, 4097, 0, now), Err(Errno::EINVAL));
        assert_eq!(
            RawVolumeMeta::new(4096, RAW_VOLUME_MAX_SIZE_BYTES + 4096, 0, now),
            Err(Errno::EINVAL)
        );
        // Incompatible version rejected on decode with EPROTONOSUPPORT.
        let mut bad = bytes.clone();
        bad[0] = RAW_VOLUME_META_VERSION + 1;
        assert_eq!(RawVolumeMeta::decode(&bad), Err(Errno::EPROTONOSUPPORT));
    }
}
