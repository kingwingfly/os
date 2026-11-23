//! Self-verifying read-only Snapshot Pack Archive (`OSCOWA1\0`, `.cowpack`) encoder, footer/index
//! parser, and zero-copy random-access [`ArchiveReader`] (`docs/architecture/contract.md` §2.15,
//! §2.16, #79).
//!
//! Binary layout (all integers big-endian):
//! ```text
//! [0..16]           Header: magic[8] ("OSCOWA1\0") || version[2] (1) || flags[2] (0) || reserved[4] (0)
//! [16..pack_end]    Concatenated `COWP` packs (each <= 8 MiB)
//! [pack_end..n_end] Concatenated length-prefixed nodes (`len[4] || bytes[len]`)
//! [n_end..idx_end]  Sorted binary index:
//!                     pack_count[4]  + [pack_sha256[32], offset[8], len[4]] * pack_count
//!                     block_count[4] + [block_digest[32], pack_idx[4], pack_off[4], block_len[4]] * block_count
//!                     node_count[4]  + [node_digest[32], offset[8], len[4]] * node_count
//! [EOF-96..EOF]     96-byte Footer:
//!                     magic[8] ("OSCOWA1F") || version[2] (1) || flags[2] (0) || reserved[4] (0)
//!                     || index_offset[8] || index_len[8] || root_digest[32] || index_sha256[32]
//! ```

use crate::pack::BuiltPack;
use crate::store::Digest;
use crate::{EXTENT_MAX_BYTES, NODE_MAX_BYTES, PACK_MAX_BYTES, sha256};
use abi::Errno;
use std::collections::HashSet;
use vfs::{BoxFuture, Result};

/// Archive header magic (`OSCOWA1\0`).
pub const ARCHIVE_HEADER_MAGIC: [u8; 8] = *b"OSCOWA1\0";
/// Archive footer magic (`OSCOWA1F`).
pub const ARCHIVE_FOOTER_MAGIC: [u8; 8] = *b"OSCOWA1F";
/// Archive format version.
pub const ARCHIVE_VERSION: u16 = 1;
/// Header size in bytes (`16`).
pub const ARCHIVE_HEADER_BYTES: usize = 16;
/// Footer size in bytes (`96`).
pub const ARCHIVE_FOOTER_BYTES: usize = 96;
/// Bounded maximum index size (`16 MiB`) preventing OOM on corrupt footers in `wasm32`.
pub const ARCHIVE_MAX_INDEX_BYTES: u64 = 16 * 1024 * 1024;

const PACK_ENTRY_BYTES: usize = 32 + 8 + 4; // 44
const BLOCK_ENTRY_BYTES: usize = 32 + 4 + 4 + 4; // 44
const NODE_ENTRY_BYTES: usize = 32 + 8 + 4; // 44

/// Indexed `COWP` pack location inside a `.cowpack` file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchivePackEntry {
    pub digest: Digest,
    pub offset: u64,
    pub len: u32,
}

/// Indexed data block location inside one pack of a `.cowpack` file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveBlockEntry {
    pub digest: Digest,
    pub pack_idx: u32,
    pub pack_off: u32,
    pub block_len: u32,
}

/// Indexed CoW B+tree node (or `RootObject`) location inside a `.cowpack` file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveNodeEntry {
    pub digest: Digest,
    pub offset: u64,
    pub len: u32,
}

/// Parsed 96-byte `OSCOWA1F` trailer footer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveFooter {
    pub version: u16,
    pub flags: u16,
    pub index_offset: u64,
    pub index_len: u64,
    pub root_digest: Digest,
    pub index_sha256: Digest,
}

/// Verified sorted binary index of a `.cowpack` archive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchiveIndex {
    pub packs: Vec<ArchivePackEntry>,
    pub blocks: Vec<ArchiveBlockEntry>,
    pub nodes: Vec<ArchiveNodeEntry>,
}

impl ArchiveIndex {
    pub fn find_pack(&self, digest: &Digest) -> Option<&ArchivePackEntry> {
        self.packs
            .binary_search_by_key(digest, |e| e.digest)
            .ok()
            .map(|i| &self.packs[i])
    }

    pub fn find_block(&self, digest: &Digest) -> Option<&ArchiveBlockEntry> {
        self.blocks
            .binary_search_by_key(digest, |e| e.digest)
            .ok()
            .map(|i| &self.blocks[i])
    }

    pub fn find_node(&self, digest: &Digest) -> Option<&ArchiveNodeEntry> {
        self.nodes
            .binary_search_by_key(digest, |e| e.digest)
            .ok()
            .map(|i| &self.nodes[i])
    }
}

/// Zero-copy random-access byte reader over a regular file (`vfs::FileRef::read_at`) or buffer.
pub trait ArchiveReader {
    fn size(&self) -> BoxFuture<'_, u64>;
    fn read_at<'a>(&'a self, offset: u64, len: usize) -> BoxFuture<'a, Vec<u8>>;
}

/// Encode the 16-byte `OSCOWA1\0` header.
pub fn encode_archive_header() -> [u8; ARCHIVE_HEADER_BYTES] {
    let mut out = [0u8; ARCHIVE_HEADER_BYTES];
    out[0..8].copy_from_slice(&ARCHIVE_HEADER_MAGIC);
    out[8..10].copy_from_slice(&ARCHIVE_VERSION.to_be_bytes());
    // flags = 0, reserved = 0
    out
}

/// Validate a 16-byte `OSCOWA1\0` header.
pub fn decode_archive_header(bytes: &[u8]) -> Result<()> {
    if bytes.len() != ARCHIVE_HEADER_BYTES {
        return Err(Errno::EIO);
    }
    if bytes[0..8] != ARCHIVE_HEADER_MAGIC {
        return Err(Errno::EIO);
    }
    let version = u16::from_be_bytes([bytes[8], bytes[9]]);
    if version != ARCHIVE_VERSION {
        return Err(Errno::EPROTONOSUPPORT);
    }
    let flags = u16::from_be_bytes([bytes[10], bytes[11]]);
    if flags != 0 {
        return Err(Errno::EPROTONOSUPPORT);
    }
    Ok(())
}

/// Decode and bounds-check the 96-byte `OSCOWA1F` footer against the total archive `file_size`.
pub fn decode_archive_footer(bytes: &[u8], file_size: u64) -> Result<ArchiveFooter> {
    if bytes.len() != ARCHIVE_FOOTER_BYTES {
        return Err(Errno::EIO);
    }
    if bytes[0..8] != ARCHIVE_FOOTER_MAGIC {
        return Err(Errno::EIO);
    }
    let version = u16::from_be_bytes([bytes[8], bytes[9]]);
    if version != ARCHIVE_VERSION {
        return Err(Errno::EPROTONOSUPPORT);
    }
    let flags = u16::from_be_bytes([bytes[10], bytes[11]]);
    if flags != 0 {
        return Err(Errno::EPROTONOSUPPORT);
    }
    let index_offset = u64::from_be_bytes(bytes[16..24].try_into().unwrap());
    let index_len = u64::from_be_bytes(bytes[24..32].try_into().unwrap());
    let mut root_digest = [0u8; 32];
    root_digest.copy_from_slice(&bytes[32..64]);
    let mut index_sha256 = [0u8; 32];
    index_sha256.copy_from_slice(&bytes[64..96]);

    if index_len > ARCHIVE_MAX_INDEX_BYTES || index_offset < ARCHIVE_HEADER_BYTES as u64 {
        return Err(Errno::EIO);
    }
    let index_end = index_offset.checked_add(index_len).ok_or(Errno::EIO)?;
    let expected_end = file_size
        .checked_sub(ARCHIVE_FOOTER_BYTES as u64)
        .ok_or(Errno::EIO)?;
    if index_end != expected_end {
        return Err(Errno::EIO);
    }

    Ok(ArchiveFooter {
        version,
        flags,
        index_offset,
        index_len,
        root_digest,
        index_sha256,
    })
}

/// Decode and SHA-256 verify the sorted binary index section against `footer`.
pub fn decode_archive_index(bytes: &[u8], footer: &ArchiveFooter) -> Result<ArchiveIndex> {
    if bytes.len() as u64 != footer.index_len {
        return Err(Errno::EIO);
    }
    if sha256(bytes) != footer.index_sha256 {
        return Err(Errno::EIO);
    }
    let mut cursor = 0usize;
    let pack_count = read_u32(bytes, &mut cursor)? as usize;
    let pack_bytes = pack_count.checked_mul(PACK_ENTRY_BYTES).ok_or(Errno::EIO)?;
    if cursor.checked_add(pack_bytes).ok_or(Errno::EIO)? > bytes.len() {
        return Err(Errno::EIO);
    }
    let mut packs = Vec::with_capacity(pack_count.min(4096));
    let mut prev_pack: Option<Digest> = None;
    for _ in 0..pack_count {
        let digest = read_digest(bytes, &mut cursor)?;
        let offset = read_u64(bytes, &mut cursor)?;
        let len = read_u32(bytes, &mut cursor)?;
        if let Some(p) = prev_pack
            && digest <= p
        {
            return Err(Errno::EIO);
        }
        if offset < ARCHIVE_HEADER_BYTES as u64 || len as usize > PACK_MAX_BYTES {
            return Err(Errno::EIO);
        }
        let end = offset.checked_add(u64::from(len)).ok_or(Errno::EIO)?;
        if end > footer.index_offset {
            return Err(Errno::EIO);
        }
        prev_pack = Some(digest);
        packs.push(ArchivePackEntry {
            digest,
            offset,
            len,
        });
    }

    let block_count = read_u32(bytes, &mut cursor)? as usize;
    let block_bytes = block_count
        .checked_mul(BLOCK_ENTRY_BYTES)
        .ok_or(Errno::EIO)?;
    if cursor.checked_add(block_bytes).ok_or(Errno::EIO)? > bytes.len() {
        return Err(Errno::EIO);
    }
    let mut blocks = Vec::with_capacity(block_count.min(4096));
    let mut prev_block: Option<Digest> = None;
    for _ in 0..block_count {
        let digest = read_digest(bytes, &mut cursor)?;
        let pack_idx = read_u32(bytes, &mut cursor)?;
        let pack_off = read_u32(bytes, &mut cursor)?;
        let block_len = read_u32(bytes, &mut cursor)?;
        if let Some(p) = prev_block
            && digest <= p
        {
            return Err(Errno::EIO);
        }
        let pack = packs.get(pack_idx as usize).ok_or(Errno::EIO)?;
        if block_len > EXTENT_MAX_BYTES {
            return Err(Errno::EIO);
        }
        let end = pack_off.checked_add(block_len).ok_or(Errno::EIO)?;
        if end > pack.len {
            return Err(Errno::EIO);
        }
        prev_block = Some(digest);
        blocks.push(ArchiveBlockEntry {
            digest,
            pack_idx,
            pack_off,
            block_len,
        });
    }

    let node_count = read_u32(bytes, &mut cursor)? as usize;
    let node_bytes = node_count.checked_mul(NODE_ENTRY_BYTES).ok_or(Errno::EIO)?;
    if cursor.checked_add(node_bytes).ok_or(Errno::EIO)? > bytes.len() {
        return Err(Errno::EIO);
    }
    let mut nodes = Vec::with_capacity(node_count.min(4096));
    let mut prev_node: Option<Digest> = None;
    for _ in 0..node_count {
        let digest = read_digest(bytes, &mut cursor)?;
        let offset = read_u64(bytes, &mut cursor)?;
        let len = read_u32(bytes, &mut cursor)?;
        if let Some(p) = prev_node
            && digest <= p
        {
            return Err(Errno::EIO);
        }
        if offset < ARCHIVE_HEADER_BYTES as u64 || len as usize > NODE_MAX_BYTES {
            return Err(Errno::EIO);
        }
        let end = offset.checked_add(u64::from(len)).ok_or(Errno::EIO)?;
        if end > footer.index_offset {
            return Err(Errno::EIO);
        }
        prev_node = Some(digest);
        nodes.push(ArchiveNodeEntry {
            digest,
            offset,
            len,
        });
    }

    if cursor != bytes.len() {
        return Err(Errno::EIO);
    }
    let index = ArchiveIndex {
        packs,
        blocks,
        nodes,
    };
    if index.find_node(&footer.root_digest).is_none() {
        return Err(Errno::EIO);
    }
    Ok(index)
}

/// Probe whether `reader` carries a valid `OSCOWA1\0` header + 96-byte `OSCOWA1F` footer.
/// Returns `Ok(None)` for non-archive raw files.
pub async fn probe_archive_footer<R: ArchiveReader>(reader: &R) -> Result<Option<ArchiveFooter>> {
    let size = reader.size().await?;
    if size < (ARCHIVE_HEADER_BYTES + ARCHIVE_FOOTER_BYTES) as u64 {
        return Ok(None);
    }
    let header = reader.read_at(0, ARCHIVE_HEADER_BYTES).await?;
    if header.len() != ARCHIVE_HEADER_BYTES || header[0..8] != ARCHIVE_HEADER_MAGIC {
        return Ok(None);
    }
    let footer_bytes = reader
        .read_at(size - ARCHIVE_FOOTER_BYTES as u64, ARCHIVE_FOOTER_BYTES)
        .await?;
    if footer_bytes.len() != ARCHIVE_FOOTER_BYTES || footer_bytes[0..8] != ARCHIVE_FOOTER_MAGIC {
        return Ok(None);
    }
    decode_archive_header(&header)?;
    let footer = decode_archive_footer(&footer_bytes, size)?;
    Ok(Some(footer))
}

/// Open and verify a `.cowpack` archive's header, 96-byte footer, and SHA-256 verified binary index
/// via zero-copy `ArchiveReader::read_at` calls (never copies the whole file).
pub async fn open_archive_index<R: ArchiveReader>(
    reader: &R,
) -> Result<(ArchiveFooter, ArchiveIndex)> {
    let size = reader.size().await?;
    if size < (ARCHIVE_HEADER_BYTES + ARCHIVE_FOOTER_BYTES) as u64 {
        return Err(Errno::EIO);
    }
    let header = reader.read_at(0, ARCHIVE_HEADER_BYTES).await?;
    decode_archive_header(&header)?;
    let footer_bytes = reader
        .read_at(size - ARCHIVE_FOOTER_BYTES as u64, ARCHIVE_FOOTER_BYTES)
        .await?;
    let footer = decode_archive_footer(&footer_bytes, size)?;
    let index_len = usize::try_from(footer.index_len).map_err(|_| Errno::EIO)?;
    let index_bytes = reader.read_at(footer.index_offset, index_len).await?;
    let index = decode_archive_index(&index_bytes, &footer)?;
    Ok((footer, index))
}

struct PendingArchiveBlock {
    digest: Digest,
    pack_digest: Digest,
    pack_off: u32,
    block_len: u32,
}

/// Streaming `.cowpack` (`OSCOWA1\0`) archive writer tracking byte offsets while the caller
/// streams packs and nodes out in bounded chunks.
pub struct ArchiveWriter {
    offset: u64,
    packs: Vec<ArchivePackEntry>,
    seen_packs: HashSet<Digest>,
    blocks: Vec<PendingArchiveBlock>,
    seen_blocks: HashSet<Digest>,
    nodes: Vec<ArchiveNodeEntry>,
    seen_nodes: HashSet<Digest>,
}

impl Default for ArchiveWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl ArchiveWriter {
    pub fn new() -> Self {
        Self {
            offset: ARCHIVE_HEADER_BYTES as u64,
            packs: Vec::new(),
            seen_packs: HashSet::new(),
            blocks: Vec::new(),
            seen_blocks: HashSet::new(),
            nodes: Vec::new(),
            seen_nodes: HashSet::new(),
        }
    }

    pub fn header_bytes(&self) -> [u8; ARCHIVE_HEADER_BYTES] {
        encode_archive_header()
    }

    pub fn current_offset(&self) -> u64 {
        self.offset
    }

    /// Record a sealed `COWP` pack to be streamed immediately at the current offset.
    /// Returns `true` if this pack was newly added and must be written to the output sink.
    pub fn record_pack(&mut self, built: &BuiltPack) -> Result<bool> {
        let pack_digest = sha256(&built.bytes);
        if !self.seen_packs.insert(pack_digest) {
            return Ok(false);
        }
        let len = u32::try_from(built.bytes.len()).map_err(|_| Errno::EFBIG)?;
        if built.bytes.len() > PACK_MAX_BYTES {
            return Err(Errno::EFBIG);
        }
        let pack_offset = self.offset;
        self.offset = self
            .offset
            .checked_add(u64::from(len))
            .ok_or(Errno::EFBIG)?;
        self.packs.push(ArchivePackEntry {
            digest: pack_digest,
            offset: pack_offset,
            len,
        });
        for entry in &built.entries {
            if self.seen_blocks.insert(entry.digest) {
                self.blocks.push(PendingArchiveBlock {
                    digest: entry.digest,
                    pack_digest,
                    pack_off: entry.offset,
                    block_len: entry.len,
                });
            }
        }
        Ok(true)
    }

    /// Record a verified node (`len[4] || node_bytes`) to be streamed immediately at the current
    /// offset. Returns `Some(len_prefix)` when newly added (caller writes `len_prefix` then
    /// `node_bytes`), or `None` if this digest was already recorded.
    pub fn record_node(&mut self, digest: Digest, node_bytes: &[u8]) -> Result<Option<[u8; 4]>> {
        if node_bytes.len() > NODE_MAX_BYTES {
            return Err(Errno::EFBIG);
        }
        if !self.seen_nodes.insert(digest) {
            return Ok(None);
        }
        let len = u32::try_from(node_bytes.len()).map_err(|_| Errno::EFBIG)?;
        let payload_offset = self.offset.checked_add(4).ok_or(Errno::EFBIG)?;
        self.offset = payload_offset
            .checked_add(u64::from(len))
            .ok_or(Errno::EFBIG)?;
        self.nodes.push(ArchiveNodeEntry {
            digest,
            offset: payload_offset,
            len,
        });
        Ok(Some(len.to_be_bytes()))
    }

    /// Sort all index sections, remap `pack_idx`, and produce `(index_bytes, footer_bytes)`.
    pub fn finish(mut self, root_digest: Digest) -> Result<(Vec<u8>, [u8; ARCHIVE_FOOTER_BYTES])> {
        self.packs.sort_by_key(|p| p.digest);
        self.nodes.sort_by_key(|n| n.digest);

        if self
            .nodes
            .binary_search_by_key(&root_digest, |n| n.digest)
            .is_err()
        {
            return Err(Errno::EINVAL);
        }

        let mut blocks: Vec<ArchiveBlockEntry> = Vec::with_capacity(self.blocks.len());
        for b in self.blocks {
            let pack_idx = self
                .packs
                .binary_search_by_key(&b.pack_digest, |p| p.digest)
                .map_err(|_| Errno::EIO)?;
            blocks.push(ArchiveBlockEntry {
                digest: b.digest,
                pack_idx: u32::try_from(pack_idx).map_err(|_| Errno::EFBIG)?,
                pack_off: b.pack_off,
                block_len: b.block_len,
            });
        }
        blocks.sort_by_key(|b| b.digest);

        let index_offset = self.offset;
        let index_size = 4
            + self.packs.len() * PACK_ENTRY_BYTES
            + 4
            + blocks.len() * BLOCK_ENTRY_BYTES
            + 4
            + self.nodes.len() * NODE_ENTRY_BYTES;
        if index_size as u64 > ARCHIVE_MAX_INDEX_BYTES {
            return Err(Errno::EFBIG);
        }

        let mut index_bytes = Vec::with_capacity(index_size);
        index_bytes.extend_from_slice(&(self.packs.len() as u32).to_be_bytes());
        for p in &self.packs {
            index_bytes.extend_from_slice(&p.digest);
            index_bytes.extend_from_slice(&p.offset.to_be_bytes());
            index_bytes.extend_from_slice(&p.len.to_be_bytes());
        }
        index_bytes.extend_from_slice(&(blocks.len() as u32).to_be_bytes());
        for b in &blocks {
            index_bytes.extend_from_slice(&b.digest);
            index_bytes.extend_from_slice(&b.pack_idx.to_be_bytes());
            index_bytes.extend_from_slice(&b.pack_off.to_be_bytes());
            index_bytes.extend_from_slice(&b.block_len.to_be_bytes());
        }
        index_bytes.extend_from_slice(&(self.nodes.len() as u32).to_be_bytes());
        for n in &self.nodes {
            index_bytes.extend_from_slice(&n.digest);
            index_bytes.extend_from_slice(&n.offset.to_be_bytes());
            index_bytes.extend_from_slice(&n.len.to_be_bytes());
        }
        debug_assert_eq!(index_bytes.len(), index_size);

        let index_sha256 = sha256(&index_bytes);
        let index_len = index_bytes.len() as u64;

        let mut footer = [0u8; ARCHIVE_FOOTER_BYTES];
        footer[0..8].copy_from_slice(&ARCHIVE_FOOTER_MAGIC);
        footer[8..10].copy_from_slice(&ARCHIVE_VERSION.to_be_bytes());
        // flags = 0, reserved = 0
        footer[16..24].copy_from_slice(&index_offset.to_be_bytes());
        footer[24..32].copy_from_slice(&index_len.to_be_bytes());
        footer[32..64].copy_from_slice(&root_digest);
        footer[64..96].copy_from_slice(&index_sha256);

        Ok((index_bytes, footer))
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

fn read_digest(bytes: &[u8], cursor: &mut usize) -> Result<Digest> {
    let s = read_slice(bytes, cursor, 32)?;
    let mut d = [0u8; 32];
    d.copy_from_slice(s);
    Ok(d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::encode_pack;

    struct VecReader(Vec<u8>);
    impl ArchiveReader for VecReader {
        fn size(&self) -> BoxFuture<'_, u64> {
            Box::pin(async move { Ok(self.0.len() as u64) })
        }
        fn read_at<'a>(&'a self, offset: u64, len: usize) -> BoxFuture<'a, Vec<u8>> {
            Box::pin(async move {
                let start = usize::try_from(offset).map_err(|_| Errno::EINVAL)?;
                let end = start.checked_add(len).ok_or(Errno::EINVAL)?;
                if end > self.0.len() {
                    return Err(Errno::EIO);
                }
                Ok(self.0[start..end].to_vec())
            })
        }
    }

    #[test]
    fn archive_roundtrip_and_corruption_detection() {
        let block = vec![0x77u8; 64 * 1024];
        let block_dig = sha256(&block);
        let built = encode_pack(&[(block_dig, block.clone())]).unwrap();

        let root_node = b"fake-root-node".to_vec();
        let root_dig = sha256(&root_node);

        let mut writer = ArchiveWriter::new();
        let mut raw = Vec::new();
        raw.extend_from_slice(&writer.header_bytes());
        assert!(writer.record_pack(&built).unwrap());
        raw.extend_from_slice(&built.bytes);
        let prefix = writer.record_node(root_dig, &root_node).unwrap().unwrap();
        raw.extend_from_slice(&prefix);
        raw.extend_from_slice(&root_node);
        let (idx_bytes, footer_bytes) = writer.finish(root_dig).unwrap();
        raw.extend_from_slice(&idx_bytes);
        raw.extend_from_slice(&footer_bytes);

        let reader = VecReader(raw.clone());
        let (footer, index) = vfs::now_or_never(open_archive_index(&reader))
            .unwrap()
            .unwrap();
        assert_eq!(footer.root_digest, root_dig);
        assert_eq!(index.packs.len(), 1);
        assert_eq!(index.blocks.len(), 1);
        assert_eq!(index.nodes.len(), 1);
        let be = index.find_block(&block_dig).unwrap();
        assert_eq!(be.block_len as usize, block.len());
        let ne = index.find_node(&root_dig).unwrap();
        assert_eq!(
            &raw[ne.offset as usize..ne.offset as usize + ne.len as usize],
            root_node.as_slice()
        );

        // Bit-flip in index fails SHA-256 verification with EIO.
        let mut corrupt_idx = raw.clone();
        corrupt_idx[footer.index_offset as usize] ^= 0x01;
        assert_eq!(
            vfs::now_or_never(open_archive_index(&VecReader(corrupt_idx))).unwrap(),
            Err(Errno::EIO)
        );
    }
}
