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
use std::collections::BTreeMap;
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
    if bytes[12..16] != [0; 4] {
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
    if bytes[12..16] != [0; 4] {
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
    if size < 8 {
        return Ok(None);
    }
    let header = reader
        .read_at(0, size.min(ARCHIVE_HEADER_BYTES as u64) as usize)
        .await?;
    if !header.starts_with(&ARCHIVE_HEADER_MAGIC) {
        return Ok(None);
    }
    if size < (ARCHIVE_HEADER_BYTES + ARCHIVE_FOOTER_BYTES) as u64 {
        return Err(Errno::EIO);
    }
    let footer_bytes = reader
        .read_at(size - ARCHIVE_FOOTER_BYTES as u64, ARCHIVE_FOOTER_BYTES)
        .await?;
    decode_archive_header(&header)?;
    let footer = decode_archive_footer(&footer_bytes, size)?;
    Ok(Some(footer))
}

const INDEX_PAGE: usize = 32 * 1024;
const ROW_BYTES: usize = 44;

#[derive(Clone, Copy, Debug, Default)]
pub struct ArchiveTable {
    offset: usize,
    count: usize,
}

impl ArchiveTable {
    pub fn len(self) -> usize {
        self.count
    }
    pub fn is_empty(self) -> bool {
        self.count == 0
    }
}

/// The footer authenticates the whole index. Retain page hashes so subsequent
/// random reads still authenticate the same index if the backing file changes.
#[derive(Debug)]
pub struct PagedArchiveIndex {
    start: u64,
    len: usize,
    hashes: Vec<Digest>,
    cache: std::cell::RefCell<std::collections::VecDeque<(usize, Vec<u8>)>>,
    pub packs: ArchiveTable,
    pub blocks: ArchiveTable,
    pub nodes: ArchiveTable,
}

impl PagedArchiveIndex {
    async fn bytes<const N: usize>(
        &self,
        reader: &impl ArchiveReader,
        offset: usize,
    ) -> Result<[u8; N]> {
        if offset.checked_add(N).is_none_or(|end| end > self.len) {
            return Err(Errno::EIO);
        }
        let mut result = [0; N];
        let mut done = 0;
        while done < N {
            let off = offset + done;
            let page = off / INDEX_PAGE;
            let within = off % INDEX_PAGE;
            let n = (N - done).min(INDEX_PAGE - within);
            if let Some((_, bytes)) = self.cache.borrow().iter().find(|(i, _)| *i == page) {
                result[done..done + n].copy_from_slice(&bytes[within..within + n]);
                done += n;
                continue;
            }
            let len = INDEX_PAGE.min(self.len - page * INDEX_PAGE);
            let bytes = reader
                .read_at(self.start + (page * INDEX_PAGE) as u64, len)
                .await?;
            if bytes.len() != len || sha256(&bytes) != self.hashes[page] {
                return Err(Errno::EIO);
            }
            result[done..done + n].copy_from_slice(&bytes[within..within + n]);
            let mut cache = self.cache.borrow_mut();
            if cache.len() == 4 {
                cache.pop_front();
            }
            cache.push_back((page, bytes));
            done += n;
        }
        Ok(result)
    }

    async fn table(&self, r: &impl ArchiveReader, cur: &mut usize) -> Result<ArchiveTable> {
        let count = u32::from_be_bytes(self.bytes(r, *cur).await?) as usize;
        let offset = *cur + 4;
        *cur = offset
            .checked_add(count.checked_mul(ROW_BYTES).ok_or(Errno::EIO)?)
            .filter(|end| *end <= self.len)
            .ok_or(Errno::EIO)?;
        Ok(ArchiveTable { offset, count })
    }

    async fn row(
        &self,
        r: &impl ArchiveReader,
        t: ArchiveTable,
        idx: usize,
    ) -> Result<[u8; ROW_BYTES]> {
        if idx >= t.count {
            return Err(Errno::EIO);
        }
        self.bytes(r, t.offset + idx * ROW_BYTES).await
    }

    async fn find(
        &self,
        r: &impl ArchiveReader,
        t: ArchiveTable,
        d: &Digest,
    ) -> Result<Option<usize>> {
        let (mut lo, mut hi) = (0, t.count);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let row = self.row(r, t, mid).await?;
            match row[..32].cmp(d) {
                std::cmp::Ordering::Equal => return Ok(Some(mid)),
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
            }
        }
        Ok(None)
    }

    pub async fn pack_at(&self, r: &impl ArchiveReader, i: usize) -> Result<ArchivePackEntry> {
        let row = self.row(r, self.packs, i).await?;
        Ok(ArchivePackEntry {
            digest: row[..32].try_into().unwrap(),
            offset: u64::from_be_bytes(row[32..40].try_into().unwrap()),
            len: u32::from_be_bytes(row[40..].try_into().unwrap()),
        })
    }
    pub async fn find_pack(
        &self,
        r: &impl ArchiveReader,
        d: &Digest,
    ) -> Result<Option<ArchivePackEntry>> {
        match self.find(r, self.packs, d).await? {
            Some(i) => Ok(Some(self.pack_at(r, i).await?)),
            None => Ok(None),
        }
    }
    pub async fn node_at(&self, r: &impl ArchiveReader, i: usize) -> Result<ArchiveNodeEntry> {
        let row = self.row(r, self.nodes, i).await?;
        Ok(ArchiveNodeEntry {
            digest: row[..32].try_into().unwrap(),
            offset: u64::from_be_bytes(row[32..40].try_into().unwrap()),
            len: u32::from_be_bytes(row[40..].try_into().unwrap()),
        })
    }
    pub async fn find_node(
        &self,
        r: &impl ArchiveReader,
        d: &Digest,
    ) -> Result<Option<ArchiveNodeEntry>> {
        match self.find(r, self.nodes, d).await? {
            Some(i) => Ok(Some(self.node_at(r, i).await?)),
            None => Ok(None),
        }
    }
    async fn block_at(&self, r: &impl ArchiveReader, i: usize) -> Result<ArchiveBlockEntry> {
        let row = self.row(r, self.blocks, i).await?;
        Ok(ArchiveBlockEntry {
            digest: row[..32].try_into().unwrap(),
            pack_idx: u32::from_be_bytes(row[32..36].try_into().unwrap()),
            pack_off: u32::from_be_bytes(row[36..40].try_into().unwrap()),
            block_len: u32::from_be_bytes(row[40..].try_into().unwrap()),
        })
    }
    pub async fn find_block(
        &self,
        r: &impl ArchiveReader,
        d: &Digest,
    ) -> Result<Option<ArchiveBlockEntry>> {
        match self.find(r, self.blocks, d).await? {
            Some(i) => Ok(Some(self.block_at(r, i).await?)),
            None => Ok(None),
        }
    }
}

/// Check that the indexed physical records exactly cover their section.
fn section_end(records: &mut Vec<(u64, u32)>, mut start: u64, limit: u64) -> Result<u64> {
    records.sort_unstable();
    for (offset, len) in records.drain(..) {
        if offset != start {
            return Err(Errno::EIO);
        }
        start = start
            .checked_add(u64::from(len))
            .filter(|end| *end <= limit)
            .ok_or(Errno::EIO)?;
    }
    Ok(start)
}

pub async fn open_archive_index<R: ArchiveReader>(
    reader: &R,
) -> Result<(ArchiveFooter, PagedArchiveIndex)> {
    use sha2::{Digest as _, Sha256};
    let footer = probe_archive_footer(reader).await?.ok_or(Errno::EIO)?;
    let len = usize::try_from(footer.index_len).map_err(|_| Errno::EIO)?;
    let mut hash = Sha256::new();
    let mut hashes = Vec::with_capacity(len.div_ceil(INDEX_PAGE));
    for pos in (0..len).step_by(INDEX_PAGE) {
        let n = (len - pos).min(INDEX_PAGE);
        let bytes = reader.read_at(footer.index_offset + pos as u64, n).await?;
        if bytes.len() != n {
            return Err(Errno::EIO);
        }
        hash.update(&bytes);
        hashes.push(sha256(&bytes));
    }
    if hash.finalize().as_slice() != footer.index_sha256 {
        return Err(Errno::EIO);
    }
    let mut index = PagedArchiveIndex {
        start: footer.index_offset,
        len,
        hashes,
        cache: Default::default(),
        packs: Default::default(),
        blocks: Default::default(),
        nodes: Default::default(),
    };
    let mut cur = 0;
    index.packs = index.table(reader, &mut cur).await?;
    index.blocks = index.table(reader, &mut cur).await?;
    index.nodes = index.table(reader, &mut cur).await?;
    if cur != len {
        return Err(Errno::EIO);
    }
    let mut records = Vec::with_capacity(index.packs.len().max(index.nodes.len()));
    let mut pack_lengths = Vec::with_capacity(index.packs.len());
    let mut prev = None;
    for i in 0..index.packs.len() {
        let p = index.pack_at(reader, i).await?;
        if prev.is_some_and(|d| d >= p.digest)
            || !(crate::pack::PACK_FOOTER_BYTES..=PACK_MAX_BYTES).contains(&(p.len as usize))
        {
            return Err(Errno::EIO);
        }
        prev = Some(p.digest);
        pack_lengths.push(p.len);
        records.push((p.offset, p.len));
    }
    let pack_end = section_end(
        &mut records,
        ARCHIVE_HEADER_BYTES as u64,
        footer.index_offset,
    )?;
    prev = None;
    for i in 0..index.blocks.len() {
        let b = index.block_at(reader, i).await?;
        if prev.is_some_and(|d| d >= b.digest) || b.block_len == 0 || b.block_len > EXTENT_MAX_BYTES
        {
            return Err(Errno::EIO);
        }
        let pack_len = *pack_lengths.get(b.pack_idx as usize).ok_or(Errno::EIO)?;
        if b.pack_off
            .checked_add(b.block_len)
            .is_none_or(|end| end > pack_len)
        {
            return Err(Errno::EIO);
        }
        prev = Some(b.digest);
    }
    prev = None;
    for i in 0..index.nodes.len() {
        let n = index.node_at(reader, i).await?;
        if prev.is_some_and(|d| d >= n.digest) || n.len == 0 || n.len as usize > NODE_MAX_BYTES {
            return Err(Errno::EIO);
        }
        prev = Some(n.digest);
        records.push((n.offset.checked_sub(4).ok_or(Errno::EIO)?, n.len + 4));
    }
    if section_end(&mut records, pack_end, footer.index_offset)? != footer.index_offset
        || index
            .find(reader, index.nodes, &footer.root_digest)
            .await?
            .is_none()
    {
        return Err(Errno::EIO);
    }
    Ok((footer, index))
}

/// Tracks one sorted row per emitted object. Pack ordinals are remapped to sorted
/// indices when serializing, without building a second copy of the tables.
pub struct ArchiveWriter {
    offset: u64,
    packs: BTreeMap<Digest, (u64, u32, usize)>,
    blocks: BTreeMap<Digest, (u32, u32, u32)>,
    nodes: BTreeMap<Digest, (u64, u32)>,
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
            packs: BTreeMap::new(),
            blocks: BTreeMap::new(),
            nodes: BTreeMap::new(),
        }
    }

    pub fn header_bytes(&self) -> [u8; ARCHIVE_HEADER_BYTES] {
        encode_archive_header()
    }
    pub fn current_offset(&self) -> u64 {
        self.offset
    }
    pub fn has_block(&self, digest: &Digest) -> bool {
        self.blocks.contains_key(digest)
    }
    pub fn has_node(&self, digest: &Digest) -> bool {
        self.nodes.contains_key(digest)
    }

    fn check_entry_budget(&self, additional: usize) -> Result<()> {
        let count = self.blocks.len() + self.packs.len() + self.nodes.len() + additional;
        if count > (ARCHIVE_MAX_INDEX_BYTES as usize - 12) / ROW_BYTES {
            return Err(Errno::EFBIG);
        }
        Ok(())
    }

    pub fn record_pack(&mut self, built: &BuiltPack) -> Result<bool> {
        let digest = sha256(&built.bytes);
        if self.packs.contains_key(&digest) {
            return Ok(false);
        }
        if built.bytes.len() > PACK_MAX_BYTES {
            return Err(Errno::EFBIG);
        }
        let len = built.bytes.len() as u32;
        self.check_entry_budget(
            1 + built
                .entries
                .iter()
                .filter(|e| !self.has_block(&e.digest))
                .count(),
        )?;
        let ordinal = self.packs.len();
        let next = self
            .offset
            .checked_add(u64::from(len))
            .ok_or(Errno::EFBIG)?;
        self.packs.insert(digest, (self.offset, len, ordinal));
        self.offset = next;
        for entry in &built.entries {
            self.blocks
                .entry(entry.digest)
                .or_insert((ordinal as u32, entry.offset, entry.len));
        }
        Ok(true)
    }

    pub fn record_node(&mut self, digest: Digest, bytes: &[u8]) -> Result<Option<[u8; 4]>> {
        if bytes.len() > NODE_MAX_BYTES {
            return Err(Errno::EFBIG);
        }
        if self.has_node(&digest) {
            return Ok(None);
        }
        self.check_entry_budget(1)?;
        let len = bytes.len() as u32;
        let offset = self.offset.checked_add(4).ok_or(Errno::EFBIG)?;
        self.offset = offset.checked_add(u64::from(len)).ok_or(Errno::EFBIG)?;
        self.nodes.insert(digest, (offset, len));
        Ok(Some(len.to_be_bytes()))
    }

    /// Emit bounded index pages followed by the authenticated footer.
    pub fn finish_chunks(self, root: Digest) -> Result<impl Iterator<Item = Vec<u8>>> {
        use sha2::{Digest as _, Sha256};
        if !self.has_node(&root) {
            return Err(Errno::EINVAL);
        }
        let mut ordinals = vec![0u32; self.packs.len()];
        for (index, &(_, _, ordinal)) in self.packs.values().enumerate() {
            ordinals[ordinal] = index as u32;
        }
        fn count(n: usize) -> (usize, [u8; ROW_BYTES]) {
            let mut row = [0; ROW_BYTES];
            row[..4].copy_from_slice(&(n as u32).to_be_bytes());
            (4, row)
        }
        fn record(digest: Digest, offset: u64, len: u32) -> (usize, [u8; ROW_BYTES]) {
            let mut row = [0; ROW_BYTES];
            row[..32].copy_from_slice(&digest);
            row[32..40].copy_from_slice(&offset.to_be_bytes());
            row[40..].copy_from_slice(&len.to_be_bytes());
            (ROW_BYTES, row)
        }
        let packs = std::iter::once(count(self.packs.len())).chain(
            self.packs
                .into_iter()
                .map(|(d, (off, len, _))| record(d, off, len)),
        );
        let blocks = std::iter::once(count(self.blocks.len())).chain(self.blocks.into_iter().map(
            move |(d, (ordinal, off, len))| {
                let packed_offset = (u64::from(ordinals[ordinal as usize]) << 32) | u64::from(off);
                record(d, packed_offset, len)
            },
        ));
        let nodes = std::iter::once(count(self.nodes.len())).chain(
            self.nodes
                .into_iter()
                .map(|(d, (off, len))| record(d, off, len)),
        );
        let mut rows = packs.chain(blocks).chain(nodes);
        let mut hash = Some(Sha256::new());
        let mut len = 0u64;
        Ok(std::iter::from_fn(move || {
            let hasher = hash.as_mut()?;
            let mut page = Vec::with_capacity(INDEX_PAGE);
            while page.len() <= INDEX_PAGE - ROW_BYTES {
                let Some((size, row)) = rows.next() else {
                    break;
                };
                page.extend_from_slice(&row[..size]);
            }
            if !page.is_empty() {
                hasher.update(&page);
                len += page.len() as u64;
                return Some(page);
            }
            let mut footer = [0u8; ARCHIVE_FOOTER_BYTES];
            footer[..8].copy_from_slice(&ARCHIVE_FOOTER_MAGIC);
            footer[8..10].copy_from_slice(&ARCHIVE_VERSION.to_be_bytes());
            footer[16..24].copy_from_slice(&self.offset.to_be_bytes());
            footer[24..32].copy_from_slice(&len.to_be_bytes());
            footer[32..64].copy_from_slice(&root);
            footer[64..].copy_from_slice(&hash.take()?.finalize());
            Some(footer.to_vec())
        }))
    }

    /// Collect the index for callers that need its contiguous wire representation.
    pub fn finish(self, root: Digest) -> Result<(Vec<u8>, [u8; ARCHIVE_FOOTER_BYTES])> {
        let mut chunks = self.finish_chunks(root)?.peekable();
        let mut bytes = Vec::new();
        while let Some(page) = chunks.next() {
            if chunks.peek().is_none() {
                return Ok((bytes, page.try_into().map_err(|_| Errno::EIO)?));
            }
            bytes.extend(page);
        }
        Err(Errno::EIO)
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
        let be = vfs::now_or_never(index.find_block(&reader, &block_dig))
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(be.block_len as usize, block.len());
        let ne = vfs::now_or_never(index.find_node(&reader, &root_dig))
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            &raw[ne.offset as usize..ne.offset as usize + ne.len as usize],
            root_node.as_slice()
        );

        // Bit-flip in index fails SHA-256 verification with EIO.
        let mut corrupt_idx = raw.clone();
        corrupt_idx[footer.index_offset as usize] ^= 0x01;
        assert_eq!(
            vfs::now_or_never(open_archive_index(&VecReader(corrupt_idx)))
                .unwrap()
                .unwrap_err(),
            Errno::EIO
        );
    }
}
