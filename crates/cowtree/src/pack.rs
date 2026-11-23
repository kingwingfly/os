//! Immutable `<= 8 MiB` `COWP` pack encoder, trailer decoder, and block SHA-256 verification.
//!
//! Binary layout:
//! - `[0..payload_end]`: concatenated raw block payloads (each `<= 1 MiB`)
//! - `[payload_end..trailer_end]`: trailer index:
//!   `magic[4] ("COWP") || version[2] (1 BE) || count[4] (BE) || entries[count * 46]`
//!   where each entry is `digest[32] || offset[4] || len[4] || raw_len[4] || flags[2]`.
//! - `[trailer_end..pack_end]` (40-byte footer):
//!   `trailer_len[4] (BE) || trailer_sha256[32] || footer_magic[4] ("COWP")`.

use crate::store::{BlockLoc, Digest, PackId, PackIndexEntry, PackTrailer};
use crate::{EXTENT_MAX_BYTES, PACK_MAGIC, PACK_MAX_BYTES, PACK_VERSION, digest_to_hex, sha256};
use abi::Errno;
use std::collections::HashMap;
use vfs::Result;

pub const PACK_TRAILER_HEADER_BYTES: usize = 10;
pub const PACK_INDEX_ENTRY_BYTES: usize = 46;
pub const PACK_FOOTER_BYTES: usize = 40;

/// Verify `sha256(bytes) == expected` BEFORE exposing block bytes (`Errno::EIO` on corruption).
pub fn verify_block_digest(expected: &Digest, bytes: &[u8]) -> Result<()> {
    if &sha256(bytes) != expected {
        return Err(Errno::EIO);
    }
    Ok(())
}

/// Shared v1 pack entry validation enforced across [`PackBuilder`], [`encode_pack`], and
/// [`decode_pack_trailer_bytes`]: `len <= EXTENT_MAX_BYTES` (`1 MiB`), `raw_len == len`, and
/// `flags == 0` (raw uncompressed layout in v1).
pub fn validate_v1_pack_entry(
    entry: &PackIndexEntry,
    oversize_err: Errno,
    invalid_err: Errno,
) -> Result<()> {
    if entry.len > EXTENT_MAX_BYTES || entry.raw_len > EXTENT_MAX_BYTES {
        return Err(oversize_err);
    }
    if entry.flags != 0 || entry.raw_len != entry.len {
        return Err(invalid_err);
    }
    Ok(())
}

/// Sealed immutable pack ready to be written once to [`crate::PackStore`].
#[derive(Clone, Debug)]
pub struct BuiltPack {
    pub pack_id: PackId,
    pub bytes: Vec<u8>,
    pub entries: Vec<PackIndexEntry>,
    pub locations: Vec<(Digest, BlockLoc)>,
}

/// Accumulates content-addressed blocks and flushes them into one or more immutable `<= 8 MiB`
/// `COWP` packs with intra-batch deduplication.
#[derive(Default)]
pub struct PackBuilder {
    payload: Vec<u8>,
    entries: Vec<PackIndexEntry>,
    seen: HashMap<Digest, usize>,
    finished: Vec<BuiltPack>,
    streaming: bool,
}

impl PackBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Limit the working set of a long-running transfer, including the per-block index.
    /// The caller deduplicates blocks in already published packs.
    pub fn streaming() -> Self {
        Self {
            streaming: true,
            ..Self::default()
        }
    }

    pub fn contains(&self, digest: &Digest) -> bool {
        self.seen.contains_key(digest)
    }

    fn current_encoded_size(&self) -> usize {
        self.payload.len()
            + PACK_TRAILER_HEADER_BYTES
            + self.entries.len() * PACK_INDEX_ENTRY_BYTES
            + PACK_FOOTER_BYTES
    }

    /// Add one raw block (`bytes.len() <= 1 MiB`) with its precomputed `digest`.
    /// Splits into a new pack automatically when adding would exceed `PACK_MAX_BYTES` (`8 MiB`).
    pub fn push(&mut self, digest: Digest, bytes: &[u8]) -> Result<()> {
        if bytes.len() > EXTENT_MAX_BYTES as usize {
            return Err(Errno::EFBIG);
        }
        if self.seen.contains_key(&digest) {
            return Ok(());
        }
        let added = bytes.len() + PACK_INDEX_ENTRY_BYTES;
        let limit = if self.streaming {
            2 * 1024 * 1024
        } else {
            PACK_MAX_BYTES
        };
        if !self.entries.is_empty()
            && (self.current_encoded_size() + added > limit
                || self.streaming && self.entries.len() >= 1024)
        {
            self.seal_current()?;
        }
        if self.current_encoded_size() + added > PACK_MAX_BYTES {
            return Err(Errno::EFBIG);
        }
        let offset = u32::try_from(self.payload.len()).map_err(|_| Errno::EFBIG)?;
        let len = u32::try_from(bytes.len()).map_err(|_| Errno::EFBIG)?;
        self.payload.extend_from_slice(bytes);
        let idx = self.entries.len();
        self.entries.push(PackIndexEntry {
            digest,
            offset,
            len,
            raw_len: len,
            flags: 0,
        });
        self.seen.insert(digest, idx);
        Ok(())
    }

    fn seal_current(&mut self) -> Result<()> {
        if self.entries.is_empty() {
            return Ok(());
        }
        let payload = std::mem::take(&mut self.payload);
        let entries = std::mem::take(&mut self.entries);
        if self.streaming {
            self.seen.clear();
        }
        let built = encode_pack_parts(payload, entries)?;
        self.finished.push(built);
        Ok(())
    }

    /// Drain any packs that were sealed by previous `push()` calls so streaming callers
    /// (`cowfs receive`, `.cowpack` export) can flush `<= 8 MiB` packs incrementally without
    /// buffering multiple packs in RAM.
    pub fn drain_finished(&mut self) -> Vec<BuiltPack> {
        std::mem::take(&mut self.finished)
    }

    /// Finalize all buffered blocks into immutable `<= 8 MiB` packs.
    pub fn finish(mut self) -> Result<Vec<BuiltPack>> {
        self.seal_current()?;
        Ok(self.finished)
    }
}

/// Encode a slice of `(digest, raw_bytes)` blocks into a single `<= 8 MiB` pack.
pub fn encode_pack(blocks: &[(Digest, Vec<u8>)]) -> Result<BuiltPack> {
    let mut payload = Vec::new();
    let mut entries = Vec::with_capacity(blocks.len());
    for (digest, bytes) in blocks {
        if bytes.len() > EXTENT_MAX_BYTES as usize {
            return Err(Errno::EFBIG);
        }
        let offset = u32::try_from(payload.len()).map_err(|_| Errno::EFBIG)?;
        let len = u32::try_from(bytes.len()).map_err(|_| Errno::EFBIG)?;
        let entry = PackIndexEntry {
            digest: *digest,
            offset,
            len,
            raw_len: len,
            flags: 0,
        };
        validate_v1_pack_entry(&entry, Errno::EFBIG, Errno::EINVAL)?;
        payload.extend_from_slice(bytes);
        entries.push(entry);
    }
    encode_pack_parts(payload, entries)
}

fn encode_pack_parts(mut payload: Vec<u8>, entries: Vec<PackIndexEntry>) -> Result<BuiltPack> {
    let payload_limit = u32::try_from(payload.len()).map_err(|_| Errno::EFBIG)?;
    for entry in &entries {
        validate_v1_pack_entry(entry, Errno::EFBIG, Errno::EINVAL)?;
        let end = entry.offset.checked_add(entry.len).ok_or(Errno::EFBIG)?;
        if end > payload_limit {
            return Err(Errno::EINVAL);
        }
    }
    let trailer_len = PACK_TRAILER_HEADER_BYTES + entries.len() * PACK_INDEX_ENTRY_BYTES;
    let total_len = payload.len() + trailer_len + PACK_FOOTER_BYTES;
    if total_len > PACK_MAX_BYTES {
        return Err(Errno::EFBIG);
    }
    let mut trailer = Vec::with_capacity(trailer_len);
    trailer.extend_from_slice(&PACK_MAGIC);
    trailer.extend_from_slice(&PACK_VERSION.to_be_bytes());
    let count = u32::try_from(entries.len()).map_err(|_| Errno::EFBIG)?;
    trailer.extend_from_slice(&count.to_be_bytes());
    for entry in &entries {
        trailer.extend_from_slice(&entry.digest);
        trailer.extend_from_slice(&entry.offset.to_be_bytes());
        trailer.extend_from_slice(&entry.len.to_be_bytes());
        trailer.extend_from_slice(&entry.raw_len.to_be_bytes());
        trailer.extend_from_slice(&entry.flags.to_be_bytes());
    }
    let trailer_sha256 = sha256(&trailer);
    let trailer_len_u32 = u32::try_from(trailer.len()).map_err(|_| Errno::EFBIG)?;

    payload.reserve(trailer.len() + PACK_FOOTER_BYTES);
    payload.extend_from_slice(&trailer);
    payload.extend_from_slice(&trailer_len_u32.to_be_bytes());
    payload.extend_from_slice(&trailer_sha256);
    payload.extend_from_slice(&PACK_MAGIC);

    let pack_digest = sha256(&payload);
    let pack_id = PackId(digest_to_hex(&pack_digest));
    let locations = entries
        .iter()
        .map(|e| {
            (
                e.digest,
                BlockLoc {
                    pack_id: pack_id.clone(),
                    offset: e.offset,
                    len: e.len,
                    raw_len: e.raw_len,
                    flags: e.flags,
                },
            )
        })
        .collect();

    Ok(BuiltPack {
        pack_id,
        bytes: payload,
        entries,
        locations,
    })
}

/// Parse the 40-byte footer at the end of a pack file, returning `(trailer_len, trailer_sha256)`.
pub fn decode_pack_footer(footer: &[u8]) -> Result<(u32, Digest)> {
    if footer.len() != PACK_FOOTER_BYTES {
        return Err(Errno::EIO);
    }
    if footer[36..40] != PACK_MAGIC {
        return Err(Errno::EIO);
    }
    let trailer_len = u32::from_be_bytes([footer[0], footer[1], footer[2], footer[3]]);
    let mut trailer_sha256 = [0u8; 32];
    trailer_sha256.copy_from_slice(&footer[4..36]);
    if (trailer_len as usize) < PACK_TRAILER_HEADER_BYTES || (trailer_len as usize) > PACK_MAX_BYTES
    {
        return Err(Errno::EIO);
    }
    Ok((trailer_len, trailer_sha256))
}

/// Decode and SHA-256 verify a pack trailer section against `expected_sha256` from the footer.
pub fn decode_pack_trailer_bytes(
    trailer_bytes: &[u8],
    expected_sha256: Digest,
    payload_limit: u32,
) -> Result<PackTrailer> {
    if sha256(trailer_bytes) != expected_sha256 {
        return Err(Errno::EIO);
    }
    if trailer_bytes.len() < PACK_TRAILER_HEADER_BYTES {
        return Err(Errno::EIO);
    }
    let mut magic = [0u8; 4];
    magic.copy_from_slice(&trailer_bytes[0..4]);
    if magic != PACK_MAGIC {
        return Err(Errno::EIO);
    }
    let version = u16::from_be_bytes([trailer_bytes[4], trailer_bytes[5]]);
    if version != PACK_VERSION {
        return Err(Errno::EPROTONOSUPPORT);
    }
    let count = u32::from_be_bytes([
        trailer_bytes[6],
        trailer_bytes[7],
        trailer_bytes[8],
        trailer_bytes[9],
    ]) as usize;
    let expected_len = PACK_TRAILER_HEADER_BYTES
        .checked_add(
            count
                .checked_mul(PACK_INDEX_ENTRY_BYTES)
                .ok_or(Errno::EIO)?,
        )
        .ok_or(Errno::EIO)?;
    if trailer_bytes.len() != expected_len {
        return Err(Errno::EIO);
    }
    let mut entries = Vec::with_capacity(count.min(4096));
    let mut cursor = PACK_TRAILER_HEADER_BYTES;
    for _ in 0..count {
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&trailer_bytes[cursor..cursor + 32]);
        cursor += 32;
        let offset = u32::from_be_bytes(trailer_bytes[cursor..cursor + 4].try_into().unwrap());
        cursor += 4;
        let len = u32::from_be_bytes(trailer_bytes[cursor..cursor + 4].try_into().unwrap());
        cursor += 4;
        let raw_len = u32::from_be_bytes(trailer_bytes[cursor..cursor + 4].try_into().unwrap());
        cursor += 4;
        let flags = u16::from_be_bytes(trailer_bytes[cursor..cursor + 2].try_into().unwrap());
        cursor += 2;
        let entry = PackIndexEntry {
            digest,
            offset,
            len,
            raw_len,
            flags,
        };
        validate_v1_pack_entry(&entry, Errno::EIO, Errno::EIO)?;
        let end = offset.checked_add(len).ok_or(Errno::EIO)?;
        if end > payload_limit {
            return Err(Errno::EIO);
        }
        entries.push(entry);
    }
    Ok(PackTrailer {
        magic,
        version,
        entries,
        trailer_sha256: expected_sha256,
    })
}

/// Decode and verify the trailer from a complete pack buffer.
pub fn decode_pack_trailer(pack_bytes: &[u8]) -> Result<PackTrailer> {
    if pack_bytes.len() < PACK_TRAILER_HEADER_BYTES + PACK_FOOTER_BYTES
        || pack_bytes.len() > PACK_MAX_BYTES
    {
        return Err(Errno::EIO);
    }
    let footer_start = pack_bytes.len() - PACK_FOOTER_BYTES;
    let (trailer_len, trailer_sha) = decode_pack_footer(&pack_bytes[footer_start..])?;
    let trailer_start = footer_start
        .checked_sub(trailer_len as usize)
        .ok_or(Errno::EIO)?;
    let payload_limit = u32::try_from(trailer_start).map_err(|_| Errno::EIO)?;
    decode_pack_trailer_bytes(
        &pack_bytes[trailer_start..footer_start],
        trailer_sha,
        payload_limit,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_builder_splits_at_8mib_and_verifies_trailer() {
        let mut builder = PackBuilder::new();
        // Push 130 distinct 64 KiB blocks (> 8 MiB) -> must split into 2 packs <= 8 MiB each.
        for i in 0u32..130 {
            let mut block = vec![0u8; 64 * 1024];
            block[0..4].copy_from_slice(&i.to_le_bytes());
            let digest = sha256(&block);
            builder.push(digest, &block).unwrap();
        }
        let packs = builder.finish().unwrap();
        assert_eq!(packs.len(), 2);
        for p in &packs {
            assert!(p.bytes.len() <= PACK_MAX_BYTES);
            let trailer = decode_pack_trailer(&p.bytes).unwrap();
            assert_eq!(trailer.entries.len(), p.entries.len());
            assert_eq!(trailer.magic, PACK_MAGIC);
            assert_eq!(trailer.version, PACK_VERSION);
        }
        // Bit-flip in trailer fails verification with EIO.
        let mut corrupt = packs[0].bytes.clone();
        let idx = corrupt.len() - PACK_FOOTER_BYTES - 1;
        corrupt[idx] ^= 0x80;
        assert_eq!(decode_pack_trailer(&corrupt), Err(Errno::EIO));
    }
}
