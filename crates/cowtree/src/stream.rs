//! Merkle Delta Stream v1 (`OSCOWS1\0`) deterministic framing encoder, incremental SHA-256
//! verified decoder, and bounded memory helpers (`docs/architecture/contract.md` §2.15, #79).
//!
//! Wire format (big-endian integers):
//! 1. Header:
//!    `magic[8] ("OSCOWS1\0") || version[2] (1) || flags[2] || source_vol_len[2] (<= 256) ||`
//!    `source_vol[len] || parent_root[32] || target_root[32]`
//!    (`flags & 1 != 0` iff incremental `parent_root` is present; otherwise `parent_root == [0; 32]`).
//! 2. Canonical post-order records (blocks -> leaf nodes -> internal nodes -> `RootObject`):
//!    `frame_type[1] || body_len[4] || body[body_len]`
//!    - `0x01 NODE`: `digest[32] || node_bytes` (`node_bytes.len() <= NODE_MAX_BYTES`)
//!    - `0x02 BLOCK`: `digest[32] || block_bytes` (`block_bytes.len() <= EXTENT_MAX_BYTES`)
//!    - `0xFF END`: `stream_sha256[32] || node_count[8] || block_count[8]` (`body_len == 48`)
//!
//! `stream_sha256` covers every byte of the header and every `NODE`/`BLOCK` frame header+body
//! prior to the `END` frame.

use crate::store::Digest;
use crate::{EXTENT_MAX_BYTES, NODE_MAX_BYTES, sha256};
use abi::Errno;
use sha2::{Digest as _, Sha256};
use std::collections::VecDeque;
use vfs::Result;

/// Magic header for Merkle Delta Stream v1 (`OSCOWS1\0`).
pub const STREAM_MAGIC: [u8; 8] = *b"OSCOWS1\0";
/// Protocol version for Merkle Delta Stream v1.
pub const STREAM_VERSION: u16 = 1;
/// Header flag bit 0: incremental stream carrying a non-zero `parent_root` digest.
pub const STREAM_FLAG_INCREMENTAL: u16 = 1 << 0;
/// Maximum UTF-8 byte length of `source_volume` in the stream header.
pub const STREAM_MAX_VOL_LEN: usize = 256;
/// Bounded I/O transfer chunk size (`64 KiB`) keeping Wasm peak memory well under 32 MiB.
pub const STREAM_CHUNK_BYTES: usize = 64 * 1024;

/// Frame type: `NODE` (`digest[32] || node_bytes`).
pub const FRAME_NODE: u8 = 0x01;
/// Frame type: `BLOCK` (`digest[32] || block_bytes`).
pub const FRAME_BLOCK: u8 = 0x02;
/// Frame type: `END` (`stream_sha256[32] || node_count[8] || block_count[8]`).
pub const FRAME_END: u8 = 0xFF;

const FRAME_HEADER_BYTES: usize = 5;
const END_BODY_BYTES: usize = 48;
const HEADER_PREFIX_BYTES: usize = 14; // magic(8) + version(2) + flags(2) + vol_len(2)
const HEADER_DIGESTS_BYTES: usize = 64; // parent_root(32) + target_root(32)

/// Parsed header of an `OSCOWS1\0` Merkle delta stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamHeader {
    pub version: u16,
    pub flags: u16,
    pub source_volume: String,
    pub parent_root: Option<Digest>,
    pub target_root: Digest,
}

impl StreamHeader {
    pub fn full(source_volume: impl Into<String>, target_root: Digest) -> Self {
        Self {
            version: STREAM_VERSION,
            flags: 0,
            source_volume: source_volume.into(),
            parent_root: None,
            target_root,
        }
    }

    pub fn incremental(
        source_volume: impl Into<String>,
        parent_root: Digest,
        target_root: Digest,
    ) -> Self {
        Self {
            version: STREAM_VERSION,
            flags: STREAM_FLAG_INCREMENTAL,
            source_volume: source_volume.into(),
            parent_root: Some(parent_root),
            target_root,
        }
    }

    pub fn is_incremental(&self) -> bool {
        (self.flags & STREAM_FLAG_INCREMENTAL) != 0
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.version != STREAM_VERSION {
            return Err(Errno::EPROTONOSUPPORT);
        }
        if (self.flags & !STREAM_FLAG_INCREMENTAL) != 0 {
            return Err(Errno::EINVAL);
        }
        let vol_bytes = self.source_volume.as_bytes();
        if vol_bytes.len() > STREAM_MAX_VOL_LEN {
            return Err(Errno::EINVAL);
        }
        let parent_bytes = match (self.is_incremental(), self.parent_root) {
            (true, Some(p)) if p != [0u8; 32] => p,
            (false, None) => [0u8; 32],
            _ => return Err(Errno::EINVAL),
        };
        let mut out =
            Vec::with_capacity(HEADER_PREFIX_BYTES + vol_bytes.len() + HEADER_DIGESTS_BYTES);
        out.extend_from_slice(&STREAM_MAGIC);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&(vol_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(vol_bytes);
        out.extend_from_slice(&parent_bytes);
        out.extend_from_slice(&self.target_root);
        Ok(out)
    }
}

/// Streaming encoder maintaining the running SHA-256 over all pre-`END` bytes.
#[derive(Clone)]
pub struct StreamEncoder {
    hasher: Sha256,
    header_written: bool,
    finished: bool,
    bytes_written: u64,
    node_count: u64,
    block_count: u64,
}

impl Default for StreamEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamEncoder {
    pub fn new() -> Self {
        Self {
            hasher: Sha256::new(),
            header_written: false,
            finished: false,
            bytes_written: 0,
            node_count: 0,
            block_count: 0,
        }
    }

    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    pub fn node_count(&self) -> u64 {
        self.node_count
    }

    pub fn block_count(&self) -> u64 {
        self.block_count
    }

    pub fn encode_header(&mut self, header: &StreamHeader) -> Result<Vec<u8>> {
        if self.header_written || self.finished {
            return Err(Errno::EINVAL);
        }
        let bytes = header.encode()?;
        self.hasher.update(&bytes);
        self.bytes_written = self.bytes_written.saturating_add(bytes.len() as u64);
        self.header_written = true;
        Ok(bytes)
    }

    pub fn encode_node(&mut self, digest: &Digest, node_bytes: &[u8]) -> Result<Vec<u8>> {
        if !self.header_written || self.finished {
            return Err(Errno::EINVAL);
        }
        if node_bytes.len() > NODE_MAX_BYTES {
            return Err(Errno::EFBIG);
        }
        let body_len = u32::try_from(32 + node_bytes.len()).map_err(|_| Errno::EFBIG)?;
        let mut out = Vec::with_capacity(FRAME_HEADER_BYTES + body_len as usize);
        out.push(FRAME_NODE);
        out.extend_from_slice(&body_len.to_be_bytes());
        out.extend_from_slice(digest);
        out.extend_from_slice(node_bytes);
        self.hasher.update(&out);
        self.bytes_written = self.bytes_written.saturating_add(out.len() as u64);
        self.node_count = self.node_count.saturating_add(1);
        Ok(out)
    }

    pub fn encode_block(&mut self, digest: &Digest, block_bytes: &[u8]) -> Result<Vec<u8>> {
        if !self.header_written || self.finished {
            return Err(Errno::EINVAL);
        }
        if block_bytes.len() > EXTENT_MAX_BYTES as usize {
            return Err(Errno::EFBIG);
        }
        let body_len = u32::try_from(32 + block_bytes.len()).map_err(|_| Errno::EFBIG)?;
        let mut out = Vec::with_capacity(FRAME_HEADER_BYTES + body_len as usize);
        out.push(FRAME_BLOCK);
        out.extend_from_slice(&body_len.to_be_bytes());
        out.extend_from_slice(digest);
        out.extend_from_slice(block_bytes);
        self.hasher.update(&out);
        self.bytes_written = self.bytes_written.saturating_add(out.len() as u64);
        self.block_count = self.block_count.saturating_add(1);
        Ok(out)
    }

    pub fn encode_end(&mut self) -> Result<Vec<u8>> {
        if !self.header_written || self.finished {
            return Err(Errno::EINVAL);
        }
        self.finished = true;
        let digest = self.hasher.clone().finalize();
        let mut out = Vec::with_capacity(FRAME_HEADER_BYTES + END_BODY_BYTES);
        out.push(FRAME_END);
        out.extend_from_slice(&(END_BODY_BYTES as u32).to_be_bytes());
        out.extend_from_slice(&digest);
        out.extend_from_slice(&self.node_count.to_be_bytes());
        out.extend_from_slice(&self.block_count.to_be_bytes());
        self.bytes_written = self.bytes_written.saturating_add(out.len() as u64);
        Ok(out)
    }
}

/// Verified event emitted by [`StreamDecoder`] as chunks arrive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamEvent {
    Header(StreamHeader),
    Node {
        digest: Digest,
        bytes: Vec<u8>,
    },
    Block {
        digest: Digest,
        bytes: Vec<u8>,
    },
    End {
        stream_sha256: Digest,
        node_count: u64,
        block_count: u64,
    },
}

enum DecodeState {
    HeaderPrefix,
    HeaderRest {
        version: u16,
        flags: u16,
        vol_len: usize,
    },
    FrameHeader,
    FrameBody {
        frame_type: u8,
        body_len: usize,
    },
    Ended,
}

/// Incremental streaming `OSCOWS1\0` decoder verifying every frame bound, SHA-256 object digest,
/// running stream SHA-256, object counts, and strict EOF (no truncation, no trailing garbage).
pub struct StreamDecoder {
    state: DecodeState,
    buf: Vec<u8>,
    read_pos: usize,
    hasher: Sha256,
    seen_nodes: u64,
    seen_blocks: u64,
    bytes_read: u64,
    events: VecDeque<StreamEvent>,
}

impl Default for StreamDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamDecoder {
    pub fn new() -> Self {
        Self {
            state: DecodeState::HeaderPrefix,
            buf: Vec::new(),
            read_pos: 0,
            hasher: Sha256::new(),
            seen_nodes: 0,
            seen_blocks: 0,
            bytes_read: 0,
            events: VecDeque::new(),
        }
    }

    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    pub fn is_ended(&self) -> bool {
        matches!(self.state, DecodeState::Ended)
    }

    fn available(&self) -> &[u8] {
        &self.buf[self.read_pos..]
    }

    fn consume(&mut self, n: usize) {
        self.read_pos += n;
        if self.read_pos == self.buf.len() {
            self.buf.clear();
            self.read_pos = 0;
        } else if self.read_pos >= STREAM_CHUNK_BYTES {
            self.buf.drain(..self.read_pos);
            self.read_pos = 0;
        }
    }

    /// Feed a bounded chunk of raw bytes into the decoder. Call [`Self::next_event`] to drain
    /// verified frames before feeding the next chunk.
    pub fn feed(&mut self, chunk: &[u8]) -> Result<()> {
        if chunk.is_empty() {
            return Ok(());
        }
        if matches!(self.state, DecodeState::Ended) {
            return Err(Errno::EIO);
        }
        self.bytes_read = self.bytes_read.saturating_add(chunk.len() as u64);
        self.buf.extend_from_slice(chunk);

        loop {
            match self.state {
                DecodeState::HeaderPrefix => {
                    if self.available().len() < HEADER_PREFIX_BYTES {
                        return Ok(());
                    }
                    let prefix = self.available()[..HEADER_PREFIX_BYTES].to_vec();
                    if prefix[0..8] != STREAM_MAGIC {
                        return Err(Errno::EPROTONOSUPPORT);
                    }
                    let version = u16::from_be_bytes([prefix[8], prefix[9]]);
                    if version != STREAM_VERSION {
                        return Err(Errno::EPROTONOSUPPORT);
                    }
                    let flags = u16::from_be_bytes([prefix[10], prefix[11]]);
                    if (flags & !STREAM_FLAG_INCREMENTAL) != 0 {
                        return Err(Errno::EPROTONOSUPPORT);
                    }
                    let vol_len = u16::from_be_bytes([prefix[12], prefix[13]]) as usize;
                    if vol_len > STREAM_MAX_VOL_LEN {
                        return Err(Errno::EIO);
                    }
                    self.hasher.update(&prefix);
                    self.consume(HEADER_PREFIX_BYTES);
                    self.state = DecodeState::HeaderRest {
                        version,
                        flags,
                        vol_len,
                    };
                }
                DecodeState::HeaderRest {
                    version,
                    flags,
                    vol_len,
                } => {
                    let need = vol_len + HEADER_DIGESTS_BYTES;
                    if self.available().len() < need {
                        return Ok(());
                    }
                    let rest = self.available()[..need].to_vec();
                    let source_volume = std::str::from_utf8(&rest[..vol_len])
                        .map_err(|_| Errno::EIO)?
                        .to_string();
                    let mut parent_raw = [0u8; 32];
                    parent_raw.copy_from_slice(&rest[vol_len..vol_len + 32]);
                    let mut target_root = [0u8; 32];
                    target_root.copy_from_slice(&rest[vol_len + 32..vol_len + 64]);
                    let incremental = (flags & STREAM_FLAG_INCREMENTAL) != 0;
                    let parent_root = if incremental {
                        if parent_raw == [0u8; 32] {
                            return Err(Errno::EIO);
                        }
                        Some(parent_raw)
                    } else {
                        if parent_raw != [0u8; 32] {
                            return Err(Errno::EIO);
                        }
                        None
                    };
                    self.hasher.update(&rest);
                    self.consume(need);
                    self.events.push_back(StreamEvent::Header(StreamHeader {
                        version,
                        flags,
                        source_volume,
                        parent_root,
                        target_root,
                    }));
                    self.state = DecodeState::FrameHeader;
                }
                DecodeState::FrameHeader => {
                    if self.available().len() < FRAME_HEADER_BYTES {
                        return Ok(());
                    }
                    let hdr = [
                        self.available()[0],
                        self.available()[1],
                        self.available()[2],
                        self.available()[3],
                        self.available()[4],
                    ];
                    let frame_type = hdr[0];
                    let body_len = u32::from_be_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]) as usize;
                    match frame_type {
                        FRAME_NODE => {
                            if !(32..=32 + NODE_MAX_BYTES).contains(&body_len) {
                                return Err(Errno::EIO);
                            }
                            self.hasher.update(hdr);
                        }
                        FRAME_BLOCK => {
                            if !(32..=32 + EXTENT_MAX_BYTES as usize).contains(&body_len) {
                                return Err(Errno::EIO);
                            }
                            self.hasher.update(hdr);
                        }
                        FRAME_END => {
                            if body_len != END_BODY_BYTES {
                                return Err(Errno::EIO);
                            }
                            // END frame is NOT hashed into stream_sha256.
                        }
                        _ => return Err(Errno::EIO),
                    }
                    self.consume(FRAME_HEADER_BYTES);
                    self.state = DecodeState::FrameBody {
                        frame_type,
                        body_len,
                    };
                }
                DecodeState::FrameBody {
                    frame_type,
                    body_len,
                } => {
                    if self.available().len() < body_len {
                        return Ok(());
                    }
                    let body = self.available()[..body_len].to_vec();
                    self.consume(body_len);
                    match frame_type {
                        FRAME_NODE => {
                            self.hasher.update(&body);
                            let mut digest = [0u8; 32];
                            digest.copy_from_slice(&body[..32]);
                            let payload = body[32..].to_vec();
                            if sha256(&payload) != digest {
                                return Err(Errno::EIO);
                            }
                            self.seen_nodes = self.seen_nodes.saturating_add(1);
                            self.events.push_back(StreamEvent::Node {
                                digest,
                                bytes: payload,
                            });
                            self.state = DecodeState::FrameHeader;
                        }
                        FRAME_BLOCK => {
                            self.hasher.update(&body);
                            let mut digest = [0u8; 32];
                            digest.copy_from_slice(&body[..32]);
                            let payload = body[32..].to_vec();
                            if sha256(&payload) != digest {
                                return Err(Errno::EIO);
                            }
                            self.seen_blocks = self.seen_blocks.saturating_add(1);
                            self.events.push_back(StreamEvent::Block {
                                digest,
                                bytes: payload,
                            });
                            self.state = DecodeState::FrameHeader;
                        }
                        FRAME_END => {
                            let mut expected_sha = [0u8; 32];
                            expected_sha.copy_from_slice(&body[..32]);
                            let node_count = u64::from_be_bytes(body[32..40].try_into().unwrap());
                            let block_count = u64::from_be_bytes(body[40..48].try_into().unwrap());
                            let actual_out = self.hasher.clone().finalize();
                            let mut actual_sha = [0u8; 32];
                            actual_sha.copy_from_slice(&actual_out);
                            if actual_sha != expected_sha
                                || node_count != self.seen_nodes
                                || block_count != self.seen_blocks
                            {
                                return Err(Errno::EIO);
                            }
                            self.events.push_back(StreamEvent::End {
                                stream_sha256: expected_sha,
                                node_count,
                                block_count,
                            });
                            self.state = DecodeState::Ended;
                            if !self.available().is_empty() {
                                return Err(Errno::EIO);
                            }
                            return Ok(());
                        }
                        _ => return Err(Errno::EIO),
                    }
                }
                DecodeState::Ended => {
                    if !self.available().is_empty() {
                        return Err(Errno::EIO);
                    }
                    return Ok(());
                }
            }
        }
    }

    pub fn next_event(&mut self) -> Option<StreamEvent> {
        self.events.pop_front()
    }

    /// Validate that EOF occurred cleanly immediately after a verified `END` frame.
    pub fn finish(&self) -> Result<()> {
        if !matches!(self.state, DecodeState::Ended) || !self.available().is_empty() {
            return Err(Errno::EIO);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_roundtrip_arbitrary_chunk_boundaries_and_bitflip_rejection() {
        let block = vec![0x42u8; 4096];
        let block_digest = sha256(&block);
        let node = b"COWN-test-node".to_vec();
        let node_digest = sha256(&node);
        let hdr = StreamHeader::incremental("vol-src", [0x11; 32], node_digest);

        let mut enc = StreamEncoder::new();
        let mut wire = Vec::new();
        wire.extend_from_slice(&enc.encode_header(&hdr).unwrap());
        wire.extend_from_slice(&enc.encode_block(&block_digest, &block).unwrap());
        wire.extend_from_slice(&enc.encode_node(&node_digest, &node).unwrap());
        wire.extend_from_slice(&enc.encode_end().unwrap());
        assert_eq!(enc.bytes_written() as usize, wire.len());

        // Decode in tiny 13-byte chunks to stress incremental framing across boundaries.
        let mut dec = StreamDecoder::new();
        let mut events = Vec::new();
        for ch in wire.chunks(13) {
            dec.feed(ch).unwrap();
            while let Some(ev) = dec.next_event() {
                events.push(ev);
            }
        }
        dec.finish().unwrap();
        assert_eq!(events.len(), 4);
        assert_eq!(events[0], StreamEvent::Header(hdr));
        assert_eq!(
            events[1],
            StreamEvent::Block {
                digest: block_digest,
                bytes: block
            }
        );
        assert_eq!(
            events[2],
            StreamEvent::Node {
                digest: node_digest,
                bytes: node
            }
        );
        assert!(matches!(
            events[3],
            StreamEvent::End {
                node_count: 1,
                block_count: 1,
                ..
            }
        ));

        // Truncation -> EIO.
        let mut trunc = StreamDecoder::new();
        let _ = trunc.feed(&wire[..wire.len() - 1]);
        assert_eq!(trunc.finish(), Err(Errno::EIO));

        // Trailing garbage -> EIO.
        let mut trailing = wire.clone();
        trailing.push(0x00);
        let mut dec2 = StreamDecoder::new();
        assert_eq!(dec2.feed(&trailing), Err(Errno::EIO));

        // Flipping any byte after magic/version/flags triggers EIO (or EPROTONOSUPPORT on magic).
        for pos in [0, 8, 20, wire.len() / 2, wire.len() - 5] {
            let mut bad = wire.clone();
            bad[pos] ^= 0x01;
            let mut dec_bad = StreamDecoder::new();
            let res = dec_bad.feed(&bad).and_then(|()| dec_bad.finish());
            assert!(res.is_err(), "bit-flip at offset {pos} must fail");
        }
    }
}
