//! Shared GUI Document surface message chunking and bounded reassembly.
//!
//! GUI v1 caps each `ClientReq::DocumentReply` and `InputEvent::DocumentMessage`
//! payload at `abi::gui::MAX_DOCUMENT_MESSAGE` (4096 UTF-8 bytes). Any Document
//! application (such as `/usr/bin/terminal` or `/usr/bin/files`) can reuse these
//! helpers to split larger JSON payloads at UTF-8 character boundaries while
//! accounting for JSON string escaping overhead.

use abi::gui::MAX_DOCUMENT_MESSAGE;
use serde::Deserialize;

/// Maximum wire size reserved for any single `DocumentReply` JSON payload.
pub const MAX_CHUNK_WIRE_BYTES: usize = MAX_DOCUMENT_MESSAGE - 64;

/// Hard upper bound on a reassembled chunked Document message (`256 KiB`).
pub const MAX_ASSEMBLED_DOCUMENT_BYTES: usize = 256 * 1024;

/// Maximum number of chunks allowed for a single assembled message.
const MAX_CHUNKS: usize = 256;

/// Split an arbitrary UTF-8 JSON payload into one or more wire frames, each strictly
/// `<= MAX_DOCUMENT_MESSAGE` (4096) UTF-8 bytes so `ClientReq::DocumentReply` never overflows.
pub fn chunk_document_message(seq: u64, payload: &str) -> Vec<String> {
    if payload.len() <= MAX_CHUNK_WIRE_BYTES {
        return vec![payload.to_owned()];
    }
    // Split on UTF-8 char boundaries while accounting for JSON escaping overhead of `d`.
    // Reserve generous room for envelope `{"t":"chunk","id":...,"i":...,"n":...,"d":"..."}` (~80 bytes).
    let max_encoded_d = MAX_CHUNK_WIRE_BYTES - 120;
    let mut slices: Vec<&str> = Vec::new();
    let mut start = 0usize;
    while start < payload.len() {
        let mut end = start;
        let mut encoded_len = 0usize;
        for (rel_idx, ch) in payload[start..].char_indices() {
            let char_json_len = match ch {
                '"' | '\\' | '\n' | '\r' | '\t' | '\x08' | '\x0c' => 2,
                c if (c as u32) < 0x20 => 6,
                c => c.len_utf8(),
            };
            if encoded_len + char_json_len > max_encoded_d && end > start {
                break;
            }
            encoded_len += char_json_len;
            end = start + rel_idx + ch.len_utf8();
        }
        if end == start {
            // Guaranteed progress for any single character.
            let ch = payload[start..].chars().next().unwrap();
            end = start + ch.len_utf8();
        }
        slices.push(&payload[start..end]);
        start = end;
    }

    let total = slices.len();
    slices
        .into_iter()
        .enumerate()
        .map(|(i, part)| {
            let frame = serde_json::json!({
                "t": "chunk",
                "id": seq,
                "i": i,
                "n": total,
                "d": part,
            })
            .to_string();
            debug_assert!(frame.len() <= MAX_DOCUMENT_MESSAGE);
            frame
        })
        .collect()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChunkEnvelope {
    t: String,
    id: u64,
    i: u32,
    n: u32,
    d: String,
}

/// Bounded assembler for `{"t":"chunk","id":u64,"i":u32,"n":u32,"d":"..."}` frames
/// with configurable payload and chunk limits (defaults to `256 KiB` / `256` chunks).
#[derive(Clone, Debug)]
pub struct DocChunkAssembler {
    id: u64,
    total: usize,
    parts: Vec<Option<String>>,
    received_bytes: usize,
    max_bytes: usize,
    max_chunks: usize,
}

impl Default for DocChunkAssembler {
    fn default() -> Self {
        Self::with_limits(MAX_ASSEMBLED_DOCUMENT_BYTES, MAX_CHUNKS)
    }
}

impl DocChunkAssembler {
    /// Construct a chunk assembler with explicit payload-byte and chunk-count bounds.
    pub fn with_limits(max_bytes: usize, max_chunks: usize) -> Self {
        Self {
            id: 0,
            total: 0,
            parts: Vec::new(),
            received_bytes: 0,
            max_bytes,
            max_chunks,
        }
    }

    /// Reset all partially received chunk state.
    pub fn reset(&mut self) {
        self.id = 0;
        self.total = 0;
        self.parts.clear();
        self.received_bytes = 0;
    }

    /// Push one chunk; returns the complete reassembled string once all `n` parts arrive.
    pub fn push(&mut self, id: u64, idx: u32, total: u32, data: String) -> Option<String> {
        let total = usize::try_from(total).ok()?;
        let idx = usize::try_from(idx).ok()?;
        if total == 0 || total > self.max_chunks || idx >= total {
            return None;
        }
        if self.id != id || self.total != total {
            self.id = id;
            self.total = total;
            self.parts = vec![None; total];
            self.received_bytes = 0;
        }
        if self.parts[idx].is_some() {
            return None;
        }
        if self.received_bytes.saturating_add(data.len()) > self.max_bytes {
            self.reset();
            return None;
        }
        self.received_bytes += data.len();
        self.parts[idx] = Some(data);
        if self.parts.iter().all(Option::is_some) {
            let mut out = String::with_capacity(self.received_bytes);
            for part in self.parts.drain(..).flatten() {
                out.push_str(&part);
            }
            self.total = 0;
            self.received_bytes = 0;
            return Some(out);
        }
        None
    }

    /// Feed a raw Document JSON frame: reassembles `{"t":"chunk",...}` envelopes and
    /// passes non-chunk frames through unchanged.
    pub fn feed(&mut self, raw: &str) -> Option<String> {
        if let Ok(env) = serde_json::from_str::<ChunkEnvelope>(raw)
            && env.t == "chunk"
        {
            return self.push(env.id, env.i, env.n, env.d);
        }
        Some(raw.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn chunk_and_reassemble_unicode_and_escapes() {
        let big = "\"\\界🚀\n".repeat(1500);
        let chunks = chunk_document_message(7, &big);
        assert!(chunks.len() > 2);
        let mut asm = DocChunkAssembler::default();
        let mut completed = None;
        for (idx, frame) in chunks.iter().enumerate() {
            assert!(
                frame.len() <= MAX_DOCUMENT_MESSAGE,
                "chunk {idx} exceeded {MAX_DOCUMENT_MESSAGE} bytes: {}",
                frame.len()
            );
            let parsed: Value = serde_json::from_str(frame).unwrap();
            assert_eq!(parsed["t"], "chunk");
            assert_eq!(parsed["id"], 7);
            assert_eq!(parsed["i"], idx);
            assert_eq!(parsed["n"], chunks.len());
            let next = asm.feed(frame);
            if idx + 1 < chunks.len() {
                assert!(next.is_none());
            } else {
                completed = next;
            }
        }
        assert_eq!(completed.as_deref(), Some(big.as_str()));
    }

    #[test]
    fn assembler_passes_non_chunks_and_enforces_256kib_cap() {
        let mut asm = DocChunkAssembler::default();
        assert_eq!(
            asm.feed(r#"{"t":"ready"}"#).as_deref(),
            Some(r#"{"t":"ready"}"#)
        );
        assert_eq!(asm.push(1, 1, 2, "world".into()), None);
        assert_eq!(asm.push(1, 1, 2, "dup".into()), None);
        assert_eq!(
            asm.push(1, 0, 2, "hello ".into()).as_deref(),
            Some("hello world")
        );
        let huge = "x".repeat(MAX_ASSEMBLED_DOCUMENT_BYTES + 1);
        assert_eq!(asm.push(2, 0, 1, huge), None);
        assert_eq!(asm.push(3, 0, 0, "bad".into()), None);
        assert_eq!(asm.push(3, 2, 2, "bad".into()), None);
    }
}
