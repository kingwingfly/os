//! Bounded gRPC-over-HTTP/2 cleartext (h2c) server and client over Unix domain sockets (`0600`).
//!
//! Implements RFC 7540 HTTP/2 framing (`SETTINGS`, `PING`, `WINDOW_UPDATE`, `HEADERS`,
//! `CONTINUATION`, `DATA`, `RST_STREAM`, `GOAWAY`) and RFC 7541 HPACK (full 61-entry static
//! table, per-connection dynamic table, and complete Appendix B Huffman decoder) with a strict
//! `4 MiB` per-message cap and zero extra external crates.

use crate::proto::*;
use crate::spec::*;
use os_nbd::server::{bind_unix_socket_0600, validate_safe_unix_socket_path};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;

const H2_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const FRAME_DATA: u8 = 0x0;
const FRAME_HEADERS: u8 = 0x1;
const FRAME_RST_STREAM: u8 = 0x3;
const FRAME_SETTINGS: u8 = 0x4;
const FRAME_PING: u8 = 0x6;
const FRAME_GOAWAY: u8 = 0x7;
const FRAME_WINDOW_UPDATE: u8 = 0x8;
const FRAME_CONTINUATION: u8 = 0x9;

const FLAG_END_STREAM: u8 = 0x1;
const FLAG_ACK: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_PADDED: u8 = 0x8;
const FLAG_PRIORITY: u8 = 0x20;

const MAX_H2_FRAME_PAYLOAD: usize = 64 * 1024;
const MAX_HEADER_BLOCK_BYTES: usize = 64 * 1024;
const INITIAL_WINDOW_SIZE: u32 = 4 * 1024 * 1024 + 65_536;

// ---------------------------------------------------------------------------
// RFC 7541 HPACK Static Table (1-indexed, 61 entries)
// ---------------------------------------------------------------------------

const HPACK_STATIC: &[(&str, &str)] = &[
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

// RFC 7541 Appendix B Huffman code table (symbols 0..=255 + EOS 256): (code, bit_len).
const HUFFMAN_TABLE: [(u32, u8); 257] = [
    (0x1ff8, 13),
    (0x7fffd8, 23),
    (0xfffffe2, 28),
    (0xfffffe3, 28),
    (0xfffffe4, 28),
    (0xfffffe5, 28),
    (0xfffffe6, 28),
    (0xfffffe7, 28),
    (0xfffffe8, 28),
    (0xffffea, 24),
    (0x3ffffffc, 30),
    (0xfffffe9, 28),
    (0xfffffea, 28),
    (0x3ffffffd, 30),
    (0xfffffeb, 28),
    (0xfffffec, 28),
    (0xfffffed, 28),
    (0xfffffee, 28),
    (0xfffffef, 28),
    (0xffffff0, 28),
    (0xffffff1, 28),
    (0xffffff2, 28),
    (0x3ffffffe, 30),
    (0xffffff3, 28),
    (0xffffff4, 28),
    (0xffffff5, 28),
    (0xffffff6, 28),
    (0xffffff7, 28),
    (0xffffff8, 28),
    (0xffffff9, 28),
    (0xffffffa, 28),
    (0xffffffb, 28),
    (0x14, 6),
    (0x3f8, 10),
    (0x3f9, 10),
    (0xffa, 12),
    (0x1ff9, 13),
    (0x15, 6),
    (0xf8, 8),
    (0x7fa, 11),
    (0x3fa, 10),
    (0x3fb, 10),
    (0xf9, 8),
    (0x7fb, 11),
    (0xfa, 8),
    (0x16, 6),
    (0x17, 6),
    (0x18, 6),
    (0x0, 5),
    (0x1, 5),
    (0x2, 5),
    (0x19, 6),
    (0x1a, 6),
    (0x1b, 6),
    (0x1c, 6),
    (0x1d, 6),
    (0x1e, 6),
    (0x1f, 6),
    (0x5c, 7),
    (0xfb, 8),
    (0x7ffc, 15),
    (0x20, 6),
    (0xffb, 12),
    (0x3fc, 10),
    (0x1ffa, 13),
    (0x21, 6),
    (0x5d, 7),
    (0x5e, 7),
    (0x5f, 7),
    (0x60, 7),
    (0x61, 7),
    (0x62, 7),
    (0x63, 7),
    (0x64, 7),
    (0x65, 7),
    (0x66, 7),
    (0x67, 7),
    (0x68, 7),
    (0x69, 7),
    (0x6a, 7),
    (0x6b, 7),
    (0x6c, 7),
    (0x6d, 7),
    (0x6e, 7),
    (0x6f, 7),
    (0x70, 7),
    (0x71, 7),
    (0x72, 7),
    (0xfc, 8),
    (0x73, 7),
    (0xfd, 8),
    (0x1ffb, 13),
    (0x7fff0, 19),
    (0x1ffc, 13),
    (0x3ffc, 14),
    (0x22, 6),
    (0x7ffd, 15),
    (0x3, 5),
    (0x23, 6),
    (0x4, 5),
    (0x24, 6),
    (0x5, 5),
    (0x25, 6),
    (0x26, 6),
    (0x27, 6),
    (0x6, 5),
    (0x74, 7),
    (0x75, 7),
    (0x28, 6),
    (0x29, 6),
    (0x2a, 6),
    (0x7, 5),
    (0x2b, 6),
    (0x76, 7),
    (0x2c, 6),
    (0x8, 5),
    (0x9, 5),
    (0x2d, 6),
    (0x77, 7),
    (0x78, 7),
    (0x79, 7),
    (0x7a, 7),
    (0x7b, 7),
    (0x7ffe, 15),
    (0x7fc, 11),
    (0x3ffd, 14),
    (0x1ffd, 13),
    (0xffffffc, 28),
    (0xfffe6, 20),
    (0x3fffd2, 22),
    (0xfffe7, 20),
    (0xfffe8, 20),
    (0x3fffd3, 22),
    (0x3fffd4, 22),
    (0x3fffd5, 22),
    (0x7fffd9, 23),
    (0x3fffd6, 22),
    (0x7fffda, 23),
    (0x7fffdb, 23),
    (0x7fffdc, 23),
    (0x7fffdd, 23),
    (0x7fffde, 23),
    (0xffffeb, 24),
    (0x7fffdf, 23),
    (0xffffec, 24),
    (0xffffed, 24),
    (0x3fffd7, 22),
    (0x7fffe0, 23),
    (0xffffee, 24),
    (0x7fffe1, 23),
    (0x7fffe2, 23),
    (0x7fffe3, 23),
    (0x7fffe4, 23),
    (0x1fffdc, 21),
    (0x3fffd8, 22),
    (0x7fffe5, 23),
    (0x3fffd9, 22),
    (0x7fffe6, 23),
    (0x7fffe7, 23),
    (0xffffef, 24),
    (0x3fffda, 22),
    (0x1fffdd, 21),
    (0xfffe9, 20),
    (0x3fffdb, 22),
    (0x3fffdc, 22),
    (0x7fffe8, 23),
    (0x7fffe9, 23),
    (0x1fffde, 21),
    (0x7fffea, 23),
    (0x3fffdd, 22),
    (0x3fffde, 22),
    (0xfffff0, 24),
    (0x1fffdf, 21),
    (0x3fffdf, 22),
    (0x7fffeb, 23),
    (0x7fffec, 23),
    (0x1fffe0, 21),
    (0x1fffe1, 21),
    (0x3fffe0, 22),
    (0x1fffe2, 21),
    (0x7fffed, 23),
    (0x3fffe1, 22),
    (0x7fffee, 23),
    (0x7fffef, 23),
    (0xfffea, 20),
    (0x3fffe2, 22),
    (0x3fffe3, 22),
    (0x3fffe4, 22),
    (0x7ffff0, 23),
    (0x3fffe5, 22),
    (0x3fffe6, 22),
    (0x7ffff1, 23),
    (0x3ffffe0, 26),
    (0x3ffffe1, 26),
    (0xfffeb, 20),
    (0x7fff1, 19),
    (0x3fffe7, 22),
    (0x7ffff2, 23),
    (0x3fffe8, 22),
    (0x1ffffec, 25),
    (0x3ffffe2, 26),
    (0x3ffffe3, 26),
    (0x3ffffe4, 26),
    (0x7ffffde, 27),
    (0x7ffffdf, 27),
    (0x3ffffe5, 26),
    (0xfffff1, 24),
    (0x1ffffed, 25),
    (0x7fff2, 19),
    (0x1fffe3, 21),
    (0x3ffffe6, 26),
    (0x7ffffe0, 27),
    (0x7ffffe1, 27),
    (0x3ffffe7, 26),
    (0x7ffffe2, 27),
    (0xfffff2, 24),
    (0x1fffe4, 21),
    (0x1fffe5, 21),
    (0x3ffffe8, 26),
    (0x3ffffe9, 26),
    (0xffffffd, 28),
    (0x7ffffe3, 27),
    (0x7ffffe4, 27),
    (0x7ffffe5, 27),
    (0xfffec, 20),
    (0xfffff3, 24),
    (0xfffed, 20),
    (0x1fffe6, 21),
    (0x3fffe9, 22),
    (0x1fffe7, 21),
    (0x1fffe8, 21),
    (0x7ffff3, 23),
    (0x3fffea, 22),
    (0x3fffeb, 22),
    (0x1ffffee, 25),
    (0x1ffffef, 25),
    (0xfffff4, 24),
    (0xfffff5, 24),
    (0x3ffffea, 26),
    (0x7ffff4, 23),
    (0x3ffffeb, 26),
    (0x7ffffe6, 27),
    (0x3ffffec, 26),
    (0x3ffffed, 26),
    (0x7ffffe7, 27),
    (0x7ffffe8, 27),
    (0x7ffffe9, 27),
    (0x7ffffea, 27),
    (0x7ffffeb, 27),
    (0xffffffe, 28),
    (0x7ffffec, 27),
    (0x7ffffed, 27),
    (0x7ffffee, 27),
    (0x7ffffef, 27),
    (0x7fffff0, 27),
    (0x3ffffee, 26),
    (0x3fffffff, 30),
];

struct HuffNode {
    children: [u16; 2],
    symbol: i16, // -1 internal, 0..=255 byte, 256 EOS
}

fn huffman_trie() -> &'static [HuffNode] {
    static TRIE: std::sync::OnceLock<Vec<HuffNode>> = std::sync::OnceLock::new();
    TRIE.get_or_init(|| {
        let mut nodes = vec![HuffNode {
            children: [0, 0],
            symbol: -1,
        }];
        for (sym, &(code, len)) in HUFFMAN_TABLE.iter().enumerate() {
            let mut cur = 0usize;
            for bit_idx in (0..len).rev() {
                let bit = ((code >> bit_idx) & 1) as usize;
                let mut next = nodes[cur].children[bit] as usize;
                if next == 0 {
                    next = nodes.len();
                    nodes.push(HuffNode {
                        children: [0, 0],
                        symbol: -1,
                    });
                    nodes[cur].children[bit] = next as u16;
                }
                cur = next;
            }
            nodes[cur].symbol = sym as i16;
        }
        nodes
    })
}

pub fn hpack_huffman_decode(input: &[u8]) -> io::Result<Vec<u8>> {
    let trie = huffman_trie();
    let mut out = Vec::with_capacity(input.len() * 2);
    let mut node = 0usize;
    let mut bits_in_current = 0u8;
    let mut current_bits = 0u8;
    for &byte in input {
        for shift in (0..8).rev() {
            let bit = ((byte >> shift) & 1) as usize;
            let next = trie[node].children[bit] as usize;
            if next == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid HPACK Huffman sequence",
                ));
            }
            node = next;
            bits_in_current += 1;
            current_bits = (current_bits << 1) | (bit as u8);
            let sym = trie[node].symbol;
            if sym >= 0 {
                if sym == 256 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected EOS in HPACK Huffman stream",
                    ));
                }
                out.push(sym as u8);
                node = 0;
                bits_in_current = 0;
                current_bits = 0;
            }
        }
    }
    // RFC 7541 §5.2: trailing padding must be <= 7 bits and all 1s (MSB of EOS).
    if bits_in_current > 7
        || (bits_in_current > 0 && current_bits != ((1u8 << bits_in_current) - 1))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid HPACK Huffman padding",
        ));
    }
    Ok(out)
}

struct HpackDecoder {
    dynamic: VecDeque<(String, String)>,
    dynamic_size: usize,
    max_dynamic_size: usize,
}

impl HpackDecoder {
    fn new(max_dynamic_size: usize) -> Self {
        Self {
            dynamic: VecDeque::new(),
            dynamic_size: 0,
            max_dynamic_size,
        }
    }

    fn set_max_size(&mut self, max_size: usize) {
        self.max_dynamic_size = max_size;
        while self.dynamic_size > self.max_dynamic_size {
            if let Some((k, v)) = self.dynamic.pop_back() {
                self.dynamic_size = self.dynamic_size.saturating_sub(k.len() + v.len() + 32);
            } else {
                break;
            }
        }
    }

    fn insert(&mut self, name: String, value: String) {
        let entry_size = name.len() + value.len() + 32;
        if entry_size > self.max_dynamic_size {
            self.dynamic.clear();
            self.dynamic_size = 0;
            return;
        }
        while self.dynamic_size + entry_size > self.max_dynamic_size {
            if let Some((k, v)) = self.dynamic.pop_back() {
                self.dynamic_size = self.dynamic_size.saturating_sub(k.len() + v.len() + 32);
            } else {
                break;
            }
        }
        self.dynamic.push_front((name, value));
        self.dynamic_size += entry_size;
    }

    fn lookup(&self, idx: usize) -> io::Result<(String, String)> {
        if idx == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "HPACK index 0 invalid",
            ));
        }
        if idx <= HPACK_STATIC.len() {
            let (k, v) = HPACK_STATIC[idx - 1];
            return Ok((k.to_string(), v.to_string()));
        }
        let dyn_idx = idx - HPACK_STATIC.len() - 1;
        self.dynamic
            .get(dyn_idx)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HPACK index out of range"))
    }

    fn decode_int(buf: &[u8], pos: &mut usize, prefix_bits: u8) -> io::Result<usize> {
        if *pos >= buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated HPACK integer",
            ));
        }
        let mask = ((1u16 << prefix_bits) - 1) as u8;
        let mut val = (buf[*pos] & mask) as usize;
        *pos += 1;
        if val < mask as usize {
            return Ok(val);
        }
        let mut shift = 0u32;
        loop {
            if *pos >= buf.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated HPACK multi-byte integer",
                ));
            }
            let b = buf[*pos];
            *pos += 1;
            let chunk = ((b & 0x7f) as usize)
                .checked_shl(shift)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HPACK int overflow"))?;
            val = val
                .checked_add(chunk)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HPACK int overflow"))?;
            if (b & 0x80) == 0 {
                return Ok(val);
            }
            shift += 7;
            if shift > 28 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HPACK integer too large",
                ));
            }
        }
    }

    fn decode_str(buf: &[u8], pos: &mut usize) -> io::Result<String> {
        if *pos >= buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated HPACK string",
            ));
        }
        let huffman = (buf[*pos] & 0x80) != 0;
        let len = Self::decode_int(buf, pos, 7)?;
        let end = pos
            .checked_add(len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HPACK string overflow"))?;
        if end > buf.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated HPACK string bytes",
            ));
        }
        let raw = &buf[*pos..end];
        *pos = end;
        let decoded = if huffman {
            hpack_huffman_decode(raw)?
        } else {
            raw.to_vec()
        };
        String::from_utf8(decoded)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF8 HPACK header"))
    }

    fn decode_block(&mut self, buf: &[u8]) -> io::Result<Vec<(String, String)>> {
        let mut pos = 0usize;
        let mut out = Vec::new();
        while pos < buf.len() {
            let b = buf[pos];
            if (b & 0x80) != 0 {
                // Indexed Header Field
                let idx = Self::decode_int(buf, &mut pos, 7)?;
                out.push(self.lookup(idx)?);
            } else if (b & 0xc0) == 0x40 {
                // Literal Header Field with Incremental Indexing
                let idx = Self::decode_int(buf, &mut pos, 6)?;
                let name = if idx == 0 {
                    Self::decode_str(buf, &mut pos)?
                } else {
                    self.lookup(idx)?.0
                };
                let value = Self::decode_str(buf, &mut pos)?;
                self.insert(name.clone(), value.clone());
                out.push((name, value));
            } else if (b & 0xe0) == 0x20 {
                // Dynamic Table Size Update
                let new_size = Self::decode_int(buf, &mut pos, 5)?;
                if new_size > 65_536 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "HPACK dynamic table size exceeds limit",
                    ));
                }
                self.set_max_size(new_size);
            } else {
                // Literal Header Field without Indexing (0000xxxx) or Never Indexed (0001xxxx)
                let idx = Self::decode_int(buf, &mut pos, 4)?;
                let name = if idx == 0 {
                    Self::decode_str(buf, &mut pos)?
                } else {
                    self.lookup(idx)?.0
                };
                let value = Self::decode_str(buf, &mut pos)?;
                out.push((name, value));
            }
        }
        Ok(out)
    }
}

fn hpack_encode_int(out: &mut Vec<u8>, prefix_bits: u8, prefix_mask: u8, mut val: usize) {
    let max_prefix = ((1u16 << prefix_bits) - 1) as usize;
    if val < max_prefix {
        out.push(prefix_mask | (val as u8));
        return;
    }
    out.push(prefix_mask | (max_prefix as u8));
    val -= max_prefix;
    while val >= 128 {
        out.push(((val & 0x7f) as u8) | 0x80);
        val >>= 7;
    }
    out.push(val as u8);
}

fn hpack_encode_str(out: &mut Vec<u8>, s: &str) {
    hpack_encode_int(out, 7, 0x00, s.len());
    out.extend_from_slice(s.as_bytes());
}

fn hpack_encode_headers(headers: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    for &(k, v) in headers {
        if let Some(pos) = HPACK_STATIC.iter().position(|&(sk, sv)| sk == k && sv == v) {
            hpack_encode_int(&mut out, 7, 0x80, pos + 1);
        } else if let Some(pos) = HPACK_STATIC.iter().position(|&(sk, _)| sk == k) {
            hpack_encode_int(&mut out, 4, 0x00, pos + 1);
            hpack_encode_str(&mut out, v);
        } else {
            out.push(0x00);
            hpack_encode_str(&mut out, k);
            hpack_encode_str(&mut out, v);
        }
    }
    out
}

fn percent_encode_grpc_message(msg: &str) -> String {
    let mut out = String::with_capacity(msg.len());
    for b in msg.bytes() {
        if (0x20..=0x7e).contains(&b) && b != b'%' {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn percent_decode_grpc_message(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2]))
        {
            out.push((hi << 4) | lo);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------------
// HTTP/2 Frame I/O
// ---------------------------------------------------------------------------

struct H2Frame {
    frame_type: u8,
    flags: u8,
    stream_id: u32,
    payload: Vec<u8>,
}

async fn read_h2_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<H2Frame>> {
    let mut hdr = [0u8; 9];
    match r.read_exact(&mut hdr).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = ((hdr[0] as usize) << 16) | ((hdr[1] as usize) << 8) | (hdr[2] as usize);
    if len > MAX_H2_FRAME_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("HTTP/2 frame payload {len} exceeds {MAX_H2_FRAME_PAYLOAD}"),
        ));
    }
    let frame_type = hdr[3];
    let flags = hdr[4];
    let stream_id = u32::from_be_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) & 0x7fff_ffff;
    let mut payload = vec![0u8; len];
    if !payload.is_empty() {
        r.read_exact(&mut payload).await?;
    }
    Ok(Some(H2Frame {
        frame_type,
        flags,
        stream_id,
        payload,
    }))
}

async fn write_h2_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    frame_type: u8,
    flags: u8,
    stream_id: u32,
    payload: &[u8],
) -> io::Result<()> {
    let len = payload.len();
    let mut hdr = [0u8; 9];
    hdr[0] = ((len >> 16) & 0xff) as u8;
    hdr[1] = ((len >> 8) & 0xff) as u8;
    hdr[2] = (len & 0xff) as u8;
    hdr[3] = frame_type;
    hdr[4] = flags;
    hdr[5..9].copy_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
    w.write_all(&hdr).await?;
    if !payload.is_empty() {
        w.write_all(payload).await?;
    }
    Ok(())
}

const MAX_CONCURRENT_STREAMS: usize = 64;
const MAX_GRPC_ERROR_MSG_BYTES: usize = 4096;
const H2_ERR_REFUSED_STREAM: u32 = 7;

async fn write_initial_settings<W: AsyncWrite + Unpin>(w: &mut W) -> io::Result<()> {
    let mut payload = Vec::with_capacity(18);
    // SETTINGS_MAX_CONCURRENT_STREAMS (0x03) = 64
    payload.extend_from_slice(&0x0003u16.to_be_bytes());
    payload.extend_from_slice(&(MAX_CONCURRENT_STREAMS as u32).to_be_bytes());
    // SETTINGS_INITIAL_WINDOW_SIZE (0x04)
    payload.extend_from_slice(&0x0004u16.to_be_bytes());
    payload.extend_from_slice(&INITIAL_WINDOW_SIZE.to_be_bytes());
    // SETTINGS_MAX_FRAME_SIZE (0x05) = 65536
    payload.extend_from_slice(&0x0005u16.to_be_bytes());
    payload.extend_from_slice(&(MAX_H2_FRAME_PAYLOAD as u32).to_be_bytes());
    write_h2_frame(w, FRAME_SETTINGS, 0, 0, &payload).await?;
    // Connection-level window update so large client messages never stall.
    let delta = INITIAL_WINDOW_SIZE.saturating_sub(65_535);
    write_h2_frame(w, FRAME_WINDOW_UPDATE, 0, 0, &delta.to_be_bytes()).await?;
    w.flush().await
}

fn strip_header_block(frame_type: u8, flags: u8, payload: &[u8]) -> io::Result<&[u8]> {
    let mut start = 0usize;
    let mut end = payload.len();
    if frame_type == FRAME_HEADERS {
        if (flags & FLAG_PADDED) != 0 {
            if payload.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "empty padded HEADERS",
                ));
            }
            let pad_len = payload[0] as usize;
            start += 1;
            end = end.checked_sub(pad_len).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid HEADERS pad length")
            })?;
        }
        if (flags & FLAG_PRIORITY) != 0 {
            start += 5;
        }
    }
    if start > end {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed HEADERS frame",
        ));
    }
    Ok(&payload[start..end])
}

fn strip_data_payload(flags: u8, payload: &[u8]) -> io::Result<&[u8]> {
    if (flags & FLAG_PADDED) != 0 {
        if payload.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "empty padded DATA",
            ));
        }
        let pad_len = payload[0] as usize;
        let end = payload
            .len()
            .checked_sub(pad_len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid DATA pad length"))?;
        if 1 > end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid DATA padding",
            ));
        }
        Ok(&payload[1..end])
    } else {
        Ok(payload)
    }
}

// ---------------------------------------------------------------------------
// CSI Service Router + Server Handle
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct CsiServiceRouter {
    pub identity: Arc<dyn CsiIdentity>,
    pub controller: Option<Arc<dyn CsiController>>,
    pub node: Option<Arc<dyn CsiNode>>,
}

impl CsiServiceRouter {
    pub fn new(
        identity: Arc<dyn CsiIdentity>,
        controller: Option<Arc<dyn CsiController>>,
        node: Option<Arc<dyn CsiNode>>,
    ) -> Self {
        Self {
            identity,
            controller,
            node,
        }
    }

    pub async fn dispatch(&self, path: &str, body: &[u8]) -> CsiResult<Vec<u8>> {
        match path {
            "/csi.v1.Identity/GetPluginInfo" => {
                let resp = self
                    .identity
                    .get_plugin_info(GetPluginInfoRequest {})
                    .await?;
                Ok(encode_get_plugin_info_resp(&resp))
            }
            "/csi.v1.Identity/GetPluginCapabilities" => {
                let resp = self
                    .identity
                    .get_plugin_capabilities(GetPluginCapabilitiesRequest {})
                    .await?;
                Ok(encode_get_plugin_capabilities_resp(&resp))
            }
            "/csi.v1.Identity/Probe" => {
                let resp = self.identity.probe(ProbeRequest {}).await?;
                Ok(encode_probe_resp(&resp))
            }
            "/csi.v1.Controller/CreateVolume" => {
                let ctrl = self
                    .controller
                    .as_ref()
                    .ok_or_else(|| CsiError::unimplemented("Controller service not enabled"))?;
                let req = decode_create_volume_req(body)?;
                let resp = ctrl.create_volume(req).await?;
                Ok(encode_create_volume_resp(&resp))
            }
            "/csi.v1.Controller/DeleteVolume" => {
                let ctrl = self
                    .controller
                    .as_ref()
                    .ok_or_else(|| CsiError::unimplemented("Controller service not enabled"))?;
                let req = decode_delete_volume_req(body)?;
                let _ = ctrl.delete_volume(req).await?;
                Ok(Vec::new())
            }
            "/csi.v1.Controller/ControllerPublishVolume" => {
                let ctrl = self
                    .controller
                    .as_ref()
                    .ok_or_else(|| CsiError::unimplemented("Controller service not enabled"))?;
                let req = decode_controller_publish_req(body)?;
                let resp = ctrl.controller_publish_volume(req).await?;
                Ok(encode_controller_publish_resp(&resp))
            }
            "/csi.v1.Controller/ControllerUnpublishVolume" => {
                let ctrl = self
                    .controller
                    .as_ref()
                    .ok_or_else(|| CsiError::unimplemented("Controller service not enabled"))?;
                let req = decode_controller_unpublish_req(body)?;
                let _ = ctrl.controller_unpublish_volume(req).await?;
                Ok(Vec::new())
            }
            "/csi.v1.Controller/ValidateVolumeCapabilities" => {
                let ctrl = self
                    .controller
                    .as_ref()
                    .ok_or_else(|| CsiError::unimplemented("Controller service not enabled"))?;
                let req = decode_validate_volume_caps_req(body)?;
                let resp = ctrl.validate_volume_capabilities(req).await?;
                Ok(encode_validate_volume_caps_resp(&resp))
            }
            "/csi.v1.Controller/ListVolumes" => {
                let ctrl = self
                    .controller
                    .as_ref()
                    .ok_or_else(|| CsiError::unimplemented("Controller service not enabled"))?;
                let req = decode_list_volumes_req(body)?;
                let resp = ctrl.list_volumes(req).await?;
                Ok(encode_list_volumes_resp(&resp))
            }
            "/csi.v1.Controller/ControllerGetCapabilities" => {
                let ctrl = self
                    .controller
                    .as_ref()
                    .ok_or_else(|| CsiError::unimplemented("Controller service not enabled"))?;
                let resp = ctrl
                    .controller_get_capabilities(ControllerGetCapabilitiesRequest {})
                    .await?;
                Ok(encode_controller_get_caps_resp(&resp))
            }
            "/csi.v1.Controller/CreateSnapshot" => {
                let ctrl = self
                    .controller
                    .as_ref()
                    .ok_or_else(|| CsiError::unimplemented("Controller service not enabled"))?;
                let req = decode_create_snapshot_req(body)?;
                let resp = ctrl.create_snapshot(req).await?;
                Ok(encode_create_snapshot_resp(&resp))
            }
            "/csi.v1.Controller/DeleteSnapshot" => {
                let ctrl = self
                    .controller
                    .as_ref()
                    .ok_or_else(|| CsiError::unimplemented("Controller service not enabled"))?;
                let req = decode_delete_snapshot_req(body)?;
                let _ = ctrl.delete_snapshot(req).await?;
                Ok(Vec::new())
            }
            "/csi.v1.Controller/ListSnapshots" => {
                let ctrl = self
                    .controller
                    .as_ref()
                    .ok_or_else(|| CsiError::unimplemented("Controller service not enabled"))?;
                let req = decode_list_snapshots_req(body)?;
                let resp = ctrl.list_snapshots(req).await?;
                Ok(encode_list_snapshots_resp(&resp))
            }
            "/csi.v1.Node/NodeStageVolume" => {
                let node = self
                    .node
                    .as_ref()
                    .ok_or_else(|| CsiError::unimplemented("Node service not enabled"))?;
                let req = decode_node_stage_req(body)?;
                let _ = node.node_stage_volume(req).await?;
                Ok(Vec::new())
            }
            "/csi.v1.Node/NodeUnstageVolume" => {
                let node = self
                    .node
                    .as_ref()
                    .ok_or_else(|| CsiError::unimplemented("Node service not enabled"))?;
                let req = decode_node_unstage_req(body)?;
                let _ = node.node_unstage_volume(req).await?;
                Ok(Vec::new())
            }
            "/csi.v1.Node/NodePublishVolume" => {
                let node = self
                    .node
                    .as_ref()
                    .ok_or_else(|| CsiError::unimplemented("Node service not enabled"))?;
                let req = decode_node_publish_req(body)?;
                let _ = node.node_publish_volume(req).await?;
                Ok(Vec::new())
            }
            "/csi.v1.Node/NodeUnpublishVolume" => {
                let node = self
                    .node
                    .as_ref()
                    .ok_or_else(|| CsiError::unimplemented("Node service not enabled"))?;
                let req = decode_node_unpublish_req(body)?;
                let _ = node.node_unpublish_volume(req).await?;
                Ok(Vec::new())
            }
            "/csi.v1.Node/NodeGetVolumeStats" => {
                let node = self
                    .node
                    .as_ref()
                    .ok_or_else(|| CsiError::unimplemented("Node service not enabled"))?;
                let req = decode_node_volume_stats_req(body)?;
                let resp = node.node_get_volume_stats(req).await?;
                Ok(encode_node_volume_stats_resp(&resp))
            }
            "/csi.v1.Node/NodeGetCapabilities" => {
                let node = self
                    .node
                    .as_ref()
                    .ok_or_else(|| CsiError::unimplemented("Node service not enabled"))?;
                let resp = node
                    .node_get_capabilities(NodeGetCapabilitiesRequest {})
                    .await?;
                Ok(encode_node_get_caps_resp(&resp))
            }
            "/csi.v1.Node/NodeGetInfo" => {
                let node = self
                    .node
                    .as_ref()
                    .ok_or_else(|| CsiError::unimplemented("Node service not enabled"))?;
                let resp = node.node_get_info(NodeGetInfoRequest {}).await?;
                Ok(encode_node_get_info_resp(&resp))
            }
            other => Err(CsiError::unimplemented(format!(
                "unknown CSI method {other}"
            ))),
        }
    }
}

pub struct CsiGrpcServerHandle {
    socket_path: PathBuf,
    shutdown_tx: watch::Sender<bool>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl CsiGrpcServerHandle {
    pub fn bind_and_spawn(socket_path: PathBuf, router: CsiServiceRouter) -> io::Result<Self> {
        validate_safe_unix_socket_path(&socket_path)?;
        let listener = bind_unix_socket_0600(&socket_path)?;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(async move {
            run_grpc_accept_loop(listener, router, shutdown_rx).await;
        });
        Ok(Self {
            socket_path,
            shutdown_tx,
            task: Some(task),
        })
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub async fn shutdown(&mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(t) = self.task.take() {
            let _ = t.await;
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

impl Drop for CsiGrpcServerHandle {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(t) = self.task.take() {
            t.abort();
        }
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

async fn run_grpc_accept_loop(
    listener: UnixListener,
    router: CsiServiceRouter,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        let r = router.clone();
                        let s = shutdown_rx.clone();
                        tokio::spawn(async move {
                            let _ = handle_h2c_connection(stream, r, s).await;
                        });
                    }
                    Err(_) => break,
                }
            }
        }
    }
}

struct StreamAccum {
    path: String,
    header_block: Vec<u8>,
    headers_complete: bool,
    end_stream: bool,
    data: Vec<u8>,
}

async fn send_grpc_response<W: AsyncWrite + Unpin>(
    stream: &mut W,
    stream_id: u32,
    result: CsiResult<Vec<u8>>,
) -> io::Result<()> {
    match result {
        Ok(msg) => {
            let framed = match encode_grpc_frame(&msg) {
                Ok(f) => f,
                Err(e) => return send_grpc_error(stream, stream_id, e).await,
            };
            let resp_headers =
                hpack_encode_headers(&[(":status", "200"), ("content-type", "application/grpc")]);
            write_h2_frame(
                stream,
                FRAME_HEADERS,
                FLAG_END_HEADERS,
                stream_id,
                &resp_headers,
            )
            .await?;
            for chunk in framed.chunks(MAX_H2_FRAME_PAYLOAD) {
                write_h2_frame(stream, FRAME_DATA, 0, stream_id, chunk).await?;
            }
            let trailers = hpack_encode_headers(&[("grpc-status", "0")]);
            write_h2_frame(
                stream,
                FRAME_HEADERS,
                FLAG_END_HEADERS | FLAG_END_STREAM,
                stream_id,
                &trailers,
            )
            .await?;
            stream.flush().await
        }
        Err(e) => send_grpc_error(stream, stream_id, e).await,
    }
}

fn truncate_grpc_error_message(msg: &str) -> &str {
    // Percent-encoding expands each byte at most 3x; cap raw UTF-8 bytes so encoded output <= 4096.
    let max_raw = MAX_GRPC_ERROR_MSG_BYTES / 3;
    if msg.len() <= max_raw {
        return msg;
    }
    let mut end = max_raw;
    while end > 0 && !msg.is_char_boundary(end) {
        end -= 1;
    }
    &msg[..end]
}

async fn send_grpc_error<W: AsyncWrite + Unpin>(
    stream: &mut W,
    stream_id: u32,
    err: CsiError,
) -> io::Result<()> {
    let status_str = err.code.as_u32().to_string();
    let msg_enc = percent_encode_grpc_message(truncate_grpc_error_message(&err.message));
    let headers = hpack_encode_headers(&[
        (":status", "200"),
        ("content-type", "application/grpc"),
        ("grpc-status", &status_str),
        ("grpc-message", &msg_enc),
    ]);
    write_h2_frame(
        stream,
        FRAME_HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        stream_id,
        &headers,
    )
    .await?;
    stream.flush().await
}

async fn handle_h2c_connection<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    router: CsiServiceRouter,
    mut shutdown_rx: watch::Receiver<bool>,
) -> io::Result<()> {
    let mut preface = [0u8; 24];
    stream.read_exact(&mut preface).await?;
    if &preface != H2_PREFACE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid HTTP/2 connection preface",
        ));
    }
    write_initial_settings(&mut stream).await?;

    let mut hpack = HpackDecoder::new(4096);
    let mut streams: HashMap<u32, StreamAccum> = HashMap::new();

    loop {
        let frame = tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    break;
                }
                continue;
            }
            f = read_h2_frame(&mut stream) => {
                match f? {
                    Some(f) => f,
                    None => break,
                }
            }
        };

        match frame.frame_type {
            FRAME_SETTINGS => {
                if (frame.flags & FLAG_ACK) == 0 {
                    write_h2_frame(&mut stream, FRAME_SETTINGS, FLAG_ACK, 0, &[]).await?;
                    stream.flush().await?;
                }
            }
            FRAME_PING => {
                if (frame.flags & FLAG_ACK) == 0 && frame.payload.len() == 8 {
                    write_h2_frame(&mut stream, FRAME_PING, FLAG_ACK, 0, &frame.payload).await?;
                    stream.flush().await?;
                }
            }
            FRAME_WINDOW_UPDATE => {}
            FRAME_RST_STREAM => {
                streams.remove(&frame.stream_id);
            }
            FRAME_GOAWAY => break,
            FRAME_HEADERS | FRAME_CONTINUATION => {
                let sid = frame.stream_id;
                if sid == 0 {
                    continue;
                }
                if !streams.contains_key(&sid) {
                    if frame.frame_type == FRAME_CONTINUATION {
                        continue;
                    }
                    if streams.len() >= MAX_CONCURRENT_STREAMS {
                        write_h2_frame(
                            &mut stream,
                            FRAME_RST_STREAM,
                            0,
                            sid,
                            &H2_ERR_REFUSED_STREAM.to_be_bytes(),
                        )
                        .await?;
                        stream.flush().await?;
                        continue;
                    }
                }
                let frag = strip_header_block(frame.frame_type, frame.flags, &frame.payload)?;
                let entry = streams.entry(sid).or_insert_with(|| StreamAccum {
                    path: String::new(),
                    header_block: Vec::new(),
                    headers_complete: false,
                    end_stream: false,
                    data: Vec::new(),
                });
                if entry.header_block.len() + frag.len() > MAX_HEADER_BLOCK_BYTES {
                    streams.remove(&sid);
                    send_grpc_error(
                        &mut stream,
                        sid,
                        CsiError::resource_exhausted("HTTP/2 header block exceeds limit"),
                    )
                    .await?;
                    continue;
                }
                entry.header_block.extend_from_slice(frag);
                if frame.frame_type == FRAME_HEADERS && (frame.flags & FLAG_END_STREAM) != 0 {
                    entry.end_stream = true;
                }
                if (frame.flags & FLAG_END_HEADERS) != 0 {
                    let decoded = hpack.decode_block(&entry.header_block)?;
                    entry.header_block.clear();
                    for (k, v) in decoded {
                        if k == ":path" {
                            entry.path = v;
                        }
                    }
                    entry.headers_complete = true;
                }
                if entry.end_stream && entry.headers_complete {
                    let acc = streams.remove(&sid).unwrap();
                    let res = match decode_grpc_frame(&acc.data) {
                        Ok(body) => router.dispatch(&acc.path, body).await,
                        Err(_) if acc.data.is_empty() => router.dispatch(&acc.path, &[]).await,
                        Err(e) => Err(e),
                    };
                    send_grpc_response(&mut stream, sid, res).await?;
                }
            }
            FRAME_DATA => {
                let sid = frame.stream_id;
                if sid == 0 {
                    continue;
                }
                let full_len = frame.payload.len() as u32;
                let data_slice = strip_data_payload(frame.flags, &frame.payload)?;
                let has_stream = streams.contains_key(&sid);
                if full_len > 0 {
                    // RFC 7540 §6.9.1: replenish flow-control window by full DATA frame payload
                    // length (including padding), skipping stream updates on unknown/closed streams.
                    write_h2_frame(
                        &mut stream,
                        FRAME_WINDOW_UPDATE,
                        0,
                        0,
                        &full_len.to_be_bytes(),
                    )
                    .await?;
                    if has_stream {
                        write_h2_frame(
                            &mut stream,
                            FRAME_WINDOW_UPDATE,
                            0,
                            sid,
                            &full_len.to_be_bytes(),
                        )
                        .await?;
                    }
                    stream.flush().await?;
                }
                if !has_stream {
                    continue;
                }
                let mut oversize = false;
                if let Some(entry) = streams.get_mut(&sid) {
                    if entry.data.len() + data_slice.len() > MAX_GRPC_MESSAGE_BYTES + 5 {
                        oversize = true;
                    } else {
                        entry.data.extend_from_slice(data_slice);
                    }
                }
                if oversize {
                    streams.remove(&sid);
                    send_grpc_error(
                        &mut stream,
                        sid,
                        CsiError::resource_exhausted("gRPC request exceeds 4 MiB"),
                    )
                    .await?;
                    continue;
                }
                if (frame.flags & FLAG_END_STREAM) != 0
                    && let Some(acc) = streams.remove(&sid)
                {
                    let res = match decode_grpc_frame(&acc.data) {
                        Ok(body) => router.dispatch(&acc.path, body).await,
                        Err(e) => Err(e),
                    };
                    send_grpc_response(&mut stream, sid, res).await?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// gRPC-h2c Unix Client
// ---------------------------------------------------------------------------

pub struct CsiGrpcClient {
    stream: UnixStream,
    hpack: HpackDecoder,
    next_stream_id: u32,
}

impl CsiGrpcClient {
    pub async fn connect_unix(path: &Path) -> io::Result<Self> {
        let mut stream = UnixStream::connect(path).await?;
        stream.write_all(H2_PREFACE).await?;
        write_initial_settings(&mut stream).await?;
        Ok(Self {
            stream,
            hpack: HpackDecoder::new(4096),
            next_stream_id: 1,
        })
    }

    pub async fn unary(&mut self, method_path: &str, req_proto: &[u8]) -> CsiResult<Vec<u8>> {
        let sid = self.next_stream_id;
        self.next_stream_id = self.next_stream_id.wrapping_add(2);
        let framed = encode_grpc_frame(req_proto)?;
        let req_headers = hpack_encode_headers(&[
            (":method", "POST"),
            (":scheme", "http"),
            (":path", method_path),
            (":authority", "localhost"),
            ("content-type", "application/grpc"),
            ("te", "trailers"),
        ]);
        write_h2_frame(
            &mut self.stream,
            FRAME_HEADERS,
            FLAG_END_HEADERS,
            sid,
            &req_headers,
        )
        .await
        .map_err(|e| CsiError::unavailable(format!("h2 write headers: {e}")))?;

        let chunks: Vec<&[u8]> = framed.chunks(MAX_H2_FRAME_PAYLOAD).collect();
        for (idx, chunk) in chunks.iter().enumerate() {
            let flags = if idx + 1 == chunks.len() {
                FLAG_END_STREAM
            } else {
                0
            };
            write_h2_frame(&mut self.stream, FRAME_DATA, flags, sid, chunk)
                .await
                .map_err(|e| CsiError::unavailable(format!("h2 write data: {e}")))?;
        }
        self.stream
            .flush()
            .await
            .map_err(|e| CsiError::unavailable(format!("h2 flush: {e}")))?;

        let mut resp_data = Vec::new();
        let mut grpc_status: Option<u32> = None;
        let mut grpc_message = String::new();
        let mut header_buf = Vec::new();
        let mut client_end_stream = false;

        loop {
            let frame = read_h2_frame(&mut self.stream)
                .await
                .map_err(|e| CsiError::unavailable(format!("h2 read: {e}")))?
                .ok_or_else(|| CsiError::unavailable("server closed h2c connection"))?;
            match frame.frame_type {
                FRAME_SETTINGS => {
                    if (frame.flags & FLAG_ACK) == 0 {
                        let _ = write_h2_frame(&mut self.stream, FRAME_SETTINGS, FLAG_ACK, 0, &[])
                            .await;
                        let _ = self.stream.flush().await;
                    }
                }
                FRAME_PING => {
                    if (frame.flags & FLAG_ACK) == 0 && frame.payload.len() == 8 {
                        let _ = write_h2_frame(
                            &mut self.stream,
                            FRAME_PING,
                            FLAG_ACK,
                            0,
                            &frame.payload,
                        )
                        .await;
                        let _ = self.stream.flush().await;
                    }
                }
                FRAME_WINDOW_UPDATE => {}
                FRAME_HEADERS | FRAME_CONTINUATION if frame.stream_id == sid => {
                    let frag = strip_header_block(frame.frame_type, frame.flags, &frame.payload)
                        .map_err(|e| CsiError::internal(format!("bad response headers: {e}")))?;
                    if header_buf.len() + frag.len() > MAX_HEADER_BLOCK_BYTES {
                        return Err(CsiError::resource_exhausted(
                            "HTTP/2 response header block exceeds limit",
                        ));
                    }
                    header_buf.extend_from_slice(frag);
                    if frame.frame_type == FRAME_HEADERS && (frame.flags & FLAG_END_STREAM) != 0 {
                        client_end_stream = true;
                    }
                    if (frame.flags & FLAG_END_HEADERS) != 0 {
                        let decoded = self
                            .hpack
                            .decode_block(&header_buf)
                            .map_err(|e| CsiError::internal(format!("hpack decode: {e}")))?;
                        header_buf.clear();
                        for (k, v) in decoded {
                            if k == "grpc-status" {
                                grpc_status = v.parse::<u32>().ok();
                            } else if k == "grpc-message" {
                                grpc_message = percent_decode_grpc_message(&v);
                            }
                        }
                        if client_end_stream {
                            break;
                        }
                    }
                }
                FRAME_DATA if frame.stream_id == sid => {
                    let full_len = frame.payload.len() as u32;
                    let slice = strip_data_payload(frame.flags, &frame.payload)
                        .map_err(|e| CsiError::internal(format!("bad data frame: {e}")))?;
                    if resp_data.len() + slice.len() > MAX_GRPC_MESSAGE_BYTES + 5 {
                        return Err(CsiError::resource_exhausted("gRPC response exceeds 4 MiB"));
                    }
                    resp_data.extend_from_slice(slice);
                    if full_len > 0 {
                        let inc = full_len.to_be_bytes();
                        let _ =
                            write_h2_frame(&mut self.stream, FRAME_WINDOW_UPDATE, 0, 0, &inc).await;
                        let _ = write_h2_frame(&mut self.stream, FRAME_WINDOW_UPDATE, 0, sid, &inc)
                            .await;
                        let _ = self.stream.flush().await;
                    }
                    if (frame.flags & FLAG_END_STREAM) != 0 {
                        break;
                    }
                }
                FRAME_RST_STREAM if frame.stream_id == sid => {
                    return Err(CsiError::unavailable("stream reset by server"));
                }
                _ => {}
            }
        }

        let code = grpc_status.unwrap_or(CsiStatusCode::Unknown.as_u32());
        if code != CsiStatusCode::Ok.as_u32() {
            return Err(CsiError::new(CsiStatusCode::from_u32(code), grpc_message));
        }
        if resp_data.is_empty() {
            return Ok(Vec::new());
        }
        Ok(decode_grpc_frame(&resp_data)?.to_vec())
    }

    pub async fn get_plugin_info(&mut self) -> CsiResult<GetPluginInfoResponse> {
        let raw = self.unary("/csi.v1.Identity/GetPluginInfo", &[]).await?;
        decode_get_plugin_info_resp(&raw)
    }

    pub async fn probe(&mut self) -> CsiResult<ProbeResponse> {
        let raw = self.unary("/csi.v1.Identity/Probe", &[]).await?;
        decode_probe_resp(&raw)
    }

    pub async fn create_volume(
        &mut self,
        req: &CreateVolumeRequest,
    ) -> CsiResult<CreateVolumeResponse> {
        let raw = self
            .unary(
                "/csi.v1.Controller/CreateVolume",
                &encode_create_volume_req(req),
            )
            .await?;
        decode_create_volume_resp(&raw)
    }

    pub async fn delete_volume(&mut self, req: &DeleteVolumeRequest) -> CsiResult<()> {
        let _ = self
            .unary(
                "/csi.v1.Controller/DeleteVolume",
                &encode_delete_volume_req(req),
            )
            .await?;
        Ok(())
    }

    pub async fn controller_publish_volume(
        &mut self,
        req: &ControllerPublishVolumeRequest,
    ) -> CsiResult<ControllerPublishVolumeResponse> {
        let raw = self
            .unary(
                "/csi.v1.Controller/ControllerPublishVolume",
                &encode_controller_publish_req(req),
            )
            .await?;
        decode_controller_publish_resp(&raw)
    }

    pub async fn controller_unpublish_volume(
        &mut self,
        req: &ControllerUnpublishVolumeRequest,
    ) -> CsiResult<()> {
        let _ = self
            .unary(
                "/csi.v1.Controller/ControllerUnpublishVolume",
                &encode_controller_unpublish_req(req),
            )
            .await?;
        Ok(())
    }

    pub async fn list_volumes(
        &mut self,
        req: &ListVolumesRequest,
    ) -> CsiResult<ListVolumesResponse> {
        let raw = self
            .unary(
                "/csi.v1.Controller/ListVolumes",
                &encode_list_volumes_req(req),
            )
            .await?;
        decode_list_volumes_resp(&raw)
    }

    pub async fn create_snapshot(
        &mut self,
        req: &CreateSnapshotRequest,
    ) -> CsiResult<CreateSnapshotResponse> {
        let raw = self
            .unary(
                "/csi.v1.Controller/CreateSnapshot",
                &encode_create_snapshot_req(req),
            )
            .await?;
        decode_create_snapshot_resp(&raw)
    }

    pub async fn delete_snapshot(&mut self, req: &DeleteSnapshotRequest) -> CsiResult<()> {
        let _ = self
            .unary(
                "/csi.v1.Controller/DeleteSnapshot",
                &encode_delete_snapshot_req(req),
            )
            .await?;
        Ok(())
    }

    pub async fn list_snapshots(
        &mut self,
        req: &ListSnapshotsRequest,
    ) -> CsiResult<ListSnapshotsResponse> {
        let raw = self
            .unary(
                "/csi.v1.Controller/ListSnapshots",
                &encode_list_snapshots_req(req),
            )
            .await?;
        decode_list_snapshots_resp(&raw)
    }

    pub async fn node_stage_volume(&mut self, req: &NodeStageVolumeRequest) -> CsiResult<()> {
        let _ = self
            .unary("/csi.v1.Node/NodeStageVolume", &encode_node_stage_req(req))
            .await?;
        Ok(())
    }

    pub async fn node_unstage_volume(&mut self, req: &NodeUnstageVolumeRequest) -> CsiResult<()> {
        let _ = self
            .unary(
                "/csi.v1.Node/NodeUnstageVolume",
                &encode_node_unstage_req(req),
            )
            .await?;
        Ok(())
    }

    pub async fn node_publish_volume(&mut self, req: &NodePublishVolumeRequest) -> CsiResult<()> {
        let _ = self
            .unary(
                "/csi.v1.Node/NodePublishVolume",
                &encode_node_publish_req(req),
            )
            .await?;
        Ok(())
    }

    pub async fn node_unpublish_volume(
        &mut self,
        req: &NodeUnpublishVolumeRequest,
    ) -> CsiResult<()> {
        let _ = self
            .unary(
                "/csi.v1.Node/NodeUnpublishVolume",
                &encode_node_unpublish_req(req),
            )
            .await?;
        Ok(())
    }

    pub async fn node_get_info(&mut self) -> CsiResult<NodeGetInfoResponse> {
        let raw = self.unary("/csi.v1.Node/NodeGetInfo", &[]).await?;
        decode_node_get_info_resp(&raw)
    }

    pub async fn node_get_volume_stats(
        &mut self,
        req: &NodeGetVolumeStatsRequest,
    ) -> CsiResult<NodeGetVolumeStatsResponse> {
        let raw = self
            .unary(
                "/csi.v1.Node/NodeGetVolumeStats",
                &encode_node_volume_stats_req(req),
            )
            .await?;
        decode_node_volume_stats_resp(&raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7541_huffman_test_vectors_decode_exact() {
        // RFC 7541 C.4.1 / C.4.2 / C.6.1 official wire test vectors.
        let v1 = [
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        assert_eq!(hpack_huffman_decode(&v1).unwrap(), b"www.example.com");

        let v2 = [0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf];
        assert_eq!(hpack_huffman_decode(&v2).unwrap(), b"no-cache");

        let v3 = [0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f];
        assert_eq!(hpack_huffman_decode(&v3).unwrap(), b"custom-key");

        let v4 = [0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf];
        assert_eq!(hpack_huffman_decode(&v4).unwrap(), b"custom-value");

        let v5 = [0xae, 0xc3, 0x77, 0x1a, 0x4b];
        assert_eq!(hpack_huffman_decode(&v5).unwrap(), b"private");
    }

    #[test]
    fn hpack_dynamic_table_and_huffman_block_decode() {
        let mut dec = HpackDecoder::new(4096);
        // RFC 7541 C.4.1 request block: :method GET, :scheme http, :path /, :authority www.example.com (Huffman)
        let block = [
            0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab,
            0x90, 0xf4, 0xff,
        ];
        let hdrs = dec.decode_block(&block).unwrap();
        assert_eq!(
            hdrs,
            vec![
                (":method".into(), "GET".into()),
                (":scheme".into(), "http".into()),
                (":path".into(), "/".into()),
                (":authority".into(), "www.example.com".into()),
            ]
        );
        // Dynamic entry 62 now resolves to (:authority, www.example.com).
        let hdrs2 = dec.decode_block(&[0xbe]).unwrap();
        assert_eq!(hdrs2, vec![(":authority".into(), "www.example.com".into())]);
    }

    #[test]
    fn percent_decode_handles_multibyte_utf8_after_percent_without_panicking() {
        // P0-1 regression: `%` followed by ASCII + multi-byte UTF-8 must never slice mid-char.
        assert_eq!(percent_decode_grpc_message("%a\u{00e9}"), "%a\u{00e9}");
        assert_eq!(percent_decode_grpc_message("ok%20%25%2F"), "ok %/");
        assert!(
            truncate_grpc_error_message(&"\u{00e9}".repeat(2000)).len()
                <= MAX_GRPC_ERROR_MSG_BYTES / 3
        );
    }
}
