//! Pure-Rust FIPS 180-4 SHA-256 implementation with serializable 105-byte resumable state
//! (used by OCI Distribution v1.1 chunked uploads across Worker invocations and GUI bundle checks).

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

fn compress(h: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for (i, word) in w.iter_mut().take(16).enumerate() {
        *word = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);
        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }
    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(hh);
}

/// Serialized byte length of [`ResumableSha256`] state:
/// `h[8] (32 B) + total_len (8 B) + buf_len (1 B) + buf (64 B) = 105 bytes`.
pub const RESUMABLE_SHA256_STATE_BYTES: usize = 105;

/// Incremental FIPS 180-4 SHA-256 hasher whose exact intermediate state can be persisted
/// between stateless HTTP requests (e.g., OCI chunked `PATCH` blob uploads).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResumableSha256 {
    h: [u32; 8],
    total_len: u64,
    buf_len: u8,
    buf: [u8; 64],
}

impl Default for ResumableSha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl ResumableSha256 {
    pub const fn new() -> Self {
        Self {
            h: IV,
            total_len: 0,
            buf_len: 0,
            buf: [0u8; 64],
        }
    }

    pub const fn total_len(&self) -> u64 {
        self.total_len
    }

    pub fn update(&mut self, mut data: &[u8]) {
        if data.is_empty() {
            return;
        }
        self.total_len = self.total_len.wrapping_add(data.len() as u64);
        let buffered = usize::from(self.buf_len);
        if buffered > 0 {
            let need = 64 - buffered;
            if data.len() < need {
                self.buf[buffered..buffered + data.len()].copy_from_slice(data);
                self.buf_len = (buffered + data.len()) as u8;
                return;
            }
            self.buf[buffered..64].copy_from_slice(&data[..need]);
            let block = self.buf;
            compress(&mut self.h, &block);
            self.buf_len = 0;
            self.buf = [0u8; 64];
            data = &data[need..];
        }
        let (blocks, rem) = data.as_chunks::<64>();
        for block in blocks {
            compress(&mut self.h, block);
        }
        if !rem.is_empty() {
            self.buf[..rem.len()].copy_from_slice(rem);
            self.buf_len = rem.len() as u8;
        }
    }

    pub fn finalize_bytes(self) -> [u8; 32] {
        let mut h = self.h;
        let rem_len = usize::from(self.buf_len);
        let mut pad = [0u8; 128];
        pad[..rem_len].copy_from_slice(&self.buf[..rem_len]);
        pad[rem_len] = 0x80;
        let total_bits = (self.total_len as u128).wrapping_mul(8) as u64;
        let pad_len = if rem_len < 56 { 64 } else { 128 };
        pad[pad_len - 8..pad_len].copy_from_slice(&total_bits.to_be_bytes());
        let first: &[u8; 64] = pad[..64].try_into().expect("first padded block");
        compress(&mut h, first);
        if pad_len == 128 {
            let second: &[u8; 64] = pad[64..128].try_into().expect("second padded block");
            compress(&mut h, second);
        }
        let mut out = [0u8; 32];
        for (i, word) in h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    pub fn finalize_hex(self) -> String {
        bytes_to_hex(&self.finalize_bytes())
    }

    pub fn to_bytes(&self) -> [u8; RESUMABLE_SHA256_STATE_BYTES] {
        let mut out = [0u8; RESUMABLE_SHA256_STATE_BYTES];
        for (i, word) in self.h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out[32..40].copy_from_slice(&self.total_len.to_be_bytes());
        out[40] = self.buf_len;
        let bl = usize::from(self.buf_len).min(64);
        out[41..41 + bl].copy_from_slice(&self.buf[..bl]);
        out
    }

    pub fn from_bytes(raw: &[u8]) -> Option<Self> {
        if raw.len() != RESUMABLE_SHA256_STATE_BYTES {
            return None;
        }
        let buf_len = raw[40];
        if buf_len >= 64 {
            return None;
        }
        let mut h = [0u32; 8];
        for (i, word) in h.iter_mut().enumerate() {
            *word =
                u32::from_be_bytes([raw[i * 4], raw[i * 4 + 1], raw[i * 4 + 2], raw[i * 4 + 3]]);
        }
        let total_len = u64::from_be_bytes(raw[32..40].try_into().ok()?);
        if total_len % 64 != u64::from(buf_len) {
            return None;
        }
        let mut buf = [0u8; 64];
        let bl = usize::from(buf_len);
        buf[..bl].copy_from_slice(&raw[41..41 + bl]);
        Some(Self {
            h,
            total_len,
            buf_len,
            buf,
        })
    }

    pub fn to_base64(&self) -> String {
        STANDARD.encode(self.to_bytes())
    }

    pub fn from_base64(encoded: &str) -> Option<Self> {
        let raw = STANDARD.decode(encoded).ok()?;
        Self::from_bytes(&raw)
    }
}

fn bytes_to_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Pure-Rust FIPS 180-4 SHA-256 bytes digest.
pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = ResumableSha256::new();
    hasher.update(data);
    hasher.finalize_bytes()
}

/// Pure-Rust FIPS 180-4 SHA-256 hex digest.
pub fn sha256_hex(data: &[u8]) -> String {
    bytes_to_hex(&sha256_bytes(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resumable_sha256_matches_fips_vectors_and_chunk_splits() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256_hex(b"{}"),
            "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        );

        for len in [0usize, 1, 55, 56, 63, 64, 65, 119, 120, 128, 1024, 4097] {
            let payload: Vec<u8> = (0..len).map(|i| ((i * 31 + 7) & 0xff) as u8).collect();
            let expected = sha256_hex(&payload);
            for chunk_size in [1usize, 7, 19, 63, 64, 65, 257] {
                let mut h = ResumableSha256::new();
                for chunk in payload.chunks(chunk_size) {
                    h.update(chunk);
                    let encoded = h.to_base64();
                    h = ResumableSha256::from_base64(&encoded).expect("valid state");
                }
                assert_eq!(h.total_len(), len as u64);
                assert_eq!(
                    h.finalize_hex(),
                    expected,
                    "len={len} chunk_size={chunk_size}"
                );
            }
        }
    }

    #[test]
    fn resumable_sha256_rejects_malformed_state() {
        assert!(ResumableSha256::from_bytes(&[0u8; 104]).is_none());
        assert!(ResumableSha256::from_bytes(&[0u8; 106]).is_none());
        let mut bad = [0u8; RESUMABLE_SHA256_STATE_BYTES];
        bad[40] = 64;
        assert!(ResumableSha256::from_bytes(&bad).is_none());
    }
}
