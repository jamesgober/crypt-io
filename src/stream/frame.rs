//! Wire format for streamed AEAD.
//!
//! # Header (24 bytes)
//!
//! ```text
//!   offset | size | field
//!   -------+------+--------------------------------------------------
//!    0..8  |  8   | magic = b"\x89CRYPTIO"
//!    8     |  1   | version = 0x01
//!    9     |  1   | algorithm (0x00 ChaCha20-Poly1305, 0x01 AES-256-GCM)
//!    10    |  1   | chunk_size_log2 (default 16 = 64 KiB chunks)
//!    11..16|  5   | reserved (all zero)
//!    16..23|  7   | nonce_prefix (random per stream)
//!    23    |  1   | reserved (zero)
//! ```
//!
//! The full 24-byte header is fed as Additional Authenticated Data (AAD)
//! to every chunk. Tampering with the algorithm byte, chunk-size byte,
//! or nonce prefix produces an authentication failure on the first
//! chunk.
//!
//! # Per-chunk nonce (12 bytes) — STREAM construction
//!
//! ```text
//!   offset | size | field
//!   -------+------+--------------------------------------------------
//!    0..7  |  7   | nonce_prefix (copied from header)
//!    7..11 |  4   | counter (u32 big-endian, starts at 0)
//!    11    |  1   | last_flag (0x00 for non-final, 0x01 for final)
//! ```
//!
//! The `last_flag` bit is what defeats truncation attacks. A non-final
//! chunk and the final chunk use different nonces — even if an attacker
//! reads ahead and tries to verify a non-final chunk as final (or vice
//! versa), the GHASH/Poly1305 tag will not match.
//!
//! # Stream body
//!
//! ```text
//!   [header (24 B)]
//!   [chunk_0 (chunk_size + 16 B)]   ── non-final, last_flag = 0
//!   [chunk_1 (chunk_size + 16 B)]   ── non-final, last_flag = 0
//!   ...
//!   [chunk_N-1 (chunk_size + 16 B)] ── non-final, last_flag = 0
//!   [chunk_N (< chunk_size + 16 B)] ── final, last_flag = 1
//! ```
//!
//! The final chunk is **always** strictly smaller than `chunk_size + 16`
//! bytes. If the encryptor's internal buffer happens to hold exactly
//! `chunk_size` bytes when `finalize` is called, it emits the buffered
//! data as a non-final chunk and then a zero-byte final chunk (16 bytes
//! total — just the tag). This makes EOF detection unambiguous: short
//! read → final chunk; full read → non-final.

use crate::aead::Algorithm;
use crate::error::{Error, Result};

/// Magic prefix identifying a `crypt-io` stream. 8 bytes. The high bit
/// in the first byte (0x89) helps detect binary-as-text mis-handling.
pub const MAGIC: &[u8; 8] = b"\x89CRYPTIO";

/// Header size in bytes.
pub const HEADER_LEN: usize = 24;

/// Per-chunk nonce size in bytes (matches both shipped AEADs).
pub const NONCE_LEN: usize = 12;

/// Length of the random nonce prefix carried in the header.
pub const NONCE_PREFIX_LEN: usize = 7;

/// AEAD tag size (matches both shipped AEADs).
pub const TAG_LEN: usize = 16;

/// Format version.
pub const VERSION: u8 = 0x01;

/// Default chunk-size log2 — 16 means 64 KiB chunks.
pub const DEFAULT_CHUNK_SIZE_LOG2: u8 = 16;

/// Minimum chunk-size log2 — 10 (1 KiB). Below this the per-chunk
/// AEAD overhead dominates.
pub const MIN_CHUNK_SIZE_LOG2: u8 = 10;

/// Maximum chunk-size log2 — 24 (16 MiB). Above this the buffering
/// memory cost gets uncomfortable for streaming workflows.
pub const MAX_CHUNK_SIZE_LOG2: u8 = 24;

pub(super) const ALG_CHACHA20_POLY1305: u8 = 0x00;
pub(super) const ALG_AES_256_GCM: u8 = 0x01;

/// Encode `algorithm` as the on-the-wire byte.
pub(super) fn encode_algorithm(algorithm: Algorithm) -> u8 {
    match algorithm {
        Algorithm::ChaCha20Poly1305 => ALG_CHACHA20_POLY1305,
        Algorithm::Aes256Gcm => ALG_AES_256_GCM,
    }
}

/// Decode the algorithm byte from the wire.
pub(super) fn decode_algorithm(byte: u8) -> Result<Algorithm> {
    match byte {
        ALG_CHACHA20_POLY1305 => Ok(Algorithm::ChaCha20Poly1305),
        ALG_AES_256_GCM => Ok(Algorithm::Aes256Gcm),
        _ => Err(Error::InvalidCiphertext(alloc::format!(
            "unknown algorithm byte: 0x{byte:02x}"
        ))),
    }
}

/// Build a header for a fresh stream. `nonce_prefix` must be 7 random bytes.
#[must_use]
pub(super) fn build_header(
    algorithm: Algorithm,
    chunk_size_log2: u8,
    nonce_prefix: &[u8; NONCE_PREFIX_LEN],
) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[0..8].copy_from_slice(MAGIC);
    h[8] = VERSION;
    h[9] = encode_algorithm(algorithm);
    h[10] = chunk_size_log2;
    // bytes 11..16: reserved zero (already)
    h[16..23].copy_from_slice(nonce_prefix);
    // byte 23: reserved zero (already)
    h
}

/// Parsed view of a header.
#[derive(Debug, Clone, Copy)]
pub(super) struct ParsedHeader {
    pub algorithm: Algorithm,
    pub chunk_size_log2: u8,
    pub nonce_prefix: [u8; NONCE_PREFIX_LEN],
    /// Original 24 header bytes — used as AAD for every chunk.
    pub raw: [u8; HEADER_LEN],
}

/// Parse and validate a 24-byte header.
pub(super) fn parse_header(bytes: &[u8]) -> Result<ParsedHeader> {
    if bytes.len() < HEADER_LEN {
        return Err(Error::InvalidCiphertext(alloc::format!(
            "stream header too short ({} bytes, need {HEADER_LEN})",
            bytes.len()
        )));
    }
    let raw_slice = &bytes[..HEADER_LEN];

    if &raw_slice[0..8] != MAGIC {
        return Err(Error::InvalidCiphertext(alloc::string::String::from(
            "stream magic mismatch (not a crypt-io stream)",
        )));
    }
    if raw_slice[8] != VERSION {
        return Err(Error::InvalidCiphertext(alloc::format!(
            "unsupported stream version: 0x{:02x} (this build understands 0x{VERSION:02x})",
            raw_slice[8],
        )));
    }
    let algorithm = decode_algorithm(raw_slice[9])?;
    let chunk_size_log2 = raw_slice[10];
    if !(MIN_CHUNK_SIZE_LOG2..=MAX_CHUNK_SIZE_LOG2).contains(&chunk_size_log2) {
        return Err(Error::InvalidCiphertext(alloc::format!(
            "chunk_size_log2 out of range: {chunk_size_log2}"
        )));
    }
    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    nonce_prefix.copy_from_slice(&raw_slice[16..23]);

    let mut raw = [0u8; HEADER_LEN];
    raw.copy_from_slice(raw_slice);

    Ok(ParsedHeader {
        algorithm,
        chunk_size_log2,
        nonce_prefix,
        raw,
    })
}

/// Build the 12-byte per-chunk nonce from the prefix, counter, and
/// last-chunk flag.
#[must_use]
pub(super) fn build_nonce(
    nonce_prefix: &[u8; NONCE_PREFIX_LEN],
    counter: u32,
    is_final: bool,
) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[0..7].copy_from_slice(nonce_prefix);
    n[7..11].copy_from_slice(&counter.to_be_bytes());
    n[11] = u8::from(is_final);
    n
}

/// Compute the chunk size in bytes from `chunk_size_log2`.
#[must_use]
pub(super) fn chunk_size_from_log2(log2: u8) -> usize {
    1usize << log2
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trip_chacha() {
        let prefix = [0xaau8; NONCE_PREFIX_LEN];
        let h = build_header(Algorithm::ChaCha20Poly1305, 16, &prefix);
        let p = parse_header(&h).unwrap();
        assert_eq!(p.algorithm, Algorithm::ChaCha20Poly1305);
        assert_eq!(p.chunk_size_log2, 16);
        assert_eq!(p.nonce_prefix, prefix);
        assert_eq!(p.raw, h);
    }

    #[test]
    fn header_round_trip_aes() {
        let prefix = [0xbbu8; NONCE_PREFIX_LEN];
        let h = build_header(Algorithm::Aes256Gcm, 12, &prefix);
        let p = parse_header(&h).unwrap();
        assert_eq!(p.algorithm, Algorithm::Aes256Gcm);
        assert_eq!(p.chunk_size_log2, 12);
        assert_eq!(p.nonce_prefix, prefix);
    }

    #[test]
    fn header_rejects_wrong_magic() {
        let mut h = build_header(Algorithm::ChaCha20Poly1305, 16, &[0u8; 7]);
        h[0] = b'X';
        let err = parse_header(&h).unwrap_err();
        assert!(matches!(err, Error::InvalidCiphertext(_)));
    }

    #[test]
    fn header_rejects_unknown_version() {
        let mut h = build_header(Algorithm::ChaCha20Poly1305, 16, &[0u8; 7]);
        h[8] = 0xff;
        let err = parse_header(&h).unwrap_err();
        assert!(matches!(err, Error::InvalidCiphertext(_)));
    }

    #[test]
    fn header_rejects_unknown_algorithm() {
        let mut h = build_header(Algorithm::ChaCha20Poly1305, 16, &[0u8; 7]);
        h[9] = 0x42;
        let err = parse_header(&h).unwrap_err();
        assert!(matches!(err, Error::InvalidCiphertext(_)));
    }

    #[test]
    fn header_rejects_out_of_range_chunk_size_log2() {
        for bad in [0u8, 9, 25, 64, 255] {
            let mut h = build_header(Algorithm::ChaCha20Poly1305, 16, &[0u8; 7]);
            h[10] = bad;
            let err = parse_header(&h).unwrap_err();
            assert!(matches!(err, Error::InvalidCiphertext(_)), "bad={bad}");
        }
    }

    #[test]
    fn header_rejects_too_short() {
        let err = parse_header(&[0u8; HEADER_LEN - 1]).unwrap_err();
        assert!(matches!(err, Error::InvalidCiphertext(_)));
    }

    #[test]
    fn nonce_distinct_per_counter_and_flag() {
        let prefix = [0xccu8; NONCE_PREFIX_LEN];
        let n0 = build_nonce(&prefix, 0, false);
        let n1 = build_nonce(&prefix, 1, false);
        let n0_final = build_nonce(&prefix, 0, true);
        assert_ne!(n0, n1);
        assert_ne!(n0, n0_final);
        assert_ne!(n1, n0_final);
        // Prefix preserved
        assert_eq!(&n0[..7], &prefix);
        assert_eq!(n0[7..11], 0u32.to_be_bytes());
        assert_eq!(n0[11], 0);
        assert_eq!(n0_final[11], 1);
    }

    #[test]
    fn chunk_size_from_log2_matches_pow2() {
        assert_eq!(chunk_size_from_log2(10), 1024);
        assert_eq!(chunk_size_from_log2(16), 65_536);
        assert_eq!(chunk_size_from_log2(20), 1_048_576);
    }
}
