//! Wire format for streamed AEAD.
//!
//! Two format versions exist. crypt-io 1.1 writes **v2** by default and
//! reads both. The full specification, with test vectors, is
//! `docs/FILE_FORMAT.md`.
//!
//! # Header (24 bytes, both versions)
//!
//! ```text
//!   offset | size | v1 (0x01)                    | v2 (0x02)
//!   -------+------+------------------------------+------------------------------
//!    0..8  |  8   | magic = b"\x89CRYPTIO"       | same
//!    8     |  1   | version = 0x01               | version = 0x02
//!    9     |  1   | algorithm (0x00, 0x01)       | algorithm (0x00, 0x01, 0x02)
//!    10    |  1   | chunk_size_log2 (10..=24)    | same
//!    11..16|  5   | reserved                     | reserved, must be zero
//!    16..23|  7   | nonce_prefix (random)        | reserved, must be zero
//!    23    |  1   | reserved                     | reserved, must be zero
//! ```
//!
//! Algorithm bytes: `0x00` ChaCha20-Poly1305, `0x01` AES-256-GCM,
//! `0x02` XChaCha20-Poly1305 (v2 only).
//!
//! # v2: per-stream subkey
//!
//! A v2 header is followed by a 32-byte random **salt**. The chunks are
//! not encrypted under the caller's key but under a subkey derived for
//! this stream alone:
//!
//! ```text
//!   okm          = HKDF-SHA256(ikm  = key,
//!                              salt = salt,
//!                              info = "crypt-io stream v2" || header,
//!                              len  = 32 + P)
//!   subkey       = okm[0..32]
//!   nonce_prefix = okm[32..32 + P]        P = nonce_len - 5 (7, or 19 for XChaCha)
//! ```
//!
//! Two streams under one key share chunk nonces only if their 256-bit
//! salts collide, so the v1 limit of about 2^12 streams per key is gone.
//! The AAD of every v2 chunk is `header || salt` (56 bytes); for v1 it
//! is the 24-byte header.
//!
//! # Per-chunk nonce — STREAM construction
//!
//! ```text
//!   nonce = nonce_prefix (P bytes) || counter (u32 big-endian) || last_flag (1 byte)
//! ```
//!
//! `last_flag` is `0x00` for non-final chunks and `0x01` for the final
//! chunk, which is what defeats truncation: a non-final chunk and the
//! final chunk never share a nonce, so a chunk cannot be verified in the
//! other role.
//!
//! # Stream body
//!
//! ```text
//!   [header (24 B)]
//!   [salt (32 B)]                   ── v2 only
//!   [chunk_0 (chunk_size + 16 B)]   ── non-final, last_flag = 0
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

/// Header size in bytes (both format versions). A v2 stream follows
/// the header with a [`SALT_LEN`]-byte salt, which the encryptor emits
/// at the start of its first output.
pub const HEADER_LEN: usize = 24;

/// Per-chunk nonce size in bytes for ChaCha20-Poly1305 and AES-256-GCM
/// streams. XChaCha20-Poly1305 streams (v2 only) use 24-byte nonces.
pub const NONCE_LEN: usize = 12;

/// Length of the nonce prefix of a ChaCha20-Poly1305 or AES-256-GCM
/// stream. In v1 it is random and carried in the header; in v2 it is
/// derived from the key and salt.
pub const NONCE_PREFIX_LEN: usize = 7;

/// AEAD tag size (matches every shipped AEAD).
pub const TAG_LEN: usize = 16;

/// Version byte of stream format v1 (written by crypt-io 1.0.x; still
/// read by 1.1, and written on request via
/// [`StreamFormat::V1`]).
pub const VERSION: u8 = 0x01;

/// Version byte of stream format v2 (per-stream subkey; written by
/// default since 1.1.0).
pub const VERSION_2: u8 = 0x02;

/// Length of the random salt that follows a v2 header, in bytes.
/// Equal to `32`.
pub const SALT_LEN: usize = 32;

/// HKDF `info` prefix for the v2 per-stream subkey. The 24 header
/// bytes are appended to it.
pub const V2_KDF_INFO: &[u8] = b"crypt-io stream v2";

/// Default chunk-size log2 — 16 means 64 KiB chunks.
pub const DEFAULT_CHUNK_SIZE_LOG2: u8 = 16;

/// Minimum chunk-size log2 — 10 (1 KiB). Below this the per-chunk
/// AEAD overhead dominates.
pub const MIN_CHUNK_SIZE_LOG2: u8 = 10;

/// Maximum chunk-size log2 — 24 (16 MiB). Above this the buffering
/// memory cost gets uncomfortable for streaming workflows.
pub const MAX_CHUNK_SIZE_LOG2: u8 = 24;

/// Longest per-chunk nonce (XChaCha20-Poly1305).
pub(super) const MAX_NONCE_LEN: usize = 24;

/// Longest AAD: a v2 header plus its salt.
pub(super) const MAX_AAD_LEN: usize = HEADER_LEN + SALT_LEN;

/// Stream format version written by [`StreamEncryptor`](super::StreamEncryptor).
///
/// New in 1.1.0. Decryptors detect the version from the header, so this
/// only matters when encrypting.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum StreamFormat {
    /// The 1.0 format: a random 56-bit nonce prefix in the header and
    /// every chunk encrypted directly under the caller's key. Keep one
    /// key below about 2^12 (4,096) v1 streams. Only use it while some
    /// readers still run crypt-io 1.0.x, which cannot read v2.
    /// Supports ChaCha20-Poly1305 and AES-256-GCM.
    V1,
    /// The 1.1 format (default): a 32-byte random salt after the
    /// header and an HKDF-SHA256 subkey per stream, so streams under
    /// one key never share nonces in practice. Supports every
    /// [`Algorithm`].
    #[default]
    V2,
}

impl StreamFormat {
    /// The version byte this format writes into the header.
    #[must_use]
    pub const fn version_byte(self) -> u8 {
        match self {
            Self::V1 => VERSION,
            Self::V2 => VERSION_2,
        }
    }
}

/// Parsed view of a header.
#[derive(Debug, Clone, Copy)]
pub(super) struct ParsedHeader {
    pub format: StreamFormat,
    pub algorithm: Algorithm,
    pub chunk_size_log2: u8,
    /// v1 only: the random nonce prefix from the header.
    pub nonce_prefix: [u8; NONCE_PREFIX_LEN],
    /// Original 24 header bytes — the start of every chunk's AAD.
    pub raw: [u8; HEADER_LEN],
}

/// Check `chunk_size_log2` against the supported range.
pub(super) fn chunk_size_log2_in_range(log2: u8) -> bool {
    (MIN_CHUNK_SIZE_LOG2..=MAX_CHUNK_SIZE_LOG2).contains(&log2)
}

/// Build a v1 header. `nonce_prefix` must be 7 random bytes.
#[cfg(any(feature = "std", feature = "getrandom"))]
#[must_use]
pub(super) fn build_header_v1(
    algorithm: Algorithm,
    chunk_size_log2: u8,
    nonce_prefix: &[u8; NONCE_PREFIX_LEN],
) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[0..8].copy_from_slice(MAGIC);
    h[8] = VERSION;
    h[9] = algorithm.id();
    h[10] = chunk_size_log2;
    h[16..23].copy_from_slice(nonce_prefix);
    h
}

/// Build a v2 header. Bytes 11..24 are zero.
#[cfg(any(feature = "std", feature = "getrandom"))]
#[must_use]
pub(super) fn build_header_v2(algorithm: Algorithm, chunk_size_log2: u8) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[0..8].copy_from_slice(MAGIC);
    h[8] = VERSION_2;
    h[9] = algorithm.id();
    h[10] = chunk_size_log2;
    h
}

/// Parse and validate a 24-byte header.
pub(super) fn parse_header(bytes: &[u8]) -> Result<ParsedHeader> {
    if bytes.len() < HEADER_LEN {
        return Err(Error::InvalidCiphertext(alloc::format!(
            "stream header too short ({} bytes, need {HEADER_LEN})",
            bytes.len()
        )));
    }
    let mut raw = [0u8; HEADER_LEN];
    raw.copy_from_slice(&bytes[..HEADER_LEN]);

    if &raw[0..8] != MAGIC {
        return Err(Error::InvalidCiphertext(alloc::string::String::from(
            "stream magic mismatch (not a crypt-io stream)",
        )));
    }
    let format = match raw[8] {
        VERSION => StreamFormat::V1,
        VERSION_2 => StreamFormat::V2,
        other => {
            return Err(Error::InvalidCiphertext(alloc::format!(
                "unsupported stream version: 0x{other:02x} (this build understands 0x01 and 0x02)"
            )));
        }
    };
    // v1 has no byte for XChaCha20-Poly1305.
    let ((
        StreamFormat::V1,
        Some(algorithm @ (Algorithm::ChaCha20Poly1305 | Algorithm::Aes256Gcm)),
    )
    | (StreamFormat::V2, Some(algorithm))) = (format, Algorithm::from_id(raw[9]))
    else {
        return Err(Error::InvalidCiphertext(alloc::format!(
            "unknown algorithm byte: 0x{:02x}",
            raw[9]
        )));
    };
    let chunk_size_log2 = raw[10];
    if !chunk_size_log2_in_range(chunk_size_log2) {
        return Err(Error::InvalidCiphertext(alloc::format!(
            "chunk_size_log2 out of range: {chunk_size_log2}"
        )));
    }
    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    match format {
        StreamFormat::V1 => nonce_prefix.copy_from_slice(&raw[16..23]),
        StreamFormat::V2 => {
            if raw[11..].iter().any(|&b| b != 0) {
                return Err(Error::InvalidCiphertext(alloc::string::String::from(
                    "stream v2 header: reserved bytes must be zero",
                )));
            }
        }
    }

    Ok(ParsedHeader {
        format,
        algorithm,
        chunk_size_log2,
        nonce_prefix,
        raw,
    })
}

/// Derive the v2 subkey and nonce prefix for one stream. Writes the
/// subkey to `subkey` and the `nonce_len - 5` prefix bytes to the start
/// of `nonce_base`. The intermediate output is wiped.
pub(super) fn derive_v2(
    key: &[u8; 32],
    header: &[u8; HEADER_LEN],
    salt: &[u8],
    nonce_len: usize,
    subkey: &mut [u8; 32],
    nonce_base: &mut [u8; MAX_NONCE_LEN],
) -> Result<()> {
    let prefix_len = nonce_len - 5;
    let mut okm = [0u8; 32 + MAX_NONCE_LEN];
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), key);
    let result = hk
        .expand_multi_info(&[V2_KDF_INFO, header], &mut okm[..32 + prefix_len])
        .map_err(|_| Error::Kdf("stream v2 subkey"));
    if result.is_ok() {
        subkey.copy_from_slice(&okm[..32]);
        nonce_base[..prefix_len].copy_from_slice(&okm[32..32 + prefix_len]);
    }
    crate::wipe::wipe_bytes(&mut okm);
    result
}

/// Build the per-chunk nonce: `prefix || counter (BE) || last_flag`,
/// `nonce_len` bytes long, from a base whose first `nonce_len - 5`
/// bytes are the prefix.
#[must_use]
pub(super) fn chunk_nonce(
    nonce_base: &[u8; MAX_NONCE_LEN],
    nonce_len: usize,
    counter: u32,
    is_final: bool,
) -> [u8; MAX_NONCE_LEN] {
    let mut n = *nonce_base;
    n[nonce_len - 5..nonce_len - 1].copy_from_slice(&counter.to_be_bytes());
    n[nonce_len - 1] = u8::from(is_final);
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
    fn header_v1_round_trip() {
        let prefix = [0xaau8; NONCE_PREFIX_LEN];
        for alg in [Algorithm::ChaCha20Poly1305, Algorithm::Aes256Gcm] {
            let h = build_header_v1(alg, 16, &prefix);
            let p = parse_header(&h).unwrap();
            assert_eq!(p.format, StreamFormat::V1);
            assert_eq!(p.algorithm, alg);
            assert_eq!(p.chunk_size_log2, 16);
            assert_eq!(p.nonce_prefix, prefix);
            assert_eq!(p.raw, h);
        }
    }

    #[test]
    fn header_v2_round_trip() {
        for alg in [
            Algorithm::ChaCha20Poly1305,
            Algorithm::Aes256Gcm,
            Algorithm::XChaCha20Poly1305,
        ] {
            let h = build_header_v2(alg, 12);
            assert_eq!(&h[11..], &[0u8; 13]);
            let p = parse_header(&h).unwrap();
            assert_eq!(p.format, StreamFormat::V2);
            assert_eq!(p.algorithm, alg);
            assert_eq!(p.chunk_size_log2, 12);
        }
    }

    #[test]
    fn header_v1_rejects_xchacha_byte() {
        let mut h = build_header_v1(Algorithm::ChaCha20Poly1305, 16, &[0u8; 7]);
        h[9] = Algorithm::XChaCha20Poly1305.id();
        assert!(matches!(
            parse_header(&h).unwrap_err(),
            Error::InvalidCiphertext(_)
        ));
    }

    #[test]
    fn header_v2_rejects_nonzero_reserved_bytes() {
        for i in 11..HEADER_LEN {
            let mut h = build_header_v2(Algorithm::ChaCha20Poly1305, 16);
            h[i] = 1;
            assert!(
                matches!(parse_header(&h).unwrap_err(), Error::InvalidCiphertext(_)),
                "byte {i}"
            );
        }
    }

    #[test]
    fn header_v1_ignores_reserved_bytes() {
        // FILE_FORMAT.md: v1 decoders must not reject on reserved bytes.
        let mut h = build_header_v1(Algorithm::ChaCha20Poly1305, 16, &[0u8; 7]);
        h[11] = 0xff;
        h[23] = 0xff;
        assert!(parse_header(&h).is_ok());
    }

    #[test]
    fn header_rejects_wrong_magic() {
        let mut h = build_header_v2(Algorithm::ChaCha20Poly1305, 16);
        h[0] = b'X';
        let err = parse_header(&h).unwrap_err();
        assert!(matches!(err, Error::InvalidCiphertext(_)));
    }

    #[test]
    fn header_rejects_unknown_version() {
        for v in [0x00u8, 0x03, 0xff] {
            let mut h = build_header_v2(Algorithm::ChaCha20Poly1305, 16);
            h[8] = v;
            let err = parse_header(&h).unwrap_err();
            assert!(matches!(err, Error::InvalidCiphertext(_)));
        }
    }

    #[test]
    fn header_rejects_unknown_algorithm() {
        let mut h = build_header_v2(Algorithm::ChaCha20Poly1305, 16);
        h[9] = 0x42;
        let err = parse_header(&h).unwrap_err();
        assert!(matches!(err, Error::InvalidCiphertext(_)));
    }

    #[test]
    fn header_rejects_out_of_range_chunk_size_log2() {
        for bad in [0u8, 9, 25, 64, 255] {
            let mut h = build_header_v2(Algorithm::ChaCha20Poly1305, 16);
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
        let mut base = [0u8; MAX_NONCE_LEN];
        base[..NONCE_PREFIX_LEN].copy_from_slice(&[0xcc; NONCE_PREFIX_LEN]);
        let n0 = chunk_nonce(&base, NONCE_LEN, 0, false);
        let n1 = chunk_nonce(&base, NONCE_LEN, 1, false);
        let n0_final = chunk_nonce(&base, NONCE_LEN, 0, true);
        assert_ne!(n0[..NONCE_LEN], n1[..NONCE_LEN]);
        assert_ne!(n0[..NONCE_LEN], n0_final[..NONCE_LEN]);
        assert_ne!(n1[..NONCE_LEN], n0_final[..NONCE_LEN]);
        assert_eq!(&n0[..7], &[0xcc; 7]);
        assert_eq!(n0[7..11], 0u32.to_be_bytes());
        assert_eq!(n0[11], 0);
        assert_eq!(n0_final[11], 1);
        // 24-byte layout: counter at 19..23, flag at 23.
        let x = chunk_nonce(&base, 24, 0x0102_0304, true);
        assert_eq!(x[19..23], [1, 2, 3, 4]);
        assert_eq!(x[23], 1);
    }

    #[test]
    fn derive_v2_depends_on_key_salt_and_header() {
        let key = [1u8; 32];
        let h = build_header_v2(Algorithm::ChaCha20Poly1305, 16);
        let mut k1 = [0u8; 32];
        let mut b1 = [0u8; MAX_NONCE_LEN];
        derive_v2(&key, &h, &[2u8; SALT_LEN], NONCE_LEN, &mut k1, &mut b1).unwrap();
        let mut k2 = [0u8; 32];
        let mut b2 = [0u8; MAX_NONCE_LEN];
        derive_v2(&key, &h, &[3u8; SALT_LEN], NONCE_LEN, &mut k2, &mut b2).unwrap();
        assert_ne!(k1, k2);
        let h_aes = build_header_v2(Algorithm::Aes256Gcm, 16);
        derive_v2(&key, &h_aes, &[2u8; SALT_LEN], NONCE_LEN, &mut k2, &mut b2).unwrap();
        assert_ne!(k1, k2);
        assert_ne!(k1, key);
        // Only the prefix bytes are written.
        assert_eq!(
            &b1[NONCE_PREFIX_LEN..],
            &[0u8; MAX_NONCE_LEN - NONCE_PREFIX_LEN]
        );
    }

    #[test]
    fn chunk_size_from_log2_matches_pow2() {
        assert_eq!(chunk_size_from_log2(10), 1024);
        assert_eq!(chunk_size_from_log2(16), 65_536);
        assert_eq!(chunk_size_from_log2(20), 1_048_576);
    }
}
