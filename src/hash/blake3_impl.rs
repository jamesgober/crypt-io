//! BLAKE3 backend.
//!
//! Thin wrapper over the `blake3` crate. BLAKE3 is the default hash for
//! `crypt-io`: fastest cryptographic hash on every modern platform, with a
//! 32-byte default output and an extendable-output (XOF) mode for arbitrary
//! lengths.

use alloc::vec::Vec;

use super::BLAKE3_OUTPUT_LEN;

/// Compute a 32-byte BLAKE3 digest of `data`.
///
/// # Example
///
/// ```
/// # #[cfg(feature = "hash-blake3")] {
/// use crypt_io::hash;
/// let d = hash::blake3(b"abc");
/// assert_eq!(d.len(), 32);
/// # }
/// ```
#[must_use]
pub fn blake3(data: &[u8]) -> [u8; BLAKE3_OUTPUT_LEN] {
    *::blake3::hash(data).as_bytes()
}

/// Compute a BLAKE3 digest of arbitrary length via the extendable-output
/// function (XOF) mode.
///
/// `len` may be any value, including zero. The output is deterministic in
/// `data` — different inputs produce uncorrelated outputs, identical inputs
/// produce identical outputs.
///
/// For the common 32-byte case prefer [`blake3()`] — it skips the XOF reader
/// path entirely.
///
/// # Example
///
/// ```
/// # #[cfg(feature = "hash-blake3")] {
/// use crypt_io::hash;
/// let d = hash::blake3_long(b"abc", 64);
/// assert_eq!(d.len(), 64);
/// # }
/// ```
#[must_use]
pub fn blake3_long(data: &[u8], len: usize) -> Vec<u8> {
    let mut hasher = ::blake3::Hasher::new();
    let _ = hasher.update(data);
    let mut out = alloc::vec![0u8; len];
    let mut reader = hasher.finalize_xof();
    reader.fill(&mut out);
    out
}

/// Streaming BLAKE3 hasher for inputs that don't fit in memory or arrive
/// in chunks.
///
/// Construct with [`Blake3Hasher::new`], feed data with
/// [`update`](Self::update), and finalise with [`finalize`](Self::finalize)
/// (returns the default 32-byte digest) or
/// [`finalize_xof`](Self::finalize_xof) (returns an arbitrary-length
/// digest).
///
/// `update` can be called any number of times; the hasher is consumed by
/// finalisation.
///
/// # Example
///
/// ```
/// # #[cfg(feature = "hash-blake3")] {
/// use crypt_io::hash::Blake3Hasher;
///
/// let mut h = Blake3Hasher::new();
/// h.update(b"first ");
/// h.update(b"second");
/// let d = h.finalize();
/// assert_eq!(d.len(), 32);
/// # }
/// ```
#[derive(Debug, Clone, Default)]
pub struct Blake3Hasher {
    inner: ::blake3::Hasher,
}

impl Blake3Hasher {
    /// Construct a fresh hasher.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: ::blake3::Hasher::new(),
        }
    }

    /// Absorb `data` into the running hash. Returns `&mut Self` so calls
    /// can chain.
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        let _ = self.inner.update(data);
        self
    }

    /// Finalise the hash and return a 32-byte digest. Consumes the hasher.
    #[must_use]
    pub fn finalize(self) -> [u8; BLAKE3_OUTPUT_LEN] {
        *self.inner.finalize().as_bytes()
    }

    /// Finalise the hash and return `len` bytes of XOF output. Consumes the
    /// hasher.
    #[must_use]
    pub fn finalize_xof(self, len: usize) -> Vec<u8> {
        let mut out = alloc::vec![0u8; len];
        let mut reader = self.inner.finalize_xof();
        reader.fill(&mut out);
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, unused_results)]
mod tests {
    use super::*;

    // BLAKE3 official test vectors. The canonical reference is the
    // `BLAKE3-team/BLAKE3` repository's `test_vectors.json`. The vectors
    // below are the unkeyed hashes for the well-known short inputs.
    //
    // Empty input — the first vector in every published test set.
    const KAT_EMPTY: [u8; 32] = [
        0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc, 0xc9,
        0x49, 0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca, 0xe4, 0x1f,
        0x32, 0x62,
    ];

    // "IETF" — 4-byte ASCII input. Value computed against the upstream
    // `blake3` crate and asserted byte-for-byte so we catch any future
    // wrapper-level mistake.
    const KAT_IETF: [u8; 32] = [
        0x83, 0xa2, 0xde, 0x1e, 0xe6, 0xf4, 0xe6, 0xab, 0x68, 0x68, 0x89, 0x24, 0x8f, 0x4e, 0xc0,
        0xcf, 0x4c, 0xc5, 0x70, 0x94, 0x46, 0xa6, 0x82, 0xff, 0xd1, 0xcb, 0xb4, 0xd6, 0x16, 0x51,
        0x81, 0xe2,
    ];

    #[test]
    fn kat_empty() {
        assert_eq!(blake3(b""), KAT_EMPTY);
    }

    #[test]
    fn kat_ietf() {
        assert_eq!(blake3(b"IETF"), KAT_IETF);
    }

    #[test]
    fn xof_length_matches_request() {
        for n in [0usize, 1, 16, 32, 64, 128, 1024] {
            assert_eq!(blake3_long(b"input", n).len(), n);
        }
    }

    #[test]
    fn xof_is_deterministic_in_input() {
        let a = blake3_long(b"same", 64);
        let b = blake3_long(b"same", 64);
        assert_eq!(a, b);
        let c = blake3_long(b"diff", 64);
        assert_ne!(a, c);
    }

    #[test]
    fn xof_extends_default_output() {
        // BLAKE3 XOF mode is a superset of the default hash: the first
        // 32 bytes of `blake3_long(data, 32+N)` match `blake3(data)`.
        let extended = blake3_long(b"foo bar", 64);
        let short = blake3(b"foo bar");
        assert_eq!(&extended[..32], &short[..]);
    }

    #[test]
    fn streaming_equals_one_shot() {
        let data = b"the quick brown fox jumps over the lazy dog";
        let one_shot = blake3(data);
        let mut h = Blake3Hasher::new();
        h.update(&data[..10]);
        h.update(&data[10..25]);
        h.update(&data[25..]);
        let streamed = h.finalize();
        assert_eq!(one_shot, streamed);
    }

    #[test]
    fn streaming_chain_returns_self() {
        let data = b"chain-friendly";
        let mut h = Blake3Hasher::new();
        let _ret: &mut Blake3Hasher = h.update(b"chain").update(b"-friendly");
        let d = blake3(data);
        let mut h2 = Blake3Hasher::new();
        h2.update(b"chain").update(b"-friendly");
        assert_eq!(h2.finalize(), d);
    }

    #[test]
    fn streaming_xof_finalize_matches_one_shot_long() {
        let data = b"streaming-xof";
        let one_shot = blake3_long(data, 100);
        let mut h = Blake3Hasher::new();
        h.update(data);
        let streamed = h.finalize_xof(100);
        assert_eq!(one_shot, streamed);
    }

    #[test]
    fn empty_input_through_streaming() {
        let mut h = Blake3Hasher::new();
        let _ = h.update(b"");
        assert_eq!(h.finalize(), KAT_EMPTY);
    }
}
