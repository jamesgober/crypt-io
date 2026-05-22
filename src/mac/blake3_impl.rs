//! BLAKE3 keyed-mode backend.
//!
//! BLAKE3's keyed mode (`blake3::keyed_hash`) takes a fixed 32-byte key
//! and produces a 32-byte tag. It is the BLAKE3-native authenticator and
//! is typically 4–10× faster than HMAC-SHA256 on modern hardware.
//!
//! Unlike HMAC, the key is type-checked as `&[u8; 32]` — there is no
//! variable-length key surface. This matches BLAKE3's design intent (the
//! key is a fixed-size secret derived elsewhere — from `key-vault`, from
//! an HKDF expansion, etc.) and removes a class of "I gave it the wrong
//! key length" bugs at compile time.

use super::{BLAKE3_MAC_KEY_LEN, BLAKE3_MAC_OUTPUT_LEN};

/// Compute a BLAKE3 keyed-mode tag over `data` under `key`.
///
/// # Example
///
/// ```
/// # #[cfg(feature = "mac-blake3")] {
/// use crypt_io::mac;
/// let key = [0x42u8; 32];
/// let tag = mac::blake3_keyed(&key, b"message");
/// assert_eq!(tag.len(), 32);
/// # }
/// ```
#[must_use]
pub fn blake3_keyed(key: &[u8; BLAKE3_MAC_KEY_LEN], data: &[u8]) -> [u8; BLAKE3_MAC_OUTPUT_LEN] {
    *::blake3::keyed_hash(key, data).as_bytes()
}

/// Verify a BLAKE3 keyed-mode tag in constant time.
///
/// Computes the tag for `(key, data)` and compares it to `expected_tag`
/// using BLAKE3's [`Hash`] equality, which is constant-time (the BLAKE3
/// crate documents this guarantee on `Hash::PartialEq`).
///
/// Returns `true` if the tags match, `false` otherwise (including when
/// `expected_tag` is not 32 bytes long).
///
/// **Always** use this rather than `tag == expected`.
///
/// [`Hash`]: ::blake3::Hash
///
/// # Example
///
/// ```
/// # #[cfg(feature = "mac-blake3")] {
/// use crypt_io::mac;
/// let key = [0x42u8; 32];
/// let tag = mac::blake3_keyed(&key, b"message");
/// assert!(mac::blake3_keyed_verify(&key, b"message", &tag));
/// assert!(!mac::blake3_keyed_verify(&key, b"tampered", &tag));
/// # }
/// ```
#[must_use]
pub fn blake3_keyed_verify(
    key: &[u8; BLAKE3_MAC_KEY_LEN],
    data: &[u8],
    expected_tag: &[u8],
) -> bool {
    if expected_tag.len() != BLAKE3_MAC_OUTPUT_LEN {
        return false;
    }
    let computed = ::blake3::keyed_hash(key, data);
    let mut expected = [0u8; BLAKE3_MAC_OUTPUT_LEN];
    expected.copy_from_slice(expected_tag);
    let expected_hash = ::blake3::Hash::from_bytes(expected);
    computed == expected_hash
}

/// Streaming BLAKE3 keyed-mode MAC for inputs that don't fit in memory.
///
/// Construct with [`Blake3Mac::new`], absorb data with
/// [`update`](Self::update), and finalise with [`finalize`](Self::finalize)
/// (returns the 32-byte tag) or [`verify`](Self::verify) (constant-time
/// compare against an expected tag).
///
/// # Example
///
/// ```
/// # #[cfg(feature = "mac-blake3")] {
/// use crypt_io::mac::Blake3Mac;
///
/// let key = [0x42u8; 32];
/// let mut m = Blake3Mac::new(&key);
/// m.update(b"first chunk ");
/// m.update(b"second chunk");
/// let tag = m.finalize();
/// assert_eq!(tag.len(), 32);
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct Blake3Mac {
    inner: ::blake3::Hasher,
}

impl Blake3Mac {
    /// Construct a fresh keyed MAC.
    ///
    /// Unlike HMAC this is infallible — BLAKE3's keyed mode takes a
    /// type-checked 32-byte key, so there is no runtime length-check to
    /// fail.
    #[must_use]
    pub fn new(key: &[u8; BLAKE3_MAC_KEY_LEN]) -> Self {
        Self {
            inner: ::blake3::Hasher::new_keyed(key),
        }
    }

    /// Absorb `data` into the running MAC. Returns `&mut Self` so calls
    /// can chain.
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        let _ = self.inner.update(data);
        self
    }

    /// Finalise the MAC and return the 32-byte tag. Consumes the hasher.
    #[must_use]
    pub fn finalize(self) -> [u8; BLAKE3_MAC_OUTPUT_LEN] {
        *self.inner.finalize().as_bytes()
    }

    /// Finalise and verify against `expected_tag` in constant time.
    /// Returns `true` iff the computed tag matches `expected_tag` (and
    /// `expected_tag` is the correct length).
    /// Consumes the hasher.
    #[must_use]
    pub fn verify(self, expected_tag: &[u8]) -> bool {
        if expected_tag.len() != BLAKE3_MAC_OUTPUT_LEN {
            return false;
        }
        let mut expected = [0u8; BLAKE3_MAC_OUTPUT_LEN];
        expected.copy_from_slice(expected_tag);
        let expected_hash = ::blake3::Hash::from_bytes(expected);
        self.inner.finalize() == expected_hash
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, unused_results)]
mod tests {
    use super::*;

    // BLAKE3 official test set uses a 32-byte ASCII key
    // "whats the Elvish word for friend" (exactly 32 chars). The empty-
    // input keyed tag is pinned below. Subsequent tests verify the
    // wrapper round-trips against the upstream primitive for known
    // inputs.

    const ELVISH_KEY: &[u8; 32] = b"whats the Elvish word for friend";

    // Empty input keyed tag — value computed against the upstream `blake3`
    // crate and pinned as a byte-array constant so we catch any future
    // wrapper-level mistake immediately.
    const KAT_EMPTY: [u8; 32] = [
        0x92, 0xb2, 0xb7, 0x56, 0x04, 0xed, 0x3c, 0x76, 0x1f, 0x9d, 0x6f, 0x62, 0x39, 0x2c, 0x8a,
        0x92, 0x27, 0xad, 0x0e, 0xa3, 0xf0, 0x95, 0x73, 0xe7, 0x83, 0xf1, 0x49, 0x8a, 0x4e, 0xd6,
        0x0d, 0x26,
    ];

    #[test]
    fn kat_empty_input() {
        assert_eq!(blake3_keyed(ELVISH_KEY, b""), KAT_EMPTY);
        assert!(blake3_keyed_verify(ELVISH_KEY, b"", &KAT_EMPTY));
    }

    #[test]
    fn round_trip_short_input() {
        let key = [0x01u8; 32];
        let tag = blake3_keyed(&key, b"the quick brown fox");
        assert!(blake3_keyed_verify(&key, b"the quick brown fox", &tag));
    }

    #[test]
    fn different_keys_produce_different_tags() {
        let key1 = [0x01u8; 32];
        let key2 = [0x02u8; 32];
        let tag1 = blake3_keyed(&key1, b"same data");
        let tag2 = blake3_keyed(&key2, b"same data");
        assert_ne!(tag1, tag2);
    }

    #[test]
    fn different_data_produces_different_tags() {
        let key = [0x01u8; 32];
        let tag1 = blake3_keyed(&key, b"data one");
        let tag2 = blake3_keyed(&key, b"data two");
        assert_ne!(tag1, tag2);
    }

    #[test]
    fn verify_rejects_wrong_tag() {
        let key = [0x01u8; 32];
        let tag = blake3_keyed(&key, b"message");
        let mut tampered = tag;
        tampered[0] ^= 0x01;
        assert!(!blake3_keyed_verify(&key, b"message", &tampered));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let correct = [0x01u8; 32];
        let wrong = [0x02u8; 32];
        let tag = blake3_keyed(&correct, b"message");
        assert!(!blake3_keyed_verify(&wrong, b"message", &tag));
    }

    #[test]
    fn verify_rejects_wrong_data() {
        let key = [0x01u8; 32];
        let tag = blake3_keyed(&key, b"original");
        assert!(!blake3_keyed_verify(&key, b"tampered", &tag));
    }

    #[test]
    fn verify_rejects_truncated_tag() {
        let key = [0x01u8; 32];
        let tag = blake3_keyed(&key, b"message");
        assert!(!blake3_keyed_verify(&key, b"message", &tag[..16]));
    }

    #[test]
    fn verify_rejects_oversized_tag() {
        let key = [0x01u8; 32];
        let tag = blake3_keyed(&key, b"message");
        let mut oversized = alloc::vec::Vec::from(&tag[..]);
        oversized.push(0u8);
        assert!(!blake3_keyed_verify(&key, b"message", &oversized));
    }

    // --- Streaming-equivalence + verify tests ---

    #[test]
    fn streaming_equals_one_shot() {
        let key = [0x42u8; 32];
        let data = b"the quick brown fox jumps over the lazy dog";
        let one_shot = blake3_keyed(&key, data);
        let mut m = Blake3Mac::new(&key);
        m.update(&data[..10]);
        m.update(&data[10..25]);
        m.update(&data[25..]);
        assert_eq!(m.finalize(), one_shot);
    }

    #[test]
    fn streaming_chain_returns_self() {
        let key = [0x01u8; 32];
        let mut m = Blake3Mac::new(&key);
        m.update(b"chain").update(b"-friendly");
        let one_shot = blake3_keyed(&key, b"chain-friendly");
        assert_eq!(m.finalize(), one_shot);
    }

    #[test]
    fn streaming_verify_accepts_correct_tag() {
        let key = [0x01u8; 32];
        let tag = blake3_keyed(&key, b"msg");
        let mut m = Blake3Mac::new(&key);
        m.update(b"msg");
        assert!(m.verify(&tag));
    }

    #[test]
    fn streaming_verify_rejects_wrong_tag() {
        let key = [0x01u8; 32];
        let tag = blake3_keyed(&key, b"msg");
        let mut tampered = tag;
        tampered[0] ^= 0xff;
        let mut m = Blake3Mac::new(&key);
        m.update(b"msg");
        assert!(!m.verify(&tampered));
    }
}
