//! HMAC-SHA256 / HMAC-SHA512 backend.
//!
//! Thin wrapper over the `hmac` crate (`RustCrypto`). HMAC accepts a key
//! of any length — short keys are zero-padded, long keys are hashed down
//! to the block size, both per [RFC 2104]. The wrapper preserves that
//! contract; callers do not need to size their keys.
//!
//! [RFC 2104]: https://datatracker.ietf.org/doc/html/rfc2104

use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};

use super::{HMAC_SHA256_OUTPUT_LEN, HMAC_SHA512_OUTPUT_LEN};
use crate::error::{Error, Result};

type HmacSha256Inner = Hmac<Sha256>;
type HmacSha512Inner = Hmac<Sha512>;

/// Compute an HMAC-SHA256 tag over `data` under `key`.
///
/// # Errors
///
/// Returns [`Error::Mac`] if the upstream `hmac` crate refuses the key.
/// In practice this never happens — HMAC accepts any key length — but the
/// upstream API is fallible by signature, so the wrapper preserves it.
///
/// # Example
///
/// ```
/// # #[cfg(feature = "mac-hmac")] {
/// use crypt_io::mac;
/// let tag = mac::hmac_sha256(b"shared key", b"message")?;
/// assert_eq!(tag.len(), 32);
/// # }
/// # Ok::<(), crypt_io::Error>(())
/// ```
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; HMAC_SHA256_OUTPUT_LEN]> {
    let mut mac =
        HmacSha256Inner::new_from_slice(key).map_err(|_| Error::Mac("hmac-sha256 init"))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().into())
}

/// Verify an HMAC-SHA256 tag in constant time.
///
/// Computes the tag for `(key, data)` and compares it to `expected_tag`.
/// Returns `Ok(true)` if the tags match, `Ok(false)` if they don't, and
/// [`Error::Mac`] if the upstream MAC could not be constructed.
///
/// **Always** use this rather than `tag == expected`. The comparison
/// inside is `subtle::ConstantTimeEq` (via the `hmac` crate's
/// `verify_slice`), so timing does not leak how many leading bytes
/// matched.
///
/// # Errors
///
/// Same as [`hmac_sha256`] — the upstream MAC construction is fallible
/// by signature, unreachable in practice.
///
/// # Example
///
/// ```
/// # #[cfg(feature = "mac-hmac")] {
/// use crypt_io::mac;
/// let key = b"shared";
/// let tag = mac::hmac_sha256(key, b"data")?;
/// assert!(mac::hmac_sha256_verify(key, b"data", &tag)?);
/// assert!(!mac::hmac_sha256_verify(key, b"tampered", &tag)?);
/// # }
/// # Ok::<(), crypt_io::Error>(())
/// ```
pub fn hmac_sha256_verify(key: &[u8], data: &[u8], expected_tag: &[u8]) -> Result<bool> {
    let mut mac =
        HmacSha256Inner::new_from_slice(key).map_err(|_| Error::Mac("hmac-sha256 init"))?;
    mac.update(data);
    Ok(mac.verify_slice(expected_tag).is_ok())
}

/// Compute an HMAC-SHA512 tag over `data` under `key`.
///
/// # Errors
///
/// Same as [`hmac_sha256`].
///
/// # Example
///
/// ```
/// # #[cfg(feature = "mac-hmac")] {
/// use crypt_io::mac;
/// let tag = mac::hmac_sha512(b"shared key", b"message")?;
/// assert_eq!(tag.len(), 64);
/// # }
/// # Ok::<(), crypt_io::Error>(())
/// ```
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> Result<[u8; HMAC_SHA512_OUTPUT_LEN]> {
    let mut mac =
        HmacSha512Inner::new_from_slice(key).map_err(|_| Error::Mac("hmac-sha512 init"))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().into())
}

/// Verify an HMAC-SHA512 tag in constant time. See [`hmac_sha256_verify`].
///
/// # Errors
///
/// Same as [`hmac_sha256_verify`].
pub fn hmac_sha512_verify(key: &[u8], data: &[u8], expected_tag: &[u8]) -> Result<bool> {
    let mut mac =
        HmacSha512Inner::new_from_slice(key).map_err(|_| Error::Mac("hmac-sha512 init"))?;
    mac.update(data);
    Ok(mac.verify_slice(expected_tag).is_ok())
}

/// Streaming HMAC-SHA256 for inputs that don't fit in memory.
///
/// Construct with [`HmacSha256::new`], absorb data with
/// [`update`](Self::update), finalise with [`finalize`](Self::finalize)
/// (returns the 32-byte tag) or [`verify`](Self::verify) (constant-time
/// compare against an expected tag).
///
/// # Example
///
/// ```
/// # #[cfg(feature = "mac-hmac")] {
/// use crypt_io::mac::HmacSha256;
///
/// let mut m = HmacSha256::new(b"shared key")?;
/// m.update(b"first chunk ");
/// m.update(b"second chunk");
/// let tag = m.finalize();
/// assert_eq!(tag.len(), 32);
/// # }
/// # Ok::<(), crypt_io::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct HmacSha256 {
    inner: HmacSha256Inner,
}

impl HmacSha256 {
    /// Construct a fresh hasher under `key`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Mac`] if the upstream `hmac` crate refuses the key.
    /// Unreachable in practice (HMAC accepts any key length).
    pub fn new(key: &[u8]) -> Result<Self> {
        let inner =
            HmacSha256Inner::new_from_slice(key).map_err(|_| Error::Mac("hmac-sha256 init"))?;
        Ok(Self { inner })
    }

    /// Absorb `data` into the running MAC. Returns `&mut Self` so calls
    /// can chain.
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.inner.update(data);
        self
    }

    /// Finalise the MAC and return the 32-byte tag. Consumes the hasher.
    #[must_use]
    pub fn finalize(self) -> [u8; HMAC_SHA256_OUTPUT_LEN] {
        self.inner.finalize().into_bytes().into()
    }

    /// Finalise and verify against `expected_tag` in constant time.
    /// Returns `true` iff the computed tag matches `expected_tag`.
    /// Consumes the hasher.
    #[must_use]
    pub fn verify(self, expected_tag: &[u8]) -> bool {
        self.inner.verify_slice(expected_tag).is_ok()
    }
}

/// Streaming HMAC-SHA512. Same shape as [`HmacSha256`] with a 64-byte tag.
///
/// # Example
///
/// ```
/// # #[cfg(feature = "mac-hmac")] {
/// use crypt_io::mac::HmacSha512;
///
/// let mut m = HmacSha512::new(b"shared key")?;
/// m.update(b"first chunk ");
/// m.update(b"second chunk");
/// let tag = m.finalize();
/// assert_eq!(tag.len(), 64);
/// # }
/// # Ok::<(), crypt_io::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct HmacSha512 {
    inner: HmacSha512Inner,
}

impl HmacSha512 {
    /// Construct a fresh hasher under `key`.
    ///
    /// # Errors
    ///
    /// See [`HmacSha256::new`].
    pub fn new(key: &[u8]) -> Result<Self> {
        let inner =
            HmacSha512Inner::new_from_slice(key).map_err(|_| Error::Mac("hmac-sha512 init"))?;
        Ok(Self { inner })
    }

    /// Absorb `data` into the running MAC. Returns `&mut Self` so calls
    /// can chain.
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.inner.update(data);
        self
    }

    /// Finalise the MAC and return the 64-byte tag. Consumes the hasher.
    #[must_use]
    pub fn finalize(self) -> [u8; HMAC_SHA512_OUTPUT_LEN] {
        self.inner.finalize().into_bytes().into()
    }

    /// Finalise and verify against `expected_tag` in constant time.
    /// Returns `true` iff the computed tag matches `expected_tag`.
    /// Consumes the hasher.
    #[must_use]
    pub fn verify(self, expected_tag: &[u8]) -> bool {
        self.inner.verify_slice(expected_tag).is_ok()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, unused_results)]
mod tests {
    use super::*;

    fn hex_to_bytes(s: &str) -> alloc::vec::Vec<u8> {
        hex::decode(s).expect("valid hex")
    }

    // RFC 4231 test vectors for HMAC-SHA256 and HMAC-SHA512. The full
    // set has 7 cases; we ship cases 1 and 2, which together cover the
    // basics (short repeated-byte key + ASCII key with ASCII data) and
    // are the most commonly cited.

    // --- HMAC-SHA256 KATs ---

    /// RFC 4231 Test Case 1: K = 0x0b × 20, data = "Hi There".
    #[test]
    fn hmac_sha256_rfc4231_case1() {
        let key = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let data = b"Hi There";
        let expected =
            hex_to_bytes("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        assert_eq!(&hmac_sha256(&key, data).unwrap()[..], &expected[..]);
        assert!(hmac_sha256_verify(&key, data, &expected).unwrap());
    }

    /// RFC 4231 Test Case 2: K = "Jefe" (4 bytes — shorter than block).
    #[test]
    fn hmac_sha256_rfc4231_case2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected =
            hex_to_bytes("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        assert_eq!(&hmac_sha256(key, data).unwrap()[..], &expected[..]);
        assert!(hmac_sha256_verify(key, data, &expected).unwrap());
    }

    // --- HMAC-SHA512 KATs ---

    /// RFC 4231 Test Case 1 (SHA-512 variant).
    #[test]
    fn hmac_sha512_rfc4231_case1() {
        let key = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let data = b"Hi There";
        let expected = hex_to_bytes(
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde\
             daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
        );
        assert_eq!(&hmac_sha512(&key, data).unwrap()[..], &expected[..]);
        assert!(hmac_sha512_verify(&key, data, &expected).unwrap());
    }

    /// RFC 4231 Test Case 2 (SHA-512 variant).
    #[test]
    fn hmac_sha512_rfc4231_case2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected = hex_to_bytes(
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
             9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
        );
        assert_eq!(&hmac_sha512(key, data).unwrap()[..], &expected[..]);
        assert!(hmac_sha512_verify(key, data, &expected).unwrap());
    }

    // --- Verify-rejection tests ---

    #[test]
    fn hmac_sha256_verify_rejects_wrong_tag() {
        let tag = hmac_sha256(b"key", b"data").unwrap();
        let mut tampered = tag;
        tampered[0] ^= 0x01;
        assert!(!hmac_sha256_verify(b"key", b"data", &tampered).unwrap());
    }

    #[test]
    fn hmac_sha256_verify_rejects_wrong_key() {
        let tag = hmac_sha256(b"correct", b"data").unwrap();
        assert!(!hmac_sha256_verify(b"wrong", b"data", &tag).unwrap());
    }

    #[test]
    fn hmac_sha256_verify_rejects_wrong_data() {
        let tag = hmac_sha256(b"key", b"original").unwrap();
        assert!(!hmac_sha256_verify(b"key", b"tampered", &tag).unwrap());
    }

    #[test]
    fn hmac_sha256_verify_rejects_truncated_tag() {
        let tag = hmac_sha256(b"key", b"data").unwrap();
        // upstream `verify_slice` rejects wrong-length tags; we propagate
        // the boolean rejection without surfacing the length detail.
        assert!(!hmac_sha256_verify(b"key", b"data", &tag[..16]).unwrap());
    }

    #[test]
    fn hmac_sha512_verify_rejects_wrong_tag() {
        let tag = hmac_sha512(b"key", b"data").unwrap();
        let mut tampered = tag;
        tampered[0] ^= 0x01;
        assert!(!hmac_sha512_verify(b"key", b"data", &tampered).unwrap());
    }

    // --- Streaming-equivalence tests ---

    #[test]
    fn hmac_sha256_streaming_equals_one_shot() {
        let key = b"shared secret";
        let data = b"the quick brown fox jumps over the lazy dog";
        let one_shot = hmac_sha256(key, data).unwrap();
        let mut m = HmacSha256::new(key).unwrap();
        m.update(&data[..10]);
        m.update(&data[10..25]);
        m.update(&data[25..]);
        assert_eq!(m.finalize(), one_shot);
    }

    #[test]
    fn hmac_sha512_streaming_equals_one_shot() {
        let key = b"shared secret";
        let data = b"the quick brown fox jumps over the lazy dog";
        let one_shot = hmac_sha512(key, data).unwrap();
        let mut m = HmacSha512::new(key).unwrap();
        m.update(&data[..10]);
        m.update(&data[10..25]);
        m.update(&data[25..]);
        assert_eq!(m.finalize(), one_shot);
    }

    #[test]
    fn hmac_sha256_streaming_chain_returns_self() {
        let mut m = HmacSha256::new(b"k").unwrap();
        m.update(b"chain").update(b"-friendly");
        assert_eq!(m.finalize(), hmac_sha256(b"k", b"chain-friendly").unwrap());
    }

    #[test]
    fn hmac_sha512_streaming_chain_returns_self() {
        let mut m = HmacSha512::new(b"k").unwrap();
        m.update(b"chain").update(b"-friendly");
        assert_eq!(m.finalize(), hmac_sha512(b"k", b"chain-friendly").unwrap());
    }

    // --- Streaming verify tests ---

    #[test]
    fn hmac_sha256_streaming_verify_accepts_correct_tag() {
        let key = b"k";
        let tag = hmac_sha256(key, b"message").unwrap();
        let mut m = HmacSha256::new(key).unwrap();
        m.update(b"message");
        assert!(m.verify(&tag));
    }

    #[test]
    fn hmac_sha256_streaming_verify_rejects_wrong_tag() {
        let key = b"k";
        let tag = hmac_sha256(key, b"message").unwrap();
        let mut tampered = tag;
        tampered[0] ^= 0xff;
        let mut m = HmacSha256::new(key).unwrap();
        m.update(b"message");
        assert!(!m.verify(&tampered));
    }

    #[test]
    fn hmac_sha512_streaming_verify_accepts_correct_tag() {
        let key = b"k";
        let tag = hmac_sha512(key, b"message").unwrap();
        let mut m = HmacSha512::new(key).unwrap();
        m.update(b"message");
        assert!(m.verify(&tag));
    }

    // --- Key-length edge cases (HMAC accepts any length). ---

    #[test]
    fn hmac_sha256_accepts_empty_key() {
        let tag = hmac_sha256(&[], b"data").unwrap();
        assert!(hmac_sha256_verify(&[], b"data", &tag).unwrap());
    }

    #[test]
    fn hmac_sha256_accepts_long_key() {
        // Longer than the SHA-256 block size (64 bytes) — HMAC hashes it
        // down internally.
        let key = [0xaau8; 256];
        let tag = hmac_sha256(&key, b"data").unwrap();
        assert!(hmac_sha256_verify(&key, b"data", &tag).unwrap());
    }
}
