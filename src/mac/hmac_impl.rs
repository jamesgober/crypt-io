//! HMAC-SHA256 / HMAC-SHA512 backend.
//!
//! Thin wrapper over the `hmac` crate (`RustCrypto`). HMAC accepts a key
//! of any length — short keys are zero-padded, long keys are hashed down
//! to the block size, both per [RFC 2104]. The wrapper preserves that
//! contract; callers do not need to size their keys.
//!
//! With the `zeroize` feature (default on) the HMAC state, which is
//! derived from the key, is wiped when a MAC is dropped (`hmac` and
//! `sha2` `zeroize` support, new in crypt-io 1.1.0).
//!
//! [RFC 2104]: https://datatracker.ietf.org/doc/html/rfc2104

use hmac::{Hmac, KeyInit, Mac};
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

/// Check an HMAC-SHA256 tag in constant time.
///
/// Computes the tag for `(key, data)` and compares it to `expected_tag`
/// with `subtle::ConstantTimeEq` (via the `hmac` crate's
/// `verify_slice`). Returns `Ok(())` on a match and
/// `Err(`[`Error::AuthenticationFailed`]`)` on a mismatch, including an
/// `expected_tag` of the wrong length.
///
/// Because a mismatch is an error, `hmac_sha256_check(..)?;` does the
/// right thing. New in 1.1.0; replaces [`hmac_sha256_verify`].
///
/// # Errors
///
/// - [`Error::AuthenticationFailed`] if the tag does not match.
/// - [`Error::Mac`] if the upstream MAC could not be constructed
///   (unreachable in practice).
///
/// # Example
///
/// ```
/// # #[cfg(feature = "mac-hmac")] {
/// use crypt_io::{mac, Error};
/// let key = b"shared";
/// let tag = mac::hmac_sha256(key, b"data")?;
///
/// mac::hmac_sha256_check(key, b"data", &tag)?;
/// assert_eq!(
///     mac::hmac_sha256_check(key, b"tampered", &tag),
///     Err(Error::AuthenticationFailed)
/// );
/// # }
/// # Ok::<(), crypt_io::Error>(())
/// ```
pub fn hmac_sha256_check(key: &[u8], data: &[u8], expected_tag: &[u8]) -> Result<()> {
    let mut mac =
        HmacSha256Inner::new_from_slice(key).map_err(|_| Error::Mac("hmac-sha256 init"))?;
    mac.update(data);
    mac.verify_slice(expected_tag)
        .map_err(|_| Error::AuthenticationFailed)
}

/// Verify an HMAC-SHA256 tag in constant time.
///
/// **Deprecated since 1.1.0:** use [`hmac_sha256_check`], which returns
/// `Err(AuthenticationFailed)` on a mismatch.
///
/// Computes the tag for `(key, data)` and compares it to `expected_tag`.
/// Returns `Ok(true)` if the tags match, `Ok(false)` if they don't, and
/// [`Error::Mac`] if the upstream MAC could not be constructed.
///
/// **A mismatch is `Ok(false)`, not an error.** Writing
/// `hmac_sha256_verify(..)?;` throws that `bool` away and accepts any
/// tag, including a forged one. Always branch on the value, as in the
/// example below.
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
/// # #![allow(deprecated)]
/// # #[cfg(feature = "mac-hmac")] {
/// use crypt_io::mac;
/// let key = b"shared";
/// let tag = mac::hmac_sha256(key, b"data")?;
///
/// // Correct: branch on the returned bool.
/// if !mac::hmac_sha256_verify(key, b"data", &tag)? {
///     return Err(crypt_io::Error::AuthenticationFailed);
/// }
/// assert!(!mac::hmac_sha256_verify(key, b"tampered", &tag)?);
/// # }
/// # Ok::<(), crypt_io::Error>(())
/// ```
#[deprecated(
    since = "1.1.0",
    note = "returns Ok(false) on a mismatch, so `hmac_sha256_verify(..)?;` accepts forged tags; use `hmac_sha256_check`, which returns Err(AuthenticationFailed)"
)]
#[must_use = "a mismatch is Ok(false): check the bool, or use `hmac_sha256_check`"]
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

/// Check an HMAC-SHA512 tag in constant time. Returns
/// `Err(`[`Error::AuthenticationFailed`]`)` on a mismatch. See
/// [`hmac_sha256_check`]. New in 1.1.0; replaces
/// [`hmac_sha512_verify`].
///
/// # Errors
///
/// Same as [`hmac_sha256_check`].
pub fn hmac_sha512_check(key: &[u8], data: &[u8], expected_tag: &[u8]) -> Result<()> {
    let mut mac =
        HmacSha512Inner::new_from_slice(key).map_err(|_| Error::Mac("hmac-sha512 init"))?;
    mac.update(data);
    mac.verify_slice(expected_tag)
        .map_err(|_| Error::AuthenticationFailed)
}

/// Verify an HMAC-SHA512 tag in constant time. See [`hmac_sha256_verify`].
///
/// **Deprecated since 1.1.0:** use [`hmac_sha512_check`].
///
/// **A mismatch is `Ok(false)`, not an error.** Branch on the returned
/// `bool` (`if !hmac_sha512_verify(..)? { reject }`); never write
/// `hmac_sha512_verify(..)?;`.
///
/// # Errors
///
/// Same as [`hmac_sha256_verify`].
#[deprecated(
    since = "1.1.0",
    note = "returns Ok(false) on a mismatch, so `hmac_sha512_verify(..)?;` accepts forged tags; use `hmac_sha512_check`, which returns Err(AuthenticationFailed)"
)]
#[must_use = "a mismatch is Ok(false): check the bool, or use `hmac_sha512_check`"]
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
/// (returns the 32-byte tag) or [`check`](Self::check) (constant-time
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
    /// Consumes the hasher. See [`check`](Self::check) for the
    /// `Result` form.
    #[must_use]
    pub fn verify(self, expected_tag: &[u8]) -> bool {
        self.inner.verify_slice(expected_tag).is_ok()
    }

    /// Finalise and check against `expected_tag` in constant time.
    /// Consumes the hasher. New in 1.1.0.
    ///
    /// # Errors
    ///
    /// [`Error::AuthenticationFailed`] if the tag does not match.
    pub fn check(self, expected_tag: &[u8]) -> Result<()> {
        self.inner
            .verify_slice(expected_tag)
            .map_err(|_| Error::AuthenticationFailed)
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
    /// Consumes the hasher. See [`check`](Self::check) for the
    /// `Result` form.
    #[must_use]
    pub fn verify(self, expected_tag: &[u8]) -> bool {
        self.inner.verify_slice(expected_tag).is_ok()
    }

    /// Finalise and check against `expected_tag` in constant time.
    /// Consumes the hasher. New in 1.1.0.
    ///
    /// # Errors
    ///
    /// [`Error::AuthenticationFailed`] if the tag does not match.
    pub fn check(self, expected_tag: &[u8]) -> Result<()> {
        self.inner
            .verify_slice(expected_tag)
            .map_err(|_| Error::AuthenticationFailed)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, unused_results, deprecated)]
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

    // --- 1.1.0: check functions and state wiping ---

    #[test]
    fn check_functions_accept_and_reject() {
        let tag = hmac_sha256(b"k", b"d").unwrap();
        assert_eq!(hmac_sha256_check(b"k", b"d", &tag), Ok(()));
        assert_eq!(
            hmac_sha256_check(b"k", b"x", &tag),
            Err(Error::AuthenticationFailed)
        );
        assert_eq!(
            hmac_sha256_check(b"k", b"d", &tag[..31]),
            Err(Error::AuthenticationFailed)
        );
        let tag = hmac_sha512(b"k", b"d").unwrap();
        assert_eq!(hmac_sha512_check(b"k", b"d", &tag), Ok(()));
        assert_eq!(
            hmac_sha512_check(b"j", b"d", &tag),
            Err(Error::AuthenticationFailed)
        );
        let mut m = HmacSha512::new(b"k").unwrap();
        m.update(b"d");
        assert_eq!(m.clone().check(&tag), Ok(()));
        assert_eq!(m.check(&[0u8; 64]), Err(Error::AuthenticationFailed));
    }

    /// With `zeroize`, dropping a MAC wipes its key-derived state
    /// (`hmac`/`sha2` zeroize support, deferred in 1.0.1).
    #[cfg(feature = "zeroize")]
    #[test]
    fn drop_wipes_hmac_state() {
        use alloc::boxed::Box;
        use core::mem::{MaybeUninit, size_of};

        fn wiped_after_drop<T>(value: T) -> bool {
            let mut slot: Box<MaybeUninit<T>> = Box::new(MaybeUninit::new(value));
            // SAFETY: `slot` holds an initialised value; it is dropped
            // exactly once here and never used as a `T` again.
            unsafe { slot.assume_init_drop() };
            let ptr = slot.as_ptr().cast::<u8>();
            // SAFETY: the allocation is live and `size_of::<T>()` bytes
            // long; drop glue only writes to it. Padding bytes may be
            // uninitialised in principle, but every field here is
            // zeroed by the drop, so all bytes were written.
            (0..size_of::<T>()).all(|i| unsafe { ptr.add(i).read_volatile() } == 0)
        }

        let key = [0x5au8; 40];
        let mut a = HmacSha256::new(&key).unwrap();
        a.update(b"some data");
        assert!(wiped_after_drop(a), "HMAC-SHA256 state survived drop");
        let mut b = HmacSha512::new(&key).unwrap();
        b.update(b"some data");
        assert!(wiped_after_drop(b), "HMAC-SHA512 state survived drop");
    }
}
