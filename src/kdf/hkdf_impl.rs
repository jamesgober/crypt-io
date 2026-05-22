//! HKDF backend (RFC 5869).
//!
//! Thin wrapper over the `hkdf` crate. HKDF is the right choice when
//! the input keying material (IKM) is already high-entropy — a master
//! key, a Diffie-Hellman shared secret, a token from a secrets manager.
//! It is *not* a password hash; for passwords use Argon2id.
//!
//! The wrapper exposes `extract-then-expand` as a single function call
//! (HKDF's full flow) with an optional salt and a caller-supplied `info`
//! context string. Per RFC 5869:
//!
//! - `salt` should be a random value if available; otherwise `None`.
//! - `info` is a context label binding the derived key to its purpose
//!   (e.g. `b"app:session-key:v1"`). Different `info` values produce
//!   uncorrelated outputs from the same `(ikm, salt)`.
//! - Output `len` may not exceed `255 * digest_size` bytes — 8160 for
//!   SHA-256, 16320 for SHA-512.

use alloc::vec;
use alloc::vec::Vec;

use hkdf::Hkdf;
use sha2::{Sha256, Sha512};

use crate::error::{Error, Result};

/// Maximum HKDF-SHA256 output length, in bytes. Equal to `255 * 32 = 8160`.
pub const HKDF_MAX_OUTPUT_SHA256: usize = 255 * 32;

/// Maximum HKDF-SHA512 output length, in bytes. Equal to `255 * 64 = 16320`.
pub const HKDF_MAX_OUTPUT_SHA512: usize = 255 * 64;

/// Derive `len` bytes of output keying material via HKDF-SHA256.
///
/// `ikm` is the input keying material — the high-entropy secret to
/// derive from. `salt` is the optional salt (see RFC 5869 §3.1); pass
/// `None` if no salt is available. `info` is the application-specific
/// context that binds the output to its purpose; pass `b""` if you
/// don't need it.
///
/// # Errors
///
/// Returns [`Error::Kdf`] if `len` exceeds [`HKDF_MAX_OUTPUT_SHA256`]
/// (8160 bytes).
///
/// # Example
///
/// ```
/// # #[cfg(feature = "kdf-hkdf")] {
/// use crypt_io::kdf;
///
/// let master = [0x42u8; 32];
/// let session_key = kdf::hkdf_sha256(
///     &master,
///     Some(b"randomly-generated-salt"),
///     b"app:session:v1",
///     32,
/// )?;
/// assert_eq!(session_key.len(), 32);
/// # }
/// # Ok::<(), crypt_io::Error>(())
/// ```
pub fn hkdf_sha256(ikm: &[u8], salt: Option<&[u8]>, info: &[u8], len: usize) -> Result<Vec<u8>> {
    if len > HKDF_MAX_OUTPUT_SHA256 {
        return Err(Error::Kdf("hkdf-sha256 output > 255 * 32 bytes"));
    }
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut out = vec![0u8; len];
    hk.expand(info, &mut out)
        .map_err(|_| Error::Kdf("hkdf-sha256 expand"))?;
    Ok(out)
}

/// Derive `len` bytes of output keying material via HKDF-SHA512.
///
/// Same shape as [`hkdf_sha256`]. The wider digest allows up to
/// [`HKDF_MAX_OUTPUT_SHA512`] (16320 bytes) of output.
///
/// # Errors
///
/// Returns [`Error::Kdf`] if `len` exceeds [`HKDF_MAX_OUTPUT_SHA512`]
/// (16320 bytes).
///
/// # Example
///
/// ```
/// # #[cfg(feature = "kdf-hkdf")] {
/// use crypt_io::kdf;
///
/// let master = [0x42u8; 32];
/// let big_subkey = kdf::hkdf_sha512(&master, None, b"app:vault:v1", 64)?;
/// assert_eq!(big_subkey.len(), 64);
/// # }
/// # Ok::<(), crypt_io::Error>(())
/// ```
pub fn hkdf_sha512(ikm: &[u8], salt: Option<&[u8]>, info: &[u8], len: usize) -> Result<Vec<u8>> {
    if len > HKDF_MAX_OUTPUT_SHA512 {
        return Err(Error::Kdf("hkdf-sha512 output > 255 * 64 bytes"));
    }
    let hk = Hkdf::<Sha512>::new(salt, ikm);
    let mut out = vec![0u8; len];
    hk.expand(info, &mut out)
        .map_err(|_| Error::Kdf("hkdf-sha512 expand"))?;
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, unused_results)]
mod tests {
    use super::*;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        hex::decode(s).expect("valid hex")
    }

    // --- RFC 5869 known-answer tests ---

    /// RFC 5869 Test Case 1 (HKDF-SHA256, basic).
    /// IKM = 22 bytes of 0x0b; salt = 13 bytes 0x00..0x0c;
    /// info = 10 bytes 0xf0..0xf9; L = 42.
    #[test]
    fn rfc5869_test_case_1_sha256() {
        let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex_to_bytes("000102030405060708090a0b0c");
        let info = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9");
        let expected = hex_to_bytes(
            "3cb25f25faacd57a90434f64d0362f2a\
             2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865",
        );
        let got = hkdf_sha256(&ikm, Some(&salt), &info, 42).unwrap();
        assert_eq!(got, expected);
    }

    /// RFC 5869 Test Case 3 (HKDF-SHA256, no salt, no info, L = 42).
    #[test]
    fn rfc5869_test_case_3_sha256_no_salt_no_info() {
        let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let expected = hex_to_bytes(
            "8da4e775a563c18f715f802a063c5a31\
             b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8",
        );
        // RFC 5869 §3.1 — `salt` defaults to a zero-byte string when
        // None is passed. Both `None` and `Some(&[])` produce the same
        // output.
        let got_none = hkdf_sha256(&ikm, None, &[], 42).unwrap();
        let got_empty = hkdf_sha256(&ikm, Some(&[]), &[], 42).unwrap();
        assert_eq!(got_none, expected);
        assert_eq!(got_empty, expected);
    }

    // RFC 5869 Test Case 4 (HKDF-SHA1) we skip — we don't ship SHA-1.
    // We use Test Case 1 + 3 for SHA-256 and a derived SHA-512 vector
    // below.

    /// HKDF-SHA512 wrapper round-trip. RFC 5869 only ships SHA-256 /
    /// SHA-1 vectors, so for SHA-512 we cross-check the wrapper output
    /// against a direct call into the upstream `hkdf` crate with the
    /// same parameters. This catches any wrapper-level mistake
    /// (wrong digest selected, length-bound off-by-one, salt mis-passed)
    /// without committing to a specific KAT we'd have to maintain.
    #[test]
    fn hkdf_sha512_matches_upstream() {
        let ikm = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex_to_bytes("000102030405060708090a0b0c");
        let info = hex_to_bytes("f0f1f2f3f4f5f6f7f8f9");

        let got = hkdf_sha512(&ikm, Some(&salt), &info, 64).unwrap();

        let hk = Hkdf::<Sha512>::new(Some(&salt), &ikm);
        let mut expected = vec![0u8; 64];
        hk.expand(&info, &mut expected).unwrap();

        assert_eq!(got, expected);
        assert_eq!(got.len(), 64);
    }

    // --- Length and bounds ---

    #[test]
    fn hkdf_sha256_zero_length_output() {
        let out = hkdf_sha256(&[0u8; 32], None, &[], 0).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn hkdf_sha256_max_length_accepted() {
        let out = hkdf_sha256(&[0u8; 32], None, &[], HKDF_MAX_OUTPUT_SHA256).unwrap();
        assert_eq!(out.len(), HKDF_MAX_OUTPUT_SHA256);
    }

    #[test]
    fn hkdf_sha256_over_max_rejected() {
        let err = hkdf_sha256(&[0u8; 32], None, &[], HKDF_MAX_OUTPUT_SHA256 + 1).unwrap_err();
        assert!(matches!(err, Error::Kdf(_)), "{err:?}");
    }

    #[test]
    fn hkdf_sha512_max_length_accepted() {
        let out = hkdf_sha512(&[0u8; 32], None, &[], HKDF_MAX_OUTPUT_SHA512).unwrap();
        assert_eq!(out.len(), HKDF_MAX_OUTPUT_SHA512);
    }

    #[test]
    fn hkdf_sha512_over_max_rejected() {
        let err = hkdf_sha512(&[0u8; 32], None, &[], HKDF_MAX_OUTPUT_SHA512 + 1).unwrap_err();
        assert!(matches!(err, Error::Kdf(_)), "{err:?}");
    }

    // --- Domain-separation: different info produces uncorrelated output ---

    #[test]
    fn different_info_produces_different_output() {
        let master = [0x42u8; 32];
        let a = hkdf_sha256(&master, None, b"info:a", 32).unwrap();
        let b = hkdf_sha256(&master, None, b"info:b", 32).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn different_salt_produces_different_output() {
        let master = [0x42u8; 32];
        let a = hkdf_sha256(&master, Some(b"salt-a"), b"info", 32).unwrap();
        let b = hkdf_sha256(&master, Some(b"salt-b"), b"info", 32).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn deterministic_in_inputs() {
        let master = [0x42u8; 32];
        let a = hkdf_sha256(&master, Some(b"salt"), b"info", 32).unwrap();
        let b = hkdf_sha256(&master, Some(b"salt"), b"info", 32).unwrap();
        assert_eq!(a, b);
    }
}
