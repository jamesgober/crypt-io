//! Authenticated encryption with associated data (AEAD).
//!
//! This module exposes the high-level [`Crypt`] handle and the [`Algorithm`]
//! enum. The default algorithm is **ChaCha20-Poly1305** ([RFC 8439]): it is
//! fast in software, post-quantum-safe at 256-bit symmetric strength, and the
//! recommended choice when hardware AES acceleration is not available.
//!
//! [RFC 8439]: https://datatracker.ietf.org/doc/html/rfc8439
//!
//! # Wire format
//!
//! The ciphertext returned by [`Crypt::encrypt`] / [`Crypt::encrypt_with_aad`]
//! is the concatenation `nonce || ciphertext || tag`, where:
//!
//! - `nonce` is a 12-byte CSPRNG-generated value (mod-rand Tier 3, backed by
//!   the OS — `getrandom` on Linux, `getentropy` on macOS,
//!   `BCryptGenRandom` on Windows).
//! - `ciphertext` is the encryption of the plaintext under the supplied key
//!   and generated nonce.
//! - `tag` is the 16-byte Poly1305 authentication tag, covering both the
//!   ciphertext and any associated data passed to the AAD variants.
//!
//! [`Crypt::decrypt`] / [`Crypt::decrypt_with_aad`] split this layout,
//! verify the tag in constant time (provided by upstream RustCrypto), and
//! return the decrypted plaintext.
//!
//! # Nonce policy
//!
//! Nonces are generated fresh for every call. The 96-bit nonce space has a
//! birthday bound of ~`2^48` — well beyond any realistic message volume for
//! a single key. Callers that need a specific nonce (interop with another
//! implementation, deterministic test vectors) are out of scope for the
//! 0.2.0 API; that surface will arrive in a later milestone with explicit
//! "I understand the risk" naming.
//!
//! # Example
//!
//! ```
//! # #[cfg(feature = "aead-chacha20")] {
//! use crypt_io::Crypt;
//!
//! let key = [0x42u8; 32];
//! let plaintext = b"attack at dawn";
//!
//! let crypt = Crypt::new();
//! let ciphertext = crypt.encrypt(&key, plaintext).expect("encrypt");
//! let recovered = crypt.decrypt(&key, &ciphertext).expect("decrypt");
//!
//! assert_eq!(&*recovered, plaintext);
//! # }
//! ```

use alloc::vec::Vec;

#[cfg_attr(feature = "aead-chacha20", allow(unused_imports))]
use crate::error::{Error, Result};

#[cfg(feature = "aead-chacha20")]
mod chacha20;

/// Length of a ChaCha20-Poly1305 nonce, in bytes. Equal to `12`.
pub const CHACHA20_NONCE_LEN: usize = 12;

/// Length of a ChaCha20-Poly1305 authentication tag, in bytes. Equal to `16`.
pub const CHACHA20_TAG_LEN: usize = 16;

/// Length of a symmetric key for any algorithm shipped in this version,
/// in bytes. Equal to `32` (256-bit keys).
pub const KEY_LEN: usize = 32;

/// Supported AEAD algorithms.
///
/// The enum is `#[non_exhaustive]`. Additional algorithms (e.g. AES-256-GCM
/// in 0.3.0) will be added in minor releases; downstream `match` sites must
/// include a wildcard arm.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Algorithm {
    /// ChaCha20-Poly1305 ([RFC 8439]). The default. Fast in software,
    /// post-quantum-safe at 256-bit symmetric strength.
    ///
    /// [RFC 8439]: https://datatracker.ietf.org/doc/html/rfc8439
    #[default]
    ChaCha20Poly1305,
}

impl Algorithm {
    /// Human-readable name of the algorithm.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ChaCha20Poly1305 => "ChaCha20-Poly1305",
        }
    }

    /// Required key length in bytes for this algorithm.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::ChaCha20Poly1305 => KEY_LEN,
        }
    }

    /// Nonce length in bytes that this algorithm uses.
    #[must_use]
    pub const fn nonce_len(self) -> usize {
        match self {
            Self::ChaCha20Poly1305 => CHACHA20_NONCE_LEN,
        }
    }

    /// Authentication-tag length in bytes that this algorithm produces.
    #[must_use]
    pub const fn tag_len(self) -> usize {
        match self {
            Self::ChaCha20Poly1305 => CHACHA20_TAG_LEN,
        }
    }
}

/// High-level encryption handle.
///
/// `Crypt` is cheap to construct and to clone — it carries only the
/// algorithm choice, not any key material. Keys are passed per-call to
/// [`encrypt`](Self::encrypt) and [`decrypt`](Self::decrypt), and never
/// stored inside `Crypt` itself.
///
/// # Defaults
///
/// `Crypt::new()` returns a handle configured for
/// [`Algorithm::ChaCha20Poly1305`]. Use [`Crypt::with_algorithm`] to pick
/// a different algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Crypt {
    algorithm: Algorithm,
}

impl Crypt {
    /// Construct a `Crypt` with the default algorithm
    /// ([`Algorithm::ChaCha20Poly1305`]).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            algorithm: Algorithm::ChaCha20Poly1305,
        }
    }

    /// Construct a `Crypt` with an explicit algorithm.
    #[must_use]
    pub const fn with_algorithm(algorithm: Algorithm) -> Self {
        Self { algorithm }
    }

    /// The algorithm this handle is configured to use.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Encrypt `plaintext` under `key` and return `nonce || ciphertext || tag`.
    ///
    /// A fresh 12-byte nonce is generated for every call via OS-backed
    /// CSPRNG (`mod_rand::tier3::fill_bytes`). The nonce is prepended to
    /// the returned buffer so the corresponding [`decrypt`](Self::decrypt)
    /// call needs only the key and the buffer.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidKey`] if `key` is not 32 bytes.
    /// - [`Error::RandomFailure`] if the OS random source could not
    ///   produce a nonce.
    /// - [`Error::AlgorithmNotEnabled`] if the algorithm was disabled
    ///   at compile time (a feature-flag gate).
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "aead-chacha20")] {
    /// use crypt_io::Crypt;
    /// let crypt = Crypt::new();
    /// let key = [0u8; 32];
    /// let ciphertext = crypt.encrypt(&key, b"hello").expect("encrypt");
    /// assert!(ciphertext.len() > 5);
    /// # }
    /// ```
    pub fn encrypt(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        self.encrypt_with_aad(key, plaintext, &[])
    }

    /// Encrypt `plaintext` under `key` with additional authenticated data.
    ///
    /// `aad` is authenticated alongside the ciphertext but is **not**
    /// encrypted and is **not** included in the returned buffer. Callers
    /// must supply identical `aad` to [`decrypt_with_aad`](Self::decrypt_with_aad)
    /// — otherwise authentication will fail.
    ///
    /// Pass `&[]` for `aad` to encrypt without associated data, or call
    /// the convenience method [`encrypt`](Self::encrypt) which does so.
    ///
    /// # Errors
    ///
    /// Same as [`encrypt`](Self::encrypt).
    pub fn encrypt_with_aad(&self, key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        match self.algorithm {
            Algorithm::ChaCha20Poly1305 => {
                #[cfg(feature = "aead-chacha20")]
                {
                    chacha20::encrypt(key, plaintext, aad)
                }
                #[cfg(not(feature = "aead-chacha20"))]
                {
                    let _ = (key, plaintext, aad);
                    Err(Error::AlgorithmNotEnabled("aead-chacha20"))
                }
            }
        }
    }

    /// Decrypt a buffer produced by [`encrypt`](Self::encrypt) and return
    /// the plaintext.
    ///
    /// The buffer is expected to be `nonce || ciphertext || tag` — exactly
    /// the layout [`encrypt`](Self::encrypt) returns. The tag is verified
    /// in constant time; any tampering, wrong key, or wrong length results
    /// in [`Error::AuthenticationFailed`].
    ///
    /// The returned `Vec<u8>` does **not** auto-zeroize. Callers handling
    /// long-lived keys should move the bytes into a `Zeroizing<Vec<u8>>`
    /// (`zeroize` crate) or — for production use cases — keep the
    /// plaintext in a `key-vault` handle and never let it touch a raw
    /// `Vec`.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidKey`] if `key` is not 32 bytes.
    /// - [`Error::InvalidCiphertext`] if the buffer is too short to
    ///   contain a nonce + tag.
    /// - [`Error::AuthenticationFailed`] for any cryptographic failure —
    ///   wrong key, tampered ciphertext, or wrong associated data.
    /// - [`Error::AlgorithmNotEnabled`] if the algorithm was disabled
    ///   at compile time.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "aead-chacha20")] {
    /// use crypt_io::Crypt;
    /// let crypt = Crypt::new();
    /// let key = [0u8; 32];
    /// let ciphertext = crypt.encrypt(&key, b"hello").expect("encrypt");
    /// let recovered = crypt.decrypt(&key, &ciphertext).expect("decrypt");
    /// assert_eq!(&*recovered, b"hello");
    /// # }
    /// ```
    pub fn decrypt(&self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.decrypt_with_aad(key, ciphertext, &[])
    }

    /// Decrypt with associated data. `aad` must match what was passed to
    /// [`encrypt_with_aad`](Self::encrypt_with_aad).
    ///
    /// # Errors
    ///
    /// Same as [`decrypt`](Self::decrypt).
    pub fn decrypt_with_aad(&self, key: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        match self.algorithm {
            Algorithm::ChaCha20Poly1305 => {
                #[cfg(feature = "aead-chacha20")]
                {
                    chacha20::decrypt(key, ciphertext, aad)
                }
                #[cfg(not(feature = "aead-chacha20"))]
                {
                    let _ = (key, ciphertext, aad);
                    Err(Error::AlgorithmNotEnabled("aead-chacha20"))
                }
            }
        }
    }
}

impl Default for Crypt {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(test, feature = "aead-chacha20"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn algorithm_metadata_matches_constants() {
        let a = Algorithm::default();
        assert_eq!(a, Algorithm::ChaCha20Poly1305);
        assert_eq!(a.key_len(), KEY_LEN);
        assert_eq!(a.nonce_len(), CHACHA20_NONCE_LEN);
        assert_eq!(a.tag_len(), CHACHA20_TAG_LEN);
        assert_eq!(a.name(), "ChaCha20-Poly1305");
    }

    #[test]
    fn crypt_defaults_to_chacha20() {
        let c = Crypt::new();
        assert_eq!(c.algorithm(), Algorithm::ChaCha20Poly1305);
        let d = Crypt::default();
        assert_eq!(d.algorithm(), Algorithm::ChaCha20Poly1305);
    }

    #[test]
    fn round_trip_empty_plaintext() {
        let crypt = Crypt::new();
        let key = [0x11u8; 32];
        let ciphertext = crypt.encrypt(&key, b"").unwrap();
        // Layout: 12-byte nonce + 0-byte body + 16-byte tag.
        assert_eq!(ciphertext.len(), CHACHA20_NONCE_LEN + CHACHA20_TAG_LEN);
        let recovered = crypt.decrypt(&key, &ciphertext).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn round_trip_short_plaintext() {
        let crypt = Crypt::new();
        let key = [0x22u8; 32];
        let plaintext = b"hello, world!";
        let ciphertext = crypt.encrypt(&key, plaintext).unwrap();
        let recovered = crypt.decrypt(&key, &ciphertext).unwrap();
        assert_eq!(&*recovered, plaintext);
    }

    #[test]
    fn round_trip_one_megabyte() {
        let crypt = Crypt::new();
        let key = [0x33u8; 32];
        let plaintext = vec![0xa5u8; 1024 * 1024];
        let ciphertext = crypt.encrypt(&key, &plaintext).unwrap();
        let recovered = crypt.decrypt(&key, &ciphertext).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn two_encryptions_of_same_plaintext_differ() {
        let crypt = Crypt::new();
        let key = [0u8; 32];
        let plaintext = b"deterministic? no.";
        let a = crypt.encrypt(&key, plaintext).unwrap();
        let b = crypt.encrypt(&key, plaintext).unwrap();
        assert_ne!(a, b, "nonce-prepended outputs must differ across calls");
    }

    #[test]
    fn wrong_key_fails_authentication() {
        let crypt = Crypt::new();
        let key = [0x44u8; 32];
        let wrong = [0x55u8; 32];
        let ciphertext = crypt.encrypt(&key, b"secret").unwrap();
        let err = crypt.decrypt(&wrong, &ciphertext).unwrap_err();
        assert_eq!(err, Error::AuthenticationFailed);
    }

    #[test]
    fn tampered_ciphertext_fails_authentication() {
        let crypt = Crypt::new();
        let key = [0x66u8; 32];
        let mut ciphertext = crypt.encrypt(&key, b"hands off").unwrap();
        // Flip one byte in the body (avoid the nonce so we exercise tag verification).
        let i = ciphertext.len() / 2;
        ciphertext[i] ^= 0x01;
        let err = crypt.decrypt(&key, &ciphertext).unwrap_err();
        assert_eq!(err, Error::AuthenticationFailed);
    }

    #[test]
    fn tampered_tag_fails_authentication() {
        let crypt = Crypt::new();
        let key = [0x77u8; 32];
        let mut ciphertext = crypt.encrypt(&key, b"sign me").unwrap();
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0xff;
        let err = crypt.decrypt(&key, &ciphertext).unwrap_err();
        assert_eq!(err, Error::AuthenticationFailed);
    }

    #[test]
    fn truncated_ciphertext_is_rejected() {
        let crypt = Crypt::new();
        let key = [0u8; 32];
        // Anything shorter than nonce_len + tag_len cannot be a valid frame.
        for len in 0..(CHACHA20_NONCE_LEN + CHACHA20_TAG_LEN) {
            let err = crypt.decrypt(&key, &vec![0u8; len]).unwrap_err();
            assert!(
                matches!(err, Error::InvalidCiphertext(_)),
                "len={len} should error"
            );
        }
    }

    #[test]
    fn aad_round_trip() {
        let crypt = Crypt::new();
        let key = [0x88u8; 32];
        let plaintext = b"plaintext";
        let aad = b"associated";
        let ciphertext = crypt.encrypt_with_aad(&key, plaintext, aad).unwrap();
        let recovered = crypt.decrypt_with_aad(&key, &ciphertext, aad).unwrap();
        assert_eq!(&*recovered, plaintext);
    }

    #[test]
    fn aad_mismatch_fails_authentication() {
        let crypt = Crypt::new();
        let key = [0x99u8; 32];
        let ciphertext = crypt
            .encrypt_with_aad(&key, b"body", b"original-aad")
            .unwrap();
        let err = crypt
            .decrypt_with_aad(&key, &ciphertext, b"tampered-aad")
            .unwrap_err();
        assert_eq!(err, Error::AuthenticationFailed);
    }

    #[test]
    fn encrypt_with_aad_then_decrypt_without_aad_fails() {
        let crypt = Crypt::new();
        let key = [0xaau8; 32];
        let ciphertext = crypt.encrypt_with_aad(&key, b"body", b"required").unwrap();
        let err = crypt.decrypt(&key, &ciphertext).unwrap_err();
        assert_eq!(err, Error::AuthenticationFailed);
    }

    #[test]
    fn invalid_key_length_rejected_on_encrypt() {
        let crypt = Crypt::new();
        let err = crypt.encrypt(&[0u8; 16], b"x").unwrap_err();
        assert_eq!(
            err,
            Error::InvalidKey {
                expected: 32,
                actual: 16
            }
        );
    }

    #[test]
    fn invalid_key_length_rejected_on_decrypt() {
        let crypt = Crypt::new();
        // First encrypt a real ciphertext so the length-check is the
        // reason decrypt rejects.
        let ciphertext = crypt.encrypt(&[0u8; 32], b"x").unwrap();
        let err = crypt.decrypt(&[0u8; 16], &ciphertext).unwrap_err();
        assert_eq!(
            err,
            Error::InvalidKey {
                expected: 32,
                actual: 16
            }
        );
    }
}
