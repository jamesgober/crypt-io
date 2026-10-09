//! Authenticated encryption with associated data (AEAD).
//!
//! This module exposes the high-level [`Crypt`] handle and the [`Algorithm`]
//! enum. The default algorithm is **ChaCha20-Poly1305** ([RFC 8439]): it is
//! fast in software, post-quantum-safe at 256-bit symmetric strength, and the
//! recommended choice when hardware AES acceleration is not available.
//!
//! Three algorithms share the same `Crypt::encrypt` / `Crypt::decrypt`
//! surface and the same 32-byte key and 16-byte tag:
//!
//! | Algorithm            | Nonce  | Feature         | Pick it when                               |
//! |----------------------|--------|-----------------|--------------------------------------------|
//! | ChaCha20-Poly1305    | 12 B   | `aead-chacha20` | default; fast everywhere in software        |
//! | XChaCha20-Poly1305   | 24 B   | `aead-chacha20` | one key encrypts a very large number of messages |
//! | AES-256-GCM          | 12 B   | `aead-aes-gcm`  | AES-NI / ARMv8 crypto, or interop          |
//!
//! [RFC 8439]: https://datatracker.ietf.org/doc/html/rfc8439
//!
//! # Wire formats
//!
//! [`Crypt::encrypt`] / [`Crypt::encrypt_with_aad`] return the 1.0
//! format `nonce || ciphertext || tag`:
//!
//! - `nonce` is a fresh value from the OS CSPRNG (12 bytes, or 24 for
//!   XChaCha20-Poly1305).
//! - `ciphertext` is the encryption of the plaintext.
//! - `tag` is the 16-byte authentication tag (Poly1305 or GHASH),
//!   covering the ciphertext and any associated data.
//!
//! That format does not record which algorithm produced it, so the
//! reader must already know. [`Crypt::seal`] / [`Crypt::open`] (new in
//! 1.1.0) write a **sealed** format that does:
//!
//! ```text
//! version (1 B, 0x01) || algorithm (1 B) || nonce || ciphertext || tag
//! ```
//!
//! The two header bytes are authenticated together with the caller's
//! associated data, so they cannot be changed without the tag failing.
//! `open` reads the algorithm from the header, which lets data written
//! under one algorithm be read by a handle configured for another
//! (useful while migrating). Algorithm bytes: `0x00`
//! ChaCha20-Poly1305, `0x01` AES-256-GCM, `0x02` XChaCha20-Poly1305
//! (the same values the stream header uses).
//!
//! Decryption verifies the tag in constant time (provided by upstream
//! RustCrypto) before any plaintext is produced.
//!
//! # Algorithm choice
//!
//! Pick **ChaCha20-Poly1305** unless you have a reason not to. It is fast
//! in software, has no timing-side-channel risk on platforms without
//! constant-time hardware AES, and is the post-quantum-safe default at the
//! 256-bit symmetric strength the crate ships.
//!
//! Pick **XChaCha20-Poly1305** when a single key may encrypt more than
//! 2^32 messages (see the nonce policy below). Its 192-bit random nonce
//! makes collisions negligible at any realistic volume.
//!
//! Pick **AES-256-GCM** when:
//!
//! - You're on a server-class x86 CPU with AES-NI + CLMUL (every Intel /
//!   AMD chip since ~2010), or an ARMv8 CPU with the crypto extensions
//!   (modern Apple Silicon, AWS Graviton, recent mobile SoCs). The
//!   `aes-gcm` crate detects these at runtime and dispatches to the
//!   hardware-accelerated path automatically — typically a 2–5× throughput
//!   win over the software path.
//! - You have an interop requirement (TLS records, JWE A256GCM, anything
//!   spec'd to AES-GCM).
//!
//! # Nonce policy
//!
//! Nonces are generated fresh for every call from the OS CSPRNG. Because
//! they are random, two encryptions under the same key can collide. For
//! the 96-bit nonces of ChaCha20-Poly1305 and AES-256-GCM the
//! probability is about `n^2 / 2^97` after `n` messages, and a single
//! collision is catastrophic for AES-256-GCM (it leaks the XOR of the two
//! plaintexts and the GHASH key, which allows forgeries) and serious for
//! ChaCha20-Poly1305.
//!
//! **Limit for 96-bit nonces: at most 2^32 encryptions per key** (about
//! 4.3 billion; the NIST SP 800-38D cap for random 96-bit IVs, collision
//! probability about 2^-33). The often-quoted `2^48` is not a safe
//! limit: it is the point where a collision becomes likely (about 39%).
//! crypt-io does not count messages for you. If one key may exceed 2^32
//! messages, use [`Algorithm::XChaCha20Poly1305`] (192-bit nonces: 2^64
//! messages still have a collision probability around 2^-65), rotate
//! keys, or derive per-context subkeys with HKDF.
//!
//! Callers that need a specific nonce (interop with another
//! implementation, deterministic test vectors) are out of scope for the
//! 1.x API.
//!
//! # Without a random source
//!
//! Encryption needs fresh nonces, so `encrypt*`, `seal*` and
//! [`generate_key`] are only available with the `std` feature or the
//! `getrandom` feature. Decryption (`decrypt*`, `open*`) works in any
//! build.
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

#[cfg_attr(
    any(feature = "aead-chacha20", feature = "aead-aes-gcm"),
    allow(unused_imports)
)]
use crate::error::{Error, Result};

#[cfg(feature = "aead-aes-gcm")]
mod aes_gcm;
pub(crate) mod backend;
#[cfg(feature = "aead-chacha20")]
mod chacha20;

/// Length of a ChaCha20-Poly1305 nonce, in bytes. Equal to `12`.
pub const CHACHA20_NONCE_LEN: usize = 12;

/// Length of a ChaCha20-Poly1305 authentication tag, in bytes. Equal to `16`.
pub const CHACHA20_TAG_LEN: usize = 16;

/// Length of an XChaCha20-Poly1305 nonce, in bytes. Equal to `24`
/// (192 bits). New in 1.1.0.
pub const XCHACHA20_NONCE_LEN: usize = 24;

/// Length of an XChaCha20-Poly1305 authentication tag, in bytes. Equal
/// to `16`. New in 1.1.0.
pub const XCHACHA20_TAG_LEN: usize = 16;

/// Length of an AES-256-GCM nonce, in bytes. Equal to `12` (96 bits — the
/// length NIST SP 800-38D specifies as the GCM default).
pub const AES_GCM_NONCE_LEN: usize = 12;

/// Length of an AES-256-GCM authentication tag, in bytes. Equal to `16`.
pub const AES_GCM_TAG_LEN: usize = 16;

/// Length of a symmetric key for any algorithm shipped in this version,
/// in bytes. Equal to `32` (256-bit keys).
pub const KEY_LEN: usize = 32;

/// Length of the header [`Crypt::seal`] writes in front of the nonce:
/// one version byte and one algorithm byte. Equal to `2`. New in 1.1.0.
pub const SEALED_HEADER_LEN: usize = 2;

/// Version byte of the sealed format written by [`Crypt::seal`].
/// Equal to `0x01`. New in 1.1.0.
pub const SEALED_VERSION: u8 = 0x01;

/// Tag length shared by every shipped AEAD.
pub(crate) const TAG_LEN: usize = 16;

/// Longest nonce of any shipped AEAD (XChaCha20-Poly1305).
#[cfg(any(feature = "std", feature = "getrandom"))]
pub(crate) const MAX_NONCE_LEN: usize = XCHACHA20_NONCE_LEN;

/// Supported AEAD algorithms.
///
/// The enum is `#[non_exhaustive]`. New algorithms are added in minor
/// releases; downstream `match` sites must include a wildcard arm.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Algorithm {
    /// ChaCha20-Poly1305 ([RFC 8439]). The default. Fast in software,
    /// post-quantum-safe at 256-bit symmetric strength, no timing-side-channel
    /// risk on platforms without constant-time hardware AES.
    ///
    /// [RFC 8439]: https://datatracker.ietf.org/doc/html/rfc8439
    #[default]
    ChaCha20Poly1305,
    /// AES-256-GCM ([NIST SP 800-38D]). Hardware-accelerated on every modern
    /// x86 CPU (AES-NI + CLMUL) and on ARMv8 with the crypto extensions.
    /// Pick this when you need interop with TLS / JWE / spec'd protocols
    /// or when running on AES-accelerated hardware.
    ///
    /// [NIST SP 800-38D]: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
    Aes256Gcm,
    /// XChaCha20-Poly1305 ([draft-irtf-cfrg-xchacha]): ChaCha20-Poly1305
    /// with a 192-bit nonce. Random nonces of that size never collide in
    /// practice, so one key can encrypt far more than the 2^32 messages
    /// that 96-bit nonces allow. Costs one extra ChaCha20 block (the
    /// `HChaCha20` subkey step) per message. Enabled by the
    /// `aead-chacha20` feature. New in 1.1.0.
    ///
    /// [draft-irtf-cfrg-xchacha]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03
    XChaCha20Poly1305,
}

impl Algorithm {
    /// Human-readable name of the algorithm.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ChaCha20Poly1305 => "ChaCha20-Poly1305",
            Self::Aes256Gcm => "AES-256-GCM",
            Self::XChaCha20Poly1305 => "XChaCha20-Poly1305",
        }
    }

    /// Required key length in bytes for this algorithm.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::ChaCha20Poly1305 | Self::Aes256Gcm | Self::XChaCha20Poly1305 => KEY_LEN,
        }
    }

    /// Nonce length in bytes that this algorithm uses.
    #[must_use]
    pub const fn nonce_len(self) -> usize {
        match self {
            Self::ChaCha20Poly1305 => CHACHA20_NONCE_LEN,
            Self::Aes256Gcm => AES_GCM_NONCE_LEN,
            Self::XChaCha20Poly1305 => XCHACHA20_NONCE_LEN,
        }
    }

    /// Authentication-tag length in bytes that this algorithm produces.
    #[must_use]
    pub const fn tag_len(self) -> usize {
        match self {
            Self::ChaCha20Poly1305 => CHACHA20_TAG_LEN,
            Self::Aes256Gcm => AES_GCM_TAG_LEN,
            Self::XChaCha20Poly1305 => XCHACHA20_TAG_LEN,
        }
    }

    /// The byte that identifies this algorithm in the sealed format and
    /// the stream header.
    pub(crate) const fn id(self) -> u8 {
        match self {
            Self::ChaCha20Poly1305 => 0x00,
            Self::Aes256Gcm => 0x01,
            Self::XChaCha20Poly1305 => 0x02,
        }
    }

    /// Inverse of [`id`](Self::id).
    pub(crate) const fn from_id(id: u8) -> Option<Self> {
        match id {
            0x00 => Some(Self::ChaCha20Poly1305),
            0x01 => Some(Self::Aes256Gcm),
            0x02 => Some(Self::XChaCha20Poly1305),
            _ => None,
        }
    }
}

/// Run `$body` with `$C` bound to the cipher type for `$alg`, or return
/// [`Error::AlgorithmNotEnabled`] when its feature is off.
macro_rules! with_cipher {
    ($alg:expr, $C:ident => $body:expr) => {
        match $alg {
            Algorithm::ChaCha20Poly1305 => {
                #[cfg(feature = "aead-chacha20")]
                {
                    type $C = ::chacha20poly1305::ChaCha20Poly1305;
                    $body
                }
                #[cfg(not(feature = "aead-chacha20"))]
                {
                    Err(Error::AlgorithmNotEnabled("aead-chacha20"))
                }
            }
            Algorithm::XChaCha20Poly1305 => {
                #[cfg(feature = "aead-chacha20")]
                {
                    type $C = ::chacha20poly1305::XChaCha20Poly1305;
                    $body
                }
                #[cfg(not(feature = "aead-chacha20"))]
                {
                    Err(Error::AlgorithmNotEnabled("aead-chacha20"))
                }
            }
            Algorithm::Aes256Gcm => {
                #[cfg(feature = "aead-aes-gcm")]
                {
                    type $C = ::aes_gcm::Aes256Gcm;
                    $body
                }
                #[cfg(not(feature = "aead-aes-gcm"))]
                {
                    Err(Error::AlgorithmNotEnabled("aead-aes-gcm"))
                }
            }
        }
    };
}
// Used by the stream module.
#[allow(unused_imports)]
pub(crate) use with_cipher;

/// Build the associated data for the sealed format, `header || aad`,
/// and pass it to `f`. Short AAD (the common case) stays on the stack.
fn with_sealed_aad<R>(
    header: [u8; SEALED_HEADER_LEN],
    aad: &[u8],
    f: impl FnOnce(&[u8]) -> R,
) -> R {
    const STACK: usize = 128;
    if aad.len() <= STACK - SEALED_HEADER_LEN {
        let mut buf = [0u8; STACK];
        buf[..SEALED_HEADER_LEN].copy_from_slice(&header);
        buf[SEALED_HEADER_LEN..SEALED_HEADER_LEN + aad.len()].copy_from_slice(aad);
        f(&buf[..SEALED_HEADER_LEN + aad.len()])
    } else {
        let mut buf = Vec::with_capacity(SEALED_HEADER_LEN + aad.len());
        buf.extend_from_slice(&header);
        buf.extend_from_slice(aad);
        f(&buf)
    }
}

/// Generate a fresh random 256-bit key from the OS CSPRNG.
///
/// The key comes back in [`Zeroizing`](zeroize::Zeroizing), so it is
/// wiped when it goes out of scope. Use it for any of the AEAD
/// algorithms, the stream encryptor, or as HKDF input key material.
///
/// Requires the `zeroize` feature and a random source (`std` or
/// `getrandom`). New in 1.1.0.
///
/// # Errors
///
/// [`Error::RandomFailure`] if the OS random source fails.
///
/// # Example
///
/// ```
/// # #[cfg(all(feature = "aead-chacha20", feature = "zeroize"))] {
/// use crypt_io::{Crypt, generate_key};
///
/// let key = generate_key()?;
/// let ciphertext = Crypt::new().encrypt(&*key, b"hello")?;
/// # }
/// # Ok::<(), crypt_io::Error>(())
/// ```
#[cfg(all(feature = "zeroize", any(feature = "std", feature = "getrandom")))]
pub fn generate_key() -> Result<zeroize::Zeroizing<[u8; KEY_LEN]>> {
    let mut key = zeroize::Zeroizing::new([0u8; KEY_LEN]);
    crate::rng::fill(&mut key[..])?;
    Ok(key)
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

    /// Convenience constructor for [`Algorithm::Aes256Gcm`]. Available only
    /// when the `aead-aes-gcm` Cargo feature is enabled.
    ///
    /// Equivalent to `Crypt::with_algorithm(Algorithm::Aes256Gcm)`. Provided
    /// because picking AES-GCM is an explicit, deliberate choice — usually
    /// driven by an interop requirement or by a target platform with
    /// AES-NI / ARMv8 crypto extensions — and the call site reads cleaner
    /// when it says so.
    #[cfg(feature = "aead-aes-gcm")]
    #[must_use]
    pub const fn aes_256_gcm() -> Self {
        Self {
            algorithm: Algorithm::Aes256Gcm,
        }
    }

    /// Convenience constructor for [`Algorithm::XChaCha20Poly1305`].
    /// Available when the `aead-chacha20` feature is enabled. New in
    /// 1.1.0.
    #[cfg(feature = "aead-chacha20")]
    #[must_use]
    pub const fn xchacha20_poly1305() -> Self {
        Self {
            algorithm: Algorithm::XChaCha20Poly1305,
        }
    }

    /// The algorithm this handle is configured to use.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Encrypt `plaintext` under `key` and return `nonce || ciphertext || tag`.
    ///
    /// A fresh nonce (12 bytes, or 24 for XChaCha20-Poly1305) is
    /// generated for every call from the OS CSPRNG. The nonce is
    /// prepended to the returned buffer so the corresponding
    /// [`decrypt`](Self::decrypt) call needs only the key and the
    /// buffer.
    ///
    /// Requires a random source (`std` or `getrandom` feature).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidKey`] if `key` is not 32 bytes.
    /// - [`Error::RandomFailure`] if the OS random source could not
    ///   produce a nonce.
    /// - [`Error::LimitExceeded`] if `plaintext` or the associated
    ///   data is longer than the cipher allows (64 GiB for AES-256-GCM,
    ///   256 GiB for the ChaCha20 ciphers). 1.0.x reported this as
    ///   [`Error::AuthenticationFailed`].
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
    #[cfg(any(feature = "std", feature = "getrandom"))]
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
    #[cfg(any(feature = "std", feature = "getrandom"))]
    pub fn encrypt_with_aad(&self, key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        with_cipher!(self.algorithm, C => backend::encrypt::<C>(key, plaintext, aad, &[]))
    }

    /// Decrypt a buffer produced by [`encrypt`](Self::encrypt) and return
    /// the plaintext.
    ///
    /// The buffer is expected to be `nonce || ciphertext || tag` — exactly
    /// the layout [`encrypt`](Self::encrypt) returns. The tag is verified
    /// in constant time; any tampering, wrong key, or wrong length results
    /// in [`Error::AuthenticationFailed`].
    ///
    /// The returned `Vec<u8>` does **not** auto-zeroize. Use
    /// [`decrypt_zeroizing`](Self::decrypt_zeroizing) to get the
    /// plaintext in a buffer that is wiped on drop.
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
        with_cipher!(self.algorithm, C => backend::decrypt::<C>(key, ciphertext, aad))
    }

    /// Like [`decrypt`](Self::decrypt), but the plaintext is returned in
    /// a [`Zeroizing`](zeroize::Zeroizing) buffer that is wiped when it
    /// is dropped. The plaintext is written once, into that buffer; no
    /// unwiped copy is made along the way.
    ///
    /// Requires the `zeroize` feature. New in 1.1.0.
    ///
    /// # Errors
    ///
    /// Same as [`decrypt`](Self::decrypt).
    #[cfg(feature = "zeroize")]
    pub fn decrypt_zeroizing(
        &self,
        key: &[u8],
        ciphertext: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        self.decrypt_with_aad_zeroizing(key, ciphertext, &[])
    }

    /// [`decrypt_zeroizing`](Self::decrypt_zeroizing) with associated
    /// data. New in 1.1.0.
    ///
    /// # Errors
    ///
    /// Same as [`decrypt`](Self::decrypt).
    #[cfg(feature = "zeroize")]
    pub fn decrypt_with_aad_zeroizing(
        &self,
        key: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        self.decrypt_with_aad(key, ciphertext, aad)
            .map(zeroize::Zeroizing::new)
    }

    /// Zero-allocation encrypt — writes `nonce || ciphertext || tag`
    /// into the caller-supplied `out` buffer. The buffer is cleared
    /// first and then grown as needed. Reusing the same buffer across
    /// calls amortises the allocation cost away.
    ///
    /// On error `out` is empty. If the upstream cipher rejects the
    /// input after the plaintext was copied into `out`, the copy is
    /// overwritten with zeros before returning.
    ///
    /// Equivalent to [`encrypt`](Self::encrypt) but does not allocate
    /// a fresh `Vec` per call. New in 0.10.0.
    ///
    /// # Errors
    ///
    /// Same as [`encrypt`](Self::encrypt).
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "aead-chacha20")] {
    /// use crypt_io::Crypt;
    /// let crypt = Crypt::new();
    /// let key = [0u8; 32];
    /// let mut out = Vec::new();
    ///
    /// // First call grows `out` to capacity.
    /// crypt.encrypt_into(&key, b"hello", &mut out)?;
    ///
    /// // Subsequent calls reuse the capacity — no allocation.
    /// crypt.encrypt_into(&key, b"world", &mut out)?;
    /// # }
    /// # Ok::<(), crypt_io::Error>(())
    /// ```
    #[cfg(any(feature = "std", feature = "getrandom"))]
    pub fn encrypt_into(&self, key: &[u8], plaintext: &[u8], out: &mut Vec<u8>) -> Result<()> {
        self.encrypt_with_aad_into(key, plaintext, &[], out)
    }

    /// Zero-allocation encrypt with associated data. See
    /// [`encrypt_into`](Self::encrypt_into).
    ///
    /// # Errors
    ///
    /// Same as [`encrypt`](Self::encrypt).
    #[cfg(any(feature = "std", feature = "getrandom"))]
    pub fn encrypt_with_aad_into(
        &self,
        key: &[u8],
        plaintext: &[u8],
        aad: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<()> {
        out.clear();
        with_cipher!(self.algorithm, C => backend::encrypt_into::<C>(key, plaintext, aad, &[], out))
    }

    /// Zero-allocation decrypt — writes the recovered plaintext into
    /// the caller-supplied `out` buffer. The buffer is cleared first
    /// and then grown as needed.
    ///
    /// `out` is cleared before any check runs, so on **every** error
    /// (`InvalidKey`, `InvalidCiphertext`, `AuthenticationFailed`, ...)
    /// it is empty and never holds a previous message's plaintext. On
    /// authentication failure the whole allocation (length and spare
    /// capacity) is also overwritten with zeros before returning. If
    /// `out` has to grow, its old allocation is wiped before it is
    /// freed (1.1.0; `Vec::reserve` would leave a copy behind).
    ///
    /// Note that `out` is not wiped on success or when it is dropped;
    /// the recovered plaintext is the caller's to manage.
    ///
    /// Equivalent to [`decrypt`](Self::decrypt) but does not allocate
    /// a fresh `Vec` per call. New in 0.10.0.
    ///
    /// # Errors
    ///
    /// Same as [`decrypt`](Self::decrypt).
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "aead-chacha20")] {
    /// use crypt_io::Crypt;
    /// let crypt = Crypt::new();
    /// let key = [0u8; 32];
    ///
    /// let mut ciphertext = Vec::new();
    /// crypt.encrypt_into(&key, b"hello", &mut ciphertext)?;
    ///
    /// let mut plaintext = Vec::new();
    /// crypt.decrypt_into(&key, &ciphertext, &mut plaintext)?;
    /// assert_eq!(&plaintext[..], b"hello");
    /// # }
    /// # Ok::<(), crypt_io::Error>(())
    /// ```
    pub fn decrypt_into(&self, key: &[u8], ciphertext: &[u8], out: &mut Vec<u8>) -> Result<()> {
        self.decrypt_with_aad_into(key, ciphertext, &[], out)
    }

    /// Zero-allocation decrypt with associated data. See
    /// [`decrypt_into`](Self::decrypt_into).
    ///
    /// # Errors
    ///
    /// Same as [`decrypt`](Self::decrypt).
    pub fn decrypt_with_aad_into(
        &self,
        key: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<()> {
        // Clear before anything can fail, so no error path returns the
        // caller's previous contents.
        out.clear();
        with_cipher!(self.algorithm, C => backend::decrypt_into::<C>(key, ciphertext, aad, out))
    }

    /// Encrypt into the **sealed** format, which records the format
    /// version and the algorithm:
    /// `0x01 || algorithm || nonce || ciphertext || tag`.
    ///
    /// Use this instead of [`encrypt`](Self::encrypt) for new data that
    /// may outlive one algorithm choice: [`open`](Self::open) routes on
    /// the stored algorithm byte, so a later switch of algorithm (or a
    /// mix of algorithms in one store) needs no out-of-band bookkeeping.
    /// The header bytes are authenticated. New in 1.1.0.
    ///
    /// Requires a random source (`std` or `getrandom` feature).
    ///
    /// # Errors
    ///
    /// Same as [`encrypt`](Self::encrypt).
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "aead-chacha20")] {
    /// use crypt_io::{Algorithm, Crypt};
    ///
    /// let key = [7u8; 32];
    /// let sealed = Crypt::with_algorithm(Algorithm::XChaCha20Poly1305).seal(&key, b"hi")?;
    ///
    /// // Any handle opens it; the algorithm comes from the header.
    /// assert_eq!(Crypt::new().open(&key, &sealed)?, b"hi");
    /// assert_eq!(Crypt::sealed_algorithm(&sealed)?, Algorithm::XChaCha20Poly1305);
    /// # }
    /// # Ok::<(), crypt_io::Error>(())
    /// ```
    #[cfg(any(feature = "std", feature = "getrandom"))]
    pub fn seal(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        self.seal_with_aad(key, plaintext, &[])
    }

    /// [`seal`](Self::seal) with associated data, which must be passed
    /// unchanged to [`open_with_aad`](Self::open_with_aad). New in
    /// 1.1.0.
    ///
    /// # Errors
    ///
    /// Same as [`encrypt`](Self::encrypt).
    #[cfg(any(feature = "std", feature = "getrandom"))]
    pub fn seal_with_aad(&self, key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let header = [SEALED_VERSION, self.algorithm.id()];
        with_sealed_aad(
            header,
            aad,
            |full_aad| with_cipher!(self.algorithm, C => backend::encrypt::<C>(key, plaintext, full_aad, &header)),
        )
    }

    /// Decrypt a buffer produced by [`seal`](Self::seal). The algorithm
    /// is read from the (authenticated) header, not from this handle.
    /// New in 1.1.0.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidCiphertext`] if the buffer is too short, has
    ///   an unknown version byte or an unknown algorithm byte.
    /// - [`Error::AlgorithmNotEnabled`] if the stored algorithm's
    ///   feature is disabled in this build.
    /// - [`Error::InvalidKey`] and [`Error::AuthenticationFailed`] as
    ///   for [`decrypt`](Self::decrypt). Changing a header byte fails
    ///   authentication.
    pub fn open(&self, key: &[u8], sealed: &[u8]) -> Result<Vec<u8>> {
        self.open_with_aad(key, sealed, &[])
    }

    /// [`open`](Self::open) with associated data. New in 1.1.0.
    ///
    /// # Errors
    ///
    /// Same as [`open`](Self::open).
    pub fn open_with_aad(&self, key: &[u8], sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let algorithm = Self::sealed_algorithm(sealed)?;
        let header = [SEALED_VERSION, algorithm.id()];
        let body = &sealed[SEALED_HEADER_LEN..];
        with_sealed_aad(
            header,
            aad,
            |full_aad| with_cipher!(algorithm, C => backend::decrypt::<C>(key, body, full_aad)),
        )
    }

    /// Read the algorithm recorded in a sealed buffer's header, without
    /// decrypting it. The header is not authenticated until
    /// [`open`](Self::open) succeeds. New in 1.1.0.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidCiphertext`] if the buffer is shorter than the
    /// header or has an unknown version or algorithm byte.
    pub fn sealed_algorithm(sealed: &[u8]) -> Result<Algorithm> {
        let [version, alg, ..] = *sealed else {
            return Err(Error::InvalidCiphertext(alloc::string::String::from(
                "sealed buffer shorter than its 2-byte header",
            )));
        };
        if version != SEALED_VERSION {
            return Err(Error::InvalidCiphertext(alloc::format!(
                "unsupported sealed format version: 0x{version:02x}"
            )));
        }
        Algorithm::from_id(alg).ok_or_else(|| {
            Error::InvalidCiphertext(alloc::format!("unknown algorithm byte: 0x{alg:02x}"))
        })
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
        assert_eq!(recovered, [] as [u8; 0]);
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

// AES-256-GCM end-to-end tests exercised through the `Crypt` surface.
// Mirrors the ChaCha20 test suite above so the cross-algorithm contract
// is verified at the public API layer (not just the backend module).
#[cfg(all(test, feature = "aead-aes-gcm"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod aes_gcm_tests {
    use super::*;
    use alloc::vec;

    fn aes() -> Crypt {
        Crypt::aes_256_gcm()
    }

    #[test]
    fn algorithm_metadata_matches_constants() {
        let a = Algorithm::Aes256Gcm;
        assert_eq!(a.key_len(), KEY_LEN);
        assert_eq!(a.nonce_len(), AES_GCM_NONCE_LEN);
        assert_eq!(a.tag_len(), AES_GCM_TAG_LEN);
        assert_eq!(a.name(), "AES-256-GCM");
    }

    #[test]
    fn aes_256_gcm_constructor_selects_algorithm() {
        let c = aes();
        assert_eq!(c.algorithm(), Algorithm::Aes256Gcm);
        let alt = Crypt::with_algorithm(Algorithm::Aes256Gcm);
        assert_eq!(c, alt);
    }

    #[test]
    fn round_trip_empty_plaintext() {
        let crypt = aes();
        let key = [0x11u8; 32];
        let ciphertext = crypt.encrypt(&key, b"").unwrap();
        assert_eq!(ciphertext.len(), AES_GCM_NONCE_LEN + AES_GCM_TAG_LEN);
        let recovered = crypt.decrypt(&key, &ciphertext).unwrap();
        assert_eq!(recovered, [] as [u8; 0]);
    }

    #[test]
    fn round_trip_short_plaintext() {
        let crypt = aes();
        let key = [0x22u8; 32];
        let plaintext = b"hello, world!";
        let ciphertext = crypt.encrypt(&key, plaintext).unwrap();
        let recovered = crypt.decrypt(&key, &ciphertext).unwrap();
        assert_eq!(&*recovered, plaintext);
    }

    #[test]
    fn round_trip_one_megabyte() {
        let crypt = aes();
        let key = [0x33u8; 32];
        let plaintext = vec![0xa5u8; 1024 * 1024];
        let ciphertext = crypt.encrypt(&key, &plaintext).unwrap();
        let recovered = crypt.decrypt(&key, &ciphertext).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn two_encryptions_of_same_plaintext_differ() {
        let crypt = aes();
        let key = [0u8; 32];
        let plaintext = b"deterministic? no.";
        let a = crypt.encrypt(&key, plaintext).unwrap();
        let b = crypt.encrypt(&key, plaintext).unwrap();
        assert_ne!(a, b, "nonce-prepended outputs must differ across calls");
    }

    #[test]
    fn wrong_key_fails_authentication() {
        let crypt = aes();
        let key = [0x44u8; 32];
        let wrong = [0x55u8; 32];
        let ciphertext = crypt.encrypt(&key, b"secret").unwrap();
        let err = crypt.decrypt(&wrong, &ciphertext).unwrap_err();
        assert_eq!(err, Error::AuthenticationFailed);
    }

    #[test]
    fn tampered_ciphertext_fails_authentication() {
        let crypt = aes();
        let key = [0x66u8; 32];
        let mut ciphertext = crypt.encrypt(&key, b"hands off").unwrap();
        let i = ciphertext.len() / 2;
        ciphertext[i] ^= 0x01;
        let err = crypt.decrypt(&key, &ciphertext).unwrap_err();
        assert_eq!(err, Error::AuthenticationFailed);
    }

    #[test]
    fn tampered_tag_fails_authentication() {
        let crypt = aes();
        let key = [0x77u8; 32];
        let mut ciphertext = crypt.encrypt(&key, b"sign me").unwrap();
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0xff;
        let err = crypt.decrypt(&key, &ciphertext).unwrap_err();
        assert_eq!(err, Error::AuthenticationFailed);
    }

    #[test]
    fn truncated_ciphertext_is_rejected() {
        let crypt = aes();
        let key = [0u8; 32];
        for len in 0..(AES_GCM_NONCE_LEN + AES_GCM_TAG_LEN) {
            let err = crypt.decrypt(&key, &vec![0u8; len]).unwrap_err();
            assert!(
                matches!(err, Error::InvalidCiphertext(_)),
                "len={len} should error"
            );
        }
    }

    #[test]
    fn aad_round_trip() {
        let crypt = aes();
        let key = [0x88u8; 32];
        let plaintext = b"plaintext";
        let aad = b"associated";
        let ciphertext = crypt.encrypt_with_aad(&key, plaintext, aad).unwrap();
        let recovered = crypt.decrypt_with_aad(&key, &ciphertext, aad).unwrap();
        assert_eq!(&*recovered, plaintext);
    }

    #[test]
    fn aad_mismatch_fails_authentication() {
        let crypt = aes();
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
    fn invalid_key_length_rejected_on_encrypt() {
        let crypt = aes();
        let err = crypt.encrypt(&[0u8; 16], b"x").unwrap_err();
        assert_eq!(
            err,
            Error::InvalidKey {
                expected: 32,
                actual: 16
            }
        );
    }
}

// Cross-algorithm integration tests: confirm that ciphertext produced by
// one algorithm cannot be decrypted by the other. This is the contract
// callers depend on when they store ciphertexts they later need to route
// to the correct decryption path.
#[cfg(all(test, feature = "aead-chacha20", feature = "aead-aes-gcm"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod cross_algorithm_tests {
    use super::*;

    #[test]
    fn chacha_ciphertext_does_not_decrypt_as_aes() {
        let key = [0xcdu8; 32];
        let ct = Crypt::new().encrypt(&key, b"message").unwrap();
        let err = Crypt::aes_256_gcm().decrypt(&key, &ct).unwrap_err();
        assert_eq!(err, Error::AuthenticationFailed);
    }

    #[test]
    fn aes_ciphertext_does_not_decrypt_as_chacha() {
        let key = [0xefu8; 32];
        let ct = Crypt::aes_256_gcm().encrypt(&key, b"message").unwrap();
        let err = Crypt::new().decrypt(&key, &ct).unwrap_err();
        assert_eq!(err, Error::AuthenticationFailed);
    }

    #[test]
    fn algorithm_name_table_is_unique() {
        let names = [
            Algorithm::ChaCha20Poly1305.name(),
            Algorithm::Aes256Gcm.name(),
        ];
        for (i, a) in names.iter().enumerate() {
            for (j, b) in names.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "algorithm names must be distinct");
                }
            }
        }
    }
}

#[cfg(all(test, feature = "aead-chacha20"))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod xchacha_and_sealed_tests {
    use super::*;

    fn x() -> Crypt {
        Crypt::xchacha20_poly1305()
    }

    #[test]
    fn xchacha_metadata() {
        let a = Algorithm::XChaCha20Poly1305;
        assert_eq!(a.nonce_len(), XCHACHA20_NONCE_LEN);
        assert_eq!(a.tag_len(), XCHACHA20_TAG_LEN);
        assert_eq!(a.key_len(), KEY_LEN);
        assert_eq!(a.name(), "XChaCha20-Poly1305");
        assert_eq!(x().algorithm(), a);
    }

    #[test]
    fn xchacha_round_trip_and_layout() {
        let key = [0x31u8; 32];
        let ct = x().encrypt_with_aad(&key, b"payload", b"ad").unwrap();
        assert_eq!(ct.len(), XCHACHA20_NONCE_LEN + 7 + XCHACHA20_TAG_LEN);
        assert_eq!(x().decrypt_with_aad(&key, &ct, b"ad").unwrap(), b"payload");
        assert_eq!(
            x().decrypt_with_aad(&key, &ct, b"AD").unwrap_err(),
            Error::AuthenticationFailed
        );
        // A ChaCha20-Poly1305 handle reads the first 12 bytes as the
        // nonce and fails closed.
        assert_eq!(
            Crypt::new().decrypt_with_aad(&key, &ct, b"ad").unwrap_err(),
            Error::AuthenticationFailed
        );
    }

    #[test]
    fn xchacha_into_round_trip_and_short_input() {
        let key = [0x32u8; 32];
        let mut ct = Vec::new();
        x().encrypt_into(&key, b"abc", &mut ct).unwrap();
        let mut pt = Vec::new();
        x().decrypt_into(&key, &ct, &mut pt).unwrap();
        assert_eq!(pt, b"abc");
        for len in 0..(XCHACHA20_NONCE_LEN + XCHACHA20_TAG_LEN) {
            assert!(matches!(
                x().decrypt(&key, &ct[..len.min(ct.len())]).unwrap_err(),
                Error::InvalidCiphertext(_)
            ));
        }
    }

    #[test]
    fn algorithm_ids_round_trip() {
        for a in [
            Algorithm::ChaCha20Poly1305,
            Algorithm::Aes256Gcm,
            Algorithm::XChaCha20Poly1305,
        ] {
            assert_eq!(Algorithm::from_id(a.id()), Some(a));
        }
        assert_eq!(Algorithm::from_id(0x03), None);
    }

    #[test]
    fn seal_open_round_trip_every_algorithm() {
        let key = [0x44u8; 32];
        let mut algs = alloc::vec![Algorithm::ChaCha20Poly1305, Algorithm::XChaCha20Poly1305];
        if cfg!(feature = "aead-aes-gcm") {
            algs.push(Algorithm::Aes256Gcm);
        }
        for a in algs {
            let sealed = Crypt::with_algorithm(a)
                .seal_with_aad(&key, b"sealed body", b"ctx")
                .unwrap();
            assert_eq!(sealed[0], SEALED_VERSION);
            assert_eq!(sealed[1], a.id());
            assert_eq!(
                sealed.len(),
                SEALED_HEADER_LEN + a.nonce_len() + 11 + a.tag_len()
            );
            assert_eq!(Crypt::sealed_algorithm(&sealed).unwrap(), a);
            // Any handle opens it.
            assert_eq!(
                Crypt::new().open_with_aad(&key, &sealed, b"ctx").unwrap(),
                b"sealed body"
            );
            assert_eq!(
                Crypt::new()
                    .open_with_aad(&key, &sealed, b"other")
                    .unwrap_err(),
                Error::AuthenticationFailed
            );
        }
    }

    #[test]
    fn sealed_long_aad_round_trip() {
        let key = [0x45u8; 32];
        let aad = alloc::vec![0x5au8; 1000];
        let sealed = Crypt::new().seal_with_aad(&key, b"x", &aad).unwrap();
        assert_eq!(
            Crypt::new().open_with_aad(&key, &sealed, &aad).unwrap(),
            b"x"
        );
    }

    #[test]
    fn sealed_header_is_authenticated() {
        let key = [0x46u8; 32];
        let sealed = Crypt::new().seal(&key, b"body").unwrap();
        // Switching the algorithm byte to XChaCha changes the nonce
        // split and the AAD: must fail, not misdecode.
        let mut tampered = sealed.clone();
        tampered[1] = Algorithm::XChaCha20Poly1305.id();
        assert!(Crypt::new().open(&key, &tampered).is_err());
        // Unknown version and algorithm bytes are rejected up front.
        let mut v = sealed.clone();
        v[0] = 0x02;
        assert!(matches!(
            Crypt::new().open(&key, &v).unwrap_err(),
            Error::InvalidCiphertext(_)
        ));
        let mut a = sealed;
        a[1] = 0x7f;
        assert!(matches!(
            Crypt::new().open(&key, &a).unwrap_err(),
            Error::InvalidCiphertext(_)
        ));
        assert!(matches!(
            Crypt::new().open(&key, &[SEALED_VERSION]).unwrap_err(),
            Error::InvalidCiphertext(_)
        ));
    }

    #[test]
    fn legacy_and_sealed_do_not_cross_decrypt() {
        let key = [0x47u8; 32];
        let legacy = Crypt::new().encrypt(&key, b"m").unwrap();
        let sealed = Crypt::new().seal(&key, b"m").unwrap();
        assert!(Crypt::new().decrypt(&key, &sealed).is_err());
        assert!(Crypt::new().open(&key, &legacy).is_err());
    }

    #[cfg(feature = "zeroize")]
    #[test]
    fn generate_key_and_decrypt_zeroizing() {
        let k1 = generate_key().unwrap();
        let k2 = generate_key().unwrap();
        assert_ne!(*k1, *k2);
        let ct = Crypt::new().encrypt(&*k1, b"secret").unwrap();
        let pt = Crypt::new().decrypt_zeroizing(&*k1, &ct).unwrap();
        assert_eq!(&pt[..], b"secret");
    }
}
