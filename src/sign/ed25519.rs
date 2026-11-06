//! Ed25519 signing (RFC 8032, pure mode).

use core::fmt;

use aws_lc_rs::signature::{ED25519, Ed25519KeyPair, KeyPair, ParsedPublicKey};

use crate::error::{Error, Result};

/// Length of an Ed25519 signature in bytes.
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// Length of an Ed25519 public key in bytes.
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// Length of an Ed25519 private key seed in bytes.
pub const ED25519_SEED_LEN: usize = 32;

/// An Ed25519 private key (RFC 8032).
///
/// Signatures are deterministic: the same key and message always give
/// the same 64 bytes. DKIM's `ed25519-sha256` (RFC 8463) signs the
/// SHA-256 of the canonicalized header data with this, and JOSE calls
/// it `EdDSA`.
///
/// The private key lives inside AWS-LC and is cleansed when the key is
/// dropped. `Debug` prints only the public key. The type is `Send` and
/// `Sync`, so one key can sign from many threads.
///
/// New in 1.3.0. Requires the `sign-ed25519` feature.
///
/// # Example
///
/// ```
/// use crypt_io::sign::Ed25519SigningKey;
///
/// // RFC 8032 section 7.1, test 1.
/// let seed = [
///     0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
///     0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
///     0x1c, 0xae, 0x7f, 0x60,
/// ];
/// let key = Ed25519SigningKey::from_seed(&seed)?;
/// let signature = key.sign(b"");
/// assert_eq!(&signature[..4], &[0xe5, 0x56, 0x43, 0x00]);
/// # Ok::<(), crypt_io::Error>(())
/// ```
pub struct Ed25519SigningKey {
    inner: Ed25519KeyPair,
}

impl Ed25519SigningKey {
    /// Parse an unencrypted PKCS#8 private key (RFC 5208 v1 or
    /// RFC 5958 v2, DER). This is what `openssl genpkey -algorithm
    /// ed25519` writes (base64 between the PEM lines). If a v2 document
    /// carries the public key, it must match the private key.
    ///
    /// # Errors
    ///
    /// [`Error::Sign`](crate::Error::Sign) if `der` is not a valid
    /// Ed25519 PKCS#8 document.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        Ed25519KeyPair::from_pkcs8(der)
            .map(|inner| Self { inner })
            .map_err(super::key_rejected)
    }

    /// Build a key from its 32-byte private seed (RFC 8032 section 5.1.5;
    /// the "secret key" in the RFC's test vectors).
    ///
    /// A public key is also 32 bytes; passing one here gives a working
    /// but wrong key that no check can detect. Prefer
    /// [`from_pkcs8_der`](Self::from_pkcs8_der) when you have the
    /// PKCS#8 file.
    ///
    /// # Errors
    ///
    /// [`Error::Sign`](crate::Error::Sign) if the backend cannot build
    /// the key (it does not reject any seed value).
    pub fn from_seed(seed: &[u8; ED25519_SEED_LEN]) -> Result<Self> {
        Ed25519KeyPair::from_seed_unchecked(seed)
            .map(|inner| Self { inner })
            .map_err(super::key_rejected)
    }

    /// Sign `message`.
    ///
    /// # Panics
    ///
    /// Only if AWS-LC fails internally (for example, cannot allocate),
    /// which does not happen for a valid key; the same contract as
    /// `aws-lc-rs`.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; ED25519_SIGNATURE_LEN] {
        let signature = self.inner.sign(message);
        let mut out = [0u8; ED25519_SIGNATURE_LEN];
        out.copy_from_slice(signature.as_ref());
        out
    }

    /// The 32-byte public key, as published in a DKIM `p=` record
    /// (base64) or a JWK `x` member (base64url).
    #[must_use]
    pub fn public_key(&self) -> [u8; ED25519_PUBLIC_KEY_LEN] {
        let mut out = [0u8; ED25519_PUBLIC_KEY_LEN];
        out.copy_from_slice(self.inner.public_key().as_ref());
        out
    }
}

impl fmt::Debug for Ed25519SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519SigningKey")
            .field("public_key", &Hex(self.public_key()))
            .finish_non_exhaustive()
    }
}

/// An Ed25519 public key, parsed once, for checking signatures (RFC 8032).
///
/// Build it from the 32-byte key a DKIM `p=` record (base64) or a JWK
/// `x` member (base64url) carries, then call [`check`](Self::check) for
/// each signature. Parsing happens once, so checking many signatures
/// with one key costs only the verification.
///
/// The key is public: it is `Clone`, and `Debug` prints it in hex. The
/// type is `Send` and `Sync`.
///
/// New in 1.4.0. Requires the `sign-ed25519` feature.
///
/// # Example
///
/// ```
/// use crypt_io::sign::{Ed25519PublicKey, Ed25519SigningKey};
///
/// let signing = Ed25519SigningKey::from_seed(&[7u8; 32])?;
/// let signature = signing.sign(b"message");
///
/// let public = Ed25519PublicKey::from_bytes(&signing.public_key())?;
/// public.check(b"message", &signature)?;
/// assert_eq!(
///     public.check(b"tampered", &signature),
///     Err(crypt_io::Error::AuthenticationFailed)
/// );
/// # Ok::<(), crypt_io::Error>(())
/// ```
#[derive(Clone)]
pub struct Ed25519PublicKey {
    inner: ParsedPublicKey,
    bytes: [u8; ED25519_PUBLIC_KEY_LEN],
}

impl Ed25519PublicKey {
    /// Parse a raw 32-byte Ed25519 public key.
    ///
    /// # Errors
    ///
    /// [`Error::Sign`](crate::Error::Sign) if the bytes are not a valid
    /// key encoding.
    pub fn from_bytes(public_key: &[u8; ED25519_PUBLIC_KEY_LEN]) -> Result<Self> {
        ParsedPublicKey::new(&ED25519, public_key)
            .map(|inner| Self {
                inner,
                bytes: *public_key,
            })
            .map_err(super::key_rejected)
    }

    /// Check that `signature` is this key's Ed25519 signature of
    /// `message`.
    ///
    /// # Errors
    ///
    /// [`Error::AuthenticationFailed`](crate::Error::AuthenticationFailed)
    /// if it is not: a wrong or altered signature, a different message,
    /// or a signature that is not 64 bytes. Non-canonical signatures
    /// (`S` not reduced, RFC 8032 section 5.1.7) are rejected.
    pub fn check(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        if signature.len() != ED25519_SIGNATURE_LEN {
            return Err(Error::AuthenticationFailed);
        }
        self.inner
            .verify_sig(message, signature)
            .map_err(|_| Error::AuthenticationFailed)
    }

    /// The 32 key bytes.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; ED25519_PUBLIC_KEY_LEN] {
        self.bytes
    }
}

impl PartialEq for Ed25519PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for Ed25519PublicKey {}

impl fmt::Debug for Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Ed25519PublicKey")
            .field(&Hex(self.bytes))
            .finish()
    }
}

struct Hex([u8; ED25519_PUBLIC_KEY_LEN]);

impl fmt::Debug for Hex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};

    const SEED: [u8; 32] = [7u8; 32];

    #[test]
    fn sign_verifies_with_the_public_key() {
        let key = Ed25519SigningKey::from_seed(&SEED).unwrap();
        let sig = key.sign(b"hello");
        UnparsedPublicKey::new(&ED25519, key.public_key())
            .verify(b"hello", &sig)
            .unwrap();
        assert!(
            UnparsedPublicKey::new(&ED25519, key.public_key())
                .verify(b"hellO", &sig)
                .is_err()
        );
    }

    #[test]
    fn debug_shows_only_the_public_key() {
        let key = Ed25519SigningKey::from_seed(&SEED).unwrap();
        let text = format!("{key:?}");
        assert!(text.starts_with("Ed25519SigningKey { public_key: "));
        assert!(!text.contains(&"07".repeat(32)));
    }

    #[test]
    fn is_send_and_sync() {
        fn check<T: Send + Sync>() {}
        check::<Ed25519SigningKey>();
    }

    #[test]
    fn rejects_garbage_pkcs8() {
        assert!(matches!(
            Ed25519SigningKey::from_pkcs8_der(&[0x30, 0x03, 0x02, 0x01, 0x00]),
            Err(crate::Error::Sign(_))
        ));
        assert!(Ed25519SigningKey::from_pkcs8_der(&[]).is_err());
    }
}
