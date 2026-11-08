//! RSA signing: PKCS#1 v1.5 with SHA-256 (RFC 8017 section 8.2).

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    KeyPair, ParsedPublicKey, RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
    RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_SHA256, RsaKeyPair, RsaParameters,
};

use crate::error::{Error, Result};

/// Smallest RSA modulus [`RsaSigningKey`] accepts, in bits.
pub const RSA_MIN_MODULUS_BITS: u32 = 2048;

/// Largest RSA modulus [`RsaSigningKey`] accepts, in bits.
pub const RSA_MAX_MODULUS_BITS: u32 = 8192;

/// An RSA private key for PKCS#1 v1.5 signatures with SHA-256.
///
/// This is DKIM's `rsa-sha256` (RFC 6376) and JOSE's `RS256`. Keys from
/// [`RSA_MIN_MODULUS_BITS`] (2048) to [`RSA_MAX_MODULUS_BITS`] (8192)
/// bits are accepted; anything smaller is rejected when the key is
/// parsed, as NIST SP 800-131A requires. Signing uses AWS-LC's blinded,
/// constant-time RSA.
///
/// The private key lives inside AWS-LC, which cleanses it when the key
/// is dropped. `Debug` prints only the modulus size. The type is `Send`
/// and `Sync`.
///
/// New in 1.3.0. Requires the `sign-rsa` feature.
///
/// # Example
///
/// ```no_run
/// use crypt_io::sign::RsaSigningKey;
///
/// let mut der = std::fs::read("dkim-private.der")?;   // PKCS#8; PKCS#1 has its own constructor
/// let key = RsaSigningKey::from_pkcs8_der(&der)?;
/// crypt_io::wipe(&mut der);                            // the key no longer needs the file bytes
///
/// let signature = key.sign_pkcs1v15_sha256(b"data")?;
/// assert_eq!(signature.len() * 8, key.modulus_bits() as usize);
/// let dns_p_value = key.public_key_der();   // SubjectPublicKeyInfo, base64 it for DNS
/// # let _ = dns_p_value;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct RsaSigningKey {
    inner: RsaKeyPair,
    public_key_der: Box<[u8]>,
    modulus_bits: u32,
}

impl RsaSigningKey {
    /// Parse an unencrypted PKCS#8 private key (RFC 5208, DER): the
    /// `-----BEGIN PRIVATE KEY-----` format that `openssl genpkey`
    /// writes.
    ///
    /// # Errors
    ///
    /// [`Error::Sign`] if `der` is not a valid RSA PKCS#8 document or
    /// the modulus is outside 2048 to 8192 bits.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        RsaKeyPair::from_pkcs8(der)
            .map_err(super::key_rejected)
            .and_then(Self::new)
    }

    /// Parse a PKCS#1 `RSAPrivateKey` (RFC 8017 appendix A.1.2, DER):
    /// the `-----BEGIN RSA PRIVATE KEY-----` format.
    ///
    /// # Errors
    ///
    /// [`Error::Sign`] if `der` is not a valid `RSAPrivateKey` or the
    /// modulus is outside 2048 to 8192 bits.
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self> {
        RsaKeyPair::from_der(der)
            .map_err(super::key_rejected)
            .and_then(Self::new)
    }

    fn new(inner: RsaKeyPair) -> Result<Self> {
        let public = inner.public_key();
        let modulus_bits = bit_length(public.modulus().big_endian_without_leading_zero());
        if !(RSA_MIN_MODULUS_BITS..=RSA_MAX_MODULUS_BITS).contains(&modulus_bits) {
            // The backend enforces the same range; keep the promise
            // even if it ever changes.
            return Err(Error::Sign(
                "key rejected: RSA modulus outside 2048 to 8192 bits",
            ));
        }
        let public_key_der = public
            .as_der()
            .map_err(|_| Error::Sign("cannot encode the RSA public key"))?
            .as_ref()
            .into();
        Ok(Self {
            inner,
            public_key_der,
            modulus_bits,
        })
    }

    /// Sign `message` with RSASSA-PKCS1-v1_5 and SHA-256. `message` is
    /// the data itself; it is hashed here. The signature is as long as
    /// the modulus (256 bytes for a 2048-bit key).
    ///
    /// # Errors
    ///
    /// [`Error::Sign`] if AWS-LC reports a failure, which does not
    /// happen for a key this type accepted.
    pub fn sign_pkcs1v15_sha256(&self, message: &[u8]) -> Result<Vec<u8>> {
        let mut signature = vec![0u8; self.inner.public_modulus_len()];
        // PKCS#1 v1.5 is deterministic; AWS-LC ignores the RNG here.
        self.inner
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                message,
                &mut signature,
            )
            .map_err(|_| Error::Sign("RSA signing failed"))?;
        Ok(signature)
    }

    /// Size of the modulus in bits (2048 to 8192).
    #[must_use]
    pub fn modulus_bits(&self) -> u32 {
        self.modulus_bits
    }

    /// The public key as a DER `SubjectPublicKeyInfo` (RFC 5280): the
    /// value a DKIM `p=` record carries in base64, and the body of a
    /// `-----BEGIN PUBLIC KEY-----` file.
    #[must_use]
    pub fn public_key_der(&self) -> &[u8] {
        &self.public_key_der
    }
}

/// Bit length of a big-endian unsigned integer without leading zero
/// bytes.
fn bit_length(be: &[u8]) -> u32 {
    match be.first() {
        None => 0,
        Some(&top) => {
            // A modulus fits in far fewer than 2^29 bytes.
            let bytes = u32::try_from(be.len()).unwrap_or(u32::MAX / 8);
            bytes * 8 - top.leading_zeros()
        }
    }
}

impl fmt::Debug for RsaSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaSigningKey")
            .field("modulus_bits", &self.modulus_bits)
            .finish_non_exhaustive()
    }
}

/// Smallest RSA modulus [`RsaPublicKey::from_der_allow_1024`] accepts,
/// in bits.
pub const RSA_MIN_MODULUS_BITS_LEGACY: u32 = 1024;

/// An RSA public key, parsed once, for checking PKCS#1 v1.5 SHA-256
/// signatures (DKIM `rsa-sha256`, JOSE `RS256`).
///
/// [`from_der`](Self::from_der) accepts 2048- to 8192-bit keys, the
/// same range [`RsaSigningKey`] signs with, and the minimum RFC 7518
/// sets for `RS256`. [`from_der_allow_1024`](Self::from_der_allow_1024)
/// also accepts 1024 to 2047 bits, which a DKIM verifier must still
/// validate (RFC 8301); use it only there.
///
/// The key is public: it is `Clone`, and `Debug` prints the modulus
/// size. The type is `Send` and `Sync`.
///
/// New in 1.4.0. Requires the `sign-rsa` feature.
///
/// # Example
///
/// ```no_run
/// use crypt_io::sign::RsaPublicKey;
///
/// # let (spki, data, signature) = (Vec::<u8>::new(), Vec::<u8>::new(), Vec::<u8>::new());
/// let key = RsaPublicKey::from_der(&spki)?;          // DKIM p= (base64-decoded), or a PEM body
/// key.check_pkcs1v15_sha256(&data, &signature)?;     // Err(AuthenticationFailed) if forged
/// # Ok::<(), crypt_io::Error>(())
/// ```
#[derive(Clone)]
pub struct RsaPublicKey {
    inner: ParsedPublicKey,
    modulus_bits: u32,
}

impl RsaPublicKey {
    /// Parse a DER public key: a `SubjectPublicKeyInfo` (RFC 5280, the
    /// `-----BEGIN PUBLIC KEY-----` body and the usual DKIM `p=` value)
    /// or a PKCS#1 `RSAPublicKey` (RFC 8017 appendix A.1.1). The modulus
    /// must be 2048 to 8192 bits.
    ///
    /// # Errors
    ///
    /// [`Error::Sign`] if `der` is not an RSA public key or the modulus
    /// is outside 2048 to 8192 bits.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        Self::parse(der, RSA_MIN_MODULUS_BITS, &RSA_PKCS1_2048_8192_SHA256)
    }

    /// Like [`from_der`](Self::from_der), but also accepts 1024- to
    /// 2047-bit keys.
    ///
    /// For DKIM verifiers only: RFC 8301 requires them to validate keys
    /// from 1024 bits, and many domains still publish 1024-bit keys. A
    /// 1024-bit RSA key is within reach of a well-funded attacker, so a
    /// pass with one is weaker evidence; never sign with such a key
    /// ([`RsaSigningKey`] refuses them).
    ///
    /// # Errors
    ///
    /// [`Error::Sign`] if `der` is not an RSA public key or the modulus
    /// is outside 1024 to 8192 bits.
    pub fn from_der_allow_1024(der: &[u8]) -> Result<Self> {
        Self::parse(
            der,
            RSA_MIN_MODULUS_BITS_LEGACY,
            &RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
        )
    }

    /// Build a key from its modulus `n` and public exponent `e`
    /// (big-endian, leading zero bytes allowed), as a COSE `RSA` key
    /// (`-1` / `-2`) or a JWK (`n` / `e`, base64url-decoded) carries
    /// them. The modulus must be 2048 to 8192 bits.
    ///
    /// New in 1.5.0.
    ///
    /// # Errors
    ///
    /// [`Error::Sign`] if the components do not form a valid RSA key or
    /// the modulus is outside 2048 to 8192 bits.
    pub fn from_components(n: &[u8], e: &[u8]) -> Result<Self> {
        let strip = |b: &[u8]| -> Vec<u8> {
            let start = b.iter().position(|&x| x != 0).unwrap_or(b.len());
            b[start..].to_vec()
        };
        let (n, e) = (strip(n), strip(e));
        if n.is_empty() || e.is_empty() {
            return Err(Error::Sign("key rejected: empty RSA modulus or exponent"));
        }
        let spki = aws_lc_rs::rsa::PublicKeyComponents {
            n: &n[..],
            e: &e[..],
        }
        .as_der()
        .map_err(|_| Error::Sign("key rejected: invalid RSA components"))?;
        Self::from_der(spki.as_ref())
    }

    fn parse(der: &[u8], min_bits: u32, algorithm: &'static RsaParameters) -> Result<Self> {
        let public = aws_lc_rs::rsa::PublicKey::from_der(der).map_err(super::key_rejected)?;
        let modulus_bits = bit_length(public.modulus().big_endian_without_leading_zero());
        if modulus_bits < min_bits {
            return Err(Error::Sign(if min_bits == RSA_MIN_MODULUS_BITS {
                "key rejected: RSA modulus smaller than 2048 bits"
            } else {
                "key rejected: RSA modulus smaller than 1024 bits"
            }));
        }
        if modulus_bits > RSA_MAX_MODULUS_BITS {
            return Err(Error::Sign(
                "key rejected: RSA modulus larger than 8192 bits",
            ));
        }
        let inner = ParsedPublicKey::new(algorithm, der).map_err(super::key_rejected)?;
        Ok(Self {
            inner,
            modulus_bits,
        })
    }

    /// Check that `signature` is this key's RSASSA-PKCS1-v1_5 SHA-256
    /// signature of `message` (the data itself; it is hashed here).
    ///
    /// # Errors
    ///
    /// [`Error::AuthenticationFailed`](crate::Error::AuthenticationFailed)
    /// if it is not: a wrong or altered signature, a different message,
    /// a signature of the wrong length, or one whose padding or
    /// `DigestInfo` is not the exact DER encoding RFC 8017 prescribes.
    pub fn check_pkcs1v15_sha256(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        self.inner
            .verify_sig(message, signature)
            .map_err(|_| Error::AuthenticationFailed)
    }

    /// Size of the modulus in bits.
    #[must_use]
    pub fn modulus_bits(&self) -> u32 {
        self.modulus_bits
    }
}

impl fmt::Debug for RsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaPublicKey")
            .field("modulus_bits", &self.modulus_bits)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn bit_length_counts_from_the_top_bit() {
        assert_eq!(bit_length(&[]), 0);
        assert_eq!(bit_length(&[0x01]), 1);
        assert_eq!(bit_length(&[0x80, 0x00]), 16);
        assert_eq!(bit_length(&[0x7f, 0xff]), 15);
    }

    #[test]
    fn is_send_and_sync() {
        fn check<T: Send + Sync>() {}
        check::<RsaSigningKey>();
    }

    #[test]
    fn rejects_garbage() {
        assert!(matches!(
            RsaSigningKey::from_pkcs8_der(b"not a key"),
            Err(Error::Sign(_))
        ));
        assert!(matches!(
            RsaSigningKey::from_pkcs1_der(&[]),
            Err(Error::Sign(_))
        ));
    }
}
