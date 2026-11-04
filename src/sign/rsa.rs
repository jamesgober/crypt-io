//! RSA signing: PKCS#1 v1.5 with SHA-256 (RFC 8017 section 8.2).

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{KeyPair, RSA_PKCS1_SHA256, RsaKeyPair};

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
