//! ECDSA P-256 with SHA-256, verification only (FIPS 186-5, SEC 1).

use core::fmt;

use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_FIXED, ParsedPublicKey};

use crate::error::{Error, Result};

/// Length of an uncompressed SEC1 P-256 point (`0x04 || x || y`).
pub const P256_SEC1_UNCOMPRESSED_LEN: usize = 65;

/// Length of a fixed-size (`r || s`) P-256 signature, as JOSE uses.
pub const P256_FIXED_SIGNATURE_LEN: usize = 64;

/// An ECDSA P-256 public key for checking SHA-256 signatures: WebAuthn
/// and COSE `ES256` (DER signatures) and JOSE `ES256` (fixed `r || s`).
///
/// Verification only: crypt-io does not sign with P-256. Prefer
/// Ed25519 for keys you create; this type exists for keys other parties
/// choose, above all passkeys, most of which are P-256.
///
/// The point is checked to be on the curve when the key is parsed, and
/// the key is parsed once, so each check costs only the verification.
/// The key is public: it is `Clone`, and `Debug` prints only the type
/// name. The type is `Send` and `Sync`.
///
/// New in 1.5.0. Requires the `sign-p256` feature.
///
/// # Example
///
/// ```no_run
/// use crypt_io::sign::EcdsaP256PublicKey;
///
/// # let (point, authenticator_data_and_hash, signature) = (Vec::<u8>::new(), Vec::<u8>::new(), Vec::<u8>::new());
/// let key = EcdsaP256PublicKey::from_sec1(&point)?;          // 0x04 || x || y
/// key.check_sha256(&authenticator_data_and_hash, &signature)?;   // WebAuthn: DER signature
/// # Ok::<(), crypt_io::Error>(())
/// ```
#[derive(Clone)]
pub struct EcdsaP256PublicKey {
    der: ParsedPublicKey,
    fixed: ParsedPublicKey,
}

impl EcdsaP256PublicKey {
    /// Parse a SEC1 point (SEC 1 section 2.3.3): uncompressed
    /// (`0x04 || x || y`, 65 bytes) or compressed (`0x02` / `0x03 || x`,
    /// 33 bytes).
    ///
    /// # Errors
    ///
    /// [`Error::Sign`] if the bytes are not a P-256 point of either form,
    /// or the point is not on the curve.
    pub fn from_sec1(point: &[u8]) -> Result<Self> {
        let well_formed = match point.first() {
            Some(0x04) => point.len() == P256_SEC1_UNCOMPRESSED_LEN,
            Some(0x02 | 0x03) => point.len() == 33,
            _ => false,
        };
        if !well_formed {
            return Err(Error::Sign("key rejected: not a SEC1 P-256 point"));
        }
        Self::parse(point)
    }

    /// Parse the two 32-byte affine coordinates, as a COSE `EC2` key
    /// (`-2` / `-3`) or a JWK (`x` / `y`, base64url-decoded) carries
    /// them.
    ///
    /// # Errors
    ///
    /// [`Error::Sign`] if the point is not on the curve.
    pub fn from_coordinates(x: &[u8; 32], y: &[u8; 32]) -> Result<Self> {
        let mut point = [0u8; P256_SEC1_UNCOMPRESSED_LEN];
        point[0] = 0x04;
        point[1..33].copy_from_slice(x);
        point[33..].copy_from_slice(y);
        Self::parse(&point)
    }

    /// Parse a DER `SubjectPublicKeyInfo` (RFC 5480): the
    /// `-----BEGIN PUBLIC KEY-----` body of a P-256 key.
    ///
    /// # Errors
    ///
    /// [`Error::Sign`] if `der` is not a P-256 `SubjectPublicKeyInfo`
    /// (another curve is refused).
    pub fn from_der(der: &[u8]) -> Result<Self> {
        if der.first() != Some(&0x30) {
            return Err(Error::Sign("key rejected: not a SubjectPublicKeyInfo"));
        }
        Self::parse(der)
    }

    fn parse(bytes: &[u8]) -> Result<Self> {
        let der =
            ParsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, bytes).map_err(super::key_rejected)?;
        let fixed =
            ParsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, bytes).map_err(super::key_rejected)?;
        Ok(Self { der, fixed })
    }

    /// Check a DER-encoded ECDSA signature (`SEQUENCE { r, s }`) of
    /// SHA-256(`message`). This is the form WebAuthn, COSE `ES256` in
    /// WebAuthn, X.509 and TLS use.
    ///
    /// For a WebAuthn assertion, `message` is `authenticatorData ||
    /// SHA-256(clientDataJSON)`.
    ///
    /// # Errors
    ///
    /// [`Error::AuthenticationFailed`](crate::Error::AuthenticationFailed)
    /// for a wrong or altered signature, a different message, or a
    /// signature that is not strict DER.
    pub fn check_sha256(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        self.der
            .verify_sig(message, signature)
            .map_err(|_| Error::AuthenticationFailed)
    }

    /// Check a fixed-size signature (`r || s`, 32 bytes each, IEEE
    /// P1363) of SHA-256(`message`): the JOSE `ES256` form (RFC 7518
    /// section 3.4).
    ///
    /// # Errors
    ///
    /// [`Error::AuthenticationFailed`](crate::Error::AuthenticationFailed)
    /// for a wrong or altered signature, a different message, or a
    /// signature that is not exactly 64 bytes.
    pub fn check_sha256_fixed(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        if signature.len() != P256_FIXED_SIGNATURE_LEN {
            return Err(Error::AuthenticationFailed);
        }
        self.fixed
            .verify_sig(message, signature)
            .map_err(|_| Error::AuthenticationFailed)
    }
}

impl fmt::Debug for EcdsaP256PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaP256PublicKey").finish_non_exhaustive()
    }
}
