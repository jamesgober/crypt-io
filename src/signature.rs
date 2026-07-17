//! Strict, verification-only Ed25519 boundary.
//!
//! This module accepts only fixed-width raw Ed25519 public keys and detached
//! signatures. It intentionally does not provide signing, key generation,
//! trust policy, manifest parsing, canonicalization, or PKCS#8/PEM support.

use core::fmt;

use ed25519_dalek::{Signature as DalekSignature, VerifyingKey};
use error_forge::ForgeError;

/// Size of a raw Ed25519 public key in bytes.
pub const ED25519_PUBLIC_KEY_LENGTH: usize = 32;

/// Size of a raw Ed25519 detached signature in bytes.
pub const ED25519_SIGNATURE_LENGTH: usize = 64;

/// A result produced by detached-signature verification.
pub type Result<T> = core::result::Result<T, SignatureError>;

/// Fixed-width raw Ed25519 public-key bytes.
//
// Public keys are not secret, but the redacted Debug implementation prevents
// product identity material from entering logs by accident.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ed25519PublicKey([u8; ED25519_PUBLIC_KEY_LENGTH]);

impl Ed25519PublicKey {
    /// Wraps an exactly 32-byte raw Ed25519 public-key encoding.
    ///
    /// Structural curve-point validation is performed by
    /// [`verify_ed25519_detached`], which maps every invalid encoding to the
    /// same opaque verification failure as an invalid signature.
    #[must_use]
    pub const fn new(bytes: [u8; ED25519_PUBLIC_KEY_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Copies a raw Ed25519 public key from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureError::InvalidPublicKeyLength`] unless `bytes`
    /// contains exactly 32 bytes.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self> {
        <[u8; ED25519_PUBLIC_KEY_LENGTH]>::try_from(bytes)
            .map(Self)
            .map_err(|_| SignatureError::InvalidPublicKeyLength)
    }

    /// Returns the fixed-width raw public-key encoding.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ED25519_PUBLIC_KEY_LENGTH] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Ed25519PublicKey {
    type Error = SignatureError;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Self::try_from_slice(bytes)
    }
}

impl fmt::Debug for Ed25519PublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Ed25519PublicKey([REDACTED])")
    }
}

/// Fixed-width raw Ed25519 detached-signature bytes.
//
// Signatures are not secret, but redaction avoids logging product artifact
// identity and keeps this boundary's diagnostics data-independent.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ed25519Signature([u8; ED25519_SIGNATURE_LENGTH]);

impl Ed25519Signature {
    /// Wraps an exactly 64-byte raw Ed25519 detached signature.
    #[must_use]
    pub const fn new(bytes: [u8; ED25519_SIGNATURE_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Copies a raw Ed25519 detached signature from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`SignatureError::InvalidSignatureLength`] unless `bytes`
    /// contains exactly 64 bytes.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self> {
        <[u8; ED25519_SIGNATURE_LENGTH]>::try_from(bytes)
            .map(Self)
            .map_err(|_| SignatureError::InvalidSignatureLength)
    }

    /// Returns the fixed-width raw detached-signature encoding.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ED25519_SIGNATURE_LENGTH] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Ed25519Signature {
    type Error = SignatureError;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Self::try_from_slice(bytes)
    }
}

impl fmt::Debug for Ed25519Signature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Ed25519Signature([REDACTED])")
    }
}

/// Failure returned by the strict detached-signature boundary.
///
/// Key decoding, weak-key rejection, scalar or point malleability, a wrong
/// message, and an invalid signature all collapse into
/// [`Self::VerificationFailed`]. This prevents callers from building an
/// accidental verification oracle from upstream error details.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureError {
    /// The supplied raw public-key slice is not exactly 32 bytes.
    InvalidPublicKeyLength,
    /// The supplied raw detached-signature slice is not exactly 64 bytes.
    InvalidSignatureLength,
    /// Strict verification rejected the key, message, or signature.
    VerificationFailed,
}

impl fmt::Display for SignatureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidPublicKeyLength => "invalid Ed25519 public-key length",
            Self::InvalidSignatureLength => "invalid Ed25519 signature length",
            Self::VerificationFailed => "Ed25519 signature verification failed",
        };
        formatter.write_str(message)
    }
}

impl core::error::Error for SignatureError {}

impl ForgeError for SignatureError {
    fn kind(&self) -> &'static str {
        match self {
            Self::InvalidPublicKeyLength => "InvalidPublicKeyLength",
            Self::InvalidSignatureLength => "InvalidSignatureLength",
            Self::VerificationFailed => "VerificationFailed",
        }
    }

    fn caption(&self) -> &'static str {
        "Detached signature verification failure"
    }

    fn is_retryable(&self) -> bool {
        false
    }
}

/// Strictly verifies an Ed25519 detached signature over the exact message
/// bytes supplied by the caller.
///
/// No hashing, canonicalization, parsing, or domain-prefix transformation is
/// performed by this boundary. A product format must define and supply its
/// exact signed byte sequence and must own trust-root selection and policy.
/// The strict verifier rejects non-canonical scalar and point encodings as well
/// as weak public keys.
///
/// # Errors
///
/// Returns [`SignatureError::VerificationFailed`] for every invalid key,
/// message, or signature. No upstream diagnostic detail is exposed.
pub fn verify_ed25519_detached(
    public_key: &Ed25519PublicKey,
    exact_message: &[u8],
    signature: &Ed25519Signature,
) -> Result<()> {
    let verifying_key = VerifyingKey::from_bytes(public_key.as_bytes())
        .map_err(|_| SignatureError::VerificationFailed)?;
    let parsed_signature = DalekSignature::from_bytes(signature.as_bytes());
    verifying_key
        .verify_strict(exact_message, &parsed_signature)
        .map_err(|_| SignatureError::VerificationFailed)
}
