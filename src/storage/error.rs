//! Typed, fail-closed errors for authenticated storage operations.

use core::fmt;

use error_forge::ForgeError;

/// A result produced by `crypt-io`.
pub type Result<T> = core::result::Result<T, CryptError>;

/// Failure returned by an authenticated storage format or key boundary.
///
/// Authentication failures deliberately do not distinguish a wrong secret from
/// ciphertext or associated-data tampering. That distinction is not available
/// from AEAD and pretending otherwise would create a misleading oracle.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptError {
    /// A caller supplied an invalid value.
    InvalidInput,
    /// A configured or hard format limit was exceeded.
    LimitExceeded,
    /// The encoded format version is not supported.
    UnsupportedVersion,
    /// The encoded cryptographic suite is not supported.
    UnsupportedSuite,
    /// The input violates the structural rules of its claimed format.
    CorruptStructure,
    /// The input ends before the complete authenticated object.
    Truncated,
    /// Bytes follow the exact end of the authenticated object.
    TrailingData,
    /// AEAD authentication failed; no plaintext is returned.
    AuthenticationFailed,
    /// A provider returned a key descriptor different from the requested one.
    WrongKey,
    /// A same-scope rotation would reuse or decrease the key generation.
    KeyDowngrade,
    /// A same-scope replacement descriptor reused the source master secret.
    KeyMaterialReuse,
    /// The requested key is not available from the provider.
    KeyUnavailable,
    /// The key provider denied access to the requested key scope.
    KeyAccessDenied,
    /// The key provider failed without exposing provider-specific secrets.
    KeyProviderFailure {
        /// Whether retrying the provider operation may succeed.
        retryable: bool,
    },
    /// The operating-system entropy source failed.
    EntropyUnavailable,
    /// Memory could not be reserved for a bounded authenticated buffer.
    ///
    /// The operation returns no plaintext. Callers may retry after reducing
    /// memory pressure or use an incremental API for large payloads.
    AllocationFailed,
    /// The expected purpose, space, or caller context does not match.
    ContextMismatch,
    /// The expected logical or frame sequence does not match.
    SequenceMismatch,
    /// A stream ended without its mandatory authenticated final frame.
    MissingFinalFrame,
    /// A stream frame does not link to the preceding authentication tag.
    FrameChainMismatch,
    /// A nonce sequence cannot advance without reuse.
    NonceExhausted,
}

impl fmt::Display for CryptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidInput => "invalid cryptographic input",
            Self::LimitExceeded => "authenticated format limit exceeded",
            Self::UnsupportedVersion => "unsupported authenticated format version",
            Self::UnsupportedSuite => "unsupported cryptographic suite",
            Self::CorruptStructure => "corrupt authenticated format structure",
            Self::Truncated => "truncated authenticated object",
            Self::TrailingData => "trailing data after authenticated object",
            Self::AuthenticationFailed => "authentication failed",
            Self::WrongKey => "key provider returned the wrong key descriptor",
            Self::KeyDowngrade => "key rotation would downgrade the generation",
            Self::KeyMaterialReuse => "key rotation would reuse existing key material",
            Self::KeyUnavailable => "requested key is unavailable",
            Self::KeyAccessDenied => "key-provider access denied",
            Self::KeyProviderFailure { .. } => "key provider failed",
            Self::EntropyUnavailable => "operating-system entropy is unavailable",
            Self::AllocationFailed => "memory allocation failed",
            Self::ContextMismatch => "authenticated context does not match",
            Self::SequenceMismatch => "authenticated sequence does not match",
            Self::MissingFinalFrame => "encrypted stream is missing its final frame",
            Self::FrameChainMismatch => "encrypted stream frame chain does not match",
            Self::NonceExhausted => "nonce sequence exhausted",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for CryptError {}

impl ForgeError for CryptError {
    fn kind(&self) -> &'static str {
        match self {
            Self::InvalidInput => "InvalidInput",
            Self::LimitExceeded => "LimitExceeded",
            Self::UnsupportedVersion => "UnsupportedVersion",
            Self::UnsupportedSuite => "UnsupportedSuite",
            Self::CorruptStructure => "CorruptStructure",
            Self::Truncated => "Truncated",
            Self::TrailingData => "TrailingData",
            Self::AuthenticationFailed => "AuthenticationFailed",
            Self::WrongKey => "WrongKey",
            Self::KeyDowngrade => "KeyDowngrade",
            Self::KeyMaterialReuse => "KeyMaterialReuse",
            Self::KeyUnavailable => "KeyUnavailable",
            Self::KeyAccessDenied => "KeyAccessDenied",
            Self::KeyProviderFailure { .. } => "KeyProviderFailure",
            Self::EntropyUnavailable => "EntropyUnavailable",
            Self::AllocationFailed => "AllocationFailed",
            Self::ContextMismatch => "ContextMismatch",
            Self::SequenceMismatch => "SequenceMismatch",
            Self::MissingFinalFrame => "MissingFinalFrame",
            Self::FrameChainMismatch => "FrameChainMismatch",
            Self::NonceExhausted => "NonceExhausted",
        }
    }

    fn caption(&self) -> &'static str {
        "Cryptographic storage failure"
    }

    fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::KeyProviderFailure { retryable: true }
                | Self::EntropyUnavailable
                | Self::AllocationFailed
        )
    }
}

#[cfg(test)]
mod tests {
    use error_forge::ForgeError;

    use super::CryptError;

    #[test]
    fn test_allocation_failed_error_reports_retryable_typed_metadata() {
        let error = CryptError::AllocationFailed;

        assert_eq!(error.kind(), "AllocationFailed");
        assert!(error.is_retryable());
        assert_eq!(error.to_string(), "memory allocation failed");
    }

    #[test]
    fn test_key_material_reuse_error_is_sanitized_and_not_retryable() {
        let error = CryptError::KeyMaterialReuse;

        assert_eq!(error.kind(), "KeyMaterialReuse");
        assert!(!error.is_retryable());
        assert_eq!(
            error.to_string(),
            "key rotation would reuse existing key material"
        );
    }
}
