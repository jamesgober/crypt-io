//! Error types for `crypt-io`.
//!
//! All fallible operations in the crate return [`Result<T>`], an alias for
//! `core::result::Result<T, Error>`. [`Error`] is `#[non_exhaustive]` — match
//! sites must include a wildcard arm so future minor releases can add
//! variants without breaking downstream code.
//!
//! Error messages are redaction-clean: no key bytes, no plaintext, no nonce
//! values, no ciphertext are ever included in a rendered error. Errors are
//! safe to log, safe to ship to monitoring, safe to include in audit records.

use alloc::string::String;
use core::fmt;

/// The error type for all `crypt-io` operations.
///
/// Authentication failures are deliberately collapsed into a single variant —
/// distinguishing "wrong key" from "tampered ciphertext" would leak which
/// failure mode an attacker is closer to, which is a side-channel.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The supplied key was not the correct size for the selected algorithm
    /// (ChaCha20-Poly1305 and AES-256-GCM both require exactly 32 bytes).
    InvalidKey {
        /// The expected key length in bytes.
        expected: usize,
        /// The length actually supplied.
        actual: usize,
    },

    /// The ciphertext was malformed (too short to contain a nonce + tag, or
    /// the embedded length fields were inconsistent).
    InvalidCiphertext(String),

    /// Authentication of the ciphertext failed. This is the single
    /// observable outcome of *any* corruption: wrong key, tampered bytes,
    /// truncated message, or wrong associated data. The variant is opaque
    /// by design.
    AuthenticationFailed,

    /// The requested algorithm is not enabled at compile time. Re-build
    /// with the appropriate Cargo feature.
    AlgorithmNotEnabled(&'static str),

    /// The OS random source failed to produce a nonce. This is rare and
    /// almost always indicates a misconfigured sandbox or exhausted
    /// `getrandom` entropy on a freshly-booted VM.
    RandomFailure(&'static str),

    /// A MAC operation could not be initialised or computed. In practice
    /// this is unreachable for the algorithms shipped (HMAC accepts any
    /// key length; BLAKE3 keyed takes a fixed-size key), but the variant
    /// exists because the upstream `Mac` trait surface is fallible by
    /// signature.
    Mac(&'static str),
}

/// Type alias for `core::result::Result<T, Error>`.
pub type Result<T> = core::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKey { expected, actual } => {
                write!(
                    f,
                    "invalid key length: expected {expected} bytes, got {actual}"
                )
            }
            Self::InvalidCiphertext(why) => write!(f, "invalid ciphertext: {why}"),
            Self::AuthenticationFailed => f.write_str("authentication failed"),
            Self::AlgorithmNotEnabled(name) => {
                write!(f, "algorithm not enabled at compile time: {name}")
            }
            Self::RandomFailure(why) => write!(f, "OS random source failed: {why}"),
            Self::Mac(why) => write!(f, "MAC operation failed: {why}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::string::ToString;

    #[test]
    fn invalid_key_message_includes_lengths() {
        let e = Error::InvalidKey {
            expected: 32,
            actual: 16,
        };
        let rendered = format!("{e}");
        assert!(rendered.contains("32"));
        assert!(rendered.contains("16"));
    }

    #[test]
    fn authentication_failure_is_opaque() {
        let rendered = Error::AuthenticationFailed.to_string();
        assert_eq!(rendered, "authentication failed");
    }

    #[test]
    fn debug_does_not_panic_for_any_variant() {
        for e in [
            Error::InvalidKey {
                expected: 32,
                actual: 0,
            },
            Error::InvalidCiphertext("x".to_string()),
            Error::AuthenticationFailed,
            Error::AlgorithmNotEnabled("none"),
            Error::RandomFailure("ENOSYS"),
            Error::Mac("init"),
        ] {
            let _ = format!("{e:?}");
        }
    }
}
