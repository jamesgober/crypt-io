//! Opaque identifiers, zeroizing keys, and the external key-provider seam.

use core::fmt;

use error_forge::ForgeError;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::storage::CryptError;

/// Stable public identifier for a key, never the key material itself.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId([u8; 16]);

impl KeyId {
    /// Creates an opaque key identifier from its stable bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the stable identifier bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Monotonic generation within one key scope.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyGeneration(u32);

impl KeyGeneration {
    /// Creates a key generation.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the numeric generation.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Stable public key identifier paired with its generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyDescriptor {
    key_id: KeyId,
    generation: KeyGeneration,
}

impl KeyDescriptor {
    /// Creates a key descriptor.
    #[must_use]
    pub const fn new(key_id: KeyId, generation: KeyGeneration) -> Self {
        Self { key_id, generation }
    }

    /// Returns the stable key identifier.
    #[must_use]
    pub const fn key_id(self) -> KeyId {
        self.key_id
    }

    /// Returns the key generation.
    #[must_use]
    pub const fn generation(self) -> KeyGeneration {
        self.generation
    }
}

/// Stable opaque identifier for a key-derivation purpose.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PurposeId([u8; 16]);

impl PurposeId {
    /// Creates a purpose identifier from its stable bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the stable purpose bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Opaque physical storage-space identifier.
///
/// Callers should derive this value with a keyed hash over host, profile,
/// agent, and principal identifiers. Raw principal identities must never be
/// placed in this value.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpaceId([u8; 32]);

impl SpaceId {
    /// Creates an opaque space identifier from keyed, privacy-preserving bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the stable opaque bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SpaceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SpaceId([REDACTED])")
    }
}

/// Purpose and physical space that jointly separate derived keys.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyScope {
    space_id: SpaceId,
    purpose_id: PurposeId,
}

impl KeyScope {
    /// Creates a key scope.
    #[must_use]
    pub const fn new(space_id: SpaceId, purpose_id: PurposeId) -> Self {
        Self {
            space_id,
            purpose_id,
        }
    }

    /// Returns the physical space identifier.
    #[must_use]
    pub const fn space_id(&self) -> SpaceId {
        self.space_id
    }

    /// Returns the purpose identifier.
    #[must_use]
    pub const fn purpose_id(&self) -> PurposeId {
        self.purpose_id
    }
}

impl fmt::Debug for KeyScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyScope")
            .field("space_id", &self.space_id)
            .field("purpose_id", &self.purpose_id)
            .finish()
    }
}

/// Exactly 256 bits of secret master-key material.
///
/// The type deliberately implements neither `Clone` nor `Copy`. Its backing
/// bytes are zeroized on drop and its debug representation is always redacted.
/// Callers must supply uniformly random 256-bit master-key material generated
/// by a cryptographically secure key generator. Passwords, passphrases,
/// low-entropy values, and unhashed or directly hashed user input are not valid
/// keys for this constructor; use a separately audited password-based key
/// derivation system when human input is unavoidable.
///
/// Raw secret extraction is deliberately unavailable:
///
/// ```compile_fail
/// use crypt_io::storage::SecretKey32;
///
/// let key = SecretKey32::new([7_u8; 32]);
/// let copied_secret = key.with_secret_bytes(|bytes| *bytes);
/// assert_eq!(copied_secret, [7_u8; 32]);
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey32([u8; 32]);

impl SecretKey32 {
    /// Wraps 256 bits of key material for scoped use.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Provides temporary read-only access without returning the backing array.
    pub(crate) fn with_secret_bytes<T>(&self, operation: impl FnOnce(&[u8; 32]) -> T) -> T {
        operation(&self.0)
    }
}

impl fmt::Debug for SecretKey32 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretKey32([REDACTED])")
    }
}

/// A short-lived key descriptor and its zeroizing secret material.
pub struct KeyLease {
    key_id: KeyId,
    generation: KeyGeneration,
    secret: SecretKey32,
}

impl KeyLease {
    /// Creates a key lease returned by an external provider.
    #[must_use]
    pub const fn new(key_id: KeyId, generation: KeyGeneration, secret: SecretKey32) -> Self {
        Self {
            key_id,
            generation,
            secret,
        }
    }

    /// Returns the stable key identifier.
    #[must_use]
    pub const fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// Returns the key generation.
    #[must_use]
    pub const fn generation(&self) -> KeyGeneration {
        self.generation
    }

    /// Returns the public key descriptor without exposing secret material.
    #[must_use]
    pub const fn descriptor(&self) -> KeyDescriptor {
        KeyDescriptor::new(self.key_id, self.generation)
    }

    pub(crate) fn with_secret_bytes<T>(&self, operation: impl FnOnce(&[u8; 32]) -> T) -> T {
        self.secret.with_secret_bytes(operation)
    }
}

impl fmt::Debug for KeyLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyLease")
            .field("key_id", &self.key_id)
            .field("generation", &self.generation)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// Sanitized failure returned by an external key provider.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyProviderError {
    /// The requested key is not present or no longer available.
    Unavailable,
    /// Provider access was denied by the operating system or policy.
    AccessDenied,
    /// The provider failed for an implementation-specific reason.
    Failure {
        /// Whether retrying the provider operation may succeed.
        retryable: bool,
    },
}

impl fmt::Display for KeyProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Unavailable => "key is unavailable",
            Self::AccessDenied => "key-provider access denied",
            Self::Failure { .. } => "key provider failed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for KeyProviderError {}

impl ForgeError for KeyProviderError {
    fn kind(&self) -> &'static str {
        match self {
            Self::Unavailable => "Unavailable",
            Self::AccessDenied => "AccessDenied",
            Self::Failure { .. } => "Failure",
        }
    }

    fn caption(&self) -> &'static str {
        "Key provider failure"
    }

    fn is_retryable(&self) -> bool {
        matches!(self, Self::Failure { retryable: true })
    }
}

pub(crate) const fn map_key_provider_error(error: KeyProviderError) -> CryptError {
    match error {
        KeyProviderError::Unavailable => CryptError::KeyUnavailable,
        KeyProviderError::AccessDenied => CryptError::KeyAccessDenied,
        KeyProviderError::Failure { retryable } => CryptError::KeyProviderFailure { retryable },
    }
}

/// External boundary for active and historical encryption keys.
///
/// `crypt-io` defines this interface but never stores keys. Product code must
/// implement it with an operating-system credential store or an explicit,
/// protected headless key source.
///
/// For the entire lifetime of any referencing ciphertext, each
/// (`KeyScope`, [`KeyId`], [`KeyGeneration`]) tuple must map immutably to the
/// exact same 32-byte master secret. A provider must never reuse a descriptor
/// for different key material. Active generations must increase monotonically
/// within a scope, and every same-scope replacement must use independently
/// generated master material distinct from the source and every retired
/// generation. Historical mappings must remain available until every reference
/// has been durably and verifiably migrated. Ordinary sealing cannot detect a
/// provider that silently changes an existing descriptor; doing so can make
/// earlier objects permanently unrecoverable.
pub trait KeyProvider: Send + Sync {
    /// Returns the active key used for new objects in `scope`.
    ///
    /// Successive replacements must use a strictly newer generation. Returning
    /// an existing descriptor with different secret bytes violates the provider
    /// contract and is not detectable by an ordinary seal operation. A newer
    /// same-scope descriptor must use fresh, distinct master material; rotation
    /// rejects replacement material equal to the authenticated source secret.
    ///
    /// # Errors
    ///
    /// Returns a sanitized provider error without secret material.
    fn active(&self, scope: &KeyScope) -> Result<KeyLease, KeyProviderError>;

    /// Returns the exact historical key requested for an object in `scope`.
    ///
    /// The provider must use the caller-supplied scope as an authorization
    /// boundary. The encoded object header is not an authorization source. It
    /// must return the exact original secret for the requested descriptor while
    /// any ciphertext may reference it. Retirement is permitted only after
    /// durable verified migration and elimination of every reference.
    ///
    /// # Errors
    ///
    /// Returns a sanitized provider error without secret material.
    fn by_id(
        &self,
        scope: &KeyScope,
        key_id: KeyId,
        generation: KeyGeneration,
    ) -> Result<KeyLease, KeyProviderError>;
}

#[cfg(test)]
mod tests {
    use error_forge::ForgeError;

    use super::{KeyProviderError, map_key_provider_error};
    use crate::storage::CryptError;

    #[test]
    fn test_key_provider_error_mapping_preserves_action_and_retryability() {
        let cases = [
            (
                KeyProviderError::Unavailable,
                CryptError::KeyUnavailable,
                "KeyUnavailable",
                false,
            ),
            (
                KeyProviderError::AccessDenied,
                CryptError::KeyAccessDenied,
                "KeyAccessDenied",
                false,
            ),
            (
                KeyProviderError::Failure { retryable: false },
                CryptError::KeyProviderFailure { retryable: false },
                "KeyProviderFailure",
                false,
            ),
            (
                KeyProviderError::Failure { retryable: true },
                CryptError::KeyProviderFailure { retryable: true },
                "KeyProviderFailure",
                true,
            ),
        ];

        for (provider_error, expected, kind, retryable) in cases {
            let mapped = map_key_provider_error(provider_error);
            assert_eq!(mapped, expected);
            assert_eq!(mapped.kind(), kind);
            assert_eq!(mapped.is_retryable(), retryable);
        }
    }
}
