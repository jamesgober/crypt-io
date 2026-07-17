//! Versioned authenticated formats for database and object storage.
//!
//! This opt-in module complements the crate's established general-purpose
//! cryptographic APIs. It does not replace [`crate::stream`] or the root
//! [`crate::Error`] and [`crate::Result`] contracts.
//!
//! [`crate::storage::RecordCodec`] seals bounded records.
//! [`crate::storage::EncryptedStreamCodec`] handles bounded in-memory streams and
//! constructs incremental readers and writers over `std::io`. Both formats
//! bind their versioned headers, caller-owned scope, context, and sequence into
//! AES-256-GCM authentication.
//!
//! Keys come from [`crate::storage::KeyProvider`]. The safe APIs generate salt and nonce
//! material internally and never accept caller-provided nonces. Rotation and
//! migration authenticate and transform bytes, but callers remain responsible
//! for crash-safe staging, synchronization, and atomic publication.

// Borrowed scopes and fixed-size format fields keep call sites explicit and
// avoid copying up to 48 bytes through hot codec paths. The parent crate's
// pedantic profile otherwise recommends pass-by-value solely from type size.
#![allow(clippy::trivially_copy_pass_by_ref)]

mod error;
mod kdf;
mod key;
mod record;
mod stream;

/// Maximum caller-context bytes compacted by a record or stream constructor.
///
/// Context is metadata, not payload. Bounding it limits attacker-controlled
/// SHA-256 work before any authenticated-format size check; larger values must
/// be reduced to a product-defined, domain-separated identifier by the host.
pub const MAX_STORAGE_CONTEXT_LEN: usize = 64 * 1024;

pub use error::{CryptError, Result};
pub use key::{
    KeyDescriptor, KeyGeneration, KeyId, KeyLease, KeyProvider, KeyProviderError, KeyScope,
    PurposeId, SecretKey32, SpaceId,
};
pub use record::{
    MAX_SEALED_RECORD_PLAINTEXT_LEN, RecordCodec, RecordContext, RecordReseal,
    SEALED_RECORD_HEADER_LEN, SEALED_RECORD_MAGIC, SealedRecord,
};
pub use stream::{
    AuthenticatedFrame, AuthenticatedPrefix, DEFAULT_STREAM_FRAME_PLAINTEXT_LEN,
    ENCRYPTED_STREAM_FRAME_HEADER_LEN, ENCRYPTED_STREAM_HEADER_LEN, ENCRYPTED_STREAM_MAGIC,
    EncryptedStream, EncryptedStreamCodec, EncryptedStreamReader, EncryptedStreamWriter,
    MAX_BUFFERED_STREAM_DATA_FRAMES, MAX_BUFFERED_STREAM_PLAINTEXT_LEN, MAX_STREAM_DATA_FRAMES,
    MAX_STREAM_FRAME_PLAINTEXT_LEN, PrefixRecoveryError, StreamCompletion, StreamConfig,
    StreamContext, StreamDestinationState, StreamError, StreamIoError, StreamIoOperation,
    StreamMetadata, StreamProgress, StreamRead, StreamReseal, StreamResealError, StreamResealPhase,
};
