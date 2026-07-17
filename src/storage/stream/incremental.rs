//! Bounded, fail-closed incremental I/O for encrypted-stream v1.

use core::fmt;
use std::io::{self, Read, Write};

use aes_gcm::{
    Aes256Gcm,
    aead::{AeadInOut, KeyInit, Nonce, Tag},
};
use error_forge::ForgeError;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::storage::{
    CryptError, KeyDescriptor, KeyLease, KeyProvider, KeyScope, Result, kdf::derive_storage_key,
    key::map_key_provider_error,
};

use super::{
    ENCRYPTED_STREAM_FRAME_HEADER_LEN, ENCRYPTED_STREAM_HEADER_LEN, EncryptedStreamCodec,
    FrameHeader, HKDF_INFO_DOMAIN, MAX_STREAM_DATA_FRAMES, StreamConfig, StreamContext,
    StreamHeader, TAG_LEN, copy_array, encode_context_binding, encode_data_frame_header,
    encode_final_frame_header, encode_stream_header, frame_aad, frame_nonce, fresh_stream_material,
    parse_frame_header, parse_stream_header, validate_expected_scope, verify_context_binding,
};

/// Failure returned by incremental encrypted-stream I/O.
///
/// I/O failures permanently fault the affected reader or writer. Retrying the
/// same handle is intentionally unsupported because the underlying resource
/// may have consumed or emitted an unknown partial frame.
#[non_exhaustive]
#[derive(Debug)]
pub enum StreamError {
    /// A cryptographic, provider, structure, context, or bounds check failed.
    Cryptographic(CryptError),
    /// An I/O operation failed with its original source error preserved.
    Io(StreamIoError),
    /// The handle was previously faulted and cannot be reused.
    Faulted {
        /// Last fully authenticated or fully emitted progress.
        progress: StreamProgress,
    },
    /// The reader has already returned its authenticated completion.
    Finished {
        /// Previously authenticated completion.
        completion: StreamCompletion,
    },
}

impl fmt::Display for StreamError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cryptographic(error) => error.fmt(formatter),
            Self::Io(error) => error.fmt(formatter),
            Self::Faulted { .. } => formatter.write_str("encrypted stream handle is faulted"),
            Self::Finished { .. } => formatter.write_str("encrypted stream is already complete"),
        }
    }
}

impl std::error::Error for StreamError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Cryptographic(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Faulted { .. } | Self::Finished { .. } => None,
        }
    }
}

impl ForgeError for StreamError {
    fn kind(&self) -> &'static str {
        match self {
            Self::Cryptographic(error) => error.kind(),
            Self::Io(_) => "StreamIo",
            Self::Faulted { .. } => "StreamFaulted",
            Self::Finished { .. } => "StreamFinished",
        }
    }

    fn caption(&self) -> &'static str {
        "Encrypted stream failure"
    }

    fn is_retryable(&self) -> bool {
        false
    }
}

/// Source-preserving incremental stream I/O failure.
pub struct StreamIoError {
    operation: StreamIoOperation,
    progress: StreamProgress,
    source: io::Error,
}

impl fmt::Debug for StreamIoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StreamIoError")
            .field("operation", &self.operation)
            .field("progress", &self.progress)
            .field("source_kind", &self.source.kind())
            .field("source", &"[REDACTED]")
            .finish()
    }
}

impl StreamIoError {
    /// Returns the operation that failed.
    #[must_use]
    pub const fn operation(&self) -> StreamIoOperation {
        self.operation
    }

    /// Returns the last unambiguous stream progress before the failure.
    #[must_use]
    pub const fn progress(&self) -> StreamProgress {
        self.progress
    }

    /// Borrows the original I/O error.
    #[must_use]
    pub const fn source_error(&self) -> &io::Error {
        &self.source
    }

    /// Consumes the wrapper and returns the original I/O error.
    #[must_use]
    pub fn into_source(self) -> io::Error {
        self.source
    }
}

impl fmt::Display for StreamIoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "encrypted stream {:?} failed", self.operation)
    }
}

impl std::error::Error for StreamIoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl ForgeError for StreamIoError {
    fn kind(&self) -> &'static str {
        "StreamIo"
    }

    fn caption(&self) -> &'static str {
        "Encrypted stream I/O failure"
    }

    fn is_retryable(&self) -> bool {
        false
    }
}

/// Incremental I/O operation associated with a [`StreamIoError`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamIoOperation {
    /// Reading the fixed stream header.
    ReadHeader,
    /// Reading a frame header.
    ReadFrameHeader,
    /// Reading frame ciphertext and its authentication tag.
    ReadFrameBody,
    /// Confirming that no bytes follow the authenticated final frame.
    VerifyEnd,
    /// Writing the fixed stream header.
    WriteHeader,
    /// Writing a complete encrypted data or final frame.
    WriteFrame,
    /// Flushing the completed encoded stream.
    Flush,
}

/// Last unambiguous progress for an incremental reader or writer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamProgress {
    data_frames: u64,
    plaintext_bytes: u64,
    safe_encoded_boundary: u64,
}

impl StreamProgress {
    const EMPTY: Self = Self {
        data_frames: 0,
        plaintext_bytes: 0,
        safe_encoded_boundary: 0,
    };

    /// Returns the number of complete data frames.
    #[must_use]
    pub const fn data_frames(self) -> u64 {
        self.data_frames
    }

    /// Returns the number of plaintext bytes in complete data frames.
    #[must_use]
    pub const fn plaintext_bytes(self) -> u64 {
        self.plaintext_bytes
    }

    /// Returns the absolute end of the last safe encoded boundary.
    ///
    /// Bytes may exist after this boundary following a fault. The boundary is
    /// evidence for discard or truncation, never permission to resume a stream
    /// or reuse a frame nonce.
    #[must_use]
    pub const fn safe_encoded_boundary(self) -> u64 {
        self.safe_encoded_boundary
    }
}

/// Public, non-secret metadata authenticated by the first returned event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamMetadata {
    key: KeyDescriptor,
    max_frame_plaintext_len: u32,
}

impl StreamMetadata {
    /// Returns the key identifier and generation encoded by the stream.
    #[must_use]
    pub const fn key(self) -> KeyDescriptor {
        self.key
    }

    /// Returns the authenticated maximum plaintext length per frame.
    #[must_use]
    pub const fn max_frame_plaintext_len(self) -> u32 {
        self.max_frame_plaintext_len
    }
}

/// Exact totals authenticated by a mandatory final frame and exact EOF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamCompletion {
    metadata: StreamMetadata,
    data_frames: u64,
    plaintext_bytes: u64,
    encoded_bytes: u64,
}

impl StreamCompletion {
    /// Returns authenticated stream metadata.
    #[must_use]
    pub const fn metadata(self) -> StreamMetadata {
        self.metadata
    }

    /// Returns the authenticated number of data frames.
    #[must_use]
    pub const fn data_frames(self) -> u64 {
        self.data_frames
    }

    /// Returns the authenticated total plaintext length.
    #[must_use]
    pub const fn plaintext_bytes(self) -> u64 {
        self.plaintext_bytes
    }

    /// Returns the exact authenticated encoded length.
    #[must_use]
    pub const fn encoded_bytes(self) -> u64 {
        self.encoded_bytes
    }
}

/// Successful authenticated stream rotation or scope migration.
///
/// A missing destination completion means the source was already current and
/// the destination remained untouched. A present destination completion is the
/// proof required before a caller may publish its staged bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamReseal {
    source: StreamCompletion,
    destination: Option<StreamCompletion>,
    destination_key: KeyDescriptor,
}

impl StreamReseal {
    /// Returns the fully authenticated source completion.
    #[must_use]
    pub const fn source_completion(self) -> StreamCompletion {
        self.source
    }

    /// Returns the completed destination, or `None` for an authenticated no-op.
    #[must_use]
    pub const fn destination_completion(self) -> Option<StreamCompletion> {
        self.destination
    }

    /// Returns the authenticated source key descriptor.
    #[must_use]
    pub const fn source_key(self) -> KeyDescriptor {
        self.source.metadata.key
    }

    /// Returns the verified destination key descriptor.
    #[must_use]
    pub const fn destination_key(self) -> KeyDescriptor {
        self.destination_key
    }

    /// Reports whether a new staged encrypted stream was produced.
    #[must_use]
    pub const fn was_resealed(self) -> bool {
        self.destination.is_some()
    }
}

/// Stage in which authenticated stream resealing failed.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamResealPhase {
    /// Source staging, provider lookup, or authentication failed.
    Source,
    /// Destination key resolution, encoding, write, or flush failed.
    Destination,
    /// Rotation policy rejected the authenticated source and destination key.
    Policy,
}

/// Publication state of a staged destination after a reseal attempt.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamDestinationState {
    /// No destination bytes were written.
    Untouched,
    /// Bytes may exist but lack a publishable completion proof.
    DiscardOnly {
        /// Last unambiguous destination progress before failure.
        progress: StreamProgress,
    },
}

/// Fail-closed stream rotation or migration error.
///
/// A `DiscardOnly` destination never carries an authenticated completion token
/// and must not be published, resumed, or finalized by the caller.
pub struct StreamResealError {
    phase: StreamResealPhase,
    destination: StreamDestinationState,
    cause: StreamError,
}

impl StreamResealError {
    const fn untouched(phase: StreamResealPhase, cause: StreamError) -> Self {
        Self {
            phase,
            destination: StreamDestinationState::Untouched,
            cause,
        }
    }

    const fn discard_only(
        phase: StreamResealPhase,
        progress: StreamProgress,
        cause: StreamError,
    ) -> Self {
        Self {
            phase,
            destination: StreamDestinationState::DiscardOnly { progress },
            cause,
        }
    }

    /// Returns the stage that failed.
    #[must_use]
    pub const fn phase(&self) -> StreamResealPhase {
        self.phase
    }

    /// Returns whether the staged destination is untouched or discard-only.
    #[must_use]
    pub const fn destination_state(&self) -> StreamDestinationState {
        self.destination
    }

    /// Borrows the typed underlying stream failure.
    #[must_use]
    pub const fn cause(&self) -> &StreamError {
        &self.cause
    }

    /// Consumes this wrapper and returns the typed underlying stream failure.
    #[must_use]
    pub fn into_cause(self) -> StreamError {
        self.cause
    }
}

impl fmt::Debug for StreamResealError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StreamResealError")
            .field("phase", &self.phase)
            .field("destination", &self.destination)
            .field("cause", &self.cause)
            .finish()
    }
}

impl fmt::Display for StreamResealError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "encrypted stream {:?} phase failed", self.phase)
    }
}

impl std::error::Error for StreamResealError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

impl ForgeError for StreamResealError {
    fn kind(&self) -> &'static str {
        "StreamReseal"
    }

    fn caption(&self) -> &'static str {
        "Authenticated stream reseal failure"
    }

    fn is_retryable(&self) -> bool {
        false
    }
}

/// Explicitly recovered authenticated prefix of an incomplete stream.
///
/// A prefix is never a complete stream and carries no nonce, tag, salt, or
/// resume capability. Its plaintext must be re-encrypted into a new stream
/// with fresh entropy rather than finalized in place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedPrefix {
    metadata: StreamMetadata,
    data_frames: u64,
    plaintext_bytes: u64,
    safe_encoded_boundary: u64,
}

impl AuthenticatedPrefix {
    /// Returns authenticated stream metadata.
    #[must_use]
    pub const fn metadata(self) -> StreamMetadata {
        self.metadata
    }

    /// Returns the number of authenticated data frames.
    #[must_use]
    pub const fn data_frames(self) -> u64 {
        self.data_frames
    }

    /// Returns the number of authenticated plaintext bytes.
    #[must_use]
    pub const fn plaintext_bytes(self) -> u64 {
        self.plaintext_bytes
    }

    /// Returns the end of the last authenticated data frame.
    #[must_use]
    pub const fn safe_encoded_boundary(self) -> u64 {
        self.safe_encoded_boundary
    }
}

/// Reason authenticated-prefix recovery is unavailable.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefixRecoveryError {
    /// The reader has not encountered an incomplete physical EOF.
    NotFaulted,
    /// The stream already completed with an authenticated final frame.
    AlreadyComplete,
    /// No data frame was authenticated before physical EOF.
    NoAuthenticatedDataFrames,
    /// The failure was corruption, authentication, context, or non-EOF I/O.
    FailureNotRecoverable,
}

impl fmt::Display for PrefixRecoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::NotFaulted => "encrypted stream has not failed at physical EOF",
            Self::AlreadyComplete => "encrypted stream is already complete",
            Self::NoAuthenticatedDataFrames => "encrypted stream has no authenticated data prefix",
            Self::FailureNotRecoverable => "encrypted stream failure is not prefix-recoverable",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for PrefixRecoveryError {}

impl ForgeError for PrefixRecoveryError {
    fn kind(&self) -> &'static str {
        match self {
            Self::NotFaulted => "NotFaulted",
            Self::AlreadyComplete => "AlreadyComplete",
            Self::NoAuthenticatedDataFrames => "NoAuthenticatedDataFrames",
            Self::FailureNotRecoverable => "FailureNotRecoverable",
        }
    }

    fn caption(&self) -> &'static str {
        "Authenticated prefix recovery failure"
    }

    fn is_retryable(&self) -> bool {
        false
    }
}

/// One authenticated data frame borrowed from an incremental reader.
///
/// The plaintext is zeroized before the reader advances to another frame or
/// when the reader is dropped.
pub struct AuthenticatedFrame<'a> {
    sequence: u64,
    plaintext: &'a [u8],
    prefix: AuthenticatedPrefix,
}

impl AuthenticatedFrame<'_> {
    /// Returns the zero-based authenticated frame sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Borrows this frame's authenticated plaintext.
    #[must_use]
    pub const fn plaintext(&self) -> &[u8] {
        self.plaintext
    }

    /// Returns authenticated prefix totals through this frame.
    #[must_use]
    pub const fn prefix(&self) -> AuthenticatedPrefix {
        self.prefix
    }
}

impl fmt::Debug for AuthenticatedFrame<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedFrame")
            .field("sequence", &self.sequence)
            .field("plaintext_len", &self.plaintext.len())
            .field("plaintext", &"[REDACTED]")
            .field("prefix", &self.prefix)
            .finish()
    }
}

/// Next authenticated event from an incremental encrypted-stream reader.
///
/// Physical EOF is never represented by this enum. Only [`Self::Complete`]
/// proves that the mandatory final frame and exact end of input authenticated.
#[must_use]
#[derive(Debug)]
pub enum StreamRead<'a> {
    /// One authenticated but provisional data frame.
    Data(AuthenticatedFrame<'a>),
    /// Authenticated final totals and exact end of input.
    Complete(StreamCompletion),
}

#[derive(Debug, Clone, Copy)]
enum WriterState {
    Active,
    Faulted,
    Finished(StreamCompletion),
}

/// Explicit incremental encrypted-stream v1 writer.
///
/// The writer never finalizes on drop. Call [`Self::finish`] and require its
/// successful result before publishing the sink. `finish` flushes Rust's I/O
/// layer but does not claim filesystem durability; durable-storage callers
/// must synchronize their resource after the writer releases its borrow.
pub struct EncryptedStreamWriter<'io, W> {
    sink: &'io mut W,
    metadata: StreamMetadata,
    cipher: Option<Aes256Gcm>,
    stream_header: [u8; ENCRYPTED_STREAM_HEADER_LEN],
    nonce_prefix: [u8; 4],
    previous_tag: [u8; TAG_LEN],
    progress: StreamProgress,
    header_written: bool,
    frame_buffer: Zeroizing<Vec<u8>>,
    state: WriterState,
}

impl<P> EncryptedStreamCodec<P>
where
    P: KeyProvider,
{
    /// Prepares an incremental writer with a fresh stream key derivation.
    ///
    /// Construction resolves the active key and OS entropy but performs no
    /// sink I/O. A caller-controlled salt or nonce is never accepted.
    ///
    /// # Errors
    ///
    /// Returns a typed provider, entropy, derivation, or cipher error. The sink
    /// remains untouched when construction fails.
    pub fn writer<'io, W>(
        &self,
        sink: &'io mut W,
        scope: &KeyScope,
        context: &StreamContext,
    ) -> Result<EncryptedStreamWriter<'io, W>>
    where
        W: Write,
    {
        let lease = self
            .provider
            .active(scope)
            .map_err(map_key_provider_error)?;
        self.writer_with_lease(sink, scope, context, lease)
    }

    // Ownership guarantees the short-lived provider lease and its secret are
    // dropped before the initialized writer escapes this function.
    #[allow(clippy::needless_pass_by_value)]
    fn writer_with_lease<'io, W>(
        &self,
        sink: &'io mut W,
        scope: &KeyScope,
        context: &StreamContext,
        lease: KeyLease,
    ) -> Result<EncryptedStreamWriter<'io, W>>
    where
        W: Write,
    {
        let metadata = StreamMetadata {
            key: lease.descriptor(),
            max_frame_plaintext_len: self.config.max_frame_plaintext_len(),
        };
        let (stream_salt, nonce_prefix) = fresh_stream_material()?;
        let derived_key = derive_storage_key(
            &lease,
            scope,
            &stream_salt,
            super::SUITE_AES_256_GCM_HKDF_SHA256,
            HKDF_INFO_DOMAIN,
        )?;
        let context_binding = encode_context_binding(&lease, scope, &stream_salt, context)?;
        let stream_header = encode_stream_header(
            &lease,
            scope,
            &stream_salt,
            &nonce_prefix,
            self.config,
            &context_binding,
        );
        let cipher = Aes256Gcm::new_from_slice(derived_key.as_ref())
            .map_err(|_error| CryptError::InvalidInput)?;
        Ok(EncryptedStreamWriter {
            sink,
            metadata,
            cipher: Some(cipher),
            stream_header,
            nonce_prefix,
            previous_tag: [0_u8; TAG_LEN],
            progress: StreamProgress::EMPTY,
            header_written: false,
            frame_buffer: Zeroizing::new(Vec::new()),
            state: WriterState::Active,
        })
    }

    /// Creates a zero-I/O incremental reader over an expected scope and context.
    ///
    /// [`EncryptedStreamReader::begin`] stages one complete frame before any
    /// historical-key lookup. Header-only and mid-frame inputs therefore do not
    /// cause a provider query.
    #[must_use]
    pub fn reader<'io, 'context, R>(
        &'context self,
        source: &'io mut R,
        expected_scope: KeyScope,
        expected_context: &'context StreamContext,
    ) -> EncryptedStreamReader<'io, 'context, R, P>
    where
        R: Read,
    {
        EncryptedStreamReader {
            source,
            provider: &self.provider,
            config: self.config,
            expected_scope,
            expected_context,
            stream_header: [0_u8; ENCRYPTED_STREAM_HEADER_LEN],
            header: None,
            metadata: None,
            cipher: None,
            previous_tag: [0_u8; TAG_LEN],
            progress: StreamProgress::EMPTY,
            encoded_consumed: 0,
            frame_buffer: Zeroizing::new(Vec::new()),
            pending: PendingRead::None,
            state: ReaderState::Created,
        }
    }

    /// Authenticates a source stream and reseals it under the scope's active key.
    ///
    /// The destination must be a private staging resource. Its final frame is
    /// not written until the source final frame, totals, and exact EOF all
    /// authenticate. On error, inspect [`StreamResealError::destination_state`]
    /// and discard any destination marked [`StreamDestinationState::DiscardOnly`].
    /// This operation never overwrites or durably publishes either resource.
    ///
    /// # Errors
    ///
    /// Returns a phase-tagged source, destination, or rotation-policy failure.
    /// A reused descriptor with different secret material returns
    /// [`CryptError::WrongKey`]; a newer descriptor backed by the source secret
    /// returns [`CryptError::KeyMaterialReuse`]; a non-increasing replacement
    /// generation returns [`CryptError::KeyDowngrade`].
    pub fn rotate_to_active<R, W>(
        &self,
        scope: &KeyScope,
        context: &StreamContext,
        source: &mut R,
        destination: &mut W,
    ) -> core::result::Result<StreamReseal, StreamResealError>
    where
        R: Read,
        W: Write,
    {
        self.reseal(scope, context, scope, context, source, destination)
    }

    /// Authenticates a source stream and reseals it under an explicit scope and context.
    ///
    /// Plaintext is processed one authenticated frame at a time. Callers must
    /// stage the destination privately and publish it only after receiving a
    /// successful [`StreamReseal`] with a destination completion.
    ///
    /// # Errors
    ///
    /// Returns a phase-tagged source, destination, or same-scope rotation-policy
    /// failure. Cross-scope key generations and master-secret equality are not
    /// compared; any cross-scope key sharing is caller-owned policy.
    #[allow(clippy::too_many_arguments)]
    pub fn migrate<R, W>(
        &self,
        source_scope: &KeyScope,
        source_context: &StreamContext,
        destination_scope: &KeyScope,
        destination_context: &StreamContext,
        source: &mut R,
        destination: &mut W,
    ) -> core::result::Result<StreamReseal, StreamResealError>
    where
        R: Read,
        W: Write,
    {
        self.reseal(
            source_scope,
            source_context,
            destination_scope,
            destination_context,
            source,
            destination,
        )
    }

    // Keeping the complete source-authenticate/destination-publish state
    // machine together makes every discard-only exit auditable in one place.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn reseal<R, W>(
        &self,
        source_scope: &KeyScope,
        source_context: &StreamContext,
        destination_scope: &KeyScope,
        destination_context: &StreamContext,
        source: &mut R,
        destination: &mut W,
    ) -> core::result::Result<StreamReseal, StreamResealError>
    where
        R: Read,
        W: Write,
    {
        let mut reader = self.reader(source, *source_scope, source_context);
        let (header, first_frame) = reader
            .stage_created()
            .map_err(|cause| StreamResealError::untouched(StreamResealPhase::Source, cause))?;
        let source_lease = reader
            .resolve_source_lease(header)
            .map_err(|cause| StreamResealError::untouched(StreamResealPhase::Source, cause))?;
        let source_key = source_lease.descriptor();
        reader
            .initialize_created_cipher(header, &source_lease)
            .map_err(|cause| StreamResealError::untouched(StreamResealPhase::Source, cause))?;
        reader
            .authenticate_loaded_frame_contents(first_frame, Some(&source_lease))
            .map_err(|cause| StreamResealError::untouched(StreamResealPhase::Source, cause))?;

        let active = match self.provider.active(destination_scope) {
            Ok(active) => active,
            Err(error) => {
                let cause = reader.fault_cryptographic(map_key_provider_error(error));
                return Err(StreamResealError::untouched(
                    StreamResealPhase::Destination,
                    cause,
                ));
            }
        };
        let destination_key = active.descriptor();
        let same_scope = source_scope == destination_scope;
        if same_scope {
            let same_secret = constant_time_key_lease_secret_eq(&source_lease, &active);
            if source_key == destination_key {
                if !same_secret {
                    let cause = reader.fault_cryptographic(CryptError::WrongKey);
                    return Err(StreamResealError::untouched(
                        StreamResealPhase::Policy,
                        cause,
                    ));
                }
            } else {
                if let Err(error) = validate_stream_rotation_progress(source_key, destination_key) {
                    let cause = reader.fault_cryptographic(error);
                    return Err(StreamResealError::untouched(
                        StreamResealPhase::Policy,
                        cause,
                    ));
                }
                if same_secret {
                    let cause = reader.fault_cryptographic(CryptError::KeyMaterialReuse);
                    return Err(StreamResealError::untouched(
                        StreamResealPhase::Policy,
                        cause,
                    ));
                }
            }
        }
        drop(source_lease);

        let is_authenticated_noop = same_scope
            && constant_time_stream_context_eq(source_context, destination_context)
            && source_key == destination_key;
        if is_authenticated_noop {
            drop(active);
            reader
                .commit_loaded_frame(first_frame)
                .map_err(|cause| StreamResealError::untouched(StreamResealPhase::Source, cause))?;
            let source_completion = drain_authenticated_source(&mut reader)
                .map_err(|cause| StreamResealError::untouched(StreamResealPhase::Source, cause))?;
            return Ok(StreamReseal {
                source: source_completion,
                destination: None,
                destination_key,
            });
        }

        reader
            .commit_loaded_frame(first_frame)
            .map_err(|cause| StreamResealError::untouched(StreamResealPhase::Source, cause))?;

        let mut writer = self
            .writer_with_lease(destination, destination_scope, destination_context, active)
            .map_err(StreamError::Cryptographic)
            .map_err(|cause| StreamResealError::untouched(StreamResealPhase::Destination, cause))?;
        loop {
            let event = match reader.read_next() {
                Ok(event) => event,
                Err(cause) => {
                    return Err(StreamResealError::discard_only(
                        StreamResealPhase::Source,
                        writer.progress(),
                        cause,
                    ));
                }
            };
            match event {
                StreamRead::Data(frame) => {
                    if let Err(cause) = writer.write_frame(frame.plaintext()) {
                        return Err(StreamResealError::discard_only(
                            StreamResealPhase::Destination,
                            writer.progress(),
                            cause,
                        ));
                    }
                }
                StreamRead::Complete(source_completion) => {
                    let destination_completion = match writer.finish() {
                        Ok(completion) => completion,
                        Err(cause) => {
                            return Err(StreamResealError::discard_only(
                                StreamResealPhase::Destination,
                                writer.progress(),
                                cause,
                            ));
                        }
                    };
                    if source_completion.data_frames != destination_completion.data_frames
                        || source_completion.plaintext_bytes
                            != destination_completion.plaintext_bytes
                    {
                        return Err(StreamResealError::discard_only(
                            StreamResealPhase::Destination,
                            writer.progress(),
                            StreamError::Cryptographic(CryptError::CorruptStructure),
                        ));
                    }
                    return Ok(StreamReseal {
                        source: source_completion,
                        destination: Some(destination_completion),
                        destination_key,
                    });
                }
            }
        }
    }
}

fn drain_authenticated_source<R, P>(
    reader: &mut EncryptedStreamReader<'_, '_, R, P>,
) -> core::result::Result<StreamCompletion, StreamError>
where
    R: Read,
    P: KeyProvider,
{
    loop {
        match reader.read_next()? {
            StreamRead::Data(_frame) => {}
            StreamRead::Complete(completion) => return Ok(completion),
        }
    }
}

fn validate_stream_rotation_progress(
    source: KeyDescriptor,
    destination: KeyDescriptor,
) -> Result<()> {
    if destination.generation() <= source.generation() {
        return Err(CryptError::KeyDowngrade);
    }
    Ok(())
}

fn constant_time_key_lease_secret_eq(left: &KeyLease, right: &KeyLease) -> bool {
    left.with_secret_bytes(|left_bytes| {
        right.with_secret_bytes(|right_bytes| bool::from(left_bytes.ct_eq(right_bytes)))
    })
}

fn constant_time_stream_context_eq(left: &StreamContext, right: &StreamContext) -> bool {
    bool::from(
        left.logical_sequence.ct_eq(&right.logical_sequence) & left.digest.ct_eq(&right.digest),
    )
}

impl<W> EncryptedStreamWriter<'_, W>
where
    W: Write,
{
    /// Returns the writer's non-secret stream metadata.
    #[must_use]
    pub const fn metadata(&self) -> StreamMetadata {
        self.metadata
    }

    /// Returns the last unambiguous writer progress.
    #[must_use]
    pub const fn progress(&self) -> StreamProgress {
        self.progress
    }

    /// Encrypts and emits one non-empty bounded data frame.
    ///
    /// Encryption completes before any bytes for this frame reach the sink.
    /// An I/O failure permanently faults the writer and later calls return
    /// [`StreamError::Faulted`].
    ///
    /// # Errors
    ///
    /// Returns a typed input, limit, allocation, nonce, cipher, I/O, or state
    /// error. Empty frames are rejected because zero length is reserved for the
    /// authenticated final frame.
    pub fn write_frame(
        &mut self,
        plaintext: &[u8],
    ) -> core::result::Result<StreamProgress, StreamError> {
        self.require_active()?;
        if plaintext.is_empty() {
            return Err(StreamError::Cryptographic(CryptError::InvalidInput));
        }
        let plaintext_len = u32::try_from(plaintext.len())
            .map_err(|_error| StreamError::Cryptographic(CryptError::LimitExceeded))?;
        if plaintext_len > self.metadata.max_frame_plaintext_len {
            return Err(StreamError::Cryptographic(CryptError::LimitExceeded));
        }
        ensure_data_frame_nonce_available(self.progress.data_frames)
            .map_err(StreamError::Cryptographic)?;
        let new_plaintext_bytes = self
            .progress
            .plaintext_bytes
            .checked_add(u64::from(plaintext_len))
            .ok_or(StreamError::Cryptographic(CryptError::LimitExceeded))?;
        let new_data_frames = self
            .progress
            .data_frames
            .checked_add(1)
            .ok_or(StreamError::Cryptographic(CryptError::NonceExhausted))?;
        let next_boundary = self
            .next_encoded_boundary(plaintext.len())
            .map_err(StreamError::Cryptographic)?;
        let frame_header = encode_data_frame_header(
            self.progress.data_frames,
            plaintext.len(),
            &self.previous_tag,
        )
        .map_err(StreamError::Cryptographic)?;
        let tag = self
            .prepare_frame(&frame_header, self.progress.data_frames, plaintext)
            .map_err(StreamError::Cryptographic)?;
        self.ensure_header_written()?;
        if let Err(source) = self.sink.write_all(&self.frame_buffer) {
            return Err(self.fault_io(StreamIoOperation::WriteFrame, source));
        }
        self.previous_tag.copy_from_slice(&tag);
        self.progress = StreamProgress {
            data_frames: new_data_frames,
            plaintext_bytes: new_plaintext_bytes,
            safe_encoded_boundary: next_boundary,
        };
        Ok(self.progress)
    }

    /// Writes the mandatory authenticated final frame and flushes the sink.
    ///
    /// Completion is returned only after both operations succeed. Drop never
    /// calls this method automatically.
    ///
    /// # Errors
    ///
    /// Returns a typed allocation, cipher, I/O, or fault-state error. A failed
    /// final write or flush never returns completion and permanently faults the
    /// writer.
    pub fn finish(&mut self) -> core::result::Result<StreamCompletion, StreamError> {
        match self.state {
            WriterState::Finished(completion) => return Ok(completion),
            WriterState::Faulted => {
                return Err(StreamError::Faulted {
                    progress: self.progress,
                });
            }
            WriterState::Active => {}
        }
        let final_header = encode_final_frame_header(
            self.progress.data_frames,
            self.progress.plaintext_bytes,
            &self.previous_tag,
        );
        let next_boundary = self
            .next_encoded_boundary(0)
            .map_err(StreamError::Cryptographic)?;
        let _tag = self
            .prepare_frame(&final_header, self.progress.data_frames, &[])
            .map_err(StreamError::Cryptographic)?;
        self.cipher = None;
        self.ensure_header_written()?;
        if let Err(source) = self.sink.write_all(&self.frame_buffer) {
            return Err(self.fault_io(StreamIoOperation::WriteFrame, source));
        }
        self.progress.safe_encoded_boundary = next_boundary;
        if let Err(source) = self.sink.flush() {
            return Err(self.fault_io(StreamIoOperation::Flush, source));
        }
        let completion = StreamCompletion {
            metadata: self.metadata,
            data_frames: self.progress.data_frames,
            plaintext_bytes: self.progress.plaintext_bytes,
            encoded_bytes: next_boundary,
        };
        self.state = WriterState::Finished(completion);
        self.clear_frame_buffer();
        Ok(completion)
    }

    fn require_active(&self) -> core::result::Result<(), StreamError> {
        match self.state {
            WriterState::Active => Ok(()),
            WriterState::Faulted => Err(StreamError::Faulted {
                progress: self.progress,
            }),
            WriterState::Finished(completion) => Err(StreamError::Finished { completion }),
        }
    }

    fn ensure_header_written(&mut self) -> core::result::Result<(), StreamError> {
        if self.header_written {
            return Ok(());
        }
        if let Err(source) = self.sink.write_all(&self.stream_header) {
            return Err(self.fault_io(StreamIoOperation::WriteHeader, source));
        }
        self.header_written = true;
        self.progress.safe_encoded_boundary = ENCRYPTED_STREAM_HEADER_LEN as u64;
        Ok(())
    }

    fn prepare_frame(
        &mut self,
        frame_header: &[u8; ENCRYPTED_STREAM_FRAME_HEADER_LEN],
        sequence: u64,
        plaintext: &[u8],
    ) -> Result<[u8; TAG_LEN]> {
        self.prepare_frame_with(
            frame_header,
            sequence,
            plaintext,
            |cipher, nonce_bytes, aad, payload| {
                let nonce = Nonce::<Aes256Gcm>::try_from(nonce_bytes.as_slice())
                    .map_err(|_error| CryptError::CorruptStructure)?;
                let tag = cipher
                    .encrypt_inout_detached(&nonce, aad, payload.into())
                    .map_err(|_error| CryptError::InvalidInput)?;
                let mut tag_bytes = [0_u8; TAG_LEN];
                tag_bytes.copy_from_slice(tag.as_slice());
                Ok(tag_bytes)
            },
        )
    }

    fn prepare_frame_with<F>(
        &mut self,
        frame_header: &[u8; ENCRYPTED_STREAM_FRAME_HEADER_LEN],
        sequence: u64,
        plaintext: &[u8],
        encrypt: F,
    ) -> Result<[u8; TAG_LEN]>
    where
        F: FnOnce(&Aes256Gcm, &[u8; 12], &[u8], &mut [u8]) -> Result<[u8; TAG_LEN]>,
    {
        self.clear_frame_buffer();
        let required = ENCRYPTED_STREAM_FRAME_HEADER_LEN
            .checked_add(plaintext.len())
            .and_then(|length| length.checked_add(TAG_LEN))
            .ok_or(CryptError::LimitExceeded)?;
        self.frame_buffer
            .try_reserve_exact(required)
            .map_err(|_error| CryptError::AllocationFailed)?;
        self.frame_buffer.extend_from_slice(frame_header);
        self.frame_buffer.extend_from_slice(plaintext);

        let nonce_bytes = frame_nonce(&self.nonce_prefix, sequence);
        let aad = frame_aad(&self.stream_header, frame_header);
        let plaintext_end = ENCRYPTED_STREAM_FRAME_HEADER_LEN
            .checked_add(plaintext.len())
            .ok_or(CryptError::LimitExceeded)?;
        let encrypt_result = match self.cipher.as_ref() {
            Some(cipher) => encrypt(
                cipher,
                &nonce_bytes,
                &aad,
                &mut self.frame_buffer[ENCRYPTED_STREAM_FRAME_HEADER_LEN..plaintext_end],
            ),
            None => Err(CryptError::CorruptStructure),
        };
        let tag_bytes = match encrypt_result {
            Ok(tag_bytes) => tag_bytes,
            Err(error) => {
                self.fault_after_nonce_use();
                return Err(error);
            }
        };
        self.frame_buffer.extend_from_slice(&tag_bytes);
        Ok(tag_bytes)
    }

    fn next_encoded_boundary(&self, plaintext_len: usize) -> Result<u64> {
        let base = if self.header_written {
            self.progress.safe_encoded_boundary
        } else {
            ENCRYPTED_STREAM_HEADER_LEN as u64
        };
        let frame_len = ENCRYPTED_STREAM_FRAME_HEADER_LEN
            .checked_add(plaintext_len)
            .and_then(|length| length.checked_add(TAG_LEN))
            .ok_or(CryptError::LimitExceeded)?;
        base.checked_add(u64::try_from(frame_len).map_err(|_error| CryptError::LimitExceeded)?)
            .ok_or(CryptError::LimitExceeded)
    }

    fn fault_after_nonce_use(&mut self) {
        self.state = WriterState::Faulted;
        self.cipher = None;
        self.clear_frame_buffer();
    }

    fn fault_io(&mut self, operation: StreamIoOperation, source: io::Error) -> StreamError {
        self.state = WriterState::Faulted;
        self.cipher = None;
        self.clear_frame_buffer();
        StreamError::Io(StreamIoError {
            operation,
            progress: self.progress,
            source,
        })
    }

    fn clear_frame_buffer(&mut self) {
        self.frame_buffer.as_mut_slice().zeroize();
        self.frame_buffer.clear();
    }
}

fn ensure_data_frame_nonce_available(data_frames: u64) -> Result<()> {
    if data_frames >= MAX_STREAM_DATA_FRAMES {
        return Err(CryptError::NonceExhausted);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum ReaderState {
    Created,
    Reading,
    RecoverableEof,
    Faulted,
    Complete(StreamCompletion),
}

#[derive(Debug, Clone, Copy)]
enum PendingRead {
    None,
    Data {
        sequence: u64,
        plaintext_len: usize,
        prefix: AuthenticatedPrefix,
    },
    Complete(StreamCompletion),
}

/// Explicit incremental encrypted-stream v1 reader.
///
/// A data frame is returned only after its scope, context, sequence, chain, and
/// AEAD tag authenticate. Physical EOF is always an error unless an
/// authenticated final frame has first supplied exact totals.
pub struct EncryptedStreamReader<'io, 'context, R, P> {
    source: &'io mut R,
    provider: &'context P,
    config: StreamConfig,
    expected_scope: KeyScope,
    expected_context: &'context StreamContext,
    stream_header: [u8; ENCRYPTED_STREAM_HEADER_LEN],
    header: Option<StreamHeader>,
    metadata: Option<StreamMetadata>,
    cipher: Option<Aes256Gcm>,
    previous_tag: [u8; TAG_LEN],
    progress: StreamProgress,
    encoded_consumed: u64,
    frame_buffer: Zeroizing<Vec<u8>>,
    pending: PendingRead,
    state: ReaderState,
}

impl<R, P> EncryptedStreamReader<'_, '_, R, P>
where
    R: Read,
    P: KeyProvider,
{
    /// Reads and authenticates enough input to establish stream metadata.
    ///
    /// One complete first frame is staged before the historical key provider is
    /// queried. The frame remains pending for [`Self::read_next`], so this
    /// method never discards authenticated plaintext.
    ///
    /// # Errors
    ///
    /// Returns a typed structure, scope, provider, context, authentication,
    /// allocation, I/O, truncation, or state error. Failed authentication
    /// returns no plaintext.
    pub fn begin(&mut self) -> core::result::Result<StreamMetadata, StreamError> {
        match self.state {
            ReaderState::Created => self.begin_created()?,
            ReaderState::Reading => {}
            ReaderState::RecoverableEof | ReaderState::Faulted => {
                return Err(StreamError::Faulted {
                    progress: self.progress,
                });
            }
            ReaderState::Complete(completion) => return Ok(completion.metadata),
        }
        self.metadata
            .ok_or(StreamError::Cryptographic(CryptError::CorruptStructure))
    }

    /// Returns the next authenticated data frame or authenticated completion.
    ///
    /// The result is never `Option`: EOF without a final frame is a failure.
    /// A returned frame borrows the reader's one zeroizing frame buffer and must
    /// be consumed before advancing the reader.
    ///
    /// # Errors
    ///
    /// Returns a typed cryptographic, I/O, truncation, trailing-data, or state
    /// error. Any ambiguous I/O or integrity failure permanently faults the
    /// reader.
    pub fn read_next(&mut self) -> core::result::Result<StreamRead<'_>, StreamError> {
        if matches!(self.state, ReaderState::Created) {
            let _metadata = self.begin()?;
        }
        match self.state {
            ReaderState::RecoverableEof | ReaderState::Faulted => {
                return Err(StreamError::Faulted {
                    progress: self.progress,
                });
            }
            ReaderState::Complete(completion) => {
                return Err(StreamError::Finished { completion });
            }
            ReaderState::Created | ReaderState::Reading => {}
        }
        if matches!(self.pending, PendingRead::None) {
            self.load_next_authenticated()?;
        }
        match self.pending {
            PendingRead::Data {
                sequence,
                plaintext_len,
                prefix,
            } => {
                self.pending = PendingRead::None;
                let plaintext_end = ENCRYPTED_STREAM_FRAME_HEADER_LEN
                    .checked_add(plaintext_len)
                    .ok_or(StreamError::Cryptographic(CryptError::LimitExceeded))?;
                Ok(StreamRead::Data(AuthenticatedFrame {
                    sequence,
                    plaintext: &self.frame_buffer[ENCRYPTED_STREAM_FRAME_HEADER_LEN..plaintext_end],
                    prefix,
                }))
            }
            PendingRead::Complete(completion) => {
                self.pending = PendingRead::None;
                self.state = ReaderState::Complete(completion);
                Ok(StreamRead::Complete(completion))
            }
            PendingRead::None => Err(self.fault_cryptographic(CryptError::CorruptStructure)),
        }
    }

    /// Returns the last unambiguous reader progress.
    #[must_use]
    pub const fn progress(&self) -> StreamProgress {
        self.progress
    }

    /// Explicitly recovers totals for an authenticated prefix after truncation.
    ///
    /// Recovery is available only after exact EOF or `UnexpectedEof`, and only
    /// when at least one complete data frame authenticated. It is rejected for
    /// integrity, context, structural, trailing-data, and non-EOF I/O failures.
    ///
    /// # Errors
    ///
    /// Returns the exact reason recovery is unavailable. A successful prefix
    /// remains incomplete and cannot be resumed or finalized in place.
    pub fn recover_authenticated_prefix(
        &self,
    ) -> core::result::Result<AuthenticatedPrefix, PrefixRecoveryError> {
        match self.state {
            ReaderState::Created | ReaderState::Reading => Err(PrefixRecoveryError::NotFaulted),
            ReaderState::Complete(_) => Err(PrefixRecoveryError::AlreadyComplete),
            ReaderState::Faulted => Err(PrefixRecoveryError::FailureNotRecoverable),
            ReaderState::RecoverableEof => {
                if self.progress.data_frames == 0 {
                    return Err(PrefixRecoveryError::NoAuthenticatedDataFrames);
                }
                let metadata = self
                    .metadata
                    .ok_or(PrefixRecoveryError::FailureNotRecoverable)?;
                Ok(AuthenticatedPrefix {
                    metadata,
                    data_frames: self.progress.data_frames,
                    plaintext_bytes: self.progress.plaintext_bytes,
                    safe_encoded_boundary: self.progress.safe_encoded_boundary,
                })
            }
        }
    }

    fn begin_created(&mut self) -> core::result::Result<(), StreamError> {
        let (header, frame_header) = self.stage_created()?;
        let lease = self.resolve_source_lease(header)?;
        self.authenticate_created(header, frame_header, lease)
    }

    fn stage_created(&mut self) -> core::result::Result<(StreamHeader, FrameHeader), StreamError> {
        match read_exact_counted(self.source, &mut self.stream_header) {
            Ok(()) => {
                self.encoded_consumed = ENCRYPTED_STREAM_HEADER_LEN as u64;
            }
            Err(ExactReadFailure::Eof { bytes_read: 0 }) => {
                self.enter_recoverable_eof();
                return Err(StreamError::Cryptographic(CryptError::Truncated));
            }
            Err(ExactReadFailure::Eof { .. }) => {
                return Err(self.fault_io(
                    StreamIoOperation::ReadHeader,
                    unexpected_eof("encrypted stream header ended early"),
                    true,
                ));
            }
            Err(ExactReadFailure::Io(source)) => {
                let recoverable_eof = source.kind() == io::ErrorKind::UnexpectedEof;
                return Err(self.fault_io(StreamIoOperation::ReadHeader, source, recoverable_eof));
            }
        }
        let header = match parse_stream_header(&self.stream_header, self.config) {
            Ok(parsed) => parsed.header,
            Err(error) => return Err(self.fault_cryptographic(error)),
        };
        if let Err(error) = validate_expected_scope(&header, &self.expected_scope) {
            return Err(self.fault_cryptographic(error));
        }
        let metadata = StreamMetadata {
            key: KeyDescriptor::new(header.key_id, header.generation),
            max_frame_plaintext_len: header.max_frame_plaintext_len,
        };
        self.header = Some(header);
        self.metadata = Some(metadata);
        let frame_header = self.read_frame()?;
        if let Err(error) = self.validate_frame_position(&frame_header) {
            return Err(self.fault_cryptographic(error));
        }
        Ok((header, frame_header))
    }

    fn resolve_source_lease(
        &mut self,
        header: StreamHeader,
    ) -> core::result::Result<KeyLease, StreamError> {
        let lease =
            match self
                .provider
                .by_id(&self.expected_scope, header.key_id, header.generation)
            {
                Ok(lease) => lease,
                Err(error) => {
                    return Err(self.fault_cryptographic(map_key_provider_error(error)));
                }
            };
        if lease.key_id() != header.key_id || lease.generation() != header.generation {
            return Err(self.fault_cryptographic(CryptError::WrongKey));
        }
        Ok(lease)
    }

    fn authenticate_created(
        &mut self,
        header: StreamHeader,
        frame_header: FrameHeader,
        lease: KeyLease,
    ) -> core::result::Result<(), StreamError> {
        self.initialize_created_cipher(header, &lease)?;
        self.authenticate_loaded_frame_contents(frame_header, Some(&lease))?;
        drop(lease);
        self.commit_loaded_frame(frame_header)
    }

    fn initialize_created_cipher(
        &mut self,
        header: StreamHeader,
        lease: &KeyLease,
    ) -> core::result::Result<(), StreamError> {
        let derived_key = match derive_storage_key(
            lease,
            &self.expected_scope,
            &header.stream_salt,
            super::SUITE_AES_256_GCM_HKDF_SHA256,
            HKDF_INFO_DOMAIN,
        ) {
            Ok(key) => key,
            Err(error) => return Err(self.fault_cryptographic(error)),
        };
        let cipher = match Aes256Gcm::new_from_slice(derived_key.as_ref()) {
            Ok(cipher) => cipher,
            Err(_error) => return Err(self.fault_cryptographic(CryptError::InvalidInput)),
        };
        self.cipher = Some(cipher);
        self.state = ReaderState::Reading;
        Ok(())
    }

    fn load_next_authenticated(&mut self) -> core::result::Result<(), StreamError> {
        let frame_header = self.read_frame()?;
        self.authenticate_loaded_frame_contents(frame_header, None)?;
        self.commit_loaded_frame(frame_header)
    }

    fn read_frame(&mut self) -> core::result::Result<FrameHeader, StreamError> {
        self.clear_frame_buffer();
        if self
            .frame_buffer
            .try_reserve_exact(ENCRYPTED_STREAM_FRAME_HEADER_LEN)
            .is_err()
        {
            return Err(self.fault_cryptographic(CryptError::AllocationFailed));
        }
        self.frame_buffer
            .resize(ENCRYPTED_STREAM_FRAME_HEADER_LEN, 0);
        match read_exact_counted(self.source, &mut self.frame_buffer) {
            Ok(()) => {
                self.encoded_consumed = self
                    .encoded_consumed
                    .checked_add(ENCRYPTED_STREAM_FRAME_HEADER_LEN as u64)
                    .ok_or(StreamError::Cryptographic(CryptError::LimitExceeded))?;
            }
            Err(ExactReadFailure::Eof { bytes_read: 0 }) => {
                self.enter_recoverable_eof();
                return Err(StreamError::Cryptographic(CryptError::MissingFinalFrame));
            }
            Err(ExactReadFailure::Eof { bytes_read }) => {
                self.encoded_consumed =
                    self.encoded_consumed
                        .checked_add(u64::try_from(bytes_read).map_err(|_error| {
                            StreamError::Cryptographic(CryptError::LimitExceeded)
                        })?)
                        .ok_or(StreamError::Cryptographic(CryptError::LimitExceeded))?;
                return Err(self.fault_io(
                    StreamIoOperation::ReadFrameHeader,
                    unexpected_eof("encrypted stream frame header ended early"),
                    true,
                ));
            }
            Err(ExactReadFailure::Io(source)) => {
                let recoverable_eof = source.kind() == io::ErrorKind::UnexpectedEof;
                return Err(self.fault_io(
                    StreamIoOperation::ReadFrameHeader,
                    source,
                    recoverable_eof,
                ));
            }
        }
        let frame_header = match parse_frame_header(
            &self.frame_buffer,
            self.metadata
                .map(StreamMetadata::max_frame_plaintext_len)
                .ok_or(StreamError::Cryptographic(CryptError::CorruptStructure))?,
        ) {
            Ok(header) => header,
            Err(error) => return Err(self.fault_cryptographic(error)),
        };
        let body_len = usize::try_from(frame_header.ciphertext_len)
            .map_err(|_error| StreamError::Cryptographic(CryptError::LimitExceeded))?
            .checked_add(TAG_LEN)
            .ok_or(StreamError::Cryptographic(CryptError::LimitExceeded))?;
        let frame_len = ENCRYPTED_STREAM_FRAME_HEADER_LEN
            .checked_add(body_len)
            .ok_or(StreamError::Cryptographic(CryptError::LimitExceeded))?;
        if self.frame_buffer.try_reserve_exact(body_len).is_err() {
            return Err(self.fault_cryptographic(CryptError::AllocationFailed));
        }
        self.frame_buffer.resize(frame_len, 0);
        match read_exact_counted(
            self.source,
            &mut self.frame_buffer[ENCRYPTED_STREAM_FRAME_HEADER_LEN..],
        ) {
            Ok(()) => {
                self.encoded_consumed =
                    self.encoded_consumed
                        .checked_add(u64::try_from(body_len).map_err(|_error| {
                            StreamError::Cryptographic(CryptError::LimitExceeded)
                        })?)
                        .ok_or(StreamError::Cryptographic(CryptError::LimitExceeded))?;
            }
            Err(ExactReadFailure::Eof { bytes_read }) => {
                self.encoded_consumed =
                    self.encoded_consumed
                        .checked_add(u64::try_from(bytes_read).map_err(|_error| {
                            StreamError::Cryptographic(CryptError::LimitExceeded)
                        })?)
                        .ok_or(StreamError::Cryptographic(CryptError::LimitExceeded))?;
                return Err(self.fault_io(
                    StreamIoOperation::ReadFrameBody,
                    unexpected_eof("encrypted stream frame body ended early"),
                    true,
                ));
            }
            Err(ExactReadFailure::Io(source)) => {
                let recoverable_eof = source.kind() == io::ErrorKind::UnexpectedEof;
                return Err(self.fault_io(
                    StreamIoOperation::ReadFrameBody,
                    source,
                    recoverable_eof,
                ));
            }
        }
        Ok(frame_header)
    }

    fn authenticate_loaded_frame_contents(
        &mut self,
        frame_header: FrameHeader,
        context_lease: Option<&KeyLease>,
    ) -> core::result::Result<(), StreamError> {
        if let Err(error) = self.validate_frame_position(&frame_header) {
            return Err(self.fault_cryptographic(error));
        }
        let ciphertext_len = usize::try_from(frame_header.ciphertext_len)
            .map_err(|_error| StreamError::Cryptographic(CryptError::LimitExceeded))?;
        let ciphertext_end = ENCRYPTED_STREAM_FRAME_HEADER_LEN
            .checked_add(ciphertext_len)
            .ok_or(StreamError::Cryptographic(CryptError::LimitExceeded))?;
        let tag_end = ciphertext_end
            .checked_add(TAG_LEN)
            .ok_or(StreamError::Cryptographic(CryptError::LimitExceeded))?;
        if tag_end != self.frame_buffer.len() {
            return Err(self.fault_cryptographic(CryptError::CorruptStructure));
        }
        let tag_bytes = copy_array::<TAG_LEN>(&self.frame_buffer, ciphertext_end);
        let tag = Tag::<Aes256Gcm>::from(tag_bytes);
        let nonce_prefix = self
            .header
            .map(|header| header.nonce_prefix)
            .ok_or(StreamError::Cryptographic(CryptError::CorruptStructure))?;
        let nonce_bytes = frame_nonce(&nonce_prefix, frame_header.sequence);
        let nonce = Nonce::<Aes256Gcm>::try_from(nonce_bytes.as_slice())
            .map_err(|_error| StreamError::Cryptographic(CryptError::CorruptStructure))?;
        let encoded_frame_header =
            copy_array::<ENCRYPTED_STREAM_FRAME_HEADER_LEN>(&self.frame_buffer, 0);
        let aad = frame_aad(&self.stream_header, &encoded_frame_header);
        let decrypt_result = match self.cipher.as_ref() {
            Some(cipher) => cipher.decrypt_inout_detached(
                &nonce,
                &aad,
                (&mut self.frame_buffer[ENCRYPTED_STREAM_FRAME_HEADER_LEN..ciphertext_end]).into(),
                &tag,
            ),
            None => return Err(self.fault_cryptographic(CryptError::CorruptStructure)),
        };
        if decrypt_result.is_err() {
            return Err(self.fault_cryptographic(CryptError::AuthenticationFailed));
        }
        if let Some(lease) = context_lease {
            let header = self
                .header
                .ok_or(StreamError::Cryptographic(CryptError::CorruptStructure))?;
            if let Err(error) = verify_context_binding(
                lease,
                &self.expected_scope,
                &header.stream_salt,
                self.expected_context,
                &header.context_binding,
            ) {
                return Err(self.fault_cryptographic(error));
            }
        }
        Ok(())
    }

    fn commit_loaded_frame(
        &mut self,
        frame_header: FrameHeader,
    ) -> core::result::Result<(), StreamError> {
        if frame_header.is_final {
            if frame_header.total_data_frames != self.progress.data_frames
                || frame_header.total_plaintext_len != self.progress.plaintext_bytes
            {
                return Err(self.fault_cryptographic(CryptError::CorruptStructure));
            }
            self.cipher = None;
            self.verify_exact_end()?;
            self.progress.safe_encoded_boundary = self.encoded_consumed;
            let metadata = self
                .metadata
                .ok_or(StreamError::Cryptographic(CryptError::CorruptStructure))?;
            let completion = StreamCompletion {
                metadata,
                data_frames: self.progress.data_frames,
                plaintext_bytes: self.progress.plaintext_bytes,
                encoded_bytes: self.encoded_consumed,
            };
            self.pending = PendingRead::Complete(completion);
            self.clear_frame_buffer();
            return Ok(());
        }

        let new_plaintext_bytes = self
            .progress
            .plaintext_bytes
            .checked_add(u64::from(frame_header.ciphertext_len))
            .ok_or(StreamError::Cryptographic(CryptError::LimitExceeded))?;
        let new_data_frames = self
            .progress
            .data_frames
            .checked_add(1)
            .ok_or(StreamError::Cryptographic(CryptError::NonceExhausted))?;
        let ciphertext_len = usize::try_from(frame_header.ciphertext_len)
            .map_err(|_error| StreamError::Cryptographic(CryptError::LimitExceeded))?;
        let ciphertext_end = ENCRYPTED_STREAM_FRAME_HEADER_LEN
            .checked_add(ciphertext_len)
            .ok_or(StreamError::Cryptographic(CryptError::LimitExceeded))?;
        let tag_bytes = copy_array::<TAG_LEN>(&self.frame_buffer, ciphertext_end);
        self.previous_tag.copy_from_slice(&tag_bytes);
        self.progress = StreamProgress {
            data_frames: new_data_frames,
            plaintext_bytes: new_plaintext_bytes,
            safe_encoded_boundary: self.encoded_consumed,
        };
        let metadata = self
            .metadata
            .ok_or(StreamError::Cryptographic(CryptError::CorruptStructure))?;
        let prefix = AuthenticatedPrefix {
            metadata,
            data_frames: new_data_frames,
            plaintext_bytes: new_plaintext_bytes,
            safe_encoded_boundary: self.encoded_consumed,
        };
        self.pending = PendingRead::Data {
            sequence: frame_header.sequence,
            plaintext_len: ciphertext_len,
            prefix,
        };
        Ok(())
    }

    fn validate_frame_position(&self, frame_header: &FrameHeader) -> Result<()> {
        if frame_header.sequence != self.progress.data_frames {
            return Err(CryptError::SequenceMismatch);
        }
        if frame_header.previous_tag != self.previous_tag {
            return Err(CryptError::FrameChainMismatch);
        }
        if !frame_header.is_final && self.progress.data_frames >= MAX_STREAM_DATA_FRAMES {
            return Err(CryptError::NonceExhausted);
        }
        if frame_header.is_final
            && (frame_header.total_data_frames != self.progress.data_frames
                || frame_header.total_plaintext_len != self.progress.plaintext_bytes)
        {
            return Err(CryptError::CorruptStructure);
        }
        Ok(())
    }

    fn verify_exact_end(&mut self) -> core::result::Result<(), StreamError> {
        let mut trailing = [0_u8; 1];
        loop {
            match self.source.read(&mut trailing) {
                Ok(0) => return Ok(()),
                Ok(_) => return Err(self.fault_cryptographic(CryptError::TrailingData)),
                Err(source) if source.kind() == io::ErrorKind::Interrupted => {}
                Err(source) => {
                    let recoverable_eof = source.kind() == io::ErrorKind::UnexpectedEof;
                    return Err(self.fault_io(
                        StreamIoOperation::VerifyEnd,
                        source,
                        recoverable_eof,
                    ));
                }
            }
        }
    }

    fn fault_cryptographic(&mut self, error: CryptError) -> StreamError {
        self.state = ReaderState::Faulted;
        self.pending = PendingRead::None;
        self.cipher = None;
        self.clear_frame_buffer();
        StreamError::Cryptographic(error)
    }

    fn fault_io(
        &mut self,
        operation: StreamIoOperation,
        source: io::Error,
        recoverable_eof: bool,
    ) -> StreamError {
        self.state = if recoverable_eof {
            ReaderState::RecoverableEof
        } else {
            ReaderState::Faulted
        };
        self.pending = PendingRead::None;
        self.cipher = None;
        self.clear_frame_buffer();
        StreamError::Io(StreamIoError {
            operation,
            progress: self.progress,
            source,
        })
    }

    fn enter_recoverable_eof(&mut self) {
        self.state = ReaderState::RecoverableEof;
        self.pending = PendingRead::None;
        self.cipher = None;
        self.clear_frame_buffer();
    }

    fn clear_frame_buffer(&mut self) {
        self.frame_buffer.as_mut_slice().zeroize();
        self.frame_buffer.clear();
    }
}

enum ExactReadFailure {
    Eof { bytes_read: usize },
    Io(io::Error),
}

fn read_exact_counted<R>(
    source: &mut R,
    buffer: &mut [u8],
) -> core::result::Result<(), ExactReadFailure>
where
    R: Read,
{
    let mut bytes_read = 0_usize;
    while bytes_read < buffer.len() {
        match source.read(&mut buffer[bytes_read..]) {
            Ok(0) => return Err(ExactReadFailure::Eof { bytes_read }),
            Ok(read) => {
                let remaining = buffer.len() - bytes_read;
                if read > remaining {
                    return Err(ExactReadFailure::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "reader reported more bytes than requested",
                    )));
                }
                bytes_read += read;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(ExactReadFailure::Io(error)),
        }
    }
    Ok(())
}

fn unexpected_eof(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, message)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::{WriterState, encode_data_frame_header, ensure_data_frame_nonce_available};
    use crate::storage::{
        CryptError, EncryptedStreamCodec, KeyGeneration, KeyId, KeyLease, KeyProvider,
        KeyProviderError, KeyScope, MAX_STREAM_DATA_FRAMES, PurposeId, SecretKey32, SpaceId,
        StreamConfig, StreamContext, StreamError,
    };

    #[derive(Clone, Copy)]
    struct TestProvider;

    impl KeyProvider for TestProvider {
        fn active(&self, _scope: &KeyScope) -> core::result::Result<KeyLease, KeyProviderError> {
            Ok(KeyLease::new(
                KeyId::new(*b"test-key-id-v001"),
                KeyGeneration::new(1),
                SecretKey32::new([0xA5; 32]),
            ))
        }

        fn by_id(
            &self,
            scope: &KeyScope,
            _key_id: KeyId,
            _generation: KeyGeneration,
        ) -> core::result::Result<KeyLease, KeyProviderError> {
            self.active(scope)
        }
    }

    fn test_scope() -> KeyScope {
        KeyScope::new(
            SpaceId::new([0x53; 32]),
            PurposeId::new(*b"memory-record-v1"),
        )
    }

    #[test]
    fn test_stream_invocation_limit_reserves_the_final_nonce() {
        assert!(ensure_data_frame_nonce_available(0).is_ok());
        assert!(ensure_data_frame_nonce_available(MAX_STREAM_DATA_FRAMES - 1).is_ok());
        assert_eq!(
            ensure_data_frame_nonce_available(MAX_STREAM_DATA_FRAMES),
            Err(CryptError::NonceExhausted)
        );
        assert_eq!(
            ensure_data_frame_nonce_available(MAX_STREAM_DATA_FRAMES + 1),
            Err(CryptError::NonceExhausted)
        );
    }

    #[test]
    fn test_post_nonce_encryption_failure_faults_writer_and_drops_cipher() {
        let codec = EncryptedStreamCodec::with_config(TestProvider, StreamConfig::new(16).unwrap());
        let mut sink = Vec::new();
        let mut writer = codec
            .writer(
                &mut sink,
                &test_scope(),
                &StreamContext::new(1, b"post nonce failure").unwrap(),
            )
            .unwrap();
        let frame_header = encode_data_frame_header(0, 7, &[0_u8; 16]).unwrap();
        let mut invocations = 0_u8;

        let result = writer.prepare_frame_with(
            &frame_header,
            0,
            b"payload",
            |_cipher, _nonce, _aad, _payload| {
                invocations = invocations.saturating_add(1);
                Err(CryptError::InvalidInput)
            },
        );

        assert_eq!(result, Err(CryptError::InvalidInput));
        assert_eq!(invocations, 1);
        assert!(matches!(writer.state, WriterState::Faulted));
        assert!(writer.cipher.is_none());
        assert!(writer.frame_buffer.is_empty());
        assert!(matches!(
            writer.write_frame(b"must not retry"),
            Err(StreamError::Faulted { .. })
        ));
        assert!(matches!(writer.finish(), Err(StreamError::Faulted { .. })));
    }
}
