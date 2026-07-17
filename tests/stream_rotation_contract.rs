//! Contract tests for bounded authenticated stream rotation and migration.

#![cfg(feature = "storage-v1")]
#![allow(clippy::unwrap_used)]

use std::{
    io::{self, Cursor, Read, Write},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use crypt_io::storage::{
    CryptError, EncryptedStreamCodec, KeyDescriptor, KeyGeneration, KeyId, KeyLease, KeyProvider,
    KeyProviderError, KeyScope, PurposeId, SecretKey32, SpaceId, StreamConfig, StreamContext,
    StreamDestinationState, StreamRead, StreamResealPhase,
};

const OLD_KEY_ID: [u8; 16] = *b"old-key-id-v0001";
const NEW_KEY_ID: [u8; 16] = *b"new-key-id-v0002";
const OLD_SECRET: [u8; 32] = [0x19; 32];
const NEW_SECRET: [u8; 32] = [0x29; 32];
const SPACE: [u8; 32] = [0x44; 32];
const SOURCE_PURPOSE: [u8; 16] = *b"snapshot-strm-v1";
const TARGET_PURPOSE: [u8; 16] = *b"archive-strm--v1";

#[derive(Clone, Copy)]
struct Provider {
    active_generation: u32,
    active_key_id: [u8; 16],
    active_secret: [u8; 32],
    stored_new_secret: [u8; 32],
    expose_old: bool,
    expose_new: bool,
}

impl Provider {
    const fn old_only() -> Self {
        Self {
            active_generation: 1,
            active_key_id: OLD_KEY_ID,
            active_secret: OLD_SECRET,
            stored_new_secret: NEW_SECRET,
            expose_old: true,
            expose_new: false,
        }
    }

    const fn rotating() -> Self {
        Self {
            active_generation: 2,
            active_key_id: NEW_KEY_ID,
            active_secret: NEW_SECRET,
            stored_new_secret: NEW_SECRET,
            expose_old: true,
            expose_new: true,
        }
    }

    const fn reused_descriptor() -> Self {
        Self {
            active_generation: 1,
            active_key_id: OLD_KEY_ID,
            active_secret: NEW_SECRET,
            stored_new_secret: NEW_SECRET,
            expose_old: true,
            expose_new: false,
        }
    }

    const fn reused_material_replacement() -> Self {
        Self {
            active_generation: 2,
            active_key_id: NEW_KEY_ID,
            active_secret: OLD_SECRET,
            stored_new_secret: OLD_SECRET,
            expose_old: true,
            expose_new: true,
        }
    }

    const fn stale_after_rotation() -> Self {
        Self {
            active_generation: 1,
            active_key_id: OLD_KEY_ID,
            active_secret: OLD_SECRET,
            stored_new_secret: NEW_SECRET,
            expose_old: true,
            expose_new: true,
        }
    }

    const fn equal_generation_replacement() -> Self {
        Self {
            active_generation: 1,
            active_key_id: NEW_KEY_ID,
            active_secret: NEW_SECRET,
            stored_new_secret: NEW_SECRET,
            expose_old: true,
            expose_new: true,
        }
    }

    fn lease(key_id: [u8; 16], generation: u32, secret: [u8; 32]) -> KeyLease {
        KeyLease::new(
            KeyId::new(key_id),
            KeyGeneration::new(generation),
            SecretKey32::new(secret),
        )
    }
}

impl KeyProvider for Provider {
    fn active(&self, _scope: &KeyScope) -> Result<KeyLease, KeyProviderError> {
        Ok(Self::lease(
            self.active_key_id,
            self.active_generation,
            self.active_secret,
        ))
    }

    fn by_id(
        &self,
        _scope: &KeyScope,
        key_id: KeyId,
        generation: KeyGeneration,
    ) -> Result<KeyLease, KeyProviderError> {
        let descriptor = KeyDescriptor::new(key_id, generation);
        if self.expose_old
            && descriptor == KeyDescriptor::new(KeyId::new(OLD_KEY_ID), KeyGeneration::new(1))
        {
            return Ok(Self::lease(OLD_KEY_ID, 1, OLD_SECRET));
        }
        if self.expose_new
            && descriptor == KeyDescriptor::new(KeyId::new(NEW_KEY_ID), KeyGeneration::new(2))
        {
            return Ok(Self::lease(NEW_KEY_ID, 2, self.stored_new_secret));
        }
        Err(KeyProviderError::Unavailable)
    }
}

#[derive(Clone, Copy)]
struct BoundaryFailingProvider {
    by_id_error: Option<KeyProviderError>,
    active_error: Option<KeyProviderError>,
}

impl KeyProvider for BoundaryFailingProvider {
    fn active(&self, _scope: &KeyScope) -> Result<KeyLease, KeyProviderError> {
        match self.active_error {
            Some(error) => Err(error),
            None => Ok(Provider::lease(NEW_KEY_ID, 2, NEW_SECRET)),
        }
    }

    fn by_id(
        &self,
        _scope: &KeyScope,
        _key_id: KeyId,
        _generation: KeyGeneration,
    ) -> Result<KeyLease, KeyProviderError> {
        match self.by_id_error {
            Some(error) => Err(error),
            None => Ok(Provider::lease(OLD_KEY_ID, 1, OLD_SECRET)),
        }
    }
}

struct CountingActiveProvider {
    active_calls: Arc<AtomicUsize>,
}

impl KeyProvider for CountingActiveProvider {
    fn active(&self, _scope: &KeyScope) -> Result<KeyLease, KeyProviderError> {
        let _previous = self.active_calls.fetch_add(1, Ordering::SeqCst);
        Err(KeyProviderError::Failure { retryable: true })
    }

    fn by_id(
        &self,
        _scope: &KeyScope,
        _key_id: KeyId,
        _generation: KeyGeneration,
    ) -> Result<KeyLease, KeyProviderError> {
        Ok(Provider::lease(OLD_KEY_ID, 1, OLD_SECRET))
    }
}

fn source_scope() -> KeyScope {
    KeyScope::new(SpaceId::new(SPACE), PurposeId::new(SOURCE_PURPOSE))
}

fn target_scope() -> KeyScope {
    KeyScope::new(SpaceId::new(SPACE), PurposeId::new(TARGET_PURPOSE))
}

fn source_context() -> StreamContext {
    StreamContext::new(11, b"snapshot generation 11").unwrap()
}

fn target_context() -> StreamContext {
    StreamContext::new(12, b"archive generation 12").unwrap()
}

fn codec(provider: Provider) -> EncryptedStreamCodec<Provider> {
    EncryptedStreamCodec::with_config(provider, StreamConfig::new(8).unwrap())
}

fn old_stream(plaintext: &[u8]) -> Vec<u8> {
    codec(Provider::old_only())
        .seal(&source_scope(), &source_context(), plaintext)
        .unwrap()
        .into_bytes()
}

#[test]
fn rotates_old_stream_to_exact_active_key_with_bounded_orchestration() {
    let plaintext = b"durable memory spans several authenticated frames";
    let mut source = Cursor::new(old_stream(plaintext));
    let mut destination = Vec::new();
    let codec = codec(Provider::rotating());

    let outcome = codec
        .rotate_to_active(
            &source_scope(),
            &source_context(),
            &mut source,
            &mut destination,
        )
        .unwrap();

    assert!(outcome.was_resealed());
    assert_eq!(
        outcome.source_key(),
        KeyDescriptor::new(KeyId::new(OLD_KEY_ID), KeyGeneration::new(1))
    );
    assert_eq!(
        outcome.destination_key(),
        KeyDescriptor::new(KeyId::new(NEW_KEY_ID), KeyGeneration::new(2))
    );
    assert!(outcome.destination_completion().is_some());
    assert_eq!(
        outcome.source_completion().plaintext_bytes(),
        plaintext.len() as u64
    );
    assert_eq!(
        outcome.destination_completion().unwrap().plaintext_bytes(),
        plaintext.len() as u64
    );
    let opened = codec
        .open(&source_scope(), &source_context(), &destination)
        .unwrap();
    assert_eq!(opened.as_slice(), plaintext);
}

#[test]
fn migrates_stream_only_to_explicit_destination_scope_and_context() {
    let plaintext = b"migrate this authenticated stream";
    let mut source = Cursor::new(old_stream(plaintext));
    let mut destination = Vec::new();
    let codec = codec(Provider::rotating());

    let outcome = codec
        .migrate(
            &source_scope(),
            &source_context(),
            &target_scope(),
            &target_context(),
            &mut source,
            &mut destination,
        )
        .unwrap();

    assert!(outcome.was_resealed());
    assert_eq!(
        codec
            .open(&target_scope(), &target_context(), &destination)
            .unwrap()
            .as_slice(),
        plaintext
    );
    assert!(
        codec
            .open(&source_scope(), &source_context(), &destination)
            .is_err()
    );
}

#[test]
fn already_current_stream_authenticates_fully_without_touching_destination() {
    let codec = codec(Provider::rotating());
    let current = codec
        .seal(&source_scope(), &source_context(), b"already current")
        .unwrap()
        .into_bytes();
    let mut source = Cursor::new(current);
    let mut destination = Vec::new();

    let outcome = codec
        .rotate_to_active(
            &source_scope(),
            &source_context(),
            &mut source,
            &mut destination,
        )
        .unwrap();

    assert!(!outcome.was_resealed());
    assert!(outcome.destination_completion().is_none());
    assert_eq!(outcome.source_key(), outcome.destination_key());
    assert!(destination.is_empty());
}

#[test]
fn reused_descriptor_with_different_secret_fails_before_destination_io() {
    let mut source = Cursor::new(old_stream(b"descriptor reuse must fail"));
    let mut destination = Vec::new();
    let result = codec(Provider::reused_descriptor()).rotate_to_active(
        &source_scope(),
        &source_context(),
        &mut source,
        &mut destination,
    );

    let error = result.unwrap_err();
    assert_eq!(error.phase(), StreamResealPhase::Policy);
    assert_eq!(error.destination_state(), StreamDestinationState::Untouched);
    assert!(matches!(
        error.cause(),
        crypt_io::storage::StreamError::Cryptographic(CryptError::WrongKey)
    ));
    assert!(destination.is_empty());
}

#[test]
fn reused_master_secret_fails_before_destination_io() {
    let mut source = Cursor::new(old_stream(b"replacement material must be fresh"));
    let mut destination = Vec::new();
    let result = codec(Provider::reused_material_replacement()).rotate_to_active(
        &source_scope(),
        &source_context(),
        &mut source,
        &mut destination,
    );

    let error = result.unwrap_err();
    assert_eq!(error.phase(), StreamResealPhase::Policy);
    assert_eq!(error.destination_state(), StreamDestinationState::Untouched);
    assert!(matches!(
        error.cause(),
        crypt_io::storage::StreamError::Cryptographic(CryptError::KeyMaterialReuse)
    ));
    assert!(destination.is_empty());
}

#[test]
fn cross_scope_migration_allows_explicit_same_master_policy() {
    let plaintext = b"cross-scope master sharing is host policy";
    let mut source = Cursor::new(old_stream(plaintext));
    let mut destination = Vec::new();
    let codec = codec(Provider::reused_material_replacement());

    let outcome = codec
        .migrate(
            &source_scope(),
            &source_context(),
            &target_scope(),
            &target_context(),
            &mut source,
            &mut destination,
        )
        .unwrap();

    assert!(outcome.was_resealed());
    let opened = codec
        .open(&target_scope(), &target_context(), &destination)
        .unwrap();
    assert_eq!(opened.as_slice(), plaintext);
}

#[test]
fn source_and_destination_provider_failures_keep_their_phase_and_type() {
    let mut source = Cursor::new(old_stream(b"provider boundary"));
    let mut destination = Vec::new();
    let source_codec = EncryptedStreamCodec::with_config(
        BoundaryFailingProvider {
            by_id_error: Some(KeyProviderError::AccessDenied),
            active_error: None,
        },
        StreamConfig::new(8).unwrap(),
    );
    let source_error = source_codec
        .rotate_to_active(
            &source_scope(),
            &source_context(),
            &mut source,
            &mut destination,
        )
        .unwrap_err();
    assert_eq!(source_error.phase(), StreamResealPhase::Source);
    assert_eq!(
        source_error.destination_state(),
        StreamDestinationState::Untouched
    );
    assert!(matches!(
        source_error.cause(),
        crypt_io::storage::StreamError::Cryptographic(CryptError::KeyAccessDenied)
    ));

    let mut source = Cursor::new(old_stream(b"provider boundary"));
    let mut destination = Vec::new();
    let destination_codec = EncryptedStreamCodec::with_config(
        BoundaryFailingProvider {
            by_id_error: None,
            active_error: Some(KeyProviderError::Failure { retryable: true }),
        },
        StreamConfig::new(8).unwrap(),
    );
    let destination_error = destination_codec
        .rotate_to_active(
            &source_scope(),
            &source_context(),
            &mut source,
            &mut destination,
        )
        .unwrap_err();
    assert_eq!(destination_error.phase(), StreamResealPhase::Destination);
    assert_eq!(
        destination_error.destination_state(),
        StreamDestinationState::Untouched
    );
    assert!(matches!(
        destination_error.cause(),
        crypt_io::storage::StreamError::Cryptographic(CryptError::KeyProviderFailure {
            retryable: true
        })
    ));
}

#[test]
fn bad_first_frame_is_rejected_before_destination_active_key_lookup() {
    let mut encoded = old_stream(b"authenticate before destination lookup");
    encoded[crypt_io::storage::ENCRYPTED_STREAM_HEADER_LEN
        + crypt_io::storage::ENCRYPTED_STREAM_FRAME_HEADER_LEN] ^= 1;
    let active_calls = Arc::new(AtomicUsize::new(0));
    let codec = EncryptedStreamCodec::with_config(
        CountingActiveProvider {
            active_calls: Arc::clone(&active_calls),
        },
        StreamConfig::new(8).unwrap(),
    );
    let mut source = Cursor::new(encoded);
    let mut destination = Vec::new();

    let error = codec
        .rotate_to_active(
            &source_scope(),
            &source_context(),
            &mut source,
            &mut destination,
        )
        .unwrap_err();

    assert_eq!(error.phase(), StreamResealPhase::Source);
    assert!(matches!(
        error.cause(),
        crypt_io::storage::StreamError::Cryptographic(CryptError::AuthenticationFailed)
    ));
    assert_eq!(active_calls.load(Ordering::SeqCst), 0);
    assert!(destination.is_empty());
}

#[test]
fn same_scope_rotation_rejects_stale_and_equal_generation_replacements() {
    let current = codec(Provider::rotating())
        .seal(&source_scope(), &source_context(), b"generation two")
        .unwrap()
        .into_bytes();
    let mut stale_source = Cursor::new(current);
    let mut stale_destination = Vec::new();
    let stale = codec(Provider::stale_after_rotation())
        .rotate_to_active(
            &source_scope(),
            &source_context(),
            &mut stale_source,
            &mut stale_destination,
        )
        .unwrap_err();
    assert!(matches!(
        stale.cause(),
        crypt_io::storage::StreamError::Cryptographic(CryptError::KeyDowngrade)
    ));
    assert_eq!(stale.destination_state(), StreamDestinationState::Untouched);

    let mut equal_source = Cursor::new(old_stream(b"generation one"));
    let mut equal_destination = Vec::new();
    let equal = codec(Provider::equal_generation_replacement())
        .rotate_to_active(
            &source_scope(),
            &source_context(),
            &mut equal_source,
            &mut equal_destination,
        )
        .unwrap_err();
    assert!(matches!(
        equal.cause(),
        crypt_io::storage::StreamError::Cryptographic(CryptError::KeyDowngrade)
    ));
    assert!(equal_destination.is_empty());
}

#[test]
fn late_source_authentication_failure_leaves_destination_discard_only() {
    let mut encoded = old_stream(b"first frames authenticate before a late final failure");
    let last = encoded.len() - 1;
    encoded[last] ^= 1;
    let mut source = Cursor::new(encoded);
    let mut destination = Vec::new();
    let codec = codec(Provider::rotating());

    let error = codec
        .rotate_to_active(
            &source_scope(),
            &source_context(),
            &mut source,
            &mut destination,
        )
        .unwrap_err();

    assert_eq!(error.phase(), StreamResealPhase::Source);
    assert!(matches!(
        error.destination_state(),
        StreamDestinationState::DiscardOnly { .. }
    ));
    assert!(matches!(
        error.cause(),
        crypt_io::storage::StreamError::Cryptographic(CryptError::AuthenticationFailed)
    ));
    assert!(!destination.is_empty());
    assert!(
        codec
            .open(&source_scope(), &source_context(), &destination)
            .is_err()
    );
}

#[test]
fn missing_final_and_trailing_data_never_finalize_the_destination() {
    let complete = old_stream(b"several frames precede source completion");
    let mut missing_final = complete.clone();
    missing_final.truncate(missing_final.len() - 64);
    let mut trailing_data = complete;
    trailing_data.push(0xA5);

    for (encoded, expects_trailing) in [(missing_final, false), (trailing_data, true)] {
        let mut source = Cursor::new(encoded);
        let mut destination = Vec::new();
        let codec = codec(Provider::rotating());
        let error = codec
            .rotate_to_active(
                &source_scope(),
                &source_context(),
                &mut source,
                &mut destination,
            )
            .unwrap_err();

        assert_eq!(error.phase(), StreamResealPhase::Source);
        assert!(matches!(
            error.destination_state(),
            StreamDestinationState::DiscardOnly { .. }
        ));
        if expects_trailing {
            assert!(matches!(
                error.cause(),
                crypt_io::storage::StreamError::Cryptographic(CryptError::TrailingData)
            ));
        } else {
            assert!(matches!(
                error.cause(),
                crypt_io::storage::StreamError::Cryptographic(CryptError::MissingFinalFrame)
            ));
        }
        assert!(!destination.is_empty());
        assert!(
            codec
                .open(&source_scope(), &source_context(), &destination)
                .is_err()
        );
    }
}

struct PartialFailingSink {
    bytes: Vec<u8>,
    remaining_before_failure: usize,
}

impl Write for PartialFailingSink {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if self.remaining_before_failure == 0 {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "sensitive partial-write detail",
            ));
        }
        let written = input.len().min(self.remaining_before_failure);
        self.bytes.extend_from_slice(&input[..written]);
        self.remaining_before_failure -= written;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn destination_partial_write_is_typed_and_discard_only() {
    let mut source = Cursor::new(old_stream(b"partial destination frame"));
    let mut destination = PartialFailingSink {
        bytes: Vec::new(),
        remaining_before_failure: crypt_io::storage::ENCRYPTED_STREAM_HEADER_LEN + 3,
    };
    let error = codec(Provider::rotating())
        .rotate_to_active(
            &source_scope(),
            &source_context(),
            &mut source,
            &mut destination,
        )
        .unwrap_err();

    assert_eq!(error.phase(), StreamResealPhase::Destination);
    assert!(matches!(
        error.destination_state(),
        StreamDestinationState::DiscardOnly { .. }
    ));
    assert!(matches!(
        error.cause(),
        crypt_io::storage::StreamError::Io(_)
    ));
    assert!(destination.bytes.len() > crypt_io::storage::ENCRYPTED_STREAM_HEADER_LEN);
}

#[derive(Clone, Copy)]
enum RejectedWrite {
    Header,
    FinalFrame,
}

struct SelectiveFailingSink {
    reject: RejectedWrite,
    bytes: Vec<u8>,
}

impl Write for SelectiveFailingSink {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let is_header = input.len() == crypt_io::storage::ENCRYPTED_STREAM_HEADER_LEN;
        let is_final = input.len() == crypt_io::storage::ENCRYPTED_STREAM_FRAME_HEADER_LEN + 16;
        if matches!(self.reject, RejectedWrite::Header) && is_header
            || matches!(self.reject, RejectedWrite::FinalFrame) && is_final
        {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "sensitive selected-write detail",
            ));
        }
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn destination_header_and_final_write_failures_never_return_completion() {
    for reject in [RejectedWrite::Header, RejectedWrite::FinalFrame] {
        let encoded = old_stream(b"nonempty data frame before the final frame");
        let encoded_len = encoded.len() as u64;
        let mut source = Cursor::new(encoded);
        let mut destination = SelectiveFailingSink {
            reject,
            bytes: Vec::new(),
        };
        let error = codec(Provider::rotating())
            .rotate_to_active(
                &source_scope(),
                &source_context(),
                &mut source,
                &mut destination,
            )
            .unwrap_err();

        assert_eq!(error.phase(), StreamResealPhase::Destination);
        assert!(matches!(
            error.destination_state(),
            StreamDestinationState::DiscardOnly { .. }
        ));
        assert!(matches!(
            error.cause(),
            crypt_io::storage::StreamError::Io(_)
        ));
        if matches!(reject, RejectedWrite::FinalFrame) {
            assert_eq!(source.position(), encoded_len);
            assert!(!destination.bytes.is_empty());
        }
    }
}

#[derive(Default)]
struct FlushFailingSink {
    bytes: Vec<u8>,
}

impl Write for FlushFailingSink {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "sensitive backend detail",
        ))
    }
}

#[test]
fn destination_flush_failure_returns_no_success_token_and_requires_discard() {
    let mut source = Cursor::new(old_stream(b"destination flush must succeed"));
    let mut destination = FlushFailingSink::default();

    let error = codec(Provider::rotating())
        .rotate_to_active(
            &source_scope(),
            &source_context(),
            &mut source,
            &mut destination,
        )
        .unwrap_err();

    assert_eq!(error.phase(), StreamResealPhase::Destination);
    assert!(matches!(
        error.destination_state(),
        StreamDestinationState::DiscardOnly { .. }
    ));
    assert!(matches!(
        error.cause(),
        crypt_io::storage::StreamError::Io(_)
    ));
    assert!(!destination.bytes.is_empty());
}

struct EofProbeSource {
    inner: Cursor<Vec<u8>>,
    exact_eof_seen: Arc<AtomicBool>,
}

impl Read for EofProbeSource {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(output)?;
        if read == 0 {
            self.exact_eof_seen.store(true, Ordering::SeqCst);
        }
        Ok(read)
    }
}

struct OrderingProbeSink {
    exact_eof_seen: Arc<AtomicBool>,
    saw_write_before_eof: bool,
    bytes: Vec<u8>,
}

impl Write for OrderingProbeSink {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if !self.exact_eof_seen.load(Ordering::SeqCst) {
            self.saw_write_before_eof = true;
        }
        if input.len() == crypt_io::storage::ENCRYPTED_STREAM_FRAME_HEADER_LEN + 16 {
            assert!(self.exact_eof_seen.load(Ordering::SeqCst));
        }
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        assert!(self.exact_eof_seen.load(Ordering::SeqCst));
        Ok(())
    }
}

#[test]
fn streams_frames_early_but_writes_final_only_after_source_exact_eof() {
    let exact_eof_seen = Arc::new(AtomicBool::new(false));
    let mut source = EofProbeSource {
        inner: Cursor::new(old_stream(
            b"interleave several frames without buffering all",
        )),
        exact_eof_seen: Arc::clone(&exact_eof_seen),
    };
    let mut destination = OrderingProbeSink {
        exact_eof_seen,
        saw_write_before_eof: false,
        bytes: Vec::new(),
    };

    let outcome = codec(Provider::rotating())
        .rotate_to_active(
            &source_scope(),
            &source_context(),
            &mut source,
            &mut destination,
        )
        .unwrap();

    assert!(outcome.was_resealed());
    assert!(destination.saw_write_before_eof);
}

#[test]
fn rotates_empty_authenticated_stream() {
    let mut source = Cursor::new(old_stream(b""));
    let mut destination = Vec::new();
    let codec = codec(Provider::rotating());

    let outcome = codec
        .rotate_to_active(
            &source_scope(),
            &source_context(),
            &mut source,
            &mut destination,
        )
        .unwrap();

    assert_eq!(outcome.source_completion().data_frames(), 0);
    assert_eq!(outcome.destination_completion().unwrap().data_frames(), 0);
    let mut opened = Cursor::new(destination);
    let context = source_context();
    let mut reader = codec.reader(&mut opened, source_scope(), &context);
    assert!(matches!(
        reader.read_next().unwrap(),
        StreamRead::Complete(_)
    ));
}
