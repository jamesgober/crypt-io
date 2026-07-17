//! Contract tests for bounded incremental encrypted-stream I/O.

#![cfg(feature = "storage-v1")]
#![allow(clippy::unwrap_used)]

use core::ops::Range;
use std::{
    error::Error as _,
    io::{self, Cursor, Read, Write},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use crypt_io::storage::{
    CryptError, ENCRYPTED_STREAM_FRAME_HEADER_LEN, ENCRYPTED_STREAM_HEADER_LEN,
    EncryptedStreamCodec, KeyGeneration, KeyId, KeyLease, KeyProvider, KeyProviderError, KeyScope,
    PrefixRecoveryError, PurposeId, SecretKey32, SpaceId, StreamConfig, StreamContext, StreamError,
    StreamIoOperation, StreamRead,
};
use error_forge::ForgeError;

const KEY_ID_BYTES: [u8; 16] = *b"stream-key-v0001";
const PURPOSE_BYTES: [u8; 16] = *b"snapshot-strm-v1";
const SPACE_BYTES: [u8; 32] = [0x71; 32];
const MASTER_KEY_BYTES: [u8; 32] = [0xC4; 32];
const GENERATION: u32 = 9;
const CONTEXT: &[u8] = b"snapshot generation 0000000000000009";
const TAG_LEN: usize = 16;

#[derive(Clone, Copy)]
struct StaticProvider;

impl StaticProvider {
    fn lease() -> KeyLease {
        KeyLease::new(
            KeyId::new(KEY_ID_BYTES),
            KeyGeneration::new(GENERATION),
            SecretKey32::new(MASTER_KEY_BYTES),
        )
    }
}

impl KeyProvider for StaticProvider {
    fn active(&self, _scope: &KeyScope) -> Result<KeyLease, KeyProviderError> {
        Ok(Self::lease())
    }

    fn by_id(
        &self,
        _scope: &KeyScope,
        key_id: KeyId,
        generation: KeyGeneration,
    ) -> Result<KeyLease, KeyProviderError> {
        if key_id != KeyId::new(KEY_ID_BYTES) || generation != KeyGeneration::new(GENERATION) {
            return Err(KeyProviderError::Unavailable);
        }
        Ok(Self::lease())
    }
}

#[derive(Clone)]
struct CountingProvider {
    lookups: Arc<AtomicUsize>,
}

impl KeyProvider for CountingProvider {
    fn active(&self, _scope: &KeyScope) -> Result<KeyLease, KeyProviderError> {
        Ok(StaticProvider::lease())
    }

    fn by_id(
        &self,
        _scope: &KeyScope,
        _key_id: KeyId,
        _generation: KeyGeneration,
    ) -> Result<KeyLease, KeyProviderError> {
        let _previous = self.lookups.fetch_add(1, Ordering::SeqCst);
        Ok(StaticProvider::lease())
    }
}

#[derive(Clone, Copy)]
struct RetryableFailureProvider;

impl KeyProvider for RetryableFailureProvider {
    fn active(&self, _scope: &KeyScope) -> Result<KeyLease, KeyProviderError> {
        Err(KeyProviderError::Failure { retryable: true })
    }

    fn by_id(
        &self,
        _scope: &KeyScope,
        _key_id: KeyId,
        _generation: KeyGeneration,
    ) -> Result<KeyLease, KeyProviderError> {
        Err(KeyProviderError::Failure { retryable: true })
    }
}

fn scope() -> KeyScope {
    KeyScope::new(SpaceId::new(SPACE_BYTES), PurposeId::new(PURPOSE_BYTES))
}

fn context() -> StreamContext {
    StreamContext::new(41, CONTEXT).unwrap()
}

fn codec(frame_len: u32) -> EncryptedStreamCodec<StaticProvider> {
    EncryptedStreamCodec::with_config(StaticProvider, StreamConfig::new(frame_len).unwrap())
}

fn frame_ranges(encoded: &[u8]) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    let mut offset = ENCRYPTED_STREAM_HEADER_LEN;
    while offset < encoded.len() {
        let length = u32::from_be_bytes([
            encoded[offset + 8],
            encoded[offset + 9],
            encoded[offset + 10],
            encoded[offset + 11],
        ]) as usize;
        let end = offset + ENCRYPTED_STREAM_FRAME_HEADER_LEN + length + TAG_LEN;
        ranges.push(offset..end);
        offset = end;
    }
    ranges
}

fn read_all_incrementally(encoded: &[u8], frame_len: u32) -> Vec<u8> {
    let codec = codec(frame_len);
    let expected_context = context();
    let mut source = Cursor::new(encoded);
    let mut reader = codec.reader(&mut source, scope(), &expected_context);
    let metadata = reader.begin().unwrap();
    assert_eq!(metadata.max_frame_plaintext_len(), frame_len);

    let mut plaintext = Vec::new();
    loop {
        match reader.read_next().unwrap() {
            StreamRead::Data(frame) => plaintext.extend_from_slice(frame.plaintext()),
            StreamRead::Complete(completion) => {
                assert_eq!(completion.plaintext_bytes(), plaintext.len() as u64);
                assert_eq!(completion.encoded_bytes(), encoded.len() as u64);
                return plaintext;
            }
        }
    }
}

#[test]
fn test_incremental_writer_and_buffered_codec_share_the_v1_wire_contract() {
    let codec = codec(8);
    let expected_context = context();
    let mut encoded = Vec::new();
    {
        let mut writer = codec
            .writer(&mut encoded, &scope(), &expected_context)
            .unwrap();
        assert_eq!(writer.progress().data_frames(), 0);
        assert_eq!(writer.write_frame(b"frame-01").unwrap().data_frames(), 1);
        assert_eq!(writer.write_frame(b"tail").unwrap().data_frames(), 2);
        let completion = writer.finish().unwrap();
        assert_eq!(completion.data_frames(), 2);
        assert_eq!(completion.plaintext_bytes(), 12);
    }

    let opened = codec.open(&scope(), &expected_context, &encoded).unwrap();
    assert_eq!(opened.as_slice(), b"frame-01tail");
    assert_eq!(read_all_incrementally(&encoded, 8), b"frame-01tail");
}

#[test]
fn test_incremental_reader_accepts_buffered_empty_and_boundary_streams() {
    for plaintext_len in [0, 1, 7, 8, 9, 16, 17] {
        let plaintext = vec![0x5A; plaintext_len];
        let encoded = codec(8)
            .seal(&scope(), &context(), &plaintext)
            .unwrap()
            .into_bytes();

        assert_eq!(read_all_incrementally(&encoded, 8), plaintext);
    }
}

#[test]
fn test_reader_header_only_does_not_lookup_a_historical_key() {
    let encoded = codec(8)
        .seal(&scope(), &context(), b"one frame")
        .unwrap()
        .into_bytes();
    let lookups = Arc::new(AtomicUsize::new(0));
    let provider = CountingProvider {
        lookups: Arc::clone(&lookups),
    };
    let codec = EncryptedStreamCodec::with_config(provider, StreamConfig::new(8).unwrap());
    let expected_context = context();
    let mut source = Cursor::new(&encoded[..ENCRYPTED_STREAM_HEADER_LEN]);
    let mut reader = codec.reader(&mut source, scope(), &expected_context);

    assert!(matches!(
        reader.begin(),
        Err(StreamError::Cryptographic(CryptError::MissingFinalFrame))
    ));
    assert_eq!(lookups.load(Ordering::SeqCst), 0);
    assert!(matches!(
        reader.recover_authenticated_prefix(),
        Err(PrefixRecoveryError::NoAuthenticatedDataFrames)
    ));
}

#[test]
fn test_reader_never_reports_a_truncated_prefix_as_complete() {
    let encoded = codec(8)
        .seal(&scope(), &context(), b"two authenticated frames")
        .unwrap()
        .into_bytes();
    let ranges = frame_ranges(&encoded);
    let truncated = &encoded[..ranges.last().unwrap().start];
    let codec = codec(8);
    let expected_context = context();
    let mut source = Cursor::new(truncated);
    let mut reader = codec.reader(&mut source, scope(), &expected_context);
    let _metadata = reader.begin().unwrap();

    let mut returned_frames = 0_u64;
    loop {
        match reader.read_next() {
            Ok(StreamRead::Data(_frame)) => returned_frames += 1,
            Ok(StreamRead::Complete(_completion)) => panic!("truncated stream reported complete"),
            Err(StreamError::Cryptographic(CryptError::MissingFinalFrame)) => break,
            Err(error) => panic!("unexpected error: {error}"),
        }
    }

    let prefix = reader.recover_authenticated_prefix().unwrap();
    assert_eq!(prefix.data_frames(), returned_frames);
    assert_eq!(prefix.safe_encoded_boundary(), truncated.len() as u64);
}

#[test]
fn test_reader_rejects_prefix_recovery_after_later_authentication_failure() {
    let mut encoded = codec(8)
        .seal(&scope(), &context(), b"two-frame-payload")
        .unwrap()
        .into_bytes();
    let ranges = frame_ranges(&encoded);
    encoded[ranges[1].start + ENCRYPTED_STREAM_FRAME_HEADER_LEN] ^= 1;
    let codec = codec(8);
    let expected_context = context();
    let mut source = Cursor::new(encoded);
    let mut reader = codec.reader(&mut source, scope(), &expected_context);
    let _metadata = reader.begin().unwrap();
    assert!(matches!(reader.read_next(), Ok(StreamRead::Data(_))));
    assert!(matches!(
        reader.read_next(),
        Err(StreamError::Cryptographic(CryptError::AuthenticationFailed))
    ));
    assert!(matches!(
        reader.recover_authenticated_prefix(),
        Err(PrefixRecoveryError::FailureNotRecoverable)
    ));
    assert!(matches!(
        reader.read_next(),
        Err(StreamError::Faulted { .. })
    ));
}

#[test]
fn test_reader_first_frame_authentication_failure_returns_no_event_and_faults() {
    let mut encoded = codec(8)
        .seal(&scope(), &context(), b"first-frame")
        .unwrap()
        .into_bytes();
    let first_frame = frame_ranges(&encoded)[0].clone();
    encoded[first_frame.start + ENCRYPTED_STREAM_FRAME_HEADER_LEN] ^= 1;
    let codec = codec(8);
    let expected_context = context();
    let mut source = Cursor::new(encoded);
    let mut reader = codec.reader(&mut source, scope(), &expected_context);

    assert!(matches!(
        reader.begin(),
        Err(StreamError::Cryptographic(CryptError::AuthenticationFailed))
    ));
    assert!(matches!(
        reader.recover_authenticated_prefix(),
        Err(PrefixRecoveryError::FailureNotRecoverable)
    ));
    assert!(matches!(
        reader.read_next(),
        Err(StreamError::Faulted { .. })
    ));
}

#[test]
fn test_reader_wrong_context_returns_no_event_and_disallows_recovery() {
    let encoded = codec(8)
        .seal(&scope(), &context(), b"context-bound")
        .unwrap()
        .into_bytes();
    let codec = codec(8);
    let wrong_context = StreamContext::new(41, b"wrong context").unwrap();
    let mut source = Cursor::new(encoded);
    let mut reader = codec.reader(&mut source, scope(), &wrong_context);

    assert!(matches!(
        reader.begin(),
        Err(StreamError::Cryptographic(CryptError::ContextMismatch))
    ));
    assert!(matches!(
        reader.recover_authenticated_prefix(),
        Err(PrefixRecoveryError::FailureNotRecoverable)
    ));
}

#[test]
fn test_reader_trailing_data_never_returns_completion() {
    let mut encoded = codec(8)
        .seal(&scope(), &context(), b"payload")
        .unwrap()
        .into_bytes();
    encoded.push(0xA5);
    let codec = codec(8);
    let expected_context = context();
    let mut source = Cursor::new(encoded);
    let mut reader = codec.reader(&mut source, scope(), &expected_context);
    let _metadata = reader.begin().unwrap();
    assert!(matches!(reader.read_next(), Ok(StreamRead::Data(_))));
    assert!(matches!(
        reader.read_next(),
        Err(StreamError::Cryptographic(CryptError::TrailingData))
    ));
    assert!(matches!(
        reader.recover_authenticated_prefix(),
        Err(PrefixRecoveryError::FailureNotRecoverable)
    ));
}

#[test]
fn test_reader_partial_first_frame_avoids_historical_key_lookup() {
    let encoded = codec(8)
        .seal(&scope(), &context(), b"one frame")
        .unwrap()
        .into_bytes();
    let first_frame = frame_ranges(&encoded)[0].clone();
    let truncated_len = first_frame.start + ENCRYPTED_STREAM_FRAME_HEADER_LEN + 2;
    let lookups = Arc::new(AtomicUsize::new(0));
    let provider = CountingProvider {
        lookups: Arc::clone(&lookups),
    };
    let codec = EncryptedStreamCodec::with_config(provider, StreamConfig::new(8).unwrap());
    let expected_context = context();
    let mut source = Cursor::new(&encoded[..truncated_len]);
    let mut reader = codec.reader(&mut source, scope(), &expected_context);

    assert!(matches!(
        reader.begin(),
        Err(StreamError::Io(ref error))
            if error.operation() == StreamIoOperation::ReadFrameBody
                && error.source_error().kind() == io::ErrorKind::UnexpectedEof
    ));
    assert_eq!(lookups.load(Ordering::SeqCst), 0);
}

#[test]
fn test_reader_rejects_invalid_first_frame_before_historical_key_lookup() {
    let mut encoded = codec(8)
        .seal(&scope(), &context(), b"one frame")
        .unwrap()
        .into_bytes();
    encoded[ENCRYPTED_STREAM_HEADER_LEN..ENCRYPTED_STREAM_HEADER_LEN + 8]
        .copy_from_slice(&1_u64.to_be_bytes());
    let lookups = Arc::new(AtomicUsize::new(0));
    let provider = CountingProvider {
        lookups: Arc::clone(&lookups),
    };
    let codec = EncryptedStreamCodec::with_config(provider, StreamConfig::new(8).unwrap());
    let expected_context = context();
    let mut source = Cursor::new(encoded);
    let mut reader = codec.reader(&mut source, scope(), &expected_context);

    assert!(matches!(
        reader.begin(),
        Err(StreamError::Cryptographic(CryptError::SequenceMismatch))
    ));
    assert_eq!(lookups.load(Ordering::SeqCst), 0);
}

#[test]
fn test_reader_latched_provider_failure_is_not_reported_retryable() {
    let encoded = codec(8)
        .seal(&scope(), &context(), b"payload")
        .unwrap()
        .into_bytes();
    let codec =
        EncryptedStreamCodec::with_config(RetryableFailureProvider, StreamConfig::new(8).unwrap());
    let expected_context = context();
    let mut source = Cursor::new(encoded);
    let mut reader = codec.reader(&mut source, scope(), &expected_context);

    let error = reader.begin().unwrap_err();
    assert!(matches!(
        error,
        StreamError::Cryptographic(CryptError::KeyProviderFailure { retryable: true })
    ));
    assert!(!error.is_retryable());
    assert!(matches!(reader.begin(), Err(StreamError::Faulted { .. })));
}

#[derive(Debug)]
struct FailAfterWriter {
    bytes: Vec<u8>,
    remaining: usize,
    flush_fails: bool,
}

impl Write for FailAfterWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "injected write failure",
            ));
        }
        let written = self.remaining.min(buffer.len());
        self.bytes.extend_from_slice(&buffer[..written]);
        self.remaining -= written;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.flush_fails {
            return Err(io::Error::other("injected flush failure"));
        }
        Ok(())
    }
}

#[test]
fn test_writer_partial_frame_failure_preserves_source_and_latches_fault() {
    let codec = codec(8);
    let expected_context = context();
    let mut sink = FailAfterWriter {
        bytes: Vec::new(),
        remaining: ENCRYPTED_STREAM_HEADER_LEN + 7,
        flush_fails: false,
    };
    let mut writer = codec
        .writer(&mut sink, &scope(), &expected_context)
        .unwrap();

    let error = writer.write_frame(b"12345678").unwrap_err();
    assert!(!format!("{error:?}").contains("injected write failure"));
    assert!(!error.to_string().contains("injected write failure"));
    let StreamError::Io(io_error) = error else {
        panic!("expected a source-preserving I/O error");
    };
    assert_eq!(io_error.operation(), StreamIoOperation::WriteFrame);
    assert_eq!(io_error.source_error().kind(), io::ErrorKind::BrokenPipe);
    assert!(io_error.source().is_some());
    assert_eq!(
        io_error.progress().safe_encoded_boundary(),
        ENCRYPTED_STREAM_HEADER_LEN as u64
    );

    let bytes_after_failure = writer.progress().safe_encoded_boundary();
    assert!(matches!(
        writer.write_frame(b"retry"),
        Err(StreamError::Faulted { .. })
    ));
    assert_eq!(
        writer.progress().safe_encoded_boundary(),
        bytes_after_failure
    );
}

#[test]
fn test_writer_partial_header_failure_reports_zero_boundary_and_latches_fault() {
    let codec = codec(8);
    let expected_context = context();
    let mut sink = FailAfterWriter {
        bytes: Vec::new(),
        remaining: 7,
        flush_fails: false,
    };
    let mut writer = codec
        .writer(&mut sink, &scope(), &expected_context)
        .unwrap();

    let error = writer.write_frame(b"12345678").unwrap_err();
    let StreamError::Io(io_error) = error else {
        panic!("expected a source-preserving I/O error");
    };
    assert_eq!(io_error.operation(), StreamIoOperation::WriteHeader);
    assert_eq!(io_error.progress().safe_encoded_boundary(), 0);
    assert!(matches!(
        writer.write_frame(b"retry"),
        Err(StreamError::Faulted { .. })
    ));
}

#[derive(Debug)]
struct PartialOnCallWriter {
    bytes: Vec<u8>,
    writes: usize,
    partial_on: usize,
    failed: bool,
}

impl Write for PartialOnCallWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.failed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "injected write failure",
            ));
        }
        self.writes += 1;
        if self.writes == self.partial_on {
            let written = 3.min(buffer.len());
            self.bytes.extend_from_slice(&buffer[..written]);
            self.failed = true;
            return Ok(written);
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn test_writer_partial_final_frame_never_returns_completion_and_latches_fault() {
    let codec = codec(8);
    let expected_context = context();
    let mut sink = PartialOnCallWriter {
        bytes: Vec::new(),
        writes: 0,
        partial_on: 3,
        failed: false,
    };
    let mut writer = codec
        .writer(&mut sink, &scope(), &expected_context)
        .unwrap();
    let progress = writer.write_frame(b"payload").unwrap();

    let error = writer.finish().unwrap_err();
    let StreamError::Io(io_error) = error else {
        panic!("expected a source-preserving I/O error");
    };
    assert_eq!(io_error.operation(), StreamIoOperation::WriteFrame);
    assert_eq!(io_error.progress(), progress);
    assert!(matches!(writer.finish(), Err(StreamError::Faulted { .. })));
}

#[test]
fn test_writer_flush_failure_never_returns_completion_and_latches_fault() {
    let codec = codec(8);
    let expected_context = context();
    let mut sink = FailAfterWriter {
        bytes: Vec::new(),
        remaining: usize::MAX,
        flush_fails: true,
    };
    let mut writer = codec
        .writer(&mut sink, &scope(), &expected_context)
        .unwrap();
    let _progress = writer.write_frame(b"payload").unwrap();

    assert!(matches!(
        writer.finish(),
        Err(StreamError::Io(ref error)) if error.operation() == StreamIoOperation::Flush
    ));
    assert!(matches!(writer.finish(), Err(StreamError::Faulted { .. })));
}

struct ErroringReader<R> {
    inner: R,
    remaining: usize,
    error_kind: io::ErrorKind,
}

impl<R: Read> Read for ErroringReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::new(self.error_kind, "injected read failure"));
        }
        let limit = self.remaining.min(buffer.len());
        let read = self.inner.read(&mut buffer[..limit])?;
        self.remaining -= read;
        Ok(read)
    }
}

#[test]
fn test_reader_non_eof_io_failure_preserves_source_and_rejects_recovery() {
    let encoded = codec(8)
        .seal(&scope(), &context(), b"payload")
        .unwrap()
        .into_bytes();
    let source = Cursor::new(encoded);
    let mut source = ErroringReader {
        inner: source,
        remaining: ENCRYPTED_STREAM_HEADER_LEN + ENCRYPTED_STREAM_FRAME_HEADER_LEN + 2,
        error_kind: io::ErrorKind::ConnectionReset,
    };
    let codec = codec(8);
    let expected_context = context();
    let mut reader = codec.reader(&mut source, scope(), &expected_context);

    let error = reader.begin().unwrap_err();
    let StreamError::Io(io_error) = error else {
        panic!("expected a source-preserving I/O error");
    };
    assert_eq!(io_error.operation(), StreamIoOperation::ReadFrameBody);
    assert_eq!(
        io_error.source_error().kind(),
        io::ErrorKind::ConnectionReset
    );
    assert!(matches!(
        reader.recover_authenticated_prefix(),
        Err(PrefixRecoveryError::FailureNotRecoverable)
    ));
    assert!(matches!(
        reader.read_next(),
        Err(StreamError::Faulted { .. })
    ));
}

#[test]
fn test_reader_direct_unexpected_eof_preserves_source_and_allows_prior_prefix() {
    let encoded = codec(8)
        .seal(&scope(), &context(), b"two-frame-payload")
        .unwrap()
        .into_bytes();
    let first_frame_end = frame_ranges(&encoded)[0].end;
    let source = Cursor::new(encoded);
    let mut source = ErroringReader {
        inner: source,
        remaining: first_frame_end,
        error_kind: io::ErrorKind::UnexpectedEof,
    };
    let codec = codec(8);
    let expected_context = context();
    let mut reader = codec.reader(&mut source, scope(), &expected_context);
    let _metadata = reader.begin().unwrap();
    assert!(matches!(reader.read_next(), Ok(StreamRead::Data(_))));

    let error = reader.read_next().unwrap_err();
    let StreamError::Io(io_error) = error else {
        panic!("expected the original unexpected-EOF error");
    };
    assert_eq!(io_error.operation(), StreamIoOperation::ReadFrameHeader);
    assert_eq!(io_error.source_error().kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(
        reader.recover_authenticated_prefix().unwrap().data_frames(),
        1
    );
}

#[test]
fn test_reader_final_probe_unexpected_eof_denies_completion_but_allows_prefix() {
    let encoded = codec(8)
        .seal(&scope(), &context(), b"payload")
        .unwrap()
        .into_bytes();
    let encoded_len = encoded.len();
    let source = Cursor::new(encoded);
    let mut source = ErroringReader {
        inner: source,
        remaining: encoded_len,
        error_kind: io::ErrorKind::UnexpectedEof,
    };
    let codec = codec(8);
    let expected_context = context();
    let mut reader = codec.reader(&mut source, scope(), &expected_context);
    let _metadata = reader.begin().unwrap();
    assert!(matches!(reader.read_next(), Ok(StreamRead::Data(_))));

    let error = reader.read_next().unwrap_err();
    let StreamError::Io(io_error) = error else {
        panic!("expected the original final-probe unexpected-EOF error");
    };
    assert_eq!(io_error.operation(), StreamIoOperation::VerifyEnd);
    assert_eq!(io_error.source_error().kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(
        reader.recover_authenticated_prefix().unwrap().data_frames(),
        1
    );
}

#[test]
fn test_reader_mid_frame_eof_exposes_only_the_prior_authenticated_prefix() {
    let encoded = codec(8)
        .seal(&scope(), &context(), b"two-frame-payload")
        .unwrap()
        .into_bytes();
    let ranges = frame_ranges(&encoded);
    let truncated_len = ranges[1].start + ENCRYPTED_STREAM_FRAME_HEADER_LEN + 2;
    let codec = codec(8);
    let expected_context = context();
    let mut source = Cursor::new(&encoded[..truncated_len]);
    let mut reader = codec.reader(&mut source, scope(), &expected_context);
    let _metadata = reader.begin().unwrap();
    assert!(matches!(reader.read_next(), Ok(StreamRead::Data(_))));

    let error = reader.read_next().unwrap_err();
    let StreamError::Io(io_error) = error else {
        panic!("expected an unexpected-EOF I/O error");
    };
    assert_eq!(io_error.operation(), StreamIoOperation::ReadFrameBody);
    assert_eq!(io_error.source_error().kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(
        reader.recover_authenticated_prefix().unwrap().data_frames(),
        1
    );
}
