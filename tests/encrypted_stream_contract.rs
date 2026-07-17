//! Contract tests for the version-one chunked encrypted-stream format.

#![cfg(feature = "storage-v1")]
#![allow(clippy::unwrap_used)]

use core::ops::Range;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering as AtomicOrdering},
};

use crypt_io::storage::{
    CryptError, ENCRYPTED_STREAM_FRAME_HEADER_LEN, ENCRYPTED_STREAM_HEADER_LEN,
    ENCRYPTED_STREAM_MAGIC, EncryptedStreamCodec, KeyGeneration, KeyId, KeyLease, KeyProvider,
    KeyProviderError, KeyScope, MAX_BUFFERED_STREAM_PLAINTEXT_LEN, MAX_STREAM_FRAME_PLAINTEXT_LEN,
    PurposeId, SecretKey32, SpaceId, StreamConfig, StreamContext,
};
use proptest::prelude::*;
use sha2::{Digest, Sha256};

const KEY_ID_BYTES: [u8; 16] = *b"stream-key-v0001";
const PURPOSE_BYTES: [u8; 16] = *b"snapshot-strm-v1";
const SPACE_BYTES: [u8; 32] = [0x71; 32];
const MASTER_KEY_BYTES: [u8; 32] = [0xC4; 32];
const GENERATION: u32 = 9;
const LOGICAL_SEQUENCE: u64 = 9;
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
        let _previous = self.lookups.fetch_add(1, AtomicOrdering::SeqCst);
        Ok(StaticProvider::lease())
    }
}

fn scope() -> KeyScope {
    KeyScope::new(SpaceId::new(SPACE_BYTES), PurposeId::new(PURPOSE_BYTES))
}

fn context() -> StreamContext {
    StreamContext::new(LOGICAL_SEQUENCE, CONTEXT).unwrap()
}

fn codec(frame_len: u32) -> EncryptedStreamCodec<StaticProvider> {
    EncryptedStreamCodec::with_config(StaticProvider, StreamConfig::new(frame_len).unwrap())
}

fn seal(frame_len: u32, plaintext: &[u8]) -> Vec<u8> {
    codec(frame_len)
        .seal(&scope(), &context(), plaintext)
        .unwrap()
        .into_bytes()
}

fn unkeyed_context_digest() -> [u8; 32] {
    let context_len = u64::try_from(CONTEXT.len()).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(b"crypt-io/stream-context/v1\0");
    hasher.update(LOGICAL_SEQUENCE.to_be_bytes());
    hasher.update(context_len.to_be_bytes());
    hasher.update(CONTEXT);
    let output = hasher.finalize();
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(&output);
    digest
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

#[test]
fn empty_stream_has_header_and_mandatory_final_frame() {
    let encoded = seal(16, &[]);

    assert_eq!(
        encoded.len(),
        ENCRYPTED_STREAM_HEADER_LEN + ENCRYPTED_STREAM_FRAME_HEADER_LEN + TAG_LEN
    );
    assert_eq!(&encoded[0..8], ENCRYPTED_STREAM_MAGIC);
    assert_eq!(&encoded[8..10], &1_u16.to_be_bytes());
    assert_eq!(&encoded[10..12], &1_u16.to_be_bytes());
    assert_eq!(&encoded[12..14], &0_u16.to_be_bytes());
    assert_eq!(
        &encoded[14..16],
        &(ENCRYPTED_STREAM_HEADER_LEN as u16).to_be_bytes()
    );
    assert_eq!(&encoded[16..32], &KEY_ID_BYTES);
    assert_eq!(&encoded[32..36], &GENERATION.to_be_bytes());
    assert_eq!(&encoded[36..52], &PURPOSE_BYTES);
    assert_eq!(&encoded[52..84], &SPACE_BYTES);
    assert_eq!(&encoded[120..124], &16_u32.to_be_bytes());
    assert_ne!(&encoded[124..156], &unkeyed_context_digest());
    assert_eq!(&encoded[156..160], &[0_u8; 4]);

    let final_offset = ENCRYPTED_STREAM_HEADER_LEN;
    assert_eq!(
        &encoded[final_offset..final_offset + 8],
        &0_u64.to_be_bytes()
    );
    assert_eq!(
        &encoded[final_offset + 8..final_offset + 12],
        &0_u32.to_be_bytes()
    );
    assert_eq!(encoded[final_offset + 12], 1);
}

#[test]
fn stream_context_debug_is_redacted() {
    assert_eq!(
        format!("{:?}", context()),
        "StreamContext { logical_sequence: 9, caller_context: \"[REDACTED]\" }"
    );
    assert_eq!(context().logical_sequence(), LOGICAL_SEQUENCE);
}

#[test]
fn round_trips_empty_boundary_and_multiframe_streams() {
    for (frame_len, plaintext_len) in [
        (16, 0),
        (16, 1),
        (16, 15),
        (16, 16),
        (16, 17),
        (16, 32),
        (16, 33),
        (4096, 65_537),
    ] {
        let plaintext = vec![0x6D; plaintext_len];
        let codec = codec(frame_len);
        let encoded = codec.seal(&scope(), &context(), &plaintext).unwrap();
        let opened = codec
            .open(&scope(), &context(), encoded.as_bytes())
            .unwrap();
        assert_eq!(opened.as_slice(), plaintext.as_slice());
    }
}

#[test]
fn test_buffered_stream_at_maximum_minus_one_round_trips() {
    let plaintext = vec![0xA5; MAX_BUFFERED_STREAM_PLAINTEXT_LEN - 1];
    let codec = codec(MAX_STREAM_FRAME_PLAINTEXT_LEN);
    let encoded = codec.seal(&scope(), &context(), &plaintext).unwrap();
    let opened = codec
        .open(&scope(), &context(), encoded.as_bytes())
        .unwrap();

    assert_eq!(opened.as_slice(), plaintext.as_slice());
}

#[test]
fn test_buffered_stream_at_maximum_round_trips() {
    let plaintext = vec![0x5A; MAX_BUFFERED_STREAM_PLAINTEXT_LEN];
    let codec = codec(MAX_STREAM_FRAME_PLAINTEXT_LEN);
    let encoded = codec.seal(&scope(), &context(), &plaintext).unwrap();
    let opened = codec
        .open(&scope(), &context(), encoded.as_bytes())
        .unwrap();

    assert_eq!(opened.as_slice(), plaintext.as_slice());
}

#[test]
fn test_buffered_stream_above_maximum_returns_limit_exceeded() {
    let plaintext = vec![0x5A; MAX_BUFFERED_STREAM_PLAINTEXT_LEN + 1];
    let result = codec(MAX_STREAM_FRAME_PLAINTEXT_LEN).seal(&scope(), &context(), &plaintext);

    assert!(matches!(result, Err(CryptError::LimitExceeded)));
}

#[test]
fn test_stream_frame_limit_at_maximum_is_accepted() {
    let config = StreamConfig::new(MAX_STREAM_FRAME_PLAINTEXT_LEN).unwrap();

    assert_eq!(
        config.max_frame_plaintext_len(),
        MAX_STREAM_FRAME_PLAINTEXT_LEN
    );
}

#[test]
fn test_stream_frame_limit_above_maximum_returns_limit_exceeded() {
    assert!(matches!(
        StreamConfig::new(MAX_STREAM_FRAME_PLAINTEXT_LEN + 1),
        Err(CryptError::LimitExceeded)
    ));
}

#[test]
fn frame_sequence_and_totals_are_canonical() {
    let encoded = seal(16, &[0xAB; 33]);
    let ranges = frame_ranges(&encoded);
    assert_eq!(ranges.len(), 4);

    for (sequence, range) in ranges[..3].iter().enumerate() {
        let offset = range.start;
        assert_eq!(
            &encoded[offset..offset + 8],
            &(sequence as u64).to_be_bytes()
        );
        assert_eq!(encoded[offset + 12], 0);
        assert_eq!(&encoded[offset + 16..offset + 32], &[0_u8; 16]);
    }

    let final_offset = ranges[3].start;
    assert_eq!(
        &encoded[final_offset..final_offset + 8],
        &3_u64.to_be_bytes()
    );
    assert_eq!(encoded[final_offset + 12], 1);
    assert_eq!(
        &encoded[final_offset + 16..final_offset + 24],
        &3_u64.to_be_bytes()
    );
    assert_eq!(
        &encoded[final_offset + 24..final_offset + 32],
        &33_u64.to_be_bytes()
    );
}

#[test]
fn rejects_missing_or_duplicate_final_frame() {
    let codec = codec(16);
    let encoded = seal(16, &[0x31; 33]);
    let ranges = frame_ranges(&encoded);

    let missing_final = &encoded[..ranges.last().unwrap().start];
    assert!(matches!(
        codec.open(&scope(), &context(), missing_final),
        Err(CryptError::MissingFinalFrame)
    ));

    let mut duplicate_final = encoded.clone();
    duplicate_final.extend_from_slice(&encoded[ranges.last().unwrap().clone()]);
    assert!(matches!(
        codec.open(&scope(), &context(), &duplicate_final),
        Err(CryptError::TrailingData)
    ));
}

#[test]
fn rejects_incomplete_stream_before_historical_key_lookup() {
    let encoded = seal(16, b"never query a key provider for a header-only object");
    let lookups = Arc::new(AtomicUsize::new(0));
    let provider = CountingProvider {
        lookups: Arc::clone(&lookups),
    };
    let codec = EncryptedStreamCodec::with_config(provider, StreamConfig::new(16).unwrap());

    assert!(matches!(
        codec.open(
            &scope(),
            &context(),
            &encoded[..ENCRYPTED_STREAM_HEADER_LEN]
        ),
        Err(CryptError::MissingFinalFrame)
    ));
    assert_eq!(lookups.load(AtomicOrdering::SeqCst), 0);
}

#[test]
fn rejects_reordered_duplicated_skipped_and_spliced_frames() {
    let codec = codec(16);
    let encoded = seal(16, &[0x41; 33]);
    let ranges = frame_ranges(&encoded);

    let mut reordered = encoded[..ENCRYPTED_STREAM_HEADER_LEN].to_vec();
    reordered.extend_from_slice(&encoded[ranges[1].clone()]);
    reordered.extend_from_slice(&encoded[ranges[0].clone()]);
    reordered.extend_from_slice(&encoded[ranges[2].clone()]);
    reordered.extend_from_slice(&encoded[ranges[3].clone()]);
    assert!(codec.open(&scope(), &context(), &reordered).is_err());

    let mut duplicated = encoded[..ENCRYPTED_STREAM_HEADER_LEN].to_vec();
    duplicated.extend_from_slice(&encoded[ranges[0].clone()]);
    duplicated.extend_from_slice(&encoded[ranges[0].clone()]);
    duplicated.extend_from_slice(&encoded[ranges[1].clone()]);
    duplicated.extend_from_slice(&encoded[ranges[2].clone()]);
    duplicated.extend_from_slice(&encoded[ranges[3].clone()]);
    assert!(codec.open(&scope(), &context(), &duplicated).is_err());

    let mut skipped = encoded[..ENCRYPTED_STREAM_HEADER_LEN].to_vec();
    skipped.extend_from_slice(&encoded[ranges[0].clone()]);
    skipped.extend_from_slice(&encoded[ranges[2].clone()]);
    skipped.extend_from_slice(&encoded[ranges[3].clone()]);
    assert!(codec.open(&scope(), &context(), &skipped).is_err());

    let other = seal(16, &[0x42; 33]);
    let other_ranges = frame_ranges(&other);
    let mut spliced = encoded.clone();
    spliced[ranges[1].clone()].copy_from_slice(&other[other_ranges[1].clone()]);
    assert!(codec.open(&scope(), &context(), &spliced).is_err());
}

#[test]
fn frame_chain_mismatch_has_an_exact_error() {
    let codec = codec(16);
    let mut encoded = seal(16, &[0x41; 33]);
    let ranges = frame_ranges(&encoded);
    encoded[ranges[1].start + 32] ^= 1;

    assert!(matches!(
        codec.open(&scope(), &context(), &encoded),
        Err(CryptError::FrameChainMismatch)
    ));
}

#[test]
fn whole_stream_replay_requires_an_external_generation_guard() {
    let codec = codec(16);
    let encoded = seal(
        16,
        b"the format authenticates but does not anchor object freshness",
    );

    let first = codec.open(&scope(), &context(), &encoded).unwrap();
    let replayed = codec.open(&scope(), &context(), &encoded).unwrap();
    assert_eq!(first.as_slice(), replayed.as_slice());
}

#[test]
fn old_stream_is_rejected_when_expected_logical_sequence_advances() {
    let codec = codec(16);
    let encoded = seal(16, b"snapshot freshness is caller anchored");
    let advanced = StreamContext::new(LOGICAL_SEQUENCE + 1, CONTEXT).unwrap();

    assert!(matches!(
        codec.open(&scope(), &advanced, &encoded),
        Err(CryptError::ContextMismatch)
    ));
}

#[test]
fn rejects_wrong_scope_and_context() {
    let codec = codec(16);
    let encoded = seal(16, b"bound to expected context");
    let wrong_scope = KeyScope::new(SpaceId::new([0x72; 32]), PurposeId::new(PURPOSE_BYTES));
    assert!(matches!(
        codec.open(&wrong_scope, &context(), &encoded),
        Err(CryptError::ContextMismatch)
    ));
    assert!(matches!(
        codec.open(
            &scope(),
            &StreamContext::new(LOGICAL_SEQUENCE, b"wrong").unwrap(),
            &encoded,
        ),
        Err(CryptError::ContextMismatch)
    ));
}

#[test]
fn rejects_every_single_bit_tamper() {
    let codec = codec(16);
    let encoded = seal(16, b"stream integrity");

    for byte_index in 0..encoded.len() {
        for bit_index in 0..8 {
            let mut tampered = encoded.clone();
            tampered[byte_index] ^= 1_u8 << bit_index;
            assert!(
                codec.open(&scope(), &context(), &tampered).is_err(),
                "accepted bit flip at byte {byte_index}, bit {bit_index}"
            );
        }
    }
}

#[test]
fn rejects_every_truncation() {
    let codec = codec(16);
    let encoded = seal(16, b"stream must end with an authenticated final frame");

    for length in 0..encoded.len() {
        assert!(
            codec
                .open(&scope(), &context(), &encoded[..length])
                .is_err(),
            "accepted prefix of length {length}"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn property_round_trip_preserves_arbitrary_bounded_streams(
        frame_len in 64_u32..4097,
        logical_sequence in any::<u64>(),
        caller_context in prop::collection::vec(any::<u8>(), 0..256),
        plaintext in prop::collection::vec(any::<u8>(), 0..32_768),
    ) {
        let config = StreamConfig::new(frame_len).unwrap();
        let codec = EncryptedStreamCodec::with_config(StaticProvider, config);
        let context = StreamContext::new(logical_sequence, &caller_context).unwrap();
        let encoded = codec.seal(&scope(), &context, &plaintext).unwrap();
        let opened = codec.open(&scope(), &context, encoded.as_bytes()).unwrap();
        prop_assert_eq!(opened.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn property_any_stream_bit_flip_fails_closed(
        plaintext in prop::collection::vec(any::<u8>(), 0..8192),
        mutation_selector in any::<usize>(),
        bit in 0_u8..8,
    ) {
        let codec = codec(1024);
        let mut encoded = codec
            .seal(&scope(), &context(), &plaintext)
            .unwrap()
            .into_bytes();
        let index = mutation_selector % encoded.len();
        encoded[index] ^= 1_u8 << bit;
        prop_assert!(codec.open(&scope(), &context(), &encoded).is_err());
    }
}
