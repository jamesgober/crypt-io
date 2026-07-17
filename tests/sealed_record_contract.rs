//! Contract tests for the version-one sealed-record storage format.

#![cfg(feature = "storage-v1")]
#![allow(clippy::unwrap_used)]

use crypt_io::storage::{
    CryptError, KeyGeneration, KeyId, KeyLease, KeyProvider, KeyProviderError, KeyScope,
    MAX_SEALED_RECORD_PLAINTEXT_LEN, PurposeId, RecordCodec, RecordContext,
    SEALED_RECORD_HEADER_LEN, SEALED_RECORD_MAGIC, SecretKey32, SpaceId,
};
use proptest::prelude::*;
use sha2::{Digest, Sha256};

const KEY_ID_BYTES: [u8; 16] = *b"test-key-id-v001";
const PURPOSE_BYTES: [u8; 16] = *b"memory-record-v1";
const SPACE_BYTES: [u8; 32] = [0x53; 32];
const MASTER_KEY_BYTES: [u8; 32] = [0xA7; 32];
const GENERATION: u32 = 7;
const LOGICAL_SEQUENCE: u64 = 42;
const CONTEXT: &[u8] = b"collection=memories;record=7f4a";
const TAG_LEN: usize = 16;

#[derive(Clone, Copy)]
struct StaticProvider {
    key_id: [u8; 16],
    generation: u32,
    secret: [u8; 32],
    returned_key_id: [u8; 16],
}

impl StaticProvider {
    const fn valid() -> Self {
        Self {
            key_id: KEY_ID_BYTES,
            generation: GENERATION,
            secret: MASTER_KEY_BYTES,
            returned_key_id: KEY_ID_BYTES,
        }
    }

    const fn with_secret(secret: [u8; 32]) -> Self {
        Self {
            secret,
            ..Self::valid()
        }
    }

    const fn with_returned_key_id(returned_key_id: [u8; 16]) -> Self {
        Self {
            returned_key_id,
            ..Self::valid()
        }
    }

    fn lease(self) -> KeyLease {
        KeyLease::new(
            KeyId::new(self.returned_key_id),
            KeyGeneration::new(self.generation),
            SecretKey32::new(self.secret),
        )
    }
}

impl KeyProvider for StaticProvider {
    fn active(&self, _scope: &KeyScope) -> Result<KeyLease, KeyProviderError> {
        Ok((*self).lease())
    }

    fn by_id(
        &self,
        _scope: &KeyScope,
        key_id: KeyId,
        generation: KeyGeneration,
    ) -> Result<KeyLease, KeyProviderError> {
        if key_id != KeyId::new(self.key_id) || generation != KeyGeneration::new(self.generation) {
            return Err(KeyProviderError::Unavailable);
        }
        Ok((*self).lease())
    }
}

fn scope() -> KeyScope {
    KeyScope::new(SpaceId::new(SPACE_BYTES), PurposeId::new(PURPOSE_BYTES))
}

fn context() -> RecordContext {
    RecordContext::new(LOGICAL_SEQUENCE, CONTEXT).unwrap()
}

fn seal(plaintext: &[u8]) -> Vec<u8> {
    RecordCodec::new(StaticProvider::valid())
        .seal(&scope(), &context(), plaintext)
        .unwrap()
        .into_bytes()
}

fn legacy_unkeyed_context_digest() -> [u8; 32] {
    let context_len = u64::try_from(CONTEXT.len()).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(b"crypt-io/record-context/v1\0");
    hasher.update(context_len.to_be_bytes());
    hasher.update(CONTEXT);
    let output = hasher.finalize();
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(&output);
    digest
}

#[test]
fn empty_record_has_exact_v1_layout() {
    let encoded = seal(&[]);

    assert_eq!(encoded.len(), SEALED_RECORD_HEADER_LEN + TAG_LEN);
    assert_eq!(&encoded[0..8], SEALED_RECORD_MAGIC);
    assert_eq!(&encoded[8..10], &1_u16.to_be_bytes());
    assert_eq!(&encoded[10..12], &1_u16.to_be_bytes());
    assert_eq!(&encoded[12..14], &0_u16.to_be_bytes());
    assert_eq!(
        &encoded[14..16],
        &(SEALED_RECORD_HEADER_LEN as u16).to_be_bytes()
    );
    assert_eq!(&encoded[16..32], &KEY_ID_BYTES);
    assert_eq!(&encoded[32..36], &GENERATION.to_be_bytes());
    assert_eq!(&encoded[36..52], &PURPOSE_BYTES);
    assert_eq!(&encoded[52..84], &SPACE_BYTES);
    assert_eq!(&encoded[128..136], &LOGICAL_SEQUENCE.to_be_bytes());
    assert_ne!(&encoded[136..168], &legacy_unkeyed_context_digest());
    assert_eq!(&encoded[168..176], &0_u64.to_be_bytes());
}

#[test]
fn seal_uses_fresh_internal_entropy() {
    let first = seal(b"same plaintext");
    let second = seal(b"same plaintext");

    assert_ne!(&first[84..116], &second[84..116]);
    assert_ne!(&first[116..128], &second[116..128]);
    assert_ne!(first, second);
}

#[test]
fn record_context_debug_is_redacted() {
    assert_eq!(
        format!("{:?}", context()),
        "RecordContext { logical_sequence: 42, caller_context: \"[REDACTED]\" }"
    );
}

#[test]
fn round_trips_boundary_lengths() {
    let codec = RecordCodec::new(StaticProvider::valid());

    for length in [0, 1, 15, 16, 17, 255, 4096] {
        let plaintext = vec![0x5A; length];
        let encoded = codec.seal(&scope(), &context(), &plaintext).unwrap();
        let opened = codec
            .open(&scope(), &context(), encoded.as_bytes())
            .unwrap();
        assert_eq!(opened.as_slice(), plaintext.as_slice());
    }
}

#[test]
fn test_sealed_record_at_maximum_minus_one_round_trips() {
    let plaintext = vec![0xA5; MAX_SEALED_RECORD_PLAINTEXT_LEN - 1];
    let codec = RecordCodec::new(StaticProvider::valid());
    let encoded = codec.seal(&scope(), &context(), &plaintext).unwrap();
    let opened = codec
        .open(&scope(), &context(), encoded.as_bytes())
        .unwrap();

    assert_eq!(opened.as_slice(), plaintext.as_slice());
}

#[test]
fn test_sealed_record_at_maximum_round_trips() {
    let plaintext = vec![0x5A; MAX_SEALED_RECORD_PLAINTEXT_LEN];
    let codec = RecordCodec::new(StaticProvider::valid());
    let encoded = codec.seal(&scope(), &context(), &plaintext).unwrap();
    let opened = codec
        .open(&scope(), &context(), encoded.as_bytes())
        .unwrap();

    assert_eq!(opened.as_slice(), plaintext.as_slice());
}

#[test]
fn test_sealed_record_above_maximum_returns_limit_exceeded() {
    let plaintext = vec![0x5A; MAX_SEALED_RECORD_PLAINTEXT_LEN + 1];
    let result = RecordCodec::new(StaticProvider::valid()).seal(&scope(), &context(), &plaintext);

    assert!(matches!(result, Err(CryptError::LimitExceeded)));
}

#[test]
fn rejects_wrong_scope_context_and_sequence() {
    let codec = RecordCodec::new(StaticProvider::valid());
    let encoded = codec.seal(&scope(), &context(), b"private memory").unwrap();

    let wrong_space = KeyScope::new(SpaceId::new([0x99; 32]), PurposeId::new(PURPOSE_BYTES));
    assert!(matches!(
        codec.open(&wrong_space, &context(), encoded.as_bytes()),
        Err(CryptError::ContextMismatch)
    ));

    let wrong_purpose = KeyScope::new(
        SpaceId::new(SPACE_BYTES),
        PurposeId::new(*b"audit-event--v1!"),
    );
    assert!(matches!(
        codec.open(&wrong_purpose, &context(), encoded.as_bytes()),
        Err(CryptError::ContextMismatch)
    ));

    let wrong_context = RecordContext::new(LOGICAL_SEQUENCE, b"another record").unwrap();
    assert!(matches!(
        codec.open(&scope(), &wrong_context, encoded.as_bytes()),
        Err(CryptError::ContextMismatch)
    ));

    let wrong_sequence = RecordContext::new(LOGICAL_SEQUENCE + 1, CONTEXT).unwrap();
    assert!(matches!(
        codec.open(&scope(), &wrong_sequence, encoded.as_bytes()),
        Err(CryptError::SequenceMismatch)
    ));
}

#[test]
fn distinguishes_descriptor_mismatch_from_authentication_failure() {
    let encoded = seal(b"authenticated");

    let wrong_descriptor = RecordCodec::new(StaticProvider::with_returned_key_id([0x22; 16]));
    assert!(matches!(
        wrong_descriptor.open(&scope(), &context(), &encoded),
        Err(CryptError::WrongKey)
    ));

    let wrong_secret = RecordCodec::new(StaticProvider::with_secret([0x33; 32]));
    assert!(matches!(
        wrong_secret.open(&scope(), &context(), &encoded),
        Err(CryptError::AuthenticationFailed)
    ));
}

#[test]
fn rejects_every_single_bit_tamper() {
    let codec = RecordCodec::new(StaticProvider::valid());
    let encoded = seal(b"tamper-evident payload");

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
fn rejects_every_truncation_and_any_trailing_byte() {
    let codec = RecordCodec::new(StaticProvider::valid());
    let encoded = seal(b"must be complete");

    for length in 0..encoded.len() {
        assert!(
            codec
                .open(&scope(), &context(), &encoded[..length])
                .is_err(),
            "accepted prefix of length {length}"
        );
    }

    let mut trailing = encoded;
    trailing.push(0);
    assert!(matches!(
        codec.open(&scope(), &context(), &trailing),
        Err(CryptError::TrailingData)
    ));
}

#[test]
fn malformed_fixed_header_fields_have_typed_errors() {
    let codec = RecordCodec::new(StaticProvider::valid());

    let mut bad_magic = seal(b"x");
    bad_magic[0] ^= 1;
    assert!(matches!(
        codec.open(&scope(), &context(), &bad_magic),
        Err(CryptError::CorruptStructure)
    ));

    let mut bad_version = seal(b"x");
    bad_version[8..10].copy_from_slice(&2_u16.to_be_bytes());
    assert!(matches!(
        codec.open(&scope(), &context(), &bad_version),
        Err(CryptError::UnsupportedVersion)
    ));

    let mut bad_suite = seal(b"x");
    bad_suite[10..12].copy_from_slice(&2_u16.to_be_bytes());
    assert!(matches!(
        codec.open(&scope(), &context(), &bad_suite),
        Err(CryptError::UnsupportedSuite)
    ));

    let mut bad_flags = seal(b"x");
    bad_flags[12..14].copy_from_slice(&1_u16.to_be_bytes());
    assert!(matches!(
        codec.open(&scope(), &context(), &bad_flags),
        Err(CryptError::CorruptStructure)
    ));

    let mut bad_header_len = seal(b"x");
    bad_header_len[14..16].copy_from_slice(&175_u16.to_be_bytes());
    assert!(matches!(
        codec.open(&scope(), &context(), &bad_header_len),
        Err(CryptError::CorruptStructure)
    ));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn property_round_trip_preserves_arbitrary_bounded_records(
        logical_sequence in any::<u64>(),
        caller_context in prop::collection::vec(any::<u8>(), 0..256),
        plaintext in prop::collection::vec(any::<u8>(), 0..16_384),
    ) {
        let codec = RecordCodec::new(StaticProvider::valid());
        let context = RecordContext::new(logical_sequence, &caller_context).unwrap();
        let encoded = codec.seal(&scope(), &context, &plaintext).unwrap();
        let opened = codec.open(&scope(), &context, encoded.as_bytes()).unwrap();
        prop_assert_eq!(opened.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn property_any_ciphertext_bit_flip_fails_closed(
        plaintext in prop::collection::vec(any::<u8>(), 0..4096),
        mutation_selector in any::<usize>(),
        bit in 0_u8..8,
    ) {
        let codec = RecordCodec::new(StaticProvider::valid());
        let mut encoded = codec
            .seal(&scope(), &context(), &plaintext)
            .unwrap()
            .into_bytes();
        let index = mutation_selector % encoded.len();
        encoded[index] ^= 1_u8 << bit;
        prop_assert!(codec.open(&scope(), &context(), &encoded).is_err());
    }
}
