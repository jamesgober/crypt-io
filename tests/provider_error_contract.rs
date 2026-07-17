//! Public-boundary contracts for key-provider error translation.

#![cfg(feature = "storage-v1")]
#![allow(clippy::unwrap_used)]

use crypt_io::storage::{
    CryptError, KeyGeneration, KeyId, KeyLease, KeyProvider, KeyProviderError, KeyScope, PurposeId,
    RecordCodec, RecordContext, SecretKey32, SpaceId,
};
#[cfg(feature = "storage-v1")]
use crypt_io::storage::{EncryptedStreamCodec, StreamConfig, StreamContext};

const KEY_ID: KeyId = KeyId::new(*b"provider-key-v01");
const GENERATION: KeyGeneration = KeyGeneration::new(3);
const SECRET: [u8; 32] = [0xA7; 32];

#[derive(Clone, Copy)]
struct StaticProvider {
    returned_key_id: KeyId,
    secret: [u8; 32],
}

impl StaticProvider {
    const VALID: Self = Self {
        returned_key_id: KEY_ID,
        secret: SECRET,
    };
}

impl KeyProvider for StaticProvider {
    fn active(&self, _scope: &KeyScope) -> Result<KeyLease, KeyProviderError> {
        Ok(KeyLease::new(
            self.returned_key_id,
            GENERATION,
            SecretKey32::new(self.secret),
        ))
    }

    fn by_id(
        &self,
        _scope: &KeyScope,
        _key_id: KeyId,
        _generation: KeyGeneration,
    ) -> Result<KeyLease, KeyProviderError> {
        self.active(&scope())
    }
}

#[derive(Clone, Copy)]
struct FailingProvider(KeyProviderError);

impl KeyProvider for FailingProvider {
    fn active(&self, _scope: &KeyScope) -> Result<KeyLease, KeyProviderError> {
        Err(self.0)
    }

    fn by_id(
        &self,
        _scope: &KeyScope,
        _key_id: KeyId,
        _generation: KeyGeneration,
    ) -> Result<KeyLease, KeyProviderError> {
        Err(self.0)
    }
}

fn scope() -> KeyScope {
    KeyScope::new(
        SpaceId::new([0x53; 32]),
        PurposeId::new(*b"provider-test-v1"),
    )
}

fn record_context() -> RecordContext {
    RecordContext::new(11, b"provider error contract").unwrap()
}

fn mappings() -> [(KeyProviderError, CryptError); 4] {
    [
        (KeyProviderError::Unavailable, CryptError::KeyUnavailable),
        (KeyProviderError::AccessDenied, CryptError::KeyAccessDenied),
        (
            KeyProviderError::Failure { retryable: false },
            CryptError::KeyProviderFailure { retryable: false },
        ),
        (
            KeyProviderError::Failure { retryable: true },
            CryptError::KeyProviderFailure { retryable: true },
        ),
    ]
}

#[test]
fn test_record_codec_maps_active_and_historical_provider_errors() {
    let encoded = RecordCodec::new(StaticProvider::VALID)
        .seal(&scope(), &record_context(), b"record")
        .unwrap();

    for (provider_error, expected) in mappings() {
        let codec = RecordCodec::new(FailingProvider(provider_error));
        assert_eq!(
            codec.seal(&scope(), &record_context(), b"record").err(),
            Some(expected)
        );
        assert_eq!(
            codec
                .open(&scope(), &record_context(), encoded.as_bytes())
                .err(),
            Some(expected)
        );
    }
}

#[cfg(feature = "storage-v1")]
#[test]
fn test_stream_codec_maps_active_and_historical_provider_errors() {
    let context = StreamContext::new(1, b"provider error contract").unwrap();
    let encoded =
        EncryptedStreamCodec::with_config(StaticProvider::VALID, StreamConfig::new(16).unwrap())
            .seal(&scope(), &context, b"stream")
            .unwrap();

    for (provider_error, expected) in mappings() {
        let codec = EncryptedStreamCodec::with_config(
            FailingProvider(provider_error),
            StreamConfig::new(16).unwrap(),
        );
        assert_eq!(
            codec.seal(&scope(), &context, b"stream").err(),
            Some(expected)
        );
        assert_eq!(
            codec.open(&scope(), &context, encoded.as_bytes()).err(),
            Some(expected)
        );
    }
}

#[cfg(feature = "storage-v1")]
#[test]
fn test_encrypted_stream_distinguishes_wrong_descriptor_and_wrong_secret() {
    let context = StreamContext::new(1, b"provider descriptor contract").unwrap();
    let encoded =
        EncryptedStreamCodec::with_config(StaticProvider::VALID, StreamConfig::new(16).unwrap())
            .seal(&scope(), &context, b"stream")
            .unwrap();
    let wrong_descriptor = EncryptedStreamCodec::with_config(
        StaticProvider {
            returned_key_id: KeyId::new(*b"provider-key-v02"),
            secret: SECRET,
        },
        StreamConfig::new(16).unwrap(),
    );
    let wrong_secret = EncryptedStreamCodec::with_config(
        StaticProvider {
            returned_key_id: KEY_ID,
            secret: [0x5A; 32],
        },
        StreamConfig::new(16).unwrap(),
    );

    assert_eq!(
        wrong_descriptor
            .open(&scope(), &context, encoded.as_bytes())
            .err(),
        Some(CryptError::WrongKey)
    );
    assert_eq!(
        wrong_secret
            .open(&scope(), &context, encoded.as_bytes())
            .err(),
        Some(CryptError::AuthenticationFailed)
    );
}
