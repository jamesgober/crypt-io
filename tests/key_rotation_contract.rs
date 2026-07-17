//! Contract tests for explicit record rotation and scope migration.

#![cfg(feature = "storage-v1")]
#![allow(clippy::unwrap_used)]

use crypt_io::storage::{
    CryptError, KeyDescriptor, KeyGeneration, KeyId, KeyLease, KeyProvider, KeyProviderError,
    KeyScope, PurposeId, RecordCodec, RecordContext, SecretKey32, SpaceId,
};

const OLD_KEY_ID: [u8; 16] = *b"old-key-id-v0001";
const NEW_KEY_ID: [u8; 16] = *b"new-key-id-v0002";
const OLD_SECRET: [u8; 32] = [0x19; 32];
const NEW_SECRET: [u8; 32] = [0x29; 32];
const SPACE: [u8; 32] = [0x44; 32];
const SOURCE_PURPOSE: [u8; 16] = *b"memory-record-v1";
const TARGET_PURPOSE: [u8; 16] = *b"audit-event--v1!";

#[derive(Clone, Copy)]
struct Provider {
    active_generation: u32,
    reused_active_secret: bool,
    expose_new_by_id: bool,
}

impl Provider {
    const fn old_only() -> Self {
        Self {
            active_generation: 1,
            reused_active_secret: false,
            expose_new_by_id: false,
        }
    }

    const fn rotating() -> Self {
        Self {
            active_generation: 2,
            reused_active_secret: false,
            expose_new_by_id: true,
        }
    }

    const fn reused_descriptor() -> Self {
        Self {
            active_generation: 1,
            reused_active_secret: true,
            expose_new_by_id: false,
        }
    }

    const fn stale_after_rotation() -> Self {
        Self {
            active_generation: 1,
            reused_active_secret: false,
            expose_new_by_id: true,
        }
    }

    fn old_lease(secret: [u8; 32]) -> KeyLease {
        KeyLease::new(
            KeyId::new(OLD_KEY_ID),
            KeyGeneration::new(1),
            SecretKey32::new(secret),
        )
    }

    fn new_lease() -> KeyLease {
        KeyLease::new(
            KeyId::new(NEW_KEY_ID),
            KeyGeneration::new(2),
            SecretKey32::new(NEW_SECRET),
        )
    }
}

#[derive(Clone, Copy)]
struct EqualGenerationReplacementProvider;

impl KeyProvider for EqualGenerationReplacementProvider {
    fn active(&self, _scope: &KeyScope) -> Result<KeyLease, KeyProviderError> {
        Ok(KeyLease::new(
            KeyId::new(NEW_KEY_ID),
            KeyGeneration::new(1),
            SecretKey32::new(NEW_SECRET),
        ))
    }

    fn by_id(
        &self,
        _scope: &KeyScope,
        key_id: KeyId,
        generation: KeyGeneration,
    ) -> Result<KeyLease, KeyProviderError> {
        if key_id == KeyId::new(OLD_KEY_ID) && generation == KeyGeneration::new(1) {
            return Ok(Provider::old_lease(OLD_SECRET));
        }
        Err(KeyProviderError::Unavailable)
    }
}

#[derive(Clone, Copy)]
struct ReusedMaterialReplacementProvider;

impl KeyProvider for ReusedMaterialReplacementProvider {
    fn active(&self, _scope: &KeyScope) -> Result<KeyLease, KeyProviderError> {
        Ok(KeyLease::new(
            KeyId::new(NEW_KEY_ID),
            KeyGeneration::new(2),
            SecretKey32::new(OLD_SECRET),
        ))
    }

    fn by_id(
        &self,
        _scope: &KeyScope,
        key_id: KeyId,
        generation: KeyGeneration,
    ) -> Result<KeyLease, KeyProviderError> {
        if key_id == KeyId::new(OLD_KEY_ID) && generation == KeyGeneration::new(1) {
            return Ok(Provider::old_lease(OLD_SECRET));
        }
        Err(KeyProviderError::Unavailable)
    }
}

impl KeyProvider for Provider {
    fn active(&self, _scope: &KeyScope) -> Result<KeyLease, KeyProviderError> {
        if self.active_generation == 2 {
            return Ok(Self::new_lease());
        }
        let secret = if self.reused_active_secret {
            NEW_SECRET
        } else {
            OLD_SECRET
        };
        Ok(Self::old_lease(secret))
    }

    fn by_id(
        &self,
        _scope: &KeyScope,
        key_id: KeyId,
        generation: KeyGeneration,
    ) -> Result<KeyLease, KeyProviderError> {
        let descriptor = KeyDescriptor::new(key_id, generation);
        if descriptor == KeyDescriptor::new(KeyId::new(OLD_KEY_ID), KeyGeneration::new(1)) {
            return Ok(Self::old_lease(OLD_SECRET));
        }
        if self.expose_new_by_id
            && descriptor == KeyDescriptor::new(KeyId::new(NEW_KEY_ID), KeyGeneration::new(2))
        {
            return Ok(Self::new_lease());
        }
        Err(KeyProviderError::Unavailable)
    }
}

fn source_scope() -> KeyScope {
    KeyScope::new(SpaceId::new(SPACE), PurposeId::new(SOURCE_PURPOSE))
}

fn target_scope() -> KeyScope {
    KeyScope::new(SpaceId::new(SPACE), PurposeId::new(TARGET_PURPOSE))
}

fn source_context() -> RecordContext {
    RecordContext::new(11, b"record=11;schema=1").unwrap()
}

fn target_context() -> RecordContext {
    RecordContext::new(12, b"record=11;schema=2").unwrap()
}

fn old_record() -> Vec<u8> {
    RecordCodec::new(Provider::old_only())
        .seal(&source_scope(), &source_context(), b"durable memory")
        .unwrap()
        .into_bytes()
}

#[test]
fn rotates_old_record_to_exact_active_key() {
    let old = old_record();
    let codec = RecordCodec::new(Provider::rotating());
    let outcome = codec
        .rotate_to_active(&source_scope(), &source_context(), &old)
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
    assert_ne!(outcome.record().as_bytes(), old.as_slice());
    let opened = codec
        .open(
            &source_scope(),
            &source_context(),
            outcome.record().as_bytes(),
        )
        .unwrap();
    assert_eq!(opened.as_slice(), b"durable memory");

    assert!(matches!(
        RecordCodec::new(Provider::old_only()).open(
            &source_scope(),
            &source_context(),
            outcome.record().as_bytes()
        ),
        Err(CryptError::KeyUnavailable)
    ));
}

#[test]
fn rotation_is_authenticated_and_idempotent_when_already_current() {
    let codec = RecordCodec::new(Provider::rotating());
    let current = codec
        .rotate_to_active(&source_scope(), &source_context(), &old_record())
        .unwrap()
        .into_record();
    let second = codec
        .rotate_to_active(&source_scope(), &source_context(), current.as_bytes())
        .unwrap();

    assert!(!second.was_resealed());
    assert_eq!(second.record().as_bytes(), current.as_bytes());
    assert_eq!(second.source_key(), second.destination_key());
}

#[test]
fn migration_requires_explicit_source_and_destination_contexts() {
    let codec = RecordCodec::new(Provider::rotating());
    let outcome = codec
        .migrate(
            &source_scope(),
            &source_context(),
            &target_scope(),
            &target_context(),
            &old_record(),
        )
        .unwrap();

    assert!(outcome.was_resealed());
    let opened = codec
        .open(
            &target_scope(),
            &target_context(),
            outcome.record().as_bytes(),
        )
        .unwrap();
    assert_eq!(opened.as_slice(), b"durable memory");
    assert!(matches!(
        codec.open(
            &source_scope(),
            &source_context(),
            outcome.record().as_bytes()
        ),
        Err(CryptError::SequenceMismatch | CryptError::ContextMismatch)
    ));
}

#[test]
fn reused_descriptor_with_different_secret_fails_closed() {
    let result = RecordCodec::new(Provider::reused_descriptor()).rotate_to_active(
        &source_scope(),
        &source_context(),
        &old_record(),
    );
    assert!(matches!(result, Err(CryptError::WrongKey)));
}

#[test]
fn rotation_rejects_new_descriptor_with_reused_master_secret() {
    let result = RecordCodec::new(ReusedMaterialReplacementProvider).rotate_to_active(
        &source_scope(),
        &source_context(),
        &old_record(),
    );

    assert!(matches!(result, Err(CryptError::KeyMaterialReuse)));
}

#[test]
fn rotation_rejects_a_stale_lower_active_generation() {
    let current_codec = RecordCodec::new(Provider::rotating());
    let current = current_codec
        .rotate_to_active(&source_scope(), &source_context(), &old_record())
        .unwrap()
        .into_record();

    let result = RecordCodec::new(Provider::stale_after_rotation()).rotate_to_active(
        &source_scope(),
        &source_context(),
        current.as_bytes(),
    );
    assert!(matches!(result, Err(CryptError::KeyDowngrade)));
}

#[test]
fn rotation_rejects_a_different_key_at_the_same_generation() {
    let result = RecordCodec::new(EqualGenerationReplacementProvider).rotate_to_active(
        &source_scope(),
        &source_context(),
        &old_record(),
    );
    assert!(matches!(result, Err(CryptError::KeyDowngrade)));
}
