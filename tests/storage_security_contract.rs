//! Compile-time security contracts for the minimal authenticated-storage graph.

#![cfg(feature = "storage-v1")]

use hmac::{Hmac, KeyInit};
use sha2::Sha256;
use zeroize::ZeroizeOnDrop;

use crypt_io::storage::{CryptError, MAX_STORAGE_CONTEXT_LEN, RecordContext, StreamContext};

fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

#[test]
fn minimal_storage_hmac_state_zeroizes_on_drop() {
    assert_zeroize_on_drop::<Sha256>();
    assert!(core::mem::needs_drop::<Hmac<Sha256>>());
    let hmac = Hmac::<Sha256>::new_from_slice(&[0_u8; 32]);
    assert!(hmac.is_ok());
}

#[test]
fn test_effective_aes_key_schedule_implements_zeroize_on_drop() {
    assert_zeroize_on_drop::<aes::Aes256>();
    assert!(core::mem::needs_drop::<polyval::Polyval>());
}

#[test]
fn caller_context_hashing_has_an_exact_cpu_bound() {
    let mut context_bytes = vec![0xA5_u8; MAX_STORAGE_CONTEXT_LEN];
    assert!(RecordContext::new(7, &context_bytes).is_ok());
    assert!(StreamContext::new(1, &context_bytes).is_ok());

    context_bytes.push(0x5A);
    assert!(matches!(
        RecordContext::new(7, &context_bytes),
        Err(CryptError::LimitExceeded)
    ));
    assert!(matches!(
        StreamContext::new(1, &context_bytes),
        Err(CryptError::LimitExceeded)
    ));
}
