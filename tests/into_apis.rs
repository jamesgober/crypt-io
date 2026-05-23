//! Coverage for the 0.10.0 `_into` zero-allocation surface.
//!
//! Verifies:
//!   - round-trip equality with the `Vec`-returning API
//!   - buffer reuse: second call into the same `Vec` doesn't
//!     reallocate (capacity is preserved)
//!   - auth-failure scrubs the output buffer (no
//!     partially-decrypted plaintext leaks)
//!   - stream `_into` matches stream `Vec`-returning behaviour
//!     across all the same edge cases

#![cfg(all(feature = "aead-chacha20", feature = "aead-aes-gcm"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crypt_io::stream::{HEADER_LEN, StreamDecryptor, StreamEncryptor};
use crypt_io::{Algorithm, Crypt, Error};

// ---------- AEAD `_into` ----------

#[test]
fn encrypt_into_matches_encrypt() {
    let key = [0x42u8; 32];
    let plaintext = b"the quick brown fox";
    let crypt = Crypt::new();

    // Hard to compare ciphertexts directly (random nonces), so
    // verify the round-trip recovers the original.
    let mut wire = Vec::new();
    crypt.encrypt_into(&key, plaintext, &mut wire).unwrap();
    let recovered = crypt.decrypt(&key, &wire).unwrap();
    assert_eq!(&*recovered, plaintext);
}

#[test]
fn decrypt_into_matches_decrypt() {
    let key = [0x42u8; 32];
    let plaintext = b"matches!";
    let crypt = Crypt::new();

    let wire = crypt.encrypt(&key, plaintext).unwrap();
    let mut out = Vec::new();
    crypt.decrypt_into(&key, &wire, &mut out).unwrap();
    assert_eq!(&out[..], plaintext);
}

#[test]
fn encrypt_into_buffer_reuse_no_realloc() {
    let key = [0u8; 32];
    let plaintext = vec![0xa5u8; 1024];
    let crypt = Crypt::new();

    let mut wire = Vec::new();
    crypt.encrypt_into(&key, &plaintext, &mut wire).unwrap();
    let cap_after_first = wire.capacity();
    assert!(cap_after_first >= 1024 + 28);

    // Second call with same-sized plaintext must reuse capacity.
    crypt.encrypt_into(&key, &plaintext, &mut wire).unwrap();
    assert_eq!(
        wire.capacity(),
        cap_after_first,
        "second encrypt_into reallocated despite identical-size plaintext",
    );
}

#[test]
fn decrypt_into_buffer_reuse_no_realloc() {
    let key = [0u8; 32];
    let plaintext = vec![0xa5u8; 1024];
    let crypt = Crypt::new();
    let wire = crypt.encrypt(&key, &plaintext).unwrap();

    let mut out = Vec::new();
    crypt.decrypt_into(&key, &wire, &mut out).unwrap();
    let cap_after_first = out.capacity();
    assert!(cap_after_first >= 1024);

    crypt.decrypt_into(&key, &wire, &mut out).unwrap();
    assert_eq!(
        out.capacity(),
        cap_after_first,
        "second decrypt_into reallocated despite identical-size ciphertext",
    );
}

#[test]
fn decrypt_into_scrubs_on_auth_failure() {
    let key = [0u8; 32];
    let crypt = Crypt::new();
    let mut wire = crypt.encrypt(&key, b"plaintext-bytes").unwrap();
    // Tamper a byte in the ciphertext body.
    let mid = wire.len() / 2;
    wire[mid] ^= 0x01;

    // Pre-fill `out` with sentinel bytes so we can detect leakage.
    let mut out = vec![0xffu8; 16];
    let err = crypt.decrypt_into(&key, &wire, &mut out).unwrap_err();
    assert_eq!(err, Error::AuthenticationFailed);
    // After auth failure the buffer MUST be cleared. No
    // partial-plaintext bytes left for the caller to read.
    assert!(
        out.is_empty(),
        "auth-failure path left {} bytes in out",
        out.len()
    );
}

#[test]
fn encrypt_with_aad_into_round_trip() {
    let key = [0x11u8; 32];
    let crypt = Crypt::aes_256_gcm();
    let aad = b"context";

    let mut wire = Vec::new();
    crypt
        .encrypt_with_aad_into(&key, b"body", aad, &mut wire)
        .unwrap();

    let mut out = Vec::new();
    crypt
        .decrypt_with_aad_into(&key, &wire, aad, &mut out)
        .unwrap();
    assert_eq!(&out[..], b"body");

    // Wrong AAD on decrypt → auth fail.
    let mut out2 = vec![0xffu8; 4];
    let err = crypt
        .decrypt_with_aad_into(&key, &wire, b"wrong", &mut out2)
        .unwrap_err();
    assert_eq!(err, Error::AuthenticationFailed);
    assert!(out2.is_empty());
}

#[test]
fn encrypt_into_both_algorithms() {
    let key = [0x22u8; 32];
    for crypt in [Crypt::new(), Crypt::aes_256_gcm()] {
        let mut wire = Vec::new();
        crypt.encrypt_into(&key, b"x", &mut wire).unwrap();
        let mut out = Vec::new();
        crypt.decrypt_into(&key, &wire, &mut out).unwrap();
        assert_eq!(&out[..], b"x");
    }
}

#[test]
fn invalid_key_rejected_on_encrypt_into() {
    let crypt = Crypt::new();
    let mut out = Vec::new();
    let err = crypt.encrypt_into(&[0u8; 16], b"x", &mut out).unwrap_err();
    assert!(matches!(err, Error::InvalidKey { .. }));
}

// ---------- Stream `_into` ----------

#[test]
fn stream_update_into_matches_update() {
    let key = [0x42u8; 32];
    let plaintext: Vec<u8> = (0..2500u32).map(|x| (x & 0xff) as u8).collect();

    // Reference: use the existing Vec-returning API.
    let (mut enc_ref, header_ref) =
        StreamEncryptor::new_with_chunk_size(&key, Algorithm::ChaCha20Poly1305, 10).unwrap();
    let mut wire_ref = header_ref.to_vec();
    wire_ref.extend(enc_ref.update(&plaintext).unwrap());
    wire_ref.extend(enc_ref.finalize().unwrap());

    // _into version writes into a caller buffer.
    let (mut enc_into, header_into) =
        StreamEncryptor::new_with_chunk_size(&key, Algorithm::ChaCha20Poly1305, 10).unwrap();
    let mut wire_into = header_into.to_vec();
    enc_into.update_into(&plaintext, &mut wire_into).unwrap();
    enc_into.finalize_into(&mut wire_into).unwrap();

    // Wire bytes differ (random nonce prefixes per stream), but
    // decrypting either reference's wire with the matching key
    // recovers the original plaintext via the _into decrypt path.
    let mut dec_into = StreamDecryptor::new(&key, &wire_into[..HEADER_LEN]).unwrap();
    let mut recovered = Vec::new();
    dec_into
        .update_into(&wire_into[HEADER_LEN..], &mut recovered)
        .unwrap();
    dec_into.finalize_into(&mut recovered).unwrap();
    assert_eq!(recovered, plaintext);

    // Cross-check: _into decrypt of the Vec-returning encrypt's wire
    // also works.
    let mut dec_cross = StreamDecryptor::new(&key, &wire_ref[..HEADER_LEN]).unwrap();
    let mut recovered_cross = Vec::new();
    dec_cross
        .update_into(&wire_ref[HEADER_LEN..], &mut recovered_cross)
        .unwrap();
    dec_cross.finalize_into(&mut recovered_cross).unwrap();
    assert_eq!(recovered_cross, plaintext);
}

#[test]
fn stream_update_into_round_trip_aes() {
    let key = [0x33u8; 32];
    let plaintext = vec![0xa5u8; 10 * 1024];

    let (mut enc, header) =
        StreamEncryptor::new_with_chunk_size(&key, Algorithm::Aes256Gcm, 10).unwrap();
    let mut wire = header.to_vec();
    enc.update_into(&plaintext, &mut wire).unwrap();
    enc.finalize_into(&mut wire).unwrap();

    let mut dec = StreamDecryptor::new(&key, &wire[..HEADER_LEN]).unwrap();
    let mut recovered = Vec::new();
    dec.update_into(&wire[HEADER_LEN..], &mut recovered)
        .unwrap();
    dec.finalize_into(&mut recovered).unwrap();
    assert_eq!(recovered, plaintext);
}

#[test]
fn stream_update_into_buffer_reuse() {
    // Two encryptions into the same wire buffer (clearing between).
    // Second one should not need to grow the buffer's capacity.
    let key = [0u8; 32];
    let plaintext = vec![0u8; 1024 * 5];

    let mut wire = Vec::new();
    {
        let (mut enc, header) =
            StreamEncryptor::new_with_chunk_size(&key, Algorithm::ChaCha20Poly1305, 10).unwrap();
        wire.extend_from_slice(&header);
        enc.update_into(&plaintext, &mut wire).unwrap();
        enc.finalize_into(&mut wire).unwrap();
    }
    let cap_after_first = wire.capacity();
    wire.clear();

    {
        let (mut enc, header) =
            StreamEncryptor::new_with_chunk_size(&key, Algorithm::ChaCha20Poly1305, 10).unwrap();
        wire.extend_from_slice(&header);
        enc.update_into(&plaintext, &mut wire).unwrap();
        enc.finalize_into(&mut wire).unwrap();
    }
    assert_eq!(
        wire.capacity(),
        cap_after_first,
        "second stream encrypt reallocated despite identical-size plaintext",
    );
}

#[test]
fn stream_update_into_empty_plaintext() {
    let key = [0u8; 32];
    let (mut enc, header) =
        StreamEncryptor::new_with_chunk_size(&key, Algorithm::ChaCha20Poly1305, 10).unwrap();
    let mut wire = header.to_vec();
    enc.update_into(b"", &mut wire).unwrap();
    enc.finalize_into(&mut wire).unwrap();

    let mut dec = StreamDecryptor::new(&key, &wire[..HEADER_LEN]).unwrap();
    let mut recovered = Vec::new();
    dec.update_into(&wire[HEADER_LEN..], &mut recovered)
        .unwrap();
    dec.finalize_into(&mut recovered).unwrap();
    assert!(recovered.is_empty());
}
