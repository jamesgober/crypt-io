//! End-to-end coverage for `crypt_io::stream` — round-trip across
//! algorithms / chunk sizes / plaintext shapes, plus the full attack
//! surface (tampering, truncation, reordering, wrong key, header
//! tamper).

#![cfg(all(
    feature = "stream",
    feature = "aead-chacha20",
    feature = "aead-aes-gcm"
))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crypt_io::stream::{
    DEFAULT_CHUNK_SIZE_LOG2, HEADER_LEN, StreamDecryptor, StreamEncryptor, TAG_LEN,
};
use crypt_io::{Algorithm, Error};

fn round_trip(algorithm: Algorithm, chunk_size_log2: u8, plaintext: &[u8]) {
    let key = [0x42u8; 32];

    let (mut enc, header) =
        StreamEncryptor::new_with_chunk_size(&key, algorithm, chunk_size_log2).unwrap();
    let mut wire = header.to_vec();
    wire.extend(enc.update(plaintext).unwrap());
    wire.extend(enc.finalize().unwrap());

    let mut dec = StreamDecryptor::new(&key, &wire[..HEADER_LEN]).unwrap();
    let mut recovered = dec.update(&wire[HEADER_LEN..]).unwrap();
    recovered.extend(dec.finalize().unwrap());

    assert_eq!(recovered, plaintext);
}

#[test]
fn round_trip_chacha_default_chunk_size_short() {
    round_trip(Algorithm::ChaCha20Poly1305, DEFAULT_CHUNK_SIZE_LOG2, b"hi");
}

#[test]
fn round_trip_aes_default_chunk_size_short() {
    round_trip(Algorithm::Aes256Gcm, DEFAULT_CHUNK_SIZE_LOG2, b"hi");
}

#[test]
fn round_trip_empty_plaintext() {
    round_trip(Algorithm::ChaCha20Poly1305, 10, b"");
    round_trip(Algorithm::Aes256Gcm, 10, b"");
}

#[test]
fn round_trip_one_byte() {
    round_trip(Algorithm::ChaCha20Poly1305, 10, b"x");
}

#[test]
fn round_trip_exact_chunk_size() {
    // chunk_size_log2 = 10 → 1024-byte chunks.
    let plaintext = vec![0xaau8; 1024];
    round_trip(Algorithm::ChaCha20Poly1305, 10, &plaintext);
    round_trip(Algorithm::Aes256Gcm, 10, &plaintext);
}

#[test]
fn round_trip_multiple_of_chunk_size() {
    let plaintext = vec![0xbbu8; 1024 * 5];
    round_trip(Algorithm::ChaCha20Poly1305, 10, &plaintext);
    round_trip(Algorithm::Aes256Gcm, 10, &plaintext);
}

#[test]
fn round_trip_chunk_size_plus_one() {
    let plaintext = vec![0xccu8; 1025];
    round_trip(Algorithm::ChaCha20Poly1305, 10, &plaintext);
}

#[test]
fn round_trip_many_chunks() {
    // ~100 chunks of 1 KiB.
    let plaintext: Vec<u8> = (0..100 * 1024).map(|i| (i & 0xff) as u8).collect();
    round_trip(Algorithm::ChaCha20Poly1305, 10, &plaintext);
}

#[test]
fn round_trip_10mib() {
    // Stand-in for the "large data" check. The roadmap mentions 1
    // GiB; that's an ignored stress test the user can opt into. The
    // 10 MiB version runs in well under a second and exercises the
    // multi-chunk paths.
    let plaintext = vec![0xddu8; 10 * 1024 * 1024];
    round_trip(Algorithm::ChaCha20Poly1305, 16, &plaintext);
}

#[test]
fn round_trip_byte_by_byte_feed() {
    // Encryptor + decryptor both buffer correctly when bytes arrive
    // one at a time on either side.
    let key = [0x33u8; 32];
    let plaintext: Vec<u8> = (0..2500u32).map(|x| (x & 0xff) as u8).collect();
    let chunk_log2 = 10;

    let (mut enc, header) =
        StreamEncryptor::new_with_chunk_size(&key, Algorithm::ChaCha20Poly1305, chunk_log2)
            .unwrap();
    let mut wire = header.to_vec();
    for b in &plaintext {
        wire.extend(enc.update(&[*b]).unwrap());
    }
    wire.extend(enc.finalize().unwrap());

    let mut dec = StreamDecryptor::new(&key, &wire[..HEADER_LEN]).unwrap();
    let mut recovered = Vec::new();
    for b in &wire[HEADER_LEN..] {
        recovered.extend(dec.update(&[*b]).unwrap());
    }
    recovered.extend(dec.finalize().unwrap());

    assert_eq!(recovered, plaintext);
}

// ---------- Attack surface ----------

fn encrypt_for_attack(algorithm: Algorithm, plaintext: &[u8]) -> ([u8; 32], Vec<u8>) {
    let key = [0xaau8; 32];
    let (mut enc, header) = StreamEncryptor::new_with_chunk_size(&key, algorithm, 10).unwrap();
    let mut wire = header.to_vec();
    wire.extend(enc.update(plaintext).unwrap());
    wire.extend(enc.finalize().unwrap());
    (key, wire)
}

fn try_decrypt(key: &[u8; 32], wire: &[u8]) -> Result<Vec<u8>, Error> {
    let mut dec = StreamDecryptor::new(key, &wire[..HEADER_LEN])?;
    let mut out = dec.update(&wire[HEADER_LEN..])?;
    out.extend(dec.finalize()?);
    Ok(out)
}

#[test]
fn wrong_key_fails_authentication() {
    let (_key, wire) = encrypt_for_attack(Algorithm::ChaCha20Poly1305, b"sensitive payload");
    let wrong = [0xffu8; 32];
    let err = try_decrypt(&wrong, &wire).unwrap_err();
    assert_eq!(err, Error::AuthenticationFailed);
}

#[test]
fn tampered_chunk_fails_authentication() {
    let (key, mut wire) = encrypt_for_attack(Algorithm::ChaCha20Poly1305, &vec![0u8; 2048]);
    // Flip one byte well into a chunk body (skip the header).
    let pos = HEADER_LEN + 100;
    wire[pos] ^= 0x01;
    let err = try_decrypt(&key, &wire).unwrap_err();
    assert_eq!(err, Error::AuthenticationFailed);
}

#[test]
fn tampered_tag_fails_authentication() {
    let (key, mut wire) = encrypt_for_attack(Algorithm::ChaCha20Poly1305, b"x");
    // Flip the final byte (inside the last chunk's tag).
    let last = wire.len() - 1;
    wire[last] ^= 0xff;
    let err = try_decrypt(&key, &wire).unwrap_err();
    assert_eq!(err, Error::AuthenticationFailed);
}

#[test]
fn truncated_to_zero_chunks_fails() {
    let (key, wire) = encrypt_for_attack(Algorithm::ChaCha20Poly1305, b"data");
    // Drop everything past the header.
    let truncated = &wire[..HEADER_LEN];
    let err = try_decrypt(&key, truncated).unwrap_err();
    // Either InvalidCiphertext (buffer too short) or AuthenticationFailed.
    assert!(
        matches!(
            err,
            Error::InvalidCiphertext(_) | Error::AuthenticationFailed
        ),
        "{err:?}",
    );
}

#[test]
fn truncated_mid_final_chunk_fails() {
    let (key, wire) = encrypt_for_attack(Algorithm::ChaCha20Poly1305, b"data");
    // Drop the last 4 bytes of the final tag.
    let truncated = &wire[..wire.len() - 4];
    let err = try_decrypt(&key, truncated).unwrap_err();
    assert_eq!(err, Error::AuthenticationFailed);
}

#[test]
fn dropped_final_chunk_fails() {
    let key = [0xa9u8; 32];
    // Multiple chunks so we can drop just the final one cleanly.
    let plaintext = vec![0x77u8; 1024 * 3];
    let (mut enc, header) =
        StreamEncryptor::new_with_chunk_size(&key, Algorithm::ChaCha20Poly1305, 10).unwrap();
    let mut wire = header.to_vec();
    wire.extend(enc.update(&plaintext).unwrap());
    let chunk_size = 1024usize;
    let chunk_frame = chunk_size + TAG_LEN;
    // Cut off the final chunk (we know it's the last 16 bytes — empty
    // plaintext + tag — because plaintext is an exact multiple of
    // chunk_size and encryptor emits a 0-byte final chunk in that
    // case).
    wire.extend(enc.finalize().unwrap());
    let body_len = wire.len() - HEADER_LEN;
    assert!(body_len > chunk_frame, "body should exceed one chunk");
    // Drop the final chunk (just the 16-byte tag, since plaintext was
    // an exact multiple of chunk_size).
    let cut_at = wire.len() - 16;
    let truncated = &wire[..cut_at];
    let err = try_decrypt(&key, truncated).unwrap_err();
    assert_eq!(err, Error::AuthenticationFailed);
}

#[test]
fn swapped_chunks_fail_authentication() {
    let key = [0xb0u8; 32];
    // Two full chunks then a final chunk.
    let plaintext = vec![0u8; 1024 * 2 + 50];
    let chunk_log2 = 10;
    let chunk_size = 1024usize;
    let chunk_frame = chunk_size + TAG_LEN;

    let (mut enc, header) =
        StreamEncryptor::new_with_chunk_size(&key, Algorithm::ChaCha20Poly1305, chunk_log2)
            .unwrap();
    let mut wire = header.to_vec();
    wire.extend(enc.update(&plaintext).unwrap());
    wire.extend(enc.finalize().unwrap());

    // Swap chunk 0 with chunk 1 in place.
    let body_start = HEADER_LEN;
    let mid = body_start + chunk_frame;
    let end = body_start + 2 * chunk_frame;
    let chunk_0: Vec<u8> = wire[body_start..mid].to_vec();
    let chunk_1: Vec<u8> = wire[mid..end].to_vec();
    wire[body_start..mid].copy_from_slice(&chunk_1);
    wire[mid..end].copy_from_slice(&chunk_0);

    let err = try_decrypt(&key, &wire).unwrap_err();
    assert_eq!(err, Error::AuthenticationFailed);
}

#[test]
fn duplicated_chunk_fails_authentication() {
    let key = [0xc0u8; 32];
    let plaintext = vec![0u8; 1024 * 2 + 50];
    let chunk_log2 = 10;
    let chunk_size = 1024usize;
    let chunk_frame = chunk_size + TAG_LEN;

    let (mut enc, header) =
        StreamEncryptor::new_with_chunk_size(&key, Algorithm::ChaCha20Poly1305, chunk_log2)
            .unwrap();
    let mut wire = header.to_vec();
    wire.extend(enc.update(&plaintext).unwrap());
    wire.extend(enc.finalize().unwrap());

    // Replace chunk 1 with a duplicate of chunk 0.
    let body_start = HEADER_LEN;
    let mid = body_start + chunk_frame;
    let end = body_start + 2 * chunk_frame;
    let chunk_0: Vec<u8> = wire[body_start..mid].to_vec();
    wire[mid..end].copy_from_slice(&chunk_0);

    let err = try_decrypt(&key, &wire).unwrap_err();
    assert_eq!(err, Error::AuthenticationFailed);
}

#[test]
fn tampered_header_algorithm_fails_authentication() {
    let (key, mut wire) = encrypt_for_attack(Algorithm::ChaCha20Poly1305, b"data");
    // Flip the algorithm byte to AES-256-GCM. Header parsing still
    // succeeds (it's a valid algorithm), but the per-chunk AEAD then
    // uses the wrong primitive AND the AAD doesn't match what the
    // encoder used → authentication failure.
    wire[9] = 0x01;
    let err = try_decrypt(&key, &wire).unwrap_err();
    assert_eq!(err, Error::AuthenticationFailed);
}

#[test]
fn tampered_header_nonce_prefix_fails_authentication() {
    let (key, mut wire) = encrypt_for_attack(Algorithm::ChaCha20Poly1305, b"data");
    wire[16] ^= 0x01; // flip first byte of nonce prefix
    let err = try_decrypt(&key, &wire).unwrap_err();
    assert_eq!(err, Error::AuthenticationFailed);
}

#[test]
fn tampered_header_magic_fails_to_parse() {
    let (key, mut wire) = encrypt_for_attack(Algorithm::ChaCha20Poly1305, b"data");
    wire[0] = b'X';
    let err = try_decrypt(&key, &wire).unwrap_err();
    assert!(matches!(err, Error::InvalidCiphertext(_)), "{err:?}");
}

#[test]
fn wrong_key_length_rejected() {
    let (_key, wire) = encrypt_for_attack(Algorithm::ChaCha20Poly1305, b"data");
    let short_key = [0u8; 16];
    let err = StreamDecryptor::new(&short_key, &wire[..HEADER_LEN]).unwrap_err();
    assert_eq!(
        err,
        Error::InvalidKey {
            expected: 32,
            actual: 16
        }
    );
}

#[test]
fn nonce_prefix_differs_per_stream() {
    let key = [0u8; 32];
    let (_a, header_a) = StreamEncryptor::new(&key, Algorithm::ChaCha20Poly1305).unwrap();
    let (_b, header_b) = StreamEncryptor::new(&key, Algorithm::ChaCha20Poly1305).unwrap();
    // Nonce prefix is in bytes 16..23 of the header — should differ
    // between two streams under the same key.
    assert_ne!(&header_a[16..23], &header_b[16..23]);
}

// ---------- File round-trip ----------

#[test]
fn file_round_trip_default_chunk_size() {
    use std::io::Write;

    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let in_path = dir.join(format!("crypt_io_stream_test_in_{pid}.bin"));
    let enc_path = dir.join(format!("crypt_io_stream_test_enc_{pid}.bin"));
    let dec_path = dir.join(format!("crypt_io_stream_test_dec_{pid}.bin"));

    // Cleanup on entry in case a previous run left junk.
    let _ = std::fs::remove_file(&in_path);
    let _ = std::fs::remove_file(&enc_path);
    let _ = std::fs::remove_file(&dec_path);

    let plaintext: Vec<u8> = (0..200_000u32).map(|i| (i & 0xff) as u8).collect();
    {
        let mut f = std::fs::File::create(&in_path).unwrap();
        f.write_all(&plaintext).unwrap();
    }

    let key = [0x55u8; 32];
    crypt_io::stream::encrypt_file(&in_path, &enc_path, &key, Algorithm::ChaCha20Poly1305).unwrap();
    crypt_io::stream::decrypt_file(&enc_path, &dec_path, &key).unwrap();

    let recovered = std::fs::read(&dec_path).unwrap();
    assert_eq!(recovered, plaintext);

    // Cleanup.
    let _ = std::fs::remove_file(&in_path);
    let _ = std::fs::remove_file(&enc_path);
    let _ = std::fs::remove_file(&dec_path);
}

#[test]
fn file_round_trip_aes() {
    use std::io::Write;

    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let in_path = dir.join(format!("crypt_io_stream_test_aes_in_{pid}.bin"));
    let enc_path = dir.join(format!("crypt_io_stream_test_aes_enc_{pid}.bin"));
    let dec_path = dir.join(format!("crypt_io_stream_test_aes_dec_{pid}.bin"));

    let _ = std::fs::remove_file(&in_path);
    let _ = std::fs::remove_file(&enc_path);
    let _ = std::fs::remove_file(&dec_path);

    let plaintext = b"the quick brown fox jumps over the lazy dog".repeat(500);
    {
        let mut f = std::fs::File::create(&in_path).unwrap();
        f.write_all(&plaintext).unwrap();
    }

    let key = [0x66u8; 32];
    crypt_io::stream::encrypt_file(&in_path, &enc_path, &key, Algorithm::Aes256Gcm).unwrap();
    crypt_io::stream::decrypt_file(&enc_path, &dec_path, &key).unwrap();

    let recovered = std::fs::read(&dec_path).unwrap();
    assert_eq!(recovered, plaintext);

    let _ = std::fs::remove_file(&in_path);
    let _ = std::fs::remove_file(&enc_path);
    let _ = std::fs::remove_file(&dec_path);
}
