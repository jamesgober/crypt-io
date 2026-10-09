//! Coverage for the APIs and behaviour changes added in 1.1.0, through
//! the public surface only.

#![cfg(all(
    feature = "stream",
    feature = "aead-chacha20",
    feature = "aead-aes-gcm",
    feature = "mac-hmac",
    feature = "mac-blake3"
))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crypt_io::stream::{
    self, DEFAULT_CHUNK_SIZE_LOG2, HEADER_LEN, SALT_LEN, StreamDecryptor, StreamEncryptor,
    StreamFormat,
};
use crypt_io::{Algorithm, Crypt, Error, Tag, mac};

fn encrypt_stream(key: &[u8; 32], alg: Algorithm, format: StreamFormat, pt: &[u8]) -> Vec<u8> {
    let (mut enc, header) = StreamEncryptor::new_with_format(key, alg, 10, format).unwrap();
    let mut wire = header.to_vec();
    wire.extend(enc.update(pt).unwrap());
    wire.extend(enc.finalize().unwrap());
    wire
}

fn decrypt_stream(key: &[u8; 32], wire: &[u8]) -> Result<Vec<u8>, Error> {
    let mut dec = StreamDecryptor::new(key, &wire[..HEADER_LEN])?;
    let mut out = dec.update(&wire[HEADER_LEN..])?;
    out.extend(dec.finalize()?);
    Ok(out)
}

#[test]
fn every_algorithm_and_format_round_trips() {
    let key = [0x21u8; 32];
    let pt: Vec<u8> = (0..5000u32).map(|i| (i % 253) as u8).collect();
    for alg in [
        Algorithm::ChaCha20Poly1305,
        Algorithm::Aes256Gcm,
        Algorithm::XChaCha20Poly1305,
    ] {
        for format in [StreamFormat::V1, StreamFormat::V2] {
            if format == StreamFormat::V1 && alg == Algorithm::XChaCha20Poly1305 {
                continue;
            }
            let wire = encrypt_stream(&key, alg, format, &pt);
            assert_eq!(wire[8], format.version_byte());
            let extra = if format == StreamFormat::V2 {
                SALT_LEN
            } else {
                0
            };
            // 4 full chunks + a 904-byte final chunk, 16-byte tags.
            assert_eq!(
                wire.len(),
                HEADER_LEN + extra + 5000 + 5 * 16,
                "{alg:?} {format:?}"
            );
            let dec = StreamDecryptor::new(&key, &wire[..HEADER_LEN]).unwrap();
            assert_eq!((dec.algorithm(), dec.format()), (alg, format));
            assert_eq!(
                decrypt_stream(&key, &wire).unwrap(),
                pt,
                "{alg:?} {format:?}"
            );
            // Wrong key fails.
            assert_eq!(
                decrypt_stream(&[0x22u8; 32], &wire).unwrap_err(),
                Error::AuthenticationFailed
            );
        }
    }
}

#[test]
fn default_constructors_write_v2() {
    let (enc, header) = StreamEncryptor::new(&[1u8; 32], Algorithm::Aes256Gcm).unwrap();
    assert_eq!(enc.format(), StreamFormat::V2);
    assert_eq!(header[8], 0x02);
    assert_eq!(StreamFormat::default(), StreamFormat::V2);
    let (enc, _) =
        StreamEncryptor::new_with_chunk_size(&[1u8; 32], Algorithm::Aes256Gcm, 12).unwrap();
    assert_eq!(enc.format(), StreamFormat::V2);
}

#[test]
fn v2_salt_is_emitted_even_without_update() {
    let key = [3u8; 32];
    let (enc, header) = StreamEncryptor::new(&key, Algorithm::ChaCha20Poly1305).unwrap();
    let tail = enc.finalize().unwrap();
    assert_eq!(tail.len(), SALT_LEN + 16);
    let mut wire = header.to_vec();
    wire.extend(tail);
    assert_eq!(decrypt_stream(&key, &wire).unwrap(), b"");
}

#[test]
fn v2_salt_is_emitted_once_with_empty_updates() {
    let key = [4u8; 32];
    let (mut enc, header) = StreamEncryptor::new(&key, Algorithm::ChaCha20Poly1305).unwrap();
    let mut wire = header.to_vec();
    let mut out = Vec::new();
    enc.update_into(&[], &mut out).unwrap();
    assert_eq!(out.len(), SALT_LEN);
    wire.extend(&out);
    wire.extend(enc.update(&[]).unwrap());
    wire.extend(enc.update(b"abc").unwrap());
    wire.extend(enc.finalize().unwrap());
    assert_eq!(decrypt_stream(&key, &wire).unwrap(), b"abc");
}

#[test]
fn file_helper_errors_use_the_new_variants() {
    let dir = std::env::temp_dir();
    let missing = dir.join("crypt_io_v1_1_missing_input.bin");
    let _ = std::fs::remove_file(&missing);
    let out = dir.join("crypt_io_v1_1_out.bin");
    let key = [0u8; 32];
    assert!(matches!(
        stream::encrypt_file(&missing, &out, &key, Algorithm::ChaCha20Poly1305).unwrap_err(),
        Error::Io(_)
    ));
    assert!(matches!(
        stream::decrypt_file(&missing, &out, &key).unwrap_err(),
        Error::Io(_)
    ));

    let same = dir.join("crypt_io_v1_1_same.bin");
    std::fs::write(&same, b"data").unwrap();
    assert!(matches!(
        stream::encrypt_file(&same, &same, &key, Algorithm::ChaCha20Poly1305).unwrap_err(),
        Error::InvalidInput(_)
    ));
    assert_eq!(std::fs::read(&same).unwrap(), b"data");
    let _ = std::fs::remove_file(&same);
}

#[test]
fn encrypt_file_writes_v2_and_reads_v1() {
    let dir = std::env::temp_dir();
    let input = dir.join("crypt_io_v1_1_input.bin");
    let enc = dir.join("crypt_io_v1_1_input.enc");
    let back = dir.join("crypt_io_v1_1_back.bin");
    let pt: Vec<u8> = (0..100_000u32).map(|i| (i * 31 % 256) as u8).collect();
    std::fs::write(&input, &pt).unwrap();
    let key = [9u8; 32];

    stream::encrypt_file(&input, &enc, &key, Algorithm::XChaCha20Poly1305).unwrap();
    assert_eq!(std::fs::read(&enc).unwrap()[8], 0x02);
    stream::decrypt_file(&enc, &back, &key).unwrap();
    assert_eq!(std::fs::read(&back).unwrap(), pt);

    // A v1 file, as crypt-io 1.0.x wrote it, still decrypts.
    let (mut e, header) = StreamEncryptor::new_with_format(
        &key,
        Algorithm::ChaCha20Poly1305,
        DEFAULT_CHUNK_SIZE_LOG2,
        StreamFormat::V1,
    )
    .unwrap();
    let mut wire = header.to_vec();
    wire.extend(e.update(&pt).unwrap());
    wire.extend(e.finalize().unwrap());
    std::fs::write(&enc, &wire).unwrap();
    stream::decrypt_file(&enc, &back, &key).unwrap();
    assert_eq!(std::fs::read(&back).unwrap(), pt);

    for p in [&input, &enc, &back] {
        let _ = std::fs::remove_file(p);
    }
}

#[test]
fn check_functions_and_tag() {
    let key = b"k";
    let tag = mac::hmac_sha256(key, b"body").unwrap();
    mac::hmac_sha256_check(key, b"body", &tag).unwrap();
    assert_eq!(
        mac::hmac_sha256_check(key, b"body2", &tag),
        Err(Error::AuthenticationFailed)
    );
    let t = Tag::from(tag);
    assert!(t == tag);
    assert!(t == tag[..]);
    assert!(t != [0u8; 32]);
    assert_eq!(Tag::<32>::try_from(&tag[..]).unwrap(), t);

    let k32 = [7u8; 32];
    let b3 = mac::blake3_keyed(&k32, b"body");
    mac::blake3_keyed_check(&k32, b"body", &b3).unwrap();
    let mut m = mac::Blake3Mac::new(&k32);
    m.update(b"bo").update(b"dy");
    m.check(&b3).unwrap();
    assert_eq!(
        mac::blake3_keyed_check(&k32, b"body", &b3[..16]),
        Err(Error::AuthenticationFailed)
    );
}

#[test]
fn sealed_format_survives_an_algorithm_switch() {
    let key = [0x55u8; 32];
    let old = Crypt::aes_256_gcm()
        .seal_with_aad(&key, b"row 1", b"users")
        .unwrap();
    let new = Crypt::xchacha20_poly1305()
        .seal_with_aad(&key, b"row 2", b"users")
        .unwrap();
    let reader = Crypt::new();
    assert_eq!(
        reader.open_with_aad(&key, &old, b"users").unwrap(),
        b"row 1"
    );
    assert_eq!(
        reader.open_with_aad(&key, &new, b"users").unwrap(),
        b"row 2"
    );
}

#[test]
fn new_error_variants_render_without_secrets() {
    for e in [
        Error::Io("stream: read input"),
        Error::InvalidInput("stream: chunk_size_log2 out of range (10..=24)"),
        Error::LimitExceeded("stream: chunk counter overflow"),
    ] {
        let shown = e.to_string();
        assert!(!shown.is_empty());
        let _: &dyn core::error::Error = &e;
    }
}
