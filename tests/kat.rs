//! Known-answer tests run through the public `crypt-io` surface.
//!
//! The backend unit tests check the upstream crates directly. These
//! tests check that published spec vectors, laid out in crypt-io's own
//! wire formats, decrypt through `Crypt` and `StreamDecryptor`, and that
//! the 1.x stream format stays byte-for-byte stable.

#![cfg(all(
    feature = "stream",
    feature = "aead-chacha20",
    feature = "aead-aes-gcm"
))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crypt_io::stream::{HEADER_LEN, SALT_LEN, StreamDecryptor, StreamFormat};
use crypt_io::{Algorithm, Crypt, Error};

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

/// RFC 8439 section 2.8.2, laid out as crypt-io's single-shot wire
/// format `nonce || ciphertext || tag` and decrypted through
/// `Crypt::decrypt_with_aad`.
#[test]
fn rfc8439_2_8_2_decrypts_through_crypt() {
    let key = h("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    let nonce = h("070000004041424344454647");
    let aad = h("50515253c0c1c2c3c4c5c6c7");
    let ct = h(concat!(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6",
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36",
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc",
        "3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd060",
        "0691",
    ));
    let plaintext: &[u8] = b"Ladies and Gentlemen of the class of '99: \
        If I could offer you only one tip for the future, sunscreen would be it.";

    let mut wire = nonce.clone();
    wire.extend_from_slice(&ct);
    let crypt = Crypt::new();
    assert_eq!(
        crypt.decrypt_with_aad(&key, &wire, &aad).unwrap(),
        plaintext
    );

    let mut out = vec![0xffu8; 3];
    crypt
        .decrypt_with_aad_into(&key, &wire, &aad, &mut out)
        .unwrap();
    assert_eq!(out, plaintext);

    // Same bytes with the AAD dropped must fail.
    assert_eq!(
        crypt.decrypt(&key, &wire).unwrap_err(),
        Error::AuthenticationFailed
    );
}

/// GCM spec (McGrew and Viega) Test Case 16: AES-256, 96-bit IV, with
/// AAD. Decrypted through `Crypt::decrypt_with_aad`.
#[test]
fn gcm_test_case_16_decrypts_through_crypt() {
    let key = h("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
    let iv = h("cafebabefacedbaddecaf888");
    let aad = h("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    let plaintext = h(concat!(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72",
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
    ));
    let ciphertext = h(concat!(
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa",
        "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
    ));
    let tag = h("76fc6ece0f4e1768cddf8853bb2d551b");

    let mut wire = iv;
    wire.extend_from_slice(&ciphertext);
    wire.extend_from_slice(&tag);
    let crypt = Crypt::aes_256_gcm();
    assert_eq!(
        crypt.decrypt_with_aad(&key, &wire, &aad).unwrap(),
        plaintext
    );

    let mut out = Vec::new();
    crypt
        .decrypt_with_aad_into(&key, &wire, &aad, &mut out)
        .unwrap();
    assert_eq!(out, plaintext);

    let mut bad_aad = aad.clone();
    bad_aad[0] ^= 1;
    assert_eq!(
        crypt.decrypt_with_aad(&key, &wire, &bad_aad).unwrap_err(),
        Error::AuthenticationFailed
    );
}

// Frozen stream vectors. Produced from the raw `chacha20poly1305` /
// `aes-gcm` crates following docs/FILE_FORMAT.md (not with crypt-io's
// stream code): key = 00 01 .. 1f, nonce prefix = a0 a1 .. a6.
// Any change to the 1.x stream format breaks these tests.

/// ChaCha20-Poly1305, chunk_size_log2 = 10, plaintext = 1100 bytes of
/// `i % 251`: one full non-final chunk plus a 76-byte final chunk.
const STREAM_CHACHA_1100: &str = concat!(
    "894352595054494f01000a0000000000a0a1a2a3a4a5a6006c380bbdd4d28f3e",
    "de2781d82a70cc871ea33863e15f2dcc782dd7f0ee94dcd118b7a4f9a8805653",
    "91da0513d59dd0e5e200c71b1ce820a84a92b59f29c9deb750d1435b1c0681db",
    "609d48983c8a0552b88d39eb38171392fb123ed17030c714bf43f6414e30f0b8",
    "7e8513134aabd48c533a39129ddd9502bfb091e601c2f19457c771be6cd15de3",
    "6193f51152c0f894213b5933769c0bff09f8d87157ef3ddcf75f63e0175b7109",
    "bcd7b5dff555f6b9bd6076612941a6ec48500981b1d097f41b2cebc5d5fc9773",
    "00a5ad4c4e77d7ee5db3ed14a89cad46c17638e580533f30d228f75f87d4bdaf",
    "4b67683569c4dacb401bc1cf0807f0f9119793f7009a1af0f7917d9c78f67a5e",
    "481542842c0c06897f502759e14f05b5a9fb6e1acef8b4c2f46c69285c50d4c1",
    "53675f4083449b729d54e26a819f6f75ae1f3896cc21988932fceb9e2ccb835e",
    "2aca47f65ca45fa27f802c06f8fdf6f71adc26dde86eb574588d29faedb19a54",
    "6c46b74e4d63af5afe1b8ff1301d97c24906288a5620c74df2268add80b4e0ba",
    "f3d826df5325ccaf89a4d1c9d20ff4dbdfed56dc6bad6328be4f8b7185c455d9",
    "2675a3395bc400af9123da635697187b1ee603d9fba2950607b26f5a30d6c96b",
    "30ec1aefd22965051632129e211b764232d53a8486d23f5ed6522b6f5c21a7ea",
    "9d8e7598bbe054195140ac78b2e3d056b303c4aa5d9fd24f3681650c0a8835d9",
    "c6f522e9ec9956165f834884a521c9de73da4add585b9e30970798d11c4ac1d7",
    "89e8087091fc684376215cd77a1b85d8535ec2086107e41eb90e9037adeb5f4d",
    "57d98354d61f6b2f00f9254c97db215121250c694c5221664f94c994f67ada11",
    "67cd114770d87dcfa358a971dee9a2065edc88581724b18844ff9dc5ce7c66e3",
    "ecff873466ffa25a9a68d25888be1aae61c0578ae007ec0dda486f33e3d57dab",
    "b63d65e67f193f8e037955acdf5e810773ae0a12de9ace058ea1d69f9a3c4aee",
    "da6ff59ec8e260b134c3f3c97e213bb022ce62bd8b0704cdc5714328122a6142",
    "82b71dba12dd17478cf7cb8a7e91e9b768ac2df954ea7c3a14715f05ab44bd6c",
    "beaf0b28b5cceee8cf57453971dfbed8941bf61fb32dfb61a8f8bf3b1db9be2f",
    "0d26ad3e462dd2ee34ecce911453cd4b7517d514451d5241fd89d94ab81234f4",
    "7dc4defc43eb0bc57e9740c98f9aa8269c5657863c3e8dceb7c10ffc4029092b",
    "7041bbaf778d2aab56b3a646c95fffe69101e37d696df111a0ba8d8158710c43",
    "43a1d09945ef76c94098eddb9f0bb8d317ba05800f07a3d96e3c2b23866fe86b",
    "62f53782986ff5c0b9062e396cb697017da89de1a4253ac77bc97f658c816ee8",
    "053811107fa292ed39e87fdabdd4d1c82106651d5f5fe3482bea8e8d9d8f2122",
    "3bbfc69c5e7672d1b03f9ea8e96aafc2ba23b5b20cd59f82ea2a21f3502892c3",
    "896bbeb566e522d717b51ae237d9d33a57d68e10042abd35028e063d6533b127",
    "e6eef05f24f0ed70803a0d521730a938d243aae76d3fa5c27c46654332715c8c",
    "5c4921279e92941651bdcec52e750c9c43fc1835354a8e9ae397bf1f73eba936",
    "93962878",
);

/// AES-256-GCM, chunk_size_log2 = 16, a single short final chunk.
const STREAM_AES_SHORT: &str = concat!(
    "894352595054494f0101100000000000a0a1a2a3a4a5a6001413306ecc2b89af",
    "2316ac5daaefd67861645984a3965c6082ab663e232598d4d94c187d1cc0e629",
    "71ba66dd627a83be15e019a9408e68",
);

fn stream_key() -> [u8; 32] {
    core::array::from_fn(|i| u8::try_from(i).unwrap())
}

fn decrypt_stream(wire: &[u8], split: usize) -> Result<Vec<u8>, Error> {
    let key = stream_key();
    let mut dec = StreamDecryptor::new(&key, &wire[..HEADER_LEN])?;
    let body = &wire[HEADER_LEN..];
    let split = split.min(body.len());
    let mut pt = dec.update(&body[..split])?;
    pt.extend(dec.update(&body[split..])?);
    pt.extend(dec.finalize()?);
    Ok(pt)
}

#[test]
fn frozen_chacha_stream_decrypts() {
    let wire = h(STREAM_CHACHA_1100);
    let expected: Vec<u8> = (0..1100u32)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect();
    for split in [0, 1, 1039, 1040, 1041, wire.len()] {
        assert_eq!(
            decrypt_stream(&wire, split).unwrap(),
            expected,
            "split={split}"
        );
    }
    // Last byte flipped: the final chunk must fail.
    let mut bad = wire.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert_eq!(
        decrypt_stream(&bad, 0).unwrap_err(),
        Error::AuthenticationFailed
    );
}

#[test]
fn frozen_aes_stream_decrypts() {
    let wire = h(STREAM_AES_SHORT);
    assert_eq!(
        decrypt_stream(&wire, 7).unwrap(),
        b"crypt-io stream format v1 frozen vector"
    );
}

// ---- Stream format v2 (1.1.0) ----

include!("../src/stream/test_vectors.rs");

#[test]
fn frozen_v2_aes_stream_decrypts() {
    // Small enough for the Miri CI job.
    let wire = h(STREAM_V2_AES_SHORT);
    assert_eq!(
        decrypt_stream(&wire, SALT_LEN / 2).unwrap(),
        b"crypt-io stream format v2 frozen vector"
    );
}

#[test]
#[cfg_attr(miri, ignore = "several KiB through three AEADs is slow under Miri")]
fn frozen_v2_streams_decrypt() {
    let cases: [(&str, Algorithm, Vec<u8>); 3] = [
        (
            STREAM_V2_CHACHA_1100,
            Algorithm::ChaCha20Poly1305,
            (0..1100u32)
                .map(|i| u8::try_from(i % 251).unwrap())
                .collect(),
        ),
        (
            STREAM_V2_AES_SHORT,
            Algorithm::Aes256Gcm,
            b"crypt-io stream format v2 frozen vector".to_vec(),
        ),
        (
            STREAM_V2_XCHACHA_2048,
            Algorithm::XChaCha20Poly1305,
            (0..2048u32)
                .map(|i| u8::try_from((i * 7) % 256).unwrap())
                .collect(),
        ),
    ];
    for (hex_wire, alg, expected) in cases {
        let wire = h(hex_wire);
        let dec = StreamDecryptor::new(&stream_key(), &wire[..HEADER_LEN]).unwrap();
        assert_eq!(dec.format(), StreamFormat::V2);
        assert_eq!(dec.algorithm(), alg);
        // Split points inside the salt, at its end, and inside chunks.
        for split in [0, 1, SALT_LEN - 1, SALT_LEN, SALT_LEN + 1, 1000, wire.len()] {
            assert_eq!(
                decrypt_stream(&wire, split).unwrap(),
                expected,
                "{alg:?} split={split}"
            );
        }
        // Any flipped bit in the salt or the last byte must fail.
        for pos in [HEADER_LEN, HEADER_LEN + SALT_LEN - 1, wire.len() - 1] {
            let mut bad = wire.clone();
            bad[pos] ^= 1;
            assert_eq!(
                decrypt_stream(&bad, 0).unwrap_err(),
                Error::AuthenticationFailed,
                "{alg:?} pos={pos}"
            );
        }
    }
}

#[test]
fn v2_stream_cut_inside_the_salt_is_rejected() {
    let wire = h(STREAM_V2_AES_SHORT);
    for cut in [HEADER_LEN, HEADER_LEN + 1, HEADER_LEN + SALT_LEN - 1] {
        let err = decrypt_stream(&wire[..cut], 0).unwrap_err();
        assert!(
            matches!(err, Error::InvalidCiphertext(_)),
            "cut={cut}: {err:?}"
        );
    }
}
