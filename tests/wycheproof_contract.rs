//! Offline Project Wycheproof evidence for the exact crypt-io primitive suite.

#![cfg(feature = "storage-v1")]
#![allow(clippy::unwrap_used)]

use aes_gcm::{
    Aes256Gcm,
    aead::{AeadInOut, KeyInit, Nonce, Tag},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;

const AES_GCM_JSON: &str = include_str!("data/wycheproof/aes_gcm_test.json");
const HKDF_SHA256_JSON: &str = include_str!("data/wycheproof/hkdf_sha256_test.json");
const HMAC_SHA256_JSON: &str = include_str!("data/wycheproof/hmac_sha256_test.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ExpectedResult {
    Valid,
    Invalid,
    Acceptable,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AeadTestSet {
    algorithm: String,
    schema: String,
    number_of_tests: usize,
    test_groups: Vec<AeadTestGroup>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AeadTestGroup {
    key_size: u32,
    iv_size: u32,
    tag_size: u32,
    tests: Vec<AeadTest>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AeadTest {
    tc_id: u32,
    key: String,
    iv: String,
    aad: String,
    msg: String,
    ct: String,
    tag: String,
    result: ExpectedResult,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HkdfTestSet {
    algorithm: String,
    schema: String,
    number_of_tests: usize,
    test_groups: Vec<HkdfTestGroup>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HkdfTestGroup {
    key_size: u32,
    tests: Vec<HkdfTest>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HkdfTest {
    tc_id: u32,
    ikm: String,
    salt: String,
    info: String,
    size: usize,
    okm: String,
    result: ExpectedResult,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HmacTestSet {
    algorithm: String,
    schema: String,
    number_of_tests: usize,
    test_groups: Vec<HmacTestGroup>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HmacTestGroup {
    key_size: u32,
    tag_size: u32,
    tests: Vec<HmacTest>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct HmacTest {
    tc_id: u32,
    key: String,
    msg: String,
    tag: String,
    result: ExpectedResult,
}

#[test]
fn aes_256_gcm_passes_all_applicable_wycheproof_cases() {
    let vectors: AeadTestSet = serde_json::from_str(AES_GCM_JSON).unwrap();
    assert_eq!(vectors.algorithm, "AES-GCM");
    assert_eq!(vectors.schema, "aead_test_schema_v1.json");
    assert_eq!(vectors.number_of_tests, 316);
    assert_eq!(
        vectors
            .test_groups
            .iter()
            .map(|group| group.tests.len())
            .sum::<usize>(),
        vectors.number_of_tests
    );

    let mut applicable = 0_usize;
    let mut valid = 0_usize;
    let mut invalid = 0_usize;
    let mut acceptable = 0_usize;
    for group in vectors.test_groups {
        if group.key_size != 256 || group.iv_size != 96 || group.tag_size != 128 {
            continue;
        }
        for test in group.tests {
            applicable += 1;
            let key = decode_hex(&test.key).unwrap();
            let iv = decode_hex(&test.iv).unwrap();
            let aad = decode_hex(&test.aad).unwrap();
            let message = decode_hex(&test.msg).unwrap();
            let ciphertext = decode_hex(&test.ct).unwrap();
            let tag_bytes = decode_hex(&test.tag).unwrap();
            let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
            let nonce = Nonce::<Aes256Gcm>::try_from(iv.as_slice()).unwrap();
            let tag = Tag::<Aes256Gcm>::try_from(tag_bytes.as_slice()).unwrap();
            let mut opened = ciphertext.clone();
            let open_result =
                cipher.decrypt_inout_detached(&nonce, &aad, opened.as_mut_slice().into(), &tag);

            match test.result {
                ExpectedResult::Valid => {
                    valid += 1;
                    assert!(open_result.is_ok(), "valid tcId {} rejected", test.tc_id);
                    assert_eq!(
                        opened, message,
                        "plaintext mismatch for tcId {}",
                        test.tc_id
                    );

                    let mut sealed = message;
                    let produced_tag = cipher
                        .encrypt_inout_detached(&nonce, &aad, sealed.as_mut_slice().into())
                        .unwrap();
                    assert_eq!(
                        sealed, ciphertext,
                        "ciphertext mismatch for tcId {}",
                        test.tc_id
                    );
                    assert_eq!(
                        produced_tag.as_slice(),
                        tag_bytes,
                        "tag mismatch for tcId {}",
                        test.tc_id
                    );
                }
                ExpectedResult::Invalid => {
                    invalid += 1;
                    assert!(open_result.is_err(), "invalid tcId {} accepted", test.tc_id);
                }
                ExpectedResult::Acceptable => acceptable += 1,
            }
        }
    }

    assert_eq!((applicable, valid, invalid, acceptable), (66, 39, 27, 0));
}

#[test]
fn hkdf_sha256_passes_all_256_bit_ikm_wycheproof_cases() {
    let vectors: HkdfTestSet = serde_json::from_str(HKDF_SHA256_JSON).unwrap();
    assert_eq!(vectors.algorithm, "HKDF-SHA-256");
    assert_eq!(vectors.schema, "hkdf_test_schema_v1.json");
    assert_eq!(vectors.number_of_tests, 86);
    assert_eq!(
        vectors
            .test_groups
            .iter()
            .map(|group| group.tests.len())
            .sum::<usize>(),
        vectors.number_of_tests
    );

    let mut applicable = 0_usize;
    let mut valid = 0_usize;
    let mut invalid = 0_usize;
    let mut acceptable = 0_usize;
    for group in vectors.test_groups {
        if group.key_size != 256 {
            continue;
        }
        for test in group.tests {
            applicable += 1;
            let ikm = decode_hex(&test.ikm).unwrap();
            let salt = decode_hex(&test.salt).unwrap();
            let info = decode_hex(&test.info).unwrap();
            let expected = decode_hex(&test.okm).unwrap();
            let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);
            let mut output = vec![0_u8; test.size];
            let expand_result = hkdf.expand(&info, &mut output);

            match test.result {
                ExpectedResult::Valid => {
                    valid += 1;
                    assert!(expand_result.is_ok(), "valid tcId {} rejected", test.tc_id);
                    assert_eq!(output, expected, "output mismatch for tcId {}", test.tc_id);
                }
                ExpectedResult::Invalid => {
                    invalid += 1;
                    assert!(
                        expand_result.is_err(),
                        "invalid tcId {} accepted",
                        test.tc_id
                    );
                }
                ExpectedResult::Acceptable => acceptable += 1,
            }
        }
    }

    assert_eq!((applicable, valid, invalid, acceptable), (37, 36, 1, 0));
}

#[test]
fn hmac_sha256_passes_all_full_tag_256_bit_key_wycheproof_cases() {
    let vectors: HmacTestSet = serde_json::from_str(HMAC_SHA256_JSON).unwrap();
    assert_eq!(vectors.algorithm, "HMACSHA256");
    assert_eq!(vectors.schema, "mac_test_schema_v1.json");
    assert_eq!(vectors.number_of_tests, 174);
    assert_eq!(
        vectors
            .test_groups
            .iter()
            .map(|group| group.tests.len())
            .sum::<usize>(),
        vectors.number_of_tests
    );

    let mut applicable = 0_usize;
    let mut valid = 0_usize;
    let mut invalid = 0_usize;
    let mut acceptable = 0_usize;
    for group in vectors.test_groups {
        if group.key_size != 256 || group.tag_size != 256 {
            continue;
        }
        for test in group.tests {
            applicable += 1;
            let key = decode_hex(&test.key).unwrap();
            let message = decode_hex(&test.msg).unwrap();
            let tag = decode_hex(&test.tag).unwrap();
            let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(&key).unwrap();
            mac.update(&message);
            let verify_result = mac.verify_slice(&tag);

            match test.result {
                ExpectedResult::Valid => {
                    valid += 1;
                    assert!(verify_result.is_ok(), "valid tcId {} rejected", test.tc_id);
                }
                ExpectedResult::Invalid => {
                    invalid += 1;
                    assert!(
                        verify_result.is_err(),
                        "invalid tcId {} accepted",
                        test.tc_id
                    );
                }
                ExpectedResult::Acceptable => acceptable += 1,
            }
        }
    }

    assert_eq!((applicable, valid, invalid, acceptable), (81, 27, 54, 0));
}

fn decode_hex(input: &str) -> Result<Vec<u8>, &'static str> {
    if input.len() % 2 != 0 {
        return Err("hex input has an odd number of digits");
    }
    let mut output = Vec::with_capacity(input.len() / 2);
    for pair in input.as_bytes().chunks_exact(2) {
        let high = hex_nibble(pair[0]).ok_or("hex input contains a non-hex digit")?;
        let low = hex_nibble(pair[1]).ok_or("hex input contains a non-hex digit")?;
        output.push((high << 4) | low);
    }
    Ok(output)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
