//! Contract and published-vector evidence for strict detached Ed25519 verification.

#![allow(clippy::unwrap_used)]

use crypt_io::signature::{
    Ed25519PublicKey, Ed25519Signature, SignatureError, verify_ed25519_detached,
};
use error_forge::ForgeError;
use hex_literal::hex;
use serde::Deserialize;

const ED25519_JSON: &str = include_str!("data/wycheproof/ed25519_test.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum ExpectedResult {
    Valid,
    Invalid,
    Acceptable,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Ed25519TestSet {
    algorithm: String,
    schema: String,
    number_of_tests: usize,
    test_groups: Vec<Ed25519TestGroup>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Ed25519TestGroup {
    #[serde(rename = "type")]
    group_type: String,
    public_key: WycheproofPublicKey,
    tests: Vec<Ed25519Test>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct WycheproofPublicKey {
    #[serde(rename = "type")]
    key_type: String,
    curve: String,
    key_size: u32,
    pk: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Ed25519Test {
    tc_id: u32,
    flags: Vec<String>,
    msg: String,
    sig: String,
    result: ExpectedResult,
}

#[test]
fn rfc_8032_vectors_verify_exact_message_bytes() {
    let first_key = Ed25519PublicKey::new(hex!(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    ));
    let first_signature = Ed25519Signature::new(hex!(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    ));
    assert!(verify_ed25519_detached(&first_key, b"", &first_signature).is_ok());

    let second_key = Ed25519PublicKey::new(hex!(
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
    ));
    let second_signature = Ed25519Signature::new(hex!(
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
    ));
    assert!(verify_ed25519_detached(&second_key, b"\x72", &second_signature).is_ok());
    assert!(verify_ed25519_detached(&second_key, b"\x73", &second_signature).is_err());
    assert!(verify_ed25519_detached(&first_key, b"\x72", &second_signature).is_err());
}

#[test]
fn altered_signature_is_rejected() {
    let key = Ed25519PublicKey::new(hex!(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    ));
    let mut signature_bytes = hex!(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    );
    signature_bytes[63] ^= 1;
    let signature = Ed25519Signature::new(signature_bytes);

    assert_eq!(
        verify_ed25519_detached(&key, b"", &signature),
        Err(SignatureError::VerificationFailed)
    );
}

#[test]
fn raw_fixed_width_boundaries_reject_every_wrong_length() {
    for length in [0_usize, 1, 31, 33, 63, 64, 65, 1_024] {
        let bytes = vec![0_u8; length];
        assert_eq!(
            Ed25519PublicKey::try_from_slice(&bytes),
            Err(SignatureError::InvalidPublicKeyLength)
        );
    }
    for length in [0_usize, 1, 31, 32, 33, 63, 65, 1_024] {
        let bytes = vec![0_u8; length];
        assert_eq!(
            Ed25519Signature::try_from_slice(&bytes),
            Err(SignatureError::InvalidSignatureLength)
        );
    }

    assert!(Ed25519PublicKey::try_from_slice(&[0_u8; 32]).is_ok());
    assert!(Ed25519Signature::try_from_slice(&[0_u8; 64]).is_ok());
}

#[test]
fn wrapper_debug_and_errors_do_not_disclose_bytes() {
    let key = Ed25519PublicKey::new([0xA5_u8; 32]);
    let signature = Ed25519Signature::new([0x5A_u8; 64]);

    assert_eq!(format!("{key:?}"), "Ed25519PublicKey([REDACTED])");
    assert_eq!(format!("{signature:?}"), "Ed25519Signature([REDACTED])");
    assert_eq!(
        SignatureError::VerificationFailed.to_string(),
        "Ed25519 signature verification failed"
    );
    assert_eq!(
        SignatureError::VerificationFailed.kind(),
        "VerificationFailed"
    );
    assert!(!SignatureError::VerificationFailed.is_retryable());
}

#[test]
fn fixed_width_wrappers_round_trip_public_bytes() {
    let key_bytes = [0x11_u8; 32];
    let signature_bytes = [0x22_u8; 64];

    assert_eq!(*Ed25519PublicKey::new(key_bytes).as_bytes(), key_bytes);
    assert_eq!(
        *Ed25519Signature::new(signature_bytes).as_bytes(),
        signature_bytes
    );
}

#[test]
fn strict_verifier_passes_all_pinned_wycheproof_cases() {
    let vectors: Ed25519TestSet = serde_json::from_str(ED25519_JSON).unwrap();
    assert_eq!(vectors.algorithm, "EDDSA");
    assert_eq!(vectors.schema, "eddsa_verify_schema_v1.json");
    assert_eq!(vectors.number_of_tests, 150);
    assert_eq!(
        vectors
            .test_groups
            .iter()
            .map(|group| group.tests.len())
            .sum::<usize>(),
        vectors.number_of_tests
    );

    let mut total = 0_usize;
    let mut valid = 0_usize;
    let mut invalid = 0_usize;
    let mut acceptable = 0_usize;
    for group in vectors.test_groups {
        assert_eq!(group.group_type, "EddsaVerify");
        assert_eq!(group.public_key.key_type, "EDDSAPublicKey");
        assert_eq!(group.public_key.curve, "edwards25519");
        assert_eq!(group.public_key.key_size, 255);
        let public_key_bytes = decode_hex(&group.public_key.pk).unwrap();
        let public_key = Ed25519PublicKey::try_from_slice(&public_key_bytes).unwrap();

        for test in group.tests {
            total += 1;
            let message = decode_hex(&test.msg).unwrap();
            let signature_bytes = decode_hex(&test.sig).unwrap();
            let verification = Ed25519Signature::try_from_slice(&signature_bytes)
                .and_then(|signature| verify_ed25519_detached(&public_key, &message, &signature));

            match test.result {
                ExpectedResult::Valid => {
                    valid += 1;
                    assert!(
                        verification.is_ok(),
                        "valid tcId {} rejected; flags={:?}",
                        test.tc_id,
                        test.flags
                    );
                }
                ExpectedResult::Invalid => {
                    invalid += 1;
                    assert!(
                        verification.is_err(),
                        "invalid tcId {} accepted; flags={:?}",
                        test.tc_id,
                        test.flags
                    );
                }
                ExpectedResult::Acceptable => acceptable += 1,
            }
        }
    }

    assert_eq!((total, valid, invalid, acceptable), (150, 88, 62, 0));
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
