//! PBKDF2-HMAC-SHA256 through the public surface.
//!
//! The grid (password, salt and output lengths around the SHA-256 block
//! size, several iteration counts) and the SCRAM values were computed
//! with Python's `hashlib` / `hmac` (`tests/data/gen_pbkdf2_grid.py`),
//! an implementation independent of crypt-io. The RFC vectors live in
//! the unit tests next to the implementation.

#![cfg(feature = "kdf-pbkdf2")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "data/pbkdf2_grid.rs"]
mod grid;

use crypt_io::{Error, kdf};

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

#[test]
fn matches_python_hashlib_grid() {
    for (i, (password, salt, iterations, expected)) in grid::GRID.iter().enumerate() {
        let expected = h(expected);
        let mut out = vec![0u8; expected.len()];
        kdf::pbkdf2_hmac_sha256(&h(password), &h(salt), *iterations, &mut out).unwrap();
        assert_eq!(out, expected, "grid case {i}");
    }
}

#[test]
fn scram_sha256_rfc7677_salted_password() {
    let mut salted = [0u8; kdf::PBKDF2_SHA256_OUTPUT_LEN];
    kdf::pbkdf2_hmac_sha256(b"pencil", &h(grid::SCRAM_SALT), 4096, &mut salted).unwrap();
    assert_eq!(salted.as_slice(), h(grid::SCRAM_SALTED_PASSWORD));
}

/// The whole RFC 7677 client and server computation on top of the
/// derived key, so a SCRAM client built on crypt-io is pinned end to
/// end against the RFC's `p=` and `v=` values.
#[cfg(feature = "mac-hmac")]
#[test]
fn scram_sha256_rfc7677_client_proof_and_server_signature() {
    use crypt_io::{hash, mac};

    let mut salted = [0u8; 32];
    kdf::pbkdf2_hmac_sha256(b"pencil", &h(grid::SCRAM_SALT), 4096, &mut salted).unwrap();
    let auth = grid::SCRAM_AUTH_MESSAGE.as_bytes();

    let client_key = mac::hmac_sha256(&salted, b"Client Key").unwrap();
    let stored_key = hash::sha256(&client_key);
    let client_signature = mac::hmac_sha256(&stored_key, auth).unwrap();
    let proof: Vec<u8> = client_key
        .iter()
        .zip(client_signature.iter())
        .map(|(a, b)| a ^ b)
        .collect();
    assert_eq!(proof, h(grid::SCRAM_CLIENT_PROOF));

    let server_key = mac::hmac_sha256(&salted, b"Server Key").unwrap();
    let server_signature = mac::hmac_sha256(&server_key, auth).unwrap();
    assert_eq!(server_signature.as_slice(), h(grid::SCRAM_SERVER_SIGNATURE));
}

#[test]
fn iteration_bounds() {
    let mut out = [0u8; 32];
    assert!(kdf::pbkdf2_hmac_sha256(b"p", b"s", 1, &mut out).is_ok());
    assert!(matches!(
        kdf::pbkdf2_hmac_sha256(b"p", b"s", 0, &mut out),
        Err(Error::InvalidInput(_))
    ));
    assert!(matches!(
        kdf::pbkdf2_hmac_sha256(b"p", b"s", kdf::PBKDF2_MAX_ITERATIONS + 1, &mut out),
        Err(Error::LimitExceeded(_))
    ));
}

#[test]
fn accepts_a_fixed_size_array() {
    // The common SCRAM call shape: a `[u8; 32]` output.
    let mut a = [0u8; 32];
    let mut b = vec![0u8; 32];
    kdf::pbkdf2_hmac_sha256(b"pw", b"salt", 10, &mut a).unwrap();
    kdf::pbkdf2_hmac_sha256(b"pw", b"salt", 10, &mut b).unwrap();
    assert_eq!(a.as_slice(), b.as_slice());
}

/// The optimised loop (raw SHA-256 states, two compressions per round)
/// against PBKDF2 written straight from RFC 8018 over the public
/// HMAC-SHA256.
#[cfg(feature = "mac-hmac")]
mod against_reference {
    use crypt_io::{kdf, mac};
    use proptest::prelude::*;

    fn reference(password: &[u8], salt: &[u8], iterations: u32, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        let mut index = 1u32;
        while out.len() < len {
            let mut first = salt.to_vec();
            first.extend_from_slice(&index.to_be_bytes());
            let mut u = mac::hmac_sha256(password, &first).unwrap();
            let mut t = u;
            for _ in 1..iterations {
                u = mac::hmac_sha256(password, &u).unwrap();
                for (a, b) in t.iter_mut().zip(u.iter()) {
                    *a ^= b;
                }
            }
            out.extend_from_slice(&t);
            index += 1;
        }
        out.truncate(len);
        out
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(if cfg!(miri) { 4 } else { 256 }))]
        #[test]
        fn matches_rfc8018_reference(
            password in proptest::collection::vec(any::<u8>(), 0..200),
            salt in proptest::collection::vec(any::<u8>(), 0..200),
            iterations in 1u32..40,
            len in 1usize..100,
        ) {
            let mut out = vec![0u8; len];
            kdf::pbkdf2_hmac_sha256(&password, &salt, iterations, &mut out).unwrap();
            prop_assert_eq!(out, reference(&password, &salt, iterations, len));
        }
    }
}
