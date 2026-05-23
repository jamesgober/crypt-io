//! Fuzz `Crypt::encrypt` + round-trip. Encrypt with arbitrary
//! key/plaintext/aad, then immediately decrypt back and assert the
//! recovered plaintext matches.
//!
//! This catches:
//!   - panics in the encrypt path
//!   - any case where encrypt succeeds but decrypt of its output
//!     fails or returns the wrong plaintext

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use crypt_io::{Algorithm, Crypt};

#[derive(Arbitrary, Debug)]
struct Input {
    algorithm_byte: u8,
    key: Vec<u8>,
    plaintext: Vec<u8>,
    aad: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let algorithm = if input.algorithm_byte & 1 == 0 {
        Algorithm::ChaCha20Poly1305
    } else {
        Algorithm::Aes256Gcm
    };
    let crypt = Crypt::with_algorithm(algorithm);

    // Need a 32-byte key to actually encrypt — skip otherwise.
    if input.key.len() != 32 {
        // Just exercise the length-check path.
        let _ = crypt.encrypt(&input.key, &input.plaintext);
        return;
    }

    // Encrypt should always succeed with a valid key.
    let ciphertext = crypt
        .encrypt_with_aad(&input.key, &input.plaintext, &input.aad)
        .expect("encrypt with valid 32-byte key must succeed");

    // Round-trip — decrypt must recover the exact plaintext.
    let recovered = crypt
        .decrypt_with_aad(&input.key, &ciphertext, &input.aad)
        .expect("decrypt of own ciphertext must succeed");
    assert_eq!(recovered, input.plaintext, "round-trip changed plaintext");
});
