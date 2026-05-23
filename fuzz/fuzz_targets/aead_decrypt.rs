//! Fuzz `Crypt::decrypt` with arbitrary key + ciphertext bytes.
//!
//! This is the attack-surface path — an attacker controls the
//! ciphertext, so any input we can't reject cleanly is a bug.
//! The target asserts only that we never panic; an
//! `Err(AuthenticationFailed)` or `Err(InvalidKey)` is the
//! expected outcome for ~all inputs.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use crypt_io::{Algorithm, Crypt};

#[derive(Arbitrary, Debug)]
struct Input {
    algorithm_byte: u8,
    key: Vec<u8>,
    ciphertext: Vec<u8>,
    aad: Vec<u8>,
}

fuzz_target!(|input: Input| {
    let algorithm = if input.algorithm_byte & 1 == 0 {
        Algorithm::ChaCha20Poly1305
    } else {
        Algorithm::Aes256Gcm
    };
    let crypt = Crypt::with_algorithm(algorithm);

    // No assertions on the result — we only care that it doesn't
    // panic. `Err(...)` is expected for almost every input.
    let _ = crypt.decrypt(&input.key, &input.ciphertext);
    let _ = crypt.decrypt_with_aad(&input.key, &input.ciphertext, &input.aad);
});
