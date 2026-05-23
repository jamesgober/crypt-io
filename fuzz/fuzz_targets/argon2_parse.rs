//! Fuzz `kdf::argon2_verify` with arbitrary PHC strings.
//!
//! This is the PHC-parser attack surface — an attacker can hand us
//! any string and we need to either parse-and-verify cleanly
//! (returning Ok(true)/Ok(false)) or surface Err(Kdf) for malformed
//! input. **Never panic.**
//!
//! We intentionally do NOT fuzz `argon2_hash` directly — at OWASP
//! defaults each iteration is ~50-150 ms, which makes the fuzzer
//! useless. The parameter-validation path is exercised through
//! `argon2_hash_with_params` indirectly.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use crypt_io::kdf::{argon2_hash_with_params, argon2_verify, Argon2Params};

#[derive(Arbitrary, Debug)]
struct Input {
    phc_attempt: Vec<u8>,
    password: Vec<u8>,
    // Fuzz the parameter-validation path with arbitrary tunables.
    // Cap each so a single iteration is fast.
    m_cost: u16,
    t_cost: u8,
    p_cost: u8,
    output_len: u8,
}

fuzz_target!(|input: Input| {
    // PHC parse path — arbitrary string in, must not panic.
    if let Ok(phc_str) = core::str::from_utf8(&input.phc_attempt) {
        let _ = argon2_verify(phc_str, &input.password);
    }

    // Parameter validation path. Cap costs aggressively so the
    // fuzzer can iterate fast; the real OWASP-default params are
    // not the interesting target here — `Params::new` is.
    let params = Argon2Params {
        m_cost: (input.m_cost as u32).max(8).min(256),
        t_cost: (input.t_cost as u32).max(1).min(2),
        p_cost: input.p_cost.max(1) as u32,
        output_len: ((input.output_len as usize).max(4)).min(64),
    };
    if let Ok(phc) = argon2_hash_with_params(&input.password, params) {
        assert!(argon2_verify(&phc, &input.password).unwrap_or(false));
    }
});
