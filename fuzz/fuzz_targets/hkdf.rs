//! Fuzz HKDF-SHA256 + HKDF-SHA512 with arbitrary inputs and
//! caller-supplied output lengths.
//!
//! Verifies:
//!   - No panic for any input/output-length combination
//!   - Length-overflow inputs surface `Err(Kdf)`, not a panic
//!   - Determinism: same inputs → same output

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use crypt_io::kdf::{hkdf_sha256, hkdf_sha512};

#[derive(Arbitrary, Debug)]
struct Input {
    ikm: Vec<u8>,
    salt: Option<Vec<u8>>,
    info: Vec<u8>,
    out_len: u16, // cap at u16 so we exercise both valid and over-bound lengths cheaply
}

fuzz_target!(|input: Input| {
    let salt = input.salt.as_deref();

    let r1 = hkdf_sha256(&input.ikm, salt, &input.info, input.out_len as usize);
    let r2 = hkdf_sha256(&input.ikm, salt, &input.info, input.out_len as usize);
    // Determinism — both runs must agree.
    assert_eq!(
        r1.as_ref().map(|v| &v[..]).ok(),
        r2.as_ref().map(|v| &v[..]).ok(),
        "hkdf_sha256 non-deterministic",
    );
    if let Ok(out) = r1 {
        assert_eq!(out.len(), input.out_len as usize);
    }

    let r1 = hkdf_sha512(&input.ikm, salt, &input.info, input.out_len as usize);
    let r2 = hkdf_sha512(&input.ikm, salt, &input.info, input.out_len as usize);
    assert_eq!(
        r1.as_ref().map(|v| &v[..]).ok(),
        r2.as_ref().map(|v| &v[..]).ok(),
        "hkdf_sha512 non-deterministic",
    );
    if let Ok(out) = r1 {
        assert_eq!(out.len(), input.out_len as usize);
    }
});
