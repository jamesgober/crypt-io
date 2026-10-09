//! Fuzz all three MACs (HMAC-SHA256, HMAC-SHA512, BLAKE3 keyed)
//! across compute + verify + streaming with arbitrary inputs.
//!
//! Verifies:
//!   - Compute + verify(tag) round-trips for any (key, data)
//!   - Verify rejects mismatched tags
//!   - Streaming MAC equals one-shot

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use crypt_io::mac::{
    blake3_keyed, blake3_keyed_check, hmac_sha256, hmac_sha256_check, hmac_sha512,
    hmac_sha512_check, Blake3Mac, HmacSha256, HmacSha512,
};
use crypt_io::Tag;

#[derive(Arbitrary, Debug)]
struct Input {
    key_var: Vec<u8>,
    key_fixed: [u8; 32],
    data: Vec<u8>,
    expected_tag: Vec<u8>,
    chunks: Vec<Vec<u8>>,
}

fuzz_target!(|input: Input| {
    // --- HMAC-SHA256 ---
    if let Ok(tag) = hmac_sha256(&input.key_var, &input.data) {
        // Check must accept our own tag.
        assert!(hmac_sha256_check(&input.key_var, &input.data, &tag).is_ok());
        // Check against an arbitrary expected tag: must agree with a
        // constant-time `Tag` comparison and never panic.
        let ok = hmac_sha256_check(&input.key_var, &input.data, &input.expected_tag).is_ok();
        assert_eq!(ok, Tag::from(tag).ct_eq(&input.expected_tag));
    }

    // --- HMAC-SHA512 ---
    if let Ok(tag) = hmac_sha512(&input.key_var, &input.data) {
        assert!(hmac_sha512_check(&input.key_var, &input.data, &tag).is_ok());
        let ok = hmac_sha512_check(&input.key_var, &input.data, &input.expected_tag).is_ok();
        assert_eq!(ok, Tag::from(tag).ct_eq(&input.expected_tag));
    }

    // --- BLAKE3 keyed (typed 32-byte key, infallible) ---
    let tag = blake3_keyed(&input.key_fixed, &input.data);
    assert!(blake3_keyed_check(&input.key_fixed, &input.data, &tag).is_ok());
    let ok = blake3_keyed_check(&input.key_fixed, &input.data, &input.expected_tag).is_ok();
    assert_eq!(ok, Tag::from(tag).ct_eq(&input.expected_tag));

    // --- Streaming MAC equivalence ---
    let combined: Vec<u8> = input.chunks.iter().flatten().copied().collect();
    if let Ok(mut m) = HmacSha256::new(&input.key_var) {
        for c in &input.chunks {
            m.update(c);
        }
        if let Ok(one_shot) = hmac_sha256(&input.key_var, &combined) {
            assert_eq!(m.finalize(), one_shot);
        }
    }
    if let Ok(mut m) = HmacSha512::new(&input.key_var) {
        for c in &input.chunks {
            m.update(c);
        }
        if let Ok(one_shot) = hmac_sha512(&input.key_var, &combined) {
            assert_eq!(m.finalize(), one_shot);
        }
    }
    {
        let mut m = Blake3Mac::new(&input.key_fixed);
        for c in &input.chunks {
            m.update(c);
        }
        assert_eq!(m.finalize(), blake3_keyed(&input.key_fixed, &combined));
    }
});
