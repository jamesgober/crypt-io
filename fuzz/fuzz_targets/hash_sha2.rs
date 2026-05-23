//! Fuzz SHA-256 + SHA-512 (one-shot + streaming) with arbitrary input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use crypt_io::hash::{sha256, sha512, Sha256Hasher, Sha512Hasher};

#[derive(Arbitrary, Debug)]
struct Input {
    data: Vec<u8>,
    chunks: Vec<Vec<u8>>,
}

fuzz_target!(|input: Input| {
    // One-shot
    let _ = sha256(&input.data);
    let _ = sha512(&input.data);

    // Streaming
    let mut h256 = Sha256Hasher::new();
    let mut h512 = Sha512Hasher::new();
    for c in &input.chunks {
        h256.update(c);
        h512.update(c);
    }
    let _ = h256.finalize();
    let _ = h512.finalize();

    // Streaming equivalence with one-shot
    let combined: Vec<u8> = input.chunks.iter().flatten().copied().collect();
    let mut a = Sha256Hasher::new();
    for c in &input.chunks {
        a.update(c);
    }
    assert_eq!(a.finalize(), sha256(&combined));
});
