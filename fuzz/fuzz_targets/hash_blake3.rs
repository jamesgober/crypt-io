//! Fuzz BLAKE3 (one-shot + XOF + streaming) with arbitrary input.

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use crypt_io::hash::{blake3, blake3_long, Blake3Hasher};

#[derive(Arbitrary, Debug)]
struct Input {
    data: Vec<u8>,
    chunks: Vec<Vec<u8>>,
    xof_len: u16, // cap XOF output at 64 KiB to keep iterations cheap
}

fuzz_target!(|input: Input| {
    // One-shot
    let _ = blake3(&input.data);

    // XOF
    let _ = blake3_long(&input.data, input.xof_len as usize);

    // Streaming — feed multiple chunks, finalise both ways
    let mut h = Blake3Hasher::new();
    for c in &input.chunks {
        h.update(c);
    }
    let _ = h.clone().finalize();
    let _ = h.finalize_xof(input.xof_len as usize);

    // Streaming equivalence with one-shot
    let combined: Vec<u8> = input.chunks.iter().flatten().copied().collect();
    let mut h2 = Blake3Hasher::new();
    for c in &input.chunks {
        h2.update(c);
    }
    assert_eq!(h2.finalize(), blake3(&combined));
});
