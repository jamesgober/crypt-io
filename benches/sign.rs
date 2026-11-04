//! Signature benchmarks (`sign-ed25519`, `sign-rsa`, new in 1.3.0).
//!
//! Signing cost only; key parsing happens once per key in practice.
//! The RSA key is the 2048-bit NIST CAVP SigGen15 test key used by
//! `tests/sign.rs`.
//!
//! Run:
//!     cargo bench --bench sign --features sign-all
//!     (add `prebuilt-nasm` on Windows without NASM)

#![allow(clippy::unwrap_used)]

use criterion::{Criterion, black_box, criterion_group, criterion_main};

use crypt_io::sign::{Ed25519SigningKey, RsaSigningKey};

#[path = "../tests/data/sign_vectors.rs"]
mod vectors;

fn bench_sign(c: &mut Criterion) {
    // A DKIM header hash is 32 bytes.
    let message = [0x5au8; 32];

    let ed = Ed25519SigningKey::from_seed(&[0x42u8; 32]).unwrap();
    c.bench_function("ed25519_sign_32B", |b| {
        b.iter(|| ed.sign(black_box(&message)))
    });

    let set = &vectors::NIST_SIGGEN15_SHA256[0];
    let rsa = RsaSigningKey::from_pkcs1_der(&hex::decode(set.pkcs1_der).unwrap()).unwrap();
    let mut group = c.benchmark_group("rsa_pkcs1v15_sha256");
    group.sample_size(20);
    group.bench_function("sign_2048_32B", |b| {
        b.iter(|| rsa.sign_pkcs1v15_sha256(black_box(&message)).unwrap())
    });
    group.finish();
}

criterion_group!(benches, bench_sign);
criterion_main!(benches);
