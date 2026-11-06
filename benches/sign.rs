//! Signature benchmarks (`sign-ed25519`, `sign-rsa`): signing (1.3.0)
//! and checking (1.4.0).
//!
//! Key parsing happens once per key in practice, so it is outside the
//! timed loop.
//! The RSA key is the 2048-bit NIST CAVP SigGen15 test key used by
//! `tests/sign.rs`.
//!
//! Run:
//!     cargo bench --bench sign --features sign-all
//!     (add `prebuilt-nasm` on Windows without NASM)

#![allow(clippy::unwrap_used)]

use criterion::{Criterion, black_box, criterion_group, criterion_main};

use crypt_io::sign::{Ed25519PublicKey, Ed25519SigningKey, RsaPublicKey, RsaSigningKey};

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
    let rsa_sig = rsa.sign_pkcs1v15_sha256(&message).unwrap();
    let rsa_public = RsaPublicKey::from_der(rsa.public_key_der()).unwrap();
    group.bench_function("check_2048_32B", |b| {
        b.iter(|| rsa_public.check_pkcs1v15_sha256(black_box(&message), black_box(&rsa_sig)))
    });
    group.finish();

    let ed_sig = ed.sign(&message);
    let ed_public = Ed25519PublicKey::from_bytes(&ed.public_key()).unwrap();
    c.bench_function("ed25519_check_32B", |b| {
        b.iter(|| ed_public.check(black_box(&message), black_box(&ed_sig)))
    });
}

criterion_group!(benches, bench_sign);
criterion_main!(benches);
