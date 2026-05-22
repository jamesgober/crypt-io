//! AEAD throughput benchmarks.
//!
//! Measures `Crypt::encrypt` and `Crypt::decrypt` across the two
//! shipped AEADs (ChaCha20-Poly1305, AES-256-GCM) and the input
//! sizes that bracket the typical use cases:
//!
//! - 64 B   — short payloads (tokens, auth tags, control messages)
//! - 1 KiB  — typical database row / message
//! - 64 KiB — file chunk / network packet
//! - 1 MiB  — bulk transfer chunk
//!
//! Run all:
//!     cargo bench --bench aead
//!
//! Run a specific group:
//!     cargo bench --bench aead -- chacha20
//!     cargo bench --bench aead -- aes_gcm
//!
//! Numbers committed to `docs/PERFORMANCE.md` come from this file
//! on the reference machine documented there. Run yourself to get
//! your own numbers — modern CPUs vary by ~3-4× for AES depending
//! on AES-NI support.

#![allow(clippy::unwrap_used)]

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

use crypt_io::Crypt;

/// Sizes (bytes) we benchmark at. Throughput is plotted per byte so
/// the numbers can be compared directly across sizes.
const SIZES: &[usize] = &[64, 1024, 64 * 1024, 1024 * 1024];

fn bench_chacha20_encrypt(c: &mut Criterion) {
    let crypt = Crypt::new();
    let key = [0u8; 32];
    let mut group = c.benchmark_group("chacha20_poly1305_encrypt");
    for &size in SIZES {
        let plaintext = vec![0xa5u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &plaintext, |b, pt| {
            b.iter(|| crypt.encrypt(black_box(&key), black_box(pt)).unwrap());
        });
    }
    group.finish();
}

fn bench_chacha20_decrypt(c: &mut Criterion) {
    let crypt = Crypt::new();
    let key = [0u8; 32];
    let mut group = c.benchmark_group("chacha20_poly1305_decrypt");
    for &size in SIZES {
        let plaintext = vec![0xa5u8; size];
        let ciphertext = crypt.encrypt(&key, &plaintext).unwrap();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &ciphertext, |b, ct| {
            b.iter(|| crypt.decrypt(black_box(&key), black_box(ct)).unwrap());
        });
    }
    group.finish();
}

fn bench_aes_gcm_encrypt(c: &mut Criterion) {
    let crypt = Crypt::aes_256_gcm();
    let key = [0u8; 32];
    let mut group = c.benchmark_group("aes_256_gcm_encrypt");
    for &size in SIZES {
        let plaintext = vec![0xa5u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &plaintext, |b, pt| {
            b.iter(|| crypt.encrypt(black_box(&key), black_box(pt)).unwrap());
        });
    }
    group.finish();
}

fn bench_aes_gcm_decrypt(c: &mut Criterion) {
    let crypt = Crypt::aes_256_gcm();
    let key = [0u8; 32];
    let mut group = c.benchmark_group("aes_256_gcm_decrypt");
    for &size in SIZES {
        let plaintext = vec![0xa5u8; size];
        let ciphertext = crypt.encrypt(&key, &plaintext).unwrap();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &ciphertext, |b, ct| {
            b.iter(|| crypt.decrypt(black_box(&key), black_box(ct)).unwrap());
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_chacha20_encrypt,
    bench_chacha20_decrypt,
    bench_aes_gcm_encrypt,
    bench_aes_gcm_decrypt,
);
criterion_main!(benches);
