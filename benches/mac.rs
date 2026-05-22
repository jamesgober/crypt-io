//! MAC throughput benchmarks.
//!
//! Measures HMAC-SHA256, HMAC-SHA512, and BLAKE3 keyed mode at the
//! same input sizes as the AEAD/hash benches.
//!
//! Run:
//!     cargo bench --bench mac

#![allow(clippy::unwrap_used)]

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

use crypt_io::mac;

const SIZES: &[usize] = &[64, 1024, 64 * 1024, 1024 * 1024];

fn bench_hmac_sha256(c: &mut Criterion) {
    let key = b"shared-key-for-hmac-bench";
    let mut group = c.benchmark_group("hmac_sha256");
    for &size in SIZES {
        let data = vec![0xa5u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, d| {
            b.iter(|| mac::hmac_sha256(black_box(key), black_box(d)).unwrap());
        });
    }
    group.finish();
}

fn bench_hmac_sha512(c: &mut Criterion) {
    let key = b"shared-key-for-hmac-bench";
    let mut group = c.benchmark_group("hmac_sha512");
    for &size in SIZES {
        let data = vec![0xa5u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, d| {
            b.iter(|| mac::hmac_sha512(black_box(key), black_box(d)).unwrap());
        });
    }
    group.finish();
}

fn bench_blake3_keyed(c: &mut Criterion) {
    let key = [0x42u8; 32];
    let mut group = c.benchmark_group("blake3_keyed");
    for &size in SIZES {
        let data = vec![0xa5u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, d| {
            b.iter(|| mac::blake3_keyed(black_box(&key), black_box(d)));
        });
    }
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    // Verify cost separately at 1 KiB — exercises the constant-time
    // tag-comparison path, the most likely failure mode.
    let key = b"shared-key";
    let data = vec![0xa5u8; 1024];
    let tag_hmac = mac::hmac_sha256(key, &data).unwrap();
    let key32 = [0x42u8; 32];
    let tag_b3 = mac::blake3_keyed(&key32, &data);

    let mut group = c.benchmark_group("verify_1KiB");
    group.throughput(Throughput::Bytes(1024));
    group.bench_function("hmac_sha256", |b| {
        b.iter(|| {
            mac::hmac_sha256_verify(black_box(key), black_box(&data), black_box(&tag_hmac)).unwrap()
        });
    });
    group.bench_function("blake3_keyed", |b| {
        b.iter(|| {
            mac::blake3_keyed_verify(black_box(&key32), black_box(&data), black_box(&tag_b3))
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_hmac_sha256,
    bench_hmac_sha512,
    bench_blake3_keyed,
    bench_verify,
);
criterion_main!(benches);
