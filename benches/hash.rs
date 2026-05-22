//! Hash throughput benchmarks.
//!
//! Measures BLAKE3, SHA-256, and SHA-512 across the same input
//! sizes the AEAD benches use, so the relative performance picture
//! is consistent.
//!
//! Run:
//!     cargo bench --bench hash
//!
//! Expectation on x86_64 with SHA-NI: SHA-256 closes the gap with
//! BLAKE3 at large inputs. Without SHA-NI: BLAKE3 wins everywhere.

#![allow(clippy::unwrap_used)]

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

use crypt_io::hash;

const SIZES: &[usize] = &[64, 1024, 64 * 1024, 1024 * 1024];

fn bench_blake3(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake3");
    for &size in SIZES {
        let data = vec![0xa5u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, d| {
            b.iter(|| hash::blake3(black_box(d)));
        });
    }
    group.finish();
}

fn bench_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256");
    for &size in SIZES {
        let data = vec![0xa5u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, d| {
            b.iter(|| hash::sha256(black_box(d)));
        });
    }
    group.finish();
}

fn bench_sha512(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha512");
    for &size in SIZES {
        let data = vec![0xa5u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, d| {
            b.iter(|| hash::sha512(black_box(d)));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_blake3, bench_sha256, bench_sha512);
criterion_main!(benches);
