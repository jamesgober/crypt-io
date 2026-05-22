//! KDF benchmarks.
//!
//! Measures HKDF-SHA256 / HKDF-SHA512 at the typical output-size
//! requests, plus Argon2id with two parameter sets:
//!
//! - **OWASP defaults** (`Argon2Params::default()`) — the production
//!   parameter set. Expect ~50–150 ms per hash depending on the CPU.
//!   These benches use `sample_size = 10` because each iteration is
//!   expensive.
//! - **Fast** (the same set used by the unit tests) — proves the
//!   Argon2 wrapper has negligible overhead vs the upstream crate
//!   without paying production-cost timing.
//!
//! Run:
//!     cargo bench --bench kdf
//!     cargo bench --bench kdf -- --sample-size 10  # if Argon2 default times out

#![allow(clippy::unwrap_used)]

use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};

use crypt_io::kdf;
use crypt_io::kdf::Argon2Params;

const HKDF_LENGTHS: &[usize] = &[32, 64, 128];

fn bench_hkdf_sha256(c: &mut Criterion) {
    let ikm = [0x42u8; 32];
    let mut group = c.benchmark_group("hkdf_sha256");
    for &out_len in HKDF_LENGTHS {
        group.throughput(Throughput::Bytes(out_len as u64));
        group.bench_with_input(BenchmarkId::from_parameter(out_len), &out_len, |b, &len| {
            b.iter(|| {
                kdf::hkdf_sha256(
                    black_box(&ikm),
                    Some(black_box(b"salt")),
                    black_box(b"app:info:v1"),
                    black_box(len),
                )
                .unwrap()
            });
        });
    }
    group.finish();
}

fn bench_hkdf_sha512(c: &mut Criterion) {
    let ikm = [0x42u8; 32];
    let mut group = c.benchmark_group("hkdf_sha512");
    for &out_len in HKDF_LENGTHS {
        group.throughput(Throughput::Bytes(out_len as u64));
        group.bench_with_input(BenchmarkId::from_parameter(out_len), &out_len, |b, &len| {
            b.iter(|| {
                kdf::hkdf_sha512(
                    black_box(&ikm),
                    Some(black_box(b"salt")),
                    black_box(b"app:info:v1"),
                    black_box(len),
                )
                .unwrap()
            });
        });
    }
    group.finish();
}

fn bench_argon2_default(c: &mut Criterion) {
    // OWASP-recommended Argon2id — ~50–150 ms per call. Sample
    // size kept low and measurement time generous so the harness
    // doesn't run for ages.
    let mut group = c.benchmark_group("argon2id_owasp_default");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(15));
    group.bench_function("hash", |b| {
        b.iter(|| kdf::argon2_hash(black_box(b"correct horse battery staple")).unwrap());
    });
    let phc = kdf::argon2_hash(b"correct horse battery staple").unwrap();
    group.bench_function("verify", |b| {
        b.iter(|| {
            kdf::argon2_verify(black_box(&phc), black_box(b"correct horse battery staple")).unwrap()
        });
    });
    group.finish();
}

fn bench_argon2_fast(c: &mut Criterion) {
    // Reduced params (same as the unit tests). Measures the
    // wrapper overhead without paying production-Argon2 cost on
    // every iteration.
    let fast = Argon2Params {
        m_cost: 8,
        t_cost: 1,
        p_cost: 1,
        output_len: 32,
    };
    let mut group = c.benchmark_group("argon2id_fast_params");
    group.sample_size(20);
    group.bench_function("hash", |b| {
        b.iter(|| kdf::argon2_hash_with_params(black_box(b"hunter2"), black_box(fast)).unwrap());
    });
    let phc = kdf::argon2_hash_with_params(b"hunter2", fast).unwrap();
    group.bench_function("verify", |b| {
        b.iter(|| kdf::argon2_verify(black_box(&phc), black_box(b"hunter2")).unwrap());
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_hkdf_sha256,
    bench_hkdf_sha512,
    bench_argon2_default,
    bench_argon2_fast,
);
criterion_main!(benches);
