//! PBKDF2-HMAC-SHA256 benchmarks (`kdf-pbkdf2`, new in 1.3.0).
//!
//! Cost is linear in the iteration count: two SHA-256 compressions per
//! iteration per 32-byte output block. 4,096 is SCRAM-SHA-256's
//! minimum (RFC 7677); 600,000 is OWASP's 2023 recommendation for
//! stored password hashes.
//!
//! Run:
//!     cargo bench --bench pbkdf2 --features kdf-pbkdf2

#![allow(clippy::unwrap_used)]

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};

use crypt_io::kdf;

fn bench_pbkdf2_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("pbkdf2_hmac_sha256");
    group.sample_size(10);
    for iterations in [4_096u32, 600_000] {
        group.bench_with_input(
            BenchmarkId::from_parameter(iterations),
            &iterations,
            |b, &iterations| {
                let mut out = [0u8; 32];
                b.iter(|| {
                    kdf::pbkdf2_hmac_sha256(
                        black_box(b"correct horse battery staple"),
                        black_box(b"16-byte-salt-abc"),
                        iterations,
                        &mut out,
                    )
                    .unwrap();
                    out
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_pbkdf2_sha256);
criterion_main!(benches);
