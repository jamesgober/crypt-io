//! One-time-password benchmarks (`otp`, new in 1.5.0).
//!
//! `totp_check` with a window of 1 computes three codes (the previous,
//! current and next step) and compares all of them.
//!
//! Run:
//!     cargo bench --bench otp --features otp
//!     (add `prebuilt-nasm` on Windows without NASM)

#![allow(clippy::unwrap_used)]

use criterion::{Criterion, black_box, criterion_group, criterion_main};

use crypt_io::otp;

fn bench_otp(c: &mut Criterion) {
    let secret = [0x42u8; 20];
    let t = 1_700_000_000u64;
    c.bench_function("totp", |b| {
        b.iter(|| otp::totp(black_box(&secret), black_box(t), 6).unwrap())
    });
    let code = format!("{:06}", otp::totp(&secret, t, 6).unwrap());
    c.bench_function("totp_check_window_1", |b| {
        b.iter(|| {
            otp::totp_check(black_box(&secret), black_box(&code), black_box(t), 6, 1).unwrap()
        })
    });
}

criterion_group!(benches, bench_otp);
criterion_main!(benches);
