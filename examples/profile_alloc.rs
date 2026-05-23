//! Heap-allocation profile for `Crypt::encrypt` vs `Crypt::encrypt_into`,
//! using [`mod-alloc`](https://github.com/jamesgober/mod-alloc) as the
//! global allocator wrapper.
//!
//! Demonstrates the wrapping-overhead gap documented in
//! `docs/PERFORMANCE.md` 0.8.0, and the close of that gap by the
//! `_into` API new in 0.10.0.
//!
//! Run with:
//!     cargo run --release --example profile_alloc

use mod_alloc::{ModAlloc, Profiler};

use crypt_io::{Algorithm, Crypt};

/// Swap in the mod-alloc wrapper around the system allocator so the
/// `Profiler` can count every allocation that flows through any code
/// path executed inside its scope.
#[global_allocator]
static GLOBAL: ModAlloc = ModAlloc::new();

const ITERATIONS: usize = 10_000;
const SIZES: &[(usize, &str)] = &[(64, "64 B"), (1024, "1 KiB"), (64 * 1024, "64 KiB")];

fn main() {
    println!(
        "crypt-io allocation profile — {} iterations per case",
        ITERATIONS
    );
    println!(
        "{:>26} | {:>10} | {:>14} | {:>14}",
        "case", "iters", "allocations", "total bytes",
    );
    println!("{}", "-".repeat(76));

    for &algorithm in &[Algorithm::ChaCha20Poly1305, Algorithm::Aes256Gcm] {
        let crypt = Crypt::with_algorithm(algorithm);
        let alg_short = match algorithm {
            Algorithm::ChaCha20Poly1305 => "chacha20",
            Algorithm::Aes256Gcm => "aes-gcm",
            _ => "unknown", // Algorithm is #[non_exhaustive]
        };

        for &(size, label) in SIZES {
            let key = [0u8; 32];
            let plaintext = vec![0xa5u8; size];

            // --- Allocating path ---
            let profile = Profiler::start();
            for _ in 0..ITERATIONS {
                let _ct = crypt.encrypt(&key, &plaintext).unwrap();
            }
            let s = profile.stop();
            println!(
                "{:>26} | {:>10} | {:>14} | {:>14}",
                format!("encrypt {} {}", alg_short, label),
                ITERATIONS,
                s.alloc_count,
                s.total_bytes,
            );

            // --- Zero-allocation path ---
            let mut buf = Vec::with_capacity(size + 28);
            let profile = Profiler::start();
            for _ in 0..ITERATIONS {
                crypt.encrypt_into(&key, &plaintext, &mut buf).unwrap();
            }
            let s = profile.stop();
            println!(
                "{:>26} | {:>10} | {:>14} | {:>14}",
                format!("encrypt_into {} {}", alg_short, label),
                ITERATIONS,
                s.alloc_count,
                s.total_bytes,
            );
        }
        println!();
    }

    println!("Notes:");
    println!("  * `encrypt` returns a fresh Vec<u8> per call.");
    println!("  * `encrypt_into` writes into a caller-supplied Vec<u8>.");
    println!("    After a one-time grow, subsequent calls reuse capacity");
    println!("    and add zero allocations to the steady state.");
    println!("  * Numbers here are per-{ITERATIONS}-iteration totals.");
    println!("    Divide by {ITERATIONS} for per-call cost.");
}
