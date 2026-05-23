//! Streaming throughput benchmarks.
//!
//! Measures `StreamEncryptor` / `StreamDecryptor` end-to-end across
//! both AEADs at the default 64 KiB chunk size, on a 1 MiB and a
//! 10 MiB plaintext. The whole pipeline runs per iteration —
//! header build, every chunk encrypt, finalize, then decrypt the
//! whole thing — so the throughput reported includes the framing
//! overhead, not just the underlying AEAD cost.
//!
//! Run:
//!     cargo bench --bench stream

#![allow(clippy::unwrap_used)]

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};

use crypt_io::Algorithm;
use crypt_io::stream::{HEADER_LEN, StreamDecryptor, StreamEncryptor};

const SIZES: &[(usize, &str)] = &[(1024 * 1024, "1MiB"), (10 * 1024 * 1024, "10MiB")];

fn stream_encrypt(algorithm: Algorithm, plaintext: &[u8]) -> Vec<u8> {
    let key = [0u8; 32];
    let (mut enc, header) = StreamEncryptor::new(&key, algorithm).unwrap();
    let mut wire = header.to_vec();
    wire.extend(enc.update(plaintext).unwrap());
    wire.extend(enc.finalize().unwrap());
    wire
}

fn stream_decrypt(wire: &[u8]) -> Vec<u8> {
    let key = [0u8; 32];
    let mut dec = StreamDecryptor::new(&key, &wire[..HEADER_LEN]).unwrap();
    let mut out = dec.update(&wire[HEADER_LEN..]).unwrap();
    out.extend(dec.finalize().unwrap());
    out
}

fn bench_stream_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("stream_encrypt");
    for &(size, label) in SIZES {
        let plaintext = vec![0xa5u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(format!("chacha20_{label}"), &plaintext, |b, pt| {
            b.iter(|| stream_encrypt(Algorithm::ChaCha20Poly1305, black_box(pt)));
        });
        group.bench_with_input(format!("aes_gcm_{label}"), &plaintext, |b, pt| {
            b.iter(|| stream_encrypt(Algorithm::Aes256Gcm, black_box(pt)));
        });
    }
    group.finish();
}

fn bench_stream_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("stream_decrypt");
    for &(size, label) in SIZES {
        let plaintext = vec![0xa5u8; size];
        let cha_wire = stream_encrypt(Algorithm::ChaCha20Poly1305, &plaintext);
        let aes_wire = stream_encrypt(Algorithm::Aes256Gcm, &plaintext);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(format!("chacha20_{label}"), &cha_wire, |b, wire| {
            b.iter(|| stream_decrypt(black_box(wire)));
        });
        group.bench_with_input(format!("aes_gcm_{label}"), &aes_wire, |b, wire| {
            b.iter(|| stream_decrypt(black_box(wire)));
        });
    }
    group.finish();
}

// --- Zero-allocation `_into` variant (0.10.0). Same per-iteration
// work as `bench_stream_encrypt` but writes into a reused buffer. ---

fn stream_encrypt_into(algorithm: Algorithm, plaintext: &[u8], wire: &mut Vec<u8>) {
    let key = [0u8; 32];
    let (mut enc, header) = StreamEncryptor::new(&key, algorithm).unwrap();
    wire.clear();
    wire.extend_from_slice(&header);
    enc.update_into(plaintext, wire).unwrap();
    enc.finalize_into(wire).unwrap();
}

fn bench_stream_encrypt_into(c: &mut Criterion) {
    let mut group = c.benchmark_group("stream_encrypt_into");
    for &(size, label) in SIZES {
        let plaintext = vec![0xa5u8; size];
        let mut wire = Vec::with_capacity(size + 4096);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(format!("chacha20_{label}"), &plaintext, |b, pt| {
            b.iter(|| {
                stream_encrypt_into(
                    Algorithm::ChaCha20Poly1305,
                    black_box(pt),
                    black_box(&mut wire),
                );
            });
        });
        group.bench_with_input(format!("aes_gcm_{label}"), &plaintext, |b, pt| {
            b.iter(|| {
                stream_encrypt_into(Algorithm::Aes256Gcm, black_box(pt), black_box(&mut wire));
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_stream_encrypt,
    bench_stream_decrypt,
    bench_stream_encrypt_into,
);
criterion_main!(benches);
