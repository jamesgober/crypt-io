<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br>
    <b>crypt-io</b>
    <br>
    <sub>
        <sup>ENCRYPTION SUITE FOR RUST</sup>
    </sub>
</h1>

<p align="center">
    <a href="https://crates.io/crates/crypt-io"><img src="https://img.shields.io/crates/v/crypt-io.svg" alt="Crates.io"></a>
    <a href="https://crates.io/crates/crypt-io"><img alt="downloads" src="https://img.shields.io/crates/d/crypt-io.svg?0099ff"></a>
    <a href="https://docs.rs/crypt-io"><img src="https://docs.rs/crypt-io/badge.svg" alt="Documentation"></a>
    <a href="https://github.com/jamesgober/crypt-io/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/jamesgober/crypt-io/actions/workflows/ci.yml/badge.svg"></a>
    <a href="https://github.com/rust-lang/rfcs/blob/master/text/2495-min-rust-version.md" title="MSRV"><img alt="MSRV" src="https://img.shields.io/badge/MSRV-1.85%2B-blue"></a>
</p>

<p align="center">
    <b>AEAD encryption, hashing, MAC, and KDF for Rust</b>
    <br>
    <i>Algorithm-agile. RustCrypto-backed primitives. Simple API. Sub-microsecond throughput.</i>
</p>

<br>

<p>
    <strong>crypt-io</strong> is a focused encryption library that wraps battle-tested cryptographic primitives (from RustCrypto and the BLAKE3 team) with a clean, ergonomic API. Built from the ground up with REPS discipline, algorithm agility, and tight integration with the portfolio (<code>mod-rand</code> for CSPRNG, <code>error-forge</code> for errors), it targets sub-microsecond throughput on common operations while keeping the API simple enough to use correctly.
</p>

<p>
    Unlike monolithic crypto crates that try to be everything, <strong>crypt-io</strong> stays focused on what most applications actually need: symmetric AEAD encryption for data, hashing for integrity, MAC for authentication, and KDF for deriving keys from passwords or master secrets. No asymmetric crypto, no PGP, no TLS - those are different problems best solved by purpose-built crates. <strong>crypt-io</strong> is the foundation primitive that handles the 95% case with a clean, hard-to-misuse API.
</p>

<p>
    With <strong>crypt-io</strong>, you can encrypt a piece of data in two lines, hash a stream in one, derive a key from a master in three. Algorithm selection is explicit via enums or feature flags - you choose ChaCha20-Poly1305 (the default, post-quantum-safe at 256 bits) or AES-256-GCM (when you want hardware acceleration), and the API stays the same. Stream encryption handles large files with chunked AEAD and proper framing. Argon2id is available for password hashing when you need it.
</p>

<hr>

## Features

### Symmetric AEAD Encryption

- **ChaCha20-Poly1305** (default) - fast, post-quantum-safe at 256 bits
- **AES-256-GCM** - hardware-accelerated on modern CPUs
- **Algorithm agility** - select via enum or Cargo feature
- **Authenticated encryption** - integrity guaranteed, tampering detected

### Stream/File Encryption

- **Chunked AEAD** with proper framing for large data
- **Resumable** on partial reads
- **Async-compatible** (with `async-trait` feature)
- **Throughput target:** >1 GiB/s on modern hardware

### Hashing

- **BLAKE3** (default) - the fastest cryptographic hash
- **SHA-256, SHA-512** - for interoperability and compliance

### Message Authentication (MAC)

- **HMAC-SHA256, HMAC-SHA512** - the classic, widely supported
- **BLAKE3 keyed mode** - faster MAC when BLAKE3 is already in use

### Key Derivation (KDF)

- **HKDF** - derive multiple keys from a master secret
- **Argon2id** - password hashing, memory-hard, the modern standard

### Integration

- **mod-rand** for CSPRNG (nonces, salts, IVs)
- **error-forge** for error types
- **log-io** (optional) for operation logging
- **metrics-lib** (optional) for performance instrumentation
- **key-vault** (consumer wires up) - works alongside but no direct dependency

### Performance targets

- **ChaCha20-Poly1305 encrypt, 1 KiB:** <2us
- **AES-256-GCM encrypt, 1 KiB (HW accel):** <1us
- **BLAKE3 hash, 1 KiB:** <500ns
- **HMAC-SHA256, 1 KiB:** <3us
- **HKDF-SHA256, 32-byte output:** <5us
- **Stream encrypt throughput:** >1 GiB/s

> **Note on benchmark numbers:** detailed criterion-backed benchmark numbers will land with **v1.0.0**. Until then, performance claims should be treated as targets, not guarantees.

---

## Quick start

```toml
[dependencies]
crypt-io = "0.1"
```

```rust
use crypt_io::Crypt;

// Encrypt
let crypt = Crypt::new();              // ChaCha20-Poly1305 by default
let ciphertext = crypt.encrypt(&key, b"plaintext data")?;
let plaintext  = crypt.decrypt(&key, &ciphertext)?;

// Hash
let hash = crypt_io::hash::blake3(b"data");

// MAC
let tag = crypt_io::mac::hmac_sha256(&key, b"data");

// Derive a key from a password
let pw_hash = crypt_io::kdf::argon2_hash(b"password", &salt)?;
```

---

## Design philosophy

**crypt-io** is intentionally focused:

- **One job:** symmetric crypto. Done well.
- **No reinvention:** primitives come from RustCrypto and BLAKE3 (battle-tested).
- **Simple API:** Encrypt in 2 lines. Hash in 1. Hard to misuse.
- **Algorithm agility:** ChaCha20 by default, AES-GCM when you want hardware acceleration.
- **Tight integration:** portfolio-aware (`mod-rand`, `error-forge`, optional `log-io`/`metrics-lib`).
- **Performance verified:** sub-microsecond targets, benchmarked before claims ship.

What we explicitly do NOT do:

- Implement crypto primitives from scratch (use battle-tested upstreams)
- Asymmetric crypto (RSA, ECDSA, Ed25519) - different problem, separate crate
- PGP/GPG (use `sequoia-openpgp`)
- TLS (use `rustls`)
- Random generation (use `mod-rand`)
- UUID generation (use `id-forge`)
- Key storage (use `key-vault`)

This keeps the scope clean and the security review tractable.

---

## When to use crypt-io

Good fit:
- Encrypting data for storage (databases, file systems, caches)
- Encrypting API tokens or session data
- File encryption for backups
- Message-level encryption in chat (paired with a key exchange crate)
- Database column encryption
- Audit log signing
- Configuration encryption

Wrong fit:
- TLS connections (use `rustls`)
- OpenPGP interop (use `sequoia-openpgp`)
- Digital signatures (use `ed25519-dalek`)
- Key exchange (use `x25519-dalek`)
- Random number generation (use `mod-rand`)

---

## Standards

- **REPS** (Rust Efficiency & Performance Standards) governs every decision. See [REPS.md](REPS.md).
- **MSRV:** Rust 1.75.
- **Edition:** 2024.
- **Cross-platform:** Linux, macOS, Windows.

---

## License

Dual-licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.




<!-- FOOT COPYRIGHT
################################################# -->
<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>JAMES GOBER.</strong></sup>
</div>