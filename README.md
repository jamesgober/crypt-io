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
    <a href="https://crates.io/crates/crypt-io"><img alt="downloads" src="https://img.shields.io/crates/d/crypt-io.svg?color=0099ff"></a>
    <a href="https://docs.rs/crypt-io"><img src="https://docs.rs/crypt-io/badge.svg" alt="Documentation"></a>
    <a href="https://github.com/jamesgober/crypt-io/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/jamesgober/crypt-io/actions/workflows/ci.yml/badge.svg"></a>
    <a href="https://github.com/rust-lang/rfcs/blob/master/text/2495-min-rust-version.md" title="MSRV"><img alt="MSRV" src="https://img.shields.io/badge/MSRV-1.85%2B-blue"></a>
</p>

<p align="center">
    <b>AEAD encryption, hashing, and message authentication for Rust</b>
    <br>
    <i>Algorithm-agile. RustCrypto-backed primitives. Simple API. REPS-disciplined.</i>
</p>

<br>

<p>
    <strong>crypt-io</strong> is a focused encryption library that wraps battle-tested cryptographic primitives (from RustCrypto and the BLAKE3 team) behind a clean, hard-to-misuse API. Built from the ground up with REPS discipline, algorithm agility, and tight portfolio integration (<code>mod-rand</code> for CSPRNG nonces, <code>error-forge</code> for error metadata), it targets the symmetric-crypto needs that <i>most</i> applications actually have: encrypt some data, hash some data, authenticate a tag, derive a key.
</p>

<p>
    Unlike monolithic crypto crates that try to be everything, <strong>crypt-io</strong> stays focused. No asymmetric crypto, no PGP, no TLS — those are different problems best solved by purpose-built crates. <strong>crypt-io</strong> is the foundation primitive that handles the 95% case with a clean API where the easy path is also the secure path: constant-time verification for MACs, fresh nonces per call for AEAD, redaction-clean errors, and a hash module that deliberately won't let you accidentally use a raw hash as a MAC.
</p>

<hr>

## Installation

```toml
[dependencies]
crypt-io = "1"
```

Or:

```bash
cargo add crypt-io
```

**MSRV:** Rust 1.85 (edition 2024). Older toolchains will not build.

<hr>

## Quick start

### AEAD round-trip

```rust
use crypt_io::Crypt;

let key = [0u8; 32];                  // your 256-bit key
let crypt = Crypt::new();             // ChaCha20-Poly1305 by default

let ciphertext = crypt.encrypt(&key, b"plaintext data")?;
let recovered  = crypt.decrypt(&key, &ciphertext)?;
assert_eq!(&*recovered, b"plaintext data");
# Ok::<(), crypt_io::Error>(())
```

### AES-256-GCM (when you want hardware acceleration)

```rust
use crypt_io::Crypt;

let key = [0u8; 32];
let crypt = Crypt::aes_256_gcm();     // requires `aead-aes-gcm` (default-on)

let ciphertext = crypt.encrypt(&key, b"hello AES")?;
let recovered  = crypt.decrypt(&key, &ciphertext)?;
# Ok::<(), crypt_io::Error>(())
```

### Hashing

```rust
use crypt_io::hash;

let digest = hash::blake3(b"the quick brown fox");   // [u8; 32]
let sha256 = hash::sha256(b"the quick brown fox");   // [u8; 32]
let sha512 = hash::sha512(b"the quick brown fox");   // [u8; 64]
let xof    = hash::blake3_long(b"input", 128);       // Vec<u8>, 128 bytes
```

### MAC with constant-time verify

```rust
use crypt_io::mac;

let key  = b"shared secret";
let data = b"message to authenticate";

let tag = mac::hmac_sha256(key, data)?;
assert!(mac::hmac_sha256_verify(key, data, &tag)?);
// Never `tag == expected_tag` against a secret — use the `*_verify` path.
# Ok::<(), crypt_io::Error>(())
```

BLAKE3 keyed mode — typed key, infallible:

```rust
use crypt_io::mac;

let key = [0x42u8; 32];
let tag = mac::blake3_keyed(&key, b"message");
assert!(mac::blake3_keyed_verify(&key, b"message", &tag));
```

### Streaming (large or chunked inputs)

```rust
use crypt_io::hash::Blake3Hasher;

let mut h = Blake3Hasher::new();
h.update(b"first chunk ");
h.update(b"second chunk");
let digest = h.finalize();
```

### Key derivation

Deriving a subkey from a master:

```rust
use crypt_io::kdf;

let master = [0x42u8; 32];
let session_key = kdf::hkdf_sha256(&master, Some(b"salt"), b"app:session:v1", 32)?;
assert_eq!(session_key.len(), 32);
# Ok::<(), crypt_io::Error>(())
```

Hashing a password (Argon2id, OWASP-recommended defaults):

```rust,no_run
use crypt_io::kdf;

let phc = kdf::argon2_hash(b"correct horse battery staple")?;
assert!(kdf::argon2_verify(&phc, b"correct horse battery staple")?);
# Ok::<(), crypt_io::Error>(())
```

### Encrypt a file

```rust,no_run
use crypt_io::Algorithm;
use crypt_io::stream;

let key = [0u8; 32];
stream::encrypt_file("input.bin", "output.enc", &key, Algorithm::ChaCha20Poly1305)?;
stream::decrypt_file("output.enc", "decrypted.bin", &key)?;
# Ok::<(), crypt_io::Error>(())
```

Chunked AEAD with the STREAM construction — works for files of any size, detects tampering / truncation / reordering. For in-memory streaming (network sockets, buffered I/O), use `StreamEncryptor` / `StreamDecryptor` directly.

See [`docs/API.md`](docs/API.md) for the full reference.

<hr>

## Design philosophy

**crypt-io** is intentionally focused:

- **One job:** symmetric crypto. Done well.
- **No reinvention.** Primitives come from RustCrypto and BLAKE3 (battle-tested, widely audited).
- **Simple API.** Encrypt in two lines. Hash in one. The easy path is the secure path.
- **Algorithm agility.** ChaCha20-Poly1305 by default, AES-256-GCM when you want hardware acceleration. Same `Crypt` API either way.
- **Constant-time discipline.** MAC verification uses upstream constant-time comparators, never `==`. Documented in module overviews.
- **Hash ≠ MAC.** `Blake3Hasher` has no `with_key`. The only way to produce a keyed tag is through the `mac` module. This separation is deliberate.
- **Redaction-clean errors.** No variant of `Error` ever contains key material, plaintext, ciphertext, nonces, or tag bytes.
- **REPS-disciplined.** Every commit passes `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all-features`, and `cargo doc` with `-D warnings`.

What we explicitly do NOT do:

- Implement crypto primitives from scratch (use battle-tested upstreams)
- Asymmetric crypto (RSA, ECDSA, Ed25519) — different problem, separate crate
- PGP/GPG (use `sequoia-openpgp`)
- TLS (use `rustls`)
- Random number generation (use `mod-rand`)
- UUID generation (use `id-forge`)
- Key storage (use `key-vault`)

<hr>

## When to use crypt-io

**Good fit:**

- Encrypting data for storage (databases, file systems, caches)
- Encrypting API tokens or session data
- Authenticating messages, audit logs, signed records
- Hashing for integrity checks, fingerprinting, content-addressed storage
- HMAC signatures for outgoing requests (AWS SigV4, JWT HS256/HS512, webhooks)
- Composing with `key-vault` for in-memory key handling

**Wrong fit:**

- TLS connections — use [`rustls`](https://crates.io/crates/rustls)
- OpenPGP interop — use [`sequoia-openpgp`](https://crates.io/crates/sequoia-openpgp)
- Digital signatures — use [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek)
- Key exchange — use [`x25519-dalek`](https://crates.io/crates/x25519-dalek)
- Random number generation — use [`mod-rand`](https://crates.io/crates/mod-rand)

<hr>

## Performance

Measured on a reference machine (AMD Ryzen 9 9950X3D, AES-NI + SHA-NI + AVX-512, WSL2 Ubuntu, Rust 1.85.0). Full methodology + per-suite tables in [`docs/PERFORMANCE.md`](docs/PERFORMANCE.md).

| Operation                                    | Target     | Measured   | Status |
|----------------------------------------------|-----------:|-----------:|:---:|
| ChaCha20-Poly1305 encrypt, 1 KiB             | < 2 µs     | 1.72 µs    | ✅ |
| AES-256-GCM encrypt, 1 KiB (HW accel)        | < 1 µs     | 944 ns     | ✅ |
| BLAKE3 hash, 1 KiB                           | < 500 ns   | 1.07 µs    | ⚠️ revised |
| BLAKE3 hash, 64 KiB                          | —          | 11.24 GiB/s| ✅ |
| SHA-256 hash, 1 KiB (SHA-NI)                 | < 2 µs     | 426 ns     | ✅ |
| HMAC-SHA256, 1 KiB                           | < 3 µs     | 565 ns     | ✅ |
| HKDF-SHA256, 32-byte output                  | < 5 µs     | 304 ns     | ✅ |
| Argon2id, default params                     | ~100 ms    | ~9 ms (Zen 5 too fast — tune `t_cost`) | ⚠️ |
| Stream encrypt, 1 MiB plaintext              | > 1 GiB/s  | 932-999 MiB/s | ⚠️ marginal |

Reproduce: `cargo bench --all-features` (numbers vary by hardware — see PERFORMANCE.md for the portable analysis).

<hr>

## Documentation

- [`docs/API.md`](docs/API.md) — complete public-API reference.
- [`docs/STABILITY-1.0.md`](docs/STABILITY-1.0.md) — what the 1.0 contract freezes, the MSRV policy, what can change in 1.x vs 2.0.
- [`docs/SECURITY.md`](docs/SECURITY.md) — threat model, algorithm rationale, vulnerability reporting.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — module layout, algorithm dispatch, dependency rationale.
- [`docs/PLATFORM-NOTES.md`](docs/PLATFORM-NOTES.md) — hardware acceleration per platform + cross-compile guide.
- [`docs/PERFORMANCE.md`](docs/PERFORMANCE.md) — measured throughput, contract-check matrix, parameter-choice guidance.
- [`docs/FILE_FORMAT.md`](docs/FILE_FORMAT.md) — stream wire format spec (frozen for the 1.x series).
- [`CHANGELOG.md`](CHANGELOG.md) — per-version Added / Changed / Security entries.
- [`docs/release/`](docs/release) — per-release notes (`v0.2.0.md`, `v0.3.0.md`, …, `v1.0.0.md`).
- [`.dev/ROADMAP.md`](.dev/ROADMAP.md) — milestone plan through 1.0 and beyond.

<hr>

## Standards

- **REPS** (Rust Efficiency & Performance Standards) governs every decision. See [`REPS.md`](REPS.md).
- **MSRV:** Rust 1.85.
- **Edition:** 2024.
- **Cross-platform:** Linux, macOS, Windows (CI matrix on stable + MSRV).

<hr>

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
