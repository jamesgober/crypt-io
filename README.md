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

## Status

**Current version:** `0.7.0` (2026-05-22). Pre-1.0 — the public API is allowed to evolve in breaking ways through the `0.x` series; `1.0.0` freezes it.

| Phase  | Surface                                          | Status |
|--------|--------------------------------------------------|--------|
| 0.1.0  | Scaffold, REPS baseline, CI                      | shipped |
| 0.2.0  | AEAD foundation — ChaCha20-Poly1305              | shipped |
| 0.3.0  | AES-256-GCM + algorithm selection                | shipped |
| 0.4.0  | Hashing — BLAKE3 (+ XOF), SHA-256, SHA-512       | shipped |
| 0.5.0  | MAC — HMAC-SHA256/512, BLAKE3 keyed              | shipped |
| 0.6.0  | KDF — HKDF-SHA256/512, Argon2id                  | shipped |
| 0.7.0  | Stream / file encryption                         | **shipped** |
| 0.8.0  | Performance verification (criterion benches)     | next |
| 0.9.0  | Fuzz testing                                     | planned |
| 0.10.0 | Docs + Release Candidate                         | planned |
| 1.0.0  | Stable Release                                   | planned |

See [`.dev/ROADMAP.md`](.dev/ROADMAP.md) for the full milestone plan and [`CHANGELOG.md`](CHANGELOG.md) for per-version detail. Per-release notes live under [`docs/release/`](docs/release).

<hr>

## What's in 0.7.0

### Symmetric AEAD encryption — `crypt_io::aead`

- **`Crypt::new()`** — ChaCha20-Poly1305 (default, post-quantum-safe at 256 bits).
- **`Crypt::aes_256_gcm()`** — AES-256-GCM (hardware-accelerated on AES-NI / ARMv8 crypto extensions, runtime-dispatched by upstream).
- **Algorithm-agile API.** Same `encrypt` / `decrypt` surface, same wire format (`nonce || ciphertext || tag`), same 32-byte key. Switch by picking the constructor.
- **Fresh nonces per call** via `mod-rand` Tier 3 (OS CSPRNG). Nonce reuse cannot happen through the public API.
- **AAD support** via `encrypt_with_aad` / `decrypt_with_aad`.
- **RFC 8439 + NIST SP 800-38D known-answer tests** verifying byte-exact output against the specs.

### Hashing — `crypt_io::hash`

- **BLAKE3** — `hash::blake3` (32-byte default) + `hash::blake3_long` (XOF, any length) + streaming `Blake3Hasher`.
- **SHA-256 / SHA-512** — `hash::sha256` / `hash::sha512` + streaming `Sha256Hasher` / `Sha512Hasher`.
- **NIST FIPS 180-4 known-answer tests** for SHA-2; byte-pinned KATs for BLAKE3.
- **Streaming-equals-one-shot** verified at multiple chunk boundaries.
- **Hash-only by design.** No `with_key`. Keyed hashing lives in `mac`.

### Message Authentication — `crypt_io::mac`

- **HMAC-SHA256 / HMAC-SHA512** — `mac::hmac_sha256` / `mac::hmac_sha512` + streaming `HmacSha256` / `HmacSha512`.
- **BLAKE3 keyed mode** — `mac::blake3_keyed` (typed 32-byte key, infallible) + streaming `Blake3Mac`.
- **Constant-time verification by default.** Every algorithm exposes a `*_verify` path that compares against an expected tag via upstream constant-time comparators. **Never** `tag == expected` against a secret.
- **RFC 4231 known-answer tests** for HMAC; byte-pinned KAT for BLAKE3 keyed.
- **Wrong-length tags are rejections, not panics.**

### Key Derivation — `crypt_io::kdf`

- **HKDF-SHA256 / HKDF-SHA512** — `kdf::hkdf_sha256` / `kdf::hkdf_sha512` for deriving subkeys from a master key, a Diffie-Hellman shared secret, or any other high-entropy input. Single-call extract-then-expand with optional salt and `info` domain-separator.
- **Argon2id** — `kdf::argon2_hash` for hashing passwords with the OWASP-recommended parameter set (~100 ms per hash). Salt is generated fresh per-call via `mod-rand` Tier 3 and embedded in the returned PHC string — callers don't manage salt storage. `kdf::argon2_verify` for constant-time verification against a stored PHC string. `kdf::argon2_hash_with_params` + `Argon2Params` for callers with different cost tolerances.
- **HKDF is not for passwords.** Module documentation explicitly distinguishes the two — HKDF assumes high-entropy input, Argon2id assumes low-entropy input that needs brute-force resistance.
- **RFC 5869 known-answer tests** for HKDF-SHA256 (Test Cases 1 + 3); SHA-512 cross-checked against the upstream `hkdf` crate.

### Stream / File Encryption — `crypt_io::stream`

- **`StreamEncryptor` / `StreamDecryptor`** — chunked AEAD for data that doesn't fit in memory. Symmetric `update()` / `finalize()` triad on both sides; callers don't have to track chunk boundaries. Default 64 KiB chunks, tunable via `new_with_chunk_size` (1 KiB..16 MiB).
- **`stream::encrypt_file` / `stream::decrypt_file`** — file-to-file helpers for the common workflow. Decryption reads the algorithm from the stream header — no need to track which one was used.
- **STREAM-construction nonces** (the same shape AGE uses) defeat **truncation**, **chunk reordering**, and **chunk duplication**. Header bytes are AAD on every chunk, so header tampering (algorithm byte, nonce prefix) fails verification on the first chunk. Wire format documented in [`docs/API.md`](docs/API.md#stream-wire-format).
- **Final-chunk-always invariant.** The encoder always emits a final chunk (even if it carries zero plaintext) so EOF detection is unambiguous — a stream that ends mid-chunk or after a non-final chunk fails to verify.
- **25 attack-surface integration tests** in `tests/stream.rs` — wrong key, body/tag tamper, three flavours of truncation, swapped chunks, duplicated chunks, header tamper, byte-by-byte feeding, file round-trip.

### Examples — `examples/`

Five runnable end-to-end programs covering the major use cases:

```bash
cargo run --example aead_round_trip
cargo run --example password_hash --release   # --release: Argon2id is intentionally slow
cargo run --example derive_subkeys
cargo run --example mac_authenticate
cargo run --example encrypt_file
```

### Portfolio integration

- **[`mod-rand`](https://crates.io/crates/mod-rand)** — Tier 3 OS-backed CSPRNG for nonces.
- **[`error-forge`](https://crates.io/crates/error-forge)** — declared dependency (deeper integration in a later phase).
- **[`log-io`](https://crates.io/crates/log-io)** *(optional)* — operation logging.
- **[`metrics-lib`](https://crates.io/crates/metrics-lib)** *(optional)* — performance instrumentation.
- **[`key-vault`](https://crates.io/crates/key-vault)** — peer crate; the consumer wires them together. No direct dependency.

### What's *not* in 0.7.0 yet

- **Benchmark suite** — Phase 0.8.0. Performance targets are in the contract (see [`.dev/ROADMAP.md`](.dev/ROADMAP.md)); committed criterion-backed measurements land in 0.8.
- **Fuzz testing** — Phase 0.9.0.
- **Resumable streaming** (checkpoint encryptor state, resume after a process restart) — post-1.0.
- **Async file helpers** — Phase 1.x.
- **Asymmetric crypto, PGP, TLS, RNG, UUIDs, key storage** — out of scope for the lifetime of this crate. Use `mod-rand`, `key-vault`, `rustls`, `sequoia-openpgp`, etc.

<hr>

## Installation

```toml
[dependencies]
crypt-io = "0.7"
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

## Performance targets

Verified by benchmarks in **Phase 0.8.0** (criterion-backed, committed baselines). Until then these are documented targets, not measured numbers:

| Operation                                    | Target    |
|----------------------------------------------|-----------|
| ChaCha20-Poly1305 encrypt, 1 KiB             | < 2 µs    |
| AES-256-GCM encrypt, 1 KiB (HW accel)        | < 1 µs    |
| BLAKE3 hash, 1 KiB                           | < 500 ns  |
| SHA-256 hash, 1 KiB                          | < 2 µs    |
| HMAC-SHA256, 1 KiB                           | < 3 µs    |
| HKDF-SHA256, 32-byte output                  | < 5 µs    |
| Argon2id, default params                     | ~100 ms (intentionally slow) |
| Stream encrypt throughput                    | > 1 GiB/s |

<hr>

## Documentation

- [`docs/API.md`](docs/API.md) — complete public-API reference for the current version.
- [`CHANGELOG.md`](CHANGELOG.md) — per-version Added / Changed / Security entries.
- [`docs/release/`](docs/release) — per-release notes (`v0.2.0.md`, `v0.3.0.md`, …).
- [`.dev/ROADMAP.md`](.dev/ROADMAP.md) — milestone plan through 1.0.

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
