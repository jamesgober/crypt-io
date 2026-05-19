# crypt-io - Project Prompt

> Context document for AI editor sessions working on `crypt-io`.
> Read this BEFORE writing any code on this crate.

---

## Read order (mandatory)

1. `REPS.md` at repo root - Rust Efficiency & Performance Standards. **SUPREME AUTHORITY.**
2. `_strategy/UNIVERSAL_PROMPT.md` - portfolio-wide engineering directives.
3. `.dev/DIRECTIVES.md` - this project's specific directives.
4. This file - project context.
5. `.dev/ROADMAP.md` - current phase, milestone targets, exit criteria.

REPS is mandatory and overrides anything else in this repository.

---

## What this crate is

`crypt-io` is the **encryption suite** for the Hive DB stack and the wider Rust ecosystem. It provides:

- **Symmetric AEAD encryption** (ChaCha20-Poly1305, AES-256-GCM)
- **Stream/file encryption** for large data
- **Hashing** (BLAKE3, SHA-256, SHA-512)
- **MAC** (HMAC-SHA256, BLAKE3 keyed)
- **KDF** (HKDF for key derivation, Argon2id for passwords)

## What it is NOT

- A from-scratch crypto implementation (primitives come from RustCrypto + BLAKE3)
- A random number generator (use `mod-rand`)
- A UUID generator (use `id-forge`)
- A key storage system (use `key-vault`)
- An asymmetric crypto library (RSA, ECDSA, Ed25519 - separate concern)
- A PGP/GPG implementation (use `sequoia-openpgp`)
- A TLS library (use `rustls`)

## Why it exists

Most Rust applications doing symmetric crypto:

- Use raw RustCrypto crates directly (verbose, easy to misuse nonces)
- Mix multiple algorithms with inconsistent APIs
- Have no portfolio integration (re-inventing error handling, random, logging)
- Lack performance discipline (no benchmarks, no tuning)

`crypt-io` fixes this with:
- One clean API across multiple algorithms
- Portfolio-aware (mod-rand, error-forge, log-io, metrics-lib)
- Benchmark-verified performance targets
- REPS discipline throughout

## Downstream consumers

- **Hive DB storage layer** - encryption at rest of CORD pages
- **audit-trail** - record signing
- **hive-server** - JWT signing, session token encryption
- **DISTRO** - encrypted WAL
- **Any application needing symmetric crypto**

`key-vault` is a **peer**, not a dependency. The consumer (Hive Core) wires them together.

## Naming conventions (locked in)

- **Main type: `Crypt`** - the encryption handle (`Crypt::new()`, `crypt.encrypt(...)`)
- **Algorithm enum: `Algorithm`** - `Algorithm::ChaCha20Poly1305`, `Algorithm::Aes256Gcm`
- **Hash functions: free fns in `crypt_io::hash`** - `hash::blake3(...)`, `hash::sha256(...)`
- **MAC functions: free fns in `crypt_io::mac`** - `mac::hmac_sha256(key, data)`
- **KDF functions: free fns in `crypt_io::kdf`** - `kdf::hkdf_sha256(...)`, `kdf::argon2_hash(...)`
- **Stream type: `StreamEncryptor` / `StreamDecryptor`** in `crypt_io::stream`

## Status

**Version:** `0.1.0` - scaffolded, no implementation yet.
**Target:** `1.0.0` stable. Effort estimate: 2-3 weeks focused work.

## Skill areas

Working on this crate requires comfort with:

- **AEAD construction** - nonce handling, associated data, tag verification
- **Constant-time discipline** - all key/MAC operations
- **Cryptographic best practices** - never reuse nonces, always authenticate, defense against padding oracles
- **RustCrypto API patterns** - trait-based, generic over algorithms
- **Benchmarking** - criterion, statistical rigor, hardware acceleration awareness
- **Stream protocols** - chunked AEAD, framing, resumable reads
- **Cross-platform crypto** - AES-NI on x86, SHA-NI on x86, Crypto extensions on ARM

## Scope (1.0)

### In scope for 1.0

- **AEAD encryption** with ChaCha20-Poly1305 (default) and AES-256-GCM (HW accel)
- **Algorithm-agile `Crypt` API** - same calls work for any AEAD
- **Stream/file encryption** - chunked AEAD with proper framing
- **Hashing** - BLAKE3 (default), SHA-256, SHA-512
- **MAC** - HMAC-SHA256, HMAC-SHA512, BLAKE3 keyed
- **KDF** - HKDF (multi-key from master), Argon2id (password hashing)
- **Portfolio integration** - mod-rand for CSPRNG, error-forge for errors
- **Optional instrumentation** - log-io, metrics-lib (feature-gated)
- **Comprehensive benchmarks** - throughput, latency, memory
- **Fuzz testing** - all input handling paths
- **Full REPS compliance** - lints, tests, docs

### Out of scope (deferred to 1.x or never)

- **Asymmetric crypto** - RSA, ECDSA, Ed25519 (separate crate when needed)
- **Post-quantum asymmetric** - Kyber, Dilithium (when ecosystem stabilizes)
- **PGP/GPG** - use `sequoia-openpgp`
- **TLS** - use `rustls`
- **Custom crypto primitives** - we wrap RustCrypto, we don't replace it
- **Random/UUID generation** - `mod-rand` and `id-forge` exist for this

## Performance targets (verified by benchmark)

| Operation | Target |
|-----------|--------|
| ChaCha20-Poly1305 encrypt, 1 KiB | <2us |
| ChaCha20-Poly1305 decrypt, 1 KiB | <2us |
| AES-256-GCM encrypt, 1 KiB (HW accel) | <1us |
| BLAKE3 hash, 1 KiB | <500ns |
| SHA-256 hash, 1 KiB | <2us |
| HMAC-SHA256, 1 KiB | <3us |
| HKDF-SHA256, 32-byte output | <5us |
| Argon2id, default params | <100ms (intentionally slow) |
| Stream encrypt throughput | >1 GiB/s |

## Architectural constraints

### MUST

- Use RustCrypto + BLAKE3 for actual primitives - no from-scratch math
- All key/MAC comparisons use `subtle::ConstantTimeEq` (transitively via RustCrypto)
- All key buffers wrapped in `Zeroizing` where possible
- Zero unsafe in our code (RustCrypto handles SIMD intrinsics safely)
- Cross-platform identical behavior (Linux, macOS, Windows)
- Compatible with stable Rust 1.75+

### MUST NOT

- Implement cryptographic primitives ourselves
- Allow nonce reuse without explicit user opt-in (and even then, document the risk)
- Hide error conditions (authentication failures must propagate)
- Pull `tokio` as a hard dependency (only feature-gated async support)

## How to develop on this crate

1. Read this document, REPS, DIRECTIVES, ROADMAP.
2. Check current phase in `.dev/ROADMAP.md`.
3. Pick the next unchecked task.
4. Implement with REPS + crypto discipline:
   - No `unwrap`, no `expect`, no `todo!`, no `unimplemented!`
   - No `print_stdout`, no `print_stderr`, no `dbg!`
   - Every new public item: rustdoc + at least one example
   - Every new algorithm: known-answer test vectors
   - Every hot path change: benchmark
5. Update `CHANGELOG.md` under `[Unreleased]` in the same commit.
6. Run the full CI gate locally before pushing.
7. Mark the task done in `.dev/ROADMAP.md` in the same commit.
8. Push.

## Reference patterns

When designing the API, look at:

- `ring` - production crypto API patterns
- `aws-lc-rs` - same, AWS-maintained
- `RustCrypto` (the project) - trait-based primitives
- `aead` crate - the trait we'd use to abstract over algorithms

When designing stream encryption, look at:

- AGE encryption format (modern, well-designed)
- TLS record framing patterns
- Tink (Google's crypto library) for chunked AEAD patterns

## When in doubt

- Read REPS first.
- For crypto decisions, default to the most conservative option (ChaCha20-Poly1305 by default, never reuse nonces, always authenticate)
- For performance, write a benchmark before claiming improvement
- For algorithm choices, prefer post-quantum-safe at 256 bits

---

<sub>crypt-io - Copyright (c) 2026 James Gober. Apache-2.0 OR MIT.</sub>