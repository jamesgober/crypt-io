# crypt-io - Production Roadmap to 1.0

> The engineering contract that takes `crypt-io` from `0.1.0` scaffold to `1.0.0` stable.
>
> Reads: `REPS.md` (supreme authority), `_strategy/UNIVERSAL_PROMPT.md`, `.dev/DIRECTIVES.md`, `.dev/PROMPT.md`.
>
> Target ship date: **2-3 focused weeks**.
> Status: Phase 0.1.0 complete (scaffold). Phase 0.2.0 next.

---

## The 1.0 Contract

When `crypt-io 1.0.0` ships, it commits to:

### Functional contract

- **`Crypt`** main type with algorithm-agile API
- **AEAD encryption** - ChaCha20-Poly1305 (default), AES-256-GCM (HW accel)
- **Stream/file encryption** - chunked AEAD with framing
- **Hashing** - BLAKE3, SHA-256, SHA-512
- **MAC** - HMAC-SHA256, HMAC-SHA512, BLAKE3 keyed
- **KDF** - HKDF, Argon2id
- **Cross-platform parity** - Linux, macOS, Windows
- **Hardware acceleration** - AES-NI, SHA-NI on x86; crypto extensions on ARM

### Performance contract (verified by benchmark)

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
| Wrapping overhead vs upstream | <20% on AEAD, <5% on hash |

### Security contract

- Zero unsafe code in our codebase
- Known-answer tests for every algorithm
- Fuzz testing clean for 1 CPU-hour per primitive
- `cargo audit` clean
- `cargo deny check` clean
- Constant-time discipline preserved through wrappers

### Stability contract

- Public API frozen for v1.x lifetime
- MSRV 1.75
- Edition 2024
- Apache-2.0 OR MIT dual licensed

---

## Phase 0.1.0 - Scaffold (COMPLETE)

- [x] Repository created on GitHub
- [x] Topics set (11 keywords)
- [x] Cargo.toml with feature flag plan
- [x] REPS.md canonical
- [x] LICENSE-APACHE + LICENSE-MIT
- [x] README, CHANGELOG
- [x] rustfmt.toml, clippy.toml, .gitignore, .editorconfig
- [x] src/lib.rs with full REPS lint discipline
- [x] tests/smoke.rs
- [x] benches/crypt_bench.rs placeholder
- [x] PROMPT.md, DIRECTIVES.md, this ROADMAP.md
- [x] CI workflow

---

## Phase 0.2.0 - AEAD foundation (ChaCha20-Poly1305)

**Goal:** Working AEAD encryption with the default algorithm.

**Effort:** 3-4 days.

### Tasks

- [ ] Design `Crypt` struct
  - Internal: algorithm enum, optional key handle
  - `Crypt::new()` defaults to ChaCha20-Poly1305
  - `Crypt::with_algorithm(Algorithm)` for explicit selection
- [ ] Design `Algorithm` enum
  - `ChaCha20Poly1305` (default)
  - `Aes256Gcm` (gated behind feature)
- [ ] Implement `Crypt::encrypt(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>>`
  - Generate nonce via `mod-rand` Tier 3
  - Prepend nonce to ciphertext
  - Use `chacha20poly1305` crate internally
- [ ] Implement `Crypt::decrypt(&self, key: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>>`
  - Extract nonce from ciphertext
  - Verify tag (constant-time)
  - Return zeroizing buffer
- [ ] Implement `Crypt::encrypt_with_aad(...)` for AEAD with associated data
- [ ] Implement `Crypt::decrypt_with_aad(...)` matching
- [ ] Error types via `error-forge`:
  - `CryptError::InvalidKey`
  - `CryptError::InvalidCiphertext`
  - `CryptError::AuthenticationFailed`
  - `CryptError::AlgorithmNotEnabled`
- [ ] Unit tests:
  - Round-trip encrypt/decrypt
  - Wrong key fails authentication
  - Tampered ciphertext fails authentication
  - Known-answer tests from RFC 8439 (ChaCha20-Poly1305)
- [ ] First doctest examples
- [ ] CHANGELOG updated

### Exit criteria

- [ ] ChaCha20-Poly1305 working end-to-end
- [ ] Known-answer tests passing
- [ ] CI green on all platforms

---

## Phase 0.3.0 - AES-256-GCM + algorithm selection

**Goal:** Add AES-256-GCM with same API. Algorithm selection works cleanly.

**Effort:** 2-3 days.

### Tasks

- [ ] Add `aead-aes-gcm` feature flag (already in Cargo.toml)
- [ ] Implement AES-256-GCM path in `Crypt::encrypt/decrypt`
- [ ] Algorithm dispatch via internal enum match
- [ ] Hardware acceleration verification (AES-NI on x86, crypto extensions on ARM)
- [ ] Known-answer tests from NIST SP 800-38D
- [ ] Benchmark comparison: ChaCha20 vs AES-GCM

### Exit criteria

- [ ] AES-256-GCM working
- [ ] Algorithm selection clean
- [ ] HW acceleration confirmed working
- [ ] Both algorithms benchmarked

---

## Phase 0.4.0 - Hashing

**Goal:** BLAKE3, SHA-256, SHA-512 with consistent API.

**Effort:** 2-3 days.

### Tasks

- [ ] Module `crypt_io::hash`
- [ ] `hash::blake3(data: &[u8]) -> [u8; 32]` (32-byte output)
- [ ] `hash::blake3_long(data: &[u8], len: usize) -> Vec<u8>` (variable output)
- [ ] `hash::sha256(data: &[u8]) -> [u8; 32]`
- [ ] `hash::sha512(data: &[u8]) -> [u8; 64]`
- [ ] Streaming hashers for large inputs:
  - `hash::Blake3Hasher`, `hash::Sha256Hasher`, `hash::Sha512Hasher`
  - `update(&mut self, data: &[u8])` + `finalize(self) -> [u8; N]`
- [ ] Known-answer tests for each algorithm
- [ ] Benchmark suite

### Exit criteria

- [ ] All three hash functions working
- [ ] Streaming API for large inputs
- [ ] KAT passing for all
- [ ] Benchmarks within targets

---

## Phase 0.5.0 - MAC

**Goal:** HMAC-SHA256, HMAC-SHA512, BLAKE3 keyed mode.

**Effort:** 2 days.

### Tasks

- [ ] Module `crypt_io::mac`
- [ ] `mac::hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32]`
- [ ] `mac::hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64]`
- [ ] `mac::blake3_keyed(key: &[u8; 32], data: &[u8]) -> [u8; 32]`
- [ ] Constant-time tag verification (provided by upstream)
- [ ] Streaming MAC for large inputs
- [ ] Known-answer tests (RFC 4231 for HMAC)

### Exit criteria

- [ ] All MAC functions working
- [ ] KAT passing
- [ ] Constant-time verification verified

---

## Phase 0.6.0 - KDF (HKDF + Argon2id)

**Goal:** Key derivation for both master-key-to-many and password-to-key.

**Effort:** 3-4 days.

### Tasks

- [ ] Module `crypt_io::kdf`
- [ ] `kdf::hkdf_sha256(ikm: &[u8], salt: Option<&[u8]>, info: &[u8], len: usize) -> Result<Vec<u8>>`
- [ ] `kdf::hkdf_sha512(...)` matching
- [ ] `kdf::argon2_hash(password: &[u8], salt: &[u8]) -> Result<String>` (returns Argon2id encoded string)
- [ ] `kdf::argon2_verify(hash_string: &str, password: &[u8]) -> Result<bool>`
- [ ] `kdf::argon2_with_params(...)` for custom parameters
- [ ] Salt generation via `mod-rand` Tier 3
- [ ] Known-answer tests for HKDF (RFC 5869)
- [ ] Argon2id default parameters documented

### Exit criteria

- [ ] HKDF working for SHA-256 and SHA-512
- [ ] Argon2id hash and verify working
- [ ] KAT passing
- [ ] Salt generation correct

---

## Phase 0.7.0 - Stream/file encryption

**Goal:** Chunked AEAD for files and large data.

**Effort:** 4-5 days.

### Tasks

- [ ] Module `crypt_io::stream`
- [ ] `StreamEncryptor::new(key, algorithm) -> Self`
- [ ] `StreamEncryptor::update(&mut self, chunk: &[u8]) -> Vec<u8>` (returns encrypted chunk)
- [ ] `StreamEncryptor::finalize(self) -> Vec<u8>` (final tag chunk)
- [ ] `StreamDecryptor` matching
- [ ] Frame format documented (chunk header + ciphertext + tag, chained MACs)
- [ ] File-level helpers:
  - `stream::encrypt_file(input_path, output_path, key) -> Result<()>`
  - `stream::decrypt_file(...)` matching
- [ ] Resumable on partial reads
- [ ] Tests with various chunk sizes (1 KiB, 64 KiB, 1 MiB)
- [ ] Large data test (1 GiB stream)

### Exit criteria

- [ ] Stream encryption working
- [ ] Frame format documented
- [ ] File helpers working
- [ ] 1 GiB streaming verified

---

## Phase 0.8.0 - Performance verification + tuning

**Goal:** Hit Performance Contract numbers via benchmarks.

**Effort:** 4-5 days.

### Tasks

- [ ] Comprehensive benchmark suite
  - `benches/aead.rs` - all AEAD scenarios
  - `benches/hash.rs` - all hash functions
  - `benches/mac.rs` - all MAC functions
  - `benches/kdf.rs` - HKDF and Argon2
  - `benches/stream.rs` - stream throughput
- [ ] Cross-platform measurements:
  - x86_64 with AES-NI
  - x86_64 without AES-NI (force software fallback)
  - ARM64 with crypto extensions (if available)
- [ ] Compare against upstream RustCrypto:
  - Wrapping overhead <20% for AEAD
  - Wrapping overhead <5% for hash
- [ ] Allocation profile with dhat
- [ ] Tune where targets missed
- [ ] `docs/PERFORMANCE.md`

### Exit criteria

- [ ] All Performance Contract targets met
- [ ] Cross-platform measurements documented
- [ ] Baselines committed

---

## Phase 0.9.0 - Fuzz testing

**Goal:** No panics, no OOMs, no infinite loops on any input.

**Effort:** 3-4 days.

### Tasks

- [ ] Set up `cargo-fuzz` workspace
- [ ] Fuzz targets:
  - AEAD encrypt with random key/plaintext/nonce/AAD
  - AEAD decrypt with random ciphertext (most likely to find issues)
  - Each hash function
  - Each MAC function
  - HKDF with random inputs
  - Argon2id parameter parsing
  - Stream encryption with random chunk boundaries
- [ ] Run each for 1 CPU-hour minimum
- [ ] Fix any findings
- [ ] Corpus inputs committed to fuzz/corpus/
- [ ] Regression tests added

### Exit criteria

- [ ] All fuzz targets clean for 1 CPU-hour
- [ ] No findings
- [ ] Corpus committed

---

## Phase 0.10.0 - Docs + Release Candidate

**Goal:** Final documentation, cut 1.0.0-rc.1.

**Effort:** 3 days.

### Tasks

- [ ] `docs/STABILITY-1.0.md`
- [ ] `docs/ARCHITECTURE.md` - internal architecture, algorithm dispatch
- [ ] `docs/SECURITY.md` - threat model, algorithm choices, KAT references
- [ ] `docs/PERFORMANCE.md` - from 0.8.0
- [ ] `docs/PLATFORM-NOTES.md` - HW acceleration availability
- [ ] `docs/FILE_FORMAT.md` - stream encryption frame format spec
- [ ] Every public item rustdoc'd with example
- [ ] `docs/release-notes/v1.0.0.md`
- [ ] Cut 1.0.0-rc.1
- [ ] 1 week soak
- [ ] Address rc.N if needed

### Exit criteria

- [ ] All docs in place
- [ ] 1.0.0-rc.1 published as pre-release
- [ ] 1 week soak clean

---

## Phase 1.0.0 - Stable release

**Goal:** Ship the encryption suite.

### Pre-flight

- [ ] No critical issues from RC soak
- [ ] All CI green
- [ ] All Performance Contract targets met
- [ ] `cargo public-api diff` clean
- [ ] `cargo audit` clean

### Release sequence

- [ ] Bump to 1.0.0
- [ ] Move CHANGELOG [Unreleased] to [1.0.0]
- [ ] Finalize release notes
- [ ] Commit, push, verify CI
- [ ] Tag v1.0.0, push tag
- [ ] GitHub release (NOT pre-release)
- [ ] cargo publish --dry-run, then cargo publish
- [ ] Verify crates.io + docs.rs

### Exit criteria

- [ ] crypt-io 1.0.0 on crates.io
- [ ] docs.rs builds clean
- [ ] At least one Hive DB component consuming crypt-io = "1.0"

---

## Post-1.0 backlog

### 1.1.x candidates

- [ ] Async API (full async-trait support across all operations)
- [ ] Additional KDF: scrypt (legacy compatibility)
- [ ] XChaCha20-Poly1305 (longer nonce variant)
- [ ] AES-256-SIV (nonce-misuse resistant)
- [ ] Hardware acceleration on additional platforms (RISC-V crypto extensions)

### 1.2.x and beyond

- [ ] Post-quantum AEAD (when standards mature)
- [ ] Threshold cryptography helpers (post-quantum-safe Shamir's secret sharing)
- [ ] Format-preserving encryption (FPE) for narrow use cases

### Explicitly out of scope forever

- Asymmetric crypto (RSA, ECDSA, Ed25519) - separate crate
- PGP/GPG - use sequoia-openpgp
- TLS - use rustls
- From-scratch crypto primitive implementations

---

## Quick reference

```
==============================================================
crypt-io roadmap to 1.0
==============================================================
0.1.0   Scaffold                              DONE
0.2.0   AEAD foundation (ChaCha20-Poly1305)   3-4 days
0.3.0   AES-256-GCM + algorithm selection     2-3 days
0.4.0   Hashing (BLAKE3, SHA-2)               2-3 days
0.5.0   MAC (HMAC, BLAKE3 keyed)              2 days
0.6.0   KDF (HKDF, Argon2id)                  3-4 days
0.7.0   Stream/file encryption                4-5 days
0.8.0   Performance verification              4-5 days
0.9.0   Fuzz testing                          3-4 days
0.10.0  Docs + Release Candidate              3 days
1.0.0   Stable Release                        1 day
==============================================================
Total: ~2-3 focused weeks
==============================================================
```

---

## Roadmap discipline

- Every task has a checkbox
- Every phase has exit criteria
- No skipping without explicit justification
- No performance claim without committed benchmark
- No algorithm without known-answer tests
- CHANGELOG updated under [Unreleased] every commit
- `Milestone Update vX.Y.Z` commit format for releases

---

<sub>crypt-io roadmap - Copyright (c) 2026 James Gober. Apache-2.0 OR MIT.</sub>