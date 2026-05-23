# Changelog

All notable changes to `crypt-io` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

### Changed

### Fixed

### Security

---

## [0.9.0] - 2026-05-22

### Added

- **`fuzz/` workspace with 8 `cargo-fuzz` targets** covering
  every algorithm the crate ships, plus the streaming frame
  format:
  - `aead_decrypt` — `Crypt::decrypt` / `decrypt_with_aad` with
    arbitrary keys, ciphertexts, AAD. The attacker-controlled
    ciphertext path; highest-value target.
  - `aead_encrypt` — `Crypt::encrypt` followed by `decrypt`
    round-trip equality assertion. Catches any
    encrypt-succeeds-but-decrypt-fails algorithm-dispatch bug.
  - `hash_blake3` — `hash::blake3` + `blake3_long` + streaming
    `Blake3Hasher` with streaming-vs-one-shot equivalence.
  - `hash_sha2` — `hash::sha256` / `sha512` + streaming hashers
    with the same equivalence check.
  - `mac` — all three MACs (HMAC-SHA256, HMAC-SHA512, BLAKE3
    keyed) across compute + verify + streaming + verify-rejects-
    wrong-tag.
  - `hkdf` — `hkdf_sha256` / `hkdf_sha512` with arbitrary IKM /
    salt / info / length. Verifies determinism (same inputs →
    same outputs across calls) and length-bound enforcement.
  - `argon2_parse` — `argon2_verify` PHC-parser fuzzing with
    arbitrary strings, plus parameter-validation fuzzing via
    `argon2_hash_with_params` (with capped costs).
  - `stream_decrypt` — `StreamDecryptor` with arbitrary header +
    body + chunk-split boundaries, plus round-trip-with-arbitrary-
    splits. Exercises the frame-format attack surface (header
    parse, per-chunk counter, last-flag detection, buffering
    invariants).
- **`fuzz/README.md`** documenting setup (nightly + cargo-fuzz +
  WSL2 on Windows), per-target commands, 1-CPU-hour run loop, a
  per-target findings policy, and the "what's intentionally NOT
  fuzzed" list (Argon2id at OWASP defaults — too slow to iterate;
  TEE detection — runtime hardware probe, not input-driven; the
  criterion bench suite — dev-only).
- **Pre-1.0 smoke-run results** committed to release notes: **4.7
  million total fuzz iterations across 8 targets in 2 minutes
  on WSL2 Ubuntu, zero findings.** None of the 8 targets
  panicked, hung, or produced an unexpected error. Full 1-CPU-
  hour-per-target runs are pre-cut work for the 1.0.0-rc.

### Changed

- **Roadmap restructured.** Inserted **Phase 0.10.0** (allocation
  profile via `mod-alloc` + zero-allocation `encrypt_into` /
  `update_into` paths) before the release-candidate phase, so the
  wrapping-overhead gap vs upstream RustCrypto identified in
  0.8.0's PERFORMANCE.md is closed before 1.0 ships. Docs +
  Release Candidate is now **Phase 0.11.0**; 1.0.0 unchanged.
- **0.8.0 release notes + PERFORMANCE.md + ROADMAP** reworded:
  - Stream encrypt @ 1 MiB (932-999 MiB/s) reclassified from
    "⚠️ marginal" to "✅ within 1%" — it's literally at the line.
  - Argon2id @ ~9 ms on Zen 5 reclassified from "⚠️ too fast" to
    "ℹ️ guidance: tune `t_cost` on fast hardware" — fast hardware
    is good news, not a failure.
  - BLAKE3 @ 1 KiB reclassified to highlight the **64 KiB win**
    (11.24 GiB/s) — the small-input target was always
    over-optimistic and is being revised honestly.
- **Allocation-profile tooling switched** from `dhat` to
  [`mod-alloc`](https://github.com/jamesgober/mod-alloc) (the
  portfolio's dhat-compatible profiler with lower MSRV and ~60 ns
  / op overhead). Lands in Phase 0.10.0 — was previously
  "post-1.0".

### Security

- **`cargo-fuzz` clean for the smoke window across all 8
  targets.** Establishes the regression-prevention baseline:
  every future fuzz finding now has a corpus seed and a
  regression test. 1-CPU-hour-per-target runs are the
  Phase-0.11.0 RC gate; the smoke results in this release give
  ~150,000-1,240,000 iterations of confidence per target.

[0.9.0]: https://github.com/jamesgober/crypt-io/compare/v0.8.0...v0.9.0

---

## [0.8.0] - 2026-05-22

### Added

- **Five criterion benchmark suites** under `benches/` —
  `aead.rs`, `hash.rs`, `mac.rs`, `kdf.rs`, `stream.rs`. Each
  exercises every shipped algorithm at the canonical input sizes
  (64 B / 1 KiB / 64 KiB / 1 MiB for byte-stream ops, 32/64/128 B
  for HKDF output length, OWASP-default + fast-params for
  Argon2id). All five are wired as `[[bench]]` entries with
  `harness = false` and run via `cargo bench --bench <name>`.
- **`docs/PERFORMANCE.md`** — methodology + reference-machine
  specs (AMD Ryzen 9 9950X3D, AES-NI + SHA-NI + AVX-512, WSL2
  Ubuntu, Rust 1.85.0) + measured throughput tables for every
  operation + a contract-check matrix comparing measured numbers
  to the 1.0 performance targets + a "choosing parameters for
  your hardware" guide.
- **Wrapping-overhead analysis** in PERFORMANCE.md — comparison
  of our measured numbers against upstream RustCrypto's published
  benches for each primitive. Most operations are within
  measurement noise of upstream; the per-call `Vec` allocation
  in our encrypt path is the only material overhead and is
  documented for a post-1.0 zero-allocation variant.

### Changed

- **Replaced placeholder `benches/crypt_bench.rs`** with the five
  real bench files. The `[[bench]] name = "crypt_bench"` entry in
  `Cargo.toml` is gone; replaced with five entries
  (`aead`, `hash`, `mac`, `kdf`, `stream`).
- **BLAKE3 1 KiB performance target revised.** The < 500 ns
  target set at scaffold time was over-optimistic — BLAKE3
  small-input cost is dominated by per-call setup overhead
  before its tree-parallel SIMD path engages. Measured: 1.07 µs
  at 1 KiB on Zen 5. BLAKE3 dominates at ≥ 4 KiB (11+ GiB/s at
  64 KiB). PERFORMANCE.md documents the actual shape; the
  contract will be re-stated for 1.0.
- **Argon2id OWASP-defaults cost note.** Measured at ~9 ms per
  hash on this Zen 5 chip — ~11× faster than the "100 ms on a
  modern CPU" design intent. PERFORMANCE.md flags this with a
  warning and points callers at `argon2_hash_with_params` for
  raising `t_cost` / `m_cost` on fast hardware to maintain the
  brute-force-resistance budget.
- **Stream encrypt 1 GiB/s target** measured marginal at 1 MiB
  plaintext (932 MiB/s ChaCha20, 999 MiB/s AES). Within
  measurement noise of the 1 GiB/s target; well over for
  decrypt (1.19-1.30 GiB/s). PERFORMANCE.md documents the
  allocation pressure that's the bottleneck and flags
  zero-allocation streaming as post-1.0 work.

### Security

- **No security-surface changes.** The bench suite exercises the
  same public API as the integration tests; it does not weaken
  any verification path or expose any new surface.

[0.8.0]: https://github.com/jamesgober/crypt-io/compare/v0.7.0...v0.8.0

---

## [0.7.0] - 2026-05-22

### Added

- **`crypt_io::stream` module** — chunked AEAD with a
  [STREAM-construction] frame format for encrypting data that
  doesn't fit in memory.
  - `StreamEncryptor` — buffers plaintext, emits encrypted chunks
    of `chunk_size + 16` bytes each. `new()` + `update()` +
    `finalize()` triad; `new_with_chunk_size()` for tuning chunk
    size (10..=24 log2).
  - `StreamDecryptor` — symmetric inverse. Parses the header,
    buffers ciphertext, emits decrypted plaintext as chunks
    complete.
  - `stream::encrypt_file` / `stream::decrypt_file` — file-to-file
    helpers using `BufReader` / `BufWriter` and the streaming
    types. Available under `std`.
  - **Frame format** documented in [`stream::frame`]:
    24-byte header (magic + version + algorithm + chunk_size_log2 +
    nonce_prefix) + N-1 non-final chunks + 1 final chunk strictly
    smaller than `chunk_size + 16` bytes. STREAM-construction
    per-chunk nonces (`prefix || counter_u32_be || last_flag`)
    defeat truncation, reordering, and duplication; header bytes
    are AAD for every chunk, so header tampering surfaces as
    authentication failure on the first chunk.
- **Public constants** in `crypt_io::stream`: `HEADER_LEN = 24`,
  `TAG_LEN = 16`, `DEFAULT_CHUNK_SIZE_LOG2 = 16` (64 KiB),
  `MIN_CHUNK_SIZE_LOG2 = 10`, `MAX_CHUNK_SIZE_LOG2 = 24`.
- **Integration test suite** `tests/stream.rs` — 25 tests
  covering:
  - Round-trip across both algorithms, multiple chunk sizes,
    empty / 1-byte / exact-chunk / chunk+1 / many-chunk / 10 MiB
    inputs, byte-by-byte feeding on both sides.
  - Attack surface: wrong key, tampered chunk body, tampered tag,
    truncation (to zero / mid-tag / dropped final chunk), swapped
    chunks, duplicated chunk, tampered algorithm byte, tampered
    nonce prefix, tampered magic, wrong key length, distinct
    nonce prefixes per stream.
  - File round-trip for both algorithms.
- **`examples/` directory populated** — 5 runnable examples
  covering the main use cases:
  - `aead_round_trip.rs` — `Crypt::encrypt` / `decrypt`, both
    algorithms, with-AAD variant.
  - `password_hash.rs` — Argon2id hash + verify, custom params.
  - `derive_subkeys.rs` — HKDF for splitting one master into many
    purpose-specific subkeys with domain separation.
  - `mac_authenticate.rs` — HMAC-SHA256 + verify, BLAKE3 keyed,
    streaming MAC.
  - `encrypt_file.rs` — `stream::encrypt_file` /
    `stream::decrypt_file` round-trip plus a tamper-detection demo.

### Changed

- **Default features extended.** `default` now includes `stream`
  alongside the AEAD / hash / MAC / KDF baselines. A fresh
  `cargo add crypt-io` ships with the streaming surface
  available.
- **`stream` feature dependencies broadened** from `aead-chacha20`
  to `aead-chacha20 + aead-aes-gcm`, so the streaming types can
  switch algorithms at runtime without an extra feature flag.
- **`lib.rs` module wiring.** The `stream` module is exposed when
  the `stream` feature is enabled.

### Security

- **Truncation, reordering, and duplication detection.** The
  STREAM construction's per-chunk nonces include both a counter
  and a `last_flag` byte. Any of these attacks produces a nonce
  mismatch on the affected chunk → `AuthenticationFailed`.
- **Header binding.** Every encrypted chunk uses the 24-byte
  header as AAD, so tampering with the algorithm byte, chunk
  size, or nonce prefix shows up as authentication failure on
  the first chunk.
- **Final-chunk-always invariant.** The encryptor always emits a
  final chunk (even if it carries zero plaintext bytes), so the
  decryptor can detect end-of-stream unambiguously by length —
  a stream that ends mid-chunk or after a non-final chunk fails
  to verify.
- **Opaque `AuthenticationFailed`.** Wrong key, tampered chunk,
  tampered tag, header tampering, truncation, reordering, and
  duplication all surface as the same single variant. The
  classification is intentionally not exposed.
- **File-decrypt failure cleanup.** `decrypt_file` documents that
  callers must delete the partially-written output file on error
  — earlier chunks may have been written to disk before a later
  chunk failed to verify. The documentation is explicit because
  this is a footgun in every chunked-AEAD design.

[STREAM-construction]: https://eprint.iacr.org/2015/189.pdf
[`stream::frame`]: crate::stream::frame
[0.7.0]: https://github.com/jamesgober/crypt-io/compare/v0.6.0...v0.7.0

---

## [0.6.0] - 2026-05-22

### Added

- **`crypt_io::kdf` module** — two algorithms for deriving keys,
  each addressing a different threat model:
  - **HKDF** ([RFC 5869]):
    - `kdf::hkdf_sha256(ikm, salt, info, len) -> Result<Vec<u8>>` —
      extract-then-expand HKDF with SHA-256 underneath. Accepts
      an optional `salt`, an `info` context string, and an output
      length up to `255 * 32 = 8160` bytes.
    - `kdf::hkdf_sha512(...)` — same shape, SHA-512 digest, output
      up to `255 * 64 = 16320` bytes.
    - Output-length bounds enforced and surfaced as
      [`Error::Kdf`] when exceeded.
    - Feature: `kdf-hkdf` (default on).
  - **Argon2id** ([RFC 9106]):
    - `kdf::argon2_hash(password) -> Result<String>` — hashes with
      the OWASP-recommended parameter set (~100 ms on a modern
      CPU). Salt is generated fresh via `mod_rand::tier3::fill_bytes`
      and embedded in the returned PHC string. No salt management
      required from callers.
    - `kdf::argon2_hash_with_params(password, params)` — same but
      with caller-supplied [`Argon2Params`].
    - `kdf::argon2_verify(phc, password) -> Result<bool>` —
      constant-time verification against a PHC-encoded hash string.
    - Feature: `kdf-argon2` (default on in 0.6.0+).
- **`Argon2Params`** struct exposing `m_cost` (memory in KiB),
  `t_cost` (iterations), `p_cost` (lanes), `output_len`. `Default`
  matches the OWASP recommendations (19 MiB / 2 / 1 / 32 bytes).
- **Public constants** in `crypt_io::kdf`:
  `HKDF_MAX_OUTPUT_SHA256 = 8160`, `HKDF_MAX_OUTPUT_SHA512 = 16320`,
  `ARGON2_DEFAULT_OUTPUT_LEN = 32`, `ARGON2_DEFAULT_SALT_LEN = 16`
  (each feature-gated).
- **`Error::Kdf(&'static str)`** variant for KDF-specific failures
  (HKDF output-length overflow, Argon2 parameter validation, PHC
  parse failures).
- **RFC 5869 known-answer tests** — Test Case 1 (full HKDF-SHA256
  with salt + info) and Test Case 3 (no salt, no info). Both pinned
  as byte arrays.
- **HKDF-SHA512 wrapper round-trip** — RFC 5869 only ships SHA-256
  / SHA-1 vectors, so for SHA-512 we cross-check the wrapper output
  against a direct call into the upstream `hkdf` crate. Catches any
  wrapper-level mistake without committing to a specific vector
  we'd have to maintain.
- **Argon2id functional tests** (with reduced parameters so the
  suite stays fast): round-trip hash/verify, wrong-password
  rejection, two-hashes-of-same-password-differ (salt randomness
  proof), unparseable-PHC rejection, tampered-PHC rejection,
  empty-password edge case, 1 KiB-password edge case, custom
  params honoured in the PHC string, default params match OWASP,
  invalid-params rejected, redaction-clean error rendering
  (passwords never appear in `Error` Display / Debug).

### Changed

- **Default features extended.** `default` now includes
  `kdf-argon2` in addition to `kdf-hkdf`. A fresh `cargo add
  crypt-io` ships with the full symmetric-crypto + KDF surface.
- **`lib.rs` module wiring.** The `kdf` module is exposed when
  either `kdf-hkdf` or `kdf-argon2` is enabled.

### Security

- **HKDF is not for passwords.** Module overview documents that
  HKDF expects high-entropy input keying material (a master key, a
  DH shared secret, a token). Feeding it a password is a security
  mistake — the module points callers at Argon2id for that case.
- **Argon2id defaults follow OWASP.** 19 MiB memory, 2 iterations,
  1 lane, 32-byte output — sized for ~100 ms per hash on a modern
  CPU. Reducing any parameter reduces resistance to brute force.
- **Salt is generated, not provided.** `argon2_hash` calls
  `mod_rand::tier3::fill_bytes` for every hash, so each PHC string
  carries a fresh random salt. Salt reuse cannot happen through
  the public API.
- **No password bytes in errors.** Verified by an explicit test
  that round-trips a known password through the unparseable-PHC
  failure path and asserts neither `Display` nor `Debug` rendering
  of the resulting `Error` contains the password.
- **PHC-string parse failures surface as `Error::Kdf`.** A
  correctly-formatted but wrong-password hash returns
  `Ok(false)`; only malformed inputs produce an error. The
  distinction matters because applications should log parse
  failures differently from authentication failures.

[RFC 5869]: https://datatracker.ietf.org/doc/html/rfc5869
[RFC 9106]: https://datatracker.ietf.org/doc/html/rfc9106
[`Error::Kdf`]: crate::Error
[0.6.0]: https://github.com/jamesgober/crypt-io/compare/v0.5.0...v0.6.0

---

## [0.5.0] - 2026-05-22

### Added

- **`crypt_io::mac` module** — three message-authentication-code
  algorithms with a consistent compute / verify / streaming
  surface:
  - **HMAC-SHA256** ([RFC 2104] + [RFC 4231] test vectors):
    - `mac::hmac_sha256(key, data) -> Result<[u8; 32]>` — one-shot.
    - `mac::hmac_sha256_verify(key, data, expected_tag) -> Result<bool>` —
      constant-time tag comparison via the upstream `hmac` crate's
      `verify_slice`.
    - `HmacSha256` streaming hasher (`new` → `update` → `finalize`
      or `verify`).
    - Feature: `mac-hmac` (default on).
  - **HMAC-SHA512**:
    - `mac::hmac_sha512(key, data) -> Result<[u8; 64]>` + matching
      `mac::hmac_sha512_verify(...)`.
    - `HmacSha512` streaming hasher.
    - Feature: `mac-hmac`.
  - **BLAKE3 keyed mode**:
    - `mac::blake3_keyed(key: &[u8; 32], data) -> [u8; 32]` —
      infallible (typed key, no runtime length check).
    - `mac::blake3_keyed_verify(...)` — constant-time tag comparison
      via BLAKE3's `Hash::eq` (the upstream crate documents this as
      constant time).
    - `Blake3Mac` streaming MAC.
    - Feature: `mac-blake3` (default on in 0.5.0+).
- **Output-length and key-length constants** in `crypt_io::mac`:
  `HMAC_SHA256_OUTPUT_LEN = 32`, `HMAC_SHA512_OUTPUT_LEN = 64`,
  `BLAKE3_MAC_OUTPUT_LEN = 32`, `BLAKE3_MAC_KEY_LEN = 32` (each
  feature-gated).
- **`Error::Mac(&'static str)`** variant for MAC construction
  failures. Unreachable in practice (HMAC accepts any key length;
  BLAKE3 keyed takes a typed `[u8; 32]`), but the variant exists
  because the upstream `Mac` trait surface is fallible by
  signature.
- **RFC 4231 known-answer tests**:
  - HMAC-SHA256 Test Case 1 (20-byte `0x0b` key, `"Hi There"`).
  - HMAC-SHA256 Test Case 2 (4-byte `"Jefe"` key, `"what do ya want..."`).
  - HMAC-SHA512 Test Case 1 and Test Case 2 (same key/data inputs).
- **BLAKE3 keyed KAT** — empty-input tag under the official 32-byte
  ASCII key `"whats the Elvish word for friend"`, pinned as a
  byte-array constant.
- **Verify-rejection tests** for every algorithm: wrong-tag,
  wrong-key, wrong-data, truncated-tag, oversized-tag (BLAKE3).
- **Streaming-equivalence tests** for every algorithm at multiple
  chunk boundaries.
- **Streaming-verify tests** for every algorithm (constant-time
  accept on match, reject on tamper).
- **Doctests** for every public entry point in the new module.

### Changed

- **Default features extended.** `default` now includes `mac-blake3`
  in addition to `mac-hmac`. A fresh `cargo add crypt-io` ships with
  all three MACs available. Drop `mac-blake3` if you want HMAC-only.
- **`lib.rs` module wiring.** The `mac` module is exposed when
  either `mac-hmac` or `mac-blake3` is enabled.

### Security

- **Constant-time verification is the only verification path.** The
  `*_verify` free functions and the streaming hashers' `verify`
  methods all use upstream constant-time comparators. The module
  documentation explicitly forbids `tag == expected` and points
  callers at the `verify` paths.
- **Hash-vs-MAC separation preserved.** Keyed-hash semantics live in
  this module; the `hash` module remains key-free. The `Blake3Hasher`
  in `hash` does **not** expose `with_key` — `Blake3Mac` in `mac`
  is the only way to produce a BLAKE3 keyed tag through this crate.
- **No raw key bytes in errors.** `Error::Mac` carries only a
  `&'static str` reason — never key material.
- **Tag-length variation is a rejection, not a panic.** All
  `*_verify` functions return `false` when `expected_tag` is the
  wrong length, rather than panicking on a length-mismatched compare.

[RFC 2104]: https://datatracker.ietf.org/doc/html/rfc2104
[RFC 4231]: https://datatracker.ietf.org/doc/html/rfc4231
[0.5.0]: https://github.com/jamesgober/crypt-io/compare/v0.4.0...v0.5.0

---

## [0.4.0] - 2026-05-22

### Added

- **`crypt_io::hash` module** — three cryptographic hash functions
  exposed through a consistent free-function API plus matching
  streaming hashers:
  - **BLAKE3** ([`blake3::hash`](https://github.com/BLAKE3-team/BLAKE3)):
    - `hash::blake3(data) -> [u8; 32]` — one-shot, 32-byte digest.
    - `hash::blake3_long(data, len) -> Vec<u8>` — one-shot, any
      output length via the extendable-output (XOF) mode.
    - `Blake3Hasher` — streaming, with `update` / `finalize` /
      `finalize_xof`.
    - Feature: `hash-blake3` (default on).
  - **SHA-256** (NIST FIPS 180-4):
    - `hash::sha256(data) -> [u8; 32]`.
    - `Sha256Hasher` — streaming, with `update` / `finalize`.
    - Feature: `hash-sha2` (default on).
  - **SHA-512** (NIST FIPS 180-4):
    - `hash::sha512(data) -> [u8; 64]`.
    - `Sha512Hasher` — streaming, with `update` / `finalize`.
    - Feature: `hash-sha2` (default on).
- **Output-length constants** in `crypt_io::hash`:
  `BLAKE3_OUTPUT_LEN = 32`, `SHA256_OUTPUT_LEN = 32`,
  `SHA512_OUTPUT_LEN = 64` (each feature-gated).
- **Known-answer tests** verifying byte-exact output against the
  spec references:
  - SHA-256: FIPS 180-4 B.1 (`abc`), B.2 (the 56-byte two-block
    input), empty-input.
  - SHA-512: FIPS 180-4 C.1 (`abc`), C.2 (the 112-byte two-block
    input), empty-input.
  - BLAKE3: empty-input + `"IETF"` against the upstream crate's
    output. Both pinned as byte-array constants so any future
    wrapper-level mistake (wrong endianness, wrong slicing) is
    caught immediately.
- **Streaming-equivalence tests** for every algorithm: feeding the
  same data in three different chunk boundaries to the streaming
  hasher produces a bit-identical digest to the one-shot path.
- **BLAKE3 XOF tests** verifying:
  - Output length always matches the requested `len`.
  - Output is deterministic in the input.
  - The first 32 bytes of an extended-output digest equal the
    default 32-byte digest of the same input.
- **Doctests** for the module overview, all six entry points, and
  both streaming-hasher constructors.

### Changed

- **Default features extended.** `default` now includes `hash-sha2`
  in addition to `hash-blake3`, so a fresh `cargo add crypt-io`
  ships with all three hash functions available. Drop
  `hash-sha2` if you want BLAKE3-only.
- **`lib.rs` module wiring.** The `hash` module is exposed when
  either `hash-blake3` or `hash-sha2` is enabled (or both).
- **`aead` module gate** widened to fire when either AEAD feature
  is enabled (was: only `aead-chacha20`); makes the module reachable
  in AES-only configurations.

### Security

- **No key/MAC surface.** This module is hash-only. Keyed BLAKE3 and
  HMAC-SHA2 live in the upcoming `crypt_io::mac` module (Phase
  0.5.0) where the authentication-tag semantics get their own,
  separate API. Using a raw hash function as a MAC is a security
  mistake; the absence of `with_key` on `Blake3Hasher` /
  `Sha256Hasher` / `Sha512Hasher` is deliberate.

[0.4.0]: https://github.com/jamesgober/crypt-io/compare/v0.3.0...v0.4.0

---

## [0.3.0] - 2026-05-21

### Added

- **`Algorithm::Aes256Gcm` variant** — AES-256-GCM ([NIST SP 800-38D])
  joins ChaCha20-Poly1305 as a peer in the `Algorithm` enum. Same
  32-byte key, same 12-byte nonce, same 16-byte tag, same wire
  layout (`nonce || ciphertext || tag`) — only the primitive
  changes. The enum is still `#[non_exhaustive]`.
- **`Crypt::aes_256_gcm()`** — feature-gated convenience constructor.
  Equivalent to `Crypt::with_algorithm(Algorithm::Aes256Gcm)`; the
  separate constructor makes call sites read like deliberate
  choices, which they should be.
- **AES-256-GCM dispatch path** in `Crypt::encrypt_with_aad` /
  `decrypt_with_aad`. When the `aead-aes-gcm` feature is enabled,
  selecting `Algorithm::Aes256Gcm` routes through the new
  `aes_gcm` backend module; when the feature is disabled, an
  `Error::AlgorithmNotEnabled("aead-aes-gcm")` is returned.
- **NIST GCM Test Cases 14 + 15 known-answer tests** verifying the
  upstream `aes-gcm` primitive produces the spec-mandated ciphertext
  and tag bytes for known inputs. Mirrors the RFC 8439 KAT shipped
  for ChaCha20-Poly1305 in 0.2.0.
- **AES-256-GCM end-to-end tests** through the `Crypt` surface:
  algorithm metadata, constructor, round-trip (empty / short /
  1 MiB), nonce-uniqueness, wrong-key, body tamper, tag tamper,
  truncation rejection, AAD round-trip, AAD mismatch, invalid key
  length. 13 new `Crypt`-level tests.
- **Cross-algorithm integration tests** (active when both
  `aead-chacha20` and `aead-aes-gcm` features are enabled):
  - Ciphertext from one algorithm fails authentication when
    decrypted with the other.
  - `Algorithm::name()` values are distinct across all shipped
    variants.
- **Public constants** `AES_GCM_NONCE_LEN = 12` and
  `AES_GCM_TAG_LEN = 16` in `crypt_io::aead` for callers
  pre-sizing buffers without conditional compilation.

### Changed

- **Default features extended.** The crate's default feature set now
  includes `aead-aes-gcm` so a vanilla `cargo add crypt-io` ships
  with both AEADs available. Drop the default and select
  `["std", "zeroize", "aead-chacha20", "hash-blake3", "mac-hmac", "kdf-hkdf"]`
  if you want the 0.2.0 surface (ChaCha20-Poly1305 only).
- **`Algorithm` accessors** (`name`, `key_len`, `nonce_len`,
  `tag_len`) now handle the new `Aes256Gcm` variant. Behaviour for
  `ChaCha20Poly1305` is unchanged.
- **`aead/mod.rs` doc-comment header** updated to introduce both
  algorithms and document the "when to pick which" decision tree
  (ChaCha20 is the default; AES-256-GCM is the deliberate choice
  for AES-NI hardware or for spec interop).
- **`clippy.toml` `doc-valid-idents` whitelist** extended with
  `ARMv8`, `AArch64`, `CLMUL`, `Graviton`, `GHASH`, `JWE`,
  `A256GCM`, `x86_64`, `Silicon`, `SoCs`. These appear in the new
  AES-GCM doc comments and need to be on the whitelist so pedantic
  `clippy::doc_markdown` doesn't trip them.

### Security

- **`AuthenticationFailed` opacity preserved across algorithms.**
  AES-256-GCM and ChaCha20-Poly1305 both surface every cryptographic
  failure mode (wrong key, tampered ciphertext, tampered tag, AAD
  mismatch) as the single `Error::AuthenticationFailed` variant.
  Switching algorithms does not change the error-classification
  surface an attacker can observe.
- **Constant-time tag verification** preserved by deferring to the
  upstream `aes-gcm` crate — no equality comparisons on tag bytes
  in this wrapper.
- **Nonce policy is per-call**, identical to the ChaCha20 path. AES-GCM
  is *especially* sensitive to nonce reuse — repeating a `(key,
  nonce)` pair leaks the XOR of the two plaintexts and the GHASH
  authentication key, which is catastrophic. This API draws a fresh
  nonce from `mod-rand::tier3::fill_bytes` for every encrypt call,
  so the failure mode cannot happen through the public surface.
- **No bytes in errors.** `aes_gcm.rs` follows the same redaction
  contract as `chacha20.rs`: no plaintext, ciphertext, nonces, or
  key material appears in any `Error` variant.

[NIST SP 800-38D]: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
[0.3.0]: https://github.com/jamesgober/crypt-io/compare/v0.2.0...v0.3.0

---

## [0.2.0] - 2026-05-21

### Added

- **AEAD foundation — ChaCha20-Poly1305 (RFC 8439).** First working
  encryption layer for the crate:
  - `Algorithm` enum (`#[non_exhaustive]`) — currently `ChaCha20Poly1305`.
    `Default` selects ChaCha20-Poly1305. The enum exposes `name()`,
    `key_len()`, `nonce_len()`, and `tag_len()` accessors.
  - `Crypt` struct — algorithm-agile encryption handle.
    `Crypt::new()` defaults to ChaCha20-Poly1305;
    `Crypt::with_algorithm(Algorithm)` for explicit selection.
  - `Crypt::encrypt(key, plaintext) -> Vec<u8>` and
    `Crypt::decrypt(key, ciphertext) -> Vec<u8>` — round-trip AEAD
    with nonce-prepended wire layout `nonce || ciphertext || tag`.
  - `Crypt::encrypt_with_aad(key, plaintext, aad)` and
    `Crypt::decrypt_with_aad(key, ciphertext, aad)` — variants that
    authenticate associated data.
  - Public constants `CHACHA20_NONCE_LEN = 12`,
    `CHACHA20_TAG_LEN = 16`, `KEY_LEN = 32` (in `crypt_io::aead`).
- **`Error` enum + `Result` type alias** with `Display` + `Error`
  impls. Variants: `InvalidKey { expected, actual }`,
  `InvalidCiphertext(String)`, `AuthenticationFailed`,
  `AlgorithmNotEnabled(&'static str)`, `RandomFailure(&'static str)`.
  `#[non_exhaustive]` — match sites need a wildcard arm. All
  variants are redaction-clean by design: no key bytes, no
  plaintext, no nonces, no ciphertext are ever included in error
  rendering.
- **RFC 8439 §2.8.2 known-answer test** verifying the upstream
  primitive integration is byte-exact against the official vector.
- **Round-trip + tamper-detection + AAD-mismatch test suite.**
  Unit-test coverage for: empty plaintext, 1 MiB plaintext,
  wrong-key authentication failure, tampered ciphertext rejection,
  tampered tag rejection, truncated-buffer rejection, AAD round-trip,
  AAD-mismatch rejection, encrypt-with-aad / decrypt-without-aad
  rejection, invalid key length rejection on both sides.
- **Doctests** for `crypt_io::Crypt::encrypt`,
  `crypt_io::Crypt::decrypt`, and the `aead` module overview.
- **Nonce generation via `mod-rand` Tier 3** (OS-backed CSPRNG —
  `getrandom` on Linux, `getentropy` on macOS, `BCryptGenRandom`
  on Windows).

### Changed

- **MSRV bumped from 1.75 to 1.85** to match the existing
  `edition = "2024"` declaration in `Cargo.toml`. Cargo ≥ 1.84
  refuses to parse the previous combination. CI matrix updated.
- **`src/lib.rs` lint block** extended to the REPS canonical set:
  adds `#![deny(clippy::unreachable)]`, `#![warn(clippy::pedantic)]`,
  and `#![allow(clippy::module_name_repetitions)]`. `extern crate
  alloc;` declared to support the `no_std` build path.
- **`clippy.toml` MSRV synced to 1.85** and `doc-valid-idents`
  whitelist added covering domain terms (`RustCrypto`, `BLAKE3`,
  `ChaCha20`, `Poly1305`, `AES-NI`, etc.).
- Crate skeleton expanded to `src/aead/`, `src/aead/chacha20.rs`,
  `src/error.rs`.

### Security

- **Authentication failures collapse to a single opaque variant.**
  `Error::AuthenticationFailed` is returned for wrong-key,
  tampered-ciphertext, tampered-tag, AAD-mismatch, and truncated-tag
  inputs. The variant is deliberately not subtype-discriminated:
  exposing which mode failed would tell an attacker how close they
  are to a successful forgery.
- **Constant-time tag verification** is preserved by deferring to
  the upstream `chacha20poly1305` crate — no equality comparisons
  on tag bytes happen in this wrapper.
- **No raw key bytes in errors.** `Error::InvalidKey` carries only
  the expected vs. actual *lengths*, never the bytes themselves.
- **Fresh nonce per call** — `mod-rand` Tier 3 fills a new 12-byte
  buffer for every `encrypt` / `encrypt_with_aad`. Nonce reuse on
  the same key cannot happen via this API.

[0.2.0]: https://github.com/jamesgober/crypt-io/compare/v0.1.0...v0.2.0

---

## [0.1.0] - 2026-05-18

### Added

- Initial scaffold and repository bootstrap.
- REPS compliance baseline.
- CI for Linux/macOS/Windows on stable and MSRV (1.75).
- Project documentation framework (PROMPT, DIRECTIVES, ROADMAP).
- Feature flags for AEAD (chacha20, aes-gcm), hashing (blake3, sha2), MAC (hmac, blake3 keyed), KDF (hkdf, argon2), stream encryption.
- Dependencies wired: `mod-rand` for CSPRNG, `error-forge` for errors, optional `log-io` and `metrics-lib`.

[Unreleased]: https://github.com/jamesgober/crypt-io/compare/v0.9.0...HEAD
[0.1.0]: https://github.com/jamesgober/crypt-io/releases/tag/v0.1.0