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

[Unreleased]: https://github.com/jamesgober/crypt-io/compare/v0.5.0...HEAD
[0.1.0]: https://github.com/jamesgober/crypt-io/releases/tag/v0.1.0