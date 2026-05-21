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

[Unreleased]: https://github.com/jamesgober/crypt-io/compare/v0.2.0...HEAD
[0.1.0]: https://github.com/jamesgober/crypt-io/releases/tag/v0.1.0