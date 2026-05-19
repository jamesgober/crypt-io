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

## [0.1.0] - 2026-05-18

### Added

- Initial scaffold and repository bootstrap.
- REPS compliance baseline.
- CI for Linux/macOS/Windows on stable and MSRV (1.75).
- Project documentation framework (PROMPT, DIRECTIVES, ROADMAP).
- Feature flags for AEAD (chacha20, aes-gcm), hashing (blake3, sha2), MAC (hmac, blake3 keyed), KDF (hkdf, argon2), stream encryption.
- Dependencies wired: `mod-rand` for CSPRNG, `error-forge` for errors, optional `log-io` and `metrics-lib`.

[Unreleased]: https://github.com/jamesgober/crypt-io/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/jamesgober/crypt-io/releases/tag/v0.1.0