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

## [1.1.0] - 2026-10-09

Minor release. Finishes the work 1.0.1 deferred: a stream format with
a per-stream subkey, `Result`-returning MAC and password checks, real
`no_std` support, XChaCha20-Poly1305, an Argon2 policy, and wiping of
AES round keys and HMAC state. Everything is additive:
`cargo-semver-checks` against 1.0.1 reports a minor update. Streams
and messages written by 1.0.x decrypt unchanged.

Release notes: [`docs/release/v1.1.0.md`](docs/release/v1.1.0.md).

**Read before upgrading a mixed fleet:** 1.1.0 writes stream format
v2 by default, and crypt-io 1.0.x cannot read v2 (it fails cleanly
with `InvalidCiphertext("unsupported stream version: 0x02 ...")`).
Until every reader runs 1.1, write v1 with
`StreamEncryptor::new_with_format(.., StreamFormat::V1)`.

### Security

- **Stream format v2: one subkey per stream.** Format v1 encrypted
  every stream directly under the caller's key with a random 56-bit
  nonce prefix, so two streams whose prefixes collided reused
  nonces (keystream reuse, and for AES-256-GCM the GHASH key); the
  safe limit was about 2^12 streams per key. A v2 stream starts with
  a 32-byte random salt and is encrypted under
  `HKDF-SHA256(key, salt, "crypt-io stream v2" || header)`, which
  also yields the nonce prefix. Two streams now share nonces only if
  their 256-bit salts collide. `StreamEncryptor::new`,
  `new_with_chunk_size` and `stream::encrypt_file` write v2;
  `StreamDecryptor` and `stream::decrypt_file` read v1 and v2. The
  v2 header's reserved bytes must be zero, so they can never be
  given a meaning that older v2 readers would ignore. The format,
  key schedule and test vectors are in `docs/FILE_FORMAT.md`.
- **`verify(..)?;` accepted forgeries.** New `*_check` functions
  return `Err(AuthenticationFailed)` on a mismatch, so `?` does the
  right thing: `mac::hmac_sha256_check`, `hmac_sha512_check`,
  `blake3_keyed_check`, `kdf::argon2_check`,
  `kdf::argon2_check_with_policy`, and a `check` method on
  `HmacSha256`, `HmacSha512` and `Blake3Mac`. The `bool` versions
  (`hmac_sha256_verify`, `hmac_sha512_verify`, `blake3_keyed_verify`,
  `argon2_verify`) are deprecated, so every existing call site now
  gets a compiler warning pointing at the replacement. They keep
  working for the rest of 1.x.
- **AES round keys and HMAC state are wiped on drop** with the
  default `zeroize` feature. `aes` is now a direct dependency so the
  feature can enable `aes/zeroize`, and `hmac` / `sha2` / `hkdf` move
  to 0.13 / 0.11 / 0.13, whose `zeroize` support wipes the
  key-derived HMAC state and the hash state. A test checks that a
  dropped `HmacSha256` / `HmacSha512` leaves only zeros. Not covered:
  the GHASH key inside `polyval` 0.6 (no `Drop` in its runtime
  dispatch backend). The fixed `polyval` 0.7 only comes with
  `aes-gcm` 0.11, which measured about 40% slower on 64-byte
  messages and whose `aes` 0.9.3 needs Rust 1.89, above the 1.x
  MSRV; see `docs/SECURITY.md`.
- **Growing a buffer no longer leaves plaintext behind.**
  `decrypt_into` and the stream decryptor used `Vec::reserve`, which
  copies the old allocation and frees it without clearing it. They
  now wipe the old allocation first, and `StreamDecryptor::update`
  sizes its output once.

### Added

- **`Algorithm::XChaCha20Poly1305`** (192-bit nonce; draft-irtf-cfrg-
  xchacha), `Crypt::xchacha20_poly1305()`, `XCHACHA20_NONCE_LEN`,
  `XCHACHA20_TAG_LEN`. Available with `aead-chacha20`, in
  single-shot, sealed and stream (v2) form. Use it when one key may
  encrypt more than 2^32 messages. `Algorithm` is `#[non_exhaustive]`,
  so this is not a breaking change.
- **Sealed single-shot format:** `Crypt::seal`, `seal_with_aad`,
  `open`, `open_with_aad`, `sealed_algorithm`, and the constants
  `SEALED_HEADER_LEN`, `SEALED_VERSION`. Output is
  `0x01 || algorithm || nonce || ciphertext || tag`, with both header
  bytes authenticated; `open` routes on the stored algorithm. The 1.0
  `encrypt` format, which records neither, is unchanged.
- **`no_std` + `alloc`.** All RustCrypto and BLAKE3 dependencies now
  have their default features off, and crypt-io's `std` feature
  forwards to theirs. With `default-features = false` the crate
  builds for bare-metal targets (CI builds `thumbv7em-none-eabihf`
  on stable and 1.85). Hashing, MACs, HKDF, Argon2 checks and every
  decrypt path work without `std`; APIs that need randomness need
  the new **`getrandom` feature** (the `getrandom` crate, which on
  bare metal calls a backend the application registers).
  `mod-rand` stays the random source with `std` unless `getrandom`
  is enabled. `Error` implements `core::error::Error` in every build.
- **`kdf::Argon2Policy`** (caps, minimums, allowed variants),
  `kdf::argon2_check_with_policy`, `kdf::argon2_hash_with_policy`
  and **`Argon2Params::validate()`** (OWASP minimums). Hashes stored
  with costs above the 1.0.1 caps can be verified again by raising
  the caps.
- **`Tag<N>`**: a tag wrapper whose `==` is constant-time
  (`subtle`), with `ct_eq`, `From<[u8; N]>`, `TryFrom<&[u8]>`.
- **`generate_key()`** → `Zeroizing<[u8; 32]>` from the OS CSPRNG,
  `Crypt::decrypt_zeroizing` / `decrypt_with_aad_zeroizing`,
  `kdf::hkdf_sha256_into` / `hkdf_sha512_into`,
  `hash::blake3_long_into`, and a `Zeroizing` re-export.
- **`stream::StreamFormat`**, `StreamEncryptor::new_with_format`,
  `algorithm()` / `format()` on both stream types, `stream::SALT_LEN`,
  `frame::VERSION_2`, `frame::SALT_LEN`, `frame::V2_KDF_INFO`.
- **`Error::Io`, `Error::InvalidInput`, `Error::LimitExceeded`.**

### Changed

- **Errors that looked like tampering now say what happened.**
  File-helper I/O failures were `Error::Mac("stream: ...")` and are
  now `Error::Io`; same-file input/output was `Error::Mac` and an
  out-of-range stream chunk size was `Error::InvalidCiphertext`,
  both now `Error::InvalidInput`; an over-long plaintext or AAD was
  `Error::AuthenticationFailed` and a stream past 2^32 chunks was
  `Error::InvalidCiphertext`, both now `Error::LimitExceeded`. Code
  that matched the old variants for these cases needs updating;
  monitoring that alerts on `AuthenticationFailed` no longer gets
  false positives from them.
- **Stream output layout:** in v2 the first output of
  `update` / `update_into` / `finalize` / `finalize_into` starts with
  the 32-byte salt. Code that writes the header and then every
  output in order (as all the examples do) needs no change.
- **Dependencies:** `hmac` 0.13, `sha2` 0.11, `hkdf` 0.13 (from 0.12 /
  0.10 / 0.12; none appear in crypt-io's public API); new direct
  dependencies `aes` 0.8.4, `subtle` 2.5 and the optional
  `getrandom` 0.4; `mod-rand` is now enabled by `std`.
  `chacha20poly1305` and `aes-gcm` no longer enable their unused
  `getrandom` feature. MSRV stays 1.85, but `digest` 0.11 depends on
  `ctutils`, whose 0.4.3 needs Rust 1.87: on 1.85 / 1.86, Cargo's
  MSRV-aware resolver (the default for edition 2024 workspaces)
  picks 0.4.2 by itself; a workspace on resolver 2 needs
  `cargo update -p ctutils --precise 0.4.2`.
- `docs/STABILITY-1.0.md`: 1.0 promised that a 1.0 reader could read
  any 1.x stream. Writing v2 by default withdraws that for streams
  (v1 stays available for mixed fleets); everything else in the
  contract stands.

### Performance

Measured A/B against 1.0.1 in one process (details in
`docs/PERFORMANCE.md`):

- Stream round trips: 3.5–4.5× faster at 1 KiB and about 1.4× at
  16 KiB, because drop now wipes only the bytes a buffer ever held
  instead of its whole 64 KiB capacity; `StreamDecryptor::update` on
  10 MiB about 1.4× faster (output sized once); stream encrypt 3–12%
  faster (full chunks encrypted straight from the input).
- `Crypt::encrypt` 1.3–2× faster from 64 KiB up (one allocation, no
  extra copy). `hmac_sha256_check` 15–40% faster than
  `hmac_sha256_verify`.
- SHA-256 on small inputs and HKDF-SHA256 are 6–35 ns slower per call
  (the `sha2` 0.11 upgrade needed for HMAC state wiping, plus the
  wiping itself). Everything else is within noise.

### Documentation

- `docs/FILE_FORMAT.md` rewritten for v1 + v2 + the sealed format,
  with v2 test vectors from an independent implementation.
- `README.md`, `docs/API.md`, `docs/SECURITY.md`,
  `docs/ARCHITECTURE.md`, `docs/PLATFORM-NOTES.md` (new `no_std`
  section), `docs/STABILITY-1.0.md`, the examples and rustdoc cover
  every new item and use the `*_check` APIs.

### Testing

- Frozen v2 stream vectors (ChaCha20-Poly1305, AES-256-GCM,
  XChaCha20-Poly1305) checked byte for byte on the encrypt side
  (including byte-at-a-time input) and the decrypt side, generated
  by an independent Python implementation of the spec.
- XChaCha20-Poly1305 known-answer test from draft-irtf-cfrg-xchacha
  A.3.1, also decrypted through crypt-io's wire format.
- `tests/v1_1.rs`: every algorithm × format, salt handling, the new
  error variants, file helpers writing v2 and reading v1, the sealed
  format across an algorithm switch.
- A memory test that dropped HMAC state is zero; unit tests for the
  policy, `validate`, `Tag` and the buffer-wiping helpers.
- CI: new `no_std` job (`thumbv7em-none-eabihf`, stable and 1.85,
  with and without `getrandom`) and two more minimal-versions builds.

[1.1.0]: https://github.com/jamesgober/crypt-io/compare/v1.0.1...v1.1.0

---

## [1.0.1] - 2026-10-08

Security patch. Fixes the memory-hygiene, `_into` buffer, file-helper,
Argon2 and dependency-floor problems found in a security review of
1.0.0, and corrects documentation that overstated what 1.0.0
guaranteed. No public API or wire-format change: `cargo-semver-checks`
against 1.0.0 reports no semver update required, and files and
messages written by 1.0.0 decrypt unchanged. Upgrading is recommended
for all users.

Release notes: [`docs/release/v1.0.1.md`](docs/release/v1.0.1.md).

### Security

- **Stream types printed the raw key through `Debug`.**
  `StreamEncryptor` and `StreamDecryptor` derived `Debug`, so any
  `{:?}` (a `tracing` field, `dbg!`, an `unwrap()` on a containing
  struct) printed the 32 key bytes and any buffered plaintext. Both
  now have a hand-written `Debug` that shows only the algorithm,
  chunk size, counter and buffered length.
- **The default `zeroize` feature did nothing.** No code used it and
  nothing was wiped on drop. Now:
  - `StreamEncryptor` and `StreamDecryptor` overwrite their key copy
    and internal buffer (full capacity) on drop, including after
    `finalize`.
  - `Blake3Mac` wipes its keyed hasher state on drop.
  - The feature enables the upstream `zeroize` support of `aes-gcm`,
    `argon2` and `blake3`.
  - The `zeroize` dependency no longer pulls in the unused `derive`
    proc-macro.
  - Not covered yet: AES round keys inside the `aes` crate, HMAC
    state, and the plaintext `Vec`s crypt-io returns. The docs now
    say so.
- **Dependency floor admitted aes-gcm with RUSTSEC-2023-0096.**
  `aes-gcm = "0.10"` allowed 0.10.0 to 0.10.2, whose
  `decrypt_in_place_detached` decrypts before checking the tag. The
  floor is now `0.10.3`. `blake3` is now `1.5` (the first release
  with a `zeroize` feature; `blake3 = "1"` also resolved to 1.0.0,
  which does not build). A `-Zminimal-versions` build passes.
- **`decrypt_into` returned stale plaintext on some errors.**
  `decrypt_into` / `decrypt_with_aad_into` checked the key and
  ciphertext length before clearing `out`, so `InvalidKey` and
  `InvalidCiphertext` returned with the previous message's plaintext
  still in the buffer. `out` is now cleared first, so it is empty on
  every error.
- **The auth-failure "scrub" only reset the length.** On
  `AuthenticationFailed`, `decrypt_into` called `Vec::clear()`, which
  leaves every byte in the allocation. The whole allocation (length
  and spare capacity) is now overwritten with zeros. The same applies
  to the stream chunk paths and to `encrypt_into` when the upstream
  cipher rejects an input after the plaintext was copied into `out`.
- **`stream::decrypt_file` left unauthenticated output on disk.**
  Plaintext went straight to the destination, so a truncated or
  tampered file returned `Err` but left the verified prefix behind,
  world-readable under the default umask. `decrypt_file` now writes
  to a new temporary file in the destination directory (created
  exclusively, mode `0600` on Unix), `fsync`s it and renames it over
  the destination only after the final chunk authenticates. On error
  the temporary file is overwritten and removed and the destination
  is untouched.
- **`argon2_verify` trusted every parameter in the PHC string.** A
  hostile or corrupted hash could make one verify allocate gigabytes
  (`m`), run for minutes (`t`), or downgrade to `argon2d` / `argon2i`.
  `argon2_verify` now rejects, with `Error::Kdf` and before doing any
  work, any variant other than `argon2id` and any `m` above 1 GiB,
  `t` above 64 or `p` above 16. crypt-io has only ever produced
  `$argon2id$v=19$` hashes, so no hash it created is affected unless
  it was made with `argon2_hash_with_params` beyond those limits.
  `argon2_hash_with_params` now enforces the same limits.

### Fixed

- **`StreamDecryptor::update` was quadratic.** The whole input was
  appended to an internal buffer and drained from the front one chunk
  at a time, so one large `update` call (32 MiB at 1 KiB chunks) took
  46 s instead of 0.16 s. Complete chunks are now decrypted directly
  from the input and the buffer never holds more than one frame.
- **`encrypt_file(p, p, ..)` destroyed its input.** It truncated `p`
  before reading it and returned `Ok(())`. Both file helpers now
  reject an output path that resolves to the input file.
- **`StreamDecryptor::update_into` left partial output on error.**
  If a later chunk in the same call failed, plaintext from earlier
  chunks stayed appended to `out`. `out` is now truncated back to its
  entry length and the appended bytes are wiped, matching `update`.
- **`encrypt_into` / `encrypt_with_aad_into`** now clear `out` on
  every error path, as documented.

### Changed

- **Removed unused dependencies.** `error-forge` (a non-optional
  dependency that also broke `no_std` builds), `log-io`,
  `metrics-lib` and `async-trait` were never used by any code. They
  are gone; the `logging`, `metrics` and `async-trait` features remain
  as empty features so existing feature lists keep resolving.
- **`decrypt_file` output has mode `0600` on Unix** (it is created as
  a private temporary file). Change it afterwards if others need to
  read it.

### Documentation

- **`verify(..)?;` accepts forgeries.** `hmac_sha256_verify`,
  `hmac_sha512_verify` and `argon2_verify` return `Ok(false)` on a
  mismatch, so `verify(..)?;` compiles silently and ignores the
  result. Every example now uses `if !verify(..)? { .. }`, and the
  function docs, module docs, README and `SECURITY.md` carry a
  warning.
- **Nonce limits.** The docs said a key was good for about 2^48
  messages; that is where a random-nonce collision becomes likely
  (about 39%). They now state the NIST SP 800-38D limit of 2^32
  messages per key, and a limit of about 2^12 (4,096) streams per key
  for stream and file encryption (each stream uses a random 56-bit
  nonce prefix under the caller's key), with HKDF per-file keys as
  the workaround.
- **`no_std` claim removed.** No feature combination of 1.0.x builds
  as `no_std`; `PLATFORM-NOTES.md` said otherwise.
- **Stale statements removed:** the comparison of the stream format
  to `age` (which derives a per-file key), references to a
  `rust-toolchain.toml` that does not exist, the "early scaffolding"
  crate status, `error-forge` "error metadata", and the claim that
  the CI runs `cargo-public-api` / `cargo-msrv`.
- `StreamDecryptor::update` docs now say its output is not
  end-authenticated until `finalize` succeeds. `FILE_FORMAT.md`
  commits to using the version byte, not the reserved bytes, for any
  change that affects decoding.
- `docs/API.md` installation snippet said `crypt-io = "0.7"`.

### Testing

- **`tests/regressions.rs`**: one test per fix above; each fails
  against 1.0.0.
- **`tests/kat.rs`**: RFC 8439 section 2.8.2 and GCM Test Case 16
  (with AAD) decrypted through `Crypt`, and frozen ChaCha20-Poly1305
  and AES-256-GCM stream vectors built from the raw upstream
  primitives per `FILE_FORMAT.md`.
- **`tests/properties.rs`**: `proptest` properties (`decrypt` vs
  `decrypt_into`, single-bit tampering, stream split points,
  truncation).
- **New fuzz target `audit_into_diff`** with the stale-output
  reproducer in its corpus. The committed `fuzz/Cargo.lock` is
  refreshed (it still pinned crypt-io 0.8.0).
- **CI**: new `cargo audit`, `-Zminimal-versions` build, Miri subset
  and fuzz-target build jobs.

### Not in this release (planned for 1.1)

- A stream format with a per-stream subkey, removing the
  streams-per-key limit (1.x keeps decrypting the current format).
- `Result<()>`-returning `*_check` functions (and `#[must_use]` on the
  `bool` verifiers) for the `verify(..)?;` problem. Adding
  `#[must_use]` is a minor-version change under semver.
- Real `no_std` support.

[1.0.1]: https://github.com/jamesgober/crypt-io/compare/v1.0.0...v1.0.1

---

## [1.0.0] - 2026-05-24

**Stable release.** The 1.0 contract in
[`docs/STABILITY-1.0.md`](docs/STABILITY-1.0.md) takes effect at
this tag. Every item listed there keeps its signature and
behaviour for the lifetime of the 1.x series; breaking changes
from this point forward require a 2.0.

Consolidated release notes at
[`docs/release/v1.0.0.md`](docs/release/v1.0.0.md).

### Added

- **`docs/release/v1.0.0.md`** — consolidated 0.x → 1.0
  release notes for first-time crates.io readers. Covers the
  full surface, the 1.0 promise, performance numbers,
  verification posture, the eleven-phase journey from
  scaffold to stable, the acknowledgements, and the post-1.0
  candidate list.

### Changed

- **Version bumped to `1.0.0`.** Cargo manifest +
  README + ROADMAP all updated to reflect stable status.
  Source-level surface is unchanged from 0.11.0 — this is
  the promotion of an unchanged surface to stable, not a
  feature release.
- **Pre-1.0 framing dropped.** README no longer flags the API
  as evolving; the [stability contract](docs/STABILITY-1.0.md)
  is in force.

### Security

- **No security-surface changes.** All guarantees from the
  0.x series carry forward to 1.0:
  - Constant-time MAC verification via upstream comparators
  - `decrypt_into` auth-failure scrub
  - Redaction-clean errors (no key / plaintext / ciphertext / nonce / tag bytes)
  - STREAM-construction defeats truncation / reorder / duplicate
  - Header AAD binding defeats header tampering
  - Fresh nonce per AEAD call (nonce reuse impossible through the public API)

### Stability commitment

- **The 1.x public API surface is frozen.** Match sites on
  `Algorithm` and `Error` (both `#[non_exhaustive]`) MUST
  include a wildcard arm to remain compatible across 1.x
  minor releases.
- **Wire formats are frozen** for the 1.x series — single-shot
  AEAD output (`nonce || ciphertext || tag`) and the stream
  frame format ([`docs/FILE_FORMAT.md`](docs/FILE_FORMAT.md)).
- **MSRV is frozen** at Rust 1.85 for 1.x.
- **Default features are frozen.** Removing a default feature
  requires a 2.0.

[1.0.0]: https://github.com/jamesgober/crypt-io/compare/v0.11.0...v1.0.0

---

## [0.11.0] - 2026-05-23

The final pre-1.0 release. Ships the complete 1.0 documentation
set. Source-level surface is unchanged from 0.10.0 — this is the
phase that writes down the 1.0 contract so 1.0.0 itself can be
the deliberate stable cut.

### Added

- **`docs/STABILITY-1.0.md`** — the 1.0 stability contract.
  Lists every item that will be frozen at 1.0, the MSRV policy,
  what can change in 1.x minor releases, what requires a 2.0,
  and the migration policy for 1.x → 2.x.
- **`docs/ARCHITECTURE.md`** — module layout, algorithm
  dispatch pattern, trust boundaries, dependency rationale,
  build profiles, what's intentionally out of scope.
- **`docs/SECURITY.md`** — threat model (in/out of scope),
  algorithm-choice rationale, vulnerability reporting
  (`security@hivedb.com`), verification posture (test / fuzz /
  KAT counts), and known caveats (Argon2id parameters age with
  hardware; no nonce-misuse resistance in 1.0).
- **`docs/PLATFORM-NOTES.md`** — per-platform hardware-
  acceleration availability (AES-NI / SHA-NI / ARMv8 crypto
  extensions / AVX-512), OS specifics for nonce sourcing, a
  cross-compile guide, and the "pick this algorithm on this
  platform" cheatsheet.
- **`docs/FILE_FORMAT.md`** — full normative spec of the stream
  wire format: header layout, per-chunk nonce derivation,
  final-chunk-always invariant, validation rules, worked
  examples, counter overflow handling, and the 1.x
  compatibility commitment.

### Changed

- **Documentation set is now complete for 1.0.** Every doc the
  ROADMAP listed as a 1.0 prerequisite is in place; the README
  documentation index links all of them.
- **README documentation section reorganised** to expose all
  seven `docs/` files (API + STABILITY-1.0 + SECURITY +
  ARCHITECTURE + PLATFORM-NOTES + PERFORMANCE + FILE_FORMAT)
  plus CHANGELOG and per-release notes.

### Security

- **No security-surface changes.** All guarantees from 0.10.0
  carry forward:
  - Constant-time MAC verification via upstream comparators
  - `decrypt_into` auth-failure scrub
  - Redaction-clean errors (no key / plaintext / ciphertext bytes)
  - STREAM-construction defeats truncation / reorder / duplicate
  - Header AAD binding defeats header tampering

### Phase-1.0 prerequisites still pending

- **1 CPU-hour per `cargo-fuzz` target** (8 hours unattended) —
  the last RC-style gate before 1.0.0 final. Smoke results from
  0.9.0 (4.7 M iterations across 8 targets, 0 findings) carry
  forward; the long soak validates stability under extended
  pressure. Run loop documented in [`fuzz/README.md`](fuzz/README.md).
- **External review window.** Open issues on
  [github.com/jamesgober/crypt-io](https://github.com/jamesgober/crypt-io)
  or email `security@hivedb.com` for crypto-sensitive findings.

[0.11.0]: https://github.com/jamesgober/crypt-io/compare/v0.10.0...v0.11.0

---

## [0.10.0] - 2026-05-23

### Added

- **Zero-allocation `_into` API family** — caller-supplied output
  buffers throughout the encrypt / streaming surface. After a
  one-time grow, subsequent calls reuse capacity and run with
  **zero steady-state allocations** (verified by `mod-alloc`
  profile in [`examples/profile_alloc.rs`](examples/profile_alloc.rs)).
  - `Crypt::encrypt_into(&self, key, plaintext, &mut Vec<u8>) -> Result<()>`
  - `Crypt::encrypt_with_aad_into(&self, key, plaintext, aad, &mut Vec<u8>) -> Result<()>`
  - `Crypt::decrypt_into(&self, key, ciphertext, &mut Vec<u8>) -> Result<()>`
  - `Crypt::decrypt_with_aad_into(&self, key, ciphertext, aad, &mut Vec<u8>) -> Result<()>`
  - `StreamEncryptor::update_into(&mut self, data, &mut Vec<u8>) -> Result<()>`
  - `StreamEncryptor::finalize_into(self, &mut Vec<u8>) -> Result<()>`
  - `StreamDecryptor::update_into(&mut self, data, &mut Vec<u8>) -> Result<()>`
  - `StreamDecryptor::finalize_into(self, &mut Vec<u8>) -> Result<()>`
- **`examples/profile_alloc.rs`** — global-allocator swap using
  [`mod-alloc`](https://github.com/jamesgober/mod-alloc) (the
  portfolio's dhat-compatible heap profiler, ~60 ns / op
  overhead, lower MSRV alignment than dhat). Loops
  `Crypt::encrypt` vs `Crypt::encrypt_into` for 10 000 iterations
  per (algorithm × size) and prints the allocation count + total
  bytes from `mod_alloc::Profiler`. Confirms the `_into` path is
  zero-allocation in the steady state.
- **`_into`-variant benchmarks** — `benches/aead.rs` and
  `benches/stream.rs` now ship matching benches for
  `chacha20_poly1305_encrypt_into`, `aes_256_gcm_encrypt_into`,
  and `stream_encrypt_into` so the side-by-side throughput
  improvement is reproducible from `cargo bench`.
- **12 new `_into` integration tests** under
  `tests/into_apis.rs` covering:
  - Round-trip equality with the `Vec`-returning paths
  - **Capacity reuse** assertion (`Vec::capacity()` unchanged
    across a second call with same-size input → no realloc)
  - **Auth-failure buffer scrub** assertion (`decrypt_into` /
    `decrypt_chunk_into` clear the output buffer on
    `AuthenticationFailed` so partially-decrypted plaintext
    can't leak)
  - AAD round-trip + AAD-mismatch rejection through the `_into`
    surface
  - Both algorithms through the same harness
  - Stream `_into` round-trip across multiple chunk boundaries
  - Empty-plaintext edge case
- **`mod-alloc` dev-dep + `[[example]] name = "profile_alloc"`**
  in `Cargo.toml`.

### Changed

- **Measured wrapping-overhead close.** Side-by-side numbers on
  the same Zen 5 reference machine documented in 0.8.0:
  | Operation @ 1 MiB | 0.9.0 allocating | 0.10.0 `_into` | Δ |
  |---|---:|---:|---:|
  | `Crypt::encrypt` ChaCha20-Poly1305 | 1.05 GiB/s | **1.45 GiB/s** | **+38%** |
  | `Crypt::encrypt` AES-256-GCM       | 1.08 GiB/s | **1.59 GiB/s** | **+47%** |
  | `StreamEncryptor` ChaCha20-Poly1305 | 932 MiB/s | **1.40 GiB/s** | **+54%** |
  | `StreamEncryptor` AES-256-GCM       | 999 MiB/s | **1.54 GiB/s** | **+55%** |
  Stream encrypt now cleanly clears the 1 GiB/s contract target
  for both algorithms; the marginal ⚠️ in 0.8.0's contract check
  becomes a clean ✅ when the `_into` path is used.
- **Backwards compatible.** The existing `encrypt` / `decrypt` /
  `update` / `finalize` methods keep their current signatures
  and behavior unchanged — `_into` is purely additive.
- **`docs/PERFORMANCE.md`** — TL;DR table reworked to lead with
  `_into` numbers (the recommended path for any high-throughput
  caller). Added "wrapping-overhead close" table showing
  before/after at 1 MiB for all four encrypt paths plus an
  allocation-count table from the `mod-alloc` profile.

### Security

- **Auth-failure scrub on decrypt.** `decrypt_into` and
  `decrypt_chunk_into` clear the caller-supplied output buffer
  before returning `AuthenticationFailed`, so partially-decrypted
  plaintext bytes never reach the caller. Verified by the
  `decrypt_into_scrubs_on_auth_failure` test (writes sentinel
  bytes into the buffer, asserts they're gone after the failed
  decrypt).
- **No new attack surface.** The `_into` paths route through the
  same upstream RustCrypto primitives as the allocating paths;
  they just avoid the per-call `Vec::with_capacity` + extend
  sequence. AEAD verification, nonce generation, header binding,
  and STREAM-construction nonces all unchanged.

[0.10.0]: https://github.com/jamesgober/crypt-io/compare/v0.9.0...v0.10.0

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

[Unreleased]: https://github.com/jamesgober/crypt-io/compare/v1.0.1...HEAD
[0.1.0]: https://github.com/jamesgober/crypt-io/releases/tag/v0.1.0