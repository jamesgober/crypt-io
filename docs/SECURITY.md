<h1 align="center" id="top">
  <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/coll-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg"><br>
  <b>crypt-io</b>
  <br><sub><sup>SECURITY</sup></sub>
</h1>

<p align="center">
    <i>What <code>crypt-io</code> protects against, what it doesn't,
    where the trust boundaries are, and how to report a vulnerability.</i>
</p>

<hr>

## Reporting a vulnerability

Email **security@hivedb.com** with:
- A description of the issue
- A proof-of-concept if you have one
- The affected version(s)
- Whether you'd like public credit

Expected response: acknowledgement within 72 hours, triage
within one week, patch + advisory within 30 days for confirmed
issues. We follow [responsible disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure).

Please **do not** open public GitHub issues for security
reports.

<hr>

## What `crypt-io` protects against

### Confidentiality + integrity of encrypted data

- **Tampering** with any byte of a ciphertext produced by
  `Crypt::encrypt` or the streaming surface fails authentication
  on decrypt.
- **Wrong-key decryption** fails authentication — opaquely,
  with no information about which mode failed.
- **AAD mismatch** on `decrypt_with_aad` fails authentication —
  AAD is bound into the tag.
- **Header tampering** on streams (algorithm byte, chunk size,
  nonce prefix) fails authentication on the first chunk — the
  24-byte header is AAD for every chunk.

### Stream-protocol attacks

The [STREAM construction](https://eprint.iacr.org/2015/189.pdf)
shipped in `crypt_io::stream` defeats:

- **Truncation** (cutting bytes off the end) — the per-chunk
  nonce includes a `last_flag` byte. A chunk encrypted as
  non-final can't be verified as final.
- **Chunk reordering** — the per-chunk nonce includes a
  32-bit counter. Swapping any two chunks produces a counter
  mismatch.
- **Chunk duplication** — same mechanism.
- **Chunk insertion** — same mechanism.

### Timing side channels

- **MAC verification** uses upstream constant-time comparators
  (`hmac::Mac::verify_slice` for HMAC, `blake3::Hash::eq` for
  BLAKE3 keyed). Both route through `subtle::ConstantTimeEq`
  internally.
- **AEAD tag verification** is the upstream crate's
  responsibility (constant-time per `chacha20poly1305` and
  `aes-gcm` docs).
- **Argon2id verification** uses the upstream `password-hash`
  crate's constant-time PHC compare.

The module documentation for `mac` and the digest comparison
note in `hash` both explicitly forbid `tag == expected` /
`digest == expected` against secret-equivalent values.

### Memory hygiene

- **No key bytes in errors.** Every `Error` variant carries
  lengths, names, or `&'static str` reasons only — never key
  material, plaintext, ciphertext, nonces, or tag bytes.
  Verified by `kdf::argon2_impl::tests::error_messages_redact_password`.
- **`_into` buffers on failure.** `decrypt_into` /
  `decrypt_with_aad_into` clear `out` before any check, so every
  error returns an empty buffer (1.0.0 returned the previous
  message's plaintext on `InvalidKey` / `InvalidCiphertext`). On
  `AuthenticationFailed` the whole allocation, including spare
  capacity, is overwritten with zeros (1.0.0 only called
  `Vec::clear()`, which leaves the bytes in place). With
  `chacha20poly1305` 0.10 and `aes-gcm` 0.10.3 or later, upstream
  verifies the tag before decrypting, so those bytes were
  ciphertext; `aes-gcm` 0.10.0 to 0.10.2 decrypted first
  (RUSTSEC-2023-0096), and 1.0.1 raises the dependency floor to
  0.10.3. Stream `update_into` truncates `out` back to its entry
  length and wipes what it appended. Verified by
  `tests/regressions.rs`.
- **`zeroize`** (default feature). `StreamEncryptor` and
  `StreamDecryptor` overwrite their key copy and internal buffer on
  drop, `Blake3Mac` wipes its keyed state on drop, and the `_into`
  failure paths above use volatile writes. The feature also turns
  on the upstream `zeroize` support in `aes-gcm` (GHASH key
  setup), `argon2` (memory blocks) and `blake3`. Not covered in
  1.0.x: AES round keys inside the `aes` crate, HMAC state, and
  every `Vec<u8>` crypt-io returns to you (plaintext, HKDF output);
  wrap those in `zeroize::Zeroizing` yourself. In 1.0.0 this feature
  did nothing.
- **No secrets in `Debug`.** The stream types print only the
  algorithm, chunk size, counter and buffered length (1.0.0 printed
  the raw key and buffered plaintext).

<hr>

## Algorithm choices

### AEAD: ChaCha20-Poly1305 (default) + AES-256-GCM

- **ChaCha20-Poly1305** ([RFC 8439]). Fast in software on any
  CPU; no timing-side-channel risk on platforms without
  constant-time hardware AES. Post-quantum-safe at the 256-bit
  symmetric strength shipped. **The safe default.**
- **AES-256-GCM** ([NIST SP 800-38D]). Hardware-accelerated on
  AES-NI (Intel/AMD, ~2010+) and ARMv8 with crypto extensions
  (modern Apple Silicon, AWS Graviton). 2-5× ChaCha20 on
  AES-accelerated hardware. **Pick for spec interop or
  AES-NI-only deployments.**

[RFC 8439]: https://datatracker.ietf.org/doc/html/rfc8439
[NIST SP 800-38D]: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf

### Hashing: BLAKE3 (default) + SHA-256 / SHA-512

- **BLAKE3** dominates on modern hardware (11+ GiB/s on Zen 5
  AVX-512 at 64 KiB). Picks up free speed from AVX2/AVX-512/NEON.
- **SHA-256 / SHA-512** for ecosystem interop. SHA-NI on Intel
  Ice Lake+ / AMD Zen 3+ closes the gap for SHA-256 at large
  inputs.

### MAC: HMAC-SHA256 (universal) + HMAC-SHA512 + BLAKE3 keyed

- **HMAC-SHA256** (RFC 2104) for spec interop (JWT, AWS SigV4,
  TLS PRF).
- **HMAC-SHA512** for the wider tag.
- **BLAKE3 keyed** for maximum throughput on hardware that
  doesn't have SHA-NI — typically 4-10× faster than HMAC-SHA256.

### KDF: HKDF + Argon2id

- **HKDF** (RFC 5869) for deriving subkeys from high-entropy
  input keying material.
- **Argon2id** (RFC 9106) for hashing passwords. OWASP-
  recommended parameter set by default; tuneable via
  `Argon2Params` for callers with different cost targets.

### Explicitly NOT shipped

- **No SHA-1, MD5** — broken.
- **No DES, 3DES** — deprecated.
- **No RC4** — broken.
- **No ECB mode** — provides no semantic security.
- **No unauthenticated CBC** — AEAD only.
- **No PBKDF2** — Argon2id is the modern replacement. Use the
  `pbkdf2` crate directly if you need legacy compatibility.
- **No bcrypt** — same. Use the `bcrypt` crate.

<hr>

## Threat model

### In scope

`crypt-io` protects ciphertext / authenticated-data integrity
and confidentiality against:

- Network attackers with full read/write capability
- Storage attackers with full read/write capability on
  persisted ciphertexts (disks, databases, S3, etc.)
- Mass / drag-net surveillance
- An attacker who flips bits in a ciphertext stream and
  observes the receiver's response

### Out of scope

- **Side channels beyond timing on tag-comparison** — power
  analysis, EM emissions, cache timing on the AEAD primitives
  themselves. These are upstream concerns (RustCrypto and
  BLAKE3 do best-effort; serious side-channel resistance needs
  hardware support like ARMv8 crypto extensions).
- **Compromised endpoints** — a malware-infected host running
  `crypt-io` can read its own plaintext. We can't help with
  that; consider key storage (`key-vault`), enclaves, or HSMs.
- **Key generation / storage / rotation** — out of scope.
  `crypt-io` takes a key as a per-call argument and assumes
  the caller obtained it from a sensible source (a KMS,
  `key-vault`, an HKDF expansion of a master, etc.).
- **Quantum attackers** with a fault-tolerant quantum computer
  large enough to run Grover on 256-bit symmetric keys (~2^128
  effective work). Not currently a threat; not in scope for
  1.0.
- **Post-quantum asymmetric** algorithms (Kyber, Dilithium) —
  this is a symmetric-only library. Use a focused PQ crate.

### Trust boundaries

- **The `key` byte slice you pass in is trusted.** We don't
  validate that it has cryptographic-grade entropy; that's the
  caller's responsibility. (We do reject the wrong *length*
  with `Error::InvalidKey`.)
- **The `plaintext` you pass in is whatever you say it is.** We
  encrypt it; we don't sanitize it.
- **The `ciphertext` you pass to `decrypt` is attacker-controlled
  in the threat model.** We must never panic on it, must always
  surface tag failures as `AuthenticationFailed`, must scrub
  partial decryptions from the output buffer on failure (the
  `_into` paths do this).
- **The OS RNG (`mod_rand::tier3`) is trusted.** Failure to
  produce randomness is a `RandomFailure` error — we don't
  fall back to a non-CSPRNG.
- **PHC strings passed to `argon2_verify` are not fully trusted.**
  Their cost parameters are capped (`m` at most 1 GiB, `t` at most
  64, `p` at most 16) and only `argon2id` is accepted, so an
  imported or tampered hash cannot make one login allocate
  gigabytes or burn minutes of CPU, or downgrade the variant.

### API misuse to avoid

- **`verify(..)?;` accepts forgeries.** `mac::hmac_sha256_verify`,
  `mac::hmac_sha512_verify` and `kdf::argon2_verify` return
  `Result<bool>`, with a mismatch as `Ok(false)`. The `?` operator
  only handles the `Err` case, so `verify(..)?;` compiles without a
  warning and ignores the result. Always write
  `if !verify(..)? { /* reject */ }`. A `Result<()>`-returning
  check API is planned for 1.1.
- **Acting on `StreamDecryptor::update` output early.** Chunks are
  authenticated one by one, but truncation at a chunk boundary is
  only detected by `finalize`. `stream::decrypt_file` handles this
  for you by writing to a temporary file and renaming it only after
  `finalize` succeeds.

<hr>

## Verification & testing posture

Coverage as of 1.0:

| Category | Count | Surface |
|---|---:|---|
| Unit tests | 126 | All modules |
| Integration tests | 38 | Streaming, `_into` APIs |
| Doctests | 33 | Every public item has a runnable example |
| `cargo-fuzz` targets | 8 | Every algorithm + stream frame format |
| Pre-release fuzz iterations | 4.7 M | 15-second smoke per target — 0 findings |
| Spec-pinned KATs | 17+ | RFC 8439 (ChaCha20-Poly1305), NIST GCM TC14+15 (AES-GCM), FIPS 180-4 B.1+B.2+C.1+C.2 + empty (SHA-2), RFC 4231 TC1+TC2 × SHA-256/SHA-512 (HMAC), RFC 5869 TC1+TC3 (HKDF), BLAKE3 official + BLAKE3-keyed empty |

Per-release [`docs/release/`](release/) notes document the
verification matrix at each phase. The full per-suite measured
performance numbers are in [`PERFORMANCE.md`](PERFORMANCE.md).

<hr>

## Reproducibility

- **MSRV** is declared as `rust-version = "1.85"` in `Cargo.toml`
  and checked by the CI matrix (there is no `rust-toolchain.toml`).
- **`Cargo.lock`** is committed. Downstream users do not get it, so
  the dependency floors in `Cargo.toml` are also checked with a
  `-Zminimal-versions` build in CI.
- **All test vectors** are pinned as byte-array constants in
  source, not generated at test time.
- **CI** runs the full gate (fmt + clippy + test + doc) on
  Linux + macOS + Windows × stable + MSRV. Pre-CI gate is
  WSL2 Ubuntu (the same Linux environment CI uses).
- **The fuzz corpus** lives at `fuzz/corpus/` (per-target);
  any future findings get committed there so future runs
  always exercise them.

<hr>

## Known caveats

- **Argon2id default parameters age with hardware.** OWASP's
  19 MiB / 2 / 1 set was calibrated for ~100 ms per hash on a
  "modern CPU". On a Zen 5 chip we measure ~9 ms — about 11×
  faster than the design intent. **Production deployments on
  modern server hardware should raise `t_cost` to 8+ or
  `m_cost` to 64 MiB+ via `argon2_hash_with_params`.** See
  [`PERFORMANCE.md`](PERFORMANCE.md) for the measurement and
  guidance.
- **The `Crypt::encrypt` (allocating) path** is slower than
  `Crypt::encrypt_into` for hot loops. Use the `_into` path
  whenever you call encrypt millions of times per second; the
  allocating path is for ergonomics-over-throughput cases.
  See [`PERFORMANCE.md`](PERFORMANCE.md) §"0.10.0 wrapping-
  overhead close".
- **Single-shot encryption: at most 2^32 messages per key.**
  Both shipped AEADs use a random 96-bit nonce per call. After `n`
  messages under one key the chance of a repeated nonce is about
  `n^2 / 2^97`: about 2^-33 at 2^32 messages (the NIST SP 800-38D
  cap for random IVs), 7.6e-6 at 2^40, and 39% at 2^48. A repeated
  nonce leaks the XOR of two plaintexts and, for AES-256-GCM, the
  GHASH key, which allows forgeries. Earlier docs called 2^48 safe;
  it is not. crypt-io does not count messages; rotate keys or
  derive subkeys with HKDF. XChaCha20-Poly1305 (192-bit nonce) is a
  1.x candidate.
- **Stream encryption: at most about 2^12 (4,096) streams per
  key.** Each stream uses a random 56-bit nonce prefix directly
  under the caller's key, with no per-stream subkey. Two streams
  with the same prefix reuse nonces for every chunk index they
  share. The collision chance is about `n^2 / 2^57`: 2^-33 at 4,096
  streams, 2^-17 at about one million, 0.2% at 16 million. For
  "one key, many files" (for example `stream::encrypt_file` in a
  loop), derive a fresh key per file with `kdf::hkdf_sha256` and a
  random salt stored next to the file. A stream format with a
  per-stream subkey is planned for 1.1; 1.x will keep decrypting
  the current format.
- **No `no_std` support in 1.0.x.** Building with
  `default-features = false` still needs `std` (through
  `mod-rand` and the RustCrypto/BLAKE3 crates' default features).
  Earlier docs said otherwise.
- **No deterministic encryption mode.** Every `encrypt` call
  draws a fresh nonce. Callers who need deterministic
  encryption (key-wrap, format-preserving encryption,
  searchable encryption) should use a focused crate.

<hr>

<sub>crypt-io security — Copyright (c) 2026 James Gober. Apache-2.0 OR MIT.</sub>
