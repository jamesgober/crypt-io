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
  salt, nonce prefix) fails authentication on the first chunk — the
  header (and in format v2 the salt) is AAD for every chunk, and in
  v2 the header and salt also feed the per-stream subkey. Non-zero
  reserved bytes in a v2 header are rejected before any decryption.
- **Sealed single-shot buffers** (`Crypt::seal`, 1.1.0) carry an
  authenticated version and algorithm byte, so a buffer cannot be
  reinterpreted under another algorithm.

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

- **MAC verification** uses constant-time comparators:
  `subtle::ConstantTimeEq` for HMAC (crypt-io's own HMAC since
  1.2.2) and `blake3::Hash::eq` for BLAKE3 keyed, which compares in
  constant time with the `constant_time_eq` crate.
- **`Tag<N>`** (1.1.0) wraps a tag with a constant-time `==`
  (`subtle::ConstantTimeEq`), for callers who compare tags
  themselves.
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
  (RUSTSEC-2023-0096), and 1.0.1 raised the dependency floor to
  0.10.3. Stream `update_into` truncates `out` back to its entry
  length and wipes what it appended. Verified by
  `tests/regressions.rs`.
- **Growing a buffer leaves no copy behind (1.1.0).** `Vec::reserve`
  moves a buffer by copying its whole allocation and freeing the old
  block without clearing it. Every decrypt path that writes
  plaintext into a buffer (`decrypt_into`, the stream decryptor's
  `update` / `update_into` / `finalize_into`) grows it with a helper
  that wipes the old allocation first, and `StreamDecryptor::update`
  sizes its output up front so it never reallocates.
- **`zeroize`** (default feature). With it:
  - `StreamEncryptor` and `StreamDecryptor` overwrite their key
    copy (in format v2, the per-stream subkey) and internal buffer
    on drop, and `Blake3Mac` wipes its keyed state on drop;
  - the `_into` failure paths above use volatile writes;
  - `wipe` and `wipe_vec` (1.2.0, public) use volatile writes;
    without `zeroize` they fall back to plain writes plus
    `core::hint::black_box`, which is best effort only;
  - upstream `zeroize` support is on in `aes` (AES round keys,
    1.1.0), `sha2` (hash and HMAC state, which is derived from the
    key, 1.1.0), `aes-gcm`, `argon2` (memory blocks) and `blake3`.
    crypt-io's HMAC and HKDF (1.2.2) also wipe the padded key
    block, a hashed long key, the inner hash and the HKDF
    intermediates. A test checks that a dropped
    `HmacSha256` / `HmacSha512` leaves only zeros behind.

  Not covered: the GHASH key inside `polyval` 0.6, whose
  runtime-dispatch backend has no `Drop` impl. `polyval` 0.7 wipes
  it, but it only comes with `aes-gcm` 0.11 (the `aead` 0.6
  generation). Measured against `aes-gcm` 0.10.3 on the reference
  machine, 0.11.1 is about twice as fast on large inputs but about
  40% slower on 64-byte messages (more per-key setup), and its `aes`
  0.9.3 needs Rust 1.89, above crypt-io's 1.x MSRV of 1.85. crypt-io
  stays on 0.10 for now. The GHASH key is left only in freed memory;
  it allows forgeries under that key but does not reveal the AES
  key. Plaintext that crypt-io returns as a plain `Vec<u8>` is
  yours to wipe; use the 1.1.0 helpers instead where it matters:
  `Crypt::decrypt_zeroizing`, `kdf::hkdf_sha256_into` /
  `hkdf_sha512_into` (derive into a buffer you own),
  `hash::blake3_long_into`, `StreamDecryptor::update_into`, and
  `generate_key()` (returns `Zeroizing<[u8; 32]>`). 1.6.0 adds
  more forms that return a wiped type: `KeyedCrypt::decrypt_zeroizing`,
  `kdf::hkdf_sha256_zeroizing` / `hkdf_sha512_zeroizing` and
  `StreamDecryptor::update_zeroizing` / `finalize_zeroizing`. For
  buffers of your own, `crypt_io::wipe` / `wipe_vec` (1.2.0) do the
  same volatile wipe crypt-io uses internally.
- **File helpers (1.6.0).** `stream::encrypt_file` reads the input
  straight into one buffer that it wipes on every exit, and
  `stream::decrypt_file` writes plaintext straight from one wiped
  buffer to the temporary file, so neither leaves a plaintext copy in
  freed memory (before 1.6.0 their `BufReader` / `BufWriter` buffers
  did). The page cache and the files themselves are outside
  crypt-io's reach. Verified by `tests/wipe_on_free.rs`.
- **`KeyedCrypt` (1.6.0)** holds a scheduled key. It is wiped on drop
  like the stream types' keys (RustCrypto wipes the ChaCha20 key and,
  with `zeroize`, the AES round keys; AWS-LC cleanses its own memory),
  with the same `polyval` GHASH exception as above.
- **No secrets in `Debug`.** The stream types print only the
  algorithm, chunk size, counter and buffered length (1.0.0 printed
  the raw key and buffered plaintext).

<hr>

## Algorithm choices

### AEAD: ChaCha20-Poly1305 (default) + XChaCha20-Poly1305 + AES-256-GCM

- **ChaCha20-Poly1305** ([RFC 8439]). Fast in software on any
  CPU; no timing-side-channel risk on platforms without
  constant-time hardware AES. Post-quantum-safe at the 256-bit
  symmetric strength shipped. **The safe default.**
- **XChaCha20-Poly1305** (1.1.0). ChaCha20-Poly1305 with a 192-bit
  nonce, so random nonces never collide in practice. **Pick when
  one key encrypts more than 2^32 messages.**
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

### KDF: HKDF + Argon2id + PBKDF2

- **HKDF** (RFC 5869) for deriving subkeys from high-entropy
  input keying material.
- **Argon2id** (RFC 9106) for hashing passwords. OWASP-
  recommended parameter set by default; tuneable via
  `Argon2Params` for callers with different cost targets.
- **PBKDF2-HMAC-SHA256** (RFC 8018, 1.3.0, feature `kdf-pbkdf2`)
  only where a protocol or stored format requires it: SCRAM-SHA-256
  (RFC 7677) and existing PBKDF2 hashes. It is not memory-hard, so
  GPUs brute-force it far more cheaply than Argon2id; do not choose
  it for new password storage. The total work, iterations times
  32-byte output blocks, is capped at `kdf::PBKDF2_MAX_ITERATIONS`
  (10,000,000, about 0.65 s on the reference machine) and checked
  before any work, so a SCRAM server or a stored hash cannot pick a
  count, or a count and output length, that ties up a thread for
  minutes. Before 1.6.0 the cap applied per block, so a long output
  multiplied it. Callers should apply a tighter policy of their own.

### Signatures: Ed25519 + RSA PKCS#1 v1.5 (1.3.0, opt-in)

- **Ed25519** (RFC 8032, feature `sign-ed25519`) is the
  recommended choice: deterministic, no per-signature randomness
  to get wrong, 32-byte keys.
- **RSA PKCS#1 v1.5 with SHA-256** (feature `sign-rsa`) for peers
  that require it (DKIM `rsa-sha256`, JOSE `RS256`). Keys from
  2048 to 8192 bits only: smaller keys are refused when parsed (NIST
  SP 800-131A disallows signing with them). Signing is AWS-LC's
  blinded, constant-time RSA. crypt-io does not use the `rsa` crate,
  so RUSTSEC-2023-0071 (Marvin timing attack in `rsa`) does not
  apply.
- The math is AWS-LC (C and assembly, maintained by AWS) via
  `aws-lc-rs`, the same backend as tls-net and rustls's default
  provider. crypt-io uses the regular (non-FIPS) build.
  Private keys never leave AWS-LC memory, which is cleansed on free;
  crypt-io keeps no copy and `Debug` prints no private material.
- **Checking (1.4.0).** `Ed25519PublicKey::check` and
  `RsaPublicKey::check_pkcs1v15_sha256` return `AuthenticationFailed`
  for any mismatch, so `?` rejects forgeries, and `Error::Sign` for a
  key that does not parse. RSA checks are strict DER (no BER padding,
  no `DigestInfo` without NULL); Ed25519 rejects non-canonical `S` and
  `Ed25519PublicKey::from_bytes` accepts small-order keys, as RFC 8032
  allows. With such a key one signature checks for every message, so
  a party who registers one can later deny any particular message; it
  is not a forgery against honest keys. `CosePublicKey` refuses
  small-order Ed25519 keys (1.6.0), since no authenticator makes
  them; callers that accept raw Ed25519 keys from other parties and
  need signatures to bind one message should do the same. Every case of
  Wycheproof's RSA PKCS#1 v1.5 SHA-256 (2048-bit) and Ed25519 files
  behaves as expected (`tests/verify.rs`).
- **1024-bit RSA is check-only and opt-in.**
  `RsaPublicKey::from_der_allow_1024` exists because RFC 8301 requires
  DKIM verifiers to accept 1024-bit keys. Treat such a pass as weaker
  evidence. Nothing in crypt-io signs with less than 2048 bits.
- **ECDSA P-256 (1.5.0, verify only).** For keys other parties pick,
  above all passkeys. The point is validated on parse; DER and fixed
  (`r || s`) signatures are both strict. crypt-io does not sign with
  ECDSA: signing needs a per-signature nonce, and Ed25519 avoids that
  failure mode.
- **WebAuthn COSE keys (1.5.0).** `CosePublicKey::from_cose_key`
  parses authenticator-supplied CBOR with a strict, bounded parser (no
  indefinite lengths, tags, duplicate labels or trailing bytes; at most
  16 parameters, nesting at most 4) and is fuzzed. `alg` must be present
  and match `kty`. Small-order Ed25519 keys are refused (1.6.0).
  Signature-counter, origin and challenge checks are the relying
  party's job, not crypt-io's.
- **ECDSA signatures are not unique.** If `(r, s)` checks, so does
  `(r, n - s)`; AWS-LC, like Wycheproof, accepts both. A signature is
  proof that the key holder signed, not an identifier: never
  deduplicate, or detect replays, by signature bytes. Use the
  challenge (and, for passkeys, the signature counter) for that.
- Key generation, RSA-PSS and ECDSA signing are not provided.

### One-time passwords (1.5.0, opt-in)

- **HMAC-SHA1 is legacy, kept for RFC 4226 / 6238 only.** Every
  authenticator app computes HOTP / TOTP with it. HMAC's security does
  not depend on SHA-1's collision resistance (broken since 2017), so the
  construction is still sound for OTPs, but it lives only in `otp` so it
  is never used as a general MAC.
- Codes are compared in constant time against every candidate in the
  window. The window is capped (`OTP_MAX_WINDOW` = 10) and secrets
  shorter than 128 bits are refused (RFC 4226 section 4).
- **Replay:** a TOTP code stays valid for its step and window. The
  check returns the matched step; callers must store it and refuse any
  code whose step is not greater. Rate-limit attempts too: six digits
  are only 10^6 possibilities.

### Explicitly NOT shipped

- **No SHA-1, MD5** — broken.
- **No DES, 3DES** — deprecated.
- **No RC4** — broken.
- **No ECB mode** — provides no semantic security.
- **No unauthenticated CBC** — AEAD only.
- **No PBKDF2 with SHA-1 or SHA-512** — only PBKDF2-HMAC-SHA256
  ships (1.3.0), for SCRAM and existing hashes. Argon2id stays the
  choice for new password storage.
- **No bcrypt** — Argon2id supersedes it. Use the `bcrypt` crate for
  existing hashes.
- **No RSA below 2048 bits, no RSA encryption (OAEP / PKCS#1 v1.5
  encryption), no DSA.**

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
- **Key storage / rotation** — out of scope. `crypt-io` takes a
  key as a per-call argument and assumes the caller obtained it
  from a sensible source (a KMS, `key-vault`, an HKDF expansion of
  a master, or `generate_key()`, which draws 32 bytes from the OS
  CSPRNG).
- **Quantum attackers** with a fault-tolerant quantum computer
  large enough to run Grover on 256-bit symmetric keys (~2^128
  effective work). Not currently a threat; not in scope for
  1.0.
- **Post-quantum asymmetric** algorithms (Kyber, Dilithium) and
  asymmetric encryption or key exchange. The only asymmetric
  operation crypt-io offers is signing (1.3.0, opt-in). Use a
  focused crate for the rest.

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
- **The OS RNG is trusted.** With `std` it is read through
  `mod_rand::tier3` (`getrandom(2)`, `getentropy`,
  `BCryptGenRandom`); with the `getrandom` feature through the
  `getrandom` crate, which on bare-metal targets calls the backend
  you register. Failure to produce randomness is a `RandomFailure`
  error — we never fall back to a non-CSPRNG.
- **PHC strings passed to `argon2_check` are not fully trusted.**
  Their cost parameters are capped by default (1.6.0: `m` at most
  256 MiB, `t` at most 64, `p` at most 16, and total work `m * t` at
  most 1 GiB-pass, under a second on the reference machine;
  1.1 to 1.5 allowed `m` up to 1 GiB with no total-work cap) and only
  `argon2id` is accepted, so an imported or tampered hash cannot make
  one login allocate gigabytes or burn many seconds of CPU, or
  downgrade the variant. The caps are checked before any memory is
  allocated. An `Argon2Policy` (1.1.0) raises or lowers those caps
  (`with_max_cost`, and `with_max_work` from 1.6.0), adds minimums (so
  a planted cheap hash is rejected), or allows `argon2i` / `argon2d`
  for migration. A server that checks untrusted hashes should still
  set caps no higher than its own hashing parameters.
- **Custom hashing parameters are checked (1.6.0).**
  `argon2_hash_with_params` refuses parameters below the OWASP
  minimums (`Argon2Params::validate()`); before 1.6.0 that check was
  opt-in. `argon2_hash_with_policy` hashes under a caller-chosen
  `Argon2Policy` instead, for tests and migrations.
- **Rejecting a forged stream header costs no memory (1.6.0).** A
  `StreamDecryptor` no longer reserves a chunk-sized buffer when the
  header is parsed, so a header announcing 16 MiB chunks makes the
  decryptor hold only as much as the peer actually sends.

### API misuse to avoid

- **`verify(..)?;` accepts forgeries.** `mac::hmac_sha256_verify`,
  `mac::hmac_sha512_verify` and `kdf::argon2_verify` return
  `Result<bool>`, with a mismatch as `Ok(false)`. The `?` operator
  only handles the `Err` case, so `verify(..)?;` ignores the
  result. Since 1.1.0 these (and `blake3_keyed_verify`) are
  deprecated, so the compiler warns at every call site; use the
  `*_check` functions (`hmac_sha256_check`, `hmac_sha512_check`,
  `blake3_keyed_check`, `argon2_check`, `argon2_check_with_policy`)
  and the streaming types' `check` methods, which return
  `Err(AuthenticationFailed)` on a mismatch, so `check(..)?;` is
  correct. Changing the `verify` signatures themselves is a 2.0
  change.
- **Acting on `StreamDecryptor::update` output early.** Chunks are
  authenticated one by one, but truncation at a chunk boundary is
  only detected by `finalize`. `stream::decrypt_file` handles this
  for you by writing to a temporary file and renaming it only after
  `finalize` succeeds.

<hr>

## Verification & testing posture

Coverage as of 1.6.0 (`cargo test --all-features` on Linux, stable):

| Category | Count | Surface |
|---|---:|---|
| Unit tests | 202 | All modules |
| Integration tests | 128 | Streaming, `_into` APIs, sealed format, signatures, OTP, WebAuthn, regressions, wiping and allocation bounds |
| Doctests | 56 | Public items with runnable examples |
| `cargo-fuzz` targets | 11 | AEAD encrypt / decrypt, stream decrypt, hashes, MACs, HKDF, Argon2 PHC parsing, COSE keys, OTP checks, `_into` differential |
| Known-answer and conformance vectors | | RFC 8439, NIST GCM, FIPS 180-4, RFC 4231, RFC 5869, BLAKE3 official, RFC 8018 / 7677 (PBKDF2), RFC 8032, NIST CAVP (RSA SigVer15, P-256), Wycheproof (Ed25519, RSA PKCS#1 v1.5, P-256 DER and P1363), RFC 4226 / 6238, WebAuthn Level 3, frozen stream-format vectors |

Each release also runs a short fuzz pass over the targets it touched
(1.6.0: `argon2_parse`, `stream_decrypt`, `aead_decrypt`, `cose_key`,
120 s each).

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
  `m_cost` to 64 MiB+ via `argon2_hash_with_params`** (raise the
  `Argon2Policy` caps for checking only if you go above
  256 MiB or 1 GiB-pass). See
  [`PERFORMANCE.md`](PERFORMANCE.md) for the measurement and
  guidance.
- **The `Crypt::encrypt` (allocating) path** allocates once per
  call and is slower than `Crypt::encrypt_into` for hot loops. Use the `_into` path
  whenever you call encrypt millions of times per second; the
  allocating path is for ergonomics-over-throughput cases.
  See [`PERFORMANCE.md`](PERFORMANCE.md) §"0.10.0 wrapping-
  overhead close".
- **Single-shot ChaCha20-Poly1305 / AES-256-GCM: at most 2^32
  messages per key.** Both use a random 96-bit nonce per call.
  After `n` messages under one key the chance of a repeated nonce
  is about `n^2 / 2^97`: about 2^-33 at 2^32 messages (the NIST SP
  800-38D cap for random IVs), 7.6e-6 at 2^40, and 39% at 2^48. A
  repeated nonce leaks the XOR of two plaintexts and, for
  AES-256-GCM, the GHASH key, which allows forgeries. crypt-io does
  not count messages. For higher volumes use XChaCha20-Poly1305
  (1.1.0; 192-bit nonces, collision chance about 2^-65 even after
  2^64 messages), rotate keys, or derive subkeys with HKDF.
- **Stream format v1: at most about 2^12 (4,096) streams per
  key.** v1 (written by 1.0.x, and by 1.1 only on request) uses a
  random 56-bit nonce prefix directly under the caller's key. Two
  streams with the same prefix reuse nonces for every chunk index
  they share; the chance is about `n^2 / 2^57`. Format v2, the
  default since 1.1.0, derives a subkey per stream from a 256-bit
  salt and has no practical streams-per-key limit. Re-encrypt v1
  files that share a key with many others
  (`StreamDecryptor::format()` tells you which ones are v1).
- **Mixed fleets.** crypt-io 1.0.x cannot read stream format v2.
  Keep writing v1 (`StreamFormat::V1`) until every reader is on
  1.1.
- **`no_std` builds** (1.1.0) need the `getrandom` feature for any
  API that draws randomness, and on bare-metal targets a
  `getrandom` custom backend backed by a real hardware RNG. A weak
  backend there weakens every nonce and salt. See
  [`PLATFORM-NOTES.md`](PLATFORM-NOTES.md).
- **Single-shot 1.0 format carries no algorithm id.** The same key
  can be used with more than one AEAD, and nothing in a
  `Crypt::encrypt` buffer says which one produced it. There is no
  known attack from that, but use the sealed format
  (`Crypt::seal` / `open`) for new data, and preferably one key per
  algorithm.
- **No deterministic encryption mode.** Every `encrypt` call
  draws a fresh nonce. Callers who need deterministic
  encryption (key-wrap, format-preserving encryption,
  searchable encryption) should use a focused crate.

<hr>

<sub>crypt-io security — Copyright (c) 2026 James Gober. Apache-2.0 OR MIT.</sub>
