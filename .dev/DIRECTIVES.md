# crypt-io - Directives

> Project-specific engineering directives. Apply on top of REPS and the portfolio universal directives.

---

## Priority order

1. `REPS.md` at repo root - **SUPREME AUTHORITY**
2. `_strategy/UNIVERSAL_PROMPT.md` - portfolio-wide directives
3. This file - crypt-io specific directives
4. `.dev/PROMPT.md` - project context
5. `.dev/ROADMAP.md` - current phase and tasks

REPS overrides everything else.

---

## Crypto discipline (the central concern)

This crate handles encryption. A bug is a security bug. Every code change must be evaluated against the security implications.

### Non-negotiable

- **Never reuse a nonce with the same key.** Period. The library generates nonces via `mod-rand` Tier 3 and tracks them where applicable.
- **Always authenticate.** AEAD by default. Don't expose unauthenticated encryption modes.
- **Constant-time tag verification.** RustCrypto handles this; don't bypass it.
- **Zeroize key material when possible.** Use `Zeroizing<Vec<u8>>` for any buffer that holds key bytes.
- **Use battle-tested primitives.** No from-scratch crypto math.
- **Authenticate then decrypt.** Don't expose decrypt-without-auth APIs.

### Fail-safe defaults

- Default AEAD: ChaCha20-Poly1305 (post-quantum safe, fast in software)
- Default hash: BLAKE3 (fastest cryptographic hash)
- Default KDF: HKDF-SHA256 (HKDF for derivation, Argon2id when password-derived)
- Default MAC: HMAC-SHA256 (universally supported) or BLAKE3 keyed
- Default features: `std`, `zeroize`, `aead-chacha20`, `hash-blake3`, `mac-hmac`, `kdf-hkdf`

---

## Algorithm choice discipline

When adding or modifying an algorithm:

- **Use the corresponding RustCrypto crate.** No reimplementation.
- **Provide known-answer test vectors** from the official spec.
- **Document the threat model** the algorithm is appropriate for.
- **Document the deprecation timeline** if the algorithm is legacy (e.g., SHA-1, MD5 - we don't ship these).
- **Benchmark across platforms** - performance varies wildly with hardware acceleration.

Algorithms we ship in 1.0:

| Category | Algorithm | Rationale |
|----------|-----------|-----------|
| AEAD | ChaCha20-Poly1305 | Default, post-quantum safe, fast in software |
| AEAD | AES-256-GCM | Hardware-accelerated on modern CPUs |
| Hash | BLAKE3 | Fastest cryptographic hash, parallelizable |
| Hash | SHA-256 | Universal compatibility |
| Hash | SHA-512 | Required for some standards |
| MAC | HMAC-SHA256 | Universal |
| MAC | HMAC-SHA512 | Universal |
| MAC | BLAKE3 keyed | When BLAKE3 is already used |
| KDF | HKDF-SHA256 | Standard for deriving keys from master |
| KDF | Argon2id | Modern password hashing |

Algorithms we explicitly do NOT ship:

- MD5, SHA-1 (broken, never)
- DES, 3DES (deprecated)
- RC4 (broken)
- ECB mode (insecure)
- Unauthenticated CBC (we only ship AEAD)
- PBKDF2 (Argon2id is the modern replacement)
- bcrypt (Argon2id supersedes for new code; users wanting bcrypt should use `bcrypt` crate)

---

## API design discipline

### Simplicity is mandatory

The API must be simple enough for non-crypto developers to use correctly:

```rust
let crypt = Crypt::new();
let ciphertext = crypt.encrypt(&key, plaintext)?;
let plaintext = crypt.decrypt(&key, &ciphertext)?;
```

Not:

```rust
let cipher = ChaCha20Poly1305::new(&key.into());
let nonce = Nonce::from_slice(&nonce_bytes);
let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).map_err(|e| ...)?;
```

We hide RustCrypto's verbosity behind a clean API.

### Nonce handling

- **Internal generation by default.** The library generates a nonce via `mod-rand` Tier 3 and prepends it to the ciphertext.
- **Caller-provided nonces** are an advanced API with explicit warnings.
- **Nonce uniqueness** is guaranteed by random generation (96-bit nonces have a ~2^48 birthday bound which is fine for any realistic use).

### Algorithm agility

Algorithm selection is explicit:

```rust
// Default (ChaCha20-Poly1305)
let crypt = Crypt::new();

// Explicit
let crypt = Crypt::with_algorithm(Algorithm::Aes256Gcm);

// Feature-gated (compile-time)
#[cfg(feature = "aead-aes-gcm")]
let crypt = Crypt::aes_256_gcm();
```

---

## REPS compliance (non-negotiable)

`src/lib.rs` MUST contain:

```rust
#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(unused_must_use)]
#![deny(unused_results)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::print_stdout)]
#![deny(clippy::print_stderr)]
#![deny(clippy::dbg_macro)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(clippy::missing_safety_doc)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
```

We have zero `unsafe` code (RustCrypto handles SIMD safely).

---

## Performance discipline

### Hot path requirements

- **AEAD throughput** within 80% of upstream RustCrypto (our wrapping shouldn't add measurable overhead)
- **Hash throughput** within 95% of upstream (we're a thin wrapper)
- **Allocation discipline** - reuse buffers, accept slices for output where possible
- `#[inline]` on small wrapper functions

### Required benchmarks

- AEAD encrypt/decrypt at 64 B, 1 KiB, 64 KiB, 1 MiB
- Hash at 64 B, 1 KiB, 64 KiB, 1 MiB
- MAC at 1 KiB
- KDF (HKDF) for 32, 64, 128 byte outputs
- KDF (Argon2id) at default and reduced parameters
- Stream encryption: 100 MB file throughput

### Cross-platform measurements

- x86_64 with AES-NI
- x86_64 without AES-NI (fall back to software)
- ARM64 with crypto extensions
- ARM64 without crypto extensions

---

## Testing discipline

### Unit tests

- **Known-answer tests (KAT)** for every algorithm, using vectors from the official spec
- Round-trip tests: encrypt then decrypt equals original
- Tampering detection: modified ciphertext fails authentication
- Wrong-key detection: wrong key fails authentication

### Property tests (proptest)

- Round-trip for any input length (0 to 1 MB)
- Multiple encrypts of same plaintext produce different ciphertexts (due to random nonces)
- HKDF with different info parameters produces different outputs

### Fuzz tests

- Each AEAD: fuzz the input (plaintext, ciphertext, key, nonce, AAD)
- Each hash: fuzz the input
- Each KDF: fuzz inputs
- Stream encryption: fuzz chunk boundaries

### Integration tests

- File encryption round-trip
- Large data (>1 GiB) streaming
- Async API (if `async-trait` feature enabled)

### Performance verification

- Benchmark suite (criterion) committed
- Baselines.json committed
- Performance targets verified before any 0.x.0 release

---

## Dependencies

### Mandatory (always pulled)

- `mod-rand = "1"` - CSPRNG for nonces, salts, IVs
- `error-forge = "1"` - Error types

### Crypto primitives (feature-gated)

- `chacha20poly1305 = "0.10"` (default via `aead-chacha20`)
- `aes-gcm = "0.10"` (via `aead-aes-gcm`)
- `blake3 = "1"` (default via `hash-blake3`)
- `sha2 = "0.10"` (via `hash-sha2`)
- `hmac = "0.12"` (via `mac-hmac`)
- `hkdf = "0.12"` (via `kdf-hkdf`)
- `argon2 = "0.5"` (via `kdf-argon2`)

### Optional integrations

- `log-io = "1"` (via `logging`)
- `metrics-lib = "1"` (via `metrics`)
- `zeroize = "1.7"` (default on)
- `async-trait = "0.1"` (via `async-trait`)

### Dev-dependencies

- `criterion = "0.5"` - benchmarks
- `proptest = "1"` - property tests
- `hex = "0.4"` - test vector parsing

**New dependencies require:**
- Strong justification (why can't we use what we have?)
- License compatibility (Apache-2.0 / MIT / compatible)
- MSRV check (must support Rust 1.75)
- `cargo audit` clean
- Maintenance status check (last release < 1 year ago for crypto crates)

---

## Out of scope (always)

- **Asymmetric crypto** (RSA, ECDSA, Ed25519) - separate crate
- **TLS** - use `rustls`
- **PGP/GPG** - use `sequoia-openpgp`
- **Random generation** - use `mod-rand`
- **UUID generation** - use `id-forge`
- **Key storage** - use `key-vault`
- **Post-quantum asymmetric** - defer to ecosystem maturity
- **Bcrypt** - users wanting bcrypt should use the `bcrypt` crate
- **PBKDF2** - Argon2id supersedes

---

## When you must break a directive

If a directive in this file genuinely needs an exception:

1. STOP. Don't break it silently. Crypto crate.
2. Document why in the PR description.
3. Get explicit maintainer approval.
4. Add a `// CRYPT-IO-EXCEPTION:` comment at the violation point with the rationale.
5. Update this file or `.dev/PROMPT.md` if the exception reveals a flaw in the directive.
6. For security-related exceptions, also document in `docs/SECURITY.md`.

---

<sub>crypt-io directives - Copyright (c) 2026 James Gober. Apache-2.0 OR MIT.</sub>