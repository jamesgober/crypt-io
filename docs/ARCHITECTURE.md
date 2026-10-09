<h1 align="center" id="top">
  <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg"><br>
  <b>crypt-io</b>
  <br><sub><sup>ARCHITECTURE</sup></sub>
</h1>

<p align="center">
    <i>How the crate is organised, what each module does, how
    algorithm dispatch works, and which decisions are deliberate.</i>
</p>

<hr>

## Layout

```text
crypt-io/
├── src/
│   ├── lib.rs            ← module wiring, lint set, public re-exports
│   ├── error.rs          ← Error enum + Result alias
│   ├── tag.rs            ← Tag<N> with constant-time equality
│   ├── rng.rs            ← OS random source (mod-rand or getrandom)
│   ├── wipe.rs           ← buffer wiping helpers
│   ├── aead/             ← Algorithm-agile AEAD surface
│   │   ├── mod.rs        ← Crypt + Algorithm + dispatch + sealed format + generate_key
│   │   ├── backend.rs    ← one implementation, generic over the cipher type
│   │   ├── chacha20.rs   ← ChaCha20 / XChaCha20-Poly1305 known-answer tests
│   │   └── aes_gcm.rs    ← AES-256-GCM known-answer tests
│   ├── hash/             ← Hash functions
│   │   ├── mod.rs        ← Module docs, re-exports, output-length constants
│   │   ├── blake3_impl.rs← BLAKE3 + Blake3Hasher + XOF
│   │   └── sha2_impl.rs  ← SHA-256 / SHA-512 + streamers
│   ├── mac/              ← Message Authentication Codes
│   │   ├── mod.rs        ← Module docs, re-exports, output-length constants
│   │   ├── hmac_impl.rs  ← HMAC-SHA256 / HMAC-SHA512 + streamers + verify
│   │   └── blake3_impl.rs← BLAKE3 keyed + Blake3Mac + verify
│   ├── kdf/              ← Key Derivation Functions
│   │   ├── mod.rs        ← Module docs, re-exports
│   │   ├── hkdf_impl.rs  ← HKDF-SHA256 / HKDF-SHA512
│   │   └── argon2_impl.rs← Argon2id + Argon2Params + Argon2Policy + PHC check
│   └── stream/           ← Chunked AEAD with STREAM construction
│       ├── mod.rs        ← Re-exports, public constants
│       ├── frame.rs      ← Header layout, v2 key schedule, per-chunk nonce
│       ├── aead.rs       ← Per-chunk encrypt/decrypt primitives
│       ├── encryptor.rs  ← StreamEncryptor (with _into variants)
│       ├── decryptor.rs  ← StreamDecryptor (with _into variants)
│       └── file.rs       ← encrypt_file / decrypt_file (std-only)
├── benches/              ← criterion benches (aead, hash, mac, kdf, stream)
├── examples/             ← runnable examples (aead, mac, kdf, stream, profile_alloc)
├── fuzz/                 ← cargo-fuzz workspace (9 targets)
├── tests/                ← integration tests (stream, into_apis, kat, regressions, properties, v1_1)
└── docs/                 ← public docs (API, PERFORMANCE, SECURITY, this file, ...)
```

<hr>

## Module responsibilities

### `aead/` — single-shot authenticated encryption

The user-facing entry point. `Crypt` is the algorithm-agile
handle; it stores **only** the algorithm choice (a single byte),
never key bytes. Per-call:

1. `Crypt::encrypt(key, plaintext)` calls
   `Crypt::encrypt_with_aad(key, plaintext, &[])`.
2. Dispatch matches on `self.algorithm` and calls
   `backend::encrypt::<C>` with `C` = `ChaCha20Poly1305`,
   `XChaCha20Poly1305` or `Aes256Gcm`.
3. `backend` (one generic implementation for every cipher):
   - check key length (must be 32 bytes)
   - draw a fresh nonce of the cipher's length (12 or 24 bytes)
     from the OS CSPRNG (`rng::fill`)
   - write `nonce || plaintext` into one buffer and encrypt in
     place with `encrypt_in_place_detached`
   - append the tag and return `nonce || ciphertext || tag`

The `_into` variants write into a caller-supplied buffer instead
of a fresh `Vec`. `seal` / `open` use the same backend with a
2-byte `version || algorithm` prefix that is also fed into the
associated data. See
[`PERFORMANCE.md`](PERFORMANCE.md) for the measured impact.

### `hash/` — one-shot + streaming hashes

Three algorithms, two API shapes each (one-shot free function,
streaming type). BLAKE3 additionally exposes XOF mode for
variable-length output. The module deliberately does **not**
provide keyed hashing — keyed BLAKE3 lives in `mac::Blake3Mac` so
the "hash-as-MAC" footgun is impossible.

### `mac/` — authentication tags with constant-time verification

Three MACs (HMAC-SHA256, HMAC-SHA512, BLAKE3 keyed) with the
same compute / verify / streaming triad each. Verification is
**always** constant-time:

- HMAC verify routes through `hmac::Mac::verify_slice` (uses
  `subtle::ConstantTimeEq` internally).
- BLAKE3 keyed verify routes through `blake3::Hash` equality
  (constant-time per upstream docs).

Module documentation explicitly forbids `tag == expected`
comparisons on secret-equivalent tags. The `*_verify` paths
exist precisely so callers don't write that code.

### `kdf/` — key derivation

Two algorithms with different threat models:

- **HKDF** (`hkdf_sha256`, `hkdf_sha512`) for deriving subkeys
  from high-entropy input. Single-call extract-then-expand;
  optional salt, mandatory `info` context for domain separation.
- **Argon2id** (`argon2_hash` + `argon2_check`) for password
  hashing. Salt is generated internally per call from the OS
  CSPRNG and embedded in the returned PHC string. A PHC string's
  variant and costs are checked against an `Argon2Policy` before
  any work is done.

The module overview explicitly distinguishes the two and points
callers at the right one for their input shape.

### `stream/` — chunked AEAD for data that doesn't fit in memory

Implements the [STREAM
construction](https://eprint.iacr.org/2015/189.pdf) — per-chunk
AEAD with a counter + last-flag byte in the nonce. Defeats:

- **Truncation** (cutting off the end) via the last-flag byte
- **Reordering / duplication** via the chunk counter
- **Header tampering** by binding the header (and the v2 salt)
  into every chunk's AAD
- **Nonce reuse across streams** (format v2) by encrypting each
  stream under its own HKDF-SHA256 subkey, derived from the
  caller's key and a 32-byte random salt

Frame format documented in detail in
[`FILE_FORMAT.md`](FILE_FORMAT.md).

The `_into` variants (encrypt + decrypt) take a caller-supplied
output buffer to avoid per-call allocation; useful for the
encrypt path where files can be large and `Vec` growth becomes a
hot loop.

<hr>

## Algorithm dispatch

`Algorithm` is a `#[non_exhaustive]` enum with three variants in
1.1 (`XChaCha20Poly1305` was added in 1.1.0). Dispatch goes
through one macro, `with_cipher!`, which binds a type name to the
cipher for the algorithm (or returns `AlgorithmNotEnabled` when its
feature is off):

```rust
with_cipher!(self.algorithm, C => backend::encrypt::<C>(key, plaintext, aad, &[]))
```

`backend` is generic over any RustCrypto `aead` 0.5 cipher
(`KeyInit + AeadInPlace`), so a new algorithm in 1.x needs a new
`Algorithm` variant, one arm in `with_cipher!`, an algorithm byte,
and KAT tests. The stream module's per-chunk primitives
(`src/stream/aead.rs`) use the same macro.

<hr>

## Error handling

`Error` is `#[non_exhaustive]` with ten variants in 1.1:

- `InvalidKey { expected, actual }` — wrong key length
- `InvalidCiphertext(String)` — malformed input that's not a
  cryptographic failure (e.g. truncated header)
- `AuthenticationFailed` — opaque cryptographic failure (wrong
  key, tampered bytes, AAD mismatch, etc.)
- `AlgorithmNotEnabled(&'static str)` — selected algorithm
  disabled at compile time
- `RandomFailure(&'static str)` — OS RNG could not produce a
  nonce
- `Mac(&'static str)` — MAC operation init failed (unreachable
  in practice — HMAC accepts any key length, BLAKE3 keyed takes
  a typed key)
- `Kdf(&'static str)` — KDF parameter validation or PHC parse
  failure
- `Io(&'static str)` *(1.1.0)* — file-helper I/O failure (1.0.x
  used `Mac`)
- `InvalidInput(&'static str)` *(1.1.0)* — a bad argument, such as
  an out-of-range chunk size or the same file as input and output
- `LimitExceeded(&'static str)` *(1.1.0)* — an encrypt-side size
  limit (1.0.x reported these as `AuthenticationFailed` or
  `InvalidCiphertext`, which looked like tampering)

**Redaction-clean by design.** No variant carries key bytes,
plaintext, nonces, or tag bytes.

**A mismatch is an error.** The `*_check` functions (1.1.0) return
`Err(AuthenticationFailed)` when a tag or password does not match,
so `check(..)?;` rejects it. The older `*_verify` functions return
`Ok(false)` instead, which `?` silently discards; they are
deprecated.

**`AuthenticationFailed` opacity is intentional.** Wrong key,
tampered ciphertext, tampered tag, AAD mismatch, header
tampering, truncation, reorder — all surface as the same
variant. Splitting them into distinct variants would let an
attacker tell how close they are to a forgery.

<hr>

## Dependency rationale

Every dependency is a deliberate choice. The full list:

| Dep | Why |
|---|---|
| `chacha20poly1305` | ChaCha20-Poly1305 primitive. RustCrypto. |
| `aes-gcm` | AES-256-GCM primitive with AES-NI / ARMv8 dispatch. RustCrypto. |
| `blake3` | BLAKE3 hash + XOF + keyed. Official BLAKE3 crate. |
| `sha2` | SHA-256 / SHA-512 with SHA-NI dispatch. RustCrypto. |
| `hmac` | Generic HMAC with constant-time `verify_slice`. RustCrypto. |
| `hkdf` | RFC 5869 HKDF. RustCrypto. |
| `argon2` | Argon2id with PHC framework. RustCrypto. |
| `aes` | Direct dependency only so `zeroize` can turn on `aes/zeroize` (AES round keys). RustCrypto. |
| `subtle` | Constant-time equality for `Tag`. |
| `mod-rand` *(with `std`)* | Portfolio CSPRNG (Tier 3 = OS-backed). |
| `getrandom` *(opt)* | OS CSPRNG for `no_std` builds, or in place of `mod-rand`. |
| `zeroize` *(opt)* | Volatile wiping of the stream types' key copy and buffer, the BLAKE3 keyed MAC state and `_into` failure buffers; enables upstream `zeroize` in `aes`, `aes-gcm`, `sha2`, `hmac`, `argon2`, `blake3` (default on). |

All RustCrypto and BLAKE3 dependencies have their default
features off; crypt-io's `std` feature forwards to their `std`
features, so a `default-features = false` build is `no_std`.

1.0.1 removed `error-forge`, `log-io`, `metrics-lib` and
`async-trait`: no code used them. The `logging`, `metrics` and
`async-trait` features remain as empty features so existing
feature lists keep resolving.

Dev dependencies for tests + benches + the alloc profile:

- `criterion` — benches
- `proptest` — property tests
- `hex` — test vector parsing
- `mod-alloc` — heap profiler for `examples/profile_alloc.rs`

<hr>

## Build profiles

```toml
[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
strip = "symbols"

[profile.bench]
opt-level = 3
lto = "fat"
codegen-units = 1
debug = true        # keep symbols so flamegraphs map back to source
```

These produce the numbers in [`PERFORMANCE.md`](PERFORMANCE.md).
Reducing `opt-level` or disabling LTO will cost 10-30%
throughput on the AEAD paths.

<hr>

## What's intentionally NOT in here

Documented elsewhere but worth restating in one place:

- **No asymmetric crypto** (RSA, ECDSA, Ed25519, X25519). Use
  the relevant focused crate.
- **No PGP / GPG**. Use `sequoia-openpgp`.
- **No TLS**. Use `rustls`.
- **No general RNG surface**. Use `mod-rand` or `getrandom`
  directly. The only randomness crypt-io hands out is
  `generate_key()` for 256-bit keys.
- **No `Crypt::with_key`** that stores a key. Keys are per-call
  arguments by design; key storage is `key-vault`'s job.
- **No `hash::*::with_key`**. Keyed hashing lives in `mac::*`.
- **No "raw" / "unauthenticated" cipher modes** (CTR, CBC).
  Authentication is non-negotiable.
- **No nonce-misuse-resistant variants** (SIV modes).
  Internally generated random nonces remove caller nonce
  mistakes, but 96-bit ones can still collide: keep each key
  below 2^32 single-shot ChaCha20-Poly1305 / AES-256-GCM messages
  or use XChaCha20-Poly1305 (see
  [`SECURITY.md`](SECURITY.md#known-caveats)).

<hr>

<sub>crypt-io architecture — Copyright (c) 2026 James Gober. Apache-2.0 OR MIT.</sub>
