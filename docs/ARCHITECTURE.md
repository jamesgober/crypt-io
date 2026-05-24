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
│   ├── aead/             ← Algorithm-agile AEAD surface
│   │   ├── mod.rs        ← Crypt + Algorithm + dispatch
│   │   ├── chacha20.rs   ← ChaCha20-Poly1305 backend (encrypt/_into/decrypt/_into)
│   │   └── aes_gcm.rs    ← AES-256-GCM backend (same shape)
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
│   │   └── argon2_impl.rs← Argon2id + Argon2Params + PHC parse/verify
│   └── stream/           ← Chunked AEAD with STREAM construction
│       ├── mod.rs        ← Re-exports, public constants
│       ├── frame.rs      ← Header layout + per-chunk nonce derivation
│       ├── aead.rs       ← Per-chunk encrypt/decrypt primitives
│       ├── encryptor.rs  ← StreamEncryptor (with _into variants)
│       ├── decryptor.rs  ← StreamDecryptor (with _into variants)
│       └── file.rs       ← encrypt_file / decrypt_file (std-only)
├── benches/              ← criterion benches (aead, hash, mac, kdf, stream)
├── examples/             ← runnable examples (aead, mac, kdf, stream, profile_alloc)
├── fuzz/                 ← cargo-fuzz workspace (8 targets)
├── tests/                ← integration tests (stream, into_apis)
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
2. Dispatch matches on `self.algorithm`:
   - `ChaCha20Poly1305` → `chacha20::encrypt(key, plaintext, aad)`
   - `Aes256Gcm` → `aes_gcm::encrypt(key, plaintext, aad)`
3. Backend functions:
   - check key length (must be 32 bytes)
   - generate a fresh 12-byte nonce via `mod_rand::tier3::fill_bytes`
   - call upstream `encrypt(nonce, Payload { msg, aad })`
   - prepend the nonce to the returned ciphertext
   - return `nonce || ciphertext || tag` as `Vec<u8>`

The `_into` variants do the same but use
`encrypt_in_place_detached` against the caller-supplied buffer
to avoid allocating a fresh `Vec` per call. See
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
- **Argon2id** (`argon2_hash` + `argon2_verify`) for password
  hashing. Salt is generated internally per-call via
  `mod_rand::tier3` and embedded in the returned PHC string.

The module overview explicitly distinguishes the two and points
callers at the right one for their input shape.

### `stream/` — chunked AEAD for data that doesn't fit in memory

Implements the [STREAM
construction](https://eprint.iacr.org/2015/189.pdf) — per-chunk
AEAD with a counter + last-flag byte in the nonce. Defeats:

- **Truncation** (cutting off the end) via the last-flag byte
- **Reordering / duplication** via the chunk counter
- **Header tampering** by binding the 24-byte header into every
  chunk's AAD

Frame format documented in detail in
[`FILE_FORMAT.md`](FILE_FORMAT.md).

The `_into` variants (encrypt + decrypt) take a caller-supplied
output buffer to avoid per-call allocation; useful for the
encrypt path where files can be large and `Vec` growth becomes a
hot loop.

<hr>

## Algorithm dispatch

`Algorithm` is a `#[non_exhaustive]` enum with two variants in
1.0. Dispatch in `Crypt::encrypt_with_aad` (and the `_into`
variants) is a simple `match`:

```rust
match self.algorithm {
    Algorithm::ChaCha20Poly1305 => chacha20::encrypt(...),
    Algorithm::Aes256Gcm        => aes_gcm::encrypt(...),
}
```

Both backends present the same internal signature:

```rust
pub(super) fn encrypt(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;
pub(super) fn encrypt_into(key: &[u8], plaintext: &[u8], aad: &[u8], out: &mut Vec<u8>) -> Result<()>;
pub(super) fn decrypt(key: &[u8], wire: &[u8], aad: &[u8]) -> Result<Vec<u8>>;
pub(super) fn decrypt_into(key: &[u8], wire: &[u8], aad: &[u8], out: &mut Vec<u8>) -> Result<()>;
```

This pattern keeps adding a new algorithm in 1.x mechanically
simple: implement the four backend functions, add the
`Algorithm` variant, add the four match arms, add KAT tests.

The streaming module has the same shape in
`src/stream/aead.rs` — `encrypt_chunk` / `decrypt_chunk` plus
`_into` variants — and the same `match self.algorithm` dispatch
in the encryptor and decryptor.

<hr>

## Error handling

`Error` is `#[non_exhaustive]` with seven variants in 1.0:

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

**Redaction-clean by design.** No variant carries key bytes,
plaintext, nonces, or tag bytes. The `*_verify` family returns
`bool` (or `Result<bool>`) rather than `Result<()>` so callers
don't accidentally panic on a wrong tag — the API contract is
"tag mismatch is not an error, it's a result."

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
| `mod-rand` | Portfolio CSPRNG (Tier 3 = OS-backed). |
| `error-forge` | Portfolio error framework. Declared but minimally used in 1.0 — manual `Display + Error` impls satisfy current needs. |
| `zeroize` *(opt)* | Zero-on-drop wrappers (default on). |
| `log-io` *(opt)* | Operation logging. Not enabled by default. |
| `metrics-lib` *(opt)* | Performance instrumentation. Not enabled by default. |
| `async-trait` *(opt)* | Reserved for 1.x async surface. Not used in 1.0. |

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
- **No RNG surface**. Use `mod-rand` directly — this crate uses
  it internally for nonces/salts only.
- **No `Crypt::with_key`** that stores a key. Keys are per-call
  arguments by design; key storage is `key-vault`'s job.
- **No `hash::*::with_key`**. Keyed hashing lives in `mac::*`.
- **No "raw" / "unauthenticated" cipher modes** (CTR, CBC).
  Authentication is non-negotiable.
- **No nonce-misuse-resistant variants** in 1.0 (SIV modes). The
  internally-generated random nonces are misuse-resistant
  enough for the current API shape.

<hr>

<sub>crypt-io architecture — Copyright (c) 2026 James Gober. Apache-2.0 OR MIT.</sub>
