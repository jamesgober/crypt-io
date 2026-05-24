<h1 align="center" id="top">
  <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg"><br>
  <b>crypt-io</b>
  <br><sub><sup>1.0 STABILITY CONTRACT</sup></sub>
</h1>

<p align="center">
    <i>What <code>crypt-io 1.0.0</code> commits to. What can change in
    <code>1.x</code> minor releases. What can never change without a
    <code>2.0</code>.</i>
</p>

<hr>

## What "1.0 stable" means here

When `crypt-io 1.0.0` ships, every item listed in
[§ The Frozen Surface](#the-frozen-surface) is **locked under
semver**:

- **Patch (`1.0.x`)** — bug fixes only. No API changes, no
  behavior changes that downstream code can observe.
- **Minor (`1.x.0`)** — additive only. New algorithms, new
  features, new methods. Existing items keep their signatures and
  behavior. New `Algorithm` / `Error` enum variants land here
  (both enums are `#[non_exhaustive]` so this doesn't break
  match sites that include a wildcard arm).
- **Major (`2.0.0`)** — anything else. Removed methods,
  renamed types, changed default behavior, raised MSRV, dropped
  algorithm support, broken wire format.

The 1.x branch will not break you. If you depend on `1.x` and
write match sites with a wildcard arm, `cargo update` is always
safe.

<hr>

## The Frozen Surface

### Top-level types

- **`Crypt`** — algorithm-agile encryption handle. Frozen
  constructors:
  - `Crypt::new() -> Crypt` *(default = ChaCha20-Poly1305)*
  - `Crypt::with_algorithm(Algorithm) -> Crypt`
  - `Crypt::aes_256_gcm() -> Crypt` *(feature `aead-aes-gcm`)*
- **`Algorithm`** — `#[non_exhaustive]` enum. Frozen variants:
  `ChaCha20Poly1305`, `Aes256Gcm`.
- **`Error`** — `#[non_exhaustive]` enum. Frozen variants:
  `InvalidKey`, `InvalidCiphertext`, `AuthenticationFailed`,
  `AlgorithmNotEnabled`, `RandomFailure`, `Mac`, `Kdf`.
- **`Result<T>`** — alias for `core::result::Result<T, Error>`.

### AEAD methods on `Crypt`

Frozen signatures, frozen wire format (see
[`FILE_FORMAT.md`](FILE_FORMAT.md)):

- `encrypt(&self, key, plaintext) -> Result<Vec<u8>>`
- `encrypt_with_aad(&self, key, plaintext, aad) -> Result<Vec<u8>>`
- `decrypt(&self, key, ciphertext) -> Result<Vec<u8>>`
- `decrypt_with_aad(&self, key, ciphertext, aad) -> Result<Vec<u8>>`
- `encrypt_into(&self, key, plaintext, out) -> Result<()>`
- `encrypt_with_aad_into(&self, key, plaintext, aad, out) -> Result<()>`
- `decrypt_into(&self, key, ciphertext, out) -> Result<()>`
- `decrypt_with_aad_into(&self, key, ciphertext, aad, out) -> Result<()>`
- `algorithm(&self) -> Algorithm`

### Hashing — `crypt_io::hash`

Frozen free functions and types (feature-gated as documented in
[API.md](API.md)):

- `hash::blake3(data) -> [u8; 32]`
- `hash::blake3_long(data, len) -> Vec<u8>` *(XOF)*
- `hash::sha256(data) -> [u8; 32]`
- `hash::sha512(data) -> [u8; 64]`
- `hash::Blake3Hasher`, `hash::Sha256Hasher`, `hash::Sha512Hasher` —
  each with `new`, `update`, `finalize`; `Blake3Hasher` additionally
  has `finalize_xof(len)`.
- Constants: `BLAKE3_OUTPUT_LEN`, `SHA256_OUTPUT_LEN`,
  `SHA512_OUTPUT_LEN`.

### MAC — `crypt_io::mac`

- `mac::hmac_sha256(key, data) -> Result<[u8; 32]>`
- `mac::hmac_sha256_verify(key, data, expected) -> Result<bool>`
- `mac::hmac_sha512(key, data) -> Result<[u8; 64]>`
- `mac::hmac_sha512_verify(key, data, expected) -> Result<bool>`
- `mac::blake3_keyed(key: &[u8; 32], data) -> [u8; 32]`
- `mac::blake3_keyed_verify(key, data, expected) -> bool`
- `mac::HmacSha256`, `mac::HmacSha512`, `mac::Blake3Mac` — each with
  `new`, `update`, `finalize`, `verify`.
- Constants: `HMAC_SHA256_OUTPUT_LEN`, `HMAC_SHA512_OUTPUT_LEN`,
  `BLAKE3_MAC_OUTPUT_LEN`, `BLAKE3_MAC_KEY_LEN`.

### KDF — `crypt_io::kdf`

- `kdf::hkdf_sha256(ikm, salt, info, len) -> Result<Vec<u8>>`
- `kdf::hkdf_sha512(ikm, salt, info, len) -> Result<Vec<u8>>`
- `kdf::argon2_hash(password) -> Result<String>`
- `kdf::argon2_hash_with_params(password, params) -> Result<String>`
- `kdf::argon2_verify(phc, password) -> Result<bool>`
- `kdf::Argon2Params` struct with public `m_cost`, `t_cost`,
  `p_cost`, `output_len` fields; `Default` impl matches OWASP.
- Constants: `HKDF_MAX_OUTPUT_SHA256`, `HKDF_MAX_OUTPUT_SHA512`,
  `ARGON2_DEFAULT_OUTPUT_LEN`, `ARGON2_DEFAULT_SALT_LEN`.

### Streaming — `crypt_io::stream`

- `stream::StreamEncryptor` — `new`, `new_with_chunk_size`,
  `chunk_size`, `chunk_size_log2`, `update`, `finalize`,
  `update_into`, `finalize_into`.
- `stream::StreamDecryptor` — same shape.
- `stream::encrypt_file(in, out, key, algorithm) -> Result<()>`
  *(feature `std`)*
- `stream::decrypt_file(in, out, key) -> Result<()>` *(feature `std`)*
- Constants: `HEADER_LEN`, `TAG_LEN`, `DEFAULT_CHUNK_SIZE_LOG2`,
  `MIN_CHUNK_SIZE_LOG2`, `MAX_CHUNK_SIZE_LOG2`.
- Wire format: see [`FILE_FORMAT.md`](FILE_FORMAT.md). The
  on-the-wire bytes are frozen — a `crypt-io 1.0` decrypt of a
  `crypt-io 1.x` encrypt is guaranteed.

<hr>

## MSRV policy

- **1.0 MSRV is Rust 1.85** (edition 2024).
- **1.x will not raise MSRV without a minor version bump.** Within
  a given minor (e.g. `1.3.x`), every patch release keeps the
  same MSRV as the minor's `.0` release.
- **MSRV raises are minor-version events**, not patch. If you pin
  `crypt-io = "=1.3.0"` you'll never see an MSRV change without
  opting in.

<hr>

## Wire format guarantees

- **Stream-encrypt wire format** ([`FILE_FORMAT.md`](FILE_FORMAT.md))
  is frozen for the 1.x series. A file encrypted by 1.0.0
  decrypts cleanly with 1.x.y for any x ≥ 0, y ≥ 0.
- **Single-shot AEAD wire format** (`nonce || ciphertext || tag`)
  is frozen — both ChaCha20-Poly1305 and AES-256-GCM use a
  12-byte nonce + 16-byte tag. Algorithm choice is **not** stored
  in the wire bytes; callers are responsible for routing
  ciphertexts to the right algorithm.
- **Argon2id PHC string format** is whatever the upstream
  `password-hash` crate emits — currently
  `$argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>`. This is
  interoperable with every other Argon2id implementation; we
  don't change it.

<hr>

## What can change in 1.x

- **New `Algorithm` variants** — e.g. XChaCha20-Poly1305 (longer
  nonce), AES-256-SIV (nonce-misuse-resistant). Existing
  variants keep their semantics.
- **New `Error` variants** — for new failure modes in newly
  added algorithms. Both `Error` and `Algorithm` are
  `#[non_exhaustive]`; match sites must include a wildcard arm.
- **New module surface** — e.g. `kdf::scrypt`, `mac::cmac_aes`
  if there's demand.
- **New `*_into` / `*_with_aad` variants** — additive ergonomics.
- **Performance** — `1.x.0` may improve throughput, allocation
  count, or memory usage. Will not reduce them.
- **Dependency versions** — minor bumps of upstream RustCrypto
  crates may land in patch releases (they're security-relevant
  and version-pinning would block urgent fixes). Major bumps of
  RustCrypto crates are minor-version events.

<hr>

## What requires a 2.0

- Removing any method listed in [§ The Frozen Surface](#the-frozen-surface).
- Renaming any item listed there.
- Changing the wire format of single-shot AEAD or stream encrypt.
- Changing the meaning of any `Error` variant (re-using the same
  variant for a different failure mode).
- Changing the default `Algorithm` (currently `ChaCha20Poly1305`).
- Removing an algorithm.
- Removing a Cargo feature flag.
- Removing a default feature.
- Raising MSRV beyond what the user expects from the documented
  policy.

<hr>

## Migration policy

- **1.x → 1.x+1** is always cargo-update-safe.
- **1.x → 2.x** ships with a `MIGRATION.md` document. Breaking
  changes are documented item-by-item; mechanical replacements
  (e.g. `Method::a → Method::b`) are spelled out; rationale is
  given for every removal. The current `1.x` line will receive
  security patches for **at least 12 months** after the `2.0`
  release.

<hr>

## How this contract is enforced

- **`cargo-public-api`** runs in CI on every PR. Any unintended
  surface change blocks merge.
- **`cargo-msrv`** verifies the MSRV declared in
  `rust-toolchain.toml` actually builds the crate. Bumping MSRV
  without bumping the minor version is a CI failure.
- **The `tests/into_apis.rs` and `tests/stream.rs` suites** lock
  in the wire-format invariants — any change that breaks
  cross-version decrypt fails the gate.

<hr>

<sub>crypt-io 1.0 stability contract — Copyright (c) 2026 James Gober. Apache-2.0 OR MIT.</sub>
