<h1 align="center" id="top">
  <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg"><br>
  <b>crypt-io</b>
  <br><sub><sup>API REFERENCE</sup></sub>
</h1>

<p align="center">
    <b><a href="#installation">Installation</a></b>
    &nbsp;&middot;&nbsp;
    <b><a href="#quick-start">Quick Start</a></b>
    &nbsp;&middot;&nbsp;
    <b><a href="#public-apis">Public APIs</a></b>
    &nbsp;&middot;&nbsp;
    <b><a href="#wire-format">Wire Format</a></b>
    &nbsp;&middot;&nbsp;
    <b><a href="#errors">Errors</a></b>
    &nbsp;&middot;&nbsp;
    <b><a href="#notes">Notes</a></b>
</p>

<p align="center">
    <i>Complete public-API reference for <code>crypt-io</code> 0.4.0.</i>
    <br>
    <i>For the milestone plan see
    <a href="../.dev/ROADMAP.md"><code>.dev/ROADMAP.md</code></a>.
    For per-version notes see <a href="../CHANGELOG.md"><code>CHANGELOG.md</code></a>.</i>
</p>

<hr>

## Table of Contents

- [Installation](#installation)
- [Cargo features](#cargo-features)
- [Quick Start](#quick-start)
- [Public APIs](#public-apis)
  - [`Crypt`](#crypt)
    - [`Crypt::new`](#cryptnew)
    - [`Crypt::with_algorithm`](#cryptwith_algorithm)
    - [`Crypt::aes_256_gcm`](#cryptaes_256_gcm)
    - [`Crypt::algorithm`](#cryptalgorithm)
    - [`Crypt::encrypt`](#cryptencrypt)
    - [`Crypt::encrypt_with_aad`](#cryptencrypt_with_aad)
    - [`Crypt::decrypt`](#cryptdecrypt)
    - [`Crypt::decrypt_with_aad`](#cryptdecrypt_with_aad)
  - [`Algorithm`](#algorithm)
    - [`Algorithm::name`](#algorithmname)
    - [`Algorithm::key_len`](#algorithmkey_len)
    - [`Algorithm::nonce_len`](#algorithmnonce_len)
    - [`Algorithm::tag_len`](#algorithmtag_len)
  - [Choosing an algorithm](#choosing-an-algorithm)
  - [`hash` module](#hash-module)
    - [`hash::blake3`](#hashblake3)
    - [`hash::blake3_long`](#hashblake3_long)
    - [`hash::sha256`](#hashsha256)
    - [`hash::sha512`](#hashsha512)
    - [`Blake3Hasher`](#blake3hasher)
    - [`Sha256Hasher`](#sha256hasher)
    - [`Sha512Hasher`](#sha512hasher)
    - [Choosing a hash](#choosing-a-hash)
  - [`Error`](#error)
  - [`Result<T>`](#resultt)
  - [Module constants](#module-constants)
- [Wire format](#wire-format)
- [Errors](#errors)
- [Notes](#notes)

<hr>

## Installation

### Default installation

Add to `Cargo.toml`:

```toml
[dependencies]
crypt-io = "0.4"
```

### Install via terminal

```bash
cargo add crypt-io
```

### Minimum supported Rust version

**Rust 1.85** (edition 2024). Older toolchains will not build.

<a href="#top">↑ TOP</a>

<hr>

## Cargo features

The 0.2.0 surface is gated behind a small subset of the feature plan
documented in `Cargo.toml`. The full plan ships across the 0.3 →
0.9 milestones; what's listed here is what 0.2.0 actually wires up.

| Feature | Default | Effect |
|---|---|---|
| `std` | ✅ | Standard-library types. Required by the current implementation. |
| `zeroize` | ✅ | `zeroize` integration on supporting types. |
| `aead-chacha20` | ✅ | ChaCha20-Poly1305 backend + [`Crypt::new`](#cryptnew). |
| `aead-aes-gcm` | ✅ | AES-256-GCM backend + [`Crypt::aes_256_gcm`](#cryptaes_256_gcm). |
| `aead-all` |  | Both AEADs (already in the 0.3.0+ default). |
| `hash-blake3` | ✅ | BLAKE3 hashing + [`Blake3Hasher`](#blake3hasher) + XOF. |
| `hash-sha2` | ✅ | SHA-256 + SHA-512 hashing + matching streaming hashers. |
| `hash-all` |  | Both hash families (already in the 0.4.0+ default). |
| `mac-hmac` | ✅ | Reserved for 0.5.0. No-op in 0.4.0. |
| `kdf-hkdf` | ✅ | Reserved for 0.6.0. No-op in 0.4.0. |
| `stream` |  | Reserved for 0.7.0. No-op in 0.4.0. |
| `preset-minimal` |  | `std` + `aead-chacha20` only — the 0.2.0 surface. |
| `preset-all` |  | All planned features enabled. Some are inert until their phase ships. |

> **Note.** Reserved features are wired in `Cargo.toml` so the
> dependency surface is stable across the 0.x series, but they
> activate no code in 0.2.0. Track the milestone plan in
> [`.dev/ROADMAP.md`](../.dev/ROADMAP.md).

<a href="#top">↑ TOP</a>

<hr>

## Quick Start

The shortest correct round-trip:

```rust
use crypt_io::Crypt;

let crypt = Crypt::new();          // ChaCha20-Poly1305 (default)
let key = [0u8; 32];               // your 256-bit key

let ciphertext = crypt.encrypt(&key, b"attack at dawn")?;
let recovered  = crypt.decrypt(&key, &ciphertext)?;
assert_eq!(&*recovered, b"attack at dawn");
# Ok::<(), crypt_io::Error>(())
```

With additional authenticated data:

```rust
use crypt_io::Crypt;

let crypt = Crypt::new();
let key = [0u8; 32];

let aad = b"vault://session/4f3a"; // context, not secret
let ciphertext = crypt.encrypt_with_aad(&key, b"payload", aad)?;
let recovered  = crypt.decrypt_with_aad(&key, &ciphertext, aad)?;
assert_eq!(&*recovered, b"payload");
# Ok::<(), crypt_io::Error>(())
```

Explicit algorithm selection:

```rust
use crypt_io::{Algorithm, Crypt};

// ChaCha20-Poly1305 (default).
let chacha = Crypt::with_algorithm(Algorithm::ChaCha20Poly1305);
assert_eq!(chacha.algorithm(), Algorithm::ChaCha20Poly1305);

// AES-256-GCM — via either the convenience constructor or the agile surface.
let aes_a = Crypt::aes_256_gcm();
let aes_b = Crypt::with_algorithm(Algorithm::Aes256Gcm);
assert_eq!(aes_a, aes_b);
```

<a href="#top">↑ TOP</a>

<hr>

## Public APIs

### `Crypt`

```rust
pub struct Crypt { /* internal */ }
```

The encryption handle. `Crypt` carries only the algorithm selection
— it does **not** store keys or nonces. Keys are passed per-call;
nonces are generated fresh inside `encrypt` / `encrypt_with_aad` and
prepended to the returned ciphertext.

`Crypt` is `Copy + Clone + Debug + PartialEq + Eq` and cheap to
construct (`const fn`). You can keep one as a module-level constant
or instantiate per-call without measurable cost.

#### `Crypt::new`

```rust
pub const fn new() -> Crypt;
```

Construct a handle configured for the default algorithm
([`Algorithm::ChaCha20Poly1305`](#algorithm)).

```rust
use crypt_io::Crypt;
let crypt = Crypt::new();
```

<a href="#top">↑ TOP</a>

#### `Crypt::with_algorithm`

```rust
pub const fn with_algorithm(algorithm: Algorithm) -> Crypt;
```

Construct a handle with an explicit algorithm choice.

```rust
use crypt_io::{Algorithm, Crypt};
let crypt = Crypt::with_algorithm(Algorithm::ChaCha20Poly1305);
```

<a href="#top">↑ TOP</a>

#### `Crypt::aes_256_gcm`

```rust
#[cfg(feature = "aead-aes-gcm")]
pub const fn aes_256_gcm() -> Crypt;
```

Convenience constructor for [`Algorithm::Aes256Gcm`](#algorithm).
Available only when the `aead-aes-gcm` Cargo feature is enabled
(it is in the 0.3.0 default set).

Equivalent to `Crypt::with_algorithm(Algorithm::Aes256Gcm)` — the
separate constructor exists because picking AES-GCM is a deliberate
choice (interop requirement, or a target with AES-NI / ARMv8
crypto extensions) and call sites read cleaner when they say so.

```rust
# #[cfg(feature = "aead-aes-gcm")] {
use crypt_io::{Algorithm, Crypt};
let crypt = Crypt::aes_256_gcm();
assert_eq!(crypt.algorithm(), Algorithm::Aes256Gcm);
# }
```

<a href="#top">↑ TOP</a>

#### `Crypt::algorithm`

```rust
pub const fn algorithm(&self) -> Algorithm;
```

Report which algorithm this handle will use.

```rust
use crypt_io::{Algorithm, Crypt};
let crypt = Crypt::new();
assert_eq!(crypt.algorithm(), Algorithm::ChaCha20Poly1305);
```

<a href="#top">↑ TOP</a>

#### `Crypt::encrypt`

```rust
pub fn encrypt(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>>;
```

Encrypt `plaintext` under `key`. Returns the [wire-format](#wire-format)
buffer `nonce || ciphertext || tag` as a `Vec<u8>`. A fresh 12-byte
nonce is generated for every call via `mod_rand::tier3::fill_bytes`
(OS-backed CSPRNG).

**Parameters**

| Name | Type | Description |
|---|---|---|
| `key` | `&[u8]` | 32-byte symmetric key. Other lengths return [`Error::InvalidKey`](#error). |
| `plaintext` | `&[u8]` | Bytes to encrypt. May be empty. |

**Returns**

`Ok(Vec<u8>)` of length `plaintext.len() + 28` bytes on success.

**Errors**

- [`Error::InvalidKey`](#error) — `key.len() != 32`.
- [`Error::RandomFailure`](#error) — the OS random source could not
  produce a nonce.
- [`Error::AlgorithmNotEnabled`](#error) — the selected algorithm
  was disabled at compile time via Cargo features.

**Example**

```rust
use crypt_io::Crypt;
let crypt = Crypt::new();
let key = [0u8; 32];
let ciphertext = crypt.encrypt(&key, b"hello")?;
assert_eq!(ciphertext.len(), 5 + 28);
# Ok::<(), crypt_io::Error>(())
```

<a href="#top">↑ TOP</a>

#### `Crypt::encrypt_with_aad`

```rust
pub fn encrypt_with_aad(&self, key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;
```

Encrypt with additional authenticated data. `aad` is authenticated
alongside the ciphertext but **not** encrypted and **not** included
in the returned buffer. Callers must supply identical `aad` to
[`decrypt_with_aad`](#cryptdecrypt_with_aad) — otherwise
authentication will fail.

Pass `&[]` for `aad` for behaviour identical to
[`encrypt`](#cryptencrypt).

**Parameters**

| Name | Type | Description |
|---|---|---|
| `key` | `&[u8]` | 32-byte symmetric key. |
| `plaintext` | `&[u8]` | Bytes to encrypt. May be empty. |
| `aad` | `&[u8]` | Associated data — authenticated, not encrypted. May be empty. |

**Errors:** same as [`encrypt`](#cryptencrypt).

**Example**

```rust
use crypt_io::Crypt;
let crypt = Crypt::new();
let key = [0u8; 32];
let aad = b"context-tag";

let ciphertext = crypt.encrypt_with_aad(&key, b"payload", aad)?;
let recovered  = crypt.decrypt_with_aad(&key, &ciphertext, aad)?;
assert_eq!(&*recovered, b"payload");
# Ok::<(), crypt_io::Error>(())
```

<a href="#top">↑ TOP</a>

#### `Crypt::decrypt`

```rust
pub fn decrypt(&self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>;
```

Decrypt a buffer produced by [`encrypt`](#cryptencrypt) and return
the plaintext.

The buffer is expected to be `nonce || ciphertext || tag` — exactly
the layout `encrypt` returns. The tag is verified in constant time
by the upstream RustCrypto primitive; any tampering, wrong key, or
wrong length results in [`Error::AuthenticationFailed`](#error).

The returned `Vec<u8>` does **not** auto-zeroize. Callers handling
long-lived plaintext should move the bytes into a
`Zeroizing<Vec<u8>>` (`zeroize` crate) or — for production —
keep the plaintext inside a [`key-vault`](https://crates.io/crates/key-vault)
handle and never let it touch a raw `Vec`.

**Errors**

- [`Error::InvalidKey`](#error) — `key.len() != 32`.
- [`Error::InvalidCiphertext`](#error) — the buffer is shorter
  than `nonce_len + tag_len` (28 bytes).
- [`Error::AuthenticationFailed`](#error) — wrong key, tampered
  ciphertext, tampered tag, or AAD mismatch when associated data
  was used at encrypt-time.
- [`Error::AlgorithmNotEnabled`](#error) — the selected algorithm
  was disabled at compile time.

**Example**

```rust
use crypt_io::Crypt;
let crypt = Crypt::new();
let key = [0u8; 32];
let ciphertext = crypt.encrypt(&key, b"hello")?;
let recovered  = crypt.decrypt(&key, &ciphertext)?;
assert_eq!(&*recovered, b"hello");
# Ok::<(), crypt_io::Error>(())
```

<a href="#top">↑ TOP</a>

#### `Crypt::decrypt_with_aad`

```rust
pub fn decrypt_with_aad(&self, key: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;
```

Decrypt with associated data. `aad` must match what was passed to
[`encrypt_with_aad`](#cryptencrypt_with_aad) — otherwise the call
returns [`Error::AuthenticationFailed`](#error).

**Errors:** same as [`decrypt`](#cryptdecrypt).

<a href="#top">↑ TOP</a>

---

### `Algorithm`

```rust
#[non_exhaustive]
pub enum Algorithm {
    ChaCha20Poly1305,
    Aes256Gcm,
    // future variants
}
```

The supported AEAD algorithms. `#[non_exhaustive]` — `match` sites
must include a wildcard arm so future minor releases do not break
downstream code.

`Default` selects `ChaCha20Poly1305`. See
[Choosing an algorithm](#choosing-an-algorithm) for guidance on
when to pick which.

#### `Algorithm::name`

```rust
pub const fn name(self) -> &'static str;
```

Human-readable name. Returns `"ChaCha20-Poly1305"` or `"AES-256-GCM"`.

#### `Algorithm::key_len`

```rust
pub const fn key_len(self) -> usize;
```

Required key length in bytes. Returns `32` for every algorithm
shipped in 0.3.0.

#### `Algorithm::nonce_len`

```rust
pub const fn nonce_len(self) -> usize;
```

Nonce length in bytes that the algorithm consumes. Returns `12`
for both `ChaCha20Poly1305` and `Aes256Gcm`.

#### `Algorithm::tag_len`

```rust
pub const fn tag_len(self) -> usize;
```

Authentication tag length in bytes the algorithm produces. Returns
`16` for both algorithms.

<a href="#top">↑ TOP</a>

---

### Choosing an algorithm

Both algorithms shipped in 0.3.0 are safe at 256-bit symmetric
strength. The choice is about hardware utilisation and interop, not
about cryptographic strength.

| You want… | Pick |
|---|---|
| The safe default with no thinking required | `ChaCha20Poly1305` |
| Maximum throughput on AES-NI / ARMv8 hardware | `Aes256Gcm` |
| Interop with TLS, JWE A256GCM, FIPS-spec'd protocols | `Aes256Gcm` |
| A target without hardware AES (older ARM, embedded, RISC-V) | `ChaCha20Poly1305` |
| Constant-time guarantee without depending on hardware AES | `ChaCha20Poly1305` |

The hardware-acceleration dispatch is handled by the upstream
`aes-gcm` crate at runtime — no `cfg` gates required on the
consumer side.

> **Note on storage.** The algorithm choice is **not** stored in
> the [wire format](#wire-format). Routing stored ciphertexts back
> to the correct algorithm on decrypt is the caller's
> responsibility — keep an external association (algorithm-id,
> key-id, or both) alongside the buffer.

<a href="#top">↑ TOP</a>

---

### `hash` module

Cryptographic hash functions. New in 0.4.0. Three algorithms
exposed through a consistent free-function API plus matching
streaming hashers:

| Algorithm  | One-shot                          | Streaming        | Output | Feature       |
|------------|-----------------------------------|------------------|--------|---------------|
| BLAKE3     | [`hash::blake3`](#hashblake3)     | [`Blake3Hasher`](#blake3hasher) | 32 B | `hash-blake3` |
| BLAKE3 XOF | [`hash::blake3_long`](#hashblake3_long) | `Blake3Hasher::finalize_xof` | N B | `hash-blake3` |
| SHA-256    | [`hash::sha256`](#hashsha256)     | [`Sha256Hasher`](#sha256hasher) | 32 B | `hash-sha2`   |
| SHA-512    | [`hash::sha512`](#hashsha512)     | [`Sha512Hasher`](#sha512hasher) | 64 B | `hash-sha2`   |

> **Hash-only, no MAC.** This module does not expose keyed hashing.
> For HMAC-SHA2 and BLAKE3 keyed mode, see the upcoming `mac`
> module (Phase 0.5.0). Using a raw hash as a MAC is a security
> mistake; the missing `with_key` is deliberate.

<a href="#top">↑ TOP</a>

#### `hash::blake3`

```rust
#[cfg(feature = "hash-blake3")]
pub fn blake3(data: &[u8]) -> [u8; 32];
```

One-shot BLAKE3 hash. Returns a fixed 32-byte digest.

```rust
# #[cfg(feature = "hash-blake3")] {
use crypt_io::hash;
let d = hash::blake3(b"the quick brown fox");
assert_eq!(d.len(), 32);
# }
```

<a href="#top">↑ TOP</a>

#### `hash::blake3_long`

```rust
#[cfg(feature = "hash-blake3")]
pub fn blake3_long(data: &[u8], len: usize) -> Vec<u8>;
```

One-shot BLAKE3 hash with arbitrary output length via the
extendable-output (XOF) mode. `len` may be any value including
zero. The first 32 bytes of the output equal
[`hash::blake3(data)`](#hashblake3) — XOF is a superset of the
default hash.

For the common 32-byte case prefer the fixed [`hash::blake3`](#hashblake3) —
it skips the XOF reader path.

```rust
# #[cfg(feature = "hash-blake3")] {
use crypt_io::hash;
let d = hash::blake3_long(b"input", 128);
assert_eq!(d.len(), 128);
# }
```

<a href="#top">↑ TOP</a>

#### `hash::sha256`

```rust
#[cfg(feature = "hash-sha2")]
pub fn sha256(data: &[u8]) -> [u8; 32];
```

One-shot SHA-256 hash (NIST FIPS 180-4). Returns a fixed 32-byte
digest.

```rust
# #[cfg(feature = "hash-sha2")] {
use crypt_io::hash;
let d = hash::sha256(b"abc");
assert_eq!(d.len(), 32);
# }
```

<a href="#top">↑ TOP</a>

#### `hash::sha512`

```rust
#[cfg(feature = "hash-sha2")]
pub fn sha512(data: &[u8]) -> [u8; 64];
```

One-shot SHA-512 hash (NIST FIPS 180-4). Returns a fixed 64-byte
digest.

```rust
# #[cfg(feature = "hash-sha2")] {
use crypt_io::hash;
let d = hash::sha512(b"abc");
assert_eq!(d.len(), 64);
# }
```

<a href="#top">↑ TOP</a>

#### `Blake3Hasher`

```rust
#[cfg(feature = "hash-blake3")]
pub struct Blake3Hasher { /* internal */ }

impl Blake3Hasher {
    pub fn new() -> Self;
    pub fn update(&mut self, data: &[u8]) -> &mut Self;
    pub fn finalize(self) -> [u8; 32];
    pub fn finalize_xof(self, len: usize) -> Vec<u8>;
}
```

Streaming BLAKE3 hasher. `update` is chainable; finalisation
consumes the hasher and returns either the default 32-byte digest
or an arbitrary-length XOF buffer.

```rust
# #[cfg(feature = "hash-blake3")] {
use crypt_io::hash::Blake3Hasher;
let mut h = Blake3Hasher::new();
h.update(b"first ");
h.update(b"second");
let d = h.finalize();
assert_eq!(d.len(), 32);
# }
```

<a href="#top">↑ TOP</a>

#### `Sha256Hasher`

```rust
#[cfg(feature = "hash-sha2")]
pub struct Sha256Hasher { /* internal */ }

impl Sha256Hasher {
    pub fn new() -> Self;
    pub fn update(&mut self, data: &[u8]) -> &mut Self;
    pub fn finalize(self) -> [u8; 32];
}
```

Streaming SHA-256 hasher. Same shape as
[`Blake3Hasher`](#blake3hasher) minus the XOF mode (which is
BLAKE3-specific).

<a href="#top">↑ TOP</a>

#### `Sha512Hasher`

```rust
#[cfg(feature = "hash-sha2")]
pub struct Sha512Hasher { /* internal */ }

impl Sha512Hasher {
    pub fn new() -> Self;
    pub fn update(&mut self, data: &[u8]) -> &mut Self;
    pub fn finalize(self) -> [u8; 64];
}
```

Streaming SHA-512 hasher.

<a href="#top">↑ TOP</a>

#### Choosing a hash

Both BLAKE3 and SHA-2 are safe at 256-bit cryptographic strength.
The choice is about speed and ecosystem interop.

| You want… | Pick |
|---|---|
| Maximum throughput on modern hardware | `BLAKE3` |
| Variable-length output (KDF, fingerprinting, MGF) | `BLAKE3` (XOF) |
| TLS / JWT / certificate fingerprint interop | `SHA-256` |
| 64-byte output for spec compliance | `SHA-512` |
| Tree-hashing for very large inputs | `BLAKE3` |
| FIPS-certified algorithm (via a downstream FIPS-validated build) | `SHA-256` / `SHA-512` |

Hardware acceleration is automatic on both:

- **BLAKE3** uses `AVX2` / `AVX-512` on x86 and `NEON` on ARM via
  upstream dispatch.
- **SHA-2** uses `SHA-NI` on supporting x86 chips and ARMv8 crypto
  extensions on AArch64 — also runtime-dispatched.

> **Comparing digests.** Don't use `==` to compare two digests
> when one of them is secret-equivalent (an authentication token,
> a session key fingerprint, etc.). Use
> `subtle::ConstantTimeEq::ct_eq` so timing doesn't leak how many
> leading bytes matched. For non-secret comparisons (file
> integrity checks, content-addressed storage keys), `==` is fine.

<a href="#top">↑ TOP</a>

---

### `Error`

```rust
#[non_exhaustive]
pub enum Error {
    InvalidKey { expected: usize, actual: usize },
    InvalidCiphertext(String),
    AuthenticationFailed,
    AlgorithmNotEnabled(&'static str),
    RandomFailure(&'static str),
}
```

The crate-wide error type. `#[non_exhaustive]` — add a wildcard
arm in match sites.

Errors are **redaction-clean by design**:

- No key bytes, plaintext, nonces, or ciphertext appear in any
  variant.
- `InvalidKey` carries only the *lengths* — not the buffers.
- `AuthenticationFailed` is collapsed (wrong-key / tampered-bytes /
  AAD-mismatch all surface as this variant). The narrower
  classification is intentionally not exposed.

Implements `Debug + Clone + PartialEq + Eq + Display`. With the
`std` feature (default on), it also implements
`std::error::Error`.

<a href="#top">↑ TOP</a>

---

### `Result<T>`

```rust
pub type Result<T> = core::result::Result<T, Error>;
```

Alias for the crate's `Result` shape.

<a href="#top">↑ TOP</a>

---

### Module constants

From `crypt_io::aead`:

| Constant | Value | Meaning |
|---|---|---|
| `CHACHA20_NONCE_LEN` | `12` | Bytes of nonce ChaCha20-Poly1305 consumes. |
| `CHACHA20_TAG_LEN` | `16` | Bytes of authentication tag ChaCha20-Poly1305 produces. |
| `AES_GCM_NONCE_LEN` | `12` | Bytes of nonce AES-256-GCM consumes (the NIST default). |
| `AES_GCM_TAG_LEN` | `16` | Bytes of authentication tag AES-256-GCM produces. |
| `KEY_LEN` | `32` | Required key length for every AEAD shipped in 0.3.0+. |

From `crypt_io::hash`:

| Constant | Value | Meaning | Feature |
|---|---|---|---|
| `BLAKE3_OUTPUT_LEN` | `32` | Bytes the default BLAKE3 digest produces. | `hash-blake3` |
| `SHA256_OUTPUT_LEN` | `32` | Bytes SHA-256 produces. | `hash-sha2` |
| `SHA512_OUTPUT_LEN` | `64` | Bytes SHA-512 produces. | `hash-sha2` |

<a href="#top">↑ TOP</a>

<hr>

## Wire format

The buffer returned by `encrypt` / `encrypt_with_aad` and consumed
by `decrypt` / `decrypt_with_aad`:

```
+-----------------+--------------------------+------------------+
| nonce (12 B)    | ciphertext (N B)         | tag (16 B)       |
+-----------------+--------------------------+------------------+
| 0 .. 12         | 12 .. 12+N               | 12+N .. 28+N     |
```

Total size: `plaintext.len() + 28` bytes. The nonce is generated
internally per call and prepended so `decrypt` only needs the key
and the buffer.

Associated data (AAD) is **not** stored in this buffer. It is the
caller's responsibility to keep AAD addressable on the decrypt side
— it is authenticated, not transmitted.

<a href="#top">↑ TOP</a>

<hr>

## Errors

- **`InvalidKey`** — key is not 32 bytes. Carries the lengths only.
- **`InvalidCiphertext`** — buffer is too short to hold a nonce +
  tag (or, in future versions, fails frame-level invariants).
- **`AuthenticationFailed`** — wrong key, tampered bytes, AAD
  mismatch, or missing AAD on decrypt. Collapsed by design.
- **`AlgorithmNotEnabled`** — selected algorithm was disabled at
  compile time. Re-build with the appropriate Cargo feature.
- **`RandomFailure`** — OS random source failed to produce a nonce.
  Rare; usually indicates a misconfigured sandbox or a freshly-booted
  VM that has not yet collected entropy.

<a href="#top">↑ TOP</a>

<hr>

## Notes

- **Nonce reuse is impossible through this API.** Every
  `encrypt` / `encrypt_with_aad` call draws a fresh 12-byte
  nonce. There is no caller-supplied-nonce surface in 0.2.0.
- **The 96-bit nonce birthday bound** is ~`2^48` messages per
  key — far beyond any realistic single-key workload.
- **Constant-time tag verification** is preserved by deferring to
  the upstream `chacha20poly1305` crate; no equality comparisons on
  tag bytes happen in this wrapper.
- **Plaintext is `Vec<u8>` in 0.2.0.** Wrap with
  `zeroize::Zeroizing::new(_)` if you need zero-on-drop for the
  recovered plaintext, or compose with `key-vault` for production
  key handling.
- **AES-256-GCM ships in 0.3.0** with NIST SP 800-38D vectors and
  hardware-acceleration verification (AES-NI on x86, crypto
  extensions on ARM).

<a href="#top">↑ TOP</a>

<hr>

<sub>crypt-io API reference — Copyright (c) 2026 James Gober. Apache-2.0 OR MIT.</sub>
