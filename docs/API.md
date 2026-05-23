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
    <i>Complete public-API reference for <code>crypt-io</code> 0.10.0.</i>
    <br>
    <i>For per-version notes see <a href="../CHANGELOG.md"><code>CHANGELOG.md</code></a>.</i>
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
    - [`Crypt::encrypt_into` / `decrypt_into` (zero-alloc, 0.10.0)](#zero-alloc-into-paths)
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
  - [`mac` module](#mac-module)
    - [`mac::hmac_sha256`](#machmac_sha256)
    - [`mac::hmac_sha256_verify`](#machmac_sha256_verify)
    - [`mac::hmac_sha512`](#machmac_sha512)
    - [`mac::hmac_sha512_verify`](#machmac_sha512_verify)
    - [`mac::blake3_keyed`](#macblake3_keyed)
    - [`mac::blake3_keyed_verify`](#macblake3_keyed_verify)
    - [`HmacSha256`](#hmacsha256)
    - [`HmacSha512`](#hmacsha512)
    - [`Blake3Mac`](#blake3mac)
    - [Choosing a MAC](#choosing-a-mac)
  - [`kdf` module](#kdf-module)
    - [`kdf::hkdf_sha256`](#kdfhkdf_sha256)
    - [`kdf::hkdf_sha512`](#kdfhkdf_sha512)
    - [`kdf::argon2_hash`](#kdfargon2_hash)
    - [`kdf::argon2_hash_with_params`](#kdfargon2_hash_with_params)
    - [`kdf::argon2_verify`](#kdfargon2_verify)
    - [`Argon2Params`](#argon2params)
    - [Choosing a KDF](#choosing-a-kdf)
  - [`stream` module](#stream-module)
    - [`StreamEncryptor`](#streamencryptor)
    - [`StreamDecryptor`](#streamdecryptor)
    - [`stream::encrypt_file`](#streamencrypt_file)
    - [`stream::decrypt_file`](#streamdecrypt_file)
    - [Stream wire format](#stream-wire-format)
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
crypt-io = "0.7"
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
| `mac-hmac` | ✅ | HMAC-SHA256 + HMAC-SHA512 + [`HmacSha256`](#hmacsha256) / [`HmacSha512`](#hmacsha512). |
| `mac-blake3` | ✅ | BLAKE3 keyed mode + [`Blake3Mac`](#blake3mac). |
| `mac-all` |  | Both MAC families (already in the 0.5.0+ default). |
| `kdf-hkdf` | ✅ | [`kdf::hkdf_sha256`](#kdfhkdf_sha256) / [`kdf::hkdf_sha512`](#kdfhkdf_sha512). |
| `kdf-argon2` | ✅ | [`kdf::argon2_hash`](#kdfargon2_hash) / [`kdf::argon2_verify`](#kdfargon2_verify) / [`Argon2Params`](#argon2params). |
| `kdf-all` |  | Both KDF families (already in the 0.6.0+ default). |
| `stream` | ✅ | [`StreamEncryptor`](#streamencryptor) / [`StreamDecryptor`](#streamdecryptor) + [`encrypt_file`](#streamencrypt_file) / [`decrypt_file`](#streamdecrypt_file). Pulls both AEAD backends. |
| `preset-minimal` |  | `std` + `aead-chacha20` only — the 0.2.0 surface. |
| `preset-all` |  | All planned features enabled. Some are inert until their phase ships. |

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

#### Zero-alloc `_into` paths

```rust
impl Crypt {
    pub fn encrypt_into(&self, key: &[u8], plaintext: &[u8], out: &mut Vec<u8>) -> Result<()>;
    pub fn encrypt_with_aad_into(&self, key: &[u8], plaintext: &[u8], aad: &[u8], out: &mut Vec<u8>) -> Result<()>;
    pub fn decrypt_into(&self, key: &[u8], ciphertext: &[u8], out: &mut Vec<u8>) -> Result<()>;
    pub fn decrypt_with_aad_into(&self, key: &[u8], ciphertext: &[u8], aad: &[u8], out: &mut Vec<u8>) -> Result<()>;
}
```

New in 0.10.0. Same semantics as the `Vec`-returning methods,
but the caller supplies the output buffer. The buffer is cleared
on entry; capacity is reserved if needed; ciphertext (or
recovered plaintext) is appended in place.

**Zero steady-state allocations.** After a one-time grow, every
subsequent call reuses the buffer's capacity. Verified by
[`examples/profile_alloc.rs`](../examples/profile_alloc.rs)
which runs 10,000 iterations under `mod-alloc` and prints
allocation counts.

**`decrypt_*_into` auth-failure scrub.** On
`Error::AuthenticationFailed` the output buffer is cleared
before returning, so partially-decrypted plaintext from the
upstream `decrypt_in_place_detached` call can't leak to the
caller.

**When to use:** any hot-path encrypt loop. The `Vec`-returning
methods are kept for ergonomics — use them when you'd discard
the returned `Vec` immediately anyway.

```rust
# #[cfg(feature = "aead-chacha20")] {
use crypt_io::Crypt;
let crypt = Crypt::new();
let key = [0u8; 32];

// Construct the buffer once, reuse forever.
let mut ct = Vec::new();
crypt.encrypt_into(&key, b"first message",  &mut ct)?;
crypt.encrypt_into(&key, b"second message", &mut ct)?;  // no allocation
crypt.encrypt_into(&key, b"third message",  &mut ct)?;  // no allocation
# }
# Ok::<(), crypt_io::Error>(())
```

Stream `_into` variants are documented in [the `stream` module
section](#stream-module) — same shape: `update_into(&mut self,
data, out)` and `finalize_into(self, out)`.

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
>
> For **MAC tags** specifically, don't even reach for `subtle`
> directly — use the [`mac`](#mac-module) module's `*_verify`
> paths, which already wrap the constant-time comparator and
> handle wrong-length tags as rejections rather than panics.

<a href="#top">↑ TOP</a>

---

### `mac` module

Message Authentication Codes. New in 0.5.0. Three algorithms with
a consistent compute / verify / streaming triad — and verification
is **always** constant-time, by design.

| Algorithm        | Compute                          | Verify                                  | Streaming       | Tag    | Feature       |
|------------------|----------------------------------|-----------------------------------------|-----------------|--------|---------------|
| HMAC-SHA256      | [`mac::hmac_sha256`](#machmac_sha256) | [`mac::hmac_sha256_verify`](#machmac_sha256_verify) | [`HmacSha256`](#hmacsha256) | 32 B | `mac-hmac`   |
| HMAC-SHA512      | [`mac::hmac_sha512`](#machmac_sha512) | [`mac::hmac_sha512_verify`](#machmac_sha512_verify) | [`HmacSha512`](#hmacsha512) | 64 B | `mac-hmac`   |
| BLAKE3 keyed     | [`mac::blake3_keyed`](#macblake3_keyed) | [`mac::blake3_keyed_verify`](#macblake3_keyed_verify) | [`Blake3Mac`](#blake3mac) | 32 B | `mac-blake3` |

> **Verify, don't `==`.** Comparing two MAC tags with `==` leaks
> how many leading bytes matched via timing — that leak is enough
> to forge tags one byte at a time. The `*_verify` functions and
> the streaming hashers' `verify` methods all use upstream
> constant-time comparators. **Never** compare a computed tag to
> an expected tag with `==`.

<a href="#top">↑ TOP</a>

#### `mac::hmac_sha256`

```rust
#[cfg(feature = "mac-hmac")]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32]>;
```

Compute an HMAC-SHA256 tag (RFC 2104) over `data` under `key`.
Accepts a key of any length — short keys are zero-padded, long
keys are hashed to block size, per RFC 2104.

**Errors.** Returns [`Error::Mac`](#error) if the upstream `hmac`
crate refuses the key. Unreachable in practice (HMAC accepts any
key length), but the upstream API is fallible by signature so the
wrapper preserves that.

```rust
# #[cfg(feature = "mac-hmac")] {
use crypt_io::mac;
let tag = mac::hmac_sha256(b"shared key", b"message")?;
assert_eq!(tag.len(), 32);
# }
# Ok::<(), crypt_io::Error>(())
```

<a href="#top">↑ TOP</a>

#### `mac::hmac_sha256_verify`

```rust
#[cfg(feature = "mac-hmac")]
pub fn hmac_sha256_verify(key: &[u8], data: &[u8], expected_tag: &[u8]) -> Result<bool>;
```

Constant-time verification of an HMAC-SHA256 tag. Computes the tag
for `(key, data)` and compares it to `expected_tag` via the
`hmac` crate's `verify_slice` (which routes through `subtle`).
Returns `Ok(true)` on match, `Ok(false)` otherwise (including when
`expected_tag` is the wrong length).

**Always use this rather than `tag == expected`.**

**Errors.** Same as [`mac::hmac_sha256`](#machmac_sha256).

```rust
# #[cfg(feature = "mac-hmac")] {
use crypt_io::mac;
let key = b"shared";
let tag = mac::hmac_sha256(key, b"data")?;
assert!(mac::hmac_sha256_verify(key, b"data", &tag)?);
assert!(!mac::hmac_sha256_verify(key, b"tampered", &tag)?);
# }
# Ok::<(), crypt_io::Error>(())
```

<a href="#top">↑ TOP</a>

#### `mac::hmac_sha512`

```rust
#[cfg(feature = "mac-hmac")]
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> Result<[u8; 64]>;
```

Compute an HMAC-SHA512 tag (RFC 2104) over `data` under `key`.
Same shape as [`mac::hmac_sha256`](#machmac_sha256) with a 64-byte
tag.

**Errors.** Same as [`mac::hmac_sha256`](#machmac_sha256).

<a href="#top">↑ TOP</a>

#### `mac::hmac_sha512_verify`

```rust
#[cfg(feature = "mac-hmac")]
pub fn hmac_sha512_verify(key: &[u8], data: &[u8], expected_tag: &[u8]) -> Result<bool>;
```

Constant-time verification for HMAC-SHA512. Same shape as
[`mac::hmac_sha256_verify`](#machmac_sha256_verify).

<a href="#top">↑ TOP</a>

#### `mac::blake3_keyed`

```rust
#[cfg(feature = "mac-blake3")]
pub fn blake3_keyed(key: &[u8; 32], data: &[u8]) -> [u8; 32];
```

Compute a BLAKE3 keyed-mode tag over `data` under a typed
32-byte key.

Unlike HMAC, this is **infallible** — the key is type-checked as
`&[u8; 32]`, so there is no runtime length check that could fail.
The fixed-size key matches BLAKE3's design intent (the key is a
fixed-size secret derived elsewhere — from `key-vault`, from an
HKDF expansion, etc.).

```rust
# #[cfg(feature = "mac-blake3")] {
use crypt_io::mac;
let key = [0x42u8; 32];
let tag = mac::blake3_keyed(&key, b"message");
assert_eq!(tag.len(), 32);
# }
```

<a href="#top">↑ TOP</a>

#### `mac::blake3_keyed_verify`

```rust
#[cfg(feature = "mac-blake3")]
pub fn blake3_keyed_verify(key: &[u8; 32], data: &[u8], expected_tag: &[u8]) -> bool;
```

Constant-time verification of a BLAKE3 keyed-mode tag. Computes
the tag for `(key, data)` and compares it to `expected_tag` via
BLAKE3's `Hash::eq` (which is documented as constant time).

Returns `true` on match, `false` otherwise (including when
`expected_tag` is not 32 bytes long).

**Always use this rather than `tag == expected`.**

```rust
# #[cfg(feature = "mac-blake3")] {
use crypt_io::mac;
let key = [0x42u8; 32];
let tag = mac::blake3_keyed(&key, b"message");
assert!(mac::blake3_keyed_verify(&key, b"message", &tag));
assert!(!mac::blake3_keyed_verify(&key, b"tampered", &tag));
# }
```

<a href="#top">↑ TOP</a>

#### `HmacSha256`

```rust
#[cfg(feature = "mac-hmac")]
pub struct HmacSha256 { /* internal */ }

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Result<Self>;
    pub fn update(&mut self, data: &[u8]) -> &mut Self;
    pub fn finalize(self) -> [u8; 32];
    pub fn verify(self, expected_tag: &[u8]) -> bool;
}
```

Streaming HMAC-SHA256. `update` is chainable; finalisation consumes
the hasher and returns either the 32-byte tag (`finalize`) or a
constant-time comparison against an expected tag (`verify`).

```rust
# #[cfg(feature = "mac-hmac")] {
use crypt_io::mac::HmacSha256;
let mut m = HmacSha256::new(b"shared key")?;
m.update(b"first ");
m.update(b"second");
let tag = m.finalize();
assert_eq!(tag.len(), 32);
# }
# Ok::<(), crypt_io::Error>(())
```

<a href="#top">↑ TOP</a>

#### `HmacSha512`

```rust
#[cfg(feature = "mac-hmac")]
pub struct HmacSha512 { /* internal */ }
```

Same shape as [`HmacSha256`](#hmacsha256) with a 64-byte tag.

<a href="#top">↑ TOP</a>

#### `Blake3Mac`

```rust
#[cfg(feature = "mac-blake3")]
pub struct Blake3Mac { /* internal */ }

impl Blake3Mac {
    pub fn new(key: &[u8; 32]) -> Self;     // infallible
    pub fn update(&mut self, data: &[u8]) -> &mut Self;
    pub fn finalize(self) -> [u8; 32];
    pub fn verify(self, expected_tag: &[u8]) -> bool;
}
```

Streaming BLAKE3 keyed-mode MAC. Construction is infallible
(typed 32-byte key); `update` is chainable; finalisation consumes
the hasher.

```rust
# #[cfg(feature = "mac-blake3")] {
use crypt_io::mac::Blake3Mac;
let key = [0x42u8; 32];
let mut m = Blake3Mac::new(&key);
m.update(b"first ");
m.update(b"second");
let tag = m.finalize();
assert_eq!(tag.len(), 32);
# }
```

<a href="#top">↑ TOP</a>

#### Choosing a MAC

All three are safe at 256-bit symmetric strength. The choice is
about interop and speed.

| You want… | Pick |
|---|---|
| JWT (HS256), TLS PRF, AWS request signing, anywhere a spec names HMAC-SHA256 | `mac::hmac_sha256` |
| 64-byte tag for spec compliance | `mac::hmac_sha512` |
| Maximum throughput, you control both sides of the wire | `mac::blake3_keyed` |
| Type-checked fixed-size key | `mac::blake3_keyed` (`&[u8; 32]`) |
| Variable-length key handled internally | `mac::hmac_*` (accepts any length) |
| Tag is being transported over the wire | Any — they're all 32 B (or 64 B for SHA-512); pick by interop |

> **Use the `verify` paths.** Never compare a computed tag to an
> expected tag with `==`. The non-constant-time leak is enough to
> forge tags. This applies to every algorithm in this table.

<a href="#top">↑ TOP</a>

---

### `kdf` module

Key Derivation Functions. New in 0.6.0. Two algorithms addressing
different threat models:

| Algorithm   | Purpose                                            | Speed         | Feature       |
|-------------|----------------------------------------------------|---------------|---------------|
| HKDF-SHA256 | Derive one-or-many subkeys from a high-entropy IKM | Fast (µs)     | `kdf-hkdf`    |
| HKDF-SHA512 | Same, wider underlying digest                      | Fast (µs)     | `kdf-hkdf`    |
| Argon2id    | Derive a key from a *password* (low-entropy input) | Slow (~100ms) | `kdf-argon2`  |

> **HKDF is not for passwords.** HKDF expects high-entropy input
> keying material (master keys, DH shared secrets, secrets-manager
> tokens). Feeding it a password makes the brute-force step
> *faster*, not slower. Use [`kdf::argon2_hash`](#kdfargon2_hash)
> for passwords.

<a href="#top">↑ TOP</a>

#### `kdf::hkdf_sha256`

```rust
#[cfg(feature = "kdf-hkdf")]
pub fn hkdf_sha256(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    len: usize,
) -> Result<Vec<u8>>;
```

Derive `len` bytes of output keying material via HKDF-SHA256.
`ikm` is the high-entropy input; `salt` is an optional random
value (pass `None` if you don't have one); `info` binds the
derived key to a purpose (pass `b""` if you don't need it).

**Errors.** Returns [`Error::Kdf`](#error) if `len` exceeds
[`HKDF_MAX_OUTPUT_SHA256`](#module-constants) (8160 bytes).

```rust
# #[cfg(feature = "kdf-hkdf")] {
use crypt_io::kdf;
let master = [0x42u8; 32];
let subkey = kdf::hkdf_sha256(&master, Some(b"salt"), b"app:session:v1", 32)?;
assert_eq!(subkey.len(), 32);
# }
# Ok::<(), crypt_io::Error>(())
```

**Deriving multiple uncorrelated subkeys from the same master:**

```rust
# #[cfg(feature = "kdf-hkdf")] {
use crypt_io::kdf;
let master = [0x42u8; 32];
let enc_key = kdf::hkdf_sha256(&master, None, b"app:encrypt:v1", 32)?;
let mac_key = kdf::hkdf_sha256(&master, None, b"app:mac:v1",     32)?;
// `info` is the domain-separator. Independent outputs.
assert_ne!(enc_key, mac_key);
# }
# Ok::<(), crypt_io::Error>(())
```

<a href="#top">↑ TOP</a>

#### `kdf::hkdf_sha512`

```rust
#[cfg(feature = "kdf-hkdf")]
pub fn hkdf_sha512(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    len: usize,
) -> Result<Vec<u8>>;
```

Same shape as [`kdf::hkdf_sha256`](#kdfhkdf_sha256) with a SHA-512
digest underneath. Allows up to
[`HKDF_MAX_OUTPUT_SHA512`](#module-constants) (16320 bytes) of
output.

**Errors.** Returns [`Error::Kdf`](#error) if `len` exceeds
[`HKDF_MAX_OUTPUT_SHA512`](#module-constants).

<a href="#top">↑ TOP</a>

#### `kdf::argon2_hash`

```rust
#[cfg(feature = "kdf-argon2")]
pub fn argon2_hash(password: &[u8]) -> Result<String>;
```

Hash `password` with Argon2id using OWASP-recommended parameters
(~100 ms per hash on a modern CPU). Returns the standard
PHC-encoded hash string
(`$argon2id$v=19$m=...,t=...,p=...$salt$hash`).

The salt is generated fresh via `mod_rand::tier3::fill_bytes` and
embedded in the returned string — callers do not need to manage
salt storage separately.

**Errors.** Returns [`Error::RandomFailure`](#error) if the OS
RNG cannot produce a salt, or [`Error::Kdf`](#error) if the
Argon2 implementation rejects the parameters or fails to hash.

```rust,no_run
# #[cfg(feature = "kdf-argon2")] {
use crypt_io::kdf;
let phc = kdf::argon2_hash(b"correct horse battery staple")?;
assert!(phc.starts_with("$argon2id$"));
# }
# Ok::<(), crypt_io::Error>(())
```

<a href="#top">↑ TOP</a>

#### `kdf::argon2_hash_with_params`

```rust
#[cfg(feature = "kdf-argon2")]
pub fn argon2_hash_with_params(password: &[u8], params: Argon2Params) -> Result<String>;
```

Like [`kdf::argon2_hash`](#kdfargon2_hash) but with caller-supplied
[`Argon2Params`](#argon2params). Use this for machine-to-machine
credentials (higher memory cost) or for tests (very low cost).

**Errors.** Same as [`kdf::argon2_hash`](#kdfargon2_hash).

```rust,no_run
# #[cfg(feature = "kdf-argon2")] {
use crypt_io::kdf::{argon2_hash_with_params, Argon2Params};
let params = Argon2Params { m_cost: 64 * 1024, t_cost: 3, p_cost: 1, output_len: 32 };
let phc = argon2_hash_with_params(b"service-token", params)?;
# }
# Ok::<(), crypt_io::Error>(())
```

<a href="#top">↑ TOP</a>

#### `kdf::argon2_verify`

```rust
#[cfg(feature = "kdf-argon2")]
pub fn argon2_verify(phc: &str, password: &[u8]) -> Result<bool>;
```

Verify `password` against a PHC-encoded Argon2 hash. Returns
`Ok(true)` on match, `Ok(false)` on wrong password, and
[`Error::Kdf`](#error) if `phc` is not a parseable PHC string.

The distinction matters: a *malformed* PHC string indicates
corruption or a coding mistake (log as `error`); a *correctly-
formatted* but wrong-password hash indicates an attacker or a user
mistyping (log as `warn`).

Verification re-derives the hash under the parameters encoded in
`phc` and compares in constant time. Cost is the same as computing
a fresh hash with those parameters (~100 ms with the defaults).

**Errors.** Returns [`Error::Kdf`](#error) only when `phc` fails
to parse. Wrong-password returns `Ok(false)`, not an error.

```rust
# #[cfg(feature = "kdf-argon2")] {
use crypt_io::kdf;
let phc = kdf::argon2_hash(b"hunter2")?;
assert!(kdf::argon2_verify(&phc, b"hunter2")?);
assert!(!kdf::argon2_verify(&phc, b"hunter3")?);
# }
# Ok::<(), crypt_io::Error>(())
```

<a href="#top">↑ TOP</a>

#### `Argon2Params`

```rust
#[cfg(feature = "kdf-argon2")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    pub m_cost: u32,      // memory cost in kibibytes
    pub t_cost: u32,      // time cost (iterations)
    pub p_cost: u32,      // parallelism (lanes)
    pub output_len: usize, // derived-key length in bytes
}

impl Argon2Params {
    pub const fn new(m_cost: u32, t_cost: u32, p_cost: u32, output_len: usize) -> Self;
}

impl Default for Argon2Params {
    /// OWASP-recommended: 19 MiB, 2 iterations, 1 lane, 32-byte output (~100 ms).
    fn default() -> Self;
}
```

Tuneable Argon2id parameters. The `Default` impl matches the
OWASP "first recommended option" for interactive web-facing
password hashing.

**Cost tuning guidance:**

| Use case | Suggested parameters |
|---|---|
| Interactive web login | `Argon2Params::default()` (~100 ms) |
| Machine-to-machine credentials | Higher `m_cost` (e.g. 64 MiB) |
| Low-end embedded | Reduced `m_cost` — accept the trade-off |
| Tests | `Argon2Params { m_cost: 8, t_cost: 1, p_cost: 1, output_len: 32 }` |

Reducing any parameter reduces resistance to brute force.

<a href="#top">↑ TOP</a>

#### Choosing a KDF

| Input | Use |
|---|---|
| Master key (32 B+) | [`kdf::hkdf_sha256`](#kdfhkdf_sha256) |
| Diffie-Hellman shared secret | [`kdf::hkdf_sha256`](#kdfhkdf_sha256) |
| Token from a secrets manager | [`kdf::hkdf_sha256`](#kdfhkdf_sha256) |
| Output of another KDF | [`kdf::hkdf_sha256`](#kdfhkdf_sha256) |
| Password from a human | [`kdf::argon2_hash`](#kdfargon2_hash) |
| PIN from a human | [`kdf::argon2_hash_with_params`](#kdfargon2_hash_with_params) (higher cost) |

HKDF and Argon2id are not interchangeable. HKDF is fast and
assumes high-entropy input. Argon2id is deliberately slow and
assumes low-entropy input that needs brute-force resistance.

<a href="#top">↑ TOP</a>

---

### `stream` module

Chunked AEAD for data that doesn't fit in memory. New in 0.7.0.
Uses the [STREAM construction](https://eprint.iacr.org/2015/189.pdf)
to defeat truncation, reordering, and chunk duplication —
properties single-shot AEAD doesn't provide because it has no
concept of chunks.

| Surface              | Purpose                                          |
|----------------------|--------------------------------------------------|
| [`StreamEncryptor`](#streamencryptor) | In-memory streaming encrypt |
| [`StreamDecryptor`](#streamdecryptor) | In-memory streaming decrypt |
| [`encrypt_file`](#streamencrypt_file) | File-to-file encrypt (std-only) |
| [`decrypt_file`](#streamdecrypt_file) | File-to-file decrypt (std-only) |

Wire format documented in [Stream wire format](#stream-wire-format).

<a href="#top">↑ TOP</a>

#### `StreamEncryptor`

```rust
#[cfg(feature = "stream")]
pub struct StreamEncryptor { /* internal */ }

impl StreamEncryptor {
    pub fn new(key: &[u8], algorithm: Algorithm) -> Result<(Self, [u8; 24])>;
    pub fn new_with_chunk_size(
        key: &[u8],
        algorithm: Algorithm,
        chunk_size_log2: u8,
    ) -> Result<(Self, [u8; 24])>;

    pub fn chunk_size(&self) -> usize;
    pub fn chunk_size_log2(&self) -> u8;

    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>>;
    pub fn finalize(self) -> Result<Vec<u8>>;
}
```

Buffers caller-supplied plaintext into fixed-size chunks, encrypts
each chunk with a STREAM-construction nonce, and emits
`ciphertext || tag` per chunk.

**Usage pattern:**

1. Call `new()` (or `new_with_chunk_size()`). The constructor
   returns the encryptor *and* the 24-byte header — write the
   header to the output sink before any encrypted chunks.
2. Feed plaintext via `update()`. Returns zero or more complete
   encrypted chunks (each `chunk_size + 16` bytes) as buffer
   fills are reached.
3. Call `finalize()` to emit any remaining buffered data as the
   final chunk. **Always** emitted (even if zero plaintext bytes
   remain) and **always** strictly smaller than `chunk_size + 16`
   bytes, so the decryptor can detect EOF unambiguously.

**Defaults.** `new()` uses a 64 KiB chunk size
(`DEFAULT_CHUNK_SIZE_LOG2 = 16`). For tuning, `new_with_chunk_size`
accepts `chunk_size_log2` in `MIN_CHUNK_SIZE_LOG2..=MAX_CHUNK_SIZE_LOG2`
(10..=24, i.e., 1 KiB..16 MiB).

**Errors:**

- [`Error::InvalidKey`](#error) — `key` is not 32 bytes.
- [`Error::InvalidCiphertext`](#error) — `chunk_size_log2` out of range.
- [`Error::RandomFailure`](#error) — OS RNG could not produce a nonce prefix.

```rust
# #[cfg(all(feature = "stream", feature = "aead-chacha20"))] {
use crypt_io::Algorithm;
use crypt_io::stream::{StreamEncryptor, StreamDecryptor};

let key = [0u8; 32];
let plaintext = b"the quick brown fox jumps over the lazy dog".repeat(1000);

let (mut enc, header) = StreamEncryptor::new(&key, Algorithm::ChaCha20Poly1305)?;
let mut wire = header.to_vec();
wire.extend(enc.update(&plaintext)?);
wire.extend(enc.finalize()?);

let mut dec = StreamDecryptor::new(&key, &wire[..24])?;
let mut recovered = dec.update(&wire[24..])?;
recovered.extend(dec.finalize()?);
assert_eq!(recovered, plaintext);
# }
# Ok::<(), crypt_io::Error>(())
```

<a href="#top">↑ TOP</a>

#### `StreamDecryptor`

```rust
#[cfg(feature = "stream")]
pub struct StreamDecryptor { /* internal */ }

impl StreamDecryptor {
    pub fn new(key: &[u8], header_bytes: &[u8]) -> Result<Self>;

    pub fn chunk_size(&self) -> usize;
    pub fn chunk_size_log2(&self) -> u8;
    pub fn algorithm(&self) -> Algorithm;

    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>>;
    pub fn finalize(self) -> Result<Vec<u8>>;
}
```

Symmetric inverse of [`StreamEncryptor`](#streamencryptor). Construct
with `new(key, header_bytes)` — parses the header and configures the
decryptor for the embedded algorithm and chunk size. Feed encrypted
bytes via `update()`, call `finalize()` when no more bytes are
coming.

Authentication failures (tampered ciphertext, wrong key, tampered
header, truncation, reordering, chunk duplication) all surface as
[`Error::AuthenticationFailed`](#error) — the variant is
intentionally opaque.

**Errors on `new`:**

- [`Error::InvalidKey`](#error) — `key` is not 32 bytes.
- [`Error::InvalidCiphertext`](#error) — header is malformed
  (wrong magic, unsupported version, unknown algorithm,
  out-of-range chunk size).

**Errors on `update` / `finalize`:**

- [`Error::AuthenticationFailed`](#error) for any cryptographic
  failure.
- [`Error::InvalidCiphertext`](#error) on `finalize` when the
  buffered tail is impossibly small (no room for a 16-byte tag).

<a href="#top">↑ TOP</a>

#### `stream::encrypt_file`

```rust
#[cfg(all(feature = "stream", feature = "std"))]
pub fn encrypt_file(
    input_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    key: &[u8],
    algorithm: Algorithm,
) -> Result<()>;
```

Encrypt `input_path` into `output_path` using the default 64 KiB
chunk size. Overwrites `output_path` if it exists.

**Errors:**

- [`Error::InvalidKey`](#error) — `key` is not 32 bytes.
- [`Error::RandomFailure`](#error) — OS RNG could not produce a nonce.
- [`Error::Mac`](#error) — I/O failure (file open, read, write,
  flush). The variant carries a `&'static str` reason; the
  underlying `std::io::Error` is not surfaced (would risk leaking
  path fragments through error rendering).

```rust,no_run
# #[cfg(all(feature = "stream", feature = "aead-chacha20"))] {
use crypt_io::Algorithm;
use crypt_io::stream;

let key = [0u8; 32];
stream::encrypt_file("input.bin", "output.enc", &key, Algorithm::ChaCha20Poly1305)?;
# }
# Ok::<(), crypt_io::Error>(())
```

<a href="#top">↑ TOP</a>

#### `stream::decrypt_file`

```rust
#[cfg(all(feature = "stream", feature = "std"))]
pub fn decrypt_file(
    input_path: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    key: &[u8],
) -> Result<()>;
```

Decrypt `input_path` into `output_path`. Algorithm is read from the
stream header — no `algorithm` argument required.

> **On error, delete the output file.** `decrypt_file` writes
> plaintext chunks to disk as they verify. If a later chunk fails
> authentication, earlier chunks may already be on disk. **Callers
> must remove the output file when this function returns an error**
> — otherwise an attacker who can flip late chunks could leak
> earlier plaintext to disk.

**Errors:**

- [`Error::InvalidKey`](#error) — `key` is not 32 bytes.
- [`Error::InvalidCiphertext`](#error) — header is malformed or
  the stream is truncated below the minimum frame.
- [`Error::AuthenticationFailed`](#error) — any cryptographic
  failure.
- [`Error::Mac`](#error) — I/O failure.

```rust,no_run
# #[cfg(all(feature = "stream", feature = "aead-chacha20"))] {
use crypt_io::stream;
let key = [0u8; 32];
stream::decrypt_file("input.enc", "output.bin", &key)?;
# }
# Ok::<(), crypt_io::Error>(())
```

<a href="#top">↑ TOP</a>

#### Stream wire format

```text
Header (24 bytes):
   [0..8]   magic = b"\x89CRYPTIO"
   [8]      version = 0x01
   [9]      algorithm (0x00 ChaCha20-Poly1305, 0x01 AES-256-GCM)
   [10]     chunk_size_log2 (default 16 = 64 KiB)
   [11..16] reserved (zero)
   [16..23] nonce_prefix (7 random bytes)
   [23]     reserved (zero)

Body:
   [chunk_0 (chunk_size + 16 B)]    ── non-final, last_flag = 0
   [chunk_1 (chunk_size + 16 B)]    ── non-final, last_flag = 0
   ...
   [chunk_N-1 (chunk_size + 16 B)]  ── non-final, last_flag = 0
   [chunk_N (< chunk_size + 16 B)]  ── final, last_flag = 1

Per-chunk nonce (12 bytes):
   [0..7]   nonce_prefix (from header)
   [7..11]  counter (u32 big-endian, starts at 0)
   [11]     last_flag (0x00 for non-final, 0x01 for final)
```

**Security properties:**

- **Truncation** is detected because the `last_flag` byte is
  part of the per-chunk nonce. A chunk encrypted as non-final
  cannot be verified as final (and vice versa); cut the final
  chunk off the stream and verification fails on the next-to-last.
- **Reorder / duplicate** is detected because the 32-bit counter
  is part of the nonce. Swap or repeat any chunk and the counter
  mismatch breaks verification.
- **Header tampering** (algorithm / chunk-size / nonce prefix) is
  detected because the 24 header bytes are AAD for every chunk.
  Tampering surfaces as authentication failure on the first chunk.

**Final-chunk-always invariant.** The encryptor always emits a
final chunk (even if zero plaintext remains), and that final chunk
is always strictly smaller than `chunk_size + 16` bytes. This makes
EOF detection unambiguous: short read → final chunk; full read →
expect more.

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
    Mac(&'static str),
    Kdf(&'static str),
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

From `crypt_io::mac`:

| Constant | Value | Meaning | Feature |
|---|---|---|---|
| `HMAC_SHA256_OUTPUT_LEN` | `32` | Bytes an HMAC-SHA256 tag occupies. | `mac-hmac` |
| `HMAC_SHA512_OUTPUT_LEN` | `64` | Bytes an HMAC-SHA512 tag occupies. | `mac-hmac` |
| `BLAKE3_MAC_OUTPUT_LEN` | `32` | Bytes a BLAKE3 keyed-mode tag occupies. | `mac-blake3` |
| `BLAKE3_MAC_KEY_LEN` | `32` | Required key length for BLAKE3 keyed mode. | `mac-blake3` |

From `crypt_io::kdf`:

| Constant | Value | Meaning | Feature |
|---|---|---|---|
| `HKDF_MAX_OUTPUT_SHA256` | `8160` | Maximum HKDF-SHA256 output (`255 * 32`). | `kdf-hkdf` |
| `HKDF_MAX_OUTPUT_SHA512` | `16320` | Maximum HKDF-SHA512 output (`255 * 64`). | `kdf-hkdf` |
| `ARGON2_DEFAULT_OUTPUT_LEN` | `32` | Default Argon2id derived-key length. | `kdf-argon2` |
| `ARGON2_DEFAULT_SALT_LEN` | `16` | Default Argon2id salt length (PHC-recommended minimum). | `kdf-argon2` |

From `crypt_io::stream`:

| Constant | Value | Meaning | Feature |
|---|---|---|---|
| `HEADER_LEN` | `24` | Bytes of stream header prepended to every stream. | `stream` |
| `TAG_LEN` | `16` | Bytes of authentication tag per chunk. | `stream` |
| `DEFAULT_CHUNK_SIZE_LOG2` | `16` | Default chunk size (`1 << 16` = 64 KiB). | `stream` |
| `MIN_CHUNK_SIZE_LOG2` | `10` | Smallest chunk size (`1 << 10` = 1 KiB). | `stream` |
| `MAX_CHUNK_SIZE_LOG2` | `24` | Largest chunk size (`1 << 24` = 16 MiB). | `stream` |

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
