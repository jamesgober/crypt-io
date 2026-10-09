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
    - [`Crypt::decrypt_zeroizing` (1.1.0)](#cryptdecrypt_zeroizing)
    - [`Crypt::seal` / `open` (sealed format, 1.1.0)](#cryptseal--open)
    - [`generate_key` (1.1.0)](#generate_key)
  - [`Algorithm`](#algorithm)
    - [`Algorithm::name`](#algorithmname)
    - [`Algorithm::key_len`](#algorithmkey_len)
    - [`Algorithm::nonce_len`](#algorithmnonce_len)
    - [`Algorithm::tag_len`](#algorithmtag_len)
  - [Choosing an algorithm](#choosing-an-algorithm)
  - [`hash` module](#hash-module)
    - [`hash::blake3`](#hashblake3)
    - [`hash::blake3_long`](#hashblake3_long) / `blake3_long_into`
    - [`hash::sha256`](#hashsha256)
    - [`hash::sha512`](#hashsha512)
    - [`Blake3Hasher`](#blake3hasher)
    - [`Sha256Hasher`](#sha256hasher)
    - [`Sha512Hasher`](#sha512hasher)
    - [Choosing a hash](#choosing-a-hash)
  - [`mac` module](#mac-module)
    - [`mac::hmac_sha256`](#machmac_sha256)
    - [`mac::hmac_sha256_check`](#machmac_sha256_check)
    - [`mac::hmac_sha512`](#machmac_sha512)
    - [`mac::hmac_sha512_check`](#machmac_sha512_check)
    - [`mac::blake3_keyed`](#macblake3_keyed)
    - [`mac::blake3_keyed_check`](#macblake3_keyed_check)
    - [Deprecated `*_verify` functions](#deprecated-_verify-functions)
    - [`HmacSha256`](#hmacsha256)
    - [`HmacSha512`](#hmacsha512)
    - [`Blake3Mac`](#blake3mac)
    - [Choosing a MAC](#choosing-a-mac)
  - [`kdf` module](#kdf-module)
    - [`kdf::hkdf_sha256`](#kdfhkdf_sha256)
    - [`kdf::hkdf_sha512`](#kdfhkdf_sha512)
    - [`kdf::hkdf_sha256_into` / `hkdf_sha512_into`](#kdfhkdf_sha256_into--hkdf_sha512_into)
    - [`kdf::argon2_hash`](#kdfargon2_hash)
    - [`kdf::argon2_hash_with_params`](#kdfargon2_hash_with_params)
    - [`kdf::argon2_check`](#kdfargon2_check)
    - [`Argon2Policy`](#argon2policy)
    - [`kdf::argon2_verify` (deprecated)](#kdfargon2_verify)
    - [`Argon2Params`](#argon2params)
    - [Choosing a KDF](#choosing-a-kdf)
  - [`stream` module](#stream-module)
    - [`StreamEncryptor`](#streamencryptor)
    - [`StreamDecryptor`](#streamdecryptor)
    - [`stream::encrypt_file`](#streamencrypt_file)
    - [`stream::decrypt_file`](#streamdecrypt_file)
    - [`StreamFormat`](#streamformat)
    - [Stream wire format](#stream-wire-format)
  - [`Tag`](#tag)
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
crypt-io = "1.1"
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

Everything below `std` and `zeroize` turns on one part of the
surface. Defaults give the full toolkit.

| Feature | Default | Effect |
|---|---|---|
| `std` | ✅ | Standard library: the file helpers, `mod-rand` as the random source, and the upstream `std` features (runtime SIMD detection in BLAKE3). Off: the crate is `no_std` + `alloc` (1.1.0; see [`PLATFORM-NOTES.md`](PLATFORM-NOTES.md#no_std-110)). |
| `getrandom` |  | 1.1.0. Use the `getrandom` crate as the random source. Needed for anything that draws randomness (`encrypt*`, `seal*`, `StreamEncryptor::new*`, `argon2_hash*`, `generate_key`) in a `no_std` build; with `std` it replaces `mod-rand`. |
| `zeroize` | ✅ | Wipes the stream types' key copy and buffer on drop, the BLAKE3 keyed MAC state on drop, and `_into` buffers on failure with volatile writes; also enables the upstream `zeroize` support in `aes` (round keys), `aes-gcm`, `sha2` and `hmac` (hash and MAC state), `argon2` and `blake3`. Provides `generate_key`, `decrypt_zeroizing` and the `Zeroizing` re-export. |
| `aead-chacha20` | ✅ | ChaCha20-Poly1305 and XChaCha20-Poly1305 + [`Crypt::new`](#cryptnew). |
| `aead-aes-gcm` | ✅ | AES-256-GCM backend + [`Crypt::aes_256_gcm`](#cryptaes_256_gcm). |
| `aead-all` |  | Both AEADs (already in the 0.3.0+ default). |
| `hash-blake3` | ✅ | BLAKE3 hashing + [`Blake3Hasher`](#blake3hasher) + XOF. |
| `hash-sha2` | ✅ | SHA-256 + SHA-512 hashing + matching streaming hashers. |
| `hash-all` |  | Both hash families (already in the 0.4.0+ default). |
| `mac-hmac` | ✅ | HMAC-SHA256 + HMAC-SHA512 + [`HmacSha256`](#hmacsha256) / [`HmacSha512`](#hmacsha512). |
| `mac-blake3` | ✅ | BLAKE3 keyed mode + [`Blake3Mac`](#blake3mac). |
| `mac-all` |  | Both MAC families (already in the 0.5.0+ default). |
| `kdf-hkdf` | ✅ | [`kdf::hkdf_sha256`](#kdfhkdf_sha256) / [`kdf::hkdf_sha512`](#kdfhkdf_sha512). |
| `kdf-argon2` | ✅ | [`kdf::argon2_hash`](#kdfargon2_hash) / [`kdf::argon2_check`](#kdfargon2_check) / [`Argon2Policy`](#argon2policy) / [`Argon2Params`](#argon2params). |
| `kdf-all` |  | Both KDF families (already in the 0.6.0+ default). |
| `stream` | ✅ | [`StreamEncryptor`](#streamencryptor) / [`StreamDecryptor`](#streamdecryptor) + [`encrypt_file`](#streamencrypt_file) / [`decrypt_file`](#streamdecrypt_file). Pulls both AEAD backends and HKDF-SHA256 (format v2 key schedule). |
| `preset-minimal` |  | `std` + `aead-chacha20` only — the 0.2.0 surface. |
| `preset-all` |  | All planned features enabled. Some are inert until their phase ships. |
| `metrics`, `logging`, `async-trait` |  | Reserved. They enable nothing; 1.0.1 removed the unused dependencies they used to pull in. |

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

**Error behaviour.** `out` is cleared before any check runs, so on
every error (`InvalidKey`, `InvalidCiphertext`,
`AuthenticationFailed`, ...) it is empty; it never hands back a
previous message's plaintext. On `AuthenticationFailed` the whole
allocation (length and spare capacity) is also overwritten with
zeros. If `encrypt_*_into` fails after the plaintext was copied
into `out`, that copy is overwritten too. `out` is not wiped on
success; the plaintext is the caller's to manage.

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

Since 1.1.0, when `decrypt_into` has to grow `out`, it wipes the old
allocation before freeing it (`Vec::reserve` would leave the
previous plaintext in freed memory).

<a href="#top">↑ TOP</a>

#### `Crypt::decrypt_zeroizing`

```rust
#[cfg(feature = "zeroize")]
impl Crypt {
    pub fn decrypt_zeroizing(&self, key: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
    pub fn decrypt_with_aad_zeroizing(&self, key: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
}
```

New in 1.1.0. Same as `decrypt` / `decrypt_with_aad`, but the
plaintext comes back in a `Zeroizing` buffer that is wiped when it
is dropped. The plaintext is written once, into that buffer. Errors
are the same as [`Crypt::decrypt`](#cryptdecrypt).

<a href="#top">↑ TOP</a>

#### `Crypt::seal` / `open`

```rust
impl Crypt {
    pub fn xchacha20_poly1305() -> Crypt;                       // feature aead-chacha20
    pub fn seal(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>>;
    pub fn seal_with_aad(&self, key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;
    pub fn open(&self, key: &[u8], sealed: &[u8]) -> Result<Vec<u8>>;
    pub fn open_with_aad(&self, key: &[u8], sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>>;
    pub fn sealed_algorithm(sealed: &[u8]) -> Result<Algorithm>;
}
```

New in 1.1.0. The **sealed** format records the format version and
the algorithm in front of the 1.0 layout:

```text
0x01 || algorithm (0x00 ChaCha20-Poly1305, 0x01 AES-256-GCM, 0x02 XChaCha20-Poly1305) || nonce || ciphertext || tag
```

Both header bytes are authenticated (they are prepended to the
associated data). `open` takes the algorithm from the header, not
from the handle, so data written under one algorithm stays readable
after you switch, and one store can hold a mix. Use `seal` for new
data unless something else must read the plain
`nonce || ciphertext || tag` layout.

**Errors.** `seal`: as [`Crypt::encrypt`](#cryptencrypt). `open`:
`InvalidCiphertext` for a short buffer or an unknown version or
algorithm byte, `AlgorithmNotEnabled` if that algorithm's feature is
off, otherwise as [`Crypt::decrypt`](#cryptdecrypt).

```rust
# #[cfg(feature = "aead-chacha20")] {
use crypt_io::{Algorithm, Crypt};
let key = [7u8; 32];
let sealed = Crypt::xchacha20_poly1305().seal(&key, b"hi")?;
assert_eq!(Crypt::sealed_algorithm(&sealed)?, Algorithm::XChaCha20Poly1305);
assert_eq!(Crypt::new().open(&key, &sealed)?, b"hi");
# }
# Ok::<(), crypt_io::Error>(())
```

<a href="#top">↑ TOP</a>

#### `generate_key`

```rust
#[cfg(all(feature = "zeroize", any(feature = "std", feature = "getrandom")))]
pub fn generate_key() -> Result<Zeroizing<[u8; 32]>>;
```

New in 1.1.0. 32 bytes from the OS CSPRNG, wiped on drop. Also at
`crypt_io::aead::generate_key`. Errors: `RandomFailure`.

```rust
# #[cfg(feature = "aead-chacha20")] {
let key = crypt_io::generate_key()?;
let ct = crypt_io::Crypt::new().encrypt(&*key, b"hello")?;
# }
# Ok::<(), crypt_io::Error>(())
```

<a href="#top">↑ TOP</a>

---

### `Algorithm`

```rust
#[non_exhaustive]
pub enum Algorithm {
    ChaCha20Poly1305,
    Aes256Gcm,
    XChaCha20Poly1305,   // 1.1.0
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

Human-readable name: `"ChaCha20-Poly1305"`, `"AES-256-GCM"` or
`"XChaCha20-Poly1305"`.

#### `Algorithm::key_len`

```rust
pub const fn key_len(self) -> usize;
```

Required key length in bytes. Returns `32` for every algorithm.

#### `Algorithm::nonce_len`

```rust
pub const fn nonce_len(self) -> usize;
```

Nonce length in bytes that the algorithm consumes: `12` for
`ChaCha20Poly1305` and `Aes256Gcm`, `24` for `XChaCha20Poly1305`.

#### `Algorithm::tag_len`

```rust
pub const fn tag_len(self) -> usize;
```

Authentication tag length in bytes the algorithm produces. Returns
`16` for every algorithm.

<a href="#top">↑ TOP</a>

---

### Choosing an algorithm

All three algorithms are safe at 256-bit symmetric strength. The
choice is about hardware utilisation, interop and message volume,
not about cryptographic strength.

| You want… | Pick |
|---|---|
| The safe default with no thinking required | `ChaCha20Poly1305` |
| Maximum throughput on AES-NI / ARMv8 hardware | `Aes256Gcm` |
| Interop with TLS, JWE A256GCM, FIPS-spec'd protocols | `Aes256Gcm` |
| A target without hardware AES (older ARM, embedded, RISC-V) | `ChaCha20Poly1305` |
| More than 2^32 messages under one key | `XChaCha20Poly1305` |
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

`blake3_long_into(data: &[u8], out: &mut [u8])` (1.1.0) writes the
same output into a buffer you own, for when the XOF output is key
material.

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
> For **MAC tags** specifically, use the [`mac`](#mac-module)
> module's `*_check` functions, which wrap the constant-time
> comparator and treat wrong-length tags as mismatches, or wrap the
> value in [`Tag`](#tag).

<a href="#top">↑ TOP</a>

---

### `mac` module

Message Authentication Codes. Three algorithms with a consistent
compute / check / streaming triad — and checking is **always**
constant-time, by design.

| Algorithm        | Compute                          | Check (1.1.0)                           | Streaming       | Tag    | Feature       |
|------------------|----------------------------------|-----------------------------------------|-----------------|--------|---------------|
| HMAC-SHA256      | [`mac::hmac_sha256`](#machmac_sha256) | [`mac::hmac_sha256_check`](#machmac_sha256_check) | [`HmacSha256`](#hmacsha256) | 32 B | `mac-hmac`   |
| HMAC-SHA512      | [`mac::hmac_sha512`](#machmac_sha512) | [`mac::hmac_sha512_check`](#machmac_sha512_check) | [`HmacSha512`](#hmacsha512) | 64 B | `mac-hmac`   |
| BLAKE3 keyed     | [`mac::blake3_keyed`](#macblake3_keyed) | [`mac::blake3_keyed_check`](#macblake3_keyed_check) | [`Blake3Mac`](#blake3mac) | 32 B | `mac-blake3` |

> **Check, don't `==`.** Comparing two MAC tags with `==` on arrays
> leaks how many leading bytes matched via timing — that leak is
> enough to forge tags one byte at a time. The `*_check` functions
> and the streaming types' `check` / `verify` methods all use
> constant-time comparators, and so does `==` on [`Tag`](#tag).

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

#### `mac::hmac_sha256_check`

```rust
#[cfg(feature = "mac-hmac")]
pub fn hmac_sha256_check(key: &[u8], data: &[u8], expected_tag: &[u8]) -> Result<()>;
```

New in 1.1.0. Constant-time check of an HMAC-SHA256 tag. Computes
the tag for `(key, data)` and compares it to `expected_tag` via the
`hmac` crate's `verify_slice` (which routes through `subtle`).
Returns `Ok(())` on a match and `Err(AuthenticationFailed)`
otherwise, including when `expected_tag` is the wrong length — so
`hmac_sha256_check(..)?;` rejects forged tags.

**Errors.** [`Error::AuthenticationFailed`](#error) on a mismatch;
[`Error::Mac`](#error) as for [`mac::hmac_sha256`](#machmac_sha256).

```rust
# #[cfg(feature = "mac-hmac")] {
use crypt_io::{mac, Error};
let key = b"shared";
let tag = mac::hmac_sha256(key, b"data")?;
mac::hmac_sha256_check(key, b"data", &tag)?;
assert_eq!(mac::hmac_sha256_check(key, b"tampered", &tag), Err(Error::AuthenticationFailed));
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

#### `mac::hmac_sha512_check`

```rust
#[cfg(feature = "mac-hmac")]
pub fn hmac_sha512_check(key: &[u8], data: &[u8], expected_tag: &[u8]) -> Result<()>;
```

New in 1.1.0. Same as [`mac::hmac_sha256_check`](#machmac_sha256_check)
for HMAC-SHA512.

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

#### `mac::blake3_keyed_check`

```rust
#[cfg(feature = "mac-blake3")]
pub fn blake3_keyed_check(key: &[u8; 32], data: &[u8], expected_tag: &[u8]) -> Result<()>;
```

New in 1.1.0. Constant-time check of a BLAKE3 keyed-mode tag via
BLAKE3's `Hash::eq`. `Err(AuthenticationFailed)` on a mismatch,
including a tag that is not 32 bytes long.

```rust
# #[cfg(feature = "mac-blake3")] {
use crypt_io::mac;
let key = [0x42u8; 32];
let tag = mac::blake3_keyed(&key, b"message");
mac::blake3_keyed_check(&key, b"message", &tag)?;
assert!(mac::blake3_keyed_check(&key, b"tampered", &tag).is_err());
# }
# Ok::<(), crypt_io::Error>(())
```

<a href="#top">↑ TOP</a>

#### Deprecated `*_verify` functions

```rust
#[deprecated(since = "1.1.0")] pub fn hmac_sha256_verify(key: &[u8], data: &[u8], expected_tag: &[u8]) -> Result<bool>;
#[deprecated(since = "1.1.0")] pub fn hmac_sha512_verify(key: &[u8], data: &[u8], expected_tag: &[u8]) -> Result<bool>;
#[deprecated(since = "1.1.0")] pub fn blake3_keyed_verify(key: &[u8; 32], data: &[u8], expected_tag: &[u8]) -> bool;
```

Still available for all of 1.x, and still constant-time. They report
a mismatch as `Ok(false)` / `false`, so `hmac_sha256_verify(..)?;`
compiles and accepts every tag, forged or not. Replace them with the
`*_check` functions; if you keep them, always write
`if !mac::hmac_sha256_verify(..)? { /* reject */ }`.

<a href="#top">↑ TOP</a>

#### `HmacSha256`

```rust
#[cfg(feature = "mac-hmac")]
pub struct HmacSha256 { /* internal */ }

impl HmacSha256 {
    pub fn new(key: &[u8]) -> Result<Self>;
    pub fn update(&mut self, data: &[u8]) -> &mut Self;
    pub fn finalize(self) -> [u8; 32];
    pub fn check(self, expected_tag: &[u8]) -> Result<()>;   // 1.1.0
    pub fn verify(self, expected_tag: &[u8]) -> bool;
}
```

Streaming HMAC-SHA256. `update` is chainable; finalisation consumes
the hasher and returns the 32-byte tag (`finalize`), or compares it
in constant time against an expected tag (`check`, which returns
`Err(AuthenticationFailed)` on a mismatch, or `verify`, which returns
`bool`). With `zeroize`, the HMAC state is wiped on drop (1.1.0).

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
    pub fn check(self, expected_tag: &[u8]) -> Result<()>;   // 1.1.0
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

> **Use the `check` paths.** Never compare a computed tag to an
> expected tag with `==` on arrays. The non-constant-time leak is enough to
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

#### `kdf::hkdf_sha256_into` / `hkdf_sha512_into`

```rust
#[cfg(feature = "kdf-hkdf")]
pub fn hkdf_sha256_into(ikm: &[u8], salt: Option<&[u8]>, info: &[u8], out: &mut [u8]) -> Result<()>;
pub fn hkdf_sha512_into(ikm: &[u8], salt: Option<&[u8]>, info: &[u8], out: &mut [u8]) -> Result<()>;
```

New in 1.1.0. Same derivation as `hkdf_sha256` / `hkdf_sha512`, but
written into `out` (its length is the output length). Use them for
key material: derive straight into a `[u8; 32]` or a `Zeroizing`
buffer and no unwiped copy is left on the heap. Errors: `Kdf` if
`out` is longer than `255 * HashLen`.

```rust
# #[cfg(feature = "kdf-hkdf")] {
let mut subkey = [0u8; 32];
crypt_io::kdf::hkdf_sha256_into(&[0x42; 32], Some(b"salt"), b"app:v1", &mut subkey)?;
# }
# Ok::<(), crypt_io::Error>(())
```

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

#### `kdf::argon2_check`

```rust
#[cfg(feature = "kdf-argon2")]
pub fn argon2_check(phc: &str, password: &[u8]) -> Result<()>;
pub fn argon2_check_with_policy(phc: &str, password: &[u8], policy: &Argon2Policy) -> Result<()>;
```

New in 1.1.0. Check `password` against a PHC-encoded Argon2 hash.
`Ok(())` on a match, `Err(AuthenticationFailed)` on a wrong password,
so `argon2_check(..)?;` rejects it.

The cost parameters come from the PHC string, so before any work
the string is checked against a policy: [`Argon2Policy::new()`](#argon2policy)
for `argon2_check` (`argon2id` only, `m` at most 1 GiB, `t` at most
64, `p` at most 16 — the 1.0.1 limits), or the one you pass to
`argon2_check_with_policy`. crypt-io has only ever produced
`$argon2id$v=19$` strings.

Verification re-derives the hash under the parameters encoded in
`phc` and compares in constant time. Cost is the same as computing
a fresh hash with those parameters (~100 ms with the defaults).

**Errors.**

- [`Error::AuthenticationFailed`](#error) — wrong password (log as
  `warn`: an attacker or a typo).
- [`Error::Kdf`](#error) — `phc` does not parse, names a variant
  the policy does not allow, or has costs outside it (log as
  `error`: corruption or a bug).

```rust
# #[cfg(feature = "kdf-argon2")] {
use crypt_io::{kdf, Error};
let phc = kdf::argon2_hash(b"hunter2")?;
kdf::argon2_check(&phc, b"hunter2")?;
assert_eq!(kdf::argon2_check(&phc, b"hunter3"), Err(Error::AuthenticationFailed));
# }
# Ok::<(), crypt_io::Error>(())
```

<a href="#top">↑ TOP</a>

#### `Argon2Policy`

```rust
#[cfg(feature = "kdf-argon2")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Policy { /* private */ }

impl Argon2Policy {
    pub const fn new() -> Self;                                   // = Default
    pub const fn with_max_cost(self, m_cost: u32, t_cost: u32, p_cost: u32) -> Self;
    pub const fn with_min_cost(self, m_cost: u32, t_cost: u32) -> Self;
    pub const fn allow_argon2i(self, allow: bool) -> Self;
    pub const fn allow_argon2d(self, allow: bool) -> Self;
    // getters: max_m_cost, max_t_cost, max_p_cost, min_m_cost, min_t_cost,
    //          argon2i_allowed, argon2d_allowed
}

pub fn argon2_hash_with_policy(password: &[u8], params: Argon2Params, policy: &Argon2Policy) -> Result<String>;
```

New in 1.1.0. What to accept when checking (and hashing). Defaults:
`argon2id` only, `m` up to 1 GiB, `t` up to 64, `p` up to 16, no
minimums.

- **Raise the caps** if you stored hashes with higher costs before
  1.0.1 introduced them (1.0.1 rejects those with `Error::Kdf`), or
  want to hash above them with `argon2_hash_with_policy`.
- **Set minimums** so a cheap hash planted in your store is
  rejected.
- **Allow `argon2i` / `argon2d`** only to migrate existing hashes.

```rust
# #[cfg(feature = "kdf-argon2")] {
use crypt_io::kdf::{self, Argon2Policy};
let legacy = Argon2Policy::new().with_max_cost(4 * 1024 * 1024, 64, 16); // 4 GiB
let strict = Argon2Policy::new().with_min_cost(19 * 1024, 2);
# let phc = kdf::argon2_hash(b"pw")?;
kdf::argon2_check_with_policy(&phc, b"pw", &strict)?;
# let _ = legacy;
# }
# Ok::<(), crypt_io::Error>(())
```

<a href="#top">↑ TOP</a>

#### `kdf::argon2_verify`

```rust
#[cfg(feature = "kdf-argon2")]
#[deprecated(since = "1.1.0")]
pub fn argon2_verify(phc: &str, password: &[u8]) -> Result<bool>;
```

Deprecated in 1.1.0; use [`kdf::argon2_check`](#kdfargon2_check).
Same checks, but a wrong password is `Ok(false)`, so
`kdf::argon2_verify(&phc, pw)?;` on its own logs everyone in. If you
keep it, always write `if !kdf::argon2_verify(&phc, pw)? { /* reject */ }`.

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
    pub fn validate(&self) -> Result<()>;   // 1.1.0
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

**`validate()`** (1.1.0) checks custom values: Argon2 accepts them,
`output_len` is at least 16, they meet one of the OWASP minimums for
Argon2id (`m_cost` ≥ 47,104 KiB with `t_cost` 1, 19,456 with 2,
12,288 with 3, 9,216 with 4, 7,168 with 5+), and they are within the
default `Argon2Policy` caps. `argon2_hash_with_params` does not call
it (tests use tiny parameters); call it on values that come from
configuration.

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

> **Formats.** 1.1.0 writes stream format **v2** by default: each
> stream starts with a 32-byte random salt and is encrypted under its
> own HKDF-SHA256 subkey, so one key can encrypt any number of
> streams. Format **v1** (1.0.x) used a random 56-bit nonce prefix
> directly under the caller's key and is limited to about 2^12
> streams per key. 1.1 reads both; 1.0.x cannot read v2, so write v1
> with [`StreamFormat::V1`](#streamformat) while 1.0.x readers
> remain.

`StreamEncryptor` and `StreamDecryptor` overwrite their key copy and
internal buffer on drop, and their `Debug` output shows only the
algorithm, chunk size, counter and buffered length.

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

    pub fn new_with_format(                      // 1.1.0
        key: &[u8],
        algorithm: Algorithm,
        chunk_size_log2: u8,
        format: StreamFormat,
    ) -> Result<(Self, [u8; 24])>;

    pub fn chunk_size(&self) -> usize;
    pub fn chunk_size_log2(&self) -> u8;
    pub fn algorithm(&self) -> Algorithm;        // 1.1.0
    pub fn format(&self) -> StreamFormat;        // 1.1.0

    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>>;
    pub fn finalize(self) -> Result<Vec<u8>>;
    pub fn update_into(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<()>;
    pub fn finalize_into(self, out: &mut Vec<u8>) -> Result<()>;
}
```

`new` and `new_with_chunk_size` write format v2. The constructors
need a random source (`std` or `getrandom`).

Buffers caller-supplied plaintext into fixed-size chunks, encrypts
each chunk with a STREAM-construction nonce, and emits
`ciphertext || tag` per chunk.

**Usage pattern:**

1. Call `new()` (or `new_with_chunk_size()`). The constructor
   returns the encryptor *and* the 24-byte header — write the
   header to the output sink before any encrypted chunks.
2. Feed plaintext via `update()`. Returns zero or more complete
   encrypted chunks (each `chunk_size + 16` bytes) as buffer
   fills are reached. In v2 the first output (of `update`,
   `update_into`, `finalize` or `finalize_into`) starts with the
   32-byte salt; write every output to the sink in order.
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
- [`Error::InvalidInput`](#error) — `chunk_size_log2` out of range, or
  `StreamFormat::V1` with XChaCha20-Poly1305 (1.0.x returned
  `InvalidCiphertext` for the chunk size).
- [`Error::RandomFailure`](#error) — OS RNG could not produce the salt
  (v2) or nonce prefix (v1).
- [`Error::LimitExceeded`](#error) — from `update` / `finalize`, once a
  stream reaches 2^32 chunks.

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
    pub fn format(&self) -> StreamFormat;        // 1.1.0

    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>>;
    pub fn finalize(self) -> Result<Vec<u8>>;
    pub fn update_into(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<()>;
    pub fn finalize_into(self, out: &mut Vec<u8>) -> Result<()>;
}
```

Reads both stream formats; works without `std` or a random source.
Pass the first 24 bytes to `new` and everything after them (the v2
salt included) to `update`. Symmetric inverse of [`StreamEncryptor`](#streamencryptor). Construct
with `new(key, header_bytes)` — parses the header and configures the
decryptor for the embedded algorithm and chunk size. Feed encrypted
bytes via `update()`, call `finalize()` when no more bytes are
coming.

Authentication failures (tampered ciphertext, wrong key, tampered
header, truncation, reordering, chunk duplication) all surface as
[`Error::AuthenticationFailed`](#error) — the variant is
intentionally opaque.

> **`update` output is not end-authenticated.** Each chunk `update`
> returns has passed its own tag check, but a stream truncated at a
> chunk boundary is only detected by `finalize`. Do not act on the
> output until `finalize` returns `Ok`; on error, discard everything
> the decryptor produced.

`update` is linear in the input size (1.0.0 was quadratic when a
large input was fed in one call). On error, `update_into` wipes
whatever it appended and leaves `out` as it was on entry.

**Errors on `new`:**

- [`Error::InvalidKey`](#error) — `key` is not 32 bytes.
- [`Error::InvalidCiphertext`](#error) — header is malformed
  (wrong magic, unsupported version, unknown algorithm,
  out-of-range chunk size, non-zero reserved bytes in v2).

**Errors on `update` / `finalize`:**

- [`Error::AuthenticationFailed`](#error) for any cryptographic
  failure.
- [`Error::InvalidCiphertext`](#error) on `finalize` when the
  buffered tail is impossibly small (no room for a 16-byte tag), or
  a v2 stream ended inside its salt.

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
chunk size and stream format v2 (one subkey per file). Overwrites
`output_path` if it exists. Rejects (with `Error::InvalidInput`) an
`output_path` that names the same file as `input_path`; 1.0.0
truncated the input instead.

**Errors:**

- [`Error::InvalidKey`](#error) — `key` is not 32 bytes.
- [`Error::RandomFailure`](#error) — OS RNG could not produce the salt.
- [`Error::Io`](#error) — I/O failure (file open, read, write,
  flush). The variant carries a `&'static str` naming the step; the
  underlying `std::io::Error` is not surfaced (would risk leaking
  path fragments through error rendering). 1.0.x used `Error::Mac`.
- [`Error::InvalidInput`](#error) — input and output are the same
  file.

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

Since 1.0.1, plaintext only reaches `output_path` after the whole
stream has been authenticated. It is written to a new temporary file
in the same directory (created exclusively, mode `0600` on Unix),
which is flushed, `fsync`ed and renamed over `output_path` once the
final chunk verifies. On any error the temporary file is overwritten
and deleted, and `output_path` is left untouched. On Unix the
decrypted file therefore has mode `0600`. An `output_path` that names
the same file as `input_path` is rejected with `Error::InvalidInput`.
Both stream formats are accepted.

**Errors:**

- [`Error::InvalidKey`](#error) — `key` is not 32 bytes.
- [`Error::InvalidCiphertext`](#error) — header is malformed or
  the stream is truncated below the minimum frame.
- [`Error::AuthenticationFailed`](#error) — any cryptographic
  failure.
- [`Error::Io`](#error) — I/O failure (1.0.x: `Error::Mac`).
- [`Error::InvalidInput`](#error) — input and output are the same
  file.

```rust,no_run
# #[cfg(all(feature = "stream", feature = "aead-chacha20"))] {
use crypt_io::stream;
let key = [0u8; 32];
stream::decrypt_file("input.enc", "output.bin", &key)?;
# }
# Ok::<(), crypt_io::Error>(())
```

<a href="#top">↑ TOP</a>

#### `StreamFormat`

```rust
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum StreamFormat {
    V1,
    #[default]
    V2,
}

impl StreamFormat {
    pub const fn version_byte(self) -> u8;   // 0x01 / 0x02
}
```

New in 1.1.0. The stream format an encryptor writes; decryptors read
the version from the header. `V2` (default) derives a subkey per
stream from a 32-byte salt. `V1` is the 1.0 format, for fleets that
still have 1.0.x readers; it supports ChaCha20-Poly1305 and
AES-256-GCM only.

<a href="#top">↑ TOP</a>

#### Stream wire format

```text
Header (24 bytes, both versions):
   [0..8]   magic = b"\x89CRYPTIO"
   [8]      version = 0x02 (v2) or 0x01 (v1)
   [9]      algorithm (0x00 ChaCha20-Poly1305, 0x01 AES-256-GCM, 0x02 XChaCha20-Poly1305 [v2 only])
   [10]     chunk_size_log2 (default 16 = 64 KiB)
   [11..24] v2: reserved, must be zero
            v1: [11..16] reserved, [16..23] nonce_prefix (7 random bytes), [23] reserved

v2 only: salt (32 random bytes), then
   okm = HKDF-SHA256(ikm = key, salt, info = "crypt-io stream v2" || header, 32 + P)
   subkey = okm[0..32], nonce_prefix = okm[32..32 + P], P = nonce_len - 5

Body:
   [chunk_0 (chunk_size + 16 B)]    ── non-final, last_flag = 0
   ...
   [chunk_N (< chunk_size + 16 B)]  ── final, last_flag = 1

Per-chunk nonce (12 bytes; 24 for XChaCha20-Poly1305):
   nonce_prefix (P bytes) || counter (u32 big-endian) || last_flag
AAD: header || salt (v2), header (v1)
```

Full specification and test vectors: [`FILE_FORMAT.md`](FILE_FORMAT.md).

**Security properties:**

- **Truncation** is detected because the `last_flag` byte is
  part of the per-chunk nonce.
- **Reorder / duplicate** is detected because the 32-bit counter
  is part of the nonce.
- **Header and salt tampering** is detected because those bytes
  are AAD for every chunk (and in v2 feed the subkey).
- **Nonce reuse across streams** (v2) is ruled out by the
  per-stream subkey.

**Final-chunk-always invariant.** The encryptor always emits a
final chunk (even if zero plaintext remains), and that final chunk
is always strictly smaller than `chunk_size + 16` bytes. This makes
EOF detection unambiguous: short read → final chunk; full read →
expect more.

<a href="#top">↑ TOP</a>

---

### `Tag`

```rust
#[derive(Clone, Copy)]
pub struct Tag<const N: usize>(/* [u8; N] */);

impl<const N: usize> Tag<N> {
    pub const fn new(bytes: [u8; N]) -> Self;
    pub const fn as_bytes(&self) -> &[u8; N];
    pub const fn into_bytes(self) -> [u8; N];
    pub fn ct_eq(&self, other: &[u8]) -> bool;
}
// From<[u8; N]>, TryFrom<&[u8]>, AsRef<[u8]>, Debug (hex),
// PartialEq / Eq with Tag<N>, [u8; N], [u8] and &[u8] — all constant-time.
```

New in 1.1.0. Wrap a computed tag in `Tag` and `==` becomes a
constant-time comparison (`subtle`). A slice of a different length
compares unequal. `Tag` does not implement `Deref`, `Ord` or `Hash`,
so it cannot be compared in variable time by accident.

```rust
# #[cfg(feature = "mac-hmac")] {
use crypt_io::{mac, Tag};
let received = mac::hmac_sha256(b"k", b"body")?;     // from the wire
let expected = Tag::from(mac::hmac_sha256(b"k", b"body")?);
assert!(expected == received);
# }
# Ok::<(), crypt_io::Error>(())
```

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
    Io(&'static str),             // 1.1.0
    InvalidInput(&'static str),   // 1.1.0
    LimitExceeded(&'static str),  // 1.1.0
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

Implements `Debug + Clone + PartialEq + Eq + Display` and
`core::error::Error` (the same trait as `std::error::Error`; since
1.1.0 also in `no_std` builds).

**Moved to the new variants in 1.1.0** (call sites that matched the
old variant for these cases need updating):

| Case | 1.0.x | 1.1.0 |
|---|---|---|
| File-helper I/O failure | `Mac("stream: ...")` | `Io("stream: ...")` |
| Same file as input and output | `Mac(..)` | `InvalidInput(..)` |
| Stream chunk size out of range (encrypt) | `InvalidCiphertext(..)` | `InvalidInput(..)` |
| Plaintext / AAD longer than the cipher allows | `AuthenticationFailed` | `LimitExceeded(..)` |
| Stream longer than 2^32 chunks (encrypt) | `InvalidCiphertext(..)` | `LimitExceeded(..)` |

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
| `XCHACHA20_NONCE_LEN` | `24` | Bytes of nonce XChaCha20-Poly1305 consumes (1.1.0). |
| `XCHACHA20_TAG_LEN` | `16` | Bytes of authentication tag XChaCha20-Poly1305 produces (1.1.0). |
| `KEY_LEN` | `32` | Required key length for every AEAD. |
| `SEALED_HEADER_LEN` | `2` | Header bytes of the sealed format (1.1.0). |
| `SEALED_VERSION` | `0x01` | Version byte of the sealed format (1.1.0). |

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
| `SALT_LEN` | `32` | Bytes of salt after a v2 header (1.1.0). | `stream` |
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

Total size: `plaintext.len() + 28` bytes (`+ 40` for
XChaCha20-Poly1305, whose nonce is 24 bytes). The sealed format of
`seal` / `open` adds two header bytes in front:
`0x01 || algorithm || nonce || ciphertext || tag`. The nonce is generated
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
- **`Mac`** / **`Kdf`** — MAC setup failure (unreachable in
  practice) / KDF parameter, PHC or policy failure.
- **`Io`** *(1.1.0)* — file-helper I/O failure.
- **`InvalidInput`** *(1.1.0)* — an argument the call cannot accept.
- **`LimitExceeded`** *(1.1.0)* — an encrypt-side size limit; not a
  sign of tampering.

<a href="#top">↑ TOP</a>

<hr>

## Notes

- **Nonces are random, so they can collide.** Every
  `encrypt` / `encrypt_with_aad` call draws a fresh random 12-byte
  nonce; there is no caller-supplied-nonce surface. Random nonces
  collide with probability about `n^2 / 2^97` after `n` messages
  under one key, and one collision is catastrophic for AES-256-GCM.
- **Limit each key to 2^32 single-shot ChaCha20-Poly1305 /
  AES-256-GCM encryptions** (the NIST SP 800-38D cap for random
  96-bit IVs; collision probability about 2^-33). `2^48` messages is
  not a safe limit: it is where a collision becomes likely (about
  39%). crypt-io does not count messages; use XChaCha20-Poly1305,
  rotate keys or derive subkeys with HKDF before that.
- **Streams:** format v2 (default) has no practical streams-per-key
  limit; format v1 is limited to about 2^12 streams per key (see the
  [`stream` module](#stream-module) note).
- **Constant-time tag verification** is preserved by deferring to
  the upstream AEAD crates; no equality comparisons on tag bytes
  happen in this wrapper.
- **Plaintext is a plain `Vec<u8>`** from `decrypt`, `open`,
  `hkdf_*` and the stream decryptor. Use `decrypt_zeroizing`,
  `hkdf_*_into`, `blake3_long_into` or the stream `_into` methods
  when the bytes are secret, or compose with `key-vault` for
  production key handling. Since 1.1.0 the HMAC state and the AES
  round keys are wiped on drop (with `zeroize`); the GHASH key
  inside `polyval` 0.6 is not (see `SECURITY.md`).
- **AES-256-GCM ships in 0.3.0** with NIST SP 800-38D vectors and
  hardware-acceleration verification (AES-NI on x86, crypto
  extensions on ARM).

<a href="#top">↑ TOP</a>

<hr>

<sub>crypt-io API reference — Copyright (c) 2026 James Gober. Apache-2.0 OR MIT.</sub>
