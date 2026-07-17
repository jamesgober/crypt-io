<h1 align="center">
    <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg">
    <br>
    <b>crypt-io</b>
    <br>
    <sub>
        <sup>ENCRYPTION SUITE FOR RUST</sup>
    </sub>
</h1> 

<p align="center">
    <a href="https://crates.io/crates/crypt-io"><img src="https://img.shields.io/crates/v/crypt-io.svg" alt="Crates.io"></a>
    <a href="https://crates.io/crates/crypt-io"><img alt="downloads" src="https://img.shields.io/crates/d/crypt-io.svg?color=0099ff"></a>
    <a href="https://docs.rs/crypt-io"><img src="https://docs.rs/crypt-io/badge.svg" alt="Documentation"></a>
    <a href="https://github.com/jamesgober/crypt-io/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/jamesgober/crypt-io/actions/workflows/ci.yml/badge.svg"></a>
    <a href="https://github.com/rust-lang/rfcs/blob/master/text/2495-min-rust-version.md" title="MSRV"><img alt="MSRV" src="https://img.shields.io/badge/MSRV-1.85%2B-blue"></a>
</p>

<p align="center">
    <b>AEAD encryption, hashing, and message authentication for Rust</b>
    <br>
    <i>Algorithm-agile. RustCrypto-backed primitives. Simple API. REPS-disciplined.</i>
</p>

<br>

<p>
    <strong>crypt-io</strong> is a focused encryption library that wraps battle-tested cryptographic primitives (from RustCrypto and the BLAKE3 team) behind a clean, hard-to-misuse API. Built from the ground up with REPS discipline, algorithm agility, and tight portfolio integration (<code>mod-rand</code> for CSPRNG nonces, <code>error-forge</code> for error metadata), it targets the symmetric-crypto needs that <i>most</i> applications actually have: encrypt some data, hash some data, authenticate a tag, derive a key.
</p>

<p>
    Unlike monolithic crypto crates that try to be everything, <strong>crypt-io</strong> stays focused. It does not provide a general-purpose asymmetric suite, PGP, or TLS. Its one public-key boundary is an opt-in, verification-only Ed25519 API for exact pre-authenticated bytes. <strong>crypt-io</strong> keeps the easy path secure: constant-time verification for MACs, fresh nonces per call for AEAD, strict detached-signature verification, redaction-clean errors, and a hash module that deliberately won't let you accidentally use a raw hash as a MAC.
</p>

<hr>

## Installation

```toml
[dependencies]
crypt-io = "1"
```

Or:

```bash
cargo add crypt-io
```

**MSRV:** Rust 1.85 (edition 2024). Older toolchains will not build.

<hr>

## Quick start

### AEAD round-trip

```rust
use crypt_io::Crypt;

let key = [0u8; 32];                  // your 256-bit key
let crypt = Crypt::new();             // ChaCha20-Poly1305 by default

let ciphertext = crypt.encrypt(&key, b"plaintext data")?;
let recovered  = crypt.decrypt(&key, &ciphertext)?;
assert_eq!(&*recovered, b"plaintext data");
# Ok::<(), crypt_io::Error>(())
```

### AES-256-GCM (when you want hardware acceleration)

```rust
use crypt_io::Crypt;

let key = [0u8; 32];
let crypt = Crypt::aes_256_gcm();     // requires `aead-aes-gcm` (default-on)

let ciphertext = crypt.encrypt(&key, b"hello AES")?;
let recovered  = crypt.decrypt(&key, &ciphertext)?;
# Ok::<(), crypt_io::Error>(())
```

### Hashing

```rust
use crypt_io::hash;

let digest = hash::blake3(b"the quick brown fox");   // [u8; 32]
let sha256 = hash::sha256(b"the quick brown fox");   // [u8; 32]
let sha512 = hash::sha512(b"the quick brown fox");   // [u8; 64]
let xof    = hash::blake3_long(b"input", 128);       // Vec<u8>, 128 bytes
```

### MAC with constant-time verify

```rust
use crypt_io::mac;

let key  = b"shared secret";
let data = b"message to authenticate";

let tag = mac::hmac_sha256(key, data)?;
assert!(mac::hmac_sha256_verify(key, data, &tag)?);
// Never `tag == expected_tag` against a secret — use the `*_verify` path.
# Ok::<(), crypt_io::Error>(())
```

BLAKE3 keyed mode — typed key, infallible:

```rust
use crypt_io::mac;

let key = [0x42u8; 32];
let tag = mac::blake3_keyed(&key, b"message");
assert!(mac::blake3_keyed_verify(&key, b"message", &tag));
```

### Streaming (large or chunked inputs)

```rust
use crypt_io::hash::Blake3Hasher;

let mut h = Blake3Hasher::new();
h.update(b"first chunk ");
h.update(b"second chunk");
let digest = h.finalize();
```

### Key derivation

Deriving a subkey from a master:

```rust
use crypt_io::kdf;

let master = [0x42u8; 32];
let session_key = kdf::hkdf_sha256(&master, Some(b"salt"), b"app:session:v1", 32)?;
assert_eq!(session_key.len(), 32);
# Ok::<(), crypt_io::Error>(())
```

Hashing a password (Argon2id, OWASP-recommended defaults):

```rust,no_run
use crypt_io::kdf;

let phc = kdf::argon2_hash(b"correct horse battery staple")?;
assert!(kdf::argon2_verify(&phc, b"correct horse battery staple")?);
# Ok::<(), crypt_io::Error>(())
```

### Encrypt a file

```rust,no_run
use crypt_io::Algorithm;
use crypt_io::stream;

let key = [0u8; 32];
stream::encrypt_file("input.bin", "output.enc", &key, Algorithm::ChaCha20Poly1305)?;
stream::decrypt_file("output.enc", "decrypted.bin", &key)?;
# Ok::<(), crypt_io::Error>(())
```

Chunked AEAD with the STREAM construction — works for files of any size, detects tampering / truncation / reordering. For in-memory streaming (network sockets, buffered I/O), use `StreamEncryptor` / `StreamDecryptor` directly.

See [`docs/API.md`](docs/API.md) for the full reference.

### Authenticated storage formats (opt-in)

The non-default `storage-v1` feature adds a separate storage-engine boundary
without changing the established root API or legacy stream format:

```toml
[dependencies]
crypt-io = { version = "1.1", features = ["storage-v1"] }
```

`crypt_io::storage::RecordCodec` seals bounded records.
`EncryptedStreamCodec` and its incremental reader/writer seal larger snapshots
with authenticated frame chaining and a mandatory final frame. Both formats
bind an opaque storage space, purpose, caller context, and sequence to keys
leased from an application-owned `KeyProvider`; the crate does not store
master keys or own trust policy. Context constructors are fallible and cap
metadata at 64 KiB so hostile input cannot trigger unbounded hashing. See the executable
[`sealed_record`](examples/sealed_record.rs) example and the
[`STORAGE_FORMATS`](docs/STORAGE_FORMATS.md) security and integration contract.

Whole-object freshness remains host-owned. An old valid record or stream is
accepted whenever the host reuses its old expected logical sequence and
context; fresh nonces, AEAD authentication, and key generation do not prevent
rollback. Persist and protect a monotonic object or snapshot sequence, bind it
through `RecordContext` or `StreamContext`, and atomically advance it with the
durable publication of the new object.

The `KeyProvider` mapping is also a durability contract: each
(`KeyScope`, `KeyId`, `KeyGeneration`) tuple must identify exactly one master
secret for as long as any ciphertext may reference it. Never reuse a descriptor
for new key bytes, keep active generations monotonic per scope, and retain
historical mappings until verified migration and reference elimination are
durable. Every same-scope replacement must use independently generated master
material distinct from the source and prior generations. A normal seal
operation cannot detect descriptor reuse, which can make older objects
unrecoverable. Cross-scope migration does not reject equal master material;
whether scopes may share a master key is an explicit host key-policy decision.

### Strict detached Ed25519 verification (opt-in)

The non-default `signature-ed25519` feature verifies a raw 64-byte detached
signature against a raw 32-byte Ed25519 public key and the exact message bytes
supplied by the caller:

```toml
[dependencies]
crypt-io = { version = "1.1", default-features = false, features = ["signature-ed25519"] }
```

```rust
use crypt_io::signature::{
    Ed25519PublicKey, Ed25519Signature, verify_ed25519_detached,
};

# let public_key_bytes = [0_u8; 32];
# let signature_bytes = [0_u8; 64];
# let exact_manifest_bytes = b"example";
let public_key = Ed25519PublicKey::new(public_key_bytes);
let signature = Ed25519Signature::new(signature_bytes);
let result = verify_ed25519_detached(
    &public_key,
    exact_manifest_bytes,
    &signature,
);
# let _ = result;
```

The caller owns trust-root selection, byte canonicalization, format parsing,
and policy. The feature has no signing, key-generation, network, PKCS#8, or
PEM surface and does not require `std`. See
[`SIGNATURES`](docs/SIGNATURES.md) for the full boundary contract.

<hr>

## Design philosophy

**crypt-io** is intentionally focused:

- **One job:** hardened data-protection and verification boundaries. Done well.
- **No reinvention.** Primitives come from RustCrypto and BLAKE3 (battle-tested, widely audited).
- **Simple API.** Encrypt in two lines. Hash in one. The easy path is the secure path.
- **Algorithm agility.** ChaCha20-Poly1305 by default, AES-256-GCM when you want hardware acceleration. Same `Crypt` API either way.
- **Constant-time discipline.** MAC verification uses upstream constant-time comparators, never `==`. Documented in module overviews.
- **Hash ≠ MAC.** `Blake3Hasher` has no `with_key`. The only way to produce a keyed tag is through the `mac` module. This separation is deliberate.
- **Redaction-clean errors.** No variant of `Error` ever contains key material, plaintext, ciphertext, nonces, or tag bytes.
- **REPS-disciplined.** Every commit passes `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all-features`, and `cargo doc` with `-D warnings`.

What we explicitly do NOT do:

- Implement crypto primitives from scratch (use battle-tested upstreams)
- General-purpose asymmetric crypto, signing, or key generation — use a focused crate; `signature-ed25519` is strictly verification-only
- PGP/GPG (use `sequoia-openpgp`)
- TLS (use `rustls`)
- General-purpose random utilities (use `mod-rand`)
- UUID generation (use `id-forge`)
- Key storage (use `key-vault`)

<hr>

## When to use crypt-io

**Good fit:**

- Encrypting data for storage (databases, file systems, caches)
- Encrypting API tokens or session data
- Authenticating messages, audit logs, signed records
- Hashing for integrity checks, fingerprinting, content-addressed storage
- HMAC signatures for outgoing requests (AWS SigV4, JWT HS256/HS512, webhooks)
- Verifying detached Ed25519 signatures over caller-defined exact artifact bytes
- Composing with `key-vault` for in-memory key handling

**Wrong fit:**

- TLS connections — use [`rustls`](https://crates.io/crates/rustls)
- OpenPGP interop — use [`sequoia-openpgp`](https://crates.io/crates/sequoia-openpgp)
- Creating digital signatures or generating key pairs — use [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek)
- Key exchange — use [`x25519-dalek`](https://crates.io/crates/x25519-dalek)
- General-purpose random utilities — use [`mod-rand`](https://crates.io/crates/mod-rand)

<hr>

## Performance

Measured on a reference machine (AMD Ryzen 9 9950X3D, AES-NI + SHA-NI + AVX-512, WSL2 Ubuntu, Rust 1.85.0). Full methodology + per-suite tables in [`docs/PERFORMANCE.md`](docs/PERFORMANCE.md).

| Operation                                    | Target     | Measured   | Status |
|----------------------------------------------|-----------:|-----------:|:---:|
| ChaCha20-Poly1305 encrypt, 1 KiB             | < 2 µs     | 1.72 µs    | ✅ |
| AES-256-GCM encrypt, 1 KiB (HW accel)        | < 1 µs     | 944 ns     | ✅ |
| BLAKE3 hash, 1 KiB                           | < 500 ns   | 1.07 µs    | ⚠️ revised |
| BLAKE3 hash, 64 KiB                          | —          | 11.24 GiB/s| ✅ |
| SHA-256 hash, 1 KiB (SHA-NI)                 | < 2 µs     | 426 ns     | ✅ |
| HMAC-SHA256, 1 KiB                           | < 3 µs     | 565 ns     | ✅ |
| HKDF-SHA256, 32-byte output                  | < 5 µs     | 304 ns     | ✅ |
| Argon2id, default params                     | ~100 ms    | ~9 ms (Zen 5 too fast — tune `t_cost`) | ⚠️ |
| Stream encrypt, 1 MiB plaintext              | > 1 GiB/s  | 932-999 MiB/s | ⚠️ marginal |

Reproduce: `cargo bench --all-features` (numbers vary by hardware — see PERFORMANCE.md for the portable analysis).

<hr>

## Documentation

- [`docs/API.md`](docs/API.md) — complete public-API reference.
- [`docs/STABILITY-1.0.md`](docs/STABILITY-1.0.md) — what the 1.0 contract freezes, the MSRV policy, what can change in 1.x vs 2.0.
- [`docs/SECURITY.md`](docs/SECURITY.md) — threat model, algorithm rationale, vulnerability reporting.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — module layout, algorithm dispatch, dependency rationale.
- [`docs/PLATFORM-NOTES.md`](docs/PLATFORM-NOTES.md) — hardware acceleration per platform + cross-compile guide.
- [`docs/PERFORMANCE.md`](docs/PERFORMANCE.md) — measured throughput, contract-check matrix, parameter-choice guidance.
- [`docs/FILE_FORMAT.md`](docs/FILE_FORMAT.md) — stream wire format spec (frozen for the 1.x series).
- [`docs/STORAGE_FORMATS.md`](docs/STORAGE_FORMATS.md) — opt-in authenticated record/stream formats and integration boundaries.
- [`docs/SIGNATURES.md`](docs/SIGNATURES.md) — verification-only Ed25519 boundary and caller-owned trust policy.
- [`CHANGELOG.md`](CHANGELOG.md) — per-version Added / Changed / Security entries.
- [`docs/release/`](docs/release) — per-release notes (`v0.2.0.md`, `v0.3.0.md`, …, `v1.0.0.md`).
- [`.dev/ROADMAP.md`](.dev/ROADMAP.md) — milestone plan through 1.0 and beyond.

<hr>

## Standards

- **REPS** (Rust Efficiency & Performance Standards) governs every decision. See [`REPS.md`](REPS.md).
- **MSRV:** Rust 1.85.
- **Edition:** 2024.
- **Cross-platform:** Linux, macOS, and Windows on the pinned Rust 1.95.0
  toolchain and Rust 1.85.0 MSRV, plus an Ubuntu forward-compatibility lane on
  Rust 1.97.1.

<hr>

## License

Dual-licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

<!-- FOOT COPYRIGHT
################################################# -->
<div align="center">
  <h2></h2>
  <sup>COPYRIGHT <small>&copy;</small> 2026 <strong>JAMES GOBER.</strong></sup>
</div>
