<h1 align="center" id="top">
  <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/coll-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg"><br>
  <b>crypt-io</b>
  <br><sub><sup>PLATFORM NOTES</sup></sub>
</h1>

<p align="center">
    <i>Hardware-acceleration availability, OS specifics, cross-
    compile notes, and which algorithm to pick on which platform.</i>
</p>

<hr>

## Supported platforms

`crypt-io` builds and tests on:

| OS | Architectures | CI matrix |
|---|---|---|
| Linux | x86_64, aarch64 | ubuntu-latest × stable + 1.85 (MSRV) |
| macOS | x86_64, aarch64 | macos-latest × stable + 1.85 |
| Windows | x86_64 | windows-latest × stable + 1.85 |

WSL2 is the canonical pre-CI gate (matches the Linux CI
environment). All 0.x and 1.0 releases pass `cargo fmt` +
`cargo clippy --all-features` + `cargo test --all-features` +
`cargo doc --all-features` on every cell of the matrix.

<hr>

## Hardware acceleration

### AEAD

| Platform | AES-256-GCM | ChaCha20-Poly1305 |
|---|---|---|
| x86_64 with AES-NI + CLMUL (Intel ≥ ~2010, AMD Bulldozer+) | **hardware** | software (AVX2 / AVX-512 when present) |
| x86_64 without AES-NI (very old / very embedded) | software (constant-time) | software |
| aarch64 with ARMv8 crypto extensions (Apple Silicon, Graviton 2+) | **hardware** | software (NEON) |
| aarch64 without crypto extensions (older Cortex-A, RPi 3) | software (constant-time) | software |

The `aes-gcm` crate detects AES-NI / ARMv8 at runtime and
dispatches automatically — no consumer-side flags required.
ChaCha20-Poly1305 doesn't have a dedicated instruction; its
SIMD speedup comes from AVX2 / AVX-512 (`chacha20` crate) and
NEON, also auto-detected.

### Hashing

| Platform | SHA-256 / SHA-512 | BLAKE3 |
|---|---|---|
| x86_64 with SHA-NI (Intel Ice Lake+, AMD Zen 3+) | **hardware (SHA-256 only)** | SIMD (AVX2/AVX-512) |
| x86_64 without SHA-NI | software | SIMD |
| aarch64 with crypto extensions | **hardware (SHA-256 only)** | NEON |
| aarch64 without crypto extensions | software | NEON |

SHA-NI accelerates **SHA-256 only**, not SHA-512. On a SHA-NI
host SHA-256 lands at ~2.5 GiB/s on the reference machine; on
an older Xeon without SHA-NI it'd be ~700 MiB/s.

BLAKE3 saturates AVX-512 at ~11+ GiB/s on Zen 5 / Sapphire
Rapids. On NEON-only ARM it's still ~3-5 GiB/s, well above
SHA-2's pace there.

### MAC

HMAC-SHA256 inherits SHA-256's acceleration story (SHA-NI helps).
BLAKE3 keyed inherits BLAKE3's (SIMD everywhere).

### KDF

HKDF inherits the underlying hash's acceleration. Argon2id's
memory-bound work doesn't benefit from crypto instructions — its
speed is dominated by memory bandwidth and the parallelism
parameter (`p_cost`).

<hr>

## Pick-by-platform cheatsheet

If you control both sides of the wire and just want the fast path:

| You're on… | AEAD | Hash | MAC |
|---|---|---|---|
| Modern Intel/AMD server (AES-NI + SHA-NI) | `Aes256Gcm` | `BLAKE3` ≥ 4 KiB / `SHA-256` < 4 KiB | `BLAKE3 keyed` |
| Modern Intel/AMD server (AES-NI, no SHA-NI) | `Aes256Gcm` | `BLAKE3` | `BLAKE3 keyed` |
| Modern Apple Silicon / Graviton 3+ | `Aes256Gcm` | `BLAKE3` | `BLAKE3 keyed` |
| Older ARM / embedded (no crypto extensions) | `ChaCha20Poly1305` | `BLAKE3` | `BLAKE3 keyed` |
| RISC-V (no AES instructions) | `ChaCha20Poly1305` | `BLAKE3` | `BLAKE3 keyed` |
| Any platform, need TLS / JWT / spec interop | `Aes256Gcm` (TLS) | `SHA-256` (JWT) | `HMAC-SHA256` (JWT, AWS SigV4) |

The defaults (ChaCha20-Poly1305 / BLAKE3 / HMAC-SHA256) are
chosen for the **"safe everywhere"** case. ChaCha20 has no
hardware dependency; HMAC-SHA256 is the universal interop
choice. Switch when you have a reason.

<hr>

## OS-specific notes

### Linux

- **`mod_rand::tier3`** sources nonces from `getrandom(2)`.
  Linux 3.17+ required (which is well below the project's
  Linux floor).
- **No special permissions needed.**
- **Memory locking** (e.g., `mlockall`) is not used — keys are
  per-call arguments, not held by the crate.

### macOS

- **`mod_rand::tier3`** sources from `getentropy(3)` (macOS
  10.12+).
- **No entitlements required.**

### Windows

- **`mod_rand::tier3`** sources from `BCryptGenRandom`.
- **No issues with `path` separators** in the file helpers —
  `std::path::Path` handles the conversion.
- **Line endings:** the repo uses LF throughout (see
  `.gitattributes`). CI on Windows uses the same — no CRLF
  surprises.

### Cross-compiling

Standard cross-compile works:

```bash
# x86_64 Linux → ARM64 Linux
rustup target add aarch64-unknown-linux-gnu
cargo build --target aarch64-unknown-linux-gnu --release

# Native macOS → iOS (requires Xcode)
rustup target add aarch64-apple-ios
cargo build --target aarch64-apple-ios --release
```

The upstream RustCrypto crates use `cfg(target_arch)` and
`cfg(target_feature)` to pick the right backend; no consumer-
side configuration required.

For **embedded targets without `std`**, build with
`default-features = false` and only `aead-chacha20` (plus any
others you need). Note that 1.0 retains a `std` requirement for
the streaming `encrypt_file` / `decrypt_file` helpers; the rest
of the surface is `no_std`-compatible.

<hr>

## Performance varies by 2-5× across platforms

The numbers in [`PERFORMANCE.md`](PERFORMANCE.md) are for one
reference machine (AMD Ryzen 9 9950X3D + AVX-512 + SHA-NI).
**Expect significantly different numbers on different hardware.**

The relative picture is portable:

- **ChaCha20 wins on no-AES hardware** (small ARMs, RISC-V,
  pre-2010 x86) by 3-4×.
- **AES-256-GCM wins on AES-accelerated hardware** at small
  sizes (where AES-NI's per-block throughput dominates). At
  large sizes the two converge.
- **BLAKE3 wins at ≥ 4 KiB on every modern platform** by
  4-10× over SHA-256.
- **SHA-256 wins at < 1 KiB on SHA-NI hardware**. Below 1 KiB
  BLAKE3's setup cost dominates.

Benchmark on your own hardware before making a final choice
for high-throughput paths:

```bash
cargo bench --all-features
```

Full methodology in [`PERFORMANCE.md`](PERFORMANCE.md).

<hr>

## TLS / FIPS notes

- **TLS:** `crypt-io` is not a TLS library. Use `rustls` (which
  ships ChaCha20-Poly1305 and AES-256-GCM ciphersuites). They
  use their own internal AEAD implementations; nothing to wire
  up.
- **FIPS 140-3:** `crypt-io` is not currently FIPS-validated.
  The underlying RustCrypto + BLAKE3 crates are not FIPS-
  validated either. If your deployment needs FIPS, use a
  vendor crate like `aws-lc-rs` or `boring`. We may revisit
  if there's demand and a tractable validation path.

<hr>

<sub>crypt-io platform notes — Copyright (c) 2026 James Gober. Apache-2.0 OR MIT.</sub>
