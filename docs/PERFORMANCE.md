<h1 align="center" id="top">
  <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/rust-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg"><br>
  <b>crypt-io</b>
  <br><sub><sup>PERFORMANCE</sup></sub>
</h1>

<p align="center">
    <i>Measured throughput for every operation in <code>crypt-io</code> 0.8.0
    on the reference machine documented below. Reproduce locally with
    <code>cargo bench --all-features</code>.</i>
</p>

<hr>

## TL;DR

Numbers below are for the **`_into` zero-allocation paths** introduced
in 0.10.0 where they apply (AEAD encrypt, stream encrypt). The
allocating paths (`encrypt`, `update`) are slower at large sizes
because of the per-call `Vec` allocation; the 0.10.0 `_into`
variants take a caller-supplied buffer and run with zero
steady-state allocations.

| Operation | Algorithm | Throughput @ 1 KiB | Throughput @ 64 KiB | @ 1 MiB |
|---|---|---|---|---|
| AEAD `encrypt_into` | ChaCha20-Poly1305 | 590 MiB/s | **1.51 GiB/s** | **1.45 GiB/s** |
| AEAD `encrypt_into` | AES-256-GCM       | 1.18 GiB/s | **1.63 GiB/s** | **1.59 GiB/s** |
| AEAD decrypt | ChaCha20-Poly1305 | 627 MiB/s | **1.48 GiB/s** | 1.49 GiB/s |
| AEAD decrypt | AES-256-GCM       | 1.27 GiB/s | **1.59 GiB/s** | 1.60 GiB/s |
| Hash         | BLAKE3            | 914 MiB/s | **11.24 GiB/s** | 11.83 GiB/s |
| Hash         | SHA-256 (SHA-NI)  | 2.24 GiB/s | 2.49 GiB/s | 2.45 GiB/s |
| Hash         | SHA-512           | 968 MiB/s | 1.11 GiB/s | 1.05 GiB/s |
| MAC          | HMAC-SHA256       | 1.69 GiB/s | 2.43 GiB/s | 2.50 GiB/s |
| MAC          | HMAC-SHA512       | 709 MiB/s | 1.02 GiB/s | 1.03 GiB/s |
| MAC          | BLAKE3 keyed      | 990 MiB/s | **11.74 GiB/s** | 11.57 GiB/s |
| KDF          | HKDF-SHA256 (32 B output) | 304 ns | — | — |
| KDF          | HKDF-SHA512 (32 B output) | 1.06 µs | — | — |
| KDF          | Argon2id (OWASP defaults) | ~9 ms / hash | — | — |
| KDF          | Argon2id (test params) | 8.2 µs / hash | — | — |
| Stream `_into` | ChaCha20-Poly1305 | — | — | **1.40 GiB/s** |
| Stream `_into` | AES-256-GCM | — | — | **1.54 GiB/s** |

### 0.10.0 wrapping-overhead close: allocating vs `_into`

| Operation @ 1 MiB | Allocating (0.9.0) | `_into` (0.10.0) | Speedup |
|---|---:|---:|---:|
| `Crypt::encrypt` ChaCha20-Poly1305 | 1.05 GiB/s | **1.45 GiB/s** | **+38%** |
| `Crypt::encrypt` AES-256-GCM       | 1.08 GiB/s | **1.59 GiB/s** | **+47%** |
| `StreamEncryptor` ChaCha20-Poly1305 | 932 MiB/s | **1.40 GiB/s** | **+54%** |
| `StreamEncryptor` AES-256-GCM       | 999 MiB/s | **1.54 GiB/s** | **+55%** |

**Allocation count, measured via `mod-alloc` over 10,000 iterations:**

| Operation | Allocations / 10k iters | Per-call |
|---|---:|---:|
| `Crypt::encrypt` (any algo, any size) | 20 000 | 2 |
| `Crypt::encrypt_into` (any algo, any size) | **0** | **0 steady-state** |

The `_into` path is **zero-allocation in the steady state**:
caller-supplied buffer grows once on first call, every subsequent
call reuses the capacity. Stream encrypt now lands cleanly over
the 1 GiB/s contract target for both algorithms at 1 MiB plaintext.

> **Single reference machine.** AES-NI machines without SHA-NI will
> see SHA-256 ~3-5× slower; CPUs without AES-NI fall back to a
> constant-time software path that's ~3-4× slower than the numbers
> above. ChaCha20-Poly1305 and BLAKE3 are SIMD-friendly on any
> modern CPU and don't depend on dedicated crypto instructions.

<hr>

## Reference machine

| | |
|---|---|
| **CPU** | AMD Ryzen 9 9950X3D (Zen 5, 16-core, 32-thread, 5.7 GHz boost) |
| **CPU flags** | `aes` (AES-NI), `sha_ni` (SHA-NI), `avx2`, `avx512f`, `avx512vbmi2`, `vaes` |
| **OS** | WSL2 Ubuntu (kernel 6.6.87.2 on Windows 11) |
| **Rust** | `1.85.0` (the MSRV pinned in `rust-toolchain.toml`) |
| **Build profile** | `[profile.bench]` — `opt-level = 3`, `lto = "fat"`, `codegen-units = 1`, `debug = true` |
| **Date** | 2026-05-22 |

The Zen 5 chip is generous to both AEADs: AES-NI is full-throughput
on the AES-256-GCM path, and the wide AVX-512 register file gives
BLAKE3 its 11 GiB/s number at 64 KiB.

<hr>

## Methodology

- **Harness:** [`criterion`](https://crates.io/crates/criterion) 0.5 with `harness = false` per the standard pattern.
- **Reps:** 100 samples per benchmark (criterion default), 3 s warm-up.
- **Black-box discipline:** every iteration wraps inputs in `criterion::black_box(...)` so the optimiser doesn't constant-fold the call away.
- **Throughput:** plotted per-byte via `Throughput::Bytes`, so different input sizes can be compared directly.
- **Sizes:** 64 B (short token), 1 KiB (typical row/message), 64 KiB (file chunk / network packet), 1 MiB (bulk transfer chunk). HKDF additionally at 32 / 64 / 128-byte output lengths.
- **Argon2id default-params:** sample size dialed down to 10 (~100 s per group), measurement time extended to 15 s — each iteration is intentionally slow.
- **Argon2id fast-params** (8 KiB / 1 / 1 / 32) — also benched for comparison against unit-test cost (the wrapper has effectively zero overhead vs upstream).

Reproduce:

```bash
cargo bench --all-features                    # all five suites
cargo bench --bench aead --all-features       # just AEAD
cargo bench --bench hash --all-features       # just hashing
cargo bench --bench mac --all-features        # just MAC
cargo bench --bench kdf --all-features        # KDF (slow — Argon2id default)
cargo bench --bench stream --all-features     # streaming
```

Filter further:

```bash
cargo bench --bench aead -- chacha20          # only ChaCha20-Poly1305
cargo bench --bench hash -- blake3            # only BLAKE3
```

<hr>

## AEAD

`Crypt::encrypt` / `Crypt::decrypt` — single-shot AEAD with internal nonce generation, AAD = `&[]`.

### ChaCha20-Poly1305

| Size | Encrypt (ns/iter) | Encrypt throughput | Decrypt (ns/iter) | Decrypt throughput |
|---:|---:|---:|---:|---:|
| 64 B | 1 217 | 50.1 MiB/s | 1 084 | 56.3 MiB/s |
| 1 KiB | 1 724 | 566 MiB/s | 1 558 | 627 MiB/s |
| 64 KiB | 42 229 | **1.45 GiB/s** | 41 155 | **1.48 GiB/s** |
| 1 MiB | 934 130 | 1.05 GiB/s | 655 010 | **1.49 GiB/s** |

ChaCha20 is the safe default on any platform — no hardware
dependency, no timing-side-channel risk. Peaks at 64 KiB chunk
size where the stream cipher's per-call setup is amortised but
the data still fits in L2 cache.

### AES-256-GCM

| Size | Encrypt (ns/iter) | Encrypt throughput | Decrypt (ns/iter) | Decrypt throughput |
|---:|---:|---:|---:|---:|
| 64 B | 334 | 183 MiB/s | 186 | 328 MiB/s |
| 1 KiB | 944 | 1.01 GiB/s | 753 | **1.27 GiB/s** |
| 64 KiB | 39 287 | **1.55 GiB/s** | 38 368 | **1.59 GiB/s** |
| 1 MiB | 901 240 | 1.08 GiB/s | 609 020 | **1.60 GiB/s** |

AES-256-GCM wins decisively at small sizes (~3-5× faster than
ChaCha20-Poly1305 at 64 B) thanks to AES-NI's per-block throughput.
At medium-to-large sizes the two converge — both saturate around
1.5 GiB/s on this machine.

### Contract check

The 1.0 performance contract from the ROADMAP, with the measured
values:

| Operation | Target | Measured | Status |
|---|---:|---:|:---:|
| ChaCha20-Poly1305 encrypt, 1 KiB | < 2 µs | 1.72 µs | ✅ |
| ChaCha20-Poly1305 decrypt, 1 KiB | < 2 µs | 1.56 µs | ✅ |
| AES-256-GCM encrypt, 1 KiB (HW accel) | < 1 µs | 944 ns | ✅ |

<a href="#top">↑ TOP</a>

<hr>

## Hashing

`hash::blake3` / `hash::sha256` / `hash::sha512` — one-shot
fixed-output hashes.

| Size | BLAKE3 | SHA-256 | SHA-512 |
|---:|---:|---:|---:|
| 64 B | 75 ns / **813 MiB/s** | 59 ns / 1005 MiB/s | 126 ns / 486 MiB/s |
| 1 KiB | 1.07 µs / 914 MiB/s | 426 ns / **2.24 GiB/s** | 1.01 µs / 968 MiB/s |
| 64 KiB | 5.43 µs / **11.24 GiB/s** | 24.5 µs / 2.49 GiB/s | 55.1 µs / 1.11 GiB/s |
| 1 MiB | 82.5 µs / **11.83 GiB/s** | 399 µs / 2.45 GiB/s | 927 µs / 1.05 GiB/s |

Two interesting things on this machine:

1. **BLAKE3 at small sizes is setup-cost dominated.** The 1.07 µs at
   1 KiB is dominated by the per-call constant overhead; BLAKE3's
   tree structure only starts paying off once SIMD-parallel
   chunks (1 KiB each internally) fire. At 64 KiB+ the picture
   inverts dramatically — 11.2 GiB/s, ~4.5× faster than SHA-256.
2. **SHA-256 with SHA-NI is fast at small sizes.** Below 1 KiB
   SHA-256 actually beats BLAKE3 on this hardware. If your
   workload is "lots of small hashes" (per-row fingerprints,
   token IDs) and you control the SHA-NI hardware, SHA-256 is
   not unreasonable.

### Contract check

| Operation | Target | Measured | Status |
|---|---:|---:|:---:|
| SHA-256, 1 KiB | < 2 µs | 426 ns | ✅ |
| BLAKE3, 1 KiB | < 500 ns | 1.07 µs | ⚠️ **target revised** |

The < 500 ns BLAKE3 target was set before measurement. On real
hardware BLAKE3's small-input cost is dominated by setup
(`Hasher::new()` initialisation + per-call overhead). At medium-to-
large inputs BLAKE3 dominates — 11+ GiB/s at 64 KiB. The contract
will be updated for 1.0 to reflect the actual shape: BLAKE3 wins
*above* ~4 KiB; SHA-256 wins below on SHA-NI hardware.

<a href="#top">↑ TOP</a>

<hr>

## MAC

`mac::hmac_sha256` / `mac::hmac_sha512` / `mac::blake3_keyed` —
one-shot authentication tags.

| Size | HMAC-SHA256 | HMAC-SHA512 | BLAKE3 keyed |
|---:|---:|---:|---:|
| 64 B | 176 ns / 347 MiB/s | 478 ns / 128 MiB/s | 71 ns / **864 MiB/s** |
| 1 KiB | 565 ns / **1.69 GiB/s** | 1.38 µs / 709 MiB/s | 987 ns / 990 MiB/s |
| 64 KiB | 25.1 µs / 2.43 GiB/s | 60.0 µs / 1.02 GiB/s | 5.20 µs / **11.74 GiB/s** |
| 1 MiB | 390 µs / 2.50 GiB/s | 952 µs / 1.03 GiB/s | 84.4 µs / **11.57 GiB/s** |

HMAC-SHA256 is the universal interop pick (JWT HS256, AWS SigV4,
TLS PRF) and is well-served by SHA-NI on this hardware. BLAKE3
keyed wins at every input size — by ~12× at 64 KiB+ — when
you control both sides of the wire and don't need spec interop.

### Constant-time verify

`*_verify` cost at 1 KiB:

| Algorithm | Cost | Notes |
|---|---:|---|
| `mac::hmac_sha256_verify` | 571 ns | Effectively identical to `hmac_sha256` — verify is "compute + constant-time compare". |
| `mac::blake3_keyed_verify` | 1.06 µs | ~7% overhead over plain `blake3_keyed` (tag-byte CT compare). |

### Contract check

| Operation | Target | Measured | Status |
|---|---:|---:|:---:|
| HMAC-SHA256, 1 KiB | < 3 µs | 565 ns | ✅ |

<a href="#top">↑ TOP</a>

<hr>

## KDF

### HKDF

`kdf::hkdf_sha256` / `kdf::hkdf_sha512` — extract-then-expand
with 4-byte info and 4-byte salt.

| Output length | HKDF-SHA256 | HKDF-SHA512 |
|---:|---:|---:|
| 32 B | **304 ns** | 1.06 µs |
| 64 B | 416 ns | 1.07 µs |
| 128 B | 576 ns | 1.40 µs |

HKDF-SHA256 dominates at the typical 32-byte subkey derivation —
half a microsecond for an entire key-splitting operation,
SHA-NI-accelerated. HKDF-SHA512 is ~3× slower because SHA-512's
64-bit word size is awkward on SHA-NI (which is SHA-256-only on
this CPU).

### Contract check

| Operation | Target | Measured | Status |
|---|---:|---:|:---:|
| HKDF-SHA256, 32-byte output | < 5 µs | 304 ns | ✅ |

### Argon2id

`kdf::argon2_hash` / `kdf::argon2_verify` — password-derived
keys. Two parameter sets:

| Parameter set | Hash cost | Verify cost |
|---|---:|---:|
| `Argon2Params::default()` (OWASP: 19 MiB / 2 / 1 / 32) | **8.9 ms** | 8.9 ms |
| Test params (8 KiB / 1 / 1 / 32) | 8.2 µs | 8.1 µs |

> ⚠️ **OWASP defaults run faster than the design intent on this
> CPU.** The 19 MiB / 2 / 1 parameter set was calibrated for an
> assumed ~100 ms per hash on a "modern CPU". On this Zen 5 chip
> (with DDR5 + huge L3) it runs in ~9 ms — about 11× faster than
> the intended brute-force-resistance budget. **For
> production deployments on modern server hardware, raise
> `t_cost` to 8+ or `m_cost` to 64 MiB+ to maintain the ~100 ms
> target.** Use `kdf::argon2_hash_with_params` to override.

The "test params" set proves the wrapper overhead is negligible
— hash and verify are nearly identical cost, both within
microseconds of the upstream `argon2` crate.

<a href="#top">↑ TOP</a>

<hr>

## Streaming

`StreamEncryptor` / `StreamDecryptor` end-to-end at the default
64 KiB chunk size. Throughput numbers cover the whole pipeline —
header build, per-chunk encrypt, finalize, per-chunk decrypt,
finalize — so framing and chunking overhead is included.

| Operation | ChaCha20-Poly1305 | AES-256-GCM |
|---|---:|---:|
| Encrypt 1 MiB | 932 MiB/s | 999 MiB/s |
| Decrypt 1 MiB | 1.19 GiB/s | 1.30 GiB/s |
| Encrypt 10 MiB | 845 MiB/s | 897 MiB/s |
| Decrypt 10 MiB | 555 MiB/s | 565 MiB/s |

Stream throughput is ~80-95% of the underlying AEAD throughput at
1 MiB. The ~30% gap at 10 MiB decrypt is allocation pressure: each
chunk decrypt produces a fresh `Vec<u8>`. A future
zero-allocation streaming path would close it; for 0.8.0 it's
documented behaviour, not a correctness bug.

### Contract check

| Operation | Target | Measured (0.9 allocating) | Measured (0.10 `_into`) | Status |
|---|---:|---:|---:|:---:|
| Stream encrypt throughput, 1 MiB plaintext | > 1 GiB/s | 999 MiB/s (AES) / 932 MiB/s (ChaCha20) | **1.54 GiB/s (AES) / 1.40 GiB/s (ChaCha20)** | ✅ over target |
| Stream decrypt throughput, 1 MiB plaintext | > 1 GiB/s | 1.30 GiB/s (AES) / 1.19 GiB/s (ChaCha20) | (decrypt path unchanged) | ✅ |

**0.10.0 closes the stream-encrypt gap.** The `_into` path takes a
caller-supplied buffer, removes the per-call `Vec` allocation, and
pushes throughput **+54% / +55%** over the allocating path at 1 MiB
— well over the 1 GiB/s contract target for both algorithms.

<a href="#top">↑ TOP</a>

<hr>

## Wrapping overhead vs upstream

`crypt-io` is a thin layer over RustCrypto. To check the overhead
isn't material, compare these numbers against the upstream
crates' own benches:

- [`chacha20poly1305`](https://crates.io/crates/chacha20poly1305) —
  RustCrypto's bench reports ~1.5-1.6 GiB/s at 1 MiB on similar
  hardware. We measure 1.05 GiB/s for encrypt and 1.49 GiB/s for
  decrypt. The encrypt-side gap is the allocation we do
  (`Vec::with_capacity` + nonce prepend); decrypt is within
  noise.
- [`aes-gcm`](https://crates.io/crates/aes-gcm) — upstream reports
  ~2 GiB/s at 1 MiB on Zen-class hardware with AES-NI. We measure
  1.08 / 1.60 GiB/s — same encrypt-side allocation gap, decrypt
  within noise.
- [`blake3`](https://crates.io/crates/blake3) — upstream reports
  ~10-12 GiB/s on Zen 5 with AVX-512. We measure 11.83 GiB/s at
  1 MiB. Essentially zero overhead — BLAKE3's API is itself
  allocation-free for the default 32-byte digest, and we just
  call through.
- [`sha2`](https://crates.io/crates/sha2) — upstream with SHA-NI
  reports ~2.5-3.0 GiB/s for SHA-256 on Zen 5. We measure 2.45 GiB/s
  at 1 MiB. Within noise.
- [`hkdf`](https://crates.io/crates/hkdf), [`hmac`](https://crates.io/crates/hmac),
  [`argon2`](https://crates.io/crates/argon2) — wrapping overhead
  not measurable: we just call through to one upstream function.

Most of our overhead in 0.9.0 and earlier was **per-call
allocation** for the output `Vec<u8>`. **0.10.0 closes this gap**
with the `_into` API family — `Crypt::encrypt_into`,
`Crypt::decrypt_into`, `StreamEncryptor::update_into` /
`finalize_into`, `StreamDecryptor::update_into` / `finalize_into`.
Each writes into a caller-supplied `Vec<u8>` and runs with **zero
steady-state allocations** (verified by `mod-alloc` profile in
`examples/profile_alloc.rs`). Wall-clock impact: +38-55% on the
encrypt paths at 1 MiB.

<a href="#top">↑ TOP</a>

<hr>

## Choosing parameters for your hardware

If you're deploying on:

- **Server-class x86_64 with AES-NI + SHA-NI (Intel Ice Lake+,
  AMD Zen 3+)** — pick `AES-256-GCM` for AEAD, `SHA-256` for
  interop hashing. Both will saturate near memory bandwidth.
  Raise Argon2id `t_cost` to maintain the ~100 ms password-hash
  budget.
- **Server-class x86_64 without SHA-NI (older Xeon, AMD Zen 1/2)**
  — same AEAD pick (`AES-256-GCM`), but use **BLAKE3** for
  hashing — SHA-256 will be ~3× slower without SHA-NI.
- **ARMv8 server (AWS Graviton, modern Apple Silicon)** — both
  AEADs are hardware-accelerated (AES via the crypto extensions,
  ChaCha20 via NEON). Pick by interop need; BLAKE3 dominates
  hashing.
- **CPUs without AES-NI / crypto extensions** (older ARM, RISC-V,
  embedded x86) — **ChaCha20-Poly1305** is the only safe choice.
  AES-256-GCM falls back to a constant-time software path that's
  3-4× slower than ChaCha20 there.

<a href="#top">↑ TOP</a>

<hr>

<sub>crypt-io performance — Copyright (c) 2026 James Gober. Apache-2.0 OR MIT.</sub>
