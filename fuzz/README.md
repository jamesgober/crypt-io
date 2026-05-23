# crypt-io fuzz harness

Eight `cargo-fuzz` targets covering every algorithm in `crypt-io`,
plus the streaming frame format. Each target is a libfuzzer
harness that exercises the public API with arbitrary input bytes
and asserts only that the library never panics, never enters an
infinite loop, and never produces an unrecoverable failure.

## Targets

| Target | Surface | Most-likely findings |
|---|---|---|
| `aead_decrypt` | `Crypt::decrypt` / `decrypt_with_aad` | Panic on malformed ciphertext, wrong-length key |
| `aead_encrypt` | `Crypt::encrypt` round-trip | Encrypt-but-decrypt-fails (algorithm dispatch bug) |
| `hash_blake3` | `hash::blake3` + XOF + `Blake3Hasher` | Streaming-vs-one-shot divergence |
| `hash_sha2` | `hash::sha256` / `sha512` + streamers | Same |
| `mac` | All three MACs + compute + verify + streaming | Tag mismatch, panic on wrong-length input |
| `hkdf` | `kdf::hkdf_sha256` / `hkdf_sha512` | Panic at boundary lengths, non-determinism |
| `argon2_parse` | `kdf::argon2_verify` PHC parser + `argon2_hash_with_params` | Panic on malformed PHC, parameter rejection |
| `stream_decrypt` | `StreamDecryptor` + round-trip | Frame-parse panic, chunk-boundary buffering bug |

## Requirements

- **Nightly Rust** — `libfuzzer-sys` requires `-Z sanitizer=address`,
  which is nightly-only. The main `crypt-io` crate stays on stable
  1.85 MSRV; this `fuzz/` workspace is the only thing that needs
  nightly.
- **Linux or macOS** — libfuzzer doesn't ship for Windows. On
  Windows use WSL2.
- **`cargo-fuzz` installed** — `cargo install cargo-fuzz`.

Setup on WSL2 Ubuntu (already the standard pre-CI gate for this
project):

```bash
rustup toolchain install nightly
cargo install cargo-fuzz
```

## Running

From the **`fuzz/`** directory:

```bash
# List available targets
cargo +nightly fuzz list

# Quick smoke (1 minute)
cargo +nightly fuzz run aead_decrypt -- -max_total_time=60

# Per-target 1 CPU-hour run (the roadmap target for 1.0)
cargo +nightly fuzz run aead_decrypt -- -max_total_time=3600

# All targets, ~5 minutes each
for t in aead_decrypt aead_encrypt hash_blake3 hash_sha2 mac hkdf argon2_parse stream_decrypt; do
    cargo +nightly fuzz run "$t" -- -max_total_time=300
done

# Reproduce a finding
cargo +nightly fuzz run aead_decrypt fuzz/artifacts/aead_decrypt/crash-<hash>
```

## Corpus

Useful inputs land in `corpus/<target>/`. Anything in there is
committed to the repo so future fuzz runs start from a meaningful
seed. Garbage (random fuzzer noise) stays in `target/` which is
`.gitignore`d.

To minimise an existing corpus:

```bash
cargo +nightly fuzz cmin <target>
```

## Findings policy

- A crash means the library panicked (or OOM'd, or hung) on
  arbitrary input. **Every crash gets a regression test in
  `tests/`** under the relevant module, plus a fix.
- Move the crash input from `artifacts/<target>/` to
  `corpus/<target>/` so subsequent runs always exercise it.
- Document the finding in `CHANGELOG.md` under `### Security`.

## What's intentionally NOT fuzzed

- **`argon2_hash` at OWASP defaults.** Each iteration is
  ~50-150 ms; the fuzzer would be useless. The parameter-
  validation path is exercised through `argon2_hash_with_params`
  in `argon2_parse.rs` with capped costs instead.
- **TEE detection.** It's a runtime hardware probe, not a
  user-controlled input.
- **The criterion benchmark suite.** Bench code is dev-only and
  isn't part of the library surface.
