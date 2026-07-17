# crypt-io 1.1 candidate performance — Apple M5 Max

This machine-local run establishes the initial authenticated-storage baseline
and compares the upgraded private AES-GCM implementation with the unchanged
v1.0.0 tag. It is regression evidence for this candidate, not a cross-machine
or competitor claim.

## Environment

- Date: 2026-07-16
- Candidate base: `a22185392c8f93391780f49697028ae6f50861d0` plus the uncommitted additive 1.1 patch
- Baseline: tag `v1.0.0` at `a22185392c8f93391780f49697028ae6f50861d0`
- Rust: `rustc 1.95.0 (59807616e 2026-04-14)`
- Criterion: 0.5.1 using the Plotters backend
- Target: `aarch64-apple-darwin`
- Hardware: Apple M5 Max, 18 cores, 128 GiB RAM
- Operating system: macOS 27.0 build `26A5353q`

## Established AES-GCM surface

Both revisions ran the unchanged `benches/aead.rs` harness, sequentially on
the same machine:

```text
cargo bench --bench aead -- 'aes_256_gcm_(encrypt|decrypt)/(1024|1048576)$' --noplot
```

Times are Criterion point estimates. Lower is better.

| Operation | Plaintext | v1.0.0 | 1.1 candidate | Change |
| --- | ---: | ---: | ---: | ---: |
| AES-256-GCM encrypt | 1 KiB | 6.4129 us | 1.5692 us | -75.5% |
| AES-256-GCM encrypt | 1 MiB | 4.4819 ms | 220.61 us | -95.1% |
| AES-256-GCM decrypt | 1 KiB | 5.1088 us | 483.39 ns | -90.5% |
| AES-256-GCM decrypt | 1 MiB | 4.3854 ms | 199.70 us | -95.4% |

The private RustCrypto upgrade produces no measured regression on the sampled
frozen 1.0 AES surface; every sampled operation improved by more than 75% on
this ARM64 host.

## New authenticated storage formats

Command:

```text
cargo bench --bench storage --features storage-v1 --locked -- --noplot
```

These are initial numbers because no storage-v1 benchmark exists on main.
Times are Criterion point estimates and throughput is derived from plaintext
bytes.

| Format | Operation | Plaintext | Time | Throughput |
| --- | --- | ---: | ---: | ---: |
| SealedRecord v1 | seal | 1 KiB | 3.8265 us | 255.21 MiB/s |
| SealedRecord v1 | open | 1 KiB | 1.6751 us | 582.98 MiB/s |
| SealedRecord v1 | seal | 64 KiB | 45.878 us | 1.3304 GiB/s |
| SealedRecord v1 | open | 64 KiB | 52.225 us | 1.1687 GiB/s |
| SealedRecord v1 | seal | 1 MiB | 693.35 us | 1.4085 GiB/s |
| SealedRecord v1 | open | 1 MiB | 671.26 us | 1.4548 GiB/s |
| EncryptedStream v1 | seal | 1 MiB | 702.93 us | 1.3893 GiB/s |
| EncryptedStream v1 | open | 1 MiB | 1.2670 ms | 789.25 MiB/s |
| EncryptedStream v1 | seal | 16 MiB | 11.816 ms | 1.3224 GiB/s |
| EncryptedStream v1 | open | 16 MiB | 19.847 ms | 806.18 MiB/s |

The 64 KiB record-open sample had 23 high-severe outliers and the 1 MiB
stream-open sample had three high outliers in 20 samples. Future release
comparisons must rerun the same harness on equivalent hardware; regressions
over 5% against the adopted main baseline block release.

## Strict detached Ed25519 verification

Command:

```text
cargo bench --bench signature --no-default-features --features signature-ed25519 --locked -- --noplot
```

The RFC 8032 one-byte-message fixture verified in **23.008 us** (Criterion
point estimate, 95% interval 22.909-23.130 us). Thirteen of 100 measurements
were high outliers. This is the initial regression baseline for the deliberately
minimal upstream feature graph with precomputed-table acceleration disabled;
artifact verification is an admission-boundary operation rather than a vector
query hot path.
