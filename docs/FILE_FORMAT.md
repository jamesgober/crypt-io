<h1 align="center" id="top">
  <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/coll-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg"><br>
  <b>crypt-io</b>
  <br><sub><sup>FILE / STREAM WIRE FORMAT</sup></sub>
</h1>

<p align="center">
    <i>The on-the-wire formats produced by <code>crypt_io::stream</code>
    and consumed by <code>StreamDecryptor</code> /
    <code>stream::decrypt_file</code>, plus the single-shot and sealed
    formats of <code>Crypt</code>.</i>
</p>

<hr>

## Versions at a glance

| Stream format | Written by | Read by | Key per stream | Streams per key |
|---|---|---|---|---|
| **v2** (`0x02`) | 1.1.0 and later (default) | 1.1.0 and later | HKDF-SHA256 subkey from a 32-byte random salt | no practical limit |
| **v1** (`0x01`) | 1.0.x; 1.1 on request (`StreamFormat::V1`) | every 1.x release | the caller's key, 56-bit random nonce prefix | about 2^12 (4,096) |

Every 1.x release decrypts v1. crypt-io 1.0.x rejects v2 with
`Error::InvalidCiphertext("unsupported stream version: 0x02 ...")`, so
while some readers still run 1.0.x, write v1 with
`StreamEncryptor::new_with_format(key, alg, log2, StreamFormat::V1)`
and switch once every reader is on 1.1.

<hr>

## Overview

A `crypt-io` stream is one **header**, a **salt** (v2 only), and a
sequence of **chunks**:

```text
+--------+---------+----------+----------+ ... +----------+----------+
| HEADER |  SALT   | chunk_0  | chunk_1  |     | chunk_N-1| chunk_N  |
| 24 B   | 32 B v2 | non-fin  | non-fin  |     | non-fin  |  final   |
+--------+---------+----------+----------+ ... +----------+----------+
                                                            ^
                                                    FINAL chunk has
                                                    last_flag = 0x01
                                                    and is STRICTLY
                                                    SMALLER than the
                                                    non-final chunks
```

- Every non-final chunk is exactly **`chunk_size + 16` bytes**
  (chunk_size is from the header; tag is 16 bytes).
- The final chunk is strictly **less than `chunk_size + 16`
  bytes** (so the decoder can detect end-of-stream
  unambiguously by short read).
- The final chunk is **always emitted**, even when zero
  plaintext bytes remain — minimum stream body is 16 bytes
  (just the final-chunk tag), plus the salt in v2.

In the API, `StreamEncryptor::new*` returns the 24-byte header, and
the encryptor's first output (from `update`, `update_into`,
`finalize` or `finalize_into`) starts with the v2 salt. On the
decrypt side, `StreamDecryptor::new` takes the 24-byte header and
`update` consumes everything after it, salt included. Code written
for 1.0 (`header`, then every output, in order) therefore produces
and reads v2 streams unchanged.

<hr>

## Header — 24 bytes

```text
 byte  | size | v1 (version 0x01)            | v2 (version 0x02)
-------+------+------------------------------+-------------------------------
 0..8  |  8   | magic b"\x89CRYPTIO"         | same
   8   |  1   | version = 0x01               | version = 0x02
   9   |  1   | algorithm                    | algorithm
  10   |  1   | chunk_size_log2 (10..=24)    | same; default 16 (64 KiB)
 11..16|  5   | reserved                     | reserved, MUST be zero
 16..23|  7   | nonce_prefix (random)        | reserved, MUST be zero
  23   |  1   | reserved                     | reserved, MUST be zero
```

Algorithm bytes (shared with the sealed single-shot format):

| Byte | Algorithm | Nonce | v1 | v2 |
|---|---|---|---|---|
| `0x00` | ChaCha20-Poly1305 | 12 B | yes | yes |
| `0x01` | AES-256-GCM | 12 B | yes | yes |
| `0x02` | XChaCha20-Poly1305 | 24 B | no | yes |

### Validation rules

A decoder MUST reject the stream with `Error::InvalidCiphertext` if:

- the header is shorter than 24 bytes;
- `magic != b"\x89CRYPTIO"`;
- `version` is not `0x01` or `0x02`;
- `algorithm` is not a known value for that version (`0x02` is
  rejected in v1);
- `chunk_size_log2 < 10 || chunk_size_log2 > 24`;
- **v2:** any of bytes `11..24` is non-zero;
- **v2:** the stream ends before the 32-byte salt is complete.

In v1 the reserved bytes are not validated (1.0 promised that), so
v1 can never give them meaning. Any change to how a stream is
decoded uses a new `version` byte, which older decoders reject.

<hr>

## v2 key schedule

The 32 bytes after a v2 header are a **salt** drawn from the OS
CSPRNG for every stream. Chunks are encrypted under a **subkey**
derived for this stream alone, never under the caller's key:

```text
P            = nonce_len - 5                  (7, or 19 for XChaCha20-Poly1305)
okm          = HKDF-SHA256( IKM  = key,                      (32 bytes, caller's key)
                            salt = salt,                     (32 bytes after the header)
                            info = "crypt-io stream v2" || header,   (18 + 24 bytes)
                            L    = 32 + P )
subkey       = okm[0 .. 32]
nonce_prefix = okm[32 .. 32 + P]
```

HKDF is RFC 5869 (extract, then expand). `info` binds the subkey to
the format, the algorithm and the chunk size, so the same key used
with two algorithms never yields related subkeys.

Two v2 streams under one key share a chunk nonce only if their
256-bit salts collide, which does not happen in practice (2^-128
after 2^64 streams). v1's limit of about 2^12 streams per key does
not apply.

The **AAD** of every v2 chunk is `header || salt` (56 bytes). In v1
it is the 24-byte header.

<hr>

## Per-chunk nonce (STREAM construction)

```text
 bytes          | field         | source
----------------+---------------+-----------------------------------------
 0 .. P         | nonce_prefix  | v1: header bytes 16..23 (P = 7)
                |               | v2: derived, see key schedule
 P .. P+4       | counter       | u32 big-endian, starts at 0,
                |               | +1 after every non-final chunk
 P+4            | last_flag     | 0x00 non-final, 0x01 final
```

The nonce is 12 bytes for ChaCha20-Poly1305 and AES-256-GCM and 24
bytes for XChaCha20-Poly1305. This is the
[STREAM construction](https://eprint.iacr.org/2015/189.pdf) by Hoang,
Reyhanitabar, Rogaway, and Vizár (2015).

**v1 limit.** v1 encrypts every stream directly under the caller's
key and relies on the 7-byte random `nonce_prefix` alone to keep
streams apart. Two v1 streams whose prefixes collide reuse the nonce
for every chunk index they share; with `n` streams under one key the
chance is about `n^2 / 2^57`. Keep one key below about 2^12 (4,096)
v1 streams.

### Why this defeats specific attacks

| Attack | Defense |
|---|---|
| **Truncation** (cut bytes off the end) | The final chunk uses `last_flag = 0x01`. A non-final chunk verified as final has a nonce mismatch → tag fails. |
| **Chunk reorder** (swap two chunks) | The counter is part of the nonce. Swapping gives counter mismatch → tag fails. |
| **Chunk duplicate** (replay) | Same — counter mismatch. |
| **Chunk insertion** | Same — counter mismatch. |
| **Header tamper** (algorithm, chunk size) | The header is AAD on every chunk, and in v2 also HKDF `info` → first chunk's tag fails. Non-zero v2 reserved bytes are rejected outright. |
| **Salt tamper** (v2) | A different salt gives a different subkey, and the salt is AAD → first chunk's tag fails. |
| **Nonce-prefix tamper** (v1) | Header AAD → first chunk's tag fails. |

<hr>

## Chunk body

Each chunk is encrypted via the AEAD identified by the header's
`algorithm` byte, called with:

- `key` — v2: the derived subkey; v1: the caller's 32-byte key
- `nonce` — built per chunk as above
- `aad` — v2: `header || salt` (56 bytes); v1: the 24-byte header
- `plaintext` — `chunk_size` bytes for non-final chunks; 0 to
  `chunk_size - 1` bytes for the final chunk

The output is `ciphertext || tag` (16-byte tag for every shipped
AEAD). So a non-final chunk is exactly `chunk_size + 16` bytes; the
final chunk is `final_plaintext_len + 16` bytes, where
`final_plaintext_len ∈ [0, chunk_size - 1]`.

<hr>

## Final-chunk-always invariant

The encryptor's `finalize` **always** emits a final chunk. Even
if no plaintext bytes remain at finalisation, a 16-byte chunk
(empty ciphertext + tag) is emitted.

This makes EOF detection unambiguous for the decoder:

- Read `chunk_size + 16` bytes with more after them → non-final.
- Read fewer → final, decrypt with `last_flag = 0x01` and stop.

### Edge case: plaintext is an exact multiple of `chunk_size`

A full chunk is emitted as **non-final** as soon as it is complete,
so if the plaintext length is a multiple of `chunk_size` the stream
ends with a **zero-byte final chunk** (just the 16-byte tag). This
preserves the "final chunk is strictly smaller than
`chunk_size + 16`" invariant.

<hr>

## Worked example: 2,100-byte plaintext, 1 KiB chunks, v2

```text
  header (24 bytes)
    [0..8]   89 43 52 59 50 54 49 4f      ; magic
    [8]      02                           ; version 2
    [9]      00                           ; ChaCha20-Poly1305
    [10]     0a                           ; chunk_size_log2 = 10
    [11..24] 00 x 13                      ; reserved, zero
  salt (32 bytes, random)
  chunk_0 (1040 bytes) — non-final, counter=0, last_flag=0
  chunk_1 (1040 bytes) — non-final, counter=1, last_flag=0
  chunk_2 (68 bytes)   — final, counter=2, last_flag=1
                         (52 ciphertext + 16 tag)

  TOTAL: 24 + 32 + 1040 + 1040 + 68 = 2204 bytes
```

The same plaintext in v1 is 32 bytes shorter (no salt): 2172 bytes.
A 2,048-byte plaintext ends with a 16-byte final chunk:
`24 + 32 + 1040 + 1040 + 16 = 2152` bytes in v2.

<hr>

## Test vectors (v2)

All three use `key = 00 01 02 .. 1f` and `salt = b0 b1 b2 .. cf`.
They were produced by an independent implementation of this
document (Python: HKDF from `hmac`/`hashlib`, ChaCha20-Poly1305 and
AES-GCM from `cryptography`, HChaCha20 written out by hand) and are
checked byte for byte by `src/stream/encryptor.rs` (encrypt side)
and `tests/kat.rs` (decrypt side). The full streams are in
`src/stream/test_vectors.rs`.

**1. AES-256-GCM, `chunk_size_log2 = 16`, plaintext
`"crypt-io stream format v2 frozen vector"` (39 bytes).**

```text
subkey       999c0f6fd9e1339bef412193547e77a1720466abea25fbdf06abdbf19e6760eb
nonce_prefix bcdc8e97527a01
stream (111 bytes):
  894352595054494f02011000000000000000000000000000          header
  b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf  salt
  43231aa6eb26651ffdaf123b55a26dc547048efa5538c7f1af1797e10f4e8e54  final chunk
  5ee4f5745de1bf0a6c3619c3f357a177bacaaf82e8d0c7                    (39 + 16 tag)
```

**2. ChaCha20-Poly1305, `chunk_size_log2 = 10`, plaintext = 1100
bytes of `i % 251`** (one full chunk and a 76-byte final chunk).

```text
subkey        68d6d270cb1b296ee62835397bfc3dc1792ad891caa76d4778c48a8186e3bc39
nonce_prefix  590a37adea1e39
stream        1188 bytes, SHA-256 ad68cb17f6bdfb7a03bd38723966a96230489c1c343c1f71db0cfff315a500d4
```

**3. XChaCha20-Poly1305, `chunk_size_log2 = 10`, plaintext = 2048
bytes of `(i * 7) % 256`** (two full chunks and an empty final
chunk).

```text
subkey        85065ba5dd78b02ace2f7a00d4c3196b88148cae1d175b48d7148519897968d7
nonce_prefix  7cf2c8fbefad42f56bf0e1247e9cfc8153f5ba
stream        2152 bytes, SHA-256 f1f95ca97d5b41bd87db952f1d9a4bf23a71896efe08bbbc638bf5cd12358839
```

v1 vectors (key `00..1f`, nonce prefix `a0..a6`) are in
`tests/kat.rs`.

<hr>

## Counter overflow

The chunk counter is a `u32`. At 64 KiB chunks (the default) that is
`2^32 × 64 KiB = 256 TiB` per stream. Encoding a longer stream
returns `Error::LimitExceeded("stream: chunk counter overflow")`
from the encryptor (1.0.x returned `Error::InvalidCiphertext`). Split
larger data across several streams (in v2 each has its own subkey),
or use a larger chunk size.

<hr>

## Single-shot formats (`Crypt`)

**1.0 format** (`Crypt::encrypt*` / `decrypt*`), unchanged in 1.1:

```text
nonce (12 B, or 24 B for XChaCha20-Poly1305) || ciphertext || tag (16 B)
```

It carries no version or algorithm byte; the reader must know the
algorithm.

**Sealed format** (`Crypt::seal*` / `open*`, new in 1.1.0):

```text
version (1 B) = 0x01 || algorithm (1 B) || nonce || ciphertext || tag (16 B)
```

The AEAD's associated data is `version || algorithm || caller_aad`,
so the two header bytes are authenticated. `open` reads the
algorithm byte (values as in the table above) to pick the cipher; an
unknown version or algorithm byte is `Error::InvalidCiphertext`.

<hr>

## Compatibility commitments

- Streams written by any 1.x release (v1 or v2) decrypt with every
  later 1.x release. v1 decoding is kept for the life of 1.x.
- A new stream format uses a new `version` byte. Older decoders
  reject it with `Error::InvalidCiphertext` rather than
  mis-decoding it.
- New algorithms get new algorithm bytes (`0x03`, ...). Older
  decoders reject them with `Error::InvalidCiphertext("unknown
  algorithm byte")`.
- The v2 reserved bytes must be zero, so a future v2 writer cannot
  give them meaning that v2 readers would ignore.
- The 1.0 single-shot format and the sealed format v1 are frozen
  for 1.x.

<hr>

<sub>crypt-io stream wire format — Copyright (c) 2026 James Gober. Apache-2.0 OR MIT.</sub>
