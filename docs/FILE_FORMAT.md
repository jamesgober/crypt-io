<h1 align="center" id="top">
  <img width="99" alt="Rust logo" src="https://raw.githubusercontent.com/jamesgober/coll-collection/72baabd71f00e14aa9184efcb16fa3deddda3a0a/assets/rust-logo.svg"><br>
  <b>crypt-io</b>
  <br><sub><sup>FILE / STREAM WIRE FORMAT</sup></sub>
</h1>

<p align="center">
    <i>The on-the-wire format produced by <code>crypt_io::stream</code>
    and consumed by <code>StreamDecryptor</code> /
    <code>stream::decrypt_file</code>. Frozen for the 1.x series.</i>
</p>

<hr>

## Overview

A `crypt-io` stream is one **header** followed by a sequence of
**chunks**:

```text
+--------+----------+----------+ ... +----------+----------+
| HEADER | chunk_0  | chunk_1  |     | chunk_N-1| chunk_N  |
| 24 B   | non-fin  | non-fin  |     | non-fin  |  final   |
+--------+----------+----------+ ... +----------+----------+
                                                ^
                                                |
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
  (just the final-chunk tag).

<hr>

## Header — 24 bytes

```text
 byte  | size | field             | values / notes
-------+------+-------------------+----------------------------------
 0..8  |  8   | magic             | b"\x89CRYPTIO"
   8   |  1   | version           | 0x01
   9   |  1   | algorithm         | 0x00 = ChaCha20-Poly1305
       |      |                   | 0x01 = AES-256-GCM
       |      |                   | future: 0x02+ in 1.x minor
  10   |  1   | chunk_size_log2   | 10..=24 (1 KiB..16 MiB)
                                  | default 16 (64 KiB)
 11..16|  5   | reserved          | all 0x00 in 1.0
 16..23|  7   | nonce_prefix      | random per-stream, OS-CSPRNG
  23   |  1   | reserved          | 0x00
```

### Validation rules

A decoder MUST reject the stream if:

- `magic != b"\x89CRYPTIO"` → `Error::InvalidCiphertext("stream magic mismatch")`
- `version != 0x01` → `Error::InvalidCiphertext("unsupported stream version")`
- `algorithm` is not a known value → `Error::InvalidCiphertext("unknown algorithm byte")`
- `chunk_size_log2 < 10 || chunk_size_log2 > 24` → `Error::InvalidCiphertext("chunk_size_log2 out of range")`
- Header is shorter than 24 bytes → `Error::InvalidCiphertext("stream header too short")`

The five "reserved" bytes are not validated — they're space for
future minor-release header extensions. 1.0 zero-fills them.

### Header is AAD

The full 24-byte header is fed as Additional Authenticated Data
to **every chunk's AEAD operation**. Tampering with any header
byte invalidates the very first chunk's tag.

<hr>

## Per-chunk nonce — 12 bytes (STREAM construction)

```text
 byte  | size | field         | source
-------+------+---------------+-----------------------------
 0..7  |  7   | nonce_prefix  | from header byte 16..23
 7..11 |  4   | counter       | u32 big-endian
                              | starts at 0
                              | increments per non-final chunk
                              | increments once after the
                              | exact-chunk_size case (see
                              | "Final chunk semantics" below)
  11   |  1   | last_flag     | 0x00 for non-final chunks
                              | 0x01 for the final chunk
```

This is the [STREAM construction](https://eprint.iacr.org/2015/189.pdf)
by Hoang, Reyhanitabar, Rogaway, and Vizár (2015) — the same
shape AGE encryption uses.

### Why this defeats specific attacks

| Attack | Defense |
|---|---|
| **Truncation** (cut bytes off the end) | The final chunk uses `last_flag = 0x01`. A non-final chunk verified as final has a nonce mismatch → tag fails. |
| **Chunk reorder** (swap two chunks) | The counter is part of the nonce. Swapping gives counter mismatch → tag fails. |
| **Chunk duplicate** (replay) | Same — counter mismatch. |
| **Chunk insertion** | Same — counter mismatch. |
| **Algorithm or chunk-size tamper in header** | The header is AAD on every chunk; tampering changes the AAD bytes → first chunk's tag fails. |
| **Nonce-prefix tamper** | Same — header AAD. |

<hr>

## Chunk body

Each chunk is encrypted via the AEAD identified by the header's
`algorithm` byte, called with:

- `key` — caller-supplied 32 bytes
- `nonce` — derived per-chunk as above (12 bytes)
- `aad` — the full 24-byte header
- `plaintext` — `chunk_size` bytes for non-final chunks; 0 to
  `chunk_size - 1` bytes for the final chunk

The output is `ciphertext || tag` (16-byte tag for both shipped
AEADs). Wire layout per chunk:

```text
 byte  | size       | field
-------+------------+-------------------
 0..N  | N          | ciphertext (N = plaintext length)
 N..N+16| 16        | authentication tag
```

So a non-final chunk is exactly `chunk_size + 16` bytes; the
final chunk is `final_plaintext_len + 16` bytes, where
`final_plaintext_len ∈ [0, chunk_size - 1]`.

<hr>

## Final-chunk-always invariant

The encryptor's `finalize` **always** emits a final chunk. Even
if no plaintext bytes remain at finalisation, a 16-byte chunk
(empty ciphertext + tag) is emitted.

This makes EOF detection unambiguous for the decoder:

- Read `chunk_size + 16` bytes → non-final, decrypt and continue.
- Read fewer → final, decrypt with `last_flag = 0x01` and stop.

### Edge case: plaintext is exact multiple of `chunk_size`

If the buffered plaintext at finalize time is *exactly*
`chunk_size` bytes, the encryptor:

1. Emits those `chunk_size` bytes as a **non-final** chunk.
2. Increments the counter.
3. Emits a **zero-byte final chunk** (just the 16-byte tag).

This preserves the "final chunk is strictly smaller than
`chunk_size + 16`" invariant. Stream body in this case is
`(chunk_size + 16) + 16 = chunk_size + 32` bytes.

<hr>

## Worked example: 100-byte plaintext, 1 KiB chunks

```text
plaintext = 100 bytes of 0x77
chunk_size = 1024 (chunk_size_log2 = 10)
algorithm = ChaCha20-Poly1305
nonce_prefix = 7 random bytes  (call them PPPPPPP)

ENCODED STREAM:
  header (24 bytes):
    [0..8]   89 43 52 59 50 54 49 4f                ; magic
    [8]      01                                     ; version
    [9]      00                                     ; ChaCha20-Poly1305
    [10]     0a                                     ; chunk_size_log2 = 10
    [11..16] 00 00 00 00 00                         ; reserved
    [16..23] PP PP PP PP PP PP PP                   ; nonce_prefix
    [23]     00                                     ; reserved

  chunk_0 (116 bytes — the final chunk, since 100 < 1024):
    [0..100]   ciphertext from encrypt(key, nonce, plaintext, aad=header)
                 where nonce = PPPPPPP || 00000000 || 01
                                          ^^^^^^^^   ^^
                                          counter=0  last_flag=1
    [100..116] 16-byte Poly1305 tag

  TOTAL STREAM SIZE: 24 + 116 = 140 bytes
                     (24 header + 100 ciphertext + 16 tag)
```

For a 2,100-byte plaintext at the same 1 KiB chunk size:

```text
  header (24 bytes)
  chunk_0 (1040 bytes) — non-final, counter=0, last_flag=0
    1024 ciphertext + 16 tag
  chunk_1 (1040 bytes) — non-final, counter=1, last_flag=0
    1024 ciphertext + 16 tag
  chunk_2 (68 bytes)   — final, counter=2, last_flag=1
    52 ciphertext + 16 tag

  TOTAL: 24 + 1040 + 1040 + 68 = 2172 bytes
```

For an exact-multiple plaintext (2,048 bytes at 1 KiB chunks),
the "final chunk is strictly smaller" rule kicks in:

```text
  header (24 bytes)
  chunk_0 (1040 bytes) — non-final, counter=0, last_flag=0
  chunk_1 (1040 bytes) — non-final, counter=1, last_flag=0
  chunk_2 (16 bytes)   — final, counter=2, last_flag=1
                         (0 ciphertext + 16 tag)

  TOTAL: 24 + 1040 + 1040 + 16 = 2120 bytes
```

<hr>

## Counter overflow

The chunk counter is a `u32` (4 bytes). At 64 KiB chunks (the
default), that's `2^32 × 64 KiB = 256 TiB` per stream. Encoding
streams larger than 256 TiB returns
`Error::InvalidCiphertext("stream chunk counter overflow")`
from the encryptor's `update` / `finalize`.

If you need to encrypt more than 256 TiB under a single key,
split it across multiple streams (each with its own random
nonce prefix). Or use a smaller chunk size if you specifically
need more chunks per stream (256 TiB × 4 if you halve the
chunk size).

<hr>

## Compatibility commitments

The wire format described here is **frozen for the 1.x series**.

A file encrypted by `crypt-io 1.0.0` decrypts cleanly with any
`crypt-io 1.x.y` (for x ≥ 0, y ≥ 0).

New `Algorithm` variants added in 1.x minor releases will use
new `algorithm` byte values (0x02, 0x03, ...). A decoder built
against an older 1.x release will return
`Error::InvalidCiphertext("unknown algorithm byte")` for streams
that use a newer algorithm — graceful failure, not a crash.

The reserved bytes (`[11..16]` and `[23]`) are reserved for
future minor-release header extensions and are currently zero-
filled. Decoders MUST NOT reject streams based on the values of
reserved bytes (so future encoders can set them without breaking
older decoders).

Breaking the wire format requires a `2.0` major-version release
with a documented migration path.

<hr>

<sub>crypt-io stream wire format — Copyright (c) 2026 James Gober. Apache-2.0 OR MIT.</sub>
