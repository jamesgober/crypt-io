//! Streaming / file encryption.
//!
//! Chunked AEAD with a [STREAM-construction] frame format. Lets you
//! encrypt data that doesn't fit in memory, transport it in pieces,
//! and decrypt back to the original with the same authentication
//! guarantees as the single-shot [`crate::Crypt`] surface — plus
//! detection of chunk truncation, reordering, and duplication.
//!
//! [STREAM-construction]: https://eprint.iacr.org/2015/189.pdf
//!
//! # Quick API tour
//!
//! - [`StreamEncryptor`] — buffer plaintext, emit chunks of `chunk_size`
//!   ciphertext + 16 bytes of authentication tag.
//! - [`StreamDecryptor`] — feed encrypted bytes, get plaintext as
//!   complete chunks decrypt.
//! - [`encrypt_file`] / [`decrypt_file`] *(requires `std`)* — the
//!   common "encrypt this file into that file" workflow.
//!
//! [`StreamDecryptor`] works in any build. [`StreamEncryptor`]'s
//! constructors need a random source (`std` or the `getrandom`
//! feature).
//!
//! # Wire format
//!
//! See [`frame`] and `docs/FILE_FORMAT.md` for the on-the-wire layout:
//! a 24-byte header, a 32-byte salt (format v2), then N-1 non-final
//! chunks of `chunk_size + 16` bytes each, then 1 final chunk of
//! strictly less than `chunk_size + 16` bytes. The final chunk is
//! always emitted (even if it carries zero plaintext) so the decoder
//! can detect end-of-stream unambiguously.
//!
//! crypt-io 1.1 writes **format v2** by default: every stream gets a
//! random 256-bit salt and its chunks are encrypted under a subkey
//! derived with HKDF-SHA256 from the caller's key and that salt. 1.0.x
//! wrote **format v1** (chunks directly under the caller's key with a
//! random 56-bit nonce prefix), which 1.1 still reads. Readers on
//! crypt-io 1.0.x cannot read v2; see [`StreamFormat`].
//!
//! # Security properties
//!
//! - **Tampering** in any chunk → `Error::AuthenticationFailed` on
//!   that chunk's decrypt.
//! - **Truncation** (cutting bytes off the end of the stream) →
//!   `Error::AuthenticationFailed` when the buffered "almost-final"
//!   chunk fails to verify under the `last_flag = 1` nonce.
//! - **Reordering or duplicating chunks** → each chunk's nonce
//!   includes a 32-bit counter; swapping or repeating produces a
//!   counter mismatch and an authentication failure.
//! - **Header tampering** (flipping the algorithm byte, the chunk
//!   size, the nonce prefix or the v2 salt) → the header (and salt)
//!   bytes are bound into every chunk's AAD and, in v2, into the
//!   subkey; tampering shows up as authentication failure on the
//!   first chunk, or as `InvalidCiphertext` for a malformed header.
//! - **Wrong key** → authentication failure on the first chunk.
//!
//! # Limits and caveats
//!
//! - **Streams per key.** Format v2 (the default) has no practical
//!   limit: two streams only share nonces if their 256-bit salts
//!   collide. Format v1 streams use a random 56-bit nonce prefix
//!   directly under the caller's key; keep one key below about 2^12
//!   (4,096) of those. See [`StreamEncryptor`](StreamEncryptor#limits).
//! - **Early output is not end-authenticated.** Plaintext returned by
//!   [`StreamDecryptor::update`] is authentic chunk by chunk, but
//!   truncation at a chunk boundary is only detected by
//!   [`StreamDecryptor::finalize`]. Don't act on it before `finalize`
//!   returns `Ok`. `decrypt_file` handles this for you.
//!
//! # Example
//!
//! ```
//! # #[cfg(all(feature = "stream", feature = "aead-chacha20"))] {
//! use crypt_io::Algorithm;
//! use crypt_io::stream::{StreamEncryptor, StreamDecryptor};
//!
//! let key = [0u8; 32];
//! let plaintext = b"the quick brown fox jumps over the lazy dog".repeat(1000);
//!
//! // Encrypt
//! let (mut enc, header) = StreamEncryptor::new(&key, Algorithm::ChaCha20Poly1305)?;
//! let mut wire = header.to_vec();
//! wire.extend(enc.update(&plaintext)?);
//! wire.extend(enc.finalize()?);
//!
//! // Decrypt
//! let mut dec = StreamDecryptor::new(&key, &wire[..24])?;
//! let mut recovered = dec.update(&wire[24..])?;
//! recovered.extend(dec.finalize()?);
//!
//! assert_eq!(recovered, plaintext);
//! # }
//! # Ok::<(), crypt_io::Error>(())
//! ```

// Crypto-style: pass fixed-size keys/nonces/prefixes by reference for
// caller clarity, even when clippy thinks small arrays should be
// pass-by-value. Matches the convention of every RustCrypto crate.
#![allow(clippy::trivially_copy_pass_by_ref)]

mod aead;
mod decryptor;
#[cfg(any(feature = "std", feature = "getrandom"))]
mod encryptor;
pub mod frame;

#[cfg(feature = "std")]
mod file;

pub use self::decryptor::StreamDecryptor;
#[cfg(any(feature = "std", feature = "getrandom"))]
pub use self::encryptor::StreamEncryptor;

#[cfg(feature = "std")]
pub use self::file::{decrypt_file, encrypt_file};

// Re-export the bits of the frame format that callers may want to
// reason about. Keep the rest of `frame` crate-private — it's
// implementation detail of the wire format.
pub use self::frame::{
    DEFAULT_CHUNK_SIZE_LOG2, HEADER_LEN, MAX_CHUNK_SIZE_LOG2, MIN_CHUNK_SIZE_LOG2, SALT_LEN,
    StreamFormat, TAG_LEN,
};
