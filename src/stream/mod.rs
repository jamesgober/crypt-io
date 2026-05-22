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
//! # Wire format
//!
//! See [`frame`] for the on-the-wire layout: 24-byte header, then
//! N-1 non-final chunks of `chunk_size + 16` bytes each, then 1
//! final chunk of strictly less than `chunk_size + 16` bytes. The
//! final chunk is always emitted (even if it carries zero plaintext)
//! so the decoder can detect end-of-stream unambiguously.
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
//!   size, or the nonce prefix) → the header bytes are bound into
//!   every chunk's AAD; tampering shows up as authentication failure
//!   on the first chunk.
//! - **Wrong key** → authentication failure on the first chunk.
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
mod encryptor;
pub mod frame;

#[cfg(feature = "std")]
mod file;

pub use self::decryptor::StreamDecryptor;
pub use self::encryptor::StreamEncryptor;

#[cfg(feature = "std")]
pub use self::file::{decrypt_file, encrypt_file};

// Re-export the bits of the frame format that callers may want to
// reason about. Keep the rest of `frame` crate-private — it's
// implementation detail of the wire format.
pub use self::frame::{
    DEFAULT_CHUNK_SIZE_LOG2, HEADER_LEN, MAX_CHUNK_SIZE_LOG2, MIN_CHUNK_SIZE_LOG2, TAG_LEN,
};
