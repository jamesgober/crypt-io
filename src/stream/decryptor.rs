//! Streaming AEAD decryptor.

use alloc::vec::Vec;

use crate::aead::Algorithm;
use crate::error::{Error, Result};

use super::aead::{decrypt_chunk, decrypt_chunk_into};
use super::frame::{HEADER_LEN, NONCE_PREFIX_LEN, build_nonce, chunk_size_from_log2, parse_header};

/// Streaming AEAD decryptor — the inverse of [`super::StreamEncryptor`].
///
/// Construct from the 24-byte header, feed encrypted chunk bytes via
/// [`update`](Self::update), and finalise with
/// [`finalize`](Self::finalize). The decryptor buffers exactly enough
/// bytes to know whether the next chunk is final, so callers don't
/// need to track chunk boundaries — only "this is all the bytes" (via
/// `finalize`).
///
/// Authentication failures (tampered ciphertext, wrong key, tampered
/// header, truncated stream, reordered chunks, duplicated chunks) all
/// surface as [`Error::AuthenticationFailed`]. The variant is
/// intentionally opaque — exposing which mode failed would leak
/// information to an attacker.
///
/// # Example
///
/// See [`super::StreamEncryptor`] for a round-trip example.
#[derive(Debug)]
pub struct StreamDecryptor {
    algorithm: Algorithm,
    key: [u8; 32],
    nonce_prefix: [u8; NONCE_PREFIX_LEN],
    aad: [u8; HEADER_LEN],
    counter: u32,
    chunk_size: usize,
    chunk_size_log2: u8,
    /// Encrypted bytes awaiting decryption. Always holds at most
    /// `chunk_size + 16` bytes after each `update` returns.
    buffer: Vec<u8>,
}

impl StreamDecryptor {
    /// Construct a decryptor by parsing `header_bytes` (must be at
    /// least 24 bytes — only the first 24 are read).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidKey`] if `key` is not 32 bytes.
    /// - [`Error::InvalidCiphertext`] if the header is malformed
    ///   (wrong magic, unsupported version, unknown algorithm,
    ///   out-of-range chunk size).
    pub fn new(key: &[u8], header_bytes: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            return Err(Error::InvalidKey {
                expected: 32,
                actual: key.len(),
            });
        }
        let parsed = parse_header(header_bytes)?;
        let chunk_size = chunk_size_from_log2(parsed.chunk_size_log2);

        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(key);

        Ok(Self {
            algorithm: parsed.algorithm,
            key: key_arr,
            nonce_prefix: parsed.nonce_prefix,
            aad: parsed.raw,
            counter: 0,
            chunk_size,
            chunk_size_log2: parsed.chunk_size_log2,
            // capacity = one non-final chunk's worth
            buffer: Vec::with_capacity(chunk_size + 16),
        })
    }

    /// Chunk size in bytes for this decryptor (read from the header).
    #[must_use]
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    /// Log2 of the chunk size (read from the header).
    #[must_use]
    pub fn chunk_size_log2(&self) -> u8 {
        self.chunk_size_log2
    }

    /// Algorithm encoded in the header.
    #[must_use]
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Feed encrypted-stream bytes. Returns zero or more decrypted
    /// plaintext bytes as complete non-final chunks are processed.
    ///
    /// The decryptor holds at most `chunk_size + 16` bytes in its
    /// internal buffer between calls — that's exactly one full
    /// non-final chunk, held in case it turns out to be the final
    /// chunk (signalled by the next `update` having nothing to add or
    /// `finalize` being called).
    ///
    /// # Errors
    ///
    /// - [`Error::AuthenticationFailed`] for any cryptographic
    ///   failure: tampered ciphertext, wrong key, tampered header,
    ///   chunk-counter desync, etc.
    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        self.buffer.extend_from_slice(data);

        let chunk_frame = self.chunk_size + 16;
        let mut out = Vec::new();

        // Process any chunks for which we know they are non-final:
        // a chunk is non-final iff there is more than `chunk_frame`
        // bytes in the buffer (because the encryptor guarantees the
        // final chunk is strictly < `chunk_frame` bytes).
        while self.buffer.len() > chunk_frame {
            let chunk_bytes: Vec<u8> = self.buffer.drain(..chunk_frame).collect();
            let nonce = build_nonce(&self.nonce_prefix, self.counter, false);
            let pt = decrypt_chunk(self.algorithm, &self.key, &nonce, &chunk_bytes, &self.aad)?;
            out.extend_from_slice(&pt);
            self.counter = self.counter.checked_add(1).ok_or(Error::InvalidCiphertext(
                alloc::string::String::from("stream chunk counter overflow"),
            ))?;
        }

        Ok(out)
    }

    /// Flush. Treats whatever is in the buffer as the final encrypted
    /// chunk and decrypts it. Returns the final plaintext bytes.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidCiphertext`] if the buffer is shorter than 16
    ///   bytes (cannot contain a tag) — typically caused by a stream
    ///   that lost its final chunk entirely.
    /// - [`Error::AuthenticationFailed`] if the buffered bytes do not
    ///   verify as the final chunk under the expected nonce. This
    ///   covers truncation (a buffered chunk that the encoder wrote
    ///   as non-final being treated as final by the decoder),
    ///   tampering, and wrong key.
    pub fn finalize(self) -> Result<Vec<u8>> {
        let chunk_frame = self.chunk_size + 16;
        if self.buffer.len() > chunk_frame {
            // The update loop holds at most chunk_frame bytes; we
            // shouldn't reach here.
            return Err(Error::InvalidCiphertext(alloc::format!(
                "stream finalize buffer too large ({} bytes, max {chunk_frame})",
                self.buffer.len()
            )));
        }
        if self.buffer.len() < 16 {
            return Err(Error::InvalidCiphertext(alloc::format!(
                "stream finalize buffer too short ({} bytes, need at least 16 for tag)",
                self.buffer.len()
            )));
        }

        let nonce = build_nonce(&self.nonce_prefix, self.counter, true);
        decrypt_chunk(self.algorithm, &self.key, &nonce, &self.buffer, &self.aad)
    }

    /// Zero-allocation [`update`](Self::update) — appends decrypted
    /// plaintext to `out` instead of returning a new `Vec`. Reusing
    /// the same `out` buffer across calls amortises the allocation
    /// cost away.
    ///
    /// New in 0.10.0.
    ///
    /// # Errors
    ///
    /// Same as [`update`](Self::update).
    pub fn update_into(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        self.buffer.extend_from_slice(data);

        let chunk_frame = self.chunk_size + 16;
        let mut scratch: Vec<u8> = Vec::with_capacity(self.chunk_size);

        while self.buffer.len() > chunk_frame {
            let chunk_bytes: Vec<u8> = self.buffer.drain(..chunk_frame).collect();
            let nonce = build_nonce(&self.nonce_prefix, self.counter, false);
            decrypt_chunk_into(
                self.algorithm,
                &self.key,
                &nonce,
                &chunk_bytes,
                &self.aad,
                &mut scratch,
            )?;
            out.extend_from_slice(&scratch);
            self.counter = self.counter.checked_add(1).ok_or(Error::InvalidCiphertext(
                alloc::string::String::from("stream chunk counter overflow"),
            ))?;
        }

        Ok(())
    }

    /// Zero-allocation [`finalize`](Self::finalize) — appends the
    /// final decrypted plaintext to `out` instead of returning a new
    /// `Vec`. See [`update_into`](Self::update_into).
    ///
    /// # Errors
    ///
    /// Same as [`finalize`](Self::finalize).
    pub fn finalize_into(self, out: &mut Vec<u8>) -> Result<()> {
        let chunk_frame = self.chunk_size + 16;
        if self.buffer.len() > chunk_frame {
            return Err(Error::InvalidCiphertext(alloc::format!(
                "stream finalize buffer too large ({} bytes, max {chunk_frame})",
                self.buffer.len()
            )));
        }
        if self.buffer.len() < 16 {
            return Err(Error::InvalidCiphertext(alloc::format!(
                "stream finalize buffer too short ({} bytes, need at least 16 for tag)",
                self.buffer.len()
            )));
        }

        let mut scratch: Vec<u8> = Vec::with_capacity(self.chunk_size);
        let nonce = build_nonce(&self.nonce_prefix, self.counter, true);
        decrypt_chunk_into(
            self.algorithm,
            &self.key,
            &nonce,
            &self.buffer,
            &self.aad,
            &mut scratch,
        )?;
        out.extend_from_slice(&scratch);
        Ok(())
    }
}
