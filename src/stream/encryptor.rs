//! Streaming AEAD encryptor.

use alloc::vec::Vec;
use core::fmt;

use crate::aead::Algorithm;
use crate::error::{Error, Result};
use crate::wipe::{wipe_bytes, wipe_vec};

use super::aead::{encrypt_chunk, encrypt_chunk_into};
use super::frame::{
    DEFAULT_CHUNK_SIZE_LOG2, HEADER_LEN, MAX_CHUNK_SIZE_LOG2, MIN_CHUNK_SIZE_LOG2,
    NONCE_PREFIX_LEN, build_header, build_nonce, chunk_size_from_log2,
};

/// Streaming AEAD encryptor. Buffers caller-supplied plaintext into
/// fixed-size chunks, encrypts each chunk with a STREAM-construction
/// nonce, and emits `ciphertext || tag` per chunk.
///
/// Usage is symmetric with the [`super::StreamDecryptor`]:
///
/// 1. Construct with [`StreamEncryptor::new`]. The constructor returns
///    the encryptor and a 24-byte header — write this header to the
///    output sink first.
/// 2. Feed plaintext via [`update`](Self::update). The method returns
///    zero or more encrypted chunks (each `chunk_size + 16` bytes) as
///    buffer fills are reached.
/// 3. Call [`finalize`](Self::finalize) to emit any remaining buffered
///    data as the final chunk. The final chunk is **always** emitted
///    (even if zero plaintext bytes remain) and is always strictly
///    smaller than `chunk_size + 16` bytes, so the decryptor can
///    detect it unambiguously by length.
///
/// # Example
///
/// ```
/// # #[cfg(all(feature = "stream", feature = "aead-chacha20"))] {
/// use crypt_io::stream::{StreamDecryptor, StreamEncryptor};
/// use crypt_io::Algorithm;
///
/// let key = [0u8; 32];
/// let plaintext = b"the quick brown fox jumps over the lazy dog".repeat(1000);
///
/// // ---- Encrypt ----
/// let (mut enc, header) = StreamEncryptor::new(&key, Algorithm::ChaCha20Poly1305)?;
/// let mut wire = header.to_vec();
/// wire.extend(enc.update(&plaintext)?);
/// wire.extend(enc.finalize()?);
///
/// // ---- Decrypt ----
/// let mut dec = StreamDecryptor::new(&key, &wire[..24])?;
/// let mut recovered = dec.update(&wire[24..])?;
/// recovered.extend(dec.finalize()?);
/// assert_eq!(recovered, plaintext);
/// # }
/// # Ok::<(), crypt_io::Error>(())
/// ```
///
/// # Key and buffer hygiene
///
/// The encryptor keeps its own copy of the key and up to one chunk of
/// buffered plaintext. Both are overwritten with zeros when the value
/// is dropped (including after [`finalize`](Self::finalize)), using
/// volatile writes when the `zeroize` feature is on. The `Debug`
/// output never shows the key, the nonce prefix or buffered plaintext.
///
/// # Limits
///
/// Each stream gets a random 56-bit nonce prefix and is encrypted
/// directly under the caller's key. Two streams whose prefixes collide
/// reuse nonces, which for AES-256-GCM also exposes the GHASH key. Keep
/// a single key below about 2^12 (4,096) streams, or derive a fresh
/// key per stream (for example with `kdf::hkdf_sha256` and a random
/// salt stored next to the ciphertext). See `docs/SECURITY.md`.
pub struct StreamEncryptor {
    algorithm: Algorithm,
    key: [u8; 32],
    nonce_prefix: [u8; NONCE_PREFIX_LEN],
    aad: [u8; HEADER_LEN],
    counter: u32,
    chunk_size: usize,
    chunk_size_log2: u8,
    /// Plaintext awaiting chunking. Held capacity is `chunk_size`.
    buffer: Vec<u8>,
}

impl StreamEncryptor {
    /// Construct a new stream encryptor with the default 64 KiB chunk
    /// size. Returns the encryptor plus the 24-byte header to be
    /// written to the output sink before any encrypted chunks.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidKey`] if `key` is not 32 bytes.
    /// - [`Error::RandomFailure`] if the OS RNG cannot produce a
    ///   nonce prefix.
    pub fn new(key: &[u8], algorithm: Algorithm) -> Result<(Self, [u8; HEADER_LEN])> {
        Self::new_with_chunk_size(key, algorithm, DEFAULT_CHUNK_SIZE_LOG2)
    }

    /// Construct with an explicit chunk size. `chunk_size_log2` must
    /// be in [`MIN_CHUNK_SIZE_LOG2`]`..=`[`MAX_CHUNK_SIZE_LOG2`]
    /// (10..=24).
    ///
    /// # Errors
    ///
    /// See [`new`](Self::new), plus
    /// [`Error::InvalidCiphertext`](crate::Error::InvalidCiphertext)
    /// on out-of-range chunk size.
    pub fn new_with_chunk_size(
        key: &[u8],
        algorithm: Algorithm,
        chunk_size_log2: u8,
    ) -> Result<(Self, [u8; HEADER_LEN])> {
        check_key(key)?;
        if !(MIN_CHUNK_SIZE_LOG2..=MAX_CHUNK_SIZE_LOG2).contains(&chunk_size_log2) {
            return Err(Error::InvalidCiphertext(alloc::format!(
                "chunk_size_log2 out of range: {chunk_size_log2}"
            )));
        }

        let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
        mod_rand::tier3::fill_bytes(&mut nonce_prefix)
            .map_err(|_| Error::RandomFailure("mod_rand::tier3::fill_bytes"))?;

        let header = build_header(algorithm, chunk_size_log2, &nonce_prefix);
        let chunk_size = chunk_size_from_log2(chunk_size_log2);

        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(key);

        let enc = Self {
            algorithm,
            key: key_arr,
            nonce_prefix,
            aad: header,
            counter: 0,
            chunk_size,
            chunk_size_log2,
            buffer: Vec::with_capacity(chunk_size),
        };
        // `[u8; 32]` is `Copy`: the struct got its own copy, so wipe
        // the stack temporary as well.
        wipe_bytes(&mut key_arr);
        Ok((enc, header))
    }

    /// Chunk size in bytes used by this encryptor.
    #[must_use]
    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    /// Log2 of the chunk size, as stored in the header.
    #[must_use]
    pub fn chunk_size_log2(&self) -> u8 {
        self.chunk_size_log2
    }

    /// Feed plaintext bytes. Returns zero or more complete encrypted
    /// chunks (each `chunk_size + 16` bytes) concatenated.
    ///
    /// # Errors
    ///
    /// - [`Error::AuthenticationFailed`] on an upstream AEAD failure
    ///   (unreachable in practice).
    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }

        // Worst case: every byte triggers a chunk boundary. In practice
        // it's at most `data.len() / chunk_size + 1` chunks.
        let estimated_chunks = data.len() / self.chunk_size + 1;
        let mut out = Vec::with_capacity(estimated_chunks * (self.chunk_size + 16));

        // Fill the buffer up to `chunk_size`, emit a non-final chunk,
        // then repeat with the remainder.
        let mut cursor = 0usize;
        while cursor < data.len() {
            let needed = self.chunk_size - self.buffer.len();
            let take = needed.min(data.len() - cursor);
            self.buffer.extend_from_slice(&data[cursor..cursor + take]);
            cursor += take;

            if self.buffer.len() == self.chunk_size {
                let nonce = build_nonce(&self.nonce_prefix, self.counter, false);
                let chunk =
                    encrypt_chunk(self.algorithm, &self.key, &nonce, &self.buffer, &self.aad)?;
                out.extend_from_slice(&chunk);
                self.counter = self.counter.checked_add(1).ok_or(Error::InvalidCiphertext(
                    alloc::string::String::from("stream chunk counter overflow"),
                ))?;
                self.buffer.clear();
            }
        }

        Ok(out)
    }

    /// Flush remaining buffered plaintext as the final chunk. Always
    /// emits at least 16 bytes (the AEAD tag), so the receiver sees
    /// an unambiguous "final" frame.
    ///
    /// # Errors
    ///
    /// Same as [`update`](Self::update).
    pub fn finalize(mut self) -> Result<Vec<u8>> {
        // If buffer is exactly chunk_size, emit it as non-final first,
        // then a 0-byte final chunk. This keeps the invariant
        // "final chunk is strictly < chunk_size + 16 bytes".
        let mut out = Vec::with_capacity(self.chunk_size + 16);
        if self.buffer.len() == self.chunk_size {
            let nonce = build_nonce(&self.nonce_prefix, self.counter, false);
            let chunk = encrypt_chunk(self.algorithm, &self.key, &nonce, &self.buffer, &self.aad)?;
            out.extend_from_slice(&chunk);
            self.counter = self.counter.checked_add(1).ok_or(Error::InvalidCiphertext(
                alloc::string::String::from("stream chunk counter overflow"),
            ))?;
            self.buffer.clear();
        }

        let nonce = build_nonce(&self.nonce_prefix, self.counter, true);
        let final_chunk =
            encrypt_chunk(self.algorithm, &self.key, &nonce, &self.buffer, &self.aad)?;
        out.extend_from_slice(&final_chunk);
        Ok(out)
    }

    /// Zero-allocation [`update`](Self::update) — appends complete
    /// encrypted chunks to `out` instead of returning a new `Vec`.
    /// Reusing the same `out` buffer across calls amortises the
    /// allocation cost away.
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

        // Scratch buffer reused across all chunks emitted by this call.
        // Pre-sized for one full encrypted chunk.
        let mut scratch: Vec<u8> = Vec::with_capacity(self.chunk_size + 16);

        let mut cursor = 0usize;
        while cursor < data.len() {
            let needed = self.chunk_size - self.buffer.len();
            let take = needed.min(data.len() - cursor);
            self.buffer.extend_from_slice(&data[cursor..cursor + take]);
            cursor += take;

            if self.buffer.len() == self.chunk_size {
                let nonce = build_nonce(&self.nonce_prefix, self.counter, false);
                encrypt_chunk_into(
                    self.algorithm,
                    &self.key,
                    &nonce,
                    &self.buffer,
                    &self.aad,
                    &mut scratch,
                )?;
                out.extend_from_slice(&scratch);
                self.counter = self.counter.checked_add(1).ok_or(Error::InvalidCiphertext(
                    alloc::string::String::from("stream chunk counter overflow"),
                ))?;
                self.buffer.clear();
            }
        }

        Ok(())
    }

    /// Zero-allocation [`finalize`](Self::finalize) — appends the
    /// final chunk to `out` instead of returning a new `Vec`. See
    /// [`update_into`](Self::update_into).
    ///
    /// # Errors
    ///
    /// Same as [`finalize`](Self::finalize).
    pub fn finalize_into(mut self, out: &mut Vec<u8>) -> Result<()> {
        let mut scratch: Vec<u8> = Vec::with_capacity(self.chunk_size + 16);

        if self.buffer.len() == self.chunk_size {
            let nonce = build_nonce(&self.nonce_prefix, self.counter, false);
            encrypt_chunk_into(
                self.algorithm,
                &self.key,
                &nonce,
                &self.buffer,
                &self.aad,
                &mut scratch,
            )?;
            out.extend_from_slice(&scratch);
            self.counter = self.counter.checked_add(1).ok_or(Error::InvalidCiphertext(
                alloc::string::String::from("stream chunk counter overflow"),
            ))?;
            self.buffer.clear();
        }

        let nonce = build_nonce(&self.nonce_prefix, self.counter, true);
        encrypt_chunk_into(
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

impl fmt::Debug for StreamEncryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Hand-written so the key, nonce prefix, header and buffered
        // plaintext can never reach logs through `{:?}`.
        f.debug_struct("StreamEncryptor")
            .field("algorithm", &self.algorithm)
            .field("chunk_size", &self.chunk_size)
            .field("counter", &self.counter)
            .field("buffered_len", &self.buffer.len())
            .finish_non_exhaustive()
    }
}

impl Drop for StreamEncryptor {
    fn drop(&mut self) {
        wipe_bytes(&mut self.key);
        wipe_vec(&mut self.buffer);
    }
}

fn check_key(key: &[u8]) -> Result<()> {
    if key.len() == 32 {
        Ok(())
    } else {
        Err(Error::InvalidKey {
            expected: 32,
            actual: key.len(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use core::mem::{MaybeUninit, offset_of};

    /// 1.0.0 had no `Drop` impl: the key copy survived the value
    /// (audit CI-H2, proof of concept 07).
    #[test]
    fn drop_wipes_key_copy() {
        let key: [u8; 32] = core::array::from_fn(|i| 0xa0 ^ u8::try_from(i).unwrap());
        for alg in [Algorithm::ChaCha20Poly1305, Algorithm::Aes256Gcm] {
            let (value, _header) = StreamEncryptor::new(&key, alg).unwrap();
            let mut slot: Box<MaybeUninit<StreamEncryptor>> = Box::new(MaybeUninit::new(value));
            // SAFETY: `slot` holds an initialised value; it is dropped
            // exactly once here and never used as a `StreamEncryptor` again.
            unsafe { slot.assume_init_drop() };
            let off = offset_of!(StreamEncryptor, key);
            // SAFETY: bytes `off..off + 32` are the `key: [u8; 32]`
            // field. They were initialised at construction and drop
            // glue only writes to them; the allocation is still live.
            let after: [u8; 32] = unsafe {
                slot.as_ptr()
                    .cast::<u8>()
                    .add(off)
                    .cast::<[u8; 32]>()
                    .read_unaligned()
            };
            assert_eq!(after, [0u8; 32], "{alg:?}");
        }
    }
}
