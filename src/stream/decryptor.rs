//! Streaming AEAD decryptor.

use alloc::vec::Vec;
use core::fmt;

use crate::aead::Algorithm;
use crate::error::{Error, Result};
use crate::wipe::{reserve_wiping, wipe_bytes, wipe_tail, wipe_vec, wipe_vec_upto};

use super::aead::decrypt_chunk_append;
use super::frame::{
    HEADER_LEN, MAX_AAD_LEN, MAX_NONCE_LEN, NONCE_PREFIX_LEN, SALT_LEN, StreamFormat, TAG_LEN,
    chunk_nonce, chunk_size_from_log2, derive_v2, parse_header,
};

/// Streaming AEAD decryptor — the inverse of [`super::StreamEncryptor`].
///
/// Construct from the 24-byte header, feed the rest of the stream via
/// [`update`](Self::update), and finalise with
/// [`finalize`](Self::finalize). The decryptor buffers exactly enough
/// bytes to know whether the next chunk is final, so callers don't
/// need to track chunk boundaries — only "this is all the bytes" (via
/// `finalize`).
///
/// Both stream formats are read: the version is taken from the header.
/// For format v2 the 32-byte salt that follows the header is consumed
/// by `update` like any other stream bytes, so callers pass everything
/// after the first 24 bytes, exactly as for v1.
///
/// Authentication failures (tampered ciphertext, wrong key, tampered
/// header or salt, truncated stream, reordered chunks, duplicated
/// chunks) all surface as [`Error::AuthenticationFailed`]. The variant
/// is intentionally opaque — exposing which mode failed would leak
/// information to an attacker.
///
/// Plaintext returned before [`finalize`](Self::finalize) succeeds is
/// authentic chunk by chunk but not yet known to be complete; see
/// [`update`](Self::update).
///
/// The decryptor's key copy and internal buffer are overwritten with
/// zeros on drop, and its `Debug` output never shows the key, the nonce
/// prefix or buffered bytes.
///
/// # Example
///
/// See [`super::StreamEncryptor`] for a round-trip example.
pub struct StreamDecryptor {
    algorithm: Algorithm,
    format: StreamFormat,
    /// v1: the caller's key. v2: the caller's key until the salt has
    /// arrived, then the per-stream subkey.
    key: [u8; 32],
    nonce_base: [u8; MAX_NONCE_LEN],
    nonce_len: usize,
    /// `header` (v1) or `header || salt` (v2).
    aad: [u8; MAX_AAD_LEN],
    aad_len: usize,
    /// v2: salt bytes received so far (`SALT_LEN` once keyed). Always
    /// `SALT_LEN` for v1.
    salt_have: usize,
    counter: u32,
    chunk_size: usize,
    chunk_size_log2: u8,
    /// Encrypted bytes awaiting decryption. Always holds at most
    /// `chunk_size + 16` bytes after each `update` returns.
    buffer: Vec<u8>,
    /// Largest length `buffer` ever reached: on drop, only that many
    /// bytes of its allocation can hold data and need wiping.
    buffer_high_water: usize,
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
    ///   out-of-range chunk size, or non-zero reserved bytes in a v2
    ///   header).
    pub fn new(key: &[u8], header_bytes: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            return Err(Error::InvalidKey {
                expected: 32,
                actual: key.len(),
            });
        }
        let parsed = parse_header(header_bytes)?;
        let chunk_size = chunk_size_from_log2(parsed.chunk_size_log2);

        let mut dec = Self {
            algorithm: parsed.algorithm,
            format: parsed.format,
            key: [0u8; 32],
            nonce_base: [0u8; MAX_NONCE_LEN],
            nonce_len: parsed.algorithm.nonce_len(),
            aad: [0u8; MAX_AAD_LEN],
            aad_len: HEADER_LEN,
            salt_have: SALT_LEN,
            counter: 0,
            chunk_size,
            chunk_size_log2: parsed.chunk_size_log2,
            // capacity = one non-final chunk's worth
            buffer: Vec::with_capacity(chunk_size + TAG_LEN),
            buffer_high_water: 0,
        };
        dec.key.copy_from_slice(key);
        dec.aad[..HEADER_LEN].copy_from_slice(&parsed.raw);
        match parsed.format {
            StreamFormat::V1 => {
                dec.nonce_base[..NONCE_PREFIX_LEN].copy_from_slice(&parsed.nonce_prefix);
            }
            StreamFormat::V2 => {
                dec.aad_len = HEADER_LEN + SALT_LEN;
                dec.salt_have = 0;
            }
        }
        Ok(dec)
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

    /// Format version of the stream (read from the header). Use it to
    /// find v1 streams worth re-encrypting. New in 1.1.0.
    #[must_use]
    pub fn format(&self) -> StreamFormat {
        self.format
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
    /// Work is linear in `data.len()`: complete chunks are decrypted
    /// straight from `data`, and only a trailing partial chunk is
    /// copied into the internal buffer. Feeding a whole file in one
    /// call costs the same as feeding it in slices.
    ///
    /// # Plaintext released here is not yet end-authenticated
    ///
    /// Every chunk returned by `update` has passed its own tag check,
    /// so it is authentic and in order. What has **not** been checked
    /// yet is that the stream is complete: an attacker who truncates
    /// the stream at a chunk boundary is only detected by
    /// [`finalize`](Self::finalize). Do not act on (or publish) the
    /// output until `finalize` has returned `Ok`; on error, discard
    /// everything this decryptor produced.
    ///
    /// # Errors
    ///
    /// - [`Error::AuthenticationFailed`] for any cryptographic
    ///   failure: tampered ciphertext, wrong key, tampered header,
    ///   chunk-counter desync, etc. Plaintext already decrypted by this
    ///   call is wiped before the error is returned.
    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        // Sized up front so the output never reallocates (a
        // reallocation would leave a plaintext copy in freed memory).
        let mut out = Vec::with_capacity(self.buffer.len().saturating_add(data.len()));
        if let Err(e) = self.process(data, &mut out) {
            wipe_vec(&mut out);
            return Err(e);
        }
        Ok(out)
    }

    /// Flush. Treats whatever is in the buffer as the final encrypted
    /// chunk and decrypts it. Returns the final plaintext bytes.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidCiphertext`] if the buffer is shorter than 16
    ///   bytes (cannot contain a tag), or a v2 stream ended inside its
    ///   salt — typically caused by a stream that lost its final chunk
    ///   entirely.
    /// - [`Error::AuthenticationFailed`] if the buffered bytes do not
    ///   verify as the final chunk under the expected nonce. This
    ///   covers truncation (a buffered chunk that the encoder wrote
    ///   as non-final being treated as final by the decoder),
    ///   tampering, and wrong key.
    pub fn finalize(self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.buffer.len());
        self.finalize_core(&mut out)?;
        Ok(out)
    }

    /// Zero-allocation [`update`](Self::update) — appends decrypted
    /// plaintext to `out` instead of returning a new `Vec`. Reusing
    /// the same `out` buffer across calls amortises the allocation
    /// cost away.
    ///
    /// The same end-authentication caveat as [`update`](Self::update)
    /// applies. On error, anything this call appended is wiped and
    /// `out` is truncated back to the length it had on entry; bytes
    /// that were already in `out` are left alone. If `out` has to
    /// grow, its old allocation is wiped before it is freed.
    ///
    /// New in 0.10.0.
    ///
    /// # Errors
    ///
    /// Same as [`update`](Self::update).
    pub fn update_into(&mut self, data: &[u8], out: &mut Vec<u8>) -> Result<()> {
        reserve_wiping(out, self.buffer.len().saturating_add(data.len()));
        let start = out.len();
        let result = self.process(data, out);
        if result.is_err() {
            wipe_tail(out, start);
        }
        result
    }

    /// Zero-allocation [`finalize`](Self::finalize) — appends the
    /// final decrypted plaintext to `out` instead of returning a new
    /// `Vec`. See [`update_into`](Self::update_into). On error `out`
    /// is left as it was on entry.
    ///
    /// # Errors
    ///
    /// Same as [`finalize`](Self::finalize).
    pub fn finalize_into(self, out: &mut Vec<u8>) -> Result<()> {
        self.finalize_core(out)
    }

    /// v2: collect salt bytes from the front of `data`; once all 32
    /// have arrived, swap the caller's key for the stream subkey.
    /// Returns the bytes of `data` that follow the salt.
    fn take_salt<'a>(&mut self, data: &'a [u8]) -> Result<&'a [u8]> {
        let need = SALT_LEN - self.salt_have;
        let take = need.min(data.len());
        let at = HEADER_LEN + self.salt_have;
        self.aad[at..at + take].copy_from_slice(&data[..take]);
        self.salt_have += take;
        if self.salt_have == SALT_LEN {
            let mut header = [0u8; HEADER_LEN];
            header.copy_from_slice(&self.aad[..HEADER_LEN]);
            let mut master = self.key;
            let derived = derive_v2(
                &master,
                &header,
                &self.aad[HEADER_LEN..HEADER_LEN + SALT_LEN],
                self.nonce_len,
                &mut self.key,
                &mut self.nonce_base,
            );
            wipe_bytes(&mut master);
            derived?;
        }
        Ok(&data[take..])
    }

    /// Shared body of `update` / `update_into`. Appends plaintext to
    /// `out`. A chunk is known to be non-final once more than one
    /// full frame (`chunk_size + 16` bytes) is available, because the
    /// encryptor guarantees the final chunk is strictly shorter.
    fn process(&mut self, mut data: &[u8], out: &mut Vec<u8>) -> Result<()> {
        if self.salt_have < SALT_LEN {
            data = self.take_salt(data)?;
        }
        let frame = self.chunk_size + TAG_LEN;

        // 1. Top up a partially-filled buffer first.
        if !self.buffer.is_empty() {
            let take = (frame - self.buffer.len()).min(data.len());
            self.buffer.extend_from_slice(&data[..take]);
            self.buffer_high_water = self.buffer_high_water.max(self.buffer.len());
            data = &data[take..];
            if self.buffer.len() < frame || data.is_empty() {
                // Either not a full frame yet, or a full frame with
                // nothing after it (it might be the final chunk).
                return Ok(());
            }
            // A full frame with more bytes after it: non-final.
            self.open_chunk(&self.buffer, false, out)?;
            self.advance_counter()?;
            self.buffer.clear();
        }

        // 2. Decrypt complete non-final frames directly from `data`.
        while data.len() > frame {
            let (chunk, rest) = data.split_at(frame);
            self.open_chunk(chunk, false, out)?;
            self.advance_counter()?;
            data = rest;
        }

        // 3. Keep the tail (at most one frame) for the next call.
        self.buffer.extend_from_slice(data);
        self.buffer_high_water = self.buffer_high_water.max(self.buffer.len());
        Ok(())
    }

    fn open_chunk(&self, chunk: &[u8], is_final: bool, out: &mut Vec<u8>) -> Result<()> {
        let nonce = chunk_nonce(&self.nonce_base, self.nonce_len, self.counter, is_final);
        decrypt_chunk_append(
            self.algorithm,
            &self.key,
            &nonce[..self.nonce_len],
            chunk,
            &self.aad[..self.aad_len],
            out,
        )
    }

    fn advance_counter(&mut self) -> Result<()> {
        self.counter = self.counter.checked_add(1).ok_or(Error::InvalidCiphertext(
            alloc::string::String::from("stream chunk counter overflow"),
        ))?;
        Ok(())
    }

    /// Shared body of `finalize` / `finalize_into`. Appends to `out`;
    /// on error `out` is left as it was on entry.
    fn finalize_core(&self, out: &mut Vec<u8>) -> Result<()> {
        if self.salt_have < SALT_LEN {
            return Err(Error::InvalidCiphertext(alloc::format!(
                "stream ended inside the v2 salt ({} of {SALT_LEN} bytes)",
                self.salt_have
            )));
        }
        let frame = self.chunk_size + TAG_LEN;
        if self.buffer.len() > frame {
            // `process` holds at most one frame; unreachable.
            return Err(Error::InvalidCiphertext(alloc::format!(
                "stream finalize buffer too large ({} bytes, max {frame})",
                self.buffer.len()
            )));
        }
        if self.buffer.len() < TAG_LEN {
            return Err(Error::InvalidCiphertext(alloc::format!(
                "stream finalize buffer too short ({} bytes, need at least {TAG_LEN} for tag)",
                self.buffer.len()
            )));
        }
        self.open_chunk(&self.buffer, true, out)
    }
}

impl fmt::Debug for StreamDecryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Hand-written so the key, nonce prefix, header and buffered
        // bytes can never reach logs through `{:?}`.
        f.debug_struct("StreamDecryptor")
            .field("algorithm", &self.algorithm)
            .field("format", &self.format)
            .field("chunk_size", &self.chunk_size)
            .field("counter", &self.counter)
            .field("buffered_len", &self.buffer.len())
            .finish_non_exhaustive()
    }
}

impl Drop for StreamDecryptor {
    fn drop(&mut self) {
        wipe_bytes(&mut self.key);
        wipe_vec_upto(&mut self.buffer, self.buffer_high_water);
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
            let (_enc, header) = super::super::StreamEncryptor::new(&key, alg).unwrap();
            let value = StreamDecryptor::new(&key, &header).unwrap();
            let mut slot: Box<MaybeUninit<StreamDecryptor>> = Box::new(MaybeUninit::new(value));
            // SAFETY: `slot` holds an initialised value; it is dropped
            // exactly once here and never used as a `StreamDecryptor` again.
            unsafe { slot.assume_init_drop() };
            let off = offset_of!(StreamDecryptor, key);
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

    /// 1.0.0 appended the whole input to `self.buffer` and drained it
    /// from the front one chunk at a time, which made a single large
    /// `update` quadratic (audit CI-M4: 32 MiB took 46 s). The
    /// buffer must never hold more than one frame.
    #[test]
    #[cfg_attr(miri, ignore = "64 KiB through two AEADs is too slow under Miri")]
    fn update_never_buffers_more_than_one_frame() {
        let key = [1u8; 32];
        let pt = alloc::vec![0x5au8; 64 * 1024 + 300];
        for alg in [Algorithm::ChaCha20Poly1305, Algorithm::Aes256Gcm] {
            let (mut enc, header) =
                super::super::StreamEncryptor::new_with_chunk_size(&key, alg, 10).unwrap();
            let mut wire = Vec::new();
            enc.update_into(&pt, &mut wire).unwrap();
            enc.finalize_into(&mut wire).unwrap();
            let frame = 1024 + TAG_LEN;

            let mut dec = StreamDecryptor::new(&key, &header).unwrap();
            let mut out = Vec::new();
            dec.update_into(&wire, &mut out).unwrap();
            assert!(dec.buffer.len() <= frame, "{alg:?}: {}", dec.buffer.len());
            assert!(
                dec.buffer.capacity() <= frame,
                "{alg:?}: buffer grew to {} bytes for a {}-byte input",
                dec.buffer.capacity(),
                wire.len()
            );
            dec.finalize_into(&mut out).unwrap();
            assert_eq!(out, pt);
        }
    }
}
