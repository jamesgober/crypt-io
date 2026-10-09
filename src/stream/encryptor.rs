//! Streaming AEAD encryptor.

use alloc::vec::Vec;
use core::fmt;

use crate::aead::Algorithm;
use crate::error::{Error, Result};
use crate::wipe::{wipe_bytes, wipe_vec_upto};

use super::aead::encrypt_chunk_append;
use super::frame::{
    DEFAULT_CHUNK_SIZE_LOG2, HEADER_LEN, MAX_AAD_LEN, MAX_NONCE_LEN, NONCE_PREFIX_LEN, SALT_LEN,
    StreamFormat, TAG_LEN, build_header_v1, build_header_v2, chunk_nonce, chunk_size_from_log2,
    chunk_size_log2_in_range, derive_v2,
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
///    buffer fills are reached. In format v2 (the default) the first
///    output of `update` / `update_into` / `finalize` / `finalize_into`
///    also starts with the stream's 32-byte salt; write every output to
///    the sink in order and this is handled for you.
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
/// The encryptor keeps a 32-byte key (in format v2 the per-stream
/// subkey, never the caller's key) and up to one chunk of buffered
/// plaintext. Both are overwritten with zeros when the value is dropped
/// (including after [`finalize`](Self::finalize)), using volatile
/// writes when the `zeroize` feature is on. The `Debug` output never
/// shows the key, the nonce prefix or buffered plaintext.
///
/// # Limits
///
/// Format v2 (the default since 1.1.0) derives a fresh subkey from a
/// 256-bit random salt for every stream, so there is no practical limit
/// on the number of streams per key. Format v1
/// ([`StreamFormat::V1`]) encrypts every stream directly under the
/// caller's key with a random 56-bit nonce prefix; keep a key below
/// about 2^12 (4,096) v1 streams. A single stream holds at most 2^32
/// chunks (256 TiB at the default chunk size).
pub struct StreamEncryptor {
    algorithm: Algorithm,
    format: StreamFormat,
    /// Chunk key: the caller's key (v1) or the per-stream subkey (v2).
    key: [u8; 32],
    /// Nonce prefix in the first `nonce_len - 5` bytes.
    nonce_base: [u8; MAX_NONCE_LEN],
    nonce_len: usize,
    /// `header` (v1) or `header || salt` (v2).
    aad: [u8; MAX_AAD_LEN],
    aad_len: usize,
    /// v2: the salt has not been written out yet.
    salt_pending: bool,
    counter: u32,
    chunk_size: usize,
    chunk_size_log2: u8,
    /// Plaintext awaiting chunking. Held capacity is `chunk_size`.
    buffer: Vec<u8>,
    /// Largest length `buffer` ever reached: on drop, only that many
    /// bytes of its allocation can hold data and need wiping.
    buffer_high_water: usize,
}

impl StreamEncryptor {
    /// Construct a new stream encryptor with the default 64 KiB chunk
    /// size, writing format v2. Returns the encryptor plus the 24-byte
    /// header to be written to the output sink before anything else.
    ///
    /// Requires a random source (`std` or `getrandom` feature).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidKey`] if `key` is not 32 bytes.
    /// - [`Error::RandomFailure`] if the OS RNG cannot produce the
    ///   stream salt.
    pub fn new(key: &[u8], algorithm: Algorithm) -> Result<(Self, [u8; HEADER_LEN])> {
        Self::new_with_chunk_size(key, algorithm, DEFAULT_CHUNK_SIZE_LOG2)
    }

    /// Construct with an explicit chunk size, writing format v2.
    /// `chunk_size_log2` must be in
    /// [`MIN_CHUNK_SIZE_LOG2`](super::MIN_CHUNK_SIZE_LOG2)`..=`[`MAX_CHUNK_SIZE_LOG2`](super::MAX_CHUNK_SIZE_LOG2)
    /// (10..=24).
    ///
    /// # Errors
    ///
    /// See [`new`](Self::new), plus [`Error::InvalidInput`] on an
    /// out-of-range chunk size (1.0.x returned
    /// [`Error::InvalidCiphertext`]).
    pub fn new_with_chunk_size(
        key: &[u8],
        algorithm: Algorithm,
        chunk_size_log2: u8,
    ) -> Result<(Self, [u8; HEADER_LEN])> {
        Self::new_with_format(key, algorithm, chunk_size_log2, StreamFormat::V2)
    }

    /// Construct with an explicit chunk size and stream format.
    ///
    /// Use [`StreamFormat::V1`] only while some readers still run
    /// crypt-io 1.0.x, which cannot read v2 streams; v1 has a limit of
    /// about 2^12 streams per key. New in 1.1.0.
    ///
    /// # Errors
    ///
    /// See [`new_with_chunk_size`](Self::new_with_chunk_size), plus
    /// [`Error::InvalidInput`] for [`StreamFormat::V1`] with
    /// [`Algorithm::XChaCha20Poly1305`] (v1 has no byte for it).
    pub fn new_with_format(
        key: &[u8],
        algorithm: Algorithm,
        chunk_size_log2: u8,
        format: StreamFormat,
    ) -> Result<(Self, [u8; HEADER_LEN])> {
        check_args(key, algorithm, chunk_size_log2, format)?;
        let mut random = [0u8; SALT_LEN];
        let random = match format {
            StreamFormat::V1 => &mut random[..NONCE_PREFIX_LEN],
            StreamFormat::V2 => &mut random[..],
        };
        crate::rng::fill(random)?;
        Self::build(key, algorithm, chunk_size_log2, format, random)
    }

    /// Shared constructor. `random` is the 7-byte v1 nonce prefix or
    /// the 32-byte v2 salt. Arguments are already checked.
    pub(super) fn build(
        key: &[u8],
        algorithm: Algorithm,
        chunk_size_log2: u8,
        format: StreamFormat,
        random: &[u8],
    ) -> Result<(Self, [u8; HEADER_LEN])> {
        check_args(key, algorithm, chunk_size_log2, format)?;
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(key);
        let nonce_len = algorithm.nonce_len();
        let mut nonce_base = [0u8; MAX_NONCE_LEN];
        let mut aad = [0u8; MAX_AAD_LEN];
        let chunk_size = chunk_size_from_log2(chunk_size_log2);

        let mut enc = Self {
            algorithm,
            format,
            key: [0u8; 32],
            nonce_base,
            nonce_len,
            aad,
            aad_len: HEADER_LEN,
            salt_pending: false,
            counter: 0,
            chunk_size,
            chunk_size_log2,
            buffer: Vec::with_capacity(chunk_size),
            buffer_high_water: 0,
        };
        let header = match format {
            StreamFormat::V1 => {
                let mut prefix = [0u8; NONCE_PREFIX_LEN];
                prefix.copy_from_slice(random);
                let header = build_header_v1(algorithm, chunk_size_log2, &prefix);
                nonce_base[..NONCE_PREFIX_LEN].copy_from_slice(&prefix);
                enc.key = key_arr;
                header
            }
            StreamFormat::V2 => {
                let header = build_header_v2(algorithm, chunk_size_log2);
                let derived = derive_v2(
                    &key_arr,
                    &header,
                    random,
                    nonce_len,
                    &mut enc.key,
                    &mut nonce_base,
                );
                if derived.is_err() {
                    wipe_bytes(&mut key_arr);
                }
                derived?;
                aad[HEADER_LEN..].copy_from_slice(random);
                enc.aad_len = HEADER_LEN + SALT_LEN;
                enc.salt_pending = true;
                header
            }
        };
        aad[..HEADER_LEN].copy_from_slice(&header);
        enc.aad = aad;
        enc.nonce_base = nonce_base;
        // `[u8; 32]` is `Copy`: wipe the stack temporary as well.
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

    /// The AEAD algorithm this encryptor uses. New in 1.1.0.
    #[must_use]
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// The stream format this encryptor writes. New in 1.1.0.
    #[must_use]
    pub fn format(&self) -> StreamFormat {
        self.format
    }

    /// Feed plaintext bytes. Returns zero or more complete encrypted
    /// chunks (each `chunk_size + 16` bytes) concatenated, preceded by
    /// the 32-byte salt on the first call of a v2 stream.
    ///
    /// # Errors
    ///
    /// - [`Error::LimitExceeded`] once the stream reaches 2^32 chunks
    ///   (1.0.x returned [`Error::InvalidCiphertext`]).
    pub fn update(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.update_len_bound(data.len()));
        self.update_into(data, &mut out)?;
        Ok(out)
    }

    /// Flush remaining buffered plaintext as the final chunk. Always
    /// emits at least 16 bytes (the AEAD tag), so the receiver sees
    /// an unambiguous "final" frame.
    ///
    /// # Errors
    ///
    /// Same as [`update`](Self::update).
    pub fn finalize(self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(SALT_LEN + self.buffer.len() + 2 * TAG_LEN);
        self.finalize_into(&mut out)?;
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
        self.emit_salt(out);
        let mut rest = data;
        while !rest.is_empty() {
            if self.buffer.is_empty() && rest.len() >= self.chunk_size {
                // Whole chunk available: encrypt it straight from the
                // input, without staging it in `buffer`.
                let (chunk, tail) = rest.split_at(self.chunk_size);
                self.seal_chunk(chunk, false, out)?;
                self.advance()?;
                rest = tail;
                continue;
            }
            let take = (self.chunk_size - self.buffer.len()).min(rest.len());
            self.buffer.extend_from_slice(&rest[..take]);
            self.buffer_high_water = self.buffer_high_water.max(self.buffer.len());
            rest = &rest[take..];
            if self.buffer.len() == self.chunk_size {
                self.seal_chunk(&self.buffer, false, out)?;
                self.advance()?;
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
        self.emit_salt(out);
        // A full buffer is emitted as non-final first, then a 0-byte
        // final chunk. This keeps the invariant "final chunk is
        // strictly < chunk_size + 16 bytes". (`update` never leaves a
        // full buffer behind, so this is defensive.)
        if self.buffer.len() == self.chunk_size {
            self.seal_chunk(&self.buffer, false, out)?;
            self.advance()?;
            self.buffer.clear();
        }
        self.seal_chunk(&self.buffer, true, out)
    }

    /// Upper bound on what `update(data_len)` appends.
    fn update_len_bound(&self, data_len: usize) -> usize {
        let chunks = self.buffer.len().saturating_add(data_len) / self.chunk_size;
        let salt = if self.salt_pending { SALT_LEN } else { 0 };
        chunks
            .saturating_mul(self.chunk_size + TAG_LEN)
            .saturating_add(salt)
    }

    fn emit_salt(&mut self, out: &mut Vec<u8>) {
        if self.salt_pending {
            out.extend_from_slice(&self.aad[HEADER_LEN..HEADER_LEN + SALT_LEN]);
            self.salt_pending = false;
        }
    }

    fn seal_chunk(&self, plaintext: &[u8], is_final: bool, out: &mut Vec<u8>) -> Result<()> {
        let nonce = chunk_nonce(&self.nonce_base, self.nonce_len, self.counter, is_final);
        encrypt_chunk_append(
            self.algorithm,
            &self.key,
            &nonce[..self.nonce_len],
            plaintext,
            &self.aad[..self.aad_len],
            out,
        )
    }

    fn advance(&mut self) -> Result<()> {
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or(Error::LimitExceeded("stream: chunk counter overflow"))?;
        Ok(())
    }
}

fn check_args(
    key: &[u8],
    algorithm: Algorithm,
    chunk_size_log2: u8,
    format: StreamFormat,
) -> Result<()> {
    if key.len() != 32 {
        return Err(Error::InvalidKey {
            expected: 32,
            actual: key.len(),
        });
    }
    if !chunk_size_log2_in_range(chunk_size_log2) {
        return Err(Error::InvalidInput(
            "stream: chunk_size_log2 out of range (10..=24)",
        ));
    }
    if format == StreamFormat::V1 && algorithm == Algorithm::XChaCha20Poly1305 {
        return Err(Error::InvalidInput(
            "stream: format v1 cannot carry XChaCha20-Poly1305",
        ));
    }
    Ok(())
}

impl fmt::Debug for StreamEncryptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Hand-written so the key, nonce prefix, header, salt and
        // buffered plaintext can never reach logs through `{:?}`.
        f.debug_struct("StreamEncryptor")
            .field("algorithm", &self.algorithm)
            .field("format", &self.format)
            .field("chunk_size", &self.chunk_size)
            .field("counter", &self.counter)
            .field("buffered_len", &self.buffer.len())
            .finish_non_exhaustive()
    }
}

impl Drop for StreamEncryptor {
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

    include!("test_vectors.rs");

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    /// (algorithm, `chunk_size_log2`, plaintext, wire hex, (subkey hex, prefix hex))
    type VectorCase = (
        Algorithm,
        u8,
        Vec<u8>,
        &'static str,
        (&'static str, &'static str),
    );

    fn vector_cases() -> [VectorCase; 3] {
        [
            (
                Algorithm::ChaCha20Poly1305,
                10,
                (0..1100u32)
                    .map(|i| u8::try_from(i % 251).unwrap())
                    .collect(),
                STREAM_V2_CHACHA_1100,
                STREAM_V2_CHACHA_1100_SUBKEY_PREFIX,
            ),
            (
                Algorithm::Aes256Gcm,
                16,
                b"crypt-io stream format v2 frozen vector".to_vec(),
                STREAM_V2_AES_SHORT,
                STREAM_V2_AES_SHORT_SUBKEY_PREFIX,
            ),
            (
                Algorithm::XChaCha20Poly1305,
                10,
                (0..2048u32)
                    .map(|i| u8::try_from((i * 7) % 256).unwrap())
                    .collect(),
                STREAM_V2_XCHACHA_2048,
                STREAM_V2_XCHACHA_2048_SUBKEY_PREFIX,
            ),
        ]
    }

    /// The encrypt side of format v2, byte for byte, against vectors
    /// from an independent implementation.
    #[test]
    #[cfg_attr(miri, ignore = "several KiB through the AEADs is slow under Miri")]
    fn v2_encrypt_matches_frozen_vectors() {
        let key: [u8; 32] = core::array::from_fn(|i| u8::try_from(i).unwrap());
        let salt: [u8; 32] = core::array::from_fn(|i| 0xb0 + u8::try_from(i).unwrap());
        for (alg, log2, pt, wire_hex, (subkey_hex, prefix_hex)) in vector_cases() {
            let expected = unhex(wire_hex);

            let (enc, header) =
                StreamEncryptor::build(&key, alg, log2, StreamFormat::V2, &salt).unwrap();
            assert_eq!(enc.key.to_vec(), unhex(subkey_hex), "{alg:?} subkey");
            let plen = alg.nonce_len() - 5;
            assert_eq!(
                enc.nonce_base[..plen].to_vec(),
                unhex(prefix_hex),
                "{alg:?} prefix"
            );
            let mut wire = header.to_vec();
            let mut enc = enc;
            enc.update_into(&pt, &mut wire).unwrap();
            enc.finalize_into(&mut wire).unwrap();
            assert_eq!(wire, expected, "{alg:?} one update");

            // Same bytes when the plaintext arrives one byte at a time.
            let (mut enc, header) =
                StreamEncryptor::build(&key, alg, log2, StreamFormat::V2, &salt).unwrap();
            let mut wire = header.to_vec();
            for b in &pt {
                wire.extend(enc.update(core::slice::from_ref(b)).unwrap());
            }
            wire.extend(enc.finalize().unwrap());
            assert_eq!(wire, expected, "{alg:?} byte by byte");
        }
    }

    #[test]
    fn v2_never_keeps_the_callers_key() {
        let key = [0x5au8; 32];
        for alg in [
            Algorithm::ChaCha20Poly1305,
            Algorithm::Aes256Gcm,
            Algorithm::XChaCha20Poly1305,
        ] {
            let (enc, _) = StreamEncryptor::new(&key, alg).unwrap();
            assert_ne!(enc.key, key, "{alg:?}");
            assert_eq!(enc.format(), StreamFormat::V2);
            assert_eq!(enc.algorithm(), alg);
        }
    }

    #[test]
    fn v1_rejects_xchacha_and_bad_chunk_size_is_invalid_input() {
        let key = [0u8; 32];
        assert!(matches!(
            StreamEncryptor::new_with_format(
                &key,
                Algorithm::XChaCha20Poly1305,
                16,
                StreamFormat::V1
            )
            .unwrap_err(),
            Error::InvalidInput(_)
        ));
        for bad in [9u8, 25] {
            assert!(matches!(
                StreamEncryptor::new_with_chunk_size(&key, Algorithm::ChaCha20Poly1305, bad)
                    .unwrap_err(),
                Error::InvalidInput(_)
            ));
        }
    }

    #[test]
    fn debug_shows_no_secrets() {
        let key = [0xabu8; 32];
        let (mut enc, _) = StreamEncryptor::new(&key, Algorithm::ChaCha20Poly1305).unwrap();
        let _ = enc.update(b"SECRETPLAINTEXT").unwrap();
        let dbg = alloc::format!("{enc:?}");
        assert!(dbg.contains("V2"), "{dbg}");
        assert!(!dbg.contains("171"), "{dbg}"); // 0xab
        assert!(!dbg.contains("SECRET"), "{dbg}");
    }
}
