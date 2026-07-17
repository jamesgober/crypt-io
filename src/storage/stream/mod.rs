//! Version-one chunked authenticated encrypted-stream format.

use core::{cmp::Ordering, fmt};

use aes_gcm::{
    Aes256Gcm,
    aead::{AeadInOut, KeyInit, Nonce, Tag},
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::storage::{
    CryptError, KeyGeneration, KeyId, KeyLease, KeyProvider, KeyScope, MAX_STORAGE_CONTEXT_LEN,
    PurposeId, Result, SpaceId, kdf::derive_storage_key, key::map_key_provider_error,
};

mod incremental;

pub use incremental::{
    AuthenticatedFrame, AuthenticatedPrefix, EncryptedStreamReader, EncryptedStreamWriter,
    PrefixRecoveryError, StreamCompletion, StreamDestinationState, StreamError, StreamIoError,
    StreamIoOperation, StreamMetadata, StreamProgress, StreamRead, StreamReseal, StreamResealError,
    StreamResealPhase,
};

/// Magic bytes at the start of every version-one encrypted stream.
pub const ENCRYPTED_STREAM_MAGIC: &[u8; 8] = b"CRIOSTR\0";

/// Exact fixed header length of a version-one encrypted stream.
pub const ENCRYPTED_STREAM_HEADER_LEN: usize = 160;

/// Exact authenticated header length of every stream frame.
pub const ENCRYPTED_STREAM_FRAME_HEADER_LEN: usize = 48;

/// Default maximum plaintext bytes in one stream frame.
pub const DEFAULT_STREAM_FRAME_PLAINTEXT_LEN: u32 = 1024 * 1024;

/// Absolute maximum plaintext bytes permitted in one stream frame.
pub const MAX_STREAM_FRAME_PLAINTEXT_LEN: u32 = 16 * 1024 * 1024;

/// Maximum authenticated data frames under one derived stream key.
///
/// Encrypted-stream v1 permits at most `2^32` AES-GCM invocations. One
/// invocation is reserved for the mandatory final frame, so data frames stop
/// one sequence earlier even though the wire sequence field is wider.
pub const MAX_STREAM_DATA_FRAMES: u64 = (1_u64 << 32) - 1;

/// Maximum plaintext accepted by the in-memory convenience codec.
///
/// Incremental reader/writer APIs use the same frame format without requiring
/// the complete stream in memory.
pub const MAX_BUFFERED_STREAM_PLAINTEXT_LEN: usize = 64 * 1024 * 1024;

/// Maximum number of data frames accepted by the buffered convenience codec.
///
/// This bounds framing overhead even when a caller selects very small frames.
pub const MAX_BUFFERED_STREAM_DATA_FRAMES: usize = 65_536;

const FORMAT_VERSION: u16 = 1;
const SUITE_AES_256_GCM_HKDF_SHA256: u16 = 1;
const FLAGS_V1: u16 = 0;
const FINAL_FRAME_FLAG: u8 = 1;
const STREAM_SALT_LEN: usize = 32;
const NONCE_PREFIX_LEN: usize = 4;
const TAG_LEN: usize = 16;
const STREAM_CONTEXT_DOMAIN: &[u8] = b"crypt-io/stream-context/v1\0";
const HKDF_INFO_DOMAIN: &[u8] = b"crypt-io/encrypted-stream/v1\0";
const CONTEXT_KEY_DOMAIN: &[u8] = b"crypt-io/encrypted-stream/context-key/v1\0";
const CONTEXT_MAC_DOMAIN: &[u8] = b"crypt-io/encrypted-stream/context-mac/v1\0";

/// Bounded policy used to encode and accept encrypted-stream frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamConfig {
    max_frame_plaintext_len: u32,
}

impl StreamConfig {
    /// Creates a stream policy with an explicit maximum frame length.
    ///
    /// # Errors
    ///
    /// Returns [`CryptError::InvalidInput`] for zero and
    /// [`CryptError::LimitExceeded`] above the absolute format policy.
    pub const fn new(max_frame_plaintext_len: u32) -> Result<Self> {
        if max_frame_plaintext_len == 0 {
            return Err(CryptError::InvalidInput);
        }
        if max_frame_plaintext_len > MAX_STREAM_FRAME_PLAINTEXT_LEN {
            return Err(CryptError::LimitExceeded);
        }
        Ok(Self {
            max_frame_plaintext_len,
        })
    }

    /// Returns the maximum plaintext bytes in one frame.
    #[must_use]
    pub const fn max_frame_plaintext_len(self) -> u32 {
        self.max_frame_plaintext_len
    }
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            max_frame_plaintext_len: DEFAULT_STREAM_FRAME_PLAINTEXT_LEN,
        }
    }
}

/// Caller-owned logical sequence and context bound to an encrypted stream.
///
/// Context values are intentionally not [`Clone`] or [`Copy`] and zeroize their
/// compacted digest on drop.
///
/// # Replay and rollback
///
/// The logical sequence is authenticated, but this crate cannot determine
/// whether it is the newest value. The host must durably protect the highest
/// accepted object or snapshot sequence and atomically advance it with object
/// publication. Reusing an old expected sequence allows an old valid stream to
/// authenticate; fresh nonces, AEAD, and key generation do not establish
/// whole-object freshness.
///
/// ```compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<crypt_io::storage::StreamContext>();
/// ```
///
/// ```compile_fail
/// fn require_eq<T: Eq>() {}
/// require_eq::<crypt_io::storage::StreamContext>();
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct StreamContext {
    logical_sequence: u64,
    digest: [u8; 32],
}

impl fmt::Debug for StreamContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "StreamContext {{ logical_sequence: {}, caller_context: \"[REDACTED]\" }}",
            self.logical_sequence
        )
    }
}

impl StreamContext {
    /// Compacts caller context and associates it with a logical sequence.
    ///
    /// # Errors
    ///
    /// Returns [`CryptError::LimitExceeded`] when `caller_context` is larger
    /// than [`MAX_STORAGE_CONTEXT_LEN`].
    pub fn new(logical_sequence: u64, caller_context: &[u8]) -> Result<Self> {
        if caller_context.len() > MAX_STORAGE_CONTEXT_LEN {
            return Err(CryptError::LimitExceeded);
        }
        let context_len =
            u64::try_from(caller_context.len()).map_err(|_| CryptError::LimitExceeded)?;
        let mut hasher = Sha256::new();
        hasher.update(STREAM_CONTEXT_DOMAIN);
        hasher.update(logical_sequence.to_be_bytes());
        hasher.update(context_len.to_be_bytes());
        hasher.update(caller_context);
        // The compacted context is privacy-sensitive; wipe the temporary
        // digest after copying it into the stored value.
        let mut output = hasher.finalize();
        let mut digest = [0_u8; 32];
        digest.copy_from_slice(&output);
        output.as_mut_slice().zeroize();
        Ok(Self {
            logical_sequence,
            digest,
        })
    }

    /// Returns the caller-owned logical sequence.
    #[must_use]
    pub const fn logical_sequence(&self) -> u64 {
        self.logical_sequence
    }
}

/// Owned encoded encrypted stream.
///
/// Structural possession does not imply authenticity. Only
/// [`EncryptedStreamCodec::open`] authenticates every frame and the mandatory
/// final frame.
///
/// Encoded streams are intentionally not [`Clone`]. Use [`Self::as_bytes`] to
/// borrow or [`Self::into_bytes`] to move the allocation without an infallible
/// duplicate.
///
/// ```compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<crypt_io::storage::EncryptedStream>();
/// ```
#[derive(PartialEq, Eq)]
pub struct EncryptedStream {
    encoded: Vec<u8>,
}

impl EncryptedStream {
    /// Returns the exact versioned wire representation.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }

    /// Consumes the wrapper and returns the exact wire representation.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.encoded
    }
}

impl fmt::Debug for EncryptedStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedStream")
            .field("encoded_len", &self.encoded.len())
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

/// Safe buffered encoder and strict decoder for encrypted-stream v1.
pub struct EncryptedStreamCodec<P> {
    provider: P,
    config: StreamConfig,
}

impl<P> EncryptedStreamCodec<P>
where
    P: KeyProvider,
{
    /// Creates a codec with the one-mebibyte default frame limit.
    #[must_use]
    pub const fn new(provider: P) -> Self {
        Self {
            provider,
            config: StreamConfig {
                max_frame_plaintext_len: DEFAULT_STREAM_FRAME_PLAINTEXT_LEN,
            },
        }
    }

    /// Creates a codec with an explicit bounded frame policy.
    #[must_use]
    pub const fn with_config(provider: P, config: StreamConfig) -> Self {
        Self { provider, config }
    }

    /// Seals a complete buffered plaintext as authenticated data frames plus a
    /// mandatory authenticated final frame.
    ///
    /// # Errors
    ///
    /// Returns a typed limit, allocation, provider, entropy, derivation, or
    /// encryption error. No caller-controlled salt or nonce enters the safe
    /// API.
    pub fn seal(
        &self,
        scope: &KeyScope,
        context: &StreamContext,
        plaintext: &[u8],
    ) -> Result<EncryptedStream> {
        self.seal_with_entropy_source(scope, context, plaintext, getrandom::fill)
    }

    fn seal_with_entropy_source<F, E>(
        &self,
        scope: &KeyScope,
        context: &StreamContext,
        plaintext: &[u8],
        fill: F,
    ) -> Result<EncryptedStream>
    where
        F: FnMut(&mut [u8]) -> core::result::Result<(), E>,
    {
        let frame_len = usize::try_from(self.config.max_frame_plaintext_len())
            .map_err(|_error| CryptError::LimitExceeded)?;
        let (data_frames, capacity) = buffered_stream_layout(plaintext.len(), frame_len)?;
        let mut encoded = try_vec_with_capacity(capacity)?;
        let lease = self
            .provider
            .active(scope)
            .map_err(map_key_provider_error)?;
        let (stream_salt, nonce_prefix) = fresh_stream_material_with(fill)?;
        let derived_key = derive_storage_key(
            &lease,
            scope,
            &stream_salt,
            SUITE_AES_256_GCM_HKDF_SHA256,
            HKDF_INFO_DOMAIN,
        )?;
        let context_binding = encode_context_binding(&lease, scope, &stream_salt, context)?;
        let stream_header = encode_stream_header(
            &lease,
            scope,
            &stream_salt,
            &nonce_prefix,
            self.config,
            &context_binding,
        );
        let cipher = Aes256Gcm::new_from_slice(derived_key.as_ref())
            .map_err(|_error| CryptError::InvalidInput)?;
        encoded.extend_from_slice(&stream_header);

        let mut previous_tag = [0_u8; TAG_LEN];
        for (sequence, chunk) in plaintext.chunks(frame_len).enumerate() {
            let sequence = u64::try_from(sequence).map_err(|_error| CryptError::NonceExhausted)?;
            let frame_header = encode_data_frame_header(sequence, chunk.len(), &previous_tag)?;
            let tag = encrypt_frame(
                &cipher,
                &stream_header,
                &frame_header,
                &nonce_prefix,
                sequence,
                chunk,
                &mut encoded,
            )?;
            previous_tag.copy_from_slice(&tag);
        }

        let data_frames_u64 =
            u64::try_from(data_frames).map_err(|_error| CryptError::NonceExhausted)?;
        let plaintext_len_u64 =
            u64::try_from(plaintext.len()).map_err(|_error| CryptError::LimitExceeded)?;
        let final_header =
            encode_final_frame_header(data_frames_u64, plaintext_len_u64, &previous_tag);
        let _final_tag = encrypt_frame(
            &cipher,
            &stream_header,
            &final_header,
            &nonce_prefix,
            data_frames_u64,
            &[],
            &mut encoded,
        )?;
        Ok(EncryptedStream { encoded })
    }

    /// Strictly opens a complete stream and authenticates its final totals.
    ///
    /// Plaintext from earlier frames is zeroized if any later frame fails.
    /// Missing final frames are never treated as successful streams.
    ///
    /// # Errors
    ///
    /// Returns a typed structure, context, sequence, frame-chain, allocation,
    /// provider, authentication, truncation, trailing-data, or final-frame
    /// error.
    pub fn open(
        &self,
        expected_scope: &KeyScope,
        expected_context: &StreamContext,
        encoded: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let parsed_header = parse_stream_header(encoded, self.config)?;
        validate_expected_scope(&parsed_header.header, expected_scope)?;
        let plaintext_capacity = preflight_stream_structure(encoded, &parsed_header)?;
        let mut plaintext = try_zeroizing_vec_with_capacity(plaintext_capacity)?;
        let lease = self
            .provider
            .by_id(
                expected_scope,
                parsed_header.header.key_id,
                parsed_header.header.generation,
            )
            .map_err(map_key_provider_error)?;
        if lease.key_id() != parsed_header.header.key_id
            || lease.generation() != parsed_header.header.generation
        {
            return Err(CryptError::WrongKey);
        }
        let derived_key = derive_storage_key(
            &lease,
            expected_scope,
            &parsed_header.header.stream_salt,
            SUITE_AES_256_GCM_HKDF_SHA256,
            HKDF_INFO_DOMAIN,
        )?;
        let cipher = Aes256Gcm::new_from_slice(derived_key.as_ref())
            .map_err(|_error| CryptError::InvalidInput)?;
        let mut offset = ENCRYPTED_STREAM_HEADER_LEN;
        let mut expected_sequence = 0_u64;
        let mut previous_tag = [0_u8; TAG_LEN];
        let mut context_verified = false;
        loop {
            if offset == encoded.len() {
                return Err(CryptError::MissingFinalFrame);
            }
            let parsed_frame = parse_frame(
                encoded,
                offset,
                parsed_header.header.max_frame_plaintext_len,
            )?;
            if parsed_frame.header.sequence != expected_sequence {
                return Err(CryptError::SequenceMismatch);
            }
            if parsed_frame.header.previous_tag != previous_tag {
                return Err(CryptError::FrameChainMismatch);
            }

            let decrypted = decrypt_frame(
                &cipher,
                parsed_header.encoded_header,
                &parsed_frame,
                &parsed_header.header.nonce_prefix,
            )?;
            if !context_verified {
                verify_context_binding(
                    &lease,
                    expected_scope,
                    &parsed_header.header.stream_salt,
                    expected_context,
                    &parsed_header.header.context_binding,
                )?;
                context_verified = true;
            }
            if parsed_frame.header.is_final {
                if parsed_frame.header.total_data_frames != expected_sequence
                    || parsed_frame.header.total_plaintext_len
                        != u64::try_from(plaintext.len())
                            .map_err(|_error| CryptError::LimitExceeded)?
                {
                    return Err(CryptError::CorruptStructure);
                }
                if parsed_frame.end.cmp(&encoded.len()) == Ordering::Less {
                    return Err(CryptError::TrailingData);
                }
                return Ok(plaintext);
            }

            if expected_sequence
                >= u64::try_from(MAX_BUFFERED_STREAM_DATA_FRAMES)
                    .map_err(|_error| CryptError::LimitExceeded)?
            {
                return Err(CryptError::LimitExceeded);
            }
            let new_len = plaintext
                .len()
                .checked_add(decrypted.len())
                .ok_or(CryptError::LimitExceeded)?;
            if new_len > MAX_BUFFERED_STREAM_PLAINTEXT_LEN {
                return Err(CryptError::LimitExceeded);
            }
            plaintext.extend_from_slice(&decrypted);
            previous_tag.copy_from_slice(parsed_frame.tag);
            expected_sequence = expected_sequence
                .checked_add(1)
                .ok_or(CryptError::NonceExhausted)?;
            offset = parsed_frame.end;
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct StreamHeader {
    key_id: KeyId,
    generation: KeyGeneration,
    purpose_id: PurposeId,
    space_id: SpaceId,
    stream_salt: [u8; STREAM_SALT_LEN],
    nonce_prefix: [u8; NONCE_PREFIX_LEN],
    max_frame_plaintext_len: u32,
    context_binding: [u8; 32],
}

struct ParsedStreamHeader<'a> {
    header: StreamHeader,
    encoded_header: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
struct FrameHeader {
    sequence: u64,
    ciphertext_len: u32,
    total_data_frames: u64,
    total_plaintext_len: u64,
    previous_tag: [u8; TAG_LEN],
    is_final: bool,
}

struct ParsedFrame<'a> {
    header: FrameHeader,
    encoded_header: &'a [u8],
    ciphertext: &'a [u8],
    tag: &'a [u8],
    end: usize,
}

fn encode_stream_header(
    lease: &KeyLease,
    scope: &KeyScope,
    stream_salt: &[u8; STREAM_SALT_LEN],
    nonce_prefix: &[u8; NONCE_PREFIX_LEN],
    config: StreamConfig,
    context_binding: &[u8; 32],
) -> [u8; ENCRYPTED_STREAM_HEADER_LEN] {
    let mut header = [0_u8; ENCRYPTED_STREAM_HEADER_LEN];
    header[0..8].copy_from_slice(ENCRYPTED_STREAM_MAGIC);
    header[8..10].copy_from_slice(&FORMAT_VERSION.to_be_bytes());
    header[10..12].copy_from_slice(&SUITE_AES_256_GCM_HKDF_SHA256.to_be_bytes());
    header[12..14].copy_from_slice(&FLAGS_V1.to_be_bytes());
    header[14..16].copy_from_slice(&160_u16.to_be_bytes());
    header[16..32].copy_from_slice(lease.key_id().as_bytes());
    header[32..36].copy_from_slice(&lease.generation().get().to_be_bytes());
    header[36..52].copy_from_slice(scope.purpose_id().as_bytes());
    header[52..84].copy_from_slice(scope.space_id().as_bytes());
    header[84..116].copy_from_slice(stream_salt);
    header[116..120].copy_from_slice(nonce_prefix);
    header[120..124].copy_from_slice(&config.max_frame_plaintext_len().to_be_bytes());
    header[124..156].copy_from_slice(context_binding);
    header
}

fn encode_data_frame_header(
    sequence: u64,
    plaintext_len: usize,
    previous_tag: &[u8; TAG_LEN],
) -> Result<[u8; ENCRYPTED_STREAM_FRAME_HEADER_LEN]> {
    let ciphertext_len =
        u32::try_from(plaintext_len).map_err(|_error| CryptError::LimitExceeded)?;
    if ciphertext_len == 0 || ciphertext_len > MAX_STREAM_FRAME_PLAINTEXT_LEN {
        return Err(CryptError::LimitExceeded);
    }
    let mut header = [0_u8; ENCRYPTED_STREAM_FRAME_HEADER_LEN];
    header[0..8].copy_from_slice(&sequence.to_be_bytes());
    header[8..12].copy_from_slice(&ciphertext_len.to_be_bytes());
    header[32..48].copy_from_slice(previous_tag);
    Ok(header)
}

fn encode_final_frame_header(
    data_frames: u64,
    total_plaintext_len: u64,
    previous_tag: &[u8; TAG_LEN],
) -> [u8; ENCRYPTED_STREAM_FRAME_HEADER_LEN] {
    let mut header = [0_u8; ENCRYPTED_STREAM_FRAME_HEADER_LEN];
    header[0..8].copy_from_slice(&data_frames.to_be_bytes());
    header[12] = FINAL_FRAME_FLAG;
    header[16..24].copy_from_slice(&data_frames.to_be_bytes());
    header[24..32].copy_from_slice(&total_plaintext_len.to_be_bytes());
    header[32..48].copy_from_slice(previous_tag);
    header
}

fn encrypt_frame(
    cipher: &Aes256Gcm,
    stream_header: &[u8; ENCRYPTED_STREAM_HEADER_LEN],
    frame_header: &[u8; ENCRYPTED_STREAM_FRAME_HEADER_LEN],
    nonce_prefix: &[u8; NONCE_PREFIX_LEN],
    sequence: u64,
    plaintext: &[u8],
    encoded: &mut Vec<u8>,
) -> Result<[u8; TAG_LEN]> {
    let nonce_bytes = frame_nonce(nonce_prefix, sequence);
    let nonce = Nonce::<Aes256Gcm>::try_from(nonce_bytes.as_slice())
        .map_err(|_error| CryptError::CorruptStructure)?;
    let aad = frame_aad(stream_header, frame_header);
    let mut ciphertext = try_zeroizing_copy(plaintext)?;
    let tag = cipher
        .encrypt_inout_detached(&nonce, &aad, ciphertext.as_mut_slice().into())
        .map_err(|_error| CryptError::InvalidInput)?;
    encoded.extend_from_slice(frame_header);
    encoded.extend_from_slice(&ciphertext);
    encoded.extend_from_slice(tag.as_slice());
    let mut tag_bytes = [0_u8; TAG_LEN];
    tag_bytes.copy_from_slice(tag.as_slice());
    Ok(tag_bytes)
}

fn parse_stream_header(encoded: &[u8], config: StreamConfig) -> Result<ParsedStreamHeader<'_>> {
    if encoded.len() < ENCRYPTED_STREAM_HEADER_LEN {
        return Err(CryptError::Truncated);
    }
    if &encoded[0..8] != ENCRYPTED_STREAM_MAGIC {
        return Err(CryptError::CorruptStructure);
    }
    if read_u16(encoded, 8) != FORMAT_VERSION {
        return Err(CryptError::UnsupportedVersion);
    }
    if read_u16(encoded, 10) != SUITE_AES_256_GCM_HKDF_SHA256 {
        return Err(CryptError::UnsupportedSuite);
    }
    if read_u16(encoded, 12) != FLAGS_V1
        || usize::from(read_u16(encoded, 14)) != ENCRYPTED_STREAM_HEADER_LEN
        || encoded[156..160] != [0_u8; 4]
    {
        return Err(CryptError::CorruptStructure);
    }
    let max_frame_plaintext_len = read_u32(encoded, 120);
    if max_frame_plaintext_len == 0 {
        return Err(CryptError::CorruptStructure);
    }
    if max_frame_plaintext_len > MAX_STREAM_FRAME_PLAINTEXT_LEN
        || max_frame_plaintext_len > config.max_frame_plaintext_len()
    {
        return Err(CryptError::LimitExceeded);
    }
    Ok(ParsedStreamHeader {
        header: StreamHeader {
            key_id: KeyId::new(copy_array::<16>(encoded, 16)),
            generation: KeyGeneration::new(read_u32(encoded, 32)),
            purpose_id: PurposeId::new(copy_array::<16>(encoded, 36)),
            space_id: SpaceId::new(copy_array::<32>(encoded, 52)),
            stream_salt: copy_array::<STREAM_SALT_LEN>(encoded, 84),
            nonce_prefix: copy_array::<NONCE_PREFIX_LEN>(encoded, 116),
            max_frame_plaintext_len,
            context_binding: copy_array::<32>(encoded, 124),
        },
        encoded_header: &encoded[..ENCRYPTED_STREAM_HEADER_LEN],
    })
}

fn parse_frame(
    encoded: &[u8],
    offset: usize,
    max_frame_plaintext_len: u32,
) -> Result<ParsedFrame<'_>> {
    let header_end = offset
        .checked_add(ENCRYPTED_STREAM_FRAME_HEADER_LEN)
        .ok_or(CryptError::LimitExceeded)?;
    if encoded.len() < header_end {
        return Err(CryptError::Truncated);
    }
    let frame_header = &encoded[offset..header_end];
    let header = parse_frame_header(frame_header, max_frame_plaintext_len)?;
    let ciphertext_len =
        usize::try_from(header.ciphertext_len).map_err(|_error| CryptError::LimitExceeded)?;
    let ciphertext_end = header_end
        .checked_add(ciphertext_len)
        .ok_or(CryptError::LimitExceeded)?;
    let frame_end = ciphertext_end
        .checked_add(TAG_LEN)
        .ok_or(CryptError::LimitExceeded)?;
    if encoded.len() < frame_end {
        return Err(CryptError::Truncated);
    }
    Ok(ParsedFrame {
        header,
        encoded_header: frame_header,
        ciphertext: &encoded[header_end..ciphertext_end],
        tag: &encoded[ciphertext_end..frame_end],
        end: frame_end,
    })
}

fn parse_frame_header(frame_header: &[u8], max_frame_plaintext_len: u32) -> Result<FrameHeader> {
    if frame_header.len() != ENCRYPTED_STREAM_FRAME_HEADER_LEN {
        return Err(CryptError::Truncated);
    }
    let sequence = read_u64(frame_header, 0);
    let ciphertext_len = read_u32(frame_header, 8);
    let flags = frame_header[12];
    if frame_header[13..16] != [0_u8; 3] || flags & !FINAL_FRAME_FLAG != 0 {
        return Err(CryptError::CorruptStructure);
    }
    let is_final = flags == FINAL_FRAME_FLAG;
    let total_data_frames = read_u64(frame_header, 16);
    let total_plaintext_len = read_u64(frame_header, 24);
    if is_final {
        if ciphertext_len != 0 {
            return Err(CryptError::CorruptStructure);
        }
    } else if ciphertext_len == 0
        || ciphertext_len > max_frame_plaintext_len
        || total_data_frames != 0
        || total_plaintext_len != 0
    {
        return Err(CryptError::CorruptStructure);
    }
    Ok(FrameHeader {
        sequence,
        ciphertext_len,
        total_data_frames,
        total_plaintext_len,
        previous_tag: copy_array::<TAG_LEN>(frame_header, 32),
        is_final,
    })
}

fn decrypt_frame(
    cipher: &Aes256Gcm,
    stream_header: &[u8],
    frame: &ParsedFrame<'_>,
    nonce_prefix: &[u8; NONCE_PREFIX_LEN],
) -> Result<Zeroizing<Vec<u8>>> {
    let nonce_bytes = frame_nonce(nonce_prefix, frame.header.sequence);
    let nonce = Nonce::<Aes256Gcm>::try_from(nonce_bytes.as_slice())
        .map_err(|_error| CryptError::CorruptStructure)?;
    let tag =
        Tag::<Aes256Gcm>::try_from(frame.tag).map_err(|_error| CryptError::CorruptStructure)?;
    let mut aad = [0_u8; ENCRYPTED_STREAM_HEADER_LEN + ENCRYPTED_STREAM_FRAME_HEADER_LEN];
    aad[..ENCRYPTED_STREAM_HEADER_LEN].copy_from_slice(stream_header);
    aad[ENCRYPTED_STREAM_HEADER_LEN..].copy_from_slice(frame.encoded_header);
    let mut plaintext = try_zeroizing_copy(frame.ciphertext)?;
    cipher
        .decrypt_inout_detached(&nonce, &aad, plaintext.as_mut_slice().into(), &tag)
        .map_err(|_error| CryptError::AuthenticationFailed)?;
    Ok(plaintext)
}

fn validate_expected_scope(header: &StreamHeader, expected_scope: &KeyScope) -> Result<()> {
    if header.purpose_id != expected_scope.purpose_id()
        || header.space_id != expected_scope.space_id()
    {
        return Err(CryptError::ContextMismatch);
    }
    Ok(())
}

fn preflight_stream_structure(
    encoded: &[u8],
    parsed_header: &ParsedStreamHeader<'_>,
) -> Result<usize> {
    let mut offset = ENCRYPTED_STREAM_HEADER_LEN;
    let mut expected_sequence = 0_u64;
    let mut total_plaintext_len = 0_u64;
    let mut previous_tag = [0_u8; TAG_LEN];

    loop {
        if offset == encoded.len() {
            return Err(CryptError::MissingFinalFrame);
        }
        let parsed_frame = parse_frame(
            encoded,
            offset,
            parsed_header.header.max_frame_plaintext_len,
        )?;
        if parsed_frame.header.sequence != expected_sequence {
            return Err(CryptError::SequenceMismatch);
        }
        if parsed_frame.header.previous_tag != previous_tag {
            return Err(CryptError::FrameChainMismatch);
        }
        if parsed_frame.header.is_final {
            if parsed_frame.header.total_data_frames != expected_sequence
                || parsed_frame.header.total_plaintext_len != total_plaintext_len
            {
                return Err(CryptError::CorruptStructure);
            }
            if parsed_frame.end < encoded.len() {
                return Err(CryptError::TrailingData);
            }
            return usize::try_from(total_plaintext_len)
                .map_err(|_error| CryptError::LimitExceeded);
        }

        if expected_sequence
            >= u64::try_from(MAX_BUFFERED_STREAM_DATA_FRAMES)
                .map_err(|_error| CryptError::LimitExceeded)?
        {
            return Err(CryptError::LimitExceeded);
        }
        total_plaintext_len = total_plaintext_len
            .checked_add(
                u64::try_from(parsed_frame.ciphertext.len())
                    .map_err(|_error| CryptError::LimitExceeded)?,
            )
            .ok_or(CryptError::LimitExceeded)?;
        if total_plaintext_len > MAX_BUFFERED_STREAM_PLAINTEXT_LEN as u64 {
            return Err(CryptError::LimitExceeded);
        }
        previous_tag.copy_from_slice(parsed_frame.tag);
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or(CryptError::NonceExhausted)?;
        offset = parsed_frame.end;
    }
}

fn context_mac(
    lease: &KeyLease,
    scope: &KeyScope,
    stream_salt: &[u8; STREAM_SALT_LEN],
    context: &StreamContext,
) -> Result<Hmac<Sha256>> {
    let context_key = derive_storage_key(
        lease,
        scope,
        stream_salt,
        SUITE_AES_256_GCM_HKDF_SHA256,
        CONTEXT_KEY_DOMAIN,
    )?;
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(context_key.as_ref())
        .map_err(|_error| CryptError::InvalidInput)?;
    mac.update(CONTEXT_MAC_DOMAIN);
    mac.update(&context.logical_sequence().to_be_bytes());
    mac.update(&context.digest);
    Ok(mac)
}

fn encode_context_binding(
    lease: &KeyLease,
    scope: &KeyScope,
    stream_salt: &[u8; STREAM_SALT_LEN],
    context: &StreamContext,
) -> Result<[u8; 32]> {
    let output = context_mac(lease, scope, stream_salt, context)?
        .finalize()
        .into_bytes();
    let mut binding = [0_u8; 32];
    binding.copy_from_slice(&output);
    Ok(binding)
}

fn verify_context_binding(
    lease: &KeyLease,
    scope: &KeyScope,
    stream_salt: &[u8; STREAM_SALT_LEN],
    context: &StreamContext,
    encoded_binding: &[u8; 32],
) -> Result<()> {
    context_mac(lease, scope, stream_salt, context)?
        .verify_slice(encoded_binding)
        .map_err(|_error| CryptError::ContextMismatch)
}

fn frame_nonce(nonce_prefix: &[u8; NONCE_PREFIX_LEN], sequence: u64) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[..NONCE_PREFIX_LEN].copy_from_slice(nonce_prefix);
    nonce[NONCE_PREFIX_LEN..].copy_from_slice(&sequence.to_be_bytes());
    nonce
}

fn frame_aad(
    stream_header: &[u8; ENCRYPTED_STREAM_HEADER_LEN],
    frame_header: &[u8; ENCRYPTED_STREAM_FRAME_HEADER_LEN],
) -> [u8; ENCRYPTED_STREAM_HEADER_LEN + ENCRYPTED_STREAM_FRAME_HEADER_LEN] {
    let mut aad = [0_u8; ENCRYPTED_STREAM_HEADER_LEN + ENCRYPTED_STREAM_FRAME_HEADER_LEN];
    aad[..ENCRYPTED_STREAM_HEADER_LEN].copy_from_slice(stream_header);
    aad[ENCRYPTED_STREAM_HEADER_LEN..].copy_from_slice(frame_header);
    aad
}

fn copy_array<const LENGTH: usize>(input: &[u8], offset: usize) -> [u8; LENGTH] {
    let mut output = [0_u8; LENGTH];
    output.copy_from_slice(&input[offset..offset + LENGTH]);
    output
}

fn read_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([input[offset], input[offset + 1]])
}

fn read_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
    ])
}

fn read_u64(input: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
        input[offset + 4],
        input[offset + 5],
        input[offset + 6],
        input[offset + 7],
    ])
}

fn buffered_stream_layout(plaintext_len: usize, frame_len: usize) -> Result<(usize, usize)> {
    if plaintext_len > MAX_BUFFERED_STREAM_PLAINTEXT_LEN {
        return Err(CryptError::LimitExceeded);
    }
    let data_frames = if plaintext_len == 0 {
        0
    } else {
        plaintext_len
            .checked_add(frame_len.checked_sub(1).ok_or(CryptError::InvalidInput)?)
            .ok_or(CryptError::LimitExceeded)?
            / frame_len
    };
    if data_frames > MAX_BUFFERED_STREAM_DATA_FRAMES {
        return Err(CryptError::LimitExceeded);
    }

    let overhead_per_frame = ENCRYPTED_STREAM_FRAME_HEADER_LEN
        .checked_add(TAG_LEN)
        .ok_or(CryptError::LimitExceeded)?;
    let overhead = data_frames
        .checked_add(1)
        .and_then(|count| count.checked_mul(overhead_per_frame))
        .ok_or(CryptError::LimitExceeded)?;
    let capacity = ENCRYPTED_STREAM_HEADER_LEN
        .checked_add(plaintext_len)
        .and_then(|length| length.checked_add(overhead))
        .ok_or(CryptError::LimitExceeded)?;
    Ok((data_frames, capacity))
}

fn fresh_stream_material() -> Result<([u8; STREAM_SALT_LEN], [u8; NONCE_PREFIX_LEN])> {
    fresh_stream_material_with(getrandom::fill)
}

fn fresh_stream_material_with<F, E>(
    mut fill: F,
) -> Result<([u8; STREAM_SALT_LEN], [u8; NONCE_PREFIX_LEN])>
where
    F: FnMut(&mut [u8]) -> core::result::Result<(), E>,
{
    let mut stream_salt = [0_u8; STREAM_SALT_LEN];
    fill(&mut stream_salt).map_err(|_error| CryptError::EntropyUnavailable)?;
    let mut nonce_prefix = [0_u8; NONCE_PREFIX_LEN];
    fill(&mut nonce_prefix).map_err(|_error| CryptError::EntropyUnavailable)?;
    Ok((stream_salt, nonce_prefix))
}

fn try_vec_with_capacity(capacity: usize) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(capacity)
        .map_err(|_error| CryptError::AllocationFailed)?;
    Ok(buffer)
}

fn try_zeroizing_vec_with_capacity(capacity: usize) -> Result<Zeroizing<Vec<u8>>> {
    try_vec_with_capacity(capacity).map(Zeroizing::new)
}

fn try_zeroizing_copy(input: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    try_zeroizing_copy_with_reserver(input, try_reserve_exact)
}

fn try_zeroizing_copy_with_reserver<R>(input: &[u8], reserve: R) -> Result<Zeroizing<Vec<u8>>>
where
    R: FnOnce(&mut Vec<u8>, usize) -> Result<()>,
{
    let mut output = Zeroizing::new(Vec::new());
    reserve(&mut output, input.len())?;
    output.extend_from_slice(input);
    Ok(output)
}

fn try_reserve_exact(buffer: &mut Vec<u8>, additional: usize) -> Result<()> {
    buffer
        .try_reserve_exact(additional)
        .map_err(|_error| CryptError::AllocationFailed)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use hex_literal::hex;

    use super::{
        EncryptedStreamCodec, StreamConfig, StreamContext, fresh_stream_material_with,
        try_vec_with_capacity, try_zeroizing_copy_with_reserver,
    };
    use crate::storage::{
        CryptError, KeyGeneration, KeyId, KeyLease, KeyProvider, KeyProviderError, KeyScope,
        PurposeId, SecretKey32, SpaceId,
    };

    #[derive(Clone, Copy)]
    struct FixtureProvider;

    impl KeyProvider for FixtureProvider {
        fn active(&self, _scope: &KeyScope) -> core::result::Result<KeyLease, KeyProviderError> {
            Ok(fixture_lease())
        }

        fn by_id(
            &self,
            _scope: &KeyScope,
            _key_id: KeyId,
            _generation: KeyGeneration,
        ) -> core::result::Result<KeyLease, KeyProviderError> {
            Ok(fixture_lease())
        }
    }

    fn fixture_lease() -> KeyLease {
        KeyLease::new(
            KeyId::new(*b"stream-key-v0001"),
            KeyGeneration::new(9),
            SecretKey32::new([0xC4; 32]),
        )
    }

    fn fixture_scope() -> KeyScope {
        KeyScope::new(
            SpaceId::new([0x71; 32]),
            PurposeId::new(*b"snapshot-strm-v1"),
        )
    }

    #[test]
    fn test_stream_reservation_capacity_overflow_returns_allocation_failed() {
        assert!(matches!(
            try_vec_with_capacity(usize::MAX),
            Err(CryptError::AllocationFailed)
        ));
    }

    #[test]
    fn test_stream_plaintext_copy_when_reservation_fails_returns_no_plaintext() {
        let result =
            try_zeroizing_copy_with_reserver(b"must never be copied", |_buffer, _additional| {
                Err(CryptError::AllocationFailed)
            });

        assert!(matches!(result, Err(CryptError::AllocationFailed)));
    }

    #[test]
    fn test_stream_context_implements_zeroize_on_drop() {
        fn require_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

        require_zeroize_on_drop::<StreamContext>();
    }

    #[test]
    fn test_stream_entropy_source_when_salt_fails_returns_entropy_unavailable() {
        let mut calls = 0_u8;
        let result = fresh_stream_material_with(|_output| {
            calls = calls.saturating_add(1);
            Err(())
        });

        assert!(matches!(result, Err(CryptError::EntropyUnavailable)));
        assert_eq!(calls, 1);
    }

    #[test]
    fn test_stream_entropy_source_when_nonce_prefix_fails_stops_after_second_fill() {
        let mut calls = 0_u8;
        let result = fresh_stream_material_with(|output| {
            calls = calls.saturating_add(1);
            if calls == 1 {
                output.fill(0xA5);
                Ok(())
            } else {
                Err(())
            }
        });

        assert!(matches!(result, Err(CryptError::EntropyUnavailable)));
        assert_eq!(calls, 2);
    }

    #[test]
    fn test_stream_entropy_source_when_both_fills_succeed_returns_material() {
        let mut calls = 0_u8;
        let (salt, nonce_prefix) = fresh_stream_material_with(|output| {
            calls = calls.saturating_add(1);
            output.fill(calls);
            Ok::<(), ()>(())
        })
        .unwrap();

        assert_eq!(salt, [1_u8; 32]);
        assert_eq!(nonce_prefix, [2_u8; 4]);
        assert_eq!(calls, 2);
    }

    #[test]
    fn test_encrypted_stream_matches_independent_v1_fixture() {
        let codec =
            EncryptedStreamCodec::with_config(FixtureProvider, StreamConfig::new(16).unwrap());
        let mut calls = 0_u8;
        let encoded = codec
            .seal_with_entropy_source(
                &fixture_scope(),
                &StreamContext::new(9, b"snapshot generation 0000000000000009").unwrap(),
                b"golden encrypted stream",
                |output| {
                    calls = calls.saturating_add(1);
                    output.fill(if calls == 1 { 0x11 } else { 0x22 });
                    Ok::<(), ()>(())
                },
            )
            .unwrap();
        let expected = hex!(
            "4352494f5354520000010001000000a073747265616d2d6b65792d7630303031
             00000009736e617073686f742d7374726d2d7631717171717171717171717171
             7171717171717171717171717171717171717171111111111111111111111111
             1111111111111111111111111111111111111111222222220000001032c48227
             18bd37ef9161eb28002d871b55759a0f7ea629e2ece549bfa541d51b00000000
             0000000000000000000000100000000000000000000000000000000000000000
             00000000000000000000000000000000dc9e7e06a63b033d9092242dfdfc05ed
             506ebe810aa4096e99e3ac54bc6fef7500000000000000010000000700000000
             00000000000000000000000000000000506ebe810aa4096e99e3ac54bc6fef75
             1316ce1934ffbfcd13c2a89da40bec51da0baf3363212c000000000000000200
             0000000100000000000000000000020000000000000017cd13c2a89da40bec51
             da0baf3363212c9c21c6411d98d64f5f6adeeea72c4b09"
        );

        assert_eq!(calls, 2);
        assert_eq!(encoded.as_bytes(), expected);
    }
}
