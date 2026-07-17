//! Version-one authenticated sealed-record format.

use core::{cmp::Ordering, fmt};

use aes_gcm::{
    Aes256Gcm,
    aead::{AeadInOut, KeyInit, Nonce, Tag},
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::storage::{
    CryptError, KeyDescriptor, KeyGeneration, KeyId, KeyLease, KeyProvider, KeyScope,
    MAX_STORAGE_CONTEXT_LEN, PurposeId, Result, SpaceId, kdf::derive_storage_key,
    key::map_key_provider_error,
};

/// Magic bytes at the start of every version-one sealed record.
pub const SEALED_RECORD_MAGIC: &[u8; 8] = b"CRIOREC\0";

/// Exact fixed header length of a version-one sealed record.
pub const SEALED_RECORD_HEADER_LEN: usize = 176;

/// Maximum plaintext bytes accepted by one sealed record.
///
/// Larger payloads must use the bounded encrypted-stream format instead.
pub const MAX_SEALED_RECORD_PLAINTEXT_LEN: usize = 16 * 1024 * 1024;

const FORMAT_VERSION: u16 = 1;
const SUITE_AES_256_GCM_HKDF_SHA256: u16 = 1;
const FLAGS_V1: u16 = 0;
const TAG_LEN: usize = 16;
const RECORD_SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const CONTEXT_DOMAIN: &[u8] = b"crypt-io/record-context/v1\0";
const HKDF_INFO_DOMAIN: &[u8] = b"crypt-io/sealed-record/v1\0";
const CONTEXT_KEY_DOMAIN: &[u8] = b"crypt-io/sealed-record/context-key/v1\0";
const CONTEXT_MAC_DOMAIN: &[u8] = b"crypt-io/sealed-record/context-mac/v1\0";

/// Caller-owned sequence and context bound into a sealed record.
///
/// The caller supplies the expected value again when opening a record. Neither
/// raw context nor its unkeyed digest is stored. The encoded header contains a
/// per-record keyed verifier that cannot be tested without key access.
/// Context values are intentionally not [`Clone`] or [`Copy`] and zeroize their
/// compacted digest on drop.
///
/// # Replay and rollback
///
/// The logical sequence is authenticated, but this crate cannot determine
/// whether it is the newest value. The host must durably protect the highest
/// accepted object sequence and atomically advance it with publication.
/// Reusing an old expected sequence allows an old valid record to authenticate;
/// fresh nonces, AEAD, and key generation do not establish object freshness.
///
/// ```compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<crypt_io::storage::RecordContext>();
/// ```
///
/// ```compile_fail
/// fn require_eq<T: Eq>() {}
/// require_eq::<crypt_io::storage::RecordContext>();
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecordContext {
    logical_sequence: u64,
    digest: [u8; 32],
}

impl fmt::Debug for RecordContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "RecordContext {{ logical_sequence: {}, caller_context: \"[REDACTED]\" }}",
            self.logical_sequence
        )
    }
}

impl RecordContext {
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
        hasher.update(CONTEXT_DOMAIN);
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

/// Owned encoded sealed record.
///
/// Possession or structural parsing of this type does not imply authenticity.
/// Only [`RecordCodec::open`] authenticates it.
///
/// Encoded records are intentionally not [`Clone`]. Use [`Self::as_bytes`] to
/// borrow or [`Self::into_bytes`] to move the allocation without an infallible
/// duplicate.
///
/// ```compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<crypt_io::storage::SealedRecord>();
/// ```
#[derive(PartialEq, Eq)]
pub struct SealedRecord {
    encoded: Vec<u8>,
}

impl SealedRecord {
    /// Structurally validates and copies encoded bytes without authenticating.
    ///
    /// # Errors
    ///
    /// Returns a typed format error for malformed, oversized, truncated, or
    /// trailing input, or [`CryptError::AllocationFailed`] when the validated
    /// encoded bytes cannot be copied.
    pub fn try_from_bytes(encoded: &[u8]) -> Result<Self> {
        let _parsed = parse_record(encoded)?;
        Ok(Self {
            encoded: try_copy_bytes(encoded)?,
        })
    }

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

impl fmt::Debug for SealedRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedRecord")
            .field("encoded_len", &self.encoded.len())
            .field("contents", &"[REDACTED]")
            .finish()
    }
}

/// Result of an authenticated record rotation or scope migration.
pub struct RecordReseal {
    record: SealedRecord,
    source_key: KeyDescriptor,
    destination_key: KeyDescriptor,
    was_resealed: bool,
}

impl RecordReseal {
    /// Returns the resulting sealed record.
    #[must_use]
    pub const fn record(&self) -> &SealedRecord {
        &self.record
    }

    /// Consumes the outcome and returns the resulting sealed record.
    #[must_use]
    pub fn into_record(self) -> SealedRecord {
        self.record
    }

    /// Returns the authenticated source key descriptor.
    #[must_use]
    pub const fn source_key(&self) -> KeyDescriptor {
        self.source_key
    }

    /// Returns the verified destination key descriptor.
    #[must_use]
    pub const fn destination_key(&self) -> KeyDescriptor {
        self.destination_key
    }

    /// Reports whether new ciphertext was produced.
    #[must_use]
    pub const fn was_resealed(&self) -> bool {
        self.was_resealed
    }
}

impl fmt::Debug for RecordReseal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordReseal")
            .field("source_key", &self.source_key)
            .field("destination_key", &self.destination_key)
            .field("was_resealed", &self.was_resealed)
            .field("record", &self.record)
            .finish()
    }
}

/// Safe version-one sealed-record encoder and decoder.
///
/// The codec obtains keys through an external [`KeyProvider`], generates all
/// salt and nonce material internally, and requires expected scope and context
/// on every open operation.
pub struct RecordCodec<P> {
    provider: P,
}

impl<P> RecordCodec<P>
where
    P: KeyProvider,
{
    /// Creates a codec over an external key provider.
    #[must_use]
    pub const fn new(provider: P) -> Self {
        Self { provider }
    }

    /// Seals plaintext with the active key for `scope`.
    ///
    /// # Errors
    ///
    /// Returns an error when the input exceeds the format limit, the key
    /// provider fails, operating-system entropy is unavailable, key derivation
    /// fails, memory cannot be reserved, or AES-GCM cannot seal the record.
    pub fn seal(
        &self,
        scope: &KeyScope,
        context: &RecordContext,
        plaintext: &[u8],
    ) -> Result<SealedRecord> {
        validate_plaintext_len(plaintext.len())?;
        let (record_salt, nonce_bytes) = fresh_record_material()?;
        self.seal_with_material(scope, context, plaintext, record_salt, nonce_bytes)
    }

    fn seal_with_material(
        &self,
        scope: &KeyScope,
        context: &RecordContext,
        plaintext: &[u8],
        record_salt: [u8; RECORD_SALT_LEN],
        nonce_bytes: [u8; NONCE_LEN],
    ) -> Result<SealedRecord> {
        validate_plaintext_len(plaintext.len())?;
        let lease = self
            .provider
            .active(scope)
            .map_err(map_key_provider_error)?;
        self.seal_with_lease(&lease, scope, context, plaintext, record_salt, nonce_bytes)
    }

    // This remains a method so every sealing path shares one codec-owned API;
    // the provider-free fixture path is intentionally private.
    #[allow(clippy::unused_self)]
    fn seal_with_lease(
        &self,
        lease: &KeyLease,
        scope: &KeyScope,
        context: &RecordContext,
        plaintext: &[u8],
        record_salt: [u8; RECORD_SALT_LEN],
        nonce_bytes: [u8; NONCE_LEN],
    ) -> Result<SealedRecord> {
        validate_plaintext_len(plaintext.len())?;
        let capacity = SEALED_RECORD_HEADER_LEN
            .checked_add(plaintext.len())
            .and_then(|length| length.checked_add(TAG_LEN))
            .ok_or(CryptError::LimitExceeded)?;
        let mut encoded = try_vec_with_capacity(capacity)?;
        let derived_key = derive_storage_key(
            lease,
            scope,
            &record_salt,
            SUITE_AES_256_GCM_HKDF_SHA256,
            HKDF_INFO_DOMAIN,
        )?;
        let context_binding = encode_context_binding(lease, scope, &record_salt, context)?;
        let header = encode_header(
            lease,
            scope,
            &record_salt,
            &nonce_bytes,
            context,
            &context_binding,
            plaintext.len(),
        )?;
        let cipher = Aes256Gcm::new_from_slice(derived_key.as_ref())
            .map_err(|_error| CryptError::InvalidInput)?;
        let nonce = Nonce::<Aes256Gcm>::try_from(nonce_bytes.as_slice())
            .map_err(|_error| CryptError::CorruptStructure)?;
        let mut ciphertext = try_zeroizing_copy(plaintext)?;
        let tag = cipher
            .encrypt_inout_detached(&nonce, &header, ciphertext.as_mut_slice().into())
            .map_err(|_error| CryptError::InvalidInput)?;

        encoded.extend_from_slice(&header);
        encoded.extend_from_slice(&ciphertext);
        encoded.extend_from_slice(tag.as_slice());
        Ok(SealedRecord { encoded })
    }

    /// Opens and authenticates an encoded record under caller-supplied scope
    /// and context.
    ///
    /// Plaintext is returned in a buffer that zeroizes on drop. No plaintext is
    /// returned when authentication or any prior validation fails.
    ///
    /// # Errors
    ///
    /// Returns a typed format, context, provider, key-descriptor, allocation,
    /// or authentication error. Tag failure is always
    /// [`CryptError::AuthenticationFailed`].
    pub fn open(
        &self,
        expected_scope: &KeyScope,
        expected_context: &RecordContext,
        encoded: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let parsed = parse_record(encoded)?;
        validate_expected_scope_and_sequence(&parsed.header, expected_scope, expected_context)?;

        let lease = self
            .provider
            .by_id(
                expected_scope,
                parsed.header.key_id,
                parsed.header.generation,
            )
            .map_err(map_key_provider_error)?;
        if lease.key_id() != parsed.header.key_id || lease.generation() != parsed.header.generation
        {
            return Err(CryptError::WrongKey);
        }
        self.open_parsed_with_lease(&parsed, expected_scope, expected_context, &lease)
    }

    /// Authenticates a record and re-seals it with the provider's active key.
    ///
    /// If the record is already on the exact active descriptor, the active
    /// secret is independently verified against the record and the original
    /// bytes are returned unchanged. Reusing a descriptor for different secret
    /// material fails as [`CryptError::WrongKey`]. A newer same-scope descriptor
    /// backed by the source secret fails as [`CryptError::KeyMaterialReuse`].
    ///
    /// # Errors
    ///
    /// Returns any source authentication, provider, entropy, allocation,
    /// destination authentication, or descriptor-consistency failure.
    pub fn rotate_to_active(
        &self,
        scope: &KeyScope,
        context: &RecordContext,
        encoded: &[u8],
    ) -> Result<RecordReseal> {
        let parsed = parse_record(encoded)?;
        validate_expected_scope_and_sequence(&parsed.header, scope, context)?;
        let source_key = KeyDescriptor::new(parsed.header.key_id, parsed.header.generation);
        let source_lease = self
            .provider
            .by_id(scope, parsed.header.key_id, parsed.header.generation)
            .map_err(map_key_provider_error)?;
        if source_lease.descriptor() != source_key {
            return Err(CryptError::WrongKey);
        }
        let plaintext = self.open_parsed_with_lease(&parsed, scope, context, &source_lease)?;
        let active = self
            .provider
            .active(scope)
            .map_err(map_key_provider_error)?;
        let destination_key = active.descriptor();
        let same_secret = constant_time_key_lease_secret_eq(&source_lease, &active);

        if source_key == destination_key {
            if !same_secret {
                return Err(CryptError::WrongKey);
            }
            return Ok(RecordReseal {
                record: SealedRecord {
                    encoded: try_copy_bytes(encoded)?,
                },
                source_key,
                destination_key,
                was_resealed: false,
            });
        }

        validate_rotation_progress(source_key, destination_key)?;
        if same_secret {
            return Err(CryptError::KeyMaterialReuse);
        }

        let (record_salt, nonce_bytes) = fresh_record_material()?;
        let record = self.seal_with_lease(
            &active,
            scope,
            context,
            &plaintext,
            record_salt,
            nonce_bytes,
        )?;
        let verified = self.open(scope, context, record.as_bytes())?;
        if !constant_time_bytes_eq(verified.as_slice(), plaintext.as_slice()) {
            return Err(CryptError::AuthenticationFailed);
        }
        Ok(RecordReseal {
            record,
            source_key,
            destination_key,
            was_resealed: true,
        })
    }

    /// Authenticates a record under its source scope and context, then re-seals
    /// it under an explicit destination scope and context.
    ///
    /// This operation transforms bytes only. A durable database migration must
    /// write and verify a new generation before atomically switching its
    /// manifest; `crypt-io` never overwrites the source object.
    ///
    /// # Errors
    ///
    /// Returns any source authentication, provider, entropy, allocation,
    /// destination authentication, or descriptor-consistency failure.
    pub fn migrate(
        &self,
        source_scope: &KeyScope,
        source_context: &RecordContext,
        destination_scope: &KeyScope,
        destination_context: &RecordContext,
        encoded: &[u8],
    ) -> Result<RecordReseal> {
        if source_scope == destination_scope
            && constant_time_record_context_eq(source_context, destination_context)
        {
            return self.rotate_to_active(source_scope, source_context, encoded);
        }
        let parsed = parse_record(encoded)?;
        validate_expected_scope_and_sequence(&parsed.header, source_scope, source_context)?;
        let source_key = KeyDescriptor::new(parsed.header.key_id, parsed.header.generation);
        let source_lease = self
            .provider
            .by_id(source_scope, parsed.header.key_id, parsed.header.generation)
            .map_err(map_key_provider_error)?;
        if source_lease.descriptor() != source_key {
            return Err(CryptError::WrongKey);
        }
        let plaintext =
            self.open_parsed_with_lease(&parsed, source_scope, source_context, &source_lease)?;
        let active = self
            .provider
            .active(destination_scope)
            .map_err(map_key_provider_error)?;
        let destination_key = active.descriptor();
        if source_scope == destination_scope {
            let same_secret = constant_time_key_lease_secret_eq(&source_lease, &active);
            if source_key == destination_key {
                if !same_secret {
                    return Err(CryptError::WrongKey);
                }
            } else {
                validate_rotation_progress(source_key, destination_key)?;
                if same_secret {
                    return Err(CryptError::KeyMaterialReuse);
                }
            }
        }
        let (record_salt, nonce_bytes) = fresh_record_material()?;
        let record = self.seal_with_lease(
            &active,
            destination_scope,
            destination_context,
            &plaintext,
            record_salt,
            nonce_bytes,
        )?;
        let verified = self.open(destination_scope, destination_context, record.as_bytes())?;
        if !constant_time_bytes_eq(verified.as_slice(), plaintext.as_slice()) {
            return Err(CryptError::AuthenticationFailed);
        }
        Ok(RecordReseal {
            record,
            source_key,
            destination_key,
            was_resealed: true,
        })
    }

    // This remains a method to keep authenticated opening behind the codec
    // boundary even when the caller has already resolved a key lease.
    #[allow(clippy::unused_self)]
    fn open_parsed_with_lease(
        &self,
        parsed: &ParsedRecord<'_>,
        expected_scope: &KeyScope,
        expected_context: &RecordContext,
        lease: &KeyLease,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let derived_key = derive_storage_key(
            lease,
            expected_scope,
            &parsed.header.record_salt,
            SUITE_AES_256_GCM_HKDF_SHA256,
            HKDF_INFO_DOMAIN,
        )?;
        let cipher = Aes256Gcm::new_from_slice(derived_key.as_ref())
            .map_err(|_error| CryptError::InvalidInput)?;
        let nonce = Nonce::<Aes256Gcm>::try_from(parsed.header.nonce.as_slice())
            .map_err(|_error| CryptError::CorruptStructure)?;
        let tag = Tag::<Aes256Gcm>::try_from(parsed.tag)
            .map_err(|_error| CryptError::CorruptStructure)?;
        let mut plaintext = try_zeroizing_copy(parsed.ciphertext)?;
        cipher
            .decrypt_inout_detached(
                &nonce,
                parsed.encoded_header,
                plaintext.as_mut_slice().into(),
                &tag,
            )
            .map_err(|_error| CryptError::AuthenticationFailed)?;
        verify_context_binding(
            lease,
            expected_scope,
            &parsed.header.record_salt,
            expected_context,
            &parsed.header.context_binding,
        )?;
        Ok(plaintext)
    }
}

#[derive(Debug, Clone, Copy)]
struct RecordHeader {
    key_id: KeyId,
    generation: KeyGeneration,
    purpose_id: PurposeId,
    space_id: SpaceId,
    record_salt: [u8; RECORD_SALT_LEN],
    nonce: [u8; NONCE_LEN],
    logical_sequence: u64,
    context_binding: [u8; 32],
}

struct ParsedRecord<'a> {
    header: RecordHeader,
    encoded_header: &'a [u8],
    ciphertext: &'a [u8],
    tag: &'a [u8],
}

fn fresh_record_material() -> Result<([u8; RECORD_SALT_LEN], [u8; NONCE_LEN])> {
    fresh_record_material_with(getrandom::fill)
}

fn constant_time_record_context_eq(left: &RecordContext, right: &RecordContext) -> bool {
    bool::from(
        left.logical_sequence.ct_eq(&right.logical_sequence) & left.digest.ct_eq(&right.digest),
    )
}

fn constant_time_key_lease_secret_eq(left: &KeyLease, right: &KeyLease) -> bool {
    left.with_secret_bytes(|left_bytes| {
        right.with_secret_bytes(|right_bytes| bool::from(left_bytes.ct_eq(right_bytes)))
    })
}

fn constant_time_bytes_eq(left: &[u8], right: &[u8]) -> bool {
    bool::from(left.ct_eq(right))
}

fn fresh_record_material_with<F, E>(mut fill: F) -> Result<([u8; RECORD_SALT_LEN], [u8; NONCE_LEN])>
where
    F: FnMut(&mut [u8]) -> core::result::Result<(), E>,
{
    let mut record_salt = [0_u8; RECORD_SALT_LEN];
    fill(&mut record_salt).map_err(|_error| CryptError::EntropyUnavailable)?;
    let mut nonce_bytes = [0_u8; NONCE_LEN];
    fill(&mut nonce_bytes).map_err(|_error| CryptError::EntropyUnavailable)?;
    Ok((record_salt, nonce_bytes))
}

fn validate_plaintext_len(length: usize) -> Result<()> {
    if length > MAX_SEALED_RECORD_PLAINTEXT_LEN {
        return Err(CryptError::LimitExceeded);
    }
    Ok(())
}

fn try_vec_with_capacity(capacity: usize) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(capacity)
        .map_err(|_error| CryptError::AllocationFailed)?;
    Ok(buffer)
}

fn try_copy_bytes(input: &[u8]) -> Result<Vec<u8>> {
    let mut output = try_vec_with_capacity(input.len())?;
    output.extend_from_slice(input);
    Ok(output)
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

fn encode_header(
    lease: &KeyLease,
    scope: &KeyScope,
    record_salt: &[u8; RECORD_SALT_LEN],
    nonce: &[u8; NONCE_LEN],
    context: &RecordContext,
    context_binding: &[u8; 32],
    plaintext_len: usize,
) -> Result<[u8; SEALED_RECORD_HEADER_LEN]> {
    validate_plaintext_len(plaintext_len)?;
    let ciphertext_len =
        u64::try_from(plaintext_len).map_err(|_error| CryptError::LimitExceeded)?;
    let mut header = [0_u8; SEALED_RECORD_HEADER_LEN];
    header[0..8].copy_from_slice(SEALED_RECORD_MAGIC);
    header[8..10].copy_from_slice(&FORMAT_VERSION.to_be_bytes());
    header[10..12].copy_from_slice(&SUITE_AES_256_GCM_HKDF_SHA256.to_be_bytes());
    header[12..14].copy_from_slice(&FLAGS_V1.to_be_bytes());
    header[14..16].copy_from_slice(&176_u16.to_be_bytes());
    header[16..32].copy_from_slice(lease.key_id().as_bytes());
    header[32..36].copy_from_slice(&lease.generation().get().to_be_bytes());
    header[36..52].copy_from_slice(scope.purpose_id().as_bytes());
    header[52..84].copy_from_slice(scope.space_id().as_bytes());
    header[84..116].copy_from_slice(record_salt);
    header[116..128].copy_from_slice(nonce);
    header[128..136].copy_from_slice(&context.logical_sequence().to_be_bytes());
    header[136..168].copy_from_slice(context_binding);
    header[168..176].copy_from_slice(&ciphertext_len.to_be_bytes());
    Ok(header)
}

fn parse_record(encoded: &[u8]) -> Result<ParsedRecord<'_>> {
    if encoded.len() < SEALED_RECORD_HEADER_LEN {
        return Err(CryptError::Truncated);
    }
    if &encoded[0..8] != SEALED_RECORD_MAGIC {
        return Err(CryptError::CorruptStructure);
    }
    if read_u16(encoded, 8) != FORMAT_VERSION {
        return Err(CryptError::UnsupportedVersion);
    }
    if read_u16(encoded, 10) != SUITE_AES_256_GCM_HKDF_SHA256 {
        return Err(CryptError::UnsupportedSuite);
    }
    if read_u16(encoded, 12) != FLAGS_V1
        || usize::from(read_u16(encoded, 14)) != SEALED_RECORD_HEADER_LEN
    {
        return Err(CryptError::CorruptStructure);
    }

    let ciphertext_len_u64 = read_u64(encoded, 168);
    if ciphertext_len_u64 > MAX_SEALED_RECORD_PLAINTEXT_LEN as u64 {
        return Err(CryptError::LimitExceeded);
    }
    let ciphertext_len =
        usize::try_from(ciphertext_len_u64).map_err(|_error| CryptError::LimitExceeded)?;
    let expected_len = SEALED_RECORD_HEADER_LEN
        .checked_add(ciphertext_len)
        .and_then(|length| length.checked_add(TAG_LEN))
        .ok_or(CryptError::LimitExceeded)?;
    match encoded.len().cmp(&expected_len) {
        Ordering::Less => return Err(CryptError::Truncated),
        Ordering::Greater => return Err(CryptError::TrailingData),
        Ordering::Equal => {}
    }

    let ciphertext_end = SEALED_RECORD_HEADER_LEN + ciphertext_len;
    Ok(ParsedRecord {
        header: RecordHeader {
            key_id: KeyId::new(copy_array::<16>(encoded, 16)),
            generation: KeyGeneration::new(read_u32(encoded, 32)),
            purpose_id: PurposeId::new(copy_array::<16>(encoded, 36)),
            space_id: SpaceId::new(copy_array::<32>(encoded, 52)),
            record_salt: copy_array::<RECORD_SALT_LEN>(encoded, 84),
            nonce: copy_array::<NONCE_LEN>(encoded, 116),
            logical_sequence: read_u64(encoded, 128),
            context_binding: copy_array::<32>(encoded, 136),
        },
        encoded_header: &encoded[..SEALED_RECORD_HEADER_LEN],
        ciphertext: &encoded[SEALED_RECORD_HEADER_LEN..ciphertext_end],
        tag: &encoded[ciphertext_end..expected_len],
    })
}

fn validate_expected_scope_and_sequence(
    header: &RecordHeader,
    expected_scope: &KeyScope,
    expected_context: &RecordContext,
) -> Result<()> {
    if header.logical_sequence != expected_context.logical_sequence() {
        return Err(CryptError::SequenceMismatch);
    }
    if header.purpose_id != expected_scope.purpose_id()
        || header.space_id != expected_scope.space_id()
    {
        return Err(CryptError::ContextMismatch);
    }
    Ok(())
}

fn context_mac(
    lease: &KeyLease,
    scope: &KeyScope,
    record_salt: &[u8; RECORD_SALT_LEN],
    context: &RecordContext,
) -> Result<Hmac<Sha256>> {
    let context_key = derive_storage_key(
        lease,
        scope,
        record_salt,
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
    record_salt: &[u8; RECORD_SALT_LEN],
    context: &RecordContext,
) -> Result<[u8; 32]> {
    let output = context_mac(lease, scope, record_salt, context)?
        .finalize()
        .into_bytes();
    let mut binding = [0_u8; 32];
    binding.copy_from_slice(&output);
    Ok(binding)
}

fn verify_context_binding(
    lease: &KeyLease,
    scope: &KeyScope,
    record_salt: &[u8; RECORD_SALT_LEN],
    context: &RecordContext,
    encoded_binding: &[u8; 32],
) -> Result<()> {
    context_mac(lease, scope, record_salt, context)?
        .verify_slice(encoded_binding)
        .map_err(|_error| CryptError::ContextMismatch)
}

fn validate_rotation_progress(source: KeyDescriptor, destination: KeyDescriptor) -> Result<()> {
    if destination.generation() <= source.generation() {
        return Err(CryptError::KeyDowngrade);
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use aes_gcm::{
        Aes256Gcm,
        aead::{AeadInOut, KeyInit, Nonce},
    };
    use hex_literal::hex;

    use super::{
        RecordCodec, RecordContext, constant_time_bytes_eq, fresh_record_material_with,
        try_vec_with_capacity, try_zeroizing_copy_with_reserver,
    };
    use crate::storage::{
        CryptError, KeyGeneration, KeyId, KeyLease, KeyProvider, KeyProviderError, KeyScope,
        PurposeId, SecretKey32, SpaceId,
    };

    #[derive(Clone, Copy)]
    struct FixtureProvider;

    impl FixtureProvider {
        fn lease() -> KeyLease {
            KeyLease::new(
                KeyId::new(*b"test-key-id-v001"),
                KeyGeneration::new(7),
                SecretKey32::new([0xA7; 32]),
            )
        }
    }

    impl KeyProvider for FixtureProvider {
        fn active(&self, _scope: &KeyScope) -> Result<KeyLease, KeyProviderError> {
            Ok(Self::lease())
        }

        fn by_id(
            &self,
            _scope: &KeyScope,
            _key_id: KeyId,
            _generation: KeyGeneration,
        ) -> Result<KeyLease, KeyProviderError> {
            Ok(Self::lease())
        }
    }

    #[test]
    fn aes256_gcm_matches_nist_empty_message_vector() {
        let cipher = Aes256Gcm::new_from_slice(&[0_u8; 32]).unwrap();
        let nonce_bytes = [0_u8; 12];
        let nonce = Nonce::<Aes256Gcm>::try_from(nonce_bytes.as_slice()).unwrap();
        let mut plaintext = [];
        let tag = cipher
            .encrypt_inout_detached(&nonce, &[], plaintext.as_mut_slice().into())
            .unwrap();
        assert_eq!(tag.as_slice(), &hex!("530f8afbc74536b9a963b4f1c4cb738b"));
    }

    #[test]
    fn sealed_record_matches_independent_v1_fixture() {
        let codec = RecordCodec::new(FixtureProvider);
        let scope = KeyScope::new(
            SpaceId::new([0x53; 32]),
            PurposeId::new(*b"memory-record-v1"),
        );
        let context = RecordContext::new(42, b"collection=memories;record=7f4a").unwrap();
        let sealed = codec
            .seal_with_material(
                &scope,
                &context,
                b"golden sealed record",
                [0x11; 32],
                [0x22; 12],
            )
            .unwrap();
        let expected = hex!(
            "4352494f5245430000010001000000b0
             746573742d6b65792d69642d76303031
             00000007
             6d656d6f72792d7265636f72642d7631
             5353535353535353535353535353535353535353535353535353535353535353
             1111111111111111111111111111111111111111111111111111111111111111
             222222222222222222222222
             000000000000002a
             ddfeb49b04141bb9666d08e12801f41650f9b6d27b12bb53ca41555adbcb88bb
             0000000000000014
             67b8de8933152d511c406e03737bef557c56bc91
             02a80114d165b5303433f010578c5d5b"
        );
        assert_eq!(sealed.as_bytes(), expected.as_slice());
        let opened = codec.open(&scope, &context, sealed.as_bytes()).unwrap();
        assert_eq!(opened.as_slice(), b"golden sealed record");
    }

    #[test]
    fn test_record_reservation_capacity_overflow_returns_allocation_failed() {
        assert!(matches!(
            try_vec_with_capacity(usize::MAX),
            Err(CryptError::AllocationFailed)
        ));
    }

    #[test]
    fn test_record_plaintext_copy_when_reservation_fails_returns_no_plaintext() {
        let result =
            try_zeroizing_copy_with_reserver(b"must never be copied", |_buffer, _additional| {
                Err(CryptError::AllocationFailed)
            });

        assert!(matches!(result, Err(CryptError::AllocationFailed)));
    }

    #[test]
    fn test_record_context_implements_zeroize_on_drop() {
        fn require_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

        require_zeroize_on_drop::<RecordContext>();
    }

    #[test]
    fn test_record_entropy_source_when_salt_fails_returns_entropy_unavailable() {
        let mut calls = 0_u8;
        let result = fresh_record_material_with(|_output| {
            calls = calls.saturating_add(1);
            Err(())
        });

        assert!(matches!(result, Err(CryptError::EntropyUnavailable)));
        assert_eq!(calls, 1);
    }

    #[test]
    fn test_record_entropy_source_when_nonce_fails_stops_after_second_fill() {
        let mut calls = 0_u8;
        let result = fresh_record_material_with(|output| {
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
    fn test_record_entropy_source_when_both_fills_succeed_returns_material() {
        let mut calls = 0_u8;
        let (salt, nonce) = fresh_record_material_with(|output| {
            calls = calls.saturating_add(1);
            output.fill(calls);
            Ok::<(), ()>(())
        })
        .unwrap();

        assert_eq!(salt, [1_u8; 32]);
        assert_eq!(nonce, [2_u8; 12]);
        assert_eq!(calls, 2);
    }

    #[test]
    fn test_constant_time_bytes_eq_when_bytes_match_returns_true() {
        assert!(constant_time_bytes_eq(b"sensitive", b"sensitive"));
    }

    #[test]
    fn test_constant_time_bytes_eq_when_bytes_differ_returns_false() {
        assert!(!constant_time_bytes_eq(b"sensitive", b"sensitivf"));
    }

    #[test]
    fn test_constant_time_bytes_eq_when_lengths_differ_returns_false() {
        assert!(!constant_time_bytes_eq(b"sensitive", b"sensitive-longer"));
    }
}
