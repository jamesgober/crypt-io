//! Shared contracts for the independent `crypt-io` fuzz workspace.

#![deny(warnings)]
#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(unused_must_use)]
#![deny(unused_results)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::print_stdout)]
#![deny(clippy::print_stderr)]
#![deny(clippy::dbg_macro)]
#![deny(clippy::unreachable)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(clippy::missing_safety_doc)]

use std::process;

use crypt_io::storage::{
    KeyGeneration, KeyId, KeyLease, KeyProvider, KeyProviderError, KeyScope, PurposeId,
    RecordContext, SecretKey32, SpaceId, StreamContext,
};

const KEY_ID_BYTES: [u8; 16] = *b"fuzz-key-id-v001";
const PURPOSE_BYTES: [u8; 16] = *b"fuzz-storage-v01";
const SPACE_BYTES: [u8; 32] = [0xA5; 32];
const PUBLIC_TEST_KEY_BYTES: [u8; 32] = [0x5A; 32];
const GENERATION: u32 = 17;

/// Maximum plaintext retained by one record-mutation input.
pub const MAX_RECORD_MUTATION_PLAINTEXT_LEN: usize = 64 * 1024;

/// Maximum plaintext retained by one stream-mutation input.
pub const MAX_STREAM_MUTATION_PLAINTEXT_LEN: usize = 16 * 1024;

/// Upper bound used to derive a stream-mutation frame length.
pub const MAX_FUZZ_STREAM_FRAME_LEN: u16 = 4096;

/// Plaintext carried by the committed authenticated record seed.
pub const RECORD_HOSTILE_PLAINTEXT: &[u8] = b"authenticated record seed";

/// Plaintext carried by the committed authenticated multi-frame stream seed.
pub const STREAM_HOSTILE_PLAINTEXT: &[u8] = b"authenticated stream seed across frames";

/// Frame size used by the committed authenticated stream seed.
pub const STREAM_HOSTILE_FRAME_LEN: u32 = 8;

/// Fixed provider whose key material is public and confined to fuzz fixtures.
#[derive(Clone, Copy)]
pub struct FuzzKeyProvider;

impl FuzzKeyProvider {
    fn lease(key_id: KeyId, generation: KeyGeneration) -> KeyLease {
        KeyLease::new(key_id, generation, SecretKey32::new(PUBLIC_TEST_KEY_BYTES))
    }
}

impl KeyProvider for FuzzKeyProvider {
    fn active(&self, _scope: &KeyScope) -> Result<KeyLease, KeyProviderError> {
        Ok(Self::lease(
            KeyId::new(KEY_ID_BYTES),
            KeyGeneration::new(GENERATION),
        ))
    }

    fn by_id(
        &self,
        _scope: &KeyScope,
        key_id: KeyId,
        generation: KeyGeneration,
    ) -> Result<KeyLease, KeyProviderError> {
        Ok(Self::lease(key_id, generation))
    }
}

/// Returns the fixed tenant and purpose scope shared by all fuzz targets.
#[must_use]
pub fn fuzz_scope() -> KeyScope {
    KeyScope::new(SpaceId::new(SPACE_BYTES), PurposeId::new(PURPOSE_BYTES))
}

/// Returns the context expected by the hostile-record decoder target.
#[must_use]
pub fn record_hostile_context() -> RecordContext {
    match RecordContext::new(0, b"crypt-io/fuzz/record-hostile") {
        Ok(context) => context,
        Err(_invalid_static_fixture) => process::abort(),
    }
}

/// Returns the context used when the record-mutation target seals its fixture.
#[must_use]
pub fn record_mutation_context() -> RecordContext {
    match RecordContext::new(23, b"crypt-io/fuzz/record-mutation") {
        Ok(context) => context,
        Err(_invalid_static_fixture) => process::abort(),
    }
}

/// Returns the context expected by the hostile-stream decoder target.
#[must_use]
pub fn stream_hostile_context() -> StreamContext {
    match StreamContext::new(1, b"crypt-io/fuzz/stream-hostile") {
        Ok(context) => context,
        Err(_invalid_static_fixture) => process::abort(),
    }
}

/// Returns the context used when the stream-mutation target seals its fixture.
#[must_use]
pub fn stream_mutation_context() -> StreamContext {
    match StreamContext::new(1, b"crypt-io/fuzz/stream-mutation") {
        Ok(context) => context,
        Err(_invalid_static_fixture) => process::abort(),
    }
}

/// Splits a mutation input into its bounded selector, bit, and plaintext fields.
///
/// Inputs shorter than the nine-byte control prefix are rejected. The payload
/// is borrowed directly and truncated to `max_payload_len`, keeping the hot fuzz
/// path allocation-free.
#[must_use]
pub fn mutation_parts(
    data: &[u8],
    selector_offset: usize,
    max_payload_len: usize,
) -> Option<(usize, u8, &[u8])> {
    let selector_end = selector_offset.checked_add(8)?;
    let payload_start = selector_end.checked_add(1)?;
    if data.len() < payload_start {
        return None;
    }

    let selector = data[selector_offset..selector_end]
        .iter()
        .fold(0_usize, |value, byte| {
            value.wrapping_mul(257).wrapping_add(usize::from(*byte))
        });
    let bit = data[selector_end] & 7;
    let payload_end = data
        .len()
        .min(payload_start.saturating_add(max_payload_len));
    Some((selector, bit, &data[payload_start..payload_end]))
}
