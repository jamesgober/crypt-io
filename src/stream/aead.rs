//! Per-chunk AEAD primitive for the stream module.
//!
//! Unlike the top-level [`crate::aead`] module — which generates a
//! nonce internally and prepends it to the ciphertext — the stream
//! protocol carries its own nonce schedule (the STREAM construction in
//! [`super::frame`]). This module exposes "encrypt with a
//! caller-supplied nonce" / "decrypt with a caller-supplied nonce"
//! primitives that operate on a single chunk at a time and append to
//! the caller's output buffer.

use alloc::vec::Vec;

use crate::aead::engine::Engine;
use crate::error::{Error, Result};
use crate::wipe::wipe_tail;

use super::frame::TAG_LEN;

/// Encrypt one chunk with `engine` (the stream's scheduled key) under
/// `nonce` and `aad`, and append `ciphertext || tag` to `out`. Bytes
/// already in `out` are left untouched. On error the appended region (a
/// plaintext copy) is wiped and `out` is truncated back.
#[cfg(any(feature = "std", feature = "getrandom"))]
pub(super) fn encrypt_chunk_append(
    engine: &Engine,
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
    out: &mut Vec<u8>,
) -> Result<()> {
    let start = out.len();
    out.reserve(plaintext.len() + TAG_LEN);
    out.extend_from_slice(plaintext);
    let tag = engine
        .seal_in_place(nonce, aad, &mut out[start..])
        .map_err(|()| {
            wipe_tail(out, start);
            Error::LimitExceeded("stream: chunk or associated data too long")
        })?;
    out.extend_from_slice(&tag);
    Ok(())
}

/// Decrypt one chunk (`ciphertext || tag`) and **append** the
/// recovered plaintext to `out`. Bytes already in `out` are left
/// untouched.
///
/// The ciphertext is copied to the end of `out` and decrypted in place
/// there, so no intermediate buffer is allocated. Callers reserve room
/// in `out` first (with `reserve_wiping`), so this never reallocates a
/// buffer that holds plaintext. On any error the appended region is
/// overwritten with zeros and `out` is truncated back to its original
/// length.
pub(super) fn decrypt_chunk_append(
    engine: &Engine,
    nonce: &[u8],
    ciphertext_and_tag: &[u8],
    aad: &[u8],
    out: &mut Vec<u8>,
) -> Result<()> {
    if ciphertext_and_tag.len() < TAG_LEN {
        return Err(Error::InvalidCiphertext(alloc::format!(
            "chunk too short ({} bytes, need at least {TAG_LEN} for tag)",
            ciphertext_and_tag.len()
        )));
    }
    let (ct, tag) = ciphertext_and_tag.split_at(ciphertext_and_tag.len() - TAG_LEN);
    let start = out.len();
    crate::wipe::reserve_wiping(out, ct.len());
    out.extend_from_slice(ct);
    engine
        .open_in_place(nonce, aad, &mut out[start..], tag)
        .map_err(|()| {
            wipe_tail(out, start);
            Error::AuthenticationFailed
        })
}
