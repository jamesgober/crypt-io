//! Single-shot AEAD over a scheduled key ([`Engine`]).
//!
//! ChaCha20-Poly1305, XChaCha20-Poly1305 and AES-256-GCM share one
//! implementation. The wrapper's jobs:
//!
//! - Check the key length (exactly 32 bytes for every shipped cipher).
//! - Draw a fresh nonce of the cipher's length from the OS CSPRNG.
//! - Lay out `prefix || nonce || ciphertext || tag`, where `prefix` is
//!   empty for the 1.0 format and the 2-byte sealed header otherwise.
//! - Map the backend's opaque failure onto crypt-io errors, and make
//!   sure no error path leaves plaintext in a caller's buffer.
//!
//! The `*_key` forms build the [`Engine`] for one call (the
//! [`Crypt`](super::Crypt) API); the others take one that a
//! [`KeyedCrypt`](super::KeyedCrypt) built once. No cryptographic math
//! lives here.

use alloc::vec::Vec;

use super::engine::Engine;
use super::{Algorithm, TAG_LEN};
use crate::error::{Error, Result};
use crate::wipe::{reserve_wiping, wipe_vec};

/// Encrypt into `out`, which is cleared first. On return `out` is
/// `prefix || nonce || ciphertext || tag`. On error `out` is empty, and
/// if the plaintext had already been copied in, wiped.
#[cfg(any(feature = "std", feature = "getrandom"))]
pub(crate) fn encrypt_into(
    engine: &Engine,
    plaintext: &[u8],
    aad: &[u8],
    prefix: &[u8],
    out: &mut Vec<u8>,
) -> Result<()> {
    out.clear();
    let nl = engine.algorithm().nonce_len();
    let mut nonce = [0u8; super::MAX_NONCE_LEN];
    crate::rng::fill(&mut nonce[..nl])?;

    let body = prefix.len() + nl;
    // `out` holds no secret here (it was cleared, and the previous
    // contents of an encrypt buffer are ciphertext), so a plain
    // `reserve` is fine.
    out.reserve(body + plaintext.len() + TAG_LEN);
    out.extend_from_slice(prefix);
    out.extend_from_slice(&nonce[..nl]);
    out.extend_from_slice(plaintext);

    let tag = engine
        .seal_in_place(&nonce[..nl], aad, &mut out[body..])
        .map_err(|()| {
            // The only encrypt-side failure is an input longer than the
            // cipher allows. `out` holds the plaintext copy: wipe it.
            wipe_vec(out);
            Error::LimitExceeded("aead: plaintext or associated data too long")
        })?;
    out.extend_from_slice(&tag);
    Ok(())
}

/// [`encrypt_into`] with the key scheduled for this call only.
#[cfg(any(feature = "std", feature = "getrandom"))]
pub(crate) fn encrypt_into_key(
    algorithm: Algorithm,
    key: &[u8],
    plaintext: &[u8],
    aad: &[u8],
    prefix: &[u8],
    out: &mut Vec<u8>,
) -> Result<()> {
    out.clear();
    Engine::with(algorithm, key, |engine| {
        encrypt_into(engine, plaintext, aad, prefix, out)
    })
}

/// Allocating form of [`encrypt_into`]: one allocation, sized exactly.
#[cfg(any(feature = "std", feature = "getrandom"))]
pub(crate) fn encrypt(
    engine: &Engine,
    plaintext: &[u8],
    aad: &[u8],
    prefix: &[u8],
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    encrypt_into(engine, plaintext, aad, prefix, &mut out)?;
    Ok(out)
}

fn split_wire(nonce_len: usize, wire: &[u8]) -> Result<(&[u8], &[u8], &[u8])> {
    if wire.len() < nonce_len + TAG_LEN {
        return Err(Error::InvalidCiphertext(alloc::format!(
            "buffer too short ({} bytes, need at least {})",
            wire.len(),
            nonce_len + TAG_LEN
        )));
    }
    let (nonce, rest) = wire.split_at(nonce_len);
    let (ct, tag) = rest.split_at(rest.len() - TAG_LEN);
    Ok((nonce, ct, tag))
}

/// Decrypt `nonce || ciphertext || tag`. The tag is checked (in
/// constant time, by the backend) before any plaintext is produced.
pub(crate) fn decrypt(engine: &Engine, wire: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let nl = engine.algorithm().nonce_len();
    let mut out = Vec::with_capacity(wire.len().saturating_sub(nl + TAG_LEN));
    decrypt_into(engine, wire, aad, &mut out)?;
    Ok(out)
}

/// Decrypt into `out`, which is cleared before any check runs. On
/// error `out` is empty; on authentication failure its whole
/// allocation is also wiped.
pub(crate) fn decrypt_into(
    engine: &Engine,
    wire: &[u8],
    aad: &[u8],
    out: &mut Vec<u8>,
) -> Result<()> {
    // Clear first so that no early-return error path below hands the
    // caller's previous plaintext back to it.
    out.clear();
    let (nonce, ct, tag) = split_wire(engine.algorithm().nonce_len(), wire)?;

    // `out` may still hold a previous plaintext in its allocation;
    // growing it with `reserve` would copy that into a new block and
    // free the old one unwiped.
    reserve_wiping(out, ct.len());
    out.extend_from_slice(ct);

    engine.open_in_place(nonce, aad, out, tag).map_err(|()| {
        // The backend verifies the tag before decrypting, but wipe the
        // whole allocation anyway (length and spare capacity) so
        // nothing derived from this failed message stays in the
        // caller's buffer.
        wipe_vec(out);
        Error::AuthenticationFailed
    })
}

/// [`decrypt_into`] with the key scheduled for this call only. `out`
/// is cleared before the key is checked.
pub(crate) fn decrypt_into_key(
    algorithm: Algorithm,
    key: &[u8],
    wire: &[u8],
    aad: &[u8],
    out: &mut Vec<u8>,
) -> Result<()> {
    out.clear();
    Engine::with(algorithm, key, |engine| {
        decrypt_into(engine, wire, aad, out)
    })
}
