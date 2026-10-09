//! Single-shot AEAD over any RustCrypto `aead` 0.5 cipher.
//!
//! ChaCha20-Poly1305, XChaCha20-Poly1305 and AES-256-GCM share one
//! implementation, generic over the cipher type. The wrapper's jobs:
//!
//! - Check the key length (exactly 32 bytes for every shipped cipher).
//! - Draw a fresh nonce of the cipher's length from the OS CSPRNG.
//! - Lay out `prefix || nonce || ciphertext || tag`, where `prefix` is
//!   empty for the 1.0 format and the 2-byte sealed header otherwise.
//! - Map upstream's opaque `aead::Error` onto crypt-io errors, and make
//!   sure no error path leaves plaintext in a caller's buffer.
//!
//! No cryptographic math lives here.

use alloc::vec::Vec;

#[cfg(all(feature = "aead-aes-gcm", not(feature = "aead-chacha20")))]
use aes_gcm::aead as aead_api;
#[cfg(feature = "aead-chacha20")]
use chacha20poly1305::aead as aead_api;

use aead_api::generic_array::typenum::Unsigned;
use aead_api::{AeadCore, AeadInPlace, KeyInit};

use super::{KEY_LEN, TAG_LEN};
use crate::error::{Error, Result};
use crate::wipe::{reserve_wiping, wipe_vec};

/// The cipher types this module accepts.
pub(crate) trait Cipher: KeyInit + AeadInPlace {}
impl<C: KeyInit + AeadInPlace> Cipher for C {}

/// Nonce length of `C` in bytes.
#[inline]
pub(crate) fn nonce_len<C: AeadCore>() -> usize {
    C::NonceSize::USIZE
}

#[inline]
pub(crate) fn check_key_len(key: &[u8]) -> Result<()> {
    if key.len() == KEY_LEN {
        Ok(())
    } else {
        Err(Error::InvalidKey {
            expected: KEY_LEN,
            actual: key.len(),
        })
    }
}

/// Build the cipher from a key already checked to be `KEY_LEN` bytes.
///
/// Returns the cipher by value, not in a `Result`: the AES-GCM state is
/// several hundred bytes, and wrapping it in a `Result` costs an extra
/// copy on every call. Panics only if `key` is not `C::KeySize` long,
/// which every caller rules out with [`check_key_len`] first (all
/// shipped ciphers take `KEY_LEN`-byte keys).
#[inline]
pub(crate) fn new_cipher<C: Cipher>(key: &[u8]) -> C {
    C::new(aead_api::Key::<C>::from_slice(key))
}

/// Encrypt into `out`, which is cleared first. On return `out` is
/// `prefix || nonce || ciphertext || tag`. On error `out` is empty, and
/// if the plaintext had already been copied in, wiped.
#[cfg(any(feature = "std", feature = "getrandom"))]
pub(crate) fn encrypt_into<C: Cipher>(
    key: &[u8],
    plaintext: &[u8],
    aad: &[u8],
    prefix: &[u8],
    out: &mut Vec<u8>,
) -> Result<()> {
    out.clear();
    check_key_len(key)?;

    let nl = nonce_len::<C>();
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

    let tag = new_cipher::<C>(key)
        .encrypt_in_place_detached(
            aead_api::Nonce::<C>::from_slice(&nonce[..nl]),
            aad,
            &mut out[body..],
        )
        .map_err(|_| {
            // The only encrypt-side failure is an input longer than the
            // cipher allows. `out` holds the plaintext copy: wipe it.
            wipe_vec(out);
            Error::LimitExceeded("aead: plaintext or associated data too long")
        })?;
    out.extend_from_slice(&tag);
    Ok(())
}

/// Allocating form of [`encrypt_into`]: one allocation, sized exactly.
#[cfg(any(feature = "std", feature = "getrandom"))]
pub(crate) fn encrypt<C: Cipher>(
    key: &[u8],
    plaintext: &[u8],
    aad: &[u8],
    prefix: &[u8],
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    encrypt_into::<C>(key, plaintext, aad, prefix, &mut out)?;
    Ok(out)
}

fn split_wire<C: Cipher>(wire: &[u8]) -> Result<(&[u8], &[u8], &[u8])> {
    let nl = nonce_len::<C>();
    if wire.len() < nl + TAG_LEN {
        return Err(Error::InvalidCiphertext(alloc::format!(
            "buffer too short ({} bytes, need at least {})",
            wire.len(),
            nl + TAG_LEN
        )));
    }
    let (nonce, rest) = wire.split_at(nl);
    let (ct, tag) = rest.split_at(rest.len() - TAG_LEN);
    Ok((nonce, ct, tag))
}

/// Decrypt `nonce || ciphertext || tag`. The tag is checked (in
/// constant time, by upstream) before any plaintext is produced.
pub(crate) fn decrypt<C: Cipher>(key: &[u8], wire: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(wire.len().saturating_sub(nonce_len::<C>() + TAG_LEN));
    decrypt_into::<C>(key, wire, aad, &mut out)?;
    Ok(out)
}

/// Decrypt into `out`, which is cleared before any check runs. On
/// error `out` is empty; on authentication failure its whole
/// allocation is also wiped.
pub(crate) fn decrypt_into<C: Cipher>(
    key: &[u8],
    wire: &[u8],
    aad: &[u8],
    out: &mut Vec<u8>,
) -> Result<()> {
    // Clear first so that no early-return error path below hands the
    // caller's previous plaintext back to it.
    out.clear();
    check_key_len(key)?;
    let (nonce, ct, tag) = split_wire::<C>(wire)?;

    // `out` may still hold a previous plaintext in its allocation;
    // growing it with `reserve` would copy that into a new block and
    // free the old one unwiped.
    reserve_wiping(out, ct.len());
    out.extend_from_slice(ct);

    new_cipher::<C>(key)
        .decrypt_in_place_detached(
            aead_api::Nonce::<C>::from_slice(nonce),
            aad,
            out,
            aead_api::Tag::<C>::from_slice(tag),
        )
        .map_err(|_| {
            // Upstream verifies the tag before decrypting, but wipe the
            // whole allocation anyway (length and spare capacity) so
            // nothing derived from this failed message stays in the
            // caller's buffer.
            wipe_vec(out);
            Error::AuthenticationFailed
        })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn check_key_len_accepts_exactly_32() {
        assert!(check_key_len(&[0u8; 32]).is_ok());
    }

    #[test]
    fn check_key_len_rejects_off_by_one() {
        assert!(check_key_len(&[0u8; 31]).is_err());
        assert!(check_key_len(&[0u8; 33]).is_err());
    }
}
