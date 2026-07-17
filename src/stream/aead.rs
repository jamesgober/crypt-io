//! Per-chunk AEAD primitive for the stream module.
//!
//! Unlike the top-level [`crate::aead`] module — which generates a
//! nonce internally and prepends it to the ciphertext — the stream
//! protocol carries its own nonce schedule (the STREAM construction in
//! [`super::frame`]). This module exposes minimal "encrypt with a
//! caller-supplied nonce" / "decrypt with a caller-supplied nonce"
//! primitives that operate on a single chunk at a time.

use alloc::vec::Vec;

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{
    Aead as AesAead, AeadInOut as AesAeadInOut, KeyInit as AesKeyInit, Nonce as AesNonce,
    Payload as AesPayload, Tag as AesTag,
};

use crate::aead::Algorithm;
use crate::error::{Error, Result};

use super::frame::NONCE_LEN;

/// Encrypt one chunk under `key` with the supplied 12-byte `nonce` and
/// `aad`. Returns `ciphertext || tag`.
pub(super) fn encrypt_chunk(
    algorithm: Algorithm,
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    match algorithm {
        Algorithm::ChaCha20Poly1305 => {
            use chacha20poly1305::aead::{Aead, KeyInit, Payload};
            use chacha20poly1305::{ChaCha20Poly1305, Key as ChaKey, Nonce as ChaNonce};

            let cipher = ChaCha20Poly1305::new(ChaKey::from_slice(key));
            cipher
                .encrypt(
                    ChaNonce::from_slice(nonce),
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| Error::AuthenticationFailed)
        }
        Algorithm::Aes256Gcm => {
            let cipher = new_aes_cipher(key)?;
            let nonce = aes_nonce(nonce)?;
            cipher
                .encrypt(
                    &nonce,
                    AesPayload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| Error::AuthenticationFailed)
        }
    }
}

/// Encrypt one chunk into a caller-supplied buffer. Buffer is cleared
/// and grown to `plaintext.len() + tag_len` bytes. The 16-byte tag is
/// appended after the in-place ciphertext.
pub(super) fn encrypt_chunk_into(
    algorithm: Algorithm,
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
    out: &mut Vec<u8>,
) -> Result<()> {
    out.clear();
    out.reserve(plaintext.len() + 16);
    out.extend_from_slice(plaintext);

    match algorithm {
        Algorithm::ChaCha20Poly1305 => {
            use chacha20poly1305::aead::{AeadInPlace, KeyInit};
            use chacha20poly1305::{ChaCha20Poly1305, Key as ChaKey, Nonce as ChaNonce};

            let cipher = ChaCha20Poly1305::new(ChaKey::from_slice(key));
            let tag = cipher
                .encrypt_in_place_detached(ChaNonce::from_slice(nonce), aad, out)
                .map_err(|_| Error::AuthenticationFailed)?;
            out.extend_from_slice(&tag);
        }
        Algorithm::Aes256Gcm => {
            let cipher = new_aes_cipher(key)?;
            let nonce = aes_nonce(nonce)?;
            let tag = cipher
                .encrypt_inout_detached(&nonce, aad, out.as_mut_slice().into())
                .map_err(|_| Error::AuthenticationFailed)?;
            out.extend_from_slice(&tag);
        }
    }
    Ok(())
}

/// Decrypt one chunk into a caller-supplied buffer. Buffer is cleared
/// and grown to `ciphertext_and_tag.len() - tag_len` bytes (the
/// recovered plaintext). The pinned backends authenticate before decrypting;
/// on authentication failure the caller-visible output length is also cleared
/// defensively before returning.
pub(super) fn decrypt_chunk_into(
    algorithm: Algorithm,
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    ciphertext_and_tag: &[u8],
    aad: &[u8],
    out: &mut Vec<u8>,
) -> Result<()> {
    if ciphertext_and_tag.len() < 16 {
        return Err(Error::InvalidCiphertext(alloc::format!(
            "chunk too short ({} bytes, need at least 16 for tag)",
            ciphertext_and_tag.len()
        )));
    }
    let (ct, tag_bytes) = ciphertext_and_tag.split_at(ciphertext_and_tag.len() - 16);

    out.clear();
    out.reserve(ct.len());
    out.extend_from_slice(ct);

    match algorithm {
        Algorithm::ChaCha20Poly1305 => {
            use chacha20poly1305::aead::{AeadInPlace, KeyInit};
            use chacha20poly1305::{ChaCha20Poly1305, Key as ChaKey, Nonce as ChaNonce};

            let cipher = ChaCha20Poly1305::new(ChaKey::from_slice(key));
            let tag = chacha20poly1305::Tag::from_slice(tag_bytes);
            cipher
                .decrypt_in_place_detached(ChaNonce::from_slice(nonce), aad, out, tag)
                .map_err(|_| {
                    out.clear();
                    Error::AuthenticationFailed
                })?;
        }
        Algorithm::Aes256Gcm => {
            let cipher = new_aes_cipher(key)?;
            let nonce = aes_nonce(nonce)?;
            let tag = AesTag::<Aes256Gcm>::try_from(tag_bytes)
                .map_err(|_| Error::InvalidCiphertext("tag length mismatch".into()))?;
            cipher
                .decrypt_inout_detached(&nonce, aad, out.as_mut_slice().into(), &tag)
                .map_err(|_| {
                    out.clear();
                    Error::AuthenticationFailed
                })?;
        }
    }
    Ok(())
}

/// Decrypt one chunk under `key` with the supplied 12-byte `nonce` and
/// `aad`. `ciphertext_and_tag` is `ciphertext || tag`.
pub(super) fn decrypt_chunk(
    algorithm: Algorithm,
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    ciphertext_and_tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    match algorithm {
        Algorithm::ChaCha20Poly1305 => {
            use chacha20poly1305::aead::{Aead, KeyInit, Payload};
            use chacha20poly1305::{ChaCha20Poly1305, Key as ChaKey, Nonce as ChaNonce};

            let cipher = ChaCha20Poly1305::new(ChaKey::from_slice(key));
            cipher
                .decrypt(
                    ChaNonce::from_slice(nonce),
                    Payload {
                        msg: ciphertext_and_tag,
                        aad,
                    },
                )
                .map_err(|_| Error::AuthenticationFailed)
        }
        Algorithm::Aes256Gcm => {
            let cipher = new_aes_cipher(key)?;
            let nonce = aes_nonce(nonce)?;
            cipher
                .decrypt(
                    &nonce,
                    AesPayload {
                        msg: ciphertext_and_tag,
                        aad,
                    },
                )
                .map_err(|_| Error::AuthenticationFailed)
        }
    }
}

#[inline]
fn new_aes_cipher(key: &[u8; 32]) -> Result<Aes256Gcm> {
    Aes256Gcm::new_from_slice(key).map_err(|_| Error::InvalidKey {
        expected: 32,
        actual: key.len(),
    })
}

#[inline]
fn aes_nonce(bytes: &[u8; NONCE_LEN]) -> Result<AesNonce<Aes256Gcm>> {
    AesNonce::<Aes256Gcm>::try_from(bytes.as_slice())
        .map_err(|_| Error::InvalidCiphertext("nonce length mismatch".into()))
}
