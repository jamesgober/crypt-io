//! Per-chunk AEAD primitive for the stream module.
//!
//! Unlike the top-level [`crate::aead`] module — which generates a
//! nonce internally and prepends it to the ciphertext — the stream
//! protocol carries its own nonce schedule (the STREAM construction in
//! [`super::frame`]). This module exposes minimal "encrypt with a
//! caller-supplied nonce" / "decrypt with a caller-supplied nonce"
//! primitives that operate on a single chunk at a time.

use alloc::vec::Vec;

use crate::aead::Algorithm;
use crate::error::{Error, Result};
use crate::wipe::{wipe_tail, wipe_vec};

use super::frame::{NONCE_LEN, TAG_LEN};

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
            use aes_gcm::aead::{Aead, KeyInit, Payload};
            use aes_gcm::{Aes256Gcm, Key as AesKey, Nonce as AesNonce};

            let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(key));
            cipher
                .encrypt(
                    AesNonce::from_slice(nonce),
                    Payload {
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
/// appended after the in-place ciphertext. On error the buffer (which
/// held a copy of the plaintext) is wiped.
pub(super) fn encrypt_chunk_into(
    algorithm: Algorithm,
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
    out: &mut Vec<u8>,
) -> Result<()> {
    out.clear();
    out.reserve(plaintext.len() + TAG_LEN);
    out.extend_from_slice(plaintext);

    match algorithm {
        Algorithm::ChaCha20Poly1305 => {
            use chacha20poly1305::aead::{AeadInPlace, KeyInit};
            use chacha20poly1305::{ChaCha20Poly1305, Key as ChaKey, Nonce as ChaNonce};

            let cipher = ChaCha20Poly1305::new(ChaKey::from_slice(key));
            let tag = cipher
                .encrypt_in_place_detached(ChaNonce::from_slice(nonce), aad, out)
                .map_err(|_| {
                    // `out` still holds the plaintext copy; wipe it.
                    wipe_vec(out);
                    Error::AuthenticationFailed
                })?;
            out.extend_from_slice(&tag);
        }
        Algorithm::Aes256Gcm => {
            use aes_gcm::aead::{AeadInPlace, KeyInit};
            use aes_gcm::{Aes256Gcm, Key as AesKey, Nonce as AesNonce};

            let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(key));
            let tag = cipher
                .encrypt_in_place_detached(AesNonce::from_slice(nonce), aad, out)
                .map_err(|_| {
                    // `out` still holds the plaintext copy; wipe it.
                    wipe_vec(out);
                    Error::AuthenticationFailed
                })?;
            out.extend_from_slice(&tag);
        }
    }
    Ok(())
}

/// Decrypt one chunk (`ciphertext || tag`) and **append** the
/// recovered plaintext to `out`. Bytes already in `out` are left
/// untouched.
///
/// The ciphertext is copied to the end of `out` and decrypted in place
/// there, so no intermediate buffer is allocated. On any error the
/// appended region is overwritten with zeros and `out` is truncated
/// back to its original length.
pub(super) fn decrypt_chunk_append(
    algorithm: Algorithm,
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
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
    let (ct, tag_bytes) = ciphertext_and_tag.split_at(ciphertext_and_tag.len() - TAG_LEN);

    let start = out.len();
    out.extend_from_slice(ct);

    let result = match algorithm {
        Algorithm::ChaCha20Poly1305 => {
            use chacha20poly1305::aead::{AeadInPlace, KeyInit};
            use chacha20poly1305::{ChaCha20Poly1305, Key as ChaKey, Nonce as ChaNonce};

            let cipher = ChaCha20Poly1305::new(ChaKey::from_slice(key));
            let tag = chacha20poly1305::Tag::from_slice(tag_bytes);
            cipher.decrypt_in_place_detached(
                ChaNonce::from_slice(nonce),
                aad,
                &mut out[start..],
                tag,
            )
        }
        Algorithm::Aes256Gcm => {
            use aes_gcm::aead::{AeadInPlace, KeyInit};
            use aes_gcm::{Aes256Gcm, Key as AesKey, Nonce as AesNonce};

            let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(key));
            let tag = aes_gcm::Tag::from_slice(tag_bytes);
            cipher.decrypt_in_place_detached(
                AesNonce::from_slice(nonce),
                aad,
                &mut out[start..],
                tag,
            )
        }
    };
    result.map_err(|_| {
        wipe_tail(out, start);
        Error::AuthenticationFailed
    })
}
