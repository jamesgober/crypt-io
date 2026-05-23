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
            use aes_gcm::aead::{AeadInPlace, KeyInit};
            use aes_gcm::{Aes256Gcm, Key as AesKey, Nonce as AesNonce};

            let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(key));
            let tag = cipher
                .encrypt_in_place_detached(AesNonce::from_slice(nonce), aad, out)
                .map_err(|_| Error::AuthenticationFailed)?;
            out.extend_from_slice(&tag);
        }
    }
    Ok(())
}

/// Decrypt one chunk into a caller-supplied buffer. Buffer is cleared
/// and grown to `ciphertext_and_tag.len() - tag_len` bytes (the
/// recovered plaintext). On authentication failure the buffer is
/// scrubbed before returning.
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
            use aes_gcm::aead::{AeadInPlace, KeyInit};
            use aes_gcm::{Aes256Gcm, Key as AesKey, Nonce as AesNonce};

            let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(key));
            let tag = aes_gcm::Tag::from_slice(tag_bytes);
            cipher
                .decrypt_in_place_detached(AesNonce::from_slice(nonce), aad, out, tag)
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
            use aes_gcm::aead::{Aead, KeyInit, Payload};
            use aes_gcm::{Aes256Gcm, Key as AesKey, Nonce as AesNonce};

            let cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(key));
            cipher
                .decrypt(
                    AesNonce::from_slice(nonce),
                    Payload {
                        msg: ciphertext_and_tag,
                        aad,
                    },
                )
                .map_err(|_| Error::AuthenticationFailed)
        }
    }
}
