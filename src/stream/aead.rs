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
