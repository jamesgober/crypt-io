//! A scheduled AEAD key: the cipher state for one algorithm and one key.
//!
//! Building a cipher from key bytes (AES key expansion and the GHASH key,
//! or the ChaCha20 key copy) is part of every single-shot call, but a
//! stream or a [`KeyedCrypt`](super::KeyedCrypt) does it once and reuses
//! the result. [`Engine`] is that result, with one in-place,
//! detached-tag interface over both backends:
//!
//! - RustCrypto (`chacha20poly1305`, `aes-gcm`): always used for
//!   XChaCha20-Poly1305, and for the other two unless `aead-aws-lc` is on.
//! - AWS-LC (`aead-aws-lc`): ChaCha20-Poly1305 and AES-256-GCM. Both
//!   backends implement RFC 8439 and NIST SP 800-38D, so the bytes are
//!   identical (pinned by the cross-backend tests in this module).
//!
//! The state is dropped with its owner. RustCrypto wipes the ChaCha20 key
//! on drop and, with `zeroize`, the AES round keys; AWS-LC cleanses its
//! memory on free. A single-shot call keeps its `Engine` on the stack (no
//! allocation); the long-lived owners ([`KeyedCrypt`](super::KeyedCrypt)
//! and the stream types) box it, so moving them never copies round keys
//! around the stack.

use super::{Algorithm, KEY_LEN, TAG_LEN};
use crate::error::{Error, Result};

#[cfg(all(
    feature = "aead-aes-gcm",
    not(feature = "aead-chacha20"),
    not(feature = "aead-aws-lc")
))]
use aes_gcm::aead as aead_api;
#[cfg(feature = "aead-chacha20")]
use chacha20poly1305::aead as aead_api;

#[cfg(any(
    feature = "aead-chacha20",
    all(feature = "aead-aes-gcm", not(feature = "aead-aws-lc"))
))]
use aead_api::{AeadInPlace, KeyInit};

/// Cipher state for one algorithm and key.
// The AES-GCM state is much larger than the ChaCha20 ones. Not boxed on
// purpose: a single-shot call keeps its engine on the stack for one
// call, and the long-lived owners box the whole `Engine`.
#[allow(clippy::large_enum_variant)]
pub(crate) enum Engine {
    #[cfg(all(feature = "aead-chacha20", not(feature = "aead-aws-lc")))]
    ChaCha20(chacha20poly1305::ChaCha20Poly1305),
    #[cfg(feature = "aead-chacha20")]
    XChaCha20(chacha20poly1305::XChaCha20Poly1305),
    #[cfg(all(feature = "aead-aes-gcm", not(feature = "aead-aws-lc")))]
    Aes256Gcm(aes_gcm::Aes256Gcm),
    /// ChaCha20-Poly1305 or AES-256-GCM through AWS-LC.
    #[cfg(feature = "aead-aws-lc")]
    AwsLc(aws_lc_rs::aead::LessSafeKey, Algorithm),
}

impl Engine {
    /// Schedule `key` for `algorithm`.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidKey`] if `key` is not 32 bytes.
    /// - [`Error::AlgorithmNotEnabled`] if the algorithm's feature is off.
    #[inline]
    pub(crate) fn new(algorithm: Algorithm, key: &[u8]) -> Result<Self> {
        if key.len() != KEY_LEN {
            return Err(Error::InvalidKey {
                expected: KEY_LEN,
                actual: key.len(),
            });
        }
        match algorithm {
            Algorithm::ChaCha20Poly1305 => Self::chacha20(key),
            Algorithm::XChaCha20Poly1305 => Self::xchacha20(key),
            Algorithm::Aes256Gcm => Self::aes256gcm(key),
        }
    }

    /// Run `f` with `key` scheduled for `algorithm`, for a single call.
    ///
    /// Same checks and errors as [`new`](Self::new). The RustCrypto AES
    /// state (round keys and GHASH key, about 1 KiB) is built directly
    /// in this frame instead of being returned through a `Result`, which
    /// would copy it; that copy is a measurable share of a short
    /// message's cost.
    #[inline]
    pub(crate) fn with<R>(
        algorithm: Algorithm,
        key: &[u8],
        f: impl FnOnce(&Self) -> Result<R>,
    ) -> Result<R> {
        #[cfg(all(feature = "aead-aes-gcm", not(feature = "aead-aws-lc")))]
        if algorithm == Algorithm::Aes256Gcm && key.len() == KEY_LEN {
            let engine = Self::Aes256Gcm(aes_gcm::Aes256Gcm::new(
                aes_gcm::Key::<aes_gcm::Aes256Gcm>::from_slice(key),
            ));
            return f(&engine);
        }
        f(&Self::new(algorithm, key)?)
    }

    // Each per-algorithm constructor returns `Result` so `new` reads the
    // same in every feature combination; some combinations cannot fail.
    #[cfg(all(feature = "aead-chacha20", not(feature = "aead-aws-lc")))]
    #[allow(clippy::unnecessary_wraps)]
    #[inline]
    fn chacha20(key: &[u8]) -> Result<Self> {
        Ok(Self::ChaCha20(chacha20poly1305::ChaCha20Poly1305::new(
            aead_api::Key::<chacha20poly1305::ChaCha20Poly1305>::from_slice(key),
        )))
    }

    #[cfg(all(feature = "aead-chacha20", feature = "aead-aws-lc"))]
    #[inline]
    fn chacha20(key: &[u8]) -> Result<Self> {
        Self::aws_lc(
            Algorithm::ChaCha20Poly1305,
            &aws_lc_rs::aead::CHACHA20_POLY1305,
            key,
        )
    }

    #[cfg(not(feature = "aead-chacha20"))]
    fn chacha20(_key: &[u8]) -> Result<Self> {
        Err(Error::AlgorithmNotEnabled("aead-chacha20"))
    }

    #[cfg(feature = "aead-chacha20")]
    #[allow(clippy::unnecessary_wraps)]
    #[inline]
    fn xchacha20(key: &[u8]) -> Result<Self> {
        Ok(Self::XChaCha20(chacha20poly1305::XChaCha20Poly1305::new(
            aead_api::Key::<chacha20poly1305::XChaCha20Poly1305>::from_slice(key),
        )))
    }

    #[cfg(not(feature = "aead-chacha20"))]
    fn xchacha20(_key: &[u8]) -> Result<Self> {
        Err(Error::AlgorithmNotEnabled("aead-chacha20"))
    }

    #[cfg(all(feature = "aead-aes-gcm", not(feature = "aead-aws-lc")))]
    #[allow(clippy::unnecessary_wraps)]
    #[inline]
    fn aes256gcm(key: &[u8]) -> Result<Self> {
        Ok(Self::Aes256Gcm(aes_gcm::Aes256Gcm::new(aes_gcm::Key::<
            aes_gcm::Aes256Gcm,
        >::from_slice(
            key
        ))))
    }

    #[cfg(all(feature = "aead-aes-gcm", feature = "aead-aws-lc"))]
    #[inline]
    fn aes256gcm(key: &[u8]) -> Result<Self> {
        Self::aws_lc(Algorithm::Aes256Gcm, &aws_lc_rs::aead::AES_256_GCM, key)
    }

    #[cfg(not(feature = "aead-aes-gcm"))]
    fn aes256gcm(_key: &[u8]) -> Result<Self> {
        Err(Error::AlgorithmNotEnabled("aead-aes-gcm"))
    }

    #[cfg(feature = "aead-aws-lc")]
    fn aws_lc(
        algorithm: Algorithm,
        lc: &'static aws_lc_rs::aead::Algorithm,
        key: &[u8],
    ) -> Result<Self> {
        let unbound = aws_lc_rs::aead::UnboundKey::new(lc, key).map_err(|_| Error::InvalidKey {
            expected: KEY_LEN,
            actual: key.len(),
        })?;
        Ok(Self::AwsLc(
            aws_lc_rs::aead::LessSafeKey::new(unbound),
            algorithm,
        ))
    }

    /// The algorithm this state was built for.
    pub(crate) fn algorithm(&self) -> Algorithm {
        match self {
            #[cfg(all(feature = "aead-chacha20", not(feature = "aead-aws-lc")))]
            Self::ChaCha20(_) => Algorithm::ChaCha20Poly1305,
            #[cfg(feature = "aead-chacha20")]
            Self::XChaCha20(_) => Algorithm::XChaCha20Poly1305,
            #[cfg(all(feature = "aead-aes-gcm", not(feature = "aead-aws-lc")))]
            Self::Aes256Gcm(_) => Algorithm::Aes256Gcm,
            #[cfg(feature = "aead-aws-lc")]
            Self::AwsLc(_, alg) => *alg,
        }
    }

    /// Encrypt `buf` in place under `nonce` (exactly the algorithm's
    /// nonce length) and `aad`, and return the tag.
    ///
    /// The only failure is an input longer than the cipher allows; `buf`
    /// may then hold partial output, which callers wipe.
    #[cfg_attr(not(any(feature = "std", feature = "getrandom")), allow(dead_code))]
    pub(crate) fn seal_in_place(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buf: &mut [u8],
    ) -> core::result::Result<[u8; TAG_LEN], ()> {
        if nonce.len() != self.algorithm().nonce_len() {
            return Err(());
        }
        let mut tag = [0u8; TAG_LEN];
        match self {
            #[cfg(all(feature = "aead-chacha20", not(feature = "aead-aws-lc")))]
            Self::ChaCha20(c) => {
                tag.copy_from_slice(
                    &c.encrypt_in_place_detached(nonce.into(), aad, buf)
                        .map_err(|_| ())?,
                );
            }
            #[cfg(feature = "aead-chacha20")]
            Self::XChaCha20(c) => {
                tag.copy_from_slice(
                    &c.encrypt_in_place_detached(nonce.into(), aad, buf)
                        .map_err(|_| ())?,
                );
            }
            #[cfg(all(feature = "aead-aes-gcm", not(feature = "aead-aws-lc")))]
            Self::Aes256Gcm(c) => {
                tag.copy_from_slice(
                    &c.encrypt_in_place_detached(nonce.into(), aad, buf)
                        .map_err(|_| ())?,
                );
            }
            #[cfg(feature = "aead-aws-lc")]
            Self::AwsLc(k, _) => {
                let n = aws_lc_rs::aead::Nonce::try_assume_unique_for_key(nonce).map_err(|_| ())?;
                let t = k
                    .seal_in_place_separate_tag(n, aws_lc_rs::aead::Aad::from(aad), buf)
                    .map_err(|_| ())?;
                tag.copy_from_slice(t.as_ref());
            }
        }
        Ok(tag)
    }

    /// Check `tag` and decrypt `buf` in place under `nonce` and `aad`.
    ///
    /// On failure `buf` may hold partial output, which callers wipe.
    pub(crate) fn open_in_place(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8],
    ) -> core::result::Result<(), ()> {
        if tag.len() != TAG_LEN || nonce.len() != self.algorithm().nonce_len() {
            return Err(());
        }
        match self {
            #[cfg(all(feature = "aead-chacha20", not(feature = "aead-aws-lc")))]
            Self::ChaCha20(c) => c
                .decrypt_in_place_detached(nonce.into(), aad, buf, tag.into())
                .map_err(|_| ()),
            #[cfg(feature = "aead-chacha20")]
            Self::XChaCha20(c) => c
                .decrypt_in_place_detached(nonce.into(), aad, buf, tag.into())
                .map_err(|_| ()),
            #[cfg(all(feature = "aead-aes-gcm", not(feature = "aead-aws-lc")))]
            Self::Aes256Gcm(c) => c
                .decrypt_in_place_detached(nonce.into(), aad, buf, tag.into())
                .map_err(|_| ()),
            #[cfg(feature = "aead-aws-lc")]
            Self::AwsLc(k, _) => {
                let n = aws_lc_rs::aead::Nonce::try_assume_unique_for_key(nonce).map_err(|_| ())?;
                k.open_in_place_separate_tag(n, aws_lc_rs::aead::Aad::from(aad), tag, buf)
                    .map(|_| ())
                    .map_err(|_| ())
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    #[cfg(feature = "aead-chacha20")]
    use alloc::vec::Vec;

    /// RustCrypto reference output for `alg`, independent of `Engine`.
    #[cfg(feature = "aead-chacha20")]
    fn reference(alg: Algorithm, key: [u8; 32], nonce: &[u8], aad: &[u8], pt: &[u8]) -> Vec<u8> {
        use aead_api::Aead;
        let payload = aead_api::Payload { msg: pt, aad };
        match alg {
            Algorithm::ChaCha20Poly1305 => chacha20poly1305::ChaCha20Poly1305::new((&key).into())
                .encrypt(nonce.into(), payload)
                .unwrap(),
            Algorithm::XChaCha20Poly1305 => chacha20poly1305::XChaCha20Poly1305::new((&key).into())
                .encrypt(nonce.into(), payload)
                .unwrap(),
            #[cfg(feature = "aead-aes-gcm")]
            Algorithm::Aes256Gcm => {
                use aes_gcm::aead::Aead as _;
                aes_gcm::Aes256Gcm::new((&key).into())
                    .encrypt(nonce.into(), aes_gcm::aead::Payload { msg: pt, aad })
                    .unwrap()
            }
            // Not reached: AES-256-GCM is only tested when enabled.
            #[cfg(not(feature = "aead-aes-gcm"))]
            Algorithm::Aes256Gcm => Vec::new(),
        }
    }

    /// The engine in use (AWS-LC with `aead-aws-lc`, RustCrypto
    /// otherwise) gives the reference bytes and opens them, for every
    /// enabled algorithm and a spread of lengths.
    #[cfg(feature = "aead-chacha20")]
    #[test]
    fn engine_matches_the_rustcrypto_reference() {
        let mut algs = alloc::vec![Algorithm::ChaCha20Poly1305, Algorithm::XChaCha20Poly1305];
        if cfg!(feature = "aead-aes-gcm") {
            algs.push(Algorithm::Aes256Gcm);
        }
        for alg in algs {
            for len in [0usize, 1, 15, 16, 17, 63, 64, 255, 1024, 4097] {
                let key: [u8; 32] = core::array::from_fn(|i| u8::try_from(i).unwrap() ^ 0x5a);
                let nonce: Vec<u8> = (0..alg.nonce_len())
                    .map(|i| u8::try_from(i).unwrap() ^ 0x33)
                    .collect();
                let aad = [0xa5u8; 13];
                let pt: Vec<u8> = (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect();

                let engine = Engine::new(alg, &key).unwrap();
                assert_eq!(engine.algorithm(), alg);
                let mut buf = pt.clone();
                let tag = engine.seal_in_place(&nonce, &aad, &mut buf).unwrap();
                buf.extend_from_slice(&tag);
                assert_eq!(
                    buf,
                    reference(alg, key, &nonce, &aad, &pt),
                    "{alg:?} len {len}"
                );

                let (ct, tag) = buf.split_at_mut(len);
                engine.open_in_place(&nonce, &aad, ct, tag).unwrap();
                assert_eq!(ct, &pt[..]);
            }
        }
    }

    #[test]
    fn bad_tag_and_key_length() {
        assert!(matches!(
            Engine::new(Algorithm::default(), &[0u8; 31]),
            Err(Error::InvalidKey {
                expected: 32,
                actual: 31
            })
        ));
        if let Ok(engine) = Engine::new(Algorithm::default(), &[1u8; 32]) {
            let nonce = [0u8; 12];
            let mut buf = [7u8; 8];
            let mut tag = engine.seal_in_place(&nonce, b"", &mut buf).unwrap();
            tag[0] ^= 1;
            assert!(engine.open_in_place(&nonce, b"", &mut buf, &tag).is_err());
            assert!(
                engine
                    .open_in_place(&nonce, b"", &mut buf, &tag[..15])
                    .is_err()
            );
        }
    }
}
