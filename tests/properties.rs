//! Property tests for the AEAD and stream surfaces. These mirror the
//! properties checked by the `audit_into_diff` fuzz target so that a
//! plain `cargo test` exercises them too.

#![cfg(all(
    feature = "stream",
    feature = "aead-chacha20",
    feature = "aead-aes-gcm"
))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crypt_io::stream::{HEADER_LEN, StreamDecryptor, StreamEncryptor};
use crypt_io::{Algorithm, Crypt};
use proptest::prelude::*;

fn alg(aes: bool) -> Algorithm {
    if aes {
        Algorithm::Aes256Gcm
    } else {
        Algorithm::ChaCha20Poly1305
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// `decrypt` and `decrypt_into` agree on arbitrary input, and
    /// `decrypt_into` leaves `out` empty on every error.
    #[test]
    fn decrypt_and_decrypt_into_agree(
        aes in any::<bool>(),
        key in proptest::collection::vec(any::<u8>(), 30..34),
        wire in proptest::collection::vec(any::<u8>(), 0..96),
        aad in proptest::collection::vec(any::<u8>(), 0..16),
    ) {
        let c = Crypt::with_algorithm(alg(aes));
        let a = c.decrypt_with_aad(&key, &wire, &aad);
        let mut out = b"previous plaintext".to_vec();
        let b = c.decrypt_with_aad_into(&key, &wire, &aad, &mut out);
        prop_assert_eq!(a.is_ok(), b.is_ok());
        match a {
            Ok(pt) => prop_assert_eq!(pt, out),
            Err(_) => prop_assert!(out.is_empty()),
        }
    }

    /// Any single-bit change to a single-shot ciphertext fails.
    #[test]
    fn modified_ciphertext_never_decrypts(
        aes in any::<bool>(),
        key in any::<[u8; 32]>(),
        pt in proptest::collection::vec(any::<u8>(), 0..200),
        pos in any::<usize>(),
        bit in 0u8..8,
    ) {
        let c = Crypt::with_algorithm(alg(aes));
        let mut ct = c.encrypt(&key, &pt).unwrap();
        let i = pos % ct.len();
        ct[i] ^= 1 << bit;
        prop_assert!(c.decrypt(&key, &ct).is_err());
    }

    /// Stream `update` and `update_into` agree for arbitrary split
    /// points, and both recover the plaintext.
    #[test]
    fn stream_split_points_agree(
        aes in any::<bool>(),
        key in any::<[u8; 32]>(),
        pt in proptest::collection::vec(any::<u8>(), 0..5000),
        splits in proptest::collection::vec(1usize..3000, 0..8),
    ) {
        let (mut enc, header) =
            StreamEncryptor::new_with_chunk_size(&key, alg(aes), 10).unwrap();
        let mut wire = header.to_vec();
        wire.extend(enc.update(&pt).unwrap());
        wire.extend(enc.finalize().unwrap());
        let body = &wire[HEADER_LEN..];

        let mut pieces = Vec::new();
        let mut rest = body;
        for s in &splits {
            let n = (*s).min(rest.len());
            let (a, b) = rest.split_at(n);
            pieces.push(a);
            rest = b;
        }
        pieces.push(rest);

        let mut dec = StreamDecryptor::new(&key, &header).unwrap();
        let mut a = Vec::new();
        for p in &pieces {
            a.extend(dec.update(p).unwrap());
        }
        a.extend(dec.finalize().unwrap());

        let mut dec = StreamDecryptor::new(&key, &header).unwrap();
        let mut b = Vec::new();
        for p in &pieces {
            dec.update_into(p, &mut b).unwrap();
        }
        dec.finalize_into(&mut b).unwrap();

        prop_assert_eq!(&a, &pt);
        prop_assert_eq!(&b, &pt);
    }

    /// Truncating a stream anywhere (including at a chunk boundary)
    /// never decrypts successfully.
    #[test]
    fn truncated_stream_never_decrypts(
        key in any::<[u8; 32]>(),
        pt in proptest::collection::vec(any::<u8>(), 0..4000),
        cut in 1usize..4100,
    ) {
        let (mut enc, header) =
            StreamEncryptor::new_with_chunk_size(&key, Algorithm::ChaCha20Poly1305, 10).unwrap();
        let mut wire = header.to_vec();
        wire.extend(enc.update(&pt).unwrap());
        wire.extend(enc.finalize().unwrap());
        let body_len = wire.len() - HEADER_LEN;
        wire.truncate(wire.len() - (cut % body_len).max(1));

        let mut dec = StreamDecryptor::new(&key, &header).unwrap();
        let r = dec
            .update(&wire[HEADER_LEN..])
            .and_then(|mut v| dec.finalize().map(|t| { v.extend(t); v }));
        prop_assert!(r.is_err());
    }
}
