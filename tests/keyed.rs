//! `KeyedCrypt`: the key-scheduled-once form of `Crypt` (1.6.0).
//!
//! Its bytes must be exactly what `Crypt` produces and accepts, for every
//! enabled algorithm, and its `open` must refuse a buffer sealed under a
//! different algorithm.

#![cfg(all(
    any(feature = "aead-chacha20", feature = "aead-aes-gcm"),
    any(feature = "std", feature = "getrandom")
))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crypt_io::{Algorithm, Crypt, Error, KeyedCrypt};

fn enabled() -> Vec<Algorithm> {
    let mut v = Vec::new();
    #[cfg(feature = "aead-chacha20")]
    v.extend([Algorithm::ChaCha20Poly1305, Algorithm::XChaCha20Poly1305]);
    #[cfg(feature = "aead-aes-gcm")]
    v.push(Algorithm::Aes256Gcm);
    v
}

const KEY: [u8; 32] = [0x5au8; 32];

#[test]
fn keyed_and_per_call_interoperate_both_ways() {
    for alg in enabled() {
        let crypt = Crypt::with_algorithm(alg);
        let keyed = crypt.keyed(&KEY).unwrap();
        assert_eq!(keyed.algorithm(), alg);
        for len in [0usize, 1, 15, 16, 17, 64, 1000, 70_000] {
            let pt: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
            // Plain.
            assert_eq!(
                crypt.decrypt(&KEY, &keyed.encrypt(&pt).unwrap()).unwrap(),
                pt
            );
            assert_eq!(
                keyed.decrypt(&crypt.encrypt(&KEY, &pt).unwrap()).unwrap(),
                pt
            );
            // With associated data.
            let ct = keyed.encrypt_with_aad(&pt, b"aad").unwrap();
            assert_eq!(crypt.decrypt_with_aad(&KEY, &ct, b"aad").unwrap(), pt);
            assert_eq!(keyed.decrypt_with_aad(&ct, b"aad").unwrap(), pt);
            assert_eq!(keyed.decrypt(&ct), Err(Error::AuthenticationFailed));
            // Sealed.
            let sealed = keyed.seal_with_aad(&pt, b"s").unwrap();
            assert_eq!(crypt.open_with_aad(&KEY, &sealed, b"s").unwrap(), pt);
            let sealed = crypt.seal(&KEY, &pt).unwrap();
            assert_eq!(keyed.open(&sealed).unwrap(), pt);
            // `_into` forms.
            let mut out = Vec::new();
            keyed.encrypt_with_aad_into(&pt, b"i", &mut out).unwrap();
            let mut back = vec![0xeeu8; 9];
            keyed.decrypt_with_aad_into(&out, b"i", &mut back).unwrap();
            assert_eq!(back, pt);
            keyed.encrypt_into(&pt, &mut out).unwrap();
            keyed.decrypt_into(&out, &mut back).unwrap();
            assert_eq!(back, pt);
            #[cfg(feature = "zeroize")]
            assert_eq!(*keyed.decrypt_zeroizing(&out).unwrap(), pt);
        }
    }
}

#[test]
fn keyed_rejects_bad_keys_like_crypt() {
    for alg in enabled() {
        let crypt = Crypt::with_algorithm(alg);
        assert!(matches!(
            crypt.keyed(&[0u8; 31]),
            Err(Error::InvalidKey {
                expected: 32,
                actual: 31
            })
        ));
        let ct = crypt.keyed(&KEY).unwrap().encrypt(b"x").unwrap();
        let other = crypt.keyed(&[1u8; 32]).unwrap();
        assert_eq!(other.decrypt(&ct), Err(Error::AuthenticationFailed));
        let mut out = vec![1, 2, 3];
        assert_eq!(
            other.decrypt_into(&ct, &mut out),
            Err(Error::AuthenticationFailed)
        );
        assert!(out.is_empty());
    }
}

#[test]
fn keyed_open_pins_the_algorithm() {
    let algs = enabled();
    for &a in &algs {
        for &b in &algs {
            let sealed = Crypt::with_algorithm(a).seal(&KEY, b"pinned").unwrap();
            let keyed = Crypt::with_algorithm(b).keyed(&KEY).unwrap();
            // `Crypt::open` follows the header.
            assert_eq!(Crypt::new().open(&KEY, &sealed).unwrap(), b"pinned");
            if a == b {
                assert_eq!(keyed.open(&sealed).unwrap(), b"pinned");
            } else {
                assert!(matches!(
                    keyed.open(&sealed),
                    Err(Error::InvalidCiphertext(_))
                ));
            }
        }
    }
}

#[test]
fn keyed_debug_shows_only_the_algorithm_and_is_send_sync() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<KeyedCrypt>();
    let alg = enabled()[0];
    let shown = format!("{:?}", Crypt::with_algorithm(alg).keyed(&KEY).unwrap());
    assert!(shown.starts_with("KeyedCrypt"), "{shown}");
    assert!(shown.contains(&format!("{alg:?}")), "{shown}");
    assert!(!shown.contains("90") && !shown.contains("5a"), "{shown}");
}
