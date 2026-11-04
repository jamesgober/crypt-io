//! `crypt_io::sign` against published vectors.
//!
//! - Ed25519: RFC 8032 section 7.1 tests 1, 2, 3, 1024 and SHA(abc),
//!   from the raw seed and from PKCS#8 v1 and v2; the RFC 8463 DKIM
//!   example signature, rebuilt from the RFC's message.
//! - RSA: every SHA-256 case of NIST CAVP SigGen15 (FIPS 186-3,
//!   PKCS#1 v1.5) for the 2048- and 3072-bit keys, from PKCS#1 and
//!   PKCS#8; the RFC 8463 1024-bit example key, which must be refused.
//!
//! `tests/data/sign_vectors.rs` is generated from the published files by
//! `tests/data/gen_sign_vectors.py`.

#![cfg(any(feature = "sign-ed25519", feature = "sign-rsa"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "data/sign_vectors.rs"]
mod vectors;

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

#[cfg(feature = "sign-ed25519")]
mod ed25519 {
    use super::{h, vectors};
    use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
    use crypt_io::Error;
    use crypt_io::sign::Ed25519SigningKey;

    fn seed(s: &str) -> [u8; 32] {
        h(s).try_into().unwrap()
    }

    /// PKCS#8 v1 (RFC 8410 section 7) around a raw seed.
    fn pkcs8_v1(seed: &[u8; 32]) -> Vec<u8> {
        let mut der = h("302e020100300506032b657004220420");
        der.extend_from_slice(seed);
        der
    }

    /// PKCS#8 v2 / OneAsymmetricKey (RFC 5958) with the public key.
    fn pkcs8_v2(seed: &[u8; 32], public_key: &[u8]) -> Vec<u8> {
        let mut der = h("3051020101300506032b657004220420");
        der.extend_from_slice(seed);
        // [1] IMPLICIT BIT STRING: 33 bytes, no unused bits, the key.
        der.extend_from_slice(&[0x81, 0x21, 0x00]);
        der.extend_from_slice(public_key);
        der
    }

    #[test]
    fn rfc8032_from_seed() {
        for v in vectors::RFC8032 {
            let key = Ed25519SigningKey::from_seed(&seed(v.seed)).unwrap();
            assert_eq!(
                key.public_key().as_slice(),
                h(v.public_key),
                "test {}",
                v.name
            );
            assert_eq!(
                key.sign(&h(v.message)).as_slice(),
                h(v.signature),
                "test {}",
                v.name
            );
        }
    }

    #[test]
    fn rfc8032_from_pkcs8_v1_and_v2() {
        for v in vectors::RFC8032 {
            let s = seed(v.seed);
            let pk = h(v.public_key);
            for der in [pkcs8_v1(&s), pkcs8_v2(&s, &pk)] {
                let key = Ed25519SigningKey::from_pkcs8_der(&der).unwrap();
                assert_eq!(key.public_key().as_slice(), pk, "test {}", v.name);
                assert_eq!(key.sign(&h(v.message)).as_slice(), h(v.signature));
            }
        }
    }

    #[test]
    fn pkcs8_v2_with_the_wrong_public_key_is_refused() {
        let v = &vectors::RFC8032[0];
        let other = h(vectors::RFC8032[1].public_key);
        assert!(matches!(
            Ed25519SigningKey::from_pkcs8_der(&pkcs8_v2(&seed(v.seed), &other)),
            Err(Error::Sign(_))
        ));
    }

    #[test]
    fn truncated_pkcs8_is_refused() {
        let der = pkcs8_v1(&seed(vectors::RFC8032[0].seed));
        for len in 0..der.len() {
            assert!(
                Ed25519SigningKey::from_pkcs8_der(&der[..len]).is_err(),
                "len {len}"
            );
        }
    }

    #[test]
    fn signatures_verify_and_tampering_is_detected() {
        let key = Ed25519SigningKey::from_seed(&[9u8; 32]).unwrap();
        let public = UnparsedPublicKey::new(&ED25519, key.public_key());
        let mut sig = key.sign(b"payload");
        public.verify(b"payload", &sig).unwrap();
        sig[10] ^= 1;
        assert!(public.verify(b"payload", &sig).is_err());
    }

    #[test]
    fn one_key_signs_from_many_threads() {
        let key = std::sync::Arc::new(Ed25519SigningKey::from_seed(&[3u8; 32]).unwrap());
        let expected = key.sign(b"same message");
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let key = std::sync::Arc::clone(&key);
                std::thread::spawn(move || key.sign(b"same message"))
            })
            .collect();
        for h in handles {
            assert_eq!(h.join().unwrap(), expected);
        }
    }

    /// RFC 8463 appendix A: the `ed25519-sha256` DKIM-Signature over the
    /// example message. DKIM signs the SHA-256 of the relaxed-canonical
    /// header block (RFC 6376 section 3.4.2) with the `b=` value empty;
    /// the signature must equal the RFC's `b=` bit for bit.
    #[cfg(feature = "hash-sha2")]
    #[test]
    fn rfc8463_dkim_example_signature() {
        let headers = concat!(
            "from:Joe SixPack <joe@football.example.com>\r\n",
            "to:Suzie Q <suzie@shopping.example.net>\r\n",
            "subject:Is dinner ready?\r\n",
            "date:Fri, 11 Jul 2003 21:00:37 -0700 (PDT)\r\n",
            "message-id:<20030712040037.46341.5F8J@football.example.com>\r\n",
            "dkim-signature:v=1; a=ed25519-sha256; c=relaxed/relaxed; ",
            "d=football.example.com; i=@football.example.com; q=dns/txt; ",
            "s=brisbane; t=1528637909; ",
            "h=from : to : subject : date : message-id : from : subject : date; ",
            "bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=; b=",
        );
        // RFC 8463 A.1: the RFC 8032 test 1 seed, in base64.
        let key = Ed25519SigningKey::from_seed(&seed(vectors::RFC8032[0].seed)).unwrap();
        let signature = key.sign(&crypt_io::hash::sha256(headers.as_bytes()));
        // RFC 8463 A.3, `b=/gCrinpcQOoIfuHNQIbq4pgh9kyIK3AQUdt9OdqQehSw...` in hex.
        assert_eq!(
            signature.as_slice(),
            h(
                "fe00ab8a7a5c40ea087ee1cd4086eae29821f64c882b701051db7d39da907a14\
               b084422e8380f5d41bac15addb4f7158e4eb14ed96e72842eaf9e5dda754350f"
            )
        );
    }
}

#[cfg(feature = "sign-rsa")]
mod rsa {
    use super::{h, vectors};
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::rsa::{KeyPair, KeySize};
    use aws_lc_rs::signature::{RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
    use crypt_io::Error;
    use crypt_io::sign::{RSA_MAX_MODULUS_BITS, RSA_MIN_MODULUS_BITS, RsaSigningKey};

    #[test]
    fn nist_siggen15_sha256_from_pkcs1_and_pkcs8() {
        for set in vectors::NIST_SIGGEN15_SHA256 {
            let keys = [
                RsaSigningKey::from_pkcs1_der(&h(set.pkcs1_der)).unwrap(),
                RsaSigningKey::from_pkcs8_der(&h(set.pkcs8_der)).unwrap(),
            ];
            for key in keys {
                assert_eq!(key.modulus_bits(), set.bits);
                assert_eq!(key.public_key_der(), h(set.spki_der).as_slice());
                for (i, case) in set.cases.iter().enumerate() {
                    assert_eq!(
                        key.sign_pkcs1v15_sha256(&h(case.message)).unwrap(),
                        h(case.signature),
                        "{} bits, case {i}",
                        set.bits
                    );
                }
            }
        }
    }

    #[test]
    fn pkcs1_and_pkcs8_are_not_interchangeable() {
        let set = &vectors::NIST_SIGGEN15_SHA256[0];
        assert!(RsaSigningKey::from_pkcs8_der(&h(set.pkcs1_der)).is_err());
        assert!(RsaSigningKey::from_pkcs1_der(&h(set.pkcs8_der)).is_err());
    }

    #[test]
    fn rfc8463_1024_bit_key_is_refused() {
        let err = RsaSigningKey::from_pkcs1_der(&h(vectors::RFC8463_RSA_1024_PKCS1)).unwrap_err();
        assert_eq!(
            err,
            Error::Sign("key rejected: RSA modulus smaller than 2048 bits")
        );
        assert_eq!(RSA_MIN_MODULUS_BITS, 2048);
        assert_eq!(RSA_MAX_MODULUS_BITS, 8192);
    }

    #[test]
    fn an_ed25519_key_is_not_an_rsa_key() {
        let mut ed = h("302e020100300506032b657004220420");
        ed.extend_from_slice(&[1u8; 32]);
        assert!(matches!(
            RsaSigningKey::from_pkcs8_der(&ed),
            Err(Error::Sign(_))
        ));
    }

    #[test]
    fn generated_4096_bit_key_signs_and_verifies() {
        let generated = KeyPair::generate(KeySize::Rsa4096).unwrap();
        let pkcs8 = AsDer::<aws_lc_rs::encoding::Pkcs8V1Der>::as_der(&generated).unwrap();
        let key = RsaSigningKey::from_pkcs8_der(pkcs8.as_ref()).unwrap();
        assert_eq!(key.modulus_bits(), 4096);
        let sig = key.sign_pkcs1v15_sha256(b"dkim header hash input").unwrap();
        assert_eq!(sig.len(), 512);
        let public = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, key.public_key_der());
        public.verify(b"dkim header hash input", &sig).unwrap();
        assert!(public.verify(b"dkim header hash inpuT", &sig).is_err());
    }

    #[test]
    fn debug_shows_only_the_modulus_size() {
        let set = &vectors::NIST_SIGGEN15_SHA256[0];
        let key = RsaSigningKey::from_pkcs1_der(&h(set.pkcs1_der)).unwrap();
        assert_eq!(
            format!("{key:?}"),
            "RsaSigningKey { modulus_bits: 2048, .. }"
        );
    }
}
