//! Shared storage-key derivation for authenticated formats.

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::storage::{CryptError, KeyLease, KeyScope, Result};

const HKDF_SALT_DOMAIN: &[u8] = b"crypt-io/hkdf-salt/v1\0";

pub(crate) fn derive_storage_key(
    lease: &KeyLease,
    scope: &KeyScope,
    object_salt: &[u8; 32],
    suite: u16,
    info_domain: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let generation_bytes = lease.generation().get().to_be_bytes();
    let suite_bytes = suite.to_be_bytes();

    let mut salt_hasher = Sha256::new();
    salt_hasher.update(HKDF_SALT_DOMAIN);
    salt_hasher.update(lease.key_id().as_bytes());
    salt_hasher.update(generation_bytes);
    let hkdf_salt = salt_hasher.finalize();

    let mut derived_key = Zeroizing::new([0_u8; 32]);
    let expand_result = lease.with_secret_bytes(|master_key| {
        // `Hkdf::new` drops the extracted PRK as an ordinary digest output.
        // Construct the zeroizing HKDF state explicitly, then wipe that
        // transient master-derived PRK before expansion.
        let (mut prk, hkdf) = Hkdf::<Sha256>::extract(Some(&hkdf_salt), master_key);
        prk.zeroize();
        hkdf.expand_multi_info(
            &[
                info_domain,
                &suite_bytes,
                lease.key_id().as_bytes(),
                &generation_bytes,
                scope.purpose_id().as_bytes(),
                scope.space_id().as_bytes(),
                object_salt,
            ],
            derived_key.as_mut(),
        )
    });
    expand_result.map_err(|_error| CryptError::InvalidInput)?;
    Ok(derived_key)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use hex_literal::hex;
    use hkdf::Hkdf;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use zeroize::Zeroizing;

    use super::derive_storage_key;
    use crate::storage::{
        KeyGeneration, KeyId, KeyLease, KeyScope, PurposeId, SecretKey32, SpaceId,
    };

    #[test]
    fn hkdf_sha256_matches_rfc5869_test_case_one() {
        let ikm = [0x0B_u8; 22];
        let salt = hex!("000102030405060708090a0b0c");
        let info = hex!("f0f1f2f3f4f5f6f7f8f9");
        let expected = hex!(
            "3cb25f25faacd57a90434f64d0362f2a
             2d2d0a90cf1a5a4c5db02d56ecc4c5bf
             34007208d5b887185865"
        );
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);
        let mut output = [0_u8; 42];
        hkdf.expand(&info, &mut output).unwrap();
        assert_eq!(output, expected);
    }

    #[test]
    fn hmac_sha256_matches_rfc4231_test_case_one() {
        let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(&[0x0B; 20]).unwrap();
        mac.update(b"Hi There");

        assert_eq!(
            mac.finalize().into_bytes().as_slice(),
            &hex!("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        );
    }

    #[test]
    fn storage_key_derivation_matches_independent_fixture() {
        let lease = KeyLease::new(
            KeyId::new(*b"test-key-id-v001"),
            KeyGeneration::new(7),
            SecretKey32::new([0xA7; 32]),
        );
        let scope = KeyScope::new(
            SpaceId::new([0x53; 32]),
            PurposeId::new(*b"memory-record-v1"),
        );
        let derived = derive_storage_key(
            &lease,
            &scope,
            &[0x11; 32],
            1,
            b"crypt-io/sealed-record/v1\0",
        )
        .unwrap();
        assert_eq!(
            derived.as_ref(),
            &hex!("5a6dc04651e4bc9a7217b6ef73c1c246b6f60fe565337bec72f373e1d59574a4")
        );
    }

    #[test]
    fn storage_key_changes_for_every_separation_input() {
        #[derive(Clone, Copy)]
        struct Fixture<'a> {
            key_id: [u8; 16],
            generation: u32,
            secret: [u8; 32],
            purpose: [u8; 16],
            space: [u8; 32],
            salt: [u8; 32],
            suite: u16,
            domain: &'a [u8],
        }

        impl Fixture<'_> {
            fn derive(self) -> Zeroizing<[u8; 32]> {
                let lease = KeyLease::new(
                    KeyId::new(self.key_id),
                    KeyGeneration::new(self.generation),
                    SecretKey32::new(self.secret),
                );
                let scope = KeyScope::new(SpaceId::new(self.space), PurposeId::new(self.purpose));
                derive_storage_key(&lease, &scope, &self.salt, self.suite, self.domain).unwrap()
            }
        }

        let fixture = Fixture {
            key_id: *b"test-key-id-v001",
            generation: 7,
            secret: [0xA7; 32],
            purpose: *b"memory-record-v1",
            space: [0x53; 32],
            salt: [0x11; 32],
            suite: 1,
            domain: b"crypt-io/sealed-record/v1\0",
        };
        let baseline = fixture.derive();

        for changed in [
            Fixture {
                key_id: *b"test-key-id-v002",
                ..fixture
            }
            .derive(),
            Fixture {
                generation: fixture.generation + 1,
                ..fixture
            }
            .derive(),
            Fixture {
                secret: [0xA8; 32],
                ..fixture
            }
            .derive(),
            Fixture {
                purpose: *b"snapshot-strm-v1",
                ..fixture
            }
            .derive(),
            Fixture {
                space: [0x54; 32],
                ..fixture
            }
            .derive(),
            Fixture {
                salt: [0x12; 32],
                ..fixture
            }
            .derive(),
            Fixture {
                suite: fixture.suite + 1,
                ..fixture
            }
            .derive(),
            Fixture {
                domain: b"crypt-io/encrypted-stream/v1\0",
                ..fixture
            }
            .derive(),
            Fixture {
                domain: b"crypt-io/sealed-record/context-key/v1\0",
                ..fixture
            }
            .derive(),
        ] {
            assert_ne!(baseline.as_ref(), changed.as_ref());
        }
    }
}
