//! HMAC and HKDF through the public surface: the full RFC 4231 and
//! RFC 5869 (SHA-2) vector sets, plus a grid of key, data, salt, info
//! and output lengths around the SHA-256 and SHA-512 block sizes.
//!
//! The grid digests were computed with Python's `hmac` and `hashlib`
//! (an independent implementation) and matched the outputs of the
//! `hmac` / `hkdf` crates that backed crypt-io up to 1.2.1, so they pin
//! the in-crate implementation of 1.2.2 to byte-identical output.

#![cfg(all(feature = "mac-hmac", feature = "kdf-hkdf"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crypt_io::{Error, hash, kdf, mac};

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

/// Deterministic test bytes: `(i * mul + add) mod 256`.
fn pat(len: usize, mul: usize, add: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * mul + add) & 0xff) as u8).collect()
}

/// One RFC 4231 case: key, data, HMAC-SHA256, HMAC-SHA512.
struct Rfc4231 {
    key: Vec<u8>,
    data: Vec<u8>,
    sha256: &'static str,
    sha512: &'static str,
}

fn rfc4231_cases() -> Vec<Rfc4231> {
    vec![
        Rfc4231 {
            key: vec![0x0b; 20],
            data: b"Hi There".to_vec(),
            sha256: "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            sha512: "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde\
                     daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
        },
        Rfc4231 {
            key: b"Jefe".to_vec(),
            data: b"what do ya want for nothing?".to_vec(),
            sha256: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            sha512: "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
                     9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
        },
        Rfc4231 {
            key: vec![0xaa; 20],
            data: vec![0xdd; 50],
            sha256: "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            sha512: "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39\
                     bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
        },
        Rfc4231 {
            key: h("0102030405060708090a0b0c0d0e0f10111213141516171819"),
            data: vec![0xcd; 50],
            sha256: "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
            sha512: "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db\
                     a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
        },
        // Case 5 (truncated output) is covered by the full tags here;
        // crypt-io never truncates.
        Rfc4231 {
            key: vec![0xaa; 131],
            data: b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
            sha256: "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            sha512: "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352\
                     6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
        },
        Rfc4231 {
            key: vec![0xaa; 131],
            data: b"This is a test using a larger than block-size key and a larger than \
                    block-size data. The key needs to be hashed before being used by the \
                    HMAC algorithm."
                .to_vec(),
            sha256: "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
            sha512: "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944\
                     b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
        },
    ]
}

#[test]
#[allow(deprecated)]
fn rfc4231_all_cases() {
    for (i, case) in rfc4231_cases().iter().enumerate() {
        let want256 = h(case.sha256);
        let want512 = h(case.sha512);
        assert_eq!(
            mac::hmac_sha256(&case.key, &case.data).unwrap().to_vec(),
            want256,
            "HMAC-SHA256 case {i}"
        );
        assert_eq!(
            mac::hmac_sha512(&case.key, &case.data).unwrap().to_vec(),
            want512,
            "HMAC-SHA512 case {i}"
        );
        mac::hmac_sha256_check(&case.key, &case.data, &want256).unwrap();
        mac::hmac_sha512_check(&case.key, &case.data, &want512).unwrap();
        assert!(mac::hmac_sha256_verify(&case.key, &case.data, &want256).unwrap());
        assert!(mac::hmac_sha512_verify(&case.key, &case.data, &want512).unwrap());

        // Streaming, one byte at a time.
        let mut m = mac::HmacSha256::new(&case.key).unwrap();
        for b in &case.data {
            m.update(core::slice::from_ref(b));
        }
        assert!(m.clone().verify(&want256));
        m.check(&want256).unwrap();
        let mut m = mac::HmacSha512::new(&case.key).unwrap();
        for b in &case.data {
            m.update(core::slice::from_ref(b));
        }
        assert_eq!(m.finalize().to_vec(), want512);
    }
}

#[test]
fn tag_comparison_rejects_every_wrong_tag_shape() {
    let tag = mac::hmac_sha256(b"k", b"d").unwrap();
    for len in [0, 1, 16, 31, 33, 64] {
        let mut wrong = tag.to_vec();
        wrong.resize(len, 0);
        if len == 32 {
            continue;
        }
        assert_eq!(
            mac::hmac_sha256_check(b"k", b"d", &wrong),
            Err(Error::AuthenticationFailed),
            "length {len}"
        );
    }
    // Each single-bit flip, in every position, is rejected.
    for byte in 0..tag.len() {
        for bit in 0..8 {
            let mut wrong = tag;
            wrong[byte] ^= 1 << bit;
            assert_eq!(
                mac::hmac_sha256_check(b"k", b"d", &wrong),
                Err(Error::AuthenticationFailed)
            );
        }
    }
    let tag = mac::hmac_sha512(b"k", b"d").unwrap();
    let mut wrong = tag;
    wrong[63] ^= 0x80;
    assert_eq!(
        mac::hmac_sha512_check(b"k", b"d", &wrong),
        Err(Error::AuthenticationFailed)
    );
    assert_eq!(
        mac::hmac_sha512_check(b"k", b"d", &tag[..32]),
        Err(Error::AuthenticationFailed)
    );
}

/// One RFC 5869 case.
struct Rfc5869 {
    ikm: Vec<u8>,
    salt: Option<Vec<u8>>,
    info: Vec<u8>,
    okm: &'static str,
}

/// RFC 5869 test cases 1 to 3 (the SHA-256 ones; 4 to 7 are SHA-1).
#[test]
fn rfc5869_sha256_cases() {
    let cases = [
        Rfc5869 {
            ikm: vec![0x0b; 22],
            salt: Some(h("000102030405060708090a0b0c")),
            info: h("f0f1f2f3f4f5f6f7f8f9"),
            okm: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865",
        },
        Rfc5869 {
            ikm: pat(80, 1, 0),
            salt: Some(pat(80, 1, 0x60)),
            info: pat(80, 1, 0xb0),
            okm: "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
             59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
             cc30c58179ec3e87c14c01d5c1f3434f1d87",
        },
        Rfc5869 {
            ikm: vec![0x0b; 22],
            salt: None,
            info: Vec::new(),
            okm: "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8",
        },
    ];
    for (i, case) in cases.iter().enumerate() {
        let want = h(case.okm);
        let salt = case.salt.as_deref();
        let got = kdf::hkdf_sha256(&case.ikm, salt, &case.info, want.len()).unwrap();
        assert_eq!(got, want, "RFC 5869 case {}", i + 1);
        let mut into = vec![0xa5; want.len()];
        kdf::hkdf_sha256_into(&case.ikm, salt, &case.info, &mut into).unwrap();
        assert_eq!(into, want);
    }
    // An absent salt is a HashLen string of zeros (RFC 5869 §2.2).
    let ikm = [0x0bu8; 22];
    let none = kdf::hkdf_sha256(&ikm, None, b"x", 42).unwrap();
    assert_eq!(none, kdf::hkdf_sha256(&ikm, Some(&[]), b"x", 42).unwrap());
    assert_eq!(
        none,
        kdf::hkdf_sha256(&ikm, Some(&[0u8; 32]), b"x", 42).unwrap()
    );
}

/// HKDF-SHA512 with the RFC 5869 case 1 inputs (RFC 5869 has no
/// SHA-512 vectors; computed with Python `hmac` + `hashlib`).
#[test]
fn hkdf_sha512_case1_inputs() {
    let got = kdf::hkdf_sha512(
        &[0x0b; 22],
        Some(&h("000102030405060708090a0b0c")),
        &h("f0f1f2f3f4f5f6f7f8f9"),
        64,
    )
    .unwrap();
    assert_eq!(
        got,
        h(
            "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c14815793\
           38da362cb8d9f925d7cbcce0dff7098769cf15959867d571c1715450cb530137"
        )
    );
    let none = kdf::hkdf_sha512(&[1; 16], None, b"x", 80).unwrap();
    assert_eq!(
        none,
        kdf::hkdf_sha512(&[1; 16], Some(&[0u8; 64]), b"x", 80).unwrap()
    );
}

const GRID_DATA_LENS: [usize; 13] = [0, 1, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 200];

#[test]
#[cfg_attr(miri, ignore = "thousands of MACs are slow under Miri")]
fn hmac_grid_matches_reference() {
    let mut acc256 = Vec::new();
    let mut acc512 = Vec::new();
    for key_len in 0..=260 {
        let key = pat(key_len, 13, 1);
        for &data_len in &GRID_DATA_LENS {
            let data = pat(data_len, 7, 3);
            acc256.extend_from_slice(&mac::hmac_sha256(&key, &data).unwrap());
            acc512.extend_from_slice(&mac::hmac_sha512(&key, &data).unwrap());
        }
    }
    assert_eq!(
        hex::encode(hash::sha256(&acc256)),
        "a93698960a73ba5e9deb654e779c8c64e8196340f42749927ed3ae0f0c64193f"
    );
    assert_eq!(
        hex::encode(hash::sha256(&acc512)),
        "07f1c1331e63c4347280f73abf483e43e07d1a1dd29779b4fc36c6f1210e45fe"
    );
}

#[test]
#[cfg_attr(miri, ignore = "megabytes of HKDF output are slow under Miri")]
fn hkdf_grid_matches_reference() {
    type Hkdf = fn(&[u8], Option<&[u8]>, &[u8], usize) -> crypt_io::Result<Vec<u8>>;
    let runs: [(Hkdf, usize, &str); 2] = [
        (
            kdf::hkdf_sha256,
            kdf::HKDF_MAX_OUTPUT_SHA256,
            "3fa57855294f733450e55d87530770f1cf3ea4bbfa8232feb97d1e92a0e2233f",
        ),
        (
            kdf::hkdf_sha512,
            kdf::HKDF_MAX_OUTPUT_SHA512,
            "3b8603d5b3c929c9ed062f7b5fc549f8dd28b0233f15ae0adcdc6e4c83453cb4",
        ),
    ];
    for (derive, max, want) in runs {
        let mut acc = Vec::new();
        for ikm_len in [0, 1, 22, 32, 64, 80, 129] {
            let ikm = pat(ikm_len, 11, 2);
            for salt_len in [None, Some(0), Some(13), Some(200)] {
                let salt = salt_len.map(|n| pat(n, 5, 9));
                for info_len in [0, 10, 300] {
                    let info = pat(info_len, 3, 17);
                    for out_len in [0, 1, 31, 32, 33, 63, 64, 65, 100, max] {
                        let okm = derive(&ikm, salt.as_deref(), &info, out_len).unwrap();
                        assert_eq!(okm.len(), out_len);
                        acc.extend_from_slice(&okm);
                    }
                }
            }
        }
        assert_eq!(hex::encode(hash::sha256(&acc)), want, "max {max}");
    }
}
