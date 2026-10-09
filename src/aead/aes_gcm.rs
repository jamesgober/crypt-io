//! AES-256-GCM backend (NIST SP 800-38D).
//!
//! The cipher is `aes_gcm::Aes256Gcm` (`RustCrypto`). The wrapping is
//! shared with the ChaCha20 backends and lives in [`super::backend`];
//! the wire layout (`nonce || ciphertext || tag`, 12-byte nonce, 16-byte
//! tag) is identical to ChaCha20-Poly1305, so callers can switch
//! algorithms without changing how they store the buffer. This module
//! holds the known-answer tests that pin the upstream primitive.
//!
//! With the `zeroize` feature the AES round keys are wiped when the
//! cipher is dropped (`aes/zeroize`). The GHASH key inside
//! `polyval` 0.6 is not: its runtime-dispatch backend has no `Drop`
//! impl. See `docs/SECURITY.md`.
//!
//! # Hardware acceleration
//!
//! The `aes-gcm` crate dispatches to the platform's hardware AES path at
//! runtime when it detects support:
//!
//! - x86 / x86_64 with AES-NI + CLMUL — Intel & AMD CPUs since ~2010.
//! - aarch64 with the ARMv8 crypto extensions — modern Apple Silicon,
//!   AWS Graviton, recent mobile SoCs.
//!
//! On other targets it falls back to a constant-time software
//! implementation. The fallback is correct and side-channel-safe but
//! noticeably slower; if your deployment target is a CPU without AES
//! hardware (or you can't guarantee the binary won't be run on one),
//! prefer [`crate::Algorithm::ChaCha20Poly1305`].
//!
//! `aes-gcm` performs the feature detection itself; no `cfg` gates here.
//! See its [README](https://docs.rs/aes-gcm) for the per-target dispatch
//! table.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Key, Nonce};

    use super::super::backend::{decrypt, encrypt};
    use super::super::{AES_GCM_NONCE_LEN, AES_GCM_TAG_LEN};

    // NIST GCM test vectors. The canonical reference is "The Galois/Counter
    // Mode of Operation (GCM)" by McGrew & Viega (the source NIST SP
    // 800-38D adopted). Vectors below are the 256-bit-key entries from
    // that document.
    //
    // These confirm:
    //  (a) the upstream `aes-gcm` crate produces the spec-mandated bytes
    //      for known inputs, and
    //  (b) our wire-format prepend is byte-exact when we layer it on top.

    /// Test Case 14: K = 0^256, IV = 0^96, AAD = ∅, P = 0^128.
    /// Expected: C = `cea7403d4d606b6e074ec5d3baf39d18`,
    ///           T = `d0d1c8a799996bf0265b98b5d48ab919`.
    #[test]
    fn nist_test_case_14_known_answer() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let plaintext = [0u8; 16];
        let expected_ct = hex_to_bytes("cea7403d4d606b6e074ec5d3baf39d18");
        let expected_tag = hex_to_bytes("d0d1c8a799996bf0265b98b5d48ab919");

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        let n = Nonce::from_slice(&nonce);
        let got = cipher
            .encrypt(
                n,
                Payload {
                    msg: &plaintext,
                    aad: &[],
                },
            )
            .unwrap();
        // Output layout from the upstream crate is `ciphertext || tag`.
        let (got_ct, got_tag) = got.split_at(expected_ct.len());
        assert_eq!(got_ct, &expected_ct[..]);
        assert_eq!(got_tag, &expected_tag[..]);

        let recovered = cipher
            .decrypt(
                n,
                Payload {
                    msg: &got,
                    aad: &[],
                },
            )
            .unwrap();
        assert_eq!(recovered, plaintext);
    }

    /// Test Case 15: K = `feffe9928665731c6d6a8f9467308308 ...`,
    /// IV = `cafebabefacedbaddecaf888`, plaintext, AAD = ∅.
    /// The vector exercises the full GCM data path on a non-trivial key.
    #[test]
    fn nist_test_case_15_known_answer() {
        let key = hex_to_bytes("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        let nonce = hex_to_bytes("cafebabefacedbaddecaf888");
        let plaintext = hex_to_bytes(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        );
        let expected_ct = hex_to_bytes(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa\
             8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
        );
        let expected_tag = hex_to_bytes("b094dac5d93471bdec1a502270e3cc6c");

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        let n = Nonce::from_slice(&nonce);
        let got = cipher
            .encrypt(
                n,
                Payload {
                    msg: &plaintext,
                    aad: &[],
                },
            )
            .unwrap();
        let (got_ct, got_tag) = got.split_at(expected_ct.len());
        assert_eq!(got_ct, &expected_ct[..]);
        assert_eq!(got_tag, &expected_tag[..]);

        let recovered = cipher
            .decrypt(
                n,
                Payload {
                    msg: &got,
                    aad: &[],
                },
            )
            .unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn round_trip_via_module_wrapper() {
        let key = [0xb2u8; 32];
        let pt = b"the wrapper layers nonce-prepend on top of the upstream primitive";
        let wire = encrypt::<Aes256Gcm>(&key, pt, &[], &[]).unwrap();
        // Wire layout sanity: nonce + ciphertext + tag, identical to the
        // ChaCha20-Poly1305 backend.
        assert_eq!(wire.len(), AES_GCM_NONCE_LEN + pt.len() + AES_GCM_TAG_LEN);
        let recovered = decrypt::<Aes256Gcm>(&key, &wire, &[]).unwrap();
        assert_eq!(recovered, pt);
    }

    fn hex_to_bytes(s: &str) -> alloc::vec::Vec<u8> {
        hex::decode(s).expect("valid hex")
    }
}
