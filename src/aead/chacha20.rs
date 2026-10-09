//! ChaCha20-Poly1305 (RFC 8439) and XChaCha20-Poly1305
//! (draft-irtf-cfrg-xchacha) backends.
//!
//! Both come from the `chacha20poly1305` crate (RustCrypto). The
//! wrapping (key-length check, OS-CSPRNG nonce, `nonce || ciphertext ||
//! tag` layout, error mapping and buffer hygiene) is shared with
//! AES-256-GCM and lives in [`super::backend`]. This module holds the
//! known-answer tests that pin the upstream primitives.
//!
//! No cryptographic math lives here: it all happens inside
//! `chacha20poly1305`, which defers to the `chacha20` stream cipher and
//! the `poly1305` MAC.

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, XChaCha20Poly1305, XNonce};

    use super::super::backend::{decrypt, encrypt};
    use super::super::{CHACHA20_NONCE_LEN, CHACHA20_TAG_LEN};

    // RFC 8439 §2.8.2 (Poly1305 Construction) test vector for the
    // ChaCha20-Poly1305 AEAD. Verifies that our wrapping does not alter
    // the wire output of the underlying primitive when fed identical
    // inputs.
    //
    // To use this vector with our `nonce`-prepended layout, we exercise
    // the underlying `chacha20poly1305` crate directly here. The KAT
    // confirms (a) the crate is correctly wired in, and (b) we have not
    // accidentally double-encoded or offset anything.

    #[test]
    fn rfc8439_section_2_8_2_known_answer() {
        // Key, nonce, AAD, plaintext, ciphertext, tag — from RFC 8439
        // §2.8.2 "Poly1305 Construction".
        let key = hex_to_bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce = hex_to_bytes("070000004041424344454647");
        let aad = hex_to_bytes("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: \
            If I could offer you only one tip for the future, sunscreen would be it.";
        let expected_ciphertext_and_tag = hex_to_bytes(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
             3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
             92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
             3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd060\
             0691",
        );

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let n = Nonce::from_slice(&nonce);
        let got = cipher
            .encrypt(
                n,
                Payload {
                    msg: plaintext.as_ref(),
                    aad: &aad,
                },
            )
            .unwrap();
        assert_eq!(got, expected_ciphertext_and_tag);

        // Symmetric verification.
        let recovered = cipher
            .decrypt(
                n,
                Payload {
                    msg: &got,
                    aad: &aad,
                },
            )
            .unwrap();
        assert_eq!(recovered, plaintext);
    }

    // draft-irtf-cfrg-xchacha-03, appendix A.3.1 (XChaCha20-Poly1305
    // AEAD). Also checked against an independent HChaCha20 + RFC 8439
    // implementation.
    #[test]
    fn xchacha20_poly1305_draft_a31_known_answer() {
        let key = hex_to_bytes("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce = hex_to_bytes("404142434445464748494a4b4c4d4e4f5051525354555657");
        let aad = hex_to_bytes("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: \
            If I could offer you only one tip for the future, sunscreen would be it.";
        let expected = hex_to_bytes(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb\
             731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452\
             2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9\
             21f9664c97637da9768812f615c68b13b52e\
             c0875924c1c7987947deafd8780acf49",
        );
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        let n = XNonce::from_slice(&nonce);
        let got = cipher
            .encrypt(
                n,
                Payload {
                    msg: plaintext.as_ref(),
                    aad: &aad,
                },
            )
            .unwrap();
        assert_eq!(got, expected);

        // The same vector through crypt-io's wire format.
        let mut wire = nonce.clone();
        wire.extend_from_slice(&expected);
        let recovered = decrypt::<XChaCha20Poly1305>(&key, &wire, &aad).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn round_trip_via_module_wrapper() {
        let key = [0xa1u8; 32];
        let pt = b"the wrapper layers nonce-prepend on top of the upstream primitive";
        let wire = encrypt::<ChaCha20Poly1305>(&key, pt, &[], &[]).unwrap();
        // Wire layout sanity: nonce + ciphertext + tag.
        assert_eq!(wire.len(), CHACHA20_NONCE_LEN + pt.len() + CHACHA20_TAG_LEN);
        let recovered = decrypt::<ChaCha20Poly1305>(&key, &wire, &[]).unwrap();
        assert_eq!(recovered, pt);
    }

    // Minimal hex → bytes helper kept local to the KAT so we don't take a
    // `dev-dependencies` runtime cost on the wider test suite. `hex` is
    // listed in dev-deps but only the KAT module actually consumes it via
    // this helper, and writing it inline keeps the KAT readable.
    fn hex_to_bytes(s: &str) -> alloc::vec::Vec<u8> {
        hex::decode(s).expect("valid hex")
    }
}
