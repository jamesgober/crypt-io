//! Fuzz `sign::CosePublicKey::from_cose_key` (and `check`) with
//! arbitrary bytes: the WebAuthn credential-key parser takes input an
//! authenticator controls. It must either parse and check cleanly or
//! return an error. **Never panic.**

#![no_main]

use arbitrary::Arbitrary;
use crypt_io::sign::CosePublicKey;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    cose_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
}

fuzz_target!(|input: Input| {
    if let Ok(key) = CosePublicKey::from_cose_key(&input.cose_key) {
        let _ = key.algorithm();
        let _ = key.check(&input.message, &input.signature);
    }
});
