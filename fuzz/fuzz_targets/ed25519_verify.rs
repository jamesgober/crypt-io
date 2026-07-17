//! Exercises strict Ed25519 decoding and verification with hostile bytes.

#![no_main]
#![deny(warnings)]
#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(unused_must_use)]
#![deny(unused_results)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::print_stdout)]
#![deny(clippy::print_stderr)]
#![deny(clippy::dbg_macro)]
#![deny(clippy::unreachable)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(clippy::missing_safety_doc)]

use crypt_io::signature::{
    Ed25519PublicKey, Ed25519Signature, verify_ed25519_detached,
};
use libfuzzer_sys::fuzz_target;

const FIXED_INPUT_LEN: usize = 32 + 64;
const MAX_MESSAGE_LEN: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() < FIXED_INPUT_LEN {
        return;
    }

    let public_key_bytes = &data[..32];
    let signature_bytes = &data[32..FIXED_INPUT_LEN];
    let message_end = data.len().min(FIXED_INPUT_LEN + MAX_MESSAGE_LEN);
    let exact_message = &data[FIXED_INPUT_LEN..message_end];
    let Ok(public_key) = Ed25519PublicKey::try_from_slice(public_key_bytes) else {
        return;
    };
    let Ok(signature) = Ed25519Signature::try_from_slice(signature_bytes) else {
        return;
    };

    match verify_ed25519_detached(&public_key, exact_message, &signature) {
        Ok(()) | Err(_) => {}
    }
});
