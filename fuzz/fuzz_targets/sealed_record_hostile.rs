//! Exercises strict record decoding with bounded attacker-controlled bytes.

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

use crypt_io::storage::RecordCodec;
use crypt_io_fuzz::{FuzzKeyProvider, fuzz_scope, record_hostile_context};
use libfuzzer_sys::fuzz_target;

const MAX_HOSTILE_INPUT_LEN: usize = 512 * 1024;

fuzz_target!(|data: &[u8]| {
    let bounded = &data[..data.len().min(MAX_HOSTILE_INPUT_LEN)];
    let codec = RecordCodec::new(FuzzKeyProvider);

    match codec.open(&fuzz_scope(), &record_hostile_context(), bounded) {
        Ok(plaintext) => drop(plaintext),
        Err(_expected_for_hostile_input) => {}
    }
});
