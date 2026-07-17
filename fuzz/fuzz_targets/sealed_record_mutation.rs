//! Proves that one-bit record mutations cannot authenticate or return plaintext.

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

use std::process;

use crypt_io::storage::RecordCodec;
use crypt_io_fuzz::{
    FuzzKeyProvider, MAX_RECORD_MUTATION_PLAINTEXT_LEN, fuzz_scope, mutation_parts,
    record_mutation_context,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((mutation_selector, bit, plaintext)) =
        mutation_parts(data, 0, MAX_RECORD_MUTATION_PLAINTEXT_LEN)
    else {
        return;
    };

    let codec = RecordCodec::new(FuzzKeyProvider);
    let scope = fuzz_scope();
    let context = record_mutation_context();
    let sealed = match codec.seal(&scope, &context, plaintext) {
        Ok(record) => record,
        Err(_unexpected_fixture_failure) => process::abort(),
    };
    let opened = match codec.open(&scope, &context, sealed.as_bytes()) {
        Ok(value) => value,
        Err(_unexpected_round_trip_failure) => process::abort(),
    };
    if opened.as_slice() != plaintext {
        process::abort();
    }
    drop(opened);

    let mut tampered = sealed.into_bytes();
    if tampered.is_empty() {
        process::abort();
    }
    let mutation_index = mutation_selector % tampered.len();
    tampered[mutation_index] ^= 1_u8 << bit;
    if codec.open(&scope, &context, &tampered).is_ok() {
        process::abort();
    }
});
