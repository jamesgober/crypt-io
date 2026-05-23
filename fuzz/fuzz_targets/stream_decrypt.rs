//! Fuzz `StreamDecryptor` with arbitrary header + body bytes plus
//! arbitrary chunk-boundary splits for the `update()` calls.
//!
//! This is the most interesting target after `aead_decrypt`: an
//! attacker controls the entire encrypted stream, can vary chunk
//! splits at every byte boundary, and the frame format has more
//! moving parts than the single-shot AEAD path (header parsing,
//! per-chunk counter, last_flag detection, buffering invariants).

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use crypt_io::stream::{StreamDecryptor, StreamEncryptor, HEADER_LEN};
use crypt_io::Algorithm;

#[derive(Arbitrary, Debug)]
struct Input {
    key: Vec<u8>,
    header: Vec<u8>,
    body: Vec<u8>,
    chunk_splits: Vec<u8>, // each byte is a split offset (mod body.len)
    // Also fuzz the round-trip side: encrypt arbitrary plaintext,
    // then feed the resulting wire back through the decryptor
    // with arbitrary chunk splits.
    plaintext_for_roundtrip: Vec<u8>,
    use_aes: bool,
}

fuzz_target!(|input: Input| {
    // ---- Attacker-controlled stream ----
    // Skip if header isn't even close to long enough — that's a
    // boring uninteresting input.
    if input.header.len() >= HEADER_LEN
        && let Ok(mut dec) = StreamDecryptor::new(&input.key, &input.header[..HEADER_LEN])
    {
        // Feed body in arbitrary chunks. Must not panic.
        let mut cursor = 0usize;
        for &split in &input.chunk_splits {
            if cursor >= input.body.len() {
                break;
            }
            let max = input.body.len() - cursor;
            let take = if max == 0 { 0 } else { (split as usize) % max + 1 };
            let end = (cursor + take).min(input.body.len());
            let _ = dec.update(&input.body[cursor..end]);
            cursor = end;
        }
        // Finalise. Either error or success — never panic.
        let _ = dec.finalize();
    }

    // ---- Round-trip with arbitrary chunk splits ----
    // Only valid 32-byte keys are interesting for the round-trip.
    if input.key.len() == 32 {
        let alg = if input.use_aes {
            Algorithm::Aes256Gcm
        } else {
            Algorithm::ChaCha20Poly1305
        };
        if let Ok((mut enc, header)) = StreamEncryptor::new(&input.key, alg) {
            let mut wire = header.to_vec();
            if let Ok(out) = enc.update(&input.plaintext_for_roundtrip) {
                wire.extend(out);
            }
            if let Ok(tail) = enc.finalize() {
                wire.extend(tail);
            }
            // Now decrypt with arbitrary chunk splits — must recover
            // the original plaintext.
            if let Ok(mut dec) = StreamDecryptor::new(&input.key, &wire[..HEADER_LEN]) {
                let body = &wire[HEADER_LEN..];
                let mut recovered = Vec::new();
                let mut cursor = 0usize;
                let mut failed = false;
                for &split in &input.chunk_splits {
                    if cursor >= body.len() {
                        break;
                    }
                    let max = body.len() - cursor;
                    let take = if max == 0 { 0 } else { (split as usize) % max + 1 };
                    let end = (cursor + take).min(body.len());
                    match dec.update(&body[cursor..end]) {
                        Ok(pt) => recovered.extend(pt),
                        Err(_) => {
                            failed = true;
                            break;
                        }
                    }
                    cursor = end;
                }
                // Feed remaining bytes if the splits ran out.
                if !failed && cursor < body.len() {
                    if let Ok(pt) = dec.update(&body[cursor..]) {
                        recovered.extend(pt);
                    } else {
                        failed = true;
                    }
                }
                if !failed {
                    if let Ok(tail) = dec.finalize() {
                        recovered.extend(tail);
                        assert_eq!(
                            recovered, input.plaintext_for_roundtrip,
                            "stream round-trip changed plaintext",
                        );
                    }
                }
            }
        }
    }
});
