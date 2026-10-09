//! Differential and property checks over the `_into` APIs and the
//! stream framing.
//!
//! Properties asserted:
//!  P1  decrypt(x) and decrypt_into(x) agree for arbitrary x (attacker bytes).
//!  P2  decrypt_into leaves `out` empty on any error (1.0.0 returned the
//!      previous plaintext on InvalidKey / InvalidCiphertext; see
//!      corpus/audit_into_diff/regression-ci-m5-stale-output).
//!  P3  encrypt -> (optional mutation / truncation) -> decrypt:
//!      unmodified => exact plaintext; modified => error (never Ok).
//!  P4  stream: update/finalize and update_into/finalize_into agree for
//!      arbitrary split points; tampering or truncation never yields Ok.
#![no_main]

use arbitrary::Arbitrary;
use crypt_io::stream::{HEADER_LEN, StreamDecryptor, StreamEncryptor};
use crypt_io::{Algorithm, Crypt};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    key: [u8; 32],
    use_aes: bool,
    raw: Vec<u8>,
    plaintext: Vec<u8>,
    aad: Vec<u8>,
    chunk_log2: u8,
    splits: Vec<u16>,
    mutate: Option<(u32, u8)>,
    truncate: Option<u16>,
    append: Vec<u8>,
}

fn alg(aes: bool) -> Algorithm {
    if aes { Algorithm::Aes256Gcm } else { Algorithm::ChaCha20Poly1305 }
}

fn feed(dec: &mut StreamDecryptor, body: &[u8], splits: &[u16], into: bool) -> Result<Vec<u8>, ()> {
    let mut out = Vec::new();
    let mut cur = 0usize;
    let mut i = 0usize;
    while cur < body.len() {
        let take = if i < splits.len() { (splits[i] as usize % 4096) + 1 } else { body.len() - cur };
        i += 1;
        let end = (cur + take).min(body.len());
        if into {
            dec.update_into(&body[cur..end], &mut out).map_err(|_| ())?;
        } else {
            out.extend(dec.update(&body[cur..end]).map_err(|_| ())?);
        }
        cur = end;
    }
    Ok(out)
}

fuzz_target!(|inp: Input| {
    let crypt = Crypt::with_algorithm(alg(inp.use_aes));

    // P1/P2 on attacker-controlled bytes.
    let a = crypt.decrypt_with_aad(&inp.key, &inp.raw, &inp.aad);
    let mut out = vec![0xA5u8; 7];
    let b = crypt.decrypt_with_aad_into(&inp.key, &inp.raw, &inp.aad, &mut out);
    assert_eq!(a.is_ok(), b.is_ok(), "P1 decrypt vs decrypt_into disagree");
    match a {
        Ok(pt) => assert_eq!(pt, out, "P1 plaintext mismatch"),
        Err(_) => assert!(out.is_empty(), "P2 out not cleared on error"),
    }

    // P3 single-shot round trip with optional modification.
    let mut ct = crypt.encrypt_with_aad(&inp.key, &inp.plaintext, &inp.aad).expect("encrypt");
    let original_ct = ct.clone();
    if let Some((pos, x)) = inp.mutate {
        if x != 0 && !ct.is_empty() {
            let p = pos as usize % ct.len();
            ct[p] ^= x;
        }
    }
    if let Some(t) = inp.truncate {
        let t = (t as usize) % (ct.len() + 1);
        if t > 0 {
            ct.truncate(ct.len() - t);
        }
    }
    if !inp.append.is_empty() {
        ct.extend_from_slice(&inp.append);
    }
    // Truncate + append can restore the original bytes.
    let modified = ct != original_ct;
    let r = crypt.decrypt_with_aad(&inp.key, &ct, &inp.aad);
    if modified {
        assert!(r.is_err(), "P3 modified single-shot ciphertext decrypted OK");
    } else {
        assert_eq!(r.expect("P3 roundtrip"), inp.plaintext);
    }

    // P4 stream.
    let log2 = 10 + (inp.chunk_log2 % 3); // 1..4 KiB chunks keep it fast
    let (mut enc, header) =
        StreamEncryptor::new_with_chunk_size(&inp.key, alg(inp.use_aes), log2).expect("stream enc");
    let mut wire = header.to_vec();
    // encrypt via update_into with splits
    let mut cur = 0usize;
    let mut i = 0usize;
    while cur < inp.plaintext.len() {
        let take = if i < inp.splits.len() { (inp.splits[i] as usize % 4096) + 1 } else { inp.plaintext.len() - cur };
        i += 1;
        let end = (cur + take).min(inp.plaintext.len());
        enc.update_into(&inp.plaintext[cur..end], &mut wire).expect("update_into");
        cur = end;
    }
    enc.finalize_into(&mut wire).expect("finalize_into");
    let original_wire = wire.clone();
    if let Some((pos, x)) = inp.mutate {
        if x != 0 {
            let p = pos as usize % wire.len();
            wire[p] ^= x;
        }
    }
    if let Some(t) = inp.truncate {
        let body_len = wire.len() - HEADER_LEN;
        let t = (t as usize) % (body_len + 1);
        if t > 0 {
            wire.truncate(wire.len() - t);
        }
    }
    if !inp.append.is_empty() {
        wire.extend_from_slice(&inp.append);
    }

    let modified = wire != original_wire;
    let run = |into: bool| -> Result<Vec<u8>, ()> {
        let mut dec = StreamDecryptor::new(&inp.key, &wire[..HEADER_LEN]).map_err(|_| ())?;
        let mut pt = feed(&mut dec, &wire[HEADER_LEN..], &inp.splits, into)?;
        if into {
            dec.finalize_into(&mut pt).map_err(|_| ())?;
        } else {
            pt.extend(dec.finalize().map_err(|_| ())?);
        }
        Ok(pt)
    };
    let r1 = run(false);
    let r2 = run(true);
    assert_eq!(r1.is_ok(), r2.is_ok(), "P4 update vs update_into disagree");
    if modified {
        assert!(r1.is_err(), "P4 tampered/truncated/extended stream decrypted OK");
    } else {
        assert_eq!(r1.expect("P4 roundtrip"), inp.plaintext);
        assert_eq!(r2.expect("P4 roundtrip into"), inp.plaintext);
    }
});
