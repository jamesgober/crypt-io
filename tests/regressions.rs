//! Regression tests for the 1.0.1 security fixes.
//!
//! Each test reproduces a defect present in 1.0.0 and fails against
//! that release. Audit IDs are given per test.

#![cfg(all(
    feature = "stream",
    feature = "aead-chacha20",
    feature = "aead-aes-gcm"
))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crypt_io::stream::{HEADER_LEN, StreamDecryptor, StreamEncryptor};
use crypt_io::{Algorithm, Crypt, Error};

const ALGS: [Algorithm; 2] = [Algorithm::ChaCha20Poly1305, Algorithm::Aes256Gcm];

fn crypt(alg: Algorithm) -> Crypt {
    Crypt::with_algorithm(alg)
}

/// Read the first `n` bytes of `v`'s allocation, including bytes past
/// `len()`.
///
/// Only call this when those `n` bytes are known to have been written
/// at some point (they were initialised by an earlier, longer length).
fn allocation_prefix(v: &mut Vec<u8>, n: usize) -> Vec<u8> {
    let len = v.len();
    assert!(n <= v.capacity());
    let mut bytes = v[..len.min(n)].to_vec();
    for b in &v.spare_capacity_mut()[..n.saturating_sub(len)] {
        // SAFETY: every caller passes an `n` no larger than a length
        // `v` has previously had, so these bytes were initialised and
        // `Vec::clear`/`truncate` never de-initialise memory.
        bytes.push(unsafe { b.assume_init() });
    }
    bytes
}

// ---------------------------------------------------------------- CI-H3

/// 1.0.0 derived `Debug` and printed the raw key and buffered plaintext.
#[test]
fn stream_debug_does_not_print_key_nonce_prefix_or_plaintext() {
    let key: [u8; 32] = core::array::from_fn(|i| [0xde, 0xad, 0xbe, 0xef][i % 4]);
    for alg in ALGS {
        let (mut enc, header) = StreamEncryptor::new(&key, alg).unwrap();
        let _ = enc.update(b"TOP-SECRET-PLAINTEXT").unwrap();
        let dec = StreamDecryptor::new(&key, &header).unwrap();

        let prefix = format!("{:?}", &header[16..23]);
        let prefix = prefix.trim_matches(|c| c == '[' || c == ']');
        for rendered in [format!("{enc:?}"), format!("{enc:#?}"), format!("{dec:?}")] {
            assert!(
                !rendered.contains("222, 173, 190, 239"),
                "key bytes: {rendered}"
            );
            assert!(
                !rendered.contains("[84, 79, 80"),
                "plaintext bytes: {rendered}"
            );
            assert!(!rendered.contains(prefix), "nonce prefix: {rendered}");
            assert!(!rendered.contains("key"), "key field: {rendered}");
        }
        let rendered = format!("{enc:?}");
        assert!(rendered.starts_with("StreamEncryptor {"), "{rendered}");
        assert!(rendered.contains("buffered_len: 20"), "{rendered}");
    }
}

// ---------------------------------------------------------------- CI-M5

/// 1.0.0 returned `InvalidCiphertext` / `InvalidKey` *before* clearing
/// `out`, so the previous message's plaintext came back with the error.
#[test]
fn decrypt_into_never_returns_stale_plaintext() {
    let key = [3u8; 32];
    for alg in ALGS {
        let c = crypt(alg);
        let msg1 = c.encrypt(&key, b"PAY alice 10").unwrap();

        // Runt frame.
        let mut out = Vec::new();
        c.decrypt_into(&key, &msg1, &mut out).unwrap();
        assert_eq!(out, b"PAY alice 10");
        let err = c.decrypt_into(&key, &[0u8; 5], &mut out).unwrap_err();
        assert!(matches!(err, Error::InvalidCiphertext(_)), "{err:?}");
        assert_eq!(out, b"", "{alg:?}: stale plaintext after InvalidCiphertext");

        // Wrong key length.
        c.decrypt_into(&key, &msg1, &mut out).unwrap();
        let err = c.decrypt_into(&[0u8; 16], &msg1, &mut out).unwrap_err();
        assert!(matches!(err, Error::InvalidKey { .. }), "{err:?}");
        assert_eq!(out, b"", "{alg:?}: stale plaintext after InvalidKey");

        // Same through the AAD variant.
        c.decrypt_into(&key, &msg1, &mut out).unwrap();
        let err = c
            .decrypt_with_aad_into(&key, &[0u8; 27], b"aad", &mut out)
            .unwrap_err();
        assert!(matches!(err, Error::InvalidCiphertext(_)), "{err:?}");
        assert_eq!(out, b"");
    }
}

/// Encrypt-side counterpart: an error never leaves the previous
/// contents in `out`.
#[test]
fn encrypt_into_clears_out_on_error() {
    for alg in ALGS {
        let mut out = b"previous ciphertext".to_vec();
        let err = crypt(alg)
            .encrypt_into(&[0u8; 31], b"x", &mut out)
            .unwrap_err();
        assert!(matches!(err, Error::InvalidKey { .. }));
        assert_eq!(out, b"");
    }
}

// ---------------------------------------------------------------- CI-M1

/// 1.0.0 "scrubbed" with `Vec::clear()`, which only resets the length:
/// the bytes stayed in the caller's allocation. The whole allocation
/// must now be zero after an authentication failure.
#[test]
fn decrypt_into_wipes_allocation_on_auth_failure() {
    let key = [7u8; 32];
    let secret = b"wire $1,000,000 to account 12345678 -- must never be visible";
    for alg in ALGS {
        let c = crypt(alg);
        // Leave plaintext of a good message in the buffer first.
        let good = c.encrypt(&key, secret).unwrap();
        let mut out = Vec::with_capacity(256);
        c.decrypt_into(&key, &good, &mut out).unwrap();

        // Then a forged message (one tag bit flipped).
        let mut forged = c.encrypt(&key, secret).unwrap();
        *forged.last_mut().unwrap() ^= 1;
        let err = c.decrypt_into(&key, &forged, &mut out).unwrap_err();
        assert_eq!(err, Error::AuthenticationFailed);
        assert!(out.is_empty());

        let left = allocation_prefix(&mut out, secret.len());
        assert!(
            left.iter().all(|&b| b == 0),
            "{alg:?}: bytes left in the caller's allocation: {left:?}"
        );
    }
}

// ---------------------------------------------------------------- CI-M4

/// A whole multi-chunk body fed in one `update` call round-trips. (The
/// 1.0.0 quadratic cost of this call is covered deterministically by
/// `stream::decryptor::tests::update_never_buffers_more_than_one_frame`.)
#[test]
#[cfg_attr(miri, ignore = "1 MiB through two AEADs is too slow under Miri")]
fn single_update_of_many_chunks_round_trips() {
    let key = [1u8; 32];
    let pt: Vec<u8> = (0..(1u32 << 20) + 77).map(|i| (i % 249) as u8).collect();
    for alg in ALGS {
        let (mut enc, header) = StreamEncryptor::new_with_chunk_size(&key, alg, 10).unwrap();
        let mut wire = header.to_vec();
        enc.update_into(&pt, &mut wire).unwrap();
        enc.finalize_into(&mut wire).unwrap();

        let mut dec = StreamDecryptor::new(&key, &header).unwrap();
        let mut got = dec.update(&wire[HEADER_LEN..]).unwrap();
        got.extend(dec.finalize().unwrap());
        assert_eq!(got, pt, "{alg:?}");
    }
}

/// `update_into` used to leave plaintext from earlier chunks of the
/// same call in `out` when a later chunk failed. It must now leave
/// `out` exactly as it was on entry.
#[test]
fn update_into_restores_out_on_failure() {
    let key = [9u8; 32];
    for alg in ALGS {
        let (mut enc, header) = StreamEncryptor::new_with_chunk_size(&key, alg, 10).unwrap();
        let mut wire = header.to_vec();
        wire.extend(enc.update(&[0x41u8; 4096]).unwrap());
        wire.extend(enc.finalize().unwrap());
        // Corrupt the third chunk; chunks 0 and 1 are valid.
        let third = HEADER_LEN + 2 * (1024 + 16) + 5;
        wire[third] ^= 1;

        let mut dec = StreamDecryptor::new(&key, &wire[..HEADER_LEN]).unwrap();
        let mut out = b"caller data".to_vec();
        let err = dec.update_into(&wire[HEADER_LEN..], &mut out).unwrap_err();
        assert_eq!(err, Error::AuthenticationFailed);
        assert_eq!(out, b"caller data", "{alg:?}");

        // The same failure through `update` is still an error.
        let mut dec = StreamDecryptor::new(&key, &wire[..HEADER_LEN]).unwrap();
        assert_eq!(
            dec.update(&wire[HEADER_LEN..]).unwrap_err(),
            Error::AuthenticationFailed
        );
    }
}

/// Byte-at-a-time and whole-buffer feeding must agree with each other
/// across chunk boundaries for both decrypt entry points.
#[test]
fn update_and_update_into_agree_for_every_split() {
    let key = [5u8; 32];
    let pt: Vec<u8> = (0..3000u32).map(|i| (i * 7 % 256) as u8).collect();
    let (mut enc, header) =
        StreamEncryptor::new_with_chunk_size(&key, Algorithm::Aes256Gcm, 10).unwrap();
    let mut wire = header.to_vec();
    wire.extend(enc.update(&pt).unwrap());
    wire.extend(enc.finalize().unwrap());
    let body = &wire[HEADER_LEN..];

    for step in [1usize, 15, 16, 17, 1039, 1040, 1041, 2080, 2081, body.len()] {
        let mut dec = StreamDecryptor::new(&key, &header).unwrap();
        let mut a = Vec::new();
        for c in body.chunks(step) {
            a.extend(dec.update(c).unwrap());
        }
        a.extend(dec.finalize().unwrap());

        let mut dec = StreamDecryptor::new(&key, &header).unwrap();
        let mut b = Vec::new();
        for c in body.chunks(step) {
            dec.update_into(c, &mut b).unwrap();
        }
        dec.finalize_into(&mut b).unwrap();

        assert_eq!(a, pt, "update, step={step}");
        assert_eq!(b, pt, "update_into, step={step}");
    }
}

// ---------------------------------------------------------------- CI-M6

#[cfg(feature = "std")]
mod files {
    use std::fs;
    use std::path::PathBuf;

    use crypt_io::Algorithm;
    use crypt_io::stream::{decrypt_file, encrypt_file};

    fn scratch_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("crypt-io-regression-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn entries(dir: &std::path::Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    /// 1.0.0 wrote plaintext straight to the destination and left
    /// 64 KiB of it there after `Err(AuthenticationFailed)` on a
    /// truncated stream.
    #[test]
    #[cfg_attr(miri, ignore = "file I/O")]
    fn decrypt_file_leaves_no_plaintext_on_truncation() {
        let dir = scratch_dir("truncate");
        let key = [9u8; 32];
        let src = dir.join("ledger.csv");
        let mut data = String::new();
        for i in 0..20_000 {
            data.push_str(&i.to_string());
            data.push_str(",debit,100\n");
        }
        fs::write(&src, &data).unwrap();
        let enc = dir.join("ledger.enc");
        encrypt_file(&src, &enc, &key, Algorithm::ChaCha20Poly1305).unwrap();

        let mut ct = fs::read(&enc).unwrap();
        ct.truncate(24 + 2 * (65_536 + 16)); // drop everything after chunk 2
        fs::write(&enc, &ct).unwrap();

        let out = dir.join("ledger.dec.csv");
        let before = entries(&dir);
        assert!(decrypt_file(&enc, &out, &key).is_err());
        assert!(!out.exists(), "plaintext left at the destination");
        assert_eq!(entries(&dir), before, "temporary file left behind");

        // An existing destination is left untouched on failure.
        fs::write(&out, b"previous contents").unwrap();
        assert!(decrypt_file(&enc, &out, &key).is_err());
        assert_eq!(fs::read(&out).unwrap(), b"previous contents");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg_attr(miri, ignore = "file I/O")]
    fn decrypt_file_round_trip_replaces_destination() {
        let dir = scratch_dir("roundtrip");
        let key = [4u8; 32];
        let src = dir.join("in.bin");
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 253) as u8).collect();
        fs::write(&src, &data).unwrap();
        let enc = dir.join("in.enc");
        encrypt_file(&src, &enc, &key, Algorithm::Aes256Gcm).unwrap();

        let out = dir.join("out.bin");
        fs::write(&out, b"stale").unwrap();
        decrypt_file(&enc, &out, &key).unwrap();
        assert_eq!(fs::read(&out).unwrap(), data);
        assert_eq!(entries(&dir), ["in.bin", "in.enc", "out.bin"]);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&out).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "decrypted file mode {mode:o}");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    /// 1.0.0: `encrypt_file(p, p, ..)` truncated `p` before reading it
    /// and returned `Ok(())`; the data was gone.
    #[test]
    #[cfg_attr(miri, ignore = "file I/O")]
    fn same_input_and_output_is_rejected() {
        let dir = scratch_dir("inplace");
        let key = [9u8; 32];
        let p = dir.join("inplace.txt");
        let original = b"important data that must survive";
        fs::write(&p, original).unwrap();

        assert!(encrypt_file(&p, &p, &key, Algorithm::ChaCha20Poly1305).is_err());
        assert_eq!(fs::read(&p).unwrap(), original);

        // Through a different spelling of the same path.
        let dotted = dir.join(".").join("inplace.txt");
        assert!(encrypt_file(&p, &dotted, &key, Algorithm::ChaCha20Poly1305).is_err());
        assert_eq!(fs::read(&p).unwrap(), original);

        let enc = dir.join("inplace.enc");
        encrypt_file(&p, &enc, &key, Algorithm::ChaCha20Poly1305).unwrap();
        let before = fs::read(&enc).unwrap();
        assert!(decrypt_file(&enc, &enc, &key).is_err());
        assert_eq!(fs::read(&enc).unwrap(), before);

        let _ = fs::remove_dir_all(&dir);
    }
}
