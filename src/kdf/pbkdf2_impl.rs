//! PBKDF2 with HMAC-SHA256 (RFC 8018 §5.2).
//!
//! Built on crypt-io's own HMAC (`hmac_core`) and the `sha2`
//! compression function, so it adds no dependency and no C code.
//!
//! The iteration loop works on the raw SHA-256 state: the HMAC inner
//! and outer states for the password are computed once, and every
//! iteration is then exactly two compression calls on a pre-padded
//! block (a 32-byte message after the 64-byte key block always pads
//! the same way). That is the minimum work PBKDF2-HMAC-SHA256 allows.

use sha2::Digest;
use sha2::block_api::compress256;
use sha2::digest::Output;

use crate::error::{Error, Result};
use crate::hmac_core::Hmac;
use crate::wipe::wipe;

/// Highest total work [`pbkdf2_hmac_sha256`] accepts: the iteration
/// count times the number of 32-byte output blocks.
///
/// For the usual 32-byte output that is ten million iterations, about
/// 0.65 s on a Ryzen 9 9950X3D (measured: 600,000 in 38.9 ms) and 17
/// times OWASP's 2023 recommendation of 600,000. A 64-byte output
/// allows half as many iterations, and so on. Anything above is
/// rejected with [`Error::LimitExceeded`] before any work is done, so a
/// peer that chooses the count (a SCRAM server, a stored hash) cannot
/// make one call run for minutes, whatever the output length. (Before
/// 1.6.0 the cap applied per block, so a long output multiplied it.)
/// Apply your own, tighter policy on top.
pub const PBKDF2_MAX_ITERATIONS: u32 = 10_000_000;

/// Output length of one PBKDF2-HMAC-SHA256 block, and the usual key
/// length (SCRAM-SHA-256 uses exactly this).
pub const PBKDF2_SHA256_OUTPUT_LEN: usize = 32;

/// SHA-256 initial hash value (FIPS 180-4 §5.3.3).
const IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// Derive `out.len()` bytes from `password` and `salt` with
/// PBKDF2-HMAC-SHA256 (RFC 8018 §5.2), running `iterations` rounds.
///
/// This is the derivation SCRAM-SHA-256 (RFC 7677) calls `Hi()`, and
/// the one many stored password formats use. For new password storage
/// prefer Argon2id (`kdf::argon2_hash`, memory-hard); use PBKDF2 where
/// a protocol or format requires it.
///
/// `out` is usually 32 bytes ([`PBKDF2_SHA256_OUTPUT_LEN`]). Longer
/// outputs are allowed, but each further 32 bytes costs another full
/// `iterations` rounds.
///
/// With the `zeroize` feature the key-derived hash states and every
/// intermediate block are wiped with volatile writes before the
/// function returns. `out` itself is yours to wipe
/// ([`crate::wipe`]).
///
/// New in 1.3.0. Requires the `kdf-pbkdf2` feature.
///
/// # Errors
///
/// - [`Error::InvalidInput`] if `iterations` is 0 or `out` is empty.
/// - [`Error::LimitExceeded`] if `iterations` times the number of
///   32-byte blocks in `out` is above [`PBKDF2_MAX_ITERATIONS`], or
///   `out` is longer than RFC 8018 allows (`(2^32 - 1) * 32` bytes).
///
/// `out` is left untouched on error.
///
/// # Example
///
/// ```
/// use crypt_io::kdf;
///
/// // SCRAM-SHA-256: SaltedPassword := Hi(password, salt, i)
/// let mut salted = [0u8; kdf::PBKDF2_SHA256_OUTPUT_LEN];
/// kdf::pbkdf2_hmac_sha256(b"pencil", b"server salt", 4096, &mut salted)?;
/// # Ok::<(), crypt_io::Error>(())
/// ```
pub fn pbkdf2_hmac_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    out: &mut [u8],
) -> Result<()> {
    if iterations == 0 {
        return Err(Error::InvalidInput(
            "PBKDF2 iteration count must be at least 1",
        ));
    }
    if out.is_empty() {
        return Err(Error::InvalidInput("PBKDF2 output must not be empty"));
    }
    let Ok(blocks) = u32::try_from(out.len().div_ceil(PBKDF2_SHA256_OUTPUT_LEN)) else {
        return Err(Error::LimitExceeded(
            "PBKDF2 output longer than (2^32 - 1) blocks",
        ));
    };
    // Total work, not the per-block count: a long output must not
    // multiply the cap.
    if u64::from(iterations) * u64::from(blocks) > u64::from(PBKDF2_MAX_ITERATIONS) {
        return Err(Error::LimitExceeded(
            "PBKDF2 iterations times output blocks above PBKDF2_MAX_ITERATIONS",
        ));
    }

    let prf = Hmac::<sha2::Sha256, 64>::new(password);
    let mut state = KeyedStates::new(password);

    let mut u = Output::<sha2::Sha256>::default();
    let mut t = [0u32; 8];
    // The second compression block of each HMAC hash: a 32-byte
    // message, then padding for 64 + 32 = 96 bytes (768 bits).
    let mut block = [0u8; 64];
    block[32] = 0x80;
    block[62] = 0x03;

    let mut index: u32 = 0;
    for chunk in out.chunks_mut(PBKDF2_SHA256_OUTPUT_LEN) {
        index += 1;
        // U_1 = PRF(P, S || INT(i)).
        let mut first = prf.clone();
        first.update(salt);
        first.update(&index.to_be_bytes());
        first.finalize_into(&mut u);
        block[..32].copy_from_slice(&u);
        load_words(&mut t, &u);

        // U_j = PRF(P, U_{j-1}); T = U_1 ^ ... ^ U_c.
        for _ in 1..iterations {
            state.round(&mut block);
            for (acc, chunk) in t.iter_mut().zip(block[..32].chunks_exact(4)) {
                *acc ^= u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            }
        }

        let mut tb = [0u8; 32];
        store_words(&mut tb, &t);
        chunk.copy_from_slice(&tb[..chunk.len()]);
        wipe(&mut tb);
    }

    wipe(&mut u);
    wipe(&mut block);
    wipe_words(&mut t);
    state.wipe();
    Ok(())
}

/// The SHA-256 states after absorbing `K ^ ipad` and `K ^ opad`, plus a
/// scratch state for each round.
struct KeyedStates {
    inner: [u32; 8],
    outer: [u32; 8],
    scratch: [u32; 8],
}

impl KeyedStates {
    fn new(password: &[u8]) -> Self {
        let mut key = [0u8; 64];
        if password.len() > key.len() {
            let mut hashed = sha2::Sha256::digest(password);
            key[..hashed.len()].copy_from_slice(&hashed);
            wipe(&mut hashed);
        } else {
            key[..password.len()].copy_from_slice(password);
        }
        let mut pad = [0u8; 64];
        let mut inner = IV;
        for (p, k) in pad.iter_mut().zip(&key) {
            *p = k ^ 0x36;
        }
        compress256(&mut inner, &[pad]);
        let mut outer = IV;
        for (p, k) in pad.iter_mut().zip(&key) {
            *p = k ^ 0x5c;
        }
        compress256(&mut outer, &[pad]);
        wipe(&mut pad);
        wipe(&mut key);
        Self {
            inner,
            outer,
            scratch: [0; 8],
        }
    }

    /// One HMAC-SHA256 of the 32-byte message in `block[..32]`; the tag
    /// replaces it. The rest of `block` holds the fixed padding.
    #[inline]
    fn round(&mut self, block: &mut [u8; 64]) {
        self.scratch = self.inner;
        compress256(&mut self.scratch, core::slice::from_ref(block));
        store_words(&mut block[..32], &self.scratch);
        self.scratch = self.outer;
        compress256(&mut self.scratch, core::slice::from_ref(block));
        store_words(&mut block[..32], &self.scratch);
    }

    fn wipe(&mut self) {
        wipe_words(&mut self.inner);
        wipe_words(&mut self.outer);
        wipe_words(&mut self.scratch);
    }
}

// By reference: passing the state by value would leave another copy
// of key-derived words on the stack.
#[allow(clippy::trivially_copy_pass_by_ref)]
#[inline]
fn store_words(out: &mut [u8], words: &[u32; 8]) {
    for (chunk, w) in out.chunks_exact_mut(4).zip(words) {
        chunk.copy_from_slice(&w.to_be_bytes());
    }
}

#[inline]
fn load_words(words: &mut [u32; 8], bytes: &[u8]) {
    for (w, chunk) in words.iter_mut().zip(bytes.chunks_exact(4)) {
        *w = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
}

/// [`wipe`] for a SHA-256 state.
fn wipe_words(words: &mut [u32; 8]) {
    #[cfg(feature = "zeroize")]
    {
        zeroize::Zeroize::zeroize(words);
    }
    #[cfg(not(feature = "zeroize"))]
    {
        words.fill(0);
        let _ = core::hint::black_box(words);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn derive(password: &[u8], salt: &[u8], iterations: u32, len: usize) -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec![0u8; len];
        pbkdf2_hmac_sha256(password, salt, iterations, &mut out).unwrap();
        out
    }

    fn hex(s: &str) -> alloc::vec::Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // RFC 7914 §11 (the scrypt RFC's PBKDF2-HMAC-SHA256 vectors).
    #[test]
    fn rfc7914_vector_1() {
        assert_eq!(
            derive(b"passwd", b"salt", 1, 64),
            hex(
                "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc\
                 49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
            )
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn rfc7914_vector_2() {
        assert_eq!(
            derive(b"Password", b"NaCl", 80_000, 64),
            hex(
                "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56\
                 a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"
            )
        );
    }

    // The RFC 6070 inputs, run with SHA-256 instead of SHA-1.
    #[test]
    fn rfc6070_style_short_counts() {
        assert_eq!(
            derive(b"password", b"salt", 1, 32),
            hex("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
        );
        assert_eq!(
            derive(b"password", b"salt", 2, 32),
            hex("ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43")
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn rfc6070_style_4096() {
        assert_eq!(
            derive(b"password", b"salt", 4096, 32),
            hex("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a")
        );
        assert_eq!(
            derive(
                b"passwordPASSWORDpassword",
                b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
                4096,
                40
            ),
            hex("348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9")
        );
        assert_eq!(
            derive(b"pass\0word", b"sa\0lt", 4096, 16),
            hex("89b69d0516f829893c696226650a8687")
        );
    }

    #[test]
    fn rejects_bad_parameters_and_leaves_out_untouched() {
        let mut out = [7u8; 32];
        assert_eq!(
            pbkdf2_hmac_sha256(b"p", b"s", 0, &mut out),
            Err(Error::InvalidInput(
                "PBKDF2 iteration count must be at least 1"
            ))
        );
        assert!(matches!(
            pbkdf2_hmac_sha256(b"p", b"s", PBKDF2_MAX_ITERATIONS + 1, &mut out),
            Err(Error::LimitExceeded(_))
        ));
        assert!(matches!(
            pbkdf2_hmac_sha256(b"p", b"s", u32::MAX, &mut out),
            Err(Error::LimitExceeded(_))
        ));
        assert_eq!(out, [7u8; 32]);
        assert!(matches!(
            pbkdf2_hmac_sha256(b"p", b"s", 1, &mut []),
            Err(Error::InvalidInput(_))
        ));
    }

    #[test]
    fn work_cap_counts_every_output_block() {
        // 1.6.0: the cap is iterations x blocks. Each of these would have
        // run for minutes under the old per-block cap; now refused before
        // any work.
        let mut two_blocks = [0u8; 64];
        assert!(matches!(
            pbkdf2_hmac_sha256(b"p", b"s", PBKDF2_MAX_ITERATIONS / 2 + 1, &mut two_blocks),
            Err(Error::LimitExceeded(_))
        ));
        let mut long = alloc::vec![0u8; 64 * 1024];
        assert!(matches!(
            pbkdf2_hmac_sha256(b"p", b"s", 10_000, &mut long),
            Err(Error::LimitExceeded(_))
        ));
        assert_eq!(two_blocks, [0u8; 64]);
        // Within the budget still works.
        assert!(pbkdf2_hmac_sha256(b"p", b"s", 3, &mut two_blocks).is_ok());
    }

    #[test]
    fn output_prefix_is_stable_across_lengths() {
        // Block i does not depend on the output length.
        let long = derive(b"key", b"salt", 3, 100);
        for len in [1, 31, 32, 33, 64, 65, 99] {
            assert_eq!(derive(b"key", b"salt", 3, len), long[..len]);
        }
    }

    #[test]
    fn long_password_is_hashed_first() {
        // RFC 2104: a key longer than the block equals its SHA-256.
        let long = [0x61u8; 65];
        let hashed = sha2::Sha256::digest(long);
        assert_eq!(
            derive(&long, b"salt", 2, 32),
            derive(&hashed, b"salt", 2, 32)
        );
        // A 64-byte key is used as is.
        assert_ne!(
            derive(&long[..64], b"salt", 2, 32),
            derive(&sha2::Sha256::digest(&long[..64]), b"salt", 2, 32)
        );
    }
}
