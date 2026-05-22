//! Argon2id backend (RFC 9106).
//!
//! Argon2id is the modern password-hashing standard — memory-hard,
//! tuneable for time / memory / parallelism cost, and resistant to
//! GPU / FPGA brute-force at sensible parameters. It is the right
//! tool for hashing *passwords* (low-entropy inputs); for high-entropy
//! material use [`crate::kdf::hkdf_sha256`] instead.
//!
//! The wrapper:
//!
//! - Generates a fresh salt via `mod_rand::tier3::fill_bytes` (OS
//!   CSPRNG) on every [`argon2_hash`] call. The salt is encoded into
//!   the returned PHC string; callers do not need to manage it.
//! - Returns the standard PHC-encoded hash string
//!   (`$argon2id$v=19$m=...,t=...,p=...$salt$hash`) which is
//!   self-describing and accepted by every Argon2 implementation in
//!   the ecosystem.
//! - Defaults to the OWASP-recommended parameter set for sensitive
//!   web-facing password hashing (~100 ms on a modern CPU).
//!
//! [PHC string format]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md

use alloc::string::{String, ToString};

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};

use crate::error::{Error, Result};

/// Default Argon2id output length, in bytes. Equal to `32` (256 bits).
pub const ARGON2_DEFAULT_OUTPUT_LEN: usize = 32;

/// Default Argon2id salt length, in bytes. Equal to `16` (128 bits, the
/// PHC-recommended minimum).
pub const ARGON2_DEFAULT_SALT_LEN: usize = 16;

/// Tuneable Argon2id parameters.
///
/// Construct via [`Argon2Params::default`] (OWASP-recommended, ~100 ms
/// on a modern CPU) or via [`Argon2Params::new`] for custom values.
///
/// - `m_cost`: memory cost in kibibytes (1 unit = 1024 bytes).
/// - `t_cost`: number of iterations (time cost).
/// - `p_cost`: parallelism / lanes.
/// - `output_len`: derived-key length in bytes; defaults to 32.
///
/// Reducing any parameter reduces resistance to brute-force; the
/// defaults are tuned for "human authentication" (login flows). For
/// machine-to-machine credentials a higher memory/time cost is
/// appropriate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    /// Memory cost in kibibytes.
    pub m_cost: u32,
    /// Time cost (iterations).
    pub t_cost: u32,
    /// Parallelism (number of lanes).
    pub p_cost: u32,
    /// Derived-key length in bytes.
    pub output_len: usize,
}

impl Argon2Params {
    /// Construct a custom parameter set.
    #[must_use]
    pub const fn new(m_cost: u32, t_cost: u32, p_cost: u32, output_len: usize) -> Self {
        Self {
            m_cost,
            t_cost,
            p_cost,
            output_len,
        }
    }
}

impl Default for Argon2Params {
    /// OWASP-recommended defaults for sensitive web-facing password
    /// hashing: 19 MiB memory, 2 iterations, 1 lane, 32-byte output.
    /// Yields roughly 100 ms per hash on a modern CPU.
    fn default() -> Self {
        Self {
            m_cost: 19 * 1024,
            t_cost: 2,
            p_cost: 1,
            output_len: ARGON2_DEFAULT_OUTPUT_LEN,
        }
    }
}

/// Hash `password` with Argon2id using the default parameter set and a
/// fresh random salt. Returns the PHC-encoded hash string.
///
/// The salt is generated via `mod_rand::tier3::fill_bytes` (OS CSPRNG)
/// and embedded in the returned string, so callers do not need to
/// manage salt storage separately.
///
/// # Errors
///
/// Returns [`Error::RandomFailure`] if the OS RNG cannot produce a
/// salt, or [`Error::Kdf`] if the Argon2 implementation rejects the
/// (default) parameters or fails to hash.
///
/// # Example
///
/// ```no_run
/// # #[cfg(feature = "kdf-argon2")] {
/// use crypt_io::kdf;
/// let phc = kdf::argon2_hash(b"correct horse battery staple")?;
/// assert!(phc.starts_with("$argon2id$"));
/// # }
/// # Ok::<(), crypt_io::Error>(())
/// ```
pub fn argon2_hash(password: &[u8]) -> Result<String> {
    argon2_hash_with_params(password, Argon2Params::default())
}

/// Like [`argon2_hash`] but uses caller-supplied parameters.
///
/// # Errors
///
/// Same as [`argon2_hash`].
pub fn argon2_hash_with_params(password: &[u8], params: Argon2Params) -> Result<String> {
    let mut salt_bytes = [0u8; ARGON2_DEFAULT_SALT_LEN];
    mod_rand::tier3::fill_bytes(&mut salt_bytes)
        .map_err(|_| Error::RandomFailure("mod_rand::tier3::fill_bytes"))?;

    let salt =
        SaltString::encode_b64(&salt_bytes).map_err(|_| Error::Kdf("argon2 salt encoding"))?;

    let argon2_params = Params::new(
        params.m_cost,
        params.t_cost,
        params.p_cost,
        Some(params.output_len),
    )
    .map_err(|_| Error::Kdf("argon2 invalid params"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let hash = argon2
        .hash_password(password, &salt)
        .map_err(|_| Error::Kdf("argon2 hash"))?;
    Ok(hash.to_string())
}

/// Verify `password` against a PHC-encoded Argon2 hash string.
///
/// Returns `Ok(true)` if the password matches, `Ok(false)` if it does
/// not, and [`Error::Kdf`] if `phc` is not a parseable Argon2 PHC
/// string.
///
/// Argon2id's verification re-derives the hash under the encoded
/// parameters and compares in constant time. The cost is the same as
/// computing a fresh hash with those parameters — usually ~100 ms with
/// the default params.
///
/// # Errors
///
/// Returns [`Error::Kdf`] only when `phc` fails to parse as a valid
/// PHC string. A correctly-formatted but wrong-password hash returns
/// `Ok(false)`.
///
/// # Example
///
/// ```no_run
/// # #[cfg(feature = "kdf-argon2")] {
/// use crypt_io::kdf;
/// let phc = kdf::argon2_hash(b"hunter2")?;
/// assert!(kdf::argon2_verify(&phc, b"hunter2")?);
/// assert!(!kdf::argon2_verify(&phc, b"hunter3")?);
/// # }
/// # Ok::<(), crypt_io::Error>(())
/// ```
pub fn argon2_verify(phc: &str, password: &[u8]) -> Result<bool> {
    let parsed = PasswordHash::new(phc).map_err(|_| Error::Kdf("argon2 phc parse"))?;
    let argon2 = Argon2::default();
    Ok(argon2.verify_password(password, &parsed).is_ok())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, unused_results)]
mod tests {
    use super::*;
    use alloc::format;

    // Reduced parameters for tests so we don't burn 100 ms per case.
    // The functional contract (round-trip, wrong-password rejection,
    // tampered-hash rejection, parse-failure surfacing) is identical;
    // only the runtime cost changes.
    fn fast_params() -> Argon2Params {
        Argon2Params {
            m_cost: 8,
            t_cost: 1,
            p_cost: 1,
            output_len: 32,
        }
    }

    #[test]
    fn hash_then_verify_round_trip() {
        let phc = argon2_hash_with_params(b"hunter2", fast_params()).unwrap();
        assert!(phc.starts_with("$argon2id$"));
        assert!(argon2_verify(&phc, b"hunter2").unwrap());
    }

    #[test]
    fn verify_rejects_wrong_password() {
        let phc = argon2_hash_with_params(b"correct", fast_params()).unwrap();
        assert!(!argon2_verify(&phc, b"wrong").unwrap());
    }

    #[test]
    fn two_hashes_of_same_password_differ() {
        // Different salts → different PHC strings, even for identical
        // password + params. Verifies salt randomisation is wired up.
        let p = fast_params();
        let a = argon2_hash_with_params(b"same", p).unwrap();
        let b = argon2_hash_with_params(b"same", p).unwrap();
        assert_ne!(a, b);
        assert!(argon2_verify(&a, b"same").unwrap());
        assert!(argon2_verify(&b, b"same").unwrap());
    }

    #[test]
    fn verify_rejects_unparseable_phc() {
        let err = argon2_verify("not-a-valid-phc-string", b"password").unwrap_err();
        assert!(matches!(err, Error::Kdf(_)), "{err:?}");
    }

    #[test]
    fn verify_rejects_tampered_phc() {
        let phc = argon2_hash_with_params(b"hunter2", fast_params()).unwrap();
        // Tamper a character in the **middle of the salt** portion.
        // The salt sits between the second-to-last and the last '$'.
        // A mid-base64 char is always a full-6-bit character — any
        // letter swap stays in the alphabet and keeps the structure
        // valid. We avoid the end of the hash portion: its trailing
        // char encodes fractional bits and strict base64 decoders
        // (e.g. `base64ct`) reject letters that introduce non-zero
        // padding bits.
        let last_dollar = phc.rfind('$').expect("PHC has final $");
        let phc_prefix = &phc[..last_dollar];
        let salt_start = phc_prefix.rfind('$').expect("PHC has salt-leading $") + 1;
        let salt_middle = salt_start + (last_dollar - salt_start) / 2;
        let mut bytes = phc.into_bytes();
        let original = bytes[salt_middle];
        bytes[salt_middle] = if original == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(bytes).expect("still valid utf-8");
        // Tampered salt → different derived hash → Ok(false), and
        // crucially NOT a parse error. This is the contract we want
        // to lock in: structurally-valid PHCs with the wrong hash
        // return Ok(false), not Err(Kdf).
        assert!(!argon2_verify(&tampered, b"hunter2").unwrap());
    }

    #[test]
    fn empty_password_round_trips() {
        // Edge case: empty password should hash and verify cleanly.
        let phc = argon2_hash_with_params(b"", fast_params()).unwrap();
        assert!(argon2_verify(&phc, b"").unwrap());
        assert!(!argon2_verify(&phc, b"not-empty").unwrap());
    }

    #[test]
    fn long_password_round_trips() {
        let password = [b'x'; 1024];
        let phc = argon2_hash_with_params(&password, fast_params()).unwrap();
        assert!(argon2_verify(&phc, &password).unwrap());
    }

    #[test]
    fn custom_params_are_honoured() {
        // Encode params into the PHC string and check they round-trip.
        let params = Argon2Params::new(16, 2, 1, 32);
        let phc = argon2_hash_with_params(b"pw", params).unwrap();
        // PHC encodes as `$argon2id$v=19$m=16,t=2,p=1$...$...`.
        assert!(phc.contains("m=16"));
        assert!(phc.contains("t=2"));
        assert!(phc.contains("p=1"));
    }

    #[test]
    fn default_params_use_owasp_recommendations() {
        let d = Argon2Params::default();
        assert_eq!(d.m_cost, 19 * 1024);
        assert_eq!(d.t_cost, 2);
        assert_eq!(d.p_cost, 1);
        assert_eq!(d.output_len, ARGON2_DEFAULT_OUTPUT_LEN);
    }

    #[test]
    fn invalid_params_rejected() {
        // m_cost too small (Argon2 requires m_cost >= 8 * p_cost).
        let bad = Argon2Params::new(0, 1, 1, 32);
        let err = argon2_hash_with_params(b"pw", bad).unwrap_err();
        assert!(matches!(err, Error::Kdf(_)), "{err:?}");
    }

    #[test]
    fn error_messages_redact_password() {
        // Defence-in-depth: ensure no Error variant rendering leaks a
        // password byte even when we go through the failure paths.
        let secret = "my-super-secret-password";
        let err = argon2_verify("not-a-phc", secret.as_bytes()).unwrap_err();
        let rendered = format!("{err}");
        assert!(!rendered.contains(secret));
        let rendered_dbg = format!("{err:?}");
        assert!(!rendered_dbg.contains(secret));
    }
}
