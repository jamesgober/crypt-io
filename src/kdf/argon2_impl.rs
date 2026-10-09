//! Argon2id backend (RFC 9106).
//!
//! Argon2id is the modern password-hashing standard — memory-hard,
//! tuneable for time / memory / parallelism cost, and resistant to
//! GPU / FPGA brute-force at sensible parameters. It is the right
//! tool for hashing *passwords* (low-entropy inputs); for high-entropy
//! material use HKDF (`kdf::hkdf_sha256`) instead.
//!
//! The wrapper:
//!
//! - Generates a fresh 16-byte salt from the OS CSPRNG on every
//!   [`argon2_hash`] call. The salt is encoded into the returned PHC
//!   string; callers do not need to manage it.
//! - Returns the standard PHC-encoded hash string
//!   (`$argon2id$v=19$m=...,t=...,p=...$salt$hash`) which is
//!   self-describing and accepted by every Argon2 implementation in
//!   the ecosystem.
//! - Defaults to the OWASP-recommended parameter set for sensitive
//!   web-facing password hashing (~100 ms on a modern CPU).
//! - Checks a PHC string's variant and cost parameters against an
//!   [`Argon2Policy`] before doing any work, so a hostile or corrupted
//!   hash cannot demand gigabytes of memory or minutes of CPU.
//!
//! [PHC string format]: https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md

#[cfg(any(feature = "std", feature = "getrandom"))]
use alloc::string::{String, ToString};

use argon2::password_hash::{PasswordHash, PasswordVerifier};
#[cfg(any(feature = "std", feature = "getrandom"))]
use argon2::password_hash::{PasswordHasher, SaltString};
use argon2::{ARGON2D_IDENT, ARGON2I_IDENT, ARGON2ID_IDENT, Argon2, Params};
#[cfg(any(feature = "std", feature = "getrandom"))]
use argon2::{Algorithm, Version};

use crate::error::{Error, Result};

/// Default Argon2id output length, in bytes. Equal to `32` (256 bits).
pub const ARGON2_DEFAULT_OUTPUT_LEN: usize = 32;

/// Default Argon2id salt length, in bytes. Equal to `16` (128 bits, the
/// PHC-recommended minimum).
pub const ARGON2_DEFAULT_SALT_LEN: usize = 16;

/// Default upper bound on `m_cost` (KiB): 1 GiB.
const MAX_M_COST_KIB: u32 = 1024 * 1024;

/// Default upper bound on `t_cost`.
const MAX_T_COST: u32 = 64;

/// Default upper bound on `p_cost`.
const MAX_P_COST: u32 = 16;

/// Which Argon2 PHC strings to accept, and which cost parameters to
/// allow, when verifying or hashing a password.
///
/// The cost parameters of a PHC string come from the string itself, so
/// a hostile or corrupted hash could otherwise demand gigabytes of
/// memory (`m`), minutes of CPU (`t`), or switch to a weaker variant.
/// [`argon2_check`] applies [`Argon2Policy::new`]; pass your own policy
/// to [`argon2_check_with_policy`] to change the limits, for example to
/// keep verifying hashes made before crypt-io 1.0.1 with costs above
/// the default caps, or to reject hashes weaker than your current
/// parameters.
///
/// | Setting            | Default (`new()`) |
/// |--------------------|-------------------|
/// | max `m_cost`       | 1,048,576 KiB (1 GiB) |
/// | max `t_cost`       | 64                |
/// | max `p_cost`       | 16                |
/// | min `m_cost`       | none              |
/// | min `t_cost`       | none              |
/// | `argon2i` allowed  | no                |
/// | `argon2d` allowed  | no                |
///
/// `argon2id` is always accepted. New in 1.1.0.
///
/// # Example
///
/// ```
/// # #[cfg(feature = "kdf-argon2")] {
/// use crypt_io::kdf::{self, Argon2Params, Argon2Policy};
///
/// // Accept the 2 GiB hashes an older deployment produced.
/// let policy = Argon2Policy::new().with_max_cost(2 * 1024 * 1024, 64, 16);
/// assert_eq!(policy.max_m_cost(), 2 * 1024 * 1024);
/// # let phc = kdf::argon2_hash_with_params(b"pw", Argon2Params::new(8, 1, 1, 32))?;
/// kdf::argon2_check_with_policy(&phc, b"pw", &policy)?;
/// # }
/// # Ok::<(), crypt_io::Error>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Policy {
    max_m_cost: u32,
    max_t_cost: u32,
    max_p_cost: u32,
    min_m_cost: u32,
    min_t_cost: u32,
    allow_argon2i: bool,
    allow_argon2d: bool,
}

impl Argon2Policy {
    /// The default policy: `argon2id` only, `m` up to 1 GiB, `t` up to
    /// 64, `p` up to 16, no minimums. These are the limits 1.0.1
    /// introduced.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_m_cost: MAX_M_COST_KIB,
            max_t_cost: MAX_T_COST,
            max_p_cost: MAX_P_COST,
            min_m_cost: 0,
            min_t_cost: 0,
            allow_argon2i: false,
            allow_argon2d: false,
        }
    }

    /// Set the upper bounds on memory cost (KiB), time cost and
    /// parallelism. Raising them lets hashes with higher costs verify,
    /// at the price of letting a hostile PHC string cost that much.
    #[must_use]
    pub const fn with_max_cost(mut self, m_cost: u32, t_cost: u32, p_cost: u32) -> Self {
        self.max_m_cost = m_cost;
        self.max_t_cost = t_cost;
        self.max_p_cost = p_cost;
        self
    }

    /// Set lower bounds on memory cost (KiB) and time cost. Hashes
    /// below them are rejected with [`Error::Kdf`], which stops an
    /// attacker who can write to your hash store from planting a cheap
    /// hash. Off by default so existing hashes keep verifying.
    #[must_use]
    pub const fn with_min_cost(mut self, m_cost: u32, t_cost: u32) -> Self {
        self.min_m_cost = m_cost;
        self.min_t_cost = t_cost;
        self
    }

    /// Also accept `$argon2i$` hashes (for migrating from systems that
    /// produced them).
    #[must_use]
    pub const fn allow_argon2i(mut self, allow: bool) -> Self {
        self.allow_argon2i = allow;
        self
    }

    /// Also accept `$argon2d$` hashes. Argon2d's memory access depends
    /// on the password, which leaks through cache timing; only enable
    /// this to migrate existing hashes.
    #[must_use]
    pub const fn allow_argon2d(mut self, allow: bool) -> Self {
        self.allow_argon2d = allow;
        self
    }

    /// Upper bound on memory cost, in KiB.
    #[must_use]
    pub const fn max_m_cost(&self) -> u32 {
        self.max_m_cost
    }

    /// Upper bound on time cost.
    #[must_use]
    pub const fn max_t_cost(&self) -> u32 {
        self.max_t_cost
    }

    /// Upper bound on parallelism.
    #[must_use]
    pub const fn max_p_cost(&self) -> u32 {
        self.max_p_cost
    }

    /// Lower bound on memory cost, in KiB (0 = none).
    #[must_use]
    pub const fn min_m_cost(&self) -> u32 {
        self.min_m_cost
    }

    /// Lower bound on time cost (0 = none).
    #[must_use]
    pub const fn min_t_cost(&self) -> u32 {
        self.min_t_cost
    }

    /// Whether `$argon2i$` hashes are accepted.
    #[must_use]
    pub const fn argon2i_allowed(&self) -> bool {
        self.allow_argon2i
    }

    /// Whether `$argon2d$` hashes are accepted.
    #[must_use]
    pub const fn argon2d_allowed(&self) -> bool {
        self.allow_argon2d
    }

    fn check_costs(self, m_cost: u32, t_cost: u32, p_cost: u32) -> Result<()> {
        if m_cost > self.max_m_cost || t_cost > self.max_t_cost || p_cost > self.max_p_cost {
            return Err(Error::Kdf("argon2 params exceed limits"));
        }
        if m_cost < self.min_m_cost || t_cost < self.min_t_cost {
            return Err(Error::Kdf("argon2 params below policy minimum"));
        }
        Ok(())
    }
}

impl Default for Argon2Policy {
    fn default() -> Self {
        Self::new()
    }
}

/// Tuneable Argon2id parameters.
///
/// Construct via [`Argon2Params::default`] (OWASP-recommended, ~100 ms
/// on a modern CPU) or via [`Argon2Params::new`] for custom values, and
/// call [`validate`](Self::validate) on custom values.
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
    /// Construct a custom parameter set. Nothing is checked here; call
    /// [`validate`](Self::validate) to check the values.
    #[must_use]
    pub const fn new(m_cost: u32, t_cost: u32, p_cost: u32, output_len: usize) -> Self {
        Self {
            m_cost,
            t_cost,
            p_cost,
            output_len,
        }
    }

    /// Check that these parameters are safe to use for password
    /// hashing. Returns `Ok(())` when all of these hold:
    ///
    /// - Argon2 accepts them (`p_cost` at least 1, `m_cost` at least
    ///   `8 * p_cost`, `t_cost` at least 1).
    /// - `output_len` is at least 16 bytes.
    /// - They meet one of the OWASP minimum configurations for Argon2id:
    ///   `m_cost` at least 47,104 KiB with `t_cost` 1, 19,456 KiB with
    ///   `t_cost` 2, 12,288 KiB with 3, 9,216 KiB with 4, or 7,168 KiB
    ///   with `t_cost` 5 or more.
    /// - They are within the default [`Argon2Policy`] caps, so the
    ///   resulting hash verifies with [`argon2_check`].
    ///
    /// [`argon2_hash_with_params`] does not call this, so that tests and
    /// existing callers with small parameters keep working; call it
    /// yourself when the values come from configuration. New in 1.1.0.
    ///
    /// # Errors
    ///
    /// [`Error::Kdf`] naming the first check that failed.
    ///
    /// # Example
    ///
    /// ```
    /// # #[cfg(feature = "kdf-argon2")] {
    /// use crypt_io::kdf::Argon2Params;
    /// assert!(Argon2Params::default().validate().is_ok());
    /// assert!(Argon2Params::new(8, 1, 1, 32).validate().is_err());
    /// # }
    /// ```
    pub fn validate(&self) -> Result<()> {
        let _ = Params::new(self.m_cost, self.t_cost, self.p_cost, Some(self.output_len))
            .map_err(|_| Error::Kdf("argon2 invalid params"))?;
        if self.output_len < 16 {
            return Err(Error::Kdf("argon2 output shorter than 16 bytes"));
        }
        // OWASP Password Storage Cheat Sheet, Argon2id minimums.
        let owasp = match self.t_cost {
            0 => false,
            1 => self.m_cost >= 47_104,
            2 => self.m_cost >= 19_456,
            3 => self.m_cost >= 12_288,
            4 => self.m_cost >= 9_216,
            _ => self.m_cost >= 7_168,
        };
        if !owasp {
            return Err(Error::Kdf("argon2 params below the OWASP minimum"));
        }
        Argon2Policy::new().check_costs(self.m_cost, self.t_cost, self.p_cost)
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
/// The salt comes from the OS CSPRNG and is embedded in the returned
/// string, so callers do not need to manage salt storage separately.
/// Requires a random source (`std` or `getrandom` feature).
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
#[cfg(any(feature = "std", feature = "getrandom"))]
pub fn argon2_hash(password: &[u8]) -> Result<String> {
    argon2_hash_with_params(password, Argon2Params::default())
}

/// Like [`argon2_hash`] but uses caller-supplied parameters.
///
/// The parameters must stay within the default [`Argon2Policy`] caps
/// (`m_cost` at most 1 GiB, `t_cost` at most 64, `p_cost` at most 16),
/// so that every hash produced here verifies with [`argon2_check`]. To
/// hash with higher costs, use [`argon2_hash_with_policy`]. Use
/// [`Argon2Params::validate`] to check that custom parameters are not
/// too weak.
///
/// # Errors
///
/// Same as [`argon2_hash`]; [`Error::Kdf`] also when a parameter is
/// above those limits.
#[cfg(any(feature = "std", feature = "getrandom"))]
pub fn argon2_hash_with_params(password: &[u8], params: Argon2Params) -> Result<String> {
    argon2_hash_with_policy(password, params, &Argon2Policy::new())
}

/// Like [`argon2_hash_with_params`], but checks `params` against
/// `policy` instead of the default caps: both its maximums and its
/// minimums apply. Always produces an Argon2id hash. New in 1.1.0.
///
/// # Errors
///
/// Same as [`argon2_hash`]; [`Error::Kdf`] also when a parameter is
/// outside `policy`.
#[cfg(any(feature = "std", feature = "getrandom"))]
pub fn argon2_hash_with_policy(
    password: &[u8],
    params: Argon2Params,
    policy: &Argon2Policy,
) -> Result<String> {
    policy.check_costs(params.m_cost, params.t_cost, params.p_cost)?;
    let mut salt_bytes = [0u8; ARGON2_DEFAULT_SALT_LEN];
    crate::rng::fill(&mut salt_bytes)?;

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

/// Check `password` against a PHC-encoded Argon2id hash string.
///
/// Returns `Ok(())` if the password matches and
/// `Err(`[`Error::AuthenticationFailed`]`)` if it does not, so
/// `argon2_check(..)?;` does the right thing. The PHC string is checked
/// against the default [`Argon2Policy`] first: `argon2id` only, `m` at
/// most 1 GiB, `t` at most 64, `p` at most 16. Use
/// [`argon2_check_with_policy`] to change those limits.
///
/// Verification re-derives the hash under the encoded parameters and
/// compares in constant time. The cost is the same as computing a fresh
/// hash with those parameters — usually ~100 ms with the default
/// params. New in 1.1.0; replaces [`argon2_verify`].
///
/// # Errors
///
/// - [`Error::AuthenticationFailed`] if the password does not match.
/// - [`Error::Kdf`] if `phc` does not parse as a PHC string, names a
///   variant the policy does not allow, or has costs outside it.
///
/// # Example
///
/// ```no_run
/// # #[cfg(feature = "kdf-argon2")] {
/// use crypt_io::{kdf, Error};
/// let phc = kdf::argon2_hash(b"hunter2")?;
///
/// kdf::argon2_check(&phc, b"hunter2")?;
/// assert_eq!(kdf::argon2_check(&phc, b"hunter3"), Err(Error::AuthenticationFailed));
/// # }
/// # Ok::<(), crypt_io::Error>(())
/// ```
pub fn argon2_check(phc: &str, password: &[u8]) -> Result<()> {
    argon2_check_with_policy(phc, password, &Argon2Policy::new())
}

/// [`argon2_check`] with a caller-chosen [`Argon2Policy`]. New in 1.1.0.
///
/// # Errors
///
/// Same as [`argon2_check`], with `policy` in place of the default.
pub fn argon2_check_with_policy(phc: &str, password: &[u8], policy: &Argon2Policy) -> Result<()> {
    let parsed = PasswordHash::new(phc).map_err(|_| Error::Kdf("argon2 phc parse"))?;
    let allowed = parsed.algorithm == ARGON2ID_IDENT
        || (policy.allow_argon2i && parsed.algorithm == ARGON2I_IDENT)
        || (policy.allow_argon2d && parsed.algorithm == ARGON2D_IDENT);
    if !allowed {
        return Err(Error::Kdf("argon2 phc variant not allowed by policy"));
    }
    let params = Params::try_from(&parsed).map_err(|_| Error::Kdf("argon2 phc parse"))?;
    policy.check_costs(params.m_cost(), params.t_cost(), params.p_cost())?;
    Argon2::default()
        .verify_password(password, &parsed)
        .map_err(|_| Error::AuthenticationFailed)
}

/// Verify `password` against a PHC-encoded Argon2id hash string.
///
/// **Deprecated since 1.1.0:** use [`argon2_check`], which returns
/// `Err(AuthenticationFailed)` for a wrong password.
///
/// Returns `Ok(true)` if the password matches, `Ok(false)` if it does
/// not, and [`Error::Kdf`] if `phc` is not an acceptable Argon2id PHC
/// string (same limits as [`argon2_check`]).
///
/// **A wrong password is `Ok(false)`, not an error.** Writing
/// `argon2_verify(..)?;` throws that `bool` away and logs everyone in.
///
/// # Errors
///
/// Returns [`Error::Kdf`] when `phc` fails to parse as a PHC string,
/// names a variant other than Argon2id, or exceeds the default limits.
/// A correctly-formatted but wrong-password hash returns `Ok(false)`.
///
/// # Example
///
/// ```no_run
/// # #![allow(deprecated)]
/// # #[cfg(feature = "kdf-argon2")] {
/// use crypt_io::kdf;
/// let phc = kdf::argon2_hash(b"hunter2")?;
///
/// // If you still use it, branch on the returned bool.
/// if !kdf::argon2_verify(&phc, b"hunter2")? {
///     return Err(crypt_io::Error::AuthenticationFailed);
/// }
/// # }
/// # Ok::<(), crypt_io::Error>(())
/// ```
#[deprecated(
    since = "1.1.0",
    note = "returns Ok(false) for a wrong password, so `argon2_verify(..)?;` logs everyone in; use `argon2_check`, which returns Err(AuthenticationFailed)"
)]
#[must_use = "a wrong password is Ok(false): check the bool, or use `argon2_check`"]
pub fn argon2_verify(phc: &str, password: &[u8]) -> Result<bool> {
    match argon2_check(phc, password) {
        Ok(()) => Ok(true),
        Err(Error::AuthenticationFailed) => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, unused_results, deprecated)]
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

    // ---- 1.0.1: PHC limits (audit CI-M3) ----

    const SALT_HASH: &str = "$c2FsdHNhbHRzYWx0c2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn verify_rejects_argon2d_and_argon2i() {
        for variant in ["argon2d", "argon2i"] {
            let phc = format!("${variant}$v=19$m=8,t=1,p=1{SALT_HASH}");
            let err = argon2_verify(&phc, b"guess").unwrap_err();
            assert!(matches!(err, Error::Kdf(_)), "{variant}: {err:?}");
        }
    }

    #[test]
    fn verify_rejects_hostile_memory_cost_without_allocating() {
        // 1.0.0 allocated 4 GiB here before comparing.
        let phc = format!("$argon2id$v=19$m=4194304,t=1,p=1{SALT_HASH}");
        let err = argon2_verify(&phc, b"guess").unwrap_err();
        assert!(matches!(err, Error::Kdf(_)), "{err:?}");
    }

    #[test]
    fn verify_rejects_hostile_time_and_lane_cost() {
        let t = format!("$argon2id$v=19$m=8,t=200000,p=1{SALT_HASH}");
        assert!(matches!(argon2_verify(&t, b"guess"), Err(Error::Kdf(_))));
        let p = format!("$argon2id$v=19$m=1024,t=1,p=64{SALT_HASH}");
        assert!(matches!(argon2_verify(&p, b"guess"), Err(Error::Kdf(_))));
    }

    #[test]
    fn verify_accepts_parameters_at_the_limits() {
        // t and p exactly at the caps (m kept small so the test is fast).
        let params = Argon2Params::new(8 * MAX_P_COST, MAX_T_COST, MAX_P_COST, 32);
        let phc = argon2_hash_with_params(b"pw", params).unwrap();
        assert!(argon2_verify(&phc, b"pw").unwrap());
    }

    #[test]
    fn hash_with_params_rejects_parameters_above_the_limits() {
        for bad in [
            Argon2Params::new(MAX_M_COST_KIB + 1, 1, 1, 32),
            Argon2Params::new(8, MAX_T_COST + 1, 1, 32),
            Argon2Params::new(8 * (MAX_P_COST + 1), 1, MAX_P_COST + 1, 32),
        ] {
            let err = argon2_hash_with_params(b"pw", bad).unwrap_err();
            assert!(matches!(err, Error::Kdf(_)), "{bad:?}: {err:?}");
        }
    }

    #[test]
    fn default_params_are_within_the_limits() {
        let d = Argon2Params::default();
        assert!(
            Argon2Policy::new()
                .check_costs(d.m_cost, d.t_cost, d.p_cost)
                .is_ok()
        );
        assert!(d.validate().is_ok());
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

    // ---- 1.1.0: check functions, policy, validate ----

    #[test]
    fn check_matches_verify() {
        let phc = argon2_hash_with_params(b"pw", fast_params()).unwrap();
        assert_eq!(argon2_check(&phc, b"pw"), Ok(()));
        assert_eq!(
            argon2_check(&phc, b"nope"),
            Err(Error::AuthenticationFailed)
        );
        assert!(matches!(argon2_check("garbage", b"pw"), Err(Error::Kdf(_))));
    }

    #[test]
    fn policy_can_raise_the_caps() {
        // t = 65 is above the default cap of 64.
        let params = Argon2Params::new(8, MAX_T_COST + 1, 1, 32);
        let roomy = Argon2Policy::new().with_max_cost(MAX_M_COST_KIB, 128, MAX_P_COST);
        let phc = argon2_hash_with_policy(b"pw", params, &roomy).unwrap();
        assert!(matches!(argon2_check(&phc, b"pw"), Err(Error::Kdf(_))));
        assert_eq!(argon2_check_with_policy(&phc, b"pw", &roomy), Ok(()));
        assert!(argon2_hash_with_params(b"pw", params).is_err());
    }

    #[test]
    fn policy_can_lower_the_caps_and_set_minimums() {
        let phc = argon2_hash_with_params(b"pw", Argon2Params::new(64, 2, 1, 32)).unwrap();
        let tight = Argon2Policy::new().with_max_cost(32, 64, 16);
        assert!(matches!(
            argon2_check_with_policy(&phc, b"pw", &tight),
            Err(Error::Kdf(_))
        ));
        let strict = Argon2Policy::new().with_min_cost(128, 1);
        assert!(matches!(
            argon2_check_with_policy(&phc, b"pw", &strict),
            Err(Error::Kdf(_))
        ));
        let strict_t = Argon2Policy::new().with_min_cost(0, 3);
        assert!(matches!(
            argon2_check_with_policy(&phc, b"pw", &strict_t),
            Err(Error::Kdf(_))
        ));
        assert!(argon2_hash_with_policy(b"pw", Argon2Params::new(64, 2, 1, 32), &strict).is_err());
    }

    #[test]
    fn policy_can_allow_other_variants() {
        // Build real argon2i / argon2d hashes with the upstream crate.
        use argon2::password_hash::{PasswordHasher, SaltString};
        let salt = SaltString::encode_b64(&[7u8; 16]).unwrap();
        let p = Params::new(8, 1, 1, Some(32)).unwrap();
        for (alg, allow_i, allow_d) in [
            (argon2::Algorithm::Argon2i, true, false),
            (argon2::Algorithm::Argon2d, false, true),
        ] {
            let phc = Argon2::new(alg, argon2::Version::V0x13, p.clone())
                .hash_password(b"pw", &salt)
                .unwrap()
                .to_string();
            assert!(matches!(argon2_check(&phc, b"pw"), Err(Error::Kdf(_))));
            let policy = Argon2Policy::new()
                .allow_argon2i(allow_i)
                .allow_argon2d(allow_d);
            assert_eq!(argon2_check_with_policy(&phc, b"pw", &policy), Ok(()));
            assert_eq!(
                argon2_check_with_policy(&phc, b"other", &policy),
                Err(Error::AuthenticationFailed)
            );
        }
    }

    #[test]
    fn policy_getters_and_default() {
        let d = Argon2Policy::default();
        assert_eq!(d, Argon2Policy::new());
        assert_eq!(
            (d.max_m_cost(), d.max_t_cost(), d.max_p_cost()),
            (MAX_M_COST_KIB, MAX_T_COST, MAX_P_COST)
        );
        assert_eq!((d.min_m_cost(), d.min_t_cost()), (0, 0));
        assert!(!d.argon2i_allowed() && !d.argon2d_allowed());
    }

    #[test]
    fn validate_enforces_owasp_minimums() {
        for ok in [
            Argon2Params::new(47_104, 1, 1, 32),
            Argon2Params::new(19_456, 2, 1, 32),
            Argon2Params::new(12_288, 3, 1, 32),
            Argon2Params::new(9_216, 4, 1, 32),
            Argon2Params::new(7_168, 5, 1, 32),
            Argon2Params::new(65_536, 3, 4, 64),
        ] {
            assert_eq!(ok.validate(), Ok(()), "{ok:?}");
        }
        for bad in [
            Argon2Params::new(47_103, 1, 1, 32),
            Argon2Params::new(19_455, 2, 1, 32),
            Argon2Params::new(7_167, 9, 1, 32),
            Argon2Params::new(8, 1, 1, 32),
            Argon2Params::new(19_456, 2, 1, 15),
            Argon2Params::new(19_456, 0, 1, 32),
            Argon2Params::new(19_456, 2, 0, 32),
            Argon2Params::new(MAX_M_COST_KIB + 1, 2, 1, 32),
        ] {
            assert!(matches!(bad.validate(), Err(Error::Kdf(_))), "{bad:?}");
        }
    }
}
