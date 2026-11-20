//! One-time passwords: HOTP (RFC 4226) and TOTP (RFC 6238), new in 1.5.0.
//!
//! These are the six-digit codes authenticator apps (Google
//! Authenticator, Microsoft Authenticator, 1Password, ...) show. Every
//! one of those apps computes them with **HMAC-SHA1**, so that is what
//! this module uses. SHA-1 is broken for collision resistance, which
//! HMAC does not rely on, and RFC 4226 / 6238 still specify it; that is
//! the only reason crypt-io ships it. It lives here, not in the `mac`
//! module, so it cannot be picked up as a general MAC by
//! accident. For anything that is not an OTP, use HMAC-SHA256.
//!
//! | Function | What it does |
//! |---|---|
//! | [`totp`] / [`hotp`] | compute the code for a time / counter |
//! | [`totp_check`] / [`hotp_check`] | check a code a user typed, in constant time, inside a small window; return the matched step / counter for the replay guard |
//! | [`hmac_sha1_legacy`] | the raw HMAC-SHA1, for OTP variants this module does not cover |
//!
//! Requires the `otp` feature. Pure Rust since 1.7.0: HMAC-SHA1 is
//! crypt-io's own HMAC over the `RustCrypto` `sha1` crate, so `otp` needs
//! no C compiler (1.5 and 1.6 used AWS-LC). The codes are the same.
//!
//! # Replay
//!
//! A TOTP code stays valid for its whole 30-second step (and for the
//! window you allow). [`totp_check`] returns the time step that matched:
//! store it, and reject any later check whose step is not greater. The
//! same goes for [`hotp_check`] and the counter.
//!
//! # Example
//!
//! ```
//! # #[cfg(feature = "otp")] {
//! use crypt_io::otp;
//!
//! let secret = b"12345678901234567890";            // the shared secret (base32-decoded)
//! let now = 1_111_111_109;                          // Unix seconds
//! let code = otp::totp(secret, now, 8)?;            // RFC 6238 appendix B
//! assert_eq!(code, 7_081_804);
//!
//! // Server side: accept one step of clock drift either way.
//! let step = otp::totp_check(secret, "07081804", now + 20, 8, 1)?;
//! assert_eq!(step, now / otp::TOTP_STEP_SECONDS);   // store it; reject steps <= it later
//! # }
//! # Ok::<(), crypt_io::Error>(())
//! ```

use subtle::{Choice, ConditionallySelectable};

use crate::error::{Error, Result};
use crate::hmac_core::Hmac;
use crate::wipe::wipe;

/// HMAC-SHA1 state (SHA-1 has a 64-byte block).
type HmacSha1 = Hmac<sha1::Sha1, 64>;

/// Shortest secret accepted, in bytes: RFC 4226 section 4 requires at
/// least 128 bits (160 recommended; most apps use 20 bytes).
pub const OTP_MIN_SECRET_LEN: usize = 16;

/// TOTP time step in seconds (RFC 6238 default, and what every
/// authenticator app uses).
pub const TOTP_STEP_SECONDS: u64 = 30;

/// Largest window [`totp_check`] (steps either side) and
/// [`hotp_check`] (counters ahead) accept.
pub const OTP_MAX_WINDOW: u32 = 10;

/// Fewest and most digits a code can have (RFC 4226 section 5.3).
pub const OTP_MIN_DIGITS: u32 = 6;
/// See [`OTP_MIN_DIGITS`].
pub const OTP_MAX_DIGITS: u32 = 8;

/// Length of an HMAC-SHA1 tag in bytes.
pub const HMAC_SHA1_OUTPUT_LEN: usize = 20;

/// HMAC-SHA1 (RFC 2104). **Legacy: for one-time-password schemes only.**
///
/// Kept for RFC 4226 / 6238 variants that [`hotp`] and [`totp`] do not
/// cover (for example a different time step). Do not use it to
/// authenticate data: use `mac::hmac_sha256`.
///
/// Requires the `otp` feature. New in 1.5.0.
#[must_use]
pub fn hmac_sha1_legacy(key: &[u8], data: &[u8]) -> [u8; HMAC_SHA1_OUTPUT_LEN] {
    let mut mac = HmacSha1::new(key);
    mac.update(data);
    let mut tag = sha1::digest::Output::<sha1::Sha1>::default();
    mac.finalize_into(&mut tag);
    tag.into()
}

/// The HOTP code for `counter` (RFC 4226 section 5.3): HMAC-SHA1 of the
/// big-endian counter, dynamic truncation, modulo 10^`digits`.
///
/// Format it with leading zeros to `digits` places for display
/// (`format!("{code:06}")`).
///
/// # Errors
///
/// [`Error::InvalidInput`] if `secret` is shorter than
/// [`OTP_MIN_SECRET_LEN`] or `digits` is outside 6 to 8.
pub fn hotp(secret: &[u8], counter: u64, digits: u32) -> Result<u32> {
    check_params(secret, digits)?;
    Ok(code_for(&HmacSha1::new(secret), counter, digits))
}

/// The TOTP code at `unix_seconds` (RFC 6238 with HMAC-SHA1, a
/// 30-second step and T0 = 0): `hotp(secret, unix_seconds / 30, digits)`.
///
/// # Errors
///
/// As [`hotp`].
pub fn totp(secret: &[u8], unix_seconds: u64, digits: u32) -> Result<u32> {
    hotp(secret, unix_seconds / TOTP_STEP_SECONDS, digits)
}

/// Check a HOTP `code` against counters `counter ..= counter +
/// look_ahead` and return the counter that matched. Store `matched + 1`
/// as the next expected counter.
///
/// `code` is what the user typed: exactly `digits` ASCII digits, leading
/// zeros included. Every candidate is computed and compared in constant
/// time.
///
/// # Errors
///
/// - [`Error::AuthenticationFailed`] if no counter in the window gives
///   `code`, or `code` is not `digits` ASCII digits.
/// - [`Error::InvalidInput`] for a short secret, `digits` outside 6 to 8,
///   or `look_ahead` above [`OTP_MAX_WINDOW`].
pub fn hotp_check(
    secret: &[u8],
    code: &str,
    counter: u64,
    digits: u32,
    look_ahead: u32,
) -> Result<u64> {
    check_window(look_ahead)?;
    check_code(
        secret,
        code,
        digits,
        counter,
        counter.saturating_add(u64::from(look_ahead)),
    )
}

/// Check a TOTP `code` at `unix_seconds`, accepting `window` time steps
/// either side (1 = 30 seconds of clock drift each way), and return the
/// time step that matched. Store it and reject any later code whose
/// step is not greater (replay guard).
///
/// `code` is what the user typed: exactly `digits` ASCII digits, leading
/// zeros included. Every candidate is computed and compared in constant
/// time.
///
/// # Errors
///
/// - [`Error::AuthenticationFailed`] if no step in the window gives
///   `code`, or `code` is not `digits` ASCII digits.
/// - [`Error::InvalidInput`] for a short secret, `digits` outside 6 to 8,
///   or `window` above [`OTP_MAX_WINDOW`].
pub fn totp_check(
    secret: &[u8],
    code: &str,
    unix_seconds: u64,
    digits: u32,
    window: u32,
) -> Result<u64> {
    check_window(window)?;
    let step = unix_seconds / TOTP_STEP_SECONDS;
    let w = u64::from(window);
    check_code(
        secret,
        code,
        digits,
        step.saturating_sub(w),
        step.saturating_add(w),
    )
}

fn check_params(secret: &[u8], digits: u32) -> Result<()> {
    if secret.len() < OTP_MIN_SECRET_LEN {
        return Err(Error::InvalidInput(
            "OTP secret shorter than 16 bytes (RFC 4226)",
        ));
    }
    if !(OTP_MIN_DIGITS..=OTP_MAX_DIGITS).contains(&digits) {
        return Err(Error::InvalidInput("OTP digits must be 6 to 8"));
    }
    Ok(())
}

fn check_window(window: u32) -> Result<()> {
    if window > OTP_MAX_WINDOW {
        return Err(Error::InvalidInput("OTP window larger than OTP_MAX_WINDOW"));
    }
    Ok(())
}

/// Compare `code` with every counter in `first ..= last`, all in
/// constant time, and return the first one that matches.
fn check_code(secret: &[u8], code: &str, digits: u32, first: u64, last: u64) -> Result<u64> {
    check_params(secret, digits)?;
    let typed = code.as_bytes();
    let len = digits as usize;
    // The code's length and character set are not secret.
    if typed.len() != len || !typed.iter().all(u8::is_ascii_digit) {
        return Err(Error::AuthenticationFailed);
    }
    let key = HmacSha1::new(secret);
    let mut found = Choice::from(0);
    let mut matched = 0u64;
    let mut candidate = [0u8; OTP_MAX_DIGITS as usize];
    let mut c = first;
    loop {
        render(code_for(&key, c, digits), &mut candidate[..len]);
        let eq = crate::ct::ct_eq(&candidate[..len], typed);
        matched = u64::conditional_select(&matched, &c, eq & !found);
        found |= eq;
        if c == last {
            break;
        }
        c += 1;
    }
    wipe(&mut candidate);
    if bool::from(found) {
        Ok(matched)
    } else {
        Err(Error::AuthenticationFailed)
    }
}

/// RFC 4226 section 5.3: dynamic truncation of HMAC(counter). The
/// offset is the low nibble of the last tag byte, which RFC 6238 keeps
/// for its SHA-256 and SHA-512 variants (the tests pin those too).
fn code_for<D, const B: usize>(key: &Hmac<D, B>, counter: u64, digits: u32) -> u32
where
    D: sha1::Digest + Clone,
{
    let mut mac = key.clone();
    mac.update(&counter.to_be_bytes());
    let mut tag = sha1::digest::Output::<D>::default();
    mac.finalize_into(&mut tag);
    let offset = usize::from(tag[tag.len() - 1] & 0x0f);
    let bin = u32::from_be_bytes([
        tag[offset],
        tag[offset + 1],
        tag[offset + 2],
        tag[offset + 3],
    ]) & 0x7fff_ffff;
    wipe(&mut tag);
    bin % 10u32.pow(digits)
}

/// Write `code` as exactly `out.len()` ASCII digits, leading zeros
/// included.
fn render(mut code: u32, out: &mut [u8]) {
    for b in out.iter_mut().rev() {
        // `code % 10` is below 10, so the cast cannot truncate.
        #[allow(clippy::cast_possible_truncation)]
        let digit = (code % 10) as u8;
        *b = b'0' + digit;
        code /= 10;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn render_pads_with_zeros() {
        let mut out = [0u8; 6];
        render(42, &mut out);
        assert_eq!(&out, b"000042");
        render(999_999, &mut out);
        assert_eq!(&out, b"999999");
    }

    #[test]
    fn parameters_are_checked() {
        assert!(matches!(
            hotp(&SECRET[..15], 0, 6),
            Err(Error::InvalidInput(_))
        ));
        assert!(matches!(hotp(SECRET, 0, 5), Err(Error::InvalidInput(_))));
        assert!(matches!(hotp(SECRET, 0, 9), Err(Error::InvalidInput(_))));
        assert!(matches!(
            totp_check(SECRET, "287082", 0, 6, OTP_MAX_WINDOW + 1),
            Err(Error::InvalidInput(_))
        ));
        assert!(hotp(&SECRET[..16], 0, 6).is_ok());
    }

    #[test]
    fn malformed_codes_fail_as_authentication() {
        for code in ["", "75522", "7552240", "75522a", "７55224", " 55224"] {
            assert_eq!(
                hotp_check(SECRET, code, 0, 6, 0),
                Err(Error::AuthenticationFailed),
                "{code:?}"
            );
        }
    }

    #[test]
    fn window_edges_and_saturation() {
        // Counter 1 gives 287082 (RFC 4226).
        assert_eq!(hotp_check(SECRET, "287082", 0, 6, 1), Ok(1));
        assert_eq!(
            hotp_check(SECRET, "287082", 0, 6, 0),
            Err(Error::AuthenticationFailed)
        );
        assert_eq!(
            hotp_check(SECRET, "287082", 2, 6, 5),
            Err(Error::AuthenticationFailed)
        );
        // Near u64::MAX the window saturates instead of wrapping.
        let code = format!("{:06}", hotp(SECRET, u64::MAX, 6).unwrap());
        assert_eq!(hotp_check(SECRET, &code, u64::MAX - 1, 6, 10), Ok(u64::MAX));
        // At time 0 the window cannot go below step 0.
        let code = format!("{:06}", totp(SECRET, 0, 6).unwrap());
        assert_eq!(totp_check(SECRET, &code, 0, 6, 3), Ok(0));
    }

    /// RFC 6238 appendix B, all three hashes: time, then the 8-digit
    /// TOTP for SHA-1, SHA-256 and SHA-512 (seeds of 20, 32 and 64
    /// bytes). The public API is SHA-1 only; the other two run the same
    /// truncation code over this crate's HMAC.
    const RFC6238: &[(u64, u32, u32, u32)] = &[
        (59, 94_287_082, 46_119_246, 90_693_936),
        (1_111_111_109, 7_081_804, 68_084_774, 25_091_201),
        (1_111_111_111, 14_050_471, 67_062_674, 99_943_326),
        (1_234_567_890, 89_005_924, 91_819_424, 93_441_116),
        (2_000_000_000, 69_279_037, 90_698_825, 38_618_901),
        (20_000_000_000, 65_353_130, 77_737_706, 47_863_826),
    ];

    #[test]
    fn rfc6238_sha1() {
        for &(t, sha1, _, _) in RFC6238 {
            assert_eq!(totp(SECRET, t, 8).unwrap(), sha1, "t={t}");
            let step = t / TOTP_STEP_SECONDS;
            assert_eq!(code_for(&HmacSha1::new(SECRET), step, 8), sha1);
        }
    }

    #[cfg(feature = "hash-sha2")]
    #[test]
    fn rfc6238_sha256_and_sha512() {
        let seed32 = b"12345678901234567890123456789012";
        let seed64 = b"1234567890123456789012345678901234567890123456789012345678901234";
        let k256 = Hmac::<sha2::Sha256, 64>::new(seed32);
        let k512 = Hmac::<sha2::Sha512, 128>::new(seed64);
        for &(t, _, sha256, sha512) in RFC6238 {
            let step = t / TOTP_STEP_SECONDS;
            assert_eq!(code_for(&k256, step, 8), sha256, "SHA-256 t={t}");
            assert_eq!(code_for(&k512, step, 8), sha512, "SHA-512 t={t}");
        }
    }

    /// Up to 1.6 HMAC-SHA1 came from AWS-LC. When a `sign-*` feature
    /// brings AWS-LC into the build, check the two agree for keys
    /// shorter than, equal to and longer than the 64-byte block.
    #[cfg(feature = "sign-ed25519")]
    #[test]
    fn hmac_sha1_matches_aws_lc() {
        use aws_lc_rs::hmac;
        let bytes: alloc::vec::Vec<u8> = (0u32..300)
            .map(|i| (i.wrapping_mul(131) >> 1).to_le_bytes()[0])
            .collect();
        for key_len in [0, 1, 16, 20, 63, 64, 65, 128, 200] {
            for data_len in [0, 1, 8, 55, 56, 64, 100, 299] {
                let key = &bytes[..key_len];
                let data = &bytes[1..=data_len];
                let theirs = hmac::sign(
                    &hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key),
                    data,
                );
                assert_eq!(
                    hmac_sha1_legacy(key, data).as_slice(),
                    theirs.as_ref(),
                    "key {key_len} data {data_len}"
                );
            }
        }
    }
}
