//! Fuzz `otp::totp_check` / `otp::hotp_check` with arbitrary codes,
//! times, counters and parameters. The code string comes from a user.
//! **Never panic**, and a code computed by `totp` / `hotp` must check.

#![no_main]

use arbitrary::Arbitrary;
use crypt_io::otp;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    secret: Vec<u8>,
    code: String,
    time_or_counter: u64,
    digits: u8,
    window: u8,
}

fuzz_target!(|input: Input| {
    let digits = u32::from(input.digits);
    let window = u32::from(input.window);
    let _ = otp::totp_check(&input.secret, &input.code, input.time_or_counter, digits, window);
    let _ = otp::hotp_check(&input.secret, &input.code, input.time_or_counter, digits, window);
    if let Ok(code) = otp::totp(&input.secret, input.time_or_counter, digits) {
        let typed = format!("{code:0width$}", width = digits as usize);
        let step = input.time_or_counter / otp::TOTP_STEP_SECONDS;
        assert_eq!(otp::totp_check(&input.secret, &typed, input.time_or_counter, digits, 0), Ok(step));
    }
});
