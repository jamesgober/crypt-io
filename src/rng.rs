//! Crate-internal access to the operating system's random source.
//!
//! Every nonce, stream salt, Argon2 salt and generated key comes from
//! here. Two backends exist, both of which read the OS CSPRNG and never
//! fall back to a userspace PRNG:
//!
//! - with the `getrandom` feature: the [`getrandom`] crate
//!   (`getrandom(2)` on Linux, `getentropy` on macOS, `ProcessPrng` on
//!   Windows, and a caller-registered backend on bare-metal targets);
//! - otherwise, with `std`: `mod_rand::tier3` (the same OS calls).
//!
//! A build with neither has no random source, and the APIs that need
//! one are not compiled.
//!
//! [`getrandom`]: https://docs.rs/getrandom

use crate::error::{Error, Result};

/// Fill `buf` with bytes from the OS CSPRNG.
#[cfg_attr(
    not(any(
        feature = "aead-chacha20",
        feature = "aead-aes-gcm",
        feature = "kdf-argon2"
    )),
    allow(dead_code)
)]
#[inline]
pub(crate) fn fill(buf: &mut [u8]) -> Result<()> {
    #[cfg(feature = "getrandom")]
    {
        getrandom::fill(buf).map_err(|_| Error::RandomFailure("getrandom::fill"))
    }
    #[cfg(all(feature = "std", not(feature = "getrandom")))]
    {
        mod_rand::tier3::fill_bytes(buf)
            .map_err(|_| Error::RandomFailure("mod_rand::tier3::fill_bytes"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn fill_produces_distinct_outputs() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        fill(&mut a).unwrap();
        fill(&mut b).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }
}
