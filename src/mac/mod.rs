//! Message Authentication Codes (MAC).
//!
//! A MAC is a small fixed-size tag computed over `(key, data)` such that
//! anyone holding the key can verify the tag is intact. Three algorithms
//! ship:
//!
//! | Algorithm        | One-shot                       | Streaming      | Tag    | Feature       |
//! |------------------|--------------------------------|----------------|--------|---------------|
//! | HMAC-SHA256      | [`hmac_sha256()`]              | [`HmacSha256`] | 32 B   | `mac-hmac`    |
//! | HMAC-SHA512      | [`hmac_sha512()`]              | [`HmacSha512`] | 64 B   | `mac-hmac`    |
//! | BLAKE3 keyed     | [`blake3_keyed()`]             | [`Blake3Mac`]  | 32 B   | `mac-blake3`  |
//!
//! Every algorithm exposes three operations:
//!
//! - **Compute** (`hmac_sha256`, `blake3_keyed`, ...): produces the tag.
//! - **Check** (`hmac_sha256_check`, `blake3_keyed_check`, ...; new in
//!   1.1.0): computes the tag for the supplied `(key, data)`, compares
//!   it against an expected tag in **constant time**, and returns
//!   `Err(Error::AuthenticationFailed)` on a mismatch.
//! - **Streaming** (`HmacSha256`, `Blake3Mac`, ...): for inputs that
//!   arrive in chunks, finished with `check` (or `finalize`).
//!
//! # Constant-time comparison — non-negotiable
//!
//! Comparing two tags with `==` leaks how many leading bytes matched via
//! timing. That leak is enough to forge tags one byte at a time. The
//! `*_check` functions and the streaming types' `check` / `verify`
//! methods all use constant-time comparators ([`subtle::ConstantTimeEq`]
//! via the `hmac` crate, and `blake3::Hash` equality).
//!
//! **Never** compare a computed tag to an expected tag with `==` on
//! arrays. Use the `check` paths in this module, or wrap the computed
//! tag in [`Tag`](crate::Tag), whose `==` is constant-time.
//!
//! # The deprecated `*_verify` functions
//!
//! `hmac_sha256_verify` and `hmac_sha512_verify` return `Result<bool>`:
//! `Err` only when the MAC cannot be set up, and `Ok(false)` when the
//! tag does not match. The `?` operator handles the `Err` and hands
//! back the `bool`, so
//!
//! ```text
//! mac::hmac_sha256_verify(key, data, tag)?;   // WRONG: accepts forged tags
//! ```
//!
//! compiles and accepts every tag. They are deprecated since 1.1.0 (as
//! is `blake3_keyed_verify`, for consistency) and stay available for
//! the rest of 1.x. Switch to the `*_check` forms:
//!
//! ```text
//! mac::hmac_sha256_check(key, data, tag)?;    // rejects forged tags
//! ```
//!
//! # Choosing a MAC
//!
//! - **HMAC-SHA256** — universal interop. JWT (HS256), TLS PRF, AWS
//!   request signing, anything that names HMAC-SHA256 in a spec.
//! - **HMAC-SHA512** — same as above when the wider tag is required.
//! - **BLAKE3 keyed** — fastest of the three on modern hardware,
//!   typically 4–10× faster than HMAC-SHA256 at the same security
//!   level. Pick this when you control both sides of the wire.
//!
//! [`subtle::ConstantTimeEq`]: https://docs.rs/subtle/latest/subtle/trait.ConstantTimeEq.html
//!
//! # Example
//!
//! ```
//! # #[cfg(feature = "mac-hmac")] {
//! use crypt_io::mac;
//!
//! let key = b"shared secret";
//! let data = b"message to authenticate";
//!
//! let tag = mac::hmac_sha256(key, data)?;
//! mac::hmac_sha256_check(key, data, &tag)?;
//! # }
//! # Ok::<(), crypt_io::Error>(())
//! ```

#[cfg(feature = "mac-blake3")]
mod blake3_impl;
#[cfg(feature = "mac-hmac")]
mod hmac_impl;

#[cfg(feature = "mac-blake3")]
#[allow(deprecated)]
pub use self::blake3_impl::{Blake3Mac, blake3_keyed, blake3_keyed_check, blake3_keyed_verify};
#[cfg(feature = "mac-hmac")]
#[allow(deprecated)]
pub use self::hmac_impl::{
    HmacSha256, HmacSha512, hmac_sha256, hmac_sha256_check, hmac_sha256_verify, hmac_sha512,
    hmac_sha512_check, hmac_sha512_verify,
};

/// Length of an HMAC-SHA256 tag, in bytes. Equal to `32`.
#[cfg(feature = "mac-hmac")]
pub const HMAC_SHA256_OUTPUT_LEN: usize = 32;

/// Length of an HMAC-SHA512 tag, in bytes. Equal to `64`.
#[cfg(feature = "mac-hmac")]
pub const HMAC_SHA512_OUTPUT_LEN: usize = 64;

/// Length of a BLAKE3 keyed-mode tag, in bytes. Equal to `32`.
#[cfg(feature = "mac-blake3")]
pub const BLAKE3_MAC_OUTPUT_LEN: usize = 32;

/// Required key length for BLAKE3 keyed mode, in bytes. Equal to `32`.
#[cfg(feature = "mac-blake3")]
pub const BLAKE3_MAC_KEY_LEN: usize = 32;
