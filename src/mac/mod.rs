//! Message Authentication Codes (MAC).
//!
//! A MAC is a small fixed-size tag computed over `(key, data)` such that
//! anyone holding the key can verify the tag is intact. Three algorithms
//! ship in 0.5.0:
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
//! - **Verify** (`hmac_sha256_verify`, `blake3_keyed_verify`, ...): computes
//!   the tag for the supplied `(key, data)` and compares it against an
//!   expected tag in **constant time**.
//! - **Streaming** (`HmacSha256`, `Blake3Mac`, ...): for inputs that
//!   arrive in chunks.
//!
//! # Constant-time verification — non-negotiable
//!
//! Comparing two tags with `==` leaks how many leading bytes matched via
//! timing. That leak is enough to forge tags one byte at a time. The
//! `*_verify` functions and the streaming hashers' [`HmacSha256::verify`]
//! / [`HmacSha512::verify`] / [`Blake3Mac::verify`] methods all use
//! upstream constant-time comparators ([`subtle::ConstantTimeEq`] via
//! the `hmac` and `blake3` crates).
//!
//! **Never** compare a computed tag to an expected tag with `==`. Use
//! the `verify` paths in this module.
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
//! assert!(mac::hmac_sha256_verify(key, data, &tag)?);
//! # }
//! # Ok::<(), crypt_io::Error>(())
//! ```

#[cfg(feature = "mac-blake3")]
mod blake3_impl;
#[cfg(feature = "mac-hmac")]
mod hmac_impl;

#[cfg(feature = "mac-blake3")]
pub use self::blake3_impl::{Blake3Mac, blake3_keyed, blake3_keyed_verify};
#[cfg(feature = "mac-hmac")]
pub use self::hmac_impl::{
    HmacSha256, HmacSha512, hmac_sha256, hmac_sha256_verify, hmac_sha512, hmac_sha512_verify,
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
