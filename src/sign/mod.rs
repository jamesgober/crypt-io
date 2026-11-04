//! Digital signatures (new in 1.3.0).
//!
//! | Algorithm | Type | Signature | Feature |
//! |---|---|---|---|
//! | Ed25519 ([RFC 8032]) | `Ed25519SigningKey` | 64 bytes | `sign-ed25519` |
//! | RSA PKCS#1 v1.5 with SHA-256 ([RFC 8017]), 2048 to 8192 bits | `RsaSigningKey` | modulus size | `sign-rsa` |
//!
//! Both are what DKIM (RFC 6376, RFC 8463) and JOSE (`EdDSA`, `RS256`)
//! sign with. Prefer Ed25519 for anything new: smaller keys and
//! signatures, much faster, and deterministic. Use RSA where a peer
//! requires it.
//!
//! # Backend and build cost
//!
//! The math comes from AWS-LC through `aws-lc-rs`, the same backend
//! tls-net uses; crypt-io's types sit in front of it so the backend can
//! be swapped without an API change. AWS-LC is C and assembly, so these
//! features are off by default and need:
//!
//! - a C compiler on every platform;
//! - on Windows x86-64, NASM on the `PATH`, or the `prebuilt-nasm`
//!   feature (uses the assembled objects that ship with `aws-lc-sys`);
//! - `std`, which the features turn on.
//!
//! The first build of `aws-lc-sys` adds roughly 15 to 25 seconds on a
//! fast machine (measured: about 16 s debug, 24 s release on 32 cores);
//! later builds reuse it. The default build is unaffected and stays
//! pure Rust.
//!
//! # Key handling
//!
//! - Private keys live inside AWS-LC, which overwrites (cleanses) every
//!   allocation when it frees it, so dropping a signing key wipes it.
//!   crypt-io keeps no copy of its own.
//! - The bytes you parse a key from (PKCS#8, PKCS#1, a seed) stay in
//!   your buffer; wipe it with [`crate::wipe`] once the key is built.
//! - `Debug` never prints private key material.
//! - RSA signing uses AWS-LC's blinded, constant-time implementation.
//!
//! # Example
//!
//! ```
//! # #[cfg(feature = "sign-ed25519")] {
//! use crypt_io::sign::Ed25519SigningKey;
//!
//! let seed = [0x42u8; 32];   // in practice: from a PKCS#8 file or a KMS
//! let key = Ed25519SigningKey::from_seed(&seed)?;
//! let signature: [u8; 64] = key.sign(b"message");
//! let public_key: [u8; 32] = key.public_key();
//! # let _ = (signature, public_key);
//! # }
//! # Ok::<(), crypt_io::Error>(())
//! ```
//!
//! [RFC 8032]: https://datatracker.ietf.org/doc/html/rfc8032
//! [RFC 8017]: https://datatracker.ietf.org/doc/html/rfc8017

#[cfg(feature = "sign-ed25519")]
mod ed25519;
#[cfg(feature = "sign-rsa")]
mod rsa;

#[cfg(feature = "sign-ed25519")]
pub use self::ed25519::{
    ED25519_PUBLIC_KEY_LEN, ED25519_SEED_LEN, ED25519_SIGNATURE_LEN, Ed25519SigningKey,
};
#[cfg(feature = "sign-rsa")]
pub use self::rsa::{RSA_MAX_MODULUS_BITS, RSA_MIN_MODULUS_BITS, RsaSigningKey};

/// Map an `aws-lc-rs` key rejection to crypt-io's error, without
/// exposing the backend's type.
fn key_rejected(e: aws_lc_rs::error::KeyRejected) -> crate::Error {
    crate::Error::Sign(match e.description_() {
        "TooSmall" => "key rejected: RSA modulus smaller than 2048 bits",
        "TooLarge" => "key rejected: RSA modulus larger than 8192 bits",
        "WrongAlgorithm" => "key rejected: not a key for this algorithm",
        "InconsistentComponents" => "key rejected: inconsistent key components",
        "InvalidEncoding" => "key rejected: invalid encoding",
        _ => "key rejected",
    })
}
