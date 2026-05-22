//! Key Derivation Functions (KDF).
//!
//! Two algorithms ship in 0.6.0, addressing different needs:
//!
//! | Algorithm   | Purpose                                            | Speed         | Feature       |
//! |-------------|----------------------------------------------------|---------------|---------------|
//! | HKDF-SHA256 | Derive one-or-many subkeys from a high-entropy IKM | Fast (µs)     | `kdf-hkdf`    |
//! | HKDF-SHA512 | Same, wider underlying digest                      | Fast (µs)     | `kdf-hkdf`    |
//! | Argon2id    | Derive a key from a *password* (low-entropy input) | Slow (~100ms) | `kdf-argon2`  |
//!
//! # Which one do I want?
//!
//! - **HKDF** ([RFC 5869]) for deriving subkeys from a master key, a
//!   shared secret from a key exchange, or anything else already
//!   high-entropy. HKDF does *not* protect against weak inputs — feeding
//!   it a password is a security mistake.
//!
//! - **Argon2id** ([RFC 9106]) for deriving a key from a password. The
//!   memory-hardness and tuneable cost are what protect against
//!   brute-force attempts; the slowness is the point.
//!
//! [RFC 5869]: https://datatracker.ietf.org/doc/html/rfc5869
//! [RFC 9106]: https://datatracker.ietf.org/doc/html/rfc9106
//!
//! # Examples
//!
//! Deriving a 32-byte subkey from a master:
//!
//! ```
//! # #[cfg(feature = "kdf-hkdf")] {
//! use crypt_io::kdf;
//! let master = [0x42u8; 32];
//! let subkey = kdf::hkdf_sha256(&master, Some(b"salt"), b"app:session:v1", 32)?;
//! assert_eq!(subkey.len(), 32);
//! # }
//! # Ok::<(), crypt_io::Error>(())
//! ```
//!
//! Hashing and verifying a password:
//!
//! ```no_run
//! # #[cfg(feature = "kdf-argon2")] {
//! use crypt_io::kdf;
//! let phc = kdf::argon2_hash(b"correct horse battery staple")?;
//! assert!(kdf::argon2_verify(&phc, b"correct horse battery staple")?);
//! assert!(!kdf::argon2_verify(&phc, b"wrong guess")?);
//! # }
//! # Ok::<(), crypt_io::Error>(())
//! ```

#[cfg(feature = "kdf-argon2")]
mod argon2_impl;
#[cfg(feature = "kdf-hkdf")]
mod hkdf_impl;

#[cfg(feature = "kdf-argon2")]
pub use self::argon2_impl::{
    ARGON2_DEFAULT_OUTPUT_LEN, ARGON2_DEFAULT_SALT_LEN, Argon2Params, argon2_hash,
    argon2_hash_with_params, argon2_verify,
};
#[cfg(feature = "kdf-hkdf")]
pub use self::hkdf_impl::{
    HKDF_MAX_OUTPUT_SHA256, HKDF_MAX_OUTPUT_SHA512, hkdf_sha256, hkdf_sha512,
};
