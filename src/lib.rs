//! # crypt-io
//!
//! ENCRYPTION SUITE FOR RUST
//!
//! AEAD encryption (ChaCha20-Poly1305, XChaCha20-Poly1305, AES-256-GCM), hashing (BLAKE3, SHA-2), MAC
//! (HMAC, BLAKE3 keyed), and KDF (HKDF, Argon2id). Algorithm-agile. RustCrypto-backed
//! primitives with REPS discipline. Simple API. Sub-microsecond throughput.
//!
//! # Design philosophy
//!
//! crypt-io is a focused encryption library that wraps proven cryptographic
//! primitives (from RustCrypto and the BLAKE3 team) with:
//!
//! - A clean, ergonomic API
//! - Algorithm agility (switch ciphers via enum or feature flag)
//! - REPS-disciplined error handling and lifecycle
//! - OS-backed CSPRNG nonces and salts via the portfolio crate `mod-rand`
//! - Sub-microsecond throughput targets verified by benchmarks
//!
//! crypt-io does NOT implement cryptographic primitives from scratch. The actual
//! math comes from battle-tested upstream crates. crypt-io's job is the integration,
//! the API design, and the safety discipline (constant-time, zeroize, key handling).
//!
//! # Scope
//!
//! In scope:
//!
//! - **Symmetric AEAD encryption** (ChaCha20-Poly1305, XChaCha20-Poly1305,
//!   AES-256-GCM)
//! - **Stream/file encryption** for large data (chunked AEAD with framing)
//! - **Hashing** (BLAKE3, SHA-256, SHA-512)
//! - **MAC** (HMAC-SHA256, HMAC-SHA512, BLAKE3 keyed)
//! - **KDF** (HKDF for key derivation, Argon2id for password hashing)
//!
//! Out of scope (use other crates):
//!
//! - **Random utilities** -> use `mod-rand`
//! - **UUID generation** -> use `id-forge`
//! - **Asymmetric crypto** (RSA, ECDSA, Ed25519) -> deferred to separate crate
//! - **PGP/GPG** -> use `sequoia-openpgp`
//! - **TLS** -> use `rustls`
//! - **Key storage** -> use `key-vault`
//!
//! # Status
//!
//! Stable (1.x). The public API and both wire formats are frozen for the
//! 1.x series; see `docs/STABILITY-1.0.md` in
//! [the repository](https://github.com/jamesgober/crypt-io).
//!
//! # Platform support
//!
//! With default features crypt-io uses `std`. Since 1.1.0 it also
//! builds as `no_std` + `alloc` (`default-features = false`, for
//! example on `thumbv7em-none-eabihf`). Without `std`:
//!
//! - Hashing, MACs, HKDF, Argon2id verification, every decrypt path,
//!   [`Crypt::open`], [`stream::StreamDecryptor`] and [`Tag`] work as
//!   usual.
//! - Anything that needs fresh randomness (`encrypt*`, `seal*`,
//!   `StreamEncryptor::new*`, `argon2_hash*`, [`generate_key`]) needs
//!   the `getrandom` feature. On targets without an OS random source,
//!   register a `getrandom` custom backend that reads your hardware
//!   RNG.
//! - The file helpers `stream::encrypt_file` / `stream::decrypt_file`
//!   need `std`.
//!
//! See `docs/PLATFORM-NOTES.md` for the feature lists.
//!
//! # Security notes
//!
//! - Check MACs and passwords with the `*_check` functions
//!   (`mac::hmac_sha256_check`, `mac::blake3_keyed_check`,
//!   `kdf::argon2_check`, ...), which return
//!   `Err(Error::AuthenticationFailed)` on a mismatch. The older
//!   `*_verify` functions (deprecated in 1.1.0) return `Ok(false)`, so
//!   `verify(..)?;` silently accepts forged tags and wrong passwords.
//! - Random 96-bit nonces (ChaCha20-Poly1305, AES-256-GCM): keep each
//!   key below 2^32 single-shot encryptions (NIST SP 800-38D), or use
//!   XChaCha20-Poly1305. Streams written by 1.1.0 (format v2) use a
//!   fresh subkey per stream and have no practical streams-per-key
//!   limit. See `docs/SECURITY.md`.
//!
//! # License
//!
//! Dual-licensed under Apache-2.0 OR MIT.

#![doc(html_root_url = "https://docs.rs/crypt-io")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]
// REPS §Code Quality canonical lint set. `#![deny(warnings)]` is
// intentionally NOT used at the crate root — new rustc versions can
// introduce lints that retroactively break downstream builds of a
// published crate. CI carries `RUSTFLAGS="-D warnings"` instead so the
// gate is enforced where the lint surface is pinned to the toolchain
// matrix.
#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(unused_must_use)]
#![deny(unused_results)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unreachable)]
#![deny(clippy::print_stdout)]
#![deny(clippy::print_stderr)]
#![deny(clippy::dbg_macro)]
#![deny(clippy::undocumented_unsafe_blocks)]
#![deny(clippy::missing_safety_doc)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

extern crate alloc;

mod error;
#[cfg(any(feature = "std", feature = "getrandom"))]
mod rng;
mod tag;

#[cfg(any(feature = "aead-chacha20", feature = "aead-aes-gcm"))]
mod wipe;

#[cfg(any(feature = "aead-chacha20", feature = "aead-aes-gcm"))]
pub mod aead;

#[cfg(any(feature = "hash-blake3", feature = "hash-sha2"))]
pub mod hash;

#[cfg(any(feature = "mac-hmac", feature = "mac-blake3"))]
pub mod mac;

#[cfg(any(feature = "kdf-hkdf", feature = "kdf-argon2"))]
pub mod kdf;

#[cfg(feature = "stream")]
pub mod stream;

pub use crate::error::{Error, Result};
pub use crate::tag::Tag;

#[cfg(any(feature = "aead-chacha20", feature = "aead-aes-gcm"))]
pub use crate::aead::{Algorithm, Crypt};

#[cfg(all(
    any(feature = "aead-chacha20", feature = "aead-aes-gcm"),
    feature = "zeroize",
    any(feature = "std", feature = "getrandom")
))]
pub use crate::aead::generate_key;

/// Re-export of [`zeroize::Zeroizing`], the wrapper that
/// [`generate_key`] and [`Crypt::decrypt_zeroizing`] return. New in
/// 1.1.0.
#[cfg(feature = "zeroize")]
pub use zeroize::Zeroizing;

/// Crate version string, populated by Cargo at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
