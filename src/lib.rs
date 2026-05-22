//! # crypt-io
//!
//! ENCRYPTION SUITE FOR RUST
//!
//! AEAD encryption (ChaCha20-Poly1305, AES-256-GCM), hashing (BLAKE3, SHA-2), MAC
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
//! - Tight integration with the portfolio (mod-rand, error-forge, optional log-io/metrics-lib)
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
//! - **Symmetric AEAD encryption** (ChaCha20-Poly1305, AES-256-GCM)
//! - **Stream/file encryption** for large data (chunked AEAD with framing)
//! - **Hashing** (BLAKE3, SHA-256, SHA-512)
//! - **MAC** (HMAC-SHA256, BLAKE3 keyed)
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
//! Early scaffolding. Public API not yet defined. See [the repository](https://github.com/jamesgober/crypt-io)
//! and `.dev/ROADMAP.md` for the milestone plan.
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

#[cfg(any(feature = "aead-chacha20", feature = "aead-aes-gcm"))]
pub mod aead;

#[cfg(any(feature = "hash-blake3", feature = "hash-sha2"))]
pub mod hash;

pub use crate::error::{Error, Result};

#[cfg(any(feature = "aead-chacha20", feature = "aead-aes-gcm"))]
pub use crate::aead::{Algorithm, Crypt};

/// Crate version string, populated by Cargo at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
