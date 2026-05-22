//! Cryptographic hash functions.
//!
//! Three algorithms ship in 0.4.0, exposed through a consistent free-function
//! API plus matching streaming hashers for inputs that don't fit in memory:
//!
//! | Algorithm  | One-shot              | Streaming         | Output | Feature       |
//! |------------|-----------------------|-------------------|--------|---------------|
//! | BLAKE3     | [`blake3()`]          | [`Blake3Hasher`]  | 32 B   | `hash-blake3` |
//! | BLAKE3 XOF | [`blake3_long()`]     | [`Blake3Hasher`]  | N B    | `hash-blake3` |
//! | SHA-256    | [`sha256()`]          | [`Sha256Hasher`]  | 32 B   | `hash-sha2`   |
//! | SHA-512    | [`sha512()`]          | [`Sha512Hasher`]  | 64 B   | `hash-sha2`   |
//!
//! # Choosing a hash
//!
//! Pick **BLAKE3** unless you have a reason not to. It is the fastest
//! cryptographic hash on every modern platform — typically 4–10× faster
//! than SHA-256 on x86_64 with `AVX2`, and faster still on the wide vector
//! units of Apple Silicon. It is also tree-structured and SIMD-friendly,
//! so very large inputs hash at near-memcpy bandwidth.
//!
//! Pick **SHA-256** when you need ecosystem interop — TLS, JWT, Bitcoin,
//! certificate fingerprints, any spec that names SHA-256 explicitly.
//!
//! Pick **SHA-512** when interop demands the wider output (some
//! certificate authorities, some old protocols) or when running on a
//! 64-bit machine where SHA-512 happens to be faster than SHA-256 (it
//! processes 64-bit words natively).
//!
//! # No-key, no-MAC
//!
//! These functions hash data only. For keyed hashing (BLAKE3 keyed mode,
//! HMAC-SHA2), see the [`mac`](../mac/index.html) module — that's the
//! Phase 0.5.0 surface and is the right home for authentication-tag
//! semantics. Using a raw hash function as a MAC is a security mistake;
//! we do not expose `Hash::with_key` here for that reason.
//!
//! # Example
//!
//! ```
//! # #[cfg(feature = "hash-blake3")] {
//! use crypt_io::hash;
//!
//! let digest = hash::blake3(b"the quick brown fox");
//! assert_eq!(digest.len(), 32);
//! # }
//! ```
//!
//! With a streaming hasher:
//!
//! ```
//! # #[cfg(feature = "hash-blake3")] {
//! use crypt_io::hash::Blake3Hasher;
//!
//! let mut h = Blake3Hasher::new();
//! h.update(b"first chunk");
//! h.update(b" second chunk");
//! let digest = h.finalize();
//! assert_eq!(digest.len(), 32);
//! # }
//! ```

#[cfg(feature = "hash-blake3")]
mod blake3_impl;
#[cfg(feature = "hash-sha2")]
mod sha2_impl;

#[cfg(feature = "hash-blake3")]
pub use self::blake3_impl::{Blake3Hasher, blake3, blake3_long};
#[cfg(feature = "hash-sha2")]
pub use self::sha2_impl::{Sha256Hasher, Sha512Hasher, sha256, sha512};

/// Length of a BLAKE3 digest, in bytes. Equal to `32`.
#[cfg(feature = "hash-blake3")]
pub const BLAKE3_OUTPUT_LEN: usize = 32;

/// Length of a SHA-256 digest, in bytes. Equal to `32`.
#[cfg(feature = "hash-sha2")]
pub const SHA256_OUTPUT_LEN: usize = 32;

/// Length of a SHA-512 digest, in bytes. Equal to `64`.
#[cfg(feature = "hash-sha2")]
pub const SHA512_OUTPUT_LEN: usize = 64;
