//! SHA-2 backend (SHA-256 + SHA-512).
//!
//! Thin wrapper over the `sha2` crate (`RustCrypto`). The wrapper exposes
//! one-shot free functions and matching streaming hashers.
//!
//! SHA-2 ships for ecosystem interop (TLS, JWT, certificate fingerprints,
//! Bitcoin, anywhere a spec names SHA-256 or SHA-512). For raw throughput
//! prefer [`super::blake3`] — it is typically 4–10× faster on modern
//! hardware.

use sha2::Digest;
use sha2::{Sha256, Sha512};

use super::{SHA256_OUTPUT_LEN, SHA512_OUTPUT_LEN};

/// Compute a 32-byte SHA-256 digest of `data`.
///
/// # Example
///
/// ```
/// # #[cfg(feature = "hash-sha2")] {
/// use crypt_io::hash;
/// let d = hash::sha256(b"abc");
/// assert_eq!(d.len(), 32);
/// # }
/// ```
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; SHA256_OUTPUT_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute a 64-byte SHA-512 digest of `data`.
///
/// # Example
///
/// ```
/// # #[cfg(feature = "hash-sha2")] {
/// use crypt_io::hash;
/// let d = hash::sha512(b"abc");
/// assert_eq!(d.len(), 64);
/// # }
/// ```
#[must_use]
pub fn sha512(data: &[u8]) -> [u8; SHA512_OUTPUT_LEN] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Streaming SHA-256 hasher for inputs that don't fit in memory.
///
/// # Example
///
/// ```
/// # #[cfg(feature = "hash-sha2")] {
/// use crypt_io::hash::Sha256Hasher;
///
/// let mut h = Sha256Hasher::new();
/// h.update(b"first ");
/// h.update(b"second");
/// let d = h.finalize();
/// assert_eq!(d.len(), 32);
/// # }
/// ```
#[derive(Debug, Clone, Default)]
pub struct Sha256Hasher {
    inner: Sha256,
}

impl Sha256Hasher {
    /// Construct a fresh hasher.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Sha256::new(),
        }
    }

    /// Absorb `data` into the running hash. Returns `&mut Self` so calls
    /// can chain.
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.inner.update(data);
        self
    }

    /// Finalise the hash and return the 32-byte digest. Consumes the hasher.
    #[must_use]
    pub fn finalize(self) -> [u8; SHA256_OUTPUT_LEN] {
        self.inner.finalize().into()
    }
}

/// Streaming SHA-512 hasher for inputs that don't fit in memory.
///
/// # Example
///
/// ```
/// # #[cfg(feature = "hash-sha2")] {
/// use crypt_io::hash::Sha512Hasher;
///
/// let mut h = Sha512Hasher::new();
/// h.update(b"first ");
/// h.update(b"second");
/// let d = h.finalize();
/// assert_eq!(d.len(), 64);
/// # }
/// ```
#[derive(Debug, Clone, Default)]
pub struct Sha512Hasher {
    inner: Sha512,
}

impl Sha512Hasher {
    /// Construct a fresh hasher.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Sha512::new(),
        }
    }

    /// Absorb `data` into the running hash. Returns `&mut Self` so calls
    /// can chain.
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.inner.update(data);
        self
    }

    /// Finalise the hash and return the 64-byte digest. Consumes the hasher.
    #[must_use]
    pub fn finalize(self) -> [u8; SHA512_OUTPUT_LEN] {
        self.inner.finalize().into()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, unused_results)]
mod tests {
    use super::*;

    fn hex_to_bytes(s: &str) -> alloc::vec::Vec<u8> {
        hex::decode(s).expect("valid hex")
    }

    // --- SHA-256 known-answer tests (FIPS 180-4 Appendix B / RFC 6234). ---

    /// FIPS 180-4 B.1: SHA-256("abc")
    #[test]
    fn sha256_kat_abc() {
        let expected =
            hex_to_bytes("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(&sha256(b"abc")[..], &expected[..]);
    }

    /// FIPS 180-4 B.2: SHA-256 over the 56-byte
    /// "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" input.
    #[test]
    fn sha256_kat_two_block() {
        let input = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let expected =
            hex_to_bytes("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
        assert_eq!(&sha256(input)[..], &expected[..]);
    }

    /// FIPS 180-4 also covers the empty-input vector.
    #[test]
    fn sha256_kat_empty() {
        let expected =
            hex_to_bytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(&sha256(b"")[..], &expected[..]);
    }

    // --- SHA-512 known-answer tests (FIPS 180-4 Appendix C). ---

    /// FIPS 180-4 C.1: SHA-512("abc")
    #[test]
    fn sha512_kat_abc() {
        let expected = hex_to_bytes(
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        );
        assert_eq!(&sha512(b"abc")[..], &expected[..]);
    }

    /// FIPS 180-4 C.2: SHA-512 over the 112-byte
    /// "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".
    #[test]
    fn sha512_kat_two_block() {
        let input = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let expected = hex_to_bytes(
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018\
             501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
        );
        assert_eq!(&sha512(input)[..], &expected[..]);
    }

    #[test]
    fn sha512_kat_empty() {
        let expected = hex_to_bytes(
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        );
        assert_eq!(&sha512(b"")[..], &expected[..]);
    }

    // --- Streaming-equivalence tests for both algorithms. ---

    #[test]
    fn sha256_streaming_equals_one_shot() {
        let data = b"the quick brown fox jumps over the lazy dog";
        let one_shot = sha256(data);
        let mut h = Sha256Hasher::new();
        h.update(&data[..10]);
        h.update(&data[10..25]);
        h.update(&data[25..]);
        assert_eq!(h.finalize(), one_shot);
    }

    #[test]
    fn sha512_streaming_equals_one_shot() {
        let data = b"the quick brown fox jumps over the lazy dog";
        let one_shot = sha512(data);
        let mut h = Sha512Hasher::new();
        h.update(&data[..10]);
        h.update(&data[10..25]);
        h.update(&data[25..]);
        assert_eq!(h.finalize(), one_shot);
    }

    #[test]
    fn sha256_streaming_chain_returns_self() {
        let mut h = Sha256Hasher::new();
        h.update(b"chain").update(b"-friendly");
        assert_eq!(h.finalize(), sha256(b"chain-friendly"));
    }

    #[test]
    fn sha512_streaming_chain_returns_self() {
        let mut h = Sha512Hasher::new();
        h.update(b"chain").update(b"-friendly");
        assert_eq!(h.finalize(), sha512(b"chain-friendly"));
    }

    #[test]
    fn sha256_empty_input_through_streaming() {
        let h = Sha256Hasher::new();
        assert_eq!(h.finalize(), sha256(b""));
    }

    #[test]
    fn sha512_empty_input_through_streaming() {
        let h = Sha512Hasher::new();
        assert_eq!(h.finalize(), sha512(b""));
    }
}
