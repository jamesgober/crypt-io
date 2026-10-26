//! HMAC (RFC 2104) and HKDF (RFC 5869) over the `RustCrypto` SHA-2
//! hashes.
//!
//! Up to 1.2.1 these came from the `hmac` and `hkdf` crates. `hmac`
//! 0.13 compares tags through `digest`'s `mac` feature, which pulls in
//! `ctutils`, and every `ctutils` release that fixes RUSTSEC-2026-0385
//! needs Rust 1.87, above crypt-io's MSRV of 1.85. A Rust 1.85 or 1.86
//! build therefore resolved a vulnerable `ctutils`. Both constructions
//! are a few lines over a hash, so crypt-io builds them here: SHA-2
//! still comes from `sha2`, tag comparison from `subtle`. The output is
//! byte-identical to the crates it replaces (`tests/hmac_hkdf.rs`).
//!
//! With the `zeroize` feature the two hash states, which are derived
//! from the key, are wiped on drop (`sha2` zeroize support). The padded
//! key block, a hashed long key, the inner hash and the HKDF
//! intermediates are wiped before they go out of scope.

use core::fmt;

use sha2::Digest;
use sha2::digest::Output;
#[cfg(feature = "mac-hmac")]
use subtle::ConstantTimeEq;

use crate::wipe::wipe;

/// HMAC-SHA256 state (SHA-256 has a 64-byte block).
#[cfg(feature = "mac-hmac")]
pub(crate) type HmacSha256 = Hmac<sha2::Sha256, 64>;

/// HMAC-SHA512 state (SHA-512 has a 128-byte block).
#[cfg(feature = "mac-hmac")]
pub(crate) type HmacSha512 = Hmac<sha2::Sha512, 128>;

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;

/// HMAC over hash `D` with block size `B` bytes: the inner hash, already
/// fed `K ^ ipad`, and the outer hash, already fed `K ^ opad`.
#[derive(Clone)]
pub(crate) struct Hmac<D, const B: usize> {
    inner: D,
    outer: D,
}

impl<D: Digest + Clone, const B: usize> Hmac<D, B> {
    /// Key the MAC. Any key length works: a key longer than the block
    /// is hashed first, a shorter one is padded with zeros (RFC 2104).
    pub(crate) fn new(key: &[u8]) -> Self {
        let mut block = [0u8; B];
        if key.len() > B {
            let mut hashed = D::digest(key);
            block[..hashed.len()].copy_from_slice(&hashed);
            wipe(&mut hashed);
        } else {
            block[..key.len()].copy_from_slice(key);
        }
        for b in &mut block {
            *b ^= IPAD;
        }
        let mut inner = D::new();
        inner.update(&block[..]);
        for b in &mut block {
            *b ^= IPAD ^ OPAD;
        }
        let mut outer = D::new();
        outer.update(&block[..]);
        wipe(&mut block);
        Self { inner, outer }
    }

    /// Absorb `data`.
    pub(crate) fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Write the tag to `out`.
    pub(crate) fn finalize_into(self, out: &mut Output<D>) {
        let Self { inner, mut outer } = self;
        let mut inner_hash = Output::<D>::default();
        inner.finalize_into(&mut inner_hash);
        outer.update(&inner_hash[..]);
        wipe(&mut inner_hash);
        outer.finalize_into(out);
    }

    /// Return the tag.
    #[cfg(feature = "mac-hmac")]
    pub(crate) fn finalize(self) -> Output<D> {
        let mut tag = Output::<D>::default();
        self.finalize_into(&mut tag);
        tag
    }

    /// Compare the tag with `expected` in constant time. A slice of the
    /// wrong length never matches (the length is not secret).
    #[cfg(feature = "mac-hmac")]
    pub(crate) fn verify(self, expected: &[u8]) -> bool {
        let tag = self.finalize();
        tag.len() == expected.len() && bool::from(ct_eq_words(&tag, expected))
    }
}

/// Constant-time equality of two equal-length slices, a `u64` at a time
/// (any tail byte by byte). `subtle`'s slice comparison puts an
/// optimisation barrier after every byte; words need an eighth of the
/// barriers for the same guarantee.
#[cfg(feature = "mac-hmac")]
fn ct_eq_words(a: &[u8], b: &[u8]) -> subtle::Choice {
    debug_assert_eq!(a.len(), b.len());
    let (wa, wb) = (a.chunks_exact(8), b.chunks_exact(8));
    let mut eq = wa.remainder().ct_eq(wb.remainder());
    for (x, y) in wa.zip(wb) {
        let mut wx = [0u8; 8];
        let mut wy = [0u8; 8];
        wx.copy_from_slice(x);
        wy.copy_from_slice(y);
        eq &= u64::from_ne_bytes(wx).ct_eq(&u64::from_ne_bytes(wy));
    }
    eq
}

impl<D, const B: usize> fmt::Debug for Hmac<D, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the key-derived state.
        f.debug_struct("Hmac").finish_non_exhaustive()
    }
}

/// HKDF extract-then-expand (RFC 5869 §2.2, §2.3) into `out`. `info` is
/// the concatenation of `info_parts`. An absent salt is `HashLen` zero
/// bytes, which HMAC pads to the same block as an empty key.
///
/// The caller checks `out.len() <= 255 * HashLen`.
#[cfg(any(feature = "kdf-hkdf", feature = "stream"))]
pub(crate) fn hkdf<D: Digest + Clone, const B: usize>(
    salt: Option<&[u8]>,
    ikm: &[u8],
    info_parts: &[&[u8]],
    out: &mut [u8],
) {
    debug_assert!(out.len() <= 255 * <D as Digest>::output_size());
    let mut prk = Output::<D>::default();
    let mut extract = Hmac::<D, B>::new(salt.unwrap_or_default());
    extract.update(ikm);
    extract.finalize_into(&mut prk);
    let expand = Hmac::<D, B>::new(&prk);
    wipe(&mut prk);

    // T(i) = HMAC(PRK, T(i - 1) || info || i), with T(0) empty.
    let mut t = Output::<D>::default();
    for (chunk, counter) in out.chunks_mut(<D as Digest>::output_size()).zip(1u8..=255) {
        let mut mac = expand.clone();
        if counter > 1 {
            mac.update(&t);
        }
        for part in info_parts {
            mac.update(part);
        }
        mac.update(&[counter]);
        mac.finalize_into(&mut t);
        chunk.copy_from_slice(&t[..chunk.len()]);
    }
    wipe(&mut t);
}

#[cfg(all(test, feature = "mac-hmac"))]
mod tests {
    use super::ct_eq_words;

    #[test]
    fn ct_eq_words_matches_plain_equality() {
        for len in 0..=70 {
            let a: alloc::vec::Vec<u8> = (0u8..)
                .take(len)
                .map(|i| i.wrapping_mul(31).wrapping_add(7))
                .collect();
            assert!(bool::from(ct_eq_words(&a, &a)), "len {len}");
            for at in 0..len {
                for bit in [0x01, 0x80] {
                    let mut b = a.clone();
                    b[at] ^= bit;
                    assert!(!bool::from(ct_eq_words(&a, &b)), "len {len} at {at}");
                }
            }
        }
    }
}
