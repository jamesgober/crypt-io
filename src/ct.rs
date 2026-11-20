//! Constant-time byte comparison, decided by one `subtle` comparison.
//!
//! `subtle`'s slice comparison puts an optimisation barrier after every
//! byte, about 50 ns for a 16-byte tag. Here the XOR of each pair of
//! 8-byte words (and of any tail bytes) is combined with OR into one
//! accumulator, which is never branched on, and a single `subtle`
//! comparison of the accumulator with zero gives the answer. The work
//! is the same whatever the inputs are; a 16-, 32- or 64-byte tag
//! compares in a few nanoseconds.
//! This is the structure of the `constant_time_eq` crate, with `subtle`
//! as the barrier. [`Tag`](crate::Tag) equality, the HMAC checks and the
//! OTP checks use it.

use subtle::{Choice, ConstantTimeEq};

/// Constant-time equality of two equal-length slices. The caller
/// checks the lengths, which are not secret.
#[inline]
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> Choice {
    debug_assert_eq!(a.len(), b.len());
    let (wa, wb) = (a.chunks_exact(8), b.chunks_exact(8));
    let mut diff = 0u64;
    for (x, y) in wa.remainder().iter().zip(wb.remainder()) {
        diff |= u64::from(x ^ y);
    }
    for (x, y) in wa.zip(wb) {
        let mut wx = [0u8; 8];
        let mut wy = [0u8; 8];
        wx.copy_from_slice(x);
        wy.copy_from_slice(y);
        diff |= u64::from_ne_bytes(wx) ^ u64::from_ne_bytes(wy);
    }
    diff.ct_eq(&0)
}

#[cfg(test)]
mod tests {
    use super::ct_eq;

    #[test]
    fn matches_plain_equality() {
        for len in 0..=70 {
            let a: alloc::vec::Vec<u8> = (0u8..)
                .take(len)
                .map(|i| i.wrapping_mul(31).wrapping_add(7))
                .collect();
            assert!(bool::from(ct_eq(&a, &a)), "len {len}");
            for at in 0..len {
                for bit in [0x01, 0x80] {
                    let mut b = a.clone();
                    b[at] ^= bit;
                    assert!(!bool::from(ct_eq(&a, &b)), "len {len} at {at}");
                }
            }
        }
    }
}
