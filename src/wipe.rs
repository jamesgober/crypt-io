//! Crate-internal helpers for overwriting secret bytes.
//!
//! With the `zeroize` feature (default on) every helper goes through
//! the `zeroize` crate, whose volatile writes the optimiser cannot
//! remove. Without the feature the same bytes are overwritten with
//! plain writes followed by `core::hint::black_box`, which is best
//! effort only.

use alloc::vec::Vec;

/// Overwrite every byte of `v`'s allocation (its length *and* its
/// spare capacity) with zeros, then set its length to zero. The
/// allocation itself is kept so callers can reuse it.
pub(crate) fn wipe_vec(v: &mut Vec<u8>) {
    #[cfg(feature = "zeroize")]
    {
        // `Zeroize for Vec<u8>` zeroes the full capacity and clears.
        zeroize::Zeroize::zeroize(v);
    }
    #[cfg(not(feature = "zeroize"))]
    {
        let cap = v.capacity();
        v.clear();
        v.resize(cap, 0);
        let _ = core::hint::black_box(v.as_mut_slice());
        v.clear();
    }
}

/// Overwrite `bytes` with zeros.
#[cfg(feature = "stream")]
pub(crate) fn wipe_bytes(bytes: &mut [u8]) {
    #[cfg(feature = "zeroize")]
    {
        zeroize::Zeroize::zeroize(bytes);
    }
    #[cfg(not(feature = "zeroize"))]
    {
        bytes.fill(0);
        let _ = core::hint::black_box(bytes);
    }
}

/// Overwrite `v[start..]` with zeros and truncate `v` to `start`.
/// Bytes before `start` are left untouched.
#[cfg(feature = "stream")]
pub(crate) fn wipe_tail(v: &mut Vec<u8>, start: usize) {
    if let Some(tail) = v.get_mut(start..) {
        wipe_bytes(tail);
    }
    v.truncate(start);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn wipe_vec_zeroes_spare_capacity_and_keeps_allocation() {
        let mut v = vec![0xa5u8; 64];
        v.truncate(10);
        let cap = v.capacity();
        wipe_vec(&mut v);
        assert_eq!(v.len(), 0);
        assert_eq!(v.capacity(), cap);
        // Read the old contents back through the spare capacity.
        let spare = v.spare_capacity_mut();
        for b in &spare[..64] {
            // SAFETY: bytes 0..64 were initialised by `vec![0xa5; 64]`
            // and then overwritten by `wipe_vec`; none were ever
            // de-initialised.
            assert_eq!(unsafe { b.assume_init() }, 0);
        }
    }

    #[cfg(feature = "stream")]
    #[test]
    fn wipe_tail_only_touches_the_tail() {
        let mut v = vec![1u8, 2, 3, 4, 5];
        wipe_tail(&mut v, 2);
        assert_eq!(v, [1, 2]);
        let spare = v.spare_capacity_mut();
        for b in &spare[..3] {
            // SAFETY: these three bytes were initialised by the `vec!`
            // literal and then overwritten by `wipe_tail`.
            assert_eq!(unsafe { b.assume_init() }, 0);
        }
    }
}
