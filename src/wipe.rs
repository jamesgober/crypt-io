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

/// Make room for `additional` more bytes in `v` without leaving a copy
/// of its contents behind.
///
/// `Vec::reserve` reallocates by copying the old allocation (all of
/// its capacity, not just its length) and freeing it without clearing
/// it, so a buffer that held plaintext would leave that plaintext in
/// freed heap memory. This helper allocates the new buffer itself,
/// copies the live bytes across, and wipes the old allocation before
/// it is freed. Growth is amortised (at least doubling), like
/// `Vec::reserve`.
#[inline]
pub(crate) fn reserve_wiping(v: &mut Vec<u8>, additional: usize) {
    if v.capacity() - v.len() < additional {
        grow_wiping(v, additional);
    }
}

#[cold]
#[inline(never)]
fn grow_wiping(v: &mut Vec<u8>, additional: usize) {
    let Some(needed) = v.len().checked_add(additional) else {
        // Unreachable for real inputs; let `Vec` report the overflow.
        v.reserve(additional);
        return;
    };
    let new_cap = needed.max(v.capacity().saturating_mul(2));
    let mut grown = Vec::with_capacity(new_cap);
    grown.extend_from_slice(v);
    wipe_vec(v);
    *v = grown;
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

/// Wipe the first `high_water` bytes of `v`'s allocation (whether they
/// are currently inside its length or in its spare capacity), then
/// clear it.
///
/// For buffers that are only ever written by appending, `high_water`
/// (the largest length the buffer ever had) bounds every byte that
/// ever held data; bytes past it were never written by us. Wiping only
/// that prefix instead of the whole capacity keeps dropping a
/// 64 KiB-capacity stream buffer that saw 1 KiB of data cheap.
#[cfg(feature = "stream")]
pub(crate) fn wipe_vec_upto(v: &mut Vec<u8>, high_water: usize) {
    let n = high_water.min(v.capacity());
    if v.len() < n {
        // Within capacity, so no reallocation.
        v.resize(n, 0);
    }
    wipe_bytes(v);
    v.clear();
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

    #[test]
    fn reserve_wiping_keeps_contents_and_grows() {
        let mut v = vec![9u8; 8];
        v.shrink_to_fit();
        reserve_wiping(&mut v, 100);
        assert_eq!(v, [9u8; 8]);
        assert!(v.capacity() >= 108);
        let cap = v.capacity();
        // Enough room already: no reallocation.
        reserve_wiping(&mut v, 10);
        assert_eq!(v.capacity(), cap);
    }

    #[cfg(feature = "stream")]
    #[test]
    fn wipe_vec_upto_wipes_spare_capacity_below_the_mark() {
        let mut v = vec![0xa5u8; 40];
        v.truncate(10);
        wipe_vec_upto(&mut v, 40);
        assert_eq!(v.len(), 0);
        let spare = v.spare_capacity_mut();
        for b in &spare[..40] {
            // SAFETY: bytes 0..40 were initialised by `vec![0xa5; 40]`
            // and then overwritten by `wipe_vec_upto`.
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
