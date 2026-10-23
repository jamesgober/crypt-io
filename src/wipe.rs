//! Overwriting secret bytes.
//!
//! [`wipe`] and [`wipe_vec`] are public (re-exported at the crate
//! root since 1.2.0); the other helpers are crate-internal.
//!
//! With the `zeroize` feature (default on) every helper goes through
//! the `zeroize` crate, whose volatile writes the optimiser cannot
//! remove. Without the feature the same bytes are overwritten with
//! plain writes followed by `core::hint::black_box`, which is best
//! effort only.

use alloc::vec::Vec;

/// Overwrite every byte of `bytes` with zeros.
///
/// With the `zeroize` feature (default on) the writes are volatile,
/// so the compiler cannot remove them even when `bytes` is never read
/// again. Without the feature the bytes are zeroed with plain writes
/// followed by `core::hint::black_box`, which stops the optimiser in
/// practice but is not guaranteed; enable `zeroize` for any buffer
/// that held secrets.
///
/// Only the bytes of the slice itself are touched. Copies left
/// elsewhere (an earlier `Vec` reallocation, a moved value) are out of
/// reach; for a `Vec` use [`wipe_vec`], which also clears its spare
/// capacity.
///
/// New in 1.2.0.
///
/// # Example
///
/// ```
/// let mut secret = *b"session token";
/// crypt_io::wipe(&mut secret);
/// assert!(secret.iter().all(|&b| b == 0));
/// ```
#[inline]
pub fn wipe(bytes: &mut [u8]) {
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

/// Overwrite every byte of `v`'s allocation (its length *and* its
/// spare capacity) with zeros, then set its length to zero.
///
/// The allocation is kept, so the buffer can be reused without a new
/// allocation. Bytes past the current length can still hold data from
/// before a `truncate` or `clear`; this function wipes them too.
///
/// Same guarantee as [`wipe`]: volatile writes with the `zeroize`
/// feature (default on), best effort without it.
///
/// New in 1.2.0.
///
/// # Example
///
/// ```
/// let mut buf = b"response body".to_vec();
/// let capacity = buf.capacity();
/// crypt_io::wipe_vec(&mut buf);
/// assert!(buf.is_empty());
/// assert_eq!(buf.capacity(), capacity);
/// ```
pub fn wipe_vec(v: &mut Vec<u8>) {
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
#[cfg(any(feature = "aead-chacha20", feature = "aead-aes-gcm"))]
#[inline]
pub(crate) fn reserve_wiping(v: &mut Vec<u8>, additional: usize) {
    if v.capacity() - v.len() < additional {
        grow_wiping(v, additional);
    }
}

#[cfg(any(feature = "aead-chacha20", feature = "aead-aes-gcm"))]
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
    wipe(v);
    v.clear();
}

/// Overwrite `v[start..]` with zeros and truncate `v` to `start`.
/// Bytes before `start` are left untouched.
#[cfg(feature = "stream")]
pub(crate) fn wipe_tail(v: &mut Vec<u8>, start: usize) {
    if let Some(tail) = v.get_mut(start..) {
        wipe(tail);
    }
    v.truncate(start);
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn wipe_zeroes_every_byte() {
        let mut buf: [u8; 256] = core::array::from_fn(|i| u8::try_from(i).unwrap() | 1);
        wipe(&mut buf);
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn wipe_empty_slice_is_a_no_op() {
        let mut empty: [u8; 0] = [];
        wipe(&mut empty);
        let mut v: Vec<u8> = Vec::new();
        wipe(&mut v);
        assert_eq!(v.len(), 0);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn wipe_large_slice() {
        let mut big = vec![0xffu8; 4 * 1024 * 1024 + 7];
        wipe(&mut big);
        assert_eq!(big.len(), 4 * 1024 * 1024 + 7);
        assert!(big.iter().all(|&b| b == 0));
    }

    #[test]
    fn wipe_touches_only_the_given_slice() {
        let mut buf = [7u8; 16];
        wipe(&mut buf[4..12]);
        assert_eq!(buf[..4], [7; 4]);
        assert_eq!(buf[4..12], [0; 8]);
        assert_eq!(buf[12..], [7; 4]);
    }

    #[test]
    fn wipe_vec_zeroes_the_whole_capacity() {
        let mut v = Vec::with_capacity(4096);
        v.extend(core::iter::repeat_n(0xa5u8, 3000));
        v.truncate(100);
        let cap = v.capacity();
        wipe_vec(&mut v);
        assert_eq!(v.len(), 0);
        assert_eq!(v.capacity(), cap);
        let spare = v.spare_capacity_mut();
        assert_eq!(spare.len(), cap);
        for b in spare.iter() {
            // SAFETY: `wipe_vec` writes a zero to every byte of the
            // capacity, including the bytes that were never written
            // before, so the whole allocation is initialised.
            assert_eq!(unsafe { b.assume_init() }, 0);
        }
    }

    #[test]
    fn wipe_vec_on_an_empty_vec() {
        let mut v: Vec<u8> = Vec::new();
        wipe_vec(&mut v);
        assert_eq!(v.len(), 0);
        assert_eq!(v.capacity(), 0);
    }

    #[test]
    fn wipe_vec_leaves_the_buffer_reusable() {
        let mut v = b"first response".to_vec();
        let cap = v.capacity();
        wipe_vec(&mut v);
        v.extend_from_slice(b"second");
        assert_eq!(v, b"second");
        assert_eq!(v.capacity(), cap);
    }

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

    #[cfg(any(feature = "aead-chacha20", feature = "aead-aes-gcm"))]
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
