//! Fixed-size authentication tags with constant-time equality.

use core::fmt;

use subtle::ConstantTimeEq;

use crate::error::{Error, Result};

/// An `N`-byte authentication tag (or any other fixed-size value that
/// must be compared without leaking timing), with **constant-time**
/// equality.
///
/// The MAC functions return plain arrays (`[u8; 32]`, `[u8; 64]`), and
/// comparing those with `==` is variable-time: it stops at the first
/// byte that differs, which lets an attacker who can measure response
/// times forge a tag one byte at a time. Wrapping the computed value in
/// a `Tag` makes `==` safe:
///
/// ```
/// # #[cfg(feature = "mac-hmac")] {
/// use crypt_io::{mac, Tag};
///
/// let key = b"shared secret";
/// let received: &[u8] = &mac::hmac_sha256(key, b"body")?; // from the wire
///
/// let expected = Tag::from(mac::hmac_sha256(key, b"body")?);
/// assert!(expected == *received);       // constant time
/// assert!(expected.ct_eq(received));    // same thing, spelled out
/// # }
/// # Ok::<(), crypt_io::Error>(())
/// ```
///
/// For the common "compute and compare" case the `*_check` functions
/// in [`mac`](crate::mac) do both steps and return
/// [`Error::AuthenticationFailed`] on a mismatch.
///
/// Comparing against a slice of a different length returns `false`
/// (the length is not secret). `Tag` deliberately does not implement
/// `Deref` to the array, `Ord` or `Hash`, so it cannot be compared in
/// variable time by accident. Use [`as_bytes`](Self::as_bytes) to get
/// at the bytes for encoding.
#[derive(Clone, Copy)]
pub struct Tag<const N: usize>([u8; N]);

impl<const N: usize> Tag<N> {
    /// Wrap `bytes`.
    #[must_use]
    pub const fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Borrow the tag bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }

    /// Return the tag bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; N] {
        self.0
    }

    /// Length of the tag in bytes (`N`).
    #[must_use]
    pub const fn len(&self) -> usize {
        N
    }

    /// `true` only for a zero-length tag.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }

    /// Compare against `other` in constant time. Returns `false` when
    /// the lengths differ.
    #[must_use]
    pub fn ct_eq(&self, other: &[u8]) -> bool {
        other.len() == N && bool::from(self.0.as_slice().ct_eq(other))
    }
}

impl<const N: usize> From<[u8; N]> for Tag<N> {
    fn from(bytes: [u8; N]) -> Self {
        Self(bytes)
    }
}

impl<const N: usize> From<Tag<N>> for [u8; N] {
    fn from(tag: Tag<N>) -> Self {
        tag.0
    }
}

impl<const N: usize> TryFrom<&[u8]> for Tag<N> {
    type Error = Error;

    /// Copy a slice of exactly `N` bytes into a tag.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidInput`] if `bytes.len() != N`.
    fn try_from(bytes: &[u8]) -> Result<Self> {
        <[u8; N]>::try_from(bytes)
            .map(Self)
            .map_err(|_| Error::InvalidInput("tag has the wrong length"))
    }
}

impl<const N: usize> AsRef<[u8]> for Tag<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> PartialEq for Tag<N> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(&other.0)
    }
}

impl<const N: usize> Eq for Tag<N> {}

impl<const N: usize> PartialEq<[u8; N]> for Tag<N> {
    fn eq(&self, other: &[u8; N]) -> bool {
        self.ct_eq(other)
    }
}

impl<const N: usize> PartialEq<[u8]> for Tag<N> {
    fn eq(&self, other: &[u8]) -> bool {
        self.ct_eq(other)
    }
}

impl<const N: usize> PartialEq<&[u8]> for Tag<N> {
    fn eq(&self, other: &&[u8]) -> bool {
        self.ct_eq(other)
    }
}

impl<const N: usize> fmt::Debug for Tag<N> {
    /// Tags are public values (they travel next to the message), so
    /// `Debug` prints them as hex.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Tag(")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use alloc::format;

    #[test]
    fn equality_is_by_value() {
        let a = Tag::new([1u8; 32]);
        let mut other = [1u8; 32];
        assert_eq!(a, Tag::new(other));
        assert_eq!(a, other);
        assert_eq!(a, other[..]);
        other[31] ^= 1;
        assert_ne!(a, Tag::new(other));
        assert_ne!(a, other);
        assert!(!a.ct_eq(&other));
    }

    #[test]
    fn length_mismatch_is_unequal() {
        let a = Tag::new([7u8; 16]);
        assert!(!a.ct_eq(&[7u8; 15]));
        assert!(!a.ct_eq(&[7u8; 17]));
        assert!(!a.ct_eq(&[]));
        assert_ne!(a, [7u8; 15][..]);
    }

    #[test]
    fn try_from_checks_length() {
        let t = Tag::<4>::try_from(&[1u8, 2, 3, 4][..]).unwrap();
        assert_eq!(t.into_bytes(), [1, 2, 3, 4]);
        assert_eq!(
            Tag::<4>::try_from(&[1u8, 2, 3][..]).unwrap_err(),
            Error::InvalidInput("tag has the wrong length")
        );
    }

    #[test]
    fn debug_is_hex() {
        assert_eq!(format!("{:?}", Tag::new([0xab, 0x01])), "Tag(ab01)");
    }
}
