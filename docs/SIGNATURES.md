# Strict detached Ed25519 verification

The optional `signature-ed25519` feature is a deliberately narrow public-key
boundary for verifying an already-defined byte sequence. It is suitable for
signed manifests and artifacts whose owning product has already specified the
exact signed bytes and selected a trusted public key.

Enable it without the default symmetric suite when verification is the only
required operation:

```toml
[dependencies]
crypt-io = { version = "1.1", default-features = false, features = ["signature-ed25519"] }
```

The feature remains compatible with `no_std` consumers. It accepts only:

- one raw 32-byte Ed25519 public key;
- one raw 64-byte detached Ed25519 signature; and
- the exact message byte slice to verify.

`verify_ed25519_detached` applies the upstream strict verification path. It
rejects non-canonical scalar and point encodings, weak public keys, malformed
keys or signatures, changed messages, and signatures made by a different key.
Every cryptographic rejection becomes the same opaque
`SignatureError::VerificationFailed`; upstream diagnostic distinctions are not
exposed as a verification oracle. Wrong fixed-width input lengths are rejected
before verification with typed length errors.

## Caller-owned contract

The caller must:

1. obtain the public key from a trusted, authenticated source;
2. define which exact bytes are signed, including any domain prefix;
3. parse and validate its manifest or artifact format strictly;
4. enforce product policy such as key IDs, revocation, expiry, version, and
   rollback prevention; and
5. call the verifier before trusting or processing the authenticated content.

The verifier performs no hashing or canonicalization before Ed25519. If a
format signs canonical JSON, a digest, or a domain-separated envelope, the
format owner must construct those exact bytes. Verifying one representation
and consuming another is a product-layer vulnerability that this primitive
cannot prevent.

## Deliberately absent

This feature provides no:

- signing or secret-key type;
- key-pair generation;
- PKCS#8, PEM, DER, JWK, or certificate parsing;
- trust-root discovery, rotation, or revocation policy;
- file or network access;
- package download or update logic;
- manifest parser; or
- implicit prehash, normalization, or canonicalization.

Those responsibilities remain with the product layer or a purpose-built
public-key library. Keeping them out of `crypt-io` makes the embedded
verification boundary small enough to audit independently.

## Dependency and evidence

The feature exact-pins `ed25519-dalek` 3.0.0 with all upstream default features
disabled and calls its inherent `VerifyingKey::verify_strict` method. No
`rand_core`, signing, serialization, digest-context, batch, PKCS#8, PEM,
`serde`, or precomputed-table feature is enabled. The complete graph supports
the crate's Rust 1.85 MSRV.

Tests include the RFC 8032 known-answer vectors and all 150 applicable cases
from the pinned C2SP/Wycheproof Ed25519 corpus: 88 valid and 62 invalid. The
invalid set includes truncated and oversized signatures, malformed encodings,
weak points, and signature-malleability cases. A dedicated fuzz target feeds
hostile fixed-width keys, signatures, and bounded messages through the same
public API.
