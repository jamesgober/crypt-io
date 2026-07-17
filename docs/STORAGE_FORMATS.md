# Authenticated storage formats

The opt-in `storage-v1` feature exposes `crypt_io::storage`, a storage-engine
boundary distinct from crypt-io's frozen 1.0 root API and legacy
`crypt_io::stream` wire format. Enabling it is additive: the default feature
set, no-default build, root `Error` and `Result`, and all established 1.0 bytes
remain unchanged.

## Ownership boundary

crypt-io owns versioned authenticated encoding, key derivation, nonce
generation, strict parsing, rotation primitives, and zeroization of transient
key/plaintext buffers. The host owns master-key custody, authorization,
recovery, opaque scope derivation, synchronization, crash-safe staging, and
atomic publication.

`KeyProvider` returns a short-lived `KeyLease` containing a stable 16-byte key
identifier, monotonic generation, and 32-byte master key. The provider must
enforce access to each `KeyScope`. `SpaceId` must be a host-prederived opaque
value; raw tenant, user, agent, path, or other principal data must not be
placed in it. A distinct 16-byte `PurposeId` prevents cross-purpose key reuse.

Each (`KeyScope`, `KeyId`, `KeyGeneration`) tuple must map immutably to exactly
one 32-byte master secret for the complete retention lifetime of every
referencing ciphertext. Never reuse a descriptor for different material.
`active` generations must increase monotonically within a scope, and `by_id`
must retain and return historical mappings while references can exist. Retire a
mapping only after migration has authenticated the source, durably published
the replacement, and durably eliminated every old reference. Ordinary `seal`
cannot detect silent descriptor reuse; reuse can make prior objects
unrecoverable. Every same-scope replacement must use independently generated
master material distinct from the source and all prior generations. Rotation
compares the authenticated source and active secrets in constant time and
rejects identical replacement material. Cross-scope migration deliberately
does not impose this comparison; any master-key sharing between scopes must be
an explicit host policy.

The safe sealing APIs obtain operating-system entropy through exact-pinned
`getrandom` 0.4.3. They do not accept caller-selected salts or nonces.
AES-256-GCM authenticates every object;
HKDF-SHA256 derives per-object keys from scope, suite, salt, key identifier,
and key generation. Caller context is stored only as a keyed verifier, not as
raw bytes or an unkeyed dictionary oracle. `RecordContext::new` and
`StreamContext::new` are fallible and accept at most 64 KiB, bounding the
attacker-controlled SHA-256 work performed while compacting metadata. Hosts
must reduce larger inputs to a product-defined, domain-separated identifier.

## Freshness and rollback boundary

Records and streams authenticate the logical sequence supplied by their caller,
but crypt-io has no trusted view of which sequence is newest. An old valid
ciphertext will authenticate whenever the host reuses its old expected scope,
context, and logical sequence. Random nonces prevent nonce reuse, AEAD prevents
undetected modification, and key generations select key material; none of them
provides whole-object freshness or rollback protection.

The host must persist and integrity-protect a monotonic object or snapshot
sequence outside the ciphertext, bind that value through `RecordContext` or
`StreamContext`, and reject any object whose expected sequence is not the
current durable value. Publication must atomically advance the protected
sequence with the new object, or use an equivalent WAL/transaction protocol
whose recovery cannot expose the new sequence with old bytes or the old
sequence with new bytes. Same-sequence replay remains intentionally
indistinguishable from rereading the same valid object.

## SealedRecord v1

`RecordCodec` accepts at most 16 MiB of plaintext. The encoded object starts
with `CRIOREC\0` and a fixed 176-byte version-one header, followed by ciphertext
and a 16-byte authentication tag. The complete header is AEAD associated data.
Opening requires the expected `KeyScope` and `RecordContext`; structural
parsing alone never implies authenticity.

`rotate` authenticates with the encoded key descriptor and reseals only when
the provider's active generation is newer. `migrate` additionally changes the
scope and caller context. These operations produce bytes; they do not perform
the host's atomic replace or durability protocol.

## EncryptedStream v1

The stream starts with `CRIOSTR\0` and a fixed 160-byte header. Every data frame
has a 48-byte authenticated header, ciphertext, and a 16-byte tag. Each frame
binds its sequence and the previous frame tag. A mandatory authenticated final
frame binds total data-frame count and plaintext length, so truncation,
reordering, duplication, and splicing fail closed.

The buffered codec accepts at most 64 MiB and 65,536 data frames. Incremental
reader/writer types use the same format without buffering the complete stream.
Frame plaintext is configurable from 1 byte through 16 MiB; the default is
1 MiB. Version one reserves one AES-GCM invocation for the final frame and
therefore permits at most `2^32 - 1` data frames under one derived key.

Incremental reads distinguish authenticated prefixes from complete streams.
An authenticated prefix is recovery evidence, not a successful object: only a
verified final frame yields completion. If any buffered open fails after an
earlier frame, accumulated plaintext is zeroized before the error returns.

## Failure and publication rules

Malformed, oversized, over-limit context, truncated, trailing, wrong-scope, wrong-context,
wrong-sequence, wrong-key, and authentication failures return typed errors and
no unauthenticated plaintext. Provider errors are mapped to sanitized public
states; debug output redacts secrets, raw space identifiers, caller context,
plaintext, and ciphertext.

Rotation and migration are deliberately not filesystem transactions. A host
must write the new object to bounded staging, make it durable, atomically
publish it under its own synchronization, and only then retire the old object
or key generation. A crash before publication must leave the previous
authenticated object available. crypt-io does not replace a database WAL or
claim durability for bytes it did not publish.

## Verification

The format suite includes boundary and hostile-input tests, provider-failure
contracts, wrong-key/context/sequence tests, rotation and migration tests,
buffered/incremental equivalence, fixed wire fixtures, Wycheproof AES-GCM,
HKDF-SHA256, and HMAC-SHA256 vectors, compile-time zeroization checks, and four
storage fuzz targets. Criterion baselines live in `benches/storage.rs`.
