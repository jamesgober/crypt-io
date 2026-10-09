//! Authenticate a message with HMAC-SHA256, then check the tag in
//! constant time. The right way to put a "this came from someone with
//! the key" tag on a message.
//!
//! Run with:
//!     cargo run --example mac_authenticate

use crypt_io::{Error, Tag, mac};

fn main() -> Result<(), Error> {
    let shared_key = b"shared-secret-between-parties";
    let message = b"please transfer $100 to account 12345";

    // ---- Sender ----
    let tag = mac::hmac_sha256(shared_key, message)?;
    println!("tag = {:02x?}", &tag[..]);

    // The sender ships `message || tag` to the receiver. The MAC
    // does not encrypt — it authenticates. Anyone can read the
    // message; only someone with the shared key can produce a tag
    // that checks out.

    // ---- Receiver ----
    // Use `*_check` for the comparison — never `tag == expected` on
    // arrays. The non-constant-time leak is enough to forge tags one
    // byte at a time. A mismatch is `Err(AuthenticationFailed)`, so
    // `?` rejects it.
    mac::hmac_sha256_check(shared_key, message, &tag)?;
    println!("Authentic message:  accepted");

    // Tampered message → rejected.
    let tampered = b"please transfer $1000000 to account 99999";
    let result = mac::hmac_sha256_check(shared_key, tampered, &tag);
    println!("Tampered message:   {result:?}");
    assert_eq!(result, Err(Error::AuthenticationFailed));

    // Wrong key → rejected.
    let wrong_key = b"different-key";
    let result = mac::hmac_sha256_check(wrong_key, message, &tag);
    println!("Wrong key:          {result:?}");
    assert_eq!(result, Err(Error::AuthenticationFailed));

    // If you need to compare tags yourself, wrap them in `Tag`, whose
    // `==` is constant-time.
    let expected = Tag::from(mac::hmac_sha256(shared_key, message)?);
    assert!(expected == tag);

    // BLAKE3 keyed mode — faster than HMAC-SHA256 on modern
    // hardware, type-checked 32-byte key. Use this when both sides
    // are yours and there's no interop requirement.
    let key32 = [0x42u8; 32];
    let tag = mac::blake3_keyed(&key32, message);
    mac::blake3_keyed_check(&key32, message, &tag)?;
    println!("BLAKE3 keyed tag:   accepted");

    // Streaming MAC for large or chunked inputs:
    let mut m = mac::HmacSha256::new(shared_key)?;
    m.update(b"first chunk ");
    m.update(b"second chunk ");
    m.update(b"third chunk");
    let one_shot_tag = mac::hmac_sha256(shared_key, b"first chunk second chunk third chunk")?;
    m.check(&one_shot_tag)?;
    println!("Streaming MAC matches one-shot.");

    Ok(())
}
