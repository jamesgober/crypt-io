//! Minimal AEAD round-trip: encrypt some bytes, decrypt them back.
//!
//! Run with:
//!     cargo run --example aead_round_trip

use crypt_io::{Algorithm, Crypt, generate_key};

fn main() -> Result<(), crypt_io::Error> {
    // Your 256-bit symmetric key. In production this comes from
    // `key-vault`, a KMS, an HKDF expansion of a master, or
    // `generate_key()` — never from a hard-coded literal. The key is
    // wiped when `key` goes out of scope.
    let key = generate_key()?;

    // Default is ChaCha20-Poly1305 — post-quantum-safe at 256-bit
    // strength, fast in software on every platform.
    let chacha = Crypt::new();

    let plaintext = b"attack at dawn";
    let ciphertext = chacha.encrypt(&*key, plaintext)?;
    let recovered = chacha.decrypt(&*key, &ciphertext)?;
    println!(
        "ChaCha20-Poly1305:  {:?}",
        core::str::from_utf8(&recovered).unwrap()
    );
    assert_eq!(&*recovered, plaintext);

    // Switch to AES-256-GCM — same surface, hardware-accelerated on
    // AES-NI / ARMv8.
    let aes = Crypt::aes_256_gcm();
    assert_eq!(aes.algorithm(), Algorithm::Aes256Gcm);
    let ciphertext = aes.encrypt(&*key, plaintext)?;
    let recovered = aes.decrypt(&*key, &ciphertext)?;
    println!(
        "AES-256-GCM:        {:?}",
        core::str::from_utf8(&recovered).unwrap()
    );

    // XChaCha20-Poly1305: 24-byte random nonces, for keys that encrypt
    // more than 2^32 messages.
    let xchacha = Crypt::xchacha20_poly1305();
    let ciphertext = xchacha.encrypt(&*key, plaintext)?;
    let recovered = xchacha.decrypt_zeroizing(&*key, &ciphertext)?; // wiped on drop
    println!(
        "XChaCha20-Poly1305: {:?}",
        core::str::from_utf8(&recovered).unwrap()
    );

    // With additional authenticated data — authenticated but not
    // encrypted. Identical AAD must be supplied on the decrypt side
    // or authentication fails.
    let aad = b"context:session:42";
    let ciphertext = chacha.encrypt_with_aad(&*key, plaintext, aad)?;
    let recovered = chacha.decrypt_with_aad(&*key, &ciphertext, aad)?;
    println!(
        "AEAD with AAD:      {:?}",
        core::str::from_utf8(&recovered).unwrap()
    );

    // The sealed format records the algorithm, so the reader does not
    // need to know it: any handle opens it.
    let sealed = xchacha.seal(&*key, plaintext)?;
    assert_eq!(
        Crypt::sealed_algorithm(&sealed)?,
        Algorithm::XChaCha20Poly1305
    );
    let recovered = Crypt::new().open(&*key, &sealed)?;
    println!(
        "Sealed (XChaCha):   {:?}",
        core::str::from_utf8(&recovered).unwrap()
    );

    Ok(())
}
