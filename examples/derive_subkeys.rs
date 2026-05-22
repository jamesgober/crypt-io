//! Derive multiple uncorrelated subkeys from a single master key with
//! HKDF. The standard pattern for splitting one secret into many.
//!
//! Run with:
//!     cargo run --example derive_subkeys

use crypt_io::kdf;

fn main() -> Result<(), crypt_io::Error> {
    // A 256-bit master key. In production this comes from a KMS, a
    // sealed `key-vault` handle, an envelope-encrypted file, etc.
    let master = [0x42u8; 32];

    // The `info` parameter is the domain separator — it binds a
    // derived key to a specific purpose. Two `hkdf_sha256` calls
    // with the same `(master, salt)` but different `info` produce
    // independent, uncorrelated outputs.
    //
    // Convention: include the application, the role, and a version.
    // `app:role:vN`. The version lets you rotate later without
    // touching the master.
    let encrypt_key = kdf::hkdf_sha256(&master, None, b"myapp:encrypt:v1", 32)?;
    let mac_key = kdf::hkdf_sha256(&master, None, b"myapp:mac:v1", 32)?;
    let session_key = kdf::hkdf_sha256(&master, None, b"myapp:session:v1", 32)?;

    println!("encrypt_key[..8] = {:02x?}", &encrypt_key[..8]);
    println!("mac_key[..8]     = {:02x?}", &mac_key[..8]);
    println!("session_key[..8] = {:02x?}", &session_key[..8]);

    // They are independent:
    assert_ne!(encrypt_key, mac_key);
    assert_ne!(encrypt_key, session_key);
    assert_ne!(mac_key, session_key);

    // The same inputs always produce the same output (deterministic):
    let again = kdf::hkdf_sha256(&master, None, b"myapp:encrypt:v1", 32)?;
    assert_eq!(encrypt_key, again);
    println!("Re-derivation matches — KDF is deterministic.");

    // Pass a salt when you have one — e.g., a per-user random value
    // stored alongside the user record. Per-instance salts make the
    // derived keys per-instance even when the master is shared.
    let user_salt = b"random-user-salt-stored-in-db";
    let user_key = kdf::hkdf_sha256(&master, Some(user_salt), b"myapp:user:v1", 32)?;
    println!("user_key[..8]    = {:02x?}", &user_key[..8]);
    assert_ne!(encrypt_key, user_key);

    // For deriving more than 32 bytes (e.g., key + IV combined), use
    // a larger `len` or `hkdf_sha512`.
    let big = kdf::hkdf_sha256(&master, None, b"myapp:bundle:v1", 96)?;
    let (k1, rest) = big.split_at(32);
    let (k2, k3) = rest.split_at(32);
    println!(
        "3-way split: k1[..4]={:02x?}, k2[..4]={:02x?}, k3[..4]={:02x?}",
        &k1[..4],
        &k2[..4],
        &k3[..4],
    );

    Ok(())
}
