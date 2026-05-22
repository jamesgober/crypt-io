//! Encrypt a file into another file, then decrypt back. Uses chunked
//! AEAD with the STREAM construction — works for files of any size,
//! detects tampering / truncation / reordering.
//!
//! Run with:
//!     cargo run --example encrypt_file

use std::io::Write;

use crypt_io::Algorithm;
use crypt_io::stream;

fn main() -> Result<(), crypt_io::Error> {
    // Create some test data — pretend this is a 200 KB file.
    let dir = std::env::temp_dir();
    let input_path = dir.join("crypt_io_example_input.bin");
    let encrypted_path = dir.join("crypt_io_example_encrypted.bin");
    let decrypted_path = dir.join("crypt_io_example_decrypted.bin");

    let plaintext: Vec<u8> = (0..200_000u32).map(|i| (i & 0xff) as u8).collect();
    {
        let mut f = std::fs::File::create(&input_path).expect("create input file");
        f.write_all(&plaintext).expect("write input file");
    }

    let key = [0x42u8; 32];

    // Encrypt input_path → encrypted_path.
    stream::encrypt_file(
        &input_path,
        &encrypted_path,
        &key,
        Algorithm::ChaCha20Poly1305,
    )?;
    let enc_size = std::fs::metadata(&encrypted_path).expect("stat enc").len();
    println!(
        "Encrypted {} bytes → {} bytes ({} bytes of overhead)",
        plaintext.len(),
        enc_size,
        enc_size as i64 - plaintext.len() as i64,
    );

    // Decrypt encrypted_path → decrypted_path.
    stream::decrypt_file(&encrypted_path, &decrypted_path, &key)?;
    let recovered = std::fs::read(&decrypted_path).expect("read decrypted");
    assert_eq!(recovered, plaintext);
    println!(
        "Decrypted matches the original — {} bytes recovered.",
        recovered.len()
    );

    // Tamper-detection demo: flip one byte in the encrypted file,
    // try to decrypt, watch authentication fail.
    {
        let mut enc = std::fs::read(&encrypted_path).expect("read enc for tamper");
        let mid = enc.len() / 2;
        enc[mid] ^= 0x01;
        std::fs::write(&encrypted_path, &enc).expect("write tampered");
    }
    let tampered_out = dir.join("crypt_io_example_tampered.bin");
    match stream::decrypt_file(&encrypted_path, &tampered_out, &key) {
        Ok(_) => panic!("tampered file should not decrypt"),
        Err(e) => println!("Tampered file rejected: {e}"),
    }
    // IMPORTANT: when decrypt fails on a partially-written output,
    // delete it. Otherwise an attacker who can corrupt later chunks
    // could leak earlier plaintext to disk.
    let _ = std::fs::remove_file(&tampered_out);

    // Cleanup.
    let _ = std::fs::remove_file(&input_path);
    let _ = std::fs::remove_file(&encrypted_path);
    let _ = std::fs::remove_file(&decrypted_path);

    Ok(())
}
