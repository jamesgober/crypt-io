//! Hash and verify a password with Argon2id — the use case for any
//! login flow.
//!
//! Run with:
//!     cargo run --example password_hash --release
//!
//! Use `--release` because Argon2id at OWASP-recommended parameters
//! is intentionally slow (~100 ms per hash). A debug build can take
//! several seconds.

use crypt_io::kdf;

fn main() -> Result<(), crypt_io::Error> {
    // On user registration / password change:
    let user_password = b"correct horse battery staple";
    let phc_string = kdf::argon2_hash(user_password)?;

    // `phc_string` is the standard PHC-format encoded hash:
    //     $argon2id$v=19$m=19456,t=2,p=1$<base64-salt>$<base64-hash>
    //
    // Store this as a single column. Salt and parameters are
    // embedded — no separate columns required, and you can re-tune
    // parameters in future without breaking existing hashes (each
    // row remembers what params it was hashed with).
    println!("Hash: {phc_string}");

    // On login attempt:
    let supplied_correct = b"correct horse battery staple";
    let supplied_wrong = b"hunter2";

    let ok = kdf::argon2_verify(&phc_string, supplied_correct)?;
    println!("Correct password verifies: {ok}");
    assert!(ok);

    let ok = kdf::argon2_verify(&phc_string, supplied_wrong)?;
    println!("Wrong password verifies:   {ok}");
    assert!(!ok);

    // Verification distinguishes between:
    //
    //   - wrong password               → Ok(false)
    //   - malformed / corrupted PHC    → Err(Error::Kdf(...))
    //
    // Log these differently. Wrong password is "attacker / typo"
    // (warn). Malformed PHC is "corruption / bug" (error).
    match kdf::argon2_verify("definitely not a phc string", user_password) {
        Ok(_) => unreachable!("malformed PHC shouldn't parse"),
        Err(e) => println!("Malformed PHC: {e}"),
    }

    // For higher-cost use cases (machine-to-machine credentials,
    // long-lived service tokens), tune the parameters explicitly:
    use crypt_io::kdf::{Argon2Params, argon2_hash_with_params};
    let strong = Argon2Params {
        m_cost: 64 * 1024, // 64 MiB
        t_cost: 3,
        p_cost: 1,
        output_len: 32,
    };
    let phc = argon2_hash_with_params(b"service-token", strong)?;
    assert!(kdf::argon2_verify(&phc, b"service-token")?);
    println!("Custom-params hash verified.");

    Ok(())
}
