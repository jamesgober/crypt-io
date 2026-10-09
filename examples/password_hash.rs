//! Hash and check a password with Argon2id — the use case for any
//! login flow.
//!
//! Run with:
//!     cargo run --example password_hash --release
//!
//! Use `--release` because Argon2id at OWASP-recommended parameters
//! is intentionally slow (~100 ms per hash). A debug build can take
//! several seconds.

use crypt_io::Error;
use crypt_io::kdf::{self, Argon2Params, Argon2Policy};

fn main() -> Result<(), Error> {
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

    // On login attempt. A wrong password is `Err(AuthenticationFailed)`,
    // so `?` rejects it.
    kdf::argon2_check(&phc_string, b"correct horse battery staple")?;
    println!("Correct password: accepted");

    let result = kdf::argon2_check(&phc_string, b"hunter2");
    println!("Wrong password:   {result:?}");
    assert_eq!(result, Err(Error::AuthenticationFailed));

    // `argon2_check` distinguishes between:
    //
    //   - wrong password               → Err(Error::AuthenticationFailed)
    //   - malformed / corrupted PHC    → Err(Error::Kdf(...))
    //   - a variant or costs outside the policy (default: argon2id,
    //     m <= 1 GiB, t <= 64, p <= 16) → Err(Error::Kdf(...))
    //
    // Log these differently. Wrong password is "attacker / typo"
    // (warn). Malformed PHC is "corruption / bug" (error).
    match kdf::argon2_check("definitely not a phc string", user_password) {
        Err(Error::Kdf(why)) => println!("Malformed PHC:    {why}"),
        other => unreachable!("malformed PHC shouldn't parse: {other:?}"),
    }

    // For higher-cost use cases (machine-to-machine credentials,
    // long-lived service tokens), tune the parameters explicitly and
    // check them before use.
    let strong = Argon2Params::new(64 * 1024, 3, 1, 32); // 64 MiB, 3 passes
    strong.validate()?;
    let phc = kdf::argon2_hash_with_params(b"service-token", strong)?;
    kdf::argon2_check(&phc, b"service-token")?;
    println!("Custom-params hash: accepted");

    // A policy changes what `argon2_check_with_policy` accepts: here,
    // reject anything cheaper than 32 MiB / 2 passes, which stops a
    // planted low-cost hash.
    let policy = Argon2Policy::new().with_min_cost(32 * 1024, 2);
    kdf::argon2_check_with_policy(&phc, b"service-token", &policy)?;
    let weak = kdf::argon2_hash_with_params(b"service-token", Argon2Params::new(8, 1, 1, 32))?;
    assert!(matches!(
        kdf::argon2_check_with_policy(&weak, b"service-token", &policy),
        Err(Error::Kdf(_))
    ));
    println!("Policy rejects the weak hash.");

    Ok(())
}
