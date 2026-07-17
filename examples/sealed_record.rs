//! Seals one record with an ephemeral demonstration provider.

#![deny(warnings)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(unused_must_use)]
#![deny(unused_results)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::print_stdout)]
#![deny(clippy::print_stderr)]
#![deny(clippy::dbg_macro)]
#![deny(clippy::unreachable)]
#![deny(clippy::undocumented_unsafe_blocks)]

use crypt_io::storage::{
    CryptError, KeyGeneration, KeyId, KeyLease, KeyProvider, KeyProviderError, KeyScope, PurposeId,
    RecordCodec, RecordContext, SecretKey32, SpaceId,
};
use zeroize::Zeroizing;

const KEY_ID: KeyId = KeyId::new(*b"example-key-v001");
const GENERATION: KeyGeneration = KeyGeneration::new(1);

/// Demonstration-only provider backed by one process-local ephemeral key.
///
/// Production applications must use a reviewed credential store or protected
/// headless key source with their own authorization and recovery policy.
struct EphemeralProvider {
    scope: KeyScope,
    secret: Zeroizing<[u8; 32]>,
}

impl EphemeralProvider {
    fn new(scope: KeyScope) -> crypt_io::storage::Result<Self> {
        let mut secret = Zeroizing::new([0_u8; 32]);
        mod_rand::tier3::fill_bytes(secret.as_mut())
            .map_err(|_error| CryptError::EntropyUnavailable)?;
        Ok(Self { scope, secret })
    }

    fn lease(&self) -> KeyLease {
        KeyLease::new(KEY_ID, GENERATION, SecretKey32::new(*self.secret))
    }
}

impl KeyProvider for EphemeralProvider {
    fn active(&self, scope: &KeyScope) -> Result<KeyLease, KeyProviderError> {
        if scope != &self.scope {
            return Err(KeyProviderError::AccessDenied);
        }
        Ok(self.lease())
    }

    fn by_id(
        &self,
        scope: &KeyScope,
        key_id: KeyId,
        generation: KeyGeneration,
    ) -> Result<KeyLease, KeyProviderError> {
        if scope != &self.scope {
            return Err(KeyProviderError::AccessDenied);
        }
        if key_id != KEY_ID || generation != GENERATION {
            return Err(KeyProviderError::Unavailable);
        }
        Ok(self.lease())
    }
}

fn main() -> crypt_io::storage::Result<()> {
    // Hosts must pre-derive this opaque value with a keyed construction. It is
    // never a raw tenant, user, agent, or other principal identifier.
    let prederived_opaque_space_id = SpaceId::new([0x53; 32]);
    let scope = KeyScope::new(
        prederived_opaque_space_id,
        PurposeId::new(*b"example-rec-v001"),
    );
    let codec = RecordCodec::new(EphemeralProvider::new(scope)?);
    let context = RecordContext::new(7, b"example/collection/record-42")?;
    let message = b"authenticated storage";

    let sealed = codec.seal(&scope, &context, message)?;
    let opened = codec.open(&scope, &context, sealed.as_bytes())?;
    if opened.as_slice() != message {
        return Err(CryptError::AuthenticationFailed);
    }

    Ok(())
}
