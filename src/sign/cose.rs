//! `COSE_Key` public keys (RFC 9052 section 7, RFC 9053), as WebAuthn
//! stores a credential's public key.

use core::fmt;

use crate::error::{Error, Result};

// COSE labels and values (IANA "COSE Key Common Parameters",
// "COSE Key Type Parameters", "COSE Algorithms", "COSE Elliptic Curves").
const LABEL_KTY: i64 = 1;
const LABEL_ALG: i64 = 3;
const LABEL_CRV_OR_N: i64 = -1;
const LABEL_X_OR_E: i64 = -2;
const LABEL_Y: i64 = -3;
const KTY_OKP: i64 = 1;
const KTY_EC2: i64 = 2;
const KTY_RSA: i64 = 3;
const CRV_P256: i64 = 1;
const CRV_ED25519: i64 = 6;

/// COSE algorithm `ES256`: ECDSA P-256 with SHA-256.
pub const COSE_ALG_ES256: i64 = -7;
/// COSE algorithm `EdDSA` (here: Ed25519).
pub const COSE_ALG_EDDSA: i64 = -8;
/// COSE algorithm `RS256`: RSASSA-PKCS1-v1_5 with SHA-256.
pub const COSE_ALG_RS256: i64 = -257;

/// A credential public key in `COSE_Key` form, as WebAuthn stores it
/// (`credentialPublicKey` in the attested credential data), parsed for
/// checking assertion signatures.
///
/// Supported: `ES256` (P-256, the common passkey key), `EdDSA` with
/// Ed25519, and `RS256` (Windows Hello). The variant depends on the
/// key; each needs its `sign-*` feature. Parse once at registration or
/// load, then [`check`](Self::check) every assertion:
///
/// ```no_run
/// use crypt_io::sign::CosePublicKey;
///
/// # let (stored_cose_key, authenticator_data, client_data_hash, signature) = (vec![0u8], vec![0u8], [0u8; 32], vec![0u8]);
/// let key = CosePublicKey::from_cose_key(&stored_cose_key)?;
/// let mut signed = authenticator_data.clone();
/// signed.extend_from_slice(&client_data_hash);        // SHA-256(clientDataJSON)
/// key.check(&signed, &signature)?;                     // Err(AuthenticationFailed) if forged
/// # Ok::<(), crypt_io::Error>(())
/// ```
///
/// `ES256` signatures are malleable (see [`EcdsaP256PublicKey`](super)),
/// so never treat the signature bytes as a replay key; key replays on the
/// challenge. Ed25519 keys of small order, with which one signature
/// checks for every message, are refused here (1.6.0).
///
/// New in 1.5.0. Requires at least one of `sign-p256`, `sign-ed25519`,
/// `sign-rsa`.
#[derive(Clone)]
#[non_exhaustive]
pub enum CosePublicKey {
    /// `ES256`.
    #[cfg(feature = "sign-p256")]
    EcdsaP256(super::EcdsaP256PublicKey),
    /// `EdDSA` with Ed25519.
    #[cfg(feature = "sign-ed25519")]
    Ed25519(super::Ed25519PublicKey),
    /// `RS256`, 2048 to 8192 bits.
    #[cfg(feature = "sign-rsa")]
    Rsa(super::RsaPublicKey),
}

impl CosePublicKey {
    /// Parse a CBOR-encoded `COSE_Key`. `bytes` must be exactly one key:
    /// a definite-length map with integer labels, no tags, no duplicate
    /// labels, and nothing after it. The key must carry `kty` and `alg`
    /// (WebAuthn requires `alg`) and match them:
    ///
    /// | `alg` | `kty` | Parameters |
    /// |---|---|---|
    /// | -7 `ES256` | 2 `EC2` | `crv` 1 (P-256), `x` and `y`, 32 bytes each |
    /// | -8 `EdDSA` | 1 `OKP` | `crv` 6 (Ed25519), `x`, 32 bytes |
    /// | -257 `RS256` | 3 `RSA` | `n`, `e` |
    ///
    /// Other parameters (`kid`, `key_ops`, ...) are skipped.
    ///
    /// # Errors
    ///
    /// - [`Error::Sign`] for malformed CBOR, a missing or inconsistent
    ///   parameter, an algorithm crypt-io does not check (`ES384`, `PS256`,
    ///   Ed448, ...), or a key the algorithm's own parser rejects.
    /// - [`Error::AlgorithmNotEnabled`] for a supported algorithm whose
    ///   feature is off.
    pub fn from_cose_key(bytes: &[u8]) -> Result<Self> {
        let params = parse_cose_key(bytes)?;
        let kty = params
            .int(LABEL_KTY)
            .ok_or(Error::Sign("COSE key: missing kty"))?;
        let alg = params
            .int(LABEL_ALG)
            .ok_or(Error::Sign("COSE key: missing alg"))?;
        match (alg, kty) {
            (COSE_ALG_ES256, KTY_EC2) => {
                if params.int(LABEL_CRV_OR_N) != Some(CRV_P256) {
                    return Err(Error::Sign("COSE key: ES256 needs crv P-256"));
                }
                let x = params.bytes32(LABEL_X_OR_E)?;
                let y = params.bytes32(LABEL_Y)?;
                es256(x, y)
            }
            (COSE_ALG_EDDSA, KTY_OKP) => {
                if params.int(LABEL_CRV_OR_N) != Some(CRV_ED25519) {
                    return Err(Error::Sign("COSE key: EdDSA needs crv Ed25519"));
                }
                eddsa(params.bytes32(LABEL_X_OR_E)?)
            }
            (COSE_ALG_RS256, KTY_RSA) => {
                let n = params
                    .bytes(LABEL_CRV_OR_N)
                    .ok_or(Error::Sign("COSE key: missing n"))?;
                let e = params
                    .bytes(LABEL_X_OR_E)
                    .ok_or(Error::Sign("COSE key: missing e"))?;
                rs256(n, e)
            }
            (COSE_ALG_ES256 | COSE_ALG_EDDSA | COSE_ALG_RS256, _) => {
                Err(Error::Sign("COSE key: kty does not match alg"))
            }
            _ => Err(Error::Sign("COSE key: unsupported algorithm")),
        }
    }

    /// The COSE algorithm: [`COSE_ALG_ES256`], [`COSE_ALG_EDDSA`] or
    /// [`COSE_ALG_RS256`].
    #[must_use]
    pub fn algorithm(&self) -> i64 {
        match self {
            #[cfg(feature = "sign-p256")]
            Self::EcdsaP256(_) => COSE_ALG_ES256,
            #[cfg(feature = "sign-ed25519")]
            Self::Ed25519(_) => COSE_ALG_EDDSA,
            #[cfg(feature = "sign-rsa")]
            Self::Rsa(_) => COSE_ALG_RS256,
        }
    }

    /// Check `signature` over `message` with this key's algorithm:
    /// a DER ECDSA signature for `ES256` (the WebAuthn form), a 64-byte
    /// Ed25519 signature, or a PKCS#1 v1.5 SHA-256 signature for
    /// `RS256`. For a WebAuthn assertion, `message` is
    /// `authenticatorData || SHA-256(clientDataJSON)`.
    ///
    /// # Errors
    ///
    /// [`Error::AuthenticationFailed`] if the signature does not check.
    pub fn check(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        match self {
            #[cfg(feature = "sign-p256")]
            Self::EcdsaP256(k) => k.check_sha256(message, signature),
            #[cfg(feature = "sign-ed25519")]
            Self::Ed25519(k) => k.check(message, signature),
            #[cfg(feature = "sign-rsa")]
            Self::Rsa(k) => k.check_pkcs1v15_sha256(message, signature),
        }
    }
}

impl fmt::Debug for CosePublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "sign-p256")]
            Self::EcdsaP256(k) => f.debug_tuple("EcdsaP256").field(k).finish(),
            #[cfg(feature = "sign-ed25519")]
            Self::Ed25519(k) => f.debug_tuple("Ed25519").field(k).finish(),
            #[cfg(feature = "sign-rsa")]
            Self::Rsa(k) => f.debug_tuple("Rsa").field(k).finish(),
        }
    }
}

#[cfg(feature = "sign-p256")]
fn es256(x: [u8; 32], y: [u8; 32]) -> Result<CosePublicKey> {
    super::EcdsaP256PublicKey::from_coordinates(&x, &y).map(CosePublicKey::EcdsaP256)
}
#[cfg(not(feature = "sign-p256"))]
fn es256(_: [u8; 32], _: [u8; 32]) -> Result<CosePublicKey> {
    Err(Error::AlgorithmNotEnabled("ES256 (feature sign-p256)"))
}

#[cfg(feature = "sign-ed25519")]
fn eddsa(x: [u8; 32]) -> Result<CosePublicKey> {
    // A small-order key lets one signature check for every message; no
    // authenticator produces one (1.6.0).
    if super::ed25519::is_small_order(x) {
        return Err(Error::Sign("COSE key: Ed25519 key of small order"));
    }
    super::Ed25519PublicKey::from_bytes(&x).map(CosePublicKey::Ed25519)
}
#[cfg(not(feature = "sign-ed25519"))]
fn eddsa(_: [u8; 32]) -> Result<CosePublicKey> {
    Err(Error::AlgorithmNotEnabled("EdDSA (feature sign-ed25519)"))
}

#[cfg(feature = "sign-rsa")]
fn rs256(n: &[u8], e: &[u8]) -> Result<CosePublicKey> {
    super::RsaPublicKey::from_components(n, e).map(CosePublicKey::Rsa)
}
#[cfg(not(feature = "sign-rsa"))]
fn rs256(_: &[u8], _: &[u8]) -> Result<CosePublicKey> {
    Err(Error::AlgorithmNotEnabled("RS256 (feature sign-rsa)"))
}

// ------------------------------------------------------------------ CBOR

/// Most entries a `COSE_Key` map may have. Real keys have 4 or 5.
const MAX_ENTRIES: usize = 16;
/// Deepest nesting allowed inside a skipped (unknown) parameter value.
const MAX_DEPTH: usize = 4;

/// Value of a parameter crypt-io reads.
#[derive(Clone, Copy)]
enum Value<'a> {
    Int(i64),
    Bytes(&'a [u8]),
    Other,
}

/// The integer-labelled parameters of one `COSE_Key`.
struct CoseKey<'a> {
    entries: [(i64, Value<'a>); MAX_ENTRIES],
    len: usize,
}

impl<'a> CoseKey<'a> {
    fn get(&self, label: i64) -> Option<Value<'a>> {
        self.entries[..self.len]
            .iter()
            .find(|(l, _)| *l == label)
            .map(|(_, v)| *v)
    }

    fn int(&self, label: i64) -> Option<i64> {
        match self.get(label) {
            Some(Value::Int(v)) => Some(v),
            _ => None,
        }
    }

    fn bytes(&self, label: i64) -> Option<&'a [u8]> {
        match self.get(label) {
            Some(Value::Bytes(b)) => Some(b),
            _ => None,
        }
    }

    fn bytes32(&self, label: i64) -> Result<[u8; 32]> {
        self.bytes(label)
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or(Error::Sign("COSE key: coordinate missing or not 32 bytes"))
    }
}

const MALFORMED: Error = Error::Sign("COSE key: malformed CBOR");

/// A CBOR data item header: major type and argument.
struct Head {
    major: u8,
    arg: u64,
}

struct Reader<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Result<u8> {
        let b = *self.input.get(self.pos).ok_or(MALFORMED)?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: u64) -> Result<&'a [u8]> {
        let n = usize::try_from(n).map_err(|_| MALFORMED)?;
        let end = self.pos.checked_add(n).ok_or(MALFORMED)?;
        let out = self.input.get(self.pos..end).ok_or(MALFORMED)?;
        self.pos = end;
        Ok(out)
    }

    /// Read a head (RFC 8949 section 3). Indefinite lengths and the
    /// reserved additional-information values are refused.
    fn head(&mut self) -> Result<Head> {
        let initial = self.byte()?;
        let major = initial >> 5;
        let info = initial & 0x1f;
        let arg = match info {
            0..=23 => u64::from(info),
            24 => u64::from(self.byte()?),
            25 => u64::from(u16::from_be_bytes(self.array()?)),
            26 => u64::from(u32::from_be_bytes(self.array()?)),
            27 => u64::from_be_bytes(self.array()?),
            _ => return Err(MALFORMED),
        };
        Ok(Head { major, arg })
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N as u64)?);
        Ok(out)
    }

    /// An integer label or value (major type 0 or 1) that fits `i64`.
    fn int_from(head: &Head) -> Result<i64> {
        let v = i64::try_from(head.arg).map_err(|_| MALFORMED)?;
        match head.major {
            0 => Ok(v),
            1 => Ok(-1 - v),
            _ => Err(MALFORMED),
        }
    }

    /// Read a value: integers and byte strings are kept, anything else
    /// is skipped (and checked to be well formed).
    fn value(&mut self) -> Result<Value<'a>> {
        let head = self.head()?;
        match head.major {
            0 | 1 => Ok(Self::int_from(&head).map_or(Value::Other, Value::Int)),
            2 => Ok(Value::Bytes(self.take(head.arg)?)),
            _ => {
                self.skip_rest(&head, 0)?;
                Ok(Value::Other)
            }
        }
    }

    /// Skip the remainder of an item whose head was just read.
    fn skip_rest(&mut self, head: &Head, depth: usize) -> Result<()> {
        if depth > MAX_DEPTH {
            return Err(MALFORMED);
        }
        match head.major {
            2 | 3 => self.take(head.arg).map(|_| ()),
            4 | 5 => {
                let items = if head.major == 5 {
                    head.arg.checked_mul(2).ok_or(MALFORMED)?
                } else {
                    head.arg
                };
                for _ in 0..items {
                    let inner = self.head()?;
                    self.skip_rest(&inner, depth + 1)?;
                }
                Ok(())
            }
            // Tags (6) are not allowed in a COSE_Key here.
            6 => Err(MALFORMED),
            // Integers (0, 1), simple values and floats (7): the
            // argument was the whole payload.
            _ => Ok(()),
        }
    }
}

fn parse_cose_key(bytes: &[u8]) -> Result<CoseKey<'_>> {
    let mut r = Reader {
        input: bytes,
        pos: 0,
    };
    let head = r.head()?;
    if head.major != 5 {
        return Err(Error::Sign("COSE key: not a CBOR map"));
    }
    let count = usize::try_from(head.arg).map_err(|_| MALFORMED)?;
    if count > MAX_ENTRIES {
        return Err(Error::Sign("COSE key: too many parameters"));
    }
    let mut key = CoseKey {
        entries: [(0, Value::Other); MAX_ENTRIES],
        len: 0,
    };
    for _ in 0..count {
        let label_head = r.head()?;
        let label = match label_head.major {
            0 | 1 => Reader::int_from(&label_head)?,
            // A text label (RFC 9052 allows them): skip its value too.
            3 => {
                let _ = r.take(label_head.arg)?;
                let _ = r.value()?;
                continue;
            }
            _ => return Err(MALFORMED),
        };
        if key.get(label).is_some() {
            return Err(Error::Sign("COSE key: duplicate parameter"));
        }
        let value = r.value()?;
        key.entries[key.len] = (label, value);
        key.len += 1;
    }
    if r.pos != bytes.len() {
        return Err(Error::Sign("COSE key: trailing bytes"));
    }
    Ok(key)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn reads_labels_ints_and_bytes() {
        // {1: 2, 3: -7, -1: 1, -2: h'0102', 4: [1, [2]], "x": 5}
        let k = parse_cose_key(&[
            0xa6, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x42, 0x01, 0x02, 0x04, 0x82, 0x01,
            0x81, 0x02, 0x61, b'x', 0x05,
        ])
        .unwrap();
        assert_eq!(k.int(1), Some(2));
        assert_eq!(k.int(3), Some(-7));
        assert_eq!(k.int(-1), Some(1));
        assert_eq!(k.bytes(-2), Some(&[1u8, 2][..]));
        assert!(k.int(4).is_none());
    }

    #[test]
    fn refuses_malformed_input() {
        let bad: &[&[u8]] = &[
            &[],
            &[0xa1],                         // map, missing entry
            &[0xa1, 0x01],                   // missing value
            &[0xbf, 0xff],                   // indefinite map
            &[0xa1, 0x01, 0x5f, 0xff],       // indefinite bytes
            &[0xa1, 0x01, 0x42, 0x01],       // short byte string
            &[0xa1, 0x01, 0xc1, 0x01],       // tagged value
            &[0xa1, 0x41, 0x00, 0x01],       // byte-string label
            &[0xa2, 0x01, 0x01, 0x01, 0x02], // duplicate label
            &[0xa1, 0x01, 0x01, 0x00],       // trailing byte
            &[0x81, 0x01],                   // array, not a map
            &[0xa1, 0x01, 0x1c],             // reserved additional info
            &[
                0xa1, 0x01, 0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            ], // huge length
        ];
        for b in bad {
            assert!(matches!(parse_cose_key(b), Err(Error::Sign(_))), "{b:02x?}");
        }
        // 17 entries.
        let mut many = vec![0xb1];
        for i in 0..17u8 {
            many.extend_from_slice(&[i, 0x00]);
        }
        assert!(parse_cose_key(&many).is_err());
        // Nesting deeper than MAX_DEPTH inside a skipped value.
        let mut deep = vec![0xa1, 0x04];
        deep.extend(core::iter::repeat_n(0x81, MAX_DEPTH + 2));
        deep.push(0x00);
        assert!(parse_cose_key(&deep).is_err());
    }

    #[test]
    fn out_of_range_negative_label_is_refused() {
        // Label -2^64 does not fit i64.
        assert!(
            parse_cose_key(&[
                0xa1, 0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00
            ])
            .is_err()
        );
    }
}
