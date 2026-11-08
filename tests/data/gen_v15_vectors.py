"""Generate tests/data/v15_vectors.rs (crypt-io 1.5.0: OTP, ES256, WebAuthn).

Usage:
    python -I tests/data/gen_v15_vectors.py SigVer.rsp ecdsa_secp256r1_sha256_test.json \
        ecdsa_secp256r1_sha256_p1363_test.json webauthn_vectors.txt tests/data/v15_vectors.rs

Then run `cargo fmt` (the committed file is formatted).

Inputs:
- SigVer.rsp from NIST CAVP 186-4ecdsatestvectors.zip
  https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-4ecdsatestvectors.zip
- Wycheproof (C2SP) testvectors_v1/ecdsa_secp256r1_sha256_test.json and
  ecdsa_secp256r1_sha256_p1363_test.json  https://github.com/C2SP/wycheproof
- WebAuthn Level 3, section 16 "Test Vectors" (https://www.w3.org/TR/webauthn-3/),
  saved as text (HTML tags stripped).
- RFC 4226 appendix D and RFC 6238 appendix B values are written below and
  checked here with Python's hmac.
"""
import hashlib
import hmac
import json
import re
import struct
import sys

sigver, wyche_der, wyche_p1363, webauthn_txt, out_path = sys.argv[1:6]

# ---------------------------------------------------------------- RFC 4226 / 6238
SECRET = b"12345678901234567890"
HOTP = [755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489]
HOTP_HMAC = [
    "cc93cf18508d94934c64b65d8ba7667fb7cde4b0",
    "75a48a19d4cbe100644e8ac1397eea747a2d33ab",
    "0bacb7fa082fef30782211938bc1c5e70416ff44",
    "66c28227d03a2d5529262ff016a1e6ef76557ece",
    "a904c900a64b35909874b33e61c5938a8e15ed1c",
    "a37e783d7b7233c083d4f62926c7a25f238d0316",
    "bc9cd28561042c83f219324d3c607256c03272ae",
    "a4fb960c0bc06e1eabb804e5b397cdc4b45596fa",
    "1b3c89f65e6c9e883012052823443f048b4332db",
    "1637409809a679dc698207310c8c7fc07290d9e5",
]
TOTP = [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
        (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130")]


def hotp_py(secret, counter, digits):
    mac = hmac.new(secret, struct.pack(">Q", counter), "sha1").digest()
    off = mac[-1] & 0x0F
    code = (int.from_bytes(mac[off:off + 4], "big") & 0x7FFFFFFF) % 10**digits
    return mac, code


for c, (want, want_mac) in enumerate(zip(HOTP, HOTP_HMAC)):
    mac, code = hotp_py(SECRET, c, 6)
    assert mac.hex() == want_mac and code == want, c
for t, want in TOTP:
    assert "%08d" % hotp_py(SECRET, t // 30, 8)[1] == want, t

# ---------------------------------------------------------------- DER helpers
def der_int(v):
    b = v.to_bytes(max(1, (v.bit_length() + 7) // 8), "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return b"\x02" + bytes([len(b)]) + b


def ecdsa_der(r, s):
    body = der_int(r) + der_int(s)
    return b"\x30" + bytes([len(body)]) + body


# ---------------------------------------------------------------- NIST SigVer P-256
nist = []
section = None
case = {}
for line in open(sigver, encoding="ascii"):
    line = line.strip()
    if line.startswith("["):
        section = line
        continue
    if section != "[P-256,SHA-256]" or "=" not in line:
        continue
    k, v = [x.strip() for x in line.split("=", 1)]
    case[k] = v
    if k == "Result":
        point = "04" + case["Qx"].zfill(64) + case["Qy"].zfill(64)
        sig = ecdsa_der(int(case["R"], 16), int(case["S"], 16)).hex()
        nist.append((point, case["Msg"], sig, v.startswith("P")))
        case = {}
assert len(nist) == 15, len(nist)

# ---------------------------------------------------------------- Wycheproof
def wyche(path):
    j = json.load(open(path, encoding="utf-8"))
    groups = []
    for g in j["testGroups"]:
        groups.append((g["publicKey"]["uncompressed"], g["publicKeyDer"],
                       [(tc["tcId"], tc["msg"], tc["sig"], tc["result"]) for tc in g["tests"]]))
    return groups


w_der = wyche(wyche_der)
w_p1363 = wyche(wyche_p1363)

# ---------------------------------------------------------------- CBOR (WebAuthn)
def cbor_item(b, i):
    """Return (value, next index) for the CBOR item at b[i]."""
    ib = b[i]
    major, info = ib >> 5, ib & 31
    i += 1
    if info < 24:
        n = info
    elif info in (24, 25, 26, 27):
        size = 1 << (info - 24)
        n = int.from_bytes(b[i:i + size], "big")
        i += size
    else:
        raise ValueError("indefinite or reserved")
    if major == 0:
        return n, i
    if major == 1:
        return -1 - n, i
    if major in (2, 3):
        v = b[i:i + n]
        return (v if major == 2 else v.decode()), i + n
    if major == 4:
        out = []
        for _ in range(n):
            v, i = cbor_item(b, i)
            out.append(v)
        return out, i
    if major == 5:
        out = {}
        for _ in range(n):
            k, i = cbor_item(b, i)
            v, i = cbor_item(b, i)
            out[k] = v
        return out, i
    if major == 7:
        return {20: False, 21: True, 22: None}.get(info, info), i
    raise ValueError("unsupported major type %d" % major)


def credential_cose_key(att_obj):
    att, end = cbor_item(att_obj, 0)
    assert end == len(att_obj)
    auth = att["authData"]
    flags = auth[32]
    assert flags & 0x40, "no attested credential data"
    i = 32 + 1 + 4 + 16
    cred_len = int.from_bytes(auth[i:i + 2], "big")
    i += 2 + cred_len
    key, j = cbor_item(auth, i)
    return auth[i:j], key


text = open(webauthn_txt, encoding="utf-8").read()
heads = list(re.finditer(r"^\s*16\.(\d+)\.\s+(.+)$", text, re.M))
webauthn = []
for n, h in enumerate(heads):
    body = text[h.end():heads[n + 1].start() if n + 1 < len(heads) else len(text)]
    if "Authentication:" not in body or "attestationObject" not in body:
        continue
    reg, auth_part = body.split("Authentication:", 1)

    def field(part, name):
        m = re.search(r"^" + name + r" = h'([0-9a-f]*)'", part, re.M)
        return m.group(1) if m else None

    att = bytes.fromhex(field(reg, "attestationObject"))
    cose, key = credential_cose_key(att)
    ad, cdj, sig = field(auth_part, "authenticatorData"), field(auth_part, "clientDataJSON"), field(auth_part, "signature")
    assert ad and cdj and sig, h.group(2)
    message = bytes.fromhex(ad) + hashlib.sha256(bytes.fromhex(cdj)).digest()
    alg = key[3]
    if alg == -257:  # RS256: check independently with pow().
        nn, e = int.from_bytes(key[-1], "big"), int.from_bytes(key[-2], "big")
        k = (nn.bit_length() + 7) // 8
        t = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(message).digest()
        em = pow(int.from_bytes(bytes.fromhex(sig), "big"), e, nn).to_bytes(k, "big")
        assert em == b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t, "RS256 vector"
    webauthn.append(("16.%s %s" % (h.group(1), h.group(2).strip()), alg, cose.hex(), message.hex(), sig))
algs = sorted({w[1] for w in webauthn})
assert -7 in algs and -257 in algs and -8 in algs, algs

# ------------------------------------------------------------------ emit
def s(x):
    return '"' + x.replace('"', '\\"') + '"'


o = [
    "// Generated by gen_v15_vectors.py from published vectors. Do not edit.",
    "//",
    "// - RFC 4226 appendix D (HOTP, with the HMAC-SHA1 intermediates) and",
    "//   RFC 6238 appendix B (TOTP, SHA-1), checked with Python's hmac.",
    "// - NIST CAVP 186-4 SigVer.rsp, every [P-256,SHA-256] case with its verdict.",
    "// - Wycheproof ecdsa_secp256r1_sha256_test.json (DER) and",
    "//   ecdsa_secp256r1_sha256_p1363_test.json (fixed r || s).",
    "// - WebAuthn Level 3 section 16: each credential's COSE key (from the",
    "//   registration attestationObject) with its authentication signature;",
    "//   message = authenticatorData || SHA-256(clientDataJSON). The RS256",
    "//   signature was re-checked with pow() here.",
    "",
    "#![allow(dead_code)]",
    "",
    f"pub const OTP_SECRET: &[u8] = b\"{SECRET.decode()}\";",
    "/// RFC 4226 appendix D: (counter, HMAC-SHA1 hex, 6-digit HOTP).",
    "pub const RFC4226: &[(u64, &str, u32)] = &[",
]
for c, (want, mac) in enumerate(zip(HOTP, HOTP_HMAC)):
    o.append(f"    ({c}, {s(mac)}, {want}),")
o += ["];", "", "/// RFC 6238 appendix B, SHA-1 rows: (Unix time, 8-digit TOTP).",
      "pub const RFC6238_SHA1: &[(u64, &str)] = &["]
for t, want in TOTP:
    o.append(f"    ({t}, {s(want)}),")
o += ["];", "", "/// (SEC1 point hex, message hex, DER signature hex, verdict)",
      "pub const NIST_P256_SHA256: &[(&str, &str, &str, bool)] = &["]
for p, m, sg, ok in nist:
    o.append(f"    ({s(p)}, {s(m)}, {s(sg)}, {str(ok).lower()}),")
o += ["];", "", "pub struct WycheEcdsaGroup {", "    pub sec1: &'static str,", "    pub spki: &'static str,",
      "    /// (tcId, message hex, signature hex, \"valid\" | \"acceptable\" | \"invalid\")",
      "    pub tests: &'static [(u32, &'static str, &'static str, &'static str)],", "}", ""]
for name, groups in (("WYCHEPROOF_P256_DER", w_der), ("WYCHEPROOF_P256_P1363", w_p1363)):
    o.append(f"pub const {name}: &[WycheEcdsaGroup] = &[")
    for sec1, spki, tests in groups:
        o.append("    WycheEcdsaGroup {")
        o.append(f"        sec1: {s(sec1)},")
        o.append(f"        spki: {s(spki)},")
        o.append("        tests: &[")
        for tc, m, sg, r in tests:
            o.append(f"            ({tc}, {s(m)}, {s(sg)}, {s(r)}),")
        o.append("        ],")
        o.append("    },")
    o += ["];", ""]
o += ["/// (section, COSE alg, COSE_Key hex, signed message hex, signature hex)",
      "pub const WEBAUTHN: &[(&str, i64, &str, &str, &str)] = &["]
for name, alg, cose, msg, sig in webauthn:
    o.append(f"    ({s(name)}, {alg}, {s(cose)}, {s(msg)}, {s(sig)}),")
o += ["];", ""]
open(out_path, "w", encoding="ascii", newline="\n").write("\n".join(o))
print("ok", len(nist), "nist,", sum(len(g[2]) for g in w_der), "der,",
      sum(len(g[2]) for g in w_p1363), "p1363,", len(webauthn), "webauthn", algs)
