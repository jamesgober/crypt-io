"""Generate tests/data/sign_vectors.rs from published vectors.

Usage:
    python -I tests/data/gen_sign_vectors.py rfc8032.txt SigGen15_186-3.txt rfc8463.txt tests/data/sign_vectors.rs

Inputs:
- https://www.rfc-editor.org/rfc/rfc8032.txt
- https://www.rfc-editor.org/rfc/rfc8463.txt
- SigGen15_186-3.txt from NIST CAVP
  https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-3rsatestvectors.zip
"""
import base64
import hashlib
import math
import re
import sys

rfc8032, siggen, rfc8463, out_path = sys.argv[1:5]


# ---------------------------------------------------------------- RFC 8032
def ed25519_tests(path):
    lines = open(path, encoding="ascii").read().splitlines()
    start = lines.index("7.1.  Test Vectors for Ed25519")
    end = lines.index("7.2.  Test Vectors for Ed25519ctx")
    tests = []
    field = None
    for raw in lines[start:end]:
        line = raw.strip()
        if line.startswith("-----TEST "):
            tests.append((line[len("-----TEST "):], {}))
            field = None
            continue
        if not tests:
            continue
        label = next((k for k in ("ALGORITHM", "SECRET KEY", "PUBLIC KEY", "MESSAGE", "SIGNATURE")
                      if line.startswith(k)), None)
        if label:
            field = label
            tests[-1][1][field] = ""
            continue
        if field and field != "ALGORITHM" and re.fullmatch(r"[0-9a-f]+", line):
            tests[-1][1][field] += line
    return tests


ed = ed25519_tests(rfc8032)
names = [n for n, _ in ed]
assert names[:5] == ["1", "2", "3", "1024", "SHA(abc)"], names
for name, f in ed:
    assert len(f["SECRET KEY"]) == 64 and len(f["PUBLIC KEY"]) == 64, name
    assert len(f["SIGNATURE"]) == 128, name
assert len(ed[3][1]["MESSAGE"]) == 2046, len(ed[3][1]["MESSAGE"])
# Test SHA(abc): the message is SHA-512("abc").
assert ed[4][1]["MESSAGE"] == hashlib.sha512(b"abc").hexdigest()


# ------------------------------------------------------------------ DER
def der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def der(tag, content):
    return bytes([tag]) + der_len(len(content)) + content


def der_int(v):
    b = v.to_bytes(max(1, (v.bit_length() + 7) // 8), "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return der(0x02, b)


def der_seq(*parts):
    return der(0x30, b"".join(parts))


RSA_ALG = der_seq(der(0x06, bytes.fromhex("2a864886f70d010101")), der(0x05, b""))


def recover_pq(n, e, d):
    k = d * e - 1
    t = 0
    r = k
    while r % 2 == 0:
        r //= 2
        t += 1
    for g in range(2, 1000):
        y = pow(g, r, n)
        if y in (1, n - 1):
            continue
        for _ in range(t):
            x = pow(y, 2, n)
            if x == 1:
                p = math.gcd(y - 1, n)
                q = n // p
                assert p * q == n and 1 < p < n
                return max(p, q), min(p, q)
            if x == n - 1:
                break
            y = x
    raise SystemExit("could not factor")


def rsa_keys(n, e, d):
    p, q = recover_pq(n, e, d)
    pkcs1 = der_seq(
        der_int(0), der_int(n), der_int(e), der_int(d), der_int(p), der_int(q),
        der_int(d % (p - 1)), der_int(d % (q - 1)), der_int(pow(q, -1, p)),
    )
    pkcs8 = der_seq(der_int(0), RSA_ALG, der(0x04, pkcs1))
    spki = der_seq(RSA_ALG, der(0x03, b"\x00" + der_seq(der_int(n), der_int(e))))
    return pkcs1, pkcs8, spki


SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def check_pkcs1v15(n, e, msg, sig):
    k = (n.bit_length() + 7) // 8
    em = pow(int.from_bytes(sig, "big"), e, n).to_bytes(k, "big")
    t = SHA256_PREFIX + hashlib.sha256(msg).digest()
    expected = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    assert em == expected, "NIST signature does not verify"


# ------------------------------------------------------------ NIST CAVP
def siggen_sets(path):
    sets = []
    cur = None
    entry = {}
    for line in open(path, encoding="ascii"):
        line = line.strip()
        m = re.match(r"\[mod = (\d+)\]", line)
        if m:
            cur = {"bits": int(m.group(1)), "cases": []}
            sets.append(cur)
            continue
        if "=" not in line or line.startswith("#"):
            continue
        k, v = [x.strip() for x in line.split("=", 1)]
        if k in ("n", "e", "d"):
            cur[k] = int(v, 16)
        elif k == "SHAAlg":
            entry = {"alg": v}
        elif k == "Msg":
            entry["msg"] = v
        elif k == "S":
            entry["s"] = v
            if entry["alg"] == "SHA256":
                cur["cases"].append(entry)
    return sets


sets = [s for s in siggen_sets(siggen) if s["bits"] in (2048, 3072)]
assert [s["bits"] for s in sets] == [2048, 3072]
for s in sets:
    assert s["n"].bit_length() == s["bits"]
    assert len(s["cases"]) == 10
    for c in s["cases"]:
        check_pkcs1v15(s["n"], s["e"], bytes.fromhex(c["msg"]), bytes.fromhex(c["s"]))


# --------------------------------------------------------------- RFC 8463
t = open(rfc8463, encoding="ascii").read()
seed_b64 = re.search(r"Test 1, converted from hex to base64\.\s+(\S+)", t).group(1)
pem = re.search(r"-----BEGIN RSA PRIVATE KEY-----(.*?)-----END RSA PRIVATE KEY-----", t, re.S).group(1)
rsa1024 = base64.b64decode("".join(pem.split()))
pub_b64 = re.search(r'p=(11qY[^"]+)"', t).group(1)
assert base64.b64decode(seed_b64).hex() == ed[0][1]["SECRET KEY"]
assert base64.b64decode(pub_b64).hex() == ed[0][1]["PUBLIC KEY"]


# ------------------------------------------------------------------ emit
def h(b):
    return b.hex() if isinstance(b, bytes) else b


def rust_str(s, indent="    "):
    chunks = [s[i:i + 64] for i in range(0, len(s), 64)] or [""]
    if len(chunks) == 1:
        return '"' + chunks[0] + '"'
    return '"' + ("\\\n" + indent + "     ").join(chunks) + '"'


o = []
o.append("// Generated by gen_sign_vectors.py from published vectors. Do not edit.")
o.append("//")
o.append("// - RFC 8032 section 7.1 (Ed25519 tests 1, 2, 3, 1024, SHA(abc)).")
o.append("// - NIST CAVP SigGen15_186-3.txt (FIPS 186-3 RSA PKCS#1 v1.5),")
o.append("//   [mod = 2048] and [mod = 3072], every SHA256 case. p and q are")
o.append("//   recovered from (n, e, d); each signature was checked with")
o.append("//   S^e mod n against EMSA-PKCS1-v1_5 before it was written here.")
o.append("// - RFC 8463 appendix A.1: the 1024-bit RSA example key (DER).")
o.append("")
o.append("#![allow(dead_code)]")
o.append("")
o.append("pub struct Ed25519Vector {")
o.append("    pub name: &'static str,")
o.append("    pub seed: &'static str,")
o.append("    pub public_key: &'static str,")
o.append("    pub message: &'static str,")
o.append("    pub signature: &'static str,")
o.append("}")
o.append("")
o.append("pub const RFC8032: &[Ed25519Vector] = &[")
for name, f in ed[:5]:
    o.append("    Ed25519Vector {")
    o.append(f'        name: "{name}",')
    o.append(f"        seed: {rust_str(f['SECRET KEY'], '        ')},")
    o.append(f"        public_key: {rust_str(f['PUBLIC KEY'], '        ')},")
    o.append(f"        message: {rust_str(f['MESSAGE'], '        ')},")
    o.append(f"        signature: {rust_str(f['SIGNATURE'], '        ')},")
    o.append("    },")
o.append("];")
o.append("")
o.append("pub struct RsaCase {")
o.append("    pub message: &'static str,")
o.append("    pub signature: &'static str,")
o.append("}")
o.append("")
o.append("pub struct RsaVectorSet {")
o.append("    pub bits: u32,")
o.append("    pub pkcs1_der: &'static str,")
o.append("    pub pkcs8_der: &'static str,")
o.append("    pub spki_der: &'static str,")
o.append("    pub cases: &'static [RsaCase],")
o.append("}")
o.append("")
o.append("pub const NIST_SIGGEN15_SHA256: &[RsaVectorSet] = &[")
for s in sets:
    pkcs1, pkcs8, spki = rsa_keys(s["n"], s["e"], s["d"])
    o.append("    RsaVectorSet {")
    o.append(f"        bits: {s['bits']},")
    o.append(f"        pkcs1_der: {rust_str(h(pkcs1), '        ')},")
    o.append(f"        pkcs8_der: {rust_str(h(pkcs8), '        ')},")
    o.append(f"        spki_der: {rust_str(h(spki), '        ')},")
    o.append("        cases: &[")
    for c in s["cases"]:
        o.append("            RsaCase {")
        o.append(f"                message: {rust_str(c['msg'], '                ')},")
        o.append(f"                signature: {rust_str(c['s'], '                ')},")
        o.append("            },")
    o.append("        ],")
    o.append("    },")
o.append("];")
o.append("")
o.append("/// RFC 8463 A.1 RSA example key (PKCS#1 DER, 1024 bits).")
o.append(f"pub const RFC8463_RSA_1024_PKCS1: &str = {rust_str(h(rsa1024))};")
o.append("")
open(out_path, "w", encoding="ascii", newline="\n").write("\n".join(o))
print("ok", len(ed), "ed25519;", [len(s["cases"]) for s in sets], "rsa cases")
