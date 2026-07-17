# Project Wycheproof vectors

These dev-only files are copied from the official
[`C2SP/wycheproof`](https://github.com/C2SP/wycheproof) repository at commit
`fc24cd5b787d8e496bff31b0468af693a652b0f2` (retrieved 2026-07-16).
They are licensed under Apache-2.0; the upstream license is included beside
them. Tests run offline and never fetch mutable network data.

The vector JSON files are byte-for-byte upstream copies:

| File | SHA-256 |
| --- | --- |
| `aes_gcm_test.json` | `985e5ecc172e181eaf49e89508b9470dcf478002eb7e8559c707eb42dc97dfe7` |
| `ed25519_test.json` | `70471c053c711731f2195ef4875b60ea7f5d6793939d99058ac12da810cb8e00` |
| `hkdf_sha256_test.json` | `bb2b462a38b251cb52a2aede706d6d4b62b26864f4e80c95497507ddb07c5f1e` |
| `hmac_sha256_test.json` | `2d201cfa61d1bf95e6f5d07d96634b4a348b31e8eaa277ad7c8d09677b7a743f` |

`wycheproof_contract.rs` validates each pinned schema and total before running
the configurations crypt-io actually ships:

- 66 AES-256-GCM cases with a 96-bit nonce and 128-bit tag;
- 150 Ed25519 verification cases (88 valid and 62 invalid);
- 37 HKDF-SHA256 cases with 256-bit input key material; and
- 81 HMAC-SHA256 cases with a 256-bit key and full 256-bit tag.

No applicable case is skipped as `acceptable`. Updating these files requires a
reviewed upstream commit pin, refreshed checksums/counts, the full security
gate, and a changelog entry.
