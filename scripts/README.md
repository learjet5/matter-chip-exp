# scripts

Standalone Python helpers for assembling and inspecting the credential values that
go into a chip-exp `--credentials` manifest: base64 DER/TLV certificates, raw P-256
keys, the Matter operational-key TLV, and the fabric IPK. Each reads one argument
(a literal value or a file path), prints to stdout, and changes no state.

## Tools

- `cert-converter.py <cert>` — convert a Matter certificate between CHIP TLV and
  X.509 DER (both base64) and print its subject fields + public key. Accepts base64,
  hex, a Uint8Array/Buffer dump, or a file (including a raw `.der`).
  Feeds manifest `rcac` / `icac` / `noc`.
- `keypair-converter.py <key>` — detect a key or public-key, print the raw bytes
  (hex + base64), split pub/priv, and for a keypair also emit the Matter
  OperationalKeystore TLV. Feeds manifest `*_public_key` / `*_private_key`.
- `ipk-converter.py <epoch_key> <fabric_id> <root_public_key>` — derive the
  compressed fabric id and operational IPK via the CHIP HKDF steps; or, given a
  single base64 arg, convert between a raw 16-byte key and an IPK keyset TLV; or
  `--json <file>`. Feeds manifest `epoch_ipk` / `operational_ipk`.
- `csr-converter.py <b64>` — keypair → a generated CSR (DER base64) + nonce, or a
  CSR → its extracted public key. For the `pairing issue-noc-chain` NOCSR flow.

## Requirements

- Python 3.
- `cert-converter.py` and `keypair-converter.py` shell out to `chip-cert`, which must
  be on `PATH`. The project build produces it — `export PATH="$PWD/build:$PATH"` from
  the repo root.
- `csr-converter.py` needs the `cryptography` package; `ipk-converter.py` is stdlib only.

`tests/` holds sample inputs (CHIP TLV / X.509 cert pairs, keypair base64 / TLV pairs,
IPK elements) for quick checks, e.g. `python3 cert-converter.py tests/cert1_x509`.
