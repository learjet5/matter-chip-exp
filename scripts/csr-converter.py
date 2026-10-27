#!/usr/bin/env python3
"""Detect base64 input as keypair or CSR, then convert/parse accordingly.

Input can be either:
- a literal base64 string
- a file path containing one base64 string

Behavior:
- If input is keypair: parse pub/priv, generate random nonce, generate CSR (DER), output base64.
- If input is CSR: parse and output public key length + public key base64.
"""

from __future__ import annotations

import argparse
import base64
import os
import sys
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


P256_PUBLIC_KEY_LEN = 65
P256_PRIVATE_KEY_LEN = 32
P256_KEYPAIR_LEN = P256_PUBLIC_KEY_LEN + P256_PRIVATE_KEY_LEN
CSR_NONCE_LEN = 32


@dataclass
class ParsedInput:
    kind: str
    source_type: str
    raw_input_bytes: bytes
    keypair_bytes: bytes | None = None
    csr_der: bytes | None = None


def _read_input(arg: str) -> tuple[str, str]:
    if os.path.isfile(arg):
        with open(arg, "r", encoding="utf-8") as f:
            return f.read().strip(), "file"
    return arg.strip(), "string"


def _compact(s: str) -> str:
    return "".join(s.split())


def _b64_decode_strict(s: str) -> bytes:
    compact = _compact(s)
    if not compact:
        raise ValueError("empty input")
    pad = "=" * ((4 - (len(compact) % 4)) % 4)
    return base64.b64decode(compact + pad, validate=True)


def _b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _parse_opkey_tlv(data: bytes) -> bytes | None:
    """Parse Matter OperationalKeystore TLV and return embedded keypair bytes."""
    if len(data) < 8:
        return None

    i = 0
    if data[i] != 0x15:
        return None
    i += 1

    if i + 3 > len(data) or data[i + 1] != 0x00 or data[i] not in (0x24, 0x25, 0x26, 0x27):
        return None
    uint_len = {0x24: 1, 0x25: 2, 0x26: 4, 0x27: 8}[data[i]]
    if i + 2 + uint_len > len(data):
        return None
    version = int.from_bytes(data[i + 2 : i + 2 + uint_len], "little")
    if version != 1:
        return None
    i += 2 + uint_len

    if i + 3 > len(data) or data[i + 1] != 0x01 or data[i] not in (0x30, 0x31, 0x32, 0x33):
        return None
    len_len = {0x30: 1, 0x31: 2, 0x32: 4, 0x33: 8}[data[i]]
    if i + 2 + len_len > len(data):
        return None
    bs_len = int.from_bytes(data[i + 2 : i + 2 + len_len], "little")
    i += 2 + len_len

    if i + bs_len + 1 != len(data):
        return None
    payload = data[i : i + bs_len]
    i += bs_len

    if data[i] != 0x18:
        return None

    return bytes(payload)


def _keypair_from_der_private_key(data: bytes) -> bytes | None:
    """Try DER private key -> raw keypair (pub65 + priv32)."""
    try:
        key = serialization.load_der_private_key(data, password=None)
    except Exception:
        return None

    if not isinstance(key, ec.EllipticCurvePrivateKey):
        return None
    if not isinstance(key.curve, ec.SECP256R1):
        return None

    priv_int = key.private_numbers().private_value
    priv = priv_int.to_bytes(P256_PRIVATE_KEY_LEN, "big")
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    if len(pub) != P256_PUBLIC_KEY_LEN:
        return None

    return pub + priv


def _parse_input(input_text: str, source_type: str) -> ParsedInput:
    data = _b64_decode_strict(input_text)

    key_from_tlv = _parse_opkey_tlv(data)
    if key_from_tlv is not None:
        if len(key_from_tlv) != P256_KEYPAIR_LEN or key_from_tlv[0] != 0x04:
            raise ValueError(
                f"TLV contains key bytes but not expected P256 keypair (need {P256_KEYPAIR_LEN} bytes, got {len(key_from_tlv)})"
            )
        return ParsedInput(
            kind="keypair",
            source_type=source_type,
            raw_input_bytes=data,
            keypair_bytes=key_from_tlv,
        )

    if len(data) == P256_KEYPAIR_LEN and data[0] == 0x04:
        return ParsedInput(
            kind="keypair",
            source_type=source_type,
            raw_input_bytes=data,
            keypair_bytes=data,
        )

    try:
        x509.load_der_x509_csr(data)
        return ParsedInput(
            kind="csr",
            source_type=source_type,
            raw_input_bytes=data,
            csr_der=data,
        )
    except Exception:
        pass

    keypair_from_der = _keypair_from_der_private_key(data)
    if keypair_from_der is not None:
        return ParsedInput(
            kind="keypair",
            source_type=source_type,
            raw_input_bytes=data,
            keypair_bytes=keypair_from_der,
        )

    raise ValueError(
        "input is neither a supported keypair base64 (raw 97 bytes or Matter opkey TLV), "
        "nor a DER CSR base64"
    )


def _build_private_key_from_keypair(keypair_bytes: bytes) -> tuple[ec.EllipticCurvePrivateKey, bytes, bytes]:
    if len(keypair_bytes) != P256_KEYPAIR_LEN:
        raise ValueError(f"invalid keypair length: {len(keypair_bytes)} (expected {P256_KEYPAIR_LEN})")

    pub = keypair_bytes[:P256_PUBLIC_KEY_LEN]
    priv = keypair_bytes[P256_PUBLIC_KEY_LEN:]

    if pub[0] != 0x04:
        raise ValueError("invalid uncompressed public key prefix (expected 0x04)")

    priv_int = int.from_bytes(priv, "big")
    if priv_int == 0:
        raise ValueError("invalid private key value: zero")

    private_key = ec.derive_private_key(priv_int, ec.SECP256R1())
    derived_pub = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )

    if derived_pub != pub:
        raise ValueError("keypair public key does not match private key")

    return private_key, pub, priv


def _generate_csr_from_keypair(keypair_bytes: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    private_key, pub, priv = _build_private_key_from_keypair(keypair_bytes)

    # Matter flow uses nonce for NOCSR elements binding; nonce is generated here and printed.
    nonce = os.urandom(CSR_NONCE_LEN)

    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "CSA"),
    ])

    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(private_key, hashes.SHA256())

    csr_der = csr.public_bytes(serialization.Encoding.DER)
    return csr_der, pub, priv, nonce


def _parse_csr_pubkey(csr_der: bytes) -> bytes:
    csr = x509.load_der_x509_csr(csr_der)
    public_key = csr.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(public_key.curve, ec.SECP256R1):
        raise ValueError("CSR public key is not ECP256")

    pub = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    return pub


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Input a base64 string or a file path containing base64. "
            "Auto-detect keypair vs CSR; keypair->generate CSR, CSR->extract pubkey."
        )
    )
    parser.add_argument("input_value", help="Base64 string, or file path containing one base64 string")
    args = parser.parse_args()

    try:
        input_text, source_type = _read_input(args.input_value)
        parsed = _parse_input(input_text, source_type)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"INPUT SOURCE TYPE: {parsed.source_type}")
    print(f"DETECTED TYPE:     {parsed.kind}")

    if parsed.kind == "keypair":
        assert parsed.keypair_bytes is not None
        try:
            csr_der, pub, priv, nonce = _generate_csr_from_keypair(parsed.keypair_bytes)
        except Exception as exc:
            print(f"Error: failed to generate CSR from keypair: {exc}", file=sys.stderr)
            return 1

        print(f"\nPublic key length: {len(pub)} bytes")
        print(f"Public key base64: {_b64_encode(pub)}")
        print(f"Private key length: {len(priv)} bytes")
        print(f"Private key base64: {_b64_encode(priv)}")
        print(f"Random nonce length: {len(nonce)} bytes")
        print(f"Random nonce base64: {_b64_encode(nonce)}")
        print(f"\nGenerated CSR DER length: {len(csr_der)} bytes")
        print(f"Generated CSR base64: {_b64_encode(csr_der)}")
        return 0

    assert parsed.csr_der is not None
    try:
        pub = _parse_csr_pubkey(parsed.csr_der)
    except Exception as exc:
        print(f"Error: failed to parse CSR: {exc}", file=sys.stderr)
        return 1

    print(f"\nCSR public key length: {len(pub)} bytes")
    print(f"CSR public key base64: {_b64_encode(pub)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
