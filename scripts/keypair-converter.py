#!/usr/bin/env python3
"""Convert key/public-key text and emit raw b64 + Matter opkey TLV b64.

Input can be:
- a literal key string
- a file path containing one key string

The script auto-detects format via:
1) Matter OperationalKeystore TLV base64 (custom parser)
2) chip-cert convert-key (private keypair formats)
3) chip-cert convert-key (public key formats)
"""

from __future__ import annotations

import argparse
import base64
import os
import re
import subprocess
import sys
from dataclasses import dataclass


P256_PUBLIC_KEY_LEN = 65
P256_PRIVATE_KEY_LEN = 32
P256_KEYPAIR_LEN = P256_PUBLIC_KEY_LEN + P256_PRIVATE_KEY_LEN


@dataclass
class ParsedInput:
    detected_format: str
    is_keypair: bool
    key_data: bytes


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


def _bytes_hex(data: bytes) -> str:
    return data.hex()


def _run_chip_cert_convert_key(out_flag: str, input_value: str) -> str:
    cp = subprocess.run(
        ["chip-cert", "convert-key", out_flag, input_value, "-"],
        check=False,
        capture_output=True,
    )
    if cp.returncode != 0:
        err = cp.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(err if err else "chip-cert convert-key failed")
    return cp.stdout.decode("utf-8", errors="replace").strip()


def _looks_like_hex(s: str) -> bool:
    t = _compact(s)
    if t.startswith(("0x", "0X")):
        t = t[2:]
    return len(t) > 0 and (len(t) % 2 == 0) and bool(re.fullmatch(r"[0-9a-fA-F]+", t))


def _guess_source_format_label(text: str) -> str:
    t = text.strip()
    if "BEGIN EC PRIVATE KEY" in t or "BEGIN PRIVATE KEY" in t or "BEGIN PUBLIC KEY" in t:
        return "x509-pem"
    if _looks_like_hex(t):
        return "x509/chip-hex (auto by chip-cert)"
    return "auto-detected by chip-cert"


def _parse_opkey_tlv(data: bytes) -> bytes | None:
    """Parse mOperationalKeystore format TLV and return embedded keypair bytes.

    Expected canonical form:
      Structure(anon)
        ContextTag(0): UnsignedInt(minimal width, value=1)
        ContextTag(1): ByteString = serialized keypair bytes
      EndOfContainer
    """
    if len(data) < 8:
        return None

    i = 0
    if data[i] != 0x15:  # Anonymous Structure
        return None
    i += 1

    # Context(0) + UnsignedInt (accept 1/2/4/8-byte widths)
    if i + 3 > len(data) or data[i + 1] != 0x00 or data[i] not in (0x24, 0x25, 0x26, 0x27):
        return None
    uint_len = {0x24: 1, 0x25: 2, 0x26: 4, 0x27: 8}[data[i]]
    if i + 2 + uint_len > len(data):
        return None
    version = int.from_bytes(data[i + 2 : i + 2 + uint_len], "little")
    if version != 1:
        return None
    i += 2 + uint_len

    # Context(1) + ByteString (accept 1/2/4/8-byte lengths)
    if i + 3 > len(data) or data[i + 1] != 0x01 or data[i] not in (0x30, 0x31, 0x32, 0x33):
        return None
    len_len = {0x30: 1, 0x31: 2, 0x32: 4, 0x33: 8}[data[i]]
    if i + 2 + len_len > len(data):
        return None
    bs_len = int.from_bytes(data[i + 2 : i + 2 + len_len], "little")
    i += 2 + len_len
    if i + bs_len + 1 != len(data):
        return None

    key_data = data[i : i + bs_len]
    i += bs_len

    if data[i] != 0x18:  # EndOfContainer
        return None

    return bytes(key_data)


def _build_opkey_tlv(keypair_bytes: bytes) -> bytes:
    """Build TLV matching PersistentStorageOperationalKeystore.

    Encoded as:
      0x15                        # anon structure
      0x24 0x00 0x01              # ctx(0), uint8, value=1 (canonical minimal encoding)
      0x30 0x01 <len1> <bytes...> # ctx(1), bytestring(1-byte length)
      0x18                        # end container
    """
    if len(keypair_bytes) > 0xFF:
        raise ValueError("keypair too long for 1-byte byte-string TLV length")

    out = bytearray()
    out.append(0x15)
    out.extend((0x24, 0x00, 0x01))
    out.extend((0x30, 0x01, len(keypair_bytes)))
    out.extend(keypair_bytes)
    out.append(0x18)
    return bytes(out)


def _detect_input(text: str) -> ParsedInput:
    # 1) Try direct parse as mOperationalKeystore TLV in base64.
    try:
        decoded = _b64_decode_strict(text)
        key_from_tlv = _parse_opkey_tlv(decoded)
        if key_from_tlv is not None:
            is_keypair = len(key_from_tlv) >= P256_KEYPAIR_LEN
            return ParsedInput(
                detected_format="matter-opkey-tlv-b64",
                is_keypair=is_keypair,
                key_data=key_from_tlv,
            )
    except Exception:
        pass

    # 2) Try keypair/private-key formats via chip-cert.
    try:
        keypair_b64 = _run_chip_cert_convert_key("--chip-b64", text)
        keypair_bytes = _b64_decode_strict(keypair_b64)
        return ParsedInput(
            detected_format=f"private-key/keypair ({_guess_source_format_label(text)})",
            is_keypair=True,
            key_data=keypair_bytes,
        )
    except Exception:
        pass

    # 3) Try public-key-only formats via chip-cert.
    try:
        pub_b64 = _run_chip_cert_convert_key("--chip-pubkey-b64", text)
        pub_bytes = _b64_decode_strict(pub_b64)
        return ParsedInput(
            detected_format=f"public-key ({_guess_source_format_label(text)})",
            is_keypair=False,
            key_data=pub_bytes,
        )
    except Exception as exc:
        raise ValueError(
            "input is not a recognized key/public-key format for chip-cert, "
            "and not mOperationalKeystore TLV base64"
        ) from exc


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Detect key/public-key format and output base64 raw key bytes; "
            "for keypair also output mOperationalKeystore TLV base64 and split pub/priv base64."
        )
    )
    parser.add_argument(
        "input_value",
        help="A key string, or a file path containing one key string.",
    )
    args = parser.parse_args()

    try:
        input_text, source_type = _read_input(args.input_value)
        parsed = _detect_input(input_text)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"INPUT SOURCE TYPE:     {source_type}")
    print(f"DETECTED INPUT FORMAT: {parsed.detected_format}")

    raw_b64 = _b64_encode(parsed.key_data)
    print("\nRaw Bytes key data:", f"({len(parsed.key_data)} bytes)")
    print("  bytes :", _bytes_hex(parsed.key_data))
    print("  base64:", raw_b64)

    if parsed.is_keypair:
        op_tlv = _build_opkey_tlv(parsed.key_data)
        op_tlv_b64 = _b64_encode(op_tlv)
        print("\nMatter TLV key data:")
        print("  bytes :", _bytes_hex(op_tlv))
        print("  base64:", op_tlv_b64)

        if len(parsed.key_data) >= P256_KEYPAIR_LEN:
            pub = parsed.key_data[:P256_PUBLIC_KEY_LEN]
            priv = parsed.key_data[P256_PUBLIC_KEY_LEN:P256_KEYPAIR_LEN]
            print("\nPublic key:", f"({len(pub)} bytes)")
            print("  bytes :", _bytes_hex(pub))
            print("  base64:", _b64_encode(pub))
            print("\nPrivate key:", f"({len(priv)} bytes)")
            print("  bytes :", _bytes_hex(priv))
            print("  base64:", _b64_encode(priv))
        else:
            print("\nPublic key (bytes hex): N/A (unexpected keypair length)")
            print("Public key (base64): N/A (unexpected keypair length)")
            print("Private key (bytes hex): N/A (unexpected keypair length)")
            print("Private key (base64): N/A (unexpected keypair length)")
    else:
        print("\nMatter TLV key data (bytes hex):")
        print("N/A (input is public-key only; mOperationalKeystore stores keypair)")
        print("\nMatter TLV key data (base64):")
        print("N/A (input is public-key only; mOperationalKeystore stores keypair)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
