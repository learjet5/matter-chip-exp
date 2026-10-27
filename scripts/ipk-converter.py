#!/usr/bin/env python3
"""Compute Matter CASE operational IPK from epoch key + fabric info.

Inputs:
1) CLI positional args: epoch_key fabric_id root_public_key
2) JSON file: --json /path/to/file
3) Single base64 string: convert between keyset TLV base64 and direct 16-byte base64

The implementation mirrors CHIP SDK logic:
- GenerateCompressedFabricId(root_public_key, fabric_id)
- DeriveGroupOperationalKey(epoch_key, compressed_fabric_id)
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import sys
from dataclasses import dataclass


def _compact(s: str) -> str:
    return "".join(s.split())


def _b64_decode_strict(s: str) -> bytes:
    text = _compact(s)
    if not text:
        raise ValueError("empty base64 input")
    pad = "=" * ((4 - (len(text) % 4)) % 4)
    return base64.b64decode(text + pad, validate=True)


def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    if length <= 0:
        raise ValueError("HKDF length must be > 0")
    if len(salt) == 0:
        salt = bytes([0] * hashlib.sha256().digest_size)

    prk = hmac.new(salt, ikm, hashlib.sha256).digest()

    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


@dataclass
class Inputs:
    epoch_key: bytes
    fabric_id: int
    root_public_key: bytes


def _parse_epoch_key(value: str) -> bytes:
    # Accept raw 16-char text, hex (0x.. or plain), or base64.
    raw = value
    if len(raw) == 16:
        return raw.encode("utf-8")

    compact = _compact(raw)

    hex_candidate = compact
    if hex_candidate.startswith(("0x", "0X")):
        hex_candidate = hex_candidate[2:]
    if len(hex_candidate) == 32 and re.fullmatch(r"[0-9a-fA-F]{32}", hex_candidate):
        parsed = bytes.fromhex(hex_candidate)
        if len(parsed) == 16:
            return parsed

    try:
        parsed = _b64_decode_strict(compact)
        if len(parsed) == 16:
            return parsed
    except Exception:
        pass

    raise ValueError(
        "epoch_key must represent exactly 16 bytes (raw 16-char string, 32-hex chars, or base64 of 16 bytes)"
    )


def _parse_fabric_id(value: str) -> int:
    text = value.strip()
    base = 16 if text.startswith(("0x", "0X")) else 10
    fabric_id = int(text, base)
    if fabric_id < 0 or fabric_id > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("fabric_id must fit uint64")
    return fabric_id


def _parse_root_public_key(value: str) -> bytes:
    compact = _compact(value)

    # Try base64 first.
    try:
        b = _b64_decode_strict(compact)
        if len(b) == 65 and b[0] == 0x04:
            return b
    except Exception:
        pass

    # Try hex: 130 hex chars (with or without 0x).
    hex_candidate = compact[2:] if compact.startswith(("0x", "0X")) else compact
    if len(hex_candidate) == 130 and re.fullmatch(r"[0-9a-fA-F]{130}", hex_candidate):
        b = bytes.fromhex(hex_candidate)
        if b[0] == 0x04:
            return b

    raise ValueError(
        "root_public_key must be uncompressed P256 public key (65 bytes, starts with 0x04), in base64 or hex"
    )


def _load_inputs_from_json(path: str) -> Inputs:
    with open(path, "r", encoding="utf-8") as f:
        doc = json.load(f)

    # Support user sample field names plus canonical names.
    epoch_raw = doc.get("epoch_key")
    if epoch_raw is None:
        epoch_raw = doc.get("epoch_key_16bytes")

    fabric_raw = doc.get("fabric_id")
    if fabric_raw is None:
        fabric_raw = doc.get("fabric_id_int")

    root_raw = doc.get("root_public_key")
    if root_raw is None:
        root_raw = doc.get("root_public_key_base64")

    if epoch_raw is None or fabric_raw is None or root_raw is None:
        raise ValueError(
            "json must contain epoch_key(epoch_key_16bytes), fabric_id(fabric_id_int), root_public_key(root_public_key_base64)"
        )

    return Inputs(
        epoch_key=_parse_epoch_key(str(epoch_raw)),
        fabric_id=_parse_fabric_id(str(fabric_raw)),
        root_public_key=_parse_root_public_key(str(root_raw)),
    )


def _load_inputs_from_cli(epoch_key: str, fabric_id: str, root_public_key: str) -> Inputs:
    return Inputs(
        epoch_key=_parse_epoch_key(epoch_key),
        fabric_id=_parse_fabric_id(fabric_id),
        root_public_key=_parse_root_public_key(root_public_key),
    )


def _generate_compressed_fabric_id(root_public_key: bytes, fabric_id: int) -> bytes:
    # CHIP SDK: input key is root public key without uncompressed-point prefix byte.
    input_key = root_public_key[1:]

    # CHIP SDK: fabric id in big-endian byte order as HKDF salt.
    fabric_id_salt = fabric_id.to_bytes(8, "big")

    # CHIP SDK constant: "CompressedFabric"
    info = b"CompressedFabric"

    # Output length is 64 bits = 8 bytes.
    return _hkdf_sha256(input_key, fabric_id_salt, info, 8)


def _derive_operational_ipk(epoch_key: bytes, compressed_fabric_id: bytes) -> bytes:
    # CHIP SDK constant: "GroupKey v1.0"
    info = b"GroupKey v1.0"

    # Operational group key length = 16 bytes.
    return _hkdf_sha256(epoch_key, compressed_fabric_id, info, 16)


def _derive_group_session_id(operational_key: bytes) -> int:
    if len(operational_key) != 16:
        raise ValueError("operational key must be 16 bytes")
    # CHIP SDK DeriveGroupSessionId: HKDF(input=OperationalKey, salt=[], info="GroupKeyHash", len=2)
    out = _hkdf_sha256(operational_key, b"", b"GroupKeyHash", 2)
    return int.from_bytes(out, "big")


def _encode_ctx_uint(tag: int, value: int) -> bytes:
    if value < 0:
        raise ValueError("value must be non-negative")
    if value <= 0xFF:
        return bytes((0x24, tag, value))
    if value <= 0xFFFF:
        return bytes((0x25, tag)) + value.to_bytes(2, "little")
    if value <= 0xFFFFFFFF:
        return bytes((0x26, tag)) + value.to_bytes(4, "little")
    return bytes((0x27, tag)) + value.to_bytes(8, "little")


def _build_ipk_keyset_tlv(operational_ipk: bytes, *, policy: int = 0, keys_count: int = 1, next_keyset_id: int = 0) -> bytes:
    if len(operational_ipk) != 16:
        raise ValueError("operational key must be 16 bytes")

    key_hash = _derive_group_session_id(operational_ipk)
    zero16 = b"\x00" * 16

    def _cred_struct(start_time: int, h: int, key: bytes) -> bytes:
        out = bytearray()
        out.append(0x15)  # anon structure
        out.extend(_encode_ctx_uint(0x04, start_time))
        out.extend(_encode_ctx_uint(0x05, h))
        out.extend((0x30, 0x06, len(key)))  # ctx(6) bytes, 1-byte length
        out.extend(key)
        out.append(0x18)
        return bytes(out)

    arr = bytearray()
    arr.extend(_cred_struct(0, key_hash, operational_ipk))
    arr.extend(_cred_struct(0, 0, zero16))
    arr.extend(_cred_struct(0, 0, zero16))

    out = bytearray()
    out.append(0x15)  # anon structure
    out.extend(_encode_ctx_uint(0x01, policy))
    out.extend(_encode_ctx_uint(0x02, keys_count))
    out.extend((0x36, 0x03))  # ctx(3) array
    out.extend(arr)
    out.append(0x18)  # end array
    out.extend(_encode_ctx_uint(0x07, next_keyset_id))
    out.append(0x18)  # end structure
    return bytes(out)


def _extract_first_keyvalue_from_ipk_keyset_tlv(blob: bytes) -> bytes | None:
    # KeySetData uses context tag 6 for key bytes. Scan for first ctx(6) byte-string of exactly 16 bytes.
    i = 0
    n = len(blob)
    while i + 4 <= n:
        ctrl = blob[i]
        if ctrl in (0x30, 0x31, 0x32, 0x33) and i + 2 <= n and blob[i + 1] == 0x06:
            len_len = {0x30: 1, 0x31: 2, 0x32: 4, 0x33: 8}[ctrl]
            if i + 2 + len_len > n:
                return None
            data_len = int.from_bytes(blob[i + 2 : i + 2 + len_len], "little")
            data_start = i + 2 + len_len
            data_end = data_start + data_len
            if data_end > n:
                return None
            if data_len == 16:
                return blob[data_start:data_end]
            i = data_end
            continue
        i += 1
    return None


def _convert_single_b64(input_b64: str) -> tuple[bytes, bytes, str]:
    raw = _b64_decode_strict(input_b64)

    # If exact 16-byte input, treat as direct operational key.
    if len(raw) == 16:
        tlv = _build_ipk_keyset_tlv(raw)
        return raw, tlv, "direct"

    # Otherwise, try parse as IPK keyset TLV and extract first keyvalue(tag=6, len=16).
    key = _extract_first_keyvalue_from_ipk_keyset_tlv(raw)
    if key is None:
        raise ValueError(
            "single base64 input must be either direct 16-byte key base64, or an IPK keyset TLV base64 containing TagKeyValue(6)"
        )

    # Keep original TLV as-is, and output normalized direct key b64.
    return key, raw, "tlv"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _hex(data: bytes) -> str:
    return data.hex()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Compute Matter CASE operational IPK from epoch key, fabric id, and root public key. "
            "Also supports single base64 conversion mode (direct 16-byte key <-> IPK keyset TLV)."
        )
    )
    parser.add_argument("epoch_key", nargs="?", help="Epoch key (16 bytes): raw(16 chars), hex, or base64")
    parser.add_argument("fabric_id", nargs="?", help="Fabric ID (uint64): decimal or 0x-prefixed hex")
    parser.add_argument("root_public_key", nargs="?", help="Root public key (uncompressed P256, 65 bytes): base64 or hex")
    parser.add_argument("--json", dest="json_path", help="JSON file containing input fields")

    args = parser.parse_args()

    try:
        # Mode A: single base64 conversion mode (no INPUT SOURCE output per request)
        if args.json_path is None and args.epoch_key and (args.fabric_id is None) and (args.root_public_key is None):
            key_bytes, tlv_bytes, detected = _convert_single_b64(args.epoch_key)

            print(f"ipk_direct ({len(key_bytes)} bytes):")
            print(f"  hex   : {_hex(key_bytes)}")
            print(f"  base64: {_b64(key_bytes)}")
            print("")
            print(f"ipk_keyset_tlv: ({len(tlv_bytes)} bytes)")
            # print(f"  hex   : {_hex(tlv_bytes)}")
            print(f"  base64: {_b64(tlv_bytes)}")
            print("")
            print(f"detected_single_input_format: {detected}")
            return 0

        # Mode B: original compute mode
        if args.json_path:
            if args.epoch_key or args.fabric_id or args.root_public_key:
                raise ValueError("use either --json or 3 positional args, not both")
            if not os.path.isfile(args.json_path):
                raise ValueError(f"json file not found: {args.json_path}")
            inputs = _load_inputs_from_json(args.json_path)
            source = f"json:{args.json_path}"
        else:
            if not (args.epoch_key and args.fabric_id and args.root_public_key):
                raise ValueError(
                    "provide 3 args: epoch_key fabric_id root_public_key, or use --json <file>, or provide 1 base64 arg for conversion"
                )
            inputs = _load_inputs_from_cli(args.epoch_key, args.fabric_id, args.root_public_key)
            source = "cli"

        compressed_fabric_id = _generate_compressed_fabric_id(inputs.root_public_key, inputs.fabric_id)
        operational_ipk = _derive_operational_ipk(inputs.epoch_key, compressed_fabric_id)
        operational_ipk_tlv = _build_ipk_keyset_tlv(operational_ipk)

    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"INPUT SOURCE: {source}")
    print(f"epoch_key (16Bytes)            hex: {_hex(inputs.epoch_key)}")
    print(f"fabric_id (int)                dec: {inputs.fabric_id}")
    # print(f"fabric_id                  hex: 0x{inputs.fabric_id:016X}")
    print(f"root_public_key (65Bytes)      hex: {_hex(inputs.root_public_key)}")
    print(f"compressed_fabric_id (8Bytes)  hex: {_hex(compressed_fabric_id)}")
    print("")
    print("operational_ipk (16Bytes):")
    print(f"  hex   : {_hex(operational_ipk)}")
    print(f"  base64: {_b64(operational_ipk)}")
    print(f"  tlv_b64: {_b64(operational_ipk_tlv)}")
    byte_values = ", ".join(f"{int(b)}" for b in operational_ipk)
    print(f"  bytes : {byte_values}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
