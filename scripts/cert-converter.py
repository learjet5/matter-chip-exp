#!/usr/bin/env python3
# using `chip-cert convert-cert` to convert between CHIP TLV and X509 DER certs, and print some details.
"""Convert Matter certificates between CHIP TLV and X509 DER (base64 text)."""

from __future__ import annotations

import argparse
import base64
import os
import re
import subprocess
import sys
import tempfile


def _read_input(arg: str) -> tuple[str | bytes, str]:
    """Return certificate data (text, or raw bytes for binary files) and source type."""
    if os.path.isfile(arg):
        with open(arg, "rb") as f:
            raw = f.read()
        try:
            return raw.decode("utf-8").strip(), "file"
        except UnicodeDecodeError:
            return raw, "file"
    return arg.strip(), "string"


def _b64_decode_strict(s: str) -> bytes:
    compact = "".join(s.split())
    if not compact:
        raise ValueError("empty input")
    pad = "=" * ((4 - (len(compact) % 4)) % 4)
    try:
        return base64.b64decode(compact + pad, validate=True)
    except Exception as exc:  # pragma: no cover
        raise ValueError("input is not valid base64 text") from exc


def _tokens_to_bytes(tokens: list[str], default_base: int) -> bytes:
    out = bytearray()
    for tok in tokens:
        try:
            value = int(tok, 16) if tok[:2] in ("0x", "0X") else int(tok, default_base)
        except ValueError as exc:
            raise ValueError(f"byte array contains a non-numeric element: {tok!r}") from exc
        if not 0 <= value <= 255:
            raise ValueError(f"byte array element out of range (0-255): {tok}")
        out.append(value)
    return bytes(out)


def _parse_byte_list(text: str) -> bytes | None:
    """Parse Uint8Array/Buffer notations into bytes; return None if not that shape.

    Accepts Uint8Array(n) [21, 48, ...], new Uint8Array([...]), [0x15, 0x30, ...],
    {"type":"Buffer","data":[...]}, <Buffer 15 30 ...> and "\\x15\\x30..." strings.
    """
    t = text.strip()

    if t.startswith("<Buffer"):
        if "more byte" in t:
            raise ValueError("<Buffer ...> dump is truncated by the console; paste the full data")
        m = re.fullmatch(r"<Buffer\s*([0-9a-fA-F\s]*)>", t)
        if m is None:
            raise ValueError("unrecognized <Buffer ...> dump")
        return _tokens_to_bytes(m.group(1).split(), default_base=16)

    unquoted = "".join(t.split()).strip("\"'")
    if re.fullmatch(r"(?:\\x[0-9a-fA-F]{2})+", unquoted):
        return bytes(int(h, 16) for h in re.findall(r"\\x([0-9a-fA-F]{2})", unquoted))

    start, end = t.find("["), t.rfind("]")
    if start == -1 or end < start:
        return None
    body = t[start + 1 : end].strip()
    if not body:
        raise ValueError("byte array is empty")
    if "more item" in body:
        raise ValueError("byte array is truncated by the console; paste the full data")
    return _tokens_to_bytes([tok for tok in re.split(r"[,\s]+", body) if tok], default_base=10)


def _hex_decode(text: str) -> bytes | None:
    """Decode a hex string (optional 0x prefix, optional separators); None if not hex."""
    compact = re.sub(r"[\s,:_-]", "", text)
    if compact[:2] in ("0x", "0X"):
        compact = compact[2:]
    if not compact or len(compact) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", compact):
        return None
    return bytes.fromhex(compact)


def _decode_input(data: str | bytes) -> tuple[bytes, str]:
    """Return raw certificate bytes plus the input encoding they were decoded from."""
    if isinstance(data, bytes):
        return data, "raw-binary"

    byte_list = _parse_byte_list(data)
    if byte_list is not None:
        return byte_list, "uint8array"

    # A plain hex string is also valid base64 text, so decide by which decoding
    # actually yields a plausible certificate. Hex is checked first because real
    # base64 certificates virtually always contain non-hex characters.
    candidates: list[tuple[bytes, str]] = []
    hex_bytes = _hex_decode(data)
    if hex_bytes:
        candidates.append((hex_bytes, "hex"))
    try:
        candidates.append((_b64_decode_strict(data), "base64"))
    except ValueError:
        pass

    for raw, encoding in candidates:
        if _looks_like_der_x509(raw) or _looks_like_chip_tlv(raw):
            return raw, encoding
    if candidates:
        # Nothing looks like a certificate; pass the likeliest bytes on so that
        # chip-cert reports the real problem. base64 is last, and preferred.
        return candidates[-1]
    raise ValueError("input is not a byte array, hex, or base64 text")


def _parse_der_len(data: bytes, idx: int) -> tuple[int, int] | tuple[None, None]:
    if idx >= len(data):
        return None, None
    first = data[idx]
    if first < 0x80:
        return first, idx + 1
    nbytes = first & 0x7F
    if nbytes == 0 or nbytes > 4 or idx + 1 + nbytes > len(data):
        return None, None
    value = 0
    for b in data[idx + 1 : idx + 1 + nbytes]:
        value = (value << 8) | b
    return value, idx + 1 + nbytes


def _looks_like_der_x509(decoded: bytes) -> bool:
    # X509 DER cert should be ASN.1 SEQUENCE containing another SEQUENCE (TBSCertificate).
    if len(decoded) < 8 or decoded[0] != 0x30:
        return False
    total_len, content_start = _parse_der_len(decoded, 1)
    if total_len is None or content_start + total_len != len(decoded):
        return False
    if content_start >= len(decoded) or decoded[content_start] != 0x30:
        return False
    tbs_len, tbs_start = _parse_der_len(decoded, content_start + 1)
    if tbs_len is None or tbs_start + tbs_len > len(decoded):
        return False
    return True


def _looks_like_chip_tlv(decoded: bytes) -> bool:
    # A CHIP TLV certificate is an anonymous structure: 0x15 ... 0x18.
    return len(decoded) > 2 and decoded[0] == 0x15 and decoded[-1] == 0x18


def _detect_format(raw: bytes) -> str:
    return "x509-der" if _looks_like_der_x509(raw) else "chip-tlv"


def _run_chip_cert(args: list[str], binary_stdout: bool = False) -> bytes | str:
    cp = subprocess.run(
        ["chip-cert", *args],
        check=False,
        capture_output=True,
    )
    if cp.returncode != 0:
        err = cp.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"chip-cert failed: {err}")
    if binary_stdout:
        return cp.stdout
    return cp.stdout.decode("utf-8", errors="replace").strip()


def _convert(raw: bytes, detected: str) -> tuple[str, str]:
    if detected == "x509-der":
        with tempfile.NamedTemporaryFile("wb", delete=True) as derf:
            derf.write(raw)
            derf.flush()
            chip_b64 = _run_chip_cert(["convert-cert", "--chip-b64", derf.name, "-"])
        return chip_b64, base64.b64encode(raw).decode("ascii")

    # Input is CHIP TLV; hand chip-cert its base64 form.
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=True) as tf:
        tf.write(base64.b64encode(raw).decode("ascii"))
        tf.flush()
        chip_b64 = _run_chip_cert(["convert-cert", "--chip-b64", tf.name, "-"])
        der_bytes = _run_chip_cert(
            ["convert-cert", "--x509-der", tf.name, "-"], binary_stdout=True
        )
    return chip_b64, base64.b64encode(der_bytes).decode("ascii")


def _print_cert_output(chip_b64: str) -> str:
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=True) as tf:
        tf.write(chip_b64)
        tf.flush()
        return _run_chip_cert(["print-cert", tf.name])


def _parse_subject_fields(print_output: str) -> list[tuple[str, str]]:
    lines = print_output.splitlines()
    start_idx = None
    for i, line in enumerate(lines):
        if re.match(r"^\s*Subject\s*:\s*\[\[", line):
            start_idx = i
            break
    if start_idx is None:
        return []

    subject_parts: list[str] = []
    line = lines[start_idx]
    after = line.split("[[", 1)[1]
    if "]]" in after:
        subject_parts.append(after.split("]]", 1)[0])
    else:
        subject_parts.append(after)
        j = start_idx + 1
        while j < len(lines):
            seg = lines[j]
            if "]]" in seg:
                subject_parts.append(seg.split("]]", 1)[0])
                break
            subject_parts.append(seg)
            j += 1

    subject_text = " ".join(p.strip() for p in subject_parts).strip()
    if not subject_text:
        return []

    fields: list[tuple[str, str]] = []
    for m in re.finditer(r"([A-Za-z0-9_]+)\s*=\s*([^,\]]+)", subject_text):
        key = m.group(1).strip()
        value = m.group(2).strip()
        fields.append((key, value))
    return fields


def _parse_public_key_bytes(print_output: str) -> bytes | None:
    lines = print_output.splitlines()
    for idx, line in enumerate(lines):
        if not re.match(r"^\s*Public Key\s*:", line):
            continue
        _, rest = line.split(":", 1)
        hex_chunks = [rest.strip()] if rest.strip() else []
        j = idx + 1
        while j < len(lines):
            cont = lines[j]
            if re.fullmatch(r"\s+[0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2})*\s*", cont):
                hex_chunks.append(cont.strip())
                j += 1
                continue
            break
        hex_text = " ".join(hex_chunks).strip()
        if not hex_text:
            return None
        return bytes.fromhex(hex_text)
    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Convert a Matter certificate (CHIP TLV or X509 DER, given as base64, hex, "
            "or a Uint8Array/Buffer dump) and output both forms."
        )
    )
    parser.add_argument(
        "input_value",
        help=(
            "Certificate as base64, hex, or Uint8Array/Buffer text; "
            "or a file path holding any of those (or raw binary)."
        ),
    )
    args = parser.parse_args()

    try:
        input_data, _ = _read_input(args.input_value)
        raw, encoding = _decode_input(input_data)
        detected = _detect_format(raw)
        chip_b64, x509_der_b64 = _convert(raw, detected)
        print_output = _print_cert_output(chip_b64)
        subject_fields = _parse_subject_fields(print_output)
        pubkey_bytes = _parse_public_key_bytes(print_output)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if pubkey_bytes is None:
        pubkey_b64 = "N/A"
        pubkey_len = "N/A"
    else:
        pubkey_b64 = base64.b64encode(pubkey_bytes).decode("ascii")
        pubkey_len = str(len(pubkey_bytes))

    print(f"DETECTED INPUT FORMAT: {detected} (encoding: {encoding})")
    print("\nCHIP TLV (base64):")
    print(chip_b64)
    print("\nCHIP TLV (hex):")
    print(_b64_decode_strict(chip_b64).hex())
    print("\nX509 DER (base64):")
    print(x509_der_b64)
    print("\nX509 DER (hex):")
    print(_b64_decode_strict(x509_der_b64).hex())
    print("")
    print("Public Key (bytes -> base64):", pubkey_b64)
    print("Public Key Length (bytes)   :", pubkey_len)
    if not subject_fields:
        print("N/A")
    else:
        for key, raw in subject_fields:
            clean = raw[2:] if raw.lower().startswith("0x") else raw
            if re.fullmatch(r"[0-9A-Fa-f]+", clean):
                value_hex = f"0x{clean.upper()}"
                value_dec = str(int(clean, 16))
            else:
                value_hex = "N/A"
                value_dec = "N/A"
            print(f"{key}: {value_dec} (dec), {value_hex} (hex)")
    print("\nchip-cert print-cert output:")
    print(print_output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
