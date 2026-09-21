#!/usr/bin/env python3
"""Drive s7dl with a minimal, runtime-constructed trigger input.

The target expects an 8-byte little-endian header (i32 block number, i32
transfer size) followed by a data buffer.  Supplying a positive transfer size
with an empty buffer causes the provided binaries to fault while processing
the request.  This script always constructs that input at runtime, runs the
binary exactly once, and reports the observed outcome faithfully.
"""

import argparse
import json
import os
import signal as signal_module
import struct
import subprocess
import sys
import tempfile
import time


def normalize_outcome(returncode):
    """Return (observable_value, signal_name_or_none)."""
    if returncode is not None and returncode < 0:
        signum = -returncode
        try:
            name = signal_module.Signals(signum).name
        except (ValueError, OverflowError):
            name = "SIG" + str(signum)
        return "crash:" + name, name
    if returncode is None:
        return "exit:unknown", None
    return "exit:" + str(returncode), None


def build_trigger():
    block_number = 0
    transfer_size = 1
    return struct.pack("<ii", block_number, transfer_size)


def decode_output(raw):
    if raw is None:
        return ""
    return raw.decode("utf-8", errors="replace")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, help="path to the s7dl binary")
    parser.add_argument("--json-out", default=None, help="optional path for result JSON")
    parser.add_argument("--timeout", type=float, default=10.0, help="per-run timeout in seconds")
    args = parser.parse_args(argv)

    binary = args.binary
    payload = build_trigger()

    tmpdir = tempfile.TemporaryDirectory(prefix="s7dl-poc-")
    input_path = os.path.join(tmpdir.name, "input.bin")
    try:
        with open(input_path, "wb") as handle:
            handle.write(payload)

        command = [binary, input_path]
        started = time.perf_counter()
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        timed_out = False
        try:
            stdout, stderr = proc.communicate(timeout=args.timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.kill()
            stdout, stderr = proc.communicate()
        elapsed_ms = int((time.perf_counter() - started) * 1000)

        returncode = proc.returncode
    finally:
        tmpdir.cleanup()

    observable_value, signal_name = normalize_outcome(returncode)

    result = {
        "binary": binary,
        "command": command,
        "returncode": returncode,
        "signal": signal_name,
        "timed_out": timed_out,
        "runtime_ms": elapsed_ms,
        "stdout": decode_output(stdout),
        "stderr": decode_output(stderr),
        "observable": {"kind": "custom", "value": observable_value, "path": None},
        "error": None,
    }

    rendered = json.dumps(result)
    sys.stdout.write(rendered + "\n")
    sys.stdout.flush()

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as handle:
            handle.write(rendered + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
