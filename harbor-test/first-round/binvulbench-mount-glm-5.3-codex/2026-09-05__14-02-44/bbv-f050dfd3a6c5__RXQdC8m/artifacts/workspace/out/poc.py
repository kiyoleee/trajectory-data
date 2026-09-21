#!/usr/bin/env python3

import argparse
import json
import os
import signal
import struct
import subprocess
import sys
import tempfile
import time


def signal_name(returncode):
    if returncode is None or returncode >= 0:
        return None
    try:
        return signal.Signals(-returncode).name
    except ValueError:
        return f"SIG{-returncode}"


def decode_output(data):
    if data is None:
        return ""
    return data.decode("utf-8", errors="replace")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--json-out")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()

    if args.timeout <= 0:
        parser.error("--timeout must be positive")

    payload = struct.pack("<ii", 0, 10)
    input_path = None
    returncode = None
    timed_out = False
    stdout = ""
    stderr = ""
    error = None
    runtime_ms = 0

    try:
        with tempfile.NamedTemporaryFile(prefix="s7dl-poc-", delete=False) as input_file:
            input_file.write(payload)
            input_path = input_file.name

        command = [args.binary, input_path]
        started = time.perf_counter()
        try:
            completed = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=args.timeout,
                check=False,
            )
            runtime_ms = round((time.perf_counter() - started) * 1000)
            returncode = completed.returncode
            stdout = decode_output(completed.stdout)
            stderr = decode_output(completed.stderr)
        except subprocess.TimeoutExpired as exc:
            runtime_ms = round((time.perf_counter() - started) * 1000)
            timed_out = True
            returncode = -signal.SIGKILL
            stdout = decode_output(exc.stdout)
            stderr = decode_output(exc.stderr)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
    finally:
        if input_path is not None:
            try:
                os.unlink(input_path)
            except FileNotFoundError:
                pass

    resolved_signal = signal_name(returncode)
    if resolved_signal is not None:
        outcome = f"crash:{resolved_signal}"
    elif returncode is None:
        outcome = "exit:none"
    else:
        outcome = f"exit:{returncode}"

    result = {
        "binary": args.binary,
        "command": [args.binary, input_path],
        "returncode": returncode,
        "signal": resolved_signal,
        "timed_out": timed_out,
        "runtime_ms": runtime_ms,
        "stdout": stdout,
        "stderr": stderr,
        "observable": {
            "kind": "custom",
            "value": outcome,
            "path": None,
        },
        "error": error,
    }

    rendered = json.dumps(result)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as output_file:
            output_file.write(rendered + "\n")
    print(rendered)


if __name__ == "__main__":
    main()
