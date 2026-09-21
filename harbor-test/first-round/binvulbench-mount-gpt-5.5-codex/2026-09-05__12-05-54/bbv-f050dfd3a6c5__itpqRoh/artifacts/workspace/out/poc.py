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
    signum = -returncode
    try:
        return signal.Signals(signum).name
    except ValueError:
        return "SIG{}".format(signum)


def build_input():
    block_num = 0
    transfer_size = 0x7FFFFFFF
    data = b"A" * 16
    return struct.pack("<ii", block_num, transfer_size) + data


def decode_output(data):
    return data.decode("utf-8", errors="replace")


def make_result(binary, command, returncode, timed_out, runtime_ms, stdout, stderr, error):
    sig = signal_name(returncode)
    if timed_out:
        observable_value = "timeout"
    elif sig is not None:
        observable_value = "crash:{}".format(sig)
    else:
        observable_value = "exit:{}".format(returncode)

    return {
        "binary": binary,
        "command": command,
        "returncode": returncode,
        "signal": sig,
        "timed_out": timed_out,
        "runtime_ms": runtime_ms,
        "stdout": stdout,
        "stderr": stderr,
        "observable": {
            "kind": "custom",
            "value": observable_value,
            "path": None,
        },
        "error": error,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--json-out")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()

    temp_path = None
    stdout = ""
    stderr = ""
    returncode = None
    timed_out = False
    error = None
    start = time.monotonic()

    try:
        with tempfile.NamedTemporaryFile(prefix="s7dl-input-", delete=False) as tmp:
            temp_path = tmp.name
            tmp.write(build_input())

        command = [args.binary, temp_path]
        try:
            completed = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=args.timeout,
                check=False,
            )
            returncode = completed.returncode
            stdout = decode_output(completed.stdout)
            stderr = decode_output(completed.stderr)
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            stdout = decode_output(exc.stdout or b"")
            stderr = decode_output(exc.stderr or b"")
            error = "timeout after {} seconds".format(args.timeout)
        except OSError as exc:
            error = "{}: {}".format(type(exc).__name__, exc)
    finally:
        runtime_ms = int(round((time.monotonic() - start) * 1000))

    if temp_path is None:
        command = [args.binary, ""]
    else:
        command = [args.binary, temp_path]

    result = make_result(
        args.binary,
        command,
        returncode,
        timed_out,
        runtime_ms,
        stdout,
        stderr,
        error,
    )

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(result, f, sort_keys=False)
            f.write("\n")

    json.dump(result, sys.stdout, sort_keys=False)
    sys.stdout.write("\n")

    if temp_path is not None:
        try:
            os.unlink(temp_path)
        except OSError:
            pass


if __name__ == "__main__":
    main()
