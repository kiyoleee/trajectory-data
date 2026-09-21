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


def build_payload():
    start_offset = 0
    transfer_size = 32768
    caller_buffer = b"A"
    return struct.pack("<ii", start_offset, transfer_size) + caller_buffer


def signal_name(returncode):
    if returncode is None or returncode >= 0:
        return None
    try:
        return signal.Signals(-returncode).name
    except ValueError:
        return "SIG%d" % (-returncode)


def decode_output(data):
    return data.decode("utf-8", errors="replace")


def make_observable(stdout_text, stderr_text, returncode, sig_name, timed_out, error):
    combined = (stdout_text + stderr_text).strip()
    if sig_name:
        value = "returncode=%d signal=%s stdout=%r stderr=%r" % (
            returncode,
            sig_name,
            stdout_text.strip(),
            stderr_text.strip(),
        )
        return {"kind": "crash_trace", "value": value, "path": None}
    if timed_out:
        return {"kind": "combined_output", "value": "timeout: " + combined, "path": None}
    if error:
        return {"kind": "custom", "value": error, "path": None}
    return {"kind": "combined_output", "value": combined, "path": None}


def run_target(binary, timeout):
    trigger_path = None
    command = None
    start_time = time.monotonic()
    stdout_text = ""
    stderr_text = ""
    returncode = None
    timed_out = False
    error = None

    try:
        with tempfile.NamedTemporaryFile(prefix="s7dl-trigger-", suffix=".bin", delete=False) as trigger:
            trigger.write(build_payload())
            trigger_path = trigger.name

        command = [binary, trigger_path]
        try:
            completed = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
            returncode = completed.returncode
            stdout_text = decode_output(completed.stdout)
            stderr_text = decode_output(completed.stderr)
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            stdout_text = decode_output(exc.stdout or b"")
            stderr_text = decode_output(exc.stderr or b"")
            error = "target execution timed out"
        except OSError as exc:
            error = "failed to execute target: %s" % exc
    finally:
        runtime_ms = int((time.monotonic() - start_time) * 1000)
        if trigger_path is not None:
            try:
                os.unlink(trigger_path)
            except OSError:
                pass

    sig_name = signal_name(returncode)
    result = {
        "binary": binary,
        "command": command if command is not None else [binary, trigger_path],
        "returncode": returncode,
        "signal": sig_name,
        "timed_out": timed_out,
        "runtime_ms": runtime_ms,
        "stdout": stdout_text,
        "stderr": stderr_text,
        "observable": make_observable(stdout_text, stderr_text, returncode, sig_name, timed_out, error),
        "error": error,
    }
    return result


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Generate and run an s7dl trigger input.")
    parser.add_argument("--binary", required=True, help="Path to the target binary.")
    parser.add_argument("--json-out", help="Optional path to write the JSON result.")
    parser.add_argument("--timeout", type=float, default=30.0, help="Target execution timeout in seconds.")
    return parser.parse_args(argv)


def main(argv):
    args = parse_args(argv)
    result = run_target(args.binary, args.timeout)

    output = json.dumps(result, sort_keys=False, separators=(",", ":"))
    print(output)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            f.write(output)
            f.write("\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
