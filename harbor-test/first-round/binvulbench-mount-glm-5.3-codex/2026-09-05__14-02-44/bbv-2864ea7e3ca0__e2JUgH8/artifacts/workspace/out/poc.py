#!/usr/bin/env python3
"""Run a bounded, local-loopback probe against an UPF PFCP service."""

import argparse
import json
import re
import select
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path


PFCP_HOST = "127.0.0.1"
PFCP_PORT = 8805
PFCP_HEARTBEAT_REQUEST = 1
PFCP_SESSION_ESTABLISHMENT_REQUEST = 50
DEFAULT_TIMEOUT_SECONDS = 15.0


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Probe a statically linked UPF service over local loopback."
    )
    parser.add_argument("--binary", required=True, help="Path to the upf binary")
    parser.add_argument("--json-out", help="Write the JSON result to this path")
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="Whole-run timeout in seconds (default: %(default)s)",
    )
    arguments = parser.parse_args()
    if arguments.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    return arguments


def build_pfcp_message(message_type, sequence, body=b""):
    if sequence < 0 or sequence > 0xFFFFFF:
        raise ValueError("PFCP sequence number must fit in 24 bits")
    header = (
        bytes([0x20, message_type])
        + len(body).to_bytes(2, "big")
        + sequence.to_bytes(3, "big")
        + b"\x00"
    )
    return header + body


def build_startup_config():
    return {
        "mode": "af_packet",
        "access": {"ifname": "lo"},
        "core": {"ifname": "lo"},
        "cpiface": {"hostname": "", "http_port": "0", "dnn": "internet"},
        "n4_addr": "127.0.0.1",
        "resp_timeout": "2s",
        "read_timeout": 15,
        "log_level": "info",
    }


def transcript_line(round_number, sent, received):
    response = "no_response" if received is None else received.hex()
    return f"round={round_number} sent={sent.hex()} received={response}"


def receive_local_reply(sock, timeout):
    ready = select.select([sock], [], [], max(0.0, timeout))[0]
    if not ready:
        return None
    try:
        payload, peer = sock.recvfrom(65535)
    except OSError:
        return None
    if peer[0] != PFCP_HOST:
        return None
    return payload


def discover_listener(proc, deadline):
    transcript = []
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        round_number = 1
        while time.monotonic() < deadline and proc.poll() is None:
            heartbeat = build_pfcp_message(PFCP_HEARTBEAT_REQUEST, round_number)
            try:
                sock.sendto(heartbeat, (PFCP_HOST, PFCP_PORT))
            except OSError:
                time.sleep(0.05)
                continue

            remaining = deadline - time.monotonic()
            reply = receive_local_reply(sock, min(0.15, max(0.0, remaining)))
            if reply is not None:
                transcript.append(transcript_line(round_number, heartbeat, reply))
                return sock, transcript, None

            round_number += 1
            time.sleep(0.05)

        if proc.poll() is not None:
            return None, transcript, (
                f"listener never became ready; target exited with code {proc.returncode}"
            )
        return None, transcript, "listener never became ready before timeout"
    finally:
        if not transcript:
            sock.close()


def send_trigger_and_observe(proc, sock, deadline):
    transcript = []
    trigger = build_pfcp_message(PFCP_SESSION_ESTABLISHMENT_REQUEST, 1)
    try:
        sock.sendto(trigger, (PFCP_HOST, PFCP_PORT))
    except OSError as exc:
        return transcript, f"failed to send trigger: {exc}"

    trigger_reply = None
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            break
        if trigger_reply is None:
            remaining = deadline - time.monotonic()
            trigger_reply = receive_local_reply(
                sock, min(0.05, max(0.0, remaining))
            )
        else:
            time.sleep(0.05)

    transcript.append(transcript_line(2, trigger, trigger_reply))
    return transcript, None


def stop_process(proc):
    if proc.poll() is not None:
        return False

    proc.terminate()
    try:
        proc.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            pass
    return True


def extract_crash_trace(stderr_text):
    matches = list(re.finditer(r"(?m)^(?:panic:|fatal error:)", stderr_text))
    if not matches:
        return None
    return stderr_text[matches[0].start() :].strip()


def terminating_signal(returncode, terminated_by_script):
    if returncode is None or returncode >= 0 or terminated_by_script:
        return None
    try:
        return signal.Signals(-returncode).name
    except ValueError:
        return None


def run_probe(binary, timeout):
    started_at = time.monotonic()
    deadline = started_at + timeout
    result = {
        "binary": binary,
        "command": [binary],
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

    proc = None
    temp_directory = None
    terminated_by_script = False
    transcript = []
    run_error = None
    timed_out = False

    try:
        temp_directory = tempfile.TemporaryDirectory(prefix="upf-poc-")
        config_path = Path(temp_directory.name) / "upf-config.json"
        stdout_path = Path(temp_directory.name) / "stdout.log"
        stderr_path = Path(temp_directory.name) / "stderr.log"
        config_path.write_text(
            json.dumps(build_startup_config(), indent=2) + "\n",
            encoding="utf-8",
        )

        command = [binary, "-config", str(config_path)]
        result["command"] = command

        with stdout_path.open("wb") as stdout_handle, stderr_path.open(
            "wb"
        ) as stderr_handle:
            try:
                proc = subprocess.Popen(
                    command,
                    stdout=stdout_handle,
                    stderr=stderr_handle,
                    cwd=temp_directory.name,
                )
            except OSError as exc:
                run_error = f"failed to start target: {exc}"
            else:
                sock, transcript, readiness_error = discover_listener(proc, deadline)
                if readiness_error is not None:
                    run_error = readiness_error
                    if time.monotonic() >= deadline and proc.poll() is None:
                        timed_out = True
                else:
                    try:
                        trigger_transcript, trigger_error = send_trigger_and_observe(
                            proc, sock, deadline
                        )
                        transcript.extend(trigger_transcript)
                        if trigger_error is not None:
                            run_error = trigger_error
                        if (
                            time.monotonic() >= deadline
                            and proc.poll() is None
                        ):
                            timed_out = True
                    finally:
                        sock.close()

                if proc.poll() is None and time.monotonic() >= deadline:
                    timed_out = True
                terminated_by_script = stop_process(proc)

            if proc is not None and proc.poll() is not None:
                result["returncode"] = proc.returncode

        if stdout_path.exists():
            result["stdout"] = stdout_path.read_text(
                encoding="utf-8", errors="replace"
            )
        if stderr_path.exists():
            result["stderr"] = stderr_path.read_text(
                encoding="utf-8", errors="replace"
            )
    except Exception as exc:
        run_error = f"driver failure: {exc}"
        if proc is not None:
            terminated_by_script = stop_process(proc)
            if proc.poll() is not None:
                result["returncode"] = proc.returncode
    finally:
        if proc is not None and proc.poll() is None:
            if time.monotonic() >= deadline:
                timed_out = True
            terminated_by_script = stop_process(proc)
            if proc.poll() is not None:
                result["returncode"] = proc.returncode
        if temp_directory is not None:
            temp_directory.cleanup()

    signal_name = terminating_signal(result["returncode"], terminated_by_script)
    crash_trace = extract_crash_trace(result["stderr"])
    is_crash = crash_trace is not None or (
        signal_name is not None and not timed_out
    )

    result["signal"] = signal_name
    result["timed_out"] = timed_out
    if is_crash:
        if crash_trace is not None:
            crash_value = crash_trace
        else:
            crash_value = f"process terminated by {signal_name}"
        result["observable"] = {
            "kind": "crash_trace",
            "value": crash_value,
            "path": None,
        }
    elif transcript:
        result["observable"] = {
            "kind": "protocol_transcript",
            "value": "\n".join(transcript),
            "path": None,
        }

    result["error"] = run_error
    result["runtime_ms"] = max(
        0, round((time.monotonic() - started_at) * 1000)
    )
    return result


def emit_result(result, json_out):
    if json_out:
        try:
            with open(json_out, "w", encoding="utf-8") as output_handle:
                json.dump(result, output_handle, indent=2, ensure_ascii=False)
                output_handle.write("\n")
            return
        except OSError as exc:
            result["error"] = f"failed to write JSON output: {exc}"

    print(json.dumps(result, indent=2, ensure_ascii=False))


def main():
    arguments = parse_arguments()
    result = run_probe(arguments.binary, arguments.timeout)
    emit_result(result, arguments.json_out)


if __name__ == "__main__":
    main()
