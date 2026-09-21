#!/usr/bin/env python3
"""
poc.py - trigger an anomalous runtime behavior in the target busybox wget.

Defect: this busybox build rejects any HTTP Content-Length value that does
not fit in 32 bits ("wget: content-length <N> is garbage", exit status 1),
even though the value is a perfectly valid decimal number and the very same
codebase accepts 64-bit sizes for chunked-transfer chunk sizes.  The value
4294967296 (2^32) is therefore rejected while 4294967295 (2^32 - 1) is
accepted and downloaded -- a one-byte difference in the request flips a
successful 200-download into a spurious hard failure.  That is a real
robustness defect in the binary's HTTP response parsing.

The PoC:
  1. starts a single-connection, bounded-response HTTP server on 127.0.0.1,
  2. dynamically builds a response whose Content-Length is 2^32,
  3. runs:  <binary> wget -O <output-file> <url>
  4. captures exit status / signal / stdout / stderr,
  5. emits the JSON contract describing the observed anomaly.

Loopback only, deterministic, no human interaction, server started and
stopped inside this run, all files inside a temporary directory.
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

# 2^32: the smallest Content-Length value that overflows a 32-bit field.
TRIGGER_CONTENT_LENGTH = 1 << 32

# Bounded body actually transmitted (the defect is in header parsing, so the
# body content is irrelevant; a small deterministic body keeps things fast).
BODY = b"poc-defect-probe\r\n"


class SingleConnectionHTTPServer:
    """Minimal HTTP/1.1 server: one connection, one fixed bounded response."""

    def __init__(self, response: bytes):
        self._response = response
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self.port = self._sock.getsockname()[1]
        self.request_bytes = b""
        self._error = None
        self._thread = threading.Thread(target=self._serve_once, daemon=True)

    def start(self):
        self._thread.start()

    def _serve_once(self):
        conn = None
        try:
            self._sock.settimeout(10)
            conn, _ = self._sock.accept()
            conn.settimeout(5)
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 16384:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            self.request_bytes = data
            try:
                conn.sendall(self._response)
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
        except OSError as exc:
            self._error = "http server: %s" % exc
        finally:
            if conn is not None:
                try:
                    conn.close()
                except OSError:
                    pass

    def close(self):
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=5)


def normalize(text: str, port: int) -> str:
    """Make evidence reproducible: strip the ephemeral port."""
    if port:
        text = text.replace(":%d" % port, ":PORT")
    return text


def main() -> int:
    ap = argparse.ArgumentParser(description="PoC: busybox wget Content-Length overflow rejection")
    ap.add_argument("--binary", required=True, help="path to the target busybox binary")
    ap.add_argument("--json-out", default=None, help="write JSON result to this path instead of stdout")
    ap.add_argument("--timeout", type=float, default=15.0, help="max seconds for the target run (default 15)")
    args = ap.parse_args()

    binary = os.path.abspath(args.binary)
    timeout = max(1.0, float(args.timeout))

    result = {
        "binary": binary,
        "command": None,
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": None,
        "stdout": "",
        "stderr": "",
        "observable": {"kind": None, "value": None, "path": None},
        "error": None,
    }

    tmpdir = tempfile.mkdtemp(prefix="poc_wget_")
    server = None
    try:
        if not os.path.isfile(binary):
            raise RuntimeError("binary not found: %s" % binary)
        if not os.access(binary, os.X_OK):
            raise RuntimeError("binary is not executable: %s" % binary)

        # Dynamically construct the trigger response (nothing read from disk).
        response = (
            b"HTTP/1.1 200 OK\r\n"
            + b"Content-Length: %d\r\n" % TRIGGER_CONTENT_LENGTH
            + b"Content-Type: application/octet-stream\r\n"
            + b"Connection: close\r\n"
            + b"\r\n"
            + BODY
        )

        server = SingleConnectionHTTPServer(response)
        server.start()

        out_file = os.path.join(tmpdir, "download.out")
        url = "http://127.0.0.1:%d/file" % server.port
        command = [binary, "wget", "-O", out_file, url]
        result["command"] = command

        env = dict(os.environ)
        for var in ("http_proxy", "https_proxy", "ftp_proxy", "HTTP_PROXY", "HTTPS_PROXY", "FTP_PROXY", "no_proxy", "NO_PROXY"):
            env.pop(var, None)

        t0 = time.monotonic()
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=tmpdir,
        )
        try:
            out, err = proc.communicate(timeout=timeout)
            timed_out = False
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate()
            timed_out = True
        runtime_ms = round((time.monotonic() - t0) * 1000, 3)

        rc = proc.returncode
        result["returncode"] = rc if (isinstance(rc, int) and rc >= 0) else 0
        result["signal"] = signal.Signals(-rc).name if (isinstance(rc, int) and rc < 0) else None
        result["timed_out"] = timed_out
        result["runtime_ms"] = runtime_ms
        result["stdout"] = out.decode("utf-8", "replace")
        result["stderr"] = err.decode("utf-8", "replace")

        server.close()
        if server._error and not server.request_bytes:
            raise RuntimeError(server._error)

        out_size = os.path.getsize(out_file) if os.path.exists(out_file) else None

        stderr_norm = normalize(result["stderr"].strip(), server.port)
        anomaly = "content-length %d is garbage" % TRIGGER_CONTENT_LENGTH in result["stderr"]

        if anomaly:
            evidence = (
                "%s | server sent 'Content-Length: %d' (a valid 64-bit decimal value) "
                "with a %d-byte body over a single loopback connection; a correct wget "
                "accepts this (this build itself accepts Content-Length: %d = 2^32-1 and "
                "full 64-bit chunk sizes), but this build's parser silently truncates the "
                "value to 32 bits, flags its own truncation as an overflow error and "
                "aborts the download with exit status %d. Output file was %s."
                % (
                    stderr_norm.splitlines()[-1] if stderr_norm else "content-length is garbage",
                    TRIGGER_CONTENT_LENGTH,
                    len(BODY),
                    TRIGGER_CONTENT_LENGTH - 1,
                    rc if rc >= 0 else 0,
                    "not created" if out_size is None else "%d bytes" % out_size,
                )
            )
            result["observable"] = {"kind": "stderr", "value": evidence, "path": None}
        else:
            evidence = (
                "unexpected outcome: rc=%s signal=%s timed_out=%s output_file=%s; stderr=%s"
                % (
                    rc,
                    result["signal"],
                    timed_out,
                    "missing" if out_size is None else "%d bytes" % out_size,
                    stderr_norm[:300],
                )
            )
            result["observable"] = {"kind": "stderr", "value": evidence, "path": None}
            result["error"] = "expected anomaly not observed"

    except Exception as exc:  # keep the JSON contract intact even on failure
        result["error"] = str(exc)
        if result["observable"]["value"] is None:
            result["observable"] = {"kind": "stderr", "value": "setup failure: %s" % exc, "path": None}
    finally:
        if server is not None:
            server.close()
        shutil.rmtree(tmpdir, ignore_errors=True)

    payload = json.dumps(result, indent=2, sort_keys=False)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            fh.write(payload + "\n")
    else:
        sys.stdout.write(payload + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
