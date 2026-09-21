#!/usr/bin/env python3
"""Single-file PoC driver for an HTTP client binary.

The script starts a local loopback HTTP server, creates a temporary .netrc
credential file, launches the supplied client with redirect/name-resolution
options, records the requests the server receives, and emits a normalized
JSON protocol transcript.
"""

import argparse
import http.server
import json
import signal as signal_module
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

NETRC_CONTENT = b"""machine a.localhost
login alice
password secretpw
default
"""


class RequestRecorder:
    """Thread-safe recorder for the raw request metadata we care about."""

    def __init__(self):
        self._lock = threading.Lock()
        self.requests = []

    def add(self, headers):
        with self._lock:
            self.requests.append(headers)


class PoCHandler(http.server.BaseHTTPRequestHandler):
    """Handle the two served paths while recording Host/Authorization."""

    protocol_version = "HTTP/1.0"

    def log_message(self, format, *args):
        # Keep server chatter out of the client transcript.
        return

    def _record_and_reply(self):
        target_path = getattr(self, "path", "") or ""
        query_start = target_path.find("?")
        path_only = target_path[:query_start] if query_start != -1 else target_path

        host = self.headers.get("Host", "")
        authorization = self.headers.get("Authorization")
        self.server.recorder.add(
            {
                "host": host,
                "authorization": authorization,
            }
        )

        if path_only == "/":
            self.send_response(301)
            self.send_header("Location", "http://b.localhost:%d/followed" % self.server.server_port)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        body = b"OK"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._record_and_reply()

    def do_HEAD(self):
        self._record_and_reply()

    def do_POST(self):
        self._record_and_reply()


class RecordingThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def signal_name_from_returncode(returncode):
    if returncode is None or returncode >= 0:
        return None
    try:
        return signal_module.Signals(-returncode).name
    except (ValueError, AttributeError):
        return "SIG" + str(-returncode)


def build_transcript(requests):
    lines = []
    for index, request in enumerate(requests, start=1):
        host = request.get("host", "")
        authorization = request.get("authorization")
        auth_value = authorization if authorization is not None else "none"
        lines.append("REQ %d host=%s auth=%s" % (index, host, auth_value))
    if lines:
        return "\n".join(lines) + "\n"
    return ""


def run_client(binary, port, netrc_path, timeout):
    argv = [
        binary,
        "-L",
        "--max-redirs",
        "3",
        "--resolve",
        "a.localhost:%d:127.0.0.1" % port,
        "--resolve",
        "b.localhost:%d:127.0.0.1" % port,
        "--netrc-file",
        netrc_path,
        "http://a.localhost:%d/" % port,
    ]

    start = time.perf_counter()
    timed_out = False
    process = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    try:
        stdout_bytes, stderr_bytes = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        stdout_bytes, stderr_bytes = process.communicate()

    elapsed_ms = round((time.perf_counter() - start) * 1000)

    return {
        "argv": argv,
        "returncode": process.returncode,
        "timed_out": timed_out,
        "runtime_ms": elapsed_ms,
        "stdout": stdout_bytes.decode("utf-8", "replace"),
        "stderr": stderr_bytes.decode("utf-8", "replace"),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Drive an HTTP client against a local loopback server and emit a protocol transcript."
    )
    parser.add_argument("--binary", required=True, help="path to the HTTP client binary")
    parser.add_argument("--json-out", help="optional path for the JSON result")
    parser.add_argument("--timeout", type=float, default=30.0, help="per-run timeout in seconds")
    args = parser.parse_args(argv)

    recorder = RequestRecorder()
    server = RecordingThreadingHTTPServer(("127.0.0.1", 0), PoCHandler)
    server.recorder = recorder
    port = server.server_address[1]

    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    error = None
    client_result = None

    try:
        with tempfile.TemporaryDirectory(prefix="poc-netrc-") as temp_dir:
            netrc_path = str(Path(temp_dir) / ".netrc")
            with open(netrc_path, "wb") as netrc_file:
                netrc_file.write(NETRC_CONTENT)
            try:
                Path(netrc_path).chmod(0o600)
            except OSError:
                pass

            client_result = run_client(args.binary, port, netrc_path, args.timeout)
    except Exception as exc:
        error = str(exc) or exc.__class__.__name__
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=5)

    requests = recorder.requests
    transcript = build_transcript(requests)

    if client_result is None and error is None:
        error = "client did not run"

    signal_value = None
    if client_result is not None:
        signal_value = signal_name_from_returncode(client_result["returncode"])

    if error is None:
        # The transcript is the primary evidence.  If the client failed to
        # produce the expected two requests, attach a compact diagnostic.
        if len(requests) < 2:
            error = "expected 2 requests, observed %d" % len(requests)

    result = {
        "binary": args.binary,
        "command": client_result["argv"] if client_result is not None else [],
        "returncode": client_result["returncode"] if client_result is not None else None,
        "signal": signal_value,
        "timed_out": client_result["timed_out"] if client_result is not None else False,
        "runtime_ms": client_result["runtime_ms"] if client_result is not None else 0,
        "stdout": client_result["stdout"] if client_result is not None else "",
        "stderr": client_result["stderr"] if client_result is not None else "",
        "observable": {
            "kind": "protocol_transcript",
            "value": transcript,
            "path": None,
        },
        "error": error,
    }

    if args.json_out:
        out_path = Path(args.json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as out_file:
            json.dump(result, out_file)

    sys.stdout.write(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
