#!/usr/bin/env python3
"""PoC: drive an HTTP client binary against a local test server and report a normalized transcript."""

import argparse
import json
import os
import signal
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Drive an HTTP client binary and capture a protocol transcript."
    )
    parser.add_argument("--binary", required=True, help="Path to the HTTP client binary")
    parser.add_argument("--json-out", default=None, help="Optional path to write JSON output")
    parser.add_argument("--timeout", type=int, default=30, help="Per-run timeout in seconds")
    args = parser.parse_args()

    # --- Validate binary early --------------------------------------------------
    if not os.path.isfile(args.binary):
        _emit_error(args.binary, f"binary not found: {args.binary}", args.json_out)
        sys.exit(1)

    # --- Temporary working directory (cleaned up on exit) -----------------------
    with tempfile.TemporaryDirectory(prefix="poc_") as tmpdir:
        netrc_path = os.path.join(tmpdir, ".netrc")
        with open(netrc_path, "w") as f:
            f.write("machine a.localhost\nlogin alice\npassword secretpw\ndefault\n")
        os.chmod(netrc_path, 0o600)

        # --- Start the recording server -----------------------------------------
        server = RecordingServer(("127.0.0.1", 0), RecordingHandler)
        server.allow_reuse_address = True
        port: int = server.server_address[1]

        server_ready = threading.Event()
        server_thread = threading.Thread(
            target=_serve, args=(server, server_ready), daemon=True
        )
        server_thread.start()
        server_ready.wait()  # guarantee the server is accepting

        try:
            # --- Build the command line -----------------------------------------
            cmd: list[str] = [
                args.binary,
                "-L",
                "--max-redirs",
                "3",
                "--resolve",
                f"a.localhost:{port}:127.0.0.1",
                "--resolve",
                f"b.localhost:{port}:127.0.0.1",
                "--netrc-file",
                netrc_path,
                f"http://a.localhost:{port}/",
            ]

            # --- Run the client -------------------------------------------------
            start_time = time.monotonic()
            timed_out = False
            proc: subprocess.CompletedProcess | None = None

            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=args.timeout,
                )
            except subprocess.TimeoutExpired:
                proc = subprocess.CompletedProcess(cmd, -1, "", "")
                timed_out = True

            runtime_ms = int((time.monotonic() - start_time) * 1000)

            # --- Build transcript -----------------------------------------------
            transcript_lines: list[str] = []
            for i, req in enumerate(server.requests, 1):
                host = req.get("host", "")
                auth = req.get("auth", "none")
                transcript_lines.append(f"REQ {i} host={host} auth={auth}")
            transcript = "\n".join(transcript_lines)

            # --- Determine signal -----------------------------------------------
            sig: str | None = None
            rc = proc.returncode
            if rc < 0:
                sig_num = -rc
                try:
                    sig = signal.Signals(sig_num).name
                except ValueError:
                    sig = f"SIG{sig_num}"

            result = {
                "binary": args.binary,
                "command": cmd,
                "returncode": rc,
                "signal": sig,
                "timed_out": timed_out,
                "runtime_ms": runtime_ms,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "observable": {
                    "kind": "protocol_transcript",
                    "value": transcript,
                    "path": None,
                },
                "error": None,
            }
        finally:
            server.shutdown()

    # --- Output -----------------------------------------------------------------
    output = json.dumps(result)
    print(output)
    if args.json_out:
        with open(args.json_out, "w") as f:
            f.write(output)


def _serve(server: socketserver.TCPServer, ready: threading.Event) -> None:
    """Run the server and signal readiness once it is accepting."""
    ready.set()
    server.serve_forever()


def _emit_error(binary: str, msg: str, json_out: str | None) -> None:
    """Print a minimal error JSON and optionally write it to file."""
    result = {
        "binary": binary,
        "command": [],
        "returncode": -1,
        "signal": None,
        "timed_out": False,
        "runtime_ms": 0,
        "stdout": "",
        "stderr": "",
        "observable": {"kind": "protocol_transcript", "value": "", "path": None},
        "error": msg,
    }
    output = json.dumps(result)
    print(output)
    if json_out:
        with open(json_out, "w") as f:
            f.write(output)


# ---------------------------------------------------------------------------
# Recording HTTP server
# ---------------------------------------------------------------------------

class RecordingServer(socketserver.TCPServer):
    """A TCPServer that records every request it receives."""

    allow_reuse_address = True

    def __init__(self, *args, **kwargs):
        self.requests: list[dict[str, str]] = []
        super().__init__(*args, **kwargs)


class RecordingHandler(BaseHTTPRequestHandler):
    """HTTP handler that records Host and Authorization headers."""

    # Suppress per-request stderr logging
    def log_message(self, fmt: str, *args) -> None:  # noqa: ARG002
        pass

    # ------------------------------------------------------------------
    # GET handler
    # ------------------------------------------------------------------
    def do_GET(self) -> None:
        host = self.headers.get("Host", "")
        auth = self.headers.get("Authorization", "none")

        # Record the request
        self.server.requests.append(
            {
                "host": host,
                "auth": auth,
                "path": self.path,
            }
        )

        if self.path == "/":
            # 301 redirect to b.localhost
            port = self.server.server_address[1]
            self.send_response(HTTPStatus.MOVED_PERMANENTLY)
            self.send_header("Location", f"http://b.localhost:{port}/followed")
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            body = b"OK"
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()