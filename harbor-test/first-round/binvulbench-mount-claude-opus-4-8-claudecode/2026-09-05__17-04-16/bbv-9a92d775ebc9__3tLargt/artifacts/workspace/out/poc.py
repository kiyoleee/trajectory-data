#!/usr/bin/env python3
"""Drive an HTTP client binary against a local loopback server and report a
normalized transcript of the traffic the server received.

Self-contained, deterministic, offline. Standard library only.
"""

import argparse
import http.server
import json
import os
import shutil
import signal
import socketserver
import sys
import tempfile
import threading
import time


NETRC_CONTENT = "machine a.localhost\nlogin alice\npassword secretpw\ndefault\n"


def build_handler(records):
    """Return a request handler class that records Host/Authorization headers."""

    class Handler(http.server.BaseHTTPRequestHandler):
        # Keep protocol at HTTP/1.0-ish behaviour: no keep-alive assumptions.
        protocol_version = "HTTP/1.1"

        def _record(self):
            records.append(
                {
                    "host": self.headers.get("Host"),
                    "authorization": self.headers.get("Authorization"),
                }
            )

        def do_GET(self):
            self._record()
            # Determine the ephemeral port from the server so we can build an
            # absolute redirect Location back to b.localhost on the same port.
            port = self.server.server_address[1]
            if self.path == "/":
                body = b""
                self.send_response(301)
                self.send_header(
                    "Location", "http://b.localhost:%d/followed" % port
                )
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if body:
                    self.wfile.write(body)
            else:
                body = b"OK"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        # Silence default stderr logging.
        def log_message(self, *args, **kwargs):
            pass

    return Handler


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def make_transcript(records):
    lines = []
    for i, rec in enumerate(records, start=1):
        host = rec.get("host")
        if host is None:
            host = ""
        auth = rec.get("authorization")
        if not auth:
            auth = "none"
        lines.append("REQ %d host=%s auth=%s" % (i, host, auth))
    return "".join(line + "\n" for line in lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--json-out", default=None)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()

    result = {
        "binary": args.binary,
        "command": [],
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": 0,
        "stdout": "",
        "stderr": "",
        "observable": {
            "kind": "protocol_transcript",
            "value": "",
            "path": None,
        },
        "error": None,
    }

    tmpdir = None
    server = None
    server_thread = None
    records = []
    try:
        tmpdir = tempfile.mkdtemp(prefix="poc_netrc_")
        netrc_path = os.path.join(tmpdir, "netrc")
        with open(netrc_path, "w") as fh:
            fh.write(NETRC_CONTENT)
        os.chmod(netrc_path, 0o600)

        server = Server(("127.0.0.1", 0), build_handler(records))
        port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        command = [
            args.binary,
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
        result["command"] = command

        import subprocess

        start = time.monotonic()
        try:
            proc = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=args.timeout,
            )
            elapsed = time.monotonic() - start
            result["runtime_ms"] = int(round(elapsed * 1000))
            result["returncode"] = proc.returncode
            result["stdout"] = proc.stdout.decode("utf-8", "replace")
            result["stderr"] = proc.stderr.decode("utf-8", "replace")
            if proc.returncode is not None and proc.returncode < 0:
                try:
                    result["signal"] = signal.Signals(-proc.returncode).name
                except (ValueError, KeyError):
                    result["signal"] = str(-proc.returncode)
        except subprocess.TimeoutExpired as exc:
            elapsed = time.monotonic() - start
            result["runtime_ms"] = int(round(elapsed * 1000))
            result["timed_out"] = True
            result["returncode"] = None
            result["stdout"] = (
                exc.stdout.decode("utf-8", "replace") if exc.stdout else ""
            )
            result["stderr"] = (
                exc.stderr.decode("utf-8", "replace") if exc.stderr else ""
            )
            result["error"] = "client timed out after %s seconds" % args.timeout

        # Give the server a brief moment to finish handling any in-flight request.
        time.sleep(0.05)
        result["observable"]["value"] = make_transcript(records)

    except Exception as exc:  # pragma: no cover - defensive
        result["error"] = "%s: %s" % (type(exc).__name__, exc)
        result["observable"]["value"] = make_transcript(records)
    finally:
        if server is not None:
            try:
                server.shutdown()
            except Exception:
                pass
            try:
                server.server_close()
            except Exception:
                pass
        if tmpdir is not None:
            shutil.rmtree(tmpdir, ignore_errors=True)

    output = json.dumps(result)
    if args.json_out:
        with open(args.json_out, "w") as fh:
            fh.write(output)
    sys.stdout.write(output)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
