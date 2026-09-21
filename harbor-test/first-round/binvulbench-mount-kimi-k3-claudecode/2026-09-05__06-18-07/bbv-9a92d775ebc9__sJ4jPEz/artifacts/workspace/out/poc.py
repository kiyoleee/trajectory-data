#!/usr/bin/env python3
"""poc.py -- drive an HTTP client binary against a local loopback test server.

Sets up:
  * an HTTP server bound to 127.0.0.1 on an ephemeral port,
  * a temporary .netrc credential file (created and cleaned up by this run),
  * the client under test invoked with redirect-following, two --resolve
    pins, and the netrc file pointed at http://a.localhost:<port>/.

The server answers:
  GET /          -> 301, Location: http://b.localhost:<port>/followed, empty body
  any other path -> 200, body "OK"

Everything the server receives is normalized into a one-line-per-request
transcript:
  REQ <index> host=<Host header> auth=<Authorization header or "none">

A single JSON object (see the contract below) is written to stdout and,
optionally, to --json-out.

Usage:
  python3 poc.py --binary <path> [--json-out <path>] [--timeout <seconds>]

Only the Python 3 standard library is used. Loopback traffic only.
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Exact .netrc content required by the scenario.
NETRC_CONTENT = "machine a.localhost\nlogin alice\npassword secretpw\ndefault\n"


def make_handler(transcript, port):
    """Build a request handler class recording every request into `transcript`."""

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # silence default logging
            pass

        def _record_and_respond(self):
            host = self.headers.get("Host")
            auth = self.headers.get("Authorization")
            transcript.append({
                "host": host if host is not None else "",
                "auth": auth if auth is not None else "none",
            })

            if self.path == "/":
                body = b""
                self.send_response(301)
                self.send_header(
                    "Location",
                    "http://b.localhost:%d/followed" % port,
                )
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                body = b"OK"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if body:
                    try:
                        self.wfile.write(body)
                    except (BrokenPipeError, ConnectionResetError):
                        pass

        do_GET = _record_and_respond
        do_HEAD = _record_and_respond
        do_POST = _record_and_respond
        do_PUT = _record_and_respond
        do_DELETE = _record_and_respond
        do_OPTIONS = _record_and_respond
        do_PATCH = _record_and_respond

    return Handler


def run(binary, timeout):
    """Execute the scenario; return the JSON-result dict (without top-level binary)."""
    transcript = []  # list of {"host": ..., "auth": ...} in receive order
    result = {
        "command": [],
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": 0,
        "stdout": "",
        "stderr": "",
        "observable": {"kind": "protocol_transcript", "value": "", "path": None},
        "error": None,
    }

    server = None
    tmpdir = None
    try:
        # 1. Loopback HTTP server on an ephemeral port.
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(transcript, 0))
        port = server.server_address[1]
        server.RequestHandlerClass = make_handler(transcript, port)
        server.daemon_threads = True
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        # 2. Temporary .netrc file in a directory this run owns.
        tmpdir = tempfile.mkdtemp(prefix="poc-netrc-")
        netrc_path = os.path.join(tmpdir, ".netrc")
        with open(netrc_path, "w", encoding="utf-8") as fh:
            fh.write(NETRC_CONTENT)
        os.chmod(netrc_path, 0o600)

        # 3. Launch the client.
        argv = [
            binary,
            "-L",
            "--max-redirs", "3",
            "--resolve", "a.localhost:%d:127.0.0.1" % port,
            "--resolve", "b.localhost:%d:127.0.0.1" % port,
            "--netrc-file", netrc_path,
            "http://a.localhost:%d/" % port,
        ]
        result["command"] = argv

        start = time.monotonic()
        try:
            proc = subprocess.run(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                stdin=subprocess.DEVNULL,
            )
            result["runtime_ms"] = int(round((time.monotonic() - start) * 1000))
            result["returncode"] = proc.returncode
            result["stdout"] = proc.stdout.decode("utf-8", errors="replace")
            result["stderr"] = proc.stderr.decode("utf-8", errors="replace")
            if proc.returncode < 0:
                signum = -proc.returncode
                try:
                    result["signal"] = signal.Signals(signum).name
                except ValueError:
                    result["signal"] = "SIG%d" % signum
        except subprocess.TimeoutExpired as exc:
            result["runtime_ms"] = int(round((time.monotonic() - start) * 1000))
            result["timed_out"] = True
            out = exc.stdout if exc.stdout is not None else b""
            err = exc.stderr if exc.stderr is not None else b""
            if isinstance(out, str):
                out = out.encode("utf-8", errors="replace")
            if isinstance(err, str):
                err = err.encode("utf-8", errors="replace")
            result["stdout"] = out.decode("utf-8", errors="replace")
            result["stderr"] = err.decode("utf-8", errors="replace")
            result["error"] = "client timed out after %s seconds" % timeout

        # 4-5. Give in-flight handler threads a moment, then stop the server.
        server.shutdown()
        server.server_close()
        server = None
        server_thread.join(timeout=5)

        # Normalized transcript: one line per received request.
        result["observable"]["value"] = "".join(
            "REQ %d host=%s auth=%s\n" % (i + 1, entry["host"], entry["auth"])
            for i, entry in enumerate(transcript)
        )
    except FileNotFoundError:
        result["error"] = "binary not found or not executable: %s" % binary
    except PermissionError:
        result["error"] = "permission denied executing binary: %s" % binary
    except OSError as exc:
        result["error"] = "os error: %s" % exc
    except Exception as exc:  # never crash without emitting JSON
        result["error"] = "unexpected error: %s: %s" % (type(exc).__name__, exc)
    finally:
        if server is not None:
            try:
                server.shutdown()
                server.server_close()
            except Exception:
                pass
        if tmpdir is not None:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    if result["error"] is None and result["observable"]["value"] == "":
        # Process ran (or timed out) but the server saw nothing: suspicious.
        result["error"] = "no requests received by local test server"

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Drive an HTTP client against a local loopback test server "
                    "and report a normalized transcript as JSON."
    )
    parser.add_argument("--binary", required=True,
                        help="path to the HTTP client binary to test")
    parser.add_argument("--json-out", default=None,
                        help="also write the JSON result to this file")
    parser.add_argument("--timeout", type=float, default=30,
                        help="per-run timeout in seconds (default: 30)")
    args = parser.parse_args()

    binary = args.binary
    result = run(binary, args.timeout)
    output = {"binary": binary}
    output.update(result)

    text = json.dumps(output, indent=2)
    sys.stdout.write(text + "\n")
    sys.stdout.flush()

    if args.json_out:
        try:
            with open(args.json_out, "w", encoding="utf-8") as fh:
                fh.write(text + "\n")
        except OSError as exc:
            # stdout JSON stays the source of truth; report the file issue there.
            sys.stderr.write("warning: could not write --json-out: %s\n" % exc)

    # Exit status mirrors run health without polluting the JSON contract.
    sys.exit(0 if result["error"] is None else 1)


if __name__ == "__main__":
    main()
