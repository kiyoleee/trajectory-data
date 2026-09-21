#!/usr/bin/env python3
"""PoC driver: run an HTTP client binary against a local loopback test
server and report a normalized transcript of the traffic received."""

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

NETRC_CONTENT = "machine a.localhost\nlogin alice\npassword secretpw\ndefault\n"

requests_seen = []
requests_lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        pass

    def _record(self):
        host = self.headers.get("Host", "")
        auth = self.headers.get("Authorization")
        with requests_lock:
            requests_seen.append((host, auth if auth is not None else "none"))

    def _respond(self):
        port = self.server.server_address[1]
        if self.path == "/":
            self.send_response(301)
            self.send_header("Location", "http://b.localhost:%d/followed" % port)
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            body = b"OK"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def do_GET(self):
        self._record()
        self._respond()

    do_POST = do_GET
    do_HEAD = do_GET
    do_PUT = do_GET


def build_transcript():
    lines = []
    with requests_lock:
        snapshot = list(requests_seen)
    for index, (host, auth) in enumerate(snapshot, 1):
        lines.append("REQ %d host=%s auth=%s" % (index, host, auth))
    return "\n".join(lines) + "\n" if lines else ""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--json-out")
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
        "observable": {"kind": "protocol_transcript", "value": "", "path": None},
        "error": None,
    }

    server = None
    tmpdir = None
    try:
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        tmpdir = tempfile.TemporaryDirectory(prefix="poc-netrc-")
        netrc_path = tmpdir.name + "/.netrc"
        with open(netrc_path, "w") as handle:
            handle.write(NETRC_CONTENT)

        command = [
            args.binary,
            "-L",
            "--max-redirs", "3",
            "--resolve", "a.localhost:%d:127.0.0.1" % port,
            "--resolve", "b.localhost:%d:127.0.0.1" % port,
            "--netrc-file", netrc_path,
            "http://a.localhost:%d/" % port,
        ]
        result["command"] = command

        start = time.monotonic()
        try:
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            try:
                stdout, stderr = proc.communicate(timeout=args.timeout)
            except subprocess.TimeoutExpired:
                result["timed_out"] = True
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    proc.kill()
                try:
                    stdout, stderr = proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                    stdout, stderr = b"", b""
            result["runtime_ms"] = int(round((time.monotonic() - start) * 1000))
            result["returncode"] = proc.returncode
            if proc.returncode is not None and proc.returncode < 0:
                try:
                    result["signal"] = signal.Signals(-proc.returncode).name
                except ValueError:
                    result["signal"] = str(-proc.returncode)
            result["stdout"] = stdout.decode("utf-8", errors="replace")
            result["stderr"] = stderr.decode("utf-8", errors="replace")
        except FileNotFoundError:
            result["error"] = "binary not found: %s" % args.binary
        except PermissionError:
            result["error"] = "binary not executable: %s" % args.binary
        except OSError as exc:
            result["error"] = "failed to launch binary: %s" % exc
    except Exception as exc:  # noqa: BLE001 - report any setup failure
        result["error"] = "setup error: %s" % exc
    finally:
        if server is not None:
            server.shutdown()
            server.server_close()

    result["observable"]["value"] = build_transcript()

    output = json.dumps(result, indent=2)
    sys.stdout.write(output + "\n")
    sys.stdout.flush()
    if args.json_out:
        try:
            with open(args.json_out, "w") as handle:
                handle.write(output + "\n")
        except OSError as exc:
            sys.stderr.write("failed to write --json-out: %s\n" % exc)

    if tmpdir is not None:
        tmpdir.cleanup()


if __name__ == "__main__":
    main()
