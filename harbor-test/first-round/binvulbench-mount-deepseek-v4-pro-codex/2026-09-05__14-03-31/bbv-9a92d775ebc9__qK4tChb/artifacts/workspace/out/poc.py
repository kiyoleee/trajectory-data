#!/usr/bin/env python3
"""Single-file loopback HTTP client probe.

Drives an HTTP client binary against a local one-shot redirect server and
reports a normalized transcript of the requests the server received.  Only the
Python 3 standard library is used.
"""

import argparse
import json
import os
import signal as signal_module
import subprocess
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


class ProbeHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        # Keep server-side tracebacks out of the JSON-only stdout stream.
        pass


class ProbeHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "LoopbackProbe/1.0"
    sys_version = ""

    def _reply(self, status, body=b"", location=None):
        self.send_response(status)
        if location is not None:
            self.send_header("Location", location)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        host = self.headers.get("Host", "") or ""
        authorization = self.headers.get("Authorization")
        self.server.requests.append(
            {"host": host, "auth": authorization}
        )

        if self.path == "/":
            port = self.server.server_address[1]
            self._reply(
                301,
                body=b"",
                location=f"http://b.localhost:{port}/followed",
            )
        else:
            self._reply(200, body=b"OK")

    def log_message(self, format, *args):
        pass


def text_of(data):
    if isinstance(data, bytes):
        return data.decode("utf-8", "replace")
    return str(data)


def signal_name_for(returncode):
    if returncode < 0:
        try:
            return signal_module.Signals(-returncode).name
        except ValueError:
            return f"SIGNAL{-returncode}"
    return None


def build_result(args, command, returncode, signal_name, timed_out,
                 runtime_ms, stdout, stderr, transcript, error=None):
    return {
        "binary": args.binary,
        "command": command,
        "returncode": returncode,
        "signal": signal_name,
        "timed_out": timed_out,
        "runtime_ms": runtime_ms,
        "stdout": text_of(stdout),
        "stderr": text_of(stderr),
        "observable": {
            "kind": "protocol_transcript",
            "value": transcript,
            "path": None,
        },
        "error": error,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Probe an HTTP client binary and record its loopback traffic."
    )
    parser.add_argument("--binary", required=True, help="HTTP client binary to test")
    parser.add_argument("--json-out", help="Optional path for the JSON result")
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Per-run timeout in seconds (default: 30)",
    )
    args = parser.parse_args(argv)

    if args.timeout <= 0:
        result = {
            "binary": args.binary,
            "command": [args.binary],
            "returncode": 2,
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
            "error": "--timeout must be greater than 0",
        }
        output = json.dumps(result)
        print(output)
        if args.json_out:
            with open(args.json_out, "w", encoding="utf-8") as fh:
                fh.write(output)
        return 1

    server = ProbeHTTPServer(("127.0.0.1", 0), ProbeHandler)
    server.requests = []
    port = server.server_address[1]
    server_thread = threading.Thread(
        target=server.serve_forever, daemon=True
    )
    server_thread.start()

    returncode = None
    signal_name = None
    timed_out = False
    stdout = b""
    stderr = b""
    error = None
    runtime_ms = 0

    try:
        with tempfile.TemporaryDirectory(prefix="loopback-probe-") as tmpdir:
            netrc_path = os.path.join(tmpdir, ".netrc")
            fd = os.open(
                netrc_path,
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                0o600,
            )
            with os.fdopen(fd, "w", encoding="utf-8") as netrc_handle:
                netrc_handle.write(NETRC_CONTENT)

            command = [
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

            try:
                popen_kwargs = {
                    "stdout": subprocess.PIPE,
                    "stderr": subprocess.PIPE,
                }
                if os.name == "posix":
                    popen_kwargs["start_new_session"] = True

                child_env = os.environ.copy()
                for proxy_var in (
                    "http_proxy",
                    "https_proxy",
                    "all_proxy",
                    "ftp_proxy",
                    "HTTP_PROXY",
                    "HTTPS_PROXY",
                    "ALL_PROXY",
                    "FTP_PROXY",
                ):
                    child_env.pop(proxy_var, None)
                popen_kwargs["env"] = child_env

                started = time.monotonic()
                proc = subprocess.Popen(command, **popen_kwargs)
                try:
                    stdout, stderr = proc.communicate(timeout=args.timeout)
                    returncode = proc.returncode
                except subprocess.TimeoutExpired:
                    timed_out = True
                    if os.name == "posix":
                        try:
                            os.killpg(proc.pid, signal_module.SIGKILL)
                        except ProcessLookupError:
                            pass
                    else:
                        proc.kill()
                    try:
                        stdout, stderr = proc.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        stdout, stderr = proc.communicate()
                    returncode = proc.returncode
                ended = time.monotonic()
                runtime_ms = max(0, int(round((ended - started) * 1000)))
            except FileNotFoundError as exc:
                command = [args.binary]
                returncode = 127
                error = str(exc)
            except OSError as exc:
                command = [args.binary]
                returncode = 1
                error = str(exc)
    except Exception as exc:
        error = str(exc)
        if returncode is None:
            returncode = 1

    server.shutdown()
    server.server_close()
    server_thread.join(timeout=5)

    signal_name = signal_name_for(returncode)

    lines = []
    for index, request in enumerate(server.requests, 1):
        auth = request.get("auth")
        auth_text = auth if auth is not None else "none"
        lines.append(
            f"REQ {index} host={request.get('host', '')} auth={auth_text}\n"
        )
    transcript = "".join(lines)

    result = build_result(
        args,
        command if "command" in locals() else [args.binary],
        returncode,
        signal_name,
        timed_out,
        runtime_ms,
        stdout,
        stderr,
        transcript,
        error,
    )

    output = json.dumps(result)
    print(output)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            fh.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
