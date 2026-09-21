#!/usr/bin/env python3
import argparse
import json
import signal
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class TranscriptServer(ThreadingHTTPServer):
    daemon_threads = False
    allow_reuse_address = True

    def __init__(self, port):
        super().__init__(("127.0.0.1", port), RequestHandler)
        self.requests = []


class RequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.server.requests.append(
            {
                "host": self.headers.get("Host", ""),
                "auth": self.headers.get("Authorization", "none"),
            }
        )
        if self.path == "/":
            self.send_response(301)
            self.send_header("Location", f"http://b.localhost:{self.server.server_port}/followed")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
        else:
            body = b"OK"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def signal_name(returncode):
    if returncode is None or returncode >= 0:
        return None
    try:
        return signal.Signals(-returncode).name
    except ValueError:
        return f"SIG{-returncode}"


def transcript(server):
    lines = [
        f"REQ {index} host={request['host']} auth={request['auth']}"
        for index, request in enumerate(server.requests, 1)
    ]
    return "\n".join(lines) + ("\n" if lines else "")


def run(binary, timeout):
    server = TranscriptServer(0)
    port = server.server_port
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.start()

    try:
        with tempfile.TemporaryDirectory(prefix="http-netrc-") as temporary_directory:
            netrc_path = Path(temporary_directory) / "credentials.netrc"
            netrc_path.write_text(
                "machine a.localhost\n"
                "login alice\n"
                "password secretpw\n"
                "default\n"
            )
            netrc_path.chmod(0o600)

            command = [
                binary,
                "-L",
                "--max-redirs",
                "3",
                "--resolve",
                f"a.localhost:{port}:127.0.0.1",
                "--resolve",
                f"b.localhost:{port}:127.0.0.1",
                "--netrc-file",
                str(netrc_path),
                f"http://a.localhost:{port}/",
            ]

            started = time.monotonic()
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            timed_out = False
            error = None
            try:
                stdout_bytes, stderr_bytes = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                error = f"client timed out after {timeout} seconds"
                process.kill()
                stdout_bytes, stderr_bytes = process.communicate()
            runtime_ms = round((time.monotonic() - started) * 1000)
    finally:
        try:
            server.shutdown()
            server.server_close()
            server_thread.join()
        except Exception as cleanup_error:
            if error is None:
                error = f"server cleanup failed: {cleanup_error}"

    return {
        "binary": binary,
        "command": command,
        "returncode": process.returncode,
        "signal": signal_name(process.returncode),
        "timed_out": timed_out,
        "runtime_ms": runtime_ms,
        "stdout": stdout_bytes.decode("utf-8", errors="replace"),
        "stderr": stderr_bytes.decode("utf-8", errors="replace"),
        "observable": {
            "kind": "protocol_transcript",
            "value": transcript(server),
            "path": None,
        },
        "error": error,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--json-out")
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args()

    try:
        result = run(args.binary, args.timeout)
    except Exception as exception:
        result = {
            "binary": args.binary,
            "command": [args.binary],
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
            "error": str(exception),
        }

    output = json.dumps(result, ensure_ascii=False)
    print(output)
    if args.json_out:
        Path(args.json_out).write_text(output + "\n")


if __name__ == "__main__":
    main()
