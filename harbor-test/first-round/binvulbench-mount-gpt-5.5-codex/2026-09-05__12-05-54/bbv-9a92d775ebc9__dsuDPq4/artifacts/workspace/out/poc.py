#!/usr/bin/env python3
import argparse
import http.server
import json
import os
import signal
import subprocess
import tempfile
import threading
import time


NETRC_CONTENT = "machine a.localhost\nlogin alice\npassword secretpw\ndefault\n"


class TranscriptHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, server_address, request_handler_class):
        super().__init__(server_address, request_handler_class)
        self.records = []
        self.records_lock = threading.Lock()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self._record_request()
        if self.path == "/":
            location = "http://b.localhost:{}/followed".format(self.server.server_port)
            self.send_response(301)
            self.send_header("Location", location)
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

    def do_HEAD(self):
        self._record_request()
        if self.path == "/":
            location = "http://b.localhost:{}/followed".format(self.server.server_port)
            self.send_response(301)
            self.send_header("Location", location)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()

    def _record_request(self):
        host = self.headers.get("Host", "")
        auth = self.headers.get("Authorization") or "none"
        with self.server.records_lock:
            if len(self.server.records) < 2:
                self.server.records.append({"host": host, "auth": auth})
                if len(self.server.records) == 2:
                    threading.Thread(target=self.server.shutdown, daemon=True).start()

    def log_message(self, format, *args):
        return


def signal_name(returncode):
    if returncode is None or returncode >= 0:
        return None
    try:
        return signal.Signals(-returncode).name
    except ValueError:
        return "SIG{}".format(-returncode)


def sanitized_environment():
    env = os.environ.copy()
    for key in list(env):
        if key.lower().endswith("_proxy"):
            env.pop(key, None)
    env["NO_PROXY"] = "*"
    env["no_proxy"] = "*"
    return env


def run_client(argv, timeout):
    start = time.monotonic()
    timed_out = False
    stdout = ""
    stderr = ""
    returncode = None
    error = None

    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=sanitized_environment(),
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.kill()
            stdout, stderr = proc.communicate()
            error = "client timed out"
        returncode = proc.returncode
    except FileNotFoundError:
        error = "binary not found"
        returncode = 127
    except PermissionError:
        error = "binary is not executable"
        returncode = 126
    except OSError as exc:
        error = "failed to launch client: {}".format(exc.strerror or exc.__class__.__name__)
        returncode = 126

    runtime_ms = int(round((time.monotonic() - start) * 1000))
    return returncode, signal_name(returncode), timed_out, runtime_ms, stdout, stderr, error


def make_transcript(records):
    lines = []
    for index, record in enumerate(records, 1):
        lines.append(
            "REQ {} host={} auth={}".format(index, record["host"], record["auth"])
        )
    return "".join(line + "\n" for line in lines)


def build_result(
    binary,
    command,
    returncode,
    sig,
    timed_out,
    runtime_ms,
    stdout,
    stderr,
    transcript,
    error,
):
    return {
        "binary": binary,
        "command": command,
        "returncode": returncode,
        "signal": sig,
        "timed_out": timed_out,
        "runtime_ms": runtime_ms,
        "stdout": stdout,
        "stderr": stderr,
        "observable": {
            "kind": "protocol_transcript",
            "value": transcript,
            "path": None,
        },
        "error": error,
    }


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run a local HTTP transcript PoC.", add_help=False
    )
    parser.add_argument("--binary", required=True)
    parser.add_argument("--json-out")
    parser.add_argument("--timeout", type=float, default=30)
    return parser.parse_args()


def main():
    args = parse_args()
    server = TranscriptHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_port
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    returncode = 126
    sig = None
    timed_out = False
    runtime_ms = 0
    stdout = ""
    stderr = ""
    error = None
    command = []

    try:
        with tempfile.TemporaryDirectory(prefix="poc-netrc-") as tmpdir:
            netrc_path = os.path.join(tmpdir, ".netrc")
            with open(netrc_path, "w", encoding="utf-8", newline="\n") as netrc_file:
                netrc_file.write(NETRC_CONTENT)
            os.chmod(netrc_path, 0o600)

            command = [
                args.binary,
                "-L",
                "--max-redirs",
                "3",
                "--resolve",
                "a.localhost:{}:127.0.0.1".format(port),
                "--resolve",
                "b.localhost:{}:127.0.0.1".format(port),
                "--netrc-file",
                netrc_path,
                "http://a.localhost:{}/".format(port),
            ]
            (
                returncode,
                sig,
                timed_out,
                runtime_ms,
                stdout,
                stderr,
                error,
            ) = run_client(command, args.timeout)
    except Exception as exc:
        error = "poc failed: {}".format(exc.__class__.__name__)
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)

    with server.records_lock:
        transcript = make_transcript(list(server.records))
    if error is None and returncode != 0:
        error = "client exited with status {}".format(returncode)

    result = build_result(
        args.binary,
        command,
        returncode,
        sig,
        timed_out,
        runtime_ms,
        stdout,
        stderr,
        transcript,
        error,
    )
    output = json.dumps(result, ensure_ascii=True, separators=(",", ":"))
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as json_file:
            json_file.write(output)
            json_file.write("\n")
    print(output)


if __name__ == "__main__":
    main()
