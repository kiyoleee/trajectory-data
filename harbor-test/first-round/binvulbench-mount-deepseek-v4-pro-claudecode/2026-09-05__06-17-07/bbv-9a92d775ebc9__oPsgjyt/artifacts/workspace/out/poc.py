#!/usr/bin/env python3
"""Drive an HTTP client binary against a local loopback server and report a
normalized transcript of the requests the server receives.

The script is fully self-contained and offline-only.  During a single run it:

  1. binds an HTTP server to 127.0.0.1 on an ephemeral port,
  2. writes a temporary .netrc credential file,
  3. launches the provided binary with ``-L --max-redirs 3`` and ``--resolve``
     entries so ``a.localhost``/``b.localhost`` both map onto the loopback
     server, plus ``--netrc-file`` pointing at the temporary credential file,
  4. answers ``GET /`` with a ``301`` -> ``Location: http://b.localhost:<port>/followed``
     and every other path with ``200 OK``,
  5. stops the server and emits a single JSON object describing the traffic.

Only the Python 3 standard library is used.
"""

import argparse
import base64
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

NETRC_CONTENT = (
    "machine a.localhost\n"
    "login alice\n"
    "password secretpw\n"
    "default\n"
)


class LoopbackServer:
    """Minimal HTTP/1.1 server capturing every request line and header."""

    def __init__(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(4)
        self._sock.settimeout(1.0)
        self.port = self._sock.getsockname()[1]
        self._lock = threading.Lock()
        self._requests = []
        self._stop = threading.Event()

    def start(self):
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self._handle(conn)
            except Exception:
                pass
        try:
            self._sock.close()
        except OSError:
            pass

    def _read_request(self, conn):
        """Read the request head (request line + headers)."""
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
            if len(data) > 65536:
                break
        head, _, _ = data.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        return lines

    def _handle(self, conn):
        conn.settimeout(5.0)
        try:
            lines = self._read_request(conn)
            if not lines or not lines[0]:
                conn.close()
                return

            request_line = lines[0]
            parts = request_line.split(" ")
            method = parts[0] if parts else ""
            path = parts[1] if len(parts) > 1 else ""

            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    key, _, value = line.partition(":")
                    headers[key.strip().lower()] = value.strip()

            with self._lock:
                self._requests.append(
                    {
                        "method": method,
                        "path": path,
                        "host": headers.get("host", ""),
                        "authorization": headers.get("authorization"),
                    }
                )

            if path == "/":
                status = "301 Moved Permanently"
                body = b""
                location = "http://b.localhost:%d/followed" % self.port
                extra = "Location: %s\r\n" % location
            else:
                status = "200 OK"
                body = b"OK"
                extra = ""

            response = (
                "HTTP/1.1 %s\r\n"
                "Content-Length: %d\r\n"
                "Connection: close\r\n"
                "%s"
                "\r\n"
            ) % (status, len(body), extra)
            conn.sendall(response.encode("latin-1"))
            if body:
                conn.sendall(body)
        except Exception:
            pass
        finally:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()

    def stop(self):
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass

    def requests(self):
        with self._lock:
            return list(self._requests)


def build_transcript(requests):
    lines = []
    for i, req in enumerate(requests, 1):
        host = req["host"] or ""
        auth = req["authorization"] if req["authorization"] else "none"
        lines.append("REQ %d host=%s auth=%s" % (i, host, auth))
    return "\n".join(lines) + ("\n" if lines else "")


def run_client(binary, args, timeout):
    """Run the client, returning (returncode, signal, timed_out, stdout, stderr, runtime_ms)."""
    start = time.monotonic()
    try:
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        return None, str(exc), False, b"", b"", 0, None

    timed_out = False
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        out, err = proc.communicate()

    runtime_ms = int(round((time.monotonic() - start) * 1000))

    returncode = proc.returncode
    sig = None
    if returncode is not None and returncode < 0:
        sig = -returncode
        try:
            sig_name = signal.Signals(sig).name
        except ValueError:
            sig_name = str(sig)
        return None, None, timed_out, out, err, runtime_ms, sig_name

    return returncode, None, timed_out, out, err, runtime_ms, None


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Capture an HTTP client's redirect + netrc behavior over loopback."
    )
    parser.add_argument("--binary", required=True, help="path to the HTTP client binary")
    parser.add_argument("--json-out", default=None, help="optional path to write JSON output")
    parser.add_argument("--timeout", type=float, default=30.0, help="per-run timeout in seconds")
    opts = parser.parse_args(argv)

    binary = opts.binary

    server = LoopbackServer()
    server.start()

    tmpdir = tempfile.mkdtemp(prefix="poc-netrc-")
    netrc_path = os.path.join(tmpdir, ".netrc")

    try:
        with open(netrc_path, "w") as fh:
            fh.write(NETRC_CONTENT)
        os.chmod(netrc_path, 0o600)

        port = server.port
        target_url = "http://a.localhost:%d/" % port

        command = [
            binary,
            "-L",
            "--max-redirs", "3",
            "--resolve", "a.localhost:%d:127.0.0.1" % port,
            "--resolve", "b.localhost:%d:127.0.0.1" % port,
            "--netrc-file", netrc_path,
            target_url,
        ]

        error = None
        returncode = 0
        sig = None
        timed_out = False
        stdout = b""
        stderr = b""
        runtime_ms = 0

        try:
            (
                returncode,
                _launch_err,
                timed_out,
                stdout,
                stderr,
                runtime_ms,
                sig,
            ) = run_client(binary, command, opts.timeout)

            if _launch_err is not None:
                error = "failed to launch binary: %s" % _launch_err
                returncode = 1
                sig = None
                timed_out = False
            elif not os.path.exists(binary):
                error = "binary not found: %s" % binary
        finally:
            # Give the server a brief moment to finish reading any in-flight
            # request before we stop accepting connections.
            time.sleep(0.1)
            server.stop()

        requests = server.requests()
        transcript = build_transcript(requests)

        result = {
            "binary": binary,
            "command": command,
            "returncode": returncode,
            "signal": sig,
            "timed_out": timed_out,
            "runtime_ms": runtime_ms,
            "stdout": stdout.decode("utf-8", "replace"),
            "stderr": stderr.decode("utf-8", "replace"),
            "observable": {
                "kind": "protocol_transcript",
                "value": transcript,
                "path": None,
            },
            "error": error,
        }

        out_json = json.dumps(result)
        sys.stdout.write(out_json)
        sys.stdout.flush()

        if opts.json_out:
            with open(opts.json_out, "w") as fh:
                fh.write(out_json)

        return 0
    finally:
        server.stop()
        try:
            import shutil

            shutil.rmtree(tmpdir, ignore_errors=True)
        except OSError:
            pass


if __name__ == "__main__":
    sys.exit(main())