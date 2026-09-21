#!/usr/bin/env python3
import argparse
import json
import os
import signal
import socket
import subprocess
import tempfile
import threading
import time


def decode_bytes(data):
    return (data or b"").decode("utf-8", "replace")


def signal_name(returncode):
    if returncode is None or returncode >= 0:
        return None
    try:
        return signal.Signals(-returncode).name
    except ValueError:
        return "SIG%d" % (-returncode)


class OneShotHTTPServer:
    def __init__(self, response, timeout):
        self.response = response
        self.timeout = timeout
        self.request = b""
        self.error = None
        self._sock = None
        self._thread = None
        self.port = None

    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        sock.settimeout(self.timeout)
        self._sock = sock
        self.port = sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        try:
            conn, _addr = self._sock.accept()
            with conn:
                conn.settimeout(self.timeout)
                chunks = []
                total = 0
                while total < 8192:
                    try:
                        chunk = conn.recv(1024)
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                    if b"\r\n\r\n" in b"".join(chunks):
                        break
                self.request = b"".join(chunks)
                conn.sendall(self.response)
                try:
                    conn.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
        except Exception as exc:
            self.error = "%s: %s" % (exc.__class__.__name__, exc)
        finally:
            try:
                self._sock.close()
            except OSError:
                pass

    def stop(self):
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=1.0)


def build_response():
    declared_len = 64
    body = b"TRUNC\n"
    response = (
        b"HTTP/1.1 200 OK\r\n"
        + b"Content-Length: "
        + str(declared_len).encode("ascii")
        + b"\r\n"
        + b"Connection: close\r\n"
        + b"\r\n"
        + body
    )
    return response, declared_len, body


def run_poc(binary, timeout):
    response, declared_len, body = build_response()
    server = OneShotHTTPServer(response, timeout)
    timed_out = False
    proc_stdout = b""
    proc_stderr = b""
    returncode = None
    runtime_ms = 0
    output_size = None
    output_preview = b""
    error = None

    with tempfile.TemporaryDirectory(prefix="wget-poc-") as tmpdir:
        output_path = os.path.join(tmpdir, "download.out")
        try:
            server.start()
            url = "http://127.0.0.1:%d/poc" % server.port
            command = [binary, "wget", "-O", output_path, url]
            env = os.environ.copy()
            for key in (
                "http_proxy",
                "https_proxy",
                "ftp_proxy",
                "all_proxy",
                "HTTP_PROXY",
                "HTTPS_PROXY",
                "FTP_PROXY",
                "ALL_PROXY",
                "no_proxy",
                "NO_PROXY",
            ):
                env.pop(key, None)

            start = time.monotonic()
            try:
                completed = subprocess.run(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=timeout,
                    env=env,
                )
                returncode = completed.returncode
                proc_stdout = completed.stdout
                proc_stderr = completed.stderr
            except subprocess.TimeoutExpired as exc:
                timed_out = True
                proc_stdout = exc.stdout or b""
                proc_stderr = exc.stderr or b""
            runtime_ms = int((time.monotonic() - start) * 1000)

            if os.path.exists(output_path):
                output_size = os.path.getsize(output_path)
                with open(output_path, "rb") as f:
                    output_preview = f.read(128)
        except Exception as exc:
            error = "%s: %s" % (exc.__class__.__name__, exc)
            command = [binary, "wget", "-O", output_path, "http://127.0.0.1:0/poc"]
        finally:
            server.stop()

    sig = signal_name(returncode)
    if sig is not None:
        observable = {
            "kind": "crash_trace",
            "value": "process terminated by %s" % sig,
            "path": None,
        }
    elif returncode == 0 and output_size != declared_len:
        observable = {
            "kind": "custom",
            "value": (
                "HTTP response declared Content-Length=%d but sent %d body bytes; "
                "target exited 0 and wrote %s bytes. Output preview=%r"
                % (declared_len, len(body), output_size, output_preview)
            ),
            "path": None,
        }
    else:
        combined = decode_bytes(proc_stdout + proc_stderr).strip()
        observable = {
            "kind": "combined_output",
            "value": combined,
            "path": None,
        }
        if error is None:
            error = (
                "expected truncated-body anomaly was not observed "
                "(returncode=%r, output_size=%r, declared=%d)"
                % (returncode, output_size, declared_len)
            )

    if server.error and error is None:
        error = "server: %s" % server.error

    return {
        "binary": binary,
        "command": command,
        "returncode": returncode,
        "signal": sig,
        "timed_out": timed_out,
        "runtime_ms": runtime_ms,
        "stdout": decode_bytes(proc_stdout),
        "stderr": decode_bytes(proc_stderr),
        "observable": observable,
        "error": error,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--json-out")
    parser.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args()

    result = run_poc(args.binary, args.timeout)
    text = json.dumps(result, sort_keys=False, indent=2)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    else:
        print(text)


if __name__ == "__main__":
    main()
