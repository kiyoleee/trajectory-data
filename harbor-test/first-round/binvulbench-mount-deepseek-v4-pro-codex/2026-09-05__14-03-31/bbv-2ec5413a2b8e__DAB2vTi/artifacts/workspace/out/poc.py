#!/usr/bin/env python3
"""Single-file standard-library PoC for the goshs realtime websocket channel.

The script starts the target HTTP file server on loopback, connects a
raw RFC6455 websocket client to ``/?ws``, sends a dynamically-built
``newEntry`` clipboard message, and records every JSON message sent and
received as a protocol transcript.  The server-side action is observable:
handling ``newEntry`` makes the server update its server-side clipboard and
broadcast a ``refreshClipboard`` message back over the websocket.
"""

from __future__ import annotations

import argparse
import base64
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


DEFAULT_TIMEOUT = 25
DEAD_PROXY = "http://127.0.0.1:9"


class WebSocket:
    """Tiny RFC6455 client implementation using only the standard library."""

    def __init__(self) -> None:
        self.sock: socket.socket | None = None
        self.buf = b""

    def connect(self, host: str, port: int, timeout: float) -> None:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            "GET /?ws HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            f"Origin: http://{host}:{port}\r\n"
            "\r\n"
        )
        sock.sendall(request.encode("ascii"))

        data = b""
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                raise ConnectionError("websocket handshake: connection closed")
            data += chunk

        header_blob, _, remainder = data.partition(b"\r\n\r\n")
        headers = [
            line.strip().decode("latin-1", "replace")
            for line in header_blob.split(b"\r\n")
            if line.strip()
        ]
        if not headers or " 101 " not in f" {headers[0]} ":
            raise ConnectionError(
                f"websocket upgrade failed, status line: {headers[0] if headers else 'missing'}"
            )
        lowered = {
            k.lower(): v
            for line in headers[1:]
            for k, _, v in [line.partition(":")]
        }
        if lowered.get("upgrade", "").strip().lower() != "websocket":
            raise ConnectionError("websocket upgrade header missing")
        self.sock = sock
        self.buf = remainder

    def _read_exact(self, count: int, timeout: float) -> bytes:
        assert self.sock is not None
        self.sock.settimeout(timeout)
        data = self.buf[:count]
        self.buf = self.buf[count:]
        while len(data) < count:
            chunk = self.sock.recv(count - len(data))
            if not chunk:
                raise ConnectionError("websocket connection closed")
            data += chunk
        return data

    def send_text(self, text: str) -> None:
        assert self.sock is not None
        payload = text.encode("utf-8")
        mask = os.urandom(4)
        length = len(payload)
        if length < 126:
            header = bytes([0x81, 0x80 | length]) + mask
        elif length < 65536:
            header = bytes([0x81, 0x80 | 126]) + struct.pack("!H", length) + mask
        else:
            header = bytes([0x81, 0x80 | 127]) + struct.pack("!Q", length) + mask
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        self.sock.sendall(header + masked)

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        assert self.sock is not None
        mask = os.urandom(4)
        length = len(payload)
        if length < 126:
            header = bytes([0x80 | opcode, 0x80 | length]) + mask
        elif length < 65536:
            header = (
                bytes([0x80 | opcode, 0x80 | 126])
                + struct.pack("!H", length)
                + mask
            )
        else:
            header = (
                bytes([0x80 | opcode, 0x80 | 127])
                + struct.pack("!Q", length)
                + mask
            )
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        self.sock.sendall(header + masked)

    def recv_frame(self, timeout: float) -> tuple[int, bytes]:
        """Return ``(opcode, payload)`` for the next complete websocket frame."""
        first, second = self._read_exact(2, timeout)
        fin = bool(first & 0x80)
        opcode = first & 0x0F
        masked = bool(second & 0x80)
        length = second & 0x7F
        if length == 126:
            length = struct.unpack("!H", self._read_exact(2, timeout))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._read_exact(8, timeout))[0]
        mask = self._read_exact(4, timeout) if masked else b""
        payload = self._read_exact(length, timeout) if length else b""
        if masked:
            payload = bytes(
                byte ^ mask[index % 4] for index, byte in enumerate(payload)
            )
        if not fin and opcode == 0:
            # Reassemble simple continuation frames.
            combined = payload
            while True:
                first, second = self._read_exact(2, timeout)
                cont_opcode = first & 0x0F
                cont_fin = bool(first & 0x80)
                cont_masked = bool(second & 0x80)
                cont_length = second & 0x7F
                if cont_length == 126:
                    cont_length = struct.unpack(
                        "!H", self._read_exact(2, timeout)
                    )[0]
                elif cont_length == 127:
                    cont_length = struct.unpack(
                        "!Q", self._read_exact(8, timeout)
                    )[0]
                cont_mask = self._read_exact(4, timeout) if cont_masked else b""
                cont_payload = (
                    self._read_exact(cont_length, timeout) if cont_length else b""
                )
                if cont_masked:
                    cont_payload = bytes(
                        byte ^ cont_mask[index % 4]
                        for index, byte in enumerate(cont_payload)
                    )
                combined += cont_payload
                if cont_fin or cont_opcode != 0:
                    break
            return opcode, combined
        return opcode, payload

    def close(self) -> None:
        if self.sock is None:
            return
        try:
            self._send_frame(0x8, struct.pack("!H", 1000))
        except Exception:
            pass
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass
        self.sock = None


def free_loopback_port() -> int:
    """Reserve an ephemeral loopback port, then release it for the server."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def endpoint_ready(port: int, timeout: float) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(
                b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
            )
            seen = False
            while True:
                try:
                    chunk = sock.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                seen = True
            return seen
    except OSError:
        return False


def build_result(
    binary: str,
    command: list[str],
    started_at: float,
    ended_at: float,
    returncode: int | None,
    signal_name: str | None,
    timed_out: bool,
    stdout: str,
    stderr: str,
    transcript: str,
    error: str | None,
) -> dict:
    return {
        "binary": binary,
        "command": command,
        "returncode": 0 if returncode is None else returncode,
        "signal": signal_name,
        "timed_out": timed_out,
        "runtime_ms": max(0, int(round((ended_at - started_at) * 1000))),
        "stdout": stdout,
        "stderr": stderr,
        "observable": {
            "kind": "protocol_transcript",
            "value": transcript,
            "path": None,
        },
        "error": error,
    }


def stop_process(proc: subprocess.Popen) -> tuple[int | None, str | None]:
    """Politely stop the server and return returncode plus signal name (if any)."""
    returncode: int | None = proc.poll()
    signal_name: str | None = None
    if returncode is None:
        try:
            proc.send_signal(signal.SIGINT)
            returncode = proc.wait(timeout=5)
        except (ProcessLookupError, OSError):
            returncode = proc.poll()
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except OSError:
                pass
            try:
                returncode = proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                returncode = proc.poll()
    if returncode is not None and returncode < 0:
        signal_name = signal.Signals(-returncode).name
    return returncode, signal_name


def run(binary_arg: str, timeout: float) -> dict:
    binary = os.path.abspath(binary_arg)
    started_at = time.monotonic()
    deadline = started_at + timeout
    timed_out = False

    if not os.path.exists(binary) or not os.access(binary, os.X_OK):
        msg = f"target binary is not executable: {binary}"
        now = time.monotonic()
        return build_result(
            binary, [binary, "-i", "127.0.0.1", "-p", "0", "-d", ""],
            started_at, now, None, None, False, "", "", "", msg,
        )

    webroot = tempfile.mkdtemp(prefix="goshs-poc-")
    proc: subprocess.Popen | None = None
    ws: WebSocket | None = None
    transcript_lines: list[str] = []
    error: str | None = None
    returncode: int | None = None
    exit_signal: str | None = None
    stdout = ""
    stderr = ""
    port = free_loopback_port()
    command = [binary, "-i", "127.0.0.1", "-p", str(port), "-d", webroot]

    env = os.environ.copy()
    env["HTTP_PROXY"] = DEAD_PROXY
    env["HTTPS_PROXY"] = DEAD_PROXY
    env["http_proxy"] = DEAD_PROXY
    env["https_proxy"] = DEAD_PROXY
    env["NO_PROXY"] = ""
    env["no_proxy"] = ""

    try:
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            close_fds=True,
        )
    except OSError as exc:
        error = f"failed to start target binary: {exc}"
        ended_at = time.monotonic()
        shutil.rmtree(webroot, ignore_errors=True)
        return build_result(
            binary, command, started_at, ended_at, None, None, False,
            "", "", "", error,
        )

    try:
        # Wait for the HTTP listener on loopback.
        ready = False
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                break
            if endpoint_ready(port, 0.4):
                ready = True
                break
            time.sleep(0.05)
        if proc.poll() is not None:
            stdout, stderr = proc.communicate(timeout=1)
            stdout = stdout.decode("utf-8", "replace")
            stderr = stderr.decode("utf-8", "replace")
            error = f"target binary exited before serving (returncode={proc.poll()})"
            ended_at = time.monotonic()
            return build_result(
                binary, command, started_at, ended_at, proc.returncode, None,
                False, stdout, stderr, "", error,
            )
        if not ready:
            timed_out = True
            error = "timed out waiting for HTTP endpoint before interaction"
            returncode, exit_signal = stop_process(proc)
            stdout, stderr = proc.communicate(timeout=5)
            stdout = stdout.decode("utf-8", "replace")
            stderr = stderr.decode("utf-8", "replace")
            ended_at = time.monotonic()
            return build_result(
                binary, command, started_at, ended_at, returncode, exit_signal,
                timed_out, stdout, stderr, "", error,
            )

        # Transport-level websocket connection.  This is script infrastructure,
        # so upgrade failures are legitimate script-level errors.
        ws = WebSocket()
        ws.connect("127.0.0.1", port, timeout=2.0)

        # Drain/record any frames emitted immediately after the upgrade.
        drain_until = time.monotonic() + 0.25
        while time.monotonic() < drain_until:
            try:
                opcode, payload = ws.recv_frame(0.2)
            except socket.timeout:
                break
            except (ConnectionError, OSError):
                break
            if opcode == 1:
                transcript_lines.append(f"S< {payload.decode('utf-8', 'replace')}")
            elif opcode == 8:
                break
            elif opcode == 9:
                ws._send_frame(0xA, payload)

        # Dynamically construct the trigger during the run.
        trigger = {
            "type": "newEntry",
            "content": f"goshs-poc-{os.urandom(8).hex()}-{int(time.time() * 1000)}",
        }
        trigger_json = json.dumps(trigger, separators=(",", ":"), ensure_ascii=False)
        ws.send_text(trigger_json)
        transcript_lines.append(f"C> {trigger_json}")

        # Wait for broadcast responses until the channel is quiet or the
        # per-run deadline is reached.  A server that sends no matching
        # response is still a legitimate, complete outcome.
        quiet_deadline = time.monotonic() + 2.0
        deadline = min(deadline, time.monotonic() + 3.0)
        consecutive_empty = 0
        while time.monotonic() < deadline:
            try:
                opcode, payload = ws.recv_frame(0.5)
            except socket.timeout:
                consecutive_empty += 1
                if consecutive_empty >= 4:
                    break
                continue
            except (ConnectionError, OSError):
                break
            consecutive_empty = 0
            if opcode == 1:
                transcript_lines.append(f"S< {payload.decode('utf-8', 'replace')}")
                quiet_deadline = time.monotonic() + 1.0
            elif opcode == 9:
                ws._send_frame(0xA, payload)
            elif opcode == 8:
                break

        # Give a final short window for any late broadcast after last frame.
        final_until = min(deadline, quiet_deadline)
        while time.monotonic() < final_until:
            try:
                opcode, payload = ws.recv_frame(final_until - time.monotonic())
            except socket.timeout:
                break
            except (ConnectionError, OSError):
                break
            if opcode == 1:
                transcript_lines.append(f"S< {payload.decode('utf-8', 'replace')}")
            elif opcode == 9:
                ws._send_frame(0xA, payload)
            elif opcode == 8:
                break

        ended_at_measure = time.monotonic()
    except (OSError, ConnectionError, ValueError, UnicodeError) as exc:
        error = f"script execution failed: {exc}"
        ended_at_measure = time.monotonic()
    except Exception as exc:  # keep the JSON contract on unexpected failures
        error = f"script internal error: {exc}"
        ended_at_measure = time.monotonic()

    # Clean shutdown and output collection.
    try:
        if ws is not None:
            ws.close()
    except Exception:
        pass
    try:
        if proc is not None:
            returncode, exit_signal = stop_process(proc)
    except Exception:
        pass
    try:
        if proc is not None:
            out, err = proc.communicate(timeout=5)
            stdout = out.decode("utf-8", "replace")
            stderr = err.decode("utf-8", "replace")
    except Exception:
        pass
    try:
        shutil.rmtree(webroot, ignore_errors=True)
    except Exception:
        pass

    ended_at = time.monotonic()
    if timed_out and error is None:
        pass
    return build_result(
        binary,
        command,
        started_at,
        ended_at,
        returncode,
        exit_signal,
        timed_out,
        stdout[:200000],
        stderr[:200000],
        "\n".join(transcript_lines),
        error,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Probe goshs realtime websocket channel end-to-end."
    )
    parser.add_argument("--binary", required=True, help="path to target binary")
    parser.add_argument("--json-out", default=None, help="write JSON result here")
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"per-run timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    args = parser.parse_args(argv)

    result = run(args.binary, args.timeout)
    text = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.json_out:
        out_path = args.json_out
        out_dir = os.path.dirname(os.path.abspath(out_path))
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
