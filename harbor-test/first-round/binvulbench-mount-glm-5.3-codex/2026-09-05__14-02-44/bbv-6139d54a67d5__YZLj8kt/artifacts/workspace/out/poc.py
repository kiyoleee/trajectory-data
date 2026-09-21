#!/usr/bin/env python3
import argparse
import json
import signal
import socket
import subprocess
import tempfile
import threading
import time


def decode_stream(data):
    if data is None:
        return ""
    return data.decode("utf-8", errors="replace")


def signal_name(returncode):
    if returncode is not None and returncode < 0:
        try:
            return signal.Signals(-returncode).name
        except ValueError:
            return f"SIG{-returncode}"
    return None


def build_response():
    return (
        b"HTTP/1.1 204 No Content\r\n"
        b"Content-Length: 1\r\n"
        b"\r\n"
        b"A"
    )


def run_poc(binary, timeout):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    server.settimeout(timeout)
    port = server.getsockname()[1]
    url = f"http://127.0.0.1:{port}/trigger"
    response = build_response()
    server_error = None
    output_file = None

    def serve_once():
        nonlocal server_error
        try:
            connection, _ = server.accept()
            connection.settimeout(timeout)
            connection.recv(65536)
            connection.sendall(response)
            connection.close()
        except Exception as exc:
            server_error = str(exc)
        finally:
            try:
                server.close()
            except OSError:
                pass

    server_thread = threading.Thread(target=serve_once, daemon=True)
    server_thread.start()

    started = time.monotonic()
    stdout = b""
    stderr = b""
    timed_out = False
    output_data = None
    output_error = None

    try:
        with tempfile.TemporaryDirectory(prefix="wget-poc-") as temp_dir:
            output_file = f"{temp_dir}/downloaded"
            command = [binary, "wget", "-O", output_file, url]
            try:
                process = subprocess.run(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=timeout,
                    check=False,
                )
                stdout = process.stdout
                stderr = process.stderr
                returncode = process.returncode
            except subprocess.TimeoutExpired as exc:
                timed_out = True
                returncode = -1
                stdout = exc.stdout or b""
                stderr = exc.stderr or b""

            try:
                with open(output_file, "rb") as downloaded:
                    output_data = downloaded.read()
            except OSError as exc:
                output_error = str(exc)
    finally:
        try:
            server.close()
        except OSError:
            pass
        server_thread.join(timeout=min(timeout, 1.0))

    runtime_ms = round((time.monotonic() - started) * 1000)
    errors = []
    if server_error is not None:
        errors.append(f"server: {server_error}")
    if output_error is not None:
        errors.append(f"output: {output_error}")
    if timed_out:
        errors.append("target timed out")

    if output_data == b"A":
        observable_value = (
            "HTTP 204 No Content body was written to the output file; "
            "expected_empty=true; actual_hex=41; actual_size=1"
        )
    else:
        actual_hex = output_data.hex() if output_data is not None else None
        actual_size = len(output_data) if output_data is not None else None
        observable_value = (
            "HTTP 204 No Content body check; expected_empty=true; "
            f"actual_hex={actual_hex}; actual_size={actual_size}"
        )
        errors.append("expected HTTP 204 output-file defect was not observed")

    return {
        "binary": binary,
        "command": [binary, "wget", "-O", output_file, url],
        "returncode": returncode,
        "signal": signal_name(returncode),
        "timed_out": timed_out,
        "runtime_ms": runtime_ms,
        "stdout": decode_stream(stdout),
        "stderr": decode_stream(stderr),
        "observable": {
            "kind": "output_file",
            "value": observable_value,
            "path": None,
        },
        "error": "; ".join(errors) if errors else None,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--json-out")
    parser.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args()

    if args.timeout <= 0:
        parser.error("--timeout must be positive")

    result = run_poc(args.binary, args.timeout)
    serialized = json.dumps(result, indent=2)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as output:
            output.write(serialized)
            output.write("\n")
    else:
        print(serialized)


if __name__ == "__main__":
    main()
