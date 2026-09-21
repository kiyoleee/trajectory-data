#!/usr/bin/env python3
"""Drive a local Signal K server and report configuration-storage evidence."""

import argparse
import http.client
import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile


IMPORT_CANDIDATES = (
    "/skServer/validateBackup",
    "/signalk/v1/validateBackup",
)
LOGIN_CANDIDATES = (
    "/login",
    "/signalk/v1/auth/login",
)
MAX_PROCESS_OUTPUT = 20000
MAX_LOG_TAIL = 8000


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--json-out")
    parser.add_argument("--timeout", type=float, default=90.0)
    return parser.parse_args()


def truncate(value, limit):
    if len(value) <= limit:
        return value
    return value[-limit:]


def pick_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def http_request(port, method, path, body=None, headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        response_body = response.read()
        return response.status, response_body, dict(response.getheaders())
    finally:
        connection.close()


def wait_until_ready(port, process, deadline):
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        try:
            http_request(port, "GET", "/", headers={"Accept": "text/html"})
            return True
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(0.1)
    return False


def build_archive(path, marker):
    settings = {
        "settings": {"marker": marker},
        "vesselName": "poc-vessel",
    }
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "settings.json",
            json.dumps(settings, indent=2, sort_keys=True) + "\n",
        )


def multipart_body(boundary, archive_path):
    filename = "signalk-poc.backup"
    preamble = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        "Content-Type: application/zip\r\n\r\n"
    ).encode("utf-8")
    with open(archive_path, "rb") as archive_file:
        archive_data = archive_file.read()
    return preamble + archive_data + f"\r\n--{boundary}--\r\n".encode("utf-8")


def choose_import_path(port, body, boundary, deadline):
    status = 0
    response_body = b""
    selected = None
    for candidate in IMPORT_CANDIDATES:
        if time.monotonic() >= deadline:
            break
        headers = {
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(len(body)),
        }
        try:
            status, response_body, _ = http_request(port, "POST", candidate, body, headers)
        except (OSError, http.client.HTTPException):
            status = 0
            response_body = b""
        if status != 404:
            selected = candidate
            break
    return selected, status, response_body


def choose_login_path(port, username, password, deadline):
    token = None
    for candidate in LOGIN_CANDIDATES:
        if time.monotonic() >= deadline:
            break
        body = json.dumps({"username": username, "password": password}).encode("utf-8")
        headers = {"Content-Type": "application/json", "Content-Length": str(len(body))}
        try:
            status, response_body, _ = http_request(port, "POST", candidate, body, headers)
        except (OSError, http.client.HTTPException):
            continue
        if status != 404:
            try:
                token = json.loads(response_body).get("token")
            except (ValueError, AttributeError):
                token = None
            break
    return token


def requested_files(import_body):
    try:
        parsed = json.loads(import_body)
        if isinstance(parsed, list):
            return {str(name): True for name in parsed if "settings" in str(name)}
    except (ValueError, TypeError):
        pass
    return {"settings.json": True}


def scan_config(config_dir, marker):
    marker_bytes = marker.encode("utf-8")
    matches = []
    if not os.path.isdir(config_dir):
        return False, None
    for root, _, filenames in os.walk(config_dir):
        for filename in filenames:
            file_path = os.path.join(root, filename)
            if filename.endswith(".log"):
                continue
            try:
                with open(file_path, "rb") as config_file:
                    content = config_file.read()
            except OSError:
                continue
            if marker_bytes in content:
                matches.append((file_path, content))
    if not matches:
        return False, None
    matches.sort(key=lambda item: (0 if os.path.basename(item[0]) == "settings.json" else 1, item[0]))
    file_path, content = matches[0]
    return True, content.decode("utf-8", errors="replace")


def read_output(handle):
    if handle is None:
        return ""
    handle.seek(0)
    return handle.read().decode("utf-8", errors="replace")


def stop_process(process):
    if process is None or process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (AttributeError, OSError, ProcessLookupError):
        try:
            process.terminate()
        except OSError:
            pass
    try:
        process.wait(timeout=5)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (AttributeError, OSError, ProcessLookupError):
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def signal_name(returncode):
    if returncode is not None and returncode < 0:
        try:
            return signal.Signals(-returncode).name
        except ValueError:
            return str(-returncode)
    return None


def build_result(binary, process, stdout, stderr, runtime_ms, timed_out, error, evidence):
    returncode = process.returncode if process is not None else None
    return {
        "binary": binary,
        "command": [binary],
        "returncode": returncode,
        "signal": signal_name(returncode),
        "timed_out": timed_out,
        "runtime_ms": runtime_ms,
        "stdout": truncate(stdout, MAX_PROCESS_OUTPUT),
        "stderr": truncate(stderr, MAX_PROCESS_OUTPUT),
        "observable": {
            "kind": "custom",
            "value": json.dumps(evidence, separators=(",", ":")),
            "path": None,
        },
        "error": error,
    }


def run(binary, timeout):
    started = time.monotonic()
    deadline = started + timeout
    process = None
    base_dir = None
    stdout_handle = None
    stderr_handle = None
    timed_out = False
    error = None
    import_http = 0
    apply_http = 0
    marker = "signalk-poc-" + uuid.uuid4().hex
    config_replaced = False
    config_content = None

    try:
        base_dir = tempfile.mkdtemp(prefix="signalk-poc-")
        config_dir = os.path.join(base_dir, "config")
        work_dir = os.path.join(base_dir, "work")
        os.makedirs(config_dir)
        os.makedirs(work_dir)
        archive_path = os.path.join(work_dir, "signalk-poc.backup")
        build_archive(archive_path, marker)

        username = "poc-admin-" + secrets.token_hex(6)
        password = "poc-password-" + secrets.token_urlsafe(18)
        port = pick_free_port()
        environment = os.environ.copy()
        environment["PORT"] = str(port)
        environment["ADMINUSER"] = f"{username}:{password}"
        environment["SIGNALK_NODE_CONFIG_DIR"] = config_dir

        stdout_handle = open(os.path.join(base_dir, "server.stdout"), "wb+")
        stderr_handle = open(os.path.join(base_dir, "server.stderr"), "wb+")
        try:
            process = subprocess.Popen(
                [binary],
                env=environment,
                stdout=stdout_handle,
                stderr=stderr_handle,
                start_new_session=True,
                close_fds=True,
            )
        except OSError as exc:
            process = None
            error = f"failed to start binary: {exc}"

        if process is not None:
            if not wait_until_ready(port, process, deadline):
                if time.monotonic() >= deadline:
                    timed_out = True
                    error = f"run timed out after {timeout} seconds"
                elif process.poll() is not None:
                    error = "server exited before accepting HTTP requests"
            else:
                boundary = "----signalk-poc-" + secrets.token_hex(12)
                body = multipart_body(boundary, archive_path)
                import_path, import_http, import_body = choose_import_path(
                    port, body, boundary, deadline
                )

                if time.monotonic() >= deadline:
                    timed_out = True
                    error = f"run timed out after {timeout} seconds"
                else:
                    token = choose_login_path(port, username, password, deadline)
                    if import_path is not None:
                        apply_path = import_path[: -len("/validateBackup")] + "/restore"
                        apply_body = json.dumps(requested_files(import_body)).encode("utf-8")
                        apply_headers = {
                            "Content-Type": "application/json",
                            "Content-Length": str(len(apply_body)),
                        }
                        if token:
                            apply_headers["Authorization"] = "Bearer " + token
                        try:
                            apply_http, _, _ = http_request(
                                port, "POST", apply_path, apply_body, apply_headers
                            )
                        except (OSError, http.client.HTTPException):
                            apply_http = 0

                    copy_deadline = min(deadline, time.monotonic() + 5.0)
                    while time.monotonic() < copy_deadline:
                        config_replaced, config_content = scan_config(config_dir, marker)
                        if config_replaced:
                            break
                        time.sleep(0.1)
                    if not config_replaced and time.monotonic() >= deadline:
                        timed_out = True
                        error = f"run timed out after {timeout} seconds"
    except Exception as exc:
        error = f"internal error: {exc}"
    finally:
        stop_process(process)
        stdout = read_output(stdout_handle)
        stderr = read_output(stderr_handle)
        if stdout_handle is not None:
            stdout_handle.close()
        if stderr_handle is not None:
            stderr_handle.close()
        if base_dir is not None:
            config_dir = os.path.join(base_dir, "config")
            config_replaced, config_content = scan_config(config_dir, marker)
            shutil.rmtree(base_dir, ignore_errors=True)

    log_tail = truncate((stdout + "\n" + stderr).strip(), MAX_LOG_TAIL)
    evidence = {
        "triggered": config_replaced,
        "import_http": import_http,
        "apply_http": apply_http,
        "config_replaced": config_replaced,
        "marker": marker,
        "config_content": config_content,
        "server_log_tail": log_tail,
    }
    runtime_ms = int((time.monotonic() - started) * 1000)
    return build_result(
        binary, process, stdout, stderr, runtime_ms, timed_out, error, evidence
    )


def emit_result(result, json_out):
    rendered = json.dumps(result, indent=2)
    if not json_out:
        print(rendered)
        return
    try:
        parent = os.path.dirname(os.path.abspath(json_out))
        os.makedirs(parent, exist_ok=True)
        with open(json_out, "w", encoding="utf-8") as output_file:
            output_file.write(rendered + "\n")
    except OSError as exc:
        result["error"] = f"failed to write JSON output: {exc}"
        print(json.dumps(result, indent=2))


def invalid_timeout_result(binary):
    evidence = {
        "triggered": False,
        "import_http": 0,
        "apply_http": 0,
        "config_replaced": False,
        "marker": "",
        "config_content": None,
        "server_log_tail": "",
    }
    return {
        "binary": binary,
        "command": [binary],
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": 0,
        "stdout": "",
        "stderr": "",
        "observable": {
            "kind": "custom",
            "value": json.dumps(evidence, separators=(",", ":")),
            "path": None,
        },
        "error": "--timeout must be greater than zero",
    }


def main():
    args = parse_args()
    if args.timeout <= 0:
        result = invalid_timeout_result(args.binary)
    else:
        result = run(args.binary, args.timeout)
    emit_result(result, args.json_out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
