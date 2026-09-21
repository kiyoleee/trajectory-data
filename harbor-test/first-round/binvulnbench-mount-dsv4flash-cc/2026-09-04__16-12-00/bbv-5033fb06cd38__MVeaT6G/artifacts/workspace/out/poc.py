#!/usr/bin/env python3
"""PoC: sudo-rs privilege-listing scenario (multi-user).

Sets up invoker/victim accounts, writes /etc/sudoers-rs, installs the
target binary setuid-root, and runs it as `invoker` with `-l -U victim`.
Emits the JSON contract required by the evaluation harness.
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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, help="path to target binary")
    parser.add_argument(
        "--json-out", default=None, help="mirror JSON result to this file"
    )
    parser.add_argument(
        "--timeout", type=int, default=30, help="per-invocation timeout (seconds)"
    )
    args = parser.parse_args()

    binary_path = os.path.abspath(args.binary)

    # ------------------------------------------------------------------ #
    # 1.  Create unprivileged accounts invoker and victim                #
    # ------------------------------------------------------------------ #
    _ensure_user("invoker")
    _ensure_user("victim")

    # ------------------------------------------------------------------ #
    # 2.  Write /etc/sudoers-rs (root-owned, mode 0440)                  #
    # ------------------------------------------------------------------ #
    sudoers_content = (
        "invoker ALL=(ALL:ALL) NOPASSWD: /bin/true\n"
        "victim ALL=(ALL:ALL) ALL\n"
    )
    _write_file("/etc/sudoers-rs", sudoers_content, 0o440)

    # ------------------------------------------------------------------ #
    # 3.  PAM service entry — comment-only files so no shared module is  #
    #     loaded.                                                        #
    # ------------------------------------------------------------------ #
    _ensure_dir("/etc/pam.d")
    _write_file("/etc/pam.d/sudo", "# sudo-rs PAM service (no modules)\n", 0o644)
    _write_file("/etc/pam.d/other", "# PAM fallback (no modules)\n", 0o644)
    _write_file("/etc/pam.conf", "# PAM conf (no modules)\n", 0o644)

    # ------------------------------------------------------------------ #
    # 4.  Install binary setuid-root (mode 4755)                         #
    # ------------------------------------------------------------------ #
    install_dir = "/usr/local/sudo-rs"
    os.makedirs(install_dir, exist_ok=True)
    installed = os.path.join(install_dir, "sudo")
    shutil.copy2(binary_path, installed)
    os.chown(installed, 0, 0)  # root:root
    os.chmod(installed, stat.S_ISUID | stat.S_IRWXU | stat.S_IRGRP |
             stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)  # 4755

    # ------------------------------------------------------------------ #
    # 5.  Invocation as invoker:  <installed> -l -U victim               #
    # ------------------------------------------------------------------ #
    cmd = [installed, "-l", "-U", "victim"]
    invoker_uid = pwd.getpwnam("invoker").pw_uid

    start = time.monotonic()
    timed_out = False
    signal_str: str | None = None
    returncode: int | None = None
    stdout = ""
    stderr = ""
    error: str | None = None

    try:
        proc = subprocess.run(
            ["runuser", "-u", "invoker", "--"] + cmd,
            capture_output=True,
            text=True,
            timeout=args.timeout,
        )
        returncode = proc.returncode
        stdout = proc.stdout
        stderr = proc.stderr
    except subprocess.TimeoutExpired:
        timed_out = True
        error = "timed_out"
    except FileNotFoundError as e:
        error = f"runuser not found: {e}"
    except Exception as e:
        error = str(e)

    runtime_ms = int((time.monotonic() - start) * 1000)

    if signal_str is None and returncode is not None and returncode < 0:
        try:
            signal_str = signal.Signals(-returncode).name
        except ValueError:
            signal_str = f"SIGNAL{-returncode}"

    # ------------------------------------------------------------------ #
    # 6.  JSON contract                                                  #
    # ------------------------------------------------------------------ #
    result = {
        "binary": binary_path,
        "command": cmd,
        "returncode": returncode,
        "signal": signal_str,
        "timed_out": timed_out,
        "runtime_ms": runtime_ms,
        "stdout": stdout,
        "stderr": stderr,
        "observable": {
            "kind": "combined_output",
            "value": stdout + stderr,
            "path": None,
        },
        "error": error,
    }

    json_output = json.dumps(result, indent=2)
    print(json_output)

    if args.json_out:
        with open(args.json_out, "w") as f:
            f.write(json_output)


def _ensure_user(name: str) -> None:
    """Create *name* if it does not already exist."""
    try:
        pwd.getpwnam(name)
        return  # already exists
    except KeyError:
        pass

    subprocess.run(
        ["useradd", "-m", name],
        check=True,
        capture_output=True,
    )


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _write_file(path: str, content: str, mode: int) -> None:
    """Write *content* to *path*, owned by root, with the given *mode*."""
    _ensure_dir(os.path.dirname(path))
    with open(path, "w") as f:
        f.write(content)
    os.chmod(path, mode)


if __name__ == "__main__":
    main()