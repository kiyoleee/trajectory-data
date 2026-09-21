#!/usr/bin/env python3
import argparse
import json
import os
import pwd
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path


INVOKER = "invoker"
VICTIM = "victim"
CONFIG_PATH = Path("/etc/sudoers-rs")
PAM_PATHS = (
    Path("/etc/pam.d/sudo"),
    Path("/etc/pam.d/other"),
    Path("/etc/pam.conf"),
)
CONFIG_CONTENT = "invoker ALL=(ALL:ALL) NOPASSWD: /bin/true\nvictim ALL=(ALL:ALL) ALL\n"
PAM_CONTENT = "# PoC PAM service: intentionally load no modules\n"


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run a deterministic multi-user sudo -l -U scenario."
    )
    parser.add_argument("--binary", required=True, help="path to the target binary")
    parser.add_argument("--json-out", help="optional path for a JSON result copy")
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="per-invocation timeout in seconds (default: 10)",
    )
    return parser.parse_args()


def run(command, *, timeout=None):
    return subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout,
        check=False,
    )


def ensure_account(name):
    try:
        return pwd.getpwnam(name)
    except KeyError:
        useradd = shutil.which("useradd")
        if useradd is None:
            raise RuntimeError("useradd is required to create test accounts")
        result = run([useradd, "-m", name], timeout=10)
        if result.returncode != 0:
            raise RuntimeError(
                f"creating {name} failed with status {result.returncode}: "
                f"{result.stderr.strip()}"
            )
        return pwd.getpwnam(name)


def write_root_file(path, content, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.fchmod(fd, mode)
        os.fchown(fd, 0, 0)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def install_setuid_binary(source):
    if not os.path.isfile(source):
        raise RuntimeError(f"target binary does not exist: {source}")

    install_dir = Path(tempfile.mkdtemp(prefix="sudo-poc-", dir="/tmp"))
    os.chmod(install_dir, 0o755)
    installed_path = install_dir / "sudo"
    source_fd = os.open(source, os.O_RDONLY)
    try:
        dest_fd = os.open(
            installed_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o755,
        )
        try:
            os.fchmod(dest_fd, 0o755)
            os.fchown(dest_fd, 0, 0)
            with os.fdopen(source_fd, "rb") as source_stream:
                with os.fdopen(dest_fd, "wb") as dest_stream:
                    shutil.copyfileobj(source_stream, dest_stream)
                    dest_stream.flush()
                    os.fsync(dest_stream.fileno())
            os.chmod(installed_path, 0o4755)
        except BaseException:
            try:
                os.close(dest_fd)
            except OSError:
                pass
            raise
    finally:
        try:
            os.close(source_fd)
        except OSError:
            pass

    return installed_path


def drop_to_account(name):
    account = pwd.getpwnam(name)

    def prepare():
        os.initgroups(name, account.pw_gid)
        os.setgid(account.pw_gid)
        os.setuid(account.pw_uid)

    return prepare


def invoke_as_invoker(command, home, timeout):
    environment = {
        "HOME": home,
        "LOGNAME": INVOKER,
        "USER": INVOKER,
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "TERM": "dumb",
    }
    process = subprocess.Popen(
        command,
        cwd=home,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
        preexec_fn=drop_to_account(INVOKER),
    )

    start_time = time.monotonic()
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        timed_out = False
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate()

    runtime_ms = max(0, round((time.monotonic() - start_time) * 1000))
    return process.returncode, stdout, stderr, timed_out, runtime_ms


def signal_name(returncode):
    if returncode is not None and returncode < 0:
        try:
            return signal.Signals(-returncode).name
        except ValueError:
            return f"SIG{-returncode}"
    return None


def build_result(
    binary,
    command,
    returncode,
    stdout,
    stderr,
    timed_out,
    runtime_ms,
    error,
    evidence_path,
):
    return {
        "binary": binary,
        "command": command,
        "returncode": returncode,
        "signal": signal_name(returncode),
        "timed_out": timed_out,
        "runtime_ms": runtime_ms,
        "stdout": stdout,
        "stderr": stderr,
        "observable": {
            "kind": "combined",
            "value": stdout + stderr,
            "path": str(evidence_path),
        },
        "error": error,
    }


def main():
    args = parse_args()
    command = None
    returncode = None
    stdout = ""
    stderr = ""
    timed_out = False
    runtime_ms = 0
    error = None
    evidence_path = ""

    try:
        if args.timeout <= 0:
            raise ValueError("--timeout must be positive")

        invoker = ensure_account(INVOKER)
        ensure_account(VICTIM)
        write_root_file(CONFIG_PATH, CONFIG_CONTENT, 0o440)
        for pam_path in PAM_PATHS:
            write_root_file(pam_path, PAM_CONTENT, 0o644)

        installed_path = install_setuid_binary(args.binary)
        command = [str(installed_path), "-l", "-U", VICTIM]
        evidence_path = installed_path
        returncode, stdout, stderr, timed_out, runtime_ms = invoke_as_invoker(
            command, invoker.pw_dir, args.timeout
        )
    except Exception as exception:
        error = f"{type(exception).__name__}: {exception}"

    result = build_result(
        args.binary,
        command or [],
        returncode,
        stdout,
        stderr,
        timed_out,
        runtime_ms,
        error,
        evidence_path,
    )
    json_text = json.dumps(result, ensure_ascii=False) + "\n"

    if args.json_out:
        output_path = Path(args.json_out)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json_text, encoding="utf-8")

    sys.stdout.write(json_text)
    return 0 if error is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
