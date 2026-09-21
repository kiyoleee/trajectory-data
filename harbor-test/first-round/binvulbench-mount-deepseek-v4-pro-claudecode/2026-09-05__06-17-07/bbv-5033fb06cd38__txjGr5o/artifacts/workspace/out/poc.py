#!/usr/bin/env python3
"""Drive a sudo-like privileged tool through a deterministic multi-user scenario.

The target is a sudo-rs style tool: it needs to run as (effective) root, reads
its rules from ``/etc/sudoers-rs`` when that file exists (falling back to
``/etc/sudoers`` otherwise), and offers a ``-l`` (list privileges) mode together
with ``-U <user>`` (list privileges *for* another user).  This PoC builds the
whole trigger scenario at runtime and captures the complete stdout/stderr of a
single ``<tool> -l -U victim`` invocation performed as an unprivileged
``invoker`` account, printing one fixed JSON object.

The scenario is:

* ``invoker`` and ``victim`` accounts are created (or reused) with ``useradd -m``.
* ``/etc/sudoers-rs`` is written (root-owned, mode 0440) with::

      invoker ALL=(ALL:ALL) NOPASSWD: /bin/true
      victim ALL=(ALL:ALL) ALL

* The tool's PAM service entry ``/etc/pam.d/sudo`` is written as a comment-only
  file (no module lines), and the fallbacks ``/etc/pam.d/other`` and
  ``/etc/pam.conf`` are neutralized the same way, so the tool's PAM bootstrap
  succeeds without loading any shared PAM module in this container.
* The target binary is installed at a private location owned by root with mode
  ``4755`` so an unprivileged account can invoke it through the standard
  setuid-root mechanism.
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
import uuid

# Fixed system paths required by the scenario / the target's behaviour.
SUDOERS_RS = "/etc/sudoers-rs"
SUDOERS = "/etc/sudoers"
PAM_SUDO = "/etc/pam.d/sudo"
PAM_OTHER = "/etc/pam.d/other"
PAM_CONF = "/etc/pam.conf"

# Private, host-independent location for the setuid installation of the target.
INSTALL_DIR = "/opt/sudoers-rs-poc"
INSTALL_PATH = os.path.join(INSTALL_DIR, "sudo")

CONFIG_CONTENT = (
    "invoker ALL=(ALL:ALL) NOPASSWD: /bin/true\n"
    "victim ALL=(ALL:ALL) ALL\n"
)

PAM_COMMENT_ONLY = "# sudo-rs PoC: comment-only service, no PAM modules\n"


def run(cmd, **kwargs):
    """Run a command, returning a CompletedProcess; raise on failure."""
    proc = subprocess.run(cmd, **kwargs)
    if proc.returncode != 0:
        raise RuntimeError(
            "command failed (rc=%d): %r -> %s"
            % (proc.returncode, cmd, proc.stderr)
        )
    return proc


def ensure_user(name):
    """Create the named unprivileged account, or reuse it if it exists."""
    try:
        pwd.getpwnam(name)
    except KeyError:
        run(["useradd", "-m", name])


def write_file(path, content, mode):
    """Write *content* to *path* atomically, root-owned, with the given mode."""
    tmp = "%s.%s.tmp" % (path, uuid.uuid4().hex)
    with open(tmp, "w") as fh:
        fh.write(content)
    os.chown(tmp, 0, 0)
    os.chmod(tmp, mode)
    os.replace(tmp, path)
    os.chmod(path, mode)  # in case of an existing file being replaced


def demote_invoker():
    """Drop to the unprivileged ``invoker`` account (no supplementary groups)."""
    ent = pwd.getpwnam("invoker")
    os.setgroups([])
    os.setgid(ent.pw_gid)
    os.setuid(ent.pw_uid)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, help="path to the target binary")
    parser.add_argument("--json-out", default=None,
                        help="if given, mirror the JSON result to this file")
    parser.add_argument("--timeout", type=float, default=30.0,
                        help="per-invocation timeout in seconds")
    args = parser.parse_args(argv)

    binary = os.path.abspath(args.binary)
    result = {
        "binary": binary,
        "command": [],
        "returncode": None,
        "signal": None,
        "timed_out": False,
        "runtime_ms": 0,
        "stdout": "",
        "stderr": "",
        "observable": {"kind": "", "value": "", "path": ""},
        "error": None,
    }

    try:
        if not os.path.isfile(binary):
            raise RuntimeError("target binary not found: %s" % binary)

        # 1. Unprivileged accounts.
        ensure_user("invoker")
        ensure_user("victim")

        # 2. Tool configuration file.
        write_file(SUDOERS_RS, CONFIG_CONTENT, 0o440)
        # The tool prefers /etc/sudoers-rs when it exists; make sure a stale
        # fallback file cannot be picked up if that preference ever changes.
        if os.path.exists(SUDOERS):
            os.remove(SUDOERS)

        # 3. PAM bootstrap: comment-only service + neutralized fallbacks.
        write_file(PAM_SUDO, PAM_COMMENT_ONLY, 0o644)
        write_file(PAM_OTHER, PAM_COMMENT_ONLY, 0o644)
        write_file(PAM_CONF, PAM_COMMENT_ONLY, 0o644)

        # 4. Install the target binary setuid-root.
        if os.path.isdir(INSTALL_DIR):
            shutil.rmtree(INSTALL_DIR)
        os.makedirs(INSTALL_DIR, mode=0o755)
        shutil.copyfile(binary, INSTALL_PATH)
        os.chown(INSTALL_PATH, 0, 0)
        os.chmod(INSTALL_PATH, 0o4755)

        # 5./6. Invoke as invoker: privilege listing for victim, no command arg.
        command = [INSTALL_PATH, "-l", "-U", "victim"]
        result["command"] = command

        start = time.monotonic()
        try:
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                preexec_fn=demote_invoker,
            )
            try:
                out, err = proc.communicate(timeout=args.timeout)
                timed_out = False
            except subprocess.TimeoutExpired:
                timed_out = True
                proc.kill()
                out, err = proc.communicate()
        except Exception as exc:  # pragma: no cover - defensive
            result["error"] = "invocation failed: %s" % exc
            raise
        finally:
            result["runtime_ms"] = int((time.monotonic() - start) * 1000)

        stdout = out.decode("utf-8", "replace")
        stderr = err.decode("utf-8", "replace")

        result["timed_out"] = timed_out
        result["stdout"] = stdout
        result["stderr"] = stderr
        result["signal"] = None
        result["returncode"] = None if proc.returncode < 0 else proc.returncode
        if proc.returncode < 0:
            result["signal"] = signal.Signals(-proc.returncode).name
            result["returncode"] = None

        combined = stdout + stderr
        result["observable"] = {
            "kind": "privilege-listing",
            "value": combined,
            "path": SUDOERS_RS,
        }
    except Exception as exc:
        result["error"] = str(exc)

    # Emit exactly one JSON object to stdout.
    print(json.dumps(result))

    # Optionally mirror the result to a file.
    if args.json_out:
        with open(args.json_out, "w") as fh:
            fh.write(json.dumps(result) + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
