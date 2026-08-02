#!/usr/bin/env python3
"""
Decode Defender's mpenginedb.db SQLite page codec.

The analyzed codec is RC4-like with a fixed 256-byte key table. Page 1 leaves
SQLite header bytes 0x10..0x17 in plaintext and transforms the surrounding
ranges. Other pages are transformed as whole pages by default.

You must supply the 256-byte key from the Defender image at VA 0x180d2e220.
Either pass it as hex with --key-hex, or extract it from a PE file with
--image and --key-va/--image-base.
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path


SQLITE_HEADER = b"SQLite format 3\x00"


def parse_int(value: str) -> int:
    return int(value, 0)


def read_exact(path: Path) -> bytes:
    with path.open("rb") as f:
        return f.read()


def rc4_defender_crypt(data: bytes, key: bytes) -> bytes:
    """Implements FUN_1808f9eac + FUN_1808f9e04."""
    if not 1 <= len(key) <= 0x100:
        raise ValueError("key length must be 1..256 bytes")

    s = list(range(256))
    j = 0
    key_len = len(key)

    for i in range(256):
        j = (j + s[i] + key[i % key_len]) & 0xFF
        s[i], s[j] = s[j], s[i]

    # Defender initializes i=1, j=0 before processing.
    i = 1
    j = 0
    out = bytearray(len(data))

    for n, b in enumerate(data):
        si = s[i]
        j = (j + si) & 0xFF
        sj = s[j]
        s[i], s[j] = sj, si
        out[n] = b ^ s[(si + sj) & 0xFF]
        i = (i + 1) & 0xFF

    return bytes(out)


def decode_page(page: bytes, page_no: int, key: bytes, page1_skip_header_gap: bool) -> bytes:
    out = bytearray(page)

    if page_no == 1 and page1_skip_header_gap:
        out[0:0x10] = rc4_defender_crypt(bytes(out[0:0x10]), key)
        if len(out) > 0x18:
            out[0x18:] = rc4_defender_crypt(bytes(out[0x18:]), key)
    else:
        out[:] = rc4_defender_crypt(bytes(out), key)

    return bytes(out)


def read_u16_be(buf: bytes, off: int) -> int:
    return struct.unpack_from(">H", buf, off)[0]


def detect_page_size(encoded_db: bytes) -> int:
    if len(encoded_db) < 0x20:
        raise ValueError("input is too small to be a SQLite database")

    # In this codec, bytes 0x10..0x17 of page 1 are left plaintext.
    page_size = read_u16_be(encoded_db, 0x10)
    if page_size == 1:
        page_size = 65536

    if page_size < 512 or page_size > 65536 or (page_size & (page_size - 1)) != 0:
        raise ValueError(f"invalid page size from offset 0x10: {page_size}")

    return page_size


def decode_db(encoded: bytes, key: bytes, page_size: int, page1_skip_header_gap: bool) -> bytes:
    if page_size <= 0:
        raise ValueError("page size must be positive")

    decoded = bytearray()
    page_no = 1

    for off in range(0, len(encoded), page_size):
        page = encoded[off:off + page_size]
        if len(page) != page_size:
            decoded.extend(page)
            break

        decoded.extend(decode_page(page, page_no, key, page1_skip_header_gap))
        page_no += 1

    return bytes(decoded)


def pe_rva_to_offset(image: bytes, rva: int) -> int:
    if image[:2] != b"MZ":
        raise ValueError("image is not a PE file: missing MZ header")

    pe_off = struct.unpack_from("<I", image, 0x3C)[0]
    if image[pe_off:pe_off + 4] != b"PE\x00\x00":
        raise ValueError("image is not a PE file: missing PE header")

    coff_off = pe_off + 4
    num_sections = struct.unpack_from("<H", image, coff_off + 2)[0]
    opt_size = struct.unpack_from("<H", image, coff_off + 16)[0]
    opt_off = coff_off + 20
    sec_off = opt_off + opt_size

    for i in range(num_sections):
        off = sec_off + i * 40
        virtual_size = struct.unpack_from("<I", image, off + 8)[0]
        virtual_address = struct.unpack_from("<I", image, off + 12)[0]
        raw_size = struct.unpack_from("<I", image, off + 16)[0]
        raw_ptr = struct.unpack_from("<I", image, off + 20)[0]
        span = max(virtual_size, raw_size)
        if virtual_address <= rva < virtual_address + span:
            delta = rva - virtual_address
            if delta >= raw_size:
                raise ValueError("RVA maps past section raw data")
            return raw_ptr + delta

    raise ValueError(f"RVA 0x{rva:x} not found in PE sections")


def extract_key_from_image(image_path: Path, key_va: int, image_base: int) -> bytes:
    image = read_exact(image_path)
    rva = key_va - image_base
    if rva < 0:
        raise ValueError("key VA is below image base")
    key_off = pe_rva_to_offset(image, rva)
    key = image[key_off:key_off + 0x100]
    if len(key) != 0x100:
        raise ValueError("could not read 256-byte key from image")
    return key


def parse_key(args: argparse.Namespace) -> bytes:
    if args.key_hex:
        key_hex = "".join(args.key_hex.split())
        key = bytes.fromhex(key_hex)
        if len(key) != 0x100:
            raise ValueError(f"--key-hex must decode to 256 bytes, got {len(key)}")
        return key

    if args.key_file:
        key = read_exact(Path(args.key_file))
        if len(key) != 0x100:
            raise ValueError(f"--key-file must be exactly 256 bytes, got {len(key)}")
        return key

    if args.image:
        return extract_key_from_image(Path(args.image), args.key_va, args.image_base)

    raise ValueError("provide one of --key-hex, --key-file, or --image")


def maybe_print_header(label: str, data: bytes) -> None:
    shown = data[:64]
    print(f"{label} first {len(shown)} bytes:")
    for off in range(0, len(shown), 16):
        chunk = shown[off:off + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  {off:04x}: {hex_part:<47} {asc_part}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Decode Defender mpenginedb.db using the observed RC4-like SQLite codec."
    )
    parser.add_argument("input", help="encoded mpenginedb.db")
    parser.add_argument("output", help="decoded output SQLite DB")
    parser.add_argument("--key-hex", help="256-byte codec key as hex")
    parser.add_argument("--key-file", help="file containing the raw 256-byte codec key")
    parser.add_argument("--image", help="Defender PE image to extract the codec key from")
    parser.add_argument("--image-base", type=parse_int, default=0x180000000, help="PE image base")
    parser.add_argument("--key-va", type=parse_int, default=0x180D2E220, help="VA of DAT_180d2e220")
    parser.add_argument("--page-size", type=parse_int, help="override SQLite page size")
    parser.add_argument(
        "--no-page1-gap",
        action="store_true",
        help="decode page 1 as a full page instead of preserving bytes 0x10..0x17",
    )
    parser.add_argument("--quiet", action="store_true", help="suppress header diagnostics")

    args = parser.parse_args(argv)

    input_path = Path(args.input)
    output_path = Path(args.output)

    encoded = read_exact(input_path)
    key = parse_key(args)
    page_size = args.page_size or detect_page_size(encoded)
    decoded = decode_db(encoded, key, page_size, not args.no_page1_gap)

    output_path.write_bytes(decoded)

    if not args.quiet:
        print(f"input:      {input_path}")
        print(f"output:     {output_path}")
        print(f"size:       {len(encoded)} bytes")
        print(f"page size:  {page_size}")
        print(f"pages:      {len(encoded) // page_size}")
        print(f"key preview: {key[:16].hex()}...")
        maybe_print_header("encoded", encoded)
        maybe_print_header("decoded", decoded)
        if decoded.startswith(SQLITE_HEADER):
            print("OK: decoded output starts with SQLite header")
        else:
            print("WARN: decoded output does not start with SQLite header")
            print("      Check that the key came from the same Defender build as the DB.")
            print("      You can also try --no-page1-gap or a different --key-va.")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)