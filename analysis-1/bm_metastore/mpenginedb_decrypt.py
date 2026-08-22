#!/usr/bin/env python3
"""
Decode Defender's mpenginedb.db SQLite page codec.

The analyzed codec is RC4-like with a fixed 256-byte key table. Page 1 leaves
SQLite header bytes 0x10..0x17 in plaintext and transforms the surrounding
ranges. Other pages are transformed as whole pages by default.

You must supply or discover the 256-byte key table used by the Defender image.
The script can auto-discover it from --image by finding the codec wrapper's
RIP-relative key reference and validating it against page 1. If that fails, it
falls back to scanning PE sections for a 256-byte candidate that decodes page 1
to the SQLite header. You can also pass --key-va/--image-base, --key-hex, or
--key-file.
"""

from __future__ import annotations

import argparse
import sqlite3
import struct
import sys
import tempfile
from pathlib import Path


SQLITE_HEADER = b"SQLite format 3\x00"
DEFAULT_KEY_VA = 0x180D2E220
DEFAULT_IMAGE_BASE = 0x180000000


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


def sqlite_can_read(db_data: bytes) -> tuple[bool, str, int]:
    if not db_data.startswith(SQLITE_HEADER):
        return False, "missing SQLite header", 0

    tmp_path = ""
    try:
        with tempfile.NamedTemporaryFile(prefix="mpenginedb-dec-", suffix=".db", delete=False) as f:
            tmp_path = f.name
            f.write(db_data)

        con = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
        try:
            con.execute("PRAGMA schema_version;").fetchone()
            schema_count = con.execute("SELECT count(*) FROM sqlite_schema;").fetchone()[0]
        finally:
            con.close()
        return True, "sqlite-readable", int(schema_count)
    except Exception as exc:
        return False, str(exc), 0
    finally:
        if tmp_path:
            try:
                Path(tmp_path).unlink()
            except OSError:
                pass


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


def pe_rva_to_offset_from_sections(sections: list[dict[str, int | str]], rva: int) -> int:
    for sec in sections:
        virtual_size = int(sec["virtual_size"])
        virtual_address = int(sec["virtual_address"])
        raw_size = int(sec["raw_size"])
        raw_ptr = int(sec["raw_ptr"])
        span = max(virtual_size, raw_size)
        if virtual_address <= rva < virtual_address + span:
            delta = rva - virtual_address
            if delta >= raw_size:
                raise ValueError("RVA maps past section raw data")
            return raw_ptr + delta

    raise ValueError(f"RVA 0x{rva:x} not found in PE sections")


def raw_offset_to_va(sections: list[dict[str, int | str]], image_base: int, raw_offset: int) -> int:
    for sec in sections:
        raw_ptr = int(sec["raw_ptr"])
        raw_size = int(sec["raw_size"])
        if raw_ptr <= raw_offset < raw_ptr + raw_size:
            return image_base + int(sec["virtual_address"]) + (raw_offset - raw_ptr)

    raise ValueError(f"raw offset 0x{raw_offset:x} not found in PE sections")


def parse_pe_sections(image: bytes) -> tuple[int, list[dict[str, int | str]]]:
    if image[:2] != b"MZ":
        raise ValueError("image is not a PE file: missing MZ header")

    pe_off = struct.unpack_from("<I", image, 0x3C)[0]
    if image[pe_off:pe_off + 4] != b"PE\x00\x00":
        raise ValueError("image is not a PE file: missing PE header")

    coff_off = pe_off + 4
    num_sections = struct.unpack_from("<H", image, coff_off + 2)[0]
    opt_size = struct.unpack_from("<H", image, coff_off + 16)[0]
    opt_off = coff_off + 20
    magic = struct.unpack_from("<H", image, opt_off)[0]
    if magic == 0x20B:
        image_base = struct.unpack_from("<Q", image, opt_off + 24)[0]
    elif magic == 0x10B:
        image_base = struct.unpack_from("<I", image, opt_off + 28)[0]
    else:
        raise ValueError(f"unsupported PE optional-header magic 0x{magic:x}")

    sections: list[dict[str, int | str]] = []
    sec_off = opt_off + opt_size
    for i in range(num_sections):
        off = sec_off + i * 40
        name = image[off:off + 8].split(b"\x00", 1)[0].decode("ascii", "replace")
        virtual_size = struct.unpack_from("<I", image, off + 8)[0]
        virtual_address = struct.unpack_from("<I", image, off + 12)[0]
        raw_size = struct.unpack_from("<I", image, off + 16)[0]
        raw_ptr = struct.unpack_from("<I", image, off + 20)[0]
        characteristics = struct.unpack_from("<I", image, off + 36)[0]
        sections.append(
            {
                "name": name,
                "virtual_size": virtual_size,
                "virtual_address": virtual_address,
                "raw_size": raw_size,
                "raw_ptr": raw_ptr,
                "characteristics": characteristics,
            }
        )

    return image_base, sections


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


def page1_header_candidate(encoded_db: bytes, key: bytes) -> bytes:
    if len(encoded_db) < 0x18:
        return b""
    first_16 = rc4_defender_crypt(encoded_db[:0x10], key)
    return first_16


def looks_like_rc4_key_candidate(key: bytes) -> bool:
    if len(key) != 0x100:
        return False
    # A wrong candidate is usually zero padding, text, or pointer-ish data.
    if key.count(0) > 64:
        return False
    if len(set(key)) < 64:
        return False
    return True


def find_key_by_codec_reference(
    image: bytes, image_base: int, sections: list[dict[str, int | str]], encoded_db: bytes
) -> list[tuple[bytes, int, str, str]]:
    """Find the key by locating the codec wrapper's RIP-relative key reference.

    Observed wrapper around FUN_18092aa94:
      41 b8 00 01 00 00       mov r8d, 100h
      48 8d 15 xx xx xx xx    lea rdx, [rip + key]
      48 8d 4c 24 xx          lea rcx, [rsp + state]
      e8 xx xx xx xx          call rc4_init

    This is more version-resilient than a hard-coded VA and avoids treating the
    key as a public PE symbol, which it is not in stripped Defender binaries.
    """
    matches: list[tuple[bytes, int, str, str]] = []
    seen_vas: set[int] = set()

    for sec in sections:
        characteristics = int(sec["characteristics"])
        is_code_or_exec = (characteristics & 0x20) != 0 or (characteristics & 0x20000000) != 0
        if not is_code_or_exec:
            continue

        name = str(sec["name"])
        raw_ptr = int(sec["raw_ptr"])
        raw_size = int(sec["raw_size"])
        data = image[raw_ptr:raw_ptr + raw_size]

        for off in range(0, max(0, len(data) - 24)):
            if data[off:off + 6] != b"\x41\xb8\x00\x01\x00\x00":
                continue
            if data[off + 6:off + 9] != b"\x48\x8d\x15":
                continue
            if data[off + 13:off + 17] != b"\x48\x8d\x4c\x24":
                continue
            if data[off + 18] != 0xE8:
                continue

            lea_raw = raw_ptr + off + 6
            lea_va = raw_offset_to_va(sections, image_base, lea_raw)
            disp = struct.unpack_from("<i", data, off + 9)[0]
            key_va = lea_va + 7 + disp
            if key_va in seen_vas:
                continue
            seen_vas.add(key_va)

            try:
                key_off = pe_rva_to_offset_from_sections(sections, key_va - image_base)
            except ValueError:
                continue

            key = image[key_off:key_off + 0x100]
            if not looks_like_rc4_key_candidate(key):
                continue
            if page1_header_candidate(encoded_db, key) == SQLITE_HEADER:
                matches.append((key, key_va, name, "code-ref"))

    return matches


def find_key_candidates_in_image(image_path: Path, encoded_db: bytes) -> list[tuple[bytes, int, str, str]]:
    image = read_exact(image_path)
    image_base, sections = parse_pe_sections(image)

    matches = find_key_by_codec_reference(image, image_base, sections, encoded_db)
    if matches:
        return matches

    matches: list[tuple[bytes, int, str, str]] = []

    for sec in sections:
        name = str(sec["name"])
        raw_ptr = int(sec["raw_ptr"])
        raw_size = int(sec["raw_size"])
        va = image_base + int(sec["virtual_address"])
        data = image[raw_ptr:raw_ptr + raw_size]

        if raw_size < 0x100:
            continue

        # Prefer readonly data sections, but do not rely on section names.
        for off in range(0, raw_size - 0x100 + 1):
            key = data[off:off + 0x100]
            if not looks_like_rc4_key_candidate(key):
                continue
            if page1_header_candidate(encoded_db, key) == SQLITE_HEADER:
                matches.append((key, va + off, name, "data-scan"))

    if not matches:
        raise ValueError(
            "could not auto-discover codec key in image; use --key-va, --key-file, or --key-hex"
        )
    return matches


def find_key_in_image(
    image_path: Path, encoded_db: bytes, page_size: int, page1_skip_header_gap: bool
) -> tuple[bytes, int, str, str]:
    matches = find_key_candidates_in_image(image_path, encoded_db)
    if len(matches) == 1:
        return matches[0]

    readable: list[tuple[bytes, int, str, str, str, int]] = []
    failures: list[tuple[int, str, str, str]] = []
    for key, key_va, section_name, method in matches:
        decoded = decode_db(encoded_db, key, page_size, page1_skip_header_gap)
        ok, reason, schema_count = sqlite_can_read(decoded)
        if ok:
            readable.append((key, key_va, section_name, method, reason, schema_count))
        else:
            failures.append((key_va, section_name, method, reason))

    if readable:
        readable.sort(key=lambda item: item[5], reverse=True)
        key, key_va, section_name, method, _, schema_count = readable[0]
        if len(readable) > 1:
            method = f"{method},best-of-{len(readable)}-readable,schema={schema_count}"
        return key, key_va, section_name, method

    details = "; ".join(
        f"0x{key_va:x}({section},{method}): {reason}" for key_va, section, method, reason in failures[:8]
    )
    raise ValueError(f"tried {len(matches)} candidate keys; none produced readable SQLite: {details}")


def parse_key(args: argparse.Namespace, encoded: bytes, page_size: int) -> bytes:
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
        if args.auto_key:
            key, key_va, section_name, method = find_key_in_image(
                Path(args.image), encoded, page_size, not args.no_page1_gap
            )
            args.discovered_key_va = key_va
            args.discovered_key_section = section_name
            args.discovered_key_method = method
            return key
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
    parser.add_argument("--image-base", type=parse_int, default=DEFAULT_IMAGE_BASE, help="PE image base")
    parser.add_argument(
        "--key-va",
        type=parse_int,
        default=DEFAULT_KEY_VA,
        help="VA of the 256-byte key table when not using --auto-key",
    )
    parser.add_argument(
        "--auto-key",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="with --image, find the codec key by code reference, then fallback scan",
    )
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
    page_size = args.page_size or detect_page_size(encoded)
    key = parse_key(args, encoded, page_size)
    decoded = decode_db(encoded, key, page_size, not args.no_page1_gap)

    output_path.write_bytes(decoded)

    if not args.quiet:
        print(f"input:      {input_path}")
        print(f"output:     {output_path}")
        print(f"size:       {len(encoded)} bytes")
        print(f"page size:  {page_size}")
        print(f"pages:      {len(encoded) // page_size}")
        print(f"key preview: {key[:16].hex()}...")
        if getattr(args, "discovered_key_va", None) is not None:
            print(
                f"key found:   VA 0x{args.discovered_key_va:x} "
                f"in {args.discovered_key_section} via {args.discovered_key_method}"
            )
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