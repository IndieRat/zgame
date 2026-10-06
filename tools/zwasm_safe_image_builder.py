#!/usr/bin/env python3
"""Safely prepare a PE32 image for ZWASM.

This tool only maps PE image sections into a flat RVA-based memory image.
It never executes code, resolves imports, or silently applies relocations.
The resulting JSON manifest records the exact load contract for the runtime.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

DOS_MAGIC = 0x5A4D
PE_MAGIC = 0x00004550
PE32_MAGIC = 0x010B
IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_RELOCS_STRIPPED = 0x0001
MAX_SECTIONS = 96
SECTION_HEADER_SIZE = 40
OPTIONAL_HEADER_MIN = 96
IMAGE_DIRECTORY_ENTRY_BASERELOC = 5

# PE32 optional-header offsets relative to the optional header.
OH_ENTRY = 16
OH_IMAGE_BASE = 28
OH_SECTION_ALIGNMENT = 32
OH_FILE_ALIGNMENT = 36
OH_SIZE_OF_IMAGE = 56
OH_SIZE_OF_HEADERS = 60
OH_NUMBER_OF_RVA_AND_SIZES = 92
OH_DATA_DIRECTORIES = 96


class ImageError(RuntimeError):
    pass


def u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def align(value: int, boundary: int) -> int:
    return (value + boundary - 1) // boundary * boundary


def checked_range(size: int, off: int, length: int, label: str) -> None:
    if off < 0 or length < 0 or off > size or length > size - off:
        raise ImageError(f"{label} is outside the input file")


def parse_pe(data: bytes) -> dict:
    if len(data) < 64 or u16(data, 0) != DOS_MAGIC:
        raise ImageError("not an MZ executable")
    pe_off = u32(data, 0x3C)
    checked_range(len(data), pe_off, 24, "PE header")
    if u32(data, pe_off) != PE_MAGIC:
        raise ImageError("invalid PE signature")

    file_header = pe_off + 4
    machine = u16(data, file_header)
    sections_count = u16(data, file_header + 2)
    optional_size = u16(data, file_header + 16)
    characteristics = u16(data, file_header + 18)

    if machine != IMAGE_FILE_MACHINE_I386:
        raise ImageError(f"expected PE32/i386, got machine 0x{machine:04x}")
    if not 1 <= sections_count <= MAX_SECTIONS:
        raise ImageError(f"invalid section count: {sections_count}")
    if optional_size < OPTIONAL_HEADER_MIN:
        raise ImageError("optional header is too small")

    optional = file_header + 20
    checked_range(len(data), optional, optional_size, "optional header")
    if u16(data, optional) != PE32_MAGIC:
        raise ImageError("expected PE32 optional header (0x10b)")

    image_base = u32(data, optional + OH_IMAGE_BASE)
    section_alignment = u32(data, optional + OH_SECTION_ALIGNMENT)
    file_alignment = u32(data, optional + OH_FILE_ALIGNMENT)
    entry_rva = u32(data, optional + OH_ENTRY)
    size_of_image = u32(data, optional + OH_SIZE_OF_IMAGE)
    size_of_headers = u32(data, optional + OH_SIZE_OF_HEADERS)
    directory_count = u32(data, optional + OH_NUMBER_OF_RVA_AND_SIZES)

    if image_base == 0 or size_of_image == 0:
        raise ImageError("invalid image base or image size")
    if section_alignment == 0 or file_alignment == 0:
        raise ImageError("invalid PE alignment")
    if size_of_image % section_alignment:
        raise ImageError("SizeOfImage is not SectionAlignment-aligned")
    if size_of_headers > len(data) or size_of_headers > size_of_image:
        raise ImageError("invalid SizeOfHeaders")
    if entry_rva >= size_of_image:
        raise ImageError("entry point RVA is outside SizeOfImage")

    section_table = optional + optional_size
    table_size = sections_count * SECTION_HEADER_SIZE
    checked_range(len(data), section_table, table_size, "section table")

    sections = []
    image = bytearray(size_of_image)
    image[:size_of_headers] = data[:size_of_headers]

    for index in range(sections_count):
        off = section_table + index * SECTION_HEADER_SIZE
        name = data[off:off + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        virtual_size = u32(data, off + 8)
        virtual_address = u32(data, off + 12)
        raw_size = u32(data, off + 16)
        raw_offset = u32(data, off + 20)
        characteristics_value = u32(data, off + 36)

        mapped_size = max(virtual_size, raw_size)
        if virtual_address > size_of_image or mapped_size > size_of_image - virtual_address:
            raise ImageError(f"section {name!r} exceeds SizeOfImage")
        if raw_size:
            checked_range(len(data), raw_offset, raw_size, f"section {name} raw data")
            image[virtual_address:virtual_address + raw_size] = data[
                raw_offset:raw_offset + raw_size
            ]

        sections.append({
            "name": name,
            "rva": virtual_address,
            "virtualSize": virtual_size,
            "rawSize": raw_size,
            "rawOffset": raw_offset,
            "characteristics": characteristics_value,
        })

    reloc_rva = reloc_size = 0
    if directory_count > IMAGE_DIRECTORY_ENTRY_BASERELOC:
        directory_off = optional + OH_DATA_DIRECTORIES + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8
        if directory_off + 8 <= optional + optional_size:
            reloc_rva = u32(data, directory_off)
            reloc_size = u32(data, directory_off + 4)
            if reloc_rva and reloc_size:
                if reloc_rva >= size_of_image or reloc_size > size_of_image - reloc_rva:
                    raise ImageError("base relocation directory is outside the image")

    relocs_stripped = bool(characteristics & IMAGE_FILE_RELOCS_STRIPPED)
    relocation_policy = "stripped" if relocs_stripped else ("present" if reloc_size else "absent")

    manifest = {
        "schema": "zwasm.safe-image/1",
        "formatVersion": 1,
        "source": {
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "fileName": "",
        },
        "machine": "i386",
        "imageBase": image_base,
        "imageSize": size_of_image,
        "entryRva": entry_rva,
        "entryVa": image_base + entry_rva,
        "sectionAlignment": section_alignment,
        "fileAlignment": file_alignment,
        "sizeOfHeaders": size_of_headers,
        "relocations": {
            "policy": relocation_policy,
            "rva": reloc_rva,
            "size": reloc_size,
            "applied": False,
        },
        "sections": sections,
    }
    return manifest, bytes(image)


def main() -> int:
    p = argparse.ArgumentParser(description="Safely map a PE32 image into a ZWASM flat image")
    p.add_argument("input", type=Path)
    p.add_argument("-o", "--output", type=Path, required=True)
    p.add_argument("--manifest", type=Path)
    args = p.parse_args()

    source = args.input.resolve()
    output = args.output.resolve()
    if not source.is_file():
        raise ImageError(f"input file does not exist: {source}")
    if output == source:
        raise ImageError("output cannot overwrite the PE input")

    data = source.read_bytes()
    manifest, image = parse_pe(data)
    manifest["source"]["fileName"] = source.name

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(image)

    manifest_path = (args.manifest or output.with_suffix(".json")).resolve()
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print(f"[ZWASM] prepared image: {output}")
    print(f"[ZWASM] image base:      0x{manifest['imageBase']:08x}")
    print(f"[ZWASM] image size:      {manifest['imageSize']}")
    print(f"[ZWASM] entry RVA:       0x{manifest['entryRva']:08x}")
    print(f"[ZWASM] sections:        {len(manifest['sections'])}")
    print(f"[ZWASM] relocations:     {manifest['relocations']['policy']} (not applied)")
    print(f"[ZWASM] manifest:        {manifest_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ImageError, struct.error) as exc:
        print("[ZWASM] ERROR: " + str(exc))
        raise SystemExit(2)
