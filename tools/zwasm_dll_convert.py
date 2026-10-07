#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

MAGIC = b"ZDLL"
VERSION = 1


def read_exports_pe(data: bytes):
    """
    Placeholder export extraction.

    Safe implementation:
    - no code execution
    - no relocation processing
    - containerizes raw DLL

    Later you can swap in pefile.
    """
    return []


def build_manifest(dll_path: Path) -> dict:
    dll_data = dll_path.read_bytes()

    return {
        "name": dll_path.name,
        "size": len(dll_data),
        "sha256": hashlib.sha256(dll_data).hexdigest(),
        "exports": read_exports_pe(dll_data),
    }


def convert_dll(src: Path, dst: Path):
    dll_data = src.read_bytes()

    manifest = build_manifest(src)
    manifest_blob = json.dumps(
        manifest,
        indent=2
    ).encode("utf-8")

    with open(dst, "wb") as f:
        f.write(MAGIC)
        f.write(struct.pack("<I", VERSION))
        f.write(struct.pack("<I", len(manifest_blob)))
        f.write(manifest_blob)
        f.write(dll_data)

    print(
        f"[ZDLL] {src.name} -> {dst.name}"
    )


def main():
    ap = argparse.ArgumentParser()

    ap.add_argument(
        "dll",
        type=Path,
    )

    ap.add_argument(
        "-o",
        "--output",
        type=Path,
    )

    args = ap.parse_args()

    output = (
        args.output
        or args.dll.with_suffix(".zdll")
    )

    convert_dll(
        args.dll.resolve(),
        output.resolve(),
    )


if __name__ == "__main__":
    main()