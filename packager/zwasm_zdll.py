#!/usr/bin/env python3
"""Build a ZWASM .zdll: a small, self-describing WASM DLL container."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

MAGIC = b"ZDLLG01\0"
VERSION = 1
HEADER = struct.Struct("<8sIIQQ32s")


def build(wasm: Path, output: Path, name: str, abi: str) -> None:
    wasm_bytes = wasm.read_bytes()
    if wasm_bytes[:4] != b"\0asm":
        raise ValueError("input is not a WebAssembly module")

    digest = hashlib.sha256(wasm_bytes).digest()
    manifest = {
        "schema": "zwasm.zdll/1",
        "formatVersion": VERSION,
        "name": name,
        "abi": abi,
        "module": "module.wasm",
        "sha256": digest.hex(),
    }
    manifest_bytes = json.dumps(
        manifest, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")

    header_size = HEADER.size
    wasm_offset = header_size + len(manifest_bytes)
    header = HEADER.pack(
        MAGIC, VERSION, 0, wasm_offset, len(wasm_bytes), digest
    )

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(header + manifest_bytes + wasm_bytes)

    print("[ZWASM] wrote " + str(output))
    print("[ZWASM] name: " + name)
    print("[ZWASM] abi:  " + abi)
    print("[ZWASM] wasm: " + str(len(wasm_bytes)) + " bytes")


def main() -> int:
    p = argparse.ArgumentParser(description="Pack a WASM module into .zdll")
    p.add_argument("wasm", type=Path)
    p.add_argument("-o", "--output", type=Path, required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--abi", default="zworld.v1")
    args = p.parse_args()
    build(args.wasm.resolve(), args.output.resolve(), args.name, args.abi)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
