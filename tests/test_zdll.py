import hashlib
import json
import struct
from pathlib import Path

from packager.zwasm_zdll import HEADER, MAGIC, VERSION, build


def test_zdll_roundtrip(tmp_path):
    wasm = tmp_path / "test.wasm"
    out = tmp_path / "test.zdll"
    data = b"\0asm\x01\0\0\0"
    wasm.write_bytes(data)

    build(wasm, out, "test.dll", "zworld.v1")

    blob = out.read_bytes()
    magic, version, flags, offset, size, digest = HEADER.unpack_from(blob)
    assert magic == MAGIC
    assert version == VERSION
    assert offset + size == len(blob)
    assert blob[offset:offset + size] == data
    assert digest.hex() == hashlib.sha256(data).hexdigest()

    manifest_start = HEADER.size
    manifest = json.loads(blob[manifest_start:offset])
    assert manifest["schema"] == "zwasm.zdll/1"
    assert manifest["name"] == "test.dll"
    assert manifest["abi"] == "zworld.v1"
