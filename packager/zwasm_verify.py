#!/usr/bin/env python3
"""Validate a ZWASM v0.1 package."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import struct

MAGIC = b"ZWASMG01"
HEADER = struct.Struct("<8sIIQQQI20s")
HEADER_SIZE = 64


class VerifyError(RuntimeError):
    pass


def main() -> int:
    p = argparse.ArgumentParser(description="Verify a ZWASM .zgame")
    p.add_argument("package", type=Path)
    p.add_argument("--hash", action="store_true", help="rehash every entry")
    args = p.parse_args()

    data = args.package.read_bytes()
    if len(data) < HEADER_SIZE:
        raise VerifyError("file is smaller than the ZWASM header")

    magic, version, flags, index_offset, index_size, payload_offset, count, _ = (
        HEADER.unpack_from(data, 0)
    )
    if magic != MAGIC:
        raise VerifyError("bad magic: " + repr(magic))
    if version != 1:
        raise VerifyError("unsupported package version: " + str(version))
    if index_offset != HEADER_SIZE:
        raise VerifyError("unexpected index offset: " + str(index_offset))
    if index_offset + index_size > len(data):
        raise VerifyError("index extends beyond end of file")
    if payload_offset < index_offset + index_size or payload_offset > len(data):
        raise VerifyError("invalid payload offset")

    manifest = json.loads(data[index_offset:index_offset + index_size])
    entries = manifest.get("entries")
    if not isinstance(entries, list):
        raise VerifyError("manifest.entries is not a list")
    if len(entries) != count:
        raise VerifyError(
            "header count " + str(count) + " != manifest count " + str(len(entries))
        )

    last_end = payload_offset
    seen: set[str] = set()
    for entry in entries:
        path = str(entry["path"])
        if path in seen:
            raise VerifyError("duplicate entry: " + path)
        seen.add(path)

        offset = int(entry["offset"])
        stored_size = int(entry["storedSize"])
        size = int(entry["size"])
        compression = entry["compression"]

        if offset < payload_offset or offset + stored_size > len(data):
            raise VerifyError("entry outside payload: " + path)
        if offset < last_end:
            raise VerifyError("overlapping entry: " + path)
        last_end = offset + stored_size

        blob = data[offset:offset + stored_size]
        if compression == "gzip":
            raw = gzip.decompress(blob)
        elif compression == "none":
            raw = blob
        else:
            raise VerifyError(
                "unsupported compression " + repr(compression) + " for " + path
            )

        if len(raw) != size:
            raise VerifyError("size mismatch: " + path)
        if args.hash:
            got = hashlib.sha256(raw).hexdigest()
            if got != entry["sha256"]:
                raise VerifyError("sha256 mismatch: " + path)

    print("[PASS] ZWASM v" + str(version) + " package verified")
    print("[PASS] entries=" + str(count) + " bytes=" + str(len(data)))
    print("[INFO] name=" + repr(manifest.get("name")))
    print("[INFO] boot=" + repr(manifest.get("boot")))
    print("[INFO] image=" + repr(manifest.get("image")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (VerifyError, OSError, ValueError, json.JSONDecodeError) as exc:
        print("[ZWASM] ERROR: " + str(exc))
        raise SystemExit(2)
