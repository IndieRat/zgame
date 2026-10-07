#!/usr/bin/env python3
"""Validate the stable ZWASM native API frame (.zapi)."""

from __future__ import annotations

import json
from pathlib import Path

SCHEMA = "zwasm.zapi/1"
VERSION = 1
ABI = "zworld.v1"
FRAME = "i32x5"


class ZapiError(ValueError):
    pass


def load(path: Path) -> dict:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ZapiError(f"invalid zapi JSON: {path}: {exc}") from exc

    if doc.get("schema") != SCHEMA:
        raise ZapiError("zapi schema must be " + SCHEMA)
    if doc.get("formatVersion") != VERSION:
        raise ZapiError("unsupported zapi format version")
    if doc.get("abi") != ABI:
        raise ZapiError("zapi abi must be " + ABI)
    if doc.get("frame") != FRAME:
        raise ZapiError("zapi frame must be " + FRAME)

    dll = doc.get("dll")
    if not isinstance(dll, str) or not dll:
        raise ZapiError("zapi dll must be a non-empty string")

    functions = doc.get("functions")
    if not isinstance(functions, list):
        raise ZapiError("zapi functions must be an array")

    ids = set()
    for fn in functions:
        if not isinstance(fn, dict):
            raise ZapiError("zapi function must be an object")
        ident = fn.get("id")
        name = fn.get("name")
        argc = fn.get("argc")
        if not isinstance(ident, int) or ident < 0:
            raise ZapiError("zapi function id must be a non-negative integer")
        if ident in ids:
            raise ZapiError(f"duplicate zapi function id: {ident}")
        ids.add(ident)
        if not isinstance(name, str) or not name:
            raise ZapiError("zapi function name must be non-empty")
        if not isinstance(argc, int) or not 0 <= argc <= 4:
            raise ZapiError("zapi function argc must be between 0 and 4")
        export = fn.get("export", "zdll_call")
        if not isinstance(export, str) or not export:
            raise ZapiError("zapi function export must be non-empty")

    return doc


def main() -> int:
    import argparse

    p = argparse.ArgumentParser(description="Validate a ZWASM .zapi manifest")
    p.add_argument("path", type=Path)
    args = p.parse_args()
    load(args.path)
    print("[ZWASM] zapi valid: " + str(args.path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
