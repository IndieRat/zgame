#!/usr/bin/env python3
"""Build a ZWASM .zgame package from a game directory."""

from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import struct
from typing import Iterable

MAGIC = b"ZWASMG01"
VERSION = 1
HEADER_SIZE = 64
PAGE_SIZE = 4096
HEADER = struct.Struct("<8sIIQQQI20s")

NATIVE_SUFFIXES = {
    ".exe", ".dll", ".sys", ".drv", ".ocx", ".pdb", ".lib", ".obj",
    ".exp", ".ilk", ".scr", ".cpl",
}
SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".vs", ".idea",
    "save", "saves", "savedata", "userdata", "logs", "log",
    "tmp", "temp", "cache", "crashdumps",
}


class PackageError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_rel(path: Path, root: Path) -> str:
    rel = path.relative_to(root).as_posix()
    pp = PurePosixPath(rel)
    if pp.is_absolute() or ".." in pp.parts:
        raise PackageError("unsafe package path: " + rel)
    return rel


def should_skip(rel: str, include_native: bool, excludes: list[str]) -> bool:
    parts = PurePosixPath(rel).parts
    if any(p.lower() in SKIP_DIRS for p in parts[:-1]):
        return True
    if not include_native and PurePosixPath(rel).suffix.lower() in NATIVE_SUFFIXES:
        return True
    return any(fnmatch.fnmatch(rel, pat) for pat in excludes)


def iter_instance_files(
    root: Path, include_native: bool, excludes: list[str]
) -> Iterable[tuple[str, Path]]:
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = safe_rel(path, root)
        if should_skip(rel, include_native, excludes):
            continue
        yield "instance/" + rel, path


def choose_compression(
    data: bytes, policy: str, threshold: int
) -> tuple[str, bytes]:
    if policy == "never":
        return "none", data
    if policy not in {"auto", "always"}:
        raise PackageError("unknown compression policy: " + policy)
    if policy == "auto" and len(data) > threshold:
        return "none", data
    out = gzip.compress(data, compresslevel=6, mtime=0)
    if policy == "auto" and len(out) >= len(data):
        return "none", data
    return "gzip", out


def default_output(input_dir: Path) -> Path:
    stem = input_dir.name.replace(" ", ".")
    for c in '<>:"/\\|?*':
        stem = stem.replace(c, "_")
    return Path("dist") / (stem + ".zgame")


def build(args: argparse.Namespace) -> Path:
    root = Path(args.input).resolve()
    if not root.is_dir():
        raise PackageError("input is not a directory: " + str(root))

    output = Path(args.output) if args.output else default_output(root)
    output.parent.mkdir(parents=True, exist_ok=True)

    candidates: list[tuple[str, Path, str]] = []
    for role, supplied, default_name in (
        ("boot", args.boot, "boot.wasm"),
        ("image", args.image, "image.bin"),
        ("trail", args.trail, "boot-trail.json"),
    ):
        if not supplied:
            continue
        p = Path(supplied).resolve()
        if not p.is_file():
            raise PackageError(role + " file does not exist: " + str(p))
        candidates.append((default_name, p, role))

    seen = {p for p, _, _ in candidates}
    for package_path, p in iter_instance_files(
        root, args.include_native, args.exclude
    ):
        if package_path in seen:
            continue
        candidates.append((package_path, p, "instance"))

    if not candidates:
        raise PackageError("no files selected for the package")

    entries: list[dict] = []
    payloads: list[tuple[dict, bytes]] = []

    for package_path, source_path, kind in candidates:
        data = source_path.read_bytes()
        compression, stored = choose_compression(
            data, args.gzip, args.gzip_threshold
        )
        entry = {
            "path": package_path,
            "kind": kind,
            "sourceName": source_path.name,
            "offset": 0,
            "size": len(data),
            "storedSize": len(stored),
            "compression": compression,
            "sha256": sha256_bytes(data),
            "mode": 0o644,
        }
        entries.append(entry)
        payloads.append((entry, stored))

    manifest = {
        "schema": "zwasm.package/1",
        "formatVersion": VERSION,
        "name": root.name,
        "createdUtc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "source": {"name": root.name, "fileCount": len(entries)},
        "boot": "boot.wasm" if args.boot else None,
        "image": "image.bin" if args.image else None,
        "trail": "boot-trail.json" if args.trail else None,
        "entries": entries,
    }

    index_blob = b""
    payload_offset = 0
    for _ in range(8):
        index_blob = json.dumps(
            manifest, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        payload_offset = (
            (HEADER_SIZE + len(index_blob) + PAGE_SIZE - 1) // PAGE_SIZE
        ) * PAGE_SIZE

        offset = payload_offset
        for entry, stored in payloads:
            entry["offset"] = offset
            offset += len(stored)

        new_blob = json.dumps(
            manifest, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        index_blob = new_blob
        if len(new_blob) == len(
            json.dumps(
                manifest, ensure_ascii=False, separators=(",", ":"), sort_keys=True
            ).encode("utf-8")
        ):
            break

    with output.open("wb") as f:
        f.write(
            HEADER.pack(
                MAGIC,
                VERSION,
                0,
                HEADER_SIZE,
                len(index_blob),
                payload_offset,
                len(entries),
                b"",
            )
        )
        f.write(index_blob)
        f.write(b"\0" * (payload_offset - f.tell()))
        for entry, stored in payloads:
            if f.tell() != entry["offset"]:
                raise PackageError(
                    "internal offset error for "
                    + entry["path"]
                    + ": "
                    + str(f.tell())
                    + " != "
                    + str(entry["offset"])
                )
            f.write(stored)

    print("[ZWASM] wrote " + str(output))
    print("[ZWASM] entries: " + str(len(entries)))
    print("[ZWASM] bytes:   " + str(output.stat().st_size))
    print("[ZWASM] boot:    " + (manifest["boot"] or "(none)"))
    print("[ZWASM] image:   " + (manifest["image"] or "(none)"))
    return output


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Pack a directory into a ZWASM .zgame"
    )
    p.add_argument("input", help="game/resource directory")
    p.add_argument("--output", "-o", help="output .zgame path")
    p.add_argument("--boot", help="browser-ready boot.wasm to embed")
    p.add_argument("--image", help="prepared memory image to embed")
    p.add_argument("--trail", help="boot trail JSON to embed")
    p.add_argument("--exclude", action="append", default=[], help="glob to exclude")
    p.add_argument(
        "--include-native",
        action="store_true",
        help="include native .exe/.dll/.pdb/etc. files",
    )
    p.add_argument(
        "--gzip", choices=("auto", "always", "never"), default="auto"
    )
    p.add_argument(
        "--gzip-threshold",
        type=int,
        default=16 * 1024 * 1024,
        help="auto mode only compresses files up to this size",
    )
    return p.parse_args()


def main() -> int:
    try:
        build(parse_args())
        return 0
    except PackageError as exc:
        print("[ZWASM] ERROR: " + str(exc))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
