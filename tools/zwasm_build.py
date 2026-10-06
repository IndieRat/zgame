#!/usr/bin/env python3
"""Build boot.wasm with clang, then package a directory as .zgame."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BOOT_SOURCE = ROOT / "runtime" / "boot.c"
BRIDGE_SOURCE = ROOT / "runtime" / "bridge.c"
PACKER = ROOT / "packager" / "zwasm_pack.py"


def find_clang(explicit: str | None) -> str:
    if explicit:
        return explicit
    found = shutil.which("clang")
    if found:
        return found
    for candidate in (
        Path(r"C:\Program Files\LLVM\bin\clang.exe"),
        Path(r"C:\Program Files\LLVM\bin\clang-cl.exe"),
    ):
        if candidate.is_file():
            return str(candidate)
    raise RuntimeError("clang was not found; pass --clang or install LLVM.")


def build_boot(clang: str, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([
        clang, "--target=wasm32", "-O2", "-nostdlib",
        "-Wl,--no-entry", "-Wl,--export-memory",
        "-Wl,--export-table", "-Wl,--allow-undefined",
        "-o", str(output), str(BOOT_SOURCE), str(BRIDGE_SOURCE),
    ], check=True)


def main() -> int:
    p = argparse.ArgumentParser(description="Build a ZWASM .zgame")
    p.add_argument("input", type=Path)
    p.add_argument("-o", "--output", type=Path)
    p.add_argument("--clang")
    p.add_argument("--boot", type=Path)
    p.add_argument("--image", type=Path)
    p.add_argument("--trail", type=Path)
    p.add_argument("--include-native", action="store_true")
    p.add_argument("--gzip", choices=("auto", "always", "never"), default="auto")
    args = p.parse_args()

    root = args.input.resolve()
    if not root.is_dir():
        raise RuntimeError("input is not a directory: " + str(root))

    generated = root / ".zwasm"
    generated.mkdir(exist_ok=True)

    boot = args.boot.resolve() if args.boot else generated / "boot.wasm"
    if not args.boot:
        build_boot(find_clang(args.clang), boot)

    image = args.image.resolve() if args.image else None
    if image is None:
        for candidate in (root / "isaac.segs.bin", root / "image.bin"):
            if candidate.is_file():
                image = candidate
                break

    if image is None:
        print("[ZWASM] WARNING: no prepared image; package is boot/resource-only.")

    output = args.output.resolve() if args.output else (
        ROOT / "dist" / (root.name.replace(" ", ".") + ".zgame")
    )

    cmd = [
        sys.executable, str(PACKER), str(root),
        "--output", str(output), "--boot", str(boot),
        "--gzip", args.gzip,
    ]
    if image:
        cmd += ["--image", str(image)]
    if args.trail:
        cmd += ["--trail", str(args.trail.resolve())]
    if args.include_native:
        cmd.append("--include-native")

    subprocess.run(cmd, check=True)
    print("[ZWASM] READY: " + str(output))
    print("[ZWASM] SHELL: " + str(ROOT / "web" / "index.html"))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print("[ZWASM] ERROR: " + str(exc))
        raise SystemExit(2)
