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
    p.add_argument("--boot", type=Path, help="browser/runtime WASM module; auto-detects runtime.wasm when present")
    p.add_argument("--runtime", type=Path, help="alias for --boot; intended for an XWASM x86 runtime.wasm")
    p.add_argument("--image", type=Path)
    p.add_argument("--guest", type=Path, help="raw PE/guest executable to embed as zwasm_guest/guest.pe")
    p.add_argument("--trail", type=Path)
    p.add_argument("--include-native", action="store_true")
    p.add_argument("--gzip", choices=("auto", "always", "never"), default="auto")
    args = p.parse_args()

    root = args.input.resolve()
    if not root.is_dir():
        raise RuntimeError("input is not a directory: " + str(root))

    generated = root / ".zwasm"
    generated.mkdir(exist_ok=True)

    explicit_boot = args.runtime or args.boot
    if args.runtime and args.boot:
        raise RuntimeError("use only one of --boot or --runtime")
    if explicit_boot:
        boot = explicit_boot.resolve()
    else:
        runtime_candidates = (
            root / "runtime.wasm",
            root / ".zwasm" / "runtime.wasm",
            ROOT / "runtime.wasm",
        )
        boot = next((p for p in runtime_candidates if p.is_file()), generated / "boot.wasm")
        if boot == generated / "boot.wasm":
            build_boot(find_clang(args.clang), boot)
            print("[ZWASM] generated adapter boot.wasm; pass --runtime for an x86 runtime")
        else:
            print("[ZWASM] using executable runtime: " + str(boot))

    image = args.image.resolve() if args.image else None
    if image is None:
        for candidate in (root / "isaac.segs.bin", root / "image.bin"):
            if candidate.is_file():
                image = candidate
                break

    guest = args.guest.resolve() if args.guest else None
    if guest is None:
        exe_candidates = sorted(root.glob("*.exe"))
        preferred = [p for p in exe_candidates if p.name.lower() in ("isaac.exe", "isaacng.exe", "game.exe")]
        guest = preferred[0] if preferred else (exe_candidates[0] if len(exe_candidates) == 1 else None)
    if guest is not None:
        guest_dir = root / "zwasm_guest"
        guest_dir.mkdir(exist_ok=True)
        guest_copy = guest_dir / "guest.pe"
        if guest.resolve() != guest_copy.resolve():
            shutil.copy2(guest, guest_copy)
        print("[ZWASM] embedded guest PE: " + str(guest_copy))
    else:
        print("[ZWASM] WARNING: no PE guest found; runtime cannot launch an x86 executable.")

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
