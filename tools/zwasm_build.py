#!/usr/bin/env python3
"""Build a self-contained ZWASM .zgame with a vendored x86 runtime."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BOOT_SOURCE = ROOT / "runtime" / "boot.c"
BRIDGE_SOURCE = ROOT / "runtime" / "bridge.c"
X86_RUNTIME_SOURCE = ROOT / "runtime" / "x86" / "runtime.c"
PACKER = ROOT / "packager" / "zwasm_pack.py"
SAFE_IMAGE_BUILDER = ROOT / "tools" / "zwasm_safe_image_builder.py"


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


def build_x86_runtime(clang: str, output: Path) -> None:
    """Compile the vendored XWASM CPU/runtime; no external XWASM checkout required."""
    output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([
        clang, "--target=wasm32", "-O2", "-nostdlib",
        "-Wl,--no-entry", "-Wl,--export-memory",
        "-Wl,--export-table", "-Wl,--allow-undefined",
        "-o", str(output), str(X86_RUNTIME_SOURCE),
    ], check=True)


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
    p.add_argument("--boot", type=Path, help="explicit browser/runtime WASM module")
    p.add_argument("--runtime", type=Path, help="explicit external XWASM runtime.wasm (optional)")
    p.add_argument("--image", type=Path)
    p.add_argument("--guest", type=Path, help="raw PE/guest executable to embed")
    p.add_argument("--trail", type=Path)
    p.add_argument("--xapi", type=Path, action="append", default=[], help="xapi manifest (.xapi.json) to embed (repeatable)")
    p.add_argument("--no-dlls", action="store_true", help="do not bundle top-level *.dll files next to the game")
    p.add_argument("--include-native", action="store_true")
    p.add_argument("--gzip", choices=("auto", "always", "never"), default="auto")
    args = p.parse_args()

    root = args.input.resolve()
    if not root.is_dir():
        raise RuntimeError("input is not a directory: " + str(root))

    generated = root / ".zwasm"
    generated.mkdir(exist_ok=True)
    clang = find_clang(args.clang)

    explicit_boot = args.runtime or args.boot
    if args.runtime and args.boot:
        raise RuntimeError("use only one of --boot or --runtime")

    if explicit_boot:
        boot = explicit_boot.resolve()
        print("[ZWASM] using explicit runtime: " + str(boot))
    else:
        # The vendored CPU runtime is the default. This makes ZWASM portable:
        # users only need this repository plus clang, not x86-to-wasm-packager.
        boot = generated / "runtime.wasm"
        build_x86_runtime(clang, boot)
        print("[ZWASM] built vendored x86 runtime: " + str(boot))

    image = args.image.resolve() if args.image else None
    if image is None:
        for candidate in (root / "isaac.segs.bin", root / "image.bin"):
            if candidate.is_file():
                image = candidate
                break

    guest = args.guest.resolve() if args.guest else None
    if guest is None:
        exe_candidates = sorted(root.glob("*.exe"))
        preferred = [p for p in exe_candidates if p.name.lower() in ("isaac-ng.exe", "isaac.exe", "isaacng.exe", "game.exe")]
        guest = preferred[0] if preferred else (exe_candidates[0] if len(exe_candidates) == 1 else None)

    if guest is not None:
        print("[ZWASM] guest PE: " + str(guest))
    else:
        print("[ZWASM] WARNING: no PE guest found (pass --guest); runtime cannot launch an x86 executable.")

    dlls = [] if args.no_dlls else sorted(root.glob("*.dll"), key=lambda p: p.name.lower())
    if dlls:
        print("[ZWASM] bundled guest DLLs: " + ", ".join(p.name for p in dlls))

    if image is None and guest is not None and SAFE_IMAGE_BUILDER.is_file():
        generated_image = generated / "image.bin"
        subprocess.run([
            sys.executable, str(SAFE_IMAGE_BUILDER),
            str(guest), "-o", str(generated_image),
        ], check=True)
        image = generated_image
        print("[ZWASM] generated safe guest image: " + str(image))

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
    if guest is not None:
        cmd += ["--guest", str(guest)]
    for dll in dlls:
        cmd += ["--guest-dll", str(dll)]
    for xapi in args.xapi:
        cmd += ["--xapi", str(xapi.resolve())]
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
