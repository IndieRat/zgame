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
DLL_CONVERTER = ROOT / "tools" / "zwasm_dll_convert.py"


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
    output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            clang,
            "--target=wasm32",
            "-O2",
            "-nostdlib",
            "-Wl,--no-entry",
            "-Wl,--export-memory",
            "-Wl,--export-table",
            "-Wl,--allow-undefined",
            "-o",
            str(output),
            str(X86_RUNTIME_SOURCE),
        ],
        check=True,
    )


def build_boot(clang: str, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            clang,
            "--target=wasm32",
            "-O2",
            "-nostdlib",
            "-Wl,--no-entry",
            "-Wl,--export-memory",
            "-Wl,--export-table",
            "-Wl,--allow-undefined",
            "-o",
            str(output),
            str(BOOT_SOURCE),
            str(BRIDGE_SOURCE),
        ],
        check=True,
    )


def main() -> int:
    p = argparse.ArgumentParser(description="Build a ZWASM .zgame")

    p.add_argument("input", type=Path)
    p.add_argument("-o", "--output", type=Path)

    p.add_argument("--clang")
    p.add_argument("--boot", type=Path, help="explicit browser/runtime WASM module")
    p.add_argument("--runtime", type=Path, help="explicit external runtime.wasm")

    p.add_argument(
        "--guest-dll",
        action="append",
        default=[],
        type=Path,
        help="bundled guest DLL (repeatable)",
    )

    p.add_argument(
        "--zapi",
        action="append",
        default=[],
        type=Path,
        help="ZWASM API manifest (repeatable)",
    )

    p.add_argument(
        "--xapi",
        action="append",
        default=[],
        type=Path,
        help="legacy .xapi compatibility alias",
    )

    p.add_argument(
        "--zdll",
        action="append",
        default=[],
        type=Path,
        help="ZWASM WASM DLL container (repeatable)",
    )

    p.add_argument("--image", type=Path)
    p.add_argument("--guest", type=Path, help="raw PE/guest executable to embed")
    p.add_argument("--trail", type=Path)

    p.add_argument("--no-dlls", action="store_true")
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
        print("[ZWASM] using explicit runtime:", boot)
    else:
        boot = generated / "runtime.wasm"
        build_x86_runtime(clang, boot)
        print("[ZWASM] built vendored x86 runtime:", boot)

    image = args.image.resolve() if args.image else None

    if image is None:
        for candidate in (root / "isaac.segs.bin", root / "image.bin"):
            if candidate.is_file():
                image = candidate
                break

    guest = args.guest.resolve() if args.guest else None

    if guest is None:
        exe_candidates = sorted(root.glob("*.exe"))
        preferred = [
            p
            for p in exe_candidates
            if p.name.lower()
            in ("isaac-ng.exe", "isaac.exe", "isaacng.exe", "game.exe")
        ]

        guest = (
            preferred[0]
            if preferred
            else (exe_candidates[0] if len(exe_candidates) == 1 else None)
        )

    if guest is not None:
        print("[ZWASM] guest PE:", guest)
    else:
        print("[ZWASM] WARNING: no PE guest found")

    dlls = [] if args.no_dlls else sorted(
        root.glob("*.dll"), key=lambda p: p.name.lower()
    )
    
    generated_zdlls = []

    for dll in dlls:
        zdll = generated / (dll.stem + ".zdll")

        subprocess.run([
            sys.executable,
            str(DLL_CONVERTER),
            str(dll),
            "-o",
            str(zdll),
        ], check=True)

        generated_zdlls.append(zdll)

    if image is None and guest is not None and SAFE_IMAGE_BUILDER.is_file():
        generated_image = generated / "image.bin"

        subprocess.run(
            [
                sys.executable,
                str(SAFE_IMAGE_BUILDER),
                str(guest),
                "-o",
                str(generated_image),
            ],
            check=True,
        )

        image = generated_image

    output = args.output.resolve() if args.output else (
        ROOT / "dist" / (root.name.replace(" ", ".") + ".zgame")
    )

    cmd = [
        sys.executable,
        str(PACKER),
        str(root),
        "--output",
        str(output),
        "--boot",
        str(boot),
        "--gzip",
        args.gzip,
    ]

    if image:
        cmd += ["--image", str(image)]

    if guest:
        cmd += ["--guest", str(guest)]

    for zdll in generated_zdlls:
        cmd += ["--zdll", str(zdll)]

    for api in [*args.zapi, *args.xapi]:
        cmd += ["--zapi", str(api.resolve())]

    for zdll in args.zdll:
        cmd += ["--zdll", str(zdll.resolve())]

    if args.trail:
        cmd += ["--trail", str(args.trail.resolve())]

    if args.include_native:
        cmd.append("--include-native")

    subprocess.run(cmd, check=True)

    print("[ZWASM] READY:", output)
    print("[ZWASM] SHELL:", ROOT / "web" / "index.html")

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print("[ZWASM] ERROR:", exc)
        raise SystemExit(2)
