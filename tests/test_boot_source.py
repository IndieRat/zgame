from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def test_boot_source_exists():
    source = ROOT / "runtime" / "boot.c"
    text = source.read_text(encoding="utf-8")
    assert "zwasm_init" in text
    assert "zwasm_frame" in text
    assert "zwasm_input" in text


def test_boot_compiles_when_clang_exists(tmp_path):
    clang = shutil.which("clang")
    if not clang:
        return
    output = tmp_path / "boot.wasm"
    subprocess.run([
        clang, "--target=wasm32", "-O2", "-nostdlib",
        "-Wl,--no-entry", "-Wl,--export-memory",
        "-Wl,--export-table", "-Wl,--allow-undefined",
        "-o", str(output), str(ROOT / "runtime" / "boot.c"),
    ], check=True)
    assert output.is_file() and output.stat().st_size > 0
