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


def test_vendored_x86_runtime_exists():
    source = ROOT / "runtime" / "x86" / "runtime.c"
    text = source.read_text(encoding="utf-8")
    assert "XWASM X86 Runtime" in text
    assert 'export_name("x86_load_pe")' in text
    assert 'export_name("x86_run")' in text


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


def test_vendored_x86_runtime_compiles_when_clang_exists(tmp_path):
    clang = shutil.which("clang")
    if not clang:
        return
    output = tmp_path / "runtime.wasm"
    subprocess.run([
        clang, "--target=wasm32", "-O2", "-nostdlib",
        "-Wl,--no-entry", "-Wl,--export-memory",
        "-Wl,--export-table", "-Wl,--allow-undefined",
        "-o", str(output), str(ROOT / "runtime" / "x86" / "runtime.c"),
    ], check=True)
    assert output.is_file() and output.stat().st_size > 0


def test_builder_supports_self_contained_x86_runtime():
    source = (ROOT / "tools" / "zwasm_build.py").read_text(encoding="utf-8")
    assert '--runtime' in source
    assert '--guest' in source
    assert 'runtime/x86' in source or 'X86_RUNTIME_SOURCE' in source
    assert 'zwasm_guest' in source
    assert 'guest.pe' in source
    assert 'runtime.wasm' in source
