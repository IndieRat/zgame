from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def test_bridge_source_declares_host_dispatch():
    header = (ROOT / "runtime" / "bridge.h").read_text(encoding="utf-8")
    source = (ROOT / "runtime" / "bridge.c").read_text(encoding="utf-8")
    assert "Z_API_K32_GET_TICK_COUNT" in header
    assert "Z_API_U32_GET_ASYNC_KEY_STATE" in header
    assert "Z_API_GL_DRAW_ARRAYS" in header
    assert "z_host_api" in source
    assert "zwasm_bridge_call" in source


def test_bridge_compiles_with_boot_when_clang_exists(tmp_path):
    clang = shutil.which("clang")
    if not clang:
        return
    output = tmp_path / "bridge.wasm"
    subprocess.run([
        clang, "--target=wasm32", "-O2", "-nostdlib",
        "-Wl,--no-entry", "-Wl,--export-memory",
        "-Wl,--export-table", "-Wl,--allow-undefined",
        "-Wl,--export=zwasm_init",
        "-Wl,--export=zwasm_frame",
        "-Wl,--export=zwasm_input",
        "-Wl,--export=zwasm_status",
        "-Wl,--export=zwasm_image_size",
        "-Wl,--export=zwasm_frame_count",
        "-Wl,--export=zwasm_last_input",
        "-Wl,--export=zwasm_bridge_call",
        "-Wl,--export=zwasm_bridge_last_api",
        "-Wl,--export=zwasm_bridge_last_result",
        "-Wl,--export=zwasm_bridge_call_count",
        "-Wl,--export=zwasm_bridge_unsupported_count",
        "-o", str(output),
        str(ROOT / "runtime" / "boot.c"),
        str(ROOT / "runtime" / "bridge.c"),
    ], check=True)
    assert output.is_file() and output.stat().st_size > 0
