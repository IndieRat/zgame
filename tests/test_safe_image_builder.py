from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "zwasm_safe_image_builder.py"


def make_pe32(path: Path) -> bytes:
    data = bytearray(0x600)
    struct.pack_into("<H", data, 0, 0x5A4D)
    struct.pack_into("<I", data, 0x3C, 0x80)
    struct.pack_into("<I", data, 0x80, 0x4550)
    fh = 0x84
    struct.pack_into("<HHIIIHH", data, fh, 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)
    oh = fh + 20
    struct.pack_into("<H", data, oh, 0x10B)
    struct.pack_into("<I", data, oh + 16, 0x1000)
    struct.pack_into("<I", data, oh + 28, 0x400000)
    struct.pack_into("<I", data, oh + 32, 0x1000)
    struct.pack_into("<I", data, oh + 36, 0x200)
    struct.pack_into("<I", data, oh + 56, 0x3000)
    struct.pack_into("<I", data, oh + 60, 0x200)
    struct.pack_into("<I", data, oh + 92, 16)
    sh = oh + 0xE0
    data[sh:sh + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, sh + 8, 0x10, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", data, sh + 36, 0x60000020)
    data[0x200:0x210] = b"ZWASM-TEST-IMAGE"
    return bytes(data)


def test_builder_maps_sections_and_writes_manifest(tmp_path):
    exe = tmp_path / "test.exe"
    image = tmp_path / "image.bin"
    make_pe32(exe)
    subprocess.run(
        [sys.executable, str(SCRIPT), str(exe), "-o", str(image)],
        check=True,
    )
    raw = image.read_bytes()
    assert len(raw) == 0x3000
    assert raw[0x1000:0x1010] == b"ZWASM-TEST-IMAGE"
    manifest = image.with_suffix(".json").read_text(encoding="utf-8")
    assert '"machine": "i386"' in manifest
    assert '"applied": false' in manifest


def test_builder_rejects_non_pe(tmp_path):
    bad = tmp_path / "bad.exe"
    bad.write_bytes(b"not a pe")
    image = tmp_path / "image.bin"
    result = subprocess.run(
        [sys.executable, str(SCRIPT), str(bad), "-o", str(image)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 2
    assert not image.exists()
