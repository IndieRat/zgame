from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "packager" / "zwasm_pack.py"
VERIFY = ROOT / "packager" / "zwasm_verify.py"


def test_round_trip(tmp_path: Path) -> None:
    game = tmp_path / "game"
    (game / "resources").mkdir(parents=True)
    (game / "resources" / "hello.lua").write_text(
        "print('hello')\n", encoding="utf-8"
    )
    (game / "native.exe").write_bytes(b"not browser code")
    boot = tmp_path / "boot.wasm"
    boot.write_bytes(b"wasm-placeholder")
    image = tmp_path / "image.bin"
    image.write_bytes(bytes(range(64)))
    out = tmp_path / "game.zgame"

    subprocess.run(
        [
            sys.executable, str(PACK), str(game),
            "--boot", str(boot), "--image", str(image),
            "--output", str(out), "--gzip", "always",
        ],
        check=True,
    )
    subprocess.run(
        [sys.executable, str(VERIFY), str(out), "--hash"],
        check=True,
    )

    raw = out.read_bytes()
    magic, version, flags, index_offset, index_size, payload_offset, count, _ = (
        struct.unpack_from("<8sIIQQQI20s", raw)
    )
    assert magic == b"ZWASMG01"
    assert version == 1
    assert count == 3

    manifest = json.loads(raw[index_offset:index_offset + index_size])
    paths = {e["path"] for e in manifest["entries"]}
    assert "native.exe" not in paths
    assert "instance/resources/hello.lua" in paths
    assert manifest["boot"] == "boot.wasm"
    assert manifest["image"] == "image.bin"
