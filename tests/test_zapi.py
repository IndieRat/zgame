import json

from packager.zwasm_zapi import ABI, FRAME, SCHEMA, VERSION, ZapiError, load


def test_zapi_valid(tmp_path):
    path = tmp_path / "kernel32.zapi"
    path.write_text(json.dumps({
        "schema": SCHEMA,
        "formatVersion": VERSION,
        "name": "kernel32",
        "abi": ABI,
        "frame": FRAME,
        "dll": "kernel32.zdll",
        "functions": [
            {"id": 1, "name": "GetTickCount", "argc": 0, "export": "zdll_call"},
        ],
    }), encoding="utf-8")
    assert load(path)["dll"] == "kernel32.zdll"


def test_zapi_rejects_duplicate_ids(tmp_path):
    path = tmp_path / "bad.zapi"
    path.write_text(json.dumps({
        "schema": SCHEMA, "formatVersion": VERSION, "abi": ABI, "frame": FRAME,
        "dll": "test.zdll",
        "functions": [
            {"id": 1, "name": "a", "argc": 0},
            {"id": 1, "name": "b", "argc": 0},
        ],
    }), encoding="utf-8")
    try:
        load(path)
    except ZapiError:
        return
    raise AssertionError("duplicate ids were accepted")
