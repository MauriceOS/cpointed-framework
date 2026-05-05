# Made by Sn0w8ird

import json

import pytest

from cpointed.core.engine import Target
from cpointed.payloads import operator_bundle_for_target
from cpointed.payloads.bundle import OperatorBundle


def test_safe_read_and_manifest(tmp_path):
    root = tmp_path / "op"
    root.mkdir()
    (root / "a.txt").write_text("hello", encoding="utf-8")
    (root / "nested").mkdir()
    (root / "nested" / "b.bin").write_bytes(b"\x00\x01")
    manifest = {
        "version": 1,
        "entries": [
            {"id": "alpha", "path": "a.txt"},
            {"id": "beta", "path": "nested/b.bin"},
        ],
    }
    (root / "operator_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    b = OperatorBundle.from_path(root)
    assert b.read_text("a.txt") == "hello"
    p = b.resolve_manifest_id("beta")
    assert p.read_bytes() == b"\x00\x01"
    rep = b.describe_for_report()
    assert rep["manifest_entries"][0]["id"] == "alpha"
    assert rep["manifest_entries"][0]["exists"] is True


def test_path_traversal_blocked(tmp_path):
    root = tmp_path / "op"
    root.mkdir()
    b = OperatorBundle.from_path(root)
    with pytest.raises(ValueError, match="inside"):
        b.read_bytes("../outside")
def test_operator_bundle_for_target_metadata(tmp_path):
    root = tmp_path / "op"
    root.mkdir()
    (root / "x.txt").write_text("z", encoding="utf-8")
    t = Target(host="127.0.0.1", port=443, use_ssl=True)
    t.metadata["payload_dir"] = str(root)
    ob = operator_bundle_for_target(t)
    assert ob is not None
    assert ob.read_text("x.txt") == "z"
