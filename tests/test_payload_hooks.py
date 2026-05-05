# Made by Sn0w8ird

import base64

from cpointed.core.payload_hooks import PayloadHook


def test_load_payload_raw_templating():
    out = PayloadHook.load_payload("echo {c2_host}:{c2_port}", {"c2_host": "10.0.0.1", "c2_port": 4444})
    assert out == "echo 10.0.0.1:4444"


def test_load_payload_unknown_placeholder_preserved():
    out = PayloadHook.load_payload("{known} {unknown}", {"known": "x"})
    assert out == "x {unknown}"


def test_load_payload_from_file(tmp_path):
    p = tmp_path / "t.txt"
    p.write_text("host={callback_url}", encoding="utf-8")
    out = PayloadHook.load_payload(f"@{p}", {"callback_url": "https://lab.example/hook"})
    assert out == "host=https://lab.example/hook"


def test_load_payload_from_php_file_with_vars(tmp_path):
    p = tmp_path / "probe.php"
    p.write_text("<?php\n// host {c2_host}\n$u = '{c2_port}';\n", encoding="utf-8")
    out = PayloadHook.load_payload(f"@{p}", {"c2_host": "10.0.0.1", "c2_port": "4444"})
    assert "10.0.0.1" in out
    assert "4444" in out
