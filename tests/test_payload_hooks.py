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


def test_load_payload_b64():
    raw = "a={x}"
    b64 = "b64:" + base64.b64encode(raw.encode("utf-8")).decode("ascii")
    assert PayloadHook.load_payload(b64, {"x": "1"}) == "a=1"
