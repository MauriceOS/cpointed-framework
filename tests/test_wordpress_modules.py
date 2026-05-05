# Made by Sn0w8ird

import asyncio

import pytest

from cpointed.core.engine import Target, TargetType
from cpointed.modules.wordpress.cve_2026_1357_wpvivid import CVE20261357WPvivid


def test_wordpress_module_applies_with_metadata_flags():
    m = CVE20261357WPvivid()
    t = Target(host="127.0.0.1", port=443)
    assert m.applies_to(t) is False
    t.metadata["include_wordpress_modules"] = True
    assert m.applies_to(t) is True
    t2 = Target(host="127.0.0.1", port=443, target_type=TargetType.WORDPRESS)
    assert m.applies_to(t2) is True


def test_wordpress_exploit_live_http_when_authorized(monkeypatch, httpserver):
    monkeypatch.setenv("CPOINTED_AUTHORIZED", "1")
    monkeypatch.setattr(
        "cpointed.modules.wordpress.cve_2026_1357_wpvivid.random.randint",
        lambda a, b: 5555,
    )
    httpserver.expect_request(
        "/wp-admin/admin-ajax.php", method="GET", query_string="action=heartbeat"
    ).respond_with_data("0", status=200)
    httpserver.expect_request("/wp-admin/admin-ajax.php", method="POST").respond_with_data(
        '{"success":false}',
        content_type="application/json",
    )
    httpserver.expect_request("/wp-content/uploads/cpointed_5555.php", method="GET").respond_with_data(
        "TEST output",
        status=200,
    )
    httpserver.expect_request("/wp-login.php", method="GET", query_string="action=register").respond_with_data(
        '<form name="registerform" id="registerform">',
        content_type="text/html",
    )
    httpserver.expect_request("/wp-login.php", method="POST", query_string="action=register").respond_with_data(
        "registration closed",
        status=200,
        content_type="text/html",
    )
    m = CVE20261357WPvivid()
    out = asyncio.run(
        m.exploit(
            Target(host=httpserver.host, port=httpserver.port, use_ssl=False),
            timeout=5.0,
        )
    )
    assert out["mode"] == "live_http_exploit_primitive"
    assert out.get("success") is True
    assert "verify_response" in out or out.get("verify_status_code") == 200


def test_wordpress_exploit_blocked_without_auth(monkeypatch):
    monkeypatch.delenv("CPOINTED_AUTHORIZED", raising=False)
    m = CVE20261357WPvivid()
    from cpointed.core.exceptions import UnauthorizedOperationError

    with pytest.raises(UnauthorizedOperationError):
        asyncio.run(m.exploit(Target(host="127.0.0.1", port=443)))
