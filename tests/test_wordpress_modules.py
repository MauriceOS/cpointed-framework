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


def test_wordpress_exploit_playbook_when_authorized(monkeypatch):
    monkeypatch.setenv("CPOINTED_AUTHORIZED", "1")
    m = CVE20261357WPvivid()
    out = asyncio.run(m.exploit(Target(host="127.0.0.1", port=443)))
    assert out["mode"] == "operator_playbook"


def test_wordpress_exploit_blocked_without_auth(monkeypatch):
    monkeypatch.delenv("CPOINTED_AUTHORIZED", raising=False)
    m = CVE20261357WPvivid()
    from cpointed.core.exceptions import UnauthorizedOperationError

    with pytest.raises(UnauthorizedOperationError):
        asyncio.run(m.exploit(Target(host="127.0.0.1", port=443)))
