# Made by Sn0w8ird

import asyncio
import json

import pytest

from cpointed.core.engine import Target
from cpointed.core.session import CPointedClient
from cpointed.modules.cpanel.cve_2026_41940 import CVE202641940
from cpointed.scanner.ports import scan_ports_connect_ex


@pytest.mark.asyncio
async def test_mint_session_parses_whostmgrsession(httpserver) -> None:
    httpserver.expect_request("/login/", method="POST", query_string="login_only=1").respond_with_data(
        "ok",
        status=200,
        headers={"Set-Cookie": "whostmgrsession=testsess; path=/; HttpOnly"},
    )
    target = Target(host=httpserver.host, port=httpserver.port, use_ssl=False)
    client = CPointedClient(target)
    mod = CVE202641940()
    sid = await mod._mint_session(client, 5.0)
    assert sid == "testsess"


@pytest.mark.asyncio
async def test_verify_root_parses_json_api(httpserver) -> None:
    httpserver.expect_request("/json-api/version", method="GET").respond_with_data(
        json.dumps({"result": 1, "version": "11.x"}),
        content_type="application/json",
    )
    target = Target(host=httpserver.host, port=httpserver.port, use_ssl=False)
    client = CPointedClient(target)
    mod = CVE202641940()
    ok = await mod._verify_root(client, "any", 5.0)
    assert ok is True


@pytest.mark.asyncio
async def test_find_wordpress_installs_json_accounts(httpserver) -> None:
    body = json.dumps({"data": [{"user": "custacct"}]})
    httpserver.expect_request("/json-api/listaccts", method="GET").respond_with_data(
        body,
        content_type="application/json",
    )
    target = Target(host=httpserver.host, port=httpserver.port, use_ssl=False)
    client = CPointedClient(target)
    mod = CVE202641940()
    paths = await mod._find_wordpress_installs(client, "sess", 5.0)
    assert "/home/custacct/public_html" in paths


@pytest.mark.asyncio
async def test_find_wordpress_installs_regex_home(httpserver) -> None:
    html = '<tr><td>/home/u1/public_html</td></tr>'
    httpserver.expect_request("/json-api/listaccts", method="GET").respond_with_data(html, content_type="text/html")
    target = Target(host=httpserver.host, port=httpserver.port, use_ssl=False)
    client = CPointedClient(target)
    mod = CVE202641940()
    paths = await mod._find_wordpress_installs(client, "sess", 5.0)
    assert "/home/u1/public_html" in paths


def test_scan_ports_connect_ex_closed_port() -> None:
    assert scan_ports_connect_ex("127.0.0.1", [59987], timeout=0.2) == []
