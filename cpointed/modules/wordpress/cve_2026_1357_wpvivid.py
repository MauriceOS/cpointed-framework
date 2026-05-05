# Made by Sn0w8ird

from __future__ import annotations

from cpointed.core.engine import ScanResult, Target
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

    async def check(self, target: Target, *, timeout: float = 30.0) -> ScanResult:
        return await self.check_from_readme(target, timeout=timeout)
