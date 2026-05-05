# Made by Sn0w8ird

from __future__ import annotations

from cpointed.core.engine import ScanResult, Target
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

    async def check(self, target: Target, *, timeout: float = 30.0) -> ScanResult:
        return await self.check_from_readme(target, timeout=timeout)
