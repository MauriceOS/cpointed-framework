# Made by Sn0w8ird

from __future__ import annotations

from cpointed.core.engine import ScanResult, Target
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

    async def check(self, target: Target, *, timeout: float = 30.0) -> ScanResult:
        return await self.check_from_readme(target, timeout=timeout)
