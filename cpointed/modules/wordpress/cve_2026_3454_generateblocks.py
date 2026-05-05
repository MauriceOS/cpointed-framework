# Made by Sn0w8ird

from __future__ import annotations

from cpointed.core.engine import ScanResult, Target
from cpointed.modules.wordpress.base import WordPressModule


class CVE20263454GenerateBlocks(WordPressModule):
    name = "CVE-2026-3454"
    severity = 6.5
    affected_versions = ["generateblocks: verify against vendor advisory"]
    cwe = "CWE-639 (context-specific)"
    plugin_readme_paths = ("/wp-content/plugins/generateblocks/readme.txt",)
    slug_hint = "generateblocks"
    exploit_admin_ajax_action = "generateblocks_get_dynamic_tag_output"
    exploit_ajax_extra_fields = {"tag_name": "cpointed-read-test", "context": "author"}

    async def check(self, target: Target, *, timeout: float = 30.0) -> ScanResult:
        return await self.check_from_readme(target, timeout=timeout)
