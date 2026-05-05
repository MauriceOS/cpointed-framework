# Made by Sn0w8ird

from __future__ import annotations

from cpointed.core.engine import ScanResult, Target
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
    exploit_admin_ajax_action = "geekybot_install_plugin"
    exploit_ajax_extra_fields = {"plugin_slug": "cpointed-probe-zip"}

    async def check(self, target: Target, *, timeout: float = 30.0) -> ScanResult:
        return await self.check_from_readme(target, timeout=timeout)
