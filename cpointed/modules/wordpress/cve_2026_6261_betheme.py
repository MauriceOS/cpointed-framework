# Made by Sn0w8ird

from __future__ import annotations

import re

from cpointed.core.engine import ScanResult, Target
from cpointed.core.session import CPointedClient
from cpointed.modules.wordpress.base import WordPressModule


class CVE20266261Betheme(WordPressModule):
    name = "CVE-2026-6261"
    severity = 7.0
    affected_versions = ["Betheme theme: confirm patched train with vendor SA"]
    cwe = "CWE-434 (context-specific)"
    plugin_readme_paths = ()
    slug_hint = "betheme"
    fixed_in_version = None

    @staticmethod
    def _theme_version(text: str) -> str | None:
        m = re.search(r"(?im)^version:\s*([0-9a-zA-Z.+-]+)\s*$", text)
        return m.group(1).strip() if m else None

    async def check(self, target: Target, *, timeout: float = 30.0) -> ScanResult:
        if target.metadata.get("scan_dry_run"):
            return self._result(
                target,
                False,
                0.0,
                {"scan_dry_run": True, "note": "Theme GET skipped in dry-run."},
            )
        client = CPointedClient(target)
        path = self._path(target, "/wp-content/themes/betheme/style.css")
        details: dict = {"asset": path}
        try:
            r = await client.request("GET", path, timeout=timeout)
        except Exception as exc:  # pragma: no cover
            details["error"] = str(exc)
            return self._result(target, False, 0.0, details)
        text = r.text or ""
        details["status_code"] = r.status_code
        ver = self._theme_version(text) if r.status_code == 200 else None
        details["style_version"] = ver
        details["declared_cvss"] = self.severity
        vuln, vmeta = self.assess_semver(ver)
        details.update(vmeta)
        surface = bool(ver) or (r.status_code == 200 and "betheme" in text.lower())
        details["theme_surface"] = surface
        details["note"] = "Theme header fingerprint; exploitation remains context-specific."
        return self._result(target, vuln, self.severity if vuln else 0.0, details)
