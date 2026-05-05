# Made by Sn0w8ird

from __future__ import annotations

import os
import re
from typing import Any, Dict, Optional, Tuple

from cpointed.core.engine import ScanResult, Target, TargetType
from cpointed.core.session import CPointedClient
from cpointed.core.versioning import is_strictly_older
from cpointed.modules.base import VulnerabilityModule


class WordPressModule(VulnerabilityModule):
    """Remote WordPress/plugin checks plus advisory-version correlation.

    Remote *exploit* primitives (upload/RCE) are intentionally out of scope;
    use the operator playbook from ``exploit()`` when ``CPOINTED_AUTHORIZED=1``.
    """

    plugin_readme_paths: tuple[str, ...] = ()
    slug_hint: str = ""
    fixed_in_version: Optional[str] = None

    def applies_to(self, target: Target) -> bool:
        if target.target_type == TargetType.WORDPRESS:
            return True
        if target.metadata.get("wordpress") is True:
            return True
        if target.metadata.get("include_wordpress_modules") is True:
            return True
        return False

    @staticmethod
    def wp_prefix(target: Target) -> str:
        p = (target.metadata.get("wp_base_path") or "/").strip()
        if not p or p == "/":
            return ""
        return p.rstrip("/")

    def _path(self, target: Target, rel: str) -> str:
        rel = rel if rel.startswith("/") else f"/{rel}"
        pre = self.wp_prefix(target)
        if not pre:
            return rel
        return f"{pre}{rel}"

    @staticmethod
    def extract_stable_tag(text: str) -> Optional[str]:
        m = re.search(r"(?im)^\s*stable tag:\s*([0-9a-zA-Z.+-]+)\s*$", text)
        return m.group(1).strip() if m else None

    def assess_semver(self, installed: Optional[str]) -> Tuple[bool, Dict[str, Any]]:
        meta: Dict[str, Any] = {}
        if not self.fixed_in_version:
            meta["reason"] = "no_fixed_reference_programmed"
            return False, meta
        if not installed:
            meta["reason"] = "missing_version_signal"
            return False, meta
        meta["installed"] = installed
        meta["fixed_in"] = self.fixed_in_version
        older, err = is_strictly_older(installed, self.fixed_in_version)
        if err:
            meta["compare_error"] = err
            return False, meta
        meta["older_than_fixed"] = older
        return older, meta

    async def probe_readmes(
        self,
        target: Target,
        *,
        timeout: float,
    ) -> Tuple[Dict[str, Any], Optional[str]]:
        client = CPointedClient(target)
        details: Dict[str, Any] = {"probes": []}
        for rel in self.plugin_readme_paths:
            try:
                r = await client.request("GET", self._path(target, rel), timeout=timeout)
            except Exception as exc:  # pragma: no cover - network
                details["probes"].append({"path": rel, "error": str(exc)})
                continue
            row: Dict[str, Any] = {"path": rel, "status_code": r.status_code}
            text = ""
            if r.status_code == 200:
                try:
                    text = r.text or ""
                except Exception:
                    text = ""
            row["bytes"] = len(text.encode("utf-8", errors="ignore"))
            details["probes"].append(row)
            if r.status_code != 200:
                continue
            slug_l = (self.slug_hint or "").lower()
            if slug_l and slug_l not in text.lower():
                continue
            ver = self.extract_stable_tag(text)
            details["stable_tag"] = ver
            return details, ver
        return details, None

    async def check_from_readme(self, target: Target, *, timeout: float) -> ScanResult:
        if target.metadata.get("scan_dry_run"):
            return self._result(
                target,
                False,
                0.0,
                {"scan_dry_run": True, "note": "GET probes to plugin readmes skipped in dry-run."},
            )
        details, ver = await self.probe_readmes(target, timeout=timeout)
        details["declared_cvss"] = self.severity
        vuln, vmeta = self.assess_semver(ver)
        details.update(vmeta)
        surface = bool(ver) or any(p.get("status_code") == 200 for p in details.get("probes", []))
        details["plugin_surface"] = surface
        details["note"] = (
            "Version compared against packaged fixed_in metadata when available; confirm with vendor SA."
        )
        return self._result(target, vuln, self.severity if vuln else 0.0, details)

    async def exploit(self, target: Target, **kwargs: Any) -> Dict[str, Any]:
        from cpointed.core.exceptions import UnauthorizedOperationError

        if os.environ.get("CPOINTED_AUTHORIZED") != "1":
            raise UnauthorizedOperationError(
                f"{self.name}: set CPOINTED_AUTHORIZED=1 only with explicit written permission."
            )
        steps = [
            "Collect vendor advisory, CVSS, and patched release list.",
            "Capture remote readme/style version markers and archive checksums.",
            "Upgrade via supported channel; re-run cpointed wp scan to confirm remediation.",
            "Rotate secrets and review mu-plugins/uploads for unexpected PHP after incidents.",
        ]
        return {
            "module": self.name,
            "mode": "operator_playbook",
            "target": f"{target.host}:{target.port}",
            "steps": steps,
        }
