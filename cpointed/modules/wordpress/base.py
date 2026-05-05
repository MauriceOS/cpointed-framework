# Made by Sn0w8ird

from __future__ import annotations

import os
import re
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlencode

from cpointed.core.engine import ScanResult, Target, TargetType
from cpointed.core.session import CPointedClient
from cpointed.core.versioning import is_strictly_older
from cpointed.modules.base import VulnerabilityModule


class WordPressModule(VulnerabilityModule):
    """Remote WordPress/plugin checks and live HTTP exploit primitives (authorized engagement use)."""

    plugin_readme_paths: tuple[str, ...] = ()
    slug_hint: str = ""
    fixed_in_version: Optional[str] = None
    exploit_admin_ajax_action: str = ""
    exploit_ajax_extra_fields: Dict[str, str] = {}

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
    def _path_for_wp(wp_path: str, rel: str) -> str:
        """Join URL path prefix (no host) to relative path (exploit primitives)."""
        rel = rel if rel.startswith("/") else f"/{rel}"
        pre = (wp_path or "").strip().rstrip("/")
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

    async def discover_wp_install_path(
        self,
        target: Target,
        client: CPointedClient,
        *,
        timeout: float,
    ) -> str:
        """Return WordPress path prefix (``wp_base_path`` metadata); extend with live probes if needed."""
        _ = client, timeout
        return self.wp_prefix(target)

    async def exploit_remote_primitive(
        self,
        client: CPointedClient,
        wp_path: str,
        *,
        target: Target,
        timeout: float,
    ) -> Dict[str, Any]:
        """Default POST to ``admin-ajax.php`` when ``exploit_admin_ajax_action`` is set."""
        out: Dict[str, Any] = {"admin_ajax_posts": []}
        if not self.exploit_admin_ajax_action:
            out["primitive_note"] = "override_exploit_remote_primitive_or_set_exploit_admin_ajax_action"
            return out
        ajax = self._path_for_wp(wp_path, "/wp-admin/admin-ajax.php")
        fields: Dict[str, str] = {"action": self.exploit_admin_ajax_action}
        fields.update(self.exploit_ajax_extra_fields)
        body = urlencode(fields).encode("utf-8")
        try:
            r = await client.request(
                "POST",
                ajax,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                content=body,
                timeout=timeout,
            )
            snippet = (r.text or "")[:2000]
            out["admin_ajax_posts"].append(
                {
                    "path": ajax,
                    "action": self.exploit_admin_ajax_action,
                    "status_code": r.status_code,
                    "body_snippet": snippet,
                }
            )
        except Exception as exc:  # pragma: no cover - network
            out["admin_ajax_posts"].append(
                {"action": self.exploit_admin_ajax_action, "error": str(exc)}
            )
        return out

    async def _attempt_open_registration(
        self,
        target: Target,
        client: CPointedClient,
        *,
        timeout: float,
        wp_path: str,
    ) -> Dict[str, Any]:
        reg_url = self._path_for_wp(wp_path, "/wp-login.php?action=register")
        out: Dict[str, Any] = {"registration_probe": None}
        try:
            r0 = await client.request("GET", reg_url, timeout=timeout)
            login_user = os.environ.get("CPOINTED_WP_AUDIT_USER", "cpointed_audit_user")
            login_email = os.environ.get("CPOINTED_WP_AUDIT_EMAIL", "cpointed-audit@example.invalid")
            nonce = ""
            m = re.search(r'name="[_]?wpnonce" value="([^"]+)"', r0.text or "", re.I)
            if m:
                nonce = m.group(1)
            fields = {
                "user_login": login_user,
                "user_email": login_email,
                "redirect_to": "",
                "wp-submit": "Register",
            }
            if nonce:
                fields["_wpnonce"] = nonce
            body = urlencode(fields).encode("utf-8")
            r1 = await client.request(
                "POST",
                reg_url,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                content=body,
                timeout=timeout,
            )
            text = (r1.text or "").lower()
            out["registration_probe"] = {
                "get_status": r0.status_code,
                "post_status": r1.status_code,
                "response_hint_register_disabled": "error" in text or "not allowed" in text,
                "body_snippet": (r1.text or "")[:1500],
            }
        except Exception as exc:  # pragma: no cover - network
            out["registration_probe"] = {"error": str(exc)}
        return out

    async def exploit(self, target: Target, **kwargs: Any) -> Dict[str, Any]:
        from cpointed.core.exceptions import UnauthorizedOperationError

        if os.environ.get("CPOINTED_AUTHORIZED") != "1":
            raise UnauthorizedOperationError(
                f"{self.name}: set CPOINTED_AUTHORIZED=1 only with explicit written permission."
            )
        timeout = float(kwargs.get("timeout") or 30)
        client = CPointedClient(target)
        trace: Dict[str, Any] = {
            "module": self.name,
            "target": f"{target.host}:{target.port}",
            "mode": "live_http_exploit_primitive",
        }
        wp_path = await self.discover_wp_install_path(target, client, timeout=timeout)
        trace["wp_install_path_prefix"] = wp_path or ""

        ajax_path = self._path_for_wp(wp_path, "/wp-admin/admin-ajax.php")
        try:
            r_hello = await client.request(
                "GET",
                ajax_path + "?action=heartbeat",
                timeout=timeout,
            )
            trace["admin_ajax_heartbeat"] = {
                "path": ajax_path,
                "status_code": r_hello.status_code,
                "body_snippet": (r_hello.text or "")[:800],
            }
        except Exception as exc:  # pragma: no cover - network
            trace["admin_ajax_heartbeat"] = {"path": ajax_path, "error": str(exc)}

        primitive = await self.exploit_remote_primitive(
            client, wp_path, target=target, timeout=timeout
        )
        trace.update(primitive)
        trace["success"] = bool(primitive.get("success"))
        if kwargs.get("registration_probe", True):
            reg = await self._attempt_open_registration(
                target, client, timeout=timeout, wp_path=wp_path
            )
            trace.update(reg)

        trace["remediation_hint"] = (
            "Archive this JSON for the org report; patch plugins, rotate creds, review users and mu-plugins."
        )
        return trace
