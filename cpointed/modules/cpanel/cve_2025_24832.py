# Made by Sn0w8ird

from cpointed.core.engine import ScanResult, Target, TargetType
from cpointed.core.session import CPointedClient
from cpointed.modules.base import VulnerabilityModule


class CVE202524832(VulnerabilityModule):
    name = "CVE-2025-24832"
    severity = 7.2
    affected_versions = ["Acronis Backup plugin for cPanel/WHM — fixed builds per vendor"]
    cwe = "CWE-59"

    def applies_to(self, target: Target) -> bool:
        if target.target_type is None:
            return True
        return target.target_type in (TargetType.CPANEL, TargetType.WHM)

    async def check(self, target: Target, *, timeout: float = 30.0) -> ScanResult:
        client = CPointedClient(target)
        paths = (
            "/AcronisBackup/",
            "/frontend/acronis/",
            "/acronis/",
        )
        details: dict = {"paths": []}
        evidence: list[str] = []
        hit = False
        for path in paths:
            try:
                r = await client.request("GET", path, timeout=timeout)
            except Exception as exc:
                details["paths"].append({"path": path, "error": str(exc)})
                continue
            text = (r.text or "").lower()
            entry = {"path": path, "status_code": r.status_code}
            if "acronis" in text or r.status_code in (200, 301, 302, 401, 403):
                entry["acronis_hint"] = "acronis" in text or "backup" in text
                if entry["acronis_hint"]:
                    hit = True
                    evidence.append(path)
            details["paths"].append(entry)
        return self._result(target, hit, self.severity, details, evidence or None)
