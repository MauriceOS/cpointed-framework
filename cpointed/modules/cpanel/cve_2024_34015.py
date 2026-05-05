# Made by Sn0w8ird

from cpointed.core.engine import ScanResult, Target, TargetType
from cpointed.core.session import CPointedClient
from cpointed.modules.base import VulnerabilityModule


class CVE202434015(VulnerabilityModule):
    name = "CVE-2024-34015"
    severity = 6.5
    affected_versions = ["Acronis plugin — info disclosure; verify build >= 818"]
    cwe = "CWE-200"

    def applies_to(self, target: Target) -> bool:
        if target.target_type is None:
            return True
        return target.target_type in (TargetType.CPANEL, TargetType.WHM)

    async def check(self, target: Target, *, timeout: float = 30.0) -> ScanResult:
        client = CPointedClient(target)
        paths = ("/frontend/acronis/", "/AcronisBackup/", "/cgi/acronis/")
        details: dict = {"paths": []}
        hit = False
        evidence: list[str] = []
        for path in paths:
            try:
                r = await client.request("GET", path, timeout=timeout)
            except Exception as exc:
                details["paths"].append({"path": path, "error": str(exc)})
                continue
            text = (r.text or "")
            row = {"path": path, "status_code": r.status_code, "bytes": len(text.encode("utf-8", errors="ignore"))}
            low = text.lower()
            if r.status_code == 200 and len(text) > 50 and ("path" in low or "error" in low or "json" in low):
                row["disclosure_surface"] = True
                hit = True
                evidence.append(path)
            details["paths"].append(row)
        return self._result(target, hit, self.severity, details, evidence or None)
