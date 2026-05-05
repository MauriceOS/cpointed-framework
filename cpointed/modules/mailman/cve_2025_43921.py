# Made by Sn0w8ird

from cpointed.core.engine import ScanResult, Target, TargetType
from cpointed.core.session import CPointedClient
from cpointed.modules.base import VulnerabilityModule


class CVE202543921(VulnerabilityModule):
    name = "CVE-2025-43921"
    severity = 7.5
    affected_versions = ["GNU Mailman 2.1.x — verify >= 2.1.40"]
    cwe = "CWE-306"

    def applies_to(self, target: Target) -> bool:
        if target.target_type is None:
            return True
        return target.target_type in (TargetType.CPANEL, TargetType.WHM, TargetType.WP_SQUARED)

    async def check(self, target: Target, *, timeout: float = 30.0) -> ScanResult:
        client = CPointedClient(target)
        candidates = ("/mailman/listinfo", "/cgi-bin/mailman/listinfo", "/pipermail/")
        details: dict = {"checked": []}
        evidence: list[str] = []
        hit = False
        for path in candidates:
            try:
                r = await client.request("GET", path, timeout=timeout)
            except Exception as exc:
                details["checked"].append({"path": path, "error": str(exc)})
                continue
            text = r.text or ""
            row = {"path": path, "status_code": r.status_code}
            if r.status_code == 200 and "mailman" in text.lower():
                row["mailman"] = True
                hit = True
                evidence.append(path)
            details["checked"].append(row)
        return self._result(target, hit, self.severity, details, evidence or None)
