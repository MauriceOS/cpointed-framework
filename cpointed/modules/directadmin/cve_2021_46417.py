# Made by Sn0w8ird

from cpointed.core.engine import ScanResult, Target, TargetType
from cpointed.core.session import CPointedClient
from cpointed.modules.base import VulnerabilityModule


class CVE202146417(VulnerabilityModule):
    """DirectAdmin local privilege escalation research marker (version/help surface).

    Remote HTTP cannot confirm LPE; correlate retrieved build hints with CVE-2021-46417 offline.
    """

    name = "CVE-2021-46417"
    severity = 7.8
    affected_versions = ["DirectAdmin builds per vendor; confirm LPE chain offline"]
    cwe = "CWE-269 (local)"

    def applies_to(self, target: Target) -> bool:
        if target.target_type is None:
            return True
        return target.target_type == TargetType.DIRECTADMIN

    async def check(self, target: Target, *, timeout: float = 30.0) -> ScanResult:
        client = CPointedClient(target)
        details: dict = {"paths": []}
        evidence: list[str] = []
        hit = False
        for path in ("/CMD_LICENSE", "/CMD_API_SYSTEM_INFO", "/CMD_LOGIN"):
            try:
                r = await client.request("GET", path, timeout=timeout)
            except Exception as exc:
                details["paths"].append({"path": path, "error": str(exc)})
                continue
            text = r.text or ""
            row = {"path": path, "status_code": r.status_code}
            if "directadmin" in text.lower():
                row["directadmin"] = True
                if "1." in text and "directadmin" in text.lower():
                    hit = True
                    evidence.append(path)
            details["paths"].append(row)
        return self._result(target, hit, self.severity, details, evidence or None)
