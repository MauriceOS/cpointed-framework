# Made by Sn0w8ird

from cpointed.core.engine import ScanResult, Target, TargetType
from cpointed.core.session import CPointedClient
from cpointed.modules.base import VulnerabilityModule


class SEC585Locale(VulnerabilityModule):
    """SEC-585 style WHM locale/unserialization attack surface fingerprint."""

    name = "SEC-585"
    severity = 8.0
    affected_versions = ["cPanel/WHM < 98.0.1 per vendor SEC-585 advisory"]
    cwe = "CWE-502"

    def applies_to(self, target: Target) -> bool:
        if target.target_type is None:
            return True
        return target.target_type in (TargetType.CPANEL, TargetType.WHM)

    async def check(self, target: Target, *, timeout: float = 30.0) -> ScanResult:
        client = CPointedClient(target)
        probes = (
            "/scripts2/locale",
            "/scripts2/locale_upload",
            "/whm/scripts2/locale",
        )
        details: dict = {"paths": []}
        evidence: list[str] = []
        hit = False
        for path in probes:
            try:
                r = await client.request("GET", path, timeout=timeout)
            except Exception as exc:
                details["paths"].append({"path": path, "error": str(exc)})
                continue
            row = {"path": path, "status_code": r.status_code}
            if r.status_code in (200, 302, 401, 403):
                row["locale_endpoint_reachable"] = True
                hit = True
                evidence.append(path)
            details["paths"].append(row)
        return self._result(target, hit, self.severity, details, evidence or None)
