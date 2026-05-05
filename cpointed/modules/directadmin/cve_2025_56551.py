# Made by Sn0w8ird

from cpointed.core.engine import ScanResult, Target, TargetType
from cpointed.core.session import CPointedClient
from cpointed.modules.base import VulnerabilityModule


class CVE202556551(VulnerabilityModule):
    name = "CVE-2025-56551"
    severity = 7.5
    affected_versions = ["DirectAdmin 1.680 and earlier per advisory (fixed 1.681)"]
    cwe = "CWE-79 (context-dependent)"

    def applies_to(self, target: Target) -> bool:
        if target.target_type is None:
            return True
        return target.target_type == TargetType.DIRECTADMIN

    async def check(self, target: Target, *, timeout: float = 30.0) -> ScanResult:
        client = CPointedClient(target)
        details: dict = {"paths": []}
        evidence: list[str] = []
        hit = False
        for path in ("/CMD_LOGIN", "/", "/user/login"):
            try:
                r = await client.request(
                    "GET",
                    path,
                    params={"test": "<script>cpointed</script>"},
                    timeout=timeout,
                )
            except Exception as exc:  # pragma: no cover
                details["paths"].append({"path": path, "error": str(exc)})
                continue
            text = (r.text or "").lower()
            details["paths"].append({"path": path, "status_code": r.status_code})
            if "directadmin" in text or "/CMD_" in (r.text or ""):
                details["paths"][-1]["directadmin_hint"] = True
            if "<script>cpointed</script>" in (r.text or ""):
                hit = True
                evidence.append(f"{path}: reflected probe tag")
        return self._result(target, hit, self.severity, details, evidence or None)
