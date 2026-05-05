# Made by Sn0w8ird

from __future__ import annotations

import abc
from typing import Any, Dict, Optional

from cpointed.core.engine import ScanResult, Target


class VulnerabilityModule(abc.ABC):
    name: str = "base"
    severity: float = 0.0
    affected_versions: list[str] = []
    cwe: str = ""

    @abc.abstractmethod
    def applies_to(self, target: Target) -> bool:
        raise NotImplementedError

    @abc.abstractmethod
    async def check(self, target: Target, *, timeout: float = 30.0) -> ScanResult:
        raise NotImplementedError

    async def exploit(self, target: Target, **kwargs: Any) -> Dict[str, Any]:
        raise NotImplementedError(f"{self.name} exploit not implemented")

    def _result(
        self,
        target: Target,
        vulnerable: bool,
        score: float,
        details: Dict[str, Any],
        evidence: Optional[list[str]] = None,
    ) -> ScanResult:
        return ScanResult(
            target=target,
            module=self.name,
            vulnerable=vulnerable,
            severity=score if vulnerable else 0.0,
            details=details,
            evidence=evidence,
        )
