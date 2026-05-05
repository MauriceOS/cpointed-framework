# Made by Sn0w8ird

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from cpointed.modules.base import VulnerabilityModule


class TargetType(Enum):
    CPANEL = "cpanel"
    WHM = "whm"
    WP_SQUARED = "wp_squared"
    DIRECTADMIN = "directadmin"
    PLESK = "plesk"
    WORDPRESS = "wordpress"
    UNKNOWN = "unknown"


class Severity(Enum):
    CRITICAL = 9.0
    HIGH = 7.0
    MEDIUM = 4.0
    LOW = 0.1


def _empty_metadata() -> Dict[str, Any]:
    return {}


@dataclass
class Target:
    host: str
    port: int
    use_ssl: bool = True
    target_type: Optional[TargetType] = None
    metadata: Dict[str, Any] = field(default_factory=_empty_metadata)


@dataclass
class ScanResult:
    target: Target
    module: str
    vulnerable: bool
    severity: float
    details: Dict[str, Any]
    evidence: Optional[List[str]] = None


class CPointedEngine:
    """Orchestrates scanning, exploitation, and reporting."""

    def __init__(self, threads: int = 10, timeout: int = 30):
        self.threads = max(1, threads)
        self.timeout = timeout
        self.modules: List[VulnerabilityModule] = []
        self.results: List[ScanResult] = []

    def register_module(self, module: VulnerabilityModule) -> None:
        self.modules.append(module)

    async def scan_target(self, target: Target) -> List[ScanResult]:
        semaphore = asyncio.Semaphore(self.threads)

        async def run_one(mod: VulnerabilityModule) -> Optional[ScanResult]:
            if not mod.applies_to(target):
                return None
            async with semaphore:
                return await mod.check(target, timeout=self.timeout)

        tasks = [run_one(m) for m in self.modules]
        raw = await asyncio.gather(*tasks, return_exceptions=True)
        results: List[ScanResult] = []
        for item in raw:
            if isinstance(item, ScanResult):
                results.append(item)
            elif isinstance(item, BaseException):
                results.append(
                    ScanResult(
                        target,
                        module="engine",
                        vulnerable=False,
                        severity=0.0,
                        details={"error": str(item)},
                    )
                )
        return results
