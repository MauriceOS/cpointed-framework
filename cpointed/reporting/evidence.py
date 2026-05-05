# Made by Sn0w8ird

from __future__ import annotations

from pathlib import Path
from typing import List

from cpointed.core.engine import ScanResult


def attach_evidence_paths(result: ScanResult, paths: List[str]) -> ScanResult:
    ev = list(result.evidence or [])
    for p in paths:
        ev.append(str(Path(p).resolve()))
    return ScanResult(
        target=result.target,
        module=result.module,
        vulnerable=result.vulnerable,
        severity=result.severity,
        details=result.details,
        evidence=ev,
    )
