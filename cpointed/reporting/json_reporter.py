# Made by Sn0w8ird

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List

from cpointed.core.engine import ScanResult, Target, TargetType


def _serialize_target(t: Target) -> Dict[str, Any]:
    return {
        "host": t.host,
        "port": t.port,
        "use_ssl": t.use_ssl,
        "target_type": t.target_type.value if isinstance(t.target_type, TargetType) else None,
        "metadata": t.metadata,
    }


def _serialize_result(r: ScanResult) -> Dict[str, Any]:
    return {
        "target": _serialize_target(r.target),
        "module": r.module,
        "vulnerable": r.vulnerable,
        "severity": r.severity,
        "details": r.details,
        "evidence": r.evidence,
    }


def write_json_report(results: List[ScanResult], path: str | Path) -> None:
    payload = {"results": [_serialize_result(r) for r in results]}
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
