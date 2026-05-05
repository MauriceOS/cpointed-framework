# Made by Sn0w8ird

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence

from cpointed.core.engine import CPointedEngine, ScanResult, Target
from cpointed.modules.base import VulnerabilityModule


@dataclass
class AssessmentSettings:
    threads: int = 10
    timeout: int = 30
    include_wordpress: bool = False
    run_http_wordpress_discovery: bool = False


async def run_assessment(
    targets: Sequence[Target],
    modules: Sequence[VulnerabilityModule],
    *,
    settings: Optional[AssessmentSettings] = None,
) -> List[ScanResult]:
    """Run a single engine pass across targets with shared concurrency settings."""
    cfg = settings or AssessmentSettings()
    engine = CPointedEngine(threads=cfg.threads, timeout=cfg.timeout)
    for m in modules:
        engine.register_module(m)

    all_results: List[ScanResult] = []
    for target in targets:
        if cfg.include_wordpress:
            target.metadata.setdefault("include_wordpress_modules", True)

        if cfg.run_http_wordpress_discovery:
            try:
                from cpointed.modules.wordpress.discovery import discover_wordpress, merge_discovery_into_target

                scheme = "https" if target.use_ssl else "http"
                prefix = (target.metadata.get("wp_base_path") or "/").strip()
                if prefix and not prefix.startswith("/"):
                    prefix = "/" + prefix
                base = f"{scheme}://{target.host}:{target.port}{prefix}"
                d = await discover_wordpress(base, timeout=float(cfg.timeout), verify_ssl=target.use_ssl)
                merge_discovery_into_target(target.metadata, d)
            except Exception as exc:  # pragma: no cover - network/discovery optional
                target.metadata["wordpress_discovery_error"] = str(exc)

        results = await engine.scan_target(target)
        all_results.extend(results)

    return all_results


def summarize(results: Sequence[ScanResult]) -> Dict[str, Any]:
    positives = [r for r in results if r.vulnerable]
    return {
        "total": len(results),
        "vulnerable": len(positives),
        "modules": sorted({r.module for r in positives}),
    }
