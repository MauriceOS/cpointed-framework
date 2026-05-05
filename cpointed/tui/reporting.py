# Made by Sn0w8ird
"""Build structured strings and payloads for creative (but professional) TUI views."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

from cpointed.core.engine import ScanResult, Target
from cpointed.tui.icons import Icons, Tags, sev_label, severity_rich_tag


def attack_tree_payload(target: Target, results: List[ScanResult]) -> Dict[str, Any]:
    host = f"{target.host}:{target.port}"
    panel = target.target_type.value if target.target_type else "unknown"
    vulns: List[Dict[str, Any]] = []
    for r in results:
        if r.module == "engine":
            continue
        vulns.append(
            {
                "cve": r.module,
                "severity": r.severity,
                "vulnerable": r.vulnerable,
                "tier": sev_label(r.severity),
                "summary": _one_line_summary(r),
                "raw": r,
            }
        )
    persistence = target.metadata.get("persistence") if isinstance(target.metadata, dict) else None
    if not isinstance(persistence, list):
        persistence = []
    return {"host": host, "panel": panel, "vulns": vulns, "persistence": persistence}


def _one_line_summary(r: ScanResult) -> str:
    err = r.details.get("error")
    if err:
        return str(err)[:120]
    st = r.details.get("stable_tag")
    if st:
        return f"stable_tag={st}"[:120]
    tv = r.details.get("style_version")
    if tv:
        return f"theme_version={tv}"[:120]
    if r.evidence:
        return str(r.evidence[0])[:120]
    g = r.details.get("gadgets")
    if isinstance(g, list) and g:
        last = g[-1]
        if isinstance(last, dict):
            return str(last.get("path") or last)[:120]
    return "—"


def heatmap_rows(results: List[ScanResult]) -> List[Tuple[str, float, int]]:
    """Per module: max severity, count of positive findings."""
    buckets: Dict[str, List[ScanResult]] = {}
    for r in results:
        if r.module == "engine":
            continue
        buckets.setdefault(r.module, []).append(r)
    rows: List[Tuple[str, float, int]] = []
    for mod, rs in sorted(buckets.items()):
        pos = [x for x in rs if x.vulnerable]
        if not pos:
            continue
        mx = max(x.severity for x in pos)
        rows.append((mod, mx, len(pos)))
    rows.sort(key=lambda x: (-x[1], x[0]))
    return rows


def format_severity_heatmap(rows: List[Tuple[str, float, int]], *, width: int = 28) -> str:
    lines = [f"{Tags.SEVERITY} Module exposure (max CVSS / hits)", "─" * 72]
    if not rows:
        lines.append(f"{Icons.INFO} No vulnerable modules in this run.")
        return "\n".join(lines)
    scale = 10.0
    for mod, sev, hits in rows:
        filled = max(0, min(width, int(round((sev / scale) * width))))
        bar = Icons.PROG_FULL * filled + Icons.PROG_EMPTY * (width - filled)
        lines.append(f"{mod:26} {bar} {sev:4.1f}  ({hits} hit(s))")
    lines.append("─" * 72)
    return "\n".join(lines)


def executive_summary_dict(target: Target, results: List[ScanResult]) -> Dict[str, Any]:
    mods = [r for r in results if r.module != "engine"]
    vuln_hits = [r for r in mods if r.vulnerable]
    critical = sorted({r.module for r in vuln_hits if r.severity >= 9.0})
    high = sorted({r.module for r in vuln_hits if 7.0 <= r.severity < 9.0})
    med = sorted({r.module for r in vuln_hits if 4.0 <= r.severity < 7.0})
    panel = target.target_type.value if target.target_type else "unknown"
    top_hosts = [
        (
            f"{target.host}:{target.port}",
            panel,
            ", ".join(sorted({r.module for r in vuln_hits})) or "—",
        )
    ]
    remediation = target.metadata.get("remediation") if isinstance(target.metadata, dict) else {}
    if not isinstance(remediation, dict):
        remediation = {}
    return {
        "total_targets": 1,
        "vulnerable_modules": len({r.module for r in vuln_hits}),
        "positive_findings": len(vuln_hits),
        "critical_cves": critical,
        "high_cves": high,
        "medium_cves": med,
        "top_hosts": top_hosts,
        "remediation": {
            "patched": int(remediation.get("patched", 0)),
            "malware_removed": int(remediation.get("malware_removed", 0)),
            "sessions_purged": int(remediation.get("sessions_purged", 0)),
        },
    }


def format_executive_dashboard(summary: Dict[str, Any]) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    sep = "═" * 64
    inner = "─" * 64
    vm = summary["vulnerable_modules"]
    pf = summary["positive_findings"]
    crit = ", ".join(summary.get("critical_cves") or []) or "—"
    high = ", ".join(summary.get("high_cves") or []) or "—"
    med = ", ".join(summary.get("medium_cves") or []) or "—"
    lines = [
        sep,
        " cpointed — executive view",
        f" Generated: {now}",
        sep,
        f"{Tags.METRICS} Targets: {summary['total_targets']} | "
        f"Vulnerable modules: {vm} | Positive rows: {pf}",
        inner,
        f"{Tags.SEVERITY} Critical (9.0+): {crit}",
        f"{'':17}High (7.0–8.9): {high}",
        f"{'':17}Medium (4.0–6.9): {med}",
        inner,
        f"{Tags.TOP} Hosts (this run)",
    ]
    for i, (host, kind, note) in enumerate(summary.get("top_hosts") or [], 1):
        lines.append(f"   {i}. {host} ({kind}) {Icons.ARROW} {note}")
    r = summary.get("remediation") or {}
    lines.extend(
        [
            inner,
            f"{Tags.REMEDIATION} Patched hosts: {r.get('patched', 0)} | "
            f"Malware removals: {r.get('malware_removed', 0)} | "
            f"Sessions purged: {r.get('sessions_purged', 0)}",
            sep,
        ]
    )
    return "\n".join(lines)


def format_panel_line(target: Target) -> str:
    tt = target.target_type.name if target.target_type else "UNKNOWN"
    scheme = "https" if target.use_ssl else "http"
    return f"{Tags.SURFACE} {scheme}://{target.host}:{target.port}/  [{tt}]"
