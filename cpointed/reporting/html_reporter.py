# Made by Sn0w8ird

from __future__ import annotations

import html
from pathlib import Path
from typing import List

from cpointed.core.engine import ScanResult
from cpointed.reporting.json_reporter import _serialize_result


def write_html_report(results: List[ScanResult], path: str | Path, title: str = "cpointed report") -> None:
    rows = []
    for r in results:
        d = _serialize_result(r)
        vuln = "yes" if d["vulnerable"] else "no"
        mod = html.escape(str(d["module"]))
        host = html.escape(str(d["target"]["host"]))
        port = html.escape(str(d["target"]["port"]))
        sev = html.escape(str(d["severity"]))
        rows.append(f"<tr><td>{host}</td><td>{port}</td><td>{mod}</td><td>{vuln}</td><td>{sev}</td></tr>")
    body = "\n".join(rows)
    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>{html.escape(title)}</title>
<style>body{{font-family:system-ui,Segoe UI,Roboto,sans-serif;margin:2rem}} table{{border-collapse:collapse;width:100%}} th,td{{border:1px solid #ccc;padding:8px;text-align:left}} th{{background:#f4f4f4}}</style>
</head><body>
<h1>{html.escape(title)}</h1>
<p>Author: Sn0w8ird · MauriceOS · MIT License · For authorized testing only.</p>
<table><thead><tr><th>Host</th><th>Port</th><th>Module</th><th>Vulnerable</th><th>Severity</th></tr></thead>
<tbody>{body}</tbody></table>
</body></html>"""
    Path(path).write_text(doc, encoding="utf-8")
