# Made by Sn0w8ird

from cpointed.core.engine import ScanResult, Target
from cpointed.tui.reporting import executive_summary_dict, heatmap_rows


def test_executive_summary_counts():
    t = Target(host="10.0.0.1", port=2083)
    rows = [
        ScanResult(t, "CVE-2026-41940", True, 9.8, {}),
        ScanResult(t, "CVE-2025-56551", False, 7.5, {}),
    ]
    s = executive_summary_dict(t, rows)
    assert s["total_targets"] == 1
    assert s["vulnerable_modules"] == 1
    assert s["positive_findings"] == 1
    assert "CVE-2026-41940" in s["critical_cves"]


def test_heatmap_rows_aggregate():
    t = Target(host="10.0.0.1", port=2083)
    rows = [
        ScanResult(t, "CVE-2026-41940", True, 9.8, {}),
        ScanResult(t, "CVE-2026-41940", True, 9.8, {}),
    ]
    h = heatmap_rows(rows)
    assert h == [("CVE-2026-41940", 9.8, 2)]
