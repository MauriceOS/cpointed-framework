# Made by Sn0w8ird

"""Remote WordPress surface discovery (HTTP only; no filesystem access).

For post-exploitation *local* enumeration (e.g. finding wp-config.php on disk),
integrate via your own audited SSH/file stage — not bundled here.
"""

from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import urljoin

import httpx


async def discover_wordpress(
    base_url: str,
    *,
    timeout: float = 15.0,
    verify_ssl: bool = False,
) -> Dict[str, Any]:
    """Probe common endpoints; returns hints, not exploit primitives."""
    base = base_url.rstrip("/") + "/"
    out: Dict[str, Any] = {"base_url": base.rstrip("/") or base_url, "signals": [], "paths_checked": []}
    paths = [
        "/",
        "/wp-login.php",
        "/wp-json/",
        "/readme.html",
        "/xmlrpc.php",
        "/wp-includes/js/wp-emoji-release.min.js",
    ]

    async with httpx.AsyncClient(
        verify=verify_ssl,
        follow_redirects=True,
        timeout=timeout,
        headers={"User-Agent": "cpointed-wordpress-discovery/0.1 (research)"},
    ) as client:
        for p in paths:
            url = urljoin(base, p.lstrip("/"))
            out["paths_checked"].append(url)
            try:
                r = await client.get(url)
            except httpx.HTTPError as exc:
                out["signals"].append({"path": p, "error": str(exc)})
                continue
            text = ""
            try:
                text = (r.text or "")[:8000]
            except Exception:
                text = ""
            signal: Dict[str, Any] = {"path": p, "status_code": r.status_code}
            low = text.lower()
            if "wp-login" in p and r.status_code in (200, 302):
                signal["wordpress_login"] = True
            if "/wp-json" in p and r.status_code == 200 and "wp/v2" in low:
                signal["rest_namespace"] = True
            if p == "/readme.html" and "wordpress" in low:
                signal["readme_wordpress"] = True
            if p == "/" and ("/wp-content/" in low or "/wp-includes/" in low):
                signal["wp_paths_html"] = True
            out["signals"].append(signal)

    out["likely_wordpress"] = _score_likely(out["signals"])
    return out


def _score_likely(signals: List[Dict[str, Any]]) -> bool:
    score = 0
    for s in signals:
        if s.get("wordpress_login"):
            score += 2
        if s.get("rest_namespace"):
            score += 2
        if s.get("readme_wordpress"):
            score += 1
        if s.get("wp_paths_html"):
            score += 1
    return score >= 2


def merge_discovery_into_target(metadata: Dict[str, Any], discovery: Dict[str, Any]) -> None:
    metadata["wordpress_discovery"] = discovery
    if discovery.get("likely_wordpress"):
        metadata["wordpress"] = True
