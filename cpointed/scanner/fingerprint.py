# Made by Sn0w8ird

from __future__ import annotations

import re
from typing import Any, Dict, Optional

import httpx

from cpointed.core.engine import Target, TargetType


async def fingerprint_service(target: Target, timeout: float = 10.0) -> Dict[str, Any]:
    """Lightweight HTTP banner/title fingerprint for cPanel vs DirectAdmin hints."""
    scheme = "https" if target.use_ssl else "http"
    url = f"{scheme}://{target.host}:{target.port}/"
    out: Dict[str, Any] = {"url": url, "hints": []}
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=timeout) as client:
            r = await client.get(url)
    except httpx.HTTPError as exc:
        out["error"] = str(exc)
        return out

    text = r.text or ""
    headers = {k.lower(): v for k, v in r.headers.items()}
    server = headers.get("server", "")
    out["x_cpanel_version"] = headers.get("x-cpanel-version")
    out["x_cpanel"] = headers.get("x-cpanel")
    out["x_powered_by"] = headers.get("x-powered-by", "")
    if out["x_cpanel_version"] or "cpanel" in (out.get("x_powered_by") or "").lower():
        out["hints"].append("cpanel_version_header")
    if "cpanel" in text.lower() or "cpsession" in text.lower():
        out["hints"].append("cpanel_html")
    if "directadmin" in text.lower() or "DirectAdmin" in text:
        out["hints"].append("directadmin_html")
    if re.search(r"cPanel", text, re.I):
        out["hints"].append("cpanel_title")
    out["status_code"] = r.status_code
    out["server_header"] = server
    return out


def guess_target_type(fp: Dict[str, Any]) -> Optional[TargetType]:
    hints = fp.get("hints") or []
    if "directadmin_html" in hints:
        return TargetType.DIRECTADMIN
    if "cpanel_html" in hints or "cpanel_title" in hints or "cpanel_version_header" in hints:
        return TargetType.CPANEL
    return None
