# Made by Sn0w8ird

from __future__ import annotations

import random
from typing import Any, Dict, Optional
from urllib.parse import urlencode, urljoin

import httpx

from cpointed.core.engine import Target
from cpointed.core.exceptions import SessionError

DEFAULT_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]


class CPointedClient:
    """Async HTTP client with jitter, UA rotation, and proxy hooks."""

    def __init__(
        self,
        target: Target,
        proxy: Optional[str] = None,
        verify_ssl: bool = False,
    ):
        self.target = target
        scheme = "https" if target.use_ssl else "http"
        self.base_url = f"{scheme}://{target.host}:{target.port}"
        self.proxy = proxy
        self.verify_ssl = verify_ssl

    def _headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        h: Dict[str, str] = {
            "User-Agent": random.choice(DEFAULT_UAS),
            "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "close",
        }
        if extra:
            h.update(extra)
        return h

    async def request(
        self,
        method: str,
        path: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        content: Optional[bytes] = None,
        timeout: float = 30.0,
        follow_redirects: bool = True,
    ) -> httpx.Response:
        url = urljoin(self.base_url.rstrip("/") + "/", path.lstrip("/"))
        merged = self._headers(headers)
        try:
            timeout_obj = httpx.Timeout(timeout, connect=min(3.0, float(timeout)))
            client_kw: Dict[str, Any] = {
                "verify": self.verify_ssl,
                "follow_redirects": follow_redirects,
                "timeout": timeout_obj,
            }
            if self.proxy:
                client_kw["proxy"] = self.proxy
            async with httpx.AsyncClient(**client_kw) as client:
                return await client.request(
                    method.upper(),
                    url,
                    headers=merged,
                    params=params,
                    content=content,
                )
        except httpx.HTTPError as exc:  # pragma: no cover - network dependent
            raise SessionError(str(exc)) from exc

    async def get_json_api(self, endpoint: str, query: Dict[str, Any], timeout: float) -> httpx.Response:
        qs = urlencode(query)
        path = f"/json-api/{endpoint}?{qs}"
        return await self.request("GET", path, timeout=timeout)
