# Made by Sn0w8ird

from __future__ import annotations

import asyncio
import socket
from typing import Any, Dict, Iterable, List, Tuple

import httpx

COMMON_CPANEL_PORTS = (2083, 2087, 2082, 2086, 2095, 2096, 2222, 80, 443)


def common_cp_ports() -> Tuple[int, ...]:
    return COMMON_CPANEL_PORTS


def parse_port_list(spec: str) -> Tuple[int, ...]:
    """Parse comma-separated ports e.g. '2087,2222,80'."""
    parts = [p.strip() for p in spec.split(",") if p.strip()]
    out: List[int] = []
    for p in parts:
        out.append(int(p, 10))
    return tuple(out)


async def scan_tcp_ports_async(host: str, ports: Iterable[int], timeout: float = 1.5) -> List[int]:
    """Async TCP connect probe (open connection then close)."""
    open_ports: List[int] = []

    async def one(port: int) -> None:
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            open_ports.append(port)
        except Exception:
            return

    await asyncio.gather(*(one(p) for p in ports))
    return sorted(set(open_ports))


def scan_ports_connect_ex(host: str, ports: Iterable[int], timeout: float = 1.5) -> List[int]:
    """Sync port scan using ``connect_ex`` (checklist-aligned primitive)."""
    open_ports: List[int] = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            code = s.connect_ex((host, port))
            if code == 0:
                open_ports.append(port)
        finally:
            s.close()
    return sorted(set(open_ports))


def tcp_connect_sync(host: str, port: int, timeout: float = 1.5) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


async def detect_service(
    host: str,
    port: int,
    *,
    use_ssl: bool = True,
    timeout: float = 8.0,
    path: str = "/",
) -> Dict[str, Any]:
    """HTTP **HEAD** (with GET fallback) against ``host:port``; returns status and banner headers."""
    scheme = "https" if use_ssl else "http"
    url = f"{scheme}://{host}:{port}{path if path.startswith('/') else '/' + path}"
    out: Dict[str, Any] = {"url": url, "method_used": "HEAD"}
    try:
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=timeout) as client:
            r = await client.request("HEAD", url)
    except httpx.HTTPError as exc:
        out["head_error"] = str(exc)
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=timeout) as client:
                r = await client.request("GET", url)
            out["method_used"] = "GET"
        except httpx.HTTPError as exc2:
            out["get_error"] = str(exc2)
            return out
    out["status_code"] = r.status_code
    h = {k.lower(): v for k, v in r.headers.items()}
    out["server"] = h.get("server", "")
    out["x_powered_by"] = h.get("x-powered-by", "")
    return out
