# Made by Sn0w8ird

from __future__ import annotations

import asyncio
import socket
from typing import Iterable, List, Tuple

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
