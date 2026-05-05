# Made by Sn0w8ird

from __future__ import annotations

import ipaddress
from typing import List


def hosts_from_cidr(cidr: str, *, limit: int = 65536) -> List[str]:
    """Expand an IPv4/IPv6 CIDR to host strings (bounded).

    Single-address networks (e.g. ``/32``) use the sole address.
    """
    net = ipaddress.ip_network(cidr.strip(), strict=False)
    if isinstance(net, ipaddress.IPv4Network) and net.prefixlen == 32:
        return [str(net.network_address)]
    if isinstance(net, ipaddress.IPv6Network) and net.prefixlen == 128:
        return [str(net.network_address)]
    out: List[str] = []
    for i, addr in enumerate(net.hosts()):
        if i >= limit:
            break
        out.append(str(addr))
    return out
