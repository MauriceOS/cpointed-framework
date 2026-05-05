# Made by Sn0w8ird

from __future__ import annotations

from pathlib import Path
from typing import Iterable, List

from cpointed.core.engine import Target


def load_targets_file(path: str | Path, *, default_ssl: bool = True) -> List[Target]:
    p = Path(path)
    targets: List[Target] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        host = line
        port = 2083 if default_ssl else 2082
        if ":" in line:
            host, pstr = line.rsplit(":", 1)
            port = int(pstr)
        targets.append(Target(host=host, port=port, use_ssl=default_ssl))
    return targets


def targets_from_network(hosts: Iterable[str], ports: Iterable[int], *, use_ssl: bool = True) -> List[Target]:
    out: List[Target] = []
    for h in hosts:
        for p in ports:
            out.append(Target(host=h, port=int(p), use_ssl=use_ssl))
    return out
