# Made by Sn0w8ird

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Set

_marker_dirs = frozenset({".git", "node_modules", "vendor", ".svn"})


@dataclass(frozen=True)
class WordPressInstall:
    root: Path
    wp_config: Path


def enumerate_wordpress_installs(
    base: str | Path,
    *,
    max_depth: int = 14,
    max_installs: int = 500,
) -> List[WordPressInstall]:
    """Find WordPress roots by locating wp-config.php under *base*.

    Intended for authorized forensic / hardening workflows on hosts you control.
    """
    root_base = Path(base).expanduser().resolve()
    if not root_base.is_dir():
        return []

    found: List[WordPressInstall] = []
    seen_roots: Set[str] = set()

    def walk(cur: Path, depth: int) -> None:
        nonlocal found
        if depth > max_depth or len(found) >= max_installs:
            return
        try:
            children: Iterable[Path] = list(cur.iterdir())
        except OSError:
            return

        cfg = cur / "wp-config.php"
        version_stub = cur / "wp-includes" / "version.php"
        if cfg.is_file() and version_stub.is_file():
            key = str(cur)
            if key not in seen_roots:
                seen_roots.add(key)
                found.append(WordPressInstall(root=cur, wp_config=cfg))
            return

        for child in children:
            if not child.is_dir():
                continue
            name = child.name
            if name.startswith(".") and name != ".":
                continue
            if name in _marker_dirs:
                continue
            walk(child, depth + 1)

    walk(root_base, 0)
    return sorted(found, key=lambda i: str(i.root))
