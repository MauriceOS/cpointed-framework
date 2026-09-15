# Made by Sn0w8ird
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Sn0w8ird (MauriceOS)
"""Startup banner for cpointed: ASCII art, version, dynamic module counts."""

from __future__ import annotations

from cpointed import __version__ as VERSION

try:
    from cpointed.modules import ALL_MODULES
    from cpointed.persistence import PERSISTENCE_MODULES
    from cpointed.remediation import REMEDIATION_MODULES
    from pathlib import Path

    def _aux_count() -> int:
        pkg = Path(__file__).resolve().parent.parent
        return (
            sum(1 for p in (pkg / "scanner").glob("*.py") if p.name != "__init__.py")
            + sum(1 for p in (pkg / "local").glob("*.py") if p.name != "__init__.py")
            + sum(1 for p in (pkg / "payloads").glob("*.py") if p.name != "__init__.py")
            + (1 if (pkg / "modules" / "wordpress" / "discovery.py").exists() else 0)
        )

    EXPLOIT_COUNT = len(ALL_MODULES)
    AUX_COUNT = _aux_count()
    PAYLOAD_COUNT = len(PERSISTENCE_MODULES)
    POST_COUNT = len(REMEDIATION_MODULES)
except ImportError:
    EXPLOIT_COUNT, AUX_COUNT, PAYLOAD_COUNT, POST_COUNT = 14, 8, 12, 5


def build_banner() -> str:
    def _pad(s: str, width: int = 66) -> str:
        return s[:width].ljust(width)

    info = f"  v{VERSION}  |  Red Team Framework  |  MIT  |  Authorized Use Only"
    author = "  Sn0w8ird / MauriceOS"
    counts = (
        f"  {EXPLOIT_COUNT} exploits"
        f"  {AUX_COUNT} auxiliary"
        f"  {POST_COUNT} post"
        f"  {PAYLOAD_COUNT} persistence"
    )
    return (
        "\n"
        "╔══════════════════════════════════════════════════════════════════╗\n"
        "║                                                                  ║\n"
        "║    ██████╗██████╗  ██████╗ ██╗███╗   ██╗████████╗███████╗██████╗ ║\n"
        "║   ██╔════╝██╔══██╗██╔═══██╗██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗║\n"
        "║   ██║     ██████╔╝██║   ██║██║██╔██╗ ██║   ██║   █████╗  ██║  ██║║\n"
        "║   ██║     ██╔═══╝ ██║   ██║██║██║╚██╗██║   ██║   ██╔══╝  ██║  ██║║\n"
        "║   ╚██████╗██║     ╚██████╔╝██║██║ ╚████║   ██║   ███████╗██████╔╝║\n"
        "║    ╚═════╝╚═╝      ╚═════╝ ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═════╝ ║\n"
        "║                                                                  ║\n"
        f"║{_pad(info)}║\n"
        f"║{_pad(author)}║\n"
        "║                                                                  ║\n"
        f"║{_pad(counts)}║\n"
        "╚══════════════════════════════════════════════════════════════════╝\n"
        "Use --help for available commands."
        "  Set CPOINTED_AUTHORIZED=1 for exploit and persistence operations.\n"
    )


def show_banner() -> None:
    print(build_banner())
