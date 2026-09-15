# Made by Sn0w8ird
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Sn0w8ird (MauriceOS)
"""Startup banner for cpointed: ASCII art, version, dynamic module counts, operator context."""

from __future__ import annotations

import os
import socket
import subprocess
from pathlib import Path

from cpointed import __version__ as VERSION


def _auxiliary_capability_count() -> int:
    """Scanner + local + WP discovery + operator payload bundle surfaces."""
    pkg = Path(__file__).resolve().parent.parent
    scanner = sum(1 for p in (pkg / "scanner").glob("*.py") if p.name != "__init__.py")
    local = sum(1 for p in (pkg / "local").glob("*.py") if p.name != "__init__.py")
    payloads = sum(1 for p in (pkg / "payloads").glob("*.py") if p.name != "__init__.py")
    discovery = 1 if (pkg / "modules" / "wordpress" / "discovery.py").exists() else 0
    return scanner + local + payloads + discovery


try:
    from cpointed.modules import ALL_MODULES
    from cpointed.persistence import PERSISTENCE_MODULES
    from cpointed.remediation import REMEDIATION_MODULES

    EXPLOIT_COUNT = len(ALL_MODULES)
    AUX_COUNT = _auxiliary_capability_count()
    PAYLOAD_COUNT = len(PERSISTENCE_MODULES)
    POST_COUNT = len(REMEDIATION_MODULES)
except ImportError:
    EXPLOIT_COUNT, AUX_COUNT, PAYLOAD_COUNT, POST_COUNT = 14, 8, 12, 5


def get_git_branch() -> str:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout:
            return f"[{proc.stdout.strip()}]"
    except (OSError, subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return ""


def _hostname() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return "localhost"


def get_user_and_path(with_branch: bool = True) -> str:
    user = os.environ.get("USER") or os.environ.get("USERNAME") or "operator"
    cwd = Path.cwd()
    home = Path.home()
    if str(cwd).startswith(str(home)):
        try:
            cwd = Path("~") / cwd.relative_to(home)
        except ValueError:
            pass
    branch = get_git_branch() if with_branch else ""
    return f"{user}@{_hostname()}:{cwd} {branch}".strip()


def _operator_identity() -> str:
    return os.environ.get("USER") or os.environ.get("USERNAME") or "operator"


def build_banner() -> str:
    who = _operator_identity()
    ctx = get_user_and_path()

    def _pad(s: str, width: int = 66) -> str:
        """Fit *s* into *width* chars so the right ║ border stays aligned."""
        return s[:width].ljust(width)

    stat1 = f"  + ---[ {EXPLOIT_COUNT} exploits - {AUX_COUNT} auxiliary - {POST_COUNT} post"
    stat2 = f"  + ---[ {PAYLOAD_COUNT} persistence payloads"
    ver_line = f"                   v{VERSION} | Authorized Use Only"
    logged = f"  \u25cf  Logged in as: {who}"
    ctxline = f"    {ctx}"
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
        "║         Red Team Framework | Hosting Control Panel Security      ║\n"
        f"║{_pad(ver_line)}║\n"
        "║                                                                  ║\n"
        "║                Built by: Sn0w8ird                               ║\n"
        "║                Licensed to: MauriceOS                            ║\n"
        "╠══════════════════════════════════════════════════════════════════╣\n"
        f"║{_pad(stat1)}║\n"
        f"║{_pad(stat2)}║\n"
        "║  + ---[ Free for authorized use only                             ║\n"
        "╠══════════════════════════════════════════════════════════════════╣\n"
        "║                                                                  ║\n"
        "║  ☺  Welcome to cpointed – Red Team for Hosting Control Panels    ║\n"
        "║                                                                  ║\n"
        f"║{_pad(logged)}║\n"
        f"║{_pad(ctxline)}║\n"
        "║                                                                  ║\n"
        "║  ──────────────────────────────────────────────────────────────  ║\n"
        "║  Enter a command or use --help. For destructive actions, set     ║\n"
        "║  CPOINTED_AUTHORIZED=1 in your environment.                      ║\n"
        "║  ──────────────────────────────────────────────────────────────  ║\n"
        "╚══════════════════════════════════════════════════════════════════╝\n"
    )


def show_banner() -> None:
    print(build_banner())
