# Made by Sn0w8ird
"""Professional TUI / CLI glyphs (Sn0w8ird / MauriceOS)."""

from __future__ import annotations

from enum import Enum


class TuiVisualStyle(str, Enum):
    PROFESSIONAL = "professional"
    MODERN = "modern"


class Icons:
    SUCCESS = "\u2713"
    FAILURE = "\u2717"
    PENDING = "\u2026"
    BULLET = "\u2022"
    WARNING = "!"
    INFO = "i"
    TARGET = ">"
    ARROW = "\u2192"
    TREE_BRANCH = "\u251c\u2500 "
    TREE_LAST = "\u2514\u2500 "
    TREE_VBAR = "\u2502 "
    PROG_FULL = "\u2588"
    PROG_EMPTY = "\u2591"
    LOG_INFO = "[i]"
    LOG_WARN = "[!]"
    LOG_ERROR = "[x]"


class Tags:
    METRICS = "[METRICS]"
    SEVERITY = "[SEVERITY]"
    TOP = "[TOP]"
    REMEDIATION = "[REMEDIATION]"
    SURFACE = "[SURFACE]"
    TIMELINE = "[TIMELINE]"
    DETAIL = "[DETAIL]"
    FIX = "[FIX]"
    PERSIST = "[PERSIST]"
    TARGET_HDR = "[TARGET]"


def sev_label(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def severity_rich_tag(score: float) -> str:
    tier = sev_label(score)
    if score >= 9.0:
        return f"[bold red]{tier}[/]"
    if score >= 7.0:
        return f"[bold yellow]{tier}[/]"
    if score >= 4.0:
        return f"[cyan]{tier}[/]"
    return f"[dim]{tier}[/]"
