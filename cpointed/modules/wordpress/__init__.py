# Made by Sn0w8ird

from .base import WordPressModule
from .discovery import discover_wordpress, merge_discovery_into_target
from .cve_2026_1357_wpvivid import CVE20261357WPvivid
from .cve_2026_2991_kivicare import CVE20262991KiviCare
from .cve_2025_13374_kalrav import CVE202513374Kalrav
from .cve_2026_5294_geekybot import CVE20265294GeekyBot
from .cve_2026_7567_templogin import CVE20267567TemporaryLogin
from .cve_2026_6261_betheme import CVE20266261Betheme
from .cve_2026_3454_generateblocks import CVE20263454GenerateBlocks

__all__ = [
    "WordPressModule",
    "discover_wordpress",
    "merge_discovery_into_target",
    "DEFAULT_WP_MODULES",
]

DEFAULT_WP_MODULES = [
    CVE20261357WPvivid(),
    CVE20262991KiviCare(),
    CVE202513374Kalrav(),
    CVE20265294GeekyBot(),
    CVE20267567TemporaryLogin(),
    CVE20266261Betheme(),
    CVE20263454GenerateBlocks(),
]
