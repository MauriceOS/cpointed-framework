# Made by Sn0w8ird

from .base import VulnerabilityModule
from .cpanel import CVE202434015, CVE202524832, CVE202641940, SEC585Locale
from .directadmin import CVE202146417, CVE202556551
from .mailman import CVE202543921
from .wordpress import DEFAULT_WP_MODULES

__all__ = [
    "VulnerabilityModule",
    "CVE202641940",
    "CVE202524832",
    "CVE202434015",
    "SEC585Locale",
    "CVE202556551",
    "CVE202146417",
    "CVE202543921",
    "DEFAULT_MODULES",
    "DEFAULT_WP_MODULES",
    "ALL_MODULES",
]

DEFAULT_MODULES = [
    CVE202641940(),
    CVE202524832(),
    CVE202434015(),
    SEC585Locale(),
    CVE202556551(),
    CVE202146417(),
    CVE202543921(),
]

ALL_MODULES = DEFAULT_MODULES + DEFAULT_WP_MODULES
