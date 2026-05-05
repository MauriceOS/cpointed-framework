# Made by Sn0w8ird

from __future__ import annotations

from typing import Optional, Tuple

from packaging.version import InvalidVersion, Version


def parse_version(value: str) -> Optional[Version]:
    try:
        return Version(value)
    except InvalidVersion:
        return None


def is_strictly_older(installed: str, fixed_in: str) -> Tuple[bool, Optional[str]]:
    """Return (older_than_fixed, error_reason).

    True means *installed < fixed_in* using PEP 440 rules where possible.
    """
    a = parse_version(installed)
    b = parse_version(fixed_in)
    if a is None:
        return False, "unparseable_installed"
    if b is None:
        return False, "unparseable_fixed"
    return a < b, None
