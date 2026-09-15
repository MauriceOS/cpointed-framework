# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Sn0w8ird (MauriceOS)
# Made by Sn0w8ird
"""Setup for cpointed — MauriceOS / Sn0w8ird."""

import re
from pathlib import Path

from setuptools import find_packages, setup


def _version() -> str:
    text = (Path(__file__).parent / "cpointed" / "__init__.py").read_text(encoding="utf-8")
    m = re.search(r'^__version__\s*=\s*["\']([^"\']+)["\']', text, re.MULTILINE)
    if not m:
        raise RuntimeError("__version__ not found in cpointed/__init__.py")
    return m.group(1)


setup(
    name="cpointed",
    version=_version(),
    description="cpointed security research framework (authorized use only)",
    author="Sn0w8ird",
    license="MIT",
    license_files=("LICENSE",),
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    packages=find_packages(exclude=("tests",)),
    python_requires=">=3.10",
    install_requires=[
        "httpx>=0.27.0,<1.0.0",
        "packaging>=23.0,<26.0",
    ],
    extras_require={
        "tui": ["textual>=0.47.0", "rich>=13.6.0"],
        "remediation": ["paramiko>=3.3.0,<4.0.0"],
        "dev": ["pytest>=7.0.0", "pytest-asyncio>=0.23.0", "pytest-httpserver>=1.0.0", "ruff>=0.4.0"],
    },
    entry_points={
        "console_scripts": [
            "cpointed=cpointed.__main__:main",
        ],
    },
)
