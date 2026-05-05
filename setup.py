# Made by Sn0w8ird
"""Setup for cpointed — MauriceOS / Sn0w8ird."""

from setuptools import find_packages, setup

setup(
    name="cpointed",
    version="1.0.0",
    description="cpointed security research framework (authorized use only)",
    author="Sn0w8ird",
    license="LicenseRef-MauriceOS",
    packages=find_packages(exclude=("tests",)),
    python_requires=">=3.10",
    install_requires=[
        "httpx>=0.27.0,<1.0.0",
        "packaging>=23.0,<26.0",
    ],
    extras_require={
        "tui": ["textual>=0.47.0", "rich>=13.6.0"],
        "remediation": ["paramiko>=3.3.0,<4.0.0"],
        "dev": ["pytest>=7.0.0", "pytest-asyncio>=0.23.0", "pytest-httpserver>=1.0.0"],
    },
    entry_points={
        "console_scripts": [
            "cpointed=cpointed.__main__:main",
        ],
    },
)
