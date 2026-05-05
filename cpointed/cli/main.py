# Made by Sn0w8ird
"""CLI entry (``python -m cpointed.cli.main``) — delegates to full ``cpointed`` argparse driver."""

from __future__ import annotations

from cpointed.__main__ import main


if __name__ == "__main__":
    raise SystemExit(main())
