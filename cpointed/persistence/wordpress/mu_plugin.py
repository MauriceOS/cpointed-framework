# Made by Sn0w8ird

from __future__ import annotations

import asyncio
import os
from pathlib import Path

from cpointed.core.exceptions import UnauthorizedOperationError

_PROBE_HEADER = """<?php
/**
 * Plugin Name: cpointed Lab Probe
 * Description: Authorized filesystem write verification only. Delete this file after testing.
 * Author: Sn0w8ird
 * Version: 0.1.0
 */
if (!defined('ABSPATH')) {
    exit;
}
// No runtime behavior on purpose.
"""


class MuPluginPersistence:
    """Deploy a minimal must-use plugin file for *authorized* write-path verification."""

    def __init__(self, wordpress_path: str | Path) -> None:
        self.wordpress_path = Path(wordpress_path).expanduser().resolve()

    def _ensure_authorized(self) -> None:
        if os.environ.get("CPOINTED_AUTHORIZED") != "1":
            raise UnauthorizedOperationError(
                "Set CPOINTED_AUTHORIZED=1 only when you have explicit permission to write under this WordPress tree."
            )

    def _validate_target_tree(self) -> None:
        if not self.wordpress_path.is_dir():
            raise FileNotFoundError(f"WordPress root not found: {self.wordpress_path}")
        cfg = self.wordpress_path / "wp-config.php"
        ver = self.wordpress_path / "wp-includes" / "version.php"
        if not cfg.is_file() or not ver.is_file():
            raise ValueError(
                f"Refusing to write: missing wp-config.php or wp-includes/version.php under {self.wordpress_path}"
            )

    def deploy_sync(self, *, filename: str = "cpointed-lab-probe.php") -> Path:
        """Create mu-plugins directory (if needed) and write the probe file."""
        self._ensure_authorized()
        self._validate_target_tree()
        mu_dir = self.wordpress_path / "wp-content" / "mu-plugins"
        mu_dir.mkdir(parents=True, exist_ok=True)
        path = mu_dir / filename
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(_PROBE_HEADER, encoding="utf-8")
        tmp.replace(path)
        return path

    async def deploy(self, **_kwargs) -> Path:
        return await asyncio.to_thread(self.deploy_sync)
