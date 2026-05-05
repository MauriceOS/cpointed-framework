# Made by Sn0w8ird

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from cpointed.core.exceptions import UnauthorizedOperationError


class DatabasePersistence:
    """Generate offline SQL review artifacts (no live DB connections in-tree)."""

    def __init__(self, db_connection: Any = None) -> None:
        self.db = db_connection

    def write_audit_stub(self, output_path: str | Path) -> Path:
        if os.environ.get("CPOINTED_AUTHORIZED") != "1":
            raise UnauthorizedOperationError(
                "Set CPOINTED_AUTHORIZED=1 only for hosts you own or have written permission to assess."
            )
        path = Path(output_path).expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        body = (
            "-- cpointed / Sn0w8ird — SQL audit stub\n"
            "-- Replace this template with your DB hardening checklist.\n"
            "-- Example: review wp_options autoloaded rows, user capabilities, suspicious cron hooks.\n"
            "SELECT NOW();\n"
        )
        path.write_text(body, encoding="utf-8", newline="\n")
        return path

    async def inject_cached_backdoor(self, **_kwargs) -> bool:
        raise UnauthorizedOperationError(
            "Live database mutation is not shipped; use vendor backup/restore and formal patching workflows."
        )
