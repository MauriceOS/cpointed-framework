# Made by Sn0w8ird

"""Operator-supplied payload directory: files live outside the framework tree."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

_MANIFEST_NAME = "operator_manifest.json"


@dataclass(frozen=True)
class OperatorBundle:
    """Resolved, trusted root for engagement-specific artifacts (never auto-created)."""

    root: Path

    @property
    def manifest_path(self) -> Path:
        return self.root / _MANIFEST_NAME

    @classmethod
    def from_path(cls, path: str | Path) -> OperatorBundle:
        root = Path(path).expanduser().resolve()
        if not root.is_dir():
            raise FileNotFoundError(f"Operator bundle root is missing or not a directory: {root}")
        return cls(root=root)

    @classmethod
    def from_environment(cls) -> Optional[OperatorBundle]:
        raw = os.environ.get("CPOINTED_PAYLOAD_DIR") or os.environ.get("CPOINTED_OPERATOR_BUNDLE")
        if not raw:
            return None
        return cls.from_path(raw)

    def _safe_child(self, relative: str | Path) -> Path:
        rel_path = Path(relative)
        if rel_path.is_absolute():
            raise ValueError("Relative path must not be absolute")
        for part in rel_path.parts:
            if part == "..":
                raise ValueError("Relative path must stay inside the bundle root")
        target = (self.root / rel_path).resolve()
        try:
            target.relative_to(self.root)
        except ValueError as exc:
            raise ValueError("Path escapes bundle root") from exc
        return target

    def read_bytes(self, relative: str | Path) -> bytes:
        p = self._safe_child(relative)
        if not p.is_file():
            raise FileNotFoundError(str(p))
        return p.read_bytes()

    def read_text(self, relative: str | Path, encoding: str = "utf-8") -> str:
        return self.read_bytes(relative).decode(encoding, errors="replace")

    def copy_file(self, relative: str | Path, destination: str | Path) -> Path:
        import shutil

        src = self._safe_child(relative)
        if not src.is_file():
            raise FileNotFoundError(str(src))
        dest = Path(destination).expanduser().resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
        return dest

    def _load_manifest(self) -> Dict[str, Any]:
        if not self.manifest_path.is_file():
            return {"version": 1, "entries": []}
        data = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("operator_manifest.json must be a JSON object")
        entries = data.get("entries")
        if entries is None:
            data = {**data, "entries": []}
        elif not isinstance(entries, list):
            raise ValueError("operator_manifest.json 'entries' must be a list")
        return data

    def manifest_entries(self) -> List[Dict[str, Any]]:
        return list(self._load_manifest().get("entries") or [])

    def resolve_manifest_id(self, entry_id: str) -> Path:
        for e in self.manifest_entries():
            if not isinstance(e, dict):
                continue
            if e.get("id") == entry_id:
                rel = e.get("path")
                if not rel or not isinstance(rel, str):
                    raise KeyError(f"Manifest entry {entry_id!r} has no string path")
                return self._safe_child(rel)
        raise KeyError(f"No manifest entry with id={entry_id!r}")

    def describe_for_report(self) -> Dict[str, Any]:
        rows: List[Dict[str, Any]] = []
        for e in self.manifest_entries():
            if not isinstance(e, dict):
                continue
            eid = e.get("id")
            rel = e.get("path")
            row: Dict[str, Any] = {"id": eid, "path": rel}
            if isinstance(rel, str):
                try:
                    p = self._safe_child(rel)
                    row["exists"] = p.is_file()
                    if p.is_file():
                        row["size_bytes"] = p.stat().st_size
                except ValueError:
                    row["exists"] = False
                    row["path_error"] = "invalid_relative_path"
            rows.append(row)
        return {
            "root": str(self.root),
            "manifest": str(self.manifest_path),
            "manifest_entries": rows,
        }

    def list_relative_files(self, *, max_depth: int = 12) -> List[str]:
        """Best-effort inventory (for audit); skips symlinks outside root."""

        out: List[str] = []
        root = self.root.resolve()

        def walk(cur: Path, depth: int) -> None:
            if depth > max_depth:
                return
            try:
                for child in sorted(cur.iterdir()):
                    if child.name == _MANIFEST_NAME and child.parent == root:
                        continue
                    try:
                        rel = child.relative_to(root).as_posix()
                    except ValueError:
                        continue
                    if child.is_dir():
                        walk(child, depth + 1)
                    elif child.is_file():
                        out.append(rel)
            except OSError:
                return

        walk(root, 0)
        return sorted(out)


def operator_bundle_for_target(target: object) -> Optional[OperatorBundle]:
    meta = getattr(target, "metadata", None)
    if not isinstance(meta, dict):
        meta = {}
    for key in ("payload_dir", "operator_bundle", "CPOINTED_PAYLOAD_DIR"):
        v = meta.get(key)
        if v:
            return OperatorBundle.from_path(str(v))
    return OperatorBundle.from_environment()
