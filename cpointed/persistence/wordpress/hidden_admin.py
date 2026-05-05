# Made by Sn0w8ird

from __future__ import annotations

from pathlib import Path


def write_operator_wordpress_admin_bundle(output_dir: str | Path) -> Path:
    """Emit a review bundle with wp-cli oriented steps (no auto-provisioning)."""
    d = Path(output_dir).expanduser().resolve()
    d.mkdir(parents=True, exist_ok=True)
    path = d / "wordpress_admin_operator_notes.md"
    body = """# cpointed — WordPress admin provisioning (operator review)

Use only on systems you own or have explicit permission to harden/recover.

1. Prefer `wp user create` / `wp user update` from an authenticated shell.
2. Rotate all application passwords and salts in `wp-config.php` after incident.
3. Review `wp user list --role=administrator` for unexpected accounts.
4. Avoid storing long-lived passwords in the database; use session + MFA where possible.

Signed: Sn0w8ird / MauriceOS
"""
    path.write_text(body, encoding="utf-8", newline="\n")
    return path
