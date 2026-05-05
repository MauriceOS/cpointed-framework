# Made by Sn0w8ird

from __future__ import annotations

from typing import Any, Dict

from textual.app import ComposeResult
from textual.containers import Container, Vertical
from textual.screen import ModalScreen
from textual.widgets import Footer, Static

from cpointed.tui.icons import Icons, Tags, severity_rich_tag


class VulnDetailScreen(ModalScreen[None]):
    """Detail pane for a selected tree leaf (read-only metadata)."""

    BINDINGS = [("escape", "dismiss", "Close")]

    def __init__(self, vuln: Dict[str, Any]) -> None:
        super().__init__()
        self.vuln = vuln

    def compose(self) -> ComposeResult:
        cve = self.vuln.get("cve", "—")
        sev = float(self.vuln.get("severity") or 0.0)
        vuln_flag = bool(self.vuln.get("vulnerable"))
        status = f"{Icons.SUCCESS} positive" if vuln_flag else f"{Icons.FAILURE} not indicated"
        tier = severity_rich_tag(sev)
        body = "\n".join(
            [
                f"[bold]{Tags.DETAIL}[/] [bold]{cve}[/]",
                f"Severity: {sev:.1f} ({tier})",
                f"Status: {status}",
                "",
                f"[dim]{self.vuln.get('summary', '—')}[/]",
                "",
                "[dim]Escape closes.[/]",
            ]
        )
        yield Container(
            Vertical(
                Static(body, id="vuln-body"),
                classes="vuln-modal",
            ),
            id="vuln-modal-outer",
        )
        yield Footer()

    def action_dismiss(self) -> None:
        self.dismiss()
