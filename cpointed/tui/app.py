# Made by Sn0w8ird

from __future__ import annotations

import os

from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import ScrollableContainer, Vertical
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Log,
    Static,
    TabbedContent,
    Tab,
    Tree,
)

from cpointed.core.banner import build_banner
from cpointed.core.engine import CPointedEngine, ScanResult, Target
from cpointed.modules import ALL_MODULES, DEFAULT_MODULES
from cpointed.scanner.fingerprint import fingerprint_service, guess_target_type
from cpointed.tui.reporting import (
    attack_tree_payload,
    executive_summary_dict,
    format_executive_dashboard,
    format_panel_line,
    format_severity_heatmap,
    heatmap_rows,
)
from cpointed.tui.screens.vuln_detail import VulnDetailScreen
from cpointed.tui.tree_utils import populate_attack_surface_tree
from cpointed.tui.icons import Icons, Tags


class CPointedTUI(App):
    """Textual front-end with tabbed analytic views (authorized use)."""

    CSS = """
    Screen { background: $surface; }
    TabbedContent { height: 1fr; }
    #results-stack { height: 1fr; }
    #results-table { height: 12; min-height: 8; }
    #run-log { height: 8; min-height: 5; background: $panel; border: solid $boost; }
    #attack-tree { height: 1fr; min-height: 10; border: solid $boost; }
    #heatmap-view { margin: 1 0; }
    #dashboard-view { margin: 1 0; }
    #target-line { padding: 0 1; background: $panel; }
    #help { padding: 0 1; color: $text-muted; }
    #banner-scroll {
        max-height: 20;
        border: solid $boost;
        margin: 0 1;
        background: $panel;
    }
    #official-banner {
        text-style: none;
        color: $text;
    }
    #vuln-modal-outer {
        align: center middle;
    }
    .vuln-modal {
        width: 70%;
        max-width: 88;
        padding: 1 2;
        background: $surface;
        border: heavy $primary;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("s", "run_scan", "Scan"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        with ScrollableContainer(id="banner-scroll"):
            yield Static(build_banner(), id="official-banner")
        with TabbedContent(initial="results"):
            with Tab("Results", id="results"):
                with Vertical(id="results-stack"):
                    yield DataTable(id="results-table")
                    yield Log(id="run-log", highlight=True, auto_scroll=True)
                    yield Static("", id="target-line")
                    yield Static(
                        f"{Tags.METRICS} s scan  |  q quit  |  "
                        f"Tabs: Results / Surface / Analytics  |  "
                        f"CPOINTED_HOST / PORT / SSL  |  CPOINTED_WORDPRESS_MODULES=1 for WP modules.",
                        id="help",
                    )
            with Tab("Surface", id="surface"):
                with Vertical():
                    yield Tree("[SURFACE] (run scan)", id="attack-tree")
                    yield Static(
                        f"{Icons.INFO} Expand branches; select a CVE row for read-only detail (Escape closes).",
                        id="surface-help",
                    )
            with Tab("Analytics", id="analytics"):
                with Vertical():
                    yield Static("", id="heatmap-view")
                    yield Static("", id="dashboard-view")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#results-table", DataTable)
        table.add_columns("Host", "Port", "Module", "Vuln", "Severity")

    def action_run_scan(self) -> None:
        self.run_scan_job()

    @on(Tree.NodeSelected, "#attack-tree")
    def on_attack_tree_select(self, event: Tree.NodeSelected) -> None:
        data = event.node.data
        if isinstance(data, dict) and "cve" in data:
            self.push_screen(VulnDetailScreen(data))

    @work(exclusive=True)
    async def run_scan_job(self) -> None:
        log = self.query_one("#run-log", Log)
        log.clear()
        log.write_line(f"{Icons.TARGET} job started (Sn0w8ird / MauriceOS)")

        host = os.environ.get("CPOINTED_HOST", "127.0.0.1")
        port = int(os.environ.get("CPOINTED_PORT", "2083"))
        use_ssl = os.environ.get("CPOINTED_SSL", "1") not in ("0", "false", "no")
        target = Target(host=host, port=port, use_ssl=use_ssl)

        log.write_line(f"{Icons.INFO} fingerprint {format_panel_line(target)}")
        fp = await fingerprint_service(target, timeout=8.0)
        gt = guess_target_type(fp)
        if gt:
            target.target_type = gt
            log.write_line(f"{Icons.SUCCESS} panel hint: {gt.value}")

        use_wp = os.environ.get("CPOINTED_WORDPRESS_MODULES", "0").lower() in ("1", "true", "yes")
        modules = ALL_MODULES if use_wp else DEFAULT_MODULES
        if use_wp:
            target.metadata["include_wordpress_modules"] = True

        engine = CPointedEngine(threads=6, timeout=25)
        for m in modules:
            engine.register_module(m)
        results: list[ScanResult] = await engine.scan_target(target)

        table = self.query_one("#results-table", DataTable)
        table.clear()
        for r in results:
            table.add_row(
                r.target.host,
                str(r.target.port),
                r.module,
                "yes" if r.vulnerable else "no",
                f"{r.severity:.1f}",
            )

        self.query_one("#target-line", Static).update(format_panel_line(target))

        payload = attack_tree_payload(target, results)
        populate_attack_surface_tree(self.query_one("#attack-tree", Tree), payload)

        hrows = heatmap_rows(results)
        heatmap = format_severity_heatmap(hrows)
        self.query_one("#heatmap-view", Static).update(heatmap)

        summary = executive_summary_dict(target, results)
        dash = format_executive_dashboard(summary)
        self.query_one("#dashboard-view", Static).update(dash)

        vuln_n = sum(1 for r in results if r.vulnerable and r.module != "engine")
        log.write_line(f"{Icons.SUCCESS} scan finished — modules flagged: {vuln_n}")


def run_tui() -> None:
    CPointedTUI().run()
