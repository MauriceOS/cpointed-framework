# Made by Sn0w8ird

from __future__ import annotations

import platform
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List

from cpointed.core.exceptions import UnauthorizedOperationError


@dataclass
class RemediationStep:
    description: str
    shell: str
    risk: str = "medium"


@dataclass
class RemediationPlan:
    title: str
    steps: List[RemediationStep] = field(default_factory=list)


def cpanel_blue_team_plan(*, auto_patch: bool = False) -> RemediationPlan:
    """Curated bash-oriented remediation checklist (Linux cPanel hosts)."""
    steps = [
        RemediationStep("Kill common coin-miner process names", "pkill -9 -f nuclear.x86 || true; pkill -9 -f xmrig || true; pkill -9 -f kinsing || true", "high"),
        RemediationStep("Purge cPanel raw sessions (requires root)", "rm -rf /var/cpanel/sessions/raw/* 2>/dev/null || true", "high"),
        RemediationStep("Restart cpsrvd (requires root)", "/scripts/restartsrv_cpsrvd 2>/dev/null || systemctl restart cpanel.service || true", "high"),
        RemediationStep("Mark tagged SSH keys for review", "grep -n 'cpointed' /root/.ssh/authorized_keys 2>/dev/null || true", "low"),
    ]
    if auto_patch:
        steps.append(
            RemediationStep("Force cPanel update (dangerous; maintenance window)", "/scripts/upcp --force 2>/dev/null || true", "high"),
        )
    return RemediationPlan(title="cPanel / WHM - blue-team checklist", steps=steps)


def execute_plan(
    plan: RemediationPlan,
    *,
    execute: bool,
    authorized: bool,
) -> List[Dict[str, Any]]:
    """Print or run remediation shell snippets on the *local* operator machine.

    Intended for jump-boxes with SSH to the target; does not imply safe defaults on Windows.
    """
    if execute and not authorized:
        raise UnauthorizedOperationError("Remediation execution requires CPOINTED_AUTHORIZED=1.")

    out: List[Dict[str, Any]] = []
    if platform.system() == "Windows" and execute:
        raise RuntimeError("Direct execution is blocked on Windows hosts; run from a Linux jump box or WSL.")

    for step in plan.steps:
        row = {"description": step.description, "shell": step.shell, "risk": step.risk}
        if not execute:
            row["status"] = "planned"
            out.append(row)
            continue
        proc = subprocess.run(
            ["bash", "-lc", step.shell],
            capture_output=True,
            text=True,
            timeout=600,
        )
        row["status"] = "executed"
        row["returncode"] = proc.returncode
        row["stdout_tail"] = (proc.stdout or "")[-2000:]
        row["stderr_tail"] = (proc.stderr or "")[-2000:]
        out.append(row)
    return out


def plan_to_text(plan: RemediationPlan) -> str:
    lines = [plan.title, "=" * 72]
    for i, s in enumerate(plan.steps, 1):
        lines.append(f"{i}. [{s.risk}] {s.description}")
        lines.append(f"   $ {s.shell}")
    return "\n".join(lines)
