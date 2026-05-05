# Made by Sn0w8ird

from cpointed.remediation.engine import RemediationPlan, RemediationStep, execute_plan, plan_to_text

__all__ = ["session_purge_plan", "run_session_purge"]


def session_purge_plan() -> RemediationPlan:
    steps = [
        RemediationStep("List poisoned session dir", "ls -la /var/cpanel/sessions/raw 2>/dev/null | head", "low"),
        RemediationStep("Purge raw sessions", "rm -rf /var/cpanel/sessions/raw/* 2>/dev/null || true", "high"),
        RemediationStep("Restart cpsrvd", "/scripts/restartsrv_cpsrvd 2>/dev/null || true", "high"),
    ]
    return RemediationPlan(title="cPanel session purge", steps=steps)


def run_session_purge(*, execute: bool, authorized: bool):
    return execute_plan(session_purge_plan(), execute=execute, authorized=authorized)


def session_purge_text() -> str:
    return plan_to_text(session_purge_plan())
