# Made by Sn0w8ird

from cpointed.remediation.engine import cpanel_blue_team_plan, execute_plan, plan_to_text

__all__ = ["patch_plan_text", "run_patch_plan"]


def patch_plan_text(*, auto_patch: bool = False) -> str:
    return plan_to_text(cpanel_blue_team_plan(auto_patch=auto_patch))


def run_patch_plan(*, execute: bool, authorized: bool, auto_patch: bool = True):
    plan = cpanel_blue_team_plan(auto_patch=auto_patch)
    return execute_plan(plan, execute=execute, authorized=authorized)
