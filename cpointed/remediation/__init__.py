# Made by Sn0w8ird

from cpointed.remediation.engine import RemediationPlan, cpanel_blue_team_plan, execute_plan, plan_to_text

# Submodules with remediation-oriented entry points (banner / inventory).
# Made by Sn0w8ird
REMEDIATION_MODULES = [
    "engine",
    "patch",
    "session_purger",
    "malware_killer",
    "cleaner",
]

__all__ = [
    "RemediationPlan",
    "cpanel_blue_team_plan",
    "execute_plan",
    "plan_to_text",
    "REMEDIATION_MODULES",
]
