# Made by Sn0w8ird

from __future__ import annotations

from typing import Any, Dict

from textual.widgets import Tree
from textual.widgets.tree import TreeNode

from cpointed.tui.icons import Icons, Tags, sev_label


def populate_attack_surface_tree(tree: Tree[Dict[str, Any]], payload: Dict[str, Any]) -> None:
    """Fill a Textual Tree with attack-surface branches (professional labels)."""
    tree.clear()
    root: TreeNode[Dict[str, Any]] = tree.root
    root.set_label(f"{Icons.TARGET} {payload['host']}  [{payload.get('panel', 'unknown')}]")
    root.expand()

    vuln_branch = root.add(f"{Tags.SEVERITY} Findings", data=None)
    vuln_branch.expand()
    vulns = payload.get("vulns") or []
    if not vulns:
        vuln_branch.add_leaf(f"{Icons.INFO} No module rows recorded.", data=None)
    else:
        for v in vulns:
            cve = v.get("cve", "?")
            sev = float(v.get("severity") or 0.0)
            flag = v.get("vulnerable")
            mark = Icons.SUCCESS if flag else Icons.FAILURE
            tier = sev_label(sev)
            label = f"{mark} {cve}  [{tier}]  {Icons.ARROW}  {v.get('summary', '')[:48]}"
            vuln_branch.add_leaf(label, data=v)

    persist = payload.get("persistence") or []
    if persist:
        pnode = root.add("[REMEDIATION] Persistence (declared)", data=None)
        pnode.expand()
        for entry in persist:
            pnode.add_leaf(f"{Icons.BULLET} {entry}", data=None)
    else:
        root.add_leaf(f"{Icons.INFO} No persistence metadata on this target.", data=None)
