# Made by Sn0w8ird

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import List

from cpointed.core.engine import CPointedEngine, ScanResult, Target, TargetType
from cpointed.core.exceptions import UnauthorizedOperationError
from cpointed.exploit import ExploitManager
from cpointed.modules import DEFAULT_MODULES, DEFAULT_WP_MODULES, ALL_MODULES
from cpointed.modules.wordpress.discovery import discover_wordpress, merge_discovery_into_target
from cpointed.reporting import write_html_report, write_json_report
from cpointed.scanner.bulk import load_targets_file
from cpointed.scanner.cidr import hosts_from_cidr
from cpointed.scanner.fingerprint import fingerprint_service, guess_target_type
from cpointed.scanner.ports import common_cp_ports, parse_port_list, scan_tcp_ports_async
from cpointed.tui.app import run_tui


def _build_target(ns: argparse.Namespace) -> Target:
    tt: TargetType | None = None
    if ns.target_type:
        tt = TargetType[ns.target_type]
    return Target(host=ns.host, port=ns.port, use_ssl=ns.ssl, target_type=tt)


async def _cmd_scan(ns: argparse.Namespace) -> int:
    targets: List[Target] = []
    tt: TargetType | None = TargetType[ns.target_type] if ns.target_type else None

    if ns.cidr:
        for h in hosts_from_cidr(ns.cidr, limit=ns.cidr_limit):
            targets.append(Target(host=h, port=ns.port, use_ssl=ns.ssl, target_type=tt))
    elif ns.targets_file:
        targets.extend(load_targets_file(ns.targets_file, default_ssl=ns.ssl))
        if tt:
            for t in targets:
                if t.target_type is None:
                    t.target_type = tt
    else:
        targets.append(_build_target(ns))

    port_scan_set = parse_port_list(ns.ports) if ns.ports else common_cp_ports()

    if ns.discover_ports:
        for t in targets:
            open_ports = await scan_tcp_ports_async(t.host, port_scan_set, timeout=ns.port_timeout)
            t.metadata["open_ports"] = open_ports
            if not ns.port and open_ports:
                prefer = 2083 if t.use_ssl else 2082
                t.port = prefer if prefer in open_ports else open_ports[0]

    if ns.wordpress:
        for t in targets:
            t.metadata["include_wordpress_modules"] = True

    if ns.dry_run:
        for t in targets:
            t.metadata["scan_dry_run"] = True

    engine = CPointedEngine(threads=ns.threads, timeout=ns.timeout)
    module_list = ALL_MODULES if ns.wordpress else DEFAULT_MODULES
    for m in module_list:
        engine.register_module(m)

    all_results = []
    for target in targets:
        if ns.fingerprint:
            fp = await fingerprint_service(target, timeout=float(ns.timeout))
            target.metadata["fingerprint"] = fp
            gt = guess_target_type(fp)
            if gt and target.target_type is None:
                target.target_type = gt
        results = await engine.scan_target(target)
        all_results.extend(results)

    for r in all_results:
        flag = "VULN" if r.vulnerable else "ok"
        print(f"[{flag}] {r.target.host}:{r.target.port} {r.module} sev={r.severity}")

    if ns.json_out:
        write_json_report(all_results, ns.json_out)
    if ns.html_out:
        write_html_report(all_results, ns.html_out)

    return 0


async def _cmd_exploit(ns: argparse.Namespace) -> int:
    target = _build_target(ns)
    if getattr(ns, "payload_dir", None):
        target.metadata["payload_dir"] = str(Path(ns.payload_dir).expanduser().resolve())
    mgr = ExploitManager(ALL_MODULES)
    kwargs = {}
    if getattr(ns, "dry_run", False):
        kwargs["dry_run"] = True
    try:
        out = await mgr.run(ns.cve, target, **kwargs)
    except UnauthorizedOperationError as exc:
        print(f"Blocked: {exc}", file=sys.stderr)
        return 2
    except NotImplementedError as exc:
        print(f"Not implemented: {exc}", file=sys.stderr)
        return 3
    print(out)
    return 0


async def _cmd_wp_discover(ns: argparse.Namespace) -> int:
    import json

    d = await discover_wordpress(ns.url, timeout=float(ns.timeout), verify_ssl=bool(ns.verify_ssl))
    print(json.dumps(d, indent=2))
    return 0


async def _cmd_wp_scan(ns: argparse.Namespace) -> int:
    targets: List[Target] = []
    if ns.targets_file:
        targets.extend(load_targets_file(ns.targets_file, default_ssl=ns.ssl))
        for t in targets:
            t.target_type = TargetType.WORDPRESS
            t.metadata.setdefault("wp_base_path", ns.path)
            t.metadata["wordpress"] = True
    else:
        t = Target(
            host=ns.host,
            port=ns.port,
            use_ssl=ns.ssl,
            target_type=TargetType.WORDPRESS,
        )
        t.metadata["wp_base_path"] = ns.path
        t.metadata["wordpress"] = True
        targets.append(t)

    all_results: List[ScanResult] = []
    for target in targets:
        if ns.discover_first:
            scheme = "https" if target.use_ssl else "http"
            prefix = (target.metadata.get("wp_base_path") or "/").strip()
            if not prefix.startswith("/"):
                prefix = "/" + prefix
            base = f"{scheme}://{target.host}:{target.port}{prefix}"
            d = await discover_wordpress(base, timeout=float(ns.timeout), verify_ssl=target.use_ssl)
            merge_discovery_into_target(target.metadata, d)
        engine = CPointedEngine(threads=ns.threads, timeout=ns.timeout)
        for m in DEFAULT_WP_MODULES:
            engine.register_module(m)
        results = await engine.scan_target(target)
        all_results.extend(results)

    for r in all_results:
        if r.vulnerable:
            flag = "VULN"
        else:
            surf = bool(r.details.get("plugin_surface") or r.details.get("theme_surface"))
            flag = "surface" if surf else "ok"
        print(f"[{flag}] {r.target.host}:{r.target.port} {r.module} sev={r.severity}")

    if ns.json_out:
        write_json_report(all_results, ns.json_out)
    if ns.html_out:
        write_html_report(all_results, ns.html_out)
    return 0


async def _cmd_local_deploy_probe(ns: argparse.Namespace) -> int:
    from cpointed.persistence.wordpress import MuPluginPersistence

    path = await MuPluginPersistence(ns.wordpress_root).deploy()
    print(str(path))
    return 0


def _cmd_local_enumerate_wp(ns: argparse.Namespace) -> int:
    import json
    from pathlib import Path

    from cpointed.local import enumerate_wordpress_installs

    installs = enumerate_wordpress_installs(
        ns.base,
        max_depth=ns.max_depth,
        max_installs=ns.max_installs,
    )
    payload = [{"root": str(i.root), "wp_config": str(i.wp_config)} for i in installs]
    text = json.dumps(payload, indent=2)
    if ns.json_out:
        Path(ns.json_out).write_text(text, encoding="utf-8")
    print(text)
    return 0


def _cmd_local_sql_stub(ns: argparse.Namespace) -> int:
    from cpointed.persistence.wordpress import DatabasePersistence

    path = DatabasePersistence().write_audit_stub(ns.output)
    print(str(path))
    return 0


def _cmd_remediate(ns: argparse.Namespace) -> int:
    import json
    import os

    from cpointed.remediation.engine import cpanel_blue_team_plan, execute_plan, plan_to_text

    plan = cpanel_blue_team_plan(auto_patch=ns.auto_patch)
    if ns.plan_only or not ns.execute:
        print(plan_to_text(plan))
        return 0
    ok = os.environ.get("CPOINTED_AUTHORIZED") == "1"
    out = execute_plan(plan, execute=True, authorized=ok)
    print(json.dumps(out, indent=2))
    return 0


def _cmd_local_wp_bundle(ns: argparse.Namespace) -> int:
    from cpointed.persistence.wordpress import write_operator_wordpress_admin_bundle

    print(str(write_operator_wordpress_admin_bundle(ns.output)))
    return 0


def _cmd_operator_bundle_list(ns: argparse.Namespace) -> int:
    from cpointed.payloads import OperatorBundle

    raw = ns.bundle or os.environ.get("CPOINTED_PAYLOAD_DIR") or os.environ.get("CPOINTED_OPERATOR_BUNDLE")
    if not raw:
        print(
            "Set --bundle or CPOINTED_PAYLOAD_DIR / CPOINTED_OPERATOR_BUNDLE.",
            file=sys.stderr,
        )
        return 2
    b = OperatorBundle.from_path(raw)
    out = {
        "root": str(b.root),
        "manifest_entries": b.manifest_entries(),
        "files": b.list_relative_files(),
    }
    print(json.dumps(out, indent=2))
    return 0


def _cmd_operator_bundle_copy(ns: argparse.Namespace) -> int:
    from cpointed.payloads import OperatorBundle

    if os.environ.get("CPOINTED_AUTHORIZED") != "1":
        print(
            "Blocked: operator-bundle-copy requires CPOINTED_AUTHORIZED=1.",
            file=sys.stderr,
        )
        return 2
    raw = ns.bundle or os.environ.get("CPOINTED_PAYLOAD_DIR") or os.environ.get("CPOINTED_OPERATOR_BUNDLE")
    if not raw:
        print(
            "Set --bundle or CPOINTED_PAYLOAD_DIR / CPOINTED_OPERATOR_BUNDLE.",
            file=sys.stderr,
        )
        return 2
    b = OperatorBundle.from_path(raw)
    dest = b.copy_file(ns.rel, ns.to)
    print(str(dest))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cpointed",
        description="cpointed framework — Sn0w8ird / MauriceOS. Authorized security research only.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Run module checks against target(s)")
    p_scan.add_argument("--host", default="127.0.0.1")
    p_scan.add_argument("--port", type=int, default=2083)
    p_scan.add_argument("--ssl", action=argparse.BooleanOptionalAction, default=True)
    p_scan.add_argument("--target-type", choices=[e.name for e in TargetType], default=None)
    p_scan.add_argument("--cidr", default=None, help="Scan all hosts in CIDR (IPv4/IPv6)")
    p_scan.add_argument("--cidr-limit", type=int, default=4096)
    p_scan.add_argument(
        "--ports",
        default=None,
        help="Comma port list for --discover-ports (default: built-in hosting set)",
    )
    p_scan.add_argument(
        "--dry-run",
        action="store_true",
        help="Non-intrusive mode (skips aggressive probes where implemented)",
    )
    p_scan.add_argument("--targets-file", default=None, help="Lines of host or host:port")
    p_scan.add_argument("--fingerprint", action="store_true")
    p_scan.add_argument("--discover-ports", action="store_true")
    p_scan.add_argument("--port-timeout", type=float, default=1.5)
    p_scan.add_argument("--threads", type=int, default=10)
    p_scan.add_argument("--timeout", type=int, default=30)
    p_scan.add_argument("--json-out", default=None)
    p_scan.add_argument("--html-out", default=None)
    p_scan.add_argument("--wordpress", action="store_true", help="Include WordPress fingerprint modules")

    p_ex = sub.add_parser("exploit", help="Invoke module exploit hook (gated)")
    p_ex.add_argument("--cve", required=True, help="Module name e.g. CVE-2026-41940")
    p_ex.add_argument("--host", default="127.0.0.1")
    p_ex.add_argument("--port", type=int, default=2083)
    p_ex.add_argument("--ssl", action=argparse.BooleanOptionalAction, default=True)
    p_ex.add_argument("--target-type", choices=[e.name for e in TargetType], default=None)
    p_ex.add_argument("--dry-run", action="store_true", help="Plan exploit chain only (supported modules)")
    p_ex.add_argument(
        "--payload-dir",
        default=None,
        help="Operator bundle root (overrides CPOINTED_PAYLOAD_DIR for this run)",
    )

    p_rem = sub.add_parser("remediate", help="Blue-team remediation checklist (Linux cPanel-oriented)")
    p_rem.add_argument("--plan-only", action="store_true", help="Print bash checklist only")
    p_rem.add_argument("--execute", action="store_true", help="Run checklist via bash -lc (requires Linux/WSL)")
    p_rem.add_argument("--auto-patch", action=argparse.BooleanOptionalAction, default=False)

    p_wp = sub.add_parser("wp", help="WordPress HTTP discovery / plugin surface fingerprints")
    wp_sub = p_wp.add_subparsers(dest="wp_cmd", required=True)

    p_wp_d = wp_sub.add_parser("discover", help="Probe common WP endpoints for a base URL")
    p_wp_d.add_argument("--url", required=True)
    p_wp_d.add_argument("--timeout", type=float, default=15.0)
    p_wp_d.add_argument("--verify-ssl", action=argparse.BooleanOptionalAction, default=False)

    p_wp_s = wp_sub.add_parser("scan", help="Run WP module fingerprints against host:port")
    p_wp_s.add_argument("--host", default="127.0.0.1")
    p_wp_s.add_argument("--port", type=int, default=443)
    p_wp_s.add_argument("--ssl", action=argparse.BooleanOptionalAction, default=True)
    p_wp_s.add_argument("--path", default="/", help="Path prefix if WP is not at /")
    p_wp_s.add_argument("--discover-first", action="store_true")
    p_wp_s.add_argument("--targets-file", default=None)
    p_wp_s.add_argument("--threads", type=int, default=10)
    p_wp_s.add_argument("--timeout", type=int, default=30)
    p_wp_s.add_argument("--json-out", default=None)
    p_wp_s.add_argument("--html-out", default=None)

    p_loc = sub.add_parser("local", help="Host-local utilities (authorized installs only)")
    loc_sub = p_loc.add_subparsers(dest="local_cmd", required=True)

    p_le = loc_sub.add_parser("enumerate-wp", help="Locate wp-config.php trees under a base path")
    p_le.add_argument("--base", required=True)
    p_le.add_argument("--max-depth", type=int, default=14)
    p_le.add_argument("--max-installs", type=int, default=500)
    p_le.add_argument("--json-out", default=None)

    p_ld = loc_sub.add_parser("deploy-mu-probe", help="Write a harmless mu-plugin probe (requires CPOINTED_AUTHORIZED=1)")
    p_ld.add_argument("--wordpress-root", required=True)

    p_lb = loc_sub.add_parser("wp-operator-bundle", help="Write WordPress operator recovery notes to a directory")
    p_lb.add_argument("--output", required=True)

    p_ls = loc_sub.add_parser("sql-audit-stub", help="Emit a starter SQL review file (requires CPOINTED_AUTHORIZED=1)")
    p_ls.add_argument("--output", required=True)

    p_lo = loc_sub.add_parser(
        "operator-bundle-list",
        help="List operator payload bundle (manifest + file inventory); set CPOINTED_PAYLOAD_DIR or --bundle",
    )
    p_lo.add_argument("--bundle", default=None, help="Bundle root directory")

    p_lc = loc_sub.add_parser(
        "operator-bundle-copy",
        help="Copy one file from the operator bundle to a destination path (requires CPOINTED_AUTHORIZED=1)",
    )
    p_lc.add_argument("--bundle", default=None, help="Bundle root directory")
    p_lc.add_argument("--rel", required=True, help="Source path relative to bundle root")
    p_lc.add_argument("--to", required=True, help="Destination file path")

    sub.add_parser("tui", help="Launch Textual interface")

    sub.add_parser("gui", help="Future GUI (stub)")

    ns = parser.parse_args(argv)

    if sys.stdout.isatty() and os.environ.get("CPOINTED_NO_BANNER") != "1":
        from cpointed.core.banner import show_banner

        show_banner()

    if ns.command == "remediate":
        return _cmd_remediate(ns)
    if ns.command == "local":
        if ns.local_cmd == "enumerate-wp":
            return _cmd_local_enumerate_wp(ns)
        if ns.local_cmd == "deploy-mu-probe":
            return asyncio.run(_cmd_local_deploy_probe(ns))
        if ns.local_cmd == "wp-operator-bundle":
            return _cmd_local_wp_bundle(ns)
        if ns.local_cmd == "sql-audit-stub":
            return _cmd_local_sql_stub(ns)
        if ns.local_cmd == "operator-bundle-list":
            return _cmd_operator_bundle_list(ns)
        if ns.local_cmd == "operator-bundle-copy":
            return _cmd_operator_bundle_copy(ns)
        return 1
    if ns.command == "wp":
        if ns.wp_cmd == "discover":
            return asyncio.run(_cmd_wp_discover(ns))
        if ns.wp_cmd == "scan":
            return asyncio.run(_cmd_wp_scan(ns))
        return 1
    if ns.command == "scan":
        return asyncio.run(_cmd_scan(ns))
    if ns.command == "exploit":
        return asyncio.run(_cmd_exploit(ns))
    if ns.command == "tui":
        run_tui()
        return 0
    if ns.command == "gui":
        from cpointed.gui import show_main_window_stub

        show_main_window_stub()
        return 4

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
